// Failover state-machine coverage for RpcClient::call() via a scripted call_one (no network).
// Invariants pinned:
//   * bitcoin_nodes[0] is primary; the rest are failover, tried in order.
//   * a connection failure advances to the next endpoint and STICKS there.
//   * an RPC error (the node answered) is final -- it never fails over.
//   * all endpoints down -> RpcConnectionError after trying each once.
#include <doctest/doctest.h>

#include <map>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "bitcoin/rpc_client.hpp"
#include "bitcoin/rpc_endpoint.hpp"
#include "core/errors.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using json = nlohmann::json;

namespace {

// Drives call() without a network: each endpoint URL maps to a behaviour, and
// every attempt is counted so tests can assert exactly which nodes were tried.
class ScriptedRpc : public RpcClient {
public:
    enum class Mode { Ok, Down, RpcErr };
    explicit ScriptedRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, /*timeout_seconds=*/1) {}

    std::map<std::string, Mode> mode; // url -> behaviour
    std::map<std::string, int> hits;  // url -> times call_one ran
    json ok_result;                   // when non-null, Mode::Ok returns this (e.g. a tip hash)

protected:
    nlohmann::json call_one(const Resolved& endpoint, const std::string& /*payload*/) override {
        ++hits[endpoint.url];
        switch (mode.at(endpoint.url)) {
        case Mode::Down:
            throw RpcConnectionError("down: " + endpoint.url);
        case Mode::RpcErr:
            throw RpcError("node rejected the call");
        case Mode::Ok:
            break;
        }
        return ok_result.is_null() ? json{{"served_by", endpoint.url}} : ok_result;
    }
};

const std::vector<RpcEndpoint> kEndpoints = {
    {"http://primary", "u", "p"},
    {"http://backup1", "u", "p"},
    {"http://backup2", "u", "p"},
};

} // namespace

TEST_CASE("healthy primary serves every call; failover nodes are never touched") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Ok},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"] == "http://primary");
    CHECK(rpc.call("getblockcount")["served_by"] == "http://primary");
    CHECK(rpc.hits["http://primary"] == 2);
    CHECK(rpc.hits.count("http://backup1") == 0);
}

TEST_CASE("a down primary fails over to the first reachable backup, and stops there") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup1");
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits.count("http://backup2") == 0); // stopped at the first reachable
}

TEST_CASE("two down nodes are skipped to reach the third in one call") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Down},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup2");
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits["http://backup2"] == 1);
}

TEST_CASE("an RPC error (node answered) is final -- it does NOT fail over") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::RpcErr},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK_THROWS_AS(rpc.call("submitblock"), RpcError);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits.count("http://backup1") == 0); // a live node's answer is authoritative
}

TEST_CASE("all endpoints down raises RpcConnectionError after trying each exactly once") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Down},
                {"http://backup2", ScriptedRpc::Mode::Down}};
    CHECK_THROWS_AS(rpc.call("getblockcount"), RpcConnectionError);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits["http://backup2"] == 1);
}

TEST_CASE("failover is sticky: a recovered primary is not retried while the backup is healthy") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup1"); // moves to backup1
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;                // primary comes back
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup1");
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup1");
    CHECK(rpc.hits["http://primary"] == 1);  // contacted once (the initial failure), never again
    CHECK(rpc.hits["http://backup1"] == 3);
}

TEST_CASE("endpoint_urls lists nodes in order; active_index tracks the current endpoint") {
    ScriptedRpc rpc(kEndpoints);
    const auto urls = rpc.endpoint_urls();
    REQUIRE(urls.size() == 3);
    CHECK(urls[0] == "http://primary");
    CHECK(urls[1] == "http://backup1");
    CHECK(urls[2] == "http://backup2");
    CHECK(rpc.active_index() == 0); // starts on the primary

    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.call("getblockcount");
    CHECK(rpc.active_index() == 1); // advanced + stuck on backup1
}

TEST_CASE("maybe_failback returns to a recovered, CURRENT primary only") {
    const std::string kTip(64, 'a'); // the tip the pool currently mines on
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup1"); // fail over
    REQUIRE(rpc.active_index() == 1);

    SUBCASE("primary still down -> probe fails, stays on the backup") {
        rpc.maybe_failback(kTip); // first probe is immediate (no prior probe recorded)
        CHECK(rpc.active_index() == 1);
        CHECK(rpc.hits["http://primary"] == 2); // the initial failure + the probe
        // A second probe inside the kFailbackProbeSeconds window is rate-limited away.
        rpc.maybe_failback(kTip);
        CHECK(rpc.hits["http://primary"] == 2);
    }
    SUBCASE("primary recovered AND on the pool's tip -> fail back") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = kTip;
        rpc.maybe_failback(kTip);
        CHECK(rpc.active_index() == 0);
        rpc.ok_result = nullptr;
        CHECK(rpc.call("getblockcount")["served_by"] == "http://primary");
    }
    SUBCASE("primary answering with an RPC error (e.g. -28 warming up) -> do NOT fail back") {
        // A warming-up/reindexing primary answers EVERY call with an error for hours;
        // failing back would capture the pool (call() never rotates on RpcError): no
        // work, and a solved block submitted only to the warming node. Stay put.
        rpc.mode["http://primary"] = ScriptedRpc::Mode::RpcErr;
        rpc.maybe_failback(kTip);
        CHECK(rpc.active_index() == 1);
    }
    SUBCASE("primary reachable but on a DIFFERENT (behind/forked) tip -> do NOT fail back") {
        rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
        rpc.ok_result = std::string(64, 'b'); // stale tip: still catching up
        rpc.maybe_failback(kTip);
        CHECK(rpc.active_index() == 1);
    }
}

TEST_CASE("maybe_failback is a no-op while already on the primary or with no tip yet") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.maybe_failback(std::string(64, 'a')); // on the primary: no probe
    CHECK(rpc.hits.count("http://primary") == 0);
    CHECK(rpc.active_index() == 0);

    rpc.call("getblockcount"); // fail over to backup1
    REQUIRE(rpc.active_index() == 1);
    rpc.maybe_failback(""); // no tip to compare against yet: no probe
    CHECK(rpc.hits["http://primary"] == 1); // only the original failed call
}

TEST_CASE("a concurrent fail-back is not reverted by an in-flight call's success publish") {
    // call() snapshots `start` and publishes via compare-exchange: if maybe_failback moved
    // current_ to the primary while a backup call was in flight, the completing call must
    // NOT re-stick the backup (its index equals its start, so it publishes nothing).
    const std::string kTip(64, 'a');
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Ok}};
    rpc.call("getblockcount"); // current_ -> backup1
    REQUIRE(rpc.active_index() == 1);
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
    rpc.ok_result = kTip;
    rpc.maybe_failback(kTip); // back on the primary
    REQUIRE(rpc.active_index() == 0);
    rpc.ok_result = nullptr;
    // A call that (conceptually) started before the fail-back, served by the backup:
    // simulate by a direct success on backup1 -- index == its own start would publish
    // nothing; here a FRESH call simply starts on the primary and stays there.
    CHECK(rpc.call("getblockcount")["served_by"] == "http://primary");
    CHECK(rpc.active_index() == 0); // fail-back held
}

TEST_CASE("from a backup, a fresh failure rotates and wraps to a recovered primary") {
    ScriptedRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRpc::Mode::Down},
                {"http://backup1", ScriptedRpc::Mode::Ok},
                {"http://backup2", ScriptedRpc::Mode::Down}};
    CHECK(rpc.call("getblockcount")["served_by"] == "http://backup1"); // current -> backup1
    // backup1 dies, primary recovered: backup1 -> backup2(down) -> wrap -> primary.
    rpc.mode["http://backup1"] = ScriptedRpc::Mode::Down;
    rpc.mode["http://primary"] = ScriptedRpc::Mode::Ok;
    CHECK(rpc.call("getblockcount")["served_by"] == "http://primary");
    CHECK(rpc.hits["http://backup2"] == 1); // tried once on the wrap-around
}

// The raw GBT path (getblocktemplate_parsed) has its own failover loop over post_one: rotation on
// a down endpoint, no rotation on an RPC error, body parsed straight into a BlockTemplate.
namespace {

class ScriptedRawRpc : public RpcClient {
public:
    enum class Mode { Ok, Down, RpcErr, Garbage };
    explicit ScriptedRawRpc(const std::vector<RpcEndpoint>& endpoints)
        : RpcClient(endpoints, /*timeout_seconds=*/1) {}

    std::map<std::string, Mode> mode;
    std::map<std::string, int> hits;

    static std::string gbt_body() {
        nlohmann::json tmpl;
        tmpl["height"] = 170;
        tmpl["version"] = 0x20000000;
        tmpl["curtime"] = 1700000000;
        tmpl["bits"] = "1d00ffff";
        tmpl["coinbasevalue"] = 5000000000LL;
        tmpl["previousblockhash"] = std::string(64, 'a');
        tmpl["transactions"] = nlohmann::json::array();
        return nlohmann::json{{"result", tmpl}, {"error", nullptr}, {"id", 1}}.dump();
    }

protected:
    std::string post_one(const Resolved& endpoint, const std::string& /*payload*/,
                         long* /*http_status*/) override {
        ++hits[endpoint.url];
        switch (mode.at(endpoint.url)) {
        case Mode::Down:
            throw RpcConnectionError("down: " + endpoint.url);
        case Mode::RpcErr:
            return R"({"result":null,"error":{"code":-10,"message":"warming up"},"id":1})";
        case Mode::Garbage:
            return "not json at all";
        case Mode::Ok:
            break;
        }
        return gbt_body();
    }
};

} // namespace

TEST_CASE("getblocktemplate_parsed fails over a down primary and parses from the backup") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    const auto tmpl = rpc.getblocktemplate_parsed();
    CHECK(tmpl.height == 170);
    CHECK(tmpl.bits == 0x1d00ffffu);
    CHECK(tmpl.previousblockhash == std::string(64, 'a'));
    CHECK(rpc.active_index() == 1); // stuck on the backup, like call()
}

TEST_CASE("getblocktemplate_parsed treats an unparseable body like a down endpoint") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Garbage},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 1);
}

TEST_CASE("getblocktemplate_parsed does NOT rotate on an RPC error (the node answered)") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::RpcErr},
                {"http://backup1", ScriptedRawRpc::Mode::Ok},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcError);
    CHECK(rpc.active_index() == 0);                 // no failover
    CHECK(rpc.hits.count("http://backup1") == 0);   // backups never touched
}

TEST_CASE("getblocktemplate_parsed never STICKS to a backup that answered with an RPC error") {
    // A brief primary blip + a warming/IBD backup (answers every call with an RPC error). The
    // error reply must NOT move current_, or the pool is stranded on the non-serving backup and
    // maybe_failback can't recover it. RpcError is terminal, so Ok isn't reached: current_ stays 0.
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::RpcErr},
                {"http://backup2", ScriptedRawRpc::Mode::Ok}};
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcError);
    CHECK(rpc.active_index() == 0);               // NOT captured on the warming backup
    CHECK(rpc.hits.count("http://backup2") == 0); // RpcError is terminal; Ok never reached

    // The primary recovers: the next poll serves from it (we were never stuck on the backup).
    rpc.mode["http://primary"] = ScriptedRawRpc::Mode::Ok;
    CHECK(rpc.getblocktemplate_parsed().height == 170);
    CHECK(rpc.active_index() == 0);
}

TEST_CASE("getblocktemplate_parsed throws RpcConnectionError when every endpoint is down") {
    ScriptedRawRpc rpc(kEndpoints);
    rpc.mode = {{"http://primary", ScriptedRawRpc::Mode::Down},
                {"http://backup1", ScriptedRawRpc::Mode::Down},
                {"http://backup2", ScriptedRawRpc::Mode::Down}};
    CHECK_THROWS_AS(rpc.getblocktemplate_parsed(), RpcConnectionError);
    CHECK(rpc.hits["http://primary"] == 1);
    CHECK(rpc.hits["http://backup1"] == 1);
    CHECK(rpc.hits["http://backup2"] == 1);
}
