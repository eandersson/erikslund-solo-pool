// Request/response protocol coverage for RpcClient -- the layer the failover tests mock past.
// A scripted post_one returns a raw body (and captures the outgoing payload + endpoint), so the
// REAL call_one parse, submitblock result interpretation, JSON-RPC envelope construction, base64
// auth header, and URL normalization all execute. Invariants pinned:
//   * call_one extracts the "result" subtree; a present+non-null "error" becomes RpcError;
//     a missing/null "error" is success; an unparseable body becomes RpcConnectionError (HTTP code
//     preserved); a missing "result" yields a null json.
//   * submitblock: null result = accepted (nullopt); a string = the reject reason verbatim;
//     anything else = its dump. The payload carries method "submitblock" and the block hex.
//   * call(method, params) builds a jsonrpc-1.0 envelope and the request id strictly increases.
//   * the auth header is HTTP Basic base64(user:pass); scheme-less URLs gain http://, https:// is kept.
#include <doctest/doctest.h>

#include <optional>
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

class BodyRpc : public RpcClient {
public:
    explicit BodyRpc(std::string user = "user", std::string pass = "pass")
        : RpcClient(std::vector<RpcEndpoint>{{"http://node:8332", std::move(user), std::move(pass)}},
                    /*timeout_seconds=*/1) {}

    std::string body = R"({"result":null,"error":null,"id":1})";
    long http = 200;

    std::string last_payload; // the JSON-RPC request body we sent
    std::string last_auth;    // the Authorization header we'd have sent
    int calls = 0;

protected:
    std::string post_one(const Resolved& endpoint, const std::string& payload,
                         long* http_status) override {
        ++calls;
        last_payload = payload;
        last_auth = endpoint.auth_header;
        if (http_status)
            *http_status = http;
        return body;
    }
};

} // namespace

TEST_CASE("call_one returns the result subtree, not the whole envelope") {
    BodyRpc rpc;
    rpc.body = R"({"result":{"blocks":170,"chain":"main"},"error":null,"id":1})";
    const json result = rpc.call("getblockchaininfo");
    CHECK(result["blocks"] == 170);
    CHECK(result["chain"] == "main");
    CHECK_FALSE(result.contains("id")); // the envelope id/error are stripped
}

TEST_CASE("call_one yields a null json when the reply has no result key") {
    BodyRpc rpc;
    rpc.body = R"({"error":null,"id":1})";
    CHECK(rpc.call("getblockcount").is_null());
}

TEST_CASE("a null/absent error field is NOT treated as a failure") {
    BodyRpc rpc;
    SUBCASE("error explicitly null") {
        rpc.body = R"({"result":42,"error":null,"id":1})";
        CHECK(rpc.call("getblockcount") == 42);
    }
    SUBCASE("error key absent entirely") {
        rpc.body = R"({"result":42,"id":1})";
        CHECK(rpc.call("getblockcount") == 42);
    }
}

TEST_CASE("a present, non-null error becomes RpcError carrying the node's message") {
    BodyRpc rpc;
    rpc.body = R"({"result":null,"error":{"code":-22,"message":"TX decode failed"},"id":1})";
    try {
        rpc.call("sendrawtransaction");
        FAIL("expected RpcError");
    } catch (const RpcError& e) {
        const std::string what = e.what();
        CHECK(what.find("TX decode failed") != std::string::npos);
        CHECK(what.find("-22") != std::string::npos);
    }
}

TEST_CASE("an unparseable body is a connection error that preserves the HTTP status") {
    BodyRpc rpc;
    rpc.body = "<html>502 Bad Gateway</html>"; // not JSON
    rpc.http = 502;
    try {
        rpc.call("getblockcount");
        FAIL("expected RpcConnectionError");
    } catch (const RpcConnectionError& e) {
        CHECK(std::string(e.what()).find("502") != std::string::npos);
    }
}

TEST_CASE("call() builds a jsonrpc-1.0 envelope with method + params") {
    BodyRpc rpc;
    rpc.body = R"({"result":"ok","error":null,"id":1})";
    rpc.call("getblockheader", json::array({"deadbeef", true}));
    const json sent = json::parse(rpc.last_payload);
    CHECK(sent["jsonrpc"] == "1.0");
    CHECK(sent["method"] == "getblockheader");
    CHECK(sent["params"] == json::array({"deadbeef", true}));
    CHECK(sent["id"].is_number());
}

TEST_CASE("each request gets a strictly increasing id") {
    BodyRpc rpc;
    rpc.body = R"({"result":1,"error":null,"id":1})";
    rpc.call("a");
    const int id1 = json::parse(rpc.last_payload)["id"].get<int>();
    rpc.call("b");
    const int id2 = json::parse(rpc.last_payload)["id"].get<int>();
    CHECK(id2 > id1);
}

TEST_CASE("submitblock: a null result means the block was ACCEPTED") {
    BodyRpc rpc;
    rpc.body = R"({"result":null,"error":null,"id":1})";
    CHECK(rpc.submitblock("00abcdef") == std::nullopt);
}

TEST_CASE("submitblock: a string result is the verbatim reject reason") {
    BodyRpc rpc;
    SUBCASE("high-hash") {
        rpc.body = R"({"result":"high-hash","error":null,"id":1})";
        CHECK(rpc.submitblock("00") == "high-hash");
    }
    SUBCASE("duplicate") {
        rpc.body = R"({"result":"duplicate","error":null,"id":1})";
        CHECK(rpc.submitblock("00") == "duplicate");
    }
    SUBCASE("inconclusive") {
        rpc.body = R"({"result":"inconclusive","error":null,"id":1})";
        CHECK(rpc.submitblock("00") == "inconclusive");
    }
}

TEST_CASE("submitblock: a non-string result is returned as its JSON dump") {
    BodyRpc rpc;
    rpc.body = R"({"result":{"reason":"bad"},"error":null,"id":1})";
    CHECK(rpc.submitblock("00") == R"({"reason":"bad"})");
}

TEST_CASE("submitblock payload carries the submitblock method and the block hex") {
    BodyRpc rpc;
    rpc.body = R"({"result":null,"error":null,"id":1})";
    rpc.submitblock("0011aabbccdd");
    const json sent = json::parse(rpc.last_payload);
    CHECK(sent["method"] == "submitblock");
    REQUIRE(sent["params"].is_array());
    CHECK(sent["params"][0] == "0011aabbccdd");
}

TEST_CASE("getbestblockhash returns the result string and uses the right method") {
    BodyRpc rpc;
    const std::string tip(64, 'a');
    rpc.body = json{{"result", tip}, {"error", nullptr}, {"id", 1}}.dump();
    CHECK(rpc.getbestblockhash() == tip);
    CHECK(json::parse(rpc.last_payload)["method"] == "getbestblockhash");
}

TEST_CASE("the auth header is HTTP Basic base64(user:pass)") {
    BodyRpc rpc("Aladdin", "open sesame");
    rpc.body = R"({"result":1,"error":null,"id":1})";
    rpc.call("getblockcount");
    CHECK(rpc.last_auth == "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
}

TEST_CASE("endpoint URLs are scheme-normalized: http:// added, https:// preserved") {
    const RpcClient rpc(std::vector<RpcEndpoint>{{"node:8332", "u", "p"},
                                                 {"https://secure:8332", "u", "p"},
                                                 {"http://plain:8332", "u", "p"}});
    const auto urls = rpc.endpoint_urls();
    REQUIRE(urls.size() == 3);
    CHECK(urls[0] == "http://node:8332");
    CHECK(urls[1] == "https://secure:8332");
    CHECK(urls[2] == "http://plain:8332");
}
