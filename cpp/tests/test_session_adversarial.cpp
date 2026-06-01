// Adversarial / negative coverage for Session::handle_line(): malformed submits, out-of-order
// protocol, bad fields, stale/duplicate jobs, non-JSON; each must reply gracefully or no-op.
#include <doctest/doctest.h>

#include <ctime>
#include <format>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "bitcoin/block_template.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::stratum;
using json = nlohmann::json;

namespace {

const Bytes kPayoutScript = util::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");

std::shared_ptr<Job> make_fake_job(uint32_t curtime) {
    nlohmann::json t;
    t["height"] = 200;
    t["version"] = 0x20000000;
    t["curtime"] = curtime;
    t["bits"] = "207fffff"; // regtest-easy
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, '0');
    t["transactions"] = nlohmann::json::array();
    const auto tmpl = bitcoin::BlockTemplate::from_json(t);
    const Bytes tag{'/', 'e', 'p', '/'};
    return std::make_shared<Job>("job1", tmpl, tag, 4, 4, 1);
}

class FakeConnection : public Connection {
public:
    std::vector<json> sent;
    void send_line(std::string_view line) override { sent.push_back(json::parse(line)); }
    std::string peer() const override { return "test-peer"; }

    std::optional<json> by_id(const json& id) const {
        for (const auto& m : sent)
            if (m.contains("id") && m["id"] == id)
                return std::make_optional(m);
        return std::nullopt;
    }
    std::optional<json> by_method(std::string_view method) const {
        for (const auto& m : sent)
            if (m.contains("method") && m["method"] == method)
                return std::make_optional(m);
        return std::nullopt;
    }
};

class FakePool : public PoolContext {
public:
    std::shared_ptr<Job> job;
    int accepted = 0;
    int rejected = 0;

    explicit FakePool(uint32_t curtime) : job(make_fake_job(curtime)) {}

    size_t extranonce2_size() const override { return 4; }
    double start_difficulty() const override { return 1e-9; }
    std::optional<Bytes> validate_address(const std::string& address) override {
        if (address == "validaddr")
            return kPayoutScript;
        return std::nullopt;
    }
    std::shared_ptr<const Job> current_job() const override { return job; }
    std::shared_ptr<const Job> recent_job(const std::string& job_id) const override {
        return (job && job->job_id() == job_id) ? job : nullptr;
    }
    void note_accepted_share(const std::string&, const std::string&, double, double) override {
        ++accepted;
    }
    void note_rejected_share(const std::string&, const std::string&) override { ++rejected; }
    void on_block_found(Session&, const Job&, const ShareResult&) override {}
    bool vardiff_enabled() const override { return false; }
    double min_difficulty() const override { return 0.001; }
    double max_difficulty() const override { return 0.0; }
    double vardiff_target_shares_per_minute() const override { return 12.0; }
    int vardiff_retarget_seconds() const override { return 60; }
    uint32_t version_mask() const override { return 0x1fffe000u; }
};

struct Fixture {
    uint32_t curtime = static_cast<uint32_t>(std::time(nullptr));
    FakePool pool{curtime};
    FakeConnection conn;
    Session session{pool, conn, util::from_hex("deadbeef")};

    void subscribe() {
        session.handle_line(R"({"id":1,"method":"mining.subscribe","params":["miner/1.0"]})");
    }
    void authorize_valid() {
        session.handle_line(
            R"({"id":3,"method":"mining.authorize","params":["validaddr.w","x"]})");
    }
    // Build a mining.submit line with arbitrary (possibly malformed) fields.
    std::string submit(const std::string& job_id, const std::string& en2,
                       const std::string& ntime, const std::string& nonce,
                       const std::string& extra = "") {
        return std::format(
            R"({{"id":6,"method":"mining.submit","params":["w","{}","{}","{}","{}"{}]}})",
            job_id, en2, ntime, nonce, extra);
    }
};

} // namespace

TEST_CASE("submit before subscribe AND before authorize is unauthorized (auth checked first)") {
    Fixture f;
    // No subscribe, no authorize. handle_submit checks authorized_ before subscribed_.
    f.session.handle_line(
        f.submit("job1", "01020304", f.pool.job->ntime_hex(), "00000000"));
    const auto reply = f.conn.by_id(6);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 24); // ERR_UNAUTHORIZED
    CHECK(f.pool.accepted == 0);
}

TEST_CASE("subscribe twice does not corrupt state; second is acknowledged") {
    Fixture f;
    f.subscribe();
    f.conn.sent.clear();
    f.session.handle_line(R"({"id":2,"method":"mining.subscribe","params":["miner/2.0"]})");
    const auto reply = f.conn.by_id(2);
    REQUIRE(reply.has_value());
    CHECK(f.session.subscribed());
}

TEST_CASE("authorize before subscribe still validates the address (no crash)") {
    Fixture f;
    // No subscribe first; authorize is independent of subscribe in this impl.
    f.session.handle_line(R"({"id":3,"method":"mining.authorize","params":["validaddr.w","x"]})");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"] == true);
}

TEST_CASE("submit with fewer than 5 params is an other-error") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    for (const char* params : {
             R"([])",
             R"(["w"])",
             R"(["w","job1"])",
             R"(["w","job1","01020304"])",
             R"(["w","job1","01020304","00000000"])", // only 4
         }) {
        f.conn.sent.clear();
        f.session.handle_line(
            std::format(R"({{"id":7,"method":"mining.submit","params":{}}})", params));
        const auto reply = f.conn.by_id(7);
        REQUIRE(reply.has_value());
        CHECK((*reply)["error"][0] == 20); // ERR_OTHER
    }
}

TEST_CASE("submit to an unknown / stale job id is rejected as stale and counted rejected") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    f.session.handle_line(f.submit("does-not-exist", "01020304", f.pool.job->ntime_hex(), "00000000"));
    const auto reply = f.conn.by_id(6);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 21); // ERR_STALE
    CHECK(f.pool.rejected == 1);
    CHECK(f.pool.accepted == 0);
}

TEST_CASE("submit with non-hex extranonce2 is rejected (other-error), no crash") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    f.session.handle_line(f.submit("job1", "zzzzzzzz", f.pool.job->ntime_hex(), "00000000"));
    const auto reply = f.conn.by_id(6);
    REQUIRE(reply.has_value());
    // malformed share field -> not "above target" -> ERR_OTHER.
    CHECK((*reply)["error"][0] == 20);
    CHECK(f.pool.rejected == 1);
}

TEST_CASE("submit with wrong-length extranonce2 is rejected") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    // expected 4 bytes (8 hex). Try 2 bytes and 6 bytes.
    f.session.handle_line(f.submit("job1", "0102", f.pool.job->ntime_hex(), "00000000"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);

    f.conn.sent.clear();
    f.session.handle_line(f.submit("job1", "010203040506", f.pool.job->ntime_hex(), "00000000"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);
}

TEST_CASE("submit with non-hex / wrong-length ntime is rejected gracefully") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();

    f.session.handle_line(f.submit("job1", "01020304", "nothexxx", "00000000"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);

    f.conn.sent.clear();
    // ntime longer than 8 hex digits -> parse_hex_u32 throws internally; validate_share
    // must catch and report "malformed share field", not propagate.
    f.session.handle_line(f.submit("job1", "01020304", "00000000ff", "00000000"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);
}

TEST_CASE("submit with non-hex / oversized nonce is rejected gracefully") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();

    f.session.handle_line(f.submit("job1", "01020304", f.pool.job->ntime_hex(), "xyz!"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);

    f.conn.sent.clear();
    // 9 hex digits overflows parse_hex_u32's 8-digit cap.
    f.session.handle_line(f.submit("job1", "01020304", f.pool.job->ntime_hex(), "123456789"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);
}

TEST_CASE("submit with an empty-string field is rejected, not crashed") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    // empty extranonce2 (size mismatch), empty ntime, empty nonce.
    f.session.handle_line(f.submit("job1", "", f.pool.job->ntime_hex(), "00000000"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 20);
}

TEST_CASE("an exact-duplicate submit (even of a rejected share) is flagged duplicate") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    // A clearly-above-target nonce with a tiny difficulty; the FIRST submit is processed.
    const std::string line = f.submit("job1", "01020304", f.pool.job->ntime_hex(), "00000000");
    f.session.handle_line(line);
    const auto first = f.conn.by_id(6);
    REQUIRE(first.has_value());
    const int rejected_after_first = f.pool.rejected;

    // Resubmitting the identical params hits the dedup guard before validation.
    f.conn.sent.clear();
    f.session.handle_line(line);
    const auto second = f.conn.by_id(6);
    REQUIRE(second.has_value());
    CHECK((*second)["error"][0] == 22); // ERR_DUPLICATE
    CHECK(f.pool.rejected == rejected_after_first + 1);
}

TEST_CASE("submit with version bits outside the negotiated mask is rejected") {
    Fixture f;
    f.subscribe();
    // negotiate a mask so version bits are actually checked.
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]})");
    f.authorize_valid();
    // 6th param is the version bits; 0x00000001 is outside 0x1fffe000.
    f.session.handle_line(
        f.submit("job1", "01020304", f.pool.job->ntime_hex(), "00000000", R"(,"00000001")"));
    const auto reply = f.conn.by_id(6);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 20); // ERR_OTHER (version bits outside mask)
}

TEST_CASE("submit with malformed version bits hex is rejected, not crashed") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(
        R"({"id":2,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]})");
    f.authorize_valid();
    f.session.handle_line(
        f.submit("job1", "01020304", f.pool.job->ntime_hex(), "00000000", R"(,"zz")"));
    const auto reply = f.conn.by_id(6);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 20);
}

TEST_CASE("authorize with an empty username is an other-error and stays unauthorized") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(R"({"id":3,"method":"mining.authorize","params":[""]})");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 20);
    CHECK_FALSE(f.session.authorized());
}

TEST_CASE("authorize with no params is an other-error") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(R"({"id":3,"method":"mining.authorize","params":[]})");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 20);
    CHECK_FALSE(f.session.authorized());
}

TEST_CASE("authorize with an address the pool rejects returns result=false, not authorized") {
    Fixture f;
    f.subscribe();
    f.session.handle_line(R"({"id":3,"method":"mining.authorize","params":["badaddr.w","x"]})");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"] == false);
    CHECK_FALSE(f.session.authorized());
    // A submit afterward is still unauthorized.
    f.conn.sent.clear();
    f.session.handle_line(f.submit("job1", "01020304", f.pool.job->ntime_hex(), "00000000"));
    REQUIRE(f.conn.by_id(6).has_value());
    CHECK((*f.conn.by_id(6))["error"][0] == 24);
}

TEST_CASE("authorize with a username that is just a dot yields an empty address (rejected)") {
    Fixture f;
    f.subscribe();
    // "." -> address substr before '.' is "" -> validate_address("") returns nullopt.
    f.session.handle_line(R"({"id":3,"method":"mining.authorize","params":["."]})");
    const auto reply = f.conn.by_id(3);
    REQUIRE(reply.has_value());
    CHECK((*reply)["result"] == false);
    CHECK_FALSE(f.session.authorized());
}

TEST_CASE("an unknown method with an id gets ERR_OTHER; with null id it is silent") {
    Fixture f;
    f.subscribe();
    f.conn.sent.clear();
    f.session.handle_line(R"({"id":99,"method":"mining.frobnicate","params":[]})");
    const auto reply = f.conn.by_id(99);
    REQUIRE(reply.has_value());
    CHECK((*reply)["error"][0] == 20);

    f.conn.sent.clear();
    f.session.handle_line(R"({"method":"mining.frobnicate","params":[]})"); // no id
    CHECK(f.conn.sent.empty());
}

TEST_CASE("completely non-JSON lines are no-ops (no reply, no throw)") {
    Fixture f;
    f.conn.sent.clear();
    for (const char* line : {"this is not json", "", "   ", "{", "}}}", "\x01\x02",
                             "GET / HTTP/1.1", "[1,2,3]", "42", "null"}) {
        f.session.handle_line(line);
    }
    CHECK(f.conn.sent.empty());
}

TEST_CASE("a parse-rejected (over-deep) line is a silent no-op") {
    Fixture f;
    f.conn.sent.clear();
    std::string deep(5000, '[');
    f.session.handle_line(deep);
    CHECK(f.conn.sent.empty());
}

TEST_CASE("feeding many malformed lines in a row never crashes and keeps state sane") {
    Fixture f;
    f.subscribe();
    f.authorize_valid();
    const int baseline = f.pool.accepted;
    for (int i = 0; i < 200; ++i) {
        f.session.handle_line(f.submit("job1", "zz", "qq", "!!"));      // garbage fields
        f.session.handle_line("not json at all");
        f.session.handle_line(f.submit("nope", "01020304", "00000000", "00000000")); // stale
    }
    // No accepted shares could come from garbage; the session is still usable.
    CHECK(f.pool.accepted == baseline);
    CHECK(f.session.authorized());
}
