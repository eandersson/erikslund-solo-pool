#include <doctest/doctest.h>

#include <string>

#include "stratum/message.hpp"

using namespace erikslund::stratum;

TEST_CASE("parse_request accepts a well-formed request") {
    const auto req = parse_request(R"({"id":7,"method":"mining.submit","params":["a","b"]})");
    REQUIRE(req.has_value());
    CHECK(req->id == 7);
    CHECK(req->method == "mining.submit");
    CHECK(req->params.size() == 2);
    CHECK(req->params[0] == "a");
    CHECK(req->params[1] == "b");
}

TEST_CASE("parse_request tolerates a missing id / params") {
    const auto req = parse_request(R"({"method":"mining.subscribe"})");
    REQUIRE(req.has_value());
    CHECK(req->id.is_null());
    CHECK(req->params.empty());
}

TEST_CASE("parse_request extracts mining.configure version-rolling") {
    const auto req = parse_request(
        R"({"id":1,"method":"mining.configure","params":[["version-rolling"],{"version-rolling.mask":"1fffe000"}]})");
    REQUIRE(req.has_value());
    CHECK(req->configure_version_rolling);
    REQUIRE(req->version_rolling_mask.has_value());
    CHECK(*req->version_rolling_mask == "1fffe000");
}

TEST_CASE("parse_request captures the mining.suggest_difficulty number") {
    const auto integer = parse_request(
        R"({"id":4,"method":"mining.suggest_difficulty","params":[1024]})");
    REQUIRE(integer.has_value());
    REQUIRE(integer->suggested_difficulty.has_value());
    CHECK(*integer->suggested_difficulty == doctest::Approx(1024.0));

    const auto fractional = parse_request(
        R"({"method":"mining.suggest_difficulty","params":[0.5]})");
    REQUIRE(fractional.has_value());
    REQUIRE(fractional->suggested_difficulty.has_value());
    CHECK(*fractional->suggested_difficulty == doctest::Approx(0.5));

    // a string-encoded suggestion is tolerated too
    const auto text = parse_request(
        R"({"method":"mining.suggest_difficulty","params":["256"]})");
    REQUIRE(text.has_value());
    REQUIRE(text->suggested_difficulty.has_value());
    CHECK(*text->suggested_difficulty == doctest::Approx(256.0));

    // missing / non-numeric -> unset (acked but ignored downstream)
    const auto empty = parse_request(
        R"({"method":"mining.suggest_difficulty","params":[]})");
    REQUIRE(empty.has_value());
    CHECK_FALSE(empty->suggested_difficulty.has_value());
    const auto junk = parse_request(
        R"({"method":"mining.suggest_difficulty","params":["abc"]})");
    REQUIRE(junk.has_value());
    CHECK_FALSE(junk->suggested_difficulty.has_value());
}

TEST_CASE("parse_request maps non-string params to empty strings (position-preserving)") {
    const auto req = parse_request(R"({"method":"mining.submit","params":["w","j",2,"t"]})");
    REQUIRE(req.has_value());
    REQUIRE(req->params.size() == 4);
    CHECK(req->params[2].empty());  // the JSON number 2 -> "" (rejected downstream)
    CHECK(req->params[3] == "t");   // positions preserved
}

TEST_CASE("parse_request rejects junk") {
    CHECK_FALSE(parse_request("not json").has_value());
    CHECK_FALSE(parse_request("[1,2,3]").has_value());          // not an object
    CHECK_FALSE(parse_request(R"({"id":1})").has_value());       // no method
    CHECK_FALSE(parse_request(R"({"method":123})").has_value()); // method not a string
}

TEST_CASE("response builders shape the JSON-RPC objects") {
    const json ok = make_result(1, true);
    CHECK(ok["id"] == 1);
    CHECK(ok["result"] == true);
    CHECK(ok["error"].is_null());

    const json err = make_error(2, ERR_DUPLICATE);
    CHECK(err["id"] == 2);
    CHECK(err["result"].is_null());
    CHECK(err["error"][0] == 22);
    CHECK(err["error"][2].is_null());

    const json note = make_notification("mining.set_difficulty", json::array({1024.0}));
    CHECK(note["id"].is_null());
    CHECK(note["method"] == "mining.set_difficulty");
    CHECK(note["params"][0] == 1024.0);
}

TEST_CASE("parse_request preserves a string id") {
    const auto req = parse_request(R"({"id":"abc-123","method":"mining.subscribe"})");
    REQUIRE(req.has_value());
    REQUIRE(req->id.is_string());
    CHECK(req->id.get<std::string>() == "abc-123");
}

TEST_CASE("parse_request keeps an explicit null id null") {
    const auto req = parse_request(R"({"id":null,"method":"mining.subscribe"})");
    REQUIRE(req.has_value());
    CHECK(req->id.is_null());
}

TEST_CASE("a non-int / non-string id (e.g. a float) stays null") {
    const auto req = parse_request(R"({"id":1.5,"method":"mining.subscribe"})");
    REQUIRE(req.has_value());
    CHECK(req->id.is_null()); // only integer and string ids are carried
}

TEST_CASE("suggest_difficulty parses every numeric encoding") {
    // Plain integer.
    auto r = parse_request(R"({"method":"mining.suggest_difficulty","params":[1024]})");
    REQUIRE(r.has_value());
    REQUIRE(r->suggested_difficulty.has_value());
    CHECK(*r->suggested_difficulty == doctest::Approx(1024.0));

    // A value beyond int32 (still an unsigned/long integer).
    r = parse_request(R"({"method":"mining.suggest_difficulty","params":[5000000000]})");
    REQUIRE(r.has_value());
    REQUIRE(r->suggested_difficulty.has_value());
    CHECK(*r->suggested_difficulty == doctest::Approx(5000000000.0));

    // Floating point.
    r = parse_request(R"({"method":"mining.suggest_difficulty","params":[0.25]})");
    REQUIRE(r.has_value());
    REQUIRE(r->suggested_difficulty.has_value());
    CHECK(*r->suggested_difficulty == doctest::Approx(0.25));

    // String-encoded float.
    r = parse_request(R"({"method":"mining.suggest_difficulty","params":["12.5"]})");
    REQUIRE(r.has_value());
    REQUIRE(r->suggested_difficulty.has_value());
    CHECK(*r->suggested_difficulty == doctest::Approx(12.5));
}

TEST_CASE("suggest_difficulty leaves the value unset for non-numeric input") {
    // Boolean param.
    auto r = parse_request(R"({"method":"mining.suggest_difficulty","params":[true]})");
    REQUIRE(r.has_value());
    CHECK_FALSE(r->suggested_difficulty.has_value());
    // Empty string.
    r = parse_request(R"({"method":"mining.suggest_difficulty","params":[""]})");
    REQUIRE(r.has_value());
    CHECK_FALSE(r->suggested_difficulty.has_value());
}

TEST_CASE("mining.configure without a mask leaves the mask unset but flags the extension") {
    const auto req = parse_request(
        R"({"id":1,"method":"mining.configure","params":[["version-rolling"],{}]})");
    REQUIRE(req.has_value());
    CHECK(req->configure_version_rolling);
    CHECK_FALSE(req->version_rolling_mask.has_value());
}

TEST_CASE("mining.configure that does not request version-rolling stays off") {
    const auto req = parse_request(
        R"({"id":1,"method":"mining.configure","params":[["minimum-difficulty"],{"minimum-difficulty.value":16}]})");
    REQUIRE(req.has_value());
    CHECK_FALSE(req->configure_version_rolling);
    CHECK_FALSE(req->version_rolling_mask.has_value());
}

TEST_CASE("params element that is null becomes an empty string (position preserved)") {
    const auto req = parse_request(R"({"method":"mining.submit","params":["a",null,"c"]})");
    REQUIRE(req.has_value());
    REQUIRE(req->params.size() == 3);
    CHECK(req->params[0] == "a");
    CHECK(req->params[1].empty()); // null -> ""
    CHECK(req->params[2] == "c");
}

TEST_CASE("a params field that is not an array yields no params") {
    const auto req = parse_request(R"({"method":"mining.submit","params":{"not":"an array"}})");
    REQUIRE(req.has_value());
    CHECK(req->params.empty());
}

TEST_CASE("pathologically deep JSON is rejected before parsing") {
    // 200 nested arrays exceeds the depth guard (kMaxJsonDepth = 64).
    std::string deep;
    for (int i = 0; i < 200; ++i)
        deep.push_back('[');
    deep += R"("x")";
    for (int i = 0; i < 200; ++i)
        deep.push_back(']');
    CHECK_FALSE(parse_request(deep).has_value());
}

TEST_CASE("brace characters inside a string do not inflate the depth count") {
    // The braces here are inside a JSON string value, so depth stays shallow and it parses.
    const auto req = parse_request(R"({"method":"mining.authorize","params":["{{{{{{","x"]})");
    REQUIRE(req.has_value());
    CHECK(req->params[0] == "{{{{{{");
}

TEST_CASE("make_error carries the right code for each StratumError") {
    CHECK(make_error(1, ERR_OTHER)["error"][0] == 20);
    CHECK(make_error(1, ERR_STALE)["error"][0] == 21);
    CHECK(make_error(1, ERR_DUPLICATE)["error"][0] == 22);
    CHECK(make_error(1, ERR_LOW_DIFFICULTY)["error"][0] == 23);
    CHECK(make_error(1, ERR_UNAUTHORIZED)["error"][0] == 24);
    CHECK(make_error(1, ERR_NOT_SUBSCRIBED)["error"][0] == 25);
    // The message string is carried at index 1.
    CHECK(make_error(1, ERR_DUPLICATE)["error"][1] == "Duplicate share");
}

TEST_CASE("make_result echoes the id type (string preserved)") {
    const json ok = make_result(std::string("xyz"), json::array({"sub", "en1", 4}));
    CHECK(ok["id"] == "xyz");
    CHECK(ok["result"][0] == "sub");
    CHECK(ok["error"].is_null());
}

TEST_CASE("make_result_line is byte-identical to make_result(...).dump()") {
    // The fast submit-response path must produce exactly the same wire bytes as the json builder.
    CHECK(make_result_line(7, true) == make_result(7, true).dump());
    CHECK(make_result_line(7, false) == make_result(7, false).dump());
    CHECK(make_result_line(nullptr, true) == make_result(nullptr, true).dump());
    CHECK(make_result_line(std::string("abc-1"), true) == make_result(std::string("abc-1"), true).dump());
    // Explicit expected bytes (nlohmann orders object keys lexicographically: error, id, result).
    CHECK(make_result_line(7, true) == R"({"error":null,"id":7,"result":true})");
    CHECK(make_result_line(std::string("x"), true) == R"({"error":null,"id":"x","result":true})");
}

TEST_CASE("make_error_line is byte-identical to make_error(...).dump()") {
    for (const StratumError& err : {ERR_OTHER, ERR_STALE, ERR_DUPLICATE, ERR_LOW_DIFFICULTY,
                                    ERR_UNAUTHORIZED, ERR_NOT_SUBSCRIBED}) {
        CHECK(make_error_line(9, err) == make_error(9, err).dump());
        CHECK(make_error_line(nullptr, err) == make_error(nullptr, err).dump());
        CHECK(make_error_line(std::string("id-1"), err) == make_error(std::string("id-1"), err).dump());
    }
    CHECK(make_error_line(9, ERR_DUPLICATE) ==
          R"({"error":[22,"Duplicate share",null],"id":9,"result":null})");
}

TEST_CASE("make_notify_line is byte-identical to make_notification(...).dump()") {
    // mining.notify is parity-locked on the wire: the fast per-client path must match the json
    // builder byte for byte, across empty/multi-branch jobs and both clean flags.
    const std::string job_id = "deadbeef00000001";
    const std::string prevhash =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const std::string cb1 = "01000000010000000000000000000000";
    const std::string cb2 = "ffffffff0100f2052a010000001600145555";
    const std::string version = "20000000";
    const std::string nbits = "1d00ffff";
    const std::string ntime = "6553f100";

    const auto reference = [&](const std::vector<std::string>& branches, bool clean) {
        return make_notification("mining.notify",
                                 json::array({job_id, prevhash, cb1, cb2, branches, version,
                                              nbits, ntime, clean}))
            .dump();
    };

    const std::vector<std::string> none{};
    const std::vector<std::string> two{std::string(64, '1'), std::string(64, '2')};
    CHECK(make_notify_line(job_id, prevhash, cb1, cb2, none, version, nbits, ntime, true) ==
          reference(none, true));
    CHECK(make_notify_line(job_id, prevhash, cb1, cb2, none, version, nbits, ntime, false) ==
          reference(none, false));
    CHECK(make_notify_line(job_id, prevhash, cb1, cb2, two, version, nbits, ntime, true) ==
          reference(two, true));
    CHECK(make_notify_line(job_id, prevhash, cb1, cb2, two, version, nbits, ntime, false) ==
          reference(two, false));
}
