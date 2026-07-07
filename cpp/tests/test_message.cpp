#include <doctest/doctest.h>

#include <initializer_list>
#include <string>
#include <vector>

#include "stratum/message.hpp"
#include "util/json_number.hpp"

using namespace erikslund::stratum;
using erikslund::util::format_json_number;
using json = glz::generic;

namespace {

json jarray(std::initializer_list<json> elements) {
    json out = json::array_t{};
    for (const json& element : elements)
        out.get_array().push_back(element);
    return out;
}

json jstrings(const std::vector<std::string>& values) {
    json out = json::array_t{};
    for (const std::string& value : values)
        out.get_array().emplace_back(json(value));
    return out;
}

std::string dump(const json& value) { return glz::write_json(value).value_or(""); }

} // namespace

TEST_CASE("parse_request accepts a well-formed request") {
    const auto req = parse_request(R"({"id":7,"method":"mining.submit","params":["a","b"]})");
    REQUIRE(req.has_value());
    CHECK(req->id.get<double>() == 7);
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
    json ok = make_result(1, true);
    CHECK(ok["id"].get<double>() == 1);
    CHECK(ok["result"].get<bool>() == true);
    CHECK(ok["error"].is_null());

    json err = make_error(2, ERR_DUPLICATE);
    CHECK(err["id"].get<double>() == 2);
    CHECK(err["result"].is_null());
    CHECK(err["error"][0].get<double>() == 22);
    CHECK(err["error"][2].is_null());

    json note = make_notification("mining.set_difficulty", jarray({json(1024.0)}));
    CHECK(note["id"].is_null());
    CHECK(note["method"].get<std::string>() == "mining.set_difficulty");
    CHECK(note["params"][0].get<double>() == doctest::Approx(1024.0));
}

TEST_CASE("set_difficulty line matches the Python pool (msgspec) byte-for-byte") {
    // Golden strings are msgspec.json.encode(difficulty). The risk is the ".0" on integer/power-of-2
    // difficulties, which glaze drops.
    struct Golden {
        double difficulty;
        const char* number;
    };
    const Golden goldens[] = {
        {0.001, "0.001"},           {0.01, "0.01"},
        {0.1, "0.1"},               {0.5, "0.5"},
        {1.0, "1.0"},               {2.0, "2.0"},
        {8.0, "8.0"},               {16.0, "16.0"},
        {512.0, "512.0"},           {1024.0, "1024.0"},
        {2048.0, "2048.0"},         {4096.0, "4096.0"},
        {16384.0, "16384.0"},       {65536.0, "65536.0"},
        {100000.0, "100000.0"},     {1000000.0, "1000000.0"},
        {33554432.0, "33554432.0"}, {1073741824.0, "1073741824.0"},
        {2048.5, "2048.5"},         {12345.678, "12345.678"},
        {0.00025, "0.00025"},       {1e9, "1000000000.0"},
        {4.5e6, "4500000.0"},       {7.25, "7.25"},
        {999999.0, "999999.0"},     {0.001953125, "0.001953125"},
    };
    for (const auto& g : goldens) {
        CHECK(format_json_number(g.difficulty) == g.number);
        CHECK(make_set_difficulty_line(g.difficulty) ==
              std::string(R"({"id":null,"method":"mining.set_difficulty","params":[)") + g.number +
                  "]}");
    }
    // Out-of-domain e-notation still tracks msgspec (lowercase 'e', no '+', no leading zeros).
    CHECK(format_json_number(1e-7) == "1e-7");
    CHECK(format_json_number(1.5e-8) == "1.5e-8");
    CHECK(format_json_number(1e16) == "1e16");
    CHECK(format_json_number(1e20) == "1e20");
    CHECK(format_json_number(1.25e18) == "1.25e18");
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
    // Trailing garbage: a difficulty string must be a bare number (whole-string parse, matching the
    // Python pool's float()), so "12.5abc" is rejected rather than silently read as 12.5.
    r = parse_request(R"({"method":"mining.suggest_difficulty","params":["12.5abc"]})");
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
    auto code_of = [](const StratumError& error) {
        json m = make_error(1, error);
        return m["error"][0].get<double>();
    };
    CHECK(code_of(ERR_OTHER) == 20);
    CHECK(code_of(ERR_STALE) == 21);
    CHECK(code_of(ERR_DUPLICATE) == 22);
    CHECK(code_of(ERR_LOW_DIFFICULTY) == 23);
    CHECK(code_of(ERR_UNAUTHORIZED) == 24);
    CHECK(code_of(ERR_NOT_SUBSCRIBED) == 25);
    // The message string is carried at index 1.
    json dup = make_error(1, ERR_DUPLICATE);
    CHECK(dup["error"][1].get<std::string>() == "Duplicate share");
}

TEST_CASE("make_result echoes the id type (string preserved)") {
    json ok = make_result(std::string("xyz"), jarray({json("sub"), json("en1"), json(4)}));
    CHECK(ok["id"].get<std::string>() == "xyz");
    CHECK(ok["result"][0].get<std::string>() == "sub");
    CHECK(ok["error"].is_null());
}

TEST_CASE("make_result_line is byte-identical to make_result(...) serialized") {
    // The fast submit-response path must produce exactly the same wire bytes as the json builder.
    CHECK(make_result_line(7, true) == dump(make_result(7, true)));
    CHECK(make_result_line(7, false) == dump(make_result(7, false)));
    CHECK(make_result_line(nullptr, true) == dump(make_result(nullptr, true)));
    CHECK(make_result_line(std::string("abc-1"), true) ==
          dump(make_result(std::string("abc-1"), true)));
    // Explicit expected bytes (the pinned wire order: error, id, result).
    CHECK(make_result_line(7, true) == R"({"error":null,"id":7,"result":true})");
    CHECK(make_result_line(std::string("x"), true) == R"({"error":null,"id":"x","result":true})");
}

TEST_CASE("make_error_line is byte-identical to make_error(...) serialized") {
    for (const StratumError& err : {ERR_OTHER, ERR_STALE, ERR_DUPLICATE, ERR_LOW_DIFFICULTY,
                                    ERR_UNAUTHORIZED, ERR_NOT_SUBSCRIBED}) {
        CHECK(make_error_line(9, err) == dump(make_error(9, err)));
        CHECK(make_error_line(nullptr, err) == dump(make_error(nullptr, err)));
        CHECK(make_error_line(std::string("id-1"), err) == dump(make_error(std::string("id-1"), err)));
    }
    CHECK(make_error_line(9, ERR_DUPLICATE) ==
          R"({"error":[22,"Duplicate share",null],"id":9,"result":null})");
}

TEST_CASE("make_notify_line is byte-identical to make_notification(...) serialized") {
    // mining.notify is parity-locked on the wire: the fast per-client path must match the json
    // builder byte for byte, across empty/multi-branch jobs and both clean flags.
    const std::string job_id = "abbaabba00000001";
    const std::string prevhash =
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const std::string cb1 = "01000000010000000000000000000000";
    const std::string cb2 = "ffffffff0100f2052a010000001600145555";
    const std::string version = "20000000";
    const std::string nbits = "1d00ffff";
    const std::string ntime = "6553f100";

    const auto reference = [&](const std::vector<std::string>& branches, bool clean) {
        return dump(make_notification(
            "mining.notify", jarray({json(job_id), json(prevhash), json(cb1), json(cb2),
                                     jstrings(branches), json(version), json(nbits), json(ntime),
                                     json(clean)})));
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

namespace {

// The typed fast path and the DOM path must agree on every field AND on the response bytes the
// echoed id produces. Called for lines that take the fast path and lines that fall back alike.
void check_parse_paths_agree(const std::string& line) {
    CAPTURE(line);
    const auto fast = parse_request(line);
    const auto dom = detail::parse_request_dom(line);
    REQUIRE(fast.has_value() == dom.has_value());
    if (!fast)
        return;
    CHECK(fast->method == dom->method);
    CHECK(fast->params == dom->params);
    // The id is compared through its wire echo: that is the byte contract that matters.
    CHECK(make_result_line(fast->id, true) == make_result_line(dom->id, true));
    CHECK(make_error_line(fast->id, ERR_OTHER) == make_error_line(dom->id, ERR_OTHER));
    CHECK(fast->configure_extensions == dom->configure_extensions);
    CHECK(fast->configure_version_rolling == dom->configure_version_rolling);
    CHECK(fast->version_rolling_mask_present == dom->version_rolling_mask_present);
    CHECK(fast->version_rolling_mask == dom->version_rolling_mask);
    CHECK(fast->suggested_difficulty == dom->suggested_difficulty);
}

} // namespace

TEST_CASE("typed parse fast path matches the DOM path across id/params spellings") {
    // id spellings on a hot-path submit line: integers echo, string echoes, everything else nulls.
    for (const char* id : {"1", "-1", "0", "9007199254740992", "1.0", "1e2", "1.5", "-0.5",
                           "\"abc\"", "\"\"", "null", "true", "false", "[1]", "{\"a\":1}"}) {
        check_parse_paths_agree(std::string(R"({"id":)") + id +
                                R"(,"method":"mining.submit","params":["w","j","0001","6553f100","2a2a2a2a"]})");
    }
    // Structural spellings: params shapes, unknown keys, duplicates, malformed tails.
    for (const char* line : {
             R"({"method":"mining.submit"})",                                  // no id, no params
             R"({"method":"mining.submit","params":[]})",                      // empty params
             R"({"method":"mining.submit","params":null})",                    // null params
             R"({"method":"mining.submit","params":{"a":1}})",                 // params object
             R"({"method":"mining.submit","params":["w",null,3,"x"]})",        // non-string elements
             R"({"id":1,"jsonrpc":"2.0","method":"mining.submit","params":["w"],"vendor":5})",
             R"({"id":1,"id":2,"method":"mining.submit","params":["w"]})",     // duplicate id
             R"({"method":"a","method":"mining.submit","params":["w"]})",      // duplicate method
             R"({"method":""})",                                               // empty method: valid
             R"({"method":null})",                                             // null method: reject
             R"({"id":1,"params":["w"]})",                                     // missing method
             R"({"method":123})",                                              // non-string method
             R"([1,2,3])",                                                     // not an object
             R"("just a string")",                                             // not an object
             R"({"method":"mining.submit","params":["w"]} trailing)",          // trailing garbage
             R"({"method":"mining.subscribe","params":["agent/1.0"]})",
             R"({"method":"mining.authorize","params":["addr.worker","x"]})",
             R"({"id":9,"method":"mining.suggest_difficulty","params":[12.5]})",
             R"({"id":9,"method":"mining.suggest_difficulty","params":["12.5"]})",
             R"({"id":3,"method":"mining.configure","params":[["version-rolling"],)"
             R"({"version-rolling.mask":"1fffe000"}]})",
             R"({"method":"mining.extranonce.subscribe","params":[]})",
             R"({"method":"mining.submit","nparams":["w",null,3,{"a":[11,2]},t4rue]})",
             R"({"j3onrpc":".0","id":9007199254740992,"method":"mining.submit","par\ms":[]})",
         }) {
        check_parse_paths_agree(line);
    }
}
