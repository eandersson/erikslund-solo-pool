// Adversarial / negative coverage for Config::from_json / from_file: malformed input must be
// rejected by throwing (ConfigError where noted, otherwise some std::exception), never crash.
#include <doctest/doctest.h>

#include <exception>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "core/config.hpp"
#include "core/errors.hpp"

using namespace erikslund;
using json = nlohmann::json;

TEST_CASE("non-object top-level config is a ConfigError") {
    CHECK_THROWS_AS(Config::from_json(json::array()), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json("a string")), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json(42)), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json(true)), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json(nullptr)), ConfigError);
}

TEST_CASE("any unknown key is a ConfigError") {
    for (const char* key : {"definitely_not_a_key", "rpc_url", "bind_port", "logdir",
                            "btcd", "Coinbase_Signature", "stratum_port"}) {
        json j;
        j[key] = "x";
        CAPTURE(key);
        CHECK_THROWS_AS(Config::from_json(j), ConfigError);
    }
}

TEST_CASE("the legacy flat schema (rpc_url / bind_port) is rejected outright") {
    const auto j = json::parse(R"({"rpc_url":"http://node:8332","bind_port":4444})");
    CHECK_THROWS_AS(Config::from_json(j), ConfigError);
}

TEST_CASE("donation_percent outside [0,100] is a ConfigError; the boundaries pass") {
    CHECK_THROWS_AS(Config::from_json(json{{"donation_percent", -0.01}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"donation_percent", -100.0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"donation_percent", 100.01}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"donation_percent", 1000.0}}), ConfigError);
    CHECK_NOTHROW(Config::from_json(json{{"donation_percent", 0.0}}));
    CHECK_NOTHROW(Config::from_json(json{{"donation_percent", 100.0}}));
}

TEST_CASE("an over-long coinbase_signature (no room in the 100-byte scriptSig) is a ConfigError") {
    // default extranonce1=4, extranonce2=8, height push budget 10 -> tag must be <= 78.
    CHECK_THROWS_AS(Config::from_json(json{{"coinbase_signature", std::string(79, 'x')}}),
                    ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"coinbase_signature", std::string(500, 'x')}}),
                    ConfigError);
    CHECK_NOTHROW(Config::from_json(json{{"coinbase_signature", std::string(78, 'x')}}));
}

TEST_CASE("the scriptSig budget also reflects larger extranonce sizes") {
    // en1=8 + en2=8 + height 10 -> tag must be <= 74.
    const auto reject = json{{"extranonce1_size", 8}, {"extranonce2_size", 8},
                             {"coinbase_signature", std::string(75, 'x')}};
    CHECK_THROWS_AS(Config::from_json(reject), ConfigError);
}

TEST_CASE("a bitcoin_nodes entry missing the required address throws") {
    // nodes[0].at("address") throws nlohmann json::out_of_range when absent.
    const auto j = json::parse(R"({"bitcoin_nodes":[{"username":"u","password":"p"}]})");
    // Graceful rejection (throws); the type is a json exception, not ConfigError.
    CHECK_THROWS(Config::from_json(j));
}

TEST_CASE("version_rolling_mask as non-hex is a ConfigError") {
    CHECK_THROWS_AS(Config::from_json(json{{"version_rolling_mask", "nothex"}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"version_rolling_mask", "zzzzzzzz"}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"version_rolling_mask", "!!!!"}}), ConfigError);
}

TEST_CASE("version_rolling_mask: a hex string with trailing junk parses its prefix (no throw)") {
    // std::stoul stops at the first non-hex char, so "1fffe000xyz" -> 0x1fffe000.
    CHECK_NOTHROW(Config::from_json(json{{"version_rolling_mask", "1fffe000xyz"}}));
    CHECK(Config::from_json(json{{"version_rolling_mask", "1fffe000xyz"}}).version_rolling_mask ==
          0x1fffe000u);
}

TEST_CASE("version_rolling_mask: an over-uint32 hex value is truncated, not rejected") {
    // stoul yields a wider integer; the static_cast<uint32_t> truncates -- no throw.
    CHECK_NOTHROW(Config::from_json(json{{"version_rolling_mask", "1ffffffff"}}));
}

TEST_CASE("a stratum_listen port that is not a number is a ConfigError") {
    CHECK_THROWS_AS(Config::from_json(json::parse(R"({"stratum_listen":"0.0.0.0:notaport"})")),
                    ConfigError);
    CHECK_THROWS_AS(Config::from_json(json::parse(R"({"stratum_listen":["0.0.0.0:xyz"]})")),
                    ConfigError);
}

TEST_CASE("a stratum_listen with NO ':' is a ConfigError (no silent ephemeral-port bind)") {
    // A listen address must carry an explicit port; a missing one would bind an arbitrary
    // ephemeral port no miner could reach.
    CHECK_THROWS_AS(Config::from_json(json::parse(R"({"stratum_listen":"justhostname"})")),
                    ConfigError);
}

TEST_CASE("a stratum_listen port of 0 or out of range is a ConfigError") {
    CHECK_THROWS_AS(Config::from_json(json::parse(R"({"stratum_listen":"0.0.0.0:0"})")), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json::parse(R"({"stratum_listen":"0.0.0.0:70000"})")),
                    ConfigError);
    CHECK_THROWS_AS(Config::from_json(json::parse(R"({"stratum_listen":"0.0.0.0:3333x"})")),
                    ConfigError); // trailing garbage rejected
}

TEST_CASE("multi-entry stratum_listen with differing hosts is a ConfigError") {
    // Only one bind host is honored, so differing per-entry hosts must be rejected, not dropped.
    CHECK_THROWS_AS(
        Config::from_json(json::parse(R"({"stratum_listen":["0.0.0.0:3333","127.0.0.1:4001"]})")),
        ConfigError);
    // Same host across entries is fine.
    const Config c =
        Config::from_json(json::parse(R"({"stratum_listen":["0.0.0.0:3333","0.0.0.0:4001"]})"));
    CHECK(c.bind_host == "0.0.0.0");
    CHECK(c.bind_ports == std::vector<uint16_t>{3333, 4001});
}

TEST_CASE("an empty stratum_listen array leaves the defaults untouched (no crash)") {
    const Config c = Config::from_json(json{{"stratum_listen", json::array()}});
    CHECK(c.bind_port == 3333); // default preserved
}

TEST_CASE("a wrong-typed scalar is a ConfigError") {
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce2_size", "eight"}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"max_clients", "many"}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"initial_difficulty", "hard"}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"variable_difficulty", "yes"}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"block_poll_milliseconds", "soon"}}), ConfigError);
}

TEST_CASE("a coinbase_signature that is not a string is a ConfigError") {
    CHECK_THROWS_AS(Config::from_json(json{{"coinbase_signature", 12345}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"coinbase_signature", json::array({"a"})}}), ConfigError);
}

TEST_CASE("from_file throws ConfigError on a missing file") {
    CHECK_THROWS_AS(Config::from_file("/nonexistent/definitely/absent_config.yaml"), ConfigError);
}

TEST_CASE("from_file throws ConfigError on malformed YAML") {
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() / "ep_adv_bad_config.yaml";
    std::ofstream(path, std::ios::binary) << "stratum_listen: [unterminated\n";
    CHECK_THROWS_AS(Config::from_file(path.string()), ConfigError);
    std::filesystem::remove(path);
}

TEST_CASE("from_file rejects a config file whose root is not a mapping") {
    // A YAML sequence at the document root -> yaml_to_json yields an array ->
    // from_json's "must be an object" check fires as a ConfigError.
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() / "ep_adv_seq_config.yaml";
    std::ofstream(path, std::ios::binary) << "- a\n- b\n";
    CHECK_THROWS_AS(Config::from_file(path.string()), ConfigError);
    std::filesystem::remove(path);
}

TEST_CASE("out-of-range numeric values are a ConfigError (schema bounds enforced)") {
    // Out-of-range values would otherwise busy-loop, divide by zero, or reject every share:
    // fail fast at load instead.
    CHECK_THROWS_AS(Config::from_json(json{{"initial_difficulty", 0.0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"initial_difficulty", -1.0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"minimum_difficulty", 0.0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"minimum_difficulty", -0.5}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"maximum_difficulty", -0.1}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"vardiff_target_shares_per_minute", 0.0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"vardiff_retarget_seconds", 0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"work_rebroadcast_seconds", 0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"block_poll_milliseconds", 0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce1_size", 1}}), ConfigError);
    // Min 4: a 2-3 byte extranonce1 space can wrap on a long-lived pool, handing two
    // concurrent miners identical search space.
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce1_size", 2}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce1_size", 3}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce1_size", 9}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce2_size", 0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"extranonce2_size", 9}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"max_clients", -1}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"drop_idle_seconds", -1}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"auth_timeout_seconds", -1}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"max_protocol_errors", -1}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(json{{"status_interval_seconds", -1.0}}), ConfigError);
}

TEST_CASE("schema-boundary numeric values are accepted") {
    CHECK_NOTHROW(Config::from_json(json{{"extranonce1_size", 4}}));
    CHECK_NOTHROW(Config::from_json(json{{"extranonce1_size", 8}}));
    CHECK_NOTHROW(Config::from_json(json{{"extranonce2_size", 8}}));
    CHECK_NOTHROW(Config::from_json(json{{"vardiff_retarget_seconds", 1}}));
    CHECK_NOTHROW(Config::from_json(json{{"work_rebroadcast_seconds", 1}}));
    CHECK_NOTHROW(Config::from_json(json{{"block_poll_milliseconds", 1}}));
    CHECK_NOTHROW(Config::from_json(json{{"maximum_difficulty", 0.0}}));    // 0 = no cap
    CHECK_NOTHROW(Config::from_json(json{{"drop_idle_seconds", 0}}));       // 0 = never
    CHECK_NOTHROW(Config::from_json(json{{"auth_timeout_seconds", 0}}));    // 0 = never
    CHECK_NOTHROW(Config::from_json(json{{"status_interval_seconds", 0.0}}));
}

TEST_CASE("a valid minimal config still parses after all the negative probing") {
    // Sanity: the happy path is unaffected.
    const auto j = json::parse(R"({"bitcoin_nodes":[{"address":"http://n:8332"}],
                                    "stratum_listen":"0.0.0.0:3333"})");
    const Config c = Config::from_json(j);
    CHECK(c.rpc_url == "http://n:8332");
    CHECK(c.bind_port == 3333);
}
