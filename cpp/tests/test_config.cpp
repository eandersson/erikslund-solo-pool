#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/config.hpp"
#include "core/errors.hpp"

using namespace erikslund;

TEST_CASE("defaults are the regtest harness values") {
    const Config config = Config::from_json(nlohmann::json::object());
    CHECK(config.rpc_url == "http://127.0.0.1:18443");
    CHECK(config.bind_port == 3333);
    CHECK(config.extranonce2_size == 8);
    CHECK(config.coinbase_version == 1);
}

TEST_CASE("known keys override, others keep defaults") {
    const auto j = nlohmann::json::parse(R"({
        "bitcoin_nodes": [{"address": "http://node:8332", "username": "u", "password": "p"}],
        "stratum_listen": ["0.0.0.0:4444"],
        "initial_difficulty": 1024,
        "coinbase_signature": "/test/"
    })");
    const Config config = Config::from_json(j);
    CHECK(config.rpc_url == "http://node:8332");
    CHECK(config.rpc_user == "u");
    CHECK(config.bind_port == 4444);
    CHECK(config.initial_difficulty == doctest::Approx(1024.0));
    CHECK(config.coinbase_signature == "/test/");
    CHECK(config.api_port == 7777); // untouched default
}

TEST_CASE("the pool config schema parses into the typed config") {
    const auto j = nlohmann::json::parse(R"({
        "$schema": "../conf/pool.schema.json",
        "bitcoin_nodes": [
            {"address": "bitcoind:8332", "username": "u", "password": "p", "notify": true},
            {"address": "backup:8332", "username": "u2", "password": "p2"}
        ],
        "stratum_listen": ["0.0.0.0:3333", "0.0.0.0:4001"],
        "coinbase_signature": "/erikslund/",
        "initial_difficulty": 10000,
        "minimum_difficulty": 1,
        "maximum_difficulty": 1000000,
        "extranonce1_size": 4,
        "extranonce2_size": 8,
        "api_listen": ["127.0.0.1:7777"],
        "zmq_block_endpoint": "tcp://bitcoind:28332",
        "block_poll_milliseconds": 250,
        "work_rebroadcast_seconds": 20,
        "max_clients": 50,
        "drop_idle_seconds": 900,
        "auth_timeout_seconds": 45,
        "max_protocol_errors": 7,
        "worker_threads": 6,
        "version_rolling_mask": "1fffe000"
    })");
    const Config c = Config::from_json(j);
    CHECK(c.rpc_url == "bitcoind:8332"); // scheme added later by RpcClient
    CHECK(c.rpc_user == "u");
    CHECK(c.rpc_password == "p");
    REQUIRE(c.rpc_failover.size() == 1);
    CHECK(c.rpc_failover[0].url == "backup:8332");
    CHECK(c.rpc_endpoints().size() == 2);
    CHECK(c.stratum_ports() == std::vector<uint16_t>{3333, 4001});
    CHECK(c.bind_host == "0.0.0.0");
    CHECK(c.coinbase_signature == "/erikslund/");
    CHECK(c.initial_difficulty == doctest::Approx(10000.0));
    CHECK(c.minimum_difficulty == doctest::Approx(1.0));
    CHECK(c.maximum_difficulty == doctest::Approx(1000000.0));
    CHECK(c.extranonce1_size == 4);
    CHECK(c.extranonce2_size == 8);
    CHECK(c.api_host == "127.0.0.1");
    CHECK(c.api_port == 7777);
    CHECK(c.zmq_block_endpoint == "tcp://bitcoind:28332");
    CHECK(c.poll_interval == doctest::Approx(0.25)); // block_poll_milliseconds -> seconds
    CHECK(c.work_rebroadcast_seconds == doctest::Approx(20.0));
    CHECK(c.max_clients == 50);
    CHECK(c.drop_idle_seconds == 900);
    CHECK(c.auth_timeout_seconds == 45);
    CHECK(c.max_protocol_errors == 7);
    CHECK(c.worker_threads == 6);
    CHECK(c.version_rolling_mask == 0x1fffe000u);
}

TEST_CASE("a single stratum_listen string is accepted") {
    const auto j = nlohmann::json::parse(R"({"stratum_listen": "0.0.0.0:3333"})");
    const Config config = Config::from_json(j);
    CHECK(config.bind_host == "0.0.0.0");
    CHECK(config.stratum_ports() == std::vector<uint16_t>{3333});
}

TEST_CASE("proxy_protocol_from: absent -> empty (feature off)") {
    CHECK(Config::from_json(nlohmann::json::object()).proxy_protocol_from.empty());
}

TEST_CASE("proxy_protocol_from accepts a single string") {
    const auto j = nlohmann::json::parse(R"({"proxy_protocol_from": "10.0.0.5"})");
    const Config c = Config::from_json(j);
    REQUIRE(c.proxy_protocol_from.size() == 1);
    CHECK(c.proxy_protocol_from[0] == "10.0.0.5");
}

TEST_CASE("proxy_protocol_from accepts a list, in order") {
    const auto j = nlohmann::json::parse(R"({"proxy_protocol_from": ["10.0.0.5", "172.19.0.0/16"]})");
    const Config c = Config::from_json(j);
    REQUIRE(c.proxy_protocol_from.size() == 2);
    CHECK(c.proxy_protocol_from[0] == "10.0.0.5");
    CHECK(c.proxy_protocol_from[1] == "172.19.0.0/16");
}

TEST_CASE("the old flat schema is rejected (no backwards-compat bridge)") {
    const auto j = nlohmann::json::parse(R"({"rpc_url": "http://node:8332", "bind_port": 4444})");
    CHECK_THROWS_AS(Config::from_json(j), ConfigError);
}

TEST_CASE("unknown keys are rejected") {
    nlohmann::json j;
    j["definitely_not_a_key"] = 1;
    CHECK_THROWS_AS(Config::from_json(j), ConfigError);
}

TEST_CASE("a non-object is rejected") {
    CHECK_THROWS_AS(Config::from_json(nlohmann::json::array()), ConfigError);
}

TEST_CASE("donation_percent must be within [0, 100]") {
    CHECK_THROWS_AS(Config::from_json(nlohmann::json{{"donation_percent", -1.0}}), ConfigError);
    CHECK_THROWS_AS(Config::from_json(nlohmann::json{{"donation_percent", 100.5}}), ConfigError);
    // Boundaries are accepted.
    CHECK(Config::from_json(nlohmann::json{{"donation_percent", 0.0}}).donation_percent == 0.0);
    CHECK(Config::from_json(nlohmann::json{{"donation_percent", 100.0}}).donation_percent ==
          doctest::Approx(100.0));
    CHECK(Config::from_json(nlohmann::json{{"donation_percent", 1.5}}).donation_percent ==
          doctest::Approx(1.5));
}

TEST_CASE("an over-long coinbase_signature is rejected at load") {
    // Budget 10 + 4 + 8 + tag <= 100, so the default extranonces leave the tag 78 bytes.
    CHECK_THROWS_AS(Config::from_json(nlohmann::json{{"coinbase_signature", std::string(79, 'x')}}),
                    ConfigError);
    CHECK(Config::from_json(nlohmann::json{{"coinbase_signature", std::string(78, 'x')}})
              .coinbase_signature.size() == 78);
}

namespace {
// Caller removes the returned path.
std::filesystem::path write_temp(const std::string& name, const std::string& text) {
    const std::filesystem::path path = std::filesystem::temp_directory_path() / name;
    std::ofstream(path, std::ios::binary) << text;
    return path;
}
} // namespace

TEST_CASE("from_file parses a YAML config") {
    // Numbers and booleans stay typed; strings that look numeric are quoted.
    const auto path = write_temp("ep_config_test.yaml", R"(
bitcoin_nodes:
  - address: http://node:8332
    username: u
    password: p
stratum_listen:
  - 0.0.0.0:4444
initial_difficulty: 1024
minimum_difficulty: 0.0001
block_poll_milliseconds: 250
variable_difficulty: false
coinbase_signature: "/test/"
version_rolling_mask: 1fffe000
)");
    const Config config = Config::from_file(path.string());
    CHECK(config.rpc_url == "http://node:8332");
    CHECK(config.rpc_user == "u");
    CHECK(config.bind_port == 4444);
    CHECK(config.initial_difficulty == doctest::Approx(1024.0));
    // A fractional scalar must stay a double, not be truncated to an int (0).
    CHECK(config.minimum_difficulty == doctest::Approx(0.0001));
    CHECK(config.poll_interval == doctest::Approx(0.25)); // 250 ms -> seconds
    CHECK(config.variable_difficulty == false);
    CHECK(config.coinbase_signature == "/test/");
    // A bare hex string (not numeric) stays a string and is parsed base-16.
    CHECK(config.version_rolling_mask == 0x1fffe000u);
    std::filesystem::remove(path);
}

TEST_CASE("max_workers_per_address loads, defaults to 256, and rejects negatives") {
    CHECK(Config::from_json(nlohmann::json{{"max_workers_per_address", 32}})
              .max_workers_per_address == 32);
    CHECK(Config::from_json(nlohmann::json::object()).max_workers_per_address == 256); // default
    CHECK(Config::from_json(nlohmann::json{{"max_workers_per_address", 0}})
              .max_workers_per_address == 0); // 0 = unlimited
    CHECK_THROWS_AS(Config::from_json(nlohmann::json{{"max_workers_per_address", -1}}),
                    ConfigError);
}

TEST_CASE("user_stats_retention_days loads, defaults to 90, and rejects negatives") {
    CHECK(Config::from_json(nlohmann::json{{"user_stats_retention_days", 30}})
              .user_stats_retention_days == 30);
    CHECK(Config::from_json(nlohmann::json::object()).user_stats_retention_days == 90); // default
    CHECK(Config::from_json(nlohmann::json{{"user_stats_retention_days", 0}})
              .user_stats_retention_days == 0); // 0 = keep forever
    CHECK_THROWS_AS(Config::from_json(nlohmann::json{{"user_stats_retention_days", -1}}),
                    ConfigError);
    // Upper bound (~100 years): beyond it the file_time_type cutoff arithmetic would overflow.
    CHECK_THROWS_AS(Config::from_json(nlohmann::json{{"user_stats_retention_days", 36501}}),
                    ConfigError);
}

TEST_CASE("YAML quoting is honored: quoted scalars stay strings (matches the Python pool)") {
    // A quoted numeric-looking value is an explicit string. For a string-typed key it must
    // survive untouched (a password like "12345" or "true" must never coerce to a number/bool).
    const auto ok_path = write_temp("ep_config_quote_ok.yaml", R"(
coinbase_signature: "12345"
version_rolling_mask: "1fffe000"
)");
    const Config config = Config::from_file(ok_path.string());
    CHECK(config.coinbase_signature == "12345");
    CHECK(config.version_rolling_mask == 0x1fffe000u); // quoted mask string still parses base-16
    std::filesystem::remove(ok_path);

    // For a numeric-typed key a quoted value is a type error, not a silent coercion.
    const auto bad_path = write_temp("ep_config_quote_bad.yaml", R"(
initial_difficulty: "1024"
)");
    CHECK_THROWS_AS(Config::from_file(bad_path.string()), ConfigError);
    std::filesystem::remove(bad_path);
}

TEST_CASE("from_file still reads a JSON config (YAML is a JSON superset)") {
    const auto path = write_temp("ep_config_test.json", R"({
        "bitcoin_nodes": [{"address": "http://node:8332"}],
        "stratum_listen": "0.0.0.0:3333",
        "max_clients": 50
    })");
    const Config config = Config::from_file(path.string());
    CHECK(config.rpc_url == "http://node:8332");
    CHECK(config.bind_port == 3333);
    CHECK(config.max_clients == 50);
    std::filesystem::remove(path);
}

TEST_CASE("from_file throws ConfigError on malformed YAML") {
    const auto path = write_temp("ep_config_bad.yaml", "bitcoin_nodes: [unterminated\n");
    CHECK_THROWS_AS(Config::from_file(path.string()), ConfigError);
    std::filesystem::remove(path);
}

TEST_CASE("from_file throws ConfigError when the file cannot be opened") {
    CHECK_THROWS_AS(Config::from_file("/nonexistent/dir/definitely_absent.yaml"), ConfigError);
}

TEST_CASE("version_rolling_mask accepts both a hex string and a JSON integer") {
    // Bare hex string -> parsed base-16.
    CHECK(Config::from_json(nlohmann::json{{"version_rolling_mask", "1fffe000"}})
              .version_rolling_mask == 0x1fffe000u);
    // JSON integer -> taken as-is (within the BIP320 range, no clamp).
    CHECK(Config::from_json(nlohmann::json{{"version_rolling_mask", 0x00002000}})
              .version_rolling_mask == 0x00002000u);
}

TEST_CASE("version_rolling_mask is clamped to the BIP320 range") {
    // Bits outside 0x1fffe000 would let a miner roll nVersion's high bits -> bad-version blocks.
    CHECK(Config::from_json(nlohmann::json{{"version_rolling_mask", "ffffffff"}})
              .version_rolling_mask == 0x1fffe000u);
    CHECK(Config::from_json(nlohmann::json{{"version_rolling_mask", 0x00003000}})
              .version_rolling_mask == 0x00002000u); // bit 12 dropped, bit 13 kept
}

TEST_CASE("every remaining scalar key maps onto its config field") {
    const auto j = nlohmann::json::parse(R"({
        "coinbase_version": 2,
        "variable_difficulty": false,
        "vardiff_target_shares_per_minute": 30,
        "vardiff_retarget_seconds": 120,
        "fast_block_notify": false,
        "status_interval_seconds": 15,
        "stats_directory": "/var/lib/pool",
        "max_line_bytes": 8192,
        "donation_percent": 2.5,
        "donation_address": "bc1qexample"
    })");
    const Config c = Config::from_json(j);
    CHECK(c.coinbase_version == 2u);
    CHECK(c.variable_difficulty == false);
    CHECK(c.vardiff_target_shares_per_minute == doctest::Approx(30.0));
    CHECK(c.vardiff_retarget_seconds == 120);
    CHECK(c.fast_block_notify == false);
    CHECK(c.status_interval_seconds == doctest::Approx(15.0));
    CHECK(c.stats_directory == "/var/lib/pool");
    CHECK(c.max_line_bytes == 8192u);
    CHECK(c.donation_percent == doctest::Approx(2.5));
    CHECK(c.donation_address == "bc1qexample");
}

TEST_CASE("api_listen accepts a single string and an array (first entry wins)") {
    CHECK(Config::from_json(nlohmann::json{{"api_listen", "127.0.0.1:9000"}}).api_port == 9000);
    const auto arr = nlohmann::json::parse(R"({"api_listen": ["0.0.0.0:9001", "ignored:1"]})");
    const Config c = Config::from_json(arr);
    CHECK(c.api_host == "0.0.0.0");
    CHECK(c.api_port == 9001);
}

TEST_CASE("an empty bitcoin_nodes array leaves the RPC defaults in place") {
    const Config c = Config::from_json(nlohmann::json{{"bitcoin_nodes", nlohmann::json::array()}});
    CHECK(c.rpc_url == "http://127.0.0.1:18443"); // default preserved
    CHECK(c.rpc_failover.empty());
}

TEST_CASE("a failover node inherits the primary's credentials when omitted") {
    const auto j = nlohmann::json::parse(R"({
        "bitcoin_nodes": [
            {"address": "http://primary:8332", "username": "alice", "password": "secret"},
            {"address": "http://backup:8332"}
        ]
    })");
    const Config c = Config::from_json(j);
    REQUIRE(c.rpc_failover.size() == 1);
    CHECK(c.rpc_failover[0].user == "alice");
    CHECK(c.rpc_failover[0].password == "secret");
}

TEST_CASE("block_poll_milliseconds converts to a fractional second poll interval") {
    CHECK(Config::from_json(nlohmann::json{{"block_poll_milliseconds", 500}}).poll_interval ==
          doctest::Approx(0.5));
    CHECK(Config::from_json(nlohmann::json{{"block_poll_milliseconds", 1000}}).poll_interval ==
          doctest::Approx(1.0));
}

TEST_CASE("worker_threads 0 (auto) is a valid value that survives parsing") {
    CHECK(Config::from_json(nlohmann::json{{"worker_threads", 0}}).worker_threads == 0);
    CHECK(Config::from_json(nlohmann::json{{"worker_threads", 12}}).worker_threads == 12);
}

TEST_CASE("the scriptSig budget tracks the extranonce sizes, not just the signature length") {
    // height_push(10) + en1 + en2 + sig must stay <= 100. With en1=8, en2=8, a 75-byte
    // tag = 10+8+8+75 = 101 -> rejected; 74 -> 100 exactly -> accepted.
    const auto reject = nlohmann::json{
        {"extranonce1_size", 8}, {"extranonce2_size", 8}, {"coinbase_signature", std::string(75, 'x')}};
    CHECK_THROWS_AS(Config::from_json(reject), ConfigError);
    const auto accept = nlohmann::json{
        {"extranonce1_size", 8}, {"extranonce2_size", 8}, {"coinbase_signature", std::string(74, 'x')}};
    CHECK_NOTHROW(Config::from_json(accept));
}

TEST_CASE("rpc_endpoints lists the primary first, then failover in order") {
    const auto j = nlohmann::json::parse(R"({
        "bitcoin_nodes": [
            {"address": "p", "username": "pu", "password": "pp"},
            {"address": "a", "username": "au", "password": "ap"},
            {"address": "b", "username": "bu", "password": "bp"}
        ]
    })");
    const auto endpoints = Config::from_json(j).rpc_endpoints();
    REQUIRE(endpoints.size() == 3);
    CHECK(endpoints[0].url == "p");
    CHECK(endpoints[0].password == "pp");
    CHECK(endpoints[1].url == "a");
    CHECK(endpoints[2].url == "b");
}
