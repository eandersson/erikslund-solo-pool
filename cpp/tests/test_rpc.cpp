#include <doctest/doctest.h>

#include <stdexcept>
#include <vector>

#include <nlohmann/json.hpp>

#include "bitcoin/rpc_client.hpp"
#include "bitcoin/rpc_endpoint.hpp"
#include "core/config.hpp"

using namespace erikslund;

TEST_CASE("bitcoin_nodes parse and keep failover order") {
    // bitcoin_nodes[0] is the primary; the rest are failover. An entry that omits
    // username/password inherits the primary's credentials.
    const auto j = nlohmann::json::parse(R"({
        "bitcoin_nodes": [
            {"address": "http://primary:8332", "username": "erikslund", "password": "x"},
            {"address": "http://backup1:8332", "username": "u1", "password": "p1"},
            {"address": "backup2:8332"}
        ]
    })");
    const Config config = Config::from_json(j);
    REQUIRE(config.rpc_failover.size() == 2);

    const auto endpoints = config.rpc_endpoints();
    REQUIRE(endpoints.size() == 3);
    CHECK(endpoints[0].url == "http://primary:8332"); // primary first
    CHECK(endpoints[1].url == "http://backup1:8332");
    CHECK(endpoints[1].user == "u1");
    CHECK(endpoints[2].url == "backup2:8332");
    CHECK(endpoints[2].user == "erikslund"); // omitted -> inherits primary
}

TEST_CASE("no rpc_failover -> a single endpoint") {
    const Config config = Config::from_json(nlohmann::json::object());
    CHECK(config.rpc_endpoints().size() == 1);
}

TEST_CASE("multi-port config parses") {
    const auto j = nlohmann::json::parse(R"({
        "stratum_listen": ["0.0.0.0:3333", "0.0.0.0:4444"]
    })");
    const Config config = Config::from_json(j);
    REQUIRE(config.stratum_ports().size() == 2);
    CHECK(config.stratum_ports()[0] == 3333);
    CHECK(config.stratum_ports()[1] == 4444);
}

TEST_CASE("default stratum port is the single bind_port") {
    const Config config = Config::from_json(nlohmann::json::object());
    CHECK(config.stratum_ports() == std::vector<uint16_t>{3333});
}

TEST_CASE("RpcClient single-endpoint constructor yields one endpoint") {
    bitcoin::RpcClient rpc("http://127.0.0.1:18443", "user", "pass");
    CHECK(rpc.endpoint_count() == 1);
}

TEST_CASE("RpcClient multi-endpoint constructor counts every endpoint") {
    const std::vector<bitcoin::RpcEndpoint> endpoints = {
        {"http://primary:8332", "u", "p"},
        {"backup:8332", "u2", "p2"}, // scheme-less; normalized internally
        {"https://tertiary:8332", "u3", "p3"}};
    bitcoin::RpcClient rpc(endpoints);
    CHECK(rpc.endpoint_count() == 3);
}

TEST_CASE("RpcClient rejects an empty endpoint list") {
    CHECK_THROWS_AS(bitcoin::RpcClient(std::vector<bitcoin::RpcEndpoint>{}), std::invalid_argument);
}

TEST_CASE("RpcClient is constructible straight from Config::rpc_endpoints()") {
    const auto j = nlohmann::json::parse(R"({
        "bitcoin_nodes": [
            {"address": "http://primary:8332", "username": "u", "password": "p"},
            {"address": "backup:8332"}
        ]
    })");
    const Config config = Config::from_json(j);
    bitcoin::RpcClient rpc(config.rpc_endpoints());
    CHECK(rpc.endpoint_count() == 2);
}
