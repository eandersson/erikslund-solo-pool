#include <doctest/doctest.h>

#include <string>

#include "api/http_server.hpp"
#include "bitcoin/rpc_client.hpp"
#include "core/config.hpp"
#include "pool/pool.hpp"

using namespace erikslund;
using namespace erikslund::api;

namespace {
bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}
} // namespace

TEST_CASE("parse_request_line") {
    const auto get = parse_request_line("GET /metrics HTTP/1.1");
    REQUIRE(get.has_value());
    CHECK(get->first == "GET");
    CHECK(get->second == "/metrics");

    const auto query = parse_request_line("GET /stats/client/bc1q?refresh=1 HTTP/1.1");
    REQUIRE(query.has_value());
    CHECK(query->second == "/stats/client/bc1q"); // query stripped

    CHECK_FALSE(parse_request_line("garbage").has_value());
    CHECK_FALSE(parse_request_line("GET /only-two-tokens").has_value());
}

TEST_CASE("routing covers the endpoints + methods") {
    // A Pool with an unconnected RPC client; route() only reads snapshot(), no I/O.
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);

    CHECK(route("POST", "/metrics", pool).status == 405);
    CHECK(route("GET", "/does-not-exist", pool).status == 404);

    const auto metrics = route("GET", "/metrics", pool);
    CHECK(metrics.status == 200);
    CHECK(contains(metrics.content_type, "version=0.0.4"));
    CHECK(contains(metrics.body, "erikslundpool_up"));

    const auto status = route("GET", "/status", pool);
    CHECK(status.status == 200);
    CHECK(contains(status.content_type, "application/json"));

    // Not ready (no job, connector not marked up).
    CHECK(route("GET", "/health", pool).status == 503);

    CHECK(route("GET", "/stats/client/bad!char", pool).status == 400);
    CHECK(route("GET", "/stats/client/bc1qunknown", pool).status == 404);

    CHECK(route("GET", "/", pool).status == 200);
    CHECK(route("HEAD", "/metrics", pool).status == 200);
}

TEST_CASE("parse_request_line edge cases") {
    // Leading slash path with HTTP version is fine.
    const auto ok = parse_request_line("HEAD / HTTP/1.0");
    REQUIRE(ok.has_value());
    CHECK(ok->first == "HEAD");
    CHECK(ok->second == "/");

    // Query-only path strips to its prefix; an empty prefix ("?...") is rejected.
    CHECK_FALSE(parse_request_line("GET ?onlyquery HTTP/1.1").has_value());

    // A bare path with a fragment-like '?' keeps everything before '?'.
    const auto frag = parse_request_line("GET /stats/pool?x=1&y=2 HTTP/1.1");
    REQUIRE(frag.has_value());
    CHECK(frag->second == "/stats/pool");

    // Missing the second space (no HTTP version) is rejected.
    CHECK_FALSE(parse_request_line("GET /metrics").has_value());
    // Empty string is rejected.
    CHECK_FALSE(parse_request_line("").has_value());
    // Empty method (leading space) is rejected.
    CHECK_FALSE(parse_request_line(" /metrics HTTP/1.1").has_value());
}

TEST_CASE("every read-only JSON endpoint returns 200 application/json") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);

    for (const char* path : {"/metrics.json", "/status", "/stats/pool", "/stats/stratifier",
                             "/stats/connector", "/stats/generator"}) {
        const auto response = route("GET", path, pool);
        CHECK(response.status == 200);
        CHECK(contains(response.content_type, "application/json"));
    }
}

TEST_CASE("the root path serves HTML, /metrics serves prometheus text") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);

    const auto root = route("GET", "/", pool);
    CHECK(contains(root.content_type, "text/html"));
    CHECK(contains(root.body, "<html"));

    const auto metrics = route("GET", "/metrics", pool);
    CHECK(contains(metrics.content_type, "text/plain"));
}

TEST_CASE("an over-long client address is rejected as a bad request") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    // 128 valid characters exceeds the 127-byte cap.
    const std::string long_address = "/stats/client/" + std::string(128, 'a');
    CHECK(route("GET", long_address, pool).status == 400);
    // An empty address ("/stats/client/") is also a 400.
    CHECK(route("GET", "/stats/client/", pool).status == 400);
}

TEST_CASE("HEAD is allowed on JSON endpoints and 405 on a write method") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    CHECK(route("HEAD", "/status", pool).status == 200);
    CHECK(route("HEAD", "/", pool).status == 200);
    CHECK(route("PUT", "/status", pool).status == 405);
    CHECK(route("DELETE", "/", pool).status == 405);
}
