// Adversarial / negative coverage for the read-only HTTP API (parse_request_line
// and route(); both pure, route only reads pool.snapshot()).
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
// A Pool over an unconnected RPC client; route() only reads snapshot() (no I/O).
struct PoolFixture {
    Config config;
    bitcoin::RpcClient rpc{"http://127.0.0.1:1", "user", "pass"};
    Pool pool{config, rpc};
};
} // namespace

TEST_CASE("parse_request_line rejects lines without two spaces") {
    CHECK_FALSE(parse_request_line("").has_value());
    CHECK_FALSE(parse_request_line("GET").has_value());
    CHECK_FALSE(parse_request_line("GET/metrics").has_value());
    CHECK_FALSE(parse_request_line("GET /metrics").has_value());        // missing HTTP version
    CHECK_FALSE(parse_request_line("garbage-with-no-spaces").has_value());
    CHECK_FALSE(parse_request_line("\t\t").has_value());                // tabs aren't spaces
}

TEST_CASE("parse_request_line rejects an empty method or empty path") {
    CHECK_FALSE(parse_request_line(" /metrics HTTP/1.1").has_value()); // empty method
    CHECK_FALSE(parse_request_line("GET  HTTP/1.1").has_value());       // empty path (double space)
    CHECK_FALSE(parse_request_line("GET ?q=1 HTTP/1.1").has_value());   // path is just a query
}

TEST_CASE("parse_request_line strips the query string and keeps the path prefix") {
    const auto r = parse_request_line("GET /stats/client/bc1q?refresh=1&x=2 HTTP/1.1");
    REQUIRE(r.has_value());
    CHECK(r->second == "/stats/client/bc1q");

    // A '?' immediately after the path leaves the bare path.
    const auto bare = parse_request_line("GET /metrics? HTTP/1.1");
    REQUIRE(bare.has_value());
    CHECK(bare->second == "/metrics");
}

TEST_CASE("parse_request_line tolerates extra tokens after the version (takes 2nd space)") {
    // Only the first two spaces matter; the remainder is the (ignored) version+junk.
    const auto r = parse_request_line("GET /metrics HTTP/1.1 extra junk here");
    REQUIRE(r.has_value());
    CHECK(r->first == "GET");
    CHECK(r->second == "/metrics");
}

TEST_CASE("parse_request_line does not throw on very long lines") {
    const std::string line = "GET /" + std::string(100000, 'a') + " HTTP/1.1";
    const auto r = parse_request_line(line);
    REQUIRE(r.has_value());
    CHECK(r->second.size() == 100001); // "/" + 100000 'a'
}

TEST_CASE("route returns 405 for every non-GET/HEAD method") {
    PoolFixture f;
    for (const char* method : {"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT",
                              "get", "Get", "FOObar", ""}) {
        CAPTURE(method);
        CHECK(route(method, "/metrics", f.pool).status == 405);
    }
}

TEST_CASE("405 is returned even for paths that would otherwise 404") {
    PoolFixture f;
    CHECK(route("POST", "/does-not-exist", f.pool).status == 405);
    CHECK(route("DELETE", "/", f.pool).status == 405);
}

TEST_CASE("route returns 404 for unknown paths") {
    PoolFixture f;
    for (const char* path : {"/does-not-exist", "/metrics/extra", "/status/", "/STATUS",
                            "/stats", "/stats/", "/stats/pools", "/../etc/passwd",
                            "/metrics.json/x", "/favicon.ico", "/index.html"}) {
        CAPTURE(path);
        CHECK(route("GET", path, f.pool).status == 404);
    }
}

TEST_CASE("route is case-sensitive on the path (no normalization)") {
    PoolFixture f;
    CHECK(route("GET", "/Metrics", f.pool).status == 404);
    CHECK(route("GET", "/metrics", f.pool).status == 200);
}

TEST_CASE("client stats: an empty address is a 400") {
    PoolFixture f;
    CHECK(route("GET", "/stats/client/", f.pool).status == 400);
}

TEST_CASE("client stats: out-of-charset / traversal-ish addresses are a 400, never crash") {
    PoolFixture f;
    for (const char* addr : {
             "/stats/client/bad!char",
             "/stats/client/../../etc/passwd", // '/' is out of charset -> 400
             "/stats/client/a b",              // space
             "/stats/client/semi;colon",
             "/stats/client/quote\"x",
             "/stats/client/back\\slash",
             "/stats/client/percent%2e%2e",    // '%' is out of charset
             "/stats/client/null\x01byte",
             "/stats/client/{brace}",
             "/stats/client/<tag>",
         }) {
        CAPTURE(std::string(addr));
        CHECK(route("GET", addr, f.pool).status == 400);
    }
}

TEST_CASE("client stats: a dots-only address is charset-clean -> safely a 404, not traversal") {
    // '.'/'_' are legal worker chars; the address is only ever a map key, never a
    // filesystem path, so ".." is just an unknown client (no traversal surface).
    PoolFixture f;
    CHECK(route("GET", "/stats/client/..", f.pool).status == 404);
    CHECK(route("GET", "/stats/client/.", f.pool).status == 404);
    CHECK(route("GET", "/stats/client/..__..", f.pool).status == 404);
}

TEST_CASE("client stats: an over-127-char address is a 400 (length cap)") {
    PoolFixture f;
    CHECK(route("GET", "/stats/client/" + std::string(128, 'a'), f.pool).status == 400);
    CHECK(route("GET", "/stats/client/" + std::string(5000, 'a'), f.pool).status == 400);
    // Exactly 127 valid chars passes the cap, then 404s (no such client).
    CHECK(route("GET", "/stats/client/" + std::string(127, 'a'), f.pool).status == 404);
}

TEST_CASE("client stats: a well-formed but unknown address is a 404") {
    PoolFixture f;
    CHECK(route("GET", "/stats/client/bc1qunknownbutvalidchars", f.pool).status == 404);
    // Dots and underscores are in the allowed charset.
    CHECK(route("GET", "/stats/client/some.worker_name", f.pool).status == 404);
}

TEST_CASE("the known read-only endpoints return their expected statuses (no crash on empty pool)") {
    PoolFixture f;
    CHECK(route("GET", "/metrics", f.pool).status == 200);
    CHECK(route("GET", "/metrics.json", f.pool).status == 200);
    CHECK(route("GET", "/status", f.pool).status == 200);
    CHECK(route("GET", "/", f.pool).status == 200);
    CHECK(route("HEAD", "/metrics", f.pool).status == 200);
    // /health is 503 until the pool is ready (no job + connector not up).
    CHECK(route("GET", "/health", f.pool).status == 503);
}

TEST_CASE("a 405 response carries a body and a content-type (well-formed error)") {
    PoolFixture f;
    const auto r = route("POST", "/metrics", f.pool);
    CHECK(r.status == 405);
    CHECK_FALSE(r.body.empty());
    CHECK(contains(r.content_type, "text/plain"));
}

TEST_CASE("a 400 client-address response is well-formed") {
    PoolFixture f;
    const auto r = route("GET", "/stats/client/bad!char", f.pool);
    CHECK(r.status == 400);
    CHECK_FALSE(r.body.empty());
    CHECK(contains(r.content_type, "text/plain"));
}
