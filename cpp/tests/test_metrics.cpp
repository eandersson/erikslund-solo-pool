#include <doctest/doctest.h>

#include <optional>
#include <string>

#include "api/metrics.hpp"

using namespace erikslund::api;

namespace {

PoolSnapshot sample() {
    PoolSnapshot s;
    s.version = "0.1.0";
    s.chain = "regtest";
    s.rpc_url = "http://node:18443";
    s.pid = 42;
    s.starttime = 1700000000;
    s.uptime = 120;
    s.generator_ready = true;
    s.connector_ready = true;
    s.stratifier_ready = true;
    s.ready = true;
    s.height = 200;
    s.network_diff = 1.0;
    s.current_job = "a";
    s.connected = 2;
    s.users = 1;
    s.blocks_found = 3;
    s.shares_accepted = 10;
    s.shares_rejected = 1;
    s.accepted_diff = 5.0;
    s.best_share = 7.5;
    s.hashrate_estimate = 12345.0;
    s.jobs_created = 4;
    s.recent_jobs_cached = 4;
    s.txns_in_job = 2;
    s.merkle_branch_len = 2;
    s.bitcoind_reachable = true;
    s.tip_height = 199;
    s.last_template_age_sec = 5;
    s.bitcoind_nodes = {"http://node:18443"};
    s.bitcoind_active_index = 0;

    ClientSnapshot c;
    c.address = "bc1qaddr";
    c.worker = "bc1qaddr.w1";
    c.peer = "1.2.3.4:5";
    c.user_agent = "cgminer";
    c.difficulty = 1.0;
    c.best_difficulty = 7.5;
    c.shares_accepted = 10;
    c.shares_rejected = 1;
    c.last_share_ts = 1700000100;
    c.connected_for = 120;
    c.subscribed = true;
    c.authorized = true;
    s.clients.push_back(c);
    return s;
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

std::string redacted_rpc_url(const PoolSnapshot& s) {
    return generator_stats_json(s)["rpc_url"].get<std::string>();
}

} // namespace

TEST_CASE("prometheus emits every expected metric name + TYPE") {
    const std::string m = build_prometheus(sample());
    for (const char* name :
         {"erikslundpool_up", "erikslundpool_ready", "erikslundpool_uptime_seconds",
          "erikslundpool_subsystem_ready", "erikslundpool_info", "erikslundpool_network_difficulty",
          "erikslundpool_block_height", "erikslundpool_blocks_found_total",
          "erikslundpool_shares_accepted_total", "erikslundpool_shares_rejected_total",
          "erikslundpool_best_share", "erikslundpool_users", "erikslundpool_workers",
          "erikslundpool_hashrate_hashes_per_second"}) {
        CHECK(contains(m, std::string("# TYPE ") + name));
    }
    // Types, labels, and integer values.
    CHECK(contains(m, "# TYPE erikslundpool_blocks_found_total counter"));
    CHECK(contains(m, "# TYPE erikslundpool_block_height gauge"));
    CHECK(contains(m, "erikslundpool_subsystem_ready{subsystem=\"bitcoind\"} 1"));
    CHECK(contains(m, "erikslundpool_subsystem_ready{subsystem=\"work\"} 1"));
    CHECK(contains(m, "erikslundpool_subsystem_ready{subsystem=\"connections\"} 1"));
    CHECK(contains(m, "erikslundpool_info{version=\"0.1.0\"} 1"));
    CHECK(contains(m, "erikslundpool_hashrate_hashes_per_second{window=\"estimate\"}"));
    CHECK(contains(m, "erikslundpool_hashrate_hashes_per_second{window=\"1m\"}"));
    CHECK(contains(m, "erikslundpool_hashrate_hashes_per_second{window=\"7d\"}"));
    CHECK(contains(m, "erikslundpool_blocks_found_total 3"));
    CHECK(contains(m, "erikslundpool_shares_accepted_total 10"));
    CHECK(contains(m, "erikslundpool_shares_rejected_total 1"));
    CHECK(contains(m, "erikslundpool_workers 2"));
    CHECK(contains(m, "erikslundpool_block_height 200"));
}

TEST_CASE("optional gauges are omitted with no job, counters remain") {
    PoolSnapshot s = sample();
    s.height = std::nullopt;
    s.network_diff = std::nullopt;
    const std::string m = build_prometheus(s);
    CHECK_FALSE(contains(m, "erikslundpool_block_height"));
    CHECK_FALSE(contains(m, "erikslundpool_network_difficulty"));
    CHECK(contains(m, "erikslundpool_shares_accepted_total 10"));
}

TEST_CASE("JSON bodies match the C/Python contract") {
    const auto s = sample();

    auto st = status_json(s);
    CHECK(st["name"].get<std::string>() == "erikslund-solo-pool");
    CHECK_FALSE(st.contains("mode"));
    CHECK(st["bitcoind_connected"].get<bool>() == true);
    CHECK(st["work_ready"].get<bool>() == true);
    CHECK(st["accepting_connections"].get<bool>() == true);
    CHECK(st["ready"].get<bool>() == true);

    auto ps = pool_stats_json(s);
    CHECK(ps["height"].get<double>() == 200);
    CHECK(ps["blocks_found"].get<double>() == 3);
    CHECK(ps["workers"].get<double>() == 2);
    CHECK(ps["shares_rejected"].get<double>() == 1);
    CHECK(ps["best_share_percent"].get<double>() == doctest::Approx(750.0)); // 7.5 / 1.0 * 100
    CHECK(ps["hashrate_estimate"].get<double>() == doctest::Approx(12345.0));

    auto cs = connector_stats_json(s);
    CHECK(cs["workers"].get<double>() == 2);
    CHECK(cs["subscribed"].get<double>() == 1);
    CHECK(cs["authorized"].get<double>() == 1);

    auto m = metrics_json(s);
    CHECK_FALSE(m.contains("mode"));
    CHECK(m["bitcoind_connected"].get<bool>() == true);
    CHECK(m["pool"]["height"].get<double>() == 200);
    CHECK(m["generator"]["chain"].get<std::string>() == "regtest");
    CHECK(m["stratifier"]["txns_in_job"].get<double>() == 2);
}

TEST_CASE("generator rpc_url is redacted of embedded credentials") {
    PoolSnapshot s = sample();
    s.rpc_url = "http://user:secretpass@node:18443";
    const std::string url = redacted_rpc_url(s);
    CHECK(url == "http://node:18443");
    CHECK_FALSE(contains(url, "secretpass"));
    CHECK_FALSE(contains(url, "@"));

    // A URL without userinfo is passed through unchanged.
    s.rpc_url = "http://node:18443";
    CHECK(redacted_rpc_url(s) == "http://node:18443");
}

TEST_CASE("bitcoind nodes are listed with the active one flagged and credentials redacted") {
    PoolSnapshot s = sample();
    s.bitcoind_nodes = {"http://primary:18443", "http://user:secretpass@backup:18443"};
    s.bitcoind_active_index = 1; // failed over to the backup

    auto gen = generator_stats_json(s);
    auto& nodes = gen["bitcoind_nodes"].get_array();
    REQUIRE(nodes.size() == 2);
    CHECK(nodes[0]["address"].get<std::string>() == "http://primary:18443");
    CHECK(nodes[0]["active"].get<bool>() == false);
    CHECK(nodes[1]["address"].get<std::string>() == "http://backup:18443"); // userinfo stripped
    CHECK(nodes[1]["active"].get<bool>() == true);

    const std::string m = build_prometheus(s);
    CHECK(contains(m, "# TYPE erikslundpool_bitcoind_node_active gauge"));
    CHECK(contains(m, "erikslundpool_bitcoind_node_active{url=\"http://primary:18443\"} 0"));
    CHECK(contains(m, "erikslundpool_bitcoind_node_active{url=\"http://backup:18443\"} 1"));
    CHECK_FALSE(contains(m, "secretpass")); // credentials never reach the label

    const std::string html = dashboard_html(s);
    CHECK(contains(html, "bitcoind nodes"));
    CHECK(contains(html, "http://backup:18443 (active)"));
    CHECK_FALSE(contains(html, "secretpass"));
}

TEST_CASE("client stats strip the worker suffix and 404 on miss") {
    const auto s = sample();
    auto client = client_stats_json(s, "bc1qaddr.w1");
    REQUIRE(client.has_value());
    CHECK((*client)["address"].get<std::string>() == "bc1qaddr");
    CHECK((*client)["workers"].get<double>() == 1);
    CHECK((*client)["shares_rejected"].get<double>() == 1);
    auto& sessions = (*client)["sessions"].get_array();
    CHECK(sessions[0]["user_agent"].get<std::string>() == "cgminer");
    CHECK(sessions[0]["shares_rejected"].get<double>() == 1);
    CHECK_FALSE(client_stats_json(s, "bc1qother").has_value());
}

TEST_CASE("null fields when there is no job") {
    PoolSnapshot s; // empty
    auto ps = pool_stats_json(s);
    CHECK(ps["height"].is_null());
    CHECK(ps["network_diff"].is_null());
    CHECK(ps["current_job"].is_null());
}

TEST_CASE("redact_url strips userinfo in several URL shapes") {
    // user + password.
    {
        PoolSnapshot s = sample();
        s.rpc_url = "http://u:p@host:8332";
        CHECK(redacted_rpc_url(s) == "http://host:8332");
    }
    // username only (no colon password) still gets stripped.
    {
        PoolSnapshot s = sample();
        s.rpc_url = "http://justuser@host:8332";
        CHECK(redacted_rpc_url(s) == "http://host:8332");
    }
    // https scheme is handled the same way.
    {
        PoolSnapshot s = sample();
        s.rpc_url = "https://a:b@example.com";
        CHECK(redacted_rpc_url(s) == "https://example.com");
    }
    // A password containing an '@' must be stripped WHOLE (cut at the last '@', not the first).
    {
        PoolSnapshot s = sample();
        s.rpc_url = "http://u:p@ss@host:8332";
        const std::string redacted = redacted_rpc_url(s);
        CHECK(redacted == "http://host:8332");
        CHECK_FALSE(contains(redacted, "@"));
    }
    // No scheme, with credentials: userinfo still stripped.
    {
        PoolSnapshot s = sample();
        s.rpc_url = "user:pass@host:8332";
        CHECK(redacted_rpc_url(s) == "host:8332");
    }
    // userinfo only in the authority -- an '@' after the path must NOT be treated as userinfo.
    {
        PoolSnapshot s = sample();
        s.rpc_url = "http://host:8332/path@x";
        CHECK(redacted_rpc_url(s) == "http://host:8332/path@x");
    }
}

TEST_CASE("subscribed/authorized counts sum only the matching clients") {
    PoolSnapshot s = sample(); // one client, subscribed + authorized
    ClientSnapshot half;
    half.subscribed = true;
    half.authorized = false; // subscribed but not yet authorized
    s.clients.push_back(half);
    auto cs = connector_stats_json(s);
    CHECK(cs["subscribed"].get<double>() == 2);
    CHECK(cs["authorized"].get<double>() == 1);
}

TEST_CASE("connector stats are zero with no clients") {
    PoolSnapshot s; // no clients
    auto cs = connector_stats_json(s);
    CHECK(cs["workers"].get<double>() == 0);
    CHECK(cs["subscribed"].get<double>() == 0);
    CHECK(cs["authorized"].get<double>() == 0);
}

TEST_CASE("stratifier null fields when there is no job") {
    PoolSnapshot s; // no txns_in_job / merkle_branch_len set
    auto ss = stratifier_stats_json(s);
    CHECK(ss["current_job"].is_null());
    CHECK(ss["height"].is_null());
    CHECK(ss["txns_in_job"].is_null());
    CHECK(ss["merkle_branch_len"].is_null());
    CHECK(ss["jobs_created"].get<double>() == 0);
}

TEST_CASE("client_stats_json aggregates multiple workers of one address") {
    PoolSnapshot s;
    ClientSnapshot w1;
    w1.address = "addr";
    w1.worker = "addr.w1";
    w1.shares_accepted = 3;
    w1.best_difficulty = 5.0;
    w1.last_share_ts = 100;
    ClientSnapshot w2;
    w2.address = "addr";
    w2.worker = "addr.w2";
    w2.shares_accepted = 4;
    w2.best_difficulty = 9.0;
    w2.last_share_ts = 200;
    s.clients = {w1, w2};

    auto client = client_stats_json(s, "addr.w1"); // worker suffix is stripped to "addr"
    REQUIRE(client.has_value());
    CHECK((*client)["address"].get<std::string>() == "addr");
    CHECK((*client)["workers"].get<double>() == 2);
    CHECK((*client)["shares_accepted"].get<double>() == 7);          // 3 + 4
    CHECK((*client)["best_diff"].get<double>() == doctest::Approx(9.0)); // max
    CHECK((*client)["last_share_ts"].get<double>() == 200);          // max
    CHECK((*client)["sessions"].get_array().size() == 2);
}

TEST_CASE("prometheus omits height/network_difficulty individually") {
    PoolSnapshot s = sample();
    s.height = 200;
    s.network_diff = std::nullopt; // only the network difficulty is missing
    const std::string m = build_prometheus(s);
    CHECK(contains(m, "erikslundpool_block_height 200"));
    CHECK_FALSE(contains(m, "erikslundpool_network_difficulty"));
}

TEST_CASE("dashboard_html renders headline figures and an em-dash for missing data") {
    PoolSnapshot s = sample();
    const std::string html = dashboard_html(s);
    CHECK(contains(html, "erikslund-solo-pool"));
    CHECK(contains(html, "<title>"));
    CHECK(contains(html, "READY"));              // readiness banner
    CHECK(contains(html, "regtest"));            // chain
    CHECK(contains(html, "200"));                // height
    CHECK(contains(html, "connected workers"));  // renamed row
    CHECK(contains(html, "/metrics"));           // link to the prometheus endpoint

    PoolSnapshot empty; // no height / network diff / chain
    const std::string blank = dashboard_html(empty);
    CHECK(contains(blank, "NOT READY"));
    CHECK(contains(blank, "&mdash;")); // placeholder for missing height / network difficulty
}

TEST_CASE("dashboard formats network difficulty as abbreviated + raw (like height)") {
    PoolSnapshot s = sample();
    s.network_diff = 1.24e9;
    CHECK(contains(dashboard_html(s), "1.24G (1,240,000,000)"));
    s.network_diff = 4.657e-10; // sub-1 (regtest) keeps the compact scientific form
    CHECK(contains(dashboard_html(s), "4.657e-10"));
}

TEST_CASE("dashboard shows the best share, abbreviated + raw (like difficulty)") {
    PoolSnapshot s = sample();
    s.best_share = 1.1e14;
    const std::string html = dashboard_html(s);
    CHECK(contains(html, "best share"));
    CHECK(contains(html, "110T (110,000,000,000,000)"));
}

TEST_CASE("metrics_json nests every subsystem block") {
    auto m = metrics_json(sample());
    CHECK(m.contains("pool"));
    CHECK(m.contains("stratifier"));
    CHECK(m.contains("connector"));
    CHECK(m.contains("generator"));
    CHECK(m["generator"]["bitcoind_reachable"].get<bool>() == true);
    CHECK(m["ready"].get<bool>() == true);
}
