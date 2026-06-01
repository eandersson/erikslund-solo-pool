#include <doctest/doctest.h>

#include <filesystem>
#include <fstream>
#include <sstream>

#include <yaml-cpp/yaml.h>

#include "api/snapshot.hpp"
#include "stats/poolstatus.hpp"

using namespace erikslund;
using namespace erikslund::stats;

TEST_CASE("suffix_string matches the C pool format") {
    CHECK(suffix_string(0) == "0");
    CHECK(suffix_string(999) == "999");
    CHECK(suffix_string(1000) == "1K");
    CHECK(suffix_string(1500) == "1.5K");
    CHECK(suffix_string(43400000) == "43.4M");
    CHECK(suffix_string(2.5e9) == "2.5G");
    CHECK(suffix_string(1e12) == "1T");
    CHECK(suffix_string(1.5e15) == "1.5P");
}

TEST_CASE("suffix_string sub-1000 values have no suffix and no decimals") {
    CHECK(suffix_string(1) == "1");
    CHECK(suffix_string(42) == "42");
    CHECK(suffix_string(500) == "500");
    CHECK(suffix_string(999.9) == "999"); // truncated to an unsigned integer below 1K
}

TEST_CASE("suffix_string scales into the exa range") {
    CHECK(suffix_string(1e18) == "1E");
    CHECK(suffix_string(2.5e18) == "2.5E");
}

TEST_CASE("suffix_string crosses the M threshold cleanly") {
    // Exactly 1e6 is the first mega value.
    CHECK(suffix_string(1e6) == "1M");
    CHECK(suffix_string(2e6) == "2M");
    // A value comfortably inside the K range stays in K with 3 significant figures.
    CHECK(suffix_string(123456.0) == "123K");
}

TEST_CASE("suffix_string with explicit significant digits uses fixed precision") {
    // 4 significant digits over a kilo value -> "1.500K".
    CHECK(suffix_string(1500.0, 4) == "1.500K");
    // 3 significant digits of a mega value.
    CHECK(suffix_string(43400000.0, 3) == "43.4M");
}

TEST_CASE("build_pool_status computes best_share_percent against the network diff") {
    api::PoolSnapshot s;
    s.uptime = 10;
    s.network_diff = 1000.0;
    s.best_share = 250.0; // 25% of the network difficulty
    const auto status = build_pool_status(s);
    CHECK(status["shares"]["best_share_percent"] == doctest::Approx(25.0));
    CHECK_FALSE(status["shares"].contains("progress_to_block_percent"));
    CHECK_FALSE(status["pool_stat"].contains("time_to_block_seconds"));
}

TEST_CASE("build_pool_status best_share_percent is zero when the network diff is unknown") {
    api::PoolSnapshot s;
    s.uptime = 10;
    s.best_share = 250.0; // no network_diff set
    const auto status = build_pool_status(s);
    CHECK(status["shares"]["best_share_percent"] == doctest::Approx(0.0));
}

TEST_CASE("build_pool_status reports users, workers, and runtime when idle") {
    api::PoolSnapshot s;
    s.uptime = 5;
    s.users = 0;
    s.connected = 0;
    const auto status = build_pool_status(s);
    CHECK(status["pool_stat"]["users"] == 0);
    CHECK(status["pool_stat"]["workers"] == 0);
    CHECK(status["pool_stat"]["runtime"] == 5);
    CHECK_FALSE(status["pool_stat"].contains("Idle"));
    CHECK_FALSE(status["pool_stat"].contains("Disconnected"));
    CHECK_FALSE(status["pool_stat"].contains("time_to_block_seconds"));
}

TEST_CASE("build_user_stats returns empty fields for an unknown address") {
    api::PoolSnapshot s; // no clients
    const auto user = build_user_stats("ghost", s);
    CHECK(user["workers"] == 0);
    CHECK(user["shares_accepted"] == 0);
    CHECK(user["bestshare"] == doctest::Approx(0.0));
    CHECK(user["worker"].is_array());
    CHECK(user["worker"].empty());
    // All seven hashrate windows still present, all "0".
    CHECK(user["hashrate1m"] == "0");
    CHECK(user["hashrate7d"] == "0");
    CHECK(user["blocks"] == 0);
}

TEST_CASE("build_user_stats attributes accepted blocks to the payout address") {
    api::PoolSnapshot s;
    s.blocks_by_address["addr1"] = 2;
    CHECK(build_user_stats("addr1", s)["blocks"] == 2);
    CHECK(build_user_stats("other", s)["blocks"] == 0);
}

TEST_CASE("read_pool_status tolerates a malformed file and a missing shares block") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_poolstatus_malformed";
    fs::remove_all(dir);
    fs::create_directories(dir / "pool");

    // A YAML scalar (not a map) -> nullopt.
    { std::ofstream(dir / "pool" / "pool.status", std::ios::binary) << "just a scalar\n"; }
    CHECK_FALSE(read_pool_status(dir.string()).has_value());

    // A map without a shares block -> recovered, but zeroed.
    { std::ofstream(dir / "pool" / "pool.status", std::ios::binary) << "pool_stat: {runtime: 7}\n"; }
    const auto recovered = read_pool_status(dir.string());
    REQUIRE(recovered.has_value());
    CHECK(recovered->accepted_diff == doctest::Approx(0.0));
    CHECK(recovered->best_share == doctest::Approx(0.0));

    fs::remove_all(dir);
}

TEST_CASE("build_pool_status has the C pool's shape") {
    constexpr double kNonces = 4294967296.0; // 2^32
    api::PoolSnapshot s;
    s.uptime = 100;
    s.starttime = 1700000000;
    s.users = 2;
    s.connected = 3;
    s.shares_accepted = 50;
    s.shares_rejected = 2;
    s.accepted_diff = 123.0;
    s.best_share = 45.0;
    s.hashrate_estimate = 1e6;
    s.network_diff = 1000.0;
    // Per-window decaying diff/s (distinct per window).
    s.hashrate_windows = {5e6 / kNonces, 4e6 / kNonces, 3e6 / kNonces, 2e6 / kNonces,
                          1e6 / kNonces, 5e5 / kNonces, 1e5 / kNonces};
    s.sps_windows = {1.234567, 0.5, 0.25, 0.125};

    const auto status = build_pool_status(s);
    CHECK(status["pool_stat"]["users"] == 2);
    CHECK(status["pool_stat"]["workers"] == 3);
    CHECK(status["shares"]["best_share_percent"] == doctest::Approx(4.5)); // 45 / 1000 * 100
    // lastupdate is an RFC 9557 UTC timestamp string, e.g. "2026-06-04T11:31:24Z[UTC]".
    CHECK(status["pool_stat"]["lastupdate"].is_string());
    CHECK(status["pool_stat"]["lastupdate"].get<std::string>().ends_with("Z[UTC]"));
    CHECK(status["shares"]["accepted"] == 123);
    CHECK(status["shares"]["rejected"] == 2);
    CHECK(status["shares"]["bestshare"] == 45);
    // Per-window hashrate strings differ window to window.
    CHECK(status["hashrate"]["hashrate1m"] == "5M");
    CHECK(status["hashrate"]["hashrate5m"] == "4M");
    CHECK(status["hashrate"]["hashrate7d"] == "100K");
    CHECK(status["hashrate"].size() == 7); // seven decaying windows
    // SPS fields are shares_per_second_*, rounded to 5 decimals.
    CHECK(status["shares"]["shares_per_second_1m"] == doctest::Approx(1.23457));
    CHECK(status["shares"]["shares_per_second_5m"] == doctest::Approx(0.5));
    CHECK(status["shares"]["shares_per_second_15m"] == doctest::Approx(0.25));
    CHECK(status["shares"]["shares_per_second_1h"] == doctest::Approx(0.125));
    CHECK_FALSE(status["shares"].contains("SPS1m"));
}

TEST_CASE("pool.status round-trips through disk for restart recovery") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_poolstatus_test";
    fs::remove_all(dir);

    api::PoolSnapshot s;
    s.uptime = 10;
    s.accepted_diff = 777.0;
    s.best_share = 88.0;
    s.shares_accepted = 5;
    write_pool_status(dir.string(), s);

    // On disk it's YAML (the API serves JSON); confirm nested shares.* survive.
    std::ifstream file(dir / "pool" / "pool.status", std::ios::binary);
    std::stringstream raw;
    raw << file.rdbuf();
    const YAML::Node doc = YAML::Load(raw.str());
    REQUIRE(doc.IsMap());
    CHECK(doc["shares"]["accepted"].as<int64_t>() == 777);
    CHECK(doc["shares"]["bestshare"].as<int64_t>() == 88);
    CHECK(doc["pool_stat"]["runtime"].as<int64_t>() == 10);
    CHECK(doc["hashrate"]["hashrate1m"].as<std::string>().size() > 0);
    // lastupdate is an RFC 9557 UTC timestamp on disk; recovery must tolerate it.
    CHECK(doc["pool_stat"]["lastupdate"].as<std::string>().ends_with("Z[UTC]"));

    const auto recovered = read_pool_status(dir.string());
    REQUIRE(recovered.has_value());
    CHECK(recovered->accepted_diff == doctest::Approx(777.0));
    CHECK(recovered->best_share == doctest::Approx(88.0));

    fs::remove_all(dir);
    CHECK_FALSE(read_pool_status(dir.string()).has_value()); // absent -> nullopt
}

TEST_CASE("blocks_found and per-address tallies persist across a restart") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_blocks_persist";
    fs::remove_all(dir);

    api::PoolSnapshot s;
    s.uptime = 5;
    s.blocks_found = 4;
    s.last_block_found = 1700000000; // round-trips through the RFC 9557 string on disk
    s.blocks_by_address = {{"bc1qa", 3}, {"bc1qb", 1}};
    write_pool_status(dir.string(), s);

    const auto recovered = read_pool_status(dir.string());
    REQUIRE(recovered.has_value());
    CHECK(recovered->blocks_found == 4);
    CHECK(recovered->last_block_found == 1700000000);
    REQUIRE(recovered->blocks_by_address.size() == 2);
    CHECK(recovered->blocks_by_address.at("bc1qa") == 3);
    CHECK(recovered->blocks_by_address.at("bc1qb") == 1);

    // A status without the new fields (old/foreign file) recovers as zero/empty.
    api::PoolSnapshot empty;
    empty.uptime = 1;
    write_pool_status(dir.string(), empty);
    const auto rec2 = read_pool_status(dir.string());
    REQUIRE(rec2.has_value());
    CHECK(rec2->blocks_found == 0);
    CHECK(rec2->last_block_found == 0);
    CHECK(rec2->blocks_by_address.empty());

    fs::remove_all(dir);
}

TEST_CASE("format_rfc9557 emits a UTC RFC 9557 timestamp (empty for none)") {
    CHECK(format_rfc9557(0) == "");
    CHECK(format_rfc9557(-5) == "");
    CHECK(format_rfc9557(1700000000) == "2023-11-14T22:13:20Z[UTC]");
}

TEST_CASE("write_user_files only writes safe, authorized addresses (path-injection guard)") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_userfiles_safety";
    const fs::path escaped = fs::temp_directory_path() / "ep_userfiles_pwned";
    fs::remove_all(dir);
    fs::remove(escaped);

    // Registry rows (only authorized addresses ever enter the registry); is_safe_address is the
    // defense-in-depth filename guard at the write choke point.
    const auto row = [](const std::string& address) {
        api::WorkerSnapshot w;
        w.address = address;
        w.worker = "w1";
        w.shares_accepted = 1; // a real (mined) row so the zero-stat skip doesn't drop it
        return w;
    };
    api::PoolSnapshot s;
    s.workers = {row("bc1qexampleaddress"), // safe -> the only file written
                 row("evil/escape"),        // '/' in the address -> skipped
                 row(escaped.string()),     // absolute path -> must NOT escape
                 row("..")};                // ".." -> skipped

    write_user_files(dir.string(), s);

    CHECK(fs::exists(dir / "users" / "bc1qexampleaddress")); // the one good file
    CHECK_FALSE(fs::exists(escaped)); // absolute-path address did NOT escape users/
    CHECK_FALSE(fs::exists(dir / "users" / "evil" / "escape")); // '/' did not nest
    size_t files = 0;
    if (fs::exists(dir / "users"))
        for (const auto& entry : fs::directory_iterator(dir / "users")) {
            (void)entry;
            ++files;
        }
    CHECK(files == 1); // exactly the one safe, authorized address

    fs::remove_all(dir);
    fs::remove(escaped); // cleanup if the guard ever regressed
}

TEST_CASE("write_user_files stops creating files at the cap; existing addresses keep updating") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_userfiles_cap";
    fs::remove_all(dir);

    const auto client_for = [](const std::string& address) {
        api::WorkerSnapshot w;
        w.address = address;
        w.worker = "w";
        w.shares_accepted = 1; // a real (mined) row so the zero-stat skip doesn't drop it
        return w;
    };

    // Fill to the cap with two known addresses (deterministic: no third competing).
    api::PoolSnapshot s;
    s.workers = {client_for("addr1"), client_for("addr2")};
    write_user_files(dir.string(), s, /*max_user_files=*/2);
    CHECK(fs::exists(dir / "users" / "addr1"));
    CHECK(fs::exists(dir / "users" / "addr2"));

    // At the cap: a NEW address is refused, while a known one still updates.
    api::PoolSnapshot at_cap;
    at_cap.workers = {client_for("addr1"), client_for("addr3")};
    write_user_files(dir.string(), at_cap, /*max_user_files=*/2);
    CHECK_FALSE(fs::exists(dir / "users" / "addr3")); // creation capped
    CHECK(fs::exists(dir / "users" / "addr1"));       // update still allowed
    size_t files = 0;
    for (const auto& entry : fs::directory_iterator(dir / "users")) {
        (void)entry;
        ++files;
    }
    CHECK(files == 2);

    fs::remove_all(dir);
}

TEST_CASE("write_user_files seeds its cap registry from an existing directory (restart)") {
    // On the first visit to a stats dir, the known-address registry is seeded from what is
    // already on disk -- so a restart with N existing files counts them against the cap instead
    // of starting from zero. A unique temp dir guarantees this is a genuine first visit.
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_userfiles_seed";
    fs::remove_all(dir);
    fs::create_directories(dir / "users");
    std::ofstream(dir / "users" / "addrA") << "x"; // pre-existing from a prior run
    std::ofstream(dir / "users" / "addrB") << "x";

    const auto client_for = [](const std::string& address) {
        api::WorkerSnapshot w;
        w.address = address;
        w.worker = "w";
        w.shares_accepted = 1; // a real (mined) row so the zero-stat skip doesn't drop it
        return w;
    };
    // Cap 2, already full from the seeded files: a NEW address is refused...
    api::PoolSnapshot fresh;
    fresh.workers = {client_for("addrNEW")};
    write_user_files(dir.string(), fresh, /*max_user_files=*/2);
    CHECK_FALSE(fs::exists(dir / "users" / "addrNEW"));
    // ...but a pre-existing (seeded) address still updates.
    api::PoolSnapshot known;
    known.workers = {client_for("addrA")};
    write_user_files(dir.string(), known, /*max_user_files=*/2);
    CHECK(fs::exists(dir / "users" / "addrA"));

    fs::remove_all(dir);
}

TEST_CASE("stale user files are pruned; active miners and retention=0 never are") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_userfiles_retention";
    fs::remove_all(dir);

    const auto client_for = [](const std::string& address) {
        api::WorkerSnapshot w;
        w.address = address;
        w.worker = "w";
        w.shares_accepted = 1; // a real (mined) row so the zero-stat skip doesn't drop it
        return w;
    };
    const auto backdate = [&](const std::string& name, std::chrono::hours age) {
        fs::last_write_time(dir / "users" / name, fs::file_time_type::clock::now() - age);
    };

    // Mint two files, filling the cap of 2.
    api::PoolSnapshot both;
    both.workers = {client_for("gone"), client_for("stays")};
    write_user_files(dir.string(), both, /*max_user_files=*/2);
    REQUIRE(fs::exists(dir / "users" / "gone"));
    REQUIRE(fs::exists(dir / "users" / "stays"));

    // Backdate BOTH beyond a 1-day retention; "gone" no longer has a registry row, "stays" does.
    backdate("gone", std::chrono::hours{48});
    backdate("stays", std::chrono::hours{48});
    api::PoolSnapshot after;
    after.workers = {client_for("stays"), client_for("fresh")};
    write_user_files(dir.string(), after, /*max_user_files=*/2,
                     /*retention_seconds=*/86400.0, /*prune_sweep_seconds=*/0.0);
    CHECK_FALSE(fs::exists(dir / "users" / "gone")); // stale + no current row -> file pruned
    CHECK(fs::exists(dir / "users" / "stays"));      // stale mtime but still rendered -> kept

    // The prune freed a cap slot: the next write mints the new address's file.
    write_user_files(dir.string(), after, /*max_user_files=*/2,
                     /*retention_seconds=*/86400.0, /*prune_sweep_seconds=*/0.0);
    CHECK(fs::exists(dir / "users" / "fresh"));

    // retention 0 = keep forever, however stale.
    backdate("stays", std::chrono::hours{24 * 365});
    api::PoolSnapshot empty;
    write_user_files(dir.string(), empty, /*max_user_files=*/2,
                     /*retention_seconds=*/0.0, /*prune_sweep_seconds=*/0.0);
    CHECK(fs::exists(dir / "users" / "stays"));

    fs::remove_all(dir);
}

namespace {
constexpr double kNonces = 4294967296.0; // 2^32
api::WorkerSnapshot make_worker(const std::string& address, const std::string& worker,
                                uint64_t shares, uint64_t rejected, double best, int64_t ts,
                                double hps_1m) {
    api::WorkerSnapshot w;
    w.address = address;
    w.worker = worker;
    w.shares_accepted = shares;
    w.shares_rejected = rejected;
    w.best_difficulty = best;
    w.last_share_ts = ts;
    // Only the 1m window matters for the assertions; populate it (diff/s) and a smaller 7d.
    w.hashrate_windows = {hps_1m / kNonces, 0, 0, 0, 0, 0, hps_1m / kNonces / 50.0};
    return w;
}
api::ClientSnapshot make_conn(const std::string& address, const std::string& worker) {
    api::ClientSnapshot c;
    c.address = address;
    c.worker = worker;
    c.authorized = true;
    return c;
}
} // namespace

TEST_CASE("write_user_files skips a no-activity address but keeps a rejected-only active rig") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_userfiles_rejectonly";
    fs::remove_all(dir);
    api::PoolSnapshot s;
    // "rejector": authorized + submitting, all rejected (misconfigured) -> must surface.
    // "ghost": authorize-then-disconnect, no shares at all -> skipped (anti-churn).
    s.workers = {make_worker("rejector", "w", /*shares=*/0, /*rejected=*/3, 0.0, 0, 0.0),
                 make_worker("ghost", "w", /*shares=*/0, /*rejected=*/0, 0.0, 0, 0.0)};
    write_user_files(dir.string(), s, /*max_user_files=*/10);
    CHECK(fs::exists(dir / "users" / "rejector")); // rejected-only but active -> file written
    CHECK_FALSE(fs::exists(dir / "users" / "ghost")); // no activity -> no file
    fs::remove_all(dir);
}

TEST_CASE("build_user_stats renders the persistent registry rows; address = their sum") {
    api::PoolSnapshot s;
    // Two persistent worker rows for addr1 + one for another address (ignored). The registry
    // already holds one row per worker NAME, so the renderer just emits + sums them.
    s.workers = {make_worker("addr1", "w1", 3, 1, 9.0, 100, 5e6),
                 make_worker("addr1", "w2", 2, 0, 4.0, 200, 5e6),
                 make_worker("addr2", "w9", 1, 0, 1.0, 50, 1e6)};
    // Two live connections for addr1 drive the "workers" count (rows persist past disconnect).
    s.clients = {make_conn("addr1", "w1"), make_conn("addr1", "w2")};

    const auto user = build_user_stats("addr1", s);
    CHECK(user["workers"] == 2); // live connection count
    CHECK(user["shares_accepted"] == 5);
    CHECK(user["shares_rejected"] == 1);
    CHECK(user["bestshare"] == doctest::Approx(9.0));
    CHECK(user["lastshare"] == format_rfc9557(200));
    REQUIRE(user["worker"].size() == 2);          // one row per name
    CHECK(user["worker"][0]["workername"] == "w1"); // sorted by name
    CHECK(user["worker"][0]["hashrate1m"] == "5M");
    CHECK(user["worker"][0]["shares_rejected"] == 1);
    CHECK_FALSE(user["worker"][0].contains("difficulty")); // not unique per name
    CHECK(user["worker"][0].contains("last_share_age"));
    // Address-level windows are the SUM of the two rows (10e6 -> "10M").
    CHECK(user["hashrate1m"] == "10M");
    CHECK(user.contains("hashrate6hr"));
}

TEST_CASE("a persistent worker row renders even with zero live connections (post-disconnect)") {
    api::PoolSnapshot s;
    s.workers = {make_worker("addr1", "w1", 7, 0, 9.0, 140, 4e6)};
    // No clients: the worker disconnected, but its registry row persists (decaying).
    const auto user = build_user_stats("addr1", s);
    CHECK(user["workers"] == 0);          // nobody connected
    CHECK(user["shares_accepted"] == 7);  // ...but the accumulated shares survive
    REQUIRE(user["worker"].size() == 1);
    CHECK(user["worker"][0]["workername"] == "w1");
    CHECK(user["worker"][0]["hashrate1m"] == "4M");
}

TEST_CASE("the bare-address registry bucket renders under the address name") {
    api::PoolSnapshot s;
    s.workers = {make_worker("addr1", "", 5, 1, 3.0, 130, 2e6),   // overflow/unnamed bucket
                 make_worker("addr1", "w1", 1, 0, 9.0, 140, 1e6)};
    const auto user = build_user_stats("addr1", s);
    REQUIRE(user["worker"].size() == 2);
    CHECK(user["worker"][0]["workername"] == "addr1"); // "" sorts first, renders as the address
    CHECK(user["worker"][0]["shares_accepted"] == 5);
    CHECK(user["worker"][1]["workername"] == "w1");
}
