#include <doctest/doctest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "api/snapshot.hpp"
#include "bitcoin/rpc_client.hpp"
#include "core/config.hpp"
#include "pool/pool.hpp"
#include "stats/poolstatus.hpp"

using namespace erikslund;

namespace {
// A Pool with an unconnected RPC client -- next_job_id() does no I/O (same pattern as
// test_http.cpp). The submit thread idles and stops cleanly on destruction.
bool is_lower_hex(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789abcdef") == std::string::npos;
}
} // namespace

TEST_CASE("validate_address resolves locally, without any bitcoind RPC") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass"); // refused -> any RPC call throws
    Pool pool(config, rpc);

    // network_ defaults to Regtest. A valid regtest address yields a P2WPKH script with no RPC --
    // the dead endpoint above would make any RPC-based validation fail.
    const auto ok = pool.validate_address("bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf");
    REQUIRE(ok.has_value());
    CHECK(ok->size() == 22); // OP_0 <0x14> + 20-byte witness program

    // Rejected locally (no RPC, no throw): garbage, a wrong-network (mainnet) address, and empty.
    CHECK_FALSE(pool.validate_address("notanaddress").has_value());
    CHECK_FALSE(pool.validate_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
    CHECK_FALSE(pool.validate_address("").has_value());
}

TEST_CASE("next_job_id is 16 hex: a stable per-process prefix + a monotonic counter") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);

    const std::string a = pool.next_job_id();
    const std::string b = pool.next_job_id();
    const std::string c = pool.next_job_id();

    for (const std::string& id : {a, b, c}) {
        CHECK(id.size() == 16); // 8-hex prefix + 8-hex counter (e.g. "1eccbf7200000001")
        CHECK(is_lower_hex(id));
    }
    // The high half is the per-process prefix -- identical across calls.
    CHECK(a.substr(0, 8) == b.substr(0, 8));
    CHECK(b.substr(0, 8) == c.substr(0, 8));
    // The low half is a monotonic counter starting at 1.
    CHECK(a.substr(8) == "00000001");
    CHECK(b.substr(8) == "00000002");
    CHECK(c.substr(8) == "00000003");
    CHECK(a != b);
    CHECK(b != c);
}

TEST_CASE("next_job_id: independent pools advance independent counters") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool p1(config, rpc);
    Pool p2(config, rpc);

    // Each pool's counter starts at 1; the random 32-bit prefix makes the full ids
    // globally unique across processes (collision probability ~2^-32, not asserted here).
    const std::string id1 = p1.next_job_id();
    const std::string id2 = p2.next_job_id();
    CHECK(id1.size() == 16);
    CHECK(id2.size() == 16);
    CHECK(id1.substr(8) == "00000001"); // independent counters, both from 1
    CHECK(id2.substr(8) == "00000001");
}

TEST_CASE("resubmit_spooled_blocks leaves the block on disk when bitcoind is unreachable") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_test";
    fs::remove_all(stats);
    fs::create_directories(stats / "blocks");
    const fs::path block = stats / "blocks" / "500_abc.hex";
    { std::ofstream(block, std::ios::binary) << "00112233\n"; }

    Config config;
    config.stats_directory = stats.string();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass"); // refused -> submitblock throws
    Pool pool(config, rpc);
    pool.resubmit_spooled_blocks();

    // The node was unreachable, so the block must stay (a later restart retries it),
    // never silently archived as submitted/rejected.
    CHECK(fs::exists(block));
    CHECK_FALSE(fs::exists(block.string() + ".submitted"));
    CHECK_FALSE(fs::exists(block.string() + ".rejected"));

    fs::remove_all(stats);
}

TEST_CASE("resubmit_spooled_blocks is a no-op when there is no blocks directory") {
    namespace fs = std::filesystem;
    const fs::path stats = fs::temp_directory_path() / "ep_resubmit_empty";
    fs::remove_all(stats);

    Config config;
    config.stats_directory = stats.string();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    CHECK_NOTHROW(pool.resubmit_spooled_blocks()); // nothing spooled -> nothing to do
}

// Persistent per-worker stats: the registry survives disconnect (entries are not tied to a live
// session) and restart (recover_user_stats re-seeds from users/ files, decaying by file age).
// These drive a Pool through its share hooks + snapshot; no bitcoind I/O is needed.

namespace {
// Find an address's worker rows in a snapshot (sorted by name for stable assertions).
std::vector<api::WorkerSnapshot> workers_of(const api::PoolSnapshot& s, const std::string& addr) {
    std::vector<api::WorkerSnapshot> out;
    for (const auto& w : s.workers)
        if (w.address == addr)
            out.push_back(w);
    std::sort(out.begin(), out.end(),
              [](const auto& a, const auto& b) { return a.worker < b.worker; });
    return out;
}
const char* kAddr = "bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf";
} // namespace

TEST_CASE("share hooks accumulate persistent per-worker stats; sessions with one name merge") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);

    // Two connections share worker name "w1"; a third is "w2". They must MERGE by name.
    pool.note_accepted_share(kAddr, "w1", 5.0, 5.0);
    pool.note_accepted_share(kAddr, "w1", 3.0, 3.0);
    pool.note_rejected_share(kAddr, "w1");
    pool.note_accepted_share(kAddr, "w2", 1.0, 1.0);

    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].worker == "w1");
    CHECK(rows[0].shares_accepted == 2);   // merged across the two w1 connections
    CHECK(rows[0].shares_rejected == 1);
    CHECK(rows[0].best_difficulty == doctest::Approx(5.0));
    CHECK(rows[0].hashrate_windows[0] > 0.0); // a fresh share registers hashrate
    CHECK(rows[1].worker == "w2");
    CHECK(rows[1].shares_accepted == 1);
}

TEST_CASE("per-worker bestshare is the actual hash difficulty, not the credited target") {
    // A best share is by definition far above the share target; the registry must record the
    // actual difficulty met (share_difficulty), not the credited target, or it under-reports.
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    pool.note_accepted_share(kAddr, "w1", /*credited=*/8.0, /*share_difficulty=*/5000.0);
    pool.note_accepted_share(kAddr, "w1", /*credited=*/8.0, /*share_difficulty=*/120.0);
    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].best_difficulty == doctest::Approx(5000.0)); // max actual, not the 8.0 credited
    CHECK(rows[0].shares_accepted == 2);
}

TEST_CASE("a worker row persists in the registry after its connection ends") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    pool.note_accepted_share(kAddr, "rig", 4.0, 4.0);

    // snapshot() has no live clients (none were attached), yet the row is present: persistence.
    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].worker == "rig");
    CHECK(rows[0].shares_accepted == 1);
    CHECK_FALSE(rows[0].connected); // no live session, but the stats survive
}

TEST_CASE("attach_worker creates a zero row so an idle authorized worker appears") {
    Config config;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    pool.attach_worker(kAddr, "idle");
    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].worker == "idle");
    CHECK(rows[0].shares_accepted == 0);
}

TEST_CASE("worker names beyond max_workers_per_address fold into the bare-address bucket") {
    Config config;
    config.max_workers_per_address = 2;
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool pool(config, rpc);
    pool.note_accepted_share(kAddr, "w1", 1.0, 1.0);
    pool.note_accepted_share(kAddr, "w2", 1.0, 1.0);
    pool.note_accepted_share(kAddr, "w3", 7.0, 7.0); // over the cap -> folds into ""
    pool.note_accepted_share(kAddr, "w4", 1.0, 1.0); // also folds

    const auto rows = workers_of(pool.snapshot(true), kAddr);
    REQUIRE(rows.size() == 3); // "" (bucket), w1, w2
    CHECK(rows[0].worker == "");
    CHECK(rows[0].shares_accepted == 2);            // w3 + w4
    CHECK(rows[0].best_difficulty == doctest::Approx(7.0));
    CHECK(rows[1].worker == "w1");
    CHECK(rows[2].worker == "w2");
}

TEST_CASE("recover_user_stats re-seeds the registry from users/ files, decayed by file age") {
    namespace fs = std::filesystem;
    const fs::path dir = fs::temp_directory_path() / "ep_recover_userstats";
    fs::remove_all(dir);

    // Write a users/<addr> file via the normal path so the format matches exactly.
    {
        Config wcfg;
        wcfg.stats_directory = dir.string();
        bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
        Pool writer(wcfg, rpc);
        for (int i = 0; i < 20; ++i)
            writer.note_accepted_share(kAddr, "rig", 1000.0, 1000.0); // build up some hashrate
        const auto snap = writer.snapshot(/*include_workers=*/true);
        stats::write_user_files(dir.string(), snap);
    }
    REQUIRE(fs::exists(dir / "users" / kAddr));

    // A fresh pool recovers it.
    Config rcfg;
    rcfg.stats_directory = dir.string();
    bitcoin::RpcClient rpc("http://127.0.0.1:1", "user", "pass");
    Pool reader(rcfg, rpc);
    reader.recover_user_stats();

    const auto rows = workers_of(reader.snapshot(true), kAddr);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].worker == "rig");
    CHECK(rows[0].shares_accepted == 20);   // shares recovered exactly
    CHECK(rows[0].best_difficulty == doctest::Approx(1000.0));
    CHECK(rows[0].hashrate_windows[0] > 0.0); // hashrate recovered (decayed, but non-zero)

    fs::remove_all(dir);
}
