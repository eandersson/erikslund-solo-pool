// Cross-thread stress for the phased Session::handle_submit (mutex narrowed so SHA256d validation
// runs unlocked). Models the REAL threading: exactly one reactor thread submits for a connection,
// while the work thread fans out mining.notify, the vardiff thread retargets, and the HTTP thread
// snapshots stats -- all against the same Session. Single-threaded runs catch logic bugs; under
// docker/tsan.sh (-DSANITIZE_THREAD=ON) this is the data-race / lock-order gate for the narrowed
// lock, the shared_ptr coinbase2 cache, and the difficulty-snapshot handoff between phases.
#include <doctest/doctest.h>

#include <atomic>
#include <cstdint>
#include <format>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "gbt_fixture.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::stratum;
using namespace erikslund::test;

namespace {

const Bytes kPayout = util::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");

std::shared_ptr<Job> make_job(const std::string& id, uint32_t curtime) {
    gbt_json t = gbt_json::object_t{};
    t["height"] = 200;
    t["version"] = 0x20000000;
    t["curtime"] = curtime;
    t["bits"] = std::string("207fffff"); // regtest-easy: shares (and blocks) accept cheaply
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, '0');
    t["transactions"] = gbt_json::array_t{};
    const Bytes tag{'/', 'e', 'p', '/'};
    return std::make_shared<Job>(id, from_template(t), tag, 4, 4, 1);
}

// Thread-safe response sink: the reactor thread (ack) and the work thread (notify) both send.
// Classifies output instead of blind-counting so a lost or duplicated submit response cannot hide
// under the notify volume: submit responses carry "id":10, acks are result:true, errors carry a
// code. All sends happen under the session mutex_, so plain counters would do -- atomics keep the
// sink obviously safe if that ever changes.
class ClassifyingConnection : public Connection {
public:
    std::atomic<uint64_t> submit_acks{0};   // "id":10 + result true
    std::atomic<uint64_t> submit_errors{0}; // "id":10 + error code
    std::atomic<uint64_t> other_lines{0};   // subscribe/authorize replies, notifies, set_difficulty
    void send_line(std::string_view line) override {
        if (line.find("\"id\":10") != std::string_view::npos) {
            if (line.find("\"result\":true") != std::string_view::npos)
                submit_acks.fetch_add(1, std::memory_order_relaxed);
            else
                submit_errors.fetch_add(1, std::memory_order_relaxed);
        } else {
            other_lines.fetch_add(1, std::memory_order_relaxed);
        }
    }
    std::string peer() const override { return "stress"; }
};

// Thread-safe PoolContext: recent_job hands out one of two stable jobs so the submitter and the
// notifier can drive the coinbase2 cache to swap under the narrowed lock.
class StressPool : public PoolContext {
public:
    std::shared_ptr<Job> job_a;
    std::shared_ptr<Job> job_b;
    std::shared_ptr<const RuntimeConfig> runtime;
    std::atomic<int> accepted{0}, rejected{0}, blocks{0};
    // Every credited difficulty note_accepted_share saw, for post-join verification that the
    // phase-A snapshot handoff only ever produces difficulties the session legitimately held.
    std::mutex credited_mutex;
    std::vector<double> credited_seen;

    explicit StressPool(uint32_t curtime)
        : job_a(make_job("aaaa0001", curtime)), job_b(make_job("bbbb0002", curtime)) {
        RuntimeConfig config = Config{}.runtime_config();
        config.initial_difficulty = 1e-9;
        config.minimum_difficulty = 1e-12;
        config.vardiff_retarget_seconds = 0; // retarget on every call
        runtime = std::make_shared<const RuntimeConfig>(config);
    }

    size_t extranonce2_size() const override { return 4; }
    std::shared_ptr<const RuntimeConfig> runtime_config() const override { return runtime; }
    std::optional<Bytes> validate_address(const std::string& address) override {
        return address == "validaddr" ? std::make_optional(kPayout) : std::nullopt;
    }
    std::shared_ptr<const Job> current_job() const override { return job_a; }
    std::shared_ptr<const Job> recent_job(const std::string& job_id) const override {
        if (job_a->job_id() == job_id)
            return job_a;
        if (job_b->job_id() == job_id)
            return job_b;
        return nullptr;
    }
    void note_accepted_share(const std::string&, const std::string&, double credited,
                             double) override {
        accepted.fetch_add(1, std::memory_order_relaxed);
        const std::scoped_lock lock(credited_mutex);
        credited_seen.push_back(credited);
    }
    void note_rejected_share(const std::string&, const std::string&, RejectClass) override {
        rejected.fetch_add(1, std::memory_order_relaxed);
    }
    void on_block_found(const std::string&, const std::string&, const Job&,
                        const ShareResult&) override {
        blocks.fetch_add(1, std::memory_order_relaxed);
    }
    uint32_t version_mask() const override { return 0x1fffe000u; }
};

} // namespace

TEST_CASE("phased handle_submit is race-free against notify, vardiff, and stats threads") {
    const auto curtime = static_cast<uint32_t>(std::time(nullptr));
    StressPool pool(curtime);
    ClassifyingConnection conn;
    Session session(pool, conn, util::from_hex("e06ae06a"));

    session.handle_line(R"({"id":1,"method":"mining.subscribe","params":["miner/1.0"]})");
    session.handle_line(R"({"id":2,"method":"mining.authorize","params":["validaddr","w"]})");
    REQUIRE(session.subscribed());
    REQUIRE(session.authorized());

    constexpr int kSubmits = 3000;

    // The single reactor thread for this connection. Mostly distinct valid shares (distinct nonce
    // => distinct dedup key, so validation runs every time; ~half accept, ~half reject on
    // 207fffff), salted with the phase-A reject kinds so the stale / malformed / duplicate
    // branches -- the ones that still call pool accounting under mutex_ -- also race the other
    // threads under TSan.
    std::thread submitter([&] {
        const std::string ntime = std::format("{:08x}", curtime);
        for (int i = 0; i < kSubmits; ++i) {
            std::string job_id = "aaaa0001";
            std::string nonce = std::format("{:08x}", static_cast<uint32_t>(i));
            if (i % 97 == 5)
                job_id = "dead0003"; // recent_job -> nullptr: the Stale branch
            else if (i % 97 == 17)
                nonce = "2a2a2a2a2a"; // >8 chars: the Malformed size gate
            else if (i % 97 == 29)
                nonce = std::format("{:08x}", static_cast<uint32_t>(i - 1)); // exact resubmit: Duplicate
            const std::string line = std::format(
                R"({{"id":10,"method":"mining.submit","params":["validaddr.w","{}","01020304","{}","{}"]}})",
                job_id, ntime, nonce);
            session.handle_line(line);
        }
    });
    // The work thread: fan out notify, alternating jobs so coinbase2_for swaps the cached shared_ptr
    // while the submitter may be mid-validation against its own copy.
    std::atomic<bool> stop{false};
    std::thread notifier([&] {
        bool a = true;
        while (!stop.load(std::memory_order_relaxed)) {
            session.send_notify(a ? *pool.job_a : *pool.job_b, /*clean=*/a);
            a = !a;
        }
    });
    // The vardiff thread: retarget (mutates difficulty_/previous_/pending_ under the lock that the
    // submitter's phase A snapshots).
    std::thread vardiffer([&] {
        while (!stop.load(std::memory_order_relaxed))
            session.maybe_retarget();
    });
    // The HTTP thread: snapshot stats (reads the same members under the lock).
    std::thread reader([&] {
        while (!stop.load(std::memory_order_relaxed))
            (void)session.stats();
    });

    submitter.join();
    stop.store(true, std::memory_order_relaxed);
    notifier.join();
    vardiffer.join();
    reader.join();

    // Exact response accounting: every submit produced exactly one classified response -- none
    // lost between the phases, none duplicated -- and the wire verdicts match the pool's ledger.
    CHECK(conn.submit_acks.load() + conn.submit_errors.load() == kSubmits);
    CHECK(conn.submit_acks.load() == static_cast<uint64_t>(pool.accepted.load()));
    CHECK(conn.submit_errors.load() == static_cast<uint64_t>(pool.rejected.load()));
    CHECK(conn.other_lines.load() >= 2); // subscribe + authorize replies, plus notify traffic
    // Every submit was accounted for exactly once, split across accept/reject with no loss/dup
    // (the stale/malformed/duplicate salts land in `rejected` alongside validation rejects).
    CHECK(pool.accepted.load() + pool.rejected.load() == kSubmits);
    CHECK(pool.accepted.load() > 0); // the easy target accepts a healthy fraction
    CHECK(static_cast<uint64_t>(session.shares_accepted()) == static_cast<uint64_t>(pool.accepted.load()));
    // The credited-difficulty handoff (phase-A snapshot -> phase-C note): every value the pool saw
    // is positive and vardiff-clamped, and the session's own ledger sums the identical sequence
    // (same doubles, same order -> exactly equal), so no credit was lost, doubled, or torn.
    CHECK(pool.credited_seen.size() == static_cast<size_t>(pool.accepted.load()));
    double credited_sum = 0.0;
    for (const double credited : pool.credited_seen) {
        CHECK(credited > 0.0);
        CHECK(credited <= 1e12); // vardiff_next's no-maximum default cap
        credited_sum += credited;
    }
    CHECK(session.stats().total_share_difficulty == credited_sum);
    // Blocks only counted for shares that also cleared the network target (subset of accepts).
    CHECK(pool.blocks.load() <= pool.accepted.load());
}
