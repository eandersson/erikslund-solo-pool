// Micro-benchmark of the share-validation hot path (Job::validate_share), gated behind EP_BENCH:
//   EP_BENCH=1 /build/cmake/erikslund_tests --test-case="*validate_share throughput*"
#include <doctest/doctest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <format>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "bitcoin/block_template.hpp"
#include "stratum/job.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::stratum;
using namespace erikslund::util;

namespace {
Job bench_job() {
    nlohmann::json tx1;
    tx1["data"] = "0123456789abcdef";
    tx1["txid"] = std::string(64, '1');
    nlohmann::json t;
    t["height"] = 170;
    t["version"] = 0x20000000;
    t["curtime"] = 1700000000;
    t["bits"] = "1d00ffff"; // hard target -> the share is above target -> full work, reject path
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = "00000000000000000000abcdef0123456789abcdef0123456789abcdef012345";
    t["default_witness_commitment"] = std::string("6a24aa21a9ed") + std::string(64, '0');
    t["transactions"] = nlohmann::json::array();
    t["transactions"].push_back(tx1);
    const auto bt = bitcoin::BlockTemplate::from_json(t);
    const Bytes tag{'/', 'b', '/'};
    return Job("job1", bt, tag, 4, 4, 1);
}

double run_bench(const Job& job, const Bytes& coinbase2, const Bytes& enonce1, int threads,
                 double seconds) {
    const uint256 share_target = target_from_compact(0x1d00ffff);
    std::atomic<bool> go{false};
    std::atomic<bool> stop{false};
    std::atomic<uint64_t> total{0};
    std::vector<std::thread> workers;
    for (int tnum = 0; tnum < threads; ++tnum) {
        workers.emplace_back([&, tnum] {
            ShareInput in;
            in.coinbase2 = coinbase2;
            in.extranonce1 = enonce1;
            in.extranonce2_hex = "01020304";
            in.ntime_hex = "6553f100";
            in.share_target = share_target;
            in.now_unix = 1700000001;
            uint64_t count = 0;
            uint32_t nonce = static_cast<uint32_t>(tnum) * 1000000u;
            std::string nbuf;
            while (!go.load(std::memory_order_acquire)) {
            }
            while (!stop.load(std::memory_order_relaxed)) {
                nbuf = std::format("{:08x}", nonce++);
                in.nonce_hex = nbuf;
                // Separate TU + observed result so the optimizer can't elide the call.
                const ShareResult r = job.validate_share(in);
                if (r.valid)
                    total.fetch_add(0, std::memory_order_relaxed);
                ++count;
            }
            total.fetch_add(count, std::memory_order_relaxed);
        });
    }
    const auto t0 = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    std::this_thread::sleep_for(std::chrono::duration<double>(seconds));
    stop.store(true, std::memory_order_relaxed);
    for (auto& w : workers)
        w.join();
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    return static_cast<double>(total.load()) / elapsed;
}
} // namespace

TEST_CASE("validate_share throughput benchmark") {
    if (std::getenv("EP_BENCH") == nullptr)
        return; // skipped in normal ctest; set EP_BENCH=1 to run
    const Job job = bench_job();
    const Bytes payout = from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes coinbase2 = job.build_coinbase2(payout);
    const Bytes enonce1 = from_hex("deadbeef");

    const double one = run_bench(job, coinbase2, enonce1, 1, 3.0);
    const double four = run_bench(job, coinbase2, enonce1, 4, 3.0);
    std::printf("\n[BENCH] validate_share: 1 thread = %.0f/s | 4 threads = %.0f/s | scaling = %.2fx\n",
                one, four, one > 0.0 ? four / one : 0.0);
    std::fflush(stdout);
    CHECK(one > 0.0);
    CHECK(four > 0.0);
}
