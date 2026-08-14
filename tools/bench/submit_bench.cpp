#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>

#include <glaze/glaze.hpp>

#include "bitcoin/block_template.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::stratum;

namespace {

const Bytes kPayoutScript = util::from_hex("0014751e76e8199196d454941c45d1b3a323f1433bd6");

std::shared_ptr<Job> make_job(uint32_t curtime) {
    glz::generic t = glz::generic::object_t{};
    t["height"] = 200;
    t["version"] = 0x20000000;
    t["curtime"] = curtime;
    t["bits"] = std::string("207fffff"); // regtest-easy target -> validation runs, share usually accepted
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, '0');
    t["transactions"] = glz::generic::array_t{};
    const std::string envelope =
        R"({"error":null,"result":)" + glz::write_json(t).value_or("null") + "}";
    const auto tmpl = bitcoin::BlockTemplate::from_gbt(envelope);
    const Bytes tag{'/', 'e', 'p', '/'};
    return std::make_shared<Job>("job1", tmpl, tag, 4, 4, 1);
}

class DiscardConnection : public Connection {
public:
    uint64_t lines = 0;
    void send_line(std::string_view) override { ++lines; }
    std::string peer() const override { return "bench"; }
};

class BenchPool : public PoolContext {
public:
    std::shared_ptr<Job> job;
    uint64_t accepted = 0;
    uint64_t rejected = 0;
    explicit BenchPool(uint32_t curtime) : job(make_job(curtime)) {}

    size_t extranonce2_size() const override { return 4; }
    std::shared_ptr<const RuntimeConfig> runtime_config() const override {
        Config config;
        config.initial_difficulty = 1e-9;
        config.variable_difficulty = false;
        return std::make_shared<const RuntimeConfig>(config.runtime_config());
    }
    std::optional<Bytes> validate_address(const std::string& address) override {
        return address == "validaddr" ? std::optional<Bytes>(kPayoutScript) : std::nullopt;
    }
    std::shared_ptr<const Job> current_job() const override { return job; }
    std::shared_ptr<const Job> recent_job(const std::string& job_id) const override {
        return (job && job->job_id() == job_id) ? job : nullptr;
    }
    void note_accepted_share(const std::string&, const std::string&, double, double) override {
        ++accepted;
    }
    void note_rejected_share(const std::string&, const std::string&, RejectClass) override {
        ++rejected;
    }
    void on_block_found(const std::string&, const std::string&, const Job&,
                        const ShareResult&) override {}
    uint32_t version_mask() const override { return 0x1fffe000u; }
};

std::string submit(uint32_t nonce, std::string_view ntime) {
    return std::format(
        R"({{"id":9,"method":"mining.submit","params":["validaddr","job1","01020304","{}","{:08x}"]}})",
        ntime, nonce);
}

} // namespace

int main(int argc, char** argv) {
    const uint64_t iters = argc > 1 ? std::strtoull(argv[1], nullptr, 10) : 2'000'000;
    const auto curtime = static_cast<uint32_t>(std::time(nullptr));

    BenchPool pool(curtime);
    DiscardConnection conn;
    Session session{pool, conn, util::from_hex("e06ae06a")};
    session.handle_line(R"({"id":1,"method":"mining.subscribe","params":["bench/1.0"]})");
    session.handle_line(R"({"id":3,"method":"mining.authorize","params":["validaddr","x"]})");
    const std::string ntime = pool.job->ntime_hex();

    for (uint32_t i = 0; i < 10'000; ++i) // warmup
        session.handle_line(submit(i, ntime));

    const auto start = std::chrono::steady_clock::now();
    for (uint64_t i = 0; i < iters; ++i)
        session.handle_line(submit(static_cast<uint32_t>(i + 100'000), ntime));
    const auto end = std::chrono::steady_clock::now();

    const double secs = std::chrono::duration<double>(end - start).count();
    std::println(
        "submits={} time={:.3f}s throughput={:.0f} submits/sec (accepted={} rejected={})",
        iters, secs, iters / secs, pool.accepted, pool.rejected);
    return 0;
}
