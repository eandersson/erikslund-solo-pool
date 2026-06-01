#pragma once
// Polls bitcoind for templates, builds Jobs, broadcasts work, validates addresses, submits
// solved blocks. Implements stratum::PoolContext.
//
// Locks: mutex_ guards the client list; jobs_mutex_ (shared) the current/recent jobs; stats_mutex_
// the decaying hashrate windows; per-session state has its own mutex; counters are atomics. The
// work thread copies the client list under mutex_ then notifies lock-free, never holding two locks.
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <shared_mutex>
#include <span>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "api/snapshot.hpp"
#include "bitcoin/network.hpp"
#include "bitcoin/rpc_client.hpp"
#include "core/config.hpp"
#include "stats/hashrate.hpp"
#include "stratum/job.hpp"
#include "stratum/session.hpp"

namespace erikslund {

class Pool : public stratum::PoolContext {
public:
    Pool(Config config, bitcoin::RpcClient& rpc);

    void detect_network();

    void refresh_work(const std::stop_token& stop);

    void vardiff_loop(const std::stop_token& stop);
    void status_loop(const std::stop_token& stop);

    void recover_stats();
    // Re-submit any block a previous run spooled but never confirmed. Call once at startup
    // after bitcoind is reachable.
    void resubmit_spooled_blocks();

    void notify_new_block();

    std::shared_ptr<stratum::Session> add_client(std::shared_ptr<stratum::Connection> connection);
    void remove_client(const std::shared_ptr<stratum::Session>& session);
    size_t client_count() const;

    void set_connector_ready(bool ready);

    // include_workers samples the persistent per-worker registry into snapshot.workers (an
    // O(registry) walk under user_stats_mutex_). Only the stats-file writer passes true; the HTTP
    // path leaves it false to avoid that cost and share-lock contention.
    api::PoolSnapshot snapshot(bool include_workers = false) const;
    // Cheap readiness probe for /health (same predicate as PoolSnapshot::ready).
    bool ready() const;

    void on_zmq_block(const std::string& block_hash_display);

    size_t extranonce2_size() const override { return config_.extranonce2_size; }
    double start_difficulty() const override { return config_.initial_difficulty; }
    std::optional<Bytes> validate_address(const std::string& address) override;
    std::shared_ptr<const stratum::Job> current_job() const override;
    std::shared_ptr<const stratum::Job> recent_job(const std::string& job_id) const override;
    void note_accepted_share(const std::string& address, const std::string& worker, double credited,
                             double share_difficulty) override;
    void note_rejected_share(const std::string& address, const std::string& worker) override;
    void attach_worker(const std::string& address, const std::string& worker) override;
    // Seed the per-worker registry from a prior run's users/ files, decaying each worker's hashrate
    // windows by the file's age. Call once at startup before serving.
    void recover_user_stats();
    void on_block_found(stratum::Session& session, const stratum::Job& job,
                        const stratum::ShareResult& result) override;
    bool vardiff_enabled() const override { return config_.variable_difficulty; }
    double min_difficulty() const override { return config_.minimum_difficulty; }
    double max_difficulty() const override { return config_.maximum_difficulty; }
    double vardiff_target_shares_per_minute() const override {
        return config_.vardiff_target_shares_per_minute;
    }
    int vardiff_retarget_seconds() const override { return config_.vardiff_retarget_seconds; }
    uint32_t version_mask() const override { return config_.version_rolling_mask; }

    uint64_t accepted_shares() const { return accepted_shares_.load(); }
    uint64_t blocks_found() const { return blocks_found_.load(); }
    bitcoin::Network network() const { return network_; }

    std::string next_job_id();

private:
    struct Client {
        std::shared_ptr<stratum::Connection> connection;
        std::shared_ptr<stratum::Session> session;
    };

    // A solved block awaiting (or being re-tried for) submission.
    struct PendingBlock {
        int64_t height;
        std::string hash;
        std::string hex;
        std::string address; // payout address (block attribution)
        std::string worker;  // full username, pre-sanitized for logging
    };

    // Both take the template BY VALUE and move it into the Job, which steals the multi-MB tx blob.
    void build_and_broadcast(bitcoin::BlockTemplate block_template, bool clean);
    std::shared_ptr<stratum::Job> make_job(bitcoin::BlockTemplate block_template, bool clean);
    enum class PublishOutcome { Published, Duplicate, StaleHeight, StalePrevhash };
    PublishOutcome broadcast_job(const std::shared_ptr<const stratum::Job>& job, bool clean,
                                 bool require_new_prevhash = false);
    Bytes next_extranonce1();
    void write_stats();
    void spool_block(const PendingBlock& block);

    Config config_;
    bitcoin::RpcClient& rpc_;
    bitcoin::Network network_ = bitcoin::Network::Regtest;
    std::string chain_name_ = "regtest";
    Bytes donation_script_;

    // mutex_ guards: clients_, blocks_by_address_, last_prevhash_, and the template bookkeeping
    // below (has_template_/last_template_time_/last_version_/fastblock_pending_). blocks_by_address_
    // and last_prevhash_ are under mutex_, NOT jobs_mutex_, despite sitting next to its fields.
    mutable std::mutex mutex_;
    std::vector<std::shared_ptr<Client>> clients_;
    // jobs_mutex_ (shared) guards ONLY the job cache: current_job_, recent_jobs_, recent_order_,
    // publish_counter_.
    mutable std::shared_mutex jobs_mutex_;
    std::shared_ptr<const stratum::Job> current_job_;
    std::map<std::string, std::shared_ptr<const stratum::Job>> recent_jobs_;
    std::deque<std::string> recent_order_;
    uint64_t publish_counter_ = 0; // publication order stamped onto each published job
    std::map<std::string, uint64_t> blocks_by_address_; // guarded by mutex_ (not jobs_mutex_)
    std::string last_prevhash_;                         // guarded by mutex_ (not jobs_mutex_)

    std::atomic<uint64_t> job_counter_{0};
    uint32_t job_id_prefix_ = 0;
    std::atomic<uint64_t> extranonce1_counter_{0};
    std::atomic<uint64_t> accepted_shares_{0};
    std::atomic<uint64_t> rejected_shares_{0};
    std::atomic<uint64_t> blocks_found_{0};
    std::atomic<int64_t> last_block_found_{0}; // wall epoch of the most recent accepted block

    std::atomic<bool> generator_ready_{false};
    std::atomic<bool> connector_ready_{false};
    std::atomic<int64_t> chain_blocks_{-1};
    int64_t started_ = 0;
    double started_steady_ = 0.0;

    double last_template_time_ = 0.0;
    std::atomic<double> total_share_difficulty_{0.0};
    double baseline_difficulty_ = 0.0;
    double baseline_best_difficulty_ = 0.0;
    // Pool-wide best share (actual hash difficulty), ratcheted monotonically on every accepted
    // share so snapshot() reports best_share without walking the registry and a prune that drops
    // the max row can't lower the pool best.
    std::atomic<double> best_difficulty_runtime_{0.0};

    mutable std::mutex stats_mutex_; // guards the two DecayingWindows below
    stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate_windows_;
    stats::DecayingWindows<stats::kSpsWindows.size()> sps_windows_;

    struct WorkerStat {
        stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate;
        uint64_t shares_accepted = 0;
        uint64_t shares_rejected = 0;
        double best_difficulty = 0.0; // max ACTUAL hash difficulty met (not the credited target)
        int64_t last_share_ts = 0;    // wall epoch of the last accepted share (DISPLAYED)
        int64_t last_activity_ts = 0; // wall epoch of the last attach/accept/reject (prune clock)
        explicit WorkerStat(double start)
            : hashrate(std::span<const int, stats::kHashrateWindows.size()>(stats::kHashrateWindows),
                       start) {}
    };
    mutable std::mutex user_stats_mutex_;
    std::map<std::string, std::map<std::string, WorkerStat>> user_stats_; // address -> worker
    WorkerStat* worker_entry(const std::string& address, const std::string& worker);
    std::string resolve_worker_key(const std::map<std::string, WorkerStat>& workers,
                                   const std::string& worker) const;
    void prune_user_stats(const std::vector<std::pair<std::string, std::string>>& live);

    bool has_template_ = false;
    uint32_t last_version_ = 0;
    std::string empty_commitment_;
    bool fastblock_pending_ = false;

    std::atomic<double> last_broadcast_steady_{0.0};

    std::mutex wakeup_mutex_;
    std::condition_variable_any wakeup_cv_;
    bool new_block_flag_ = false;

    void submit_block(const PendingBlock& block);
    void submit_loop(const std::stop_token& stop);
    std::mutex submit_mutex_;
    std::condition_variable_any submit_cv_;
    std::deque<PendingBlock> submit_queue_;
    std::jthread submit_thread_;
};

// Whether one-block-ahead empty work is sound for the notified tip. confirmations == 1 (from
// getblockheader) proves the notified hash IS the active tip now; >= 2 or -1 would build on a
// superseded parent. Pure (exposed for tests).
bool fastblock_eligible(bool has_template, bool fastblock_pending, const std::string& notified_tip,
                        const std::string& last_prevhash, int64_t next_height,
                        int64_t confirmations, const std::string& chain_name);

// Consensus GetBlockSubsidy: 50 BTC halved every `halving_interval`, zero after 64 halvings.
uint64_t block_subsidy(int64_t height, int64_t halving_interval);

} // namespace erikslund
