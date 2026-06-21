#include "pool/pool.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <exception>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <random>
#include <set>
#include <string_view>
#include <thread>
#include <utility>

#include "bitcoin/address.hpp"
#include "bitcoin/block_template.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"
#include "core/version.hpp"
#include "stats/poolstatus.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/sha256.hpp"

namespace erikslund {

namespace {
// Late-share window: how many superseded jobs still accept shares. Jobs rotate every ~30s, so the
// depth must cover a mean block interval or a still-valid same-tip share false-rejects as stale.
// 24 x 30s = 12 min. Each job retains its tx data (up to ~4MB mainnet), so ~96MB worst-case.
constexpr size_t kMaxRecentJobs = 24;

// How long a disconnected, never-mined registry row (authorize-only) lingers before prune evicts
// it -- applied REGARDLESS of user_stats_retention_days so authorize-churn can't pin the registry
// cap forever under a keep-forever (retention <= 0) setting.
constexpr int64_t kGhostRowGraceSeconds = 3600;

// Cheap shape gate on usernames before attempting the full address decode.
constexpr std::string_view kAddressChars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";

bool plausible_address(const std::string& address) {
    return !address.empty() && address.size() <= 100 &&
           address.find_first_not_of(kAddressChars) == std::string::npos;
}

// (address, worker) joined with a NUL separator (can occur in neither field) for the
// connected-set keys.
std::string worker_key(const std::string& address, const std::string& worker) {
    std::string key = address;
    key += '\0';
    key += worker;
    return key;
}

enum class SubmitOutcome { Accepted, AlreadyKnown, Rejected };
SubmitOutcome classify_submit(const std::optional<std::string>& rejection) {
    if (!rejection || *rejection == "inconclusive")
        return SubmitOutcome::Accepted;
    if (*rejection == "duplicate" || *rejection == "duplicate-inconclusive")
        return SubmitOutcome::AlreadyKnown;
    return SubmitOutcome::Rejected;
}
} // namespace

Pool::Pool(Config config, bitcoin::RpcClient& rpc)
    : config_(std::move(config)),
      rpc_(rpc),
      started_(static_cast<int64_t>(std::time(nullptr))), // wall: DISPLAYED/STORED
      started_steady_(stats::steady_seconds()),           // monotonic
      // Seed the window clock at start so the first share folds a real interval.
      hashrate_windows_(std::span<const int, stats::kHashrateWindows.size()>(stats::kHashrateWindows),
                        started_steady_),
      sps_windows_(std::span<const int, stats::kSpsWindows.size()>(stats::kSpsWindows),
                   started_steady_) {
    // Per-process random high half of job ids -> unique across restarts/replicas, non-sequential.
    // XOR start time so a degenerate random_device still varies.
    job_id_prefix_ = static_cast<uint32_t>(std::random_device{}()) ^ static_cast<uint32_t>(started_);
    // Empty-block witness commitment: witness merkle root is the all-zero coinbase wtxid, so
    // commitment = sha256d(64 zero bytes).
    empty_commitment_ = "6a24aa21a9ed" + util::to_hex(util::sha256d(Bytes(64, 0)));
    submit_thread_ = std::jthread([this](const std::stop_token& stop) { submit_loop(stop); });
}

void Pool::detect_network() {
    const auto info = rpc_.getblockchaininfo();
    const std::string chain = info.value("chain", "regtest");
    const auto detected = bitcoin::network_from_string(chain);
    if (!detected)
        log::warning("Unrecognized bitcoind chain '{}'; using regtest address rules -- "
                     "donation/payout addresses for other networks will be rejected", chain);
    network_ = detected.value_or(bitcoin::Network::Regtest);
    chain_name_ = chain; // raw chain string for display (keeps testnet3 vs testnet4 distinct)
    chain_blocks_.store(info.value("blocks", int64_t{0}));
    generator_ready_.store(true);
    log::info("Connected to bitcoind: chain={} blocks={}", chain, info.value("blocks", 0));

    if (config_.donation_percent > 0.0 && !config_.donation_address.empty()) {
        try {
            donation_script_ = bitcoin::address_to_script(config_.donation_address, network_);
            log::info("Donation enabled: {}% of each block to {}", config_.donation_percent,
                        config_.donation_address);
        } catch (const std::exception& e) {
            log::warning("Donation disabled: invalid donation_address '{}': {}",
                         config_.donation_address, e.what());
        }
    }
}

void Pool::set_connector_ready(bool ready) {
    connector_ready_.store(ready);
}

std::string Pool::next_job_id() {
    return std::format("{:08x}{:08x}", job_id_prefix_, ++job_counter_);
}

Bytes Pool::next_extranonce1() {
    const uint64_t value = ++extranonce1_counter_;
    Bytes extranonce1(config_.extranonce1_size, 0);
    for (size_t i = 0; i < extranonce1.size(); ++i)
        extranonce1[extranonce1.size() - 1 - i] = uint8_t(value >> (8 * i));
    return extranonce1;
}

Pool::PublishOutcome Pool::broadcast_job(const std::shared_ptr<const stratum::Job>& job, bool clean,
                                         bool require_new_prevhash) {
    {
        const std::unique_lock<std::shared_mutex> lock(jobs_mutex_);
        // Suppress a broadcast byte-identical to the current job, atomically with publishing, so
        // the GBT refresh and ZMQ fastblock can't race into re-issuing the same work (which would
        // reset every miner to extranonce2=0).
        if (current_job_ && current_job_->work_signature() == job->work_signature())
            return PublishOutcome::Duplicate;
        // Height monotonicity, atomic with publication: never let a lower-height job replace a
        // higher one. build_and_broadcast pre-checks this unlocked, so a concurrent fastblock can
        // publish a higher job in the gap; this re-check stops the lagging GBT yanking miners back.
        if (current_job_ && job->height() < current_job_->height())
            return PublishOutcome::StaleHeight;
        // Fastblock-only: if a concurrent GBT already published a full job for this tip, replacing
        // it with empty work would throw the fees away. Atomic with publication closes the race.
        if (require_new_prevhash && current_job_ &&
            current_job_->prevhash_stratum() == job->prevhash_stratum())
            return PublishOutcome::StalePrevhash;
        // Stamp publication order (atomic with the publish decision); sessions use it to drop a
        // notify already superseded by a newer publication.
        job->set_publish_seq(++publish_counter_);
        current_job_ = job;
        recent_jobs_[job->job_id()] = job;
        recent_order_.push_back(job->job_id());
        while (recent_order_.size() > kMaxRecentJobs) {
            recent_jobs_.erase(recent_order_.front());
            recent_order_.pop_front();
        }
    }
    std::vector<std::shared_ptr<Client>> recipients;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        recipients = clients_;
    }
    for (const auto& client : recipients)
        client->session->send_notify(*job, clean);
    return PublishOutcome::Published;
}

std::shared_ptr<stratum::Job> Pool::make_job(bitcoin::BlockTemplate block_template, bool clean) {
    return std::make_shared<stratum::Job>(
        next_job_id(), std::move(block_template),
        Bytes(config_.coinbase_signature.begin(), config_.coinbase_signature.end()),
        config_.extranonce1_size, config_.extranonce2_size, config_.coinbase_version, clean,
        donation_script_, config_.donation_percent);
}

void Pool::build_and_broadcast(bitcoin::BlockTemplate block_template, bool clean) {
    // Height monotonicity: a template BELOW the current job's height comes from a lagging node;
    // broadcasting it would yank miners onto an orphan-doomed parent. Honest recovery always
    // arrives at an equal-or-greater height, so skipping strictly-lower templates can't pin miners.
    if (const auto current = current_job();
        current && block_template.height < current->height()) {
        log::warning("Ignoring a GBT at height {} below the current job's height {} "
                     "(lagging bitcoind?); keeping the current work",
                     block_template.height, current->height());
        return;
    }

    // Copy what the bookkeeping/logs below need BEFORE the move: make_job pilfers the template's
    // tx blob, leaving it partially moved-from.
    const int64_t height = block_template.height;
    const uint32_t version = block_template.version;
    const uint32_t txn_count = block_template.txn_count;
    const std::string prevhash = block_template.previousblockhash;

    const auto job = make_job(std::move(block_template), clean);

    const PublishOutcome outcome = broadcast_job(job, clean);
    if (outcome == PublishOutcome::StaleHeight) {
        log::warning("Ignoring a GBT at height {} below the current job's height (lagging "
                     "bitcoind?); keeping the current work",
                     height);
        return;
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        last_prevhash_ = prevhash;
        last_template_time_ = stats::steady_seconds(); // monotonic
        last_version_ = version;
        has_template_ = true;
        fastblock_pending_ = false; // a fresh GBT supersedes the fastblock empty job
    }
    last_broadcast_steady_.store(stats::steady_seconds());

    if (outcome == PublishOutcome::Published)
        log::debug("New job {} height={} txns={} clean={}", job->job_id(), height, txn_count,
                   clean);
    else
        log::debug("Work unchanged; not rebroadcasting a duplicate (job {})", job->job_id());
}

bool fastblock_eligible(bool has_template, bool fastblock_pending, const std::string& notified_tip,
                        const std::string& last_prevhash, int64_t next_height,
                        int64_t confirmations, const std::string& chain_name) {
    if (!has_template || fastblock_pending)
        return false;
    if (notified_tip == last_prevhash) // the GBT already advanced to this tip
        return false;
    // The notified hash must be the active tip now: a stale notification (>= 2) or reorged-away
    // one (-1) would put miners on a superseded parent.
    if (confirmations != 1)
        return false;
    if (next_height % 2016 == 0) // difficulty retarget -> the new tip's nBits don't apply
        return false;
    // Testnet's 20-minute rule makes required nBits depend on the new block's timestamp at every
    // height, so reusing the new tip's nBits can mint bad-diffbits work.
    if (chain_name == "test" || chain_name == "testnet4")
        return false;
    return true;
}

uint64_t block_subsidy(int64_t height, int64_t halving_interval) {
    const int64_t halvings = halving_interval > 0 ? height / halving_interval : 0;
    if (halvings >= 64)
        return 0;
    return 5000000000ULL >> halvings;
}

void Pool::on_zmq_block(const std::string& block_hash_display) {
    if (config_.fast_block_notify && !block_hash_display.empty()) {
        // Cheap precheck (no RPC); the authoritative check repeats below. Gating testnet here
        // avoids a pointless header fetch per block where fastblock is permanently ineligible.
        bool maybe_eligible = false;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            maybe_eligible = has_template_ && !fastblock_pending_ &&
                             block_hash_display != last_prevhash_ && chain_name_ != "test" &&
                             chain_name_ != "testnet4";
        }
        if (maybe_eligible) {
            try {
                // One header fetch grounds the empty job in consensus: the true next height (BIP34
                // coinbase height + exact subsidy across halvings), confirmations == 1 (active
                // tip), the new tip's nBits, and its median-time-past for the ntime floor.
                const auto header = rpc_.getblockheader(block_hash_display); // RPC: off the lock
                const int64_t next_height = header.at("height").get<int64_t>() + 1;
                const int64_t confirmations = header.value("confirmations", int64_t{-1});
                const std::string bits_hex = header.at("bits").get<std::string>();
                const uint32_t mediantime = header.at("mediantime").get<uint32_t>();

                bool eligible = false;
                uint32_t version = 0;
                int64_t halving_interval = 210000;
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    eligible = fastblock_eligible(has_template_, fastblock_pending_,
                                                  block_hash_display, last_prevhash_, next_height,
                                                  confirmations, chain_name_);
                    if (eligible) {
                        version = last_version_;
                        halving_interval = chain_name_ == "regtest" ? 150 : 210000;
                        fastblock_pending_ = true;
                    }
                }
                if (eligible) {
                    nlohmann::json empty;
                    empty["height"] = next_height;
                    empty["version"] = version;
                    // ntime must exceed the new tip's MTP; floor at MTP+1 so neither a lagging host
                    // clock nor a frozen-clock chain can synthesize a "time-too-old" block.
                    empty["curtime"] =
                        std::max(static_cast<uint32_t>(std::time(nullptr)), mediantime + 1);
                    empty["bits"] = bits_hex;
                    empty["coinbasevalue"] = block_subsidy(next_height, halving_interval);
                    empty["previousblockhash"] = block_hash_display;
                    empty["default_witness_commitment"] = empty_commitment_;
                    empty["transactions"] = nlohmann::json::array();

                    auto block_template = bitcoin::BlockTemplate::from_json(empty);
                    const auto job = make_job(std::move(block_template), /*clean=*/true);
                    const auto outcome =
                        broadcast_job(job, /*clean=*/true, /*require_new_prevhash=*/true);
                    if (outcome == PublishOutcome::Published) {
                        last_broadcast_steady_.store(stats::steady_seconds());
                        log::debug("Fastblock: empty work for height {} on new block {}",
                                   next_height, block_hash_display);
                    } else {
                        // Suppressed: release the pending latch so the next ZMQ notify isn't
                        // blocked waiting for a GBT to reset it.
                        const std::lock_guard<std::mutex> lock(mutex_);
                        fastblock_pending_ = false;
                    }
                }
            } catch (const std::exception& e) {
                log::warning("Fastblock failed: {}", e.what());
            }
        }
    }
    notify_new_block();
}

void Pool::refresh_work(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        try {
            // A mainnet template is multi-MB; fetching it every poll just to read
            // previousblockhash is ~25MB/s of allocator churn (OOMs a 512MB host). Gate the heavy
            // call on a ~100-byte tip probe: fetch only when the tip moved, a rebroadcast is due,
            // or we have no work at all.
            const bool refresh_due =
                stats::steady_seconds() - last_broadcast_steady_.load() >=
                config_.work_rebroadcast_seconds;
            const auto job = current_job();
            bool fetch = refresh_due || job == nullptr;
            if (!fetch) {
                const std::string tip = rpc_.getbestblockhash();
                generator_ready_.store(true);
                if (!job->mines_on(tip)) {
                    fetch = true;
                } else {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    fetch = tip != last_prevhash_;
                }
            }
            if (fetch) {
                // simdjson-direct parse: the multi-MB template parses straight into the compact
                // BlockTemplate (no nlohmann DOM), then MOVED through make_job into the Job.
                auto block_template = rpc_.getblocktemplate_parsed();
                generator_ready_.store(true);
                bool new_block = false;
                {
                    const std::lock_guard<std::mutex> lock(mutex_);
                    new_block = block_template.previousblockhash != last_prevhash_;
                }
                build_and_broadcast(std::move(block_template), new_block);
            }
        } catch (const RpcConnectionError& e) {
            // Every endpoint unreachable: un-latch readiness so /health reports degraded (it
            // re-latches on the next successful RPC).
            generator_ready_.store(false);
            log::warning("Work refresh failed: {}", e.what());
        } catch (const std::exception& e) {
            log::warning("Work refresh failed: {}", e.what());
        }
        // Wait poll_interval, but wake immediately on a ZMQ block notification.
        std::unique_lock<std::mutex> wait_lock(wakeup_mutex_);
        wakeup_cv_.wait_for(wait_lock, stop, std::chrono::duration<double>(config_.poll_interval),
                            [this] { return new_block_flag_; });
        new_block_flag_ = false;
    }
}

std::shared_ptr<stratum::Session>
Pool::add_client(std::shared_ptr<stratum::Connection> connection) {
    const std::string peer = connection->peer();
    auto session =
        std::make_shared<stratum::Session>(*this, *connection, next_extranonce1());
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        clients_.push_back(std::make_shared<Client>(Client{std::move(connection), session}));
    }
    log::info("Client connected: {} (extranonce1={})", peer, session->extranonce1_hex());
    return session;
}

void Pool::remove_client(const std::shared_ptr<stratum::Session>& session) {
    const std::lock_guard<std::mutex> lock(mutex_);
    std::erase_if(clients_, [&](const auto& client) { return client->session == session; });
}

size_t Pool::client_count() const {
    const std::lock_guard<std::mutex> lock(mutex_);
    return clients_.size();
}

std::optional<Bytes> Pool::validate_address(const std::string& address) {
    // Validate locally (bech32/base58 checksum + network prefix), deriving the scriptPubKey with
    // no RPC: an invalid-address flood stays cheap and miners can authorize during a bitcoind blip.
    if (!plausible_address(address))
        return std::nullopt;
    try {
        return bitcoin::address_to_script(address, network_);
    } catch (const std::invalid_argument&) {
        return std::nullopt; // malformed or wrong-network address
    }
}

std::shared_ptr<const stratum::Job> Pool::current_job() const {
    const std::shared_lock<std::shared_mutex> lock(jobs_mutex_);
    return current_job_;
}

std::shared_ptr<const stratum::Job> Pool::recent_job(const std::string& job_id) const {
    const std::shared_lock<std::shared_mutex> lock(jobs_mutex_);  // concurrent per-share reads
    const auto it = recent_jobs_.find(job_id);
    return it != recent_jobs_.end() ? it->second : nullptr;
}

std::string Pool::resolve_worker_key(const std::map<std::string, WorkerStat>& workers,
                                     const std::string& worker) const {
    if (workers.contains(worker))
        return worker; // an existing row keeps its key
    const int cap = config_.max_workers_per_address;
    if (!worker.empty() && cap > 0) {
        size_t named = 0;
        for (const auto& [name, _] : workers)
            named += !name.empty();
        if (named >= static_cast<size_t>(cap))
            return ""; // at the cap: this name folds into the bare-address bucket
    }
    return worker;
}

Pool::WorkerStat* Pool::worker_entry(const std::string& address, const std::string& worker) {
    // Caller holds user_stats_mutex_. The "" key is the bare-address bucket: always present-able.
    const auto addr_it = user_stats_.find(address);
    if (addr_it == user_stats_.end() && user_stats_.size() >= stats::kMaxUserFiles)
        return nullptr; // registry address cap (defense-in-depth vs an address-cycling attacker)
    auto& workers = user_stats_[address];
    const std::string key = resolve_worker_key(workers, worker);
    return &workers.try_emplace(key, started_steady_).first->second;
}

void Pool::attach_worker(const std::string& address, const std::string& worker) {
    if (address.empty())
        return;
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const std::lock_guard<std::mutex> lock(user_stats_mutex_);
    if (WorkerStat* stat = worker_entry(address, worker)) // create a zero row if absent
        stat->last_activity_ts = std::max(stat->last_activity_ts, now_wall);
}

void Pool::note_accepted_share(const std::string& address, const std::string& worker,
                               double credited, double share_difficulty) {
    ++accepted_shares_;
    total_share_difficulty_ += credited; // atomic: no per-share mutex_
    // Ratchet the pool-wide best monotonically (CAS loop: atomic<double> has no fetch_max).
    for (double prev = best_difficulty_runtime_.load();
         share_difficulty > prev &&
         !best_difficulty_runtime_.compare_exchange_weak(prev, share_difficulty);)
        ;
    const double now = stats::steady_seconds();       // monotonic: decay clock
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr)); // DISPLAYED
    {
        const std::lock_guard<std::mutex> lock(stats_mutex_);
        hashrate_windows_.add(credited, now);
        sps_windows_.add(1.0, now);
    }
    if (address.empty())
        return;
    const std::lock_guard<std::mutex> lock(user_stats_mutex_);
    WorkerStat* stat = worker_entry(address, worker);
    if (!stat)
        return; // address-capped: counted pool-wide, not per-worker
    stat->hashrate.add(credited, now);
    ++stat->shares_accepted;
    // bestshare is the ACTUAL hash difficulty met, not the credited target (which would
    // systematically under-report it).
    stat->best_difficulty = std::max(stat->best_difficulty, share_difficulty);
    stat->last_share_ts = now_wall;
    stat->last_activity_ts = now_wall;
}

void Pool::note_rejected_share(const std::string& address, const std::string& worker) {
    ++rejected_shares_;
    if (address.empty())
        return;
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const std::lock_guard<std::mutex> lock(user_stats_mutex_);
    if (WorkerStat* stat = worker_entry(address, worker)) {
        ++stat->shares_rejected;
        stat->last_activity_ts = now_wall; // a reject is activity (keeps a live rig out of prune)
    }
}

void Pool::prune_user_stats(const std::vector<std::pair<std::string, std::string>>& live) {
    // Evict worker rows that are idle AND disconnected. A mined row (last_share_ts > 0) ages out
    // only past the retention window (retention_days <= 0 keeps it forever); a never-mined row
    // (authorize-only) ages out after a short grace REGARDLESS of retention. Never evicts a
    // connected worker; a folded live worker resolves to its "" bucket key, protecting that row.
    const int retention_days = config_.user_stats_retention_days;
    const bool retention_on = retention_days > 0;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    const int64_t ghost_cutoff = now - kGhostRowGraceSeconds;
    const int64_t retention_cutoff =
        retention_on ? now - static_cast<int64_t>(retention_days) * 86400 : 0;
    const std::lock_guard<std::mutex> lock(user_stats_mutex_);
    std::set<std::string> connected_keys;
    for (const auto& [address, worker] : live) {
        const auto ai = user_stats_.find(address);
        const std::string key =
            ai != user_stats_.end() ? resolve_worker_key(ai->second, worker) : worker;
        connected_keys.insert(worker_key(address, key));
    }
    for (auto addr_it = user_stats_.begin(); addr_it != user_stats_.end();) {
        auto& workers = addr_it->second;
        for (auto it = workers.begin(); it != workers.end();) {
            const WorkerStat& s = it->second;
            const bool connected =
                connected_keys.contains(worker_key(addr_it->first, it->first));
            bool expired = false;
            if (!connected && s.last_activity_ts > 0) {
                if (s.last_share_ts == 0)
                    expired = s.last_activity_ts < ghost_cutoff; // never mined
                else if (retention_on)
                    expired = s.last_activity_ts < retention_cutoff; // mined, retention on
                // else: mined + keep-forever -> never expired
            }
            if (expired)
                it = workers.erase(it);
            else
                ++it;
        }
        if (workers.empty()) {
            // No rows left: delete the address file NOW so a restart between registry-prune and
            // file-prune can't resurrect the evicted rows.
            std::error_code ec;
            std::filesystem::remove(
                std::filesystem::path(config_.stats_directory) / "users" / addr_it->first, ec);
            addr_it = user_stats_.erase(addr_it);
        } else {
            ++addr_it;
        }
    }
}

void Pool::notify_new_block() {
    {
        const std::lock_guard<std::mutex> lock(wakeup_mutex_);
        new_block_flag_ = true;
    }
    wakeup_cv_.notify_all();
}

void Pool::vardiff_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        const int interval = std::max(5, config_.vardiff_retarget_seconds / 2);
        for (int i = 0; i < interval && !stop.stop_requested(); ++i)
            std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop.stop_requested())
            break;
        std::vector<std::shared_ptr<Client>> clients;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            clients = clients_;
        }
        for (const auto& client : clients) {
            // One client's retarget throwing must not kill the vardiff thread.
            try {
                client->session->maybe_retarget();
            } catch (const std::exception& e) {
                log::warning("vardiff retarget failed for a client: {}", e.what());
            }
        }
    }
}

void Pool::status_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        const double interval = std::max(1.0, config_.status_interval_seconds);
        for (double slept = 0.0; slept < interval && !stop.stop_requested(); slept += 0.5)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        if (stop.stop_requested())
            break;
        write_stats();
        std::string tip;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            tip = last_prevhash_;
        }
        if (!stop.stop_requested())
            rpc_.maybe_failback(tip);
    }
    write_stats(); // final flush so a restart resumes from the latest stats
}

void Pool::recover_stats() {
    if (const auto prior = stats::read_pool_status(config_.stats_directory)) {
        baseline_difficulty_ = prior->accepted_diff;
        baseline_best_difficulty_ = prior->best_share;
        blocks_found_.store(prior->blocks_found);
        last_block_found_.store(prior->last_block_found);
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            blocks_by_address_ = prior->blocks_by_address;
        }
        log::info("Recovered stats from {}/pool/pool.status: accepted_diff={:.0f} best={:.0f} "
                  "blocks_found={}",
                  config_.stats_directory, baseline_difficulty_, baseline_best_difficulty_,
                  prior->blocks_found);
    }
}

void Pool::recover_user_stats() {
    const auto recovered = stats::read_user_stats(config_.stats_directory);
    if (recovered.empty())
        return;
    // The prune clock is the last SHARE time (`lastshare`), NOT the file mtime -- files are
    // rewritten every cycle, so mtime would reset every idle row's retention clock on restart and
    // make evicted data immortal. Skip never-mined rows and rows already past retention.
    const int retention_days = config_.user_stats_retention_days;
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const int64_t cutoff = retention_days > 0 ? now_wall - static_cast<int64_t>(retention_days) * 86400
                                              : std::numeric_limits<int64_t>::min();

    // Two passes so the file-age decay is applied ONCE per resolved key, even when several file
    // rows fold onto the same bucket (lowered max_workers_per_address).
    struct Accum {
        std::array<double, stats::kHashrateWindows.size()> windows{};
        uint64_t shares_accepted = 0;
        uint64_t shares_rejected = 0;
        double best_difficulty = 0.0;
        int64_t last_share_ts = 0;
        double max_age = 0.0;
    };
    std::map<std::string, std::map<std::string, Accum>> by_address;
    for (const auto& rw : recovered) {
        if (rw.address.empty() || rw.last_share_ts == 0 || rw.last_share_ts < cutoff)
            continue;
        auto& keys = by_address[rw.address];
        std::string key = rw.worker; // re-apply the admission cap against the keys seen so far
        if (!key.empty() && !keys.contains(key) && config_.max_workers_per_address > 0) {
            size_t named = 0;
            for (const auto& [name, _] : keys)
                named += !name.empty();
            if (named >= static_cast<size_t>(config_.max_workers_per_address))
                key.clear();
        }
        Accum& a = keys[key];
        for (std::size_t i = 0; i < a.windows.size(); ++i)
            a.windows[i] += rw.hashrate_windows[i];
        a.shares_accepted += rw.shares_accepted;
        a.shares_rejected += rw.shares_rejected;
        a.best_difficulty = std::max(a.best_difficulty, rw.best_difficulty);
        a.last_share_ts = std::max(a.last_share_ts, rw.last_share_ts);
        a.max_age = std::max(a.max_age, rw.file_age_seconds);
    }

    size_t rows = 0;
    const std::lock_guard<std::mutex> lock(user_stats_mutex_);
    for (const auto& [address, keys] : by_address)
        for (const auto& [key, a] : keys) {
            WorkerStat* stat = worker_entry(address, key);
            if (!stat)
                continue; // registry address cap hit during recovery
            stat->shares_accepted += a.shares_accepted;
            stat->shares_rejected += a.shares_rejected;
            stat->best_difficulty = std::max(stat->best_difficulty, a.best_difficulty);
            stat->last_share_ts = std::max(stat->last_share_ts, a.last_share_ts);
            stat->last_activity_ts = std::max(stat->last_activity_ts, a.last_share_ts);
            stat->hashrate.seed(a.windows, started_steady_, a.max_age); // decay by file age, once
            ++rows;
        }
    log::info("Recovered {} worker stat row(s) from {}/users (hashrates decayed by file age)", rows,
              config_.stats_directory);
}

void Pool::write_stats() {
    try {
        // Prune FIRST so an eviction-cycle write doesn't re-publish the just-evicted rows to disk
        // (whose mtime would reset the prune clock on a later restart).
        std::vector<std::shared_ptr<Client>> clients_copy;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            clients_copy = clients_;
        }
        std::vector<std::pair<std::string, std::string>> live;
        for (const auto& client : clients_copy) {
            const auto s = client->session->stats();
            if (!s.address.empty())
                live.emplace_back(s.address, s.worker);
        }
        prune_user_stats(live);

        const auto snap = snapshot(/*include_workers=*/true); // the file writer needs the registry
        stats::write_pool_status(config_.stats_directory, snap);
        stats::write_user_files(config_.stats_directory, snap, stats::kMaxUserFiles,
                                config_.user_stats_retention_days * 86400.0);
    } catch (const std::exception& e) {
        log::warning("Failed to write stats to {}: {}", config_.stats_directory, e.what());
    }
}

void Pool::spool_block(const PendingBlock& block) {
    try {
        const std::filesystem::path dir = std::filesystem::path(config_.stats_directory) / "blocks";
        std::filesystem::create_directories(dir);
        const std::filesystem::path path = dir / std::format("{}_{}.hex", block.height, block.hash);
        // Write to a temp file then rename: a crash or disk-full mid-write must never leave a
        // truncated .hex that looks like a recoverable block.
        const std::filesystem::path temp_path =
            path.string() + ".tmp." + std::to_string(static_cast<long>(::getpid()));
        {
            std::ofstream out(temp_path, std::ios::binary);
            out.exceptions(std::ios::failbit | std::ios::badbit);
            out << block.hex << "\n";
            out.flush();
        }
        if (const int fd = ::open(temp_path.c_str(), O_RDONLY); fd >= 0) {
            ::fsync(fd);
            ::close(fd);
        }
        std::filesystem::rename(temp_path, path);
        log::info("Spooled block to {} (address={} worker={}; recover with: bitcoin-cli "
                    "submitblock <contents>)",
                    path.string(), block.address, block.worker);
    } catch (const std::exception& e) {
        log::error("CRITICAL: could not spool block hex ({}); HEX FOLLOWS: {}", e.what(),
                   block.hex);
    }
}

void Pool::resubmit_spooled_blocks() {
    // bitcoind safely rejects a stale/duplicate block, so a needless resubmit is a harmless no-op;
    // each file is archived after handling so it is never retried.
    const std::filesystem::path dir = std::filesystem::path(config_.stats_directory) / "blocks";
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec))
        return;
    std::vector<std::filesystem::path> spooled;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec))
        if (entry.path().extension() == ".hex")
            spooled.push_back(entry.path());
    for (const auto& path : spooled) {
        std::string block_hex;
        {
            std::ifstream in(path, std::ios::binary);
            block_hex.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        }
        while (!block_hex.empty() && std::isspace(static_cast<unsigned char>(block_hex.back())))
            block_hex.pop_back();
        if (block_hex.empty())
            continue;
        const std::string name = path.filename().string();
        log::warning("Resubmitting block {} spooled by a previous run", name);
        try {
            const auto rejection = rpc_.submitblock(block_hex);
            if (classify_submit(rejection) != SubmitOutcome::Rejected) {
                log::info("Spooled block {} accepted/already known; archiving", name);
                std::filesystem::rename(path, path.string() + ".submitted", ec);
            } else {
                log::warning("Spooled block {} rejected by bitcoind ({}); archiving", name,
                             rejection.value_or("unknown"));
                std::filesystem::rename(path, path.string() + ".rejected", ec);
            }
        } catch (const std::exception& e) {
            log::error("Could not resubmit spooled block {} (bitcoind unreachable: {}); "
                       "leaving it on disk for the next restart",
                       name, e.what());
        }
    }
}

api::PoolSnapshot Pool::snapshot(bool include_workers) const {
    // starttime is the wall epoch (started_); everything else here is a duration.
    const double now_steady = stats::steady_seconds();
    api::PoolSnapshot snapshot;
    snapshot.version = kVersion;
    snapshot.chain = chain_name_;
    snapshot.rpc_url = config_.rpc_url;
    snapshot.bitcoind_nodes = rpc_.endpoint_urls();
    snapshot.bitcoind_active_index = rpc_.active_index();
    snapshot.pid = ::getpid();
    snapshot.starttime = started_;
    snapshot.uptime = static_cast<int64_t>(now_steady - started_steady_);
    snapshot.generator_ready = generator_ready_.load();
    snapshot.connector_ready = connector_ready_.load();
    snapshot.bitcoind_reachable = snapshot.generator_ready;
    snapshot.blocks_found = blocks_found_.load();
    snapshot.last_block_found = last_block_found_.load();
    snapshot.shares_accepted = accepted_shares_.load();
    snapshot.jobs_created = job_counter_.load();

    std::shared_ptr<const stratum::Job> job;
    std::vector<std::shared_ptr<Client>> clients;
    double last_template = 0.0;
    {
        const std::shared_lock<std::shared_mutex> jobs_lock(jobs_mutex_);
        job = current_job_;
        snapshot.recent_jobs_cached = recent_jobs_.size();
    }
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        clients = clients_;
        last_template = last_template_time_;
        snapshot.blocks_by_address = blocks_by_address_;
    }
    {
        const std::lock_guard<std::mutex> lock(stats_mutex_);
        snapshot.hashrate_windows = hashrate_windows_.snapshot(now_steady);
        snapshot.sps_windows = sps_windows_.snapshot(now_steady);
    }
    const double total_difficulty = total_share_difficulty_.load();

    snapshot.stratifier_ready = job != nullptr;
    snapshot.ready = snapshot.generator_ready && snapshot.connector_ready && job != nullptr;
    if (job) {
        snapshot.height = job->height();
        snapshot.current_job = job->job_id();
        snapshot.network_diff = job->network_difficulty();
        snapshot.txns_in_job = job->txn_count();
        snapshot.merkle_branch_len = job->merkle_branch_hex().size();
        snapshot.tip_height = job->height() - 1;
    } else if (chain_blocks_.load() >= 0) {
        snapshot.tip_height = chain_blocks_.load();
    }
    if (last_template > 0.0)
        snapshot.last_template_age_sec = static_cast<int64_t>(now_steady - last_template);

    double best_difficulty = 0.0;
    std::set<std::string> addresses;
    snapshot.clients.reserve(clients.size());
    for (const auto& client : clients) {
        const auto session_stats = client->session->stats();
        api::ClientSnapshot client_snapshot;
        client_snapshot.address = session_stats.address;
        client_snapshot.worker = session_stats.worker;
        client_snapshot.peer = session_stats.peer;
        client_snapshot.user_agent = session_stats.user_agent;
        client_snapshot.difficulty = session_stats.difficulty;
        client_snapshot.best_difficulty = session_stats.best_difficulty;
        client_snapshot.total_share_diff = session_stats.total_share_difficulty;
        client_snapshot.shares_accepted = session_stats.shares_accepted;
        client_snapshot.shares_rejected = session_stats.shares_rejected;
        client_snapshot.last_share_ts = session_stats.last_share_timestamp;
        client_snapshot.connected_for = session_stats.connected_for; // monotonic duration
        client_snapshot.subscribed = session_stats.subscribed;
        client_snapshot.authorized = session_stats.authorized;
        client_snapshot.hashrate_windows = session_stats.hashrate_windows;
        best_difficulty = std::max(best_difficulty, session_stats.best_difficulty);
        if (!session_stats.address.empty())
            addresses.insert(session_stats.address);
        snapshot.clients.push_back(std::move(client_snapshot));
    }
    // Sample the persistent registry into snapshot.workers ONLY for the stats-file writer; the HTTP
    // path skips this O(registry) walk under the share lock. (best_share is the runtime scalar.)
    if (include_workers) {
        // Live (address, worker) pairs, resolved to registry keys so a worker folded into the ""
        // bucket still marks that bucket connected.
        std::vector<std::pair<std::string, std::string>> live;
        for (const auto& client : clients) {
            const auto session_stats = client->session->stats();
            if (!session_stats.address.empty())
                live.emplace_back(session_stats.address, session_stats.worker);
        }
        const std::lock_guard<std::mutex> lock(user_stats_mutex_);
        std::set<std::string> connected_keys;
        for (const auto& [address, worker] : live) {
            const auto ai = user_stats_.find(address);
            const std::string key =
                ai != user_stats_.end() ? resolve_worker_key(ai->second, worker) : worker;
            connected_keys.insert(worker_key(address, key));
        }
        for (const auto& [address, workers] : user_stats_)
            for (const auto& [worker, stat] : workers) {
                api::WorkerSnapshot ws;
                ws.address = address;
                ws.worker = worker;
                ws.connected = connected_keys.contains(worker_key(address, worker));
                ws.shares_accepted = stat.shares_accepted;
                ws.shares_rejected = stat.shares_rejected;
                ws.best_difficulty = stat.best_difficulty;
                ws.last_share_ts = stat.last_share_ts;
                ws.hashrate_windows = stat.hashrate.snapshot(now_steady);
                snapshot.workers.push_back(std::move(ws));
            }
    }

    snapshot.connected = clients.size();
    snapshot.users = addresses.size();
    snapshot.shares_rejected = rejected_shares_.load();
    // Pool-wide best: the runtime scalar (survives a registry prune) folded with live clients and
    // the restart baseline.
    snapshot.best_share =
        std::max({best_difficulty, baseline_best_difficulty_, best_difficulty_runtime_.load()});
    snapshot.accepted_diff = baseline_difficulty_ + total_difficulty;
    snapshot.hashrate_estimate =
        snapshot.uptime > 0 ? total_difficulty * stats::kHashesPerDiff1Share /
                                  static_cast<double>(snapshot.uptime)
                            : 0.0;
    return snapshot;
}

bool Pool::ready() const {
    return generator_ready_.load() && connector_ready_.load() && current_job() != nullptr;
}

void Pool::on_block_found(stratum::Session& session, const stratum::Job& job,
                          const stratum::ShareResult& result) {
    // An authorized session always has a payout address (handle_submit gates on auth); value_or is
    // a defensive fallback.
    const std::string address = session.address().value_or("?");
    const std::string worker = session.worker().value_or(""); // empty if the miner sent no worker
    log::info("BLOCK CANDIDATE height={} hash={} diff={:.3f} address={} worker={}", job.height(),
                result.block_hash_hex, result.difficulty, address, worker);
    PendingBlock block{job.height(), result.block_hash_hex,
                       job.build_block_hex(result.legacy_coinbase, result.header), address, worker};
    // Spool before submit so a solved block is never lost if submitblock fails.
    spool_block(block);
    // Hand the slow submitblock RPC to the submit thread: running it here would hold the caller's
    // session mutex across the RPC, stalling that miner's next-work push.
    {
        const std::lock_guard<std::mutex> lock(submit_mutex_);
        submit_queue_.push_back(std::move(block));
    }
    submit_cv_.notify_one();
}

void Pool::submit_block(const PendingBlock& block) {
    try {
        const auto rejection = rpc_.submitblock(block.hex);
        switch (classify_submit(rejection)) {
        case SubmitOutcome::Accepted:
            ++blocks_found_;
            last_block_found_.store(static_cast<int64_t>(std::time(nullptr))); // wall: DISPLAYED
            if (!block.address.empty()) {
                const std::lock_guard<std::mutex> lock(mutex_);
                ++blocks_by_address_[block.address];
            }
            log::info("BLOCK ACCEPTED height={} hash={} address={} worker={}", block.height,
                        block.hash, block.address, block.worker);
            break;
        case SubmitOutcome::AlreadyKnown:
            // Already in a chain (self-fastblock + GBT double-submit, or a retry) -- a win, not a
            // rejection; don't log an error or re-count it.
            log::info("Block {} already known (submitblock: {})", block.hash,
                      rejection.value_or("duplicate"));
            break;
        case SubmitOutcome::Rejected:
            log::error("Block {} REJECTED by bitcoind: {}", block.hash,
                       rejection.value_or("unknown"));
            break;
        }
    } catch (const std::exception& e) {
        log::error("submitblock failed: {}", e.what());
    }
}

void Pool::submit_loop(const std::stop_token& stop) {
    std::unique_lock<std::mutex> lock(submit_mutex_);
    while (true) {
        submit_cv_.wait(lock, stop, [this] { return !submit_queue_.empty(); });
        while (!submit_queue_.empty()) {
            const PendingBlock block = std::move(submit_queue_.front());
            submit_queue_.pop_front();
            lock.unlock();
            submit_block(block); // RPC off the lock
            lock.lock();
        }
        if (stop.stop_requested())
            return; // drained; any still-queued block remains spooled to disk
    }
}

} // namespace erikslund
