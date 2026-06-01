#pragma once
// One Session per TCP connection: per-connection protocol state, reaching the pool
// through the Connection and PoolContext interfaces.
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "stats/hashrate.hpp"
#include "stratum/job.hpp"
#include "stratum/message.hpp"
#include "util/bytes.hpp"

namespace erikslund::stratum {

inline constexpr size_t kMaxSeenShares = 16384;

class Session; // for PoolContext::on_block_found
struct SessionTestPeek; // test-only access to private dedup internals

// Outbound side of a connection (socket in prod, recorder in tests).
class Connection {
public:
    virtual ~Connection() = default;
    virtual void send_line(std::string_view line) = 0;
    virtual std::string peer() const = 0;
};

// Everything a session needs from the pool. Implemented by Pool; faked in tests.
class PoolContext {
public:
    virtual ~PoolContext() = default;
    virtual size_t extranonce2_size() const = 0;
    virtual double start_difficulty() const = 0;
    // Payout scriptPubKey for an address, or nullopt if it's invalid.
    virtual std::optional<Bytes> validate_address(const std::string& address) = 0;
    virtual std::shared_ptr<const Job> current_job() const = 0;
    virtual std::shared_ptr<const Job> recent_job(const std::string& job_id) const = 0;
    // Share accounting carries the worker identity for persistent per-worker stats (users/ files).
    // `credited` is the difficulty credited (shares/hashrate); `share_difficulty` is the ACTUAL
    // hash difficulty met (for the per-worker best-share).
    virtual void note_accepted_share(const std::string& address, const std::string& worker,
                                     double credited, double share_difficulty) = 0;
    virtual void note_rejected_share(const std::string& address, const std::string& worker) = 0;
    // Called on a successful authorize so an idle authorized worker appears in (and persists in)
    // the registry with zero stats.
    virtual void attach_worker(const std::string& address, const std::string& worker) {
        (void)address;
        (void)worker;
    }
    virtual void on_block_found(Session& session, const Job& job, const ShareResult& result) = 0;

    // Vardiff + protocol parameters (sourced from Config).
    virtual bool vardiff_enabled() const = 0;
    virtual double min_difficulty() const = 0;
    virtual double max_difficulty() const = 0; // 0 = no maximum
    virtual double vardiff_target_shares_per_minute() const = 0;
    virtual int vardiff_retarget_seconds() const = 0;
    virtual uint32_t version_mask() const = 0;
};

class Session {
public:
    Session(PoolContext& pool, Connection& connection, Bytes extranonce1);

    // Feed one decoded line (no trailing newline). Thread-safe.
    void handle_line(std::string_view line);

    // Thread-safe: work thread pushes work while the read thread may be in a submit.
    void send_set_difficulty();
    void send_notify(const Job& job, bool clean);

    // Thread-safe; called periodically by the pool's vardiff loop.
    void maybe_retarget();

    bool subscribed() const { return subscribed_; }
    bool authorized() const { return authorized_; }
    int protocol_errors() const { return protocol_errors_; }
    const std::string& extranonce1_hex() const { return extranonce1_hex_; }
    double difficulty() const { return difficulty_; }
    uint32_t version_mask() const { return version_mask_; }
    const std::optional<std::string>& address() const { return address_; }
    const std::optional<std::string>& worker() const { return worker_; }
    const std::string& user_agent() const { return user_agent_; }
    uint64_t shares_accepted() const { return shares_accepted_; }
    double best_difficulty() const { return best_difficulty_; }
    std::string peer() const { return connection_.peer(); }

    struct SessionStats {
        std::string address;
        std::string worker;
        std::string peer;
        std::string user_agent;
        double difficulty = 0.0;
        double best_difficulty = 0.0;
        double total_share_difficulty = 0.0;
        uint64_t shares_accepted = 0;
        uint64_t shares_rejected = 0;
        int64_t last_share_timestamp = 0; // wall epoch (DISPLAYED)
        int64_t connected_at = 0;         // wall epoch (DISPLAYED)
        int64_t connected_for = 0;        // monotonic duration in seconds
        bool subscribed = false;
        bool authorized = false;
        // Decaying hashrate (diff/s) per window, aged to snapshot time.
        std::array<double, 7> hashrate_windows{};
    };
    // Thread-safe snapshot of this session's stats (for the HTTP API).
    SessionStats stats() const;

private:
    void dispatch(const Request& request);
    void handle_subscribe(const json& id, const std::vector<std::string>& params);
    void handle_configure(const Request& request);
    void handle_authorize(const json& id, const std::vector<std::string>& params);
    void handle_submit(const json& id, const std::vector<std::string>& params);
    void handle_suggest_difficulty(const Request& request);

    // Caller holds mutex_; the public send_* wrap these.
    void do_send_set_difficulty();
    void do_send_notify(const Job& job, bool clean);

    void begin_difficulty_change(double new_difficulty);

    void send(const json& message);
    void send_result(const json& id, json result);
    void send_result(const json& id, bool result); // fast path: serializes straight to the wire
    void send_error(const json& id, const StratumError& error);

    // Canonical (lowercase, fixed-width) dedup key so different spellings of one share collapse;
    // see make_dedup_key in the .cpp for why it stays an exact string.
    std::string make_dedup_key(const std::string& job_id, std::string_view extranonce2,
                               std::string_view ntime, std::string_view nonce,
                               const std::optional<std::string>& version_bits) const;
    // Apply the share-accounting side effects of a valid share (under mutex_).
    void record_accepted_share(const ShareResult& result);

    // Caches one job's coinbase2 bytes+hex so mining.notify doesn't re-encode per broadcast.
    struct Coinbase2Cache {
        std::string job_id;
        Bytes coinbase2;
        std::string coinbase2_hex;
    };
    const Coinbase2Cache& coinbase2_for(const Job& job);
    bool remember(std::string key);

    friend struct SessionTestPeek; // test-only reach into remember()/the dedup sets

    PoolContext& pool_;
    Connection& connection_;

    Bytes extranonce1_;
    std::string extranonce1_hex_;

    bool subscribed_ = false;
    bool authorized_ = false;
    int protocol_errors_ = 0; // client-misbehaviour errors counted toward the disconnect budget
    std::optional<std::string> address_;
    std::optional<std::string> worker_;
    std::optional<Bytes> payout_script_;

    double difficulty_;
    double min_difficulty_ = 0.0; // vardiff floor
    double previous_difficulty_ = 0.0;
    bool pending_difficulty_change_ = false;
    int64_t connected_at_ = 0;          // wall epoch: DISPLAYED
    double connected_at_steady_ = 0.0;  // monotonic: decay clock + connected_for
    int64_t last_share_timestamp_ = 0;  // wall epoch: DISPLAYED
    double last_retarget_ = 0.0;        // monotonic: retarget interval is a duration
    uint64_t shares_since_retarget_ = 0;
    uint32_t version_mask_ = 0;
    std::string user_agent_ = "?";

    uint64_t shares_accepted_ = 0;
    uint64_t shares_rejected_ = 0;
    double best_difficulty_ = 0.0;
    double total_share_difficulty_ = 0.0;
    // Decaying diff/s per window. Guarded by mutex_ (written on share, read in stats()).
    stats::DecayingWindows<stats::kHashrateWindows.size()> hashrate_;

    std::optional<Coinbase2Cache> coinbase2_cache_;
    std::unordered_set<std::string> seen_shares_current_;
    std::unordered_set<std::string> seen_shares_previous_;
    void rotate_seen_shares();
    // Highest publication seq delivered to this miner (under mutex_); drops out-of-order older
    // jobs so a slow sender can't leave the miner grinding superseded work.
    uint64_t last_notified_seq_ = 0;

    mutable std::mutex mutex_; // serializes handle_line vs. send_* across threads
};

// Pure vardiff decision (exposed for testing). New difficulty clamped to [min, max];
// max 0 = no maximum (defaults to 1e12).
double vardiff_next(double current, double shares_per_minute, double target,
                    double min_difficulty, double max_difficulty);

std::optional<double> clamp_suggested_difficulty(double suggested, double min_difficulty,
                                                 double max_difficulty);

} // namespace erikslund::stratum
