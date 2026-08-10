#pragma once
// Protocol-neutral mining client interfaces and statistics.
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "stats/hashrate.hpp"
#include "stats/share_accounting.hpp"

namespace erikslund::stratum {
class Job;
}

namespace erikslund::mining {

class Connection {
public:
    virtual ~Connection() = default;
    virtual std::string peer() const = 0;
};

struct ClientChannelStats {
    std::string address;
    std::string worker;
    double difficulty = 0.0;
    double best_difficulty = 0.0;
    double total_share_difficulty = 0.0;
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    int64_t last_share_timestamp = 0;
    int64_t connected_seconds = 0;
    std::array<double, stats::kHashrateWindows.size()> hashrate_windows{};
    stats::WorkerAccountingHandle worker_accounting;
};

struct ClientStats {
    std::string address;
    std::string worker;
    std::string peer;
    std::string user_agent;
    double difficulty = 0.0;
    double best_difficulty = 0.0;
    double total_share_difficulty = 0.0;
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    int64_t last_share_timestamp = 0;
    int64_t connected_at = 0;
    int64_t connected_seconds = 0;
    bool subscribed = false;
    bool authorized = false;
    std::array<double, stats::kHashrateWindows.size()> hashrate_windows{};
    // One row per channel, so a proxy's miners are reported separately, not merged.
    std::vector<ClientChannelStats> channels;
};

class Client {
public:
    virtual ~Client() = default;
    virtual void publish_job(const stratum::Job& job, bool clean) = 0;
    virtual void maybe_retarget() = 0;
    virtual ClientStats stats(bool include_worker_accounting = false) const = 0;
    virtual bool ever_authorized() const = 0;
    virtual int protocol_errors() const = 0;
    virtual bool should_close() const = 0;
};

} // namespace erikslund::mining
