#pragma once
// Point-in-time copy of everything the HTTP API serializes; gathered under Pool's locks.
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace erikslund::api {

struct ClientSnapshot {
    std::string address;
    std::string worker;
    std::string peer;
    std::string user_agent;
    double difficulty = 0.0;
    double best_difficulty = 0.0;
    double total_share_diff = 0.0;
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    int64_t last_share_ts = 0;
    int64_t connected_for = 0;
    bool subscribed = false;
    bool authorized = false;
    // Decaying diff/s per window, aligned with stats::kHashrateWindows.
    std::array<double, 7> hashrate_windows{};
};

// One persistent (address, worker-name) registry row; survives disconnect and restart.
// `connected` is true while any live session is mining under this name.
struct WorkerSnapshot {
    std::string address;
    std::string worker; // "" = bare-address bucket (overflow + unnamed workers)
    bool connected = false;
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    double best_difficulty = 0.0;
    int64_t last_share_ts = 0;             // wall epoch (DISPLAYED)
    std::array<double, 7> hashrate_windows{}; // diff/s per window, aged to snapshot time
};

struct PoolSnapshot {
    // identity / readiness
    std::string version;
    std::string chain;
    std::string rpc_url;
    int pid = 0;
    int64_t starttime = 0;
    int64_t uptime = 0;
    bool generator_ready = false;
    bool stratifier_ready = false;
    bool connector_ready = false;
    bool ready = false;

    // pool-wide stats
    std::optional<int64_t> height;
    std::optional<double> network_diff;
    std::optional<std::string> current_job;
    size_t connected = 0;
    size_t users = 0;
    uint64_t blocks_found = 0;
    int64_t last_block_found = 0; // epoch (UTC seconds) of the most recent accepted block; 0 = none
    // Accepted blocks per payout address (for the per-user stats files).
    std::map<std::string, uint64_t> blocks_by_address;
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    double accepted_diff = 0.0;
    double best_share = 0.0;
    double hashrate_estimate = 0.0;
    // Decaying rates per window, aligned with stats::kHashrateWindows / kSpsWindows.
    std::array<double, 7> hashrate_windows{};
    std::array<double, 4> sps_windows{};

    // stratifier view
    uint64_t jobs_created = 0;
    size_t recent_jobs_cached = 0;
    std::optional<int> txns_in_job;
    std::optional<size_t> merkle_branch_len;

    // generator view
    bool bitcoind_reachable = false;
    std::optional<int64_t> tip_height;
    std::optional<int64_t> last_template_age_sec;
    // RPC failover endpoints (index 0 = primary) + the active index. URLs may carry creds: redact.
    std::vector<std::string> bitcoind_nodes;
    size_t bitcoind_active_index = 0;

    std::vector<ClientSnapshot> clients;
    // Persistent per-worker registry rows; users/<address> files render from these, so a worker
    // still shows (hashrate decaying) after it disconnects.
    std::vector<WorkerSnapshot> workers;
};

} // namespace erikslund::api
