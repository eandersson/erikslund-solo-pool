#pragma once
// On-disk pool/user stats; cumulative stats survive a restart.
//   <stats_dir>/pool/pool.status   {pool_stat, hashrate, shares}
//   <stats_dir>/users/<address>    per-address workers / shares / best
#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "api/snapshot.hpp"

namespace erikslund::stats {

// K/M/G/T/P/E-suffixed magnitude.
std::string suffix_string(double value, int significant_digits = 0);
// Inverse of suffix_string ("43.4M" -> 43400000.0; 0.0 for empty/garbage): strtod float prefix,
// then one suffix character.
double parse_suffix(std::string_view text);

// Epoch (UTC seconds) -> RFC 9557 timestamp "2026-06-04T11:31:24Z[UTC]"; "" for epoch <= 0.
std::string format_rfc9557(int64_t epoch);
// Inverse: RFC 9557/3339 UTC timestamp -> epoch (0 if unparseable).
int64_t parse_rfc9557(const std::string& value);

nlohmann::json build_pool_status(const api::PoolSnapshot& snapshot);
// Renders one address's users/<address> object from its registry rows and live connection count.
nlohmann::json build_user_stats(const std::string& address, const api::PoolSnapshot& snapshot);

// One worker row recovered from a users/<address> file at startup; the pool seeds its registry
// from these, decaying each hashrate by file_age_seconds. hashrate_windows is diff/s.
struct RecoveredWorker {
    std::string address;
    std::string worker; // "" for the bare-address bucket
    uint64_t shares_accepted = 0;
    uint64_t shares_rejected = 0;
    double best_difficulty = 0.0;
    int64_t last_share_ts = 0;
    std::array<double, 7> hashrate_windows{};
    double file_age_seconds = 0.0;
};
// Parse every users/<address> file back into worker rows (best effort: a malformed file is
// skipped). Used by restart recovery.
std::vector<RecoveredWorker> read_user_stats(const std::string& stats_directory);

// Cumulative stats recovered from a prior pool.status (survive restart).
struct RecoveredStats {
    double accepted_diff = 0.0;
    double best_share = 0.0;
    uint64_t blocks_found = 0;
    int64_t last_block_found = 0; // epoch (UTC seconds) of the most recent accepted block
    std::map<std::string, uint64_t> blocks_by_address;
};
std::optional<RecoveredStats> read_pool_status(const std::string& stats_directory);

void write_pool_status(const std::string& stats_directory, const api::PoolSnapshot& snapshot);
// max_user_files caps file CREATION only (existing files keep updating), bounding the disk/inode
// growth an address-cycling attacker can force. retention_seconds > 0 prunes files whose mtime is
// older than that (mtime == last activity, since a disconnected miner's file stops being rewritten);
// connected miners are never pruned, and a prune frees the creation-cap slot. Sweep runs at most
// every prune_sweep_seconds. Knobs overridable for tests.
inline constexpr size_t kMaxUserFiles = 100'000;
inline constexpr double kUserPruneSweepSeconds = 3600.0;
void write_user_files(const std::string& stats_directory, const api::PoolSnapshot& snapshot,
                      size_t max_user_files = kMaxUserFiles, double retention_seconds = 0.0,
                      double prune_sweep_seconds = kUserPruneSweepSeconds);

} // namespace erikslund::stats
