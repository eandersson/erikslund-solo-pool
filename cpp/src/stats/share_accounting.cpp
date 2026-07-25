#include "stats/share_accounting.hpp"

#include <algorithm>
#include <ctime>
#include <span>

namespace erikslund::stats {

WorkerAccounting::WorkerAccounting(double start)
    : hashrate_(std::span<const int, kHashrateWindows.size()>(kHashrateWindows), start) {}

void WorkerAccounting::touch(int64_t now_wall) {
    const std::scoped_lock lock(mutex_);
    last_activity_ts_ = std::max(last_activity_ts_, now_wall);
}

void WorkerAccounting::note_accepted(double credited, double share_difficulty) {
    // Read both clocks before locking: they are syscalls on the hottest per-worker path.
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const double now_steady = steady_seconds();
    const std::scoped_lock lock(mutex_);
    hashrate_.add(credited, now_steady);
    ++shares_accepted_;
    best_difficulty_ = std::max(best_difficulty_, share_difficulty);
    last_share_ts_ = std::max(last_share_ts_, now_wall);
    last_activity_ts_ = std::max(last_activity_ts_, now_wall);
}

void WorkerAccounting::note_rejected() {
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr));
    const std::scoped_lock lock(mutex_);
    ++shares_rejected_;
    last_activity_ts_ = std::max(last_activity_ts_, now_wall);
}

WorkerAccountingSnapshot WorkerAccounting::snapshot(double now_steady) const {
    const std::scoped_lock lock(mutex_);
    WorkerAccountingSnapshot out;
    out.shares_accepted = shares_accepted_;
    out.shares_rejected = shares_rejected_;
    out.best_difficulty = best_difficulty_;
    out.last_share_ts = last_share_ts_;
    out.hashrate_windows = hashrate_.snapshot(now_steady);
    return out;
}

std::pair<int64_t, int64_t> WorkerAccounting::activity() const {
    const std::scoped_lock lock(mutex_);
    return {last_activity_ts_, last_share_ts_};
}

void WorkerAccounting::recover(
    uint64_t shares_accepted, uint64_t shares_rejected, double best_difficulty,
    int64_t last_share_ts,
    const std::array<double, kHashrateWindows.size()>& hashrate_windows, double now_steady,
    double age_seconds) {
    const std::scoped_lock lock(mutex_);
    shares_accepted_ += shares_accepted;
    shares_rejected_ += shares_rejected;
    best_difficulty_ = std::max(best_difficulty_, best_difficulty);
    last_share_ts_ = std::max(last_share_ts_, last_share_ts);
    last_activity_ts_ = std::max(last_activity_ts_, last_share_ts);
    hashrate_.seed(hashrate_windows, now_steady, age_seconds);
}

} // namespace erikslund::stats
