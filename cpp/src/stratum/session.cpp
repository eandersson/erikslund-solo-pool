#include "stratum/session.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <ctime>
#include <format>
#include <optional>
#include <stdexcept>

#include "core/logging.hpp"
#include "util/difficulty.hpp"
#include "util/hex.hpp"

namespace erikslund::stratum {

namespace {
// Append `value` lowercased (no padding). For length-meaningful fields (job_id, and extranonce2
// which goes raw into the coinbase, so "ab" != "00ab") a short value must NOT collapse onto a
// valid full-width one.
void append_lower(std::string& out, std::string_view value) {
    for (char c : value)
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
}

// Append `value` lowercased and left-zero-padded to `width` hex chars. ONLY for fixed-width
// 4-byte fields (ntime/nonce/version), where a leading-zero spelling IS the same value.
void append_canonical_hex(std::string& out, std::string_view value, size_t width) {
    if (value.size() < width)
        out.append(width - value.size(), '0');
    append_lower(out, value);
}
} // namespace

double vardiff_next(double current, double shares_per_minute, double target, double min_difficulty,
                    double max_difficulty) {
    const double difficulty_cap = max_difficulty > 0.0 ? max_difficulty : 1e12;
    if (shares_per_minute > target * 2.0 && current < difficulty_cap)
        return std::min(difficulty_cap, current * 2.0);
    if (shares_per_minute < target / 2.0)
        return std::max(min_difficulty, current / 2.0);
    return current;
}

std::optional<double> clamp_suggested_difficulty(double suggested, double min_difficulty,
                                                 double max_difficulty) {
    if (!std::isfinite(suggested) || suggested <= 0.0)
        return std::nullopt;
    double clamped = std::max(suggested, min_difficulty);
    if (max_difficulty > 0.0)
        clamped = std::min(clamped, max_difficulty);
    return clamped;
}

Session::Session(PoolContext& pool, Connection& connection, Bytes extranonce1)
    : pool_(pool),
      connection_(connection),
      extranonce1_(std::move(extranonce1)),
      extranonce1_hex_(util::to_hex(extranonce1_)),
      difficulty_(pool.start_difficulty()),
      connected_at_(static_cast<int64_t>(std::time(nullptr))), // wall: DISPLAYED
      connected_at_steady_(stats::steady_seconds()),           // monotonic
      last_retarget_(connected_at_steady_),                    // monotonic
      // Seed the window clock at connect time so the first share folds a real interval.
      hashrate_(std::span<const int, stats::kHashrateWindows.size()>(stats::kHashrateWindows),
                connected_at_steady_) {
    min_difficulty_ = pool.min_difficulty();
    difficulty_ = std::max(difficulty_, min_difficulty_);
}

void Session::maybe_retarget() {
    const std::scoped_lock lock(mutex_);
    if (!pool_.vardiff_enabled() || !authorized_)
        return;
    const double now = stats::steady_seconds(); // monotonic
    const double elapsed = now - last_retarget_;
    if (elapsed < pool_.vardiff_retarget_seconds())
        return;

    const double shares_per_minute =
        elapsed > 0.0 ? (static_cast<double>(shares_since_retarget_) / elapsed) * 60.0 : 0.0;
    const double new_difficulty =
        vardiff_next(difficulty_, shares_per_minute, pool_.vardiff_target_shares_per_minute(),
                     min_difficulty_, pool_.max_difficulty());

    shares_since_retarget_ = 0;
    last_retarget_ = now;
    if (new_difficulty != difficulty_) {
        begin_difficulty_change(new_difficulty);
        do_send_set_difficulty();
        if (log::level() <= log::Level::Debug)
            log::debug("Vardiff {} -> {} ({:.1f} shares/min)", connection_.peer(),
                       util::format_difficulty(new_difficulty), shares_per_minute);
    }
}

Session::SessionStats Session::stats() const {
    const std::scoped_lock lock(mutex_);
    SessionStats snapshot;
    snapshot.address = address_.value_or("");
    snapshot.worker = worker_.value_or("");
    snapshot.peer = connection_.peer();
    snapshot.user_agent = user_agent_;
    snapshot.difficulty = difficulty_;
    snapshot.best_difficulty = best_difficulty_;
    snapshot.total_share_difficulty = total_share_difficulty_;
    snapshot.shares_accepted = shares_accepted_;
    snapshot.shares_rejected = shares_rejected_;
    snapshot.last_share_timestamp = last_share_timestamp_; // wall: DISPLAYED
    snapshot.connected_at = connected_at_;                 // wall: DISPLAYED
    const double now_steady = stats::steady_seconds();     // monotonic
    snapshot.connected_for = static_cast<int64_t>(now_steady - connected_at_steady_);
    snapshot.subscribed = subscribed_;
    snapshot.authorized = authorized_;
    snapshot.hashrate_windows = hashrate_.snapshot(now_steady);
    return snapshot;
}

void Session::send(const json& message) {
    connection_.send_line(message.dump());
}

void Session::send_result(const json& id, json result) {
    send(make_result(id, std::move(result)));
}

void Session::send_result(const json& id, bool result) {
    connection_.send_line(make_result_line(id, result));
}

void Session::send_error(const json& id, const StratumError& error) {
    // Count only client-misbehaviour errors toward the disconnect budget; normal-mining races
    // (stale/duplicate/low-difficulty) must never count.
    if (error.code == ERR_OTHER.code || error.code == ERR_UNAUTHORIZED.code ||
        error.code == ERR_NOT_SUBSCRIBED.code)
        ++protocol_errors_;
    connection_.send_line(make_error_line(id, error));
}

const Session::Coinbase2Cache& Session::coinbase2_for(const Job& job) {
    if (!payout_script_)
        throw std::logic_error("coinbase2_for called before payout_script_ was set");
    if (!coinbase2_cache_ || coinbase2_cache_->job_id != job.job_id()) {
        Bytes coinbase2 = job.build_coinbase2(*payout_script_);
        std::string coinbase2_hex = util::to_hex(coinbase2);
        coinbase2_cache_ = {job.job_id(), std::move(coinbase2), std::move(coinbase2_hex)};
    }
    return *coinbase2_cache_;
}

void Session::rotate_seen_shares() {
    // Live set becomes the lookback set (coverage never drops to zero); two-generations-back
    // contents are discarded.
    seen_shares_previous_ = std::move(seen_shares_current_);
    seen_shares_current_.clear(); // moved-from: make it valid-and-empty explicitly
}

bool Session::remember(std::string key) {
    if (seen_shares_current_.contains(key) || seen_shares_previous_.contains(key))
        return false;
    if (seen_shares_current_.size() >= kMaxSeenShares)
        rotate_seen_shares();
    seen_shares_current_.insert(std::move(key));
    return true;
}

void Session::handle_line(std::string_view line) {
    // Parse outside the lock: parse_request touches no session state, so only dispatch needs the
    // mutex. Per-share hashing in handle_submit stays under the lock (reads difficulty/dedup set).
    const auto request = parse_request(line);
    if (!request)
        return;
    const std::scoped_lock lock(mutex_);
    dispatch(*request);
}

void Session::dispatch(const Request& request) {
    const std::string& method = request.method;
    if (method == "mining.submit") [[likely]]
        handle_submit(request.id, request.params);
    else if (method == "mining.subscribe")
        handle_subscribe(request.id, request.params);
    else if (method == "mining.authorize")
        handle_authorize(request.id, request.params);
    else if (method == "mining.configure")
        handle_configure(request);
    else if (method == "mining.suggest_difficulty")
        handle_suggest_difficulty(request);
    else if (method == "mining.extranonce.subscribe")
        send_result(request.id, true);
    else if (!request.id.is_null())
        connection_.send_line(make_error_line(request.id, ERR_OTHER));
}

void Session::send_set_difficulty() {
    const std::scoped_lock lock(mutex_);
    do_send_set_difficulty();
}

void Session::do_send_set_difficulty() {
    send(make_notification("mining.set_difficulty", json::array({difficulty_})));
}

void Session::send_notify(const Job& job, bool clean) {
    const std::scoped_lock lock(mutex_);
    do_send_notify(job, clean);
}

void Session::do_send_notify(const Job& job, bool clean) {
    if (!subscribed_ || !authorized_ || !payout_script_)
        return;
    // Publication-order guard: concurrent broadcasters (GBT refresh vs ZMQ fastblock) aren't
    // ordered, so skip any job below what was already delivered (else the miner grinds superseded
    // work). seq 0 = never pool-published (tests / direct sends): always deliver.
    const uint64_t seq = job.publish_seq();
    if (seq != 0) {
        if (seq < last_notified_seq_)
            return;
        last_notified_seq_ = seq;
    }
    const Coinbase2Cache& coinbase2 = coinbase2_for(job);
    // Keep one generation of lookback on a clean job (old jobs still accept shares). Skip when the
    // live set is already empty, else we'd demote the empty set and discard a live generation.
    if (clean && !seen_shares_current_.empty())
        rotate_seen_shares();
    // Fast path: mining.notify fans out per client per broadcast; the json-tree dump dominated the
    // broadcast loop. Byte-identical (doctest-pinned).
    connection_.send_line(make_notify_line(job.job_id(), job.prevhash_stratum(),
                                           job.coinbase1_hex(), coinbase2.coinbase2_hex,
                                           job.merkle_branch_hex(), job.version_hex(),
                                           job.nbits_hex(), job.ntime_hex(), clean));
    // The new difficulty (if any) is now in effect from this job on; stop honoring the old one.
    pending_difficulty_change_ = false;
}

void Session::begin_difficulty_change(double new_difficulty) {
    if (!pending_difficulty_change_)
        previous_difficulty_ = difficulty_;
    difficulty_ = new_difficulty;
    pending_difficulty_change_ = true;
}

void Session::handle_subscribe(const json& id, const std::vector<std::string>& params) {
    if (!params.empty() && !params[0].empty())
        user_agent_ = log::sanitize(params[0]);
    subscribed_ = true;
    const std::string subscription_id = extranonce1_hex_;
    send_result(id, json::array({
                        json::array({json::array({"mining.set_difficulty", subscription_id}),
                                     json::array({"mining.notify", subscription_id})}),
                        extranonce1_hex_,
                        pool_.extranonce2_size(),
                    }));
    // Client authorized BEFORE subscribing (unusual): it has no job yet, so send work now instead
    // of waiting for the next pool broadcast.
    if (authorized_ && payout_script_) {
        do_send_set_difficulty();
        if (auto job = pool_.current_job())
            do_send_notify(*job, /*clean=*/true);
    }
}

void Session::handle_configure(const Request& request) {
    json result = json::object();
    if (request.configure_version_rolling) {
        uint32_t client_mask = 0xffffffff;
        if (request.version_rolling_mask_present) {
            client_mask = 0;
            if (request.version_rolling_mask) {
                const std::string& mask = *request.version_rolling_mask;
                if (!mask.empty() && mask.size() <= 8 &&
                    mask.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
                    client_mask = static_cast<uint32_t>(std::stoul(mask, nullptr, 16));
            }
        }
        version_mask_ = client_mask & pool_.version_mask();
        result["version-rolling"] = version_mask_ != 0;
        result["version-rolling.mask"] = std::format("{:08x}", version_mask_);
    }
    // BIP310: answer every requested extension. Only version-rolling is supported, so report false
    // for anything else (a strict miner may stall waiting otherwise).
    for (const std::string& extension : request.configure_extensions)
        if (extension != "version-rolling" && !result.contains(extension))
            result[extension] = false;
    send_result(request.id, std::move(result));
}

void Session::handle_authorize(const json& id, const std::vector<std::string>& params) {
    if (params.empty() || params[0].empty()) {
        send_error(id, ERR_OTHER);
        return;
    }
    // Stratum username is "<address>[.<worker>]"; only the payout address is validated.
    const std::string username = log::sanitize(params[0]);
    const auto dot = username.find('.');
    std::string address = username.substr(0, dot);

    // Validate into a local FIRST: a failed re-authorize must not overwrite the already-good
    // address_/payout_script_.
    auto script = pool_.validate_address(address);
    if (!script) {
        log::warning("Rejecting worker {}: invalid payout address '{}'", connection_.peer(),
                     address); // already sanitized at ingress
        send_result(id, false);
        return;
    }
    // Re-authorize may change the payout address; the cached coinbase2 is keyed only by job_id,
    // so drop it.
    if (payout_script_ != script)
        coinbase2_cache_.reset();
    address_ = std::move(address);
    // Gate the worker to ASCII from the RAW suffix, not the sanitized one: ascii_only drops
    // non-ASCII so the ASCII-only users/<address> file can't be corrupted, and gating the raw
    // (not sanitized) name keeps worker identity byte-identical to the Python pool.
    const auto raw_dot = params[0].find('.');
    worker_ = raw_dot == std::string::npos ? std::string{}
                                           : log::ascii_only(params[0].substr(raw_dot + 1));
    payout_script_ = std::move(script);
    authorized_ = true;
    // Register the worker so an idle authorized rig shows up (and persists) in the stats even
    // before its first share.
    pool_.attach_worker(*address_, *worker_);
    send_result(id, true);
    log::info("Authorized {} (address={}, user_agent={}, extranonce1={})", connection_.peer(),
              *address_, user_agent_, extranonce1_hex()); // both sanitized at ingress

    do_send_set_difficulty();
    if (auto job = pool_.current_job())
        do_send_notify(*job, /*clean=*/true);
}

void Session::handle_suggest_difficulty(const Request& request) {
    // Advisory: a missing/malformed value is acked but ignored. dispatch() holds mutex_.
    if (request.suggested_difficulty) {
        const auto clamped = clamp_suggested_difficulty(*request.suggested_difficulty,
                                                         min_difficulty_, pool_.max_difficulty());
        if (clamped && *clamped != difficulty_) {
            begin_difficulty_change(*clamped);
            shares_since_retarget_ = 0; // restart the vardiff window at the new baseline
            last_retarget_ = stats::steady_seconds();
            if (subscribed_)
                do_send_set_difficulty();
            log::info("Suggest-difficulty {} -> {}", connection_.peer(),
                      util::format_difficulty(*clamped));
        }
    }
    send_result(request.id, true);
}

void Session::handle_submit(const json& id, const std::vector<std::string>& params) {
    if (!authorized_) [[unlikely]] {
        send_error(id, ERR_UNAUTHORIZED);
        return;
    }
    if (!subscribed_) [[unlikely]] {
        send_error(id, ERR_NOT_SUBSCRIBED);
        return;
    }
    if (params.size() < 5) [[unlikely]] {
        send_error(id, ERR_OTHER);
        return;
    }

    const std::string& job_id = params[1];
    const std::string& extranonce2 = params[2];
    const std::string& ntime = params[3];
    const std::string& nonce = params[4];
    std::optional<std::string> version_bits;
    if (params.size() > 5 && !params[5].empty())
        version_bits = params[5];

    const auto job = pool_.recent_job(job_id);
    if (!job) [[unlikely]] {
        ++shares_rejected_;
        pool_.note_rejected_share(address_.value_or(""), worker_.value_or(""));
        send_error(id, ERR_STALE);
        return;
    }

    if (!remember(make_dedup_key(job_id, extranonce2, ntime, nonce, version_bits))) [[unlikely]] {
        ++shares_rejected_;
        pool_.note_rejected_share(address_.value_or(""), worker_.value_or(""));
        send_error(id, ERR_DUPLICATE);
        return;
    }

    ShareInput input;
    input.coinbase2 = coinbase2_for(*job).coinbase2;
    input.extranonce1 = extranonce1_;
    input.extranonce2_hex = extranonce2;
    input.ntime_hex = ntime;
    input.nonce_hex = nonce;
    const double accept_difficulty =
        pending_difficulty_change_ ? std::min(difficulty_, previous_difficulty_) : difficulty_;
    input.share_target = util::target_from_difficulty(accept_difficulty);
    input.version_bits_hex = version_bits;
    input.version_mask = version_mask_;
    input.now_unix = static_cast<int64_t>(std::time(nullptr));

    const auto result = job->validate_share(input);
    if (!result) {
        ++shares_rejected_;
        pool_.note_rejected_share(address_.value_or(""), worker_.value_or(""));
        if (log::level() <= log::Level::Debug)
            log::debug("Rejected share from {} ({})", address_.value_or(""),
                       reject_reason(result.error().reason));
        send_error(id,
                   result.error().reason == ShareReject::AboveTarget ? ERR_LOW_DIFFICULTY : ERR_OTHER);
        return;
    }

    record_accepted_share(*result);
    send_result(id, true);

    if (result->is_block)
        pool_.on_block_found(*this, *job, *result);
}

void Session::record_accepted_share(const ShareResult& result) {
    // During a difficulty-change grace window, credit the harder of {old, new} only when the hash
    // clears it, else the easier one. Outside a change, credit the current difficulty.
    double credited = difficulty_;
    if (pending_difficulty_change_) {
        const double hi = std::max(difficulty_, previous_difficulty_);
        const double lo = std::min(difficulty_, previous_difficulty_);
        credited = result.difficulty >= hi ? hi : lo;
    }
    const int64_t now_wall = static_cast<int64_t>(std::time(nullptr)); // wall: DISPLAYED
    const double now_steady = stats::steady_seconds();                 // monotonic

    ++shares_accepted_;
    protocol_errors_ = 0; // a valid share clears any accumulated protocol-error budget
    ++shares_since_retarget_;
    total_share_difficulty_ += credited;
    last_share_timestamp_ = now_wall;
    hashrate_.add(credited, now_steady);
    best_difficulty_ = std::max(best_difficulty_, result.difficulty);
    pool_.note_accepted_share(address_.value_or(""), worker_.value_or(""), credited,
                              result.difficulty);
    if (log::level() <= log::Level::Debug)
        log::debug("Accepted share from {} diff {}/{}", address_.value_or(""),
                   util::format_difficulty(result.difficulty), util::format_difficulty(credited));
}

std::string Session::make_dedup_key(const std::string& job_id, std::string_view extranonce2,
                                    std::string_view ntime, std::string_view nonce,
                                    const std::optional<std::string>& version_bits) const {
    // job_id/extranonce2 are length-meaningful -> lowercase only. ntime/nonce/version are 4-byte
    // fields -> pad to 8 so leading-zero spellings collapse. version_mask is part of the work
    // identity (same raw bits under a different mask = a different header), so include it.
    std::string key;
    key.reserve(job_id.size() + extranonce2.size() + 40);
    append_lower(key, job_id);
    key.push_back('|');
    append_lower(key, extranonce2);
    key.push_back('|');
    append_canonical_hex(key, ntime, 8);
    key.push_back('|');
    append_canonical_hex(key, nonce, 8);
    key.push_back('|');
    if (version_bits)
        append_canonical_hex(key, *version_bits, 8);
    key.push_back('|');
    key += std::format("{:08x}", version_mask_);
    return key;
}

} // namespace erikslund::stratum
