#include "api/metrics.hpp"

#include <algorithm>
#include <cmath>
#include <format>
#include <string>
#include <string_view>

#include "stats/hashrate.hpp"
#include "stats/poolstatus.hpp"
#include "util/url.hpp"

namespace erikslund::api {

namespace {

template <class T>
nlohmann::json or_null(const std::optional<T>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

std::string html_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        switch (c) {
        case '&': out += "&amp;"; break;
        case '<': out += "&lt;"; break;
        case '>': out += "&gt;"; break;
        case '"': out += "&quot;"; break;
        case '\'': out += "&#39;"; break;
        default: out += c;
        }
    }
    return out;
}

// Escape a Prometheus label value: backslash, double-quote, newline (all the format requires).
std::string prom_label(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        default: out += c;
        }
    }
    return out;
}

std::string format_hashrate(double hashes_per_second) {
    static constexpr const char* kUnits[] = {"H/s",  "KH/s", "MH/s", "GH/s",
                                             "TH/s", "PH/s", "EH/s"};
    double value = hashes_per_second;
    for (const char* unit : kUnits) {
        if (value < 1000.0)
            return std::format("{:.2f} {}", value, unit);
        value /= 1000.0;
    }
    return std::format("{:.2f} ZH/s", value);
}

// Thousands-separated integer: 88531 -> "88,531".
std::string group_digits(int64_t value) {
    std::string text = std::to_string(value);
    for (int i = static_cast<int>(text.size()) - 3; i > 0; i -= 3)
        text.insert(static_cast<size_t>(i), ",");
    return text;
}

// Duration from highest non-zero unit down to seconds: 90061 -> "1d 1h 1m 1s".
std::string format_duration(int64_t seconds) {
    if (seconds < 0)
        seconds = 0;
    const int64_t days = seconds / 86400, hours = seconds / 3600 % 24;
    const int64_t minutes = seconds / 60 % 60, secs = seconds % 60;
    if (days)
        return std::format("{}d {}h {}m {}s", days, hours, minutes, secs);
    if (hours)
        return std::format("{}h {}m {}s", hours, minutes, secs);
    if (minutes)
        return std::format("{}m {}s", minutes, secs);
    return std::format("{}s", secs);
}

// Difficulty: abbreviated + raw in parens; sub-1 (regtest) stays {:.4g} (no suffix is meaningful).
std::string format_difficulty(double difficulty) {
    if (difficulty < 1.0)
        return std::format("{:.4g}", difficulty);
    const int64_t raw = static_cast<int64_t>(std::llround(difficulty));
    if (difficulty < 1000.0)
        return group_digits(raw);
    return stats::suffix_string(difficulty) + " (" + group_digits(raw) + ")";
}

} // namespace

std::string build_prometheus(const PoolSnapshot& snapshot) {
    std::string out;
    const auto metric = [&out](std::string_view name, std::string_view type, std::string_view help,
                               auto value, std::string_view labels = "") {
        out += std::format("# HELP {} {}\n# TYPE {} {}\n{}{} {}\n", name, help, name, type, name,
                           labels, value);
    };

    metric("erikslundpool_up", "gauge", "1 if the pool process is serving the API", 1);
    metric("erikslundpool_ready", "gauge", "1 when all required subsystems are ready",
           snapshot.ready ? 1 : 0);
    metric("erikslundpool_uptime_seconds", "gauge", "Seconds since process start", snapshot.uptime);

    out += "# HELP erikslundpool_subsystem_ready 1 when a subsystem is ready\n"
           "# TYPE erikslundpool_subsystem_ready gauge\n";
    out += std::format("erikslundpool_subsystem_ready{{subsystem=\"bitcoind\"}} {}\n",
                       snapshot.generator_ready ? 1 : 0);
    out += std::format("erikslundpool_subsystem_ready{{subsystem=\"work\"}} {}\n",
                       snapshot.stratifier_ready ? 1 : 0);
    out += std::format("erikslundpool_subsystem_ready{{subsystem=\"connections\"}} {}\n",
                       snapshot.connector_ready ? 1 : 0);

    out += "# HELP erikslundpool_info Build and runtime info\n"
           "# TYPE erikslundpool_info gauge\n";
    out += std::format("erikslundpool_info{{version=\"{}\"}} 1\n", snapshot.version);

    if (!snapshot.bitcoind_nodes.empty()) {
        out += "# HELP erikslundpool_bitcoind_node_active 1 for the bitcoind RPC endpoint currently "
               "in use, 0 for standby\n"
               "# TYPE erikslundpool_bitcoind_node_active gauge\n";
        for (size_t i = 0; i < snapshot.bitcoind_nodes.size(); ++i)
            out += std::format("erikslundpool_bitcoind_node_active{{url=\"{}\"}} {}\n",
                               prom_label(util::redact_url(snapshot.bitcoind_nodes[i])),
                               i == snapshot.bitcoind_active_index ? 1 : 0);
    }

    if (snapshot.network_diff)
        metric("erikslundpool_network_difficulty", "gauge", "Bitcoin network difficulty",
               *snapshot.network_diff);
    if (snapshot.height)
        metric("erikslundpool_block_height", "gauge", "Block height currently being mined",
               *snapshot.height);
    metric("erikslundpool_blocks_found_total", "counter", "Blocks solved by this pool",
           snapshot.blocks_found);
    metric("erikslundpool_shares_accepted_total", "counter", "Accepted shares",
           snapshot.shares_accepted);
    metric("erikslundpool_shares_rejected_total", "counter", "Rejected shares",
           snapshot.shares_rejected);
    metric("erikslundpool_best_share", "gauge", "Best share difficulty seen", snapshot.best_share);
    metric("erikslundpool_users", "gauge", "Distinct users (addresses)", snapshot.users);
    metric("erikslundpool_workers", "gauge", "Connected workers", snapshot.connected);

    out += "# HELP erikslundpool_hashrate_hashes_per_second Pool hashrate (H/s)\n"
           "# TYPE erikslundpool_hashrate_hashes_per_second gauge\n";
    out += std::format("erikslundpool_hashrate_hashes_per_second{{window=\"estimate\"}} {}\n",
                       snapshot.hashrate_estimate);
    for (std::size_t i = 0; i < stats::kHashrateWindows.size(); ++i)
        out += std::format("erikslundpool_hashrate_hashes_per_second{{window=\"{}\"}} {}\n",
                           stats::kHashrateLabels[i],
                           snapshot.hashrate_windows[i] * stats::kHashesPerDiff1Share);
    return out;
}

nlohmann::json status_json(const PoolSnapshot& snapshot) {
    return {{"name", "erikslund-solo-pool"},
            {"version", snapshot.version},
            {"pid", snapshot.pid},
            {"starttime", snapshot.starttime},
            {"uptime", snapshot.uptime},
            {"bitcoind_connected", snapshot.generator_ready},
            {"work_ready", snapshot.stratifier_ready},
            {"accepting_connections", snapshot.connector_ready},
            {"ready", snapshot.ready}};
}

nlohmann::json pool_stats_json(const PoolSnapshot& snapshot) {
    nlohmann::json best_share_percent = nullptr;
    if (snapshot.network_diff && *snapshot.network_diff > 0.0)
        best_share_percent = snapshot.best_share / *snapshot.network_diff * 100.0;
    return {{"runtime", snapshot.uptime},
            {"height", or_null(snapshot.height)},
            {"network_diff", or_null(snapshot.network_diff)},
            {"current_job", or_null(snapshot.current_job)},
            {"workers", snapshot.connected},
            {"users", snapshot.users},
            {"blocks_found", snapshot.blocks_found},
            {"last_block_found", snapshot.last_block_found > 0
                                     ? nlohmann::json(stats::format_rfc9557(snapshot.last_block_found))
                                     : nlohmann::json(nullptr)},
            {"shares_accepted", snapshot.shares_accepted},
            {"shares_rejected", snapshot.shares_rejected},
            {"accepted_diff", snapshot.accepted_diff},
            {"best_share", snapshot.best_share},
            {"best_share_percent", best_share_percent},
            {"hashrate_estimate", snapshot.hashrate_estimate}};
}

nlohmann::json stratifier_stats_json(const PoolSnapshot& snapshot) {
    return {{"jobs_created", snapshot.jobs_created},
            {"recent_jobs_cached", snapshot.recent_jobs_cached},
            {"current_job", or_null(snapshot.current_job)},
            {"height", or_null(snapshot.height)},
            {"txns_in_job", or_null(snapshot.txns_in_job)},
            {"merkle_branch_len", or_null(snapshot.merkle_branch_len)}};
}

nlohmann::json connector_stats_json(const PoolSnapshot& snapshot) {
    size_t subscribed = 0;
    size_t authorized = 0;
    for (const auto& client : snapshot.clients) {
        subscribed += client.subscribed ? 1 : 0;
        authorized += client.authorized ? 1 : 0;
    }
    return {{"workers", snapshot.connected},
            {"subscribed", subscribed},
            {"authorized", authorized}};
}

nlohmann::json generator_stats_json(const PoolSnapshot& snapshot) {
    nlohmann::json nodes = nlohmann::json::array();
    for (size_t i = 0; i < snapshot.bitcoind_nodes.size(); ++i)
        nodes.push_back({{"address", util::redact_url(snapshot.bitcoind_nodes[i])},
                         {"active", i == snapshot.bitcoind_active_index}});
    return {{"bitcoind_reachable", snapshot.bitcoind_reachable},
            {"chain", snapshot.chain},
            {"tip_height", or_null(snapshot.tip_height)},
            {"last_template_age_sec", or_null(snapshot.last_template_age_sec)},
            {"rpc_url", util::redact_url(snapshot.rpc_url)},
            {"bitcoind_nodes", nodes}};
}

nlohmann::json metrics_json(const PoolSnapshot& snapshot) {
    return {{"uptime_seconds", snapshot.uptime},
            {"ready", snapshot.ready},
            {"bitcoind_connected", snapshot.generator_ready},
            {"work_ready", snapshot.stratifier_ready},
            {"accepting_connections", snapshot.connector_ready},
            {"pool", pool_stats_json(snapshot)},
            {"stratifier", stratifier_stats_json(snapshot)},
            {"connector", connector_stats_json(snapshot)},
            {"generator", generator_stats_json(snapshot)}};
}

std::optional<nlohmann::json> client_stats_json(const PoolSnapshot& snapshot,
                                                const std::string& address) {
    const std::string base_address = address.substr(0, address.find('.'));
    nlohmann::json sessions = nlohmann::json::array();
    uint64_t accepted_shares = 0;
    uint64_t rejected_shares = 0;
    double best_difficulty = 0.0;
    int64_t last_share_timestamp = 0;
    size_t workers = 0;
    for (const auto& client : snapshot.clients) {
        if (client.address != base_address)
            continue;
        ++workers;
        accepted_shares += client.shares_accepted;
        rejected_shares += client.shares_rejected;
        best_difficulty = std::max(best_difficulty, client.best_difficulty);
        last_share_timestamp = std::max(last_share_timestamp, client.last_share_ts);
        sessions.push_back({{"address", client.address},
                            {"worker", client.worker},
                            {"peer", client.peer},
                            {"user_agent", client.user_agent},
                            {"difficulty", client.difficulty},
                            {"shares_accepted", client.shares_accepted},
                            {"shares_rejected", client.shares_rejected},
                            {"best_diff", client.best_difficulty},
                            {"last_share_ts", client.last_share_ts},
                            {"connected_for", client.connected_for}});
    }
    if (workers == 0)
        return std::nullopt;
    return nlohmann::json{{"address", base_address},
                          {"workers", workers},
                          {"shares_accepted", accepted_shares},
                          {"shares_rejected", rejected_shares},
                          {"best_diff", best_difficulty},
                          {"last_share_ts", last_share_timestamp},
                          {"sessions", sessions}};
}

std::string dashboard_html(const PoolSnapshot& snapshot) {
    const std::string ready_text = snapshot.ready ? "READY" : "NOT READY";
    const std::string ready_class = snapshot.ready ? "ok" : "bad";
    const std::string chain = snapshot.chain.empty() ? "&mdash;" : html_escape(snapshot.chain);
    std::string height = "&mdash;";
    if (snapshot.height) {
        const int64_t h = *snapshot.height;
        height = h < 1000 ? group_digits(h)
                          : stats::suffix_string(static_cast<double>(h)) + " (" + group_digits(h) + ")";
    }
    const std::string network_difficulty =
        snapshot.network_diff ? format_difficulty(*snapshot.network_diff) : "&mdash;";

    std::string html;
    html += "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta http-equiv=\"refresh\" content=\"5\">"
            "<title>erikslund-solo-pool &mdash; solo pool</title>";
    html += "<style>"
            "body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:46rem;color:#222}"
            "h1{font-size:1.4rem;margin-bottom:.2rem}small{color:#888;font-weight:400}"
            "table{border-collapse:collapse;width:100%;margin-top:1rem}"
            "td{padding:.3rem .8rem;border-bottom:1px solid #e5e5e5}"
            "td:first-child{color:#777;width:14rem}.ok{color:#0a7d28}.bad{color:#c0392b}"
            "a{color:#2563eb;text-decoration:none}</style></head><body>";
    html += std::format("<h1>erikslund-solo-pool <small>v{} | pid {}</small></h1>", snapshot.version,
                        snapshot.pid);
    html += std::format("<p class=\"{}\"><strong>{}</strong></p>", ready_class, ready_text);
    html += "<table>";
    html += "<tr><td>chain</td><td>" + chain + "</td></tr>";
    if (!snapshot.bitcoind_nodes.empty()) {
        std::string nodes;
        for (size_t i = 0; i < snapshot.bitcoind_nodes.size(); ++i) {
            const bool active = i == snapshot.bitcoind_active_index;
            nodes += std::format("<div class=\"{}\">{}{}</div>", active ? "ok" : "",
                                 html_escape(util::redact_url(snapshot.bitcoind_nodes[i])),
                                 active ? " (active)" : "");
        }
        html += "<tr><td>bitcoind nodes</td><td>" + nodes + "</td></tr>";
    }
    html += "<tr><td>height</td><td>" + height + "</td></tr>";
    html += "<tr><td>network difficulty</td><td>" + network_difficulty + "</td></tr>";
    html += std::format("<tr><td>blocks found</td><td>{}</td></tr>", snapshot.blocks_found);
    const std::string last_block = snapshot.last_block_found > 0
                                       ? stats::format_rfc9557(snapshot.last_block_found)
                                       : "never";
    html += "<tr><td>last block found</td><td>" + last_block + "</td></tr>";
    html += std::format("<tr><td>shares accepted</td><td>{}</td></tr>", snapshot.shares_accepted);
    html += std::format("<tr><td>shares rejected</td><td>{}</td></tr>", snapshot.shares_rejected);
    html += "<tr><td>best share</td><td>" + format_difficulty(snapshot.best_share) + "</td></tr>";
    html += std::format("<tr><td>connected workers</td><td>{}</td></tr>", snapshot.connected);
    html += std::format("<tr><td>distinct addresses</td><td>{}</td></tr>", snapshot.users);
    for (size_t i = 0; i < 4; ++i) // 1m, 5m, 15m, 1hr
        html += std::format("<tr><td>hashrate ({})</td><td>{}</td></tr>", stats::kHashrateLabels[i],
                            format_hashrate(snapshot.hashrate_windows[i] * stats::kHashesPerDiff1Share));
    html += "<tr><td>uptime</td><td>" + format_duration(snapshot.uptime) + "</td></tr>";
    html += "</table>";
    html += "<p><a href=\"/status\">/status</a> | <a href=\"/stats/pool\">/stats/pool</a> "
            "| <a href=\"/metrics\">/metrics</a></p></body></html>";
    return html;
}

} // namespace erikslund::api
