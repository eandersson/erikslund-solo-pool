#include "api/metrics.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <format>
#include <string>
#include <string_view>
#include <unordered_set>

#include "stats/hashrate.hpp"
#include "stats/poolstatus.hpp"
#include "stratum/job.hpp" // reject_class_label for the by-reason counter labels
#include "util/json_number.hpp"
#include "util/url.hpp"

namespace erikslund::api {

namespace {

template <class T>
glz::generic or_null(const std::optional<T>& value) {
    return value ? glz::generic(*value) : glz::generic{};
}

// These API fields retain a decimal point even when integral; every other number is an integer.
const std::unordered_set<std::string_view> kFloatKeys = {
    "network_diff",  "accepted_diff",     "best_share", "best_share_percent",
    "hashrate_estimate", "best_diff",     "difficulty"};

// A number gets ".0" iff its key is a kFloatKey; otherwise it is a plain integer.
// Glaze handles string and key escaping.
void emit_status_json(std::string& out, const glz::generic& value, std::string_view key) {
    if (value.is_object()) {
        out += '{';
        bool first = true;
        for (const auto& [child_key, child] : value.get_object()) {
            if (!first)
                out += ',';
            first = false;
            out += glz::write_json(child_key).value_or("\"\"");
            out += ':';
            emit_status_json(out, child, child_key);
        }
        out += '}';
    } else if (value.is_array()) {
        out += '[';
        bool first = true;
        for (const auto& element : value.get_array()) {
            if (!first)
                out += ',';
            first = false;
            emit_status_json(out, element, key);
        }
        out += ']';
    } else if (value.is_string()) {
        out += glz::write_json(value.get<std::string>()).value_or("\"\"");
    } else if (value.is_boolean()) {
        out += value.get<bool>() ? "true" : "false";
    } else if (value.is_number()) {
        if (kFloatKeys.contains(key))
            out += util::format_json_number(value.get<double>());
        else
            out += std::to_string(static_cast<int64_t>(value.get<double>()));
    } else {
        out += "null";
    }
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
    out.reserve(2048 + 128 * snapshot.bitcoind_nodes.size());
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

    if (snapshot.sv2_authenticated_ready)
        metric("erikslundpool_sv2_authenticated_ready", "gauge",
               "1 when configured authenticated SV2 listeners can accept new sessions",
               *snapshot.sv2_authenticated_ready ? 1 : 0);
    if (snapshot.sv2_certificate_expiry_timestamp)
        metric("erikslundpool_sv2_certificate_expiry_timestamp_seconds", "gauge",
               "Unix timestamp when the configured SV2 certificate expires",
               *snapshot.sv2_certificate_expiry_timestamp);

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
    out += "# HELP erikslundpool_shares_rejected_by_reason_total Rejected shares by reason\n"
           "# TYPE erikslundpool_shares_rejected_by_reason_total counter\n";
    for (size_t cls = 0; cls < snapshot.shares_rejected_by_class.size(); ++cls)
        out += std::format("erikslundpool_shares_rejected_by_reason_total{{reason=\"{}\"}} {}\n",
                           stratum::reject_class_label(static_cast<stratum::RejectClass>(cls)),
                           snapshot.shares_rejected_by_class[cls]);
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

glz::generic status_json(const PoolSnapshot& snapshot) {
    glz::generic j;
    j["name"] = "erikslund-solo-pool";
    j["version"] = snapshot.version;
    j["pid"] = static_cast<double>(snapshot.pid);
    j["starttime"] = static_cast<double>(snapshot.starttime);
    j["uptime"] = static_cast<double>(snapshot.uptime);
    j["bitcoind_connected"] = snapshot.generator_ready;
    j["work_ready"] = snapshot.stratifier_ready;
    j["accepting_connections"] = snapshot.connector_ready;
    j["sv2_authenticated_ready"] = or_null(snapshot.sv2_authenticated_ready);
    j["sv2_certificate_expiry_timestamp"] = or_null(
        snapshot.sv2_certificate_expiry_timestamp);
    j["ready"] = snapshot.ready;
    return j;
}

glz::generic pool_stats_json(const PoolSnapshot& snapshot) {
    glz::generic j;
    j["runtime"] = static_cast<double>(snapshot.uptime);
    j["height"] = or_null(snapshot.height);
    j["network_diff"] = or_null(snapshot.network_diff);
    j["current_job"] = or_null(snapshot.current_job);
    j["workers"] = static_cast<double>(snapshot.connected);
    j["users"] = static_cast<double>(snapshot.users);
    j["blocks_found"] = static_cast<double>(snapshot.blocks_found);
    j["last_block_found"] = snapshot.last_block_found > 0
                                ? glz::generic(stats::format_rfc9557(snapshot.last_block_found))
                                : glz::generic{};
    j["shares_accepted"] = static_cast<double>(snapshot.shares_accepted);
    j["shares_rejected"] = static_cast<double>(snapshot.shares_rejected);
    j["accepted_diff"] = snapshot.accepted_diff;
    j["best_share"] = snapshot.best_share;
    if (snapshot.network_diff && *snapshot.network_diff > 0.0)
        j["best_share_percent"] = snapshot.best_share / *snapshot.network_diff * 100.0;
    else
        j["best_share_percent"] = glz::generic{};
    j["hashrate_estimate"] = snapshot.hashrate_estimate;
    return j;
}

glz::generic stratifier_stats_json(const PoolSnapshot& snapshot) {
    glz::generic j;
    j["jobs_created"] = static_cast<double>(snapshot.jobs_created);
    j["recent_jobs_cached"] = static_cast<double>(snapshot.recent_jobs_cached);
    j["current_job"] = or_null(snapshot.current_job);
    j["height"] = or_null(snapshot.height);
    j["txns_in_job"] = or_null(snapshot.txns_in_job);
    j["merkle_branch_len"] = or_null(snapshot.merkle_branch_len);
    return j;
}

glz::generic connector_stats_json(const PoolSnapshot& snapshot) {
    const auto subscribed = static_cast<size_t>(
        std::ranges::count_if(snapshot.clients, [](const auto& client) { return client.subscribed; }));
    const auto authorized = static_cast<size_t>(
        std::ranges::count_if(snapshot.clients, [](const auto& client) { return client.authorized; }));
    glz::generic j;
    j["workers"] = static_cast<double>(snapshot.connected);
    j["subscribed"] = static_cast<double>(subscribed);
    j["authorized"] = static_cast<double>(authorized);
    return j;
}

glz::generic generator_stats_json(const PoolSnapshot& snapshot) {
    glz::generic nodes = glz::generic::array_t{};
    for (size_t i = 0; i < snapshot.bitcoind_nodes.size(); ++i) {
        glz::generic node;
        node["address"] = util::redact_url(snapshot.bitcoind_nodes[i]);
        node["active"] = (i == snapshot.bitcoind_active_index);
        nodes.get_array().push_back(std::move(node));
    }
    glz::generic j;
    j["bitcoind_reachable"] = snapshot.bitcoind_reachable;
    j["chain"] = snapshot.chain;
    j["tip_height"] = or_null(snapshot.tip_height);
    j["last_template_age_sec"] = or_null(snapshot.last_template_age_sec);
    j["rpc_url"] = util::redact_url(snapshot.rpc_url);
    j["bitcoind_nodes"] = std::move(nodes);
    return j;
}

glz::generic metrics_json(const PoolSnapshot& snapshot) {
    glz::generic j;
    j["uptime_seconds"] = static_cast<double>(snapshot.uptime);
    j["ready"] = snapshot.ready;
    j["bitcoind_connected"] = snapshot.generator_ready;
    j["work_ready"] = snapshot.stratifier_ready;
    j["accepting_connections"] = snapshot.connector_ready;
    j["sv2_authenticated_ready"] = or_null(snapshot.sv2_authenticated_ready);
    j["sv2_certificate_expiry_timestamp"] = or_null(
        snapshot.sv2_certificate_expiry_timestamp);
    j["pool"] = pool_stats_json(snapshot);
    j["stratifier"] = stratifier_stats_json(snapshot);
    j["connector"] = connector_stats_json(snapshot);
    j["generator"] = generator_stats_json(snapshot);
    return j;
}

std::optional<glz::generic> client_stats_json(const PoolSnapshot& snapshot,
                                              const std::string& address) {
    const std::string base_address = address.substr(0, address.find('.'));
    glz::generic sessions = glz::generic::array_t{};
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
        glz::generic session;
        session["address"] = client.address;
        session["worker"] = client.worker;
        session["peer"] = client.peer;
        session["user_agent"] = client.user_agent;
        session["difficulty"] = client.difficulty;
        session["shares_accepted"] = static_cast<double>(client.shares_accepted);
        session["shares_rejected"] = static_cast<double>(client.shares_rejected);
        session["best_diff"] = client.best_difficulty;
        session["last_share_ts"] = static_cast<double>(client.last_share_ts);
        session["connected_for"] = static_cast<double>(client.connected_for);
        sessions.get_array().push_back(std::move(session));
    }
    if (workers == 0)
        return std::nullopt;
    glz::generic j;
    j["address"] = base_address;
    j["workers"] = static_cast<double>(workers);
    j["shares_accepted"] = static_cast<double>(accepted_shares);
    j["shares_rejected"] = static_cast<double>(rejected_shares);
    j["best_diff"] = best_difficulty;
    j["last_share_ts"] = static_cast<double>(last_share_timestamp);
    j["sessions"] = std::move(sessions);
    return j;
}

std::string to_status_json(const glz::generic& value) {
    std::string out;
    emit_status_json(out, value, "");
    return out;
}

std::string dashboard_html(const PoolSnapshot& snapshot) {
    const std::string ready_text = snapshot.ready ? "READY" : "NOT READY";
    const std::string ready_class = snapshot.ready ? "ok" : "bad";
    const std::string chain = snapshot.chain.empty() ? "&mdash;" : html_escape(snapshot.chain);
    std::string height = "&mdash;";
    if (snapshot.height) {
        const int64_t block_height = *snapshot.height;
        height = block_height < 1000
                     ? group_digits(block_height)
                     : stats::suffix_string(static_cast<double>(block_height)) + " (" +
                           group_digits(block_height) + ")";
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
