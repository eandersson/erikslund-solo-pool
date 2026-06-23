#include "core/config.hpp"

#include <charconv>
#include <flat_set>
#include <fstream>
#include <sstream>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <yaml-cpp/yaml.h>

#include "bitcoin/coinbase.hpp"
#include "core/errors.hpp"
#include "core/logging.hpp"

namespace erikslund {

namespace {

std::pair<std::string, uint16_t> split_host_port(const std::string& host_port) {
    const auto colon = host_port.rfind(':');
    if (colon == std::string::npos)
        throw ConfigError("listen address has no port (expected host:port or :port): " + host_port);
    const std::string port_str = host_port.substr(colon + 1);
    // Require a clean 1..65535 (reject truncation, trailing garbage, and port 0).
    uint32_t port = 0;
    const char* begin = port_str.data();
    const char* end = begin + port_str.size();
    const auto [ptr, ec] = std::from_chars(begin, end, port);
    if (ec != std::errc{} || ptr != end || port < 1 || port > 65535)
        throw ConfigError("invalid port in listen address: " + host_port);
    return {host_port.substr(0, colon), static_cast<uint16_t>(port)};
}

nlohmann::json scalar_to_json(const std::string& text) {
    if (!text.empty()) {
        const char* begin = text.data();
        const char* end = begin + text.size();

        if (int64_t as_int = 0;
            std::from_chars(begin, end, as_int).ptr == end)
            return as_int;
        if (double as_double = 0.0;
            std::from_chars(begin, end, as_double).ptr == end)
            return as_double;
        // YAML 1.1 boolean spellings.
        if (text == "true" || text == "True" || text == "TRUE")
            return true;
        if (text == "false" || text == "False" || text == "FALSE")
            return false;
    }
    return text;
}

nlohmann::json yaml_to_json(const YAML::Node& node) {
    switch (node.Type()) {
    case YAML::NodeType::Map: {
        nlohmann::json object = nlohmann::json::object();
        for (const auto& entry : node)
            object[entry.first.as<std::string>()] = yaml_to_json(entry.second);
        return object;
    }
    case YAML::NodeType::Sequence: {
        nlohmann::json array = nlohmann::json::array();
        for (const auto& element : node)
            array.push_back(yaml_to_json(element));
        return array;
    }
    case YAML::NodeType::Scalar:
        // A quoted scalar carries the non-specific "!" tag: keep it a string (don't coerce
        // password: "12345" or token: "true"). Plain scalars get type inference.
        if (node.Tag() == "!")
            return node.Scalar();
        return scalar_to_json(node.Scalar());
    case YAML::NodeType::Null:
    case YAML::NodeType::Undefined:
    default:
        return nullptr;
    }
}

} // namespace

Config Config::from_json(const nlohmann::json& object) {
    if (!object.is_object())
        throw ConfigError("config must be a JSON object");

    static const std::flat_set<std::string> known = {
        "$schema",                          "bitcoin_nodes",
        "stratum_listen",                   "api_listen",
        "coinbase_signature",               "coinbase_version",
        "initial_difficulty",               "minimum_difficulty",
        "maximum_difficulty",               "variable_difficulty",
        "vardiff_target_shares_per_minute", "vardiff_retarget_seconds",
        "extranonce1_size",                 "extranonce2_size",
        "zmq_block_endpoint",               "fast_block_notify",
        "block_poll_milliseconds",          "work_rebroadcast_seconds",
        "version_rolling_mask",             "donation_percent",
        "donation_address",                 "max_clients",
        "max_workers_per_address",
        "drop_idle_seconds",                "max_line_bytes",
        "auth_timeout_seconds",             "max_protocol_errors",
        "stats_directory",                  "status_interval_seconds",
        "user_stats_retention_days",        "worker_threads",
        "proxy_protocol_from"};
    for (const auto& item : object.items())
        if (!known.contains(item.key()))
            throw ConfigError("unknown config key: " + item.key());

    Config config;

    if (object.contains("bitcoin_nodes") && object["bitcoin_nodes"].is_array() &&
        !object["bitcoin_nodes"].empty()) {
        const auto& nodes = object["bitcoin_nodes"];
        config.rpc_url = nodes[0].at("address").get<std::string>();
        config.rpc_user = nodes[0].value("username", std::string{});
        config.rpc_password = nodes[0].value("password", std::string{});
        for (size_t i = 1; i < nodes.size(); ++i) {
            bitcoin::RpcEndpoint endpoint;
            endpoint.url = nodes[i].at("address").get<std::string>();
            endpoint.user = nodes[i].value("username", config.rpc_user);
            endpoint.password = nodes[i].value("password", config.rpc_password);
            config.rpc_failover.push_back(std::move(endpoint));
        }
    }

    if (object.contains("stratum_listen")) {
        const auto& listen = object["stratum_listen"];
        std::vector<std::string> urls;
        if (listen.is_string())
            urls.push_back(listen.get<std::string>());
        else if (listen.is_array())
            for (const auto& u : listen)
                urls.push_back(u.get<std::string>());
        if (!urls.empty()) {
            config.bind_host = split_host_port(urls[0]).first;
            config.bind_ports.clear();
            for (const auto& u : urls) {
                const auto [host, port] = split_host_port(u);
                // Only the first bind host is honored; reject differing per-entry hosts.
                if (host != config.bind_host)
                    throw ConfigError("stratum_listen entries must all use the same host "
                                      "(per-port hosts are not supported): " + u);
                config.bind_ports.push_back(port);
            }
            config.bind_port = config.bind_ports.front();
        }
    }

    if (object.contains("proxy_protocol_from")) {
        const auto& trusted = object["proxy_protocol_from"];
        if (trusted.is_string())
            config.proxy_protocol_from.push_back(trusted.get<std::string>());
        else if (trusted.is_array())
            for (const auto& entry : trusted)
                config.proxy_protocol_from.push_back(entry.get<std::string>());
    }

    if (object.contains("api_listen")) {
        const auto& listen = object["api_listen"];
        std::string host_port;
        if (listen.is_string())
            host_port = listen.get<std::string>();
        else if (listen.is_array() && !listen.empty())
            host_port = listen[0].get<std::string>();
        if (!host_port.empty()) {
            const auto [host, port] = split_host_port(host_port);
            config.api_host = host;
            config.api_port = port;
        }
    }

    const auto load = [&](const char* key, auto& field) {
        if (!object.contains(key))
            return;
        try {
            field = object.at(key).get<std::remove_reference_t<decltype(field)>>();
        } catch (const nlohmann::json::exception&) {
            throw ConfigError(std::string("invalid value type for config key '") + key + "'");
        }
    };
    load("coinbase_signature", config.coinbase_signature);
    load("coinbase_version", config.coinbase_version);
    load("initial_difficulty", config.initial_difficulty);
    load("minimum_difficulty", config.minimum_difficulty);
    load("maximum_difficulty", config.maximum_difficulty);
    load("variable_difficulty", config.variable_difficulty);
    load("vardiff_target_shares_per_minute", config.vardiff_target_shares_per_minute);
    load("vardiff_retarget_seconds", config.vardiff_retarget_seconds);
    load("extranonce1_size", config.extranonce1_size);
    load("extranonce2_size", config.extranonce2_size);
    load("zmq_block_endpoint", config.zmq_block_endpoint);
    load("fast_block_notify", config.fast_block_notify);
    load("work_rebroadcast_seconds", config.work_rebroadcast_seconds);
    load("donation_percent", config.donation_percent);
    load("donation_address", config.donation_address);
    load("max_clients", config.max_clients);
    load("max_workers_per_address", config.max_workers_per_address);
    load("drop_idle_seconds", config.drop_idle_seconds);
    load("auth_timeout_seconds", config.auth_timeout_seconds);
    load("max_protocol_errors", config.max_protocol_errors);
    load("max_line_bytes", config.max_line_bytes);
    load("stats_directory", config.stats_directory);
    load("status_interval_seconds", config.status_interval_seconds);
    load("user_stats_retention_days", config.user_stats_retention_days);
    load("worker_threads", config.worker_threads);

    if (object.contains("block_poll_milliseconds")) {
        try {
            config.poll_interval = object["block_poll_milliseconds"].get<double>() / 1000.0;
        } catch (const nlohmann::json::exception&) {
            throw ConfigError("block_poll_milliseconds must be a number");
        }
    }

    if (object.contains("version_rolling_mask")) {
        const auto& value = object.at("version_rolling_mask");
        try {
            config.version_rolling_mask = value.is_string()
                                      ? static_cast<uint32_t>(std::stoul(value.get<std::string>(),
                                                                         nullptr, 16))
                                      : value.get<uint32_t>();
        } catch (const std::exception&) {
            throw ConfigError("invalid version_rolling_mask");
        }
    }

    if (config.version_rolling_mask & ~0x1fffe000u) {
        log::warning("version_rolling_mask {:08x} has bits outside the BIP320 range; clamping to "
                     "1fffe000", config.version_rolling_mask);
        config.version_rolling_mask &= 0x1fffe000u;
    }

    if (config.donation_percent < 0.0 || config.donation_percent > 100.0)
        throw ConfigError("donation_percent must be in [0.0, 100.0]");

    if (config.initial_difficulty <= 0.0)
        throw ConfigError("initial_difficulty must be > 0");
    if (config.minimum_difficulty <= 0.0)
        throw ConfigError("minimum_difficulty must be > 0");
    if (config.maximum_difficulty < 0.0)
        throw ConfigError("maximum_difficulty must be >= 0 (0 = no maximum)");
    if (config.vardiff_target_shares_per_minute <= 0.0)
        throw ConfigError("vardiff_target_shares_per_minute must be > 0");
    if (config.vardiff_retarget_seconds < 1)
        throw ConfigError("vardiff_retarget_seconds must be >= 1");
    if (config.work_rebroadcast_seconds < 1.0)
        throw ConfigError("work_rebroadcast_seconds must be >= 1");
    if (config.poll_interval <= 0.0)
        throw ConfigError("block_poll_milliseconds must be >= 1");
    // Min 4: extranonce1 is a bare wrapping counter; a 2-byte space can lap under churn and
    // hand two concurrent miners identical search space. 4 bytes cannot lap.
    if (config.extranonce1_size < 4 || config.extranonce1_size > 8)
        throw ConfigError("extranonce1_size must be in [4, 8]");
    if (config.extranonce2_size < 2 || config.extranonce2_size > 8)
        throw ConfigError("extranonce2_size must be in [2, 8]");
    if (config.status_interval_seconds < 0.0)
        throw ConfigError("status_interval_seconds must be >= 0");
    // Cap ~100 years: beyond ~106751 days the seconds overflow file_time_type's nanosecond int64.
    if (config.user_stats_retention_days < 0 || config.user_stats_retention_days > 36500)
        throw ConfigError("user_stats_retention_days must be in [0, 36500] (0 keeps files forever)");
    if (config.max_clients < 0)
        throw ConfigError("max_clients must be >= 0");
    if (config.max_workers_per_address < 0)
        throw ConfigError("max_workers_per_address must be >= 0 (0 = unlimited)");
    if (config.drop_idle_seconds < 0)
        throw ConfigError("drop_idle_seconds must be >= 0");
    if (config.auth_timeout_seconds < 0)
        throw ConfigError("auth_timeout_seconds must be >= 0");
    if (config.max_protocol_errors < 0)
        throw ConfigError("max_protocol_errors must be >= 0");

    const size_t scriptsig_budget =
        bitcoin::kMaxHeightPush + config.extranonce1_size + config.extranonce2_size +
        config.coinbase_signature.size();
    if (scriptsig_budget > bitcoin::kMaxScriptSig)
        throw ConfigError("coinbase_signature too long: it must leave room in the " +
                          std::to_string(bitcoin::kMaxScriptSig) +
                          "-byte coinbase scriptSig for the height push and extranonces");
    return config;
}

Config Config::from_file(const std::string& path) {
    std::ifstream stream(path);
    if (!stream)
        throw ConfigError("cannot open config file: " + path);
    std::stringstream buffer;
    buffer << stream.rdbuf();

    try {
        const YAML::Node root = YAML::Load(buffer.str());
        return from_json(yaml_to_json(root));
    } catch (const YAML::Exception& error) {
        throw ConfigError("config file is not valid YAML: " + path + ": " + error.what());
    }
}

} // namespace erikslund
