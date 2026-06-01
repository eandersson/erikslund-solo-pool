#pragma once
// HTTP API serializers (Prometheus text + JSON bodies); pure functions of a PoolSnapshot.
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "api/snapshot.hpp"

namespace erikslund::api {

std::string build_prometheus(const PoolSnapshot& snapshot);

nlohmann::json status_json(const PoolSnapshot& snapshot);
nlohmann::json pool_stats_json(const PoolSnapshot& snapshot);
nlohmann::json stratifier_stats_json(const PoolSnapshot& snapshot);
nlohmann::json connector_stats_json(const PoolSnapshot& snapshot);
nlohmann::json generator_stats_json(const PoolSnapshot& snapshot);
nlohmann::json metrics_json(const PoolSnapshot& snapshot);

std::optional<nlohmann::json> client_stats_json(const PoolSnapshot& snapshot,
                                                const std::string& address);

std::string dashboard_html(const PoolSnapshot& snapshot);

} // namespace erikslund::api
