#pragma once
// HTTP API serializers (Prometheus text + JSON bodies); pure functions of a PoolSnapshot.
#include <optional>
#include <string>

#include <glaze/glaze.hpp>

#include "api/snapshot.hpp"

namespace erikslund::api {

std::string build_prometheus(const PoolSnapshot& snapshot);

glz::generic status_json(const PoolSnapshot& snapshot);
glz::generic pool_stats_json(const PoolSnapshot& snapshot);
glz::generic stratifier_stats_json(const PoolSnapshot& snapshot);
glz::generic connector_stats_json(const PoolSnapshot& snapshot);
glz::generic generator_stats_json(const PoolSnapshot& snapshot);
glz::generic metrics_json(const PoolSnapshot& snapshot);

std::optional<glz::generic> client_stats_json(const PoolSnapshot& snapshot,
                                              const std::string& address);

std::string dashboard_html(const PoolSnapshot& snapshot);

} // namespace erikslund::api
