#pragma once
// Stratum v1 JSON-RPC framing: parse a request line, build result/error/notification.
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace erikslund::stratum {

using json = nlohmann::json;

// The [code, message, null] triple in a JSON-RPC error.
struct StratumError {
    int code;
    std::string_view message;
};

inline constexpr StratumError ERR_OTHER{20, "Other/unknown"};
inline constexpr StratumError ERR_STALE{21, "Job not found / stale"};
inline constexpr StratumError ERR_DUPLICATE{22, "Duplicate share"};
inline constexpr StratumError ERR_LOW_DIFFICULTY{23, "Low difficulty share"};
inline constexpr StratumError ERR_UNAUTHORIZED{24, "Unauthorized worker"};
inline constexpr StratumError ERR_NOT_SUBSCRIBED{25, "Not subscribed"};

struct Request {
    json id = nullptr;                 // echoed in responses (number, string, or null)
    std::string method;
    // Each param as a string ("" for non-string elements; those reject downstream).
    std::vector<std::string> params;
    // mining.configure only (its params nest, so extracted during parse):
    std::vector<std::string> configure_extensions; // every extension the client requested
    bool configure_version_rolling = false;
    bool version_rolling_mask_present = false;      // the mask KEY existed (even if non-string)
    std::optional<std::string> version_rolling_mask; // set only when the value was a string
    // mining.suggest_difficulty only: a JSON number the params vector can't carry.
    std::optional<double> suggested_difficulty;
};

// Returns nullopt unless it's a JSON object with a string method.
std::optional<Request> parse_request(std::string_view line);

json make_result(const json& id, json result);
json make_error(const json& id, const StratumError& error);
json make_notification(std::string_view method, json params);

// Fast paths for the per-share submit response: serialize straight to the wire line (no json
// tree). Byte-identical to make_result/make_error dumped (key order error < id < result).
std::string make_result_line(const json& id, bool result);
std::string make_error_line(const json& id, const StratumError& error);

// Fast path for mining.notify (highest-fanout, re-serialized per client per broadcast):
// concatenate the wire line from the job's already-hex fields. All values are hex, so no JSON
// escaping; key order id < method < params. Byte-identity vs make_notification is doctest-pinned.
std::string make_notify_line(const std::string& job_id, const std::string& prevhash_stratum,
                             const std::string& coinbase1_hex, const std::string& coinbase2_hex,
                             const std::vector<std::string>& merkle_branch_hex,
                             const std::string& version_hex, const std::string& nbits_hex,
                             const std::string& ntime_hex, bool clean);

} // namespace erikslund::stratum
