#pragma once
// Synchronous bitcoind JSON-RPC over libcurl. One persistent easy handle PER THREAD, reused across
// calls for HTTP keep-alive + DNS caching (an easy handle is not shared between threads).
// Failover: a connection failure advances + sticks; an RPC error (node answered) does not.
#include <atomic>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include "bitcoin/block_template.hpp"
#include "bitcoin/rpc_endpoint.hpp"

namespace erikslund::bitcoin {

class RpcClient {
public:
    RpcClient(std::string url, const std::string& user, const std::string& password,
              long timeout_seconds = 30);
    explicit RpcClient(const std::vector<RpcEndpoint>& endpoints, long timeout_seconds = 30);

    nlohmann::json call(const std::string& method,
                        const nlohmann::json& params = nlohmann::json::array(), long timeout = 0);

    BlockTemplate getblocktemplate_parsed();
    std::optional<std::string> submitblock(const std::string& block_hex);
    nlohmann::json validateaddress(const std::string& address);
    nlohmann::json getblockchaininfo();
    // Cheap tip probe that gates the multi-MB getblocktemplate poll.
    std::string getbestblockhash();
    // Verbose header (height/bits/mediantime); grounds the fastblock empty job.
    nlohmann::json getblockheader(const std::string& block_hash);

    size_t endpoint_count() const { return endpoints_.size(); }

    std::vector<std::string> endpoint_urls() const;
    size_t active_index() const { return current_.load(); }

    void maybe_failback(const std::string& expected_tip);
    static constexpr double kFailbackProbeSeconds = 60.0;

    virtual ~RpcClient() = default;

protected:
    struct Resolved {
        std::string url;
        std::string auth_header;
    };
    virtual nlohmann::json call_one(const Resolved& endpoint, const std::string& payload,
                                    long timeout);
    virtual std::string post_one(const Resolved& endpoint, const std::string& payload, long timeout,
                                 long* http_status = nullptr);

private:
    nlohmann::json call_payload(const std::string& payload, long timeout);

    std::vector<Resolved> endpoints_;
    std::atomic<size_t> current_{0};
    long timeout_;
    long connect_timeout_;
    long poll_timeout_;
    std::atomic<int> next_id_{0};
    std::atomic<double> last_failback_probe_{-std::numeric_limits<double>::infinity()};

    // getblocktemplate_parsed() only (single caller thread); buffer + parser arena reused across polls.
    std::string gbt_body_;
    simdjson::dom::parser gbt_parser_;
};

} // namespace erikslund::bitcoin
