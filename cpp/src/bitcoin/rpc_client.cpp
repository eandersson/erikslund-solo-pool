#include "bitcoin/rpc_client.hpp"

#include <chrono>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <curl/curl.h>

#include "core/errors.hpp"
#include "core/logging.hpp"
#include "util/url.hpp"

namespace erikslund::bitcoin {

namespace {

struct CurlGlobal {
    CurlGlobal() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlGlobal() { curl_global_cleanup(); }
};
const CurlGlobal g_curl_global;

std::string base64(std::string_view input) {
    static constexpr char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int value = 0;
    int bits = -6;
    for (unsigned char c : input) {
        value = (value << 8) + c;
        bits += 8;
        while (bits >= 0) {
            out.push_back(table[(value >> bits) & 0x3f]);
            bits -= 6;
        }
    }
    if (bits > -6)
        out.push_back(table[((value << 8) >> (bits + 8)) & 0x3f]);
    while (out.size() % 4 != 0)
        out.push_back('=');
    return out;
}

size_t write_callback(char* ptr, size_t size, size_t nmemb, void* userdata) {
    auto* response = static_cast<std::string*>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

CURL* thread_handle() {
    thread_local std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(nullptr,
                                                                            curl_easy_cleanup);
    if (!handle) {
        CURL* raw = curl_easy_init();
        if (!raw)
            throw RpcConnectionError("failed to initialize curl");
        handle.reset(raw);
    }
    return handle.get();
}

} // namespace

RpcClient::RpcClient(const std::vector<RpcEndpoint>& endpoints, long timeout_seconds)
    : timeout_(timeout_seconds) {
    for (const auto& endpoint : endpoints) {
        std::string url = endpoint.url;
        if (url.rfind("http", 0) != 0)
            url.insert(0, "http://");
        endpoints_.push_back(
            {std::move(url), "Authorization: Basic " + base64(endpoint.user + ":" + endpoint.password)});
    }
    if (endpoints_.empty())
        throw std::invalid_argument("RpcClient: no endpoints configured");
}

RpcClient::RpcClient(std::string url, const std::string& user, const std::string& password,
                     long timeout_seconds)
    : RpcClient(std::vector<RpcEndpoint>{{std::move(url), user, password}}, timeout_seconds) {}

std::vector<std::string> RpcClient::endpoint_urls() const {
    std::vector<std::string> urls;
    urls.reserve(endpoints_.size());
    for (const auto& endpoint : endpoints_)
        urls.push_back(endpoint.url);
    return urls;
}

nlohmann::json RpcClient::call(const std::string& method, const nlohmann::json& params) {
    const int id = ++next_id_;
    const std::string payload =
        nlohmann::json{{"jsonrpc", "1.0"}, {"id", id}, {"method", method}, {"params", params}}
            .dump();
    return call_payload(payload);
}

nlohmann::json RpcClient::call_payload(const std::string& payload) {
    const size_t count = endpoints_.size();
    const size_t start = current_.load();
    std::string last_error;
    for (size_t i = 0; i < count; ++i) {
        const size_t index = (start + i) % count;
        try {
            nlohmann::json result = call_one(endpoints_[index], payload);
            if (index != start) {
                size_t expected = start;
                if (current_.compare_exchange_strong(expected, index))
                    log::warning("bitcoind RPC failed over to {}",
                                 util::redact_url(endpoints_[index].url));
            }
            return result;
        } catch (const RpcError&) {
            throw; // node answered with an RPC error -> it is up, do not fail over
        } catch (const RpcConnectionError& e) {
            last_error = e.what();
        }
    }
    throw RpcConnectionError("all bitcoind endpoints unreachable: " + last_error);
}

std::string RpcClient::post_one(const Resolved& endpoint, const std::string& payload,
                                long* http_status) {
    CURL* curl = thread_handle();
    curl_easy_reset(curl);

    std::string response;
    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, endpoint.auth_header.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, endpoint.url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_);
    // Multi-threaded: the resolver's timeout SIGALRM/siglongjmp isn't thread-safe.
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    const CURLcode curl_result = curl_easy_perform(curl);
    if (http_status)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_status);
    curl_slist_free_all(headers);

    if (curl_result != CURLE_OK)
        throw RpcConnectionError(std::string("transport error: ") + curl_easy_strerror(curl_result));
    return response;
}

nlohmann::json RpcClient::call_one(const Resolved& endpoint, const std::string& payload) {
    long http_status = 0;
    const std::string response = post_one(endpoint, payload, &http_status);
    nlohmann::json parsed = nlohmann::json::parse(response, nullptr, /*allow_exceptions=*/false);
    if (parsed.is_discarded())
        // Keep the HTTP code so a 401 (bad RPC creds) stays distinguishable from garbage.
        throw RpcConnectionError("unparseable body (HTTP " + std::to_string(http_status) + ")");
    if (parsed.contains("error") && !parsed["error"].is_null())
        throw RpcError(parsed["error"].dump());
    // Move the result subtree out; a ternary would copy the whole DOM.
    if (const auto it = parsed.find("result"); it != parsed.end())
        return std::move(*it);
    return nlohmann::json();
}

BlockTemplate RpcClient::getblocktemplate_parsed() {
    nlohmann::json request;
    request["rules"] = nlohmann::json::array({"segwit"});
    request["capabilities"] = nlohmann::json::array({"coinbasetxn", "workid", "coinbase/append"});
    const std::string payload = nlohmann::json{{"jsonrpc", "1.0"},
                                               {"id", ++next_id_},
                                               {"method", "getblocktemplate"},
                                               {"params", nlohmann::json::array({request})}}
                                    .dump();

    const size_t count = endpoints_.size();
    const size_t start = current_.load();
    std::string last_error;
    for (size_t i = 0; i < count; ++i) {
        const size_t index = (start + i) % count;
        simdjson::dom::element doc;
        long http_status = 0;
        try {
            gbt_body_ = post_one(endpoints_[index], payload, &http_status);
            doc = gbt_parser_.parse(gbt_body_);
        } catch (const RpcConnectionError& e) {
            last_error = e.what();
            continue;
        } catch (const simdjson::simdjson_error& e) {
            last_error = "unparseable body (HTTP " + std::to_string(http_status) + "): " + e.what();
            continue;
        }
        // Validate the reply BEFORE sticking: any throw leaves current_ at `start`, so the next
        // poll retries the recovering primary instead of being captured by a bad backup.
        simdjson::dom::element error_field;
        if (!doc["error"].get(error_field) && !error_field.is_null())
            throw RpcError(simdjson::to_string(error_field));
        simdjson::dom::element result;
        if (doc["result"].get(result) || result.is_null())
            throw RpcError("getblocktemplate reply has no result");
        BlockTemplate block_template = BlockTemplate::from_simdjson(result);
        // Only now is this endpoint proven to be serving work.
        if (index != start) {
            size_t expected = start;
            if (current_.compare_exchange_strong(expected, index))
                log::warning("bitcoind RPC failed over to {}",
                             util::redact_url(endpoints_[index].url));
        }
        return block_template;
    }
    throw RpcConnectionError("all bitcoind endpoints unreachable: " + last_error);
}

std::optional<std::string> RpcClient::submitblock(const std::string& block_hex) {
    const int id = ++next_id_;
    std::string payload;
    payload.reserve(block_hex.size() + 96);
    payload += "{\"jsonrpc\":\"1.0\",\"id\":";
    payload += std::to_string(id);
    payload += ",\"method\":\"submitblock\",\"params\":[\"";
    payload += block_hex;
    payload += "\"]}";
    const nlohmann::json result = call_payload(payload);
    if (result.is_null())
        return std::nullopt; // block accepted
    if (result.is_string())
        return result.get<std::string>();
    return result.dump();
}

nlohmann::json RpcClient::validateaddress(const std::string& address) {
    return call("validateaddress", nlohmann::json::array({address}));
}

std::string RpcClient::getbestblockhash() {
    return call("getbestblockhash").get<std::string>();
}

void RpcClient::maybe_failback(const std::string& expected_tip) {
    if (current_.load() == 0 || expected_tip.empty())
        return; // already on primary / no tip to compare against
    const double now =
        std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    if (now - last_failback_probe_.load() < kFailbackProbeSeconds)
        return;
    last_failback_probe_.store(now);
    const std::string payload =
        nlohmann::json{{"jsonrpc", "1.0"}, {"id", ++next_id_},
                       {"method", "getbestblockhash"}, {"params", nlohmann::json::array()}}
            .dump();
    nlohmann::json result;
    try {
        result = call_one(endpoints_[0], payload);
    } catch (const std::exception&) {
        // A warming primary answers every call with RPC_IN_WARMUP (-28); failing back would
        // capture the pool (call() never rotates on RpcError) with no work. Stay until it answers.
        return;
    }
    // Reachable but on a different tip (catching up / stuck / forked): failing back would pin
    // the pool to stale work. Wait until it reports the tip we mine on.
    if (!result.is_string() || result.get_ref<const std::string&>() != expected_tip)
        return;
    current_.store(0);
    log::info("bitcoind RPC failed back to the primary {}", util::redact_url(endpoints_[0].url));
}

nlohmann::json RpcClient::getblockheader(const std::string& block_hash) {
    return call("getblockheader", nlohmann::json::array({block_hash}));
}

nlohmann::json RpcClient::getblockchaininfo() {
    return call("getblockchaininfo");
}

} // namespace erikslund::bitcoin
