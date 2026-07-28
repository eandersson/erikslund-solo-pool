#include "bitcoin/rpc_client.hpp"

#include <algorithm>
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

constexpr int64_t kRpcClientNotConnected = -9;
constexpr int64_t kRpcClientInInitialDownload = -10;
constexpr int64_t kRpcInWarmup = -28;

std::optional<int64_t> rpc_error_code(const glz::generic& error) {
    if (!error.is_object() || !error.contains("code") || !error["code"].is_number())
        return std::nullopt;
    return static_cast<int64_t>(error["code"].get<double>());
}

bool endpoint_unavailable(const RpcError& error) {
    return error.code() == kRpcClientNotConnected ||
           error.code() == kRpcClientInInitialDownload || error.code() == kRpcInWarmup;
}

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
    : timeout_(std::max(1L, timeout_seconds)),
      connect_timeout_(std::min(timeout_, 5L)),
      poll_timeout_(std::min(timeout_, 10L)) {
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

glz::generic RpcClient::call(const std::string& method, const glz::generic& params, long timeout) {
    const int id = ++next_id_;
    glz::generic request;
    request["jsonrpc"] = "1.0";
    request["id"] = static_cast<double>(id);
    request["method"] = method;
    request["params"] = params.is_null() ? glz::generic(glz::generic::array_t{}) : params;
    const std::string payload = glz::write_json(request).value_or("");
    return call_payload(payload, timeout > 0 ? timeout : timeout_);
}

glz::generic RpcClient::call_payload(const std::string& payload, long timeout) {
    const size_t count = endpoints_.size();
    const size_t start = current_.load();
    std::string last_error;
    for (size_t i = 0; i < count; ++i) {
        const size_t index = (start + i) % count;
        try {
            glz::generic result = call_one(endpoints_[index], payload, timeout);
            if (index != start) {
                size_t expected = start;
                if (current_.compare_exchange_strong(expected, index))
                    log::warning("bitcoind RPC failed over to {}",
                                 util::redact_url(endpoints_[index].url));
            }
            return result;
        } catch (const RpcError& error) {
            if (!endpoint_unavailable(error))
                throw;
            last_error = error.what();
        } catch (const RpcConnectionError& e) {
            last_error = e.what();
        }
    }
    throw RpcConnectionError("all bitcoind endpoints unavailable: " + last_error);
}

std::string RpcClient::post_one(const Resolved& endpoint, const std::string& payload, long timeout,
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, connect_timeout_);
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

glz::generic RpcClient::call_one(const Resolved& endpoint, const std::string& payload,
                                 long timeout) {
    long http_status = 0;
    const std::string response = post_one(endpoint, payload, timeout, &http_status);
    glz::generic parsed;
    if (glz::read_json(parsed, response))
        // Keep the HTTP code so a 401 (bad RPC creds) stays distinguishable from garbage.
        throw RpcConnectionError("unparseable body (HTTP " + std::to_string(http_status) + ")");
    if (parsed.contains("error") && !parsed["error"].is_null()) {
        const glz::generic& error = parsed["error"];
        throw RpcError(glz::write_json(error).value_or("rpc error"), rpc_error_code(error));
    }
    // Move the result subtree out; a copy would duplicate the whole DOM.
    if (parsed.contains("result"))
        return std::move(parsed["result"]);
    return glz::generic{};
}

std::string RpcClient::make_getblocktemplate_payload() {
    glz::generic request;
    request["rules"] = glz::generic::array_t{"segwit"};
    request["capabilities"] = glz::generic::array_t{"coinbasetxn", "workid", "coinbase/append"};
    glz::generic envelope;
    envelope["jsonrpc"] = "1.0";
    envelope["id"] = static_cast<double>(++next_id_);
    envelope["method"] = "getblocktemplate";
    envelope["params"] = glz::generic::array_t{request};
    return glz::write_json(envelope).value_or("");
}

BlockTemplate RpcClient::fetch_template_from(size_t index, const std::string& payload) {
    long http_status = 0;
    gbt_body_ = post_one(endpoints_[index], payload, poll_timeout_, &http_status);
    try {
        return BlockTemplate::from_gbt(gbt_body_);
    } catch (const std::invalid_argument& error) {
        throw RpcConnectionError("unparseable body (HTTP " + std::to_string(http_status) +
                                 "): " + error.what());
    }
}

BlockTemplate RpcClient::getblocktemplate_parsed() {
    if (auto failback_template = try_fetch_failback_template())
        return std::move(*failback_template);

    const std::string payload = make_getblocktemplate_payload();
    const size_t count = endpoints_.size();
    const size_t start = current_.load();
    std::string last_error;

    for (size_t offset = 0; offset < count; ++offset) {
        const size_t index = (start + offset) % count;
        BlockTemplate block_template;
        try {
            block_template = fetch_template_from(index, payload);
        } catch (const RpcError& error) {
            if (!endpoint_unavailable(error))
                throw;
            last_error = error.what();
            continue;
        } catch (const RpcConnectionError& e) {
            last_error = e.what();
            continue;
        }
        // Only now is this endpoint proven to be serving work.
        if (index != start) {
            size_t expected = start;
            if (current_.compare_exchange_strong(expected, index))
                log::warning("bitcoind RPC failed over to {}",
                             util::redact_url(endpoints_[index].url));
        }
        return block_template;
    }
    throw RpcConnectionError("all bitcoind endpoints unavailable for mining work: " + last_error);
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
    const glz::generic result = call_payload(payload, timeout_); // patient: never abort a block
    if (result.is_null())
        return std::nullopt; // block accepted
    if (result.is_string())
        return result.get<std::string>();
    return glz::write_json(result).value_or("");
}

glz::generic RpcClient::validateaddress(const std::string& address) {
    glz::generic params = glz::generic::array_t{address};
    return call("validateaddress", params);
}

std::string RpcClient::getbestblockhash() {
    return call("getbestblockhash", glz::generic{}, poll_timeout_).get<std::string>();
}

void RpcClient::maybe_failback(const std::string& expected_tip) {
    if (current_.load() == 0 || expected_tip.empty())
        return; // already on primary / no tip to compare against
    const double now =
        std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
    if (now - last_failback_probe_.load() < kFailbackProbeSeconds)
        return;
    last_failback_probe_.store(now);
    glz::generic request;
    request["jsonrpc"] = "1.0";
    request["id"] = static_cast<double>(++next_id_);
    request["method"] = "getbestblockhash";
    request["params"] = glz::generic::array_t{};
    const std::string payload = glz::write_json(request).value_or("");
    glz::generic result;
    try {
        result = call_one(endpoints_[0], payload, poll_timeout_);
    } catch (const std::exception&) {
        return;
    }
    if (!result.is_string() || result.get<std::string>() != expected_tip)
        return;
    {
        const std::scoped_lock lock(failback_mutex_);
        failback_expected_tip_ = expected_tip;
    }
}

std::optional<BlockTemplate> RpcClient::try_fetch_failback_template() {
    std::optional<std::string> expected_tip;
    {
        const std::scoped_lock lock(failback_mutex_);
        expected_tip = std::exchange(failback_expected_tip_, std::nullopt);
    }
    if (!expected_tip || current_.load() == 0)
        return std::nullopt;

    try {
        BlockTemplate block_template =
            fetch_template_from(0, make_getblocktemplate_payload());
        if (block_template.previousblockhash != *expected_tip)
            return std::nullopt;
        if (current_.exchange(0) != 0)
            log::info("bitcoind RPC failed back to the primary {}",
                      util::redact_url(endpoints_[0].url));
        return block_template;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

glz::generic RpcClient::getblockheader(const std::string& block_hash) {
    glz::generic params = glz::generic::array_t{block_hash};
    return call("getblockheader", params);
}

glz::generic RpcClient::getblockchaininfo() {
    return call("getblockchaininfo");
}

} // namespace erikslund::bitcoin
