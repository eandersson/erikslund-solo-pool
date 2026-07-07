#include "bitcoin/work_source_rpc.hpp"

#include <cstdint>

#include <glaze/glaze.hpp>

#include "core/errors.hpp"

namespace erikslund::bitcoin {

namespace {
std::string opt_str(glz::generic& obj, const char* key, const std::string& fallback) {
    if (obj.contains(key) && obj[key].is_string())
        return obj[key].get<std::string>();
    return fallback;
}
int64_t opt_int(glz::generic& obj, const char* key, int64_t fallback) {
    if (obj.contains(key) && obj[key].is_number())
        return static_cast<int64_t>(obj[key].get<double>());
    return fallback;
}
int64_t require_int(glz::generic& obj, const char* key) {
    if (!obj.contains(key) || !obj[key].is_number())
        throw RpcError(std::string("bitcoind reply missing numeric field: ") + key);
    return static_cast<int64_t>(obj[key].get<double>());
}
std::string require_str(glz::generic& obj, const char* key) {
    if (!obj.contains(key) || !obj[key].is_string())
        throw RpcError(std::string("bitcoind reply missing string field: ") + key);
    return obj[key].get<std::string>();
}
} // namespace

ChainInfo RpcWorkSource::detect_chain() {
    auto info = client_.getblockchaininfo();
    return ChainInfo{.chain = opt_str(info, "chain", "regtest"), .blocks = opt_int(info, "blocks", 0)};
}

HeaderFacts RpcWorkSource::fetch_header(const std::string& block_hash) {
    auto header = client_.getblockheader(block_hash);
    return HeaderFacts{
        .height = require_int(header, "height"),
        .confirmations = opt_int(header, "confirmations", -1),
        .bits_hex = require_str(header, "bits"),
        .mediantime = static_cast<uint32_t>(require_int(header, "mediantime")),
    };
}

} // namespace erikslund::bitcoin
