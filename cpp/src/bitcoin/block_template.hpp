#pragma once
// A parsed getblocktemplate reply. Transactions are stored pre-concatenated (txn_data) plus a
// txid list -- the shape the Job consumes, so the multi-MB blob is decoded once and moved in.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <simdjson.h>

#include "util/bytes.hpp"
#include "util/sha256.hpp"

namespace erikslund::bitcoin {

struct BlockTemplate {
    int64_t height = 0;
    uint32_t version = 0;
    uint32_t curtime = 0;
    uint32_t bits = 0;
    std::string bits_hex;
    uint64_t coinbase_value = 0;
    std::string previousblockhash;
    std::optional<Bytes> witness_commitment;

    uint32_t txn_count = 0;
    Bytes txn_data;                            // all raw tx bytes, template order
    std::vector<util::Hash256> txids_internal; // internal byte order, template order

    static BlockTemplate from_json(const nlohmann::json& result);
    static BlockTemplate from_simdjson(const simdjson::dom::element& result);
};

} // namespace erikslund::bitcoin
