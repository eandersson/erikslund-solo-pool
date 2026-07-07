#pragma once
// A mineable block template, independent of whether it came from JSON-RPC or Mining IPC.
// Transaction bytes and the coinbase merkle path are already in the shape Job consumes.
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "bitcoin/coinbase.hpp"
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

    Bytes coinbase_script_sig_prefix;
    std::optional<uint32_t> coinbase_version;
    uint32_t coinbase_sequence = UINT32_MAX;
    uint32_t coinbase_lock_time = 0;
    std::optional<Bytes> coinbase_witness;
    std::vector<CoinbaseOutput> coinbase_required_outputs; // appended after pool outputs

    uint32_t txn_count = 0;
    Bytes txn_data; // all non-coinbase transactions, serialized in template order
    std::vector<util::Hash256> merkle_branch_internal;

    static BlockTemplate from_gbt(const std::string& response_json);
};

} // namespace erikslund::bitcoin
