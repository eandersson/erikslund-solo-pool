#pragma once
// Coinbase assembly + Stratum split: coinbase1 || extranonce1 || extranonce2 || coinbase2.
// The merkle-root txid uses this legacy form; the submitted block uses legacy_to_witness().
#include <cstddef>
#include <cstdint>
#include <vector>

#include "util/bytes.hpp"

namespace erikslund::bitcoin {

inline constexpr size_t kMaxScriptSig = 100;
inline constexpr size_t kMaxHeightPush = 10;

struct CoinbaseOutput {
    uint64_t value;
    Bytes script;
};

Bytes build_coinbase1(ByteView script_sig_prefix, size_t extranonce_total, ByteView tag,
                      uint32_t version);
Bytes build_coinbase1(int64_t height, size_t extranonce_total, ByteView tag, uint32_t version = 1);
Bytes build_coinbase2(const std::vector<CoinbaseOutput>& outputs,
                      const std::vector<CoinbaseOutput>& required_outputs, ByteView tag,
                      uint32_t sequence = UINT32_MAX, uint32_t lock_time = 0);
Bytes legacy_to_witness(ByteView legacy_coinbase, ByteView witness_item);
Bytes legacy_to_witness(ByteView legacy_coinbase);

} // namespace erikslund::bitcoin
