#pragma once
// bech32 / bech32m segwit address coding (BIP173 + BIP350).
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "util/bytes.hpp"

namespace erikslund::util {

struct WitnessProgram {
    int version;    // 0..16
    Bytes program;  // 2..40 bytes
};

// Returns nullopt on any malformed/wrong-hrp/bad-checksum input.
// Enforces BIP350: v0 must be bech32, v1+ must be bech32m.
std::optional<WitnessProgram> segwit_address_decode(std::string_view hrp, std::string_view address);

// Throws std::invalid_argument if version/length are out of range.
std::string segwit_address_encode(std::string_view hrp, int version,
                                  std::span<const uint8_t> program);

} // namespace erikslund::util
