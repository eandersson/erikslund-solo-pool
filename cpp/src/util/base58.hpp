#pragma once
// Base58 / Base58Check (legacy P2PKH/P2SH address encoding).
#include <span>
#include <string>
#include <string_view>

#include "util/bytes.hpp"

namespace erikslund::util {

// Throws std::invalid_argument on an out-of-alphabet character.
Bytes base58_decode(std::string_view input);
std::string base58_encode(std::span<const uint8_t> data);

// Verifies + strips the trailing 4-byte double-SHA256 checksum.
Bytes base58check_decode(std::string_view input);
std::string base58check_encode(std::span<const uint8_t> payload);

} // namespace erikslund::util
