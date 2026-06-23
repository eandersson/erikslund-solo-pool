#pragma once
// Hex <-> bytes.
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "util/bytes.hpp"

namespace erikslund::util {

std::string to_hex(std::span<const uint8_t> data);

// True iff non-empty, even-length, and all hex digits.
bool is_hex(std::string_view text) noexcept;

// Throws std::invalid_argument on odd length or non-hex char. Accepts either case.
Bytes from_hex(std::string_view text);

// Decode onto `out`'s tail (no temporary), for the multi-MB GBT-parse buffer. Same validation as
// from_hex; on throw, `out` keeps the bytes decoded before the bad digit.
void from_hex_append(Bytes& out, std::string_view text);

// Parse 1..8 hex digits (Stratum ntime/nonce/version). Throws on empty/too-long/non-hex.
uint32_t parse_hex_u32(std::string_view text);

std::optional<Bytes> try_from_hex(std::string_view text);
std::optional<uint32_t> try_parse_hex_u32(std::string_view text) noexcept;

} // namespace erikslund::util
