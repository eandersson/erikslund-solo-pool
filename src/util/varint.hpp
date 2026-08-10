#pragma once
// Bitcoin CompactSize ("varint") encoding for counts/lengths in tx serialization.
#include <cstddef>
#include <cstdint>
#include <span>

#include "util/bytes.hpp"

namespace erikslund::util {

// Encode as a CompactSize varint (1, 3, 5, or 9 bytes).
Bytes encode_varint(uint64_t value);

struct Varint {
    uint64_t value;
    size_t consumed; // bytes read
};

// Throws std::invalid_argument if the buffer is too short.
Varint decode_varint(std::span<const uint8_t> in);

} // namespace erikslund::util
