#pragma once
// BIP34 block-height script encoding for the coinbase.
#include <cstdint>

#include "util/bytes.hpp"
#include "util/varint.hpp"

namespace erikslund::bitcoin {

inline Bytes serialize_height(int64_t height) {
    if (height == 0)
        return Bytes{0x00};
    if (height >= 1 && height <= 16)
        return Bytes{uint8_t(0x50 + height)};

    Bytes magnitude;
    int64_t n = height;
    while (n) {
        magnitude.push_back(uint8_t(n & 0xff));
        n >>= 8;
    }
    if (magnitude.back() & 0x80)
        magnitude.push_back(0x00);

    Bytes out;
    out.push_back(uint8_t(magnitude.size()));
    append(out, magnitude);
    return out;
}

} // namespace erikslund::bitcoin
