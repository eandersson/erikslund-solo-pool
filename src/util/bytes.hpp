#pragma once
// Owning Bytes + non-owning ByteView aliases and small append helpers.
#include <cstdint>
#include <initializer_list>
#include <span>
#include <vector>

namespace erikslund {

using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;

inline void append(Bytes& dst, ByteView src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

inline void append(Bytes& dst, std::initializer_list<uint8_t> src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

} // namespace erikslund
