#pragma once
#include <cstddef>

namespace erikslund::util {

inline constexpr std::size_t kHeaderSize = 80;
inline constexpr std::size_t kVersionOffset = 0;
inline constexpr std::size_t kPrevhashOffset = 4;
inline constexpr std::size_t kMerkleOffset = 36;
inline constexpr std::size_t kTimeOffset = 68;
inline constexpr std::size_t kBitsOffset = 72;
inline constexpr std::size_t kNonceOffset = 76;

} // namespace erikslund::util
