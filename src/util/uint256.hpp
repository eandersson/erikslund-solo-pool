#pragma once
// 256-bit block hash / mining target. Stored little-endian (the order sha256d
// emits) but compares as a 256-bit big integer, so `hash <= target` is natural.
#include <array>
#include <compare>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace erikslund::util {

class uint256 {
public:
    uint256() = default;

    // Raw little-endian bytes (e.g. from sha256d). Shorter span zero-extends high bytes.
    static uint256 from_le_bytes(std::span<const uint8_t> little_endian);

    // Big-endian "display" hex as shown by bitcoind / block explorers.
    static uint256 from_display_hex(std::string_view hex);

    const std::array<uint8_t, 32>& le_bytes() const { return bytes_; }
    std::string to_display_hex() const;
    bool is_zero() const;

    std::strong_ordering operator<=>(const uint256& other) const;
    bool operator==(const uint256& other) const = default;

private:
    std::array<uint8_t, 32> bytes_{}; // little-endian
};

} // namespace erikslund::util
