#include "util/uint256.hpp"

#include <algorithm>
#include <stdexcept>

#include "util/endian.hpp"
#include "util/hex.hpp"

namespace erikslund::util {

uint256 uint256::from_le_bytes(std::span<const uint8_t> little_endian) {
    if (little_endian.size() > 32)
        throw std::invalid_argument("uint256: more than 32 bytes");
    uint256 result;
    std::copy(little_endian.begin(), little_endian.end(), result.bytes_.begin());
    return result;
}

uint256 uint256::from_display_hex(std::string_view hex) {
    const Bytes big_endian = from_hex(hex); // MSB first
    if (big_endian.size() > 32)
        throw std::invalid_argument("uint256: hex longer than 32 bytes");
    uint256 result;
    // BE -> LE, right-aligned at low bytes.
    for (size_t i = 0; i < big_endian.size(); ++i)
        result.bytes_[i] = big_endian[big_endian.size() - 1 - i];
    return result;
}

std::string uint256::to_display_hex() const {
    return to_hex(reversed(bytes_));
}

bool uint256::is_zero() const {
    return std::ranges::all_of(bytes_, [](uint8_t byte) { return byte == 0; });
}

std::strong_ordering uint256::operator<=>(const uint256& other) const {
    for (int i = 31; i >= 0; --i) {
        const auto index = static_cast<size_t>(i);
        if (bytes_[index] != other.bytes_[index])
            return bytes_[index] <=> other.bytes_[index];
    }
    return std::strong_ordering::equal;
}

} // namespace erikslund::util
