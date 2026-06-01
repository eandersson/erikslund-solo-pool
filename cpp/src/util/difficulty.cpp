#include "util/difficulty.hpp"

#include <array>

#include "util/endian.hpp"

namespace erikslund::util {

namespace {

// diff-1 target (0xffff * 2^208) and 2^64/2^128/2^192 word scales.
constexpr double kTrueDiffOne =
    26959535291011309493156476344723991336010898738574164086137773096960.0;
constexpr double kBits64 = 18446744073709551616.0;
constexpr double kBits128 = 340282366920938463463374607431768211456.0;
constexpr double kBits192 = 6277101735386680763835789423207666416102355444464034512896.0;

double le256_to_double(const std::array<uint8_t, 32>& target) {
    double value = double(read_le64(target.data() + 24)) * kBits192;
    value += double(read_le64(target.data() + 16)) * kBits128;
    value += double(read_le64(target.data() + 8)) * kBits64;
    value += double(read_le64(target.data()));
    return value;
}

} // namespace

uint256 target_from_compact(uint32_t nbits) {
    const uint32_t exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x007fffff; // drop sign bit; targets are positive

    std::array<uint8_t, 32> target{};
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[0] = uint8_t(mantissa);
        target[1] = uint8_t(mantissa >> 8);
        target[2] = uint8_t(mantissa >> 16);
    } else {
        const size_t index = exponent - 3; // low mantissa byte offset
        if (index <= 31)
            target[index] = uint8_t(mantissa);
        if (index + 1 <= 31)
            target[index + 1] = uint8_t(mantissa >> 8);
        if (index + 2 <= 31)
            target[index + 2] = uint8_t(mantissa >> 16);
    }
    return uint256::from_le_bytes(target);
}

double difficulty_from_target(const uint256& target) {
    const double value = le256_to_double(target.le_bytes());
    if (value == 0.0)
        return 0.0;
    return kTrueDiffOne / value;
}

double difficulty_from_compact(uint32_t nbits) {
    return difficulty_from_target(target_from_compact(nbits));
}

uint256 target_from_difficulty(double difficulty) {
    std::array<uint8_t, 32> target{};
    // A non-positive, NaN, or absurdly tiny difficulty makes kTrueDiffOne/difficulty exceed 2^256,
    // overflowing the double->uint64_t conversions below (UB). Treat it as the easiest target
    // (all-ones); no configured difficulty (min default 0.001) reaches this.
    if (!(difficulty > 2.4e-10)) {
        target.fill(0xff);
        return uint256::from_le_bytes(target);
    }

    double remaining = kTrueDiffOne / difficulty;

    uint64_t word = uint64_t(remaining / kBits192);
    write_le64(target.data() + 24, word);
    remaining -= double(word) * kBits192;

    word = uint64_t(remaining / kBits128);
    write_le64(target.data() + 16, word);
    remaining -= double(word) * kBits128;

    word = uint64_t(remaining / kBits64);
    write_le64(target.data() + 8, word);
    remaining -= double(word) * kBits64;

    word = uint64_t(remaining);
    write_le64(target.data(), word);

    return uint256::from_le_bytes(target);
}

bool meets_target(const uint256& hash, const uint256& target) {
    return hash <= target;
}

} // namespace erikslund::util
