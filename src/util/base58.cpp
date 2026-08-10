#include "util/base58.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>

#include "util/sha256.hpp"

namespace erikslund::util {

namespace {

constexpr char kAlphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

constexpr std::array<int, 256> make_reverse_table() {
    std::array<int, 256> table{};
    for (auto& entry : table)
        entry = -1;
    for (int i = 0; i < 58; ++i)
        table[static_cast<uint8_t>(kAlphabet[i])] = i;
    return table;
}

constexpr auto kReverse = make_reverse_table();

} // namespace

std::optional<Bytes> try_base58_decode(std::string_view input) {
    Bytes digits; // base-256, little-endian during accumulation
    for (char character : input) {
        const int value = kReverse[static_cast<uint8_t>(character)];
        if (value < 0)
            return std::nullopt;
        int carry = value;
        for (uint8_t& byte : digits) {
            carry += byte * 58;
            byte = uint8_t(carry & 0xff);
            carry >>= 8;
        }
        while (carry) {
            digits.push_back(uint8_t(carry & 0xff));
            carry >>= 8;
        }
    }
    // Each leading '1' is a leading zero byte.
    for (char character : input) {
        if (character != '1')
            break;
        digits.push_back(0);
    }
    std::reverse(digits.begin(), digits.end());
    return digits;
}

Bytes base58_decode(std::string_view input) {
    if (auto decoded = try_base58_decode(input))
        return std::move(*decoded);
    throw std::invalid_argument("base58: invalid character");
}

std::string base58_encode(std::span<const uint8_t> data) {
    std::vector<uint8_t> digits; // base-58, little-endian during accumulation
    for (uint8_t byte : data) {
        int carry = byte;
        for (uint8_t& digit : digits) {
            carry += digit << 8;
            digit = uint8_t(carry % 58);
            carry /= 58;
        }
        while (carry) {
            digits.push_back(uint8_t(carry % 58));
            carry /= 58;
        }
    }
    std::string out;
    for (uint8_t byte : data) {
        if (byte != 0)
            break;
        out.push_back('1');
    }
    for (auto it = digits.rbegin(); it != digits.rend(); ++it)
        out.push_back(kAlphabet[*it]);
    return out;
}

std::optional<Bytes> try_base58check_decode(std::string_view input) {
    const auto full = try_base58_decode(input);
    if (!full || full->size() < 4)
        return std::nullopt;
    Bytes payload(full->begin(), full->end() - 4);
    const Hash256 hash = sha256d(payload);
    if (!std::equal(full->end() - 4, full->end(), hash.begin()))
        return std::nullopt;
    return payload;
}

Bytes base58check_decode(std::string_view input) {
    if (auto payload = try_base58check_decode(input))
        return std::move(*payload);
    throw std::invalid_argument("base58check: invalid, too short, or checksum mismatch");
}

std::string base58check_encode(std::span<const uint8_t> payload) {
    const Hash256 hash = sha256d(payload);
    Bytes full(payload.begin(), payload.end());
    full.insert(full.end(), hash.begin(), hash.begin() + 4);
    return base58_encode(full);
}

} // namespace erikslund::util
