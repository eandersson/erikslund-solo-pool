#include "util/hex.hpp"

#include <array>
#include <stdexcept>

namespace erikslund::util {

namespace {

constexpr char kHexChars[] = "0123456789abcdef";

// Maps ASCII byte to nibble value, or -1 for non-hex.
constexpr std::array<int, 256> make_hex_table() {
    std::array<int, 256> table{};
    for (auto& entry : table)
        entry = -1;
    for (int i = 0; i < 10; ++i)
        table[static_cast<uint8_t>('0' + i)] = i;
    for (int i = 0; i < 6; ++i) {
        table[static_cast<uint8_t>('a' + i)] = 10 + i;
        table[static_cast<uint8_t>('A' + i)] = 10 + i;
    }
    return table;
}

constexpr auto kHexTable = make_hex_table();

} // namespace

std::string to_hex(std::span<const uint8_t> data) {
    std::string out(data.size() * 2, '\0');
    size_t j = 0;
    for (uint8_t byte : data) {
        out[j++] = kHexChars[byte >> 4];
        out[j++] = kHexChars[byte & 0x0f];
    }
    return out;
}

bool is_hex(std::string_view text) noexcept {
    if (text.empty() || (text.size() % 2) != 0)
        return false;
    for (char c : text)
        if (kHexTable[static_cast<uint8_t>(c)] < 0)
            return false;
    return true;
}

Bytes from_hex(std::string_view text) {
    Bytes out;
    out.reserve(text.size() / 2);
    from_hex_append(out, text);
    return out;
}

void from_hex_append(Bytes& out, std::string_view text) {
    if ((text.size() % 2) != 0)
        throw std::invalid_argument("hex string has odd length");
    out.reserve(out.size() + text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        const int hi = kHexTable[static_cast<uint8_t>(text[i])];
        const int lo = kHexTable[static_cast<uint8_t>(text[i + 1])];
        if (hi < 0 || lo < 0)
            throw std::invalid_argument("hex string has a non-hex character");
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
}

std::optional<Bytes> try_from_hex(std::string_view text) {
    if ((text.size() % 2) != 0)
        return std::nullopt;
    Bytes out;
    out.reserve(text.size() / 2);
    for (size_t i = 0; i < text.size(); i += 2) {
        const int hi = kHexTable[static_cast<uint8_t>(text[i])];
        const int lo = kHexTable[static_cast<uint8_t>(text[i + 1])];
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<uint32_t> try_parse_hex_u32(std::string_view text) noexcept {
    if (text.empty() || text.size() > 8)
        return std::nullopt;
    uint32_t value = 0;
    for (char c : text) {
        const int nibble = kHexTable[static_cast<uint8_t>(c)];
        if (nibble < 0)
            return std::nullopt;
        value = (value << 4) | static_cast<uint32_t>(nibble);
    }
    return value;
}

uint32_t parse_hex_u32(std::string_view text) {
    if (const auto value = try_parse_hex_u32(text))
        return *value;
    throw std::invalid_argument("hex u32: empty, longer than 8 digits, or non-hex");
}

} // namespace erikslund::util
