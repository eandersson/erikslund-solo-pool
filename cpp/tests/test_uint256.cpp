#include <doctest/doctest.h>

#include <stdexcept>
#include <string>

#include "util/bytes.hpp"
#include "util/hex.hpp"
#include "util/uint256.hpp"

using namespace erikslund;
using namespace erikslund::util;

namespace {
std::string value_hex(unsigned low_byte) {
    std::string s(63, '0');
    const char* d = "0123456789abcdef";
    s.push_back(d[low_byte & 0x0f]);
    // only encodes 0..15 in the last nibble; fine for small test values
    return s;
}
} // namespace

TEST_CASE("display hex round-trips") {
    const std::string h = "000000000000000000026f7bba1e5e4a3ba3edfd7a7b12b27ac72c3e67768f61";
    CHECK(uint256::from_display_hex(h).to_display_hex() == h);
}

TEST_CASE("numeric ordering, not lexicographic on stored bytes") {
    const auto one = uint256::from_display_hex(value_hex(1));
    const auto two = uint256::from_display_hex(value_hex(2));
    CHECK(one < two);
    CHECK(two > one);
    CHECK(one != two);
    CHECK(one == uint256::from_display_hex(value_hex(1)));

    // A big high byte must outrank a big low byte.
    const auto high = uint256::from_display_hex(
        "0100000000000000000000000000000000000000000000000000000000000000");
    const auto low = uint256::from_display_hex(
        "00000000000000000000000000000000000000000000000000000000000000ff");
    CHECK(high > low);
}

TEST_CASE("from_le_bytes is the reverse of display order") {
    Bytes le(32, 0);
    le[0] = 0x01; // least significant byte
    CHECK(uint256::from_le_bytes(le).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000000001");
}

TEST_CASE("is_zero") {
    CHECK(uint256{}.is_zero());
    CHECK_FALSE(uint256::from_display_hex(
                    "0000000000000000000000000000000000000000000000000000000000000001")
                    .is_zero());
}

TEST_CASE("default-constructed uint256 is zero and renders all zeros") {
    CHECK(uint256{}.to_display_hex() == std::string(64, '0'));
    CHECK(uint256{} == uint256{});
}

TEST_CASE("from_le_bytes zero-extends a short span into the high bytes") {
    // One low byte; everything above zero-extends.
    const auto v = uint256::from_le_bytes(Bytes{0x01});
    CHECK(v.to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000000001");

    // An empty span is the zero value.
    CHECK(uint256::from_le_bytes(Bytes{}).is_zero());

    // Exactly 32 bytes is accepted; the first byte is least-significant.
    Bytes full(32, 0);
    full[31] = 0xff; // most-significant byte
    CHECK(uint256::from_le_bytes(full).to_display_hex() ==
          "ff00000000000000000000000000000000000000000000000000000000000000");
}

TEST_CASE("from_le_bytes rejects more than 32 bytes") {
    CHECK_THROWS_AS(uint256::from_le_bytes(Bytes(33, 0)), std::invalid_argument);
}

TEST_CASE("from_display_hex accepts short hex (zero-padded high) and rejects oversize/odd") {
    // Fewer than 64 hex digits is left-padded with zeros.
    CHECK(uint256::from_display_hex("ff").to_display_hex() ==
          "00000000000000000000000000000000000000000000000000000000000000ff");
    CHECK(uint256::from_display_hex("").is_zero());

    // More than 32 bytes (over 64 hex digits) is rejected.
    CHECK_THROWS_AS(uint256::from_display_hex(std::string(66, 'a')), std::invalid_argument);
    // Odd-length hex is rejected by the underlying decoder.
    CHECK_THROWS_AS(uint256::from_display_hex("abc"), std::invalid_argument);
}

TEST_CASE("le_bytes exposes the stored little-endian order") {
    const auto v = uint256::from_display_hex(
        "00000000000000000000000000000000000000000000000000000000000000ff");
    CHECK(v.le_bytes()[0] == 0xff); // least-significant byte stored first
    CHECK(v.le_bytes()[31] == 0x00);
}

TEST_CASE("ordering is consistent across <, >, <=, >=") {
    const auto a = uint256::from_display_hex(
        "0000000000000000000000000000000000000000000000000000000000000005");
    const auto b = uint256::from_display_hex(
        "0000000000000000000000000000000000000000000000000000000000000005");
    const auto c = uint256::from_display_hex(
        "0000000000000000000000000000000000000000000000000000000000000006");
    CHECK(a <= b);
    CHECK(a >= b);
    CHECK(a < c);
    CHECK(c >= a);
    CHECK_FALSE(c < a);
}
