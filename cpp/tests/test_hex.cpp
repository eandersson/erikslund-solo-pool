#include <doctest/doctest.h>

#include <stdexcept>

#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("to_hex encodes bytes lowercase") {
    CHECK(to_hex(Bytes{0x00, 0x01, 0xff, 0xab}) == "0001ffab");
    CHECK(to_hex(Bytes{0xde, 0xad, 0xbe, 0xef}) == "deadbeef");
    CHECK(to_hex(Bytes{}) == "");
}

TEST_CASE("from_hex decodes, case-insensitive") {
    CHECK(from_hex("0001ffab") == Bytes{0x00, 0x01, 0xff, 0xab});
    CHECK(from_hex("DEADBEEF") == Bytes{0xde, 0xad, 0xbe, 0xef});
    CHECK(from_hex("dEaDbEeF") == Bytes{0xde, 0xad, 0xbe, 0xef});
    CHECK(from_hex("") == Bytes{});
}

TEST_CASE("from_hex rejects malformed input") {
    CHECK_THROWS_AS(from_hex("abc"), std::invalid_argument);   // odd length
    CHECK_THROWS_AS(from_hex("xyzz"), std::invalid_argument);  // non-hex
    CHECK_THROWS_AS(from_hex("00gg"), std::invalid_argument);
}

TEST_CASE("is_hex validates") {
    CHECK(is_hex("00ff"));
    CHECK(is_hex("DEADBEEF"));
    CHECK_FALSE(is_hex("0"));     // odd
    CHECK_FALSE(is_hex("0g"));    // non-hex
    CHECK_FALSE(is_hex(""));      // empty
}

TEST_CASE("hex round-trips") {
    const Bytes original{0, 1, 2, 3, 4, 5, 250, 251, 252, 253, 254, 255};
    CHECK(from_hex(to_hex(original)) == original);
}

TEST_CASE("to_hex covers every nibble value") {
    Bytes all(256);
    for (int i = 0; i < 256; ++i)
        all[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    const std::string encoded = to_hex(all);
    REQUIRE(encoded.size() == 512);
    CHECK(encoded.substr(0, 2) == "00");
    CHECK(encoded.substr(2, 2) == "01");
    CHECK(encoded.substr(20, 2) == "0a");
    CHECK(encoded.substr(510, 2) == "ff");
    CHECK(from_hex(encoded) == all);
}

TEST_CASE("is_hex boundary cases") {
    CHECK(is_hex("00"));
    CHECK(is_hex("0123456789abcdefABCDEF"));
    CHECK_FALSE(is_hex(" 00"));   // leading space is not hex
    CHECK_FALSE(is_hex("00 "));   // trailing space is not hex
    CHECK_FALSE(is_hex("0x00"));  // 0x prefix is not accepted
    CHECK_FALSE(is_hex("g"));     // single non-hex
}

TEST_CASE("parse_hex_u32 parses 1..8 digits, either case") {
    CHECK(parse_hex_u32("0") == 0u);
    CHECK(parse_hex_u32("f") == 0xfu);
    CHECK(parse_hex_u32("ff") == 0xffu);
    CHECK(parse_hex_u32("00000000") == 0u);
    CHECK(parse_hex_u32("deadbeef") == 0xdeadbeefu);
    CHECK(parse_hex_u32("DEADBEEF") == 0xdeadbeefu);
    CHECK(parse_hex_u32("ffffffff") == 0xffffffffu);
    CHECK(parse_hex_u32("1") == 1u);
    CHECK(parse_hex_u32("80000000") == 0x80000000u); // high bit set
}

TEST_CASE("parse_hex_u32 rejects empty, too-long, and non-hex") {
    CHECK_THROWS_AS(parse_hex_u32(""), std::invalid_argument);          // empty
    CHECK_THROWS_AS(parse_hex_u32("123456789"), std::invalid_argument); // 9 digits
    CHECK_THROWS_AS(parse_hex_u32("xx"), std::invalid_argument);        // non-hex
    CHECK_THROWS_AS(parse_hex_u32("00g0"), std::invalid_argument);
}
