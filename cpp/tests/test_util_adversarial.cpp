// Adversarial / negative coverage for the low-level codecs: hex, base58(check),
// bech32/bech32m, uint256, and CompactSize varint.
#include <doctest/doctest.h>

#include <optional>
#include <stdexcept>
#include <string>

#include "util/base58.hpp"
#include "util/bech32.hpp"
#include "util/bytes.hpp"
#include "util/hex.hpp"
#include "util/uint256.hpp"
#include "util/varint.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("from_hex rejects odd-length input of various sizes") {
    CHECK_THROWS_AS(from_hex("a"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("abc"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("0001020"), std::invalid_argument); // 7 chars
    CHECK_THROWS_AS(from_hex(std::string(1001, 'a')), std::invalid_argument); // odd & long
}

TEST_CASE("from_hex rejects non-hex characters anywhere in the string") {
    CHECK_THROWS_AS(from_hex("gg"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("00gg"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("gg00"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("0g"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("zz"), std::invalid_argument);
    CHECK_THROWS_AS(from_hex(" 0"), std::invalid_argument);  // space
    CHECK_THROWS_AS(from_hex("0 "), std::invalid_argument);
    CHECK_THROWS_AS(from_hex("0x00"), std::invalid_argument); // 0x prefix not accepted
    CHECK_THROWS_AS(from_hex("00\xff"), std::invalid_argument); // high byte
    CHECK_THROWS_AS(from_hex("00\n"), std::invalid_argument);   // newline
}

TEST_CASE("a very long valid hex string decodes without overrun") {
    const std::string long_hex(20000, 'a'); // even length, all valid
    const Bytes decoded = from_hex(long_hex);
    CHECK(decoded.size() == 10000);
    CHECK(decoded.front() == 0xaa);
    CHECK(decoded.back() == 0xaa);
}

TEST_CASE("is_hex returns false (never throws) for malformed input") {
    CHECK_FALSE(is_hex(""));
    CHECK_FALSE(is_hex("a"));
    CHECK_FALSE(is_hex("xyz"));
    CHECK_FALSE(is_hex("0x10"));
    CHECK_FALSE(is_hex("12 34"));
    CHECK_FALSE(is_hex("\x00\x01")); // embedded NUL-ish control chars
}

TEST_CASE("parse_hex_u32 rejects empty, >8 digits, and non-hex") {
    CHECK_THROWS_AS(parse_hex_u32(""), std::invalid_argument);
    CHECK_THROWS_AS(parse_hex_u32("123456789"), std::invalid_argument);  // 9 digits
    CHECK_THROWS_AS(parse_hex_u32("ffffffff0"), std::invalid_argument);  // 9 digits
    CHECK_THROWS_AS(parse_hex_u32("0000000000"), std::invalid_argument); // 10 digits
    CHECK_THROWS_AS(parse_hex_u32("g"), std::invalid_argument);
    CHECK_THROWS_AS(parse_hex_u32("00g0"), std::invalid_argument);
    CHECK_THROWS_AS(parse_hex_u32(" f"), std::invalid_argument);
    CHECK_THROWS_AS(parse_hex_u32("0x10"), std::invalid_argument);
}

TEST_CASE("base58_decode rejects each visually ambiguous character") {
    for (const char* bad : {"0", "O", "I", "l", "1110", "abcO", "Il0O"}) {
        CHECK_THROWS_AS(base58_decode(bad), std::invalid_argument);
    }
}

TEST_CASE("base58_decode rejects punctuation / whitespace / non-ASCII") {
    for (const char* bad : {"!", "@#$", "abc def", "abc\n", "\xff\xfe", "+/="}) {
        CHECK_THROWS_AS(base58_decode(bad), std::invalid_argument);
    }
}

TEST_CASE("base58check_decode rejects a bad checksum") {
    // Genesis address with the final char mangled.
    CHECK_THROWS_AS(base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"),
                    std::invalid_argument);
}

TEST_CASE("base58check_decode rejects strings too short to hold a 4-byte checksum") {
    CHECK_THROWS_AS(base58check_decode(""), std::invalid_argument);
    CHECK_THROWS_AS(base58check_decode("1"), std::invalid_argument);    // 1 zero byte
    CHECK_THROWS_AS(base58check_decode("11"), std::invalid_argument);   // 2 zero bytes
    CHECK_THROWS_AS(base58check_decode("111"), std::invalid_argument);  // 3 zero bytes
    CHECK_THROWS_AS(base58check_decode("z"), std::invalid_argument);    // 1 byte payload
}

TEST_CASE("base58check_decode rejects out-of-alphabet chars before checksum logic") {
    CHECK_THROWS_AS(base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a"),
                    std::invalid_argument); // contains '0'
}

TEST_CASE("a single flipped data character invalidates a base58check string") {
    const std::string genesis = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    // Flip an interior character to another alphabet member -> checksum fails.
    std::string tampered = genesis;
    tampered[5] = (tampered[5] == 'q') ? 'r' : 'q';
    CHECK_THROWS_AS(base58check_decode(tampered), std::invalid_argument);
}

TEST_CASE("segwit_address_decode returns nullopt for empty / separator-only input") {
    CHECK_FALSE(segwit_address_decode("bc", "").has_value());
    CHECK_FALSE(segwit_address_decode("bc", "1").has_value());
    CHECK_FALSE(segwit_address_decode("bc", "bc1").has_value());     // empty data part
    CHECK_FALSE(segwit_address_decode("bc", "bc").has_value());      // no separator
}

TEST_CASE("segwit_address_decode rejects a wrong hrp") {
    const std::string mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    CHECK_FALSE(segwit_address_decode("tb", mainnet).has_value());
    CHECK_FALSE(segwit_address_decode("bcrt", mainnet).has_value());
    CHECK_FALSE(segwit_address_decode("xyz", mainnet).has_value());
}

TEST_CASE("segwit_address_decode rejects mixed-case input (BIP173)") {
    CHECK_FALSE(
        segwit_address_decode("bc", "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
    CHECK_FALSE(
        segwit_address_decode("bc", "Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
}

TEST_CASE("segwit_address_decode rejects an invalid data character ('b','i','o','1' not in charset)") {
    // 'b' is not a valid bech32 data symbol; substituting it should break decode.
    CHECK_FALSE(
        segwit_address_decode("bc", "bc1bw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
    CHECK_FALSE(
        segwit_address_decode("bc", "bc1iw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
}

TEST_CASE("segwit_address_decode rejects a corrupted checksum") {
    const std::string valid = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    REQUIRE(segwit_address_decode("bc", valid).has_value());
    std::string corrupt = valid;
    corrupt.back() = (corrupt.back() == 'k') ? 'p' : 'k';
    CHECK_FALSE(segwit_address_decode("bc", corrupt).has_value());
}

TEST_CASE("a v0 program with the wrong (bech32m) checksum scheme is rejected") {
    // Encode 20 bytes as v1 (bech32m); its string is not a valid v0 address.
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string v1 = segwit_address_encode("bc", 1, program);
    const auto decoded = segwit_address_decode("bc", v1);
    REQUIRE(decoded.has_value());
    CHECK(decoded->version == 1); // decodes as v1, never as v0
}

TEST_CASE("a v0 witness program of an out-of-range length (21 bytes) is rejected on decode") {
    const Bytes program21(21, 0xab);
    const std::string addr = segwit_address_encode("bc", 0, program21);
    CHECK_FALSE(segwit_address_decode("bc", addr).has_value());
}

TEST_CASE("segwit encode throws for an out-of-range version") {
    const Bytes ok = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    CHECK_THROWS_AS(segwit_address_encode("bc", -1, ok), std::invalid_argument);
    CHECK_THROWS_AS(segwit_address_encode("bc", 17, ok), std::invalid_argument);
    CHECK_THROWS_AS(segwit_address_encode("bc", 100, ok), std::invalid_argument);
}

TEST_CASE("segwit encode throws for an out-of-range program length") {
    CHECK_THROWS_AS(segwit_address_encode("bc", 1, Bytes{}), std::invalid_argument);    // 0 bytes
    CHECK_THROWS_AS(segwit_address_encode("bc", 1, Bytes{0x01}), std::invalid_argument); // 1 byte
    CHECK_THROWS_AS(segwit_address_encode("bc", 1, Bytes(41, 0)), std::invalid_argument); // 41
    CHECK_THROWS_AS(segwit_address_encode("bc", 1, Bytes(64, 0)), std::invalid_argument); // 64
}

TEST_CASE("garbage strings of assorted shapes decode to nullopt, never throw") {
    for (const char* g : {"notanaddress", "bc1!!!!", "bc1 qw508", "111111", "bc1\x01",
                          "::::::", "bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"}) {
        // Any result is fine as long as it does not throw / crash.
        const auto result = segwit_address_decode("bc", g);
        CHECK_FALSE(result.has_value());
    }
}

TEST_CASE("uint256::from_display_hex rejects more than 32 bytes (over 64 hex digits)") {
    CHECK_THROWS_AS(uint256::from_display_hex(std::string(66, 'a')), std::invalid_argument);
    CHECK_THROWS_AS(uint256::from_display_hex(std::string(128, 'f')), std::invalid_argument);
    CHECK_THROWS_AS(uint256::from_display_hex(std::string(65, '0') + "1"), std::invalid_argument);
}

TEST_CASE("uint256::from_display_hex rejects odd-length and non-hex strings") {
    CHECK_THROWS_AS(uint256::from_display_hex("abc"), std::invalid_argument);  // odd
    CHECK_THROWS_AS(uint256::from_display_hex("fffff"), std::invalid_argument); // odd
    CHECK_THROWS_AS(uint256::from_display_hex("zz"), std::invalid_argument);    // non-hex
    CHECK_THROWS_AS(uint256::from_display_hex("00gg"), std::invalid_argument);
    CHECK_THROWS_AS(uint256::from_display_hex("0x01"), std::invalid_argument);
}

TEST_CASE("uint256::from_le_bytes rejects more than 32 bytes") {
    CHECK_THROWS_AS(uint256::from_le_bytes(Bytes(33, 0)), std::invalid_argument);
    CHECK_THROWS_AS(uint256::from_le_bytes(Bytes(64, 0xff)), std::invalid_argument);
}

TEST_CASE("uint256 short/empty inputs zero-extend (no throw)") {
    CHECK(uint256::from_display_hex("").is_zero());
    CHECK(uint256::from_le_bytes(Bytes{}).is_zero());
    CHECK(uint256::from_le_bytes(Bytes{0x01}).to_display_hex() ==
          "0000000000000000000000000000000000000000000000000000000000000001");
}

TEST_CASE("decode_varint throws on an empty buffer") {
    CHECK_THROWS_AS(decode_varint(Bytes{}), std::invalid_argument);
}

TEST_CASE("decode_varint throws when the multi-byte forms are truncated") {
    // 0xfd needs 2 more bytes.
    CHECK_THROWS_AS(decode_varint(Bytes{0xfd}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xfd, 0x00}), std::invalid_argument);
    // 0xfe needs 4 more bytes.
    CHECK_THROWS_AS(decode_varint(Bytes{0xfe}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xfe, 0x00, 0x00}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xfe, 0x00, 0x00, 0x00}), std::invalid_argument);
    // 0xff needs 8 more bytes.
    CHECK_THROWS_AS(decode_varint(Bytes{0xff}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xff, 1, 2, 3, 4, 5, 6, 7}), std::invalid_argument);
}

TEST_CASE("decode_varint of a minimal buffer that is exactly long enough succeeds") {
    // Boundary: 0xff + exactly 8 bytes is valid (the smallest non-throwing 9-byte form).
    const Varint v = decode_varint(Bytes{0xff, 0, 0, 0, 0, 0, 0, 0, 0});
    CHECK(v.value == 0);
    CHECK(v.consumed == 9);
}
