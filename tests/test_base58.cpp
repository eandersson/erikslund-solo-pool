#include <doctest/doctest.h>

#include <stdexcept>

#include "util/base58.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("base58check decodes a known P2PKH address") {
    // 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa = the genesis coinbase address.
    const Bytes payload = base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    REQUIRE(payload.size() == 21);
    CHECK(payload[0] == 0x00); // mainnet P2PKH version
    const Bytes hash160(payload.begin() + 1, payload.end());
    CHECK(to_hex(hash160) == "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
}

TEST_CASE("base58 round-trips") {
    const Bytes data = from_hex("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    CHECK(base58_decode(base58_encode(data)) == data);
}

TEST_CASE("base58check round-trips and re-encodes the address") {
    const Bytes payload = from_hex("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    const std::string addr = base58check_encode(payload);
    CHECK(addr == "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    CHECK(base58check_decode(addr) == payload);
}

TEST_CASE("leading ones map to leading zero bytes") {
    const Bytes decoded = base58_decode("111");
    CHECK(decoded == Bytes{0x00, 0x00, 0x00});
}

TEST_CASE("base58check rejects corruption") {
    CHECK_THROWS_AS(base58check_decode("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfff"),
                    std::invalid_argument);
    CHECK_THROWS_AS(base58_decode("0OIl"), std::invalid_argument); // ambiguous chars not in alphabet
}

TEST_CASE("base58 of an empty input is empty, and vice versa") {
    CHECK(base58_encode(Bytes{}) == "");
    CHECK(base58_decode("") == Bytes{});
}

TEST_CASE("base58 alphabet excludes the visually ambiguous characters") {
    // 0 (zero), O (capital o), I (capital i), l (lower L) are not in the alphabet.
    CHECK_THROWS_AS(base58_decode("0"), std::invalid_argument);
    CHECK_THROWS_AS(base58_decode("O"), std::invalid_argument);
    CHECK_THROWS_AS(base58_decode("I"), std::invalid_argument);
    CHECK_THROWS_AS(base58_decode("l"), std::invalid_argument);
}

TEST_CASE("a single zero byte encodes to '1'") {
    CHECK(base58_encode(Bytes{0x00}) == "1");
    CHECK(base58_decode("1") == Bytes{0x00});
}

TEST_CASE("base58 preserves an arbitrary multi-byte value through a round trip") {
    const Bytes data = from_hex("00112233445566778899aabbccddeeff");
    CHECK(base58_decode(base58_encode(data)) == data);
}

TEST_CASE("leading zero bytes map to leading '1's on encode") {
    const Bytes data = from_hex("000012ab");
    const std::string encoded = base58_encode(data);
    REQUIRE(encoded.size() >= 2);
    CHECK(encoded[0] == '1');
    CHECK(encoded[1] == '1');
    CHECK(base58_decode(encoded) == data);
}

TEST_CASE("base58check_decode rejects a string shorter than the 4-byte checksum") {
    // "1111" decodes to 4 zero bytes; stripping a 4-byte checksum leaves an empty
    // payload whose checksum can't match -> mismatch (not the too-short branch).
    CHECK_THROWS_AS(base58check_decode("1111"), std::invalid_argument);
    // "111" decodes to only 3 bytes: too short to even hold a checksum.
    CHECK_THROWS_AS(base58check_decode("111"), std::invalid_argument);
}

TEST_CASE("base58check_encode appends a valid 4-byte double-SHA checksum") {
    // Re-decoding what we encoded must return the original payload unchanged.
    const Bytes payload = from_hex("6f62e907b15cbf27d5425399ebf6f0fb50ebb88f18"); // testnet P2PKH
    const std::string addr = base58check_encode(payload);
    CHECK(base58check_decode(addr) == payload);
    // Flipping the last character breaks the checksum.
    std::string corrupted = addr;
    corrupted.back() = (corrupted.back() == 'A') ? 'B' : 'A';
    CHECK_THROWS_AS(base58check_decode(corrupted), std::invalid_argument);
}
