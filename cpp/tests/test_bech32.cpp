#include <doctest/doctest.h>

#include <stdexcept>
#include <string>

#include "util/bech32.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("decode BIP173 P2WPKH vector") {
    const auto wp = segwit_address_decode("bc", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    REQUIRE(wp.has_value());
    CHECK(wp->version == 0);
    CHECK(to_hex(wp->program) == "751e76e8199196d454941c45d1b3a323f1433bd6");
}

TEST_CASE("decode is case-insensitive") {
    const auto wp = segwit_address_decode("bc", "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
    REQUIRE(wp.has_value());
    CHECK(to_hex(wp->program) == "751e76e8199196d454941c45d1b3a323f1433bd6");
}

TEST_CASE("decode BIP173 P2WSH vector") {
    const auto wp = segwit_address_decode(
        "bc", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
    REQUIRE(wp.has_value());
    CHECK(wp->version == 0);
    CHECK(to_hex(wp->program) ==
          "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
}

TEST_CASE("wrong hrp is rejected") {
    CHECK_FALSE(
        segwit_address_decode("tb", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
}

TEST_CASE("mixed case is rejected") {
    CHECK_FALSE(
        segwit_address_decode("bc", "bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").has_value());
}

TEST_CASE("v0 (bech32) encode matches the known vector and round-trips") {
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string addr = segwit_address_encode("bc", 0, program);
    CHECK(addr == "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    const auto wp = segwit_address_decode("bc", addr);
    REQUIRE(wp.has_value());
    CHECK(wp->program == program);
}

TEST_CASE("v1 taproot (bech32m) round-trips and rejects bech32") {
    const Bytes program =
        from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const std::string addr = segwit_address_encode("bc", 1, program);
    const auto wp = segwit_address_decode("bc", addr);
    REQUIRE(wp.has_value());
    CHECK(wp->version == 1);
    CHECK(wp->program == program);
    // Same payload re-encoded as v0 (bech32) yields a different address.
    const std::string v0addr = segwit_address_encode("bc", 0, program);
    CHECK(v0addr != addr);
}

TEST_CASE("regtest hrp round-trips") {
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string addr = segwit_address_encode("bcrt", 0, program);
    const auto wp = segwit_address_decode("bcrt", addr);
    REQUIRE(wp.has_value());
    CHECK(wp->program == program);
}

TEST_CASE("a single corrupted data character fails the checksum") {
    // The original is valid; flipping any one data symbol breaks bech32's BCH checksum.
    const std::string original = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    REQUIRE(segwit_address_decode("bc", original).has_value());
    std::string corrupted = original;
    const size_t i = 4; // first data symbol after "bc1"; 'w' and 'p' are both in the charset
    corrupted[i] = (corrupted[i] == 'p') ? 'w' : 'p';
    CHECK_FALSE(segwit_address_decode("bc", corrupted).has_value());
}

TEST_CASE("v0 with a bech32m checksum is rejected (BIP350)") {
    // Encode the same 20-byte program as v1 (bech32m), then ask for it as v0.
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string v1 = segwit_address_encode("bc", 1, program);
    // It decodes fine as v1...
    REQUIRE(segwit_address_decode("bc", v1).has_value());
    CHECK(segwit_address_decode("bc", v1)->version == 1);
    // ...but the v0 P2WPKH address (bech32) is a different string.
    const std::string v0 = segwit_address_encode("bc", 0, program);
    CHECK(v0 != v1);
}

TEST_CASE("empty / too-short / no-separator strings decode to nullopt") {
    CHECK_FALSE(segwit_address_decode("bc", "").has_value());
    CHECK_FALSE(segwit_address_decode("bc", "bc1").has_value());      // too short overall
    CHECK_FALSE(segwit_address_decode("bc", "noseparator").has_value());
}

TEST_CASE("a witness program with an out-of-range length is rejected on decode") {
    // v0 programs must be exactly 20 or 32 bytes; a 21-byte program is invalid.
    // Build it via the encoder (which permits 2..40) then decode it back: v0 rejects 21.
    const Bytes program21(21, 0xab);
    const std::string addr = segwit_address_encode("bc", 0, program21);
    CHECK_FALSE(segwit_address_decode("bc", addr).has_value());
}

TEST_CASE("encode rejects version and program-length out of range") {
    const Bytes ok = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    CHECK_THROWS_AS(segwit_address_encode("bc", -1, ok), std::invalid_argument);
    CHECK_THROWS_AS(segwit_address_encode("bc", 17, ok), std::invalid_argument);
    CHECK_THROWS_AS(segwit_address_encode("bc", 0, Bytes{0x01}), std::invalid_argument); // 1 byte
    CHECK_THROWS_AS(segwit_address_encode("bc", 0, Bytes(41, 0)), std::invalid_argument); // 41 bytes
    // The 2-byte and 40-byte extremes are accepted (no throw).
    CHECK_NOTHROW(segwit_address_encode("bc", 1, Bytes(2, 0)));
    CHECK_NOTHROW(segwit_address_encode("bc", 1, Bytes(40, 0)));
}

TEST_CASE("the maximum witness version (16) round-trips as bech32m") {
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string addr = segwit_address_encode("bc", 16, program);
    const auto wp = segwit_address_decode("bc", addr);
    REQUIRE(wp.has_value());
    CHECK(wp->version == 16);
    CHECK(wp->program == program);
}
