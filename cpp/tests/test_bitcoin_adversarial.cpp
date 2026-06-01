// Adversarial / negative coverage for bitcoin/address and bitcoin/coinbase.
#include <doctest/doctest.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "bitcoin/address.hpp"
#include "bitcoin/coinbase.hpp"
#include "bitcoin/network.hpp"
#include "util/base58.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using namespace erikslund::util;

namespace {
Bytes tag(const std::string& s) { return Bytes(s.begin(), s.end()); }
} // namespace

TEST_CASE("address_to_script throws on empty and whitespace addresses") {
    CHECK_THROWS_AS(address_to_script("", Network::Mainnet), std::invalid_argument);
    CHECK_THROWS_AS(address_to_script(" ", Network::Mainnet), std::invalid_argument);
    CHECK_THROWS_AS(address_to_script("   ", Network::Regtest), std::invalid_argument);
}

TEST_CASE("address_to_script throws on pure garbage") {
    for (const char* g : {"not-an-address", "hello world", "1234567890", "!!!!!!",
                          "0x1234", "bc1", "tb1", "@@@@"}) {
        CHECK_THROWS_AS(address_to_script(g, Network::Mainnet), std::invalid_argument);
    }
}

TEST_CASE("address_to_script throws on an oversized junk string (no overrun)") {
    CHECK_THROWS_AS(address_to_script(std::string(5000, 'x'), Network::Mainnet),
                    std::invalid_argument);
    CHECK_THROWS_AS(address_to_script(std::string(5000, '1'), Network::Mainnet),
                    std::invalid_argument);
}

TEST_CASE("a mainnet P2PKH address is rejected under regtest") {
    CHECK_THROWS_AS(address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Regtest),
                    std::invalid_argument);
}

TEST_CASE("a mainnet bech32 address is rejected under every non-mainnet network") {
    const char* mainnet = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    CHECK_THROWS_AS(address_to_script(mainnet, Network::Regtest), std::invalid_argument);
    CHECK_THROWS_AS(address_to_script(mainnet, Network::Testnet), std::invalid_argument);
    CHECK_THROWS_AS(address_to_script(mainnet, Network::Signet), std::invalid_argument);
}

TEST_CASE("a testnet-prefixed base58 address is rejected under mainnet") {
    // Build a testnet P2PKH (version 0x6f); it must not decode under mainnet versions.
    const Bytes hash160 = from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    Bytes payload{0x6f};
    append(payload, hash160);
    const std::string testnet_addr = base58check_encode(payload);
    CHECK_THROWS_AS(address_to_script(testnet_addr, Network::Mainnet), std::invalid_argument);
}

TEST_CASE("a P2PKH address with a corrupted checksum is rejected") {
    CHECK_THROWS_AS(address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", Network::Mainnet),
                    std::invalid_argument);
    CHECK_THROWS_AS(address_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfff", Network::Mainnet),
                    std::invalid_argument);
}

TEST_CASE("a bech32 address with one flipped data symbol is rejected") {
    std::string addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    addr[10] = (addr[10] == 'q') ? 'p' : 'q';
    CHECK_THROWS_AS(address_to_script(addr, Network::Mainnet), std::invalid_argument);
}

TEST_CASE("a base58check payload of the wrong length is not a recognized address") {
    // A valid checksum but a 20-byte payload (not the 21 a versioned hash160 needs).
    const Bytes payload = from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"); // 20 bytes
    const std::string addr = base58check_encode(payload);
    // base58check_decode succeeds (checksum is valid) but size != 21 -> unrecognized.
    CHECK_THROWS_AS(address_to_script(addr, Network::Mainnet), std::invalid_argument);
}

TEST_CASE("a base58check address with an unknown version byte is rejected") {
    // Version 0x42 is neither P2PKH (0x00) nor P2SH (0x05) on mainnet.
    const Bytes hash160 = from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    Bytes payload{0x42};
    append(payload, hash160);
    const std::string addr = base58check_encode(payload);
    CHECK_THROWS_AS(address_to_script(addr, Network::Mainnet), std::invalid_argument);
}

TEST_CASE("build_coinbase1 rejects a scriptSig pushed over the 100-byte cap") {
    // height 1 (1-byte push) + extranonce_total 8 + tag must stay <= 100.
    CHECK_THROWS_AS(build_coinbase1(1, 8, tag(std::string(92, 'x'))), std::invalid_argument);
    CHECK_THROWS_AS(build_coinbase1(1, 8, tag(std::string(200, 'x'))), std::invalid_argument);
    // Exactly 100 (1 + 8 + 91) is accepted.
    CHECK_NOTHROW(build_coinbase1(1, 8, tag(std::string(91, 'x'))));
}

TEST_CASE("the scriptSig cap correctly accounts for a multi-byte height push") {
    // height 500000 -> 4-byte push (3 value bytes + 1 length byte counted by the impl).
    CHECK_NOTHROW(build_coinbase1(500000, 8, tag(std::string(88, 'x'))));   // 100 exactly
    CHECK_THROWS_AS(build_coinbase1(500000, 8, tag(std::string(89, 'x'))),  // 101
                    std::invalid_argument);
}

TEST_CASE("a huge extranonce_total alone can exceed the cap and is rejected") {
    CHECK_THROWS_AS(build_coinbase1(1, 200, tag("/x/")), std::invalid_argument);
    CHECK_THROWS_AS(build_coinbase1(1, 100, tag("")), std::invalid_argument); // 1 + 100 + 0 = 101
}

TEST_CASE("absurdly large block heights still build a coinbase without crashing") {
    // A height needing many push bytes; with a tiny tag and zero extranonce it fits.
    CHECK_NOTHROW(build_coinbase1(2100000000LL, 0, tag("/x/")));   // > 21M-block era
    CHECK_NOTHROW(build_coinbase1(4000000000LL, 0, tag("/x/")));   // ~ uint32 range
    // The maximum a 6-byte BIP34 push could carry stays under kMaxHeightPush(10).
    CHECK_NOTHROW(build_coinbase1(1000000000000LL, 0, tag("/")));  // 10^12
}

TEST_CASE("height 0 and height 1 (OP_0 / OP_1) build without throwing") {
    CHECK_NOTHROW(build_coinbase1(0, 8, tag("/x/")));
    CHECK_NOTHROW(build_coinbase1(1, 8, tag("/x/")));
}

TEST_CASE("legacy_to_witness rejects a coinbase shorter than 8 bytes (version + locktime)") {
    CHECK_THROWS_AS(legacy_to_witness(from_hex("")), std::invalid_argument);          // 0
    CHECK_THROWS_AS(legacy_to_witness(from_hex("00")), std::invalid_argument);        // 1
    CHECK_THROWS_AS(legacy_to_witness(from_hex("0100000000")), std::invalid_argument); // 5
    CHECK_THROWS_AS(legacy_to_witness(from_hex("01000000000000")), std::invalid_argument); // 7
    // 8 bytes (4-byte version + 4-byte locktime, empty body) is the accepted boundary.
    CHECK_NOTHROW(legacy_to_witness(from_hex("0100000000000000")));
}
