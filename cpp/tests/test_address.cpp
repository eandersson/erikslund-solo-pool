#include <doctest/doctest.h>

#include <stdexcept>
#include <string>

#include "bitcoin/address.hpp"
#include "bitcoin/network.hpp"
#include "util/base58.hpp"
#include "util/bech32.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using namespace erikslund::util;

namespace {
Bytes script_of(std::string_view a, Network n) { return address_to_script(a, n).value(); }
bool rejected(std::string_view a, Network n) { return !address_to_script(a, n).has_value(); }
} // namespace

TEST_CASE("mainnet P2PKH -> scriptPubKey") {
    CHECK(to_hex(script_of("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Mainnet)) ==
          "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac");
}

TEST_CASE("mainnet P2WPKH -> scriptPubKey") {
    CHECK(to_hex(script_of("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                                   Network::Mainnet)) ==
          "0014751e76e8199196d454941c45d1b3a323f1433bd6");
}

TEST_CASE("mainnet P2WSH -> scriptPubKey") {
    CHECK(to_hex(script_of(
              "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
              Network::Mainnet)) ==
          "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262");
}

TEST_CASE("P2SH round-trips through the script encoder") {
    // Build a mainnet P2SH address (version 0x05) for a known hash, then decode.
    const Bytes hash160 = from_hex("748284390f9e263a4b766a75d0633c50426eb875");
    Bytes payload{0x05};
    append(payload, hash160);
    const std::string addr = base58check_encode(payload);
    CHECK(to_hex(script_of(addr, Network::Mainnet)) ==
          "a914748284390f9e263a4b766a75d0633c50426eb87587");
}

TEST_CASE("regtest P2PKH path (testnet prefix 0x6f)") {
    const Bytes hash160 = from_hex("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
    Bytes payload{0x6f};
    append(payload, hash160);
    const std::string addr = base58check_encode(payload);
    CHECK(to_hex(script_of(addr, Network::Regtest)) ==
          "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac");
}

TEST_CASE("wrong network is rejected") {
    // Mainnet bech32 under regtest hrp.
    CHECK(rejected("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Network::Regtest));
    // Mainnet P2PKH under regtest base58 version.
    CHECK(rejected("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", Network::Regtest));
    // Pure garbage.
    CHECK(rejected("not-an-address", Network::Mainnet));
}

TEST_CASE("mainnet P2TR (v1 taproot) -> OP_1 push32 scriptPubKey") {
    // Derive the address from a known 32-byte program so the expectation is exact.
    const Bytes program =
        from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
    const std::string addr = segwit_address_encode("bc", 1, program);
    // scriptPubKey for witness v1 = 0x51 (OP_1) 0x20 (push 32) || program.
    CHECK(to_hex(script_of(addr, Network::Mainnet)) == "5120" + to_hex(program));
}

TEST_CASE("testnet/signet share the 'tb' bech32 hrp") {
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string addr = segwit_address_encode("tb", 0, program);
    CHECK(to_hex(script_of(addr, Network::Testnet)) == "0014" + to_hex(program));
    CHECK(to_hex(script_of(addr, Network::Signet)) == "0014" + to_hex(program));
    // The same address is wrong under mainnet's 'bc' hrp.
    CHECK(rejected(addr, Network::Mainnet));
}

TEST_CASE("regtest bech32 (bcrt) P2WPKH decodes") {
    const Bytes program = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const std::string addr = segwit_address_encode("bcrt", 0, program);
    CHECK(to_hex(script_of(addr, Network::Regtest)) == "0014" + to_hex(program));
}

TEST_CASE("regtest P2SH (testnet version 0xc4) -> a914..87") {
    const Bytes hash160 = from_hex("748284390f9e263a4b766a75d0633c50426eb875");
    Bytes payload{0xc4};
    append(payload, hash160);
    const std::string addr = base58check_encode(payload);
    CHECK(to_hex(script_of(addr, Network::Regtest)) ==
          "a914748284390f9e263a4b766a75d0633c50426eb87587");
}

TEST_CASE("a P2PKH address with the wrong checksum is rejected") {
    // Genesis address with its final character mangled.
    CHECK(rejected("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", Network::Mainnet));
}

TEST_CASE("network_from_string accepts the bitcoind chain names") {
    CHECK(network_from_string("main") == Network::Mainnet);
    CHECK(network_from_string("mainnet") == Network::Mainnet);
    CHECK(network_from_string("test") == Network::Testnet);
    CHECK(network_from_string("testnet") == Network::Testnet);
    CHECK(network_from_string("testnet4") == Network::Testnet);
    CHECK(network_from_string("regtest") == Network::Regtest);
    CHECK(network_from_string("signet") == Network::Signet);
    CHECK_FALSE(network_from_string("bogus").has_value());
    CHECK_FALSE(network_from_string("").has_value());
}

TEST_CASE("network_name maps back to the canonical short name") {
    CHECK(network_name(Network::Mainnet) == "main");
    CHECK(network_name(Network::Testnet) == "test");
    CHECK(network_name(Network::Regtest) == "regtest");
    CHECK(network_name(Network::Signet) == "signet");
    // Canonical names round-trip back to the enum.
    CHECK(network_from_string(network_name(Network::Regtest)) == Network::Regtest);
}

TEST_CASE("testnet and signet: every address type (shared tb hrp + testnet base58 versions)") {
    const Bytes h160 = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");
    const Bytes prog32 =
        from_hex("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");

    for (const Network net : {Network::Testnet, Network::Signet}) {
        Bytes p2pkh{0x6f}; // testnet/signet P2PKH version
        append(p2pkh, h160);
        CHECK(to_hex(script_of(base58check_encode(p2pkh), net)) ==
              "76a914" + to_hex(h160) + "88ac");

        Bytes p2sh{0xc4}; // testnet/signet P2SH version
        append(p2sh, h160);
        CHECK(to_hex(script_of(base58check_encode(p2sh), net)) ==
              "a914" + to_hex(h160) + "87");

        CHECK(to_hex(script_of(segwit_address_encode("tb", 0, h160), net)) == // P2WPKH
              "0014" + to_hex(h160));
        CHECK(to_hex(script_of(segwit_address_encode("tb", 1, prog32), net)) == // P2TR
              "5120" + to_hex(prog32));
    }
}

TEST_CASE("testnet4 chain name resolves to testnet address rules end to end") {
    const auto net = network_from_string("testnet4");
    REQUIRE(net == Network::Testnet);
    const Bytes h160 = from_hex("751e76e8199196d454941c45d1b3a323f1433bd6");

    // A testnet (tb) address validates under the testnet4-resolved network.
    CHECK(to_hex(script_of(segwit_address_encode("tb", 0, h160), *net)) ==
          "0014" + to_hex(h160));
    // Mainnet and regtest forms of the same program are rejected on testnet4.
    CHECK(rejected(segwit_address_encode("bc", 0, h160), *net));
    CHECK(rejected(segwit_address_encode("bcrt", 0, h160), *net));
}
