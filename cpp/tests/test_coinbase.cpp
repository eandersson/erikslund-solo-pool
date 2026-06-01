#include <doctest/doctest.h>

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "bitcoin/coinbase.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using namespace erikslund::util;

namespace {
Bytes tag(const std::string& s) { return Bytes(s.begin(), s.end()); }
} // namespace

TEST_CASE("build_coinbase1 frames version, the single null input, and scriptSig length") {
    // height 170 -> push "02aa00" (3 bytes); extranonce_total 8; tag 11 bytes -> scriptSig 22 = 0x16.
    const Bytes cb1 = build_coinbase1(170, 8, tag("/erikslund/"), 1);
    const std::string hex = to_hex(cb1);
    // nVersion (le) + input count + 36-byte null prevout.
    CHECK(hex.rfind("01000000" "01"
                    "0000000000000000000000000000000000000000000000000000000000000000"
                    "ffffffff",
                    0) == 0);
    // ...then the scriptSig length varint (0x16) and the height push.
    CHECK(hex.substr(hex.size() - 8) == "1602aa00");
}

TEST_CASE("build_coinbase1 honors a non-default nVersion") {
    const Bytes cb1 = build_coinbase1(1, 8, tag("/x/"), 0x20000000);
    // little-endian 0x20000000 == bytes 00 00 00 20.
    CHECK(to_hex(cb1).rfind("00000020", 0) == 0);
}

TEST_CASE("scriptSig length is height_push + extranonce_total + tag, encoded as a varint") {
    // height 1 -> OP_1 push is a single byte (0x51). extranonce_total 8, tag 5 -> 1+8+5 = 14 = 0x0e.
    const Bytes cb1 = build_coinbase1(1, 8, tag("/abc/"));
    CHECK(to_hex(cb1).substr(to_hex(cb1).size() - 4) == "0e51"); // varint 0x0e then OP_1
}

TEST_CASE("build_coinbase1 rejects a scriptSig over the 100-byte cap") {
    // A tag that pushes height_push(1) + extranonce(8) + tag past 100 must throw.
    CHECK_THROWS_AS(build_coinbase1(1, 8, tag(std::string(92, 'x'))), std::invalid_argument);
    // 91-byte tag: 1 + 8 + 91 = 100 exactly -> accepted.
    CHECK_NOTHROW(build_coinbase1(1, 8, tag(std::string(91, 'x'))));
}

TEST_CASE("the scriptSig cap accounts for a multi-byte height push") {
    // height 500000 -> 4-byte push (0x20a107 preceded by length). push bytes = 4.
    // 4 + 8 + 88 = 100 -> accepted; 4 + 8 + 89 = 101 -> rejected.
    CHECK_NOTHROW(build_coinbase1(500000, 8, tag(std::string(88, 'x'))));
    CHECK_THROWS_AS(build_coinbase1(500000, 8, tag(std::string(89, 'x'))), std::invalid_argument);
}

TEST_CASE("build_coinbase2 lays out tag, sequence, outputs, and locktime") {
    std::vector<CoinbaseOutput> outputs;
    outputs.push_back({0x0102030405060708ULL, from_hex("76a914") /* arbitrary short script */});
    const Bytes cb2 = build_coinbase2(outputs, std::nullopt, tag("/t/"));
    const std::string hex = to_hex(cb2);
    // Leading tag then the 0xffffffff sequence.
    CHECK(hex.rfind(to_hex(tag("/t/")) + "ffffffff", 0) == 0);
    // One output -> count varint 0x01.
    CHECK(hex.find("ffffffff" "01") != std::string::npos);
    // Amount little-endian, then script-length varint (0x03) + the script.
    CHECK(hex.find("0807060504030201" "03" "76a914") != std::string::npos);
    // Trailing locktime is four zero bytes.
    CHECK(hex.substr(hex.size() - 8) == "00000000");
}

TEST_CASE("a witness commitment adds one more output to the count") {
    std::vector<CoinbaseOutput> outputs;
    outputs.push_back({5000000000ULL, from_hex("0014") /* placeholder */});
    const Bytes without = build_coinbase2(outputs, std::nullopt, tag("/t/"));
    const Bytes with = build_coinbase2(outputs, from_hex("6a24aa21a9ed"), tag("/t/"));
    // Two outputs vs one: with-commitment is longer and carries the commitment script.
    CHECK(with.size() > without.size());
    CHECK(to_hex(with).find("6a24aa21a9ed") != std::string::npos);
    // The commitment output has a zero amount (8 LE zero bytes before its script length).
    CHECK(to_hex(with).find("0000000000000000" "06" "6a24aa21a9ed") != std::string::npos);
}

TEST_CASE("legacy_to_witness inserts the marker/flag and the reserved-value witness") {
    // Minimal legacy coinbase: 4-byte version, a 1-byte body, 4-byte locktime (9 bytes total).
    const Bytes legacy = from_hex("01000000" "ab" "00000000");
    const Bytes witness = legacy_to_witness(legacy);
    const std::string hex = to_hex(witness);
    // version, then 00 01 marker/flag, then the body.
    CHECK(hex.rfind("01000000" "0001" "ab", 0) == 0);
    // One witness item of 32 reserved zero bytes (01 20 <32 zero>) before the locktime.
    CHECK(hex.find("0120" + std::string(64, '0') + "00000000") != std::string::npos);
    CHECK(hex.substr(hex.size() - 8) == "00000000"); // locktime preserved at the tail
}

TEST_CASE("legacy_to_witness rejects a coinbase shorter than 8 bytes") {
    CHECK_THROWS_AS(legacy_to_witness(from_hex("0100000000")), std::invalid_argument); // 5 bytes
}
