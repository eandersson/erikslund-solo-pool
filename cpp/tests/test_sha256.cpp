#include <doctest/doctest.h>

#include <span>
#include <string_view>

#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/sha256.hpp"

using namespace erikslund;
using namespace erikslund::util;

namespace {
Bytes ascii(std::string_view s) {
    return Bytes(s.begin(), s.end());
}
} // namespace

TEST_CASE("sha256 matches NIST/standard vectors") {
    CHECK(to_hex(sha256(ascii(""))) ==
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(to_hex(sha256(ascii("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(to_hex(sha256(ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST_CASE("sha256 handles multi-block input (> 64 bytes)") {
    // 1,000,000 'a' is the classic long vector.
    Bytes million(1'000'000, 'a');
    CHECK(to_hex(sha256(million)) ==
          "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("sha256d is SHA256 of SHA256") {
    CHECK(to_hex(sha256d(ascii(""))) ==
          "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456");
}

TEST_CASE("genesis block header hashes to the known block hash") {
    // 80-byte genesis header; sha256d gives the internal hash, displayed hash is reversed.
    const auto header = from_hex(
        "01000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        "29ab5f49"
        "ffff001d"
        "1dac2b7c");
    const auto internal = sha256d(header);
    CHECK(to_hex(reversed(internal)) ==
          "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
}

TEST_CASE("sha256 of exactly one block (64 bytes) and 55/56-byte padding edges") {
    // 64 zero bytes -- the padding pushes into a second block.
    CHECK(to_hex(sha256(Bytes(64, 0))) ==
          "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b");
    // 56 bytes of 0x00 -- boundary where the 8-byte length no longer fits the first block.
    CHECK(to_hex(sha256(Bytes(56, 0))) ==
          "d4817aa5497628e7c77e6b606107042bbba3130888c5f47a375e6179be789fbb");
    // 55 bytes of 0x00 -- the largest message that pads within a single block.
    CHECK(to_hex(sha256(Bytes(55, 0))) ==
          "02779466cdec163811d078815c633f21901413081449002f24aa3e80f0b88ef7");
}

TEST_CASE("sha256d of 'abc' double-hashes correctly") {
    // sha256d(x) == sha256(sha256(x)); cross-check against the chained single hashes.
    const auto once = sha256(ascii("abc"));
    CHECK(sha256d(ascii("abc")) == sha256(once));
}

TEST_CASE("hashing the same input twice is deterministic") {
    const Bytes data = ascii("erikslund-solo-pool");
    CHECK(sha256(data) == sha256(data));
    CHECK(sha256d(data) == sha256d(data));
}

TEST_CASE("sha256_init selects a backend and runs the self-test") {
    // Idempotent: returns a non-empty backend name and matches sha256_backend().
    const char* backend = sha256_init();
    REQUIRE(backend != nullptr);
    CHECK(std::string_view(backend).size() > 0);
    CHECK(std::string_view(sha256_backend()) == std::string_view(backend));
    // A known vector still holds after explicit init (the self-test didn't corrupt state).
    CHECK(to_hex(sha256(ascii("abc"))) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}
