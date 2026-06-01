#include <doctest/doctest.h>

#include "bitcoin/serialize.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using namespace erikslund::util;

TEST_CASE("BIP34 height serialization") {
    CHECK(to_hex(serialize_height(0)) == "00");   // OP_0
    CHECK(to_hex(serialize_height(1)) == "51");   // OP_1
    CHECK(to_hex(serialize_height(16)) == "60");  // OP_16
    CHECK(to_hex(serialize_height(17)) == "0111");
    CHECK(to_hex(serialize_height(127)) == "017f");
    CHECK(to_hex(serialize_height(128)) == "028000"); // high bit set -> pad byte
    CHECK(to_hex(serialize_height(170)) == "02aa00");
    CHECK(to_hex(serialize_height(256)) == "020001");
    CHECK(to_hex(serialize_height(500000)) == "0320a107");
    CHECK(to_hex(serialize_height(709632)) == "0300d40a"); // a real taproot-era height
}

TEST_CASE("BIP34 height byte-count boundaries") {
    // 255 fits in one magnitude byte but has the high bit set -> pad byte.
    CHECK(to_hex(serialize_height(255)) == "02ff00");
    // 256 needs two magnitude bytes (0x0100, little-endian).
    CHECK(to_hex(serialize_height(256)) == "020001");
    // 32767 = 0x7fff: high bit clear, so no pad byte (two bytes).
    CHECK(to_hex(serialize_height(32767)) == "02ff7f");
    // 32768 = 0x8000: high bit of the top byte set -> pad byte (three bytes).
    CHECK(to_hex(serialize_height(32768)) == "03008000");
    // 65535 = 0xffff: top byte high bit set -> pad byte.
    CHECK(to_hex(serialize_height(65535)) == "03ffff00");
    // 16777215 = 0xffffff -> pad byte makes it four data bytes.
    CHECK(to_hex(serialize_height(16777215)) == "04ffffff00");
}

TEST_CASE("the length prefix matches the magnitude byte count") {
    // First byte is the push length; the rest are the little-endian magnitude.
    const auto encoded = serialize_height(500000);
    CHECK(encoded[0] == encoded.size() - 1);
    // 17 is the first height that uses the explicit push form (not OP_N).
    CHECK(to_hex(serialize_height(17)) == "0111");
}

TEST_CASE("heights 1..16 use the single-byte OP_1..OP_16 opcodes") {
    for (int n = 1; n <= 16; ++n) {
        const auto encoded = serialize_height(n);
        REQUIRE(encoded.size() == 1);
        CHECK(encoded[0] == static_cast<uint8_t>(0x50 + n)); // OP_1 = 0x51 ... OP_16 = 0x60
    }
}

TEST_CASE("the little-endian magnitude reads back as the original height") {
    // For heights above 16, drop the length byte and read the magnitude little-endian.
    for (int64_t h : {17, 127, 128, 255, 256, 65535, 500000, 709632}) {
        const auto encoded = serialize_height(h);
        int64_t value = 0;
        for (size_t i = encoded.size(); i-- > 1;) // skip encoded[0] (the length)
            value = (value << 8) | encoded[i];
        CHECK(value == h);
    }
}
