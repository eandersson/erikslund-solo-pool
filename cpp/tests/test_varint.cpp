#include <doctest/doctest.h>

#include <stdexcept>

#include "util/varint.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("encode CompactSize boundaries") {
    CHECK(encode_varint(0) == Bytes{0x00});
    CHECK(encode_varint(0xfc) == Bytes{0xfc});
    CHECK(encode_varint(0xfd) == Bytes{0xfd, 0xfd, 0x00});
    CHECK(encode_varint(0xffff) == Bytes{0xfd, 0xff, 0xff});
    CHECK(encode_varint(0x10000) == Bytes{0xfe, 0x00, 0x00, 0x01, 0x00});
    CHECK(encode_varint(0xffffffff) == Bytes{0xfe, 0xff, 0xff, 0xff, 0xff});
    CHECK(encode_varint(0x100000000ULL) ==
          Bytes{0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00});
}

TEST_CASE("decode round-trips and reports size") {
    for (uint64_t v : {0ull, 1ull, 0xfcull, 0xfdull, 0xffffull, 0x10000ull, 0xffffffffull,
                       0x123456789ull}) {
        const auto encoded = encode_varint(v);
        const auto decoded = decode_varint(encoded);
        CHECK(decoded.value == v);
        CHECK(decoded.consumed == encoded.size());
    }
}

TEST_CASE("decode rejects truncated input") {
    CHECK_THROWS_AS(decode_varint(Bytes{}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xfd, 0x01}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xfe, 0x01, 0x02}), std::invalid_argument);
    CHECK_THROWS_AS(decode_varint(Bytes{0xff, 0x01}), std::invalid_argument);
}

TEST_CASE("encode picks the minimal width at each boundary") {
    // 1-byte form spans 0x00..0xfc.
    CHECK(encode_varint(0xfc).size() == 1);
    // 0xfd is the first value that needs the 3-byte (0xfd-prefixed) form.
    CHECK(encode_varint(0xfd).size() == 3);
    CHECK(encode_varint(0xffff).size() == 3);
    // 0x10000 is the first that needs the 5-byte (0xfe-prefixed) form.
    CHECK(encode_varint(0x10000).size() == 5);
    CHECK(encode_varint(0xffffffff).size() == 5);
    // 0x1_0000_0000 is the first that needs the 9-byte (0xff-prefixed) form.
    CHECK(encode_varint(0x100000000ULL).size() == 9);
    CHECK(encode_varint(0xffffffffffffffffULL).size() == 9);
}

TEST_CASE("decode reads only its own bytes from a longer buffer") {
    // A 1-byte value followed by trailing junk reports consumed == 1.
    const Varint single = decode_varint(Bytes{0x05, 0xaa, 0xbb});
    CHECK(single.value == 0x05);
    CHECK(single.consumed == 1);

    // 0xfd<lo><hi> + junk: 3 bytes consumed, little-endian value.
    const Varint three = decode_varint(Bytes{0xfd, 0x34, 0x12, 0xff});
    CHECK(three.value == 0x1234);
    CHECK(three.consumed == 3);

    // 0xfe + 4 bytes little-endian.
    const Varint five = decode_varint(Bytes{0xfe, 0x78, 0x56, 0x34, 0x12, 0x00});
    CHECK(five.value == 0x12345678u);
    CHECK(five.consumed == 5);

    // 0xff + 8 bytes little-endian.
    const Varint nine =
        decode_varint(Bytes{0xff, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x99});
    CHECK(nine.value == 0x0102030405060708ULL);
    CHECK(nine.consumed == 9);
}

TEST_CASE("the maximum 64-bit varint round-trips") {
    const uint64_t max = 0xffffffffffffffffULL;
    const auto encoded = encode_varint(max);
    const auto decoded = decode_varint(encoded);
    CHECK(decoded.value == max);
    CHECK(decoded.consumed == 9);
    CHECK(encoded[0] == 0xff);
}
