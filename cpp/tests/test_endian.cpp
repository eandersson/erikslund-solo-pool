#include <doctest/doctest.h>

#include "util/endian.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::util;

TEST_CASE("little-endian round trips") {
    uint8_t buf[8];
    write_le32(buf, 0x01020304);
    CHECK(buf[0] == 0x04);
    CHECK(buf[3] == 0x01);
    CHECK(read_le32(buf) == 0x01020304);

    write_le64(buf, 0x0102030405060708ULL);
    CHECK(buf[0] == 0x08);
    CHECK(buf[7] == 0x01);
    CHECK(read_le64(buf) == 0x0102030405060708ULL);
}

TEST_CASE("big-endian round trips") {
    uint8_t buf[8];
    write_be32(buf, 0x01020304);
    CHECK(buf[0] == 0x01);
    CHECK(buf[3] == 0x04);
    CHECK(read_be32(buf) == 0x01020304);

    write_be64(buf, 0x0102030405060708ULL);
    CHECK(buf[0] == 0x01);
    CHECK(read_be64(buf) == 0x0102030405060708ULL);
}

TEST_CASE("reversed flips byte order") {
    CHECK(to_hex(reversed(from_hex("0011223344"))) == "4433221100");
    CHECK(reversed(Bytes{}) == Bytes{});
}

TEST_CASE("16-bit little-endian read/write") {
    uint8_t buf[2];
    write_le16(buf, 0xabcd);
    CHECK(buf[0] == 0xcd);
    CHECK(buf[1] == 0xab);
    CHECK(read_le16(buf) == 0xabcd);

    write_le16(buf, 0x0000);
    CHECK(read_le16(buf) == 0x0000);
    write_le16(buf, 0xffff);
    CHECK(read_le16(buf) == 0xffff);
}

TEST_CASE("le32_bytes / le64_bytes produce least-significant-byte-first vectors") {
    CHECK(le32_bytes(0x01020304) == Bytes{0x04, 0x03, 0x02, 0x01});
    CHECK(le32_bytes(0) == Bytes{0x00, 0x00, 0x00, 0x00});
    CHECK(le64_bytes(0x0102030405060708ULL) ==
          Bytes{0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01});
    // The helpers round-trip through the matching reader.
    CHECK(read_le32(le32_bytes(0xe06ae06a).data()) == 0xe06ae06au);
    CHECK(read_le64(le64_bytes(0xcafef00de06ae06aULL).data()) == 0xcafef00de06ae06aULL);
}

TEST_CASE("big-endian 32/64 write the most-significant byte first") {
    uint8_t buf[8];
    write_be32(buf, 0xe06ae06a);
    CHECK(buf[0] == 0xe0);
    CHECK(buf[1] == 0x6a);
    CHECK(buf[2] == 0xe0);
    CHECK(buf[3] == 0x6a);
    write_be64(buf, 0x0102030405060708ULL);
    CHECK(buf[7] == 0x08);
    CHECK(read_be64(buf) == 0x0102030405060708ULL);
}

TEST_CASE("reversed of a single byte is itself") {
    CHECK(reversed(Bytes{0x42}) == Bytes{0x42});
}
