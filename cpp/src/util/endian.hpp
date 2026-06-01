#pragma once
// Explicit byte-shift int<->buffer conversions: host-endianness-independent.
#include <cstdint>

#include "util/bytes.hpp"

namespace erikslund::util {

inline uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(uint16_t(p[0]) | uint16_t(p[1]) << 8);
}
inline uint32_t read_le32(const uint8_t* p) {
    return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}
inline uint64_t read_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= uint64_t(p[i]) << (8 * i);
    return v;
}

inline uint32_t read_be32(const uint8_t* p) {
    return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | uint32_t(p[3]);
}
inline uint64_t read_be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v = (v << 8) | uint64_t(p[i]);
    return v;
}

inline void write_le16(uint8_t* p, uint16_t v) {
    p[0] = uint8_t(v);
    p[1] = uint8_t(v >> 8);
}
inline void write_le32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        p[i] = uint8_t(v >> (8 * i));
}
inline void write_le64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = uint8_t(v >> (8 * i));
}

inline void write_be32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        p[i] = uint8_t(v >> (8 * (3 - i)));
}
inline void write_be64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        p[i] = uint8_t(v >> (8 * (7 - i)));
}

inline Bytes le32_bytes(uint32_t v) {
    Bytes b(4);
    write_le32(b.data(), v);
    return b;
}
inline Bytes le64_bytes(uint64_t v) {
    Bytes b(8);
    write_le64(b.data(), v);
    return b;
}

// Allocation-free appenders for hot paths: write straight into the tail instead of a throwaway
// heap vector. Equivalent to appending le32_bytes()/le64_bytes(), which remain for cold callers.
inline void append_le32(Bytes& dst, uint32_t v) {
    const size_t n = dst.size();
    dst.resize(n + 4);
    write_le32(dst.data() + n, v);
}
inline void append_le64(Bytes& dst, uint64_t v) {
    const size_t n = dst.size();
    dst.resize(n + 8);
    write_le64(dst.data() + n, v);
}

// Bitcoin displays hashes in the reverse of their internal serialization.
inline Bytes reversed(ByteView in) {
    Bytes out(in.size());
    for (size_t i = 0; i < in.size(); ++i)
        out[i] = in[in.size() - 1 - i];
    return out;
}

} // namespace erikslund::util
