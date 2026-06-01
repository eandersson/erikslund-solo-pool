#include "util/varint.hpp"

#include <stdexcept>

#include "util/endian.hpp"

namespace erikslund::util {

Bytes encode_varint(uint64_t value) {
    Bytes out;
    if (value < 0xfd) {
        out.push_back(uint8_t(value));
    } else if (value <= 0xffff) {
        out.push_back(0xfd);
        out.push_back(uint8_t(value));
        out.push_back(uint8_t(value >> 8));
    } else if (value <= 0xffffffff) {
        out.push_back(0xfe);
        for (int i = 0; i < 4; ++i)
            out.push_back(uint8_t(value >> (8 * i)));
    } else {
        out.push_back(0xff);
        for (int i = 0; i < 8; ++i)
            out.push_back(uint8_t(value >> (8 * i)));
    }
    return out;
}

Varint decode_varint(std::span<const uint8_t> in) {
    if (in.empty())
        throw std::invalid_argument("varint: empty input");
    const uint8_t first = in[0];
    if (first < 0xfd)
        return {first, 1};
    if (first == 0xfd) {
        if (in.size() < 3)
            throw std::invalid_argument("varint: truncated 2-byte value");
        return {read_le16(&in[1]), 3};
    }
    if (first == 0xfe) {
        if (in.size() < 5)
            throw std::invalid_argument("varint: truncated 4-byte value");
        return {read_le32(&in[1]), 5};
    }
    if (in.size() < 9)
        throw std::invalid_argument("varint: truncated 8-byte value");
    return {read_le64(&in[1]), 9};
}

} // namespace erikslund::util
