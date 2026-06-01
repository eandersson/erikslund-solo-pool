#include "util/bech32.hpp"

#include <cctype>
#include <stdexcept>
#include <vector>

namespace erikslund::util {

namespace {

constexpr char kCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

enum class Encoding { Invalid, Bech32, Bech32m };

constexpr uint32_t kBech32Const = 1;
constexpr uint32_t kBech32mConst = 0x2bc830a3;

uint32_t polymod(const std::vector<uint8_t>& values) {
    static const uint32_t generator[5] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd,
                                          0x2a1462b3};
    uint32_t checksum = 1;
    for (uint8_t value : values) {
        const uint8_t top = uint8_t(checksum >> 25);
        checksum = ((checksum & 0x1ffffff) << 5) ^ value;
        for (int i = 0; i < 5; ++i)
            if ((top >> i) & 1)
                checksum ^= generator[i];
    }
    return checksum;
}

std::vector<uint8_t> hrp_expand(std::string_view hrp) {
    std::vector<uint8_t> out;
    out.reserve(hrp.size() * 2 + 1);
    for (char c : hrp)
        out.push_back(uint8_t(uint8_t(c) >> 5));
    out.push_back(0);
    for (char c : hrp)
        out.push_back(uint8_t(uint8_t(c) & 31));
    return out;
}

uint32_t checksum_constant(Encoding encoding) {
    return encoding == Encoding::Bech32m ? kBech32mConst : kBech32Const;
}

Encoding verify_checksum(std::string_view hrp, const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    const uint32_t residue = polymod(values);
    if (residue == kBech32Const)
        return Encoding::Bech32;
    if (residue == kBech32mConst)
        return Encoding::Bech32m;
    return Encoding::Invalid;
}

std::vector<uint8_t> create_checksum(std::string_view hrp, const std::vector<uint8_t>& data,
                                     Encoding encoding) {
    std::vector<uint8_t> values = hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);
    const uint32_t residue = polymod(values) ^ checksum_constant(encoding);
    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; ++i)
        checksum[static_cast<size_t>(i)] = uint8_t((residue >> (5 * (5 - i))) & 31);
    return checksum;
}

int charset_index(char c) {
    for (int i = 0; i < 32; ++i)
        if (kCharset[i] == c)
            return i;
    return -1;
}

// General power-of-two base conversion (BIP173 convertbits).
std::optional<std::vector<uint8_t>> convertbits(std::span<const uint8_t> in, int frombits,
                                                int tobits, bool pad) {
    uint32_t accumulator = 0;
    int bits = 0;
    std::vector<uint8_t> out;
    const uint32_t max_value = (uint32_t(1) << tobits) - 1;
    const uint32_t max_accumulator = (uint32_t(1) << (frombits + tobits - 1)) - 1;
    for (uint8_t value : in) {
        if ((value >> frombits) != 0)
            return std::nullopt;
        accumulator = ((accumulator << frombits) | value) & max_accumulator;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back(uint8_t((accumulator >> bits) & max_value));
        }
    }
    if (pad) {
        if (bits)
            out.push_back(uint8_t((accumulator << (tobits - bits)) & max_value));
    } else if (bits >= frombits || ((accumulator << (tobits - bits)) & max_value)) {
        return std::nullopt;
    }
    return out;
}

struct Decoded {
    std::string hrp;
    std::vector<uint8_t> data; // 5-bit groups, checksum stripped
    Encoding encoding;
};

std::optional<Decoded> bech32_decode(std::string_view text) {
    if (text.size() < 8 || text.size() > 90)
        return std::nullopt;

    bool has_lower = false;
    bool has_upper = false;
    for (char c : text) {
        if (c < 33 || c > 126)
            return std::nullopt;
        if (c >= 'a' && c <= 'z')
            has_lower = true;
        if (c >= 'A' && c <= 'Z')
            has_upper = true;
    }
    if (has_lower && has_upper)
        return std::nullopt;

    std::string lowered(text);
    for (char& c : lowered)
        c = char(std::tolower(static_cast<unsigned char>(c)));

    const auto separator = lowered.rfind('1');
    if (separator == std::string::npos || separator == 0 || separator + 7 > lowered.size())
        return std::nullopt;

    Decoded result;
    result.hrp = lowered.substr(0, separator);
    for (size_t i = separator + 1; i < lowered.size(); ++i) {
        const int index = charset_index(lowered[i]);
        if (index < 0)
            return std::nullopt;
        result.data.push_back(uint8_t(index));
    }

    result.encoding = verify_checksum(result.hrp, result.data);
    if (result.encoding == Encoding::Invalid)
        return std::nullopt;
    result.data.resize(result.data.size() - 6); // strip checksum symbols
    return result;
}

} // namespace

std::optional<WitnessProgram> segwit_address_decode(std::string_view hrp,
                                                    std::string_view address) {
    const auto decoded = bech32_decode(address);
    if (!decoded || decoded->hrp != hrp || decoded->data.empty())
        return std::nullopt;

    const int version = decoded->data[0];
    if (version > 16)
        return std::nullopt;

    const std::span<const uint8_t> data5(decoded->data.data() + 1, decoded->data.size() - 1);
    const auto program = convertbits(data5, 5, 8, false);
    if (!program || program->size() < 2 || program->size() > 40)
        return std::nullopt;

    // BIP350: witness v0 uses bech32, every later version uses bech32m.
    if (version == 0) {
        if (program->size() != 20 && program->size() != 32)
            return std::nullopt;
        if (decoded->encoding != Encoding::Bech32)
            return std::nullopt;
    } else if (decoded->encoding != Encoding::Bech32m) {
        return std::nullopt;
    }

    return WitnessProgram{version, *program};
}

std::string segwit_address_encode(std::string_view hrp, int version,
                                  std::span<const uint8_t> program) {
    if (version < 0 || version > 16)
        throw std::invalid_argument("segwit: version out of range");
    if (program.size() < 2 || program.size() > 40)
        throw std::invalid_argument("segwit: program length out of range");

    const auto converted = convertbits(program, 8, 5, true);
    if (!converted)
        throw std::invalid_argument("segwit: program could not be base32-encoded");

    std::vector<uint8_t> data;
    data.reserve(converted->size() + 1);
    data.push_back(uint8_t(version));
    data.insert(data.end(), converted->begin(), converted->end());

    const Encoding encoding = version == 0 ? Encoding::Bech32 : Encoding::Bech32m;
    const auto checksum = create_checksum(hrp, data, encoding);

    std::string out(hrp);
    out.push_back('1');
    for (uint8_t value : data)
        out.push_back(kCharset[value]);
    for (uint8_t value : checksum)
        out.push_back(kCharset[value]);
    return out;
}

} // namespace erikslund::util
