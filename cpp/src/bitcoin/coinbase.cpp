#include "bitcoin/coinbase.hpp"

#include <array>
#include <stdexcept>

#include "bitcoin/serialize.hpp"
#include "util/endian.hpp"
#include "util/varint.hpp"

namespace erikslund::bitcoin {

namespace {
constexpr std::array<uint8_t, 4> kSequence = {0xff, 0xff, 0xff, 0xff};
constexpr std::array<uint8_t, 4> kLocktime = {0x00, 0x00, 0x00, 0x00};
} // namespace

Bytes build_coinbase1(int64_t height, size_t extranonce_total, ByteView tag, uint32_t version) {
    const Bytes height_push = serialize_height(height);
    const size_t scriptsig_length = height_push.size() + extranonce_total + tag.size();
    if (scriptsig_length > kMaxScriptSig)
        throw std::invalid_argument("coinbase scriptSig too long (> 100 bytes)");

    Bytes out;
    append(out, util::le32_bytes(version));
    out.push_back(0x01);

    Bytes prevout_null(36, 0x00);
    prevout_null[32] = prevout_null[33] = prevout_null[34] = prevout_null[35] = 0xff;
    append(out, prevout_null);

    append(out, util::encode_varint(scriptsig_length));
    append(out, height_push);
    return out;
}

Bytes build_coinbase2(const std::vector<CoinbaseOutput>& outputs,
                      const std::optional<Bytes>& witness_commitment_script, ByteView tag) {
    Bytes out;
    append(out, tag);
    append(out, kSequence);

    const size_t output_count = outputs.size() + (witness_commitment_script ? 1 : 0);
    append(out, util::encode_varint(output_count));

    const auto write_output = [&out](uint64_t amount, ByteView script) {
        append(out, util::le64_bytes(amount));
        append(out, util::encode_varint(script.size()));
        append(out, script);
    };
    for (const auto& output : outputs)
        write_output(output.value, output.script);
    if (witness_commitment_script)
        write_output(0, *witness_commitment_script);

    append(out, kLocktime);
    return out;
}

Bytes legacy_to_witness(ByteView legacy_coinbase) {
    if (legacy_coinbase.size() < 8)
        throw std::invalid_argument("legacy_to_witness: coinbase too short");

    const ByteView version = legacy_coinbase.subspan(0, 4);
    const ByteView body = legacy_coinbase.subspan(4, legacy_coinbase.size() - 8);
    const ByteView locktime = legacy_coinbase.subspan(legacy_coinbase.size() - 4, 4);

    Bytes out;
    append(out, version);
    out.push_back(0x00);
    out.push_back(0x01);
    append(out, body);

    const Bytes reserved_value(32, 0x00);
    append(out, util::encode_varint(1));
    append(out, util::encode_varint(reserved_value.size()));
    append(out, reserved_value);

    append(out, locktime);
    return out;
}

} // namespace erikslund::bitcoin
