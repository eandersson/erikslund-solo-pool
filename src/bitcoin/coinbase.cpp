#include "bitcoin/coinbase.hpp"

#include <stdexcept>

#include "bitcoin/serialize.hpp"
#include "util/endian.hpp"
#include "util/varint.hpp"

namespace erikslund::bitcoin {

namespace {

void append_output(Bytes& bytes, const CoinbaseOutput& output) {
    util::append_le64(bytes, output.value);
    append(bytes, util::encode_varint(output.script.size()));
    append(bytes, output.script);
}

} // namespace

Bytes build_coinbase1(ByteView script_sig_prefix, size_t extranonce_total, ByteView tag,
                      uint32_t version) {
    const size_t scriptsig_length = script_sig_prefix.size() + extranonce_total + tag.size();
    if (scriptsig_length > kMaxScriptSig)
        throw std::invalid_argument("coinbase scriptSig too long (> 100 bytes)");

    Bytes out;
    util::append_le32(out, version);
    out.push_back(0x01);

    Bytes prevout_null(36, 0x00);
    prevout_null[32] = prevout_null[33] = prevout_null[34] = prevout_null[35] = 0xff;
    append(out, prevout_null);

    append(out, util::encode_varint(scriptsig_length));
    append(out, script_sig_prefix);
    return out;
}

Bytes build_coinbase1(int64_t height, size_t extranonce_total, ByteView tag, uint32_t version) {
    return build_coinbase1(serialize_height(height), extranonce_total, tag, version);
}

Bytes build_coinbase2(const std::vector<CoinbaseOutput>& outputs,
                      const std::vector<CoinbaseOutput>& required_outputs, ByteView tag,
                      uint32_t sequence, uint32_t lock_time) {
    Bytes out;
    append(out, tag);
    util::append_le32(out, sequence);

    const size_t output_count = outputs.size() + required_outputs.size();
    append(out, util::encode_varint(output_count));

    for (const auto& output : outputs)
        append_output(out, output);
    for (const auto& output : required_outputs)
        append_output(out, output);

    util::append_le32(out, lock_time);
    return out;
}

Bytes legacy_to_witness(ByteView legacy_coinbase, ByteView witness_item) {
    if (legacy_coinbase.size() < 8)
        throw std::invalid_argument("legacy_to_witness: coinbase too short");
    if (witness_item.size() != 32)
        throw std::invalid_argument("legacy_to_witness: witness item must be 32 bytes");

    const ByteView version = legacy_coinbase.subspan(0, 4);
    const ByteView body = legacy_coinbase.subspan(4, legacy_coinbase.size() - 8);
    const ByteView locktime = legacy_coinbase.subspan(legacy_coinbase.size() - 4, 4);

    Bytes out;
    append(out, version);
    out.push_back(0x00);
    out.push_back(0x01);
    append(out, body);

    append(out, util::encode_varint(1));
    append(out, util::encode_varint(witness_item.size()));
    append(out, witness_item);

    append(out, locktime);
    return out;
}

Bytes legacy_to_witness(ByteView legacy_coinbase) {
    return legacy_to_witness(legacy_coinbase, Bytes(32, 0));
}

} // namespace erikslund::bitcoin
