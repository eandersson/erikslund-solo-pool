#include "sv2/messages.hpp"

#include <algorithm>
#include <bit>
#include <limits>
#include <string_view>
#include <utility>

#include "util/endian.hpp"

namespace erikslund::sv2 {

namespace {

class Writer {
public:
    void u8(uint8_t value) { bytes_.push_back(value); }

    void u16(uint16_t value) {
        const std::size_t offset = bytes_.size();
        bytes_.resize(offset + 2);
        util::write_le16(bytes_.data() + offset, value);
    }

    void u32(uint32_t value) { util::append_le32(bytes_, value); }
    void u64(uint64_t value) { util::append_le64(bytes_, value); }
    void f32(float value) { u32(std::bit_cast<uint32_t>(value)); }
    void u256(const U256& value) { append(bytes_, value); }
    void boolean(bool value) { u8(value ? 1 : 0); }

    void string(std::string_view value) {
        if (value.size() > std::numeric_limits<uint8_t>::max())
            throw CodecError("SV2 STR0_255 exceeds 255 bytes");
        u8(static_cast<uint8_t>(value.size()));
        bytes_.insert(bytes_.end(), value.begin(), value.end());
    }

    void b0_32(ByteView value) {
        if (value.size() > 32)
            throw CodecError("SV2 B0_32 exceeds 32 bytes");
        u8(static_cast<uint8_t>(value.size()));
        append(bytes_, value);
    }

    void b0_64k(ByteView value) {
        if (value.size() > std::numeric_limits<uint16_t>::max())
            throw CodecError("SV2 B0_64K exceeds 65535 bytes");
        u16(static_cast<uint16_t>(value.size()));
        append(bytes_, value);
    }

    void sequence_u256(const std::vector<U256>& values) {
        if (values.size() > std::numeric_limits<uint8_t>::max())
            throw CodecError("SV2 SEQ0_255[U256] exceeds 255 elements");
        u8(static_cast<uint8_t>(values.size()));
        for (const U256& value : values)
            u256(value);
    }

    void option_u32(const std::optional<uint32_t>& value) {
        u8(value.has_value() ? 1 : 0);
        if (value)
            u32(*value);
    }

    [[nodiscard]] Bytes take() && { return std::move(bytes_); }

private:
    Bytes bytes_;
};

class Reader {
public:
    explicit Reader(ByteView bytes) : bytes_(bytes) {}

    [[nodiscard]] uint8_t u8() { return take(1)[0]; }
    [[nodiscard]] uint16_t u16() {
        const ByteView value = take(2);
        return util::read_le16(value.data());
    }
    [[nodiscard]] uint32_t u32() {
        const ByteView value = take(4);
        return util::read_le32(value.data());
    }
    [[nodiscard]] uint64_t u64() {
        const ByteView value = take(8);
        return util::read_le64(value.data());
    }
    [[nodiscard]] float f32() { return std::bit_cast<float>(u32()); }
    [[nodiscard]] bool boolean() { return (u8() & 1U) != 0; }

    [[nodiscard]] U256 u256() {
        U256 value{};
        const ByteView bytes = take(value.size());
        std::copy(bytes.begin(), bytes.end(), value.begin());
        return value;
    }

    [[nodiscard]] std::string string() {
        const ByteView value = take(u8());
        if (value.empty())
            return {};
        return {reinterpret_cast<const char*>(value.data()), value.size()};
    }

    [[nodiscard]] Bytes b0_32() {
        const uint8_t size = u8();
        if (size > 32)
            throw CodecError("SV2 B0_32 exceeds 32 bytes");
        const ByteView value = take(size);
        return {value.begin(), value.end()};
    }

    [[nodiscard]] Bytes b0_64k() {
        const ByteView value = take(u16());
        return {value.begin(), value.end()};
    }

    [[nodiscard]] std::vector<U256> sequence_u256() {
        const uint8_t size = u8();
        std::vector<U256> values;
        values.reserve(size);
        for (uint16_t index = 0; index < size; ++index)
            values.push_back(u256());
        return values;
    }

    [[nodiscard]] std::optional<uint32_t> option_u32() {
        const uint8_t count = u8();
        if (count == 0)
            return std::nullopt;
        if (count == 1)
            return u32();
        throw CodecError("SV2 OPTION count exceeds one");
    }

    void finish() const {
        if (offset_ != bytes_.size())
            throw CodecError("unexpected trailing bytes in SV2 message");
    }

private:
    [[nodiscard]] ByteView take(std::size_t count) {
        if (count > bytes_.size() - offset_)
            throw CodecError("truncated SV2 message");
        const ByteView value = bytes_.subspan(offset_, count);
        offset_ += count;
        return value;
    }

    ByteView bytes_;
    std::size_t offset_{};
};

template <typename Message, typename Parse>
Message decode(ByteView payload, Parse&& parse) {
    Reader reader(payload);
    Message message = parse(reader);
    reader.finish();
    return message;
}

} // namespace

Bytes encode_payload(const SetupConnection& message) {
    Writer writer;
    writer.u8(message.protocol);
    writer.u16(message.minimum_version);
    writer.u16(message.maximum_version);
    writer.u32(message.flags);
    writer.string(message.endpoint_host);
    writer.u16(message.endpoint_port);
    writer.string(message.vendor);
    writer.string(message.hardware_version);
    writer.string(message.firmware);
    writer.string(message.device_id);
    return std::move(writer).take();
}

Bytes encode_payload(const SetupConnectionSuccess& message) {
    Writer writer;
    writer.u16(message.used_version);
    writer.u32(message.flags);
    return std::move(writer).take();
}

Bytes encode_payload(const SetupConnectionError& message) {
    Writer writer;
    writer.u32(message.flags);
    writer.string(message.error_code);
    return std::move(writer).take();
}

Bytes encode_payload(const OpenStandardMiningChannel& message) {
    Writer writer;
    writer.u32(message.request_id);
    writer.string(message.user_identity);
    writer.f32(message.nominal_hash_rate);
    writer.u256(message.maximum_target);
    return std::move(writer).take();
}

Bytes encode_payload(const OpenStandardMiningChannelSuccess& message) {
    Writer writer;
    writer.u32(message.request_id);
    writer.u32(message.channel_id);
    writer.u256(message.target);
    writer.b0_32(message.extranonce_prefix);
    writer.u32(message.group_channel_id);
    return std::move(writer).take();
}

Bytes encode_payload(const OpenMiningChannelError& message) {
    Writer writer;
    writer.u32(message.request_id);
    writer.string(message.error_code);
    return std::move(writer).take();
}

Bytes encode_payload(const OpenExtendedMiningChannel& message) {
    Writer writer;
    writer.u32(message.request_id);
    writer.string(message.user_identity);
    writer.f32(message.nominal_hash_rate);
    writer.u256(message.maximum_target);
    writer.u16(message.minimum_extranonce_size);
    return std::move(writer).take();
}

Bytes encode_payload(const OpenExtendedMiningChannelSuccess& message) {
    Writer writer;
    writer.u32(message.request_id);
    writer.u32(message.channel_id);
    writer.u256(message.target);
    writer.u16(message.extranonce_size);
    writer.b0_32(message.extranonce_prefix);
    writer.u32(message.group_channel_id);
    return std::move(writer).take();
}

Bytes encode_payload(const UpdateChannel& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.f32(message.nominal_hash_rate);
    writer.u256(message.maximum_target);
    return std::move(writer).take();
}

Bytes encode_payload(const UpdateChannelError& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.string(message.error_code);
    return std::move(writer).take();
}

Bytes encode_payload(const CloseChannel& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.string(message.reason_code);
    return std::move(writer).take();
}

Bytes encode_payload(const SetExtranoncePrefix& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.b0_32(message.extranonce_prefix);
    return std::move(writer).take();
}

Bytes encode_payload(const NewMiningJob& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.job_id);
    writer.option_u32(message.minimum_ntime);
    writer.u32(message.version);
    writer.u256(message.merkle_root);
    return std::move(writer).take();
}

Bytes encode_payload(const SubmitSharesStandard& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.sequence_number);
    writer.u32(message.job_id);
    writer.u32(message.nonce);
    writer.u32(message.ntime);
    writer.u32(message.version);
    return std::move(writer).take();
}

Bytes encode_payload(const SubmitSharesExtended& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.sequence_number);
    writer.u32(message.job_id);
    writer.u32(message.nonce);
    writer.u32(message.ntime);
    writer.u32(message.version);
    writer.b0_32(message.extranonce);
    return std::move(writer).take();
}

Bytes encode_payload(const SubmitSharesSuccess& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.last_sequence_number);
    writer.u32(message.new_submits_accepted_count);
    writer.u64(message.new_shares_sum);
    return std::move(writer).take();
}

Bytes encode_payload(const SubmitSharesError& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.sequence_number);
    writer.string(message.error_code);
    return std::move(writer).take();
}

Bytes encode_payload(const NewExtendedMiningJob& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.job_id);
    writer.option_u32(message.minimum_ntime);
    writer.u32(message.version);
    writer.boolean(message.version_rolling_allowed);
    writer.sequence_u256(message.merkle_path);
    writer.b0_64k(message.coinbase_tx_prefix);
    writer.b0_64k(message.coinbase_tx_suffix);
    return std::move(writer).take();
}

Bytes encode_payload(const SetNewPrevHash& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u32(message.job_id);
    writer.u256(message.previous_hash);
    writer.u32(message.minimum_ntime);
    writer.u32(message.nbits);
    return std::move(writer).take();
}

Bytes encode_payload(const SetTarget& message) {
    Writer writer;
    writer.u32(message.channel_id);
    writer.u256(message.maximum_target);
    return std::move(writer).take();
}

SetupConnection decode_setup_connection(ByteView payload) {
    return decode<SetupConnection>(payload, [](Reader& reader) {
        SetupConnection message;
        message.protocol = reader.u8();
        message.minimum_version = reader.u16();
        message.maximum_version = reader.u16();
        message.flags = reader.u32();
        message.endpoint_host = reader.string();
        message.endpoint_port = reader.u16();
        message.vendor = reader.string();
        message.hardware_version = reader.string();
        message.firmware = reader.string();
        message.device_id = reader.string();
        return message;
    });
}

SetupConnectionSuccess decode_setup_connection_success(ByteView payload) {
    return decode<SetupConnectionSuccess>(payload, [](Reader& reader) {
        return SetupConnectionSuccess{reader.u16(), reader.u32()};
    });
}

SetupConnectionError decode_setup_connection_error(ByteView payload) {
    return decode<SetupConnectionError>(payload, [](Reader& reader) {
        return SetupConnectionError{reader.u32(), reader.string()};
    });
}

OpenStandardMiningChannel decode_open_standard_mining_channel(ByteView payload) {
    return decode<OpenStandardMiningChannel>(payload, [](Reader& reader) {
        OpenStandardMiningChannel message;
        message.request_id = reader.u32();
        message.user_identity = reader.string();
        message.nominal_hash_rate = reader.f32();
        message.maximum_target = reader.u256();
        return message;
    });
}

OpenStandardMiningChannelSuccess
decode_open_standard_mining_channel_success(ByteView payload) {
    return decode<OpenStandardMiningChannelSuccess>(payload, [](Reader& reader) {
        OpenStandardMiningChannelSuccess message;
        message.request_id = reader.u32();
        message.channel_id = reader.u32();
        message.target = reader.u256();
        message.extranonce_prefix = reader.b0_32();
        message.group_channel_id = reader.u32();
        return message;
    });
}

OpenMiningChannelError decode_open_mining_channel_error(ByteView payload) {
    return decode<OpenMiningChannelError>(payload, [](Reader& reader) {
        return OpenMiningChannelError{reader.u32(), reader.string()};
    });
}

OpenExtendedMiningChannel decode_open_extended_mining_channel(ByteView payload) {
    return decode<OpenExtendedMiningChannel>(payload, [](Reader& reader) {
        OpenExtendedMiningChannel message;
        message.request_id = reader.u32();
        message.user_identity = reader.string();
        message.nominal_hash_rate = reader.f32();
        message.maximum_target = reader.u256();
        message.minimum_extranonce_size = reader.u16();
        return message;
    });
}

OpenExtendedMiningChannelSuccess
decode_open_extended_mining_channel_success(ByteView payload) {
    return decode<OpenExtendedMiningChannelSuccess>(payload, [](Reader& reader) {
        OpenExtendedMiningChannelSuccess message;
        message.request_id = reader.u32();
        message.channel_id = reader.u32();
        message.target = reader.u256();
        message.extranonce_size = reader.u16();
        message.extranonce_prefix = reader.b0_32();
        message.group_channel_id = reader.u32();
        return message;
    });
}

UpdateChannel decode_update_channel(ByteView payload) {
    return decode<UpdateChannel>(payload, [](Reader& reader) {
        return UpdateChannel{reader.u32(), reader.f32(), reader.u256()};
    });
}

UpdateChannelError decode_update_channel_error(ByteView payload) {
    return decode<UpdateChannelError>(payload, [](Reader& reader) {
        return UpdateChannelError{reader.u32(), reader.string()};
    });
}

CloseChannel decode_close_channel(ByteView payload) {
    return decode<CloseChannel>(payload, [](Reader& reader) {
        return CloseChannel{reader.u32(), reader.string()};
    });
}

SetExtranoncePrefix decode_set_extranonce_prefix(ByteView payload) {
    return decode<SetExtranoncePrefix>(payload, [](Reader& reader) {
        return SetExtranoncePrefix{reader.u32(), reader.b0_32()};
    });
}

NewMiningJob decode_new_mining_job(ByteView payload) {
    return decode<NewMiningJob>(payload, [](Reader& reader) {
        NewMiningJob message;
        message.channel_id = reader.u32();
        message.job_id = reader.u32();
        message.minimum_ntime = reader.option_u32();
        message.version = reader.u32();
        message.merkle_root = reader.u256();
        return message;
    });
}

SubmitSharesStandard decode_submit_shares_standard(ByteView payload) {
    return decode<SubmitSharesStandard>(payload, [](Reader& reader) {
        SubmitSharesStandard message;
        message.channel_id = reader.u32();
        message.sequence_number = reader.u32();
        message.job_id = reader.u32();
        message.nonce = reader.u32();
        message.ntime = reader.u32();
        message.version = reader.u32();
        return message;
    });
}

SubmitSharesExtended decode_submit_shares_extended(ByteView payload) {
    return decode<SubmitSharesExtended>(payload, [](Reader& reader) {
        SubmitSharesExtended message;
        message.channel_id = reader.u32();
        message.sequence_number = reader.u32();
        message.job_id = reader.u32();
        message.nonce = reader.u32();
        message.ntime = reader.u32();
        message.version = reader.u32();
        message.extranonce = reader.b0_32();
        return message;
    });
}

SubmitSharesSuccess decode_submit_shares_success(ByteView payload) {
    return decode<SubmitSharesSuccess>(payload, [](Reader& reader) {
        SubmitSharesSuccess message;
        message.channel_id = reader.u32();
        message.last_sequence_number = reader.u32();
        message.new_submits_accepted_count = reader.u32();
        message.new_shares_sum = reader.u64();
        return message;
    });
}

SubmitSharesError decode_submit_shares_error(ByteView payload) {
    return decode<SubmitSharesError>(payload, [](Reader& reader) {
        return SubmitSharesError{reader.u32(), reader.u32(), reader.string()};
    });
}

NewExtendedMiningJob decode_new_extended_mining_job(ByteView payload) {
    return decode<NewExtendedMiningJob>(payload, [](Reader& reader) {
        NewExtendedMiningJob message;
        message.channel_id = reader.u32();
        message.job_id = reader.u32();
        message.minimum_ntime = reader.option_u32();
        message.version = reader.u32();
        message.version_rolling_allowed = reader.boolean();
        message.merkle_path = reader.sequence_u256();
        message.coinbase_tx_prefix = reader.b0_64k();
        message.coinbase_tx_suffix = reader.b0_64k();
        return message;
    });
}

SetNewPrevHash decode_set_new_prev_hash(ByteView payload) {
    return decode<SetNewPrevHash>(payload, [](Reader& reader) {
        SetNewPrevHash message;
        message.channel_id = reader.u32();
        message.job_id = reader.u32();
        message.previous_hash = reader.u256();
        message.minimum_ntime = reader.u32();
        message.nbits = reader.u32();
        return message;
    });
}

SetTarget decode_set_target(ByteView payload) {
    return decode<SetTarget>(payload, [](Reader& reader) {
        return SetTarget{reader.u32(), reader.u256()};
    });
}

} // namespace erikslund::sv2
