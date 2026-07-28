#include "sv2/codec.hpp"

#include <algorithm>
#include <utility>

#include "util/endian.hpp"

namespace erikslund::sv2 {

uint16_t make_extension_type(uint16_t extension_id, bool channel_message) {
    if (extension_id > kExtensionIdMask)
        throw CodecError("SV2 extension ID exceeds 15 bits");
    return static_cast<uint16_t>(
        extension_id | (channel_message ? kChannelMessageFlag : 0));
}

Bytes encode_frame(const Frame& frame) {
    if (frame.payload.size() > kMaximumFramePayloadSize)
        throw CodecError("SV2 frame payload exceeds the U24 wire limit");

    Bytes encoded(kFrameHeaderSize);
    util::write_le16(encoded.data(), frame.extension_type);
    encoded[2] = frame.message_type;
    util::write_le24(encoded.data() + 3, static_cast<uint32_t>(frame.payload.size()));
    append(encoded, frame.payload);
    return encoded;
}

std::vector<Frame> FrameDecoder::push(ByteView bytes) {
    std::vector<Frame> completed_frames;

    while (!bytes.empty()) {
        if (!reading_payload_) {
            const std::size_t bytes_to_copy =
                std::min(kFrameHeaderSize - header_size_, bytes.size());
            std::copy_n(bytes.begin(), bytes_to_copy,
                        header_.begin() +
                            static_cast<std::ptrdiff_t>(header_size_));
            header_size_ += bytes_to_copy;
            bytes = bytes.subspan(bytes_to_copy);
            if (header_size_ != kFrameHeaderSize)
                continue;
            if (!begin_payload())
                throw CodecError(
                    "SV2 frame payload exceeds the configured limit",
                    std::move(completed_frames));
        } else {
            const std::size_t bytes_to_copy = std::min(
                payload_size_ - frame_.payload.size(), bytes.size());
            frame_.payload.insert(
                frame_.payload.end(), bytes.begin(),
                bytes.begin() + static_cast<std::ptrdiff_t>(bytes_to_copy));
            bytes = bytes.subspan(bytes_to_copy);
        }

        // Reached only with a parsed header, so a zero-length payload completes here too.
        if (frame_.payload.size() == payload_size_) {
            completed_frames.push_back(std::move(frame_));
            reset_frame();
        }
    }

    return completed_frames;
}

void FrameDecoder::finish() const {
    if (header_size_ != 0 || reading_payload_)
        throw CodecError("truncated SV2 frame");
}

bool FrameDecoder::begin_payload() {
    frame_.extension_type = util::read_le16(header_.data());
    frame_.message_type = header_[2];
    payload_size_ = util::read_le24(header_.data() + 3);
    if (payload_size_ > maximum_payload_size_) {
        reset_frame();
        return false;
    }
    frame_.payload.reserve(payload_size_);
    reading_payload_ = true;
    return true;
}

void FrameDecoder::reset_frame() noexcept {
    header_size_ = 0;
    frame_ = {};
    payload_size_ = 0;
    reading_payload_ = false;
}

} // namespace erikslund::sv2
