#pragma once
// Stratum V2's transport-independent six-byte frame and incremental stream decoder.
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "util/bytes.hpp"

namespace erikslund::sv2 {

inline constexpr std::size_t kFrameHeaderSize = 6;
inline constexpr uint16_t kCoreExtensionId = 0;
inline constexpr uint16_t kChannelMessageFlag = 0x8000;
inline constexpr uint16_t kExtensionIdMask = 0x7fff;
inline constexpr uint32_t kMaximumFramePayloadSize = 0x00ff'ffff;

// extension_type contains both the 15-bit extension ID and the routing bit defined by SV2.
struct Frame {
    uint16_t extension_type{};
    uint8_t message_type{};
    Bytes payload;

    [[nodiscard]] uint16_t extension_id() const noexcept {
        return extension_type & kExtensionIdMask;
    }
    [[nodiscard]] bool is_channel_message() const noexcept {
        return (extension_type & kChannelMessageFlag) != 0;
    }

    friend bool operator==(const Frame&, const Frame&) = default;
};

class CodecError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;

    CodecError(std::string message, std::vector<Frame> completed_frames)
        : std::runtime_error(std::move(message)),
          completed_frames_(std::move(completed_frames)) {}

    [[nodiscard]] std::vector<Frame> take_completed_frames() noexcept {
        return std::move(completed_frames_);
    }

private:
    std::vector<Frame> completed_frames_;
};

[[nodiscard]] uint16_t make_extension_type(uint16_t extension_id, bool channel_message);
[[nodiscard]] Bytes encode_frame(const Frame& frame);

class FrameDecoder {
public:
    explicit FrameDecoder(uint32_t maximum_payload_size = kMaximumFramePayloadSize)
        : maximum_payload_size_(maximum_payload_size) {}

    // CodecError retains valid frames decoded before malformed input.
    [[nodiscard]] std::vector<Frame> push(ByteView bytes);

    void finish() const;

private:
    [[nodiscard]] bool begin_payload();
    void reset_frame() noexcept;

    uint32_t maximum_payload_size_;
    std::array<uint8_t, kFrameHeaderSize> header_{};
    std::size_t header_size_{};
    Frame frame_;
    uint32_t payload_size_{};
    bool reading_payload_{};
};

} // namespace erikslund::sv2
