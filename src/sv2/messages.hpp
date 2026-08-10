#pragma once
// Stratum V2 common and mining-channel messages, and their payload codecs.
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "sv2/codec.hpp"
#include "util/bytes.hpp"

namespace erikslund::sv2 {

inline constexpr uint16_t kProtocolVersion = 2;
inline constexpr uint8_t kMiningProtocol = 0;
inline constexpr uint32_t kSetupFlagRequiresStandardJobs = 1U << 0;
inline constexpr uint32_t kSetupFlagRequiresVersionRolling = 1U << 2;
inline constexpr uint32_t kSetupSuccessFlagRequiresFixedVersion = 1U << 0;

// Keep U256 as little-endian wire bytes to avoid implicit host-endian conversions.
using U256 = std::array<uint8_t, 32>;

struct SetupConnection {
    static constexpr uint8_t kMessageType = 0x00;
    static constexpr bool kChannelMessage = false;

    uint8_t protocol{};
    uint16_t minimum_version{};
    uint16_t maximum_version{};
    uint32_t flags{};
    std::string endpoint_host;
    uint16_t endpoint_port{};
    std::string vendor;
    std::string hardware_version;
    std::string firmware;
    std::string device_id;

    friend bool operator==(const SetupConnection&, const SetupConnection&) = default;
};

struct SetupConnectionSuccess {
    static constexpr uint8_t kMessageType = 0x01;
    static constexpr bool kChannelMessage = false;

    uint16_t used_version{};
    uint32_t flags{};

    friend bool operator==(const SetupConnectionSuccess&, const SetupConnectionSuccess&) = default;
};

struct SetupConnectionError {
    static constexpr uint8_t kMessageType = 0x02;
    static constexpr bool kChannelMessage = false;

    uint32_t flags{};
    std::string error_code;

    friend bool operator==(const SetupConnectionError&, const SetupConnectionError&) = default;
};

struct OpenStandardMiningChannel {
    static constexpr uint8_t kMessageType = 0x10;
    static constexpr bool kChannelMessage = false;

    uint32_t request_id{};
    std::string user_identity;
    float nominal_hash_rate{};
    U256 maximum_target{};

    friend bool operator==(const OpenStandardMiningChannel&,
                           const OpenStandardMiningChannel&) = default;
};

struct OpenStandardMiningChannelSuccess {
    static constexpr uint8_t kMessageType = 0x11;
    static constexpr bool kChannelMessage = false;

    uint32_t request_id{};
    uint32_t channel_id{};
    U256 target{};
    Bytes extranonce_prefix;
    uint32_t group_channel_id{};

    friend bool operator==(const OpenStandardMiningChannelSuccess&,
                           const OpenStandardMiningChannelSuccess&) = default;
};

struct OpenMiningChannelError {
    static constexpr uint8_t kMessageType = 0x12;
    static constexpr bool kChannelMessage = false;

    uint32_t request_id{};
    std::string error_code;

    friend bool operator==(const OpenMiningChannelError&, const OpenMiningChannelError&) = default;
};

struct OpenExtendedMiningChannel {
    static constexpr uint8_t kMessageType = 0x13;
    static constexpr bool kChannelMessage = false;

    uint32_t request_id{};
    std::string user_identity;
    float nominal_hash_rate{};
    U256 maximum_target{};
    uint16_t minimum_extranonce_size{};

    friend bool operator==(const OpenExtendedMiningChannel&,
                           const OpenExtendedMiningChannel&) = default;
};

struct OpenExtendedMiningChannelSuccess {
    static constexpr uint8_t kMessageType = 0x14;
    static constexpr bool kChannelMessage = false;

    uint32_t request_id{};
    uint32_t channel_id{};
    U256 target{};
    uint16_t extranonce_size{};
    Bytes extranonce_prefix;
    uint32_t group_channel_id{};

    friend bool operator==(const OpenExtendedMiningChannelSuccess&,
                           const OpenExtendedMiningChannelSuccess&) = default;
};

struct NewMiningJob {
    static constexpr uint8_t kMessageType = 0x15;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t job_id{};
    std::optional<uint32_t> minimum_ntime;
    uint32_t version{};
    U256 merkle_root{};

    friend bool operator==(const NewMiningJob&, const NewMiningJob&) = default;
};

struct UpdateChannel {
    static constexpr uint8_t kMessageType = 0x16;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    float nominal_hash_rate{};
    U256 maximum_target{};

    friend bool operator==(const UpdateChannel&, const UpdateChannel&) = default;
};

struct UpdateChannelError {
    static constexpr uint8_t kMessageType = 0x17;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    std::string error_code;

    friend bool operator==(const UpdateChannelError&, const UpdateChannelError&) = default;
};

struct CloseChannel {
    static constexpr uint8_t kMessageType = 0x18;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    std::string reason_code;

    friend bool operator==(const CloseChannel&, const CloseChannel&) = default;
};

struct SetExtranoncePrefix {
    static constexpr uint8_t kMessageType = 0x19;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    Bytes extranonce_prefix;

    friend bool operator==(const SetExtranoncePrefix&,
                           const SetExtranoncePrefix&) = default;
};

struct SubmitSharesStandard {
    static constexpr uint8_t kMessageType = 0x1a;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t sequence_number{};
    uint32_t job_id{};
    uint32_t nonce{};
    uint32_t ntime{};
    uint32_t version{};

    friend bool operator==(const SubmitSharesStandard&, const SubmitSharesStandard&) = default;
};

struct SubmitSharesExtended {
    static constexpr uint8_t kMessageType = 0x1b;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t sequence_number{};
    uint32_t job_id{};
    uint32_t nonce{};
    uint32_t ntime{};
    uint32_t version{};
    Bytes extranonce;

    friend bool operator==(const SubmitSharesExtended&, const SubmitSharesExtended&) = default;
};

struct SubmitSharesSuccess {
    static constexpr uint8_t kMessageType = 0x1c;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t last_sequence_number{};
    uint32_t new_submits_accepted_count{};
    uint64_t new_shares_sum{};

    friend bool operator==(const SubmitSharesSuccess&, const SubmitSharesSuccess&) = default;
};

struct SubmitSharesError {
    static constexpr uint8_t kMessageType = 0x1d;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t sequence_number{};
    std::string error_code;

    friend bool operator==(const SubmitSharesError&, const SubmitSharesError&) = default;
};

struct NewExtendedMiningJob {
    static constexpr uint8_t kMessageType = 0x1f;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t job_id{};
    std::optional<uint32_t> minimum_ntime;
    uint32_t version{};
    bool version_rolling_allowed{};
    std::vector<U256> merkle_path;
    Bytes coinbase_tx_prefix;
    Bytes coinbase_tx_suffix;

    friend bool operator==(const NewExtendedMiningJob&,
                           const NewExtendedMiningJob&) = default;
};

struct SetNewPrevHash {
    static constexpr uint8_t kMessageType = 0x20;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    uint32_t job_id{};
    U256 previous_hash{};
    uint32_t minimum_ntime{};
    uint32_t nbits{};

    friend bool operator==(const SetNewPrevHash&, const SetNewPrevHash&) = default;
};

struct SetTarget {
    static constexpr uint8_t kMessageType = 0x21;
    static constexpr bool kChannelMessage = true;

    uint32_t channel_id{};
    U256 maximum_target{};

    friend bool operator==(const SetTarget&, const SetTarget&) = default;
};

[[nodiscard]] Bytes encode_payload(const SetupConnection& message);
[[nodiscard]] Bytes encode_payload(const SetupConnectionSuccess& message);
[[nodiscard]] Bytes encode_payload(const SetupConnectionError& message);
[[nodiscard]] Bytes encode_payload(const OpenStandardMiningChannel& message);
[[nodiscard]] Bytes encode_payload(const OpenStandardMiningChannelSuccess& message);
[[nodiscard]] Bytes encode_payload(const OpenMiningChannelError& message);
[[nodiscard]] Bytes encode_payload(const OpenExtendedMiningChannel& message);
[[nodiscard]] Bytes encode_payload(const OpenExtendedMiningChannelSuccess& message);
[[nodiscard]] Bytes encode_payload(const UpdateChannel& message);
[[nodiscard]] Bytes encode_payload(const UpdateChannelError& message);
[[nodiscard]] Bytes encode_payload(const CloseChannel& message);
[[nodiscard]] Bytes encode_payload(const SetExtranoncePrefix& message);
[[nodiscard]] Bytes encode_payload(const NewMiningJob& message);
[[nodiscard]] Bytes encode_payload(const SubmitSharesStandard& message);
[[nodiscard]] Bytes encode_payload(const SubmitSharesExtended& message);
[[nodiscard]] Bytes encode_payload(const SubmitSharesSuccess& message);
[[nodiscard]] Bytes encode_payload(const SubmitSharesError& message);
[[nodiscard]] Bytes encode_payload(const NewExtendedMiningJob& message);
[[nodiscard]] Bytes encode_payload(const SetNewPrevHash& message);
[[nodiscard]] Bytes encode_payload(const SetTarget& message);

[[nodiscard]] SetupConnection decode_setup_connection(ByteView payload);
[[nodiscard]] SetupConnectionSuccess decode_setup_connection_success(ByteView payload);
[[nodiscard]] SetupConnectionError decode_setup_connection_error(ByteView payload);
[[nodiscard]] OpenStandardMiningChannel decode_open_standard_mining_channel(ByteView payload);
[[nodiscard]] OpenStandardMiningChannelSuccess
decode_open_standard_mining_channel_success(ByteView payload);
[[nodiscard]] OpenMiningChannelError decode_open_mining_channel_error(ByteView payload);
[[nodiscard]] OpenExtendedMiningChannel decode_open_extended_mining_channel(ByteView payload);
[[nodiscard]] OpenExtendedMiningChannelSuccess
decode_open_extended_mining_channel_success(ByteView payload);
[[nodiscard]] UpdateChannel decode_update_channel(ByteView payload);
[[nodiscard]] UpdateChannelError decode_update_channel_error(ByteView payload);
[[nodiscard]] CloseChannel decode_close_channel(ByteView payload);
[[nodiscard]] SetExtranoncePrefix decode_set_extranonce_prefix(ByteView payload);
[[nodiscard]] NewMiningJob decode_new_mining_job(ByteView payload);
[[nodiscard]] SubmitSharesStandard decode_submit_shares_standard(ByteView payload);
[[nodiscard]] SubmitSharesExtended decode_submit_shares_extended(ByteView payload);
[[nodiscard]] SubmitSharesSuccess decode_submit_shares_success(ByteView payload);
[[nodiscard]] SubmitSharesError decode_submit_shares_error(ByteView payload);
[[nodiscard]] NewExtendedMiningJob decode_new_extended_mining_job(ByteView payload);
[[nodiscard]] SetNewPrevHash decode_set_new_prev_hash(ByteView payload);
[[nodiscard]] SetTarget decode_set_target(ByteView payload);

template <typename Message>
[[nodiscard]] Bytes encode_message(const Message& message) {
    return encode_frame({make_extension_type(kCoreExtensionId, Message::kChannelMessage),
                         Message::kMessageType, encode_payload(message)});
}

} // namespace erikslund::sv2
