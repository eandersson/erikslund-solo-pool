#pragma once
// Authenticated SV2 Noise responder transport layered over an ordered byte connection.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <mutex>
#include <string>

#include <sv2_noise.h>

#include "sv2/connection.hpp"
#include "util/bytes.hpp"

namespace erikslund::sv2 {

struct NoiseConnectionTestPeek;

class NoiseCredentials final {
public:
    using LoadResult =
        std::expected<std::shared_ptr<const NoiseCredentials>, sv2_noise_status>;

    [[nodiscard]] static LoadResult load(ByteView static_secret_key,
                                         ByteView authority_public_key,
                                         ByteView certificate,
                                         uint32_t current_unix_time);

    ~NoiseCredentials();

    NoiseCredentials(const NoiseCredentials&) = delete;
    NoiseCredentials& operator=(const NoiseCredentials&) = delete;

private:
    struct FactoryToken {};

public:
    // Enables make_shared without exposing raw-handle construction.
    NoiseCredentials(FactoryToken, sv2_noise_credentials* credentials) noexcept;

private:
    friend class NoiseConnection;

    sv2_noise_credentials* credentials_;
};

class NoiseConnection final : public Connection {
public:
    NoiseConnection(std::shared_ptr<Connection> transport,
                    std::shared_ptr<const NoiseCredentials> credentials,
                    uint32_t maximum_payload_size);
    ~NoiseConnection() override;

    NoiseConnection(const NoiseConnection&) = delete;
    NoiseConnection& operator=(const NoiseConnection&) = delete;

    void send_bytes(ByteView bytes) noexcept override;
    std::string peer() const override;

    [[nodiscard]] Bytes receive(ByteView bytes) noexcept;

    [[nodiscard]] bool finish() noexcept;

    [[nodiscard]] bool handshake_complete() const noexcept;
    [[nodiscard]] bool terminal() const noexcept;
    [[nodiscard]] sv2_noise_status failure_status() const noexcept;

private:
    enum class StreamState : uint8_t {
        AwaitingAct1,
        Act1Ready,
        SendingAct2,
        Transport,
        Terminal,
    };

    [[nodiscard]] bool establish_transport();
    void decrypt_transport_locked(ByteView bytes, Bytes& plaintext_frames);
    void reset_incoming_frame_locked() noexcept;
    void terminate_locked(sv2_noise_status status = SV2_NOISE_OK) noexcept;
    void terminate() noexcept;

    friend struct NoiseConnectionTestPeek;

    std::shared_ptr<Connection> transport_;
    std::shared_ptr<const NoiseCredentials> credentials_;
    uint32_t maximum_payload_size_;

    // Lock order: send_mutex_ then noise_mutex_, never the reverse.
    std::mutex send_mutex_;
    std::mutex noise_mutex_;
    sv2_noise_session* session_ = nullptr;
    StreamState state_ = StreamState::AwaitingAct1;

    std::array<uint8_t, SV2_NOISE_ACT1_SIZE> act1_{};
    std::size_t act1_size_ = 0;
    std::array<uint8_t, SV2_NOISE_ENCRYPTED_HEADER_SIZE> encrypted_header_{};
    std::size_t encrypted_header_size_ = 0;
    std::array<uint8_t, SV2_NOISE_HEADER_SIZE> plaintext_header_{};
    uint32_t plaintext_payload_size_ = 0;
    std::size_t expected_encrypted_payload_size_ = 0;
    Bytes encrypted_payload_;

    std::atomic<bool> handshake_complete_{false};
    std::atomic<bool> terminal_{false};
    std::atomic<sv2_noise_status> failure_status_{SV2_NOISE_OK};
};

} // namespace erikslund::sv2
