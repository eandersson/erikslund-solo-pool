#include "sv2/noise_connection.hpp"

#include <algorithm>
#include <ctime>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

#include "sv2/codec.hpp"
#include "util/endian.hpp"

namespace erikslund::sv2 {

namespace {

[[nodiscard]] sv2_noise_status crypto_failure(sv2_noise_status status) noexcept {
    return status == SV2_NOISE_OK ? SV2_NOISE_ERROR_CRYPTO_FAILURE : status;
}

[[nodiscard]] std::optional<uint32_t> current_unix_time() noexcept {
    const std::time_t current_time = std::time(nullptr);
    if (current_time < 0)
        return std::nullopt;
    const auto unsigned_time = static_cast<uint64_t>(current_time);
    if (unsigned_time > std::numeric_limits<uint32_t>::max())
        return std::nullopt;
    return static_cast<uint32_t>(unsigned_time);
}

[[nodiscard]] std::size_t payload_ciphertext_size(
    std::size_t plaintext_size) noexcept {
    if (plaintext_size == 0)
        return 0;
    const std::size_t chunk_count =
        (plaintext_size + SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE - 1) /
        SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE;
    return plaintext_size + chunk_count * SV2_NOISE_TAG_SIZE;
}

} // namespace

NoiseCredentials::NoiseCredentials(FactoryToken,
                                   sv2_noise_credentials* credentials) noexcept
    : credentials_(credentials) {}

NoiseCredentials::~NoiseCredentials() {
    sv2_noise_credentials_free(credentials_);
}

NoiseCredentials::LoadResult NoiseCredentials::load(
    ByteView static_secret_key,
    ByteView authority_public_key,
    ByteView certificate,
    uint32_t current_unix_time) {
    if (static_secret_key.size() != SV2_NOISE_SECRET_KEY_SIZE ||
        authority_public_key.size() != SV2_NOISE_PUBLIC_KEY_SIZE ||
        certificate.size() != SV2_NOISE_CERTIFICATE_SIZE)
        return std::unexpected(SV2_NOISE_ERROR_INVALID_ARGUMENT);

    sv2_noise_credentials* credentials = nullptr;
    const sv2_noise_status status = sv2_noise_credentials_load(
        static_secret_key.data(), static_secret_key.size(),
        authority_public_key.data(), authority_public_key.size(),
        certificate.data(), certificate.size(), current_unix_time,
        &credentials);
    if (status != SV2_NOISE_OK)
        return std::unexpected(status);
    if (credentials == nullptr)
        return std::unexpected(SV2_NOISE_ERROR_CRYPTO_FAILURE);

    try {
        return std::make_shared<NoiseCredentials>(FactoryToken{}, credentials);
    } catch (...) {
        sv2_noise_credentials_free(credentials);
        throw;
    }
}

NoiseConnection::NoiseConnection(
    std::shared_ptr<Connection> transport,
    std::shared_ptr<const NoiseCredentials> credentials,
    uint32_t maximum_payload_size)
    : transport_(std::move(transport)),
      credentials_(std::move(credentials)),
      maximum_payload_size_(
          std::min(maximum_payload_size, kMaximumFramePayloadSize)) {
    if (!transport_)
        throw std::invalid_argument("SV2 Noise requires a transport");
    if (!credentials_)
        throw std::invalid_argument("SV2 Noise requires responder credentials");
}

NoiseConnection::~NoiseConnection() {
    const std::scoped_lock send_lock(send_mutex_);
    const std::scoped_lock noise_lock(noise_mutex_);
    sv2_noise_session_free(session_);
}

std::string NoiseConnection::peer() const {
    return transport_->peer();
}

bool NoiseConnection::handshake_complete() const noexcept {
    return handshake_complete_.load(std::memory_order_acquire);
}

bool NoiseConnection::terminal() const noexcept {
    return terminal_.load(std::memory_order_acquire);
}

sv2_noise_status NoiseConnection::failure_status() const noexcept {
    return failure_status_.load(std::memory_order_acquire);
}

void NoiseConnection::terminate_locked(sv2_noise_status status) noexcept {
    if (status != SV2_NOISE_OK) {
        auto expected = SV2_NOISE_OK;
        failure_status_.compare_exchange_strong(
            expected, status, std::memory_order_release,
            std::memory_order_relaxed);
    }
    sv2_noise_session_free(session_);
    session_ = nullptr;
    state_ = StreamState::Terminal;
    act1_size_ = 0;
    encrypted_header_size_ = 0;
    plaintext_payload_size_ = 0;
    expected_encrypted_payload_size_ = 0;
    encrypted_payload_.clear();
    terminal_.store(true, std::memory_order_release);
}

void NoiseConnection::terminate() noexcept {
    const std::scoped_lock lock(noise_mutex_);
    terminate_locked();
}

bool NoiseConnection::establish_transport() {
    std::array<uint8_t, SV2_NOISE_ACT2_SIZE> act2{};
    std::size_t act2_size = 0;

    // Keep application frames behind Act2.
    const std::scoped_lock send_lock(send_mutex_);
    {
        const std::scoped_lock noise_lock(noise_mutex_);
        if (state_ != StreamState::Act1Ready || terminal())
            return false;

        const std::optional<uint32_t> current_time = current_unix_time();
        if (!current_time) {
            terminate_locked();
            return false;
        }

        sv2_noise_session* session = nullptr;
        const sv2_noise_status status = sv2_noise_responder_handshake(
            credentials_->credentials_, *current_time, act1_.data(),
            act1_.size(), act2.data(), act2.size(), &act2_size, &session);
        if (status != SV2_NOISE_OK || session == nullptr ||
            act2_size != act2.size()) {
            sv2_noise_session_free(session);
            terminate_locked(crypto_failure(status));
            return false;
        }

        session_ = session;
        state_ = StreamState::SendingAct2;
        act1_size_ = 0;
    }

    try {
        transport_->send_bytes(act2);
    } catch (...) {
        terminate();
        return false;
    }

    {
        const std::scoped_lock noise_lock(noise_mutex_);
        if (state_ != StreamState::SendingAct2 || terminal())
            return false;
        state_ = StreamState::Transport;
        handshake_complete_.store(true, std::memory_order_release);
    }
    return true;
}

Bytes NoiseConnection::receive(ByteView bytes) noexcept {
    Bytes plaintext_frames;
    try {
        std::size_t input_offset = 0;
        bool act1_complete = false;
        {
            const std::scoped_lock lock(noise_mutex_);
            if (terminal())
                return {};
            if (state_ == StreamState::AwaitingAct1) {
                const std::size_t bytes_to_copy =
                    std::min(act1_.size() - act1_size_, bytes.size());
                std::copy_n(bytes.begin(), bytes_to_copy,
                            act1_.begin() + static_cast<std::ptrdiff_t>(act1_size_));
                act1_size_ += bytes_to_copy;
                input_offset = bytes_to_copy;
                if (act1_size_ == act1_.size()) {
                    state_ = StreamState::Act1Ready;
                    act1_complete = true;
                }
            } else if (state_ == StreamState::Act1Ready) {
                act1_complete = true;
            } else if (state_ != StreamState::Transport) {
                terminate_locked();
                return {};
            }
        }

        if (act1_complete && !establish_transport())
            return {};

        const std::scoped_lock lock(noise_mutex_);
        if (state_ != StreamState::Transport || terminal())
            return {};
        decrypt_transport_locked(bytes.subspan(input_offset),
                                 plaintext_frames);
    } catch (...) {
        terminate();
    }
    return plaintext_frames;
}

void NoiseConnection::decrypt_transport_locked(ByteView bytes,
                                                Bytes& plaintext_frames) {
    std::size_t input_offset = 0;

    while (input_offset < bytes.size()) {
        if (encrypted_header_size_ < encrypted_header_.size()) {
            const std::size_t bytes_to_copy =
                std::min(encrypted_header_.size() - encrypted_header_size_,
                         bytes.size() - input_offset);
            std::copy_n(
                bytes.begin() + static_cast<std::ptrdiff_t>(input_offset),
                bytes_to_copy,
                encrypted_header_.begin() +
                    static_cast<std::ptrdiff_t>(encrypted_header_size_));
            encrypted_header_size_ += bytes_to_copy;
            input_offset += bytes_to_copy;
            if (encrypted_header_size_ != encrypted_header_.size())
                continue;

            std::size_t plaintext_header_size = 0;
            const sv2_noise_status status = sv2_noise_decrypt_header(
                session_, encrypted_header_.data(), encrypted_header_.size(),
                plaintext_header_.data(), plaintext_header_.size(),
                &plaintext_header_size);
            if (status != SV2_NOISE_OK ||
                plaintext_header_size != plaintext_header_.size()) {
                terminate_locked(crypto_failure(status));
                return;
            }

            plaintext_payload_size_ = util::read_le24(plaintext_header_.data() + 3);
            if (plaintext_payload_size_ > maximum_payload_size_) {
                terminate_locked();
                return;
            }
            if (plaintext_payload_size_ == 0) {
                append(plaintext_frames, plaintext_header_);
                reset_incoming_frame_locked();
                continue;
            }

            std::size_t calculated_ciphertext_size = 0;
            const sv2_noise_status ciphertext_size_status =
                sv2_noise_payload_ciphertext_size(
                    plaintext_payload_size_, &calculated_ciphertext_size);
            if (ciphertext_size_status != SV2_NOISE_OK ||
                calculated_ciphertext_size !=
                    payload_ciphertext_size(plaintext_payload_size_)) {
                terminate_locked(crypto_failure(ciphertext_size_status));
                return;
            }
            expected_encrypted_payload_size_ = calculated_ciphertext_size;
            encrypted_payload_.clear();
            encrypted_payload_.reserve(expected_encrypted_payload_size_);
        }

        const std::size_t bytes_to_copy =
            std::min(expected_encrypted_payload_size_ - encrypted_payload_.size(),
                     bytes.size() - input_offset);
        const auto first_byte =
            bytes.begin() + static_cast<std::ptrdiff_t>(input_offset);
        encrypted_payload_.insert(
            encrypted_payload_.end(), first_byte,
            first_byte + static_cast<std::ptrdiff_t>(bytes_to_copy));
        input_offset += bytes_to_copy;
        if (encrypted_payload_.size() != expected_encrypted_payload_size_)
            continue;

        Bytes plaintext_payload(plaintext_payload_size_);
        std::size_t decrypted_size = 0;
        const sv2_noise_status status = sv2_noise_decrypt_payload(
            session_, encrypted_payload_.data(), encrypted_payload_.size(),
            plaintext_payload_size_, plaintext_payload.data(),
            plaintext_payload.size(), &decrypted_size);
        if (status != SV2_NOISE_OK ||
            decrypted_size != plaintext_payload.size()) {
            terminate_locked(crypto_failure(status));
            return;
        }

        append(plaintext_frames, plaintext_header_);
        append(plaintext_frames, plaintext_payload);
        reset_incoming_frame_locked();
    }
}

void NoiseConnection::reset_incoming_frame_locked() noexcept {
    encrypted_header_size_ = 0;
    plaintext_payload_size_ = 0;
    expected_encrypted_payload_size_ = 0;
    encrypted_payload_.clear();
}

void NoiseConnection::send_bytes(ByteView bytes) noexcept {
    const std::scoped_lock send_lock(send_mutex_);
    try {
        // The configured payload limit applies only to untrusted inbound frames.
        FrameDecoder decoder(kMaximumFramePayloadSize);
        const std::vector<Frame> frames = decoder.push(bytes);
        decoder.finish();
        if (frames.empty()) {
            terminate();
            return;
        }

        std::size_t total_ciphertext_size = 0;
        for (const Frame& frame : frames) {
            const std::size_t payload_size = frame.payload.size();
            const std::size_t encrypted_frame_size =
                SV2_NOISE_ENCRYPTED_HEADER_SIZE +
                payload_ciphertext_size(payload_size);
            if (encrypted_frame_size >
                std::numeric_limits<std::size_t>::max() -
                    total_ciphertext_size) {
                terminate();
                return;
            }
            total_ciphertext_size += encrypted_frame_size;
        }

        Bytes ciphertext;
        ciphertext.reserve(total_ciphertext_size);
        {
            const std::scoped_lock noise_lock(noise_mutex_);
            if (terminal())
                return;
            if (state_ != StreamState::Transport) {
                terminate_locked();
                return;
            }

            std::size_t plaintext_offset = 0;
            for (const Frame& frame : frames) {
                const ByteView header = bytes.subspan(
                    plaintext_offset, SV2_NOISE_HEADER_SIZE);
                const std::size_t header_offset = ciphertext.size();
                ciphertext.resize(header_offset +
                                  SV2_NOISE_ENCRYPTED_HEADER_SIZE);
                std::size_t encrypted_bytes_written = 0;
                const sv2_noise_status header_status =
                    sv2_noise_encrypt_header(
                        session_, header.data(), header.size(),
                        ciphertext.data() + header_offset,
                        SV2_NOISE_ENCRYPTED_HEADER_SIZE,
                        &encrypted_bytes_written);
                if (header_status != SV2_NOISE_OK ||
                    encrypted_bytes_written !=
                        SV2_NOISE_ENCRYPTED_HEADER_SIZE) {
                    terminate_locked(crypto_failure(header_status));
                    return;
                }
                plaintext_offset += SV2_NOISE_HEADER_SIZE;

                const std::size_t payload_size = frame.payload.size();
                if (payload_size == 0)
                    continue;
                const ByteView payload =
                    bytes.subspan(plaintext_offset, payload_size);
                const std::size_t expected_payload_ciphertext_size =
                    payload_ciphertext_size(payload_size);
                const std::size_t payload_offset = ciphertext.size();
                ciphertext.resize(payload_offset +
                                  expected_payload_ciphertext_size);
                encrypted_bytes_written = 0;
                const sv2_noise_status payload_status =
                    sv2_noise_encrypt_payload(
                        session_, payload.data(), payload.size(),
                        ciphertext.data() + payload_offset,
                        expected_payload_ciphertext_size,
                        &encrypted_bytes_written);
                if (payload_status != SV2_NOISE_OK ||
                    encrypted_bytes_written !=
                        expected_payload_ciphertext_size) {
                    terminate_locked(crypto_failure(payload_status));
                    return;
                }
                plaintext_offset += payload_size;
            }
        }

        if (terminal())
            return;
        transport_->send_bytes(ciphertext);
    } catch (...) {
        terminate();
    }
}

bool NoiseConnection::finish() noexcept {
    const std::scoped_lock send_lock(send_mutex_);
    const std::scoped_lock noise_lock(noise_mutex_);
    const bool clean =
        state_ == StreamState::Transport && encrypted_header_size_ == 0 &&
        encrypted_payload_.empty() && !terminal();
    terminate_locked();
    return clean;
}

} // namespace erikslund::sv2
