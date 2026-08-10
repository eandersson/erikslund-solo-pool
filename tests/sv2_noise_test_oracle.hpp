#pragma once
// Test-only authenticated initiator for exercising the production SV2 Noise responder adapter.
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include "sv2/noise_connection.hpp"
#include "util/bytes.hpp"

namespace erikslund::sv2::test {

using Bytes32 = std::array<uint8_t, 32>;
using Bytes64 = std::array<uint8_t, 64>;

inline constexpr std::array<uint8_t, 32> kProtocolHash{
    0x2e, 0xb4, 0x78, 0x81, 0x20, 0x8e, 0x9e, 0xee,
    0x1f, 0x66, 0x9f, 0x67, 0xc6, 0x6e, 0xe7, 0x0e,
    0xa9, 0xea, 0x88, 0x09, 0x0d, 0x50, 0x3f, 0xe8,
    0x30, 0xdc, 0x4b, 0xc8, 0x3e, 0x29, 0xbf, 0x10,
};

inline void require(bool condition, const char* message) {
    if (!condition)
        throw std::runtime_error(message);
}

struct SecpDeleter {
    void operator()(secp256k1_context* context) const {
        secp256k1_context_destroy(context);
    }
};

using SecpPtr = std::unique_ptr<secp256k1_context, SecpDeleter>;

[[nodiscard]] inline Bytes32 secret_key(uint8_t final_byte) {
    Bytes32 secret{};
    secret.back() = final_byte;
    return secret;
}

[[nodiscard]] inline Bytes32 repeated_bytes(uint8_t value) {
    Bytes32 bytes{};
    bytes.fill(value);
    return bytes;
}

inline void store_u16_le(uint8_t* output, uint16_t value) {
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
}

inline void store_u32_le(uint8_t* output, uint32_t value) {
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
    output[2] = static_cast<uint8_t>(value >> 16);
    output[3] = static_cast<uint8_t>(value >> 24);
}

[[nodiscard]] inline uint32_t read_u24(const uint8_t* input) {
    return static_cast<uint32_t>(input[0]) |
           static_cast<uint32_t>(input[1]) << 8 |
           static_cast<uint32_t>(input[2]) << 16;
}

[[nodiscard]] inline Bytes32 sha256(ByteView first, ByteView second = {}) {
    Bytes32 output{};
    unsigned int output_length = 0;
    auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);

    require(context != nullptr, "EVP_MD_CTX_new failed");
    require(EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1,
            "EVP_DigestInit_ex failed");
    if (!first.empty())
        require(EVP_DigestUpdate(context.get(), first.data(), first.size()) == 1,
                "EVP_DigestUpdate failed");
    if (!second.empty())
        require(EVP_DigestUpdate(context.get(), second.data(), second.size()) == 1,
                "EVP_DigestUpdate failed");
    require(EVP_DigestFinal_ex(context.get(), output.data(), &output_length) == 1,
            "EVP_DigestFinal_ex failed");
    require(output_length == output.size(), "unexpected SHA-256 output size");
    return output;
}

[[nodiscard]] inline Bytes32 hmac_sha256(const Bytes32& key, ByteView data) {
    std::array<uint8_t, 64> inner_pad{};
    std::array<uint8_t, 64> outer_pad{};

    inner_pad.fill(0x36);
    outer_pad.fill(0x5c);
    for (std::size_t index = 0; index < key.size(); ++index) {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    const Bytes32 inner_hash = sha256(inner_pad, data);
    return sha256(outer_pad, inner_hash);
}

[[nodiscard]] inline std::pair<Bytes32, Bytes32> hkdf_two(
    const Bytes32& chaining_key,
    ByteView input_key_material) {
    const Bytes32 temporary_key =
        hmac_sha256(chaining_key, input_key_material);
    constexpr std::array<uint8_t, 1> kFirstCounter{0x01};
    const Bytes32 first = hmac_sha256(temporary_key, kFirstCounter);
    std::array<uint8_t, 33> second_input{};

    std::ranges::copy(first, second_input.begin());
    second_input.back() = 0x02;
    return {first, hmac_sha256(temporary_key, second_input)};
}

[[nodiscard]] inline std::array<uint8_t, 12> noise_nonce(uint64_t nonce) {
    std::array<uint8_t, 12> bytes{};
    for (std::size_t index = 0; index < sizeof(nonce); ++index)
        bytes[4 + index] =
            static_cast<uint8_t>(nonce >> (index * 8));
    return bytes;
}

[[nodiscard]] inline Bytes aead_encrypt(
    const Bytes32& key,
    uint64_t nonce_value,
    ByteView associated_data,
    ByteView plaintext) {
    const auto nonce = noise_nonce(nonce_value);
    Bytes ciphertext(plaintext.size() + SV2_NOISE_TAG_SIZE);
    auto context =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int written = 0;
    int total_written = 0;

    require(context != nullptr, "EVP_CIPHER_CTX_new failed");
    require(EVP_EncryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr,
                               nullptr, nullptr) == 1,
            "EVP_EncryptInit_ex failed");
    require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                static_cast<int>(nonce.size()), nullptr) == 1,
            "setting AEAD nonce size failed");
    require(EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                               nonce.data()) == 1,
            "setting AEAD key failed");
    if (!associated_data.empty())
        require(EVP_EncryptUpdate(context.get(), nullptr, &written,
                                  associated_data.data(),
                                  static_cast<int>(associated_data.size())) == 1,
                "encrypting associated data failed");
    if (!plaintext.empty()) {
        require(EVP_EncryptUpdate(context.get(), ciphertext.data(), &written,
                                  plaintext.data(),
                                  static_cast<int>(plaintext.size())) == 1,
                "encrypting plaintext failed");
        total_written = written;
    }
    require(EVP_EncryptFinal_ex(context.get(),
                                ciphertext.data() + total_written,
                                &written) == 1,
            "finalizing encryption failed");
    total_written += written;
    require(static_cast<std::size_t>(total_written) == plaintext.size(),
            "unexpected encrypted plaintext size");
    require(EVP_CIPHER_CTX_ctrl(
                context.get(), EVP_CTRL_AEAD_GET_TAG, SV2_NOISE_TAG_SIZE,
                ciphertext.data() + plaintext.size()) == 1,
            "reading AEAD tag failed");
    return ciphertext;
}

[[nodiscard]] inline bool aead_decrypt(
    const Bytes32& key,
    uint64_t nonce_value,
    ByteView associated_data,
    ByteView ciphertext,
    Bytes& plaintext) {
    if (ciphertext.size() < SV2_NOISE_TAG_SIZE)
        return false;

    const auto nonce = noise_nonce(nonce_value);
    const std::size_t plaintext_size =
        ciphertext.size() - SV2_NOISE_TAG_SIZE;
    auto context =
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
            EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    int written = 0;
    int total_written = 0;

    plaintext.assign(plaintext_size, 0);
    require(context != nullptr, "EVP_CIPHER_CTX_new failed");
    require(EVP_DecryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr,
                               nullptr, nullptr) == 1,
            "EVP_DecryptInit_ex failed");
    require(EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_IVLEN,
                                static_cast<int>(nonce.size()), nullptr) == 1,
            "setting AEAD nonce size failed");
    require(EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(),
                               nonce.data()) == 1,
            "setting AEAD key failed");
    if (!associated_data.empty())
        require(EVP_DecryptUpdate(context.get(), nullptr, &written,
                                  associated_data.data(),
                                  static_cast<int>(associated_data.size())) == 1,
                "decrypting associated data failed");
    if (plaintext_size != 0) {
        require(EVP_DecryptUpdate(context.get(), plaintext.data(), &written,
                                  ciphertext.data(),
                                  static_cast<int>(plaintext_size)) == 1,
                "decrypting ciphertext failed");
        total_written = written;
    }
    require(EVP_CIPHER_CTX_ctrl(
                context.get(), EVP_CTRL_AEAD_SET_TAG, SV2_NOISE_TAG_SIZE,
                const_cast<uint8_t*>(ciphertext.data() + plaintext_size)) == 1,
            "setting AEAD tag failed");
    if (EVP_DecryptFinal_ex(context.get(),
                            plaintext.data() + total_written,
                            &written) != 1) {
        std::ranges::fill(plaintext, 0);
        return false;
    }
    total_written += written;
    return static_cast<std::size_t>(total_written) == plaintext_size;
}

struct Cipher {
    Bytes32 key{};
    uint64_t nonce = 0;

    [[nodiscard]] Bytes encrypt(ByteView plaintext) {
        require(nonce != std::numeric_limits<uint64_t>::max(),
                "test cipher nonce exhausted");
        Bytes ciphertext = aead_encrypt(key, nonce, {}, plaintext);
        ++nonce;
        return ciphertext;
    }

    [[nodiscard]] bool decrypt(ByteView ciphertext, Bytes& plaintext) {
        require(nonce != std::numeric_limits<uint64_t>::max(),
                "test cipher nonce exhausted");
        if (!aead_decrypt(key, nonce, {}, ciphertext, plaintext))
            return false;
        ++nonce;
        return true;
    }
};

struct ClientTransport {
    Cipher send;
    Cipher receive;

    [[nodiscard]] Bytes encrypt_frame(ByteView plaintext_frame) {
        require(plaintext_frame.size() >= SV2_NOISE_HEADER_SIZE,
                "plaintext frame has no complete header");
        const uint32_t payload_size = read_u24(plaintext_frame.data() + 3);
        require(plaintext_frame.size() == SV2_NOISE_HEADER_SIZE + payload_size,
                "plaintext frame size does not match its header");

        Bytes ciphertext =
            send.encrypt(plaintext_frame.first(SV2_NOISE_HEADER_SIZE));
        std::size_t payload_offset = SV2_NOISE_HEADER_SIZE;
        while (payload_offset < plaintext_frame.size()) {
            const std::size_t chunk_size = std::min<std::size_t>(
                SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE,
                plaintext_frame.size() - payload_offset);
            append(ciphertext,
                   send.encrypt(
                       plaintext_frame.subspan(payload_offset, chunk_size)));
            payload_offset += chunk_size;
        }
        return ciphertext;
    }

    [[nodiscard]] Bytes decrypt_flight(ByteView ciphertext) {
        Bytes plaintext_frames;
        std::size_t ciphertext_offset = 0;

        while (ciphertext_offset < ciphertext.size()) {
            require(ciphertext.size() - ciphertext_offset >=
                        SV2_NOISE_ENCRYPTED_HEADER_SIZE,
                    "encrypted flight ends inside a header");
            Bytes header;
            require(receive.decrypt(
                        ciphertext.subspan(
                            ciphertext_offset,
                            SV2_NOISE_ENCRYPTED_HEADER_SIZE),
                        header),
                    "server header authentication failed");
            require(header.size() == SV2_NOISE_HEADER_SIZE,
                    "unexpected decrypted header size");
            ciphertext_offset += SV2_NOISE_ENCRYPTED_HEADER_SIZE;
            append(plaintext_frames, header);

            std::size_t payload_remaining = read_u24(header.data() + 3);
            while (payload_remaining != 0) {
                const std::size_t chunk_size = std::min<std::size_t>(
                    SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE, payload_remaining);
                const std::size_t encrypted_chunk_size =
                    chunk_size + SV2_NOISE_TAG_SIZE;
                require(ciphertext.size() - ciphertext_offset >=
                            encrypted_chunk_size,
                        "encrypted flight ends inside a payload");
                Bytes chunk;
                require(receive.decrypt(
                            ciphertext.subspan(ciphertext_offset,
                                               encrypted_chunk_size),
                            chunk),
                        "server payload authentication failed");
                require(chunk.size() == chunk_size,
                        "unexpected decrypted payload chunk size");
                append(plaintext_frames, chunk);
                ciphertext_offset += encrypted_chunk_size;
                payload_remaining -= chunk_size;
            }
        }
        return plaintext_frames;
    }
};

class InitiatorFixture {
public:
    explicit InitiatorFixture(
        uint32_t valid_from = 0,
        uint32_t not_valid_after = std::numeric_limits<uint32_t>::max())
        : context_(secp256k1_context_create(SECP256K1_CONTEXT_NONE)) {
        require(context_ != nullptr, "secp256k1_context_create failed");
        create_authority_public_key();
        create_certificate(valid_from, not_valid_after);
        require(secp256k1_ellswift_create(
                    context_.get(), act1_.data(), initiator_secret_.data(),
                    initiator_aux_.data()) == 1,
                "creating initiator EllSwift key failed");
    }

    [[nodiscard]] const Bytes64& act1() const noexcept {
        return act1_;
    }

    [[nodiscard]] const Bytes32& static_secret() const noexcept {
        return static_secret_;
    }

    [[nodiscard]] const Bytes32& authority_public() const noexcept {
        return authority_public_;
    }

    [[nodiscard]] const std::array<uint8_t, SV2_NOISE_CERTIFICATE_SIZE>&
    certificate() const noexcept {
        return certificate_;
    }

    [[nodiscard]] NoiseCredentials::LoadResult credentials(
        uint32_t now_unix) const {
        return NoiseCredentials::load(static_secret_, authority_public_,
                                      certificate_, now_unix);
    }

    [[nodiscard]] ClientTransport accept_act2(ByteView act2,
                                               uint32_t now_unix) const {
        require(act2.size() == SV2_NOISE_ACT2_SIZE,
                "unexpected Act2 size");
        Handshake handshake;
        Bytes64 responder_ephemeral{};
        Bytes64 responder_static{};
        Bytes32 shared_secret{};
        Bytes plaintext;

        handshake.mix_hash(act1_);
        handshake.mix_hash({});
        std::ranges::copy_n(act2.begin(), responder_ephemeral.size(),
                            responder_ephemeral.begin());
        handshake.mix_hash(responder_ephemeral);
        require(secp256k1_ellswift_xdh(
                    context_.get(), shared_secret.data(), act1_.data(),
                    responder_ephemeral.data(), initiator_secret_.data(), 0,
                    secp256k1_ellswift_xdh_hash_function_bip324,
                    nullptr) == 1,
                "ephemeral XDH failed");
        handshake.mix_key(shared_secret);

        require(handshake.decrypt_and_hash(
                    act2.subspan(64, 80), plaintext),
                "responder static key authentication failed");
        require(plaintext.size() == responder_static.size(),
                "unexpected responder static key size");
        std::ranges::copy(plaintext, responder_static.begin());
        require(secp256k1_ellswift_xdh(
                    context_.get(), shared_secret.data(), act1_.data(),
                    responder_static.data(), initiator_secret_.data(), 0,
                    secp256k1_ellswift_xdh_hash_function_bip324,
                    nullptr) == 1,
                "static XDH failed");
        handshake.mix_key(shared_secret);

        require(handshake.decrypt_and_hash(
                    act2.subspan(144, 90), plaintext),
                "certificate authentication failed");
        require(plaintext.size() == certificate_.size(),
                "unexpected certificate size");
        std::array<uint8_t, SV2_NOISE_CERTIFICATE_SIZE> certificate{};
        std::ranges::copy(plaintext, certificate.begin());
        require(verify_certificate(certificate, responder_static, now_unix),
                "responder certificate rejected");

        auto [first_key, second_key] =
            hkdf_two(handshake.chaining_key, {});
        return {{first_key, 0}, {second_key, 0}};
    }

private:
    struct Handshake {
        Bytes32 chaining_key{kProtocolHash};
        Bytes32 handshake_hash{sha256(kProtocolHash)};
        Cipher cipher;

        void mix_hash(ByteView data) {
            handshake_hash = sha256(handshake_hash, data);
        }

        void mix_key(ByteView input_key_material) {
            auto [new_chaining_key, cipher_key] =
                hkdf_two(chaining_key, input_key_material);
            chaining_key = new_chaining_key;
            cipher.key = cipher_key;
            cipher.nonce = 0;
        }

        [[nodiscard]] bool decrypt_and_hash(ByteView ciphertext,
                                            Bytes& plaintext) {
            if (!aead_decrypt(cipher.key, cipher.nonce, handshake_hash,
                              ciphertext, plaintext))
                return false;
            ++cipher.nonce;
            mix_hash(ciphertext);
            return true;
        }
    };

    void create_authority_public_key() {
        secp256k1_keypair authority_keypair;
        secp256k1_xonly_pubkey authority_xonly;

        require(secp256k1_keypair_create(
                    context_.get(), &authority_keypair,
                    authority_secret_.data()) == 1,
                "creating authority keypair failed");
        require(secp256k1_keypair_xonly_pub(
                    context_.get(), &authority_xonly, nullptr,
                    &authority_keypair) == 1,
                "deriving authority public key failed");
        require(secp256k1_xonly_pubkey_serialize(
                    context_.get(), authority_public_.data(),
                    &authority_xonly) == 1,
                "serializing authority public key failed");
    }

    void create_certificate(uint32_t valid_from, uint32_t not_valid_after) {
        secp256k1_keypair static_keypair;
        secp256k1_xonly_pubkey static_xonly;
        secp256k1_keypair authority_keypair;
        Bytes32 static_public{};
        std::array<uint8_t, 42> signed_fields{};

        store_u16_le(certificate_.data(), 0);
        store_u32_le(certificate_.data() + 2, valid_from);
        store_u32_le(certificate_.data() + 6, not_valid_after);
        require(secp256k1_keypair_create(
                    context_.get(), &static_keypair,
                    static_secret_.data()) == 1,
                "creating static keypair failed");
        require(secp256k1_keypair_xonly_pub(
                    context_.get(), &static_xonly, nullptr,
                    &static_keypair) == 1,
                "deriving static public key failed");
        require(secp256k1_xonly_pubkey_serialize(
                    context_.get(), static_public.data(), &static_xonly) == 1,
                "serializing static public key failed");
        std::ranges::copy_n(certificate_.begin(), 10,
                            signed_fields.begin());
        std::ranges::copy(static_public, signed_fields.begin() + 10);
        const Bytes32 digest = sha256(signed_fields);
        require(secp256k1_keypair_create(
                    context_.get(), &authority_keypair,
                    authority_secret_.data()) == 1,
                "creating authority signing key failed");
        require(secp256k1_schnorrsig_sign32(
                    context_.get(), certificate_.data() + 10, digest.data(),
                    &authority_keypair, signature_aux_.data()) == 1,
                "signing certificate failed");
    }

    [[nodiscard]] bool verify_certificate(
        const std::array<uint8_t, SV2_NOISE_CERTIFICATE_SIZE>& certificate,
        const Bytes64& static_ellswift,
        uint32_t now_unix) const {
        const uint32_t valid_from =
            static_cast<uint32_t>(certificate[2]) |
            static_cast<uint32_t>(certificate[3]) << 8 |
            static_cast<uint32_t>(certificate[4]) << 16 |
            static_cast<uint32_t>(certificate[5]) << 24;
        const uint32_t not_valid_after =
            static_cast<uint32_t>(certificate[6]) |
            static_cast<uint32_t>(certificate[7]) << 8 |
            static_cast<uint32_t>(certificate[8]) << 16 |
            static_cast<uint32_t>(certificate[9]) << 24;
        if (now_unix < valid_from || now_unix > not_valid_after)
            return false;

        secp256k1_pubkey static_public;
        secp256k1_xonly_pubkey static_xonly;
        secp256k1_xonly_pubkey authority_xonly;
        Bytes32 static_xonly_bytes{};
        std::array<uint8_t, 42> signed_fields{};

        if (secp256k1_ellswift_decode(
                context_.get(), &static_public,
                static_ellswift.data()) != 1)
            return false;
        if (secp256k1_xonly_pubkey_from_pubkey(
                context_.get(), &static_xonly, nullptr,
                &static_public) != 1)
            return false;
        if (secp256k1_xonly_pubkey_serialize(
                context_.get(), static_xonly_bytes.data(),
                &static_xonly) != 1)
            return false;
        if (secp256k1_xonly_pubkey_parse(
                context_.get(), &authority_xonly,
                authority_public_.data()) != 1)
            return false;
        std::ranges::copy_n(certificate.begin(), 10, signed_fields.begin());
        std::ranges::copy(static_xonly_bytes, signed_fields.begin() + 10);
        const Bytes32 digest = sha256(signed_fields);
        return secp256k1_schnorrsig_verify(
                   context_.get(), certificate.data() + 10, digest.data(),
                   digest.size(), &authority_xonly) == 1;
    }

    SecpPtr context_;
    Bytes32 authority_secret_{secret_key(1)};
    Bytes32 static_secret_{secret_key(2)};
    Bytes32 initiator_secret_{secret_key(3)};
    Bytes32 initiator_aux_{repeated_bytes(0x11)};
    Bytes32 signature_aux_{repeated_bytes(0x44)};
    Bytes32 authority_public_{};
    Bytes64 act1_{};
    std::array<uint8_t, SV2_NOISE_CERTIFICATE_SIZE> certificate_{};
};

} // namespace erikslund::sv2::test
