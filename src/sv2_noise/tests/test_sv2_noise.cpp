#include "sv2_noise.h"
#include "sv2_noise_internal.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/evp.h>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

namespace {

using Bytes32 = std::array<std::uint8_t, 32>;
using Bytes64 = std::array<std::uint8_t, 64>;
using Act2 = std::array<std::uint8_t, SV2_NOISE_ACT2_SIZE>;

constexpr std::uint32_t kValidFrom = 1'000;
constexpr std::uint32_t kNotValidAfter = 2'000;
constexpr std::uint32_t kValidNow = 1'500;
constexpr std::array<std::uint8_t, 32> kProtocolHash{
    0x2e, 0xb4, 0x78, 0x81, 0x20, 0x8e, 0x9e, 0xee,
    0x1f, 0x66, 0x9f, 0x67, 0xc6, 0x6e, 0xe7, 0x0e,
    0xa9, 0xea, 0x88, 0x09, 0x0d, 0x50, 0x3f, 0xe8,
    0x30, 0xdc, 0x4b, 0xc8, 0x3e, 0x29, 0xbf, 0x10,
};
constexpr std::string_view kAct1Vector =
    "b048ba0a0db599789859b67c58bff8bad86577c9575aace57ec29e46913293f3"
    "21e46b94a87ba170b8aa6422ae07cc1d50106168709de9e68ae8cfcbb24aedba";
constexpr std::string_view kAct2Vector =
    "ffb267f66db88e257722917bb75b8402f4d7cf0c09592a0dbb956428dcf75eee"
    "9cf568f984761ff15cb4b597aaf8b8a71975f0aef80cb37d7fd6f6c9344a3074"
    "e93f119af3cdceb57bde816c1ab114efd72536a2f9b6da15ba9345753c872dcac"
    "882979d6c984ca9058ec53449d83f6749f039685749baa55dc64a51d8c8966fd"
    "85d1c61b268cc06dafec8aca0abbdc8751330779f25205c2a455eb07eaafc63a"
    "8a690f1d7669fcccbe2d6f9f2f88347fdbf8e093c1377b2a6d2e4d17026948f"
    "bf5def6263f2043a434ccc9dc753f36dd08dfad400ba80b8daf829b06c6311b6"
    "b194e078b4607f7e1dea";
constexpr std::string_view kEncryptedHeaderVector =
    "8bf4d37091fb47516def0e9d39830f645c4c773c743d";

// Plaintext and ciphertext lengths around the chunk boundary and at the wire limit.
constexpr std::array<std::pair<std::size_t, std::size_t>, 7> kPayloadCiphertextSizeVectors{{
    {0, 0},
    {1, 17},
    {65'518, 65'534},
    {65'519, 65'535},
    {65'520, 65'552},
    {131'038, 131'070},
    {SV2_NOISE_MAX_FRAME_PAYLOAD_SIZE, 16'781'327},
}};

struct TransportCiphertextVector {
    std::size_t plaintext_length;
    std::size_t ciphertext_length;
    std::string_view head_hex;
    std::string_view tail_hex;
    std::string_view digest_hex;
};

// Ciphertext from a deterministic handshake. The digest pins large payloads without embedding
// unreadable 65 KiB literals.
constexpr std::array<TransportCiphertextVector, 4> kTransportCiphertextVectors{{
    {0,
     0,
     "",
     "",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
    {1,
     17,
     "9af66ecb129a540d4ece53e2ea38d87937",
     "9af66ecb129a540d4ece53e2ea38d87937",
     "07cdcb8ff41c50bc0b71761c10f05430f182d71601e29ca4fb02287e15ec50bd"},
    {65'519,
     65'535,
     "9ae0d4e98c5b5fb152979eb31b351f7aa9cb23650ec29fa4c1f7d6278530b3f2",
     "5dd997c6b7672bd47d6e870f2fc8e2116cdc401d6235916b6f617adb046b7116",
     "e00c7722a4fe1dffdd0c8c04d6eb210068ec75293da2226256c224c9fa4d99cc"},
    {65'520,
     65'552,
     "9ae0d4e98c5b5fb152979eb31b351f7aa9cb23650ec29fa4c1f7d6278530b3f2",
     "dc401d6235916b6f617adb046b7116eebe52424ce0193a5e5cac9732279b20fb",
     "19404a81edd135caf7f7af1d8e2e28354cbba1bc9759c441a237bdba914d5f5f"},
}};

// The 65,520-byte payload spills one plaintext byte into a second chunk, which the responder
// encrypts under send nonce 1. The complete 17-byte result is pinned below.
constexpr std::string_view kTransportSecondChunkVector =
    "eebe52424ce0193a5e5cac9732279b20fb";

struct CredentialsDeleter {
    void operator()(sv2_noise_credentials *credentials) const {
        sv2_noise_credentials_free(credentials);
    }
};

struct SessionDeleter {
    void operator()(sv2_noise_session *session) const {
        sv2_noise_session_free(session);
    }
};

struct SecpDeleter {
    void operator()(secp256k1_context *context) const {
        secp256k1_context_destroy(context);
    }
};

using CredentialsPtr = std::unique_ptr<sv2_noise_credentials, CredentialsDeleter>;
using SessionPtr = std::unique_ptr<sv2_noise_session, SessionDeleter>;
using SecpPtr = std::unique_ptr<secp256k1_context, SecpDeleter>;

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

void require_status(
    sv2_noise_status actual,
    sv2_noise_status expected,
    std::string_view operation) {
    if (actual == expected)
        return;
    throw std::runtime_error(
        std::string(operation) + ": expected " +
        sv2_noise_status_string(expected) + ", got " +
        sv2_noise_status_string(actual));
}

Bytes32 secret_key(std::uint8_t final_byte) {
    Bytes32 secret{};
    secret.back() = final_byte;
    return secret;
}

Bytes32 repeated_bytes(std::uint8_t value) {
    Bytes32 bytes{};
    bytes.fill(value);
    return bytes;
}

void store_little_endian_u16(std::uint8_t *output, std::uint16_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8u);
}

void store_little_endian_u32(std::uint8_t *output, std::uint32_t value) {
    output[0] = static_cast<std::uint8_t>(value);
    output[1] = static_cast<std::uint8_t>(value >> 8u);
    output[2] = static_cast<std::uint8_t>(value >> 16u);
    output[3] = static_cast<std::uint8_t>(value >> 24u);
}

Bytes32 sha256(std::span<const std::uint8_t> first, std::span<const std::uint8_t> second = {}) {
    Bytes32 output{};
    unsigned int output_length = 0;
    auto context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(
        EVP_MD_CTX_new(),
        EVP_MD_CTX_free);

    require(context != nullptr, "EVP_MD_CTX_new");
    require(EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1, "DigestInit");
    if (!first.empty())
        require(EVP_DigestUpdate(context.get(), first.data(), first.size()) == 1, "DigestUpdate");
    if (!second.empty())
        require(EVP_DigestUpdate(context.get(), second.data(), second.size()) == 1, "DigestUpdate");
    require(EVP_DigestFinal_ex(context.get(), output.data(), &output_length) == 1, "DigestFinal");
    require(output_length == output.size(), "SHA-256 output length");
    return output;
}

Bytes32 hmac_sha256(
    const Bytes32& key,
    std::span<const std::uint8_t> data) {
    std::array<std::uint8_t, 64> inner_pad{};
    std::array<std::uint8_t, 64> outer_pad{};

    inner_pad.fill(0x36);
    outer_pad.fill(0x5c);
    for (std::size_t index = 0; index < key.size(); ++index) {
        inner_pad[index] ^= key[index];
        outer_pad[index] ^= key[index];
    }
    const auto inner_hash = sha256(inner_pad, data);
    return sha256(outer_pad, inner_hash);
}

std::pair<Bytes32, Bytes32> derive_two_hkdf_outputs(
    const Bytes32& chaining_key,
    std::span<const std::uint8_t> input_key_material) {
    const auto temporary_key = hmac_sha256(chaining_key, input_key_material);
    constexpr std::array<std::uint8_t, 1> first_counter{0x01};
    const auto first = hmac_sha256(temporary_key, first_counter);
    std::array<std::uint8_t, 33> second_input{};

    std::ranges::copy(first, second_input.begin());
    second_input.back() = 0x02;
    return {first, hmac_sha256(temporary_key, second_input)};
}

std::array<std::uint8_t, 12> noise_nonce(std::uint64_t nonce) {
    std::array<std::uint8_t, 12> bytes{};

    for (std::size_t index = 0; index < sizeof(nonce); ++index)
        bytes[4 + index] = static_cast<std::uint8_t>(nonce >> (index * 8u));
    return bytes;
}

std::vector<std::uint8_t> aead_encrypt(
    const Bytes32& key,
    std::uint64_t nonce_value,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> plaintext) {
    const auto nonce = noise_nonce(nonce_value);
    std::vector<std::uint8_t> ciphertext(plaintext.size() + SV2_NOISE_TAG_SIZE);
    auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free);
    int written = 0;
    int total_written = 0;

    require(context != nullptr, "EVP_CIPHER_CTX_new");
    require(
        EVP_EncryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1,
        "EncryptInit");
    require(
        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr) == 1,
        "set nonce length");
    require(
        EVP_EncryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) == 1,
        "set encrypt key");
    if (!associated_data.empty()) {
        require(
            EVP_EncryptUpdate(
                context.get(),
                nullptr,
                &written,
                associated_data.data(),
                static_cast<int>(associated_data.size())) == 1,
            "encrypt AD");
    }
    if (!plaintext.empty()) {
        require(
            EVP_EncryptUpdate(
                context.get(),
                ciphertext.data(),
                &written,
                plaintext.data(),
                static_cast<int>(plaintext.size())) == 1,
            "encrypt plaintext");
        total_written = written;
    }
    require(
        EVP_EncryptFinal_ex(context.get(), ciphertext.data() + total_written, &written) == 1,
        "EncryptFinal");
    total_written += written;
    require(
        static_cast<std::size_t>(total_written) == plaintext.size(),
        "encrypted plaintext length");
    require(
        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_AEAD_GET_TAG,
            SV2_NOISE_TAG_SIZE,
            ciphertext.data() + plaintext.size()) == 1,
        "get tag");
    return ciphertext;
}

bool aead_decrypt(
    const Bytes32& key,
    std::uint64_t nonce_value,
    std::span<const std::uint8_t> associated_data,
    std::span<const std::uint8_t> ciphertext,
    std::vector<std::uint8_t>& plaintext) {
    if (ciphertext.size() < SV2_NOISE_TAG_SIZE)
        return false;

    const auto nonce = noise_nonce(nonce_value);
    const auto plaintext_length = ciphertext.size() - SV2_NOISE_TAG_SIZE;
    auto context = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>(
        EVP_CIPHER_CTX_new(),
        EVP_CIPHER_CTX_free);
    int written = 0;
    int total_written = 0;

    plaintext.assign(plaintext_length, 0);
    require(context != nullptr, "EVP_CIPHER_CTX_new");
    require(
        EVP_DecryptInit_ex(context.get(), EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1,
        "DecryptInit");
    require(
        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr) == 1,
        "set nonce length");
    require(
        EVP_DecryptInit_ex(context.get(), nullptr, nullptr, key.data(), nonce.data()) == 1,
        "set decrypt key");
    if (!associated_data.empty()) {
        require(
            EVP_DecryptUpdate(
                context.get(),
                nullptr,
                &written,
                associated_data.data(),
                static_cast<int>(associated_data.size())) == 1,
            "decrypt AD");
    }
    if (plaintext_length != 0) {
        require(
            EVP_DecryptUpdate(
                context.get(),
                plaintext.data(),
                &written,
                ciphertext.data(),
                static_cast<int>(plaintext_length)) == 1,
            "decrypt ciphertext");
        total_written = written;
    }
    require(
        EVP_CIPHER_CTX_ctrl(
            context.get(),
            EVP_CTRL_AEAD_SET_TAG,
            SV2_NOISE_TAG_SIZE,
            const_cast<std::uint8_t *>(ciphertext.data() + plaintext_length)) == 1,
        "set tag");
    if (EVP_DecryptFinal_ex(context.get(), plaintext.data() + total_written, &written) != 1) {
        std::ranges::fill(plaintext, 0);
        return false;
    }
    total_written += written;
    return static_cast<std::size_t>(total_written) == plaintext_length;
}

struct OracleCipher {
    Bytes32 key{};
    std::uint64_t nonce = 0;

    std::vector<std::uint8_t> encrypt(std::span<const std::uint8_t> plaintext) {
        require(nonce != std::numeric_limits<std::uint64_t>::max(), "oracle nonce exhausted");
        auto ciphertext = aead_encrypt(key, nonce, {}, plaintext);
        ++nonce;
        return ciphertext;
    }

    bool decrypt(
        std::span<const std::uint8_t> ciphertext,
        std::vector<std::uint8_t>& plaintext) {
        require(nonce != std::numeric_limits<std::uint64_t>::max(), "oracle nonce exhausted");
        if (!aead_decrypt(key, nonce, {}, ciphertext, plaintext))
            return false;
        ++nonce;
        return true;
    }
};

struct OracleTransport {
    OracleCipher send;
    OracleCipher receive;
};

struct HandshakeOracle {
    Bytes32 chaining_key{kProtocolHash};
    Bytes32 handshake_hash{sha256(kProtocolHash)};
    OracleCipher cipher;

    void mix_hash(std::span<const std::uint8_t> data) {
        handshake_hash = sha256(handshake_hash, data);
    }

    void mix_key(std::span<const std::uint8_t> input_key_material) {
        auto [new_chaining_key, cipher_key] =
            derive_two_hkdf_outputs(chaining_key, input_key_material);
        chaining_key = new_chaining_key;
        cipher.key = cipher_key;
        cipher.nonce = 0;
    }

    bool decrypt_and_hash(
        std::span<const std::uint8_t> ciphertext,
        std::vector<std::uint8_t>& plaintext) {
        const auto associated_data = handshake_hash;
        if (!aead_decrypt(cipher.key, cipher.nonce, associated_data, ciphertext, plaintext))
            return false;
        ++cipher.nonce;
        mix_hash(ciphertext);
        return true;
    }
};

struct CredentialFixture {
    SecpPtr context{secp256k1_context_create(SECP256K1_CONTEXT_NONE)};
    Bytes32 authority_secret{secret_key(1)};
    Bytes32 static_secret{secret_key(2)};
    Bytes32 initiator_secret{secret_key(3)};
    Bytes32 responder_ephemeral_secret{secret_key(4)};
    Bytes32 initiator_randomness{repeated_bytes(0x11)};
    Bytes32 responder_ephemeral_randomness{repeated_bytes(0x22)};
    Bytes32 responder_static_randomness{repeated_bytes(0x33)};
    Bytes32 signature_randomness{repeated_bytes(0x44)};
    Bytes32 authority_public{};
    Bytes64 act1{};
    std::array<std::uint8_t, SV2_NOISE_CERTIFICATE_SIZE> certificate{};

    CredentialFixture() {
        require(context != nullptr, "secp256k1_context_create");
        create_authority_public_key();
        create_certificate();
        require(
            secp256k1_ellswift_create(
                context.get(),
                act1.data(),
                initiator_secret.data(),
                initiator_randomness.data()) == 1,
            "create initiator EllSwift key");
    }

    CredentialsPtr load(
        std::uint32_t current_time,
        const Bytes32 *static_override = nullptr,
        const Bytes32 *authority_override = nullptr,
        const std::array<std::uint8_t, SV2_NOISE_CERTIFICATE_SIZE> *certificate_override =
            nullptr,
        sv2_noise_status expected = SV2_NOISE_OK) const {
        sv2_noise_credentials *raw_credentials = nullptr;
        const auto& selected_static =
            static_override == nullptr ? static_secret : *static_override;
        const auto& selected_authority =
            authority_override == nullptr ? authority_public : *authority_override;
        const auto& selected_certificate =
            certificate_override == nullptr ? certificate : *certificate_override;
        const auto status = sv2_noise_credentials_load(
            selected_static.data(),
            selected_static.size(),
            selected_authority.data(),
            selected_authority.size(),
            selected_certificate.data(),
            selected_certificate.size(),
            current_time,
            &raw_credentials);

        require_status(status, expected, "load credentials");
        if (expected == SV2_NOISE_OK)
            require(raw_credentials != nullptr, "credential handle missing");
        else
            require(raw_credentials == nullptr, "failed credential load returned a handle");
        return CredentialsPtr(raw_credentials);
    }

private:
    void create_authority_public_key() {
        secp256k1_keypair authority_keypair;
        secp256k1_xonly_pubkey authority_xonly;

        require(
            secp256k1_keypair_create(
                context.get(),
                &authority_keypair,
                authority_secret.data()) == 1,
            "create authority keypair");
        require(
            secp256k1_keypair_xonly_pub(
                context.get(),
                &authority_xonly,
                nullptr,
                &authority_keypair) == 1,
            "derive authority x-only key");
        require(
            secp256k1_xonly_pubkey_serialize(
                context.get(),
                authority_public.data(),
                &authority_xonly) == 1,
            "serialize authority x-only key");
    }

    void create_certificate() {
        secp256k1_keypair static_keypair;
        secp256k1_xonly_pubkey static_xonly;
        secp256k1_keypair authority_keypair;
        Bytes32 static_public{};
        std::array<std::uint8_t, 42> signed_fields{};

        store_little_endian_u16(certificate.data(), 0);
        store_little_endian_u32(certificate.data() + 2, kValidFrom);
        store_little_endian_u32(certificate.data() + 6, kNotValidAfter);
        require(
            secp256k1_keypair_create(
                context.get(),
                &static_keypair,
                static_secret.data()) == 1,
            "create static keypair");
        require(
            secp256k1_keypair_xonly_pub(
                context.get(),
                &static_xonly,
                nullptr,
                &static_keypair) == 1,
            "derive static x-only key");
        require(
            secp256k1_xonly_pubkey_serialize(
                context.get(),
                static_public.data(),
                &static_xonly) == 1,
            "serialize static x-only key");
        std::ranges::copy_n(certificate.begin(), 10, signed_fields.begin());
        std::ranges::copy(static_public, signed_fields.begin() + 10);
        const auto digest = sha256(signed_fields);
        require(
            secp256k1_keypair_create(
                context.get(),
                &authority_keypair,
                authority_secret.data()) == 1,
            "create authority signing keypair");
        require(
            secp256k1_schnorrsig_sign32(
                context.get(),
                certificate.data() + 10,
                digest.data(),
                &authority_keypair,
                signature_randomness.data()) == 1,
            "sign certificate");
    }
};

bool verify_certificate(
    secp256k1_context *context,
    const std::array<std::uint8_t, SV2_NOISE_CERTIFICATE_SIZE>& certificate,
    const Bytes64& static_ellswift,
    const Bytes32& authority_public,
    std::uint32_t current_time) {
    const auto valid_from =
        static_cast<std::uint32_t>(certificate[2]) |
        (static_cast<std::uint32_t>(certificate[3]) << 8u) |
        (static_cast<std::uint32_t>(certificate[4]) << 16u) |
        (static_cast<std::uint32_t>(certificate[5]) << 24u);
    const auto not_valid_after =
        static_cast<std::uint32_t>(certificate[6]) |
        (static_cast<std::uint32_t>(certificate[7]) << 8u) |
        (static_cast<std::uint32_t>(certificate[8]) << 16u) |
        (static_cast<std::uint32_t>(certificate[9]) << 24u);
    secp256k1_pubkey static_public;
    secp256k1_xonly_pubkey static_xonly;
    secp256k1_xonly_pubkey authority_xonly;
    Bytes32 static_xonly_bytes{};
    std::array<std::uint8_t, 42> signed_fields{};

    if (current_time < valid_from || current_time > not_valid_after)
        return false;
    if (secp256k1_ellswift_decode(context, &static_public, static_ellswift.data()) != 1)
        return false;
    if (secp256k1_xonly_pubkey_from_pubkey(
            context,
            &static_xonly,
            nullptr,
            &static_public) != 1)
        return false;
    if (secp256k1_xonly_pubkey_serialize(
            context,
            static_xonly_bytes.data(),
            &static_xonly) != 1)
        return false;
    if (secp256k1_xonly_pubkey_parse(
            context,
            &authority_xonly,
            authority_public.data()) != 1)
        return false;
    std::ranges::copy_n(certificate.begin(), 10, signed_fields.begin());
    std::ranges::copy(static_xonly_bytes, signed_fields.begin() + 10);
    const auto digest = sha256(signed_fields);
    return secp256k1_schnorrsig_verify(
               context,
               certificate.data() + 10,
               digest.data(),
               digest.size(),
               &authority_xonly) == 1;
}

bool process_act2(
    const CredentialFixture& fixture,
    const Act2& act2,
    std::uint32_t current_time,
    OracleTransport& transport_out) {
    HandshakeOracle handshake;
    Bytes64 responder_ephemeral{};
    Bytes64 responder_static{};
    Bytes32 shared_secret{};
    std::vector<std::uint8_t> plaintext;
    std::array<std::uint8_t, SV2_NOISE_CERTIFICATE_SIZE> certificate{};

    handshake.mix_hash(fixture.act1);
    handshake.mix_hash({});
    std::ranges::copy_n(act2.begin(), responder_ephemeral.size(), responder_ephemeral.begin());
    handshake.mix_hash(responder_ephemeral);
    if (secp256k1_ellswift_xdh(
            fixture.context.get(),
            shared_secret.data(),
            fixture.act1.data(),
            responder_ephemeral.data(),
            fixture.initiator_secret.data(),
            0,
            secp256k1_ellswift_xdh_hash_function_bip324,
            nullptr) != 1)
        return false;
    handshake.mix_key(shared_secret);

    const auto encrypted_static = std::span(act2).subspan(64, 80);
    if (!handshake.decrypt_and_hash(encrypted_static, plaintext))
        return false;
    require(plaintext.size() == responder_static.size(), "decrypted static key length");
    std::ranges::copy(plaintext, responder_static.begin());
    if (secp256k1_ellswift_xdh(
            fixture.context.get(),
            shared_secret.data(),
            fixture.act1.data(),
            responder_static.data(),
            fixture.initiator_secret.data(),
            0,
            secp256k1_ellswift_xdh_hash_function_bip324,
            nullptr) != 1)
        return false;
    handshake.mix_key(shared_secret);

    const auto encrypted_certificate = std::span(act2).subspan(144, 90);
    if (!handshake.decrypt_and_hash(encrypted_certificate, plaintext))
        return false;
    require(plaintext.size() == certificate.size(), "decrypted certificate length");
    std::ranges::copy(plaintext, certificate.begin());
    if (!verify_certificate(
            fixture.context.get(),
            certificate,
            responder_static,
            fixture.authority_public,
            current_time))
        return false;

    auto [first_key, second_key] =
        derive_two_hkdf_outputs(handshake.chaining_key, {});
    transport_out.send.key = first_key;
    transport_out.receive.key = second_key;
    transport_out.send.nonce = 0;
    transport_out.receive.nonce = 0;
    return true;
}

struct NoiseConnection {
    SessionPtr server;
    OracleTransport client;
    Act2 act2{};
};

NoiseConnection connect(
    const CredentialFixture& fixture,
    const sv2_noise_credentials *credentials,
    std::uint32_t current_time = kValidNow) {
    sv2_noise_session *raw_session = nullptr;
    NoiseConnection connection;

    require_status(
        sv2_noise_test_responder_handshake(
            credentials,
            current_time,
            fixture.act1.data(),
            fixture.responder_ephemeral_secret.data(),
            fixture.responder_ephemeral_randomness.data(),
            fixture.responder_static_randomness.data(),
            connection.act2.data(),
            &raw_session),
        SV2_NOISE_OK,
        "deterministic responder handshake");
    connection.server.reset(raw_session);
    require(connection.server != nullptr, "session missing");
    require(
        process_act2(
            fixture,
            connection.act2,
            current_time,
            connection.client),
        "initiator rejected Act2");
    return connection;
}

std::vector<std::uint8_t> make_payload(std::size_t length) {
    std::vector<std::uint8_t> payload(length);

    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] = static_cast<std::uint8_t>((index * 131u + 17u) & 0xffu);
    return payload;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result;

    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        result.push_back(digits[byte >> 4u]);
        result.push_back(digits[byte & 0x0fu]);
    }
    return result;
}

std::vector<std::uint8_t> oracle_encrypt_payload(
    OracleCipher& cipher,
    std::span<const std::uint8_t> plaintext) {
    std::vector<std::uint8_t> ciphertext;
    std::size_t offset = 0;

    while (offset < plaintext.size()) {
        const auto chunk_length =
            std::min<std::size_t>(
                SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE,
                plaintext.size() - offset);
        auto chunk = cipher.encrypt(plaintext.subspan(offset, chunk_length));
        ciphertext.insert(ciphertext.end(), chunk.begin(), chunk.end());
        offset += chunk_length;
    }
    return ciphertext;
}

bool oracle_decrypt_payload(
    OracleCipher& cipher,
    std::span<const std::uint8_t> ciphertext,
    std::size_t plaintext_length,
    std::vector<std::uint8_t>& plaintext) {
    plaintext.clear();
    std::size_t plaintext_offset = 0;
    std::size_t ciphertext_offset = 0;

    while (plaintext_offset < plaintext_length) {
        const auto chunk_length =
            std::min<std::size_t>(
                SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE,
                plaintext_length - plaintext_offset);
        const auto encrypted_chunk_length = chunk_length + SV2_NOISE_TAG_SIZE;
        std::vector<std::uint8_t> chunk;

        if (!cipher.decrypt(
                ciphertext.subspan(ciphertext_offset, encrypted_chunk_length),
                chunk))
            return false;
        plaintext.insert(plaintext.end(), chunk.begin(), chunk.end());
        plaintext_offset += chunk_length;
        ciphertext_offset += encrypted_chunk_length;
    }
    return ciphertext_offset == ciphertext.size();
}

void test_credentials_are_strictly_verified() {
    CredentialFixture fixture;

    require(fixture.load(kValidFrom) != nullptr, "valid_from boundary rejected");
    require(fixture.load(kNotValidAfter) != nullptr, "not_valid_after boundary rejected");
    fixture.load(
        kValidFrom - 1,
        nullptr,
        nullptr,
        nullptr,
        SV2_NOISE_ERROR_CERTIFICATE_NOT_YET_VALID);
    fixture.load(
        kNotValidAfter + 1,
        nullptr,
        nullptr,
        nullptr,
        SV2_NOISE_ERROR_CERTIFICATE_EXPIRED);

    auto unsupported_version = fixture.certificate;
    unsupported_version[0] = 1;
    fixture.load(
        kValidNow,
        nullptr,
        nullptr,
        &unsupported_version,
        SV2_NOISE_ERROR_UNSUPPORTED_CERTIFICATE_VERSION);

    auto inverted_times = fixture.certificate;
    store_little_endian_u32(inverted_times.data() + 2, kNotValidAfter);
    store_little_endian_u32(inverted_times.data() + 6, kValidFrom);
    fixture.load(
        kValidNow,
        nullptr,
        nullptr,
        &inverted_times,
        SV2_NOISE_ERROR_INVALID_CERTIFICATE);

    auto bad_signature = fixture.certificate;
    bad_signature.back() ^= 0x01;
    fixture.load(
        kValidNow,
        nullptr,
        nullptr,
        &bad_signature,
        SV2_NOISE_ERROR_INVALID_CERTIFICATE);

    const auto wrong_static = secret_key(9);
    fixture.load(
        kValidNow,
        &wrong_static,
        nullptr,
        nullptr,
        SV2_NOISE_ERROR_INVALID_CERTIFICATE);

    const Bytes32 invalid_static{};
    fixture.load(
        kValidNow,
        &invalid_static,
        nullptr,
        nullptr,
        SV2_NOISE_ERROR_INVALID_STATIC_SECRET);

    const Bytes32 invalid_authority{};
    fixture.load(
        kValidNow,
        nullptr,
        &invalid_authority,
        nullptr,
        SV2_NOISE_ERROR_INVALID_AUTHORITY_KEY);
}

void test_handshake_local_oracle_and_authentication() {
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);
    auto connection = connect(fixture, credentials.get());

    require(connection.act2.size() == 234, "Act2 is not 234 bytes");
    require(to_hex(fixture.act1) == kAct1Vector, "Act1 vector drift");
    require(to_hex(connection.act2) == kAct2Vector, "Act2 vector drift");
    constexpr std::array<std::uint8_t, 6> header{0x00, 0x80, 0x10, 0x03, 0x00, 0x00};
    std::array<std::uint8_t, SV2_NOISE_ENCRYPTED_HEADER_SIZE> encrypted_header{};
    std::size_t encrypted_header_length = 0;
    require_status(
        sv2_noise_encrypt_header(
            connection.server.get(),
            header.data(),
            header.size(),
            encrypted_header.data(),
            encrypted_header.size(),
            &encrypted_header_length),
        SV2_NOISE_OK,
        "encrypt vector header");
    require(
        to_hex(encrypted_header) == kEncryptedHeaderVector,
        "encrypted header vector drift");
    auto tampered_act2 = connection.act2;
    tampered_act2[70] ^= 0x80;
    OracleTransport rejected_transport;
    require(
        !process_act2(fixture, tampered_act2, kValidNow, rejected_transport),
        "tampered Act2 authenticated");

    sv2_noise_session *random_session = nullptr;
    Act2 random_act2{};
    std::size_t random_act2_length = 0;
    require_status(
        sv2_noise_responder_handshake(
            credentials.get(),
            kValidNow,
            fixture.act1.data(),
            fixture.act1.size(),
            random_act2.data(),
            random_act2.size(),
            &random_act2_length,
            &random_session),
        SV2_NOISE_OK,
        "production responder handshake");
    SessionPtr owned_random_session(random_session);
    require(
        random_act2_length == SV2_NOISE_ACT2_SIZE,
        "production handshake returned wrong Act2 length");
    OracleTransport random_transport;
    require(
        process_act2(fixture, random_act2, kValidNow, random_transport),
        "local initiator rejected production Act2");

    sv2_noise_session *expired_session = nullptr;
    Act2 expired_act2{};
    require_status(
        sv2_noise_test_responder_handshake(
            credentials.get(),
            kNotValidAfter + 1,
            fixture.act1.data(),
            fixture.responder_ephemeral_secret.data(),
            fixture.responder_ephemeral_randomness.data(),
            fixture.responder_static_randomness.data(),
            expired_act2.data(),
            &expired_session),
        SV2_NOISE_ERROR_CERTIFICATE_EXPIRED,
        "expired handshake");
    require(expired_session == nullptr, "expired handshake returned session");

    std::array<std::uint8_t, SV2_NOISE_ACT2_SIZE - 1> short_act2{};
    std::size_t act2_length = 0;
    require_status(
        sv2_noise_responder_handshake(
            credentials.get(),
            kValidNow,
            fixture.act1.data(),
            fixture.act1.size(),
            short_act2.data(),
            short_act2.size(),
            &act2_length,
            &expired_session),
        SV2_NOISE_ERROR_BUFFER_TOO_SMALL,
        "short Act2 buffer");
    require(act2_length == SV2_NOISE_ACT2_SIZE, "required Act2 length not reported");
    require(expired_session == nullptr, "short buffer returned session");
}

void test_payload_size_boundaries() {
    for (const auto& [plaintext_length, expected_ciphertext_length] :
         kPayloadCiphertextSizeVectors) {
        std::size_t ciphertext_length = 0;
        require_status(
            sv2_noise_payload_ciphertext_size(
                plaintext_length,
                &ciphertext_length),
            SV2_NOISE_OK,
            "payload ciphertext size");
        require(
            ciphertext_length == expected_ciphertext_length,
            "wrong payload ciphertext size");
    }

    std::size_t ignored = 0;
    require_status(
        sv2_noise_payload_ciphertext_size(
            static_cast<std::size_t>(SV2_NOISE_MAX_FRAME_PAYLOAD_SIZE) + 1,
            &ignored),
        SV2_NOISE_ERROR_INVALID_ARGUMENT,
        "oversize payload");
}

void test_zero_payload_matches_current_sri_framing() {
    // SRI c1a7991 skips payload encryption and its nonce for empty payloads.
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);
    auto connection = connect(fixture, credentials.get());
    const std::array<std::uint8_t, 6> first_header{0x00, 0x80, 0x10, 0, 0, 0};
    const std::array<std::uint8_t, 6> second_header{0x00, 0x00, 0x11, 0, 0, 0};
    std::array<std::uint8_t, SV2_NOISE_ENCRYPTED_HEADER_SIZE> encrypted_header{};
    std::size_t output_length = 99;

    require_status(
        sv2_noise_encrypt_header(
            connection.server.get(),
            first_header.data(),
            first_header.size(),
            encrypted_header.data(),
            encrypted_header.size(),
            &output_length),
        SV2_NOISE_OK,
        "encrypt first header");
    std::vector<std::uint8_t> decrypted_header;
    require(
        connection.client.receive.decrypt(encrypted_header, decrypted_header),
        "client could not decrypt first header");
    require(
        std::ranges::equal(decrypted_header, first_header),
        "first header mismatch");

    output_length = 99;
    require_status(
        sv2_noise_encrypt_payload(
            connection.server.get(),
            nullptr,
            0,
            nullptr,
            0,
            &output_length),
        SV2_NOISE_OK,
        "encrypt empty payload");
    require(output_length == 0, "empty payload emitted a tag");

    require_status(
        sv2_noise_encrypt_header(
            connection.server.get(),
            second_header.data(),
            second_header.size(),
            encrypted_header.data(),
            encrypted_header.size(),
            &output_length),
        SV2_NOISE_OK,
        "encrypt second header");
    require(
        connection.client.receive.decrypt(encrypted_header, decrypted_header),
        "empty payload consumed a send nonce");
    require(
        std::ranges::equal(decrypted_header, second_header),
        "second header mismatch");

    auto inbound_first = connection.client.send.encrypt(first_header);
    std::array<std::uint8_t, 6> server_header{};
    require_status(
        sv2_noise_decrypt_header(
            connection.server.get(),
            inbound_first.data(),
            inbound_first.size(),
            server_header.data(),
            server_header.size(),
            &output_length),
        SV2_NOISE_OK,
        "decrypt first inbound header");

    output_length = 99;
    require_status(
        sv2_noise_decrypt_payload(
            connection.server.get(),
            nullptr,
            0,
            0,
            nullptr,
            0,
            &output_length),
        SV2_NOISE_OK,
        "decrypt empty payload");
    require(output_length == 0, "empty decrypt returned plaintext");

    auto inbound_second = connection.client.send.encrypt(second_header);
    require_status(
        sv2_noise_decrypt_header(
            connection.server.get(),
            inbound_second.data(),
            inbound_second.size(),
            server_header.data(),
            server_header.size(),
            &output_length),
        SV2_NOISE_OK,
        "decrypt second inbound header");
    require(
        std::ranges::equal(server_header, second_header),
        "empty payload consumed a receive nonce");
}

std::vector<std::uint8_t> encrypt_fixture_payload(
    const CredentialFixture& fixture,
    const sv2_noise_credentials *credentials,
    std::size_t plaintext_length) {
    auto connection = connect(fixture, credentials);
    const auto payload = make_payload(plaintext_length);
    std::size_t ciphertext_length = 0;

    require_status(
        sv2_noise_payload_ciphertext_size(payload.size(), &ciphertext_length),
        SV2_NOISE_OK,
        "transport vector ciphertext size");
    std::vector<std::uint8_t> ciphertext(ciphertext_length);
    require_status(
        sv2_noise_encrypt_payload(
            connection.server.get(),
            payload.data(),
            payload.size(),
            ciphertext.data(),
            ciphertext.size(),
            &ciphertext_length),
        SV2_NOISE_OK,
        "encrypt transport vector");
    require(
        ciphertext_length == ciphertext.size(),
        "transport vector reported the wrong ciphertext length");
    return ciphertext;
}

void test_transport_ciphertext_vectors() {
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);

    for (const auto& vector : kTransportCiphertextVectors) {
        const auto ciphertext =
            encrypt_fixture_payload(fixture, credentials.get(), vector.plaintext_length);
        const auto edge_length = std::min<std::size_t>(32, ciphertext.size());

        require(
            ciphertext.size() == vector.ciphertext_length,
            "transport ciphertext length drift");
        require(
            to_hex(std::span(ciphertext).first(edge_length)) == vector.head_hex,
            "transport ciphertext head drift");
        require(
            to_hex(std::span(ciphertext).last(edge_length)) == vector.tail_hex,
            "transport ciphertext tail drift");
        require(
            to_hex(sha256(ciphertext)) == vector.digest_hex,
            "transport ciphertext digest drift");
    }

    // The two-chunk payload is the one-chunk payload plus one byte, so its first chunk must be
    // byte-identical and the remainder is exactly the nonce-1 chunk.
    const auto one_chunk = encrypt_fixture_payload(
        fixture,
        credentials.get(),
        SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE);
    const auto two_chunks = encrypt_fixture_payload(
        fixture,
        credentials.get(),
        SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE + 1u);

    require(
        std::ranges::equal(std::span(two_chunks).first(one_chunk.size()), one_chunk),
        "two-chunk payload changed its first chunk");
    require(
        to_hex(std::span(two_chunks).subspan(one_chunk.size())) ==
            kTransportSecondChunkVector,
        "second chunk vector drift");
    require(
        two_chunks.size() - one_chunk.size() == 1u + SV2_NOISE_TAG_SIZE,
        "second chunk is not one byte plus a tag");
}

void test_payload_chunk_boundaries_round_trip() {
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);
    constexpr std::array<std::size_t, 5> lengths{1, 65'518, 65'519, 65'520, 131'038};

    for (const auto length : lengths) {
        const auto payload = make_payload(length);

        auto outbound_pair = connect(fixture, credentials.get());
        std::size_t encrypted_length = 0;
        require_status(
            sv2_noise_payload_ciphertext_size(length, &encrypted_length),
            SV2_NOISE_OK,
            "outbound encrypted length");
        std::vector<std::uint8_t> encrypted(encrypted_length);
        require_status(
            sv2_noise_encrypt_payload(
                outbound_pair.server.get(),
                payload.data(),
                payload.size(),
                encrypted.data(),
                encrypted.size(),
                &encrypted_length),
            SV2_NOISE_OK,
            "encrypt chunked payload");
        std::vector<std::uint8_t> decrypted;
        require(
            oracle_decrypt_payload(
                outbound_pair.client.receive,
                encrypted,
                length,
                decrypted),
            "initiator could not decrypt chunked payload");
        require(decrypted == payload, "outbound payload mismatch");

        auto inbound_pair = connect(fixture, credentials.get());
        auto inbound = oracle_encrypt_payload(inbound_pair.client.send, payload);
        std::vector<std::uint8_t> server_plaintext(length);
        std::size_t plaintext_length = 0;
        require_status(
            sv2_noise_decrypt_payload(
                inbound_pair.server.get(),
                inbound.data(),
                inbound.size(),
                length,
                server_plaintext.data(),
                server_plaintext.size(),
                &plaintext_length),
            SV2_NOISE_OK,
            "decrypt chunked payload");
        require(plaintext_length == length, "wrong decrypted length");
        require(server_plaintext == payload, "inbound payload mismatch");
    }
}

void test_late_chunk_tamper_cleanses_and_terminates() {
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);

    auto header_pair = connect(fixture, credentials.get());
    const std::array<std::uint8_t, 6> header{0x00, 0x80, 0x10, 0x01, 0, 0};
    auto tampered_header = header_pair.client.send.encrypt(header);
    tampered_header.back() ^= 0x01;
    std::array<std::uint8_t, 6> header_plaintext{};
    header_plaintext.fill(0xa5);
    std::size_t header_plaintext_length = 0;
    require_status(
        sv2_noise_decrypt_header(
            header_pair.server.get(),
            tampered_header.data(),
            tampered_header.size(),
            header_plaintext.data(),
            header_plaintext.size(),
            &header_plaintext_length),
        SV2_NOISE_ERROR_AUTHENTICATION_FAILURE,
        "tampered header");
    require(header_plaintext_length == 0, "tampered header returned plaintext length");
    require(
        std::ranges::all_of(
            header_plaintext,
            [](std::uint8_t byte) { return byte == 0; }),
        "unauthenticated header plaintext was not cleansed");
    require(
        sv2_noise_session_is_terminal(header_pair.server.get()) == 1,
        "header authentication failure did not terminate");

    auto connection = connect(fixture, credentials.get());
    const auto payload = make_payload(65'520);
    auto ciphertext =
        oracle_encrypt_payload(connection.client.send, payload);
    ciphertext.back() ^= 0x01;
    std::vector<std::uint8_t> plaintext(payload.size(), 0xa5);
    std::size_t plaintext_length = 0;

    require_status(
        sv2_noise_decrypt_payload(
            connection.server.get(),
            ciphertext.data(),
            ciphertext.size(),
            payload.size(),
            plaintext.data(),
            plaintext.size(),
            &plaintext_length),
        SV2_NOISE_ERROR_AUTHENTICATION_FAILURE,
        "tampered second chunk");
    require(plaintext_length == 0, "tampered payload returned plaintext length");
    require(
        std::ranges::all_of(plaintext, [](std::uint8_t byte) { return byte == 0; }),
        "unauthenticated plaintext was not cleansed");
    require(
        sv2_noise_session_is_terminal(connection.server.get()) == 1,
        "session did not terminate");

    require_status(
        sv2_noise_decrypt_payload(
            connection.server.get(),
            ciphertext.data(),
            ciphertext.size(),
            payload.size(),
            plaintext.data(),
            plaintext.size(),
            &plaintext_length),
        SV2_NOISE_ERROR_SESSION_TERMINAL,
        "reuse after authentication failure");
}

void test_nonce_exhaustion_is_preflighted() {
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);
    const auto payload = make_payload(65'520);
    std::size_t ciphertext_length = 0;
    require_status(
        sv2_noise_payload_ciphertext_size(payload.size(), &ciphertext_length),
        SV2_NOISE_OK,
        "payload size");

    auto outbound_pair = connect(fixture, credentials.get());
    require_status(
        sv2_noise_test_set_nonces(
            outbound_pair.server.get(),
            0,
            std::numeric_limits<std::uint64_t>::max() - 1),
        SV2_NOISE_OK,
        "set outbound nonce");
    std::vector<std::uint8_t> ciphertext(ciphertext_length, 0xa5);
    require_status(
        sv2_noise_encrypt_payload(
            outbound_pair.server.get(),
            payload.data(),
            payload.size(),
            ciphertext.data(),
            ciphertext.size(),
            &ciphertext_length),
        SV2_NOISE_ERROR_NONCE_EXHAUSTED,
        "outbound nonce preflight");
    require(
        std::ranges::all_of(ciphertext, [](std::uint8_t byte) { return byte == 0xa5; }),
        "nonce exhaustion partially encrypted payload");

    auto inbound_pair = connect(fixture, credentials.get());
    require_status(
        sv2_noise_test_set_nonces(
            inbound_pair.server.get(),
            std::numeric_limits<std::uint64_t>::max() - 1,
            0),
        SV2_NOISE_OK,
        "set inbound nonce");
    std::vector<std::uint8_t> plaintext(payload.size(), 0xa5);
    std::size_t plaintext_length = 0;
    require_status(
        sv2_noise_decrypt_payload(
            inbound_pair.server.get(),
            ciphertext.data(),
            ciphertext.size(),
            payload.size(),
            plaintext.data(),
            plaintext.size(),
            &plaintext_length),
        SV2_NOISE_ERROR_NONCE_EXHAUSTED,
        "inbound nonce preflight");
    require(
        std::ranges::all_of(plaintext, [](std::uint8_t byte) { return byte == 0xa5; }),
        "nonce exhaustion partially decrypted payload");
    require(
        sv2_noise_session_is_terminal(inbound_pair.server.get()) == 1,
        "nonce exhaustion did not terminate");

    auto final_nonce_pair = connect(fixture, credentials.get());
    require_status(
        sv2_noise_test_set_nonces(
            final_nonce_pair.server.get(),
            0,
            std::numeric_limits<std::uint64_t>::max() - 1),
        SV2_NOISE_OK,
        "set final send nonce");
    const std::array<std::uint8_t, 6> header{0x00, 0x80, 0x10, 0x01, 0, 0};
    std::array<std::uint8_t, SV2_NOISE_ENCRYPTED_HEADER_SIZE> encrypted_header{};
    std::size_t encrypted_header_length = 0;
    require_status(
        sv2_noise_encrypt_header(
            final_nonce_pair.server.get(),
            header.data(),
            header.size(),
            encrypted_header.data(),
            encrypted_header.size(),
            &encrypted_header_length),
        SV2_NOISE_OK,
        "last usable nonce");
    require_status(
        sv2_noise_encrypt_header(
            final_nonce_pair.server.get(),
            header.data(),
            header.size(),
            encrypted_header.data(),
            encrypted_header.size(),
            &encrypted_header_length),
        SV2_NOISE_ERROR_NONCE_EXHAUSTED,
        "exhausted nonce after last usable value");
    require(
        sv2_noise_session_is_terminal(final_nonce_pair.server.get()) == 1,
        "final nonce exhaustion did not terminate");
}

void test_invalid_buffer_does_not_consume_nonce() {
    CredentialFixture fixture;
    const auto credentials = fixture.load(kValidNow);
    auto connection = connect(fixture, credentials.get());
    const std::array<std::uint8_t, 6> header{0x00, 0x80, 0x10, 0x01, 0, 0};
    std::array<std::uint8_t, SV2_NOISE_ENCRYPTED_HEADER_SIZE> ciphertext{};
    std::size_t ciphertext_length = 0;

    require_status(
        sv2_noise_encrypt_header(
            connection.server.get(),
            header.data(),
            header.size(),
            ciphertext.data(),
            ciphertext.size() - 1,
            &ciphertext_length),
        SV2_NOISE_ERROR_BUFFER_TOO_SMALL,
        "short header output");
    require(
        sv2_noise_session_is_terminal(connection.server.get()) == 0,
        "short buffer terminated session");

    require_status(
        sv2_noise_encrypt_header(
            connection.server.get(),
            header.data(),
            header.size(),
            ciphertext.data(),
            ciphertext.size(),
            &ciphertext_length),
        SV2_NOISE_OK,
        "header after short output");
    std::vector<std::uint8_t> plaintext;
    require(
        connection.client.receive.decrypt(ciphertext, plaintext),
        "short output consumed nonce");
    require(std::ranges::equal(plaintext, header), "header mismatch");
}

} // namespace

int main() {
    const std::array<std::pair<std::string_view, std::function<void()>>, 9> tests{{
        {"credentials are strictly verified", test_credentials_are_strictly_verified},
        {"handshake local oracle and authentication", test_handshake_local_oracle_and_authentication},
        {"payload size boundaries", test_payload_size_boundaries},
        {"transport ciphertext vectors", test_transport_ciphertext_vectors},
        {"zero payload matches current SRI framing", test_zero_payload_matches_current_sri_framing},
        {"payload chunk boundaries round trip", test_payload_chunk_boundaries_round_trip},
        {"late chunk tamper cleanses and terminates", test_late_chunk_tamper_cleanses_and_terminates},
        {"nonce exhaustion is preflighted", test_nonce_exhaustion_is_preflighted},
        {"invalid buffer does not consume nonce", test_invalid_buffer_does_not_consume_nonce},
    }};
    std::size_t failures = 0;

    for (const auto& [name, test] : tests) {
        try {
            test();
            std::cout << "PASS " << name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL " << name << ": " << error.what() << '\n';
        }
    }
    if (failures != 0) {
        std::cerr << failures << " test(s) failed\n";
        return 1;
    }
    std::cout << tests.size() << " tests passed\n";
    return 0;
}
