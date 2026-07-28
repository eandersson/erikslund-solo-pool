#include "sv2_noise.h"

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <secp256k1.h>
#include <secp256k1_ellswift.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#if defined(SV2_NOISE_TESTING)
#include "sv2_noise_internal.h"
#endif

#define SV2_NOISE_CERTIFICATE_FIELDS_SIZE 10u
#define SV2_NOISE_ELLSWIFT_KEY_SIZE 64u
#define SV2_NOISE_HASH_SIZE 32u
#define SV2_NOISE_NONCE_SIZE 12u
#define SV2_NOISE_CERTIFICATE_VERSION 0u
#define SV2_NOISE_RANDOM_ATTEMPTS 128u

typedef struct sv2_noise_cipher_state {
    uint8_t key[SV2_NOISE_HASH_SIZE];
    uint64_t nonce;
} sv2_noise_cipher_state;

typedef struct sv2_noise_handshake_state {
    uint8_t chaining_key[SV2_NOISE_HASH_SIZE];
    uint8_t handshake_hash[SV2_NOISE_HASH_SIZE];
    sv2_noise_cipher_state cipher;
} sv2_noise_handshake_state;

struct sv2_noise_credentials {
    secp256k1_context *secp_context;
    uint8_t static_secret_key[SV2_NOISE_SECRET_KEY_SIZE];
    uint8_t certificate[SV2_NOISE_CERTIFICATE_SIZE];
    uint32_t valid_from;
    uint32_t not_valid_after;
};

struct sv2_noise_session {
    sv2_noise_cipher_state receive;
    sv2_noise_cipher_state send;
    bool terminal;
};

// SHA256("Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256") -- pins the wire protocol.
static const uint8_t kNoiseProtocolHash[SV2_NOISE_HASH_SIZE] = {
    0x2e, 0xb4, 0x78, 0x81, 0x20, 0x8e, 0x9e, 0xee,
    0x1f, 0x66, 0x9f, 0x67, 0xc6, 0x6e, 0xe7, 0x0e,
    0xa9, 0xea, 0x88, 0x09, 0x0d, 0x50, 0x3f, 0xe8,
    0x30, 0xdc, 0x4b, 0xc8, 0x3e, 0x29, 0xbf, 0x10,
};

static uint16_t load_little_endian_u16(const uint8_t *bytes) {
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8u));
}

static uint32_t load_little_endian_u32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8u) |
           ((uint32_t)bytes[2] << 16u) |
           ((uint32_t)bytes[3] << 24u);
}

static bool pointer_for_length_is_valid(const void *pointer, size_t length) {
    return pointer != NULL || length == 0u;
}

static bool ranges_overlap(
    const uint8_t *first,
    size_t first_length,
    const uint8_t *second,
    size_t second_length) {
    uintptr_t first_start;
    uintptr_t second_start;
    uintptr_t first_end;
    uintptr_t second_end;

    if (first_length == 0u || second_length == 0u)
        return false;
    if (first == NULL || second == NULL)
        return false;

    first_start = (uintptr_t)first;
    second_start = (uintptr_t)second;
    if (first_start > UINTPTR_MAX - first_length ||
        second_start > UINTPTR_MAX - second_length)
        return true;

    first_end = first_start + first_length;
    second_end = second_start + second_length;
    return first_start < second_end && second_start < first_end;
}

static bool sha256_two_parts(
    const uint8_t *first_part,
    size_t first_part_length,
    const uint8_t *second_part,
    size_t second_part_length,
    uint8_t output[SV2_NOISE_HASH_SIZE]) {
    EVP_MD_CTX *context;
    unsigned int output_length = 0u;
    bool success = false;

    context = EVP_MD_CTX_new();
    if (context == NULL)
        return false;

    if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1)
        goto done;
    if (first_part_length != 0u &&
        EVP_DigestUpdate(context, first_part, first_part_length) != 1)
        goto done;
    if (second_part_length != 0u &&
        EVP_DigestUpdate(context, second_part, second_part_length) != 1)
        goto done;
    if (EVP_DigestFinal_ex(context, output, &output_length) != 1)
        goto done;
    success = output_length == SV2_NOISE_HASH_SIZE;

done:
    if (!success)
        OPENSSL_cleanse(output, SV2_NOISE_HASH_SIZE);
    EVP_MD_CTX_free(context);
    return success;
}

static bool hmac_sha256(
    const uint8_t key[SV2_NOISE_HASH_SIZE],
    const uint8_t *data,
    size_t data_length,
    uint8_t output[SV2_NOISE_HASH_SIZE]) {
    static const uint8_t kEmpty = 0u;
    unsigned int output_length = 0u;
    const uint8_t *safe_data = data_length == 0u ? &kEmpty : data;

    if (HMAC(
            EVP_sha256(),
            key,
            (int)SV2_NOISE_HASH_SIZE,
            safe_data,
            data_length,
            output,
            &output_length) == NULL) {
        OPENSSL_cleanse(output, SV2_NOISE_HASH_SIZE);
        return false;
    }
    if (output_length != SV2_NOISE_HASH_SIZE) {
        OPENSSL_cleanse(output, SV2_NOISE_HASH_SIZE);
        return false;
    }
    return true;
}

static bool derive_two_hkdf_outputs(
    const uint8_t chaining_key[SV2_NOISE_HASH_SIZE],
    const uint8_t *input_key_material,
    size_t input_key_material_length,
    uint8_t first_output[SV2_NOISE_HASH_SIZE],
    uint8_t second_output[SV2_NOISE_HASH_SIZE]) {
    uint8_t temporary_key[SV2_NOISE_HASH_SIZE];
    uint8_t second_input[SV2_NOISE_HASH_SIZE + 1u];
    static const uint8_t kFirstCounter = 0x01u;
    bool success = false;

    if (!hmac_sha256(
            chaining_key,
            input_key_material,
            input_key_material_length,
            temporary_key))
        goto done;
    if (!hmac_sha256(temporary_key, &kFirstCounter, 1u, first_output))
        goto done;

    memcpy(second_input, first_output, SV2_NOISE_HASH_SIZE);
    second_input[SV2_NOISE_HASH_SIZE] = 0x02u;
    if (!hmac_sha256(
            temporary_key,
            second_input,
            sizeof(second_input),
            second_output))
        goto done;
    success = true;

done:
    if (!success) {
        OPENSSL_cleanse(first_output, SV2_NOISE_HASH_SIZE);
        OPENSSL_cleanse(second_output, SV2_NOISE_HASH_SIZE);
    }
    OPENSSL_cleanse(temporary_key, sizeof(temporary_key));
    OPENSSL_cleanse(second_input, sizeof(second_input));
    return success;
}

static void encode_noise_nonce(uint64_t nonce, uint8_t output[SV2_NOISE_NONCE_SIZE]) {
    size_t index;

    memset(output, 0, SV2_NOISE_NONCE_SIZE);
    for (index = 0u; index < sizeof(nonce); ++index)
        output[4u + index] = (uint8_t)(nonce >> (index * 8u));
}

static bool aead_encrypt(
    const uint8_t key[SV2_NOISE_HASH_SIZE],
    uint64_t nonce_value,
    const uint8_t *associated_data,
    size_t associated_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext) {
    EVP_CIPHER_CTX *context;
    uint8_t nonce[SV2_NOISE_NONCE_SIZE];
    int written = 0;
    int final_written = 0;
    int total_written = 0;
    bool success = false;

    if (plaintext_length > (size_t)INT_MAX ||
        associated_data_length > (size_t)INT_MAX)
        return false;

    encode_noise_nonce(nonce_value, nonce);
    context = EVP_CIPHER_CTX_new();
    if (context == NULL)
        goto done;
    if (EVP_EncryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_AEAD_SET_IVLEN,
            (int)SV2_NOISE_NONCE_SIZE,
            NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) != 1)
        goto done;
    if (associated_data_length != 0u &&
        EVP_EncryptUpdate(
            context,
            NULL,
            &written,
            associated_data,
            (int)associated_data_length) != 1)
        goto done;
    if (plaintext_length != 0u &&
        EVP_EncryptUpdate(
            context,
            ciphertext,
            &written,
            plaintext,
            (int)plaintext_length) != 1)
        goto done;
    total_written = written;
    if (EVP_EncryptFinal_ex(context, ciphertext + total_written, &final_written) != 1)
        goto done;
    total_written += final_written;
    if ((size_t)total_written != plaintext_length)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_AEAD_GET_TAG,
            (int)SV2_NOISE_TAG_SIZE,
            ciphertext + plaintext_length) != 1)
        goto done;
    success = true;

done:
    if (!success)
        OPENSSL_cleanse(ciphertext, plaintext_length + SV2_NOISE_TAG_SIZE);
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return success;
}

static bool aead_decrypt(
    const uint8_t key[SV2_NOISE_HASH_SIZE],
    uint64_t nonce_value,
    const uint8_t *associated_data,
    size_t associated_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext) {
    EVP_CIPHER_CTX *context;
    uint8_t nonce[SV2_NOISE_NONCE_SIZE];
    size_t plaintext_length;
    int written = 0;
    int final_written = 0;
    int total_written = 0;
    bool success = false;

    if (ciphertext_length < SV2_NOISE_TAG_SIZE)
        return false;
    plaintext_length = ciphertext_length - SV2_NOISE_TAG_SIZE;
    if (plaintext_length > (size_t)INT_MAX ||
        associated_data_length > (size_t)INT_MAX)
        return false;

    encode_noise_nonce(nonce_value, nonce);
    context = EVP_CIPHER_CTX_new();
    if (context == NULL)
        goto done;
    if (EVP_DecryptInit_ex(context, EVP_chacha20_poly1305(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_AEAD_SET_IVLEN,
            (int)SV2_NOISE_NONCE_SIZE,
            NULL) != 1)
        goto done;
    if (EVP_DecryptInit_ex(context, NULL, NULL, key, nonce) != 1)
        goto done;
    if (associated_data_length != 0u &&
        EVP_DecryptUpdate(
            context,
            NULL,
            &written,
            associated_data,
            (int)associated_data_length) != 1)
        goto done;
    if (plaintext_length != 0u &&
        EVP_DecryptUpdate(
            context,
            plaintext,
            &written,
            ciphertext,
            (int)plaintext_length) != 1)
        goto done;
    total_written = written;
    if (EVP_CIPHER_CTX_ctrl(
            context,
            EVP_CTRL_AEAD_SET_TAG,
            (int)SV2_NOISE_TAG_SIZE,
            (void *)(ciphertext + plaintext_length)) != 1)
        goto done;
    if (EVP_DecryptFinal_ex(context, plaintext + total_written, &final_written) != 1)
        goto done;
    total_written += final_written;
    success = (size_t)total_written == plaintext_length;

done:
    if (!success)
        OPENSSL_cleanse(plaintext, plaintext_length);
    EVP_CIPHER_CTX_free(context);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    return success;
}

static sv2_noise_status cipher_encrypt(
    sv2_noise_cipher_state *cipher,
    const uint8_t *associated_data,
    size_t associated_data_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext) {
    if (cipher->nonce == UINT64_MAX)
        return SV2_NOISE_ERROR_NONCE_EXHAUSTED;
    if (!aead_encrypt(
            cipher->key,
            cipher->nonce,
            associated_data,
            associated_data_length,
            plaintext,
            plaintext_length,
            ciphertext))
        return SV2_NOISE_ERROR_CRYPTO_FAILURE;
    ++cipher->nonce;
    return SV2_NOISE_OK;
}

static sv2_noise_status cipher_decrypt(
    sv2_noise_cipher_state *cipher,
    const uint8_t *associated_data,
    size_t associated_data_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext) {
    if (cipher->nonce == UINT64_MAX)
        return SV2_NOISE_ERROR_NONCE_EXHAUSTED;
    if (!aead_decrypt(
            cipher->key,
            cipher->nonce,
            associated_data,
            associated_data_length,
            ciphertext,
            ciphertext_length,
            plaintext))
        return SV2_NOISE_ERROR_AUTHENTICATION_FAILURE;
    ++cipher->nonce;
    return SV2_NOISE_OK;
}

static bool handshake_mix_hash(
    sv2_noise_handshake_state *state,
    const uint8_t *data,
    size_t data_length) {
    uint8_t mixed[SV2_NOISE_HASH_SIZE];

    if (!sha256_two_parts(
            state->handshake_hash,
            sizeof(state->handshake_hash),
            data,
            data_length,
            mixed))
        return false;
    memcpy(state->handshake_hash, mixed, sizeof(mixed));
    OPENSSL_cleanse(mixed, sizeof(mixed));
    return true;
}

static bool handshake_mix_key(
    sv2_noise_handshake_state *state,
    const uint8_t input_key_material[SV2_NOISE_HASH_SIZE]) {
    uint8_t new_chaining_key[SV2_NOISE_HASH_SIZE];
    uint8_t new_cipher_key[SV2_NOISE_HASH_SIZE];
    bool success;

    success = derive_two_hkdf_outputs(
        state->chaining_key,
        input_key_material,
        SV2_NOISE_HASH_SIZE,
        new_chaining_key,
        new_cipher_key);
    if (success) {
        memcpy(
            state->chaining_key,
            new_chaining_key,
            sizeof(new_chaining_key));
        memcpy(state->cipher.key, new_cipher_key, sizeof(new_cipher_key));
        state->cipher.nonce = 0u;
    }
    OPENSSL_cleanse(new_chaining_key, sizeof(new_chaining_key));
    OPENSSL_cleanse(new_cipher_key, sizeof(new_cipher_key));
    return success;
}

static sv2_noise_status handshake_encrypt_and_hash(
    sv2_noise_handshake_state *state,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext) {
    sv2_noise_status status;

    status = cipher_encrypt(
        &state->cipher,
        state->handshake_hash,
        sizeof(state->handshake_hash),
        plaintext,
        plaintext_length,
        ciphertext);
    if (status != SV2_NOISE_OK)
        return status;
    if (!handshake_mix_hash(
            state,
            ciphertext,
            plaintext_length + SV2_NOISE_TAG_SIZE)) {
        OPENSSL_cleanse(
            ciphertext,
            plaintext_length + SV2_NOISE_TAG_SIZE);
        return SV2_NOISE_ERROR_CRYPTO_FAILURE;
    }
    return SV2_NOISE_OK;
}

static sv2_noise_status validate_certificate_time(
    uint32_t valid_from,
    uint32_t not_valid_after,
    uint32_t current_time_unix) {
    if (not_valid_after < valid_from)
        return SV2_NOISE_ERROR_INVALID_CERTIFICATE;
    if (current_time_unix < valid_from)
        return SV2_NOISE_ERROR_CERTIFICATE_NOT_YET_VALID;
    if (current_time_unix > not_valid_after)
        return SV2_NOISE_ERROR_CERTIFICATE_EXPIRED;
    return SV2_NOISE_OK;
}

static bool derive_xonly_public_key(
    const secp256k1_context *context,
    const uint8_t secret_key[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t public_key[SV2_NOISE_PUBLIC_KEY_SIZE]) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly_public_key;
    bool success = false;

    if (secp256k1_keypair_create(context, &keypair, secret_key) != 1)
        goto done;
    if (secp256k1_keypair_xonly_pub(
            context,
            &xonly_public_key,
            NULL,
            &keypair) != 1)
        goto done;
    if (secp256k1_xonly_pubkey_serialize(
            context,
            public_key,
            &xonly_public_key) != 1)
        goto done;
    success = true;

done:
    OPENSSL_cleanse(&keypair, sizeof(keypair));
    return success;
}

static sv2_noise_status generate_handshake_randomness(
    const sv2_noise_credentials *credentials,
    uint8_t ephemeral_secret[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t ephemeral_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t static_randomness[SV2_NOISE_SECRET_KEY_SIZE]) {
    size_t attempt;

    for (attempt = 0u; attempt < SV2_NOISE_RANDOM_ATTEMPTS; ++attempt) {
        if (RAND_priv_bytes(ephemeral_secret, SV2_NOISE_SECRET_KEY_SIZE) != 1)
            return SV2_NOISE_ERROR_RANDOM_FAILURE;
        if (secp256k1_ec_seckey_verify(
                credentials->secp_context,
                ephemeral_secret) == 1)
            break;
    }
    if (attempt == SV2_NOISE_RANDOM_ATTEMPTS)
        return SV2_NOISE_ERROR_RANDOM_FAILURE;
    if (RAND_bytes(ephemeral_randomness, SV2_NOISE_SECRET_KEY_SIZE) != 1)
        return SV2_NOISE_ERROR_RANDOM_FAILURE;
    if (RAND_bytes(static_randomness, SV2_NOISE_SECRET_KEY_SIZE) != 1)
        return SV2_NOISE_ERROR_RANDOM_FAILURE;
    return SV2_NOISE_OK;
}

static sv2_noise_status responder_handshake_with_randomness(
    const sv2_noise_credentials *credentials,
    uint32_t current_time_unix,
    const uint8_t act1[SV2_NOISE_ACT1_SIZE],
    const uint8_t ephemeral_secret[SV2_NOISE_SECRET_KEY_SIZE],
    const uint8_t ephemeral_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    const uint8_t static_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t act2[SV2_NOISE_ACT2_SIZE],
    sv2_noise_session **session_out) {
    sv2_noise_handshake_state handshake;
    sv2_noise_session *session = NULL;
    uint8_t responder_ephemeral_key[SV2_NOISE_ELLSWIFT_KEY_SIZE];
    uint8_t responder_static_key[SV2_NOISE_ELLSWIFT_KEY_SIZE];
    uint8_t ephemeral_shared_secret[SV2_NOISE_HASH_SIZE];
    uint8_t static_shared_secret[SV2_NOISE_HASH_SIZE];
    uint8_t receive_key[SV2_NOISE_HASH_SIZE];
    uint8_t send_key[SV2_NOISE_HASH_SIZE];
    sv2_noise_status status;

    *session_out = NULL;
    memset(&handshake, 0, sizeof(handshake));
    memset(act2, 0, SV2_NOISE_ACT2_SIZE);
    memset(responder_ephemeral_key, 0, sizeof(responder_ephemeral_key));
    memset(responder_static_key, 0, sizeof(responder_static_key));
    memset(ephemeral_shared_secret, 0, sizeof(ephemeral_shared_secret));
    memset(static_shared_secret, 0, sizeof(static_shared_secret));
    memset(receive_key, 0, sizeof(receive_key));
    memset(send_key, 0, sizeof(send_key));

    status = validate_certificate_time(
        credentials->valid_from,
        credentials->not_valid_after,
        current_time_unix);
    if (status != SV2_NOISE_OK)
        goto done;
    if (secp256k1_ec_seckey_verify(
            credentials->secp_context,
            ephemeral_secret) != 1) {
        status = SV2_NOISE_ERROR_INVALID_ARGUMENT;
        goto done;
    }

    memcpy(
        handshake.chaining_key,
        kNoiseProtocolHash,
        sizeof(kNoiseProtocolHash));
    if (!sha256_two_parts(
            kNoiseProtocolHash,
            sizeof(kNoiseProtocolHash),
            NULL,
            0u,
            handshake.handshake_hash)) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    if (!handshake_mix_hash(&handshake, act1, SV2_NOISE_ACT1_SIZE) ||
        !handshake_mix_hash(&handshake, NULL, 0u)) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    if (secp256k1_ellswift_create(
            credentials->secp_context,
            responder_ephemeral_key,
            ephemeral_secret,
            ephemeral_randomness) != 1) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    memcpy(act2, responder_ephemeral_key, sizeof(responder_ephemeral_key));
    if (!handshake_mix_hash(
            &handshake,
            responder_ephemeral_key,
            sizeof(responder_ephemeral_key))) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    if (secp256k1_ellswift_xdh(
            credentials->secp_context,
            ephemeral_shared_secret,
            act1,
            responder_ephemeral_key,
            ephemeral_secret,
            1,
            secp256k1_ellswift_xdh_hash_function_bip324,
            NULL) != 1) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    if (!handshake_mix_key(&handshake, ephemeral_shared_secret)) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    if (secp256k1_ellswift_create(
            credentials->secp_context,
            responder_static_key,
            credentials->static_secret_key,
            static_randomness) != 1) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    status = handshake_encrypt_and_hash(
        &handshake,
        responder_static_key,
        sizeof(responder_static_key),
        act2 + SV2_NOISE_ELLSWIFT_KEY_SIZE);
    if (status != SV2_NOISE_OK)
        goto done;

    if (secp256k1_ellswift_xdh(
            credentials->secp_context,
            static_shared_secret,
            act1,
            responder_static_key,
            credentials->static_secret_key,
            1,
            secp256k1_ellswift_xdh_hash_function_bip324,
            NULL) != 1) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    if (!handshake_mix_key(&handshake, static_shared_secret)) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    status = handshake_encrypt_and_hash(
        &handshake,
        credentials->certificate,
        sizeof(credentials->certificate),
        act2 + 2u * SV2_NOISE_ELLSWIFT_KEY_SIZE + SV2_NOISE_TAG_SIZE);
    if (status != SV2_NOISE_OK)
        goto done;

    if (!derive_two_hkdf_outputs(
            handshake.chaining_key,
            NULL,
            0u,
            receive_key,
            send_key)) {
        status = SV2_NOISE_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    session = calloc(1u, sizeof(*session));
    if (session == NULL) {
        status = SV2_NOISE_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    memcpy(
        session->receive.key,
        receive_key,
        sizeof(receive_key));
    memcpy(
        session->send.key,
        send_key,
        sizeof(send_key));
    session->receive.nonce = 0u;
    session->send.nonce = 0u;
    session->terminal = false;
    *session_out = session;
    session = NULL;
    status = SV2_NOISE_OK;

done:
    if (status != SV2_NOISE_OK)
        OPENSSL_cleanse(act2, SV2_NOISE_ACT2_SIZE);
    if (session != NULL) {
        OPENSSL_cleanse(session, sizeof(*session));
        free(session);
    }
    OPENSSL_cleanse(&handshake, sizeof(handshake));
    OPENSSL_cleanse(responder_ephemeral_key, sizeof(responder_ephemeral_key));
    OPENSSL_cleanse(responder_static_key, sizeof(responder_static_key));
    OPENSSL_cleanse(ephemeral_shared_secret, sizeof(ephemeral_shared_secret));
    OPENSSL_cleanse(static_shared_secret, sizeof(static_shared_secret));
    OPENSSL_cleanse(receive_key, sizeof(receive_key));
    OPENSSL_cleanse(send_key, sizeof(send_key));
    return status;
}

static sv2_noise_status check_nonce_capacity(
    sv2_noise_session *session,
    const sv2_noise_cipher_state *cipher,
    size_t nonce_count) {
    uint64_t requested_nonces;

    if (session->terminal)
        return SV2_NOISE_ERROR_SESSION_TERMINAL;
    requested_nonces = (uint64_t)nonce_count;
    if ((size_t)requested_nonces != nonce_count ||
        requested_nonces > UINT64_MAX - cipher->nonce) {
        session->terminal = true;
        return SV2_NOISE_ERROR_NONCE_EXHAUSTED;
    }
    return SV2_NOISE_OK;
}

static size_t payload_chunk_count(size_t plaintext_length) {
    if (plaintext_length == 0u)
        return 0u;
    return 1u +
           (plaintext_length - 1u) / SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE;
}

const char *sv2_noise_status_string(sv2_noise_status status) {
    switch (status) {
    case SV2_NOISE_OK:
        return "success";
    case SV2_NOISE_ERROR_INVALID_ARGUMENT:
        return "invalid argument";
    case SV2_NOISE_ERROR_BUFFER_TOO_SMALL:
        return "buffer too small";
    case SV2_NOISE_ERROR_OUT_OF_MEMORY:
        return "out of memory";
    case SV2_NOISE_ERROR_INVALID_STATIC_SECRET:
        return "invalid static secret key";
    case SV2_NOISE_ERROR_INVALID_AUTHORITY_KEY:
        return "invalid authority public key";
    case SV2_NOISE_ERROR_UNSUPPORTED_CERTIFICATE_VERSION:
        return "unsupported certificate version";
    case SV2_NOISE_ERROR_INVALID_CERTIFICATE:
        return "invalid certificate";
    case SV2_NOISE_ERROR_CERTIFICATE_NOT_YET_VALID:
        return "certificate not yet valid";
    case SV2_NOISE_ERROR_CERTIFICATE_EXPIRED:
        return "certificate expired";
    case SV2_NOISE_ERROR_RANDOM_FAILURE:
        return "random number generation failed";
    case SV2_NOISE_ERROR_CRYPTO_FAILURE:
        return "cryptographic operation failed";
    case SV2_NOISE_ERROR_AUTHENTICATION_FAILURE:
        return "authentication failed";
    case SV2_NOISE_ERROR_NONCE_EXHAUSTED:
        return "nonce exhausted";
    case SV2_NOISE_ERROR_SESSION_TERMINAL:
        return "session is terminal";
    default:
        return "unknown error";
    }
}

sv2_noise_status sv2_noise_credentials_load(
    const uint8_t *static_secret_key,
    size_t static_secret_key_length,
    const uint8_t *authority_public_key,
    size_t authority_public_key_length,
    const uint8_t *certificate,
    size_t certificate_length,
    uint32_t current_time_unix,
    sv2_noise_credentials **credentials_out) {
    secp256k1_context *context = NULL;
    sv2_noise_credentials *credentials = NULL;
    secp256k1_xonly_pubkey authority_key;
    uint8_t static_public_key[SV2_NOISE_PUBLIC_KEY_SIZE];
    uint8_t certificate_hash[SV2_NOISE_HASH_SIZE];
    uint8_t context_seed[SV2_NOISE_HASH_SIZE];
    uint16_t version;
    uint32_t valid_from;
    uint32_t not_valid_after;
    sv2_noise_status status = SV2_NOISE_ERROR_CRYPTO_FAILURE;

    if (credentials_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *credentials_out = NULL;
    if (static_secret_key == NULL ||
        static_secret_key_length != SV2_NOISE_SECRET_KEY_SIZE ||
        authority_public_key == NULL ||
        authority_public_key_length != SV2_NOISE_PUBLIC_KEY_SIZE ||
        certificate == NULL ||
        certificate_length != SV2_NOISE_CERTIFICATE_SIZE)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;

    version = load_little_endian_u16(certificate);
    valid_from = load_little_endian_u32(certificate + 2u);
    not_valid_after = load_little_endian_u32(certificate + 6u);
    if (version != SV2_NOISE_CERTIFICATE_VERSION)
        return SV2_NOISE_ERROR_UNSUPPORTED_CERTIFICATE_VERSION;
    status = validate_certificate_time(
        valid_from,
        not_valid_after,
        current_time_unix);
    if (status != SV2_NOISE_OK)
        return status;

    memset(static_public_key, 0, sizeof(static_public_key));
    memset(certificate_hash, 0, sizeof(certificate_hash));
    memset(context_seed, 0, sizeof(context_seed));

    context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (context == NULL)
        goto done;
    if (RAND_priv_bytes(context_seed, sizeof(context_seed)) != 1) {
        status = SV2_NOISE_ERROR_RANDOM_FAILURE;
        goto done;
    }
    if (secp256k1_context_randomize(context, context_seed) != 1)
        goto done;
    if (secp256k1_ec_seckey_verify(context, static_secret_key) != 1) {
        status = SV2_NOISE_ERROR_INVALID_STATIC_SECRET;
        goto done;
    }
    if (secp256k1_xonly_pubkey_parse(
            context,
            &authority_key,
            authority_public_key) != 1) {
        status = SV2_NOISE_ERROR_INVALID_AUTHORITY_KEY;
        goto done;
    }
    if (!derive_xonly_public_key(
            context,
            static_secret_key,
            static_public_key))
        goto done;
    if (!sha256_two_parts(
            certificate,
            SV2_NOISE_CERTIFICATE_FIELDS_SIZE,
            static_public_key,
            sizeof(static_public_key),
            certificate_hash))
        goto done;
    if (secp256k1_schnorrsig_verify(
            context,
            certificate + SV2_NOISE_CERTIFICATE_FIELDS_SIZE,
            certificate_hash,
            sizeof(certificate_hash),
            &authority_key) != 1) {
        status = SV2_NOISE_ERROR_INVALID_CERTIFICATE;
        goto done;
    }

    credentials = calloc(1u, sizeof(*credentials));
    if (credentials == NULL) {
        status = SV2_NOISE_ERROR_OUT_OF_MEMORY;
        goto done;
    }
    credentials->secp_context = context;
    context = NULL;
    memcpy(
        credentials->static_secret_key,
        static_secret_key,
        SV2_NOISE_SECRET_KEY_SIZE);
    memcpy(
        credentials->certificate,
        certificate,
        SV2_NOISE_CERTIFICATE_SIZE);
    credentials->valid_from = valid_from;
    credentials->not_valid_after = not_valid_after;
    *credentials_out = credentials;
    credentials = NULL;
    status = SV2_NOISE_OK;

done:
    if (credentials != NULL) {
        OPENSSL_cleanse(credentials, sizeof(*credentials));
        free(credentials);
    }
    if (context != NULL)
        secp256k1_context_destroy(context);
    OPENSSL_cleanse(static_public_key, sizeof(static_public_key));
    OPENSSL_cleanse(certificate_hash, sizeof(certificate_hash));
    OPENSSL_cleanse(context_seed, sizeof(context_seed));
    return status;
}

void sv2_noise_credentials_free(sv2_noise_credentials *credentials) {
    secp256k1_context *context;

    if (credentials == NULL)
        return;
    context = credentials->secp_context;
    credentials->secp_context = NULL;
    OPENSSL_cleanse(credentials, sizeof(*credentials));
    free(credentials);
    secp256k1_context_destroy(context);
}

sv2_noise_status sv2_noise_responder_handshake(
    const sv2_noise_credentials *credentials,
    uint32_t current_time_unix,
    const uint8_t *act1,
    size_t act1_length,
    uint8_t *act2,
    size_t act2_capacity,
    size_t *act2_length_out,
    sv2_noise_session **session_out) {
    uint8_t ephemeral_secret[SV2_NOISE_SECRET_KEY_SIZE];
    uint8_t ephemeral_randomness[SV2_NOISE_SECRET_KEY_SIZE];
    uint8_t static_randomness[SV2_NOISE_SECRET_KEY_SIZE];
    sv2_noise_status status;

    if (act2_length_out == NULL || session_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *act2_length_out = SV2_NOISE_ACT2_SIZE;
    *session_out = NULL;
    if (credentials == NULL || act1 == NULL ||
        act1_length != SV2_NOISE_ACT1_SIZE || act2 == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    if (act2_capacity < SV2_NOISE_ACT2_SIZE)
        return SV2_NOISE_ERROR_BUFFER_TOO_SMALL;
    if (ranges_overlap(
            act1,
            act1_length,
            act2,
            SV2_NOISE_ACT2_SIZE))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    status = validate_certificate_time(
        credentials->valid_from,
        credentials->not_valid_after,
        current_time_unix);
    if (status != SV2_NOISE_OK) {
        *act2_length_out = 0u;
        return status;
    }

    memset(ephemeral_secret, 0, sizeof(ephemeral_secret));
    memset(ephemeral_randomness, 0, sizeof(ephemeral_randomness));
    memset(static_randomness, 0, sizeof(static_randomness));
    status = generate_handshake_randomness(
        credentials,
        ephemeral_secret,
        ephemeral_randomness,
        static_randomness);
    if (status == SV2_NOISE_OK) {
        status = responder_handshake_with_randomness(
            credentials,
            current_time_unix,
            act1,
            ephemeral_secret,
            ephemeral_randomness,
            static_randomness,
            act2,
            session_out);
    }
    OPENSSL_cleanse(ephemeral_secret, sizeof(ephemeral_secret));
    OPENSSL_cleanse(ephemeral_randomness, sizeof(ephemeral_randomness));
    OPENSSL_cleanse(static_randomness, sizeof(static_randomness));
    if (status != SV2_NOISE_OK)
        *act2_length_out = 0u;
    return status;
}

#if defined(SV2_NOISE_TESTING)
sv2_noise_status sv2_noise_test_responder_handshake(
    const sv2_noise_credentials *credentials,
    uint32_t current_time_unix,
    const uint8_t act1[SV2_NOISE_ACT1_SIZE],
    const uint8_t ephemeral_secret[SV2_NOISE_SECRET_KEY_SIZE],
    const uint8_t ephemeral_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    const uint8_t static_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t act2[SV2_NOISE_ACT2_SIZE],
    sv2_noise_session **session_out) {
    if (credentials == NULL || act1 == NULL ||
        ephemeral_secret == NULL || ephemeral_randomness == NULL ||
        static_randomness == NULL || act2 == NULL || session_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    return responder_handshake_with_randomness(
        credentials,
        current_time_unix,
        act1,
        ephemeral_secret,
        ephemeral_randomness,
        static_randomness,
        act2,
        session_out);
}
#endif

sv2_noise_status sv2_noise_payload_ciphertext_size(
    size_t plaintext_length,
    size_t *ciphertext_length_out) {
    size_t chunk_count;

    if (ciphertext_length_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *ciphertext_length_out = 0u;
    if (plaintext_length > SV2_NOISE_MAX_FRAME_PAYLOAD_SIZE)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    chunk_count = payload_chunk_count(plaintext_length);
    *ciphertext_length_out =
        plaintext_length + chunk_count * SV2_NOISE_TAG_SIZE;
    return SV2_NOISE_OK;
}

sv2_noise_status sv2_noise_encrypt_header(
    sv2_noise_session *session,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length_out) {
    sv2_noise_status status;

    if (ciphertext_length_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *ciphertext_length_out = SV2_NOISE_ENCRYPTED_HEADER_SIZE;
    if (session == NULL || plaintext == NULL ||
        plaintext_length != SV2_NOISE_HEADER_SIZE || ciphertext == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    if (ciphertext_capacity < SV2_NOISE_ENCRYPTED_HEADER_SIZE)
        return SV2_NOISE_ERROR_BUFFER_TOO_SMALL;
    if (ranges_overlap(
            plaintext,
            plaintext_length,
            ciphertext,
            SV2_NOISE_ENCRYPTED_HEADER_SIZE))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;

    status = check_nonce_capacity(session, &session->send, 1u);
    if (status != SV2_NOISE_OK) {
        *ciphertext_length_out = 0u;
        return status;
    }
    status = cipher_encrypt(
        &session->send,
        NULL,
        0u,
        plaintext,
        plaintext_length,
        ciphertext);
    if (status != SV2_NOISE_OK) {
        session->terminal = true;
        *ciphertext_length_out = 0u;
        return status;
    }
    return SV2_NOISE_OK;
}

sv2_noise_status sv2_noise_decrypt_header(
    sv2_noise_session *session,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length_out) {
    sv2_noise_status status;

    if (plaintext_length_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *plaintext_length_out = SV2_NOISE_HEADER_SIZE;
    if (session == NULL || ciphertext == NULL ||
        ciphertext_length != SV2_NOISE_ENCRYPTED_HEADER_SIZE ||
        plaintext == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    if (plaintext_capacity < SV2_NOISE_HEADER_SIZE)
        return SV2_NOISE_ERROR_BUFFER_TOO_SMALL;
    if (ranges_overlap(
            ciphertext,
            ciphertext_length,
            plaintext,
            SV2_NOISE_HEADER_SIZE))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;

    status = check_nonce_capacity(session, &session->receive, 1u);
    if (status != SV2_NOISE_OK) {
        *plaintext_length_out = 0u;
        return status;
    }
    status = cipher_decrypt(
        &session->receive,
        NULL,
        0u,
        ciphertext,
        ciphertext_length,
        plaintext);
    if (status != SV2_NOISE_OK) {
        session->terminal = true;
        *plaintext_length_out = 0u;
        return status;
    }
    return SV2_NOISE_OK;
}

sv2_noise_status sv2_noise_encrypt_payload(
    sv2_noise_session *session,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length_out) {
    size_t required_length;
    size_t chunk_count;
    size_t plaintext_offset = 0u;
    size_t ciphertext_offset = 0u;
    sv2_noise_status status;

    if (ciphertext_length_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *ciphertext_length_out = 0u;
    status = sv2_noise_payload_ciphertext_size(
        plaintext_length,
        &required_length);
    if (status != SV2_NOISE_OK)
        return status;
    *ciphertext_length_out = required_length;
    if (session == NULL ||
        !pointer_for_length_is_valid(plaintext, plaintext_length) ||
        !pointer_for_length_is_valid(ciphertext, required_length))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    if (ciphertext_capacity < required_length)
        return SV2_NOISE_ERROR_BUFFER_TOO_SMALL;
    if (ranges_overlap(
            plaintext,
            plaintext_length,
            ciphertext,
            required_length))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;

    chunk_count = payload_chunk_count(plaintext_length);
    status = check_nonce_capacity(session, &session->send, chunk_count);
    if (status != SV2_NOISE_OK) {
        *ciphertext_length_out = 0u;
        return status;
    }
    while (plaintext_offset < plaintext_length) {
        size_t chunk_length = plaintext_length - plaintext_offset;

        if (chunk_length > SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE)
            chunk_length = SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE;
        status = cipher_encrypt(
            &session->send,
            NULL,
            0u,
            plaintext + plaintext_offset,
            chunk_length,
            ciphertext + ciphertext_offset);
        if (status != SV2_NOISE_OK) {
            session->terminal = true;
            OPENSSL_cleanse(ciphertext, required_length);
            *ciphertext_length_out = 0u;
            return status;
        }
        plaintext_offset += chunk_length;
        ciphertext_offset += chunk_length + SV2_NOISE_TAG_SIZE;
    }
    return SV2_NOISE_OK;
}

sv2_noise_status sv2_noise_decrypt_payload(
    sv2_noise_session *session,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    size_t plaintext_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length_out) {
    size_t required_ciphertext_length;
    size_t chunk_count;
    size_t plaintext_offset = 0u;
    size_t ciphertext_offset = 0u;
    sv2_noise_status status;

    if (plaintext_length_out == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    *plaintext_length_out = 0u;
    status = sv2_noise_payload_ciphertext_size(
        plaintext_length,
        &required_ciphertext_length);
    if (status != SV2_NOISE_OK)
        return status;
    *plaintext_length_out = plaintext_length;
    if (session == NULL ||
        ciphertext_length != required_ciphertext_length ||
        !pointer_for_length_is_valid(ciphertext, ciphertext_length) ||
        !pointer_for_length_is_valid(plaintext, plaintext_length))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    if (plaintext_capacity < plaintext_length)
        return SV2_NOISE_ERROR_BUFFER_TOO_SMALL;
    if (ranges_overlap(
            ciphertext,
            ciphertext_length,
            plaintext,
            plaintext_length))
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;

    chunk_count = payload_chunk_count(plaintext_length);
    status = check_nonce_capacity(
        session,
        &session->receive,
        chunk_count);
    if (status != SV2_NOISE_OK) {
        *plaintext_length_out = 0u;
        return status;
    }
    while (plaintext_offset < plaintext_length) {
        size_t chunk_length = plaintext_length - plaintext_offset;
        size_t encrypted_chunk_length;

        if (chunk_length > SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE)
            chunk_length = SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE;
        encrypted_chunk_length = chunk_length + SV2_NOISE_TAG_SIZE;
        status = cipher_decrypt(
            &session->receive,
            NULL,
            0u,
            ciphertext + ciphertext_offset,
            encrypted_chunk_length,
            plaintext + plaintext_offset);
        if (status != SV2_NOISE_OK) {
            session->terminal = true;
            OPENSSL_cleanse(plaintext, plaintext_length);
            *plaintext_length_out = 0u;
            return status;
        }
        plaintext_offset += chunk_length;
        ciphertext_offset += encrypted_chunk_length;
    }
    return SV2_NOISE_OK;
}

int sv2_noise_session_is_terminal(const sv2_noise_session *session) {
    if (session == NULL)
        return 1;
    return session->terminal ? 1 : 0;
}

void sv2_noise_session_free(sv2_noise_session *session) {
    if (session == NULL)
        return;
    OPENSSL_cleanse(session, sizeof(*session));
    free(session);
}

#if defined(SV2_NOISE_TESTING)
sv2_noise_status sv2_noise_test_set_nonces(
    sv2_noise_session *session,
    uint64_t receive_nonce,
    uint64_t send_nonce) {
    if (session == NULL)
        return SV2_NOISE_ERROR_INVALID_ARGUMENT;
    if (session->terminal)
        return SV2_NOISE_ERROR_SESSION_TERMINAL;
    session->receive.nonce = receive_nonce;
    session->send.nonce = send_nonce;
    return SV2_NOISE_OK;
}
#endif
