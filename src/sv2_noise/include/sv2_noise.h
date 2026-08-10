#ifndef SV2_NOISE_H
#define SV2_NOISE_H

// Stable caller-owned-buffer C ABI for the Stratum V2 Noise responder.

#include <stddef.h>
#include <stdint.h>

// Keep the C ABI visible when the responder is built as a shared library.
#if defined(__GNUC__) || defined(__clang__)
#define SV2_NOISE_API __attribute__((visibility("default")))
#else
#define SV2_NOISE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SV2_NOISE_SECRET_KEY_SIZE 32u
#define SV2_NOISE_PUBLIC_KEY_SIZE 32u
#define SV2_NOISE_CERTIFICATE_SIZE 74u
#define SV2_NOISE_ACT1_SIZE 64u
#define SV2_NOISE_ACT2_SIZE 234u
#define SV2_NOISE_HEADER_SIZE 6u
#define SV2_NOISE_ENCRYPTED_HEADER_SIZE 22u
#define SV2_NOISE_TAG_SIZE 16u
#define SV2_NOISE_MAX_PAYLOAD_CHUNK_SIZE 65519u
#define SV2_NOISE_MAX_FRAME_PAYLOAD_SIZE 16777215u

typedef enum sv2_noise_status {
    SV2_NOISE_OK = 0,
    SV2_NOISE_ERROR_INVALID_ARGUMENT = 1,
    SV2_NOISE_ERROR_BUFFER_TOO_SMALL = 2,
    SV2_NOISE_ERROR_OUT_OF_MEMORY = 3,
    SV2_NOISE_ERROR_INVALID_STATIC_SECRET = 4,
    SV2_NOISE_ERROR_INVALID_AUTHORITY_KEY = 5,
    SV2_NOISE_ERROR_UNSUPPORTED_CERTIFICATE_VERSION = 6,
    SV2_NOISE_ERROR_INVALID_CERTIFICATE = 7,
    SV2_NOISE_ERROR_CERTIFICATE_NOT_YET_VALID = 8,
    SV2_NOISE_ERROR_CERTIFICATE_EXPIRED = 9,
    SV2_NOISE_ERROR_RANDOM_FAILURE = 10,
    SV2_NOISE_ERROR_CRYPTO_FAILURE = 11,
    SV2_NOISE_ERROR_AUTHENTICATION_FAILURE = 12,
    SV2_NOISE_ERROR_NONCE_EXHAUSTED = 13,
    SV2_NOISE_ERROR_SESSION_TERMINAL = 14
} sv2_noise_status;

typedef struct sv2_noise_credentials sv2_noise_credentials;
typedef struct sv2_noise_session sv2_noise_session;

// Returns a process-lifetime string for logging. Unknown values map to "unknown error".
SV2_NOISE_API const char *sv2_noise_status_string(sv2_noise_status status);

// Loads and verifies immutable responder credentials. certificate is:
// version U16 || valid_from U32 || not_valid_after U32 || BIP340 signature.
// Version 0 is required, and current_time_unix must be within the inclusive validity interval.
// Credentials may be shared across handshakes but must outlive them.
SV2_NOISE_API sv2_noise_status sv2_noise_credentials_load(
    const uint8_t *static_secret_key,
    size_t static_secret_key_length,
    const uint8_t *authority_public_key,
    size_t authority_public_key_length,
    const uint8_t *certificate,
    size_t certificate_length,
    uint32_t current_time_unix,
    sv2_noise_credentials **credentials_out);

SV2_NOISE_API void sv2_noise_credentials_free(sv2_noise_credentials *credentials);

// Act1 must be complete; there is no streaming path. Certificate validity is re-checked here, so
// long-lived credentials can expire between handshakes. On failure session_out is NULL, and a
// short act2 buffer reports SV2_NOISE_ACT2_SIZE without consuming randomness.
SV2_NOISE_API sv2_noise_status sv2_noise_responder_handshake(
    const sv2_noise_credentials *credentials,
    uint32_t current_time_unix,
    const uint8_t *act1,
    size_t act1_length,
    uint8_t *act2,
    size_t act2_capacity,
    size_t *act2_length_out,
    sv2_noise_session **session_out);

// Returns the exact payload ciphertext size. Empty payloads consume no nonce.
SV2_NOISE_API sv2_noise_status sv2_noise_payload_ciphertext_size(
    size_t plaintext_length,
    size_t *ciphertext_length_out);

// Encrypts or decrypts one complete six-byte SV2 frame header. The output buffer must not overlap
// the input buffer. Each successful call consumes exactly one nonce in its direction.
SV2_NOISE_API sv2_noise_status sv2_noise_encrypt_header(
    sv2_noise_session *session,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length_out);

SV2_NOISE_API sv2_noise_status sv2_noise_decrypt_header(
    sv2_noise_session *session,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length_out);

// Payloads use independent 65,519-byte plaintext chunks. Lengths must match
// sv2_noise_payload_ciphertext_size(), and input and output buffers must not overlap.
// Authentication failure or nonce exhaustion terminates the session. Validation failures do not.
SV2_NOISE_API sv2_noise_status sv2_noise_encrypt_payload(
    sv2_noise_session *session,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length_out);

SV2_NOISE_API sv2_noise_status sv2_noise_decrypt_payload(
    sv2_noise_session *session,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    size_t plaintext_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length_out);

// A session is single-owner; never use one concurrently. Freeing cleanses both transport keys.
// NULL is safe to free and reports terminal.
SV2_NOISE_API int sv2_noise_session_is_terminal(const sv2_noise_session *session);
SV2_NOISE_API void sv2_noise_session_free(sv2_noise_session *session);

#ifdef __cplusplus
}
#endif

#endif
