#ifndef SV2_NOISE_CREDENTIALS_H
#define SV2_NOISE_CREDENTIALS_H

#include <stddef.h>
#include <stdint.h>

#define SV2_CREDENTIALS_AUTHORITY_KEY_TEXT_CAPACITY 53u

#ifdef __cplusplus
extern "C" {
#endif

typedef enum sv2_credentials_status {
    SV2_CREDENTIALS_OK = 0,
    SV2_CREDENTIALS_ERROR_INVALID_ARGUMENT = 1,
    SV2_CREDENTIALS_ERROR_INVALID_VALIDITY = 2,
    SV2_CREDENTIALS_ERROR_INPUT_NOT_FOUND = 3,
    SV2_CREDENTIALS_ERROR_INPUT_NOT_REGULAR = 4,
    SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE = 5,
    SV2_CREDENTIALS_ERROR_SECRET_PERMISSIONS = 6,
    SV2_CREDENTIALS_ERROR_INVALID_SECRET = 7,
    SV2_CREDENTIALS_ERROR_INVALID_PUBLIC_KEY = 8,
    SV2_CREDENTIALS_ERROR_KEY_REUSE = 9,
    SV2_CREDENTIALS_ERROR_OUTPUT_EXISTS = 10,
    SV2_CREDENTIALS_ERROR_OUT_OF_MEMORY = 11,
    SV2_CREDENTIALS_ERROR_RANDOM_FAILURE = 12,
    SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE = 13,
    SV2_CREDENTIALS_ERROR_IO = 14
} sv2_credentials_status;

const char *sv2_credentials_status_string(sv2_credentials_status status);

// Reuses an owner-only secret or creates one with mode 0600. public_path must not exist.
sv2_credentials_status sv2_credentials_keypair(
    const char *secret_path,
    const char *public_path);

// Signs a version-0 certificate. The authority secret must be an owner-only regular file.
sv2_credentials_status sv2_credentials_issue(
    const char *authority_secret_path,
    const char *server_public_path,
    const char *authority_public_path,
    const char *certificate_path,
    uint32_t valid_from,
    uint32_t not_valid_after);

// Formats an x-only authority key using the SV2 Base58Check URL encoding.
sv2_credentials_status sv2_credentials_format_authority_key(
    const char *public_path,
    char *output,
    size_t output_capacity);

#ifdef __cplusplus
}
#endif

#endif
