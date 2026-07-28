#define _POSIX_C_SOURCE 200809L

#include "credentials.h"

#include "sv2_noise.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#define SV2_CREDENTIALS_CERTIFICATE_FIELDS_SIZE 10u
#define SV2_CREDENTIALS_CERTIFICATE_SIGNED_SIZE 42u
#define SV2_CREDENTIALS_VALID_FROM_OFFSET 2u
#define SV2_CREDENTIALS_NOT_VALID_AFTER_OFFSET 6u
#define SV2_CREDENTIALS_AUTHORITY_KEY_VERSION_SIZE 2u
#define SV2_CREDENTIALS_AUTHORITY_KEY_PAYLOAD_SIZE \
    (SV2_CREDENTIALS_AUTHORITY_KEY_VERSION_SIZE + SV2_NOISE_PUBLIC_KEY_SIZE)
#define SV2_CREDENTIALS_BASE58_CHECKSUM_SIZE 4u
#define SV2_CREDENTIALS_BASE58_INPUT_SIZE \
    (SV2_CREDENTIALS_AUTHORITY_KEY_PAYLOAD_SIZE + SV2_CREDENTIALS_BASE58_CHECKSUM_SIZE)
#define SV2_CREDENTIALS_HASH_SIZE 32u
#define SV2_CREDENTIALS_RANDOM_ATTEMPTS 128u
#define SV2_CREDENTIALS_TEMPORARY_MARKER ".tmp-"
#define SV2_CREDENTIALS_TEMPORARY_MARKER_SIZE 5u
#define SV2_CREDENTIALS_TEMPORARY_RANDOM_SIZE 8u
#define SV2_CREDENTIALS_TEMPORARY_SUFFIX_SIZE \
    (SV2_CREDENTIALS_TEMPORARY_MARKER_SIZE + \
     SV2_CREDENTIALS_TEMPORARY_RANDOM_SIZE * 2u + 1u)

static bool is_valid_path(const char *path) {
    return path != NULL && path[0] != '\0';
}

static void store_little_endian_u16(uint8_t output[2], uint16_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8u);
}

static void store_little_endian_u32(uint8_t output[4], uint32_t value) {
    output[0] = (uint8_t)value;
    output[1] = (uint8_t)(value >> 8u);
    output[2] = (uint8_t)(value >> 16u);
    output[3] = (uint8_t)(value >> 24u);
}

static sv2_credentials_status check_output_path(const char *path) {
    struct stat metadata;

    if (lstat(path, &metadata) == 0)
        return SV2_CREDENTIALS_ERROR_OUTPUT_EXISTS;
    if (errno == ENOENT)
        return SV2_CREDENTIALS_OK;
    return SV2_CREDENTIALS_ERROR_IO;
}

static sv2_credentials_status read_exact_file(
    const char *path,
    uint8_t *output,
    size_t output_size,
    bool require_secret_permissions) {
    struct stat metadata;
    uint8_t extra_byte = 0u;
    size_t offset = 0u;
    ssize_t extra_bytes_read;
    int descriptor;

    descriptor = open(path, O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        if (errno == ENOENT)
            return SV2_CREDENTIALS_ERROR_INPUT_NOT_FOUND;
        return SV2_CREDENTIALS_ERROR_IO;
    }
    if (fstat(descriptor, &metadata) != 0) {
        close(descriptor);
        return SV2_CREDENTIALS_ERROR_IO;
    }
    if (!S_ISREG(metadata.st_mode)) {
        close(descriptor);
        return SV2_CREDENTIALS_ERROR_INPUT_NOT_REGULAR;
    }
    if (metadata.st_size < 0 || (uintmax_t)metadata.st_size != (uintmax_t)output_size) {
        close(descriptor);
        return SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE;
    }
    if (require_secret_permissions && (metadata.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(descriptor);
        return SV2_CREDENTIALS_ERROR_SECRET_PERMISSIONS;
    }

    while (offset < output_size) {
        ssize_t bytes_read = read(descriptor, output + offset, output_size - offset);

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            close(descriptor);
            return SV2_CREDENTIALS_ERROR_IO;
        }
        if (bytes_read == 0) {
            close(descriptor);
            return SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE;
        }
        offset += (size_t)bytes_read;
    }
    do {
        extra_bytes_read = read(descriptor, &extra_byte, sizeof(extra_byte));
    } while (extra_bytes_read < 0 && errno == EINTR);
    OPENSSL_cleanse(&extra_byte, sizeof(extra_byte));
    if (extra_bytes_read < 0) {
        close(descriptor);
        return SV2_CREDENTIALS_ERROR_IO;
    }
    if (extra_bytes_read != 0) {
        close(descriptor);
        return SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE;
    }
    if (close(descriptor) != 0)
        return SV2_CREDENTIALS_ERROR_IO;
    return SV2_CREDENTIALS_OK;
}

static bool write_all(int descriptor, const uint8_t *data, size_t data_size) {
    size_t offset = 0u;

    while (offset < data_size) {
        ssize_t bytes_written = write(descriptor, data + offset, data_size - offset);

        if (bytes_written < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        if (bytes_written == 0)
            return false;
        offset += (size_t)bytes_written;
    }
    return true;
}

static sv2_credentials_status build_temporary_path(
    const char *path,
    char **temporary_path_out) {
    static const char kHex[] = "0123456789abcdef";
    uint8_t random_bytes[SV2_CREDENTIALS_TEMPORARY_RANDOM_SIZE];
    size_t path_length;
    size_t index;
    char *temporary_path;

    *temporary_path_out = NULL;
    path_length = strlen(path);
    if (path_length > SIZE_MAX - SV2_CREDENTIALS_TEMPORARY_SUFFIX_SIZE)
        return SV2_CREDENTIALS_ERROR_INVALID_ARGUMENT;
    temporary_path =
        malloc(path_length + SV2_CREDENTIALS_TEMPORARY_SUFFIX_SIZE);
    if (temporary_path == NULL)
        return SV2_CREDENTIALS_ERROR_OUT_OF_MEMORY;
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        free(temporary_path);
        return SV2_CREDENTIALS_ERROR_RANDOM_FAILURE;
    }

    memcpy(temporary_path, path, path_length);
    memcpy(
        temporary_path + path_length,
        SV2_CREDENTIALS_TEMPORARY_MARKER,
        SV2_CREDENTIALS_TEMPORARY_MARKER_SIZE);
    for (index = 0u; index < sizeof(random_bytes); ++index) {
        size_t suffix_offset =
            path_length +
            SV2_CREDENTIALS_TEMPORARY_MARKER_SIZE +
            index * 2u;

        temporary_path[suffix_offset] = kHex[random_bytes[index] >> 4u];
        temporary_path[suffix_offset + 1u] =
            kHex[random_bytes[index] & 0x0fu];
    }
    temporary_path[
        path_length + SV2_CREDENTIALS_TEMPORARY_SUFFIX_SIZE - 1u] = '\0';
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
    *temporary_path_out = temporary_path;
    return SV2_CREDENTIALS_OK;
}

static sv2_credentials_status write_new_file(
    const char *path,
    const uint8_t *data,
    size_t data_size,
    mode_t mode) {
    char *temporary_path = NULL;
    sv2_credentials_status status;
    size_t attempt;
    int descriptor = -1;

    status = check_output_path(path);
    if (status != SV2_CREDENTIALS_OK)
        return status;

    for (attempt = 0u; attempt < SV2_CREDENTIALS_RANDOM_ATTEMPTS; ++attempt) {
        status = build_temporary_path(path, &temporary_path);
        if (status != SV2_CREDENTIALS_OK)
            return status;
        descriptor = open(
            temporary_path,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            mode);
        if (descriptor >= 0)
            break;
        free(temporary_path);
        temporary_path = NULL;
        if (errno != EEXIST)
            return SV2_CREDENTIALS_ERROR_IO;
    }
    if (descriptor < 0)
        return SV2_CREDENTIALS_ERROR_RANDOM_FAILURE;

    bool write_succeeded =
        fchmod(descriptor, mode) == 0 &&
        write_all(descriptor, data, data_size) &&
        fsync(descriptor) == 0;
    int close_result = close(descriptor);
    if (!write_succeeded || close_result != 0) {
        unlink(temporary_path);
        free(temporary_path);
        return SV2_CREDENTIALS_ERROR_IO;
    }

    if (link(temporary_path, path) != 0) {
        status = errno == EEXIST
            ? SV2_CREDENTIALS_ERROR_OUTPUT_EXISTS
            : SV2_CREDENTIALS_ERROR_IO;
        unlink(temporary_path);
        free(temporary_path);
        return status;
    }
    if (unlink(temporary_path) != 0) {
        unlink(path);
        free(temporary_path);
        return SV2_CREDENTIALS_ERROR_IO;
    }
    free(temporary_path);
    return SV2_CREDENTIALS_OK;
}

static sv2_credentials_status create_secp_context(
    secp256k1_context **context_out) {
    uint8_t context_seed[SV2_NOISE_SECRET_KEY_SIZE];
    secp256k1_context *context;
    sv2_credentials_status status = SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;

    *context_out = NULL;
    memset(context_seed, 0, sizeof(context_seed));
    context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (context == NULL)
        goto done;
    if (RAND_priv_bytes(context_seed, sizeof(context_seed)) != 1) {
        status = SV2_CREDENTIALS_ERROR_RANDOM_FAILURE;
        goto done;
    }
    if (secp256k1_context_randomize(context, context_seed) != 1)
        goto done;
    *context_out = context;
    context = NULL;
    status = SV2_CREDENTIALS_OK;

done:
    if (context != NULL)
        secp256k1_context_destroy(context);
    OPENSSL_cleanse(context_seed, sizeof(context_seed));
    return status;
}

static sv2_credentials_status generate_secret(
    const secp256k1_context *context,
    uint8_t secret[SV2_NOISE_SECRET_KEY_SIZE]) {
    size_t attempt;

    for (attempt = 0u; attempt < SV2_CREDENTIALS_RANDOM_ATTEMPTS; ++attempt) {
        if (RAND_priv_bytes(secret, SV2_NOISE_SECRET_KEY_SIZE) != 1)
            return SV2_CREDENTIALS_ERROR_RANDOM_FAILURE;
        if (secp256k1_ec_seckey_verify(context, secret) == 1)
            return SV2_CREDENTIALS_OK;
    }
    OPENSSL_cleanse(secret, SV2_NOISE_SECRET_KEY_SIZE);
    return SV2_CREDENTIALS_ERROR_RANDOM_FAILURE;
}

static sv2_credentials_status derive_xonly_public_key(
    const secp256k1_context *context,
    const uint8_t secret[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t public_key[SV2_NOISE_PUBLIC_KEY_SIZE]) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey xonly_public_key;
    sv2_credentials_status status = SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;

    memset(&keypair, 0, sizeof(keypair));
    if (secp256k1_ec_seckey_verify(context, secret) != 1) {
        status = SV2_CREDENTIALS_ERROR_INVALID_SECRET;
        goto done;
    }
    if (secp256k1_keypair_create(context, &keypair, secret) != 1)
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
    status = SV2_CREDENTIALS_OK;

done:
    OPENSSL_cleanse(&keypair, sizeof(keypair));
    return status;
}

static sv2_credentials_status validate_xonly_public_key(
    const uint8_t public_key[SV2_NOISE_PUBLIC_KEY_SIZE]) {
    secp256k1_context *context;
    secp256k1_xonly_pubkey parsed_public_key;
    sv2_credentials_status status;

    context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (context == NULL)
        return SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;
    status = secp256k1_xonly_pubkey_parse(
            context,
            &parsed_public_key,
            public_key) == 1
        ? SV2_CREDENTIALS_OK
        : SV2_CREDENTIALS_ERROR_INVALID_PUBLIC_KEY;
    secp256k1_context_destroy(context);
    return status;
}

static bool sha256(
    const uint8_t *data,
    size_t data_size,
    uint8_t output[SV2_CREDENTIALS_HASH_SIZE]) {
    unsigned int output_size = 0u;

    if (EVP_Digest(
            data,
            data_size,
            output,
            &output_size,
            EVP_sha256(),
            NULL) != 1 ||
        output_size != SV2_CREDENTIALS_HASH_SIZE) {
        OPENSSL_cleanse(output, SV2_CREDENTIALS_HASH_SIZE);
        return false;
    }
    return true;
}

static bool encode_base58(
    const uint8_t *data,
    size_t data_size,
    char *output,
    size_t output_capacity) {
    static const char kAlphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t digits[SV2_CREDENTIALS_AUTHORITY_KEY_TEXT_CAPACITY - 1u];
    size_t leading_zero_count = 0u;
    size_t digit_count = 0u;
    size_t input_index;
    size_t output_size;

    memset(digits, 0, sizeof(digits));
    while (leading_zero_count < data_size &&
           data[leading_zero_count] == 0u)
        ++leading_zero_count;

    for (input_index = leading_zero_count; input_index < data_size; ++input_index) {
        uint32_t carry = data[input_index];
        size_t digit_index;

        for (digit_index = 0u; digit_index < digit_count; ++digit_index) {
            carry += (uint32_t)digits[digit_index] << 8u;
            digits[digit_index] = (uint8_t)(carry % 58u);
            carry /= 58u;
        }
        while (carry != 0u) {
            if (digit_count >= sizeof(digits))
                return false;
            digits[digit_count] = (uint8_t)(carry % 58u);
            ++digit_count;
            carry /= 58u;
        }
    }

    output_size = leading_zero_count + digit_count;
    if (output_size >= output_capacity)
        return false;
    memset(output, '1', leading_zero_count);
    for (input_index = 0u; input_index < digit_count; ++input_index) {
        output[leading_zero_count + input_index] =
            kAlphabet[digits[digit_count - input_index - 1u]];
    }
    output[output_size] = '\0';
    return true;
}

static bool hash_certificate(
    const uint8_t certificate[SV2_NOISE_CERTIFICATE_SIZE],
    const uint8_t server_public[SV2_NOISE_PUBLIC_KEY_SIZE],
    uint8_t output[SV2_CREDENTIALS_HASH_SIZE]) {
    uint8_t signed_fields[SV2_CREDENTIALS_CERTIFICATE_SIGNED_SIZE];
    bool success;

    memcpy(
        signed_fields,
        certificate,
        SV2_CREDENTIALS_CERTIFICATE_FIELDS_SIZE);
    memcpy(
        signed_fields + SV2_CREDENTIALS_CERTIFICATE_FIELDS_SIZE,
        server_public,
        SV2_NOISE_PUBLIC_KEY_SIZE);
    success = sha256(signed_fields, sizeof(signed_fields), output);
    OPENSSL_cleanse(signed_fields, sizeof(signed_fields));
    return success;
}

const char *sv2_credentials_status_string(sv2_credentials_status status) {
    switch (status) {
    case SV2_CREDENTIALS_OK:
        return "success";
    case SV2_CREDENTIALS_ERROR_INVALID_ARGUMENT:
        return "invalid argument";
    case SV2_CREDENTIALS_ERROR_INVALID_VALIDITY:
        return "valid_from must be earlier than not_valid_after";
    case SV2_CREDENTIALS_ERROR_INPUT_NOT_FOUND:
        return "input file not found";
    case SV2_CREDENTIALS_ERROR_INPUT_NOT_REGULAR:
        return "input is not a regular file";
    case SV2_CREDENTIALS_ERROR_INPUT_WRONG_SIZE:
        return "input file has the wrong size";
    case SV2_CREDENTIALS_ERROR_SECRET_PERMISSIONS:
        return "secret file must not grant group or other permissions";
    case SV2_CREDENTIALS_ERROR_INVALID_SECRET:
        return "invalid secp256k1 secret key";
    case SV2_CREDENTIALS_ERROR_INVALID_PUBLIC_KEY:
        return "invalid x-only secp256k1 public key";
    case SV2_CREDENTIALS_ERROR_KEY_REUSE:
        return "authority and server keys must be different";
    case SV2_CREDENTIALS_ERROR_OUTPUT_EXISTS:
        return "refusing to overwrite an existing output";
    case SV2_CREDENTIALS_ERROR_OUT_OF_MEMORY:
        return "out of memory";
    case SV2_CREDENTIALS_ERROR_RANDOM_FAILURE:
        return "random number generation failed";
    case SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE:
        return "cryptographic operation failed";
    case SV2_CREDENTIALS_ERROR_IO:
        return "file operation failed";
    default:
        return "unknown error";
    }
}

sv2_credentials_status sv2_credentials_format_authority_key(
    const char *public_path,
    char *output,
    size_t output_capacity) {
    uint8_t public_key[SV2_NOISE_PUBLIC_KEY_SIZE];
    uint8_t base58_input[SV2_CREDENTIALS_BASE58_INPUT_SIZE];
    uint8_t first_hash[SV2_CREDENTIALS_HASH_SIZE];
    uint8_t second_hash[SV2_CREDENTIALS_HASH_SIZE];
    sv2_credentials_status status;

    if (!is_valid_path(public_path) ||
        output == NULL ||
        output_capacity < SV2_CREDENTIALS_AUTHORITY_KEY_TEXT_CAPACITY)
        return SV2_CREDENTIALS_ERROR_INVALID_ARGUMENT;
    output[0] = '\0';
    memset(public_key, 0, sizeof(public_key));
    memset(base58_input, 0, sizeof(base58_input));
    memset(first_hash, 0, sizeof(first_hash));
    memset(second_hash, 0, sizeof(second_hash));

    status = read_exact_file(
        public_path,
        public_key,
        sizeof(public_key),
        false);
    if (status != SV2_CREDENTIALS_OK)
        goto done;
    status = validate_xonly_public_key(public_key);
    if (status != SV2_CREDENTIALS_OK)
        goto done;

    store_little_endian_u16(base58_input, 1u);
    memcpy(
        base58_input + SV2_CREDENTIALS_AUTHORITY_KEY_VERSION_SIZE,
        public_key,
        sizeof(public_key));
    if (!sha256(
            base58_input,
            SV2_CREDENTIALS_AUTHORITY_KEY_PAYLOAD_SIZE,
            first_hash) ||
        !sha256(first_hash, sizeof(first_hash), second_hash)) {
        status = SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    memcpy(
        base58_input + SV2_CREDENTIALS_AUTHORITY_KEY_PAYLOAD_SIZE,
        second_hash,
        SV2_CREDENTIALS_BASE58_CHECKSUM_SIZE);
    if (!encode_base58(
            base58_input,
            sizeof(base58_input),
            output,
            output_capacity)) {
        status = SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    status = SV2_CREDENTIALS_OK;

done:
    OPENSSL_cleanse(public_key, sizeof(public_key));
    OPENSSL_cleanse(base58_input, sizeof(base58_input));
    OPENSSL_cleanse(first_hash, sizeof(first_hash));
    OPENSSL_cleanse(second_hash, sizeof(second_hash));
    return status;
}

sv2_credentials_status sv2_credentials_keypair(
    const char *secret_path,
    const char *public_path) {
    secp256k1_context *context = NULL;
    uint8_t secret[SV2_NOISE_SECRET_KEY_SIZE];
    uint8_t public_key[SV2_NOISE_PUBLIC_KEY_SIZE];
    sv2_credentials_status status;
    bool generated_secret = false;
    bool created_secret = false;

    if (!is_valid_path(secret_path) ||
        !is_valid_path(public_path) ||
        strcmp(secret_path, public_path) == 0)
        return SV2_CREDENTIALS_ERROR_INVALID_ARGUMENT;

    status = check_output_path(public_path);
    if (status != SV2_CREDENTIALS_OK)
        return status;
    memset(secret, 0, sizeof(secret));
    memset(public_key, 0, sizeof(public_key));
    status = create_secp_context(&context);
    if (status != SV2_CREDENTIALS_OK)
        goto done;

    status = read_exact_file(secret_path, secret, sizeof(secret), true);
    if (status == SV2_CREDENTIALS_ERROR_INPUT_NOT_FOUND) {
        status = generate_secret(context, secret);
        if (status != SV2_CREDENTIALS_OK)
            goto done;
        generated_secret = true;
    } else if (status != SV2_CREDENTIALS_OK) {
        goto done;
    }
    status = derive_xonly_public_key(context, secret, public_key);
    if (status != SV2_CREDENTIALS_OK)
        goto done;

    if (generated_secret) {
        status = write_new_file(
            secret_path,
            secret,
            sizeof(secret),
            S_IRUSR | S_IWUSR);
        if (status != SV2_CREDENTIALS_OK)
            goto done;
        created_secret = true;
    }
    status = write_new_file(
        public_path,
        public_key,
        sizeof(public_key),
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

done:
    if (status != SV2_CREDENTIALS_OK && created_secret)
        unlink(secret_path);
    if (context != NULL)
        secp256k1_context_destroy(context);
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(public_key, sizeof(public_key));
    return status;
}

sv2_credentials_status sv2_credentials_issue(
    const char *authority_secret_path,
    const char *server_public_path,
    const char *authority_public_path,
    const char *certificate_path,
    uint32_t valid_from,
    uint32_t not_valid_after) {
    secp256k1_context *context = NULL;
    secp256k1_keypair authority_keypair;
    secp256k1_xonly_pubkey parsed_server_public;
    secp256k1_xonly_pubkey parsed_authority_public;
    uint8_t authority_secret[SV2_NOISE_SECRET_KEY_SIZE];
    uint8_t authority_public[SV2_NOISE_PUBLIC_KEY_SIZE];
    uint8_t server_public[SV2_NOISE_PUBLIC_KEY_SIZE];
    uint8_t certificate[SV2_NOISE_CERTIFICATE_SIZE];
    uint8_t digest[SV2_CREDENTIALS_HASH_SIZE];
    uint8_t signature_randomness[SV2_NOISE_SECRET_KEY_SIZE];
    sv2_credentials_status status;
    bool created_authority_public = false;

    if (!is_valid_path(authority_secret_path) ||
        !is_valid_path(server_public_path) ||
        !is_valid_path(authority_public_path) ||
        !is_valid_path(certificate_path) ||
        strcmp(authority_secret_path, authority_public_path) == 0 ||
        strcmp(authority_secret_path, certificate_path) == 0 ||
        strcmp(server_public_path, authority_public_path) == 0 ||
        strcmp(server_public_path, certificate_path) == 0 ||
        strcmp(authority_public_path, certificate_path) == 0)
        return SV2_CREDENTIALS_ERROR_INVALID_ARGUMENT;
    if (valid_from >= not_valid_after)
        return SV2_CREDENTIALS_ERROR_INVALID_VALIDITY;

    status = check_output_path(authority_public_path);
    if (status != SV2_CREDENTIALS_OK)
        return status;
    status = check_output_path(certificate_path);
    if (status != SV2_CREDENTIALS_OK)
        return status;

    memset(&authority_keypair, 0, sizeof(authority_keypair));
    memset(authority_secret, 0, sizeof(authority_secret));
    memset(authority_public, 0, sizeof(authority_public));
    memset(server_public, 0, sizeof(server_public));
    memset(certificate, 0, sizeof(certificate));
    memset(digest, 0, sizeof(digest));
    memset(signature_randomness, 0, sizeof(signature_randomness));

    status = read_exact_file(
        authority_secret_path,
        authority_secret,
        sizeof(authority_secret),
        true);
    if (status != SV2_CREDENTIALS_OK)
        goto done;
    status = read_exact_file(
        server_public_path,
        server_public,
        sizeof(server_public),
        false);
    if (status != SV2_CREDENTIALS_OK)
        goto done;
    status = create_secp_context(&context);
    if (status != SV2_CREDENTIALS_OK)
        goto done;
    status = derive_xonly_public_key(
        context,
        authority_secret,
        authority_public);
    if (status != SV2_CREDENTIALS_OK)
        goto done;
    if (secp256k1_xonly_pubkey_parse(
            context,
            &parsed_server_public,
            server_public) != 1) {
        status = SV2_CREDENTIALS_ERROR_INVALID_PUBLIC_KEY;
        goto done;
    }
    if (memcmp(authority_public, server_public, sizeof(server_public)) == 0) {
        status = SV2_CREDENTIALS_ERROR_KEY_REUSE;
        goto done;
    }

    store_little_endian_u16(certificate, 0u);
    store_little_endian_u32(
        certificate + SV2_CREDENTIALS_VALID_FROM_OFFSET,
        valid_from);
    store_little_endian_u32(
        certificate + SV2_CREDENTIALS_NOT_VALID_AFTER_OFFSET,
        not_valid_after);
    if (!hash_certificate(certificate, server_public, digest)) {
        status = SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;
        goto done;
    }
    if (RAND_priv_bytes(
            signature_randomness,
            sizeof(signature_randomness)) != 1) {
        status = SV2_CREDENTIALS_ERROR_RANDOM_FAILURE;
        goto done;
    }
    if (secp256k1_keypair_create(
            context,
            &authority_keypair,
            authority_secret) != 1 ||
        secp256k1_schnorrsig_sign32(
            context,
            certificate + SV2_CREDENTIALS_CERTIFICATE_FIELDS_SIZE,
            digest,
            &authority_keypair,
            signature_randomness) != 1 ||
        secp256k1_xonly_pubkey_parse(
            context,
            &parsed_authority_public,
            authority_public) != 1 ||
        secp256k1_schnorrsig_verify(
            context,
            certificate + SV2_CREDENTIALS_CERTIFICATE_FIELDS_SIZE,
            digest,
            sizeof(digest),
            &parsed_authority_public) != 1) {
        status = SV2_CREDENTIALS_ERROR_CRYPTO_FAILURE;
        goto done;
    }

    status = write_new_file(
        authority_public_path,
        authority_public,
        sizeof(authority_public),
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (status != SV2_CREDENTIALS_OK)
        goto done;
    created_authority_public = true;
    status = write_new_file(
        certificate_path,
        certificate,
        sizeof(certificate),
        S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

done:
    if (context != NULL)
        secp256k1_context_destroy(context);
    OPENSSL_cleanse(&authority_keypair, sizeof(authority_keypair));
    OPENSSL_cleanse(authority_secret, sizeof(authority_secret));
    OPENSSL_cleanse(signature_randomness, sizeof(signature_randomness));
    OPENSSL_cleanse(digest, sizeof(digest));
    if (status != SV2_CREDENTIALS_OK && created_authority_public)
        unlink(authority_public_path);
    return status;
}
