#ifndef SV2_NOISE_INTERNAL_H
#define SV2_NOISE_INTERNAL_H

// Test-only deterministic handshake helpers.

#if !defined(SV2_NOISE_TESTING)
#error "sv2_noise_internal.h is available only to the dedicated test build"
#endif

#include "sv2_noise.h"

#ifdef __cplusplus
extern "C" {
#endif

sv2_noise_status sv2_noise_test_responder_handshake(
    const sv2_noise_credentials *credentials,
    uint32_t current_time_unix,
    const uint8_t act1[SV2_NOISE_ACT1_SIZE],
    const uint8_t ephemeral_secret[SV2_NOISE_SECRET_KEY_SIZE],
    const uint8_t ephemeral_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    const uint8_t static_randomness[SV2_NOISE_SECRET_KEY_SIZE],
    uint8_t act2[SV2_NOISE_ACT2_SIZE],
    sv2_noise_session **session_out);

sv2_noise_status sv2_noise_test_set_nonces(
    sv2_noise_session *session,
    uint64_t receive_nonce,
    uint64_t send_nonce);

#ifdef __cplusplus
}
#endif

#endif
