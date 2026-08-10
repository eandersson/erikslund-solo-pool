#pragma once
// SHA-256 / double-SHA-256, backed by Bitcoin Core's vendored crypto (runtime-selected SIMD/SHA-NI).
#include <array>
#include <cstdint>
#include <span>

namespace erikslund::util {

using Hash256 = std::array<uint8_t, 32>;

Hash256 sha256(std::span<const uint8_t> data);
Hash256 sha256d(std::span<const uint8_t> data); // SHA256(SHA256(data))

// Select backend + run Core's self-test; returns backend name. Idempotent (hashing auto-inits too).
// Call at startup so it completes before worker threads.
const char* sha256_init();

const char* sha256_backend();

} // namespace erikslund::util
