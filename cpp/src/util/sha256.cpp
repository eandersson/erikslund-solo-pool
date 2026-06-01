#include "util/sha256.hpp"

#include <string>

#include <crypto/sha256.h> // Bitcoin Core: CSHA256, SHA256AutoDetect, SHA256D64

namespace erikslund::util {

namespace {

// Function-local static => SHA256AutoDetect (installs transform pointers + self-test)
// runs exactly once, thread-safely, even on paths that skip sha256_init().
const std::string& backend() {
    static const std::string name = SHA256AutoDetect();
    return name;
}

} // namespace

const char* sha256_init() { return backend().c_str(); }
const char* sha256_backend() { return backend().c_str(); }

Hash256 sha256(std::span<const uint8_t> data) {
    backend();
    Hash256 out;
    CSHA256().Write(data.data(), data.size()).Finalize(out.data());
    return out;
}

Hash256 sha256d(std::span<const uint8_t> data) {
    backend();
    unsigned char first[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(data.data(), data.size()).Finalize(first);
    Hash256 out;
    CSHA256().Write(first, sizeof(first)).Finalize(out.data());
    return out;
}

} // namespace erikslund::util
