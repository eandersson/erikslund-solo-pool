#pragma once
// Typed exceptions, all deriving from std::runtime_error.
#include <stdexcept>

namespace erikslund {

struct ConfigError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// bitcoind returned a JSON-RPC error object (node is up).
struct RpcError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Couldn't reach bitcoind at all (socket / auth / unparseable body).
struct RpcConnectionError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

} // namespace erikslund
