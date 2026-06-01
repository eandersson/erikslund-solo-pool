#pragma once
// A single bitcoind JSON-RPC endpoint (primary or failover).
#include <string>

namespace erikslund::bitcoin {

struct RpcEndpoint {
    std::string url;
    std::string user;
    std::string password;
};

} // namespace erikslund::bitcoin
