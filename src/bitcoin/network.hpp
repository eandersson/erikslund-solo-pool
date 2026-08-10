#pragma once
// Bitcoin network selector. Name strings match bitcoind getblockchaininfo "chain".
#include <optional>
#include <string_view>

namespace erikslund::bitcoin {

enum class Network { Mainnet, Testnet, Regtest, Signet };

inline std::optional<Network> network_from_string(std::string_view name) {
    if (name == "main" || name == "mainnet")
        return Network::Mainnet;
    if (name == "test" || name == "testnet" || name == "testnet4")
        return Network::Testnet;
    if (name == "regtest")
        return Network::Regtest;
    if (name == "signet")
        return Network::Signet;
    return std::nullopt;
}

inline std::string_view network_name(Network network) {
    switch (network) {
    case Network::Mainnet:
        return "main";
    case Network::Testnet:
        return "test";
    case Network::Regtest:
        return "regtest";
    case Network::Signet:
        return "signet";
    }
    return "unknown";
}

} // namespace erikslund::bitcoin
