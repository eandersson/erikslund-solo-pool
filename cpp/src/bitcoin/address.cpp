#include "bitcoin/address.hpp"

#include <stdexcept>
#include <string>

#include "util/base58.hpp"
#include "util/bech32.hpp"

namespace erikslund::bitcoin {

namespace {

struct Base58Versions {
    uint8_t p2pkh;
    uint8_t p2sh;
};

Base58Versions base58_versions(Network network) {
    if (network == Network::Mainnet)
        return {0x00, 0x05};
    return {0x6f, 0xc4}; // testnet, regtest and signet share the testnet prefixes
}

std::string_view bech32_hrp(Network network) {
    switch (network) {
    case Network::Mainnet:
        return "bc";
    case Network::Regtest:
        return "bcrt";
    case Network::Testnet:
    case Network::Signet:
        return "tb";
    }
    return "bc";
}

Bytes p2pkh_script(const Bytes& hash160) {
    Bytes script{0x76, 0xa9, 0x14};
    append(script, hash160);
    script.push_back(0x88);
    script.push_back(0xac);
    return script;
}

Bytes p2sh_script(const Bytes& hash160) {
    Bytes script{0xa9, 0x14};
    append(script, hash160);
    script.push_back(0x87);
    return script;
}

Bytes witness_script(int version, const Bytes& program) {
    Bytes script;
    script.push_back(version == 0 ? uint8_t(0x00) : uint8_t(0x50 + version));
    script.push_back(uint8_t(program.size()));
    append(script, program);
    return script;
}

} // namespace

Bytes address_to_script(std::string_view address, Network net) {
    if (auto witness = util::segwit_address_decode(bech32_hrp(net), address))
        return witness_script(witness->version, witness->program);

    try {
        const Bytes payload = util::base58check_decode(address);
        if (payload.size() == 21) {
            const uint8_t version = payload[0];
            const Bytes hash160(payload.begin() + 1, payload.end());
            const auto versions = base58_versions(net);
            if (version == versions.p2pkh)
                return p2pkh_script(hash160);
            if (version == versions.p2sh)
                return p2sh_script(hash160);
        }
    } catch (const std::invalid_argument&) {  // NOLINT(bugprone-empty-catch): deliberate
        // Not base58check; fall through to the unified error.
    }

    throw std::invalid_argument("address: unrecognized or wrong-network address '" +
                                std::string(address) + "'");
}

} // namespace erikslund::bitcoin
