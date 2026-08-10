#include "bitcoin/address.hpp"

#include <expected>

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
        return {.p2pkh = 0x00, .p2sh = 0x05};
    return {.p2pkh = 0x6f, .p2sh = 0xc4}; // testnet, regtest and signet share the testnet prefixes
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

std::expected<Bytes, AddressError> address_to_script(std::string_view address, Network network) {
    if (auto witness = util::segwit_address_decode(bech32_hrp(network), address))
        return witness_script(witness->version, witness->program);

    if (const auto payload = util::try_base58check_decode(address);
        payload && payload->size() == 21) {
        const uint8_t version = (*payload)[0];
        const Bytes hash160(payload->begin() + 1, payload->end());
        const auto versions = base58_versions(network);
        if (version == versions.p2pkh)
            return p2pkh_script(hash160);
        if (version == versions.p2sh)
            return p2sh_script(hash160);
    }

    return std::unexpected(AddressError::UnrecognizedOrWrongNetwork);
}

} // namespace erikslund::bitcoin
