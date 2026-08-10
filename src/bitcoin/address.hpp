#pragma once
// Decode a Bitcoin address (P2PKH/P2SH/P2WPKH/P2WSH/P2TR) into a coinbase scriptPubKey.
#include <expected>
#include <string_view>

#include "bitcoin/network.hpp"
#include "util/bytes.hpp"

namespace erikslund::bitcoin {

enum class AddressError { UnrecognizedOrWrongNetwork };

[[nodiscard]] std::expected<Bytes, AddressError> address_to_script(std::string_view address,
                                                                   Network network);

} // namespace erikslund::bitcoin
