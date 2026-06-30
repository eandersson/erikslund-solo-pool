#include "bitcoin/block_template.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <glaze/glaze.hpp>

#include "core/errors.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"

namespace erikslund::bitcoin {

namespace {

void append_transaction(BlockTemplate& block_template, std::string_view data_hex,
                        const std::optional<std::string_view>& txid,
                        const std::optional<std::string_view>& hash) {
    util::from_hex_append(block_template.txn_data, data_hex);

    std::string_view id_hex;
    if (txid) {
        id_hex = *txid;
    } else if (block_template.witness_commitment) {
        throw std::invalid_argument(
            "segwit template transaction missing txid (refusing wtxid fallback)");
    } else if (hash) {
        id_hex = *hash;
    } else {
        throw std::invalid_argument("template transaction has neither txid nor hash");
    }
    util::Hash256 txid_internal{};
    if (!util::from_hex_into(txid_internal, id_hex))
        throw std::invalid_argument("template txid is not a 32-byte hex string");
    std::ranges::reverse(txid_internal);
    block_template.txids_internal.push_back(txid_internal);
}

void check_mandatory_rule(std::string_view name) {
    if (!name.empty() && name.front() == '!' && name != "!segwit")
        throw std::invalid_argument("unsupported mandatory template rule: " + std::string(name));
}

uint32_t require_header_u32(int64_t value, const char* field) {
    if (value < 0 || value > std::numeric_limits<uint32_t>::max())
        throw std::invalid_argument(std::string("getblocktemplate ") + field +
                                    " out of uint32 range");
    return static_cast<uint32_t>(value);
}

struct GbtTransaction {
    std::optional<std::string> data;
    std::optional<std::string> txid;
    std::optional<std::string> hash;
};

struct GbtReply {
    std::optional<int64_t> height;
    std::optional<int64_t> version;
    std::optional<int64_t> curtime;
    std::optional<std::string> bits;
    std::optional<uint64_t> coinbasevalue;
    std::optional<std::string> previousblockhash;
    std::optional<std::vector<glz::generic>> rules;
    std::optional<std::string> default_witness_commitment;
    std::optional<std::vector<GbtTransaction>> transactions;
};

struct GbtEnvelope {
    std::optional<GbtReply> result;
    glz::generic error; // null when the call succeeded
};

template <typename T>
const T& require_field(const std::optional<T>& field, const char* name) {
    if (!field)
        throw std::invalid_argument(std::string("getblocktemplate missing field: ") + name);
    return *field;
}

} // namespace

BlockTemplate BlockTemplate::from_gbt(const std::string& response_json) {
    GbtEnvelope envelope;
    // Lenient: ignore the envelope "id" + the GBT fields we don't use.
    constexpr glz::opts opts{.error_on_unknown_keys = false};
    if (const auto ec = glz::read<opts>(envelope, response_json))
        throw std::invalid_argument("getblocktemplate reply is not valid JSON: " +
                                    glz::format_error(ec, response_json));
    if (!envelope.error.is_null())
        throw RpcError(glz::write_json(envelope.error).value_or("getblocktemplate error"));
    if (!envelope.result)
        throw std::invalid_argument("getblocktemplate reply has no result");
    const GbtReply& reply = *envelope.result;

    BlockTemplate block_template;
    block_template.height = require_field(reply.height, "height");
    block_template.version = require_header_u32(require_field(reply.version, "version"), "version");
    block_template.curtime = require_header_u32(require_field(reply.curtime, "curtime"), "curtime");
    block_template.bits_hex = require_field(reply.bits, "bits");
    block_template.bits = util::parse_hex_u32(block_template.bits_hex);
    block_template.coinbase_value = require_field(reply.coinbasevalue, "coinbasevalue");
    block_template.previousblockhash = require_field(reply.previousblockhash, "previousblockhash");

    if (reply.rules)
        for (const auto& rule : *reply.rules)
            if (rule.is_string()) // skip non-string entries (parity with the Python pool's isinstance guard)
                check_mandatory_rule(rule.get<std::string>());

    // Present-and-string gate; an empty string still marks a segwit-aware server (drives the txid gate).
    if (reply.default_witness_commitment)
        block_template.witness_commitment = util::from_hex(*reply.default_witness_commitment);

    if (reply.transactions) {
        const auto& transactions = *reply.transactions;
        block_template.txn_count = static_cast<uint32_t>(transactions.size());
        block_template.txids_internal.reserve(transactions.size());
        size_t total_hex = 0;
        for (const auto& tx : transactions)
            total_hex += require_field(tx.data, "transaction data").size();
        block_template.txn_data.reserve(total_hex / 2);
        for (const auto& tx : transactions) {
            std::optional<std::string_view> txid;
            std::optional<std::string_view> hash;
            if (tx.txid)
                txid = *tx.txid;
            if (tx.hash)
                hash = *tx.hash;
            append_transaction(block_template, require_field(tx.data, "transaction data"), txid,
                               hash);
        }
    }
    return block_template;
}

} // namespace erikslund::bitcoin
