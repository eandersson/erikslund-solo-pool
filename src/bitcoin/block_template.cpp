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

#include "bitcoin/serialize.hpp"
#include "core/errors.hpp"
#include "util/endian.hpp"
#include "util/hex.hpp"
#include "util/merkle.hpp"

namespace erikslund::bitcoin {

// Glaze reflection requires these file-private wire types to have external linkage.
namespace gbt_detail {

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

} // namespace gbt_detail

namespace {

util::Hash256 parse_txid(bool segwit_aware, const std::optional<std::string_view>& txid,
                         const std::optional<std::string_view>& hash) {
    std::string_view id_hex;
    if (txid) {
        id_hex = *txid;
    } else if (segwit_aware) {
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
    return txid_internal;
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

std::optional<int64_t> rpc_error_code(const glz::generic& error) {
    if (!error.is_object() || !error.contains("code") || !error["code"].is_number())
        return std::nullopt;
    return static_cast<int64_t>(error["code"].get<double>());
}

template <typename T>
const T& require_field(const std::optional<T>& field, const char* name) {
    if (!field)
        throw std::invalid_argument(std::string("getblocktemplate missing field: ") + name);
    return *field;
}

} // namespace

BlockTemplate BlockTemplate::from_gbt(const std::string& response_json) {
    gbt_detail::GbtEnvelope envelope;
    // Lenient: ignore the envelope "id" + the GBT fields we don't use.
    constexpr glz::opts opts{.error_on_unknown_keys = false};
    if (const auto ec = glz::read<opts>(envelope, response_json))
        throw std::invalid_argument("getblocktemplate reply is not valid JSON: " +
                                    glz::format_error(ec, response_json));
    if (!envelope.error.is_null())
        throw RpcError(glz::write_json(envelope.error).value_or("getblocktemplate error"),
                       rpc_error_code(envelope.error));
    if (!envelope.result)
        throw std::invalid_argument("getblocktemplate reply has no result");
    const gbt_detail::GbtReply& reply = *envelope.result;

    BlockTemplate block_template;
    block_template.height = require_field(reply.height, "height");
    block_template.version = require_header_u32(require_field(reply.version, "version"), "version");
    block_template.curtime = require_header_u32(require_field(reply.curtime, "curtime"), "curtime");
    block_template.bits_hex = require_field(reply.bits, "bits");
    block_template.bits = util::parse_hex_u32(block_template.bits_hex);
    block_template.coinbase_value = require_field(reply.coinbasevalue, "coinbasevalue");
    block_template.previousblockhash = require_field(reply.previousblockhash, "previousblockhash");
    block_template.coinbase_script_sig_prefix = serialize_height(block_template.height);

    if (reply.rules)
        for (const auto& rule : *reply.rules)
            if (rule.is_string())
                check_mandatory_rule(rule.get<std::string>());

    // Field presence makes the template segwit-aware; only a non-empty value adds the witness
    // commitment and builds a segwit coinbase.
    const bool segwit_aware = reply.default_witness_commitment.has_value();
    if (reply.default_witness_commitment && !reply.default_witness_commitment->empty()) {
        block_template.coinbase_witness = Bytes(32, 0);
        block_template.coinbase_required_outputs.push_back(
            {0, util::from_hex(*reply.default_witness_commitment)});
    }

    if (reply.transactions) {
        const auto& transactions = *reply.transactions;
        if (transactions.size() > std::numeric_limits<uint32_t>::max())
            throw std::invalid_argument("getblocktemplate has too many transactions");
        block_template.txn_count = static_cast<uint32_t>(transactions.size());
        std::vector<util::Hash256> txids;
        txids.reserve(transactions.size());
        size_t total_hex = 0;
        for (const auto& tx : transactions)
            total_hex += require_field(tx.data, "transaction data").size();
        block_template.txn_data.reserve(total_hex / 2);
        for (const auto& tx : transactions) {
            util::from_hex_append(block_template.txn_data,
                                  require_field(tx.data, "transaction data"));
            std::optional<std::string_view> txid;
            std::optional<std::string_view> hash;
            if (tx.txid)
                txid = *tx.txid;
            if (tx.hash)
                hash = *tx.hash;
            txids.push_back(parse_txid(segwit_aware, txid, hash));
        }
        block_template.merkle_branch_internal = util::merkle_branch(txids);
    }
    return block_template;
}

} // namespace erikslund::bitcoin
