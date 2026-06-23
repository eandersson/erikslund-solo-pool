#include "bitcoin/block_template.hpp"

#include <algorithm>
#include <stdexcept>
#include <string_view>

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
    const Bytes internal = util::reversed(util::from_hex(id_hex));
    if (internal.size() != 32)
        throw std::invalid_argument("template txid is not 32 bytes");
    util::Hash256 txid_internal{};
    std::copy(internal.begin(), internal.end(), txid_internal.begin());
    block_template.txids_internal.push_back(txid_internal);
}

void check_mandatory_rule(std::string_view name) {
    if (!name.empty() && name.front() == '!' && name != "!segwit")
        throw std::invalid_argument("unsupported mandatory template rule: " + std::string(name));
}

} // namespace

BlockTemplate BlockTemplate::from_json(const nlohmann::json& result) {
    BlockTemplate block_template;
    block_template.height = result.at("height").get<int64_t>();
    block_template.version = result.at("version").get<uint32_t>();
    block_template.curtime = result.at("curtime").get<uint32_t>();
    block_template.bits_hex = result.at("bits").get<std::string>();
    block_template.bits = util::parse_hex_u32(block_template.bits_hex);
    block_template.coinbase_value = result.at("coinbasevalue").get<uint64_t>();
    block_template.previousblockhash = result.at("previousblockhash").get<std::string>();

    if (const auto rules = result.find("rules"); rules != result.end() && rules->is_array())
        for (const auto& rule : *rules) {
            if (!rule.is_string())
                continue;
            check_mandatory_rule(rule.get_ref<const std::string&>());
        }

    const auto commitment = result.find("default_witness_commitment");
    if (commitment != result.end() && commitment->is_string())
        block_template.witness_commitment = util::from_hex(commitment->get_ref<const std::string&>());

    const auto transactions = result.find("transactions");
    if (transactions != result.end() && transactions->is_array()) {
        block_template.txn_count = static_cast<uint32_t>(transactions->size());
        block_template.txids_internal.reserve(transactions->size());
        // Size the multi-MB blob once to avoid geometric-growth recopies.
        const size_t total_hex = std::ranges::fold_left(
            *transactions, size_t{0}, [](size_t acc, const nlohmann::json& tx) {
                return acc + tx.at("data").get_ref<const std::string&>().size();
            });
        block_template.txn_data.reserve(total_hex / 2);
        for (const auto& tx : *transactions) {
            std::optional<std::string_view> txid;
            std::optional<std::string_view> hash;
            if (const auto it = tx.find("txid"); it != tx.end())
                txid = it->get_ref<const std::string&>();
            if (const auto it = tx.find("hash"); it != tx.end() && it->is_string())
                hash = it->get_ref<const std::string&>();
            append_transaction(block_template, tx.at("data").get_ref<const std::string&>(), txid,
                               hash);
        }
    }
    return block_template;
}

BlockTemplate BlockTemplate::from_simdjson(const simdjson::dom::element& result) {
    // Throw std::invalid_argument with field context (the exception family the refresh loop catches).
    const auto require = [](auto value_result, const char* what) {
        if (value_result.error())
            throw std::invalid_argument(std::string("getblocktemplate field missing/invalid: ") +
                                        what);
        return std::move(value_result).value();
    };

    BlockTemplate block_template;
    block_template.height = require(result["height"].get_int64(), "height");
    block_template.version = static_cast<uint32_t>(require(result["version"].get_int64(), "version"));
    block_template.curtime = static_cast<uint32_t>(require(result["curtime"].get_int64(), "curtime"));
    block_template.bits_hex = std::string(require(result["bits"].get_string(), "bits"));
    block_template.bits = util::parse_hex_u32(block_template.bits_hex);
    block_template.coinbase_value =
        require(result["coinbasevalue"].get_uint64(), "coinbasevalue");
    block_template.previousblockhash =
        std::string(require(result["previousblockhash"].get_string(), "previousblockhash"));

    simdjson::dom::array rules;
    if (!result["rules"].get(rules))
        for (const simdjson::dom::element rule : rules) {
            std::string_view name;
            if (rule.get(name)) // skip non-string entries
                continue;
            check_mandatory_rule(name);
        }

    // Present-and-string gate; an empty string still marks a segwit-aware server (drives the txid gate).
    std::string_view commitment;
    if (!result["default_witness_commitment"].get(commitment))
        block_template.witness_commitment = util::from_hex(commitment);

    simdjson::dom::array transactions;
    if (!result["transactions"].get(transactions)) {
        block_template.txn_count = static_cast<uint32_t>(transactions.size());
        block_template.txids_internal.reserve(transactions.size());
        size_t total_hex = 0;
        for (const simdjson::dom::element tx : transactions)
            total_hex += require(tx["data"].get_string(), "transaction data").size();
        block_template.txn_data.reserve(total_hex / 2);
        for (const simdjson::dom::element tx : transactions) {
            std::optional<std::string_view> txid;
            std::optional<std::string_view> hash;
            std::string_view value;
            if (!tx["txid"].get(value))
                txid = value;
            if (!tx["hash"].get(value))
                hash = value;
            append_transaction(block_template,
                               require(tx["data"].get_string(), "transaction data"), txid, hash);
        }
    }
    return block_template;
}

} // namespace erikslund::bitcoin
