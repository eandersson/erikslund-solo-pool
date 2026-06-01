#include <doctest/doctest.h>

#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "bitcoin/block_template.hpp"
#include "util/endian.hpp" // reversed
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using namespace erikslund::util;

namespace {
nlohmann::json minimal_template() {
    nlohmann::json t;
    t["height"] = 170;
    t["version"] = 0x20000000;
    t["curtime"] = 1700000000;
    t["bits"] = "1d00ffff";
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, 'a');
    t["transactions"] = nlohmann::json::array();
    return t;
}
} // namespace

TEST_CASE("from_json parses the scalar header fields") {
    const auto tmpl = BlockTemplate::from_json(minimal_template());
    CHECK(tmpl.height == 170);
    CHECK(tmpl.version == 0x20000000u);
    CHECK(tmpl.curtime == 1700000000u);
    CHECK(tmpl.bits_hex == "1d00ffff");
    CHECK(tmpl.bits == 0x1d00ffffu); // parsed base-16 from bits_hex
    CHECK(tmpl.coinbase_value == 5000000000ULL);
    CHECK(tmpl.previousblockhash == std::string(64, 'a'));
}

TEST_CASE("witness_commitment is optional") {
    // Absent in a minimal (pre-segwit-style) template.
    CHECK_FALSE(BlockTemplate::from_json(minimal_template()).witness_commitment.has_value());

    // Present and hex-decoded when supplied.
    nlohmann::json t = minimal_template();
    t["default_witness_commitment"] = "6a24aa21a9ed" + std::string(64, '0');
    const auto tmpl = BlockTemplate::from_json(t);
    REQUIRE(tmpl.witness_commitment.has_value());
    CHECK(to_hex(*tmpl.witness_commitment) == "6a24aa21a9ed" + std::string(64, '0'));
}

TEST_CASE("a mandatory ('!'-prefixed) template rule other than !segwit is refused") {
    // BIP9: getblocktemplate prefixes a rule with '!' when the miner MUST understand it to build
    // a valid block. We only understand segwit, so refuse anything else rather than mine a block
    // we may have assembled wrong (the refresh loop keeps the last good template).
    nlohmann::json t = minimal_template();
    t["rules"] = nlohmann::json::array({"!unknownfork"});
    CHECK_THROWS_AS(BlockTemplate::from_json(t), std::invalid_argument);
}

TEST_CASE("known and non-mandatory template rules are accepted") {
    // '!segwit' (mandatory, understood), plain 'segwit', and a non-'!' rule ('csv') all build.
    nlohmann::json t = minimal_template();
    t["rules"] = nlohmann::json::array({"segwit", "!segwit", "csv"});
    CHECK_NOTHROW(BlockTemplate::from_json(t));
}

TEST_CASE("a non-string entry in the rules array is skipped, not crashed on") {
    nlohmann::json ok = minimal_template();
    ok["rules"] = nlohmann::json::array({123, "!segwit"}); // 123 skipped; !segwit allowed
    CHECK_NOTHROW(BlockTemplate::from_json(ok));

    nlohmann::json bad = minimal_template();
    bad["rules"] = nlohmann::json::array({123, "!unknownfork"}); // skip 123, still catch the bad rule
    CHECK_THROWS_AS(BlockTemplate::from_json(bad), std::invalid_argument);
}

TEST_CASE("transactions are parsed with txid stored in internal (reversed) byte order") {
    nlohmann::json t = minimal_template();
    nlohmann::json tx;
    tx["data"] = "0123456789abcdef";
    // A display txid; the template stores its reverse internally.
    tx["txid"] = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    t["transactions"].push_back(tx);

    const auto tmpl = BlockTemplate::from_json(t);
    REQUIRE(tmpl.txn_count == 1);
    REQUIRE(tmpl.txids_internal.size() == 1);
    CHECK(to_hex(tmpl.txn_data) == "0123456789abcdef");
    // Internal txid == reversed display txid.
    const std::string internal_hex =
        to_hex(Bytes(tmpl.txids_internal[0].begin(), tmpl.txids_internal[0].end()));
    CHECK(internal_hex == to_hex(reversed(from_hex(
                              "00112233445566778899aabbccddeeff"
                              "00112233445566778899aabbccddeeff"))));
}

TEST_CASE("a transaction without txid falls back to 'hash' ONLY on a pre-segwit template") {
    // No witness commitment -> pre-segwit GBT server, where hash == txid by definition.
    nlohmann::json t = minimal_template();
    nlohmann::json tx;
    tx["data"] = "abcd";
    tx["hash"] = std::string(64, '3'); // no "txid" key
    t["transactions"].push_back(tx);

    const auto tmpl = BlockTemplate::from_json(t);
    REQUIRE(tmpl.txids_internal.size() == 1);
    const std::string internal_hex =
        to_hex(Bytes(tmpl.txids_internal[0].begin(), tmpl.txids_internal[0].end()));
    CHECK(internal_hex == to_hex(reversed(from_hex(std::string(64, '3')))));
}

TEST_CASE("a segwit template transaction without txid is rejected (no wtxid fallback)") {
    nlohmann::json t = minimal_template();
    t["default_witness_commitment"] = "6a24aa21a9ed" + std::string(64, '0');
    nlohmann::json tx;
    tx["data"] = "abcd";
    tx["hash"] = std::string(64, '3'); // no "txid" key on a segwit template
    t["transactions"].push_back(tx);
    CHECK_THROWS_AS(BlockTemplate::from_json(t), std::invalid_argument);

    // The same segwit template WITH txid parses fine (txid preferred over hash).
    t["transactions"][0]["txid"] = std::string(64, '4');
    const auto tmpl = BlockTemplate::from_json(t);
    REQUIRE(tmpl.txids_internal.size() == 1);
    const std::string internal_hex =
        to_hex(Bytes(tmpl.txids_internal[0].begin(), tmpl.txids_internal[0].end()));
    CHECK(internal_hex == to_hex(reversed(from_hex(std::string(64, '4')))));
}

TEST_CASE("multiple transactions preserve order") {
    nlohmann::json t = minimal_template();
    for (int i = 1; i <= 3; ++i) {
        nlohmann::json tx;
        tx["data"] = "0" + std::to_string(i); // "01","02","03"
        tx["txid"] = std::string(64, static_cast<char>('0' + i));
        t["transactions"].push_back(tx);
    }
    const auto tmpl = BlockTemplate::from_json(t);
    REQUIRE(tmpl.txn_count == 3);
    CHECK(to_hex(tmpl.txn_data) == "010203"); // concatenated in template order
    REQUIRE(tmpl.txids_internal.size() == 3);
}

TEST_CASE("a non-32-byte txid is rejected") {
    nlohmann::json t = minimal_template();
    nlohmann::json tx;
    tx["data"] = "abcd";
    tx["txid"] = "00112233"; // 4 bytes, not 32
    t["transactions"].push_back(tx);
    CHECK_THROWS_AS(BlockTemplate::from_json(t), std::invalid_argument);
}

TEST_CASE("missing required fields throw") {
    // Dropping any of the required keys makes nlohmann::json::at throw.
    for (const char* key :
         {"height", "version", "curtime", "bits", "coinbasevalue", "previousblockhash"}) {
        nlohmann::json t = minimal_template();
        t.erase(key);
        CHECK_THROWS(BlockTemplate::from_json(t));
    }
}

TEST_CASE("an omitted transactions array yields zero transactions") {
    nlohmann::json t = minimal_template();
    t.erase("transactions");
    const auto tmpl = BlockTemplate::from_json(t);
    CHECK(tmpl.txn_count == 0);
    CHECK(tmpl.txn_data.empty());
    CHECK(tmpl.txids_internal.empty());
}

// Cross-parser equivalence: from_simdjson (production GBT path) must match from_json field for
// field for every template shape -- a divergence is a silent invalid-block risk.
namespace {
BlockTemplate parse_with_simdjson(const std::string& json_text) {
    static simdjson::dom::parser parser;
    return BlockTemplate::from_simdjson(parser.parse(json_text));
}

void check_equal(const BlockTemplate& a, const BlockTemplate& b) {
    CHECK(a.height == b.height);
    CHECK(a.version == b.version);
    CHECK(a.curtime == b.curtime);
    CHECK(a.bits == b.bits);
    CHECK(a.bits_hex == b.bits_hex);
    CHECK(a.coinbase_value == b.coinbase_value);
    CHECK(a.previousblockhash == b.previousblockhash);
    CHECK(a.witness_commitment.has_value() == b.witness_commitment.has_value());
    if (a.witness_commitment && b.witness_commitment)
        CHECK(to_hex(*a.witness_commitment) == to_hex(*b.witness_commitment));
    CHECK(a.txn_count == b.txn_count);
    CHECK(to_hex(a.txn_data) == to_hex(b.txn_data));
    REQUIRE(a.txids_internal.size() == b.txids_internal.size());
    for (size_t i = 0; i < a.txids_internal.size(); ++i)
        CHECK(to_hex(Bytes(a.txids_internal[i].begin(), a.txids_internal[i].end())) ==
              to_hex(Bytes(b.txids_internal[i].begin(), b.txids_internal[i].end())));
}
} // namespace

TEST_CASE("from_simdjson and from_json parse a representative template identically") {
    nlohmann::json t = minimal_template();
    t["rules"] = nlohmann::json::array({"csv", "segwit", "!segwit"});
    t["default_witness_commitment"] = "6a24aa21a9ed" + std::string(64, '0');
    for (int i = 1; i <= 3; ++i) {
        nlohmann::json tx;
        tx["data"] = std::string(8, static_cast<char>('0' + i)); // "11111111", ...
        tx["txid"] = std::string(64, static_cast<char>('0' + i));
        tx["hash"] = std::string(64, 'f'); // wtxid: present but must be ignored (txid preferred)
        t["transactions"].push_back(tx);
    }
    const std::string text = t.dump();
    check_equal(BlockTemplate::from_json(nlohmann::json::parse(text)), parse_with_simdjson(text));
}

TEST_CASE("from_simdjson and from_json agree on a pre-segwit hash-fallback template") {
    nlohmann::json t = minimal_template();
    nlohmann::json tx;
    tx["data"] = "abcd";
    tx["hash"] = std::string(64, '3'); // no txid; pre-segwit -> hash IS the txid
    t["transactions"].push_back(tx);
    const std::string text = t.dump();
    check_equal(BlockTemplate::from_json(nlohmann::json::parse(text)), parse_with_simdjson(text));
}

TEST_CASE("from_simdjson rejects the same hostile templates as from_json") {
    // Mandatory unknown rule.
    nlohmann::json bad_rule = minimal_template();
    bad_rule["rules"] = nlohmann::json::array({"!unknownfork"});
    CHECK_THROWS_AS(parse_with_simdjson(bad_rule.dump()), std::invalid_argument);

    // Segwit template transaction without txid (no wtxid fallback).
    nlohmann::json no_txid = minimal_template();
    no_txid["default_witness_commitment"] = "6a24aa21a9ed" + std::string(64, '0');
    nlohmann::json tx;
    tx["data"] = "abcd";
    tx["hash"] = std::string(64, '3');
    no_txid["transactions"].push_back(tx);
    CHECK_THROWS_AS(parse_with_simdjson(no_txid.dump()), std::invalid_argument);

    // Wrong-length txid.
    nlohmann::json short_txid = minimal_template();
    nlohmann::json tx2;
    tx2["data"] = "abcd";
    tx2["txid"] = "00112233";
    short_txid["transactions"].push_back(tx2);
    CHECK_THROWS_AS(parse_with_simdjson(short_txid.dump()), std::invalid_argument);

    // Missing required scalar.
    nlohmann::json no_bits = minimal_template();
    no_bits.erase("bits");
    CHECK_THROWS_AS(parse_with_simdjson(no_bits.dump()), std::invalid_argument);

    // An empty-string commitment still marks a segwit-aware server (blocks the hash fallback).
    nlohmann::json empty_commitment = minimal_template();
    empty_commitment["default_witness_commitment"] = "";
    nlohmann::json tx3;
    tx3["data"] = "abcd";
    tx3["hash"] = std::string(64, '3');
    empty_commitment["transactions"].push_back(tx3);
    CHECK_THROWS_AS(parse_with_simdjson(empty_commitment.dump()), std::invalid_argument);
    CHECK_THROWS_AS(BlockTemplate::from_json(empty_commitment), std::invalid_argument);
}
