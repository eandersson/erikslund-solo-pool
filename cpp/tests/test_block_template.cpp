#include <doctest/doctest.h>

#include <algorithm>
#include <initializer_list>
#include <stdexcept>
#include <string>
#include <vector>

#include "bitcoin/block_template.hpp"
#include "gbt_fixture.hpp"
#include "util/endian.hpp" // reversed
#include "util/hex.hpp"
#include "util/merkle.hpp"

using namespace erikslund;
using namespace erikslund::bitcoin;
using namespace erikslund::util;
using namespace erikslund::test;

namespace {
gbt_json minimal_template() {
    gbt_json t = gbt_json::object_t{};
    t["height"] = 170;
    t["version"] = 0x20000000;
    t["curtime"] = 1700000000;
    t["bits"] = std::string("1d00ffff");
    t["coinbasevalue"] = 5000000000LL;
    t["previousblockhash"] = std::string(64, 'a');
    t["transactions"] = gbt_json::array_t{};
    return t;
}

// A JSON array of the given string literals.
gbt_json string_array(std::initializer_list<const char*> values) {
    gbt_json out = gbt_json::array_t{};
    for (const char* value : values)
        out.get_array().emplace_back(gbt_json(std::string(value)));
    return out;
}

// Append a transaction object to t["transactions"].
void push_transaction(gbt_json& t, gbt_json tx) {
    t["transactions"].get_array().push_back(std::move(tx));
}
} // namespace

TEST_CASE("from_gbt parses the scalar header fields") {
    const auto tmpl = from_template(minimal_template());
    CHECK(tmpl.height == 170);
    CHECK(tmpl.version == 0x20000000u);
    CHECK(tmpl.curtime == 1700000000u);
    CHECK(tmpl.bits_hex == "1d00ffff");
    CHECK(tmpl.bits == 0x1d00ffffu); // parsed base-16 from bits_hex
    CHECK(tmpl.coinbase_value == 5000000000ULL);
    CHECK(tmpl.previousblockhash == std::string(64, 'a'));
    CHECK(to_hex(tmpl.coinbase_script_sig_prefix) == "02aa00");
}

TEST_CASE("a witness commitment becomes a required output and witness item") {
    // Absent in a minimal (pre-segwit-style) template.
    const auto legacy = from_template(minimal_template());
    CHECK_FALSE(legacy.coinbase_witness.has_value());
    CHECK(legacy.coinbase_required_outputs.empty());

    // GBT supplies the script; the coinbase carries it in a zero-valued output and uses the
    // standard zero reserved value.
    gbt_json t = minimal_template();
    t["default_witness_commitment"] = std::string("6a24aa21a9ed") + std::string(64, '0');
    const auto tmpl = from_template(t);
    REQUIRE(tmpl.coinbase_witness.has_value());
    CHECK(*tmpl.coinbase_witness == Bytes(32, 0));
    REQUIRE(tmpl.coinbase_required_outputs.size() == 1);
    CHECK(tmpl.coinbase_required_outputs.front().value == 0);
    CHECK(to_hex(tmpl.coinbase_required_outputs.front().script) ==
          "6a24aa21a9ed" + std::string(64, '0'));
}

TEST_CASE("empty default_witness_commitment is segwit-aware but builds a legacy coinbase") {
    // Empty "" -> segwit-aware (txid gate armed) but no witness commitment (legacy coinbase), matching
    // Python's has_witness (commitment is not None) vs _segwit_gbt (isinstance str).
    gbt_json t = minimal_template();
    t["default_witness_commitment"] = std::string("");
    const auto tmpl = from_template(t);
    CHECK_FALSE(tmpl.coinbase_witness.has_value());
    CHECK(tmpl.coinbase_required_outputs.empty());

    // A segwit-aware tx carrying only `hash` (a wtxid) must be rejected, not used as a merkle leaf.
    gbt_json tx = gbt_json::object_t{};
    tx["data"] = std::string("00");
    tx["hash"] = std::string(64, 'b');
    push_transaction(t, tx);
    CHECK_THROWS_AS(from_template(t), std::invalid_argument);
}

TEST_CASE("a mandatory ('!'-prefixed) template rule other than !segwit is refused") {
    // BIP9: getblocktemplate prefixes a rule with '!' when the miner MUST understand it to build
    // a valid block. We only understand segwit, so refuse anything else rather than mine a block
    // we may have assembled wrong (the refresh loop keeps the last good template).
    gbt_json t = minimal_template();
    t["rules"] = string_array({"!unknownfork"});
    CHECK_THROWS_AS(from_template(t), std::invalid_argument);
}

TEST_CASE("known and non-mandatory template rules are accepted") {
    // '!segwit' (mandatory, understood), plain 'segwit', and a non-'!' rule ('csv') all build.
    gbt_json t = minimal_template();
    t["rules"] = string_array({"segwit", "!segwit", "csv"});
    CHECK_NOTHROW(from_template(t));
}

TEST_CASE("a non-string entry in the rules array is skipped, not crashed on") {
    // The Python pool skips non-string rules with an isinstance guard; from_gbt matches (a typed
    // vector<string> would reject the whole template). 123 is skipped; the '!' rule still decides.
    gbt_json ok = minimal_template();
    ok["rules"] = gbt_json::array_t{};
    ok["rules"].get_array().push_back(gbt_json(123));
    ok["rules"].get_array().push_back(gbt_json(std::string("!segwit")));
    CHECK_NOTHROW(from_template(ok));

    gbt_json bad = minimal_template();
    bad["rules"] = gbt_json::array_t{};
    bad["rules"].get_array().push_back(gbt_json(123));
    bad["rules"].get_array().push_back(gbt_json(std::string("!unknownfork")));
    CHECK_THROWS_AS(from_template(bad), std::invalid_argument);
}

TEST_CASE("transactions produce a coinbase merkle branch in internal byte order") {
    gbt_json t = minimal_template();
    gbt_json tx = gbt_json::object_t{};
    tx["data"] = std::string("0123456789abcdef");
    // A display txid; the template stores its reverse internally.
    tx["txid"] = std::string("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    push_transaction(t, std::move(tx));

    const auto tmpl = from_template(t);
    REQUIRE(tmpl.txn_count == 1);
    REQUIRE(tmpl.merkle_branch_internal.size() == 1);
    CHECK(to_hex(tmpl.txn_data) == "0123456789abcdef");
    // With one non-coinbase transaction, its internal txid is the only branch node.
    const std::string internal_hex =
        to_hex(Bytes(tmpl.merkle_branch_internal[0].begin(),
                     tmpl.merkle_branch_internal[0].end()));
    CHECK(internal_hex == to_hex(reversed(from_hex(
                              "00112233445566778899aabbccddeeff"
                              "00112233445566778899aabbccddeeff"))));
}

TEST_CASE("a transaction without txid falls back to 'hash' ONLY on a pre-segwit template") {
    // No witness commitment -> pre-segwit GBT server, where hash == txid by definition.
    gbt_json t = minimal_template();
    gbt_json tx = gbt_json::object_t{};
    tx["data"] = std::string("abcd");
    tx["hash"] = std::string(64, '3'); // no "txid" key
    push_transaction(t, std::move(tx));

    const auto tmpl = from_template(t);
    REQUIRE(tmpl.merkle_branch_internal.size() == 1);
    const std::string internal_hex =
        to_hex(Bytes(tmpl.merkle_branch_internal[0].begin(),
                     tmpl.merkle_branch_internal[0].end()));
    CHECK(internal_hex == to_hex(reversed(from_hex(std::string(64, '3')))));
}

TEST_CASE("a segwit template transaction without txid is rejected (no wtxid fallback)") {
    gbt_json t = minimal_template();
    t["default_witness_commitment"] = std::string("6a24aa21a9ed") + std::string(64, '0');
    gbt_json tx = gbt_json::object_t{};
    tx["data"] = std::string("abcd");
    tx["hash"] = std::string(64, '3'); // no "txid" key on a segwit template
    push_transaction(t, std::move(tx));
    CHECK_THROWS_AS(from_template(t), std::invalid_argument);

    // The same segwit template WITH txid parses fine (txid preferred over hash).
    t["transactions"][0]["txid"] = std::string(64, '4');
    const auto tmpl = from_template(t);
    REQUIRE(tmpl.merkle_branch_internal.size() == 1);
    const std::string internal_hex =
        to_hex(Bytes(tmpl.merkle_branch_internal[0].begin(),
                     tmpl.merkle_branch_internal[0].end()));
    CHECK(internal_hex == to_hex(reversed(from_hex(std::string(64, '4')))));
}

TEST_CASE("multiple transactions preserve order") {
    gbt_json t = minimal_template();
    for (int i = 1; i <= 3; ++i) {
        gbt_json tx = gbt_json::object_t{};
        tx["data"] = "0" + std::to_string(i); // "01","02","03"
        tx["txid"] = std::string(64, static_cast<char>('0' + i));
        push_transaction(t, std::move(tx));
    }
    const auto tmpl = from_template(t);
    REQUIRE(tmpl.txn_count == 3);
    CHECK(to_hex(tmpl.txn_data) == "010203"); // concatenated in template order
    REQUIRE(tmpl.merkle_branch_internal.size() == 2);
}

TEST_CASE("a non-32-byte txid is rejected") {
    gbt_json t = minimal_template();
    gbt_json tx = gbt_json::object_t{};
    tx["data"] = std::string("abcd");
    tx["txid"] = std::string("00112233"); // 4 bytes, not 32
    push_transaction(t, std::move(tx));
    CHECK_THROWS_AS(from_template(t), std::invalid_argument);
}

TEST_CASE("missing required fields throw") {
    // from_gbt's require_field turns a missing key into std::invalid_argument.
    for (const char* key :
         {"height", "version", "curtime", "bits", "coinbasevalue", "previousblockhash"}) {
        gbt_json t = minimal_template();
        t.get_object().erase(key);
        CHECK_THROWS_AS(from_template(t), std::invalid_argument);
    }
}

TEST_CASE("an omitted transactions array yields zero transactions") {
    gbt_json t = minimal_template();
    t.get_object().erase("transactions");
    const auto tmpl = from_template(t);
    CHECK(tmpl.txn_count == 0);
    CHECK(tmpl.txn_data.empty());
    CHECK(tmpl.merkle_branch_internal.empty());
}

TEST_CASE("from_gbt parses a representative template across all field types") {
    // Header + rules + witness commitment + a multi-transaction body, parsed via the production
    // Glaze GBT path.
    gbt_json t = minimal_template();
    t["rules"] = string_array({"csv", "segwit", "!segwit"});
    t["default_witness_commitment"] = std::string("6a24aa21a9ed") + std::string(64, '0');
    for (int i = 1; i <= 3; ++i) {
        gbt_json tx = gbt_json::object_t{};
        tx["data"] = std::string(8, static_cast<char>('0' + i)); // "11111111", ...
        tx["txid"] = std::string(64, static_cast<char>('0' + i));
        tx["hash"] = std::string(64, 'f'); // wtxid: present but must be ignored (txid preferred)
        push_transaction(t, std::move(tx));
    }
    const auto tmpl = from_template(t);
    CHECK(tmpl.height == 170);
    CHECK(tmpl.version == 0x20000000u);
    CHECK(tmpl.curtime == 1700000000u);
    CHECK(tmpl.bits_hex == "1d00ffff");
    CHECK(tmpl.coinbase_value == 5000000000ULL);
    CHECK(tmpl.previousblockhash == std::string(64, 'a'));
    REQUIRE(tmpl.coinbase_witness.has_value());
    REQUIRE(tmpl.coinbase_required_outputs.size() == 1);
    CHECK(tmpl.txn_count == 3);
    CHECK(to_hex(tmpl.txn_data) == "111111112222222233333333");
    std::vector<Hash256> expected_txids;
    for (int i = 1; i <= 3; ++i) {
        const Bytes internal =
            reversed(from_hex(std::string(64, static_cast<char>('0' + i))));
        Hash256 hash{};
        std::copy(internal.begin(), internal.end(), hash.begin());
        expected_txids.push_back(hash);
    }
    CHECK(tmpl.merkle_branch_internal == merkle_branch(expected_txids));
}

TEST_CASE("an out-of-uint32-range version/curtime is rejected (not narrowed)") {
    // A malformed/compromised bitcoind could send a header field outside [0, 2^32-1]; silently
    // narrowing it would corrupt the candidate header, so the template must be rejected.
    for (const char* field : {"version", "curtime"}) {
        gbt_json over = minimal_template();
        over[field] = int64_t{0x1'0000'0000}; // 2^32, one past uint32 max
        CHECK_THROWS_AS(from_template(over), std::invalid_argument);

        gbt_json negative = minimal_template();
        negative[field] = int64_t{-1};
        CHECK_THROWS_AS(from_template(negative), std::invalid_argument);
    }
    // Exactly uint32 max is still accepted.
    gbt_json edge = minimal_template();
    edge["version"] = int64_t{0xFFFFFFFF};
    CHECK(from_template(edge).version == 0xFFFFFFFFu);
}

TEST_CASE("from_gbt rejects hostile templates") {
    // Mandatory unknown rule.
    gbt_json bad_rule = minimal_template();
    bad_rule["rules"] = string_array({"!unknownfork"});
    CHECK_THROWS_AS(from_template(bad_rule), std::invalid_argument);

    // Segwit template transaction without txid (no wtxid fallback).
    gbt_json no_txid = minimal_template();
    no_txid["default_witness_commitment"] = std::string("6a24aa21a9ed") + std::string(64, '0');
    gbt_json tx = gbt_json::object_t{};
    tx["data"] = std::string("abcd");
    tx["hash"] = std::string(64, '3');
    push_transaction(no_txid, std::move(tx));
    CHECK_THROWS_AS(from_template(no_txid), std::invalid_argument);

    // Wrong-length txid.
    gbt_json short_txid = minimal_template();
    gbt_json tx2 = gbt_json::object_t{};
    tx2["data"] = std::string("abcd");
    tx2["txid"] = std::string("00112233");
    push_transaction(short_txid, std::move(tx2));
    CHECK_THROWS_AS(from_template(short_txid), std::invalid_argument);

    // Missing required scalar.
    gbt_json no_bits = minimal_template();
    no_bits.get_object().erase("bits");
    CHECK_THROWS_AS(from_template(no_bits), std::invalid_argument);

    // An empty-string commitment still marks a segwit-aware server (blocks the hash fallback).
    gbt_json empty_commitment = minimal_template();
    empty_commitment["default_witness_commitment"] = std::string("");
    gbt_json tx3 = gbt_json::object_t{};
    tx3["data"] = std::string("abcd");
    tx3["hash"] = std::string(64, '3');
    push_transaction(empty_commitment, std::move(tx3));
    CHECK_THROWS_AS(from_template(empty_commitment), std::invalid_argument);
}
