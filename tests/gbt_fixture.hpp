#pragma once
// Test helper: build a getblocktemplate "result" object with glz::generic and parse it through the
// production Glaze path (BlockTemplate::from_gbt). The block-template fixtures build their input
// this way so the test suite carries no separate JSON dependency.
#include <string>

#include <glaze/glaze.hpp>

#include "bitcoin/block_template.hpp"

namespace erikslund::test {

// The mutable JSON builder the fixtures use (an object/array tree:
// t["height"] = 170; t["transactions"].get_array().push_back(tx); ...).
using gbt_json = glz::generic;

// Wrap a bare GBT result object in a minimal JSON-RPC envelope (what from_gbt parses).
inline std::string gbt_envelope(const gbt_json& result) {
    return R"({"error":null,"result":)" + glz::write_json(result).value_or("null") + "}";
}

// Parse a GBT result object via the production Glaze path. Throws std::invalid_argument on a
// malformed/hostile template, exactly like BlockTemplate::from_gbt.
inline bitcoin::BlockTemplate from_template(const gbt_json& result) {
    return bitcoin::BlockTemplate::from_gbt(gbt_envelope(result));
}

} // namespace erikslund::test
