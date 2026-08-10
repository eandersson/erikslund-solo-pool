// WorkSource boundary tests: the RpcWorkSource adapter maps RpcClient replies onto the ChainInfo /
// HeaderFacts / tip primitives with the exact field defaults the pool depended on inline (notably
// confirmations == -1 when absent, which gates fastblock).
#include <doctest/doctest.h>

#include <stdexcept>
#include <string>

#include <glaze/glaze.hpp>

#include "bitcoin/rpc_client.hpp"
#include "bitcoin/work_source_rpc.hpp"
#include "core/errors.hpp"

using namespace erikslund;
using json = glz::generic;

namespace {

// Dispatches call() by the method named in the JSON-RPC payload, returning a canned result generic
// (call_one returns the already-unwrapped result, matching RpcClient::call()).
class CannedRpc : public bitcoin::RpcClient {
public:
    CannedRpc() : RpcClient("http://fake", "u", "p", /*timeout_seconds=*/1) {}
    json header;    // getblockheader result
    json chaininfo; // getblockchaininfo result
    std::string tip = "0000tip";

protected:
    json call_one(const Resolved&, const std::string& payload, long) override {
        if (payload.find("getblockheader") != std::string::npos)
            return header;
        if (payload.find("getblockchaininfo") != std::string::npos)
            return chaininfo;
        if (payload.find("getbestblockhash") != std::string::npos)
            return json(tip);
        throw RpcError("CannedRpc: unexpected method in " + payload);
    }
};

} // namespace

TEST_CASE("RpcWorkSource maps chain info and the tip probe") {
    CannedRpc rpc;
    rpc.chaininfo = json::object_t{};
    rpc.chaininfo["chain"] = std::string("main");
    rpc.chaininfo["blocks"] = 850000.0;
    bitcoin::RpcWorkSource source(rpc);

    const auto info = source.detect_chain();
    CHECK(info.chain == "main");
    CHECK(info.blocks == 850000);
    CHECK(source.get_tip() == "0000tip");
}

TEST_CASE("RpcWorkSource::fetch_header extracts every field the fastblock gate needs") {
    CannedRpc rpc;
    rpc.header = json::object_t{};
    rpc.header["height"] = 849999.0;
    rpc.header["confirmations"] = 1.0;
    rpc.header["bits"] = std::string("170355f0");
    rpc.header["mediantime"] = 1700000000.0;
    bitcoin::RpcWorkSource source(rpc);

    const auto facts = source.fetch_header("somehash");
    CHECK(facts.height == 849999);
    CHECK(facts.confirmations == 1);
    CHECK(facts.bits_hex == "170355f0");
    CHECK(facts.mediantime == 1700000000u);
}

TEST_CASE("RpcWorkSource::fetch_header defaults confirmations to -1 when absent") {
    // The fastblock gate treats confirmations != 1 as "not the active tip". A missing field MUST
    // read -1 (not 0), matching the old inline json_int(header,"confirmations",-1).
    CannedRpc rpc;
    rpc.header = json::object_t{};
    rpc.header["height"] = 849999.0;
    rpc.header["bits"] = std::string("170355f0");
    rpc.header["mediantime"] = 1700000000.0;
    bitcoin::RpcWorkSource source(rpc);

    CHECK(source.fetch_header("h").confirmations == -1);
}

TEST_CASE("RpcWorkSource::fetch_header throws on a required field missing") {
    CannedRpc rpc;
    rpc.header = json::object_t{}; // no height
    bitcoin::RpcWorkSource source(rpc);
    CHECK_THROWS_AS(source.fetch_header("h"), RpcError);
}
