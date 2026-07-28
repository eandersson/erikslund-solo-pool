#include <doctest/doctest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "sv2/codec.hpp"
#include "sv2/messages.hpp"
#include "util/hex.hpp"

using namespace erikslund;
using namespace erikslund::sv2;

namespace {

U256 increasing_u256(uint8_t first = 0) {
    U256 value{};
    for (std::size_t i = 0; i < value.size(); ++i)
        value[i] = static_cast<uint8_t>(first + i);
    return value;
}

template <typename Message, typename Decode>
void check_payload_round_trip(const Message& message, Decode&& decode) {
    const Bytes payload = encode_payload(message);
    CHECK(decode(payload) == message);
}

} // namespace

TEST_CASE("SV2 mining message IDs and routing bits match the core registry") {
    CHECK(SetupConnection::kMessageType == 0x00);
    CHECK(SetupConnectionSuccess::kMessageType == 0x01);
    CHECK(SetupConnectionError::kMessageType == 0x02);
    CHECK(OpenStandardMiningChannel::kMessageType == 0x10);
    CHECK(OpenStandardMiningChannelSuccess::kMessageType == 0x11);
    CHECK(OpenMiningChannelError::kMessageType == 0x12);
    CHECK(OpenExtendedMiningChannel::kMessageType == 0x13);
    CHECK(OpenExtendedMiningChannelSuccess::kMessageType == 0x14);
    CHECK(NewMiningJob::kMessageType == 0x15);
    CHECK(UpdateChannel::kMessageType == 0x16);
    CHECK(UpdateChannelError::kMessageType == 0x17);
    CHECK(CloseChannel::kMessageType == 0x18);
    CHECK(SetExtranoncePrefix::kMessageType == 0x19);
    CHECK(SubmitSharesStandard::kMessageType == 0x1a);
    CHECK(SubmitSharesExtended::kMessageType == 0x1b);
    CHECK(SubmitSharesSuccess::kMessageType == 0x1c);
    CHECK(SubmitSharesError::kMessageType == 0x1d);
    CHECK(NewExtendedMiningJob::kMessageType == 0x1f);
    CHECK(SetNewPrevHash::kMessageType == 0x20);
    CHECK(SetTarget::kMessageType == 0x21);

    CHECK_FALSE(SetupConnection::kChannelMessage);
    CHECK_FALSE(OpenStandardMiningChannel::kChannelMessage);
    CHECK_FALSE(OpenExtendedMiningChannel::kChannelMessage);
    CHECK_FALSE(OpenExtendedMiningChannelSuccess::kChannelMessage);
    CHECK(NewMiningJob::kChannelMessage);
    CHECK(UpdateChannel::kChannelMessage);
    CHECK(UpdateChannelError::kChannelMessage);
    CHECK(CloseChannel::kChannelMessage);
    CHECK(SetExtranoncePrefix::kChannelMessage);
    CHECK(SubmitSharesStandard::kChannelMessage);
    CHECK(SubmitSharesExtended::kChannelMessage);
    CHECK(NewExtendedMiningJob::kChannelMessage);
    CHECK(SetNewPrevHash::kChannelMessage);
    CHECK(SetTarget::kChannelMessage);
}

TEST_CASE("SV2 frame encoding pins the six-byte little-endian header") {
    const Frame frame{make_extension_type(0x0123, true), 0x1a, {0xaa, 0xbb, 0xcc}};
    CHECK(encode_frame(frame) == Bytes{0x23, 0x81, 0x1a, 0x03, 0x00, 0x00, 0xaa, 0xbb, 0xcc});
    CHECK(frame.extension_id() == 0x0123);
    CHECK(frame.is_channel_message());
    CHECK_THROWS_AS(static_cast<void>(make_extension_type(0x8000, false)),
                    CodecError);
}

TEST_CASE("SV2 frame decoder handles fragmentation at every byte boundary") {
    const Frame expected{make_extension_type(kCoreExtensionId, true), 0x15,
                         {0x10, 0x20, 0x30, 0x40}};
    const Bytes encoded = encode_frame(expected);

    for (std::size_t split = 0; split < encoded.size(); ++split) {
        FrameDecoder decoder;
        const auto first = decoder.push(ByteView(encoded).first(split));
        CHECK(first.empty());
        const auto second = decoder.push(ByteView(encoded).subspan(split));
        REQUIRE(second.size() == 1);
        CHECK(second.front() == expected);
        CHECK_NOTHROW(decoder.finish());
    }
}

TEST_CASE("SV2 frame decoder returns multiple frames from one stream fragment") {
    const Frame first{0, 0x01, {}};
    const Frame second{make_extension_type(0, true), 0x21, {0x44}};
    Bytes stream = encode_frame(first);
    append(stream, encode_frame(second));

    FrameDecoder decoder;
    const auto decoded = decoder.push(stream);
    REQUIRE(decoded.size() == 2);
    CHECK(decoded[0] == first);
    CHECK(decoded[1] == second);
    CHECK_NOTHROW(decoder.finish());
}

TEST_CASE("SV2 frame decoder rejects oversized payloads before allocating them") {
    FrameDecoder decoder(32);
    CHECK_THROWS_AS(
        static_cast<void>(
            decoder.push(Bytes{0x00, 0x00, 0x10, 0x21, 0x00, 0x00})),
        CodecError);
}

TEST_CASE("SV2 frame decoder preserves complete frames before an oversized header") {
    const Frame first{make_extension_type(0, true), 0x21, {0xaa}};
    Bytes stream = encode_frame(first);
    append(stream, Bytes{0x00, 0x00, 0x10, 0x21, 0x00, 0x00});

    FrameDecoder decoder(32);
    try {
        static_cast<void>(decoder.push(stream));
        FAIL("oversized frame was accepted");
    } catch (CodecError& error) {
        const auto complete = error.take_completed_frames();
        REQUIRE(complete.size() == 1);
        CHECK(complete.front() == first);
    }
}

TEST_CASE("SV2 frame decoder reports incomplete headers and payloads at EOF") {
    FrameDecoder short_header;
    CHECK(short_header.push(Bytes{0x00, 0x00, 0x10}).empty());
    CHECK_THROWS_AS(short_header.finish(), CodecError);

    FrameDecoder short_payload;
    CHECK(short_payload.push(Bytes{0x00, 0x00, 0x10, 0x02, 0x00, 0x00, 0xaa}).empty());
    CHECK_THROWS_AS(short_payload.finish(), CodecError);
}

// Paired with SETUP_CONNECTION_FRAME_HEX in python/erikslund_pool/tests/unit/sv2/test_codec.py;
// the inputs must stay identical on both sides for the vector to prove parity.
TEST_CASE("SetupConnection has a pinned spec-compatible byte vector") {
    const SetupConnection message{
        .protocol = 0,
        .minimum_version = 2,
        .maximum_version = 2,
        .flags = 5,
        .endpoint_host = "pool",
        .endpoint_port = 34254,
        .vendor = "erik",
        .hardware_version = "asic",
        .firmware = "1.0",
        .device_id = "rig",
    };
    const Bytes expected = {
        0x00, 0x00, 0x00, 0x22, 0x00, 0x00, // core frame, type 0x00, 34-byte payload
        0x00, 0x02, 0x00, 0x02, 0x00, 0x05, 0x00, 0x00, 0x00,
        0x04, 'p',  'o',  'o',  'l',  0xce, 0x85,
        0x04, 'e',  'r',  'i',  'k',
        0x04, 'a',  's',  'i',  'c',
        0x03, '1',  '.',  '0',
        0x03, 'r',  'i',  'g',
    };
    CHECK(encode_message(message) == expected);
    CHECK(decode_setup_connection(ByteView(expected).subspan(kFrameHeaderSize)) == message);
}

// Paired with SETUP_CONNECTION_EMPTY_STRING_FRAME_HEX in the Python suite; pins the
// zero-length STR0_255 encoding (hardware_version) on both sides.
TEST_CASE("SetupConnection pins the empty STR0_255 encoding") {
    const SetupConnection message{
        .protocol = 0,
        .minimum_version = 2,
        .maximum_version = 2,
        .flags = 1,
        .endpoint_host = "pool",
        .endpoint_port = 34254,
        .vendor = "erik",
        .hardware_version = "",
        .firmware = "fw",
        .device_id = "id",
    };
    const Bytes expected = util::from_hex(
        "0000001c0000"
        "00020002000100000004706f6f6cce85046572696b00026677026964");

    CHECK(encode_message(message) == expected);
    CHECK(decode_setup_connection(ByteView(expected).subspan(kFrameHeaderSize)) == message);
}

TEST_CASE("Mining messages round-trip every specified field") {
    const U256 target = increasing_u256();
    const U256 hash = increasing_u256(32);

    check_payload_round_trip(SetupConnectionSuccess{2, 7}, decode_setup_connection_success);
    check_payload_round_trip(SetupConnectionError{4, "unsupported-feature-flags"},
                             decode_setup_connection_error);
    check_payload_round_trip(OpenStandardMiningChannel{7, "address.worker", 12'500'000.0F, target},
                             decode_open_standard_mining_channel);
    check_payload_round_trip(OpenStandardMiningChannelSuccess{7, 42, target, {0xaa, 0xbb}, 9},
                             decode_open_standard_mining_channel_success);
    check_payload_round_trip(OpenMiningChannelError{7, "unknown-user"},
                             decode_open_mining_channel_error);
    check_payload_round_trip(
        OpenExtendedMiningChannel{8, "proxy.worker", 25'000'000.0F, target, 8},
        decode_open_extended_mining_channel);
    check_payload_round_trip(
        OpenExtendedMiningChannelSuccess{8, 43, target, 8, {0xaa, 0xbb}, 9},
        decode_open_extended_mining_channel_success);
    check_payload_round_trip(NewMiningJob{42, 100, std::nullopt, 0x20000000, hash},
                             decode_new_mining_job);
    check_payload_round_trip(NewMiningJob{42, 101, 1'715'000'123, 0x20000000, hash},
                             decode_new_mining_job);
    check_payload_round_trip(UpdateChannel{42, 25'000'000.0F, target},
                             decode_update_channel);
    check_payload_round_trip(UpdateChannelError{42, "invalid-channel"},
                             decode_update_channel_error);
    check_payload_round_trip(CloseChannel{42, "shutdown"}, decode_close_channel);
    check_payload_round_trip(SetExtranoncePrefix{42, {0xaa, 0xbb, 0xcc}},
                             decode_set_extranonce_prefix);
    check_payload_round_trip(
        SubmitSharesStandard{42, 1, 100, 0xabbaabba, 1'715'000'123, 0x20000000},
        decode_submit_shares_standard);
    check_payload_round_trip(
        SubmitSharesExtended{
            43, 2, 102, 0x12345678, 1'715'000'124, 0x20000000, {0x01, 0x02}},
        decode_submit_shares_extended);
    check_payload_round_trip(SubmitSharesSuccess{42, 1, 1, 4096}, decode_submit_shares_success);
    check_payload_round_trip(SubmitSharesError{42, 2, "low-difficulty-share"},
                             decode_submit_shares_error);
    check_payload_round_trip(
        NewExtendedMiningJob{43, 102, std::nullopt, 0x20000000, true, {target, hash},
                             {0xaa, 0xbb, 0xcc}, {0xdd, 0xee}},
        decode_new_extended_mining_job);
    check_payload_round_trip(
        NewExtendedMiningJob{43, 103, 1'715'000'124, 0x20000000, false, {}, {}, {}},
        decode_new_extended_mining_job);
    check_payload_round_trip(SetNewPrevHash{42, 100, hash, 1'715'000'123, 0x17034219},
                             decode_set_new_prev_hash);
    check_payload_round_trip(SetTarget{42, target}, decode_set_target);
}

TEST_CASE("NewMiningJob encodes U256 directly without a length prefix") {
    const U256 root = increasing_u256();
    const Bytes payload = encode_payload(NewMiningJob{1, 2, std::nullopt, 3, root});
    REQUIRE(payload.size() == 45);
    CHECK(payload[8] == 0);   // OPTION count: no min_ntime
    CHECK(payload[13] == 0);  // first raw merkle-root byte
    CHECK(payload.back() == 31);
}

TEST_CASE("SetExtranoncePrefix has a pinned cross-language byte vector") {
    const SetExtranoncePrefix message{0x01020304, {0xaa, 0xbb}};
    CHECK(encode_message(message) ==
          Bytes{0x00, 0x80, 0x19, 0x07, 0x00, 0x00,
                0x04, 0x03, 0x02, 0x01, 0x02, 0xaa, 0xbb});
}

TEST_CASE("Channel request and job frames match the Python vectors") {
    U256 target{};
    for (std::size_t index = 0; index < target.size(); ++index)
        target[index] = static_cast<uint8_t>(index);

    CHECK(encode_message(OpenStandardMiningChannel{
              0x01020304, "miner", 1.5F, target}) ==
          util::from_hex(
              "0000102e000004030201056d696e65720000c03f"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"));
    CHECK(encode_message(OpenExtendedMiningChannel{
              0x01020304, "miner", 1.5F, target, 0x1122}) ==
          util::from_hex(
              "00001330000004030201056d696e65720000c03f"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f2211"));
    CHECK(encode_message(OpenExtendedMiningChannelSuccess{
              0x01020304, 0x11223344, target, 0x0506, {0xaa, 0xbb, 0xcc},
              0xa1b2c3d4}) ==
          util::from_hex(
              "0000143200000403020144332211"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"
              "060503aabbccd4c3b2a1"));
    CHECK(encode_message(NewMiningJob{
              0x11223344, 0xa1b2c3d4, std::nullopt, 0x20000000, target}) ==
          util::from_hex(
              "0080152d000044332211d4c3b2a10000000020"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"));
    CHECK(encode_message(SubmitSharesStandard{
              0x01020304, 0x11121314, 0x21222324, 0x31323334,
              0x41424344, 0x51525354}) ==
          util::from_hex(
              "00801a180000040302011413121124232221"
              "343332314443424154535251"));
    CHECK(encode_message(SubmitSharesExtended{
              0x01020304, 0x11121314, 0x21222324, 0x31323334,
              0x41424344, 0x51525354, {0xaa, 0xbb, 0xcc}}) ==
          util::from_hex(
              "00801b1c0000040302011413121124232221"
              "34333231444342415453525103aabbcc"));
}

// Paired with the *_FRAME_HEX vectors in python/erikslund_pool/tests/unit/sv2/test_codec.py, so
// C++/Python wire drift fails here rather than at a miner.
TEST_CASE("Pool-emitted frames match the Python vectors") {
    const U256 target = increasing_u256();
    const U256 previous_hash = increasing_u256(32);

    CHECK(encode_message(OpenStandardMiningChannelSuccess{
              0x01020304, 0x11223344, target, {0xaa, 0xbb, 0xcc}, 0xa1b2c3d4}) ==
          util::from_hex(
              "0000113000000403020144332211"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"
              "03aabbccd4c3b2a1"));
    CHECK(encode_message(SubmitSharesSuccess{
              0x01020304, 0x11223344, 0x55667788, 0x0102030405060708ULL}) ==
          util::from_hex(
              "00801c1400000403020144332211887766550807060504030201"));
    CHECK(encode_message(SubmitSharesError{
              0x01020304, 0x11223344, "stale-share"}) ==
          util::from_hex(
              "00801d1400000403020144332211"
              "0b7374616c652d7368617265"));
    CHECK(encode_message(SetNewPrevHash{
              0x01020304, 0x11223344, previous_hash, 1'715'000'123, 0x17034219}) ==
          util::from_hex(
              "0080203000000403020144332211"
              "202122232425262728292a2b2c2d2e2f"
              "303132333435363738393a3b3c3d3e3f"
              "3bd3386619420317"));
    CHECK(encode_message(SetTarget{0x01020304, target}) ==
          util::from_hex(
              "00802124000004030201"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"));
}

TEST_CASE("NewExtendedMiningJob matches the Python vector") {
    const U256 first_path_node = increasing_u256();
    const U256 second_path_node = increasing_u256(32);
    const NewExtendedMiningJob message{
        0x11223344,
        0xa1b2c3d4,
        std::nullopt,
        0x20000000,
        true,
        {first_path_node, second_path_node},
        {0xaa, 0xbb, 0xcc},
        {0xdd, 0xee},
    };

    CHECK(encode_message(message) ==
          util::from_hex(
              "00801f58000044332211d4c3b2a100000000200102"
              "000102030405060708090a0b0c0d0e0f"
              "101112131415161718191a1b1c1d1e1f"
              "202122232425262728292a2b2c2d2e2f"
              "303132333435363738393a3b3c3d3e3f"
              "0300aabbcc0200ddee"));
}

TEST_CASE("SV2 BOOL uses its low bit and emits a canonical byte") {
    NewExtendedMiningJob message{
        1, 2, std::nullopt, 3, false, {}, {}, {}};
    Bytes payload = encode_payload(message);
    REQUIRE(payload.size() == 19);
    CHECK(payload[13] == 0);

    payload[13] = 0xfe;
    CHECK_FALSE(decode_new_extended_mining_job(payload).version_rolling_allowed);
    payload[13] = 0xff;
    CHECK(decode_new_extended_mining_job(payload).version_rolling_allowed);

    message.version_rolling_allowed = true;
    CHECK(encode_payload(message)[13] == 1);
}

TEST_CASE("SV2 message decoding rejects truncation, invalid lengths, and trailing bytes") {
    CHECK_THROWS_AS(
        static_cast<void>(decode_submit_shares_standard(Bytes(23, 0))),
        CodecError);

    Bytes invalid_option(45, 0);
    invalid_option[8] = 2;
    CHECK_THROWS_AS(static_cast<void>(decode_new_mining_job(invalid_option)),
                    CodecError);

    Bytes invalid_extranonce(8 + 32 + 1, 0);
    invalid_extranonce[40] = 33;
    CHECK_THROWS_AS(
        static_cast<void>(
            decode_open_standard_mining_channel_success(invalid_extranonce)),
        CodecError);

    Bytes invalid_extended_extranonce(25, 0);
    invalid_extended_extranonce[24] = 33;
    CHECK_THROWS_AS(
        static_cast<void>(decode_submit_shares_extended(invalid_extended_extranonce)),
        CodecError);

    Bytes truncated_merkle_path(15, 0);
    truncated_merkle_path[14] = 1;
    CHECK_THROWS_AS(
        static_cast<void>(decode_new_extended_mining_job(truncated_merkle_path)),
        CodecError);

    Bytes truncated_coinbase_prefix(17, 0);
    truncated_coinbase_prefix[15] = 1;
    CHECK_THROWS_AS(
        static_cast<void>(decode_new_extended_mining_job(truncated_coinbase_prefix)),
        CodecError);

    Bytes trailing = encode_payload(SetTarget{1, increasing_u256()});
    trailing.push_back(0);
    CHECK_THROWS_AS(static_cast<void>(decode_set_target(trailing)), CodecError);
}

TEST_CASE("SV2 message encoding enforces bounded variable-length fields") {
    SetupConnection long_string;
    long_string.endpoint_host = std::string(256, 'x');
    CHECK_THROWS_AS(static_cast<void>(encode_payload(long_string)), CodecError);

    OpenStandardMiningChannelSuccess long_prefix;
    long_prefix.extranonce_prefix = Bytes(33, 0);
    CHECK_THROWS_AS(static_cast<void>(encode_payload(long_prefix)), CodecError);

    SetExtranoncePrefix replacement;
    replacement.extranonce_prefix = Bytes(33, 0);
    CHECK_THROWS_AS(static_cast<void>(encode_payload(replacement)), CodecError);

    SubmitSharesExtended long_extranonce;
    long_extranonce.extranonce = Bytes(33, 0);
    CHECK_THROWS_AS(static_cast<void>(encode_payload(long_extranonce)), CodecError);

    NewExtendedMiningJob long_coinbase;
    long_coinbase.coinbase_tx_prefix = Bytes(65'536, 0);
    CHECK_THROWS_AS(static_cast<void>(encode_payload(long_coinbase)), CodecError);

    NewExtendedMiningJob long_merkle_path;
    long_merkle_path.merkle_path.resize(256);
    CHECK_THROWS_AS(static_cast<void>(encode_payload(long_merkle_path)), CodecError);
}
