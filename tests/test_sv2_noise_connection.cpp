#include <doctest/doctest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <latch>
#include <limits>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "sv2/codec.hpp"
#include "sv2/noise_connection.hpp"
#include "sv2_noise_test_oracle.hpp"
#include "util/bytes.hpp"

using namespace erikslund;
using namespace erikslund::sv2;

namespace {

class RecordingConnection final : public Connection {
public:
    void send_bytes(ByteView bytes) override {
        const std::scoped_lock lock(mutex_);
        if (fail_sends_)
            throw std::runtime_error("injected outbound failure");
        flights_.emplace_back(bytes.begin(), bytes.end());
    }

    std::string peer() const override {
        return "192.0.2.1:1234";
    }

    [[nodiscard]] std::vector<Bytes> flights() const {
        const std::scoped_lock lock(mutex_);
        return flights_;
    }

    void fail_future_sends() {
        const std::scoped_lock lock(mutex_);
        fail_sends_ = true;
    }

private:
    mutable std::mutex mutex_;
    std::vector<Bytes> flights_;
    bool fail_sends_ = false;
};

[[nodiscard]] uint32_t current_unix_time() {
    return static_cast<uint32_t>(std::time(nullptr));
}

[[nodiscard]] Bytes make_payload(std::size_t size, uint8_t seed = 17) {
    Bytes payload(size);
    for (std::size_t index = 0; index < payload.size(); ++index)
        payload[index] =
            static_cast<uint8_t>((index * 131 + seed) & 0xff);
    return payload;
}

class ConnectedHarness {
public:
    explicit ConnectedHarness(uint32_t maximum_payload_size,
                              bool fragment_act1 = false)
        : transport_(std::make_shared<RecordingConnection>()) {
        const uint32_t current_time = current_unix_time();
        auto loaded = fixture_.credentials(current_time);
        REQUIRE(loaded.has_value());
        credentials_ = *loaded;
        connection_ = std::make_unique<NoiseConnection>(
            transport_, credentials_, maximum_payload_size);

        if (fragment_act1) {
            for (const uint8_t byte : fixture_.act1())
                CHECK(connection_->receive(ByteView(&byte, 1)).empty());
        } else {
            CHECK(connection_->receive(fixture_.act1()).empty());
        }
        REQUIRE(connection_->handshake_complete());
        REQUIRE_FALSE(connection_->terminal());

        const auto sent = transport_->flights();
        REQUIRE(sent.size() == 1);
        REQUIRE(sent[0].size() == SV2_NOISE_ACT2_SIZE);
        client_ = fixture_.accept_act2(sent[0], current_time);
    }

    [[nodiscard]] NoiseConnection& connection() {
        return *connection_;
    }

    [[nodiscard]] RecordingConnection& transport() {
        return *transport_;
    }

    [[nodiscard]] test::ClientTransport& client() {
        return client_;
    }

private:
    test::InitiatorFixture fixture_;
    std::shared_ptr<RecordingConnection> transport_;
    std::shared_ptr<const NoiseCredentials> credentials_;
    std::unique_ptr<NoiseConnection> connection_;
    test::ClientTransport client_;
};

[[nodiscard]] Bytes encrypt_frames(test::ClientTransport& client,
                                   std::span<const Bytes> frames) {
    Bytes ciphertext;
    for (const Bytes& frame : frames)
        append(ciphertext, client.encrypt_frame(frame));
    return ciphertext;
}

} // namespace

namespace erikslund::sv2 {

struct NoiseConnectionTestPeek {
    static bool has_native_session(NoiseConnection& connection) {
        const std::scoped_lock lock(connection.noise_mutex_);
        return connection.session_ != nullptr;
    }
};

} // namespace erikslund::sv2

TEST_CASE("SV2 Noise credentials enforce exact raw field sizes") {
    test::InitiatorFixture fixture;
    const uint32_t current_time = current_unix_time();
    REQUIRE(fixture.credentials(current_time).has_value());

    std::array<uint8_t, SV2_NOISE_SECRET_KEY_SIZE - 1> short_secret{};
    std::array<uint8_t, SV2_NOISE_PUBLIC_KEY_SIZE> authority{};
    std::array<uint8_t, SV2_NOISE_CERTIFICATE_SIZE> certificate{};
    const auto result =
        NoiseCredentials::load(short_secret, authority, certificate,
                               current_time);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == SV2_NOISE_ERROR_INVALID_ARGUMENT);
}

TEST_CASE("SV2 Noise incrementally authenticates Act1 and every frame boundary") {
    ConnectedHarness harness(1'024, true);
    const Bytes frame =
        encode_frame(Frame{make_extension_type(0, true), 0x21,
                           make_payload(257)});
    const Bytes ciphertext = harness.client().encrypt_frame(frame);
    Bytes recovered;

    for (std::size_t index = 0; index < ciphertext.size(); ++index) {
        const Bytes chunk = harness.connection().receive(
            ByteView(ciphertext).subspan(index, 1));
        if (index + 1 != ciphertext.size())
            CHECK(chunk.empty());
        append(recovered, chunk);
    }

    CHECK(recovered == frame);
    CHECK_FALSE(harness.connection().terminal());
}

TEST_CASE("SV2 Noise returns multiple complete authenticated frames together") {
    ConnectedHarness harness(1'024);
    const std::array frames{
        encode_frame(Frame{0, 0x01, {}}),
        encode_frame(Frame{make_extension_type(0, true), 0x21,
                           {0xaa, 0xbb, 0xcc}}),
        encode_frame(Frame{0, 0x02, {0x44}}),
    };
    const Bytes ciphertext = encrypt_frames(harness.client(), frames);
    Bytes expected;
    for (const Bytes& frame : frames)
        append(expected, frame);

    CHECK(harness.connection().receive(ciphertext) == expected);
    CHECK_FALSE(harness.connection().terminal());
}

TEST_CASE("SV2 Noise zero-payload frames consume only the authenticated header") {
    ConnectedHarness harness(32);
    const Bytes zero_frame = encode_frame(Frame{0, 0x01, {}});
    const Bytes inbound = harness.client().encrypt_frame(zero_frame);
    REQUIRE(inbound.size() == SV2_NOISE_ENCRYPTED_HEADER_SIZE);
    CHECK(harness.connection().receive(inbound) == zero_frame);

    harness.connection().send_bytes(zero_frame);
    const auto flights = harness.transport().flights();
    REQUIRE(flights.size() == 2);
    CHECK(flights[1].size() == SV2_NOISE_ENCRYPTED_HEADER_SIZE);
    CHECK(harness.client().decrypt_flight(flights[1]) == zero_frame);
}

TEST_CASE("SV2 Noise chunks payloads at 65519 bytes in both directions") {
    ConnectedHarness harness(65'520);
    const std::array frames{
        encode_frame(Frame{0, 0x30, make_payload(65'519, 3)}),
        encode_frame(Frame{0, 0x31, make_payload(65'520, 7)}),
    };
    Bytes plaintext;
    for (const Bytes& frame : frames)
        append(plaintext, frame);

    const Bytes inbound = encrypt_frames(harness.client(), frames);
    CHECK(harness.connection().receive(inbound) == plaintext);

    harness.connection().send_bytes(plaintext);
    const auto flights = harness.transport().flights();
    REQUIRE(flights.size() == 2);
    CHECK(harness.client().decrypt_flight(flights[1]) == plaintext);
}

TEST_CASE("SV2 Noise rejects oversized payloads after authenticating only the header") {
    ConnectedHarness harness(32);
    const Bytes frame =
        encode_frame(Frame{0, 0x30, make_payload(33)});
    const Bytes ciphertext = harness.client().encrypt_frame(frame);

    CHECK(harness.connection().receive(ciphertext) == Bytes{});
    CHECK(harness.connection().terminal());
    CHECK(harness.connection().handshake_complete());
}

TEST_CASE("SV2 Noise preserves authenticated frames before an oversized header") {
    ConnectedHarness harness(32);
    const Bytes first =
        encode_frame(Frame{make_extension_type(0, true), 0x21, {0xaa}});
    const Bytes oversized =
        encode_frame(Frame{0, 0x30, make_payload(33)});
    const std::array frames{first, oversized};

    CHECK(harness.connection().receive(
              encrypt_frames(harness.client(), frames)) == first);
    CHECK(harness.connection().terminal());
}

TEST_CASE("SV2 Noise applies the configured payload limit only to inbound frames") {
    ConnectedHarness harness(1);
    const Bytes frame =
        encode_frame(Frame{0, 0x30, make_payload(33)});

    harness.connection().send_bytes(frame);

    const auto flights = harness.transport().flights();
    REQUIRE(flights.size() == 2);
    CHECK(harness.client().decrypt_flight(flights[1]) == frame);
    CHECK_FALSE(harness.connection().terminal());
}

TEST_CASE("SV2 Noise authentication failures are quiet and terminal") {
    SUBCASE("header tag") {
        ConnectedHarness harness(1'024);
        const Bytes frame =
            encode_frame(Frame{0, 0x30, make_payload(10)});
        Bytes ciphertext = harness.client().encrypt_frame(frame);
        ciphertext[SV2_NOISE_ENCRYPTED_HEADER_SIZE - 1] ^= 0x80;

        CHECK(harness.connection().receive(ciphertext).empty());
        CHECK(harness.connection().terminal());
        CHECK(harness.connection().receive(ciphertext).empty());

        const std::size_t flight_count =
            harness.transport().flights().size();
        harness.connection().send_bytes(frame);
        CHECK(harness.transport().flights().size() == flight_count);
        CHECK_FALSE(harness.connection().finish());
    }

    SUBCASE("payload tag") {
        ConnectedHarness harness(1'024);
        const Bytes frame =
            encode_frame(Frame{0, 0x30, make_payload(10)});
        Bytes ciphertext = harness.client().encrypt_frame(frame);
        ciphertext.back() ^= 0x01;

        CHECK(harness.connection().receive(ciphertext).empty());
        CHECK(harness.connection().terminal());
    }
}

TEST_CASE("SV2 Noise failure immediately destroys transport keys and preserves the native reason") {
    ConnectedHarness harness(1'024);
    REQUIRE(NoiseConnectionTestPeek::has_native_session(
        harness.connection()));
    const Bytes frame =
        encode_frame(Frame{0, 0x30, make_payload(10)});
    Bytes ciphertext = harness.client().encrypt_frame(frame);
    ciphertext.back() ^= 0x01;

    CHECK(harness.connection().receive(ciphertext).empty());
    CHECK(harness.connection().terminal());
    CHECK(harness.connection().failure_status() ==
          SV2_NOISE_ERROR_AUTHENTICATION_FAILURE);
    CHECK_FALSE(NoiseConnectionTestPeek::has_native_session(
        harness.connection()));
}

TEST_CASE("SV2 Noise preserves certificate expiry as the handshake failure reason") {
    test::InitiatorFixture expired_fixture(0, 1);
    auto underlying = std::make_shared<RecordingConnection>();
    auto loaded = expired_fixture.credentials(0);
    REQUIRE(loaded.has_value());
    NoiseConnection connection(underlying, *loaded, 32);

    CHECK(connection.receive(expired_fixture.act1()).empty());
    CHECK(connection.terminal());
    CHECK_FALSE(connection.handshake_complete());
    CHECK(connection.failure_status() ==
          SV2_NOISE_ERROR_CERTIFICATE_EXPIRED);
    CHECK_FALSE(NoiseConnectionTestPeek::has_native_session(connection));
}

TEST_CASE("SV2 Noise preserves not-yet-valid as the handshake failure reason") {
    constexpr uint32_t kFutureValidity =
        std::numeric_limits<uint32_t>::max() - 1;
    test::InitiatorFixture future_fixture(
        kFutureValidity, std::numeric_limits<uint32_t>::max());
    auto underlying = std::make_shared<RecordingConnection>();
    auto loaded = future_fixture.credentials(kFutureValidity);
    REQUIRE(loaded.has_value());
    NoiseConnection connection(underlying, *loaded, 32);

    CHECK(connection.receive(future_fixture.act1()).empty());
    CHECK(connection.terminal());
    CHECK_FALSE(connection.handshake_complete());
    CHECK(connection.failure_status() ==
          SV2_NOISE_ERROR_CERTIFICATE_NOT_YET_VALID);
    CHECK_FALSE(NoiseConnectionTestPeek::has_native_session(connection));
}

TEST_CASE("SV2 Noise distinguishes clean EOF from every partial transport state") {
    SUBCASE("partial Act1") {
        test::InitiatorFixture fixture;
        auto underlying = std::make_shared<RecordingConnection>();
        auto loaded = fixture.credentials(current_unix_time());
        REQUIRE(loaded.has_value());
        NoiseConnection connection(underlying, *loaded, 32);

        CHECK(connection.receive(
                  ByteView(fixture.act1()).first(
                      SV2_NOISE_ACT1_SIZE - 1))
                  .empty());
        CHECK_FALSE(connection.finish());
        CHECK(connection.terminal());
    }

    SUBCASE("partial encrypted header") {
        ConnectedHarness harness(32);
        const Bytes frame = encode_frame(Frame{0, 0x01, {}});
        const Bytes ciphertext = harness.client().encrypt_frame(frame);

        CHECK(harness.connection()
                  .receive(ByteView(ciphertext).first(
                      SV2_NOISE_ENCRYPTED_HEADER_SIZE - 1))
                  .empty());
        CHECK_FALSE(harness.connection().finish());
    }

    SUBCASE("partial encrypted payload") {
        ConnectedHarness harness(32);
        const Bytes frame =
            encode_frame(Frame{0, 0x30, make_payload(10)});
        const Bytes ciphertext = harness.client().encrypt_frame(frame);

        CHECK(harness.connection()
                  .receive(ByteView(ciphertext).first(
                      SV2_NOISE_ENCRYPTED_HEADER_SIZE + 1))
                  .empty());
        CHECK_FALSE(harness.connection().finish());
    }

    SUBCASE("exact frame boundary") {
        ConnectedHarness harness(32);
        const Bytes frame = encode_frame(Frame{0, 0x01, {}});
        const Bytes ciphertext = harness.client().encrypt_frame(frame);

        CHECK(harness.connection().receive(ciphertext) == frame);
        CHECK(harness.connection().finish());
        CHECK(harness.connection().terminal());
        CHECK(harness.connection().handshake_complete());
        CHECK_FALSE(NoiseConnectionTestPeek::has_native_session(
            harness.connection()));
        CHECK_FALSE(harness.connection().finish());
        CHECK_FALSE(NoiseConnectionTestPeek::has_native_session(
            harness.connection()));
    }
}

TEST_CASE("SV2 Noise validates a complete outbound plaintext flight before encrypting") {
    ConnectedHarness harness(32);
    const Bytes truncated_header{0x00, 0x00, 0x01};

    harness.connection().send_bytes(truncated_header);
    CHECK(harness.connection().terminal());
    CHECK(harness.transport().flights().size() == 1);
}

TEST_CASE("SV2 Noise outbound failure becomes terminal without another inbound read") {
    ConnectedHarness harness(32);
    REQUIRE(NoiseConnectionTestPeek::has_native_session(
        harness.connection()));
    harness.transport().fail_future_sends();

    harness.connection().send_bytes(
        encode_frame(Frame{0, 0x01, {}}));

    CHECK(harness.connection().terminal());
    CHECK_FALSE(NoiseConnectionTestPeek::has_native_session(
        harness.connection()));
    CHECK(harness.transport().flights().size() == 1);
}

TEST_CASE("SV2 Noise enqueues Act2 before any application response") {
    ConnectedHarness harness(32);
    const Bytes request = encode_frame(Frame{0, 0x00, {}});
    const Bytes encrypted_request = harness.client().encrypt_frame(request);
    CHECK(harness.connection().receive(encrypted_request) == request);

    const Bytes response = encode_frame(Frame{0, 0x01, {}});
    harness.connection().send_bytes(response);
    const auto flights = harness.transport().flights();
    REQUIRE(flights.size() == 2);
    CHECK(flights[0].size() == SV2_NOISE_ACT2_SIZE);
    CHECK(harness.client().decrypt_flight(flights[1]) == response);
}

TEST_CASE("SV2 Noise preserves cipher and wire order during concurrent traffic") {
    constexpr std::size_t kOutboundCount = 12;
    ConnectedHarness harness(1'024);

    Bytes inbound_ciphertext;
    Bytes expected_inbound;
    for (std::size_t index = 0; index < kOutboundCount; ++index) {
        Bytes frame = encode_frame(Frame{
            0, static_cast<uint8_t>(0x40 + index),
            make_payload(13 + index, static_cast<uint8_t>(index))});
        append(expected_inbound, frame);
        append(inbound_ciphertext,
               harness.client().encrypt_frame(frame));
    }

    std::vector<Bytes> outbound_frames;
    for (std::size_t index = 0; index < kOutboundCount; ++index)
        outbound_frames.push_back(encode_frame(Frame{
            0, static_cast<uint8_t>(0x60 + index),
            {static_cast<uint8_t>(index)}}));

    std::latch start(static_cast<std::ptrdiff_t>(kOutboundCount + 2));
    Bytes recovered_inbound;
    std::jthread receiver([&] {
        start.arrive_and_wait();
        std::size_t offset = 0;
        while (offset < inbound_ciphertext.size()) {
            const std::size_t count =
                std::min<std::size_t>(7, inbound_ciphertext.size() - offset);
            append(recovered_inbound,
                   harness.connection().receive(
                       ByteView(inbound_ciphertext).subspan(offset, count)));
            offset += count;
        }
    });

    std::vector<std::jthread> senders;
    senders.reserve(kOutboundCount);
    for (const Bytes& frame : outbound_frames) {
        senders.emplace_back([&, frame] {
            start.arrive_and_wait();
            harness.connection().send_bytes(frame);
        });
    }
    start.arrive_and_wait();
    receiver.join();
    for (std::jthread& sender : senders)
        sender.join();

    CHECK(recovered_inbound == expected_inbound);
    REQUIRE_FALSE(harness.connection().terminal());

    const auto flights = harness.transport().flights();
    REQUIRE(flights.size() == kOutboundCount + 1);
    std::vector<Bytes> decrypted_outbound;
    for (std::size_t index = 1; index < flights.size(); ++index)
        decrypted_outbound.push_back(
            harness.client().decrypt_flight(flights[index]));
    std::ranges::sort(decrypted_outbound);
    std::ranges::sort(outbound_frames);
    CHECK(decrypted_outbound == outbound_frames);
}
