// Cross-thread stress for the SocketConnection write path: one "reactor" thread cork-batching
// acks, one "work" thread firing direct notifies, one "flusher" thread simulating EPOLLOUT --
// all against a single connection, with a concurrent reader asserting that every line arrives
// exactly once, intact, and in per-sender FIFO order. Single-threaded runs catch logic bugs;
// under docker/tsan.sh (-DSANITIZE_THREAD=ON) this is the data-race gate for cork()/uncork()/
// send_lines()/flush_outbox() interleavings.
#include <doctest/doctest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <format>
#include <string>
#include <thread>
#include <vector>

#include "net/socket_connection.hpp"

using namespace erikslund::net;

namespace {

constexpr int kLinesPerSender = 4000;

// Total wire bytes for one sender's "<prefix>-<i>\n" sequence (exact, so the reader knows when
// the stream is complete).
size_t wire_bytes(const std::string& prefix) {
    size_t total = 0;
    for (int i = 0; i < kLinesPerSender; ++i)
        total += prefix.size() + 1 + std::format("{}", i).size() + 1; // "-", "\n"
    return total;
}

} // namespace

TEST_CASE("cork/send/flush are race-free and line-atomic across reactor and work threads") {
    int sv[2];
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    // The connection's fd stays BLOCKING here on purpose: with a concurrent reader the kernel
    // buffer never wedges, and a blocking send() keeps the outbox small so the 64KB cap can't
    // fire spuriously. EAGAIN queueing has its own single-threaded tests.

    std::string received;
    const size_t expected_bytes = wire_bytes("ack") + wire_bytes("notify") + wire_bytes("burst");
    std::atomic<size_t> received_bytes{0};

    std::thread reader([&] {
        char buf[8192];
        ssize_t n;
        while ((n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0) {
            received.append(buf, static_cast<size_t>(n));
            received_bytes.store(received.size(), std::memory_order_relaxed);
        }
    });

    {
        SocketConnection conn(sv[0], 30.0, "test:stress"); // owns sv[0]

        // The reactor read loop: cork around a burst of acks, exactly as handle_readable does.
        std::thread reactor([&] {
            for (int i = 0; i < kLinesPerSender; ++i) {
                conn.cork();
                conn.send_line(std::format("ack-{}", i));
                conn.uncork();
            }
        });
        // The work thread: direct notifies that race the cork windows.
        std::thread work([&] {
            for (int i = 0; i < kLinesPerSender; ++i)
                conn.send_line(std::format("notify-{}", i));
        });
        // A second uncorked sender to add outbox contention from a third thread.
        std::thread burst([&] {
            for (int i = 0; i < kLinesPerSender; ++i)
                conn.send_line(std::format("burst-{}", i));
        });
        // The EPOLLOUT path: periodic flushes racing the senders.
        std::atomic<bool> senders_done{false};
        std::thread flusher([&] {
            while (!senders_done.load(std::memory_order_relaxed)) {
                conn.flush_outbox();
                std::this_thread::yield();
            }
        });

        reactor.join();
        work.join();
        burst.join();
        senders_done.store(true, std::memory_order_relaxed);
        flusher.join();

        REQUIRE_FALSE(conn.dead());
        // Drain any tail the last sender left queued (a final send can land mid-cork).
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (received_bytes.load(std::memory_order_relaxed) < expected_bytes &&
               std::chrono::steady_clock::now() < deadline) {
            conn.flush_outbox();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        REQUIRE(received_bytes.load() == expected_bytes);
    } // ~SocketConnection closes sv[0] -> reader sees EOF
    reader.join();
    ::close(sv[1]);

    // Every received line must be exactly one sent line (atomic framing, no interleaved bytes),
    // each sender's sequence must arrive in FIFO order, and nothing may be lost or duplicated.
    int next_expected[3] = {0, 0, 0}; // ack, notify, burst
    const std::string prefixes[3] = {"ack-", "notify-", "burst-"};
    size_t start = 0;
    size_t lines = 0;
    while (start < received.size()) {
        const size_t newline = received.find('\n', start);
        REQUIRE(newline != std::string::npos); // no torn trailing fragment
        const std::string_view line(received.data() + start, newline - start);
        start = newline + 1;
        ++lines;
        bool matched = false;
        for (int sender = 0; sender < 3; ++sender) {
            if (!line.starts_with(prefixes[sender]))
                continue;
            const std::string expected =
                prefixes[sender] + std::format("{}", next_expected[sender]);
            REQUIRE(line == expected); // FIFO per sender, no gaps, no duplicates
            ++next_expected[sender];
            matched = true;
            break;
        }
        REQUIRE(matched); // no corrupted / interleaved line
    }
    CHECK(lines == static_cast<size_t>(3 * kLinesPerSender));
    CHECK(next_expected[0] == kLinesPerSender);
    CHECK(next_expected[1] == kLinesPerSender);
    CHECK(next_expected[2] == kLinesPerSender);
}
