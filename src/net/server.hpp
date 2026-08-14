#pragma once
// Epoll mining server for SV1 and authenticated or plaintext SV2.
// Reactor bookkeeping is worker-owned; sockets and sessions synchronize cross-thread pool calls.
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "core/config.hpp"
#include "pool/pool.hpp"
#include "util/unique_fd.hpp"

namespace erikslund::sv2 {
class NoiseCredentials;
}

namespace erikslund::net {

struct ServerWorker; // per-reactor epoll state; defined in server.cpp
struct ServerTestPeek;

enum class WireProtocol : uint8_t { Sv1, Sv2Noise, Sv2Plaintext };

class Server {
public:
    Server(Pool& pool, const Config& config);

    void start();

    // Test-only: the port actually bound when configured as 0.
    uint16_t bound_port(WireProtocol protocol) const;

    // Accept loop, round-robin onto reactors. Returns once `stop` fires (joins reactors).
    void run(const std::stop_token& stop);
    void reload_config(const RuntimeConfig& config) noexcept;

    ~Server(); // out-of-line: workers_ holds the incomplete ServerWorker

private:
    struct Listener {
        util::UniqueFd socket;
        uint16_t port;
        WireProtocol protocol;
    };

    void bind_listener_group(const std::string& host,
                             const std::vector<uint16_t>& ports,
                             WireProtocol protocol);
    void start_authenticated_sv2();
    void start_plaintext_sv2();
    void worker_loop(ServerWorker& worker, const std::stop_token& stop);

    // A trusted-source connection awaiting its PROXY header, deferred to the reader pool so a
    // slow/stalled header can't block new-connection accepts.
    struct PendingProxyConn {
        int fd;
        std::string peer;       // TCP peer (replaced by the header's real address on success)
        size_t worker_index;    // the reactor that will adopt the fd once the header is read
    };
    // Enqueue an accepted fd for off-thread PROXY-header parsing; false if the bounded queue is
    // full so the acceptor sheds load instead of growing unbounded.
    bool enqueue_proxy_read(int fd, std::string peer, size_t worker_index);
    void proxy_reader_loop(const std::stop_token& stop);
    // Hand an accepted fd to reactor `worker_index` for adoption (queue + wake). Thread-safe:
    // called from the acceptor and the proxy reader pool.
    void deliver_to_worker(size_t worker_index, int fd, std::string peer, WireProtocol protocol);
    bool reserve_noise_handshake();
    void release_noise_handshake();

    Pool& pool_;
    std::string host_;
    std::vector<uint16_t> ports_;
    std::string sv2_host_;
    std::vector<uint16_t> sv2_ports_;
    std::string sv2_static_secret_key_file_;
    std::string sv2_authority_public_key_file_;
    std::string sv2_certificate_file_;
    std::shared_ptr<const sv2::NoiseCredentials> sv2_noise_credentials_;
    std::optional<int64_t> sv2_certificate_expiry_timestamp_;
    std::atomic<bool> certificate_validity_warning_logged_{false};
    std::string sv2_plaintext_host_;
    std::vector<uint16_t> sv2_plaintext_ports_;
    std::atomic<int> max_clients_;
    size_t max_line_bytes_;
    std::atomic<int> drop_idle_seconds_;
    std::atomic<int> auth_timeout_seconds_;
    std::atomic<int> max_protocol_errors_;
    std::atomic<double> work_rebroadcast_seconds_;
    std::vector<std::string> proxy_protocol_from_; // trusted PROXY-header sources (empty = off)
    unsigned worker_count_;
    std::atomic<size_t> incomplete_noise_handshakes_{0};
    std::vector<Listener> listeners_;
    std::vector<std::unique_ptr<ServerWorker>> workers_;

    // Bounded pool that runs the (blocking, up to ~2s) PROXY-header read off the acceptor thread.
    // proxy_pending_ counts fds queued or being read, so they count toward max_clients.
    std::deque<PendingProxyConn> proxy_queue_;
    std::mutex proxy_mutex_;
    std::condition_variable_any proxy_cv_;
    std::atomic<size_t> proxy_pending_{0};
    // Declared last so reader jthreads join before the queue/mutex/cv they use.
    std::vector<std::jthread> proxy_readers_;

    friend struct ServerTestPeek;
};

// 0 = auto (one per core, clamped so a cgroup CPU quota can't over-thread). Exposed for testing.
unsigned resolve_worker_count(int configured);

} // namespace erikslund::net
