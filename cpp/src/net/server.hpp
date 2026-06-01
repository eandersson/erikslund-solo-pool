#pragma once
// Stratum TCP server: a pool of epoll reactor threads. Each connection is owned by exactly one
// reactor, so per-connection state needs no locking; the work thread notifies sessions lock-free
// via the connection's shared_ptr.
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "core/config.hpp"
#include "pool/pool.hpp"

namespace erikslund::net {

struct ServerWorker; // per-reactor epoll state; defined in server.cpp

class Server {
public:
    Server(Pool& pool, const Config& config);

    // Bind + listen on every configured port. Throws on failure.
    void start();

    // Accept loop, round-robin onto reactors. Returns once `stop` fires (joins reactors).
    void run(const std::stop_token& stop);

    ~Server(); // out-of-line: workers_ holds the incomplete ServerWorker

private:
    struct Listener {
        int fd;
        uint16_t port;
    };

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
    void deliver_to_worker(size_t worker_index, int fd, std::string peer);

    Pool& pool_;
    std::string host_;
    std::vector<uint16_t> ports_;
    int max_clients_;
    size_t max_line_bytes_;
    int drop_idle_seconds_;
    int auth_timeout_seconds_;
    int max_protocol_errors_;
    double work_rebroadcast_seconds_;
    std::vector<std::string> proxy_protocol_from_; // trusted PROXY-header sources (empty = off)
    unsigned worker_count_;
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
};

// 0 = auto (one per core, clamped so a cgroup CPU quota can't over-thread). Exposed for testing.
unsigned resolve_worker_count(int configured);

} // namespace erikslund::net
