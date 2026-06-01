#include "net/server.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/logging.hpp"
#include "net/proxy_protocol.hpp"
#include "net/socket_connection.hpp"

namespace erikslund::net {

struct ClientConnection {
    int fd;
    std::shared_ptr<SocketConnection> socket;
    std::shared_ptr<stratum::Session> session;
    std::string buffer;
    std::chrono::steady_clock::time_point last_activity;
    std::chrono::steady_clock::time_point created_at;
};

struct ServerWorker {
    int epoll_fd = -1;
    int event_fd = -1; // acceptor pokes it to deliver new connections
    std::mutex queue_mutex;
    std::vector<std::pair<int, std::string>> incoming; // accepted (fd, peer) awaiting adoption
    std::atomic<size_t> pending{0};                    // incoming.size() visible to the accept gate
    std::unordered_map<int, std::unique_ptr<ClientConnection>> connections;
    std::jthread thread;
};

namespace {

constexpr int kMaxEventsPerWait = 64;        // epoll_event batch size
constexpr int kEpollWaitTimeoutMs = 500;     // wakes the loop to honor stop + run the idle sweep
constexpr size_t kReadChunkBytes = 4096;     // per-recv() read buffer
constexpr size_t kMaxReadBytesPerEvent = size_t{256} * 1024;
constexpr int kListenBacklog = 1024;
constexpr int kProxyHeaderTimeoutMs = 2000;  // PROXY header read deadline
// PROXY-header reads run on this bounded pool, off the acceptor thread, so a stalled/partial header
// can't block accept(). Excess past the queue cap is shed. Both bounds count toward max_clients.
constexpr unsigned kProxyReaderThreads = 4;
constexpr size_t kMaxProxyQueue = 256;
constexpr std::chrono::seconds kEvictionSweepInterval{1};

void set_nonblocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int bind_listener(const std::string& host, uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        throw std::runtime_error(std::string("socket() failed: ") + std::strerror(errno));

    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(port);
    if (host.empty() || host == "0.0.0.0")
        bind_address.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, host.c_str(), &bind_address.sin_addr) != 1)
        throw std::runtime_error("invalid bind host: " + host);

    if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address)) < 0)
        throw std::runtime_error("bind " + host + ":" + std::to_string(port) +
                                 " failed: " + std::strerror(errno));
    if (::listen(fd, kListenBacklog) < 0)
        throw std::runtime_error(std::string("listen() failed: ") + std::strerror(errno));
    set_nonblocking(fd);
    return fd;
}

} // namespace

unsigned resolve_worker_count(int configured) {
    if (configured > 0)
        return static_cast<unsigned>(configured);
    // hardware_concurrency() reports host cores, not a cgroup quota; clamp so a CPU-limited
    // container isn't over-threaded.
    constexpr unsigned kMaxAutoWorkers = 16;
    const unsigned cores = std::max(1u, std::thread::hardware_concurrency());
    return std::min(cores, kMaxAutoWorkers);
}

Server::Server(Pool& pool, const Config& config)
    : pool_(pool),
      host_(config.bind_host),
      ports_(config.stratum_ports()),
      max_clients_(config.max_clients),
      max_line_bytes_(config.max_line_bytes),
      drop_idle_seconds_(config.drop_idle_seconds),
      auth_timeout_seconds_(config.auth_timeout_seconds),
      max_protocol_errors_(config.max_protocol_errors),
      work_rebroadcast_seconds_(config.work_rebroadcast_seconds),
      proxy_protocol_from_(config.proxy_protocol_from),
      worker_count_(resolve_worker_count(config.worker_threads)) {}

// Out-of-line so ServerWorker is complete at the point unique_ptr is destroyed.
Server::~Server() = default;

void Server::start() {
    for (uint16_t port : ports_) {
        const int fd = bind_listener(host_, port);
        listeners_.push_back({fd, port});
        log::info("Stratum listening on {}:{}", host_, port);
    }
    if (proxy_protocol_from_.empty()) {
        log::info("PROXY protocol: disabled (all connections direct)");
    } else {
        std::string sources;
        for (const auto& source : proxy_protocol_from_)
            sources += (sources.empty() ? "" : ", ") + source;
        log::info("PROXY protocol: trusting headers from {} source(s): {}", proxy_protocol_from_.size(),
                  sources);
        for (const auto& source : proxy_protocol_from_)
            if (!valid_trusted_source(source))
                log::warning("PROXY protocol: trusted source \"{}\" is not a valid IP or IPv4 CIDR; "
                             "it will never match (check for stray characters)",
                             source);
    }
}

void Server::worker_loop(ServerWorker& worker, const std::stop_token& stop) {
    // `connection` dangles after this; callers must not touch it again.
    const auto remove_connection = [&](ClientConnection* connection) {
        const int fd = connection->fd;
        connection->socket->detach_reactor();
        ::epoll_ctl(worker.epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
        pool_.remove_client(connection->session);
        log::info("Client disconnected: {}", connection->socket->peer());
        worker.connections.erase(fd); // dtor closes the fd
    };

    // Feeds complete lines to the session. Returns false if the connection was removed.
    const auto handle_readable = [&](ClientConnection* connection) -> bool {
        char chunk[kReadChunkBytes];
        size_t consumed_this_event = 0;
        while (true) {
            const ssize_t n = ::recv(connection->fd, chunk, sizeof(chunk), 0);
            if (n > 0) {
                consumed_this_event += static_cast<size_t>(n);
                connection->last_activity = std::chrono::steady_clock::now();
                connection->buffer.append(chunk, static_cast<size_t>(n));
                // Scan with a moving offset and erase the consumed prefix once at the end, not
                // per line (which would be quadratic on a pipelined burst). handle_line copies out
                // what it keeps, so a view is safe.
                size_t start = 0;
                size_t newline;
                while ((newline = connection->buffer.find('\n', start)) != std::string::npos) {
                    std::string_view line(connection->buffer.data() + start, newline - start);
                    start = newline + 1;
                    if (!line.empty() && line.back() == '\r')
                        line.remove_suffix(1);
                    if (!line.empty()) {
                        connection->session->handle_line(line);
                        if (max_protocol_errors_ > 0 &&
                            connection->session->protocol_errors() >= max_protocol_errors_) {
                            log::info("Client {} exceeded the protocol-error budget ({}); "
                                      "disconnecting",
                                      connection->socket->peer(), max_protocol_errors_);
                            remove_connection(connection);
                            return false;
                        }
                    }
                }
                if (start > 0)
                    connection->buffer.erase(0, start);
                if (connection->buffer.size() > max_line_bytes_) {
                    log::info("Client {} sent an over-long line; disconnecting",
                              connection->socket->peer());
                    remove_connection(connection);
                    return false;
                }
                // Yield to other connections after the per-event budget; level-triggered EPOLLIN
                // re-fires for what's still buffered, so no data is lost.
                if (consumed_this_event >= kMaxReadBytesPerEvent)
                    return true;
                continue;
            }
            if (n == 0) { // orderly EOF
                remove_connection(connection);
                return false;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return true; // socket drained
            if (errno == EINTR)
                continue;
            remove_connection(connection); // hard error
            return false;
        }
    };

    // Adopt accepted fds: create the session and register with epoll.
    const auto drain_incoming = [&]() {
        std::vector<std::pair<int, std::string>> batch;
        {
            const std::lock_guard<std::mutex> lock(worker.queue_mutex);
            batch.swap(worker.incoming);
        }
        if (!batch.empty())
            worker.pending.fetch_sub(batch.size(), std::memory_order_relaxed);
        for (auto& [fd, peer] : batch) {
            set_nonblocking(fd);
            auto socket = std::make_shared<SocketConnection>(fd, work_rebroadcast_seconds_, std::move(peer));
            auto session = pool_.add_client(socket);
            auto connection = std::make_unique<ClientConnection>();
            connection->fd = fd;
            connection->socket = std::move(socket);
            connection->session = std::move(session);
            const auto created = std::chrono::steady_clock::now();
            connection->last_activity = created;
            connection->created_at = created;
            // Must be set before the fd is registered, with the same data ptr epoll uses below, so
            // the socket can (dis)arm EPOLLOUT as its outbox fills/drains.
            connection->socket->attach_reactor(worker.epoll_fd, connection.get());
            epoll_event event{};
            event.events = EPOLLIN;
            event.data.ptr = connection.get();
            if (::epoll_ctl(worker.epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
                pool_.remove_client(connection->session); // dropping it closes the fd
                continue;
            }
            worker.connections.emplace(fd, std::move(connection));
        }
    };

    // Evict silent (idle) and never-authorized connections.
    const auto sweep_expired = [&]() {
        if (drop_idle_seconds_ <= 0 && auth_timeout_seconds_ <= 0)
            return;
        const auto now = std::chrono::steady_clock::now();
        std::vector<ClientConnection*> expired;
        for (auto& [fd, connection] : worker.connections) {
            if (drop_idle_seconds_ > 0 &&
                now - connection->last_activity > std::chrono::seconds(drop_idle_seconds_)) {
                log::info("Client {} idle for over {}s; disconnecting", connection->socket->peer(),
                          drop_idle_seconds_);
                expired.push_back(connection.get());
            } else if (auth_timeout_seconds_ > 0 &&
                       now - connection->created_at > std::chrono::seconds(auth_timeout_seconds_) &&
                       !connection->session->authorized()) {
                log::info("Client {} did not authorize within {}s; disconnecting",
                          connection->socket->peer(), auth_timeout_seconds_);
                expired.push_back(connection.get());
            }
        }
        for (ClientConnection* connection : expired)
            remove_connection(connection);
    };

    epoll_event events[kMaxEventsPerWait];
    auto last_sweep = std::chrono::steady_clock::now();
    while (!stop.stop_requested()) {
        const int ready = ::epoll_wait(worker.epoll_fd, events, kMaxEventsPerWait, kEpollWaitTimeoutMs);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < ready; ++i) {
            if (events[i].data.ptr == nullptr) { // eventfd: new connections to adopt
                uint64_t drained;
                while (::read(worker.event_fd, &drained, sizeof(drained)) > 0) {
                }
                drain_incoming();
                continue;
            }
            ClientConnection* connection = static_cast<ClientConnection*>(events[i].data.ptr);
            try {
                if (events[i].events & (EPOLLHUP | EPOLLERR)) {
                    remove_connection(connection);
                    continue;
                }
                if (events[i].events & EPOLLOUT) {
                    if (!connection->socket->flush_outbox()) {
                        remove_connection(connection);
                        continue;
                    }
                }
                if (events[i].events & EPOLLIN)
                    handle_readable(connection);
            } catch (const std::exception& e) {
                // Isolate: one bad message drops only this client, not the reactor.
                log::warning("Client {} handler error ({}); disconnecting",
                             connection->socket->peer(), e.what());
                remove_connection(connection);
            }
        }

        // Time-based eviction sweep, independent of event volume (gating on ready == 0 would
        // starve it on a busy reactor).
        const auto now = std::chrono::steady_clock::now();
        if (now - last_sweep >= kEvictionSweepInterval) {
            sweep_expired();
            last_sweep = now;
        }
    }

    // Shutdown: detach every connection from epoll first (so still-running work/vardiff threads
    // can't epoll_ctl against records we free or the epoll fd we close below), then drop them.
    for (auto& [fd, connection] : worker.connections) {
        connection->socket->detach_reactor();
        pool_.remove_client(connection->session);
    }
    worker.connections.clear();
    // Close any fds accepted but never adopted -- nothing else owns them.
    {
        const std::lock_guard<std::mutex> lock(worker.queue_mutex);
        for (auto& [fd, peer] : worker.incoming)
            ::close(fd);
        worker.incoming.clear();
        worker.pending.store(0, std::memory_order_relaxed);
    }
    if (worker.epoll_fd >= 0)
        ::close(worker.epoll_fd);
    if (worker.event_fd >= 0)
        ::close(worker.event_fd);
}

void Server::deliver_to_worker(size_t worker_index, int fd, std::string peer) {
    ServerWorker& worker = *workers_[worker_index];
    {
        const std::lock_guard<std::mutex> lock(worker.queue_mutex);
        worker.incoming.push_back({fd, std::move(peer)});
        worker.pending.fetch_add(1, std::memory_order_relaxed);
    }
    const uint64_t one = 1;
    const ssize_t written = ::write(worker.event_fd, &one, sizeof(one));
    (void)written;
}

bool Server::enqueue_proxy_read(int fd, std::string peer, size_t worker_index) {
    {
        const std::lock_guard<std::mutex> lock(proxy_mutex_);
        if (proxy_queue_.size() >= kMaxProxyQueue)
            return false; // shed load: the bounded queue is full
        proxy_queue_.push_back({fd, std::move(peer), worker_index});
    }
    proxy_pending_.fetch_add(1, std::memory_order_relaxed);
    proxy_cv_.notify_one();
    return true;
}

void Server::proxy_reader_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        PendingProxyConn job;
        {
            std::unique_lock<std::mutex> lock(proxy_mutex_);
            proxy_cv_.wait(lock, stop, [this] { return !proxy_queue_.empty(); });
            if (proxy_queue_.empty())
                continue; // woken by stop with nothing to do
            job = std::move(proxy_queue_.front());
            proxy_queue_.pop_front();
        }
        // The blocking read happens here, on a pool thread, never on the acceptor.
        const auto header = read_proxy_header(job.fd, kProxyHeaderTimeoutMs);
        if (header.kind == ProxyHeaderKind::Malformed) {
            log::warning("PROXY protocol: malformed header from {}; dropping (first bytes: {})",
                         job.peer, header.detail);
            ::close(job.fd);
        } else {
            std::string peer;
            if (header.kind == ProxyHeaderKind::RealAddress)
                peer = header.address;   // header carried the real client addr
            else
                peer = std::move(job.peer); // Direct: keep the TCP peer
            deliver_to_worker(job.worker_index, job.fd, std::move(peer));
        }
        proxy_pending_.fetch_sub(1, std::memory_order_relaxed);
    }
}

void Server::run(const std::stop_token& stop) {
    for (unsigned i = 0; i < worker_count_; ++i) {
        auto worker = std::make_unique<ServerWorker>();
        worker->epoll_fd = ::epoll_create1(0);
        worker->event_fd = ::eventfd(0, EFD_NONBLOCK);
        if (worker->epoll_fd < 0 || worker->event_fd < 0)
            throw std::runtime_error("epoll/eventfd setup failed");
        epoll_event event{};
        event.events = EPOLLIN;
        event.data.ptr = nullptr;
        ::epoll_ctl(worker->epoll_fd, EPOLL_CTL_ADD, worker->event_fd, &event);
        ServerWorker* worker_ptr = worker.get();
        worker->thread =
            std::jthread([this, worker_ptr](const std::stop_token& st) { worker_loop(*worker_ptr, st); });
        workers_.push_back(std::move(worker));
    }
    log::info("Stratum reactor: {} threads", worker_count_);

    // Only spin up the reader pool when PROXY protocol is enabled.
    if (!proxy_protocol_from_.empty()) {
        for (unsigned i = 0; i < kProxyReaderThreads; ++i)
            proxy_readers_.emplace_back(
                [this](const std::stop_token& st) { proxy_reader_loop(st); });
        log::info("PROXY-header reader pool: {} threads", kProxyReaderThreads);
    }

    std::vector<pollfd> poll_fds;
    poll_fds.reserve(listeners_.size());
    for (const auto& listener : listeners_)
        poll_fds.push_back({listener.fd, POLLIN, 0});

    size_t next_worker = 0;
    while (!stop.stop_requested()) {
        for (auto& poll_fd : poll_fds)
            poll_fd.revents = 0;
        const int ready = ::poll(poll_fds.data(), static_cast<nfds_t>(poll_fds.size()), 500);
        if (ready <= 0)
            continue;

        for (size_t i = 0; i < poll_fds.size(); ++i) {
            if (!(poll_fds[i].revents & POLLIN))
                continue;
            while (true) {
                sockaddr_storage addr{};
                socklen_t addr_len = sizeof(addr);
                const int fd = ::accept(listeners_[i].fd, reinterpret_cast<sockaddr*>(&addr), &addr_len);
                if (fd < 0)
                    break;
                // Capture the peer now -- a client that closes immediately would otherwise read
                // back "unknown" via a later getpeername().
                std::string peer = describe_peer(addr);
                // Count fds accepted-but-not-adopted (worker.incoming) and fds queued/being read
                // for a PROXY header (proxy_pending_) against the cap, else a burst between accept
                // and adoption overshoots max_clients.
                size_t pending_total = proxy_pending_.load(std::memory_order_relaxed);
                for (const auto& w : workers_)
                    pending_total += w->pending.load(std::memory_order_relaxed);
                if (pool_.client_count() + pending_total >= static_cast<size_t>(max_clients_)) {
                    log::warning("Max clients ({}) reached; dropping connection", max_clients_);
                    ::close(fd);
                    continue;
                }
                if (!proxy_protocol_from_.empty()) {
                    const std::string src_ip = peer.substr(0, peer.rfind(':'));
                    if (source_trusted(src_ip, proxy_protocol_from_)) {
                        // Defer the (up to ~2s) header read to the reader pool: doing it here would
                        // block accept() for every other connection. The pool delivers the fd once
                        // parsed.
                        const size_t worker_index = next_worker++ % worker_count_;
                        if (!enqueue_proxy_read(fd, std::move(peer), worker_index)) {
                            log::warning("PROXY-header reader queue full; dropping connection");
                            ::close(fd);
                        }
                        continue;
                    }
                }
                // Direct connection (PROXY disabled or untrusted source): hand straight to a reactor.
                deliver_to_worker(next_worker++ % worker_count_, fd, std::move(peer));
            }
        }
    }

    // Stop the reader pool first -- its threads call deliver_to_worker (reference workers_), so
    // they must finish before the reactors are destroyed. A reader stuck in a header read exits
    // within kProxyHeaderTimeoutMs. Then close any still-queued fds.
    for (auto& reader : proxy_readers_)
        reader.request_stop();
    proxy_cv_.notify_all();
    proxy_readers_.clear(); // jthread dtor joins each reader
    {
        const std::lock_guard<std::mutex> lock(proxy_mutex_);
        for (auto& job : proxy_queue_)
            ::close(job.fd);
        proxy_queue_.clear();
        proxy_pending_.store(0, std::memory_order_relaxed);
    }

    for (auto& worker : workers_) {
        worker->thread.request_stop();
        const uint64_t one = 1;
        ssize_t written = ::write(worker->event_fd, &one, sizeof(one));
        (void)written;
    }
    workers_.clear();

    for (auto& listener : listeners_)
        if (listener.fd >= 0)
            ::close(listener.fd);
    listeners_.clear();
}

} // namespace erikslund::net
