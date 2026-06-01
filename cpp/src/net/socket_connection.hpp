#pragma once
// TCP-backed Connection with a bounded, non-blocking outbound buffer.
#include <sys/socket.h> // sockaddr_storage

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <string_view>

#include "stratum/session.hpp"

namespace erikslund::net {

class SocketConnection : public stratum::Connection {
public:
    SocketConnection(int fd, double work_rebroadcast_seconds, std::string peer);
    ~SocketConnection() override;

    SocketConnection(const SocketConnection&) = delete;
    SocketConnection& operator=(const SocketConnection&) = delete;

    void send_line(std::string_view line) override; // never blocks
    std::string peer() const override { return peer_; }

    int fd() const { return fd_; }

    void attach_reactor(int epoll_fd, void* epoll_data);
    void detach_reactor();
    bool flush_outbox();

    // True once a write failed or the outbox overflowed; the reactor then drops the connection.
    bool dead() const { return dead_.load(std::memory_order_relaxed); }

private:
    bool drain_locked();                       // send queued bytes; false on a hard write error
    void arm_write_interest_locked(bool want_write); // (un)register EPOLLOUT
    void fail_locked();                        // mark dead + shutdown so the reactor reaps

    int fd_;
    std::string peer_;

    std::mutex write_mutex_;     // serializes all access to the outbox / arm state below
    std::string outbox_;         // framed bytes awaiting the socket
    std::size_t outbox_pos_ = 0; // bytes already written from the front of outbox_
    bool epollout_armed_ = false;
    int epoll_fd_ = -1;
    void* epoll_data_ = nullptr;
    std::atomic<bool> dead_{false};
};

int keepalive_user_timeout_ms(double work_rebroadcast_seconds);
void tune_socket(int fd, double work_rebroadcast_seconds);
std::string describe_peer(const sockaddr_storage& addr);

} // namespace erikslund::net
