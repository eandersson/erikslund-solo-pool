#include "api/http_server.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <format>
#include <stdexcept>
#include <thread>
#include <vector>

#include "api/metrics.hpp"
#include "core/logging.hpp"

namespace erikslund::api {

namespace {

constexpr std::string_view kAddressChars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
constexpr size_t kMaxRequestBytes = 8192;
constexpr int kMaxRequestsPerConn = 100;
constexpr int kKeepAliveIdleMs = 5000;
constexpr int kHeaderReadMs = 5000;
constexpr int kWriteMs = 5000;
constexpr unsigned kMinWorkers = 2;
constexpr unsigned kMaxWorkers = 4;

std::string_view reason_phrase(int status) {
    switch (status) {
    case 200:
        return "OK";
    case 400:
        return "Bad Request";
    case 404:
        return "Not Found";
    case 405:
        return "Method Not Allowed";
    case 503:
        return "Service Unavailable";
    default:
        return "OK";
    }
}

HttpResponse json_ok(std::string body) {
    return {200, "application/json; charset=utf-8", std::move(body)};
}

std::string to_lower(std::string s) {
    for (char& ch : s)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return s;
}

bool wants_keep_alive(const std::string& head, size_t header_end) {
    const std::string lower = to_lower(head.substr(0, header_end));
    if (lower.find("connection: close") != std::string::npos)
        return false;
    if (lower.find("connection: keep-alive") != std::string::npos)
        return true;
    const size_t line_end = lower.find("\r\n");
    return lower.substr(0, line_end).find("http/1.1") != std::string::npos;
}

std::string build_response(const std::string& method, const HttpResponse& response,
                           bool keep_alive) {
    std::string out = std::format(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}\r\n", response.status,
        reason_phrase(response.status), response.content_type, response.body.size(),
        keep_alive ? "Connection: keep-alive\r\nKeep-Alive: timeout=5, max=100\r\n"
                   : "Connection: close\r\n");
    if (method != "HEAD")
        out += response.body;
    return out;
}

bool send_all(int fd, const std::string& out, const std::stop_token& stop) {
    size_t sent = 0;
    while (sent < out.size() && !stop.stop_requested()) {
        pollfd pfd{fd, POLLOUT, 0};
        const int poll_result = ::poll(&pfd, 1, kWriteMs);
        if (poll_result <= 0)
            return false;
        const ssize_t n = ::send(fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
        if (n > 0)
            sent += static_cast<size_t>(n);
        else if (n < 0 && errno == EINTR)
            continue;
        else
            return false;
    }
    return sent == out.size();
}

} // namespace

std::optional<std::pair<std::string, std::string>> parse_request_line(std::string_view line) {
    const auto first_space = line.find(' ');
    if (first_space == std::string_view::npos)
        return std::nullopt;
    const auto second_space = line.find(' ', first_space + 1);
    if (second_space == std::string_view::npos)
        return std::nullopt;

    std::string method(line.substr(0, first_space));
    std::string path(line.substr(first_space + 1, second_space - first_space - 1));
    if (const auto query = path.find('?'); query != std::string::npos)
        path.erase(query);
    if (method.empty() || path.empty())
        return std::nullopt;
    return std::make_pair(std::move(method), std::move(path));
}

// Lets route() 404 an unknown path before building the full snapshot (cheap scanner probes).
static bool is_data_path(const std::string& path) {
    return path == "/metrics" || path == "/metrics.json" || path == "/status" ||
           path == "/stats/pool" || path == "/stats/stratifier" || path == "/stats/connector" ||
           path == "/stats/generator" || path == "/" || path.rfind("/stats/client/", 0) == 0;
}

HttpResponse route(const std::string& method, const std::string& path, Pool& pool) {
    if (method != "GET" && method != "HEAD")
        return {405, "text/plain; charset=utf-8", "method not allowed\n"};

    // /health needs only the readiness predicate, not the full snapshot.
    if (path == "/health")
        return pool.ready() ? HttpResponse{200, "text/plain; charset=utf-8", "ok\n"}
                            : HttpResponse{503, "text/plain; charset=utf-8", "degraded\n"};
    if (!is_data_path(path))
        return {404, "text/plain; charset=utf-8", "not found\n"};

    const PoolSnapshot snapshot = pool.snapshot();

    if (path == "/metrics")
        return {200, "text/plain; version=0.0.4; charset=utf-8", build_prometheus(snapshot)};
    if (path == "/metrics.json")
        return json_ok(metrics_json(snapshot).dump());
    if (path == "/status")
        return json_ok(status_json(snapshot).dump());
    if (path == "/stats/pool")
        return json_ok(pool_stats_json(snapshot).dump());
    if (path == "/stats/stratifier")
        return json_ok(stratifier_stats_json(snapshot).dump());
    if (path == "/stats/connector")
        return json_ok(connector_stats_json(snapshot).dump());
    if (path == "/stats/generator")
        return json_ok(generator_stats_json(snapshot).dump());
    if (path.rfind("/stats/client/", 0) == 0) {
        const std::string address = path.substr(std::strlen("/stats/client/"));
        if (address.empty() || address.size() > 127 ||
            address.find_first_not_of(kAddressChars) != std::string::npos)
            return {400, "text/plain; charset=utf-8", "invalid address\n"};
        const auto body = client_stats_json(snapshot, address);
        if (!body)
            return {404, "text/plain; charset=utf-8", "unknown address\n"};
        return json_ok(body->dump());
    }
    if (path == "/")
        return {200, "text/html; charset=utf-8", dashboard_html(snapshot)};

    return {404, "text/plain; charset=utf-8", "not found\n"};
}

HttpServer::HttpServer(Pool& pool, std::string host, uint16_t port)
    : pool_(pool), host_(std::move(host)), port_(port) {}

void HttpServer::start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0)
        throw std::runtime_error(std::string("api socket() failed: ") + std::strerror(errno));

    int one = 1;
    ::setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    sockaddr_in bind_address{};
    bind_address.sin_family = AF_INET;
    bind_address.sin_port = htons(port_);
    if (host_.empty() || host_ == "0.0.0.0")
        bind_address.sin_addr.s_addr = INADDR_ANY;
    else if (inet_pton(AF_INET, host_.c_str(), &bind_address.sin_addr) != 1)
        throw std::runtime_error("api invalid host: " + host_);

    if (::bind(listen_fd_, reinterpret_cast<sockaddr*>(&bind_address), sizeof(bind_address)) < 0)
        throw std::runtime_error("api bind " + host_ + ":" + std::to_string(port_) +
                                 " failed: " + std::strerror(errno));
    if (::listen(listen_fd_, 64) < 0)
        throw std::runtime_error(std::string("api listen() failed: ") + std::strerror(errno));

    const int flags = ::fcntl(listen_fd_, F_GETFL, 0);
    if (flags >= 0)
        ::fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);

    log::info("HTTP API listening on {}:{} (/metrics, /status, /stats/*)", host_, port_);
}

void HttpServer::run(const std::stop_token& stop) {
    const unsigned n = std::clamp(std::thread::hardware_concurrency(), kMinWorkers, kMaxWorkers);
    std::vector<std::jthread> workers;
    workers.reserve(n - 1);
    for (unsigned i = 1; i < n; ++i)
        workers.emplace_back([this, stop] { accept_loop(stop); });
    accept_loop(stop);
    workers.clear();

    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
}

void HttpServer::accept_loop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        pollfd pfd{listen_fd_, POLLIN, 0};
        if (::poll(&pfd, 1, 500) <= 0)
            continue;
        const int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0)
            continue;
        serve_connection(fd, stop);
    }
}

void HttpServer::serve_connection(int fd, const std::stop_token& stop) try {
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    std::string buffer;
    char chunk[2048];
    int requests = 0;

    while (!stop.stop_requested() && requests < kMaxRequestsPerConn) {
        size_t header_end;
        while ((header_end = buffer.find("\r\n\r\n")) == std::string::npos) {
            if (buffer.size() > kMaxRequestBytes) {
                send_all(fd, build_response("GET", {400, "text/plain; charset=utf-8",
                                                    "request too large\n"}, false),
                         stop);
                ::close(fd);
                return;
            }
            pollfd pfd{fd, POLLIN, 0};
            const int poll_result = ::poll(&pfd, 1, buffer.empty() ? kKeepAliveIdleMs : kHeaderReadMs);
            if (poll_result == 0) {
                ::close(fd);
                return;
            }
            if (poll_result < 0) {
                if (errno == EINTR)
                    continue;
                ::close(fd);
                return;
            }
            const ssize_t n = ::recv(fd, chunk, sizeof(chunk), 0);
            if (n <= 0) {
                ::close(fd);
                return;
            }
            buffer.append(chunk, static_cast<size_t>(n));
        }
        ++requests;

        const std::string request = buffer.substr(0, header_end + 4);
        buffer.erase(0, header_end + 4);
        const std::string request_line = request.substr(0, request.find("\r\n"));

        std::string method = "GET";
        HttpResponse response;
        bool parsed_ok = false;
        if (const auto parsed = parse_request_line(request_line)) {
            method = parsed->first;
            response = route(parsed->first, parsed->second, pool_);
            parsed_ok = true;
        } else {
            response = {400, "text/plain; charset=utf-8", "bad request\n"};
        }

        const bool keep_alive = parsed_ok && (method == "GET" || method == "HEAD") &&
                                wants_keep_alive(request, header_end) &&
                                requests < kMaxRequestsPerConn;
        if (!send_all(fd, build_response(method, response, keep_alive), stop) || !keep_alive) {
            ::close(fd);
            return;
        }
    }
    ::close(fd);
} catch (const std::exception& e) {
    // An exception escaping a worker jthread calls std::terminate().
    log::warning("HTTP connection handler error: {}", e.what());
    ::close(fd);
}

} // namespace erikslund::api
