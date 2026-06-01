#pragma once
// Read-only HTTP/1.1 status/metrics API (GET/HEAD only); slow-loris-resistant.
#include <cstdint>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>

#include "pool/pool.hpp"

namespace erikslund::api {

struct HttpResponse {
    int status;
    std::string content_type;
    std::string body;
};

std::optional<std::pair<std::string, std::string>> parse_request_line(std::string_view line);

HttpResponse route(const std::string& method, const std::string& path, Pool& pool);

class HttpServer {
public:
    HttpServer(Pool& pool, std::string host, uint16_t port);

    void start();
    void run(const std::stop_token& stop);
    uint16_t port() const { return port_; }

private:
    void accept_loop(const std::stop_token& stop);
    void serve_connection(int fd, const std::stop_token& stop);

    Pool& pool_;
    std::string host_;
    uint16_t port_;
    int listen_fd_ = -1;
};

} // namespace erikslund::api
