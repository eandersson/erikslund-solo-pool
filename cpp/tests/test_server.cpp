#include <doctest/doctest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include "bitcoin/work_source.hpp"
#include "core/config.hpp"
#include "net/server.hpp"
#include "pool/pool.hpp"

using namespace erikslund;
using namespace erikslund::net;

namespace erikslund::net {
struct ServerTestPeek {
    static uint16_t listener_port(const Server& server) {
        sockaddr_in address{};
        socklen_t address_size = sizeof(address);
        if (server.listeners_.empty() ||
            ::getsockname(server.listeners_.front().fd, reinterpret_cast<sockaddr*>(&address),
                          &address_size) != 0)
            throw std::runtime_error("could not read test listener port");
        return ntohs(address.sin_port);
    }
};
} // namespace erikslund::net

namespace {

class FinalSubmitWorkSource final : public bitcoin::WorkSource {
public:
    bitcoin::ChainInfo detect_chain() override { return {.chain = "regtest", .blocks = 199}; }
    std::string get_tip() override { return {}; }
    bitcoin::BlockTemplate fetch_template() override { return {}; }
    bitcoin::HeaderFacts fetch_header(const std::string&) override { return {}; }
    std::optional<std::string> submit_block_hex(const std::string&) override { return std::nullopt; }
};

template <typename Predicate>
bool wait_until(Predicate&& predicate) {
    for (int attempt = 0; attempt < 1000; ++attempt) {
        if (predicate())
            return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return predicate();
}

bool send_all(int fd, std::string_view data) {
    while (!data.empty()) {
        const ssize_t written = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        if (written <= 0)
            return false;
        data.remove_prefix(static_cast<size_t>(written));
    }
    return true;
}

} // namespace

TEST_CASE("resolve_worker_count honors an explicit count and clamps auto") {
    CHECK(resolve_worker_count(4) == 4u);
    CHECK(resolve_worker_count(100) == 100u); // explicit is unclamped

    // 0 = auto: clamped so a cgroup CPU quota can't over-thread.
    const unsigned auto_count = resolve_worker_count(0);
    CHECK(auto_count >= 1u);
    CHECK(auto_count <= 16u);
}

TEST_CASE("an explicit single worker is honored") {
    CHECK(resolve_worker_count(1) == 1u);
}

TEST_CASE("a negative configured count is treated as auto") {
    // configured <= 0 falls into the auto branch (clamped 1..16).
    const unsigned auto_count = resolve_worker_count(-1);
    CHECK(auto_count >= 1u);
    CHECK(auto_count <= 16u);
    // Auto is deterministic on a given host: two calls agree.
    CHECK(resolve_worker_count(-1) == resolve_worker_count(0));
}

TEST_CASE("a final submit is processed before a disconnected client is removed") {
    Config config;
    config.bind_host = "127.0.0.1";
    config.bind_port = 0;
    config.worker_threads = 1;

    FinalSubmitWorkSource source;
    Pool pool(config, source);
    pool.detect_network();
    Server server(pool, config);
    server.start();

    const int client_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(client_fd >= 0);
    sockaddr_in server_address{};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(ServerTestPeek::listener_port(server));
    REQUIRE(::inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr) == 1);
    REQUIRE(::connect(client_fd, reinterpret_cast<sockaddr*>(&server_address),
                      sizeof(server_address)) == 0);

    const std::string request =
        R"({"id":1,"method":"mining.subscribe","params":["test"]}
{"id":2,"method":"mining.authorize","params":["bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf.worker","x"]}
{"id":3,"method":"mining.submit","params":["worker","missing","00","00000000","00000000"]}
)";
    REQUIRE(send_all(client_fd, request));
    const linger reset_on_close{1, 0};
    REQUIRE(::setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &reset_on_close,
                         sizeof(reset_on_close)) == 0);
    ::close(client_fd);

    std::jthread server_thread([&](const std::stop_token& stop) { server.run(stop); });
    CHECK(wait_until([&] { return pool.snapshot().shares_rejected == 1; }));
    CHECK(wait_until([&] { return pool.client_count() == 0; }));
    server_thread.request_stop();
    server_thread.join();
}
