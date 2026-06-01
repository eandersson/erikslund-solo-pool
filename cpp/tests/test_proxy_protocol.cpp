#include <doctest/doctest.h>

#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <string>
#include <vector>

#include "net/proxy_protocol.hpp"

using namespace erikslund::net;

namespace {

const std::vector<uint8_t> kV2Sig = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                                     0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};

// A connected socket pair preloaded with `bytes`; the writer is then closed so reads see EOF
// after the buffered bytes (no blocking). Returns the reader fd for read_proxy_header to consume.
int fd_with(const std::vector<uint8_t>& bytes) {
    int sv[2] = {-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
    if (!bytes.empty())
        REQUIRE(::write(sv[1], bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size()));
    ::close(sv[1]); // EOF after the buffered bytes; already-written data stays readable
    return sv[0];
}

std::vector<uint8_t> bytes_of(const std::string& s) { return {s.begin(), s.end()}; }

// Whatever read_proxy_header did NOT consume (so tests can prove it read exactly the header).
std::string drain(int fd) {
    std::string out;
    char buf[256];
    ssize_t n;
    while ((n = ::recv(fd, buf, sizeof(buf), 0)) > 0)
        out.append(buf, static_cast<size_t>(n));
    return out;
}

} // namespace

TEST_CASE("PROXY v1: TCP4 yields src ip:port") {
    const auto r = parse_proxy_v1("PROXY TCP4 1.2.3.4 5.6.7.8 6324 3333");
    REQUIRE(r.has_value());
    CHECK(*r == "1.2.3.4:6324");
}

TEST_CASE("PROXY v1: TCP6 yields src ip:port") {
    const auto r = parse_proxy_v1("PROXY TCP6 2001:db8::1 2001:db8::2 6324 3333");
    REQUIRE(r.has_value());
    CHECK(*r == "2001:db8::1:6324");
}

TEST_CASE("PROXY v1: UNKNOWN / malformed -> nullopt") {
    CHECK_FALSE(parse_proxy_v1("PROXY UNKNOWN").has_value());
    CHECK_FALSE(parse_proxy_v1("PROXY TCP4 1.2.3.4 5.6.7.8 6324").has_value());        // too few fields
    CHECK_FALSE(parse_proxy_v1("PROXY TCP4 not.an.ip 5.6.7.8 6324 3333").has_value()); // bad ip
    CHECK_FALSE(parse_proxy_v1("PROXY TCP4 1.2.3.4 5.6.7.8 99999 3333").has_value());  // bad port
    CHECK_FALSE(parse_proxy_v1("GET / HTTP/1.1").has_value());
    CHECK_FALSE(parse_proxy_v1("").has_value());
}

TEST_CASE("PROXY v2: IPv4 PROXY command yields src ip:port") {
    const std::vector<uint8_t> h = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A, // signature
        0x21,             // version 2, command PROXY
        0x11,             // AF_INET, STREAM
        0x00, 0x0C,       // addr block length = 12
        1, 2, 3, 4,       // src 1.2.3.4
        5, 6, 7, 8,       // dst 5.6.7.8
        0x18, 0xB4,       // src port 6324
        0x0D, 0x05,       // dst port 3333
    };
    const auto r = parse_proxy_v2(h.data(), h.size());
    REQUIRE(r.has_value());
    CHECK(*r == "1.2.3.4:6324");
}

TEST_CASE("PROXY v2: LOCAL command and bad signature -> nullopt") {
    std::vector<uint8_t> local = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
        0x20, 0x11, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0x18, 0xB4, 0x0D, 0x05,
    };
    CHECK_FALSE(parse_proxy_v2(local.data(), local.size()).has_value()); // command LOCAL
    const std::vector<uint8_t> garbage(16, 0);
    CHECK_FALSE(parse_proxy_v2(garbage.data(), garbage.size()).has_value());
}

TEST_CASE("source_trusted: exact IP and IPv4 CIDR") {
    const std::vector<std::string> trusted = {"10.0.0.5", "172.19.0.0/16"};
    CHECK(source_trusted("10.0.0.5", trusted));
    CHECK(source_trusted("172.19.4.7", trusted));
    CHECK_FALSE(source_trusted("10.0.0.6", trusted));
    CHECK_FALSE(source_trusted("172.20.0.1", trusted));
    CHECK_FALSE(source_trusted("1.2.3.4", {}));
}

TEST_CASE("valid_trusted_source: catches typo'd entries") {
    CHECK(valid_trusted_source("13.60.28.119"));     // bare IPv4
    CHECK(valid_trusted_source("2001:db8::1"));       // bare IPv6
    CHECK(valid_trusted_source("172.19.0.0/16"));     // IPv4 CIDR
    CHECK(valid_trusted_source("10.0.0.0/0"));
    CHECK_FALSE(valid_trusted_source("1 - 13.60.28.119")); // stray list-index prefix
    CHECK_FALSE(valid_trusted_source("13.60.28.119 "));     // trailing space
    CHECK_FALSE(valid_trusted_source("172.19.0.0/33"));     // prefix out of range
    CHECK_FALSE(valid_trusted_source("not-an-ip"));
    CHECK_FALSE(valid_trusted_source(""));
}

TEST_CASE("PROXY v2: IPv6 PROXY command yields src ip:port") {
    std::vector<uint8_t> h = kV2Sig;
    for (uint8_t b : {0x21, 0x21, 0x00, 0x24}) // v2 PROXY, AF_INET6|STREAM, addr_len 36
        h.push_back(b);
    const std::vector<uint8_t> src = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const std::vector<uint8_t> dst = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    h.insert(h.end(), src.begin(), src.end());
    h.insert(h.end(), dst.begin(), dst.end());
    for (uint8_t b : {0x18, 0xB4, 0x0D, 0x05}) // sport 6324, dport 3333
        h.push_back(b);
    const auto r = parse_proxy_v2(h.data(), h.size());
    REQUIRE(r.has_value());
    CHECK(*r == "2001:db8::1:6324");
}

TEST_CASE("PROXY v2: IPv4 with a trailing TLV still yields src ip:port") {
    // addr_len 16 = 12-byte address block + a 4-byte TLV the parser must skip, not choke on.
    std::vector<uint8_t> h = kV2Sig;
    for (uint8_t b : {0x21, 0x11, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 0x18, 0xB4, 0x0D, 0x05,
                      0x03, 0x00, 0x01, 0xAB})
        h.push_back(b);
    const auto r = parse_proxy_v2(h.data(), h.size());
    REQUIRE(r.has_value());
    CHECK(*r == "1.2.3.4:6324");
}

TEST_CASE("read_proxy_header: v1 header -> RealAddress, trailing bytes preserved") {
    auto bytes = bytes_of("PROXY TCP4 1.2.3.4 5.6.7.8 6324 3333\r\n");
    const std::string rest = "{\"id\":1,\"method\":\"mining.subscribe\"}\n";
    const auto tail = bytes_of(rest);
    bytes.insert(bytes.end(), tail.begin(), tail.end());
    const int fd = fd_with(bytes);
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::RealAddress);
    CHECK(r.address == "1.2.3.4:6324");
    CHECK(drain(fd) == rest); // consumed exactly the header line
    ::close(fd);
}

TEST_CASE("read_proxy_header: v2 IPv4 PROXY -> RealAddress, trailing bytes preserved") {
    std::vector<uint8_t> bytes = kV2Sig;
    for (uint8_t b : {0x21, 0x11, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0x18, 0xB4, 0x0D, 0x05})
        bytes.push_back(b);
    const std::string rest = "{\"x\":1}\n";
    const auto tail = bytes_of(rest);
    bytes.insert(bytes.end(), tail.begin(), tail.end());
    const int fd = fd_with(bytes);
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::RealAddress);
    CHECK(r.address == "1.2.3.4:6324");
    CHECK(drain(fd) == rest);
    ::close(fd);
}

TEST_CASE("read_proxy_header: v2 LOCAL (health check) -> Direct, trailing preserved") {
    std::vector<uint8_t> bytes = kV2Sig;
    for (uint8_t b : {0x20, 0x00, 0x00, 0x00}) // v2 LOCAL, addr_len 0
        bytes.push_back(b);
    const std::string rest = "{\"hc\":1}\n";
    const auto tail = bytes_of(rest);
    bytes.insert(bytes.end(), tail.begin(), tail.end());
    const int fd = fd_with(bytes);
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::Direct); // not dropped; use the real TCP endpoint
    CHECK(r.address.empty());
    CHECK(drain(fd) == rest);
    ::close(fd);
}

TEST_CASE("read_proxy_header: v1 UNKNOWN -> Direct (header line consumed)") {
    const int fd = fd_with(bytes_of("PROXY UNKNOWN\r\n{\"x\":1}\n"));
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::Direct);
    CHECK(drain(fd) == "{\"x\":1}\n");
    ::close(fd);
}

TEST_CASE("read_proxy_header: no header (direct connect) -> Direct, nothing consumed") {
    const std::string payload = "{\"id\":1,\"method\":\"mining.subscribe\"}\n";
    const int fd = fd_with(bytes_of(payload));
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::Direct);
    CHECK(drain(fd) == payload); // only peeked; full payload left for the reactor
    ::close(fd);
}

TEST_CASE("read_proxy_header: peer closed with no data -> Direct") {
    const int fd = fd_with({});
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::Direct);
    ::close(fd);
}

TEST_CASE("read_proxy_header: bad v2 signature -> Malformed with hex detail") {
    auto bytes = bytes_of("garbage-not-a-proxy-header-xxxxx"); // long enough to read a 16-byte head
    bytes.front() = 0x0D;                                      // looks like v2 to the dispatcher
    const int fd = fd_with(bytes);
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::Malformed);
    CHECK_FALSE(r.detail.empty());            // hex snapshot for diagnosing the real bytes
    CHECK(r.detail.substr(0, 2) == "0d");     // starts with the peeked 0x0D
    ::close(fd);
}

TEST_CASE("read_proxy_header: v1-looking line with no CRLF -> Malformed") {
    const int fd = fd_with(std::vector<uint8_t>(120, 'P')); // 'P' dispatches to v1; never a newline
    const auto r = read_proxy_header(fd, 1000);
    CHECK(r.kind == ProxyHeaderKind::Malformed);
    ::close(fd);
}
