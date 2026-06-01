#include "net/proxy_protocol.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>

namespace erikslund::net {

namespace {

std::vector<std::string_view> split_ws(std::string_view s) {
    std::vector<std::string_view> out;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && s[i] == ' ')
            ++i;
        const size_t start = i;
        while (i < s.size() && s[i] != ' ')
            ++i;
        if (i > start)
            out.push_back(s.substr(start, i - start));
    }
    return out;
}

bool valid_ipv4(std::string_view ip) {
    in_addr a{};
    return inet_pton(AF_INET, std::string(ip).c_str(), &a) == 1;
}

bool valid_ipv6(std::string_view ip) {
    in6_addr a{};
    return inet_pton(AF_INET6, std::string(ip).c_str(), &a) == 1;
}

bool valid_port(std::string_view p) {
    if (p.empty() || p.size() > 5)
        return false;
    int v = 0;
    for (const char c : p) {
        if (c < '0' || c > '9')
            return false;
        v = v * 10 + (c - '0');
    }
    return v >= 0 && v <= 65535;
}

// (ip & mask) == (net & mask), IPv4. Returns false on any parse error.
bool ipv4_in_cidr(const std::string& ip, std::string_view net, int prefix) {
    if (prefix < 0 || prefix > 32)
        return false;
    in_addr ip_addr{};
    in_addr net_addr{};
    if (inet_pton(AF_INET, ip.c_str(), &ip_addr) != 1)
        return false;
    if (inet_pton(AF_INET, std::string(net).c_str(), &net_addr) != 1)
        return false;
    const uint32_t mask = prefix == 0 ? 0u : htonl(0xFFFFFFFFu << (32 - prefix));
    return (ip_addr.s_addr & mask) == (net_addr.s_addr & mask);
}

} // namespace

std::optional<std::string> parse_proxy_v1(std::string_view line) {
    const auto tok = split_ws(line);
    if (tok.size() < 2 || tok[0] != "PROXY")
        return std::nullopt;
    const std::string_view proto = tok[1];
    if (proto != "TCP4" && proto != "TCP6")
        return std::nullopt; // UNKNOWN or other -> caller keeps the direct address
    if (tok.size() != 6)
        return std::nullopt;
    const std::string_view src = tok[2];
    const std::string_view sport = tok[4];
    const bool ip_ok = proto == "TCP4" ? valid_ipv4(src) : valid_ipv6(src);
    if (!ip_ok || !valid_port(sport))
        return std::nullopt;
    return std::string(src) + ":" + std::string(sport);
}

std::optional<std::string> parse_proxy_v2(const uint8_t* data, std::size_t len) {
    static constexpr std::array<uint8_t, 12> kSig = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                                                     0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
    if (len < 16 || std::memcmp(data, kSig.data(), kSig.size()) != 0)
        return std::nullopt;
    if ((data[12] >> 4) != 0x2)
        return std::nullopt; // version must be 2
    const uint8_t command = data[12] & 0x0F;
    if (command != 0x1)
        return std::nullopt; // 0=LOCAL -> keep direct address; only PROXY=1 carries an addr
    const uint8_t family = data[13] >> 4;    // 1=AF_INET, 2=AF_INET6
    const uint8_t transport = data[13] & 0x0F; // 1=STREAM (TCP)
    const uint16_t addr_len = static_cast<uint16_t>((data[14] << 8) | data[15]);
    const uint8_t* addr = data + 16;
    if (16u + addr_len > len || transport != 0x1)
        return std::nullopt;

    char host[INET6_ADDRSTRLEN] = {};
    uint16_t port = 0;
    if (family == 0x1) { // IPv4: src(4) dst(4) sport(2) dport(2)
        if (addr_len < 12)
            return std::nullopt;
        in_addr a{};
        std::memcpy(&a, addr, 4);
        inet_ntop(AF_INET, &a, host, sizeof(host));
        port = static_cast<uint16_t>((addr[8] << 8) | addr[9]);
    } else if (family == 0x2) { // IPv6: src(16) dst(16) sport(2) dport(2)
        if (addr_len < 36)
            return std::nullopt;
        in6_addr a{};
        std::memcpy(&a, addr, 16);
        inet_ntop(AF_INET6, &a, host, sizeof(host));
        port = static_cast<uint16_t>((addr[32] << 8) | addr[33]);
    } else {
        return std::nullopt;
    }
    return std::string(host) + ":" + std::to_string(port);
}

bool source_trusted(const std::string& ip, const std::vector<std::string>& trusted) {
    for (const std::string& entry : trusted) {
        const size_t slash = entry.find('/');
        if (slash == std::string::npos) {
            if (entry == ip) // exact IP (v4 or v6)
                return true;
            continue;
        }
        const std::string net = entry.substr(0, slash);
        int prefix = 0;
        bool digits = slash + 1 < entry.size();
        for (size_t i = slash + 1; i < entry.size(); ++i) {
            if (entry[i] < '0' || entry[i] > '9') {
                digits = false;
                break;
            }
            prefix = prefix * 10 + (entry[i] - '0');
        }
        if (digits && ipv4_in_cidr(ip, net, prefix))
            return true;
    }
    return false;
}

bool valid_trusted_source(const std::string& entry) {
    const size_t slash = entry.find('/');
    if (slash == std::string::npos)
        return valid_ipv4(entry) || valid_ipv6(entry); // bare IP
    const std::string net = entry.substr(0, slash);
    if (!valid_ipv4(net)) // only IPv4 CIDRs are supported
        return false;
    if (slash + 1 >= entry.size())
        return false;
    int prefix = 0;
    for (size_t i = slash + 1; i < entry.size(); ++i) {
        if (entry[i] < '0' || entry[i] > '9')
            return false;
        prefix = prefix * 10 + (entry[i] - '0');
    }
    return prefix >= 0 && prefix <= 32;
}

namespace {

using Clock = std::chrono::steady_clock;

// Milliseconds left until `deadline`, clamped to [0, INT_MAX]. 0 means the budget is spent.
int remaining_ms(Clock::time_point deadline) {
    const auto now = Clock::now();
    if (now >= deadline)
        return 0;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
    return ms > 0 ? static_cast<int>(ms) : 1; // sub-ms remaining still gets one poll
}

bool read_exact(int fd, uint8_t* buf, size_t n, Clock::time_point deadline) {
    size_t got = 0;
    while (got < n) {
        const int ms = remaining_ms(deadline);
        if (ms <= 0)
            return false;
        pollfd pfd{fd, POLLIN, 0};
        if (::poll(&pfd, 1, ms) <= 0)
            return false;
        const ssize_t r = ::recv(fd, buf + got, n - got, 0);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            return false;
        }
        if (r == 0)
            return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

} // namespace

namespace {
std::string to_hex(const uint8_t* data, size_t n) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}
} // namespace

ProxyHeaderResult read_proxy_header(int fd, int timeout_ms) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);

    // Peek up to 16 bytes (non-consuming) to tell v1 ('P') from v2 (0x0D); keep a hex snapshot for
    // diagnostics. Stratum is JSON (starts with '{'), so neither marker collides.
    std::array<uint8_t, 16> peek{};
    ssize_t peeked = 0;
    {
        const int ms = remaining_ms(deadline);
        pollfd pfd{fd, POLLIN, 0};
        if (ms <= 0 || ::poll(&pfd, 1, ms) <= 0)
            return {ProxyHeaderKind::Direct, {}, {}}; // no data soon -> direct
        peeked = ::recv(fd, peek.data(), peek.size(), MSG_PEEK);
        if (peeked <= 0)
            return {ProxyHeaderKind::Direct, {}, {}}; // peer closed/EAGAIN -> direct
    }
    const uint8_t first = peek[0];
    const std::string peek_hex = to_hex(peek.data(), static_cast<size_t>(peeked));

    if (first == 0x0D) { // v2: 16-byte fixed prefix, then addr_len more bytes
        static constexpr std::array<uint8_t, 12> kSig = {0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D,
                                                         0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A};
        std::array<uint8_t, 16> head{};
        if (!read_exact(fd, head.data(), head.size(), deadline))
            return {ProxyHeaderKind::Malformed, {}, peek_hex};
        if (std::memcmp(head.data(), kSig.data(), kSig.size()) != 0 || (head[12] >> 4) != 0x2)
            return {ProxyHeaderKind::Malformed, {}, peek_hex};
        const uint16_t addr_len = static_cast<uint16_t>((head[14] << 8) | head[15]);
        std::vector<uint8_t> full(16 + addr_len);
        std::memcpy(full.data(), head.data(), 16);
        if (addr_len > 0 && !read_exact(fd, full.data() + 16, addr_len, deadline))
            return {ProxyHeaderKind::Malformed, {}, peek_hex};
        if ((head[12] & 0x0F) == 0x0) // LOCAL: no client addr -> use direct
            return {ProxyHeaderKind::Direct, {}, {}};
        if (const auto addr = parse_proxy_v2(full.data(), full.size()))
            return {ProxyHeaderKind::RealAddress, *addr, {}};
        return {ProxyHeaderKind::Malformed, {}, to_hex(full.data(), std::min<size_t>(full.size(), 32))};
    }

    if (first == 'P') { // v1: text line ending in CRLF, <= 107 bytes incl. CRLF
        std::string line;
        for (int i = 0; i < 107; ++i) {
            uint8_t ch = 0;
            if (!read_exact(fd, &ch, 1, deadline))
                return {ProxyHeaderKind::Malformed, {}, peek_hex};
            if (ch == '\n') {
                if (!line.empty() && line.back() == '\r')
                    line.pop_back();
                if (const auto addr = parse_proxy_v1(line))
                    return {ProxyHeaderKind::RealAddress, *addr, {}};
                return {ProxyHeaderKind::Direct, {}, {}}; // complete line, UNKNOWN/no addr -> direct
            }
            line.push_back(static_cast<char>(ch));
        }
        return {ProxyHeaderKind::Malformed, {}, peek_hex}; // no CRLF within the v1 limit -> garbage
    }

    return {ProxyHeaderKind::Direct, {}, {}}; // not a PROXY header -> direct
}

} // namespace erikslund::net
