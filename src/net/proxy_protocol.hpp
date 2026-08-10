#pragma once
// PROXY protocol: recover the real client address from a header prepended by a trusted upstream.
// Only headers from a configured trusted source are honoured (no IP spoofing); other sources are
// treated as direct.
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace erikslund::net {

// Parse a PROXY v1 header line (no trailing CRLF), e.g. "PROXY TCP4 1.2.3.4 5.6.7.8 6324 3333".
// Returns "src_ip:src_port" for TCP4/TCP6; nullopt for UNKNOWN or malformed.
std::optional<std::string> parse_proxy_v1(std::string_view line);

// Parse a PROXY v2 header (incl. the 12-byte signature). Returns "src_ip:src_port" for TCP over
// IPv4/IPv6; nullopt for the LOCAL command, non-TCP, or malformed.
std::optional<std::string> parse_proxy_v2(const uint8_t* data, std::size_t len);

// True if `ip` (bare host, no port) matches any trusted entry: an exact IP (v4/v6) or IPv4 CIDR.
bool source_trusted(const std::string& ip, const std::vector<std::string>& trusted);

// True if `entry` is a usable trusted-source spec (bare IPv4/IPv6 or IPv4 CIDR). Used to warn on a
// typo'd config entry that would silently never match.
bool valid_trusted_source(const std::string& entry);

enum class ProxyHeaderKind {
    RealAddress, // a PROXY command carried the real client address (in ProxyHeaderResult::address)
    Direct,      // no header, v1 UNKNOWN, or a v2 LOCAL command -> use the TCP peer
    Malformed,   // corrupt/truncated header -> caller should drop the connection
};
struct ProxyHeaderResult {
    ProxyHeaderKind kind;
    std::string address; // "ip:port"; set only when kind == RealAddress
    std::string detail;  // hex of first bytes seen; set only when kind == Malformed
};

// Read and consume EXACTLY one PROXY header (auto-detects v1 vs v2) from `fd`, blocking up to
// timeout_ms. Never over-reads, so stratum bytes after the header stay in the socket for the
// reactor. A missing header, v1 UNKNOWN, or v2 LOCAL command yields Direct.
ProxyHeaderResult read_proxy_header(int fd, int timeout_ms);

} // namespace erikslund::net
