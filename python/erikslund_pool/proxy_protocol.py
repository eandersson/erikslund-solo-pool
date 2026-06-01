"""PROXY protocol (HAProxy) support: recover the real client address from a header.

Only headers from a configured trusted source are honoured (so a client can't forge its
IP); non-trusted sources are treated as direct, so connecting straight to the pool works.
"""
from __future__ import annotations

import asyncio
import enum
import ipaddress
from dataclasses import dataclass

_V2_SIG = bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A])
_V1_MAX_LINE = 107  # PROXY v1 header is at most 107 bytes incl. CRLF


def parse_proxy_v1(line: str) -> str | None:
    """Parse a v1 header line (no trailing CRLF). Returns 'src_ip:src_port' for TCP4/TCP6;
    None for UNKNOWN or malformed."""
    parts = line.split()
    if len(parts) < 2 or parts[0] != "PROXY":
        return None
    proto = parts[1]
    if proto not in ("TCP4", "TCP6") or len(parts) != 6:
        return None  # UNKNOWN, or wrong field count
    src, sport = parts[2], parts[4]
    try:
        addr = ipaddress.ip_address(src)
        port = int(sport)
    except ValueError:
        return None
    want_v4 = proto == "TCP4"
    if isinstance(addr, ipaddress.IPv4Address) != want_v4:
        return None  # family must match the proto token
    if not 0 <= port <= 65535:
        return None
    return f"{src}:{port}"


def parse_proxy_v2(data: bytes) -> str | None:
    """Parse a full v2 header (incl. the 12-byte signature). Returns 'src_ip:src_port' for TCP over
    IPv4/IPv6; None for the LOCAL command, non-TCP, a bad signature, or malformed."""
    if len(data) < 16 or data[:12] != _V2_SIG:
        return None
    if (data[12] >> 4) != 0x2:
        return None  # version must be 2
    if (data[12] & 0x0F) != 0x1:
        return None  # only PROXY (1) carries an address; LOCAL (0) does not
    family = data[13] >> 4       # 1=AF_INET, 2=AF_INET6
    transport = data[13] & 0x0F  # 1=STREAM (TCP)
    addr_len = (data[14] << 8) | data[15]
    if 16 + addr_len > len(data) or transport != 0x1:
        return None
    body = data[16:]
    if family == 0x1:  # IPv4: src(4) dst(4) sport(2) dport(2)
        if addr_len < 12:
            return None
        ip = str(ipaddress.IPv4Address(bytes(body[0:4])))
        port = (body[8] << 8) | body[9]
    elif family == 0x2:  # IPv6: src(16) dst(16) sport(2) dport(2)
        if addr_len < 36:
            return None
        ip = str(ipaddress.IPv6Address(bytes(body[0:16])))
        port = (body[32] << 8) | body[33]
    else:
        return None
    return f"{ip}:{port}"


def source_trusted(ip: str, trusted: list[str]) -> bool:
    """True if `ip` matches any trusted entry: an exact IP (v4/v6) or an IPv4 CIDR. IPv6 CIDRs are
    NOT honored (startup warns on one)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in trusted:
        try:
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if isinstance(net, ipaddress.IPv4Network) and addr in net:
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            continue  # a malformed entry simply never matches (also flagged at startup)
    return False


def valid_trusted_source(entry: str) -> bool:
    """True if `entry` is a usable trusted-source spec: a bare IP (v4/v6) or an IPv4 CIDR. An IPv6
    CIDR is invalid (it would never match) so startup can warn."""
    try:
        if "/" in entry:
            return isinstance(ipaddress.ip_network(entry, strict=False), ipaddress.IPv4Network)
        ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False


class ProxyKind(enum.Enum):
    REAL_ADDRESS = "real"   # a PROXY command carried the real client address (in .address)
    DIRECT = "direct"       # no header, v1 UNKNOWN, or v2 LOCAL (health check) -> use the TCP peer
    MALFORMED = "malformed"  # looked like a header but was corrupt/truncated -> drop the connection


@dataclass
class ProxyResult:
    kind: ProxyKind
    address: str | None = None  # set only for REAL_ADDRESS
    prebuffer: bytes = b""      # bytes read but not part of a header -> hand back to the reader
    detail: str = ""            # hex of the first bytes seen; set only for MALFORMED (diagnostics)


async def read_proxy_header(reader: asyncio.StreamReader, timeout: float = 2.0) -> ProxyResult:
    """Consume one PROXY header (auto-detecting v1 vs v2). A missing header, v1 UNKNOWN, or v2
    LOCAL yields DIRECT; the byte consumed to detect "no header" is returned in .prebuffer."""
    try:
        first = await asyncio.wait_for(reader.readexactly(1), timeout)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
        return ProxyResult(ProxyKind.DIRECT)  # no data soon / peer gone -> direct (bare TCP check)

    if first == b"\x0d":  # v2: 16-byte fixed prefix, then addr_len more bytes
        try:
            head = first + await asyncio.wait_for(reader.readexactly(15), timeout)
            addr_len = (head[14] << 8) | head[15]
            body = await asyncio.wait_for(reader.readexactly(addr_len), timeout) if addr_len else b""
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, OSError):
            return ProxyResult(ProxyKind.MALFORMED, detail=first.hex())
        if head[:12] != _V2_SIG or (head[12] >> 4) != 0x2:
            return ProxyResult(ProxyKind.MALFORMED, detail=head.hex())
        if (head[12] & 0x0F) == 0x0:  # LOCAL command: health check -> use the direct endpoint
            return ProxyResult(ProxyKind.DIRECT)
        addr = parse_proxy_v2(head + body)
        if addr is not None:
            return ProxyResult(ProxyKind.REAL_ADDRESS, address=addr)
        return ProxyResult(ProxyKind.MALFORMED, detail=(head + body)[:32].hex())

    if first == b"P":  # v1: text line ending in CRLF
        try:
            rest = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                ConnectionError, OSError):
            return ProxyResult(ProxyKind.MALFORMED, detail=first.hex())
        if len(rest) + 1 > _V1_MAX_LINE:
            return ProxyResult(ProxyKind.MALFORMED, detail=(first + rest)[:32].hex())
        addr = parse_proxy_v1((first + rest).rstrip(b"\r\n").decode("latin-1"))
        if addr is not None:
            return ProxyResult(ProxyKind.REAL_ADDRESS, address=addr)
        return ProxyResult(ProxyKind.DIRECT)  # complete line but UNKNOWN/no addr -> direct

    return ProxyResult(ProxyKind.DIRECT, prebuffer=first)  # not a PROXY header -> direct
