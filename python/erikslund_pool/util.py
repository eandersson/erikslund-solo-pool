"""Bitcoin/Stratum encoding primitives -- the byte-order-critical core.

Internal hashes are raw double-SHA-256; bitcoind display hex is those reversed.
Header ints are little-endian; the Stratum wire sends version/ntime/nbits as
big-endian hex and prevhash word-reversed.
"""

import hashlib
import struct

from erikslund_pool.constants import DIFF1_TARGET


def sanitize(value, limit: int = 128) -> str:
    """Sanitize an untrusted miner string before storing/logging: drop control characters
    (anti-injection) and hard-cap the length."""
    if not value:
        return "?"
    return "".join(ch if ch.isprintable() else "?" for ch in str(value))[:limit]


def ascii_worker(worker: str, limit: int = 128) -> str:
    """Keep only printable-ASCII (0x20-0x7e) in a worker name, then cap; it is written into the
    ASCII-only ``users/<address>`` stats file. Cap after dropping (result is ASCII, char==byte)."""
    return "".join(ch for ch in worker if 0x20 <= ord(ch) <= 0x7e)[:limit]


def redact_url(url: str) -> str:
    """Strip ``user:pass@`` userinfo from a URL so node credentials aren't logged.

    Done by hand (not urlsplit) to cover a scheme-less ``user:pass@host:port`` and a password
    containing ``@`` (cut at the last ``@`` of the authority)."""
    try:
        scheme, sep, rest = url.partition("://")
        if not sep:
            scheme, rest = "", url
        # Authority ends at the first '/', '?', or '#', so an '@' in a query/fragment is left intact.
        cut = next((i for i, ch in enumerate(rest) if ch in "/?#"), len(rest))
        authority, remainder = rest[:cut], rest[cut:]
        if "@" in authority:
            authority = authority.rsplit("@", 1)[1]
        return (f"{scheme}://" if sep else "") + authority + remainder
    except Exception:
        return url


def dsha256(data: bytes) -> bytes:
    """Bitcoin's double SHA-256."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def ser_uint32(n: int) -> bytes:
    return struct.pack("<I", n)


def ser_uint64(n: int) -> bytes:
    return struct.pack("<Q", n)


def ser_varint(n: int) -> bytes:
    """Bitcoin CompactSize varint."""
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    if n <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", n)
    return b"\xff" + struct.pack("<Q", n)


def serialize_height(height: int) -> bytes:
    """Block height as CScript() << height (OP_0 / OP_1..16 / minimal push); must match
    byte-for-byte, as BIP34 validation rebuilds the same script."""
    if height == 0:
        return b"\x00"
    if 1 <= height <= 16:
        return bytes([0x50 + height])
    data = bytearray()
    n = height
    while n:
        data.append(n & 0xFF)
        n >>= 8
    if data[-1] & 0x80:        # extra byte keeps the value positive
        data.append(0x00)
    return bytes([len(data)]) + bytes(data)


def bits_to_target(bits: int) -> int:
    """Decompress nBits compact form to a full 256-bit target."""
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if exponent <= 3:
        return mantissa >> (8 * (3 - exponent))
    return mantissa << (8 * (exponent - 3))


def target_to_difficulty(target: int) -> float:
    return DIFF1_TARGET / target if target else float("inf")


def difficulty_to_target(difficulty: float) -> int:
    """Share target for a pool difficulty; a hash meets it when hash <= target."""
    return DIFF1_TARGET if difficulty <= 0 else int(DIFF1_TARGET / difficulty)


def format_difficulty(difficulty: float) -> str:
    """Render a difficulty for logs as a plain decimal, never scientific notation."""
    if difficulty >= 1:
        if difficulty == round(difficulty):
            return f"{difficulty:.0f}"
        return f"{difficulty:.2f}".rstrip("0").rstrip(".")
    return f"{difficulty:.4g}"


def hash_to_int(hash_bytes: bytes) -> int:
    """Block hash as a number for target comparison (little-endian of raw bytes)."""
    return int.from_bytes(hash_bytes, "little")


def unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def display_hash(internal: bytes) -> str:
    """Internal hash bytes -> bitcoind's big-endian display hex."""
    return internal[::-1].hex()


def prevhash_to_stratum(prevhash_be_hex: str) -> str:
    """RPC previousblockhash -> mining.notify wire form (display hash, words reversed)."""
    internal = bytes.fromhex(prevhash_be_hex)[::-1]
    if len(internal) != 32:
        # A wrong-length hash would otherwise yield a malformed prevhash / non-80-byte header.
        raise ValueError("previousblockhash is not 32 bytes")
    return b"".join(internal[i:i + 4][::-1] for i in range(0, 32, 4)).hex()
