"""PROXY-protocol parsing + the async header reader."""
import asyncio
import unittest

from erikslund_pool.config import Settings
from erikslund_pool.proxy_protocol import ProxyKind
from erikslund_pool.proxy_protocol import parse_proxy_v1
from erikslund_pool.proxy_protocol import parse_proxy_v2
from erikslund_pool.proxy_protocol import read_proxy_header
from erikslund_pool.proxy_protocol import source_trusted
from erikslund_pool.proxy_protocol import valid_trusted_source

_SIG = bytes([0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A])


def _v2_ipv4(active_cmd=0x21):
    # signature + ver/cmd + AF_INET|STREAM + len(12) + src 1.2.3.4 + dst 5.6.7.8 + sport 6324 + dport
    return _SIG + bytes([active_cmd, 0x11, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0x18, 0xB4, 0x0D, 0x05])


class ParseTests(unittest.TestCase):
    def test_v1_tcp4_and_tcp6(self):
        self.assertEqual(parse_proxy_v1("PROXY TCP4 1.2.3.4 5.6.7.8 6324 3333"), "1.2.3.4:6324")
        self.assertEqual(parse_proxy_v1("PROXY TCP6 2001:db8::1 2001:db8::2 6324 3333"),
                         "2001:db8::1:6324")

    def test_v1_unknown_and_malformed(self):
        for bad in ("PROXY UNKNOWN", "PROXY TCP4 1.2.3.4 5.6.7.8 6324",  # too few fields
                    "PROXY TCP4 not.an.ip 5.6.7.8 6324 3333", "PROXY TCP4 1.2.3.4 5.6.7.8 99999 3333",
                    "PROXY TCP4 2001:db8::1 5.6.7.8 6324 3333",  # family mismatch
                    "GET / HTTP/1.1", ""):
            self.assertIsNone(parse_proxy_v1(bad), bad)

    def test_v2_ipv4(self):
        self.assertEqual(parse_proxy_v2(_v2_ipv4()), "1.2.3.4:6324")

    def test_v2_ipv6(self):
        h = _SIG + bytes([0x21, 0x21, 0x00, 0x24])
        h += bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])   # src 2001:db8::1
        h += bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [2])   # dst 2001:db8::2
        h += bytes([0x18, 0xB4, 0x0D, 0x05])                     # sport 6324, dport 3333
        self.assertEqual(parse_proxy_v2(h), "2001:db8::1:6324")

    def test_v2_ipv4_with_trailing_tlv(self):
        h = _SIG + bytes([0x21, 0x11, 0x00, 0x10, 1, 2, 3, 4, 5, 6, 7, 8, 0x18, 0xB4, 0x0D, 0x05,
                          0x03, 0x00, 0x01, 0xAB])  # addr_len 16 = 12 addr + 4-byte TLV (ignored)
        self.assertEqual(parse_proxy_v2(h), "1.2.3.4:6324")

    def test_v2_local_and_bad_signature(self):
        self.assertIsNone(parse_proxy_v2(_v2_ipv4(active_cmd=0x20)))  # LOCAL command
        self.assertIsNone(parse_proxy_v2(bytes(16)))                   # zeroed signature

    def test_source_trusted(self):
        # Bare IPv6 and IPv4 CIDR match; IPv6 CIDR is not honored (only IPv4 CIDRs).
        trusted = ["10.0.0.5", "2001:db8::dead", "172.19.0.0/16", "2001:db8::/32"]
        self.assertTrue(source_trusted("10.0.0.5", trusted))
        self.assertTrue(source_trusted("172.19.4.7", trusted))
        self.assertTrue(source_trusted("2001:db8::dead", trusted))   # exact IPv6 still trusted
        self.assertFalse(source_trusted("2001:db8::beef", trusted))  # IPv6 CIDR is ignored
        self.assertFalse(source_trusted("10.0.0.6", trusted))
        self.assertFalse(source_trusted("172.20.0.1", trusted))
        self.assertFalse(source_trusted("1.2.3.4", []))
        self.assertFalse(source_trusted("not-an-ip", trusted))

    def test_valid_trusted_source(self):
        for good in ("13.60.28.119", "2001:db8::1", "172.19.0.0/16", "10.0.0.0/0"):
            self.assertTrue(valid_trusted_source(good), good)
        # An IPv6 CIDR is rejected (it would never match) so startup warns.
        for bad in ("2001:db8::/32", "1 - 13.60.28.119", "13.60.28.119 ", "172.19.0.0/33",
                    "not-an-ip", ""):
            self.assertFalse(valid_trusted_source(bad), bad)

    def test_config_proxy_protocol_from_scalar_list_and_absent(self):
        self.assertEqual(Settings.from_dict({}).proxy_protocol_from, [])
        self.assertEqual(Settings.from_dict({"proxy_protocol_from": "10.0.0.5"}).proxy_protocol_from,
                         ["10.0.0.5"])
        self.assertEqual(
            Settings.from_dict({"proxy_protocol_from": ["10.0.0.5", "172.19.0.0/16"]})
            .proxy_protocol_from, ["10.0.0.5", "172.19.0.0/16"])


def _reader(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


class ReadHeaderTests(unittest.IsolatedAsyncioTestCase):
    async def test_v1_real_address_trailing_preserved(self):
        rest = b'{"id":1,"method":"mining.subscribe"}\n'
        r = _reader(b"PROXY TCP4 1.2.3.4 5.6.7.8 6324 3333\r\n" + rest)
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.REAL_ADDRESS)
        self.assertEqual(result.address, "1.2.3.4:6324")
        self.assertEqual(await r.read(), rest)  # header consumed exactly

    async def test_v2_real_address_trailing_preserved(self):
        rest = b'{"x":1}\n'
        r = _reader(_v2_ipv4() + rest)
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.REAL_ADDRESS)
        self.assertEqual(result.address, "1.2.3.4:6324")
        self.assertEqual(await r.read(), rest)

    async def test_v2_local_is_direct_not_dropped(self):
        rest = b'{"hc":1}\n'
        r = _reader(_SIG + bytes([0x20, 0x00, 0x00, 0x00]) + rest)  # v2 LOCAL, addr_len 0
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.DIRECT)
        self.assertIsNone(result.address)
        self.assertEqual(await r.read(), rest)

    async def test_v1_unknown_is_direct(self):
        r = _reader(b'PROXY UNKNOWN\r\n{"x":1}\n')
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.DIRECT)
        self.assertEqual(await r.read(), b'{"x":1}\n')

    async def test_no_header_is_direct_nothing_lost(self):
        payload = b'{"id":1,"method":"mining.subscribe"}\n'
        r = _reader(payload)
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.DIRECT)
        # The sniffed byte is returned via prebuffer; nothing is lost.
        self.assertEqual(result.prebuffer + await r.read(), payload)

    async def test_peer_closed_with_no_data_is_direct(self):
        r = _reader(b"")
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.DIRECT)

    async def test_bad_v2_signature_is_malformed_with_detail(self):
        r = _reader(b"\x0d" + b"garbage-not-a-proxy-header-xxxxx")
        result = await read_proxy_header(r)
        self.assertIs(result.kind, ProxyKind.MALFORMED)
        self.assertTrue(result.detail.startswith("0d"))


if __name__ == "__main__":
    unittest.main()
