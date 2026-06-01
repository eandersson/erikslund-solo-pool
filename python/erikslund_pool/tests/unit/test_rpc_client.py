"""Unit tests for BitcoindRPC construction (URL normalization, auth header)."""

import base64
import unittest

from erikslund_pool.rpc import BitcoindRPC


class TestRPCInit(unittest.TestCase):
    def test_url_scheme_added_when_missing(self):
        self.assertEqual(BitcoindRPC("host:18443", "u", "p").url, "http://host:18443")

    def test_url_scheme_preserved(self):
        self.assertEqual(BitcoindRPC("https://node:8332", "u", "p").url, "https://node:8332")
        self.assertEqual(BitcoindRPC("http://node:8332", "u", "p").url, "http://node:8332")

    def test_basic_auth_header(self):
        rpc = BitcoindRPC("x", "user", "pass")
        self.assertEqual(rpc._endpoints[0][1], base64.b64encode(b"user:pass").decode())
