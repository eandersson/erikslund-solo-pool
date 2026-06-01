"""Functional tests for BitcoindRPC with a mocked transport."""
from __future__ import annotations

import email.message
import io
import json
import urllib.error
from unittest.mock import patch

from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.exceptions import RPCResponseError
from erikslund_pool.rpc import BitcoindRPC
from erikslund_pool.tests.base import SoloPoolTestCase


class _FakeResp:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _http_error(payload):
    body = io.BytesIO(json.dumps(payload).encode())
    return urllib.error.HTTPError("http://x", 500, "Server Error",
                                  email.message.Message(), body)


class TestRPC(SoloPoolTestCase):
    def setUp(self):
        super().setUp()
        self.rpc = BitcoindRPC("http://node:18443", "u", "p")

    @patch("urllib.request.urlopen")
    def test_call_success(self, urlopen):
        urlopen.return_value = _FakeResp({"result": 42, "error": None})
        self.assertEqual(self.rpc.call("getblockcount"), 42)

    @patch("urllib.request.urlopen")
    def test_rpc_level_error_raises(self, urlopen):
        urlopen.return_value = _FakeResp({"result": None, "error": {"code": -8, "message": "bad"}})
        with self.assertRaises(RPCResponseError) as error_context:
            self.rpc.call("foo")
        self.assertEqual(error_context.exception.code, -8)
        self.assertEqual(error_context.exception.message, "bad")

    @patch("urllib.request.urlopen")
    def test_http_error_body_surfaced_as_response_error(self, urlopen):
        # bitcoind returns HTTP 500 with a JSON error body for RPC errors.
        urlopen.side_effect = _http_error({"result": None, "error": {"message": "rpc fail"}})
        with self.assertRaises(RPCResponseError):
            self.rpc.call("foo")

    @patch("urllib.request.urlopen")
    def test_unreachable_raises_connection_error(self, urlopen):
        urlopen.side_effect = urllib.error.URLError("connection refused")
        with self.assertRaises(RPCConnectionError):
            self.rpc.call("getblockcount")

    @patch("urllib.request.urlopen")
    def test_http_error_non_json_body_raises_connection_error(self, urlopen):
        urlopen.side_effect = urllib.error.HTTPError(
            "http://x", 503, "Unavailable", email.message.Message(), io.BytesIO(b"<html>down</html>"))
        with self.assertRaises(RPCConnectionError):
            self.rpc.call("foo")

    @patch("urllib.request.urlopen")
    def test_submitblock_accept_and_reject(self, urlopen):
        urlopen.return_value = _FakeResp({"result": None, "error": None})
        self.assertIsNone(self.rpc.submitblock("00"))
        urlopen.return_value = _FakeResp({"result": "duplicate", "error": None})
        self.assertEqual(self.rpc.submitblock("00"), "duplicate")
