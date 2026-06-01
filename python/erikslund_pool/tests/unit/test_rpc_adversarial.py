"""Adversarial BitcoindRPC tests: failover exhaustion, bad responses, id hygiene."""
from __future__ import annotations

import email.message
import io
import json
import unittest
import urllib.error
from unittest.mock import patch

from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.exceptions import RPCResponseError
from erikslund_pool.rpc import BitcoindRPC


class _Resp:
    def __init__(self, body: bytes):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _json_resp(obj):
    return _Resp(json.dumps(obj).encode())


def _http_error(code, reason, body: bytes):
    return urllib.error.HTTPError("http://x", code, reason, email.message.Message(),
                                  io.BytesIO(body))


class TestFailoverExhaustion(unittest.TestCase):
    def test_single_endpoint_down_raises_connection_error(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        rpc._post = lambda *a: (_ for _ in ()).throw(RPCConnectionError("down"))
        with self.assertRaises(RPCConnectionError):
            rpc.call("getblockcount")

    def test_all_endpoints_down_raises(self):
        rpc = BitcoindRPC("http://a:1", "u", "p",
                          failover=[("http://b:2", "u", "p"), ("http://c:3", "u", "p")])
        attempts = []

        def down(url, auth, payload):
            attempts.append(url)
            raise RPCConnectionError("refused")

        rpc._post = down
        with self.assertRaises(RPCConnectionError):
            rpc.call("getblockcount")
        self.assertEqual(len(attempts), 3)   # every endpoint tried once

    def test_error_message_carries_last_connection_error(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        rpc._post = lambda *a: (_ for _ in ()).throw(RPCConnectionError("ECONNREFUSED-xyz"))
        with self.assertRaises(RPCConnectionError) as ctx:
            rpc.call("getblockcount")
        self.assertIn("ECONNREFUSED-xyz", str(ctx.exception))

    def test_rpc_error_does_not_trigger_failover(self):
        rpc = BitcoindRPC("http://a:1", "u", "p", failover=[("http://b:2", "u", "p")])
        seen = []

        def answers_error(url, auth, payload):
            seen.append(url)
            return {"result": None, "error": {"code": -8, "message": "boom"}}

        rpc._post = answers_error
        with self.assertRaises(RPCResponseError):
            rpc.call("foo")
        self.assertEqual(seen, ["http://a:1"])  # node answered -> no failover


class TestMalformedResponses(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_non_json_body_is_connection_error(self, urlopen):
        urlopen.return_value = _Resp(b"<html>I am not JSON</html>")
        rpc = BitcoindRPC("http://a:1", "u", "p")
        with self.assertRaises((RPCConnectionError, RPCResponseError, ValueError)) as ctx:
            rpc.call("getblockcount")
        # A garbage 200 body must not silently succeed.
        self.assertIsInstance(ctx.exception, RPCConnectionError)

    @patch("urllib.request.urlopen")
    def test_http_500_with_json_error_is_response_error(self, urlopen):
        # bitcoind returns 500 + a JSON error body for RPC-level errors.
        urlopen.side_effect = _http_error(
            500, "Server Error", json.dumps({"result": None, "error": {"message": "bad"}}).encode())
        rpc = BitcoindRPC("http://a:1", "u", "p")
        with self.assertRaises(RPCResponseError):
            rpc.call("foo")

    @patch("urllib.request.urlopen")
    def test_http_503_with_html_body_is_connection_error(self, urlopen):
        urlopen.side_effect = _http_error(503, "Unavailable", b"<html>down</html>")
        rpc = BitcoindRPC("http://a:1", "u", "p")
        with self.assertRaises(RPCConnectionError):
            rpc.call("foo")

    @patch("urllib.request.urlopen")
    def test_url_error_is_connection_error(self, urlopen):
        urlopen.side_effect = urllib.error.URLError("name resolution failed")
        rpc = BitcoindRPC("http://a:1", "u", "p")
        with self.assertRaises(RPCConnectionError):
            rpc.call("getblockcount")

    @patch("urllib.request.urlopen")
    def test_timeout_oserror_is_connection_error(self, urlopen):
        urlopen.side_effect = TimeoutError("timed out")  # subclass of OSError
        rpc = BitcoindRPC("http://a:1", "u", "p")
        with self.assertRaises(RPCConnectionError):
            rpc.call("getblockcount")


class TestRequestIdAndPayload(unittest.TestCase):
    def _capturing_rpc(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        captured = []

        def fake_post(url, auth, payload):
            captured.append(json.loads(payload))
            return {"result": {}, "error": None}

        rpc._post = fake_post
        return rpc, captured

    def test_id_increments_monotonically(self):
        rpc, captured = self._capturing_rpc()
        for _ in range(5):
            rpc.getblockcount()
        ids = [c["id"] for c in captured]
        self.assertEqual(ids, [1, 2, 3, 4, 5])

    def test_id_increments_even_on_rpc_error(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        captured = []

        def err_post(url, auth, payload):
            captured.append(json.loads(payload))
            return {"result": None, "error": {"code": -1, "message": "x"}}

        rpc._post = err_post
        for _ in range(3):
            with self.assertRaises(RPCResponseError):
                rpc.call("foo")
        self.assertEqual([c["id"] for c in captured], [1, 2, 3])

    def test_params_default_to_empty_list(self):
        rpc, captured = self._capturing_rpc()
        rpc.call("ping")
        self.assertEqual(captured[0]["params"], [])
        self.assertEqual(captured[0]["jsonrpc"], "1.0")

    def test_submitblock_reject_reason_passed_through(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        rpc._post = lambda *a: {"result": "high-hash", "error": None}
        self.assertEqual(rpc.submitblock("00"), "high-hash")

    def test_submitblock_accept_is_none(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        rpc._post = lambda *a: {"result": None, "error": None}
        self.assertIsNone(rpc.submitblock("00"))


class TestResponseErrorParsing(unittest.TestCase):
    def test_dict_error_extracts_code_and_message(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        rpc._post = lambda *a: {"result": None, "error": {"code": -32601, "message": "Method not found"}}
        with self.assertRaises(RPCResponseError) as ctx:
            rpc.call("nope")
        self.assertEqual(ctx.exception.code, -32601)
        self.assertEqual(ctx.exception.message, "Method not found")

    def test_non_dict_error_still_raises_cleanly(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        rpc._post = lambda *a: {"result": None, "error": "plain string error"}
        with self.assertRaises(RPCResponseError) as ctx:
            rpc.call("nope")
        self.assertIsNone(ctx.exception.code)
        self.assertIn("plain string error", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
