"""Multi-bitcoind failover in BitcoindRPC (no network -- _post is stubbed)."""
import unittest

import msgspec

from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.exceptions import RPCResponseError
from erikslund_pool.rpc import BitcoindRPC


class RpcFailoverTests(unittest.TestCase):
    def test_fails_over_to_backup_and_sticks(self):
        rpc = BitcoindRPC("http://primary:1", "u", "p",
                          failover=[("http://backup:2", "u", "p")])
        calls = []

        def fake_post(url, auth, payload):
            calls.append(url)
            if "primary" in url:
                raise RPCConnectionError("primary down")
            return {"result": 42, "error": None}

        rpc._post = fake_post
        self.assertEqual(rpc.call("getblockcount"), 42)
        self.assertEqual(rpc._current, 1)  # stuck on the backup

        # The next call goes straight to the backup (no primary attempt).
        calls.clear()
        self.assertEqual(rpc.call("getblockcount"), 42)
        self.assertEqual(calls, ["http://backup:2"])

    def test_failover_warning_redacts_credentials(self):
        # URL-embedded credentials must not leak into the failover log line.
        rpc = BitcoindRPC("http://u:secret@primary:1", "u", "p",
                          failover=[("http://u:secret@backup:2", "u", "p")])

        def fake_post(url, auth, payload):
            if "primary" in url:
                raise RPCConnectionError("primary down")
            return {"result": 1, "error": None}

        rpc._post = fake_post
        with self.assertLogs("erikslund_pool.rpc", level="WARNING") as cm:
            rpc.call("getblockcount")
        logged = "\n".join(cm.output)
        self.assertIn("backup:2", logged)
        self.assertNotIn("secret", logged)  # password stripped by redact_url

    def test_all_endpoints_down_raises(self):
        rpc = BitcoindRPC("http://a:1", "u", "p", failover=[("http://b:2", "u", "p")])

        def always_down(url, auth, payload):
            raise RPCConnectionError("down")

        rpc._post = always_down
        with self.assertRaises(RPCConnectionError):
            rpc.call("getblockcount")

    def test_rpc_error_does_not_fail_over(self):
        rpc = BitcoindRPC("http://a:1", "u", "p", failover=[("http://b:2", "u", "p")])
        calls = []

        def answers_with_error(url, auth, payload):
            calls.append(url)
            return {"result": None, "error": {"code": -1, "message": "boom"}}

        rpc._post = answers_with_error
        with self.assertRaises(RPCResponseError):
            rpc.call("foo")
        self.assertEqual(calls, ["http://a:1"])  # node answered -> no failover

    def test_rpc_error_reply_does_not_stick_failover(self):
        # A backup that answers only a JSON-RPC error must not be stuck on (error check precedes commit).
        rpc = BitcoindRPC("http://a:1", "u", "p", failover=[("http://b:2", "u", "p")])

        def post(url, auth, payload):
            if "a:1" in url:
                raise RPCConnectionError("primary down")
            return {"result": None, "error": {"code": -1, "message": "boom"}}

        rpc._post = post
        with self.assertRaises(RPCResponseError):
            rpc.call("getblockcount")
        self.assertEqual(rpc._current, 0)   # error reply did not pin _current to the backup

    def test_getblocktemplate_validate_gate_skips_an_unusable_backup(self):
        # A backup whose template validate() rejects must not be stuck on; _current stays on primary.
        rpc = BitcoindRPC("http://a:1", "u", "p", failover=[("http://b:2", "u", "p")])

        def post(url, auth, payload):
            if "a:1" in url:
                raise RPCConnectionError("primary down")
            return {"result": {"garbage": True}, "error": None}

        rpc._post = post
        with self.assertRaises(RPCConnectionError):
            rpc.getblocktemplate(validate=lambda result: (_ for _ in ()).throw(ValueError("bad")))
        self.assertEqual(rpc._current, 0)   # unusable backup template did not pin _current

    def test_getblocktemplate_validate_gate_sticks_a_usable_backup(self):
        # A backup whose template validate() accepts DOES stick the failover.
        rpc = BitcoindRPC("http://a:1", "u", "p", failover=[("http://b:2", "u", "p")])

        def post(url, auth, payload):
            if "a:1" in url:
                raise RPCConnectionError("primary down")
            return {"result": {"ok": True}, "error": None}

        rpc._post = post
        result = rpc.getblocktemplate(validate=lambda result: None)
        self.assertEqual(result, {"ok": True})
        self.assertEqual(rpc._current, 1)   # stuck to the usable backup

    def test_three_endpoints_skip_to_first_reachable(self):
        rpc = BitcoindRPC("http://a:1", "u", "p",
                          failover=[("http://b:2", "u", "p"), ("http://c:3", "u", "p")])

        def first_two_down(url, auth, payload):
            if "a:1" in url or "b:2" in url:
                raise RPCConnectionError("down")
            return {"result": 99, "error": None}

        rpc._post = first_two_down
        self.assertEqual(rpc.call("x"), 99)
        self.assertEqual(rpc._current, 2)   # stuck on the third endpoint

    def test_error_message_includes_last_connection_error(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")

        def down(url, auth, payload):
            raise RPCConnectionError("ECONNREFUSED")

        rpc._post = down
        with self.assertRaises(RPCConnectionError) as ctx:
            rpc.call("getblockcount")
        self.assertIn("ECONNREFUSED", str(ctx.exception))


class RpcFailbackTests(unittest.TestCase):
    """maybe_failback: fail back only when the primary probe SUCCEEDS and returns the
    pool's own tip; a warming-up or catching-up primary must never capture the pool."""

    TIP = "aa" * 32

    def _failed_over(self):
        rpc = BitcoindRPC("http://primary:1", "u", "p",
                          failover=[("http://backup:2", "u", "p")])
        rpc._current = 1  # as if a prior call failed over
        return rpc

    def test_returns_to_a_recovered_current_primary(self):
        rpc = self._failed_over()
        calls = []

        def primary_on_our_tip(url, auth, payload):
            calls.append(url)
            return {"result": self.TIP, "error": None}

        rpc._post = primary_on_our_tip
        rpc.maybe_failback(self.TIP)  # first probe is immediate (no prior probe recorded)
        self.assertEqual(rpc._current, 0)
        self.assertEqual(calls, ["http://primary:1"])

    def test_stays_on_the_backup_while_the_primary_is_down(self):
        rpc = self._failed_over()
        calls = []

        def primary_down(url, auth, payload):
            calls.append(url)
            raise RPCConnectionError("still down")

        rpc._post = primary_down
        rpc.maybe_failback(self.TIP)
        self.assertEqual(rpc._current, 1)
        self.assertEqual(calls, ["http://primary:1"])
        # A second probe inside FAILBACK_PROBE_SECONDS is rate-limited away.
        rpc.maybe_failback(self.TIP)
        self.assertEqual(calls, ["http://primary:1"])

    def test_a_warming_up_primary_does_not_capture_the_pool(self):
        # A primary answering -28 (RPC_IN_WARMUP) would strand the pool: call() never
        # rotates on an RPC error, so failing back means no work.
        rpc = self._failed_over()
        rpc._post = lambda url, auth, payload: {
            "result": None, "error": {"code": -28, "message": "Loading block index..."}}
        rpc.maybe_failback(self.TIP)
        self.assertEqual(rpc._current, 1)  # stay on the healthy backup

    def test_a_behind_primary_does_not_capture_the_pool(self):
        # Reachable but on a stale tip: wait until it reports the tip we mine on.
        rpc = self._failed_over()
        rpc._post = lambda url, auth, payload: {"result": "bb" * 32, "error": None}
        rpc.maybe_failback(self.TIP)
        self.assertEqual(rpc._current, 1)

    def test_noop_while_already_on_the_primary_or_without_a_tip(self):
        rpc = BitcoindRPC("http://primary:1", "u", "p",
                          failover=[("http://backup:2", "u", "p")])
        rpc._post = lambda url, auth, payload: self.fail("must not probe")
        rpc.maybe_failback(self.TIP)  # on the primary: no probe
        self.assertEqual(rpc._current, 0)
        rpc._current = 1
        rpc.maybe_failback("")  # no tip to compare against yet: no probe
        self.assertEqual(rpc._current, 1)

    def test_inflight_call_does_not_revert_a_failback(self):
        # call() publishes a failover only if _current still equals its start snapshot, so an
        # in-flight backup call must not re-stick the backup after a fail-back.
        rpc = self._failed_over()  # _current = 1: the call below starts on the backup

        def post_with_concurrent_failback(url, auth, payload):
            rpc._current = 0  # maybe_failback fires while this call is in flight
            return {"result": 1, "error": None}

        rpc._post = post_with_concurrent_failback
        self.assertEqual(rpc.call("getblockcount"), 1)  # served by the backup (start=1)
        self.assertEqual(rpc._current, 0)               # fail-back held, not reverted


class RpcCallShapeTests(unittest.TestCase):
    def _capture(self):
        rpc = BitcoindRPC("http://a:1", "u", "p")
        captured = {}

        def fake_post(url, auth, payload):
            captured["payload"] = msgspec.json.decode(payload)
            return {"result": {}, "error": None}

        rpc._post = fake_post
        return rpc, captured

    def test_getblocktemplate_payload(self):
        rpc, captured = self._capture()
        rpc.getblocktemplate()
        self.assertEqual(captured["payload"]["method"], "getblocktemplate")
        self.assertEqual(captured["payload"]["params"][0]["rules"], ["segwit"])
        self.assertIn("coinbasetxn", captured["payload"]["params"][0]["capabilities"])

    def test_validateaddress_payload(self):
        rpc, captured = self._capture()
        rpc.validateaddress("bc1qexample")
        self.assertEqual(captured["payload"]["method"], "validateaddress")
        self.assertEqual(captured["payload"]["params"], ["bc1qexample"])

    def test_request_id_increments(self):
        rpc, captured = self._capture()
        rpc.getblockcount()
        first = captured["payload"]["id"]
        rpc.getblockcount()
        self.assertEqual(captured["payload"]["id"], first + 1)


if __name__ == "__main__":
    unittest.main()
