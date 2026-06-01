"""Adversarial Pool tests: address gating, RPC short-circuit, junk job lookups.

A recording fake RPC asserts junk usernames never reach bitcoind, the gate that
stops a flood of garbage logins amplifying into validateaddress load.
"""
from __future__ import annotations

import unittest

from erikslund_pool.config import Settings
from erikslund_pool.constants import MAX_ADDRESS_CACHE
from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.pool import Pool
from erikslund_pool.util import redact_url


class _RecordingRPC:
    """Stands in for BitcoindRPC; records every validateaddress call."""

    def __init__(self, *, isvalid=True, script="0014" + "11" * 20, raise_exc=None):
        self.calls: list[str] = []
        self._isvalid = isvalid
        self._script = script
        self._raise = raise_exc

    def validateaddress(self, address):
        self.calls.append(address)
        if self._raise is not None:
            raise self._raise
        return {"isvalid": self._isvalid,
                "scriptPubKey": self._script if self._isvalid else None}


class TestPlausibleAddress(unittest.TestCase):
    def test_rejects_empty(self):
        self.assertFalse(Pool._plausible_address(""))

    def test_rejects_over_100_chars(self):
        self.assertFalse(Pool._plausible_address("a" * 101))
        self.assertFalse(Pool._plausible_address("b" * 1000))

    def test_accepts_exactly_100(self):
        self.assertTrue(Pool._plausible_address("a" * 100))

    def test_rejects_illegal_characters(self):
        for bad in ("has space", "bang!", "semi;colon", "pct%20", "slash/x",
                    "at@host", "quote'x", 'dquote"x', "back\\slash", "new\nline",
                    "tab\tchar", "uni|code", "<script>"):
            self.assertFalse(Pool._plausible_address(bad), bad)

    def test_accepts_real_address_shapes(self):
        for good in ("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k",
                     "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                     "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
                     "address.worker_1", "bc1q....name_with.dots"):
            self.assertTrue(Pool._plausible_address(good), good)


class TestValidateAddressShortCircuit(unittest.IsolatedAsyncioTestCase):
    def _pool_with_rpc(self, rpc):
        pool = Pool(Settings())
        pool.rpc = rpc
        return pool

    async def test_junk_addresses_never_call_rpc(self):
        rpc = _RecordingRPC()
        pool = self._pool_with_rpc(rpc)
        for junk in ("", "a" * 101, "has space", "bad!char", "semi;colon", "<script>"):
            valid, script = await pool.validate_address(junk)
            self.assertFalse(valid)
            self.assertIsNone(script)
        self.assertEqual(rpc.calls, [])   # the security-critical assertion

    async def test_plausible_address_does_call_rpc(self):
        rpc = _RecordingRPC()
        pool = self._pool_with_rpc(rpc)
        valid, script = await pool.validate_address("bcrt1qplausibleaddress")
        self.assertTrue(valid)
        self.assertIsNotNone(script)
        self.assertEqual(rpc.calls, ["bcrt1qplausibleaddress"])

    async def test_result_is_cached_so_rpc_called_once(self):
        rpc = _RecordingRPC()
        pool = self._pool_with_rpc(rpc)
        for _ in range(4):
            await pool.validate_address("bcrt1qcacheme")
        self.assertEqual(rpc.calls, ["bcrt1qcacheme"])   # 4 lookups, 1 RPC

    async def test_rpc_says_invalid_returns_false_and_caches(self):
        rpc = _RecordingRPC(isvalid=False)
        pool = self._pool_with_rpc(rpc)
        valid, script = await pool.validate_address("bcrt1qbadbutplausible")
        self.assertFalse(valid)
        self.assertIsNone(script)
        # Even a negative result is cached: a second lookup makes no new RPC.
        await pool.validate_address("bcrt1qbadbutplausible")
        self.assertEqual(len(rpc.calls), 1)

    async def test_rpc_exception_propagates_for_the_caller_to_classify(self):
        # A failing validateaddress re-raises (not (False, None)) so the caller can tell
        # a transient node failure from a real invalid address (abuse-budget accounting).
        rpc = _RecordingRPC(raise_exc=RPCConnectionError("node down"))
        pool = self._pool_with_rpc(rpc)
        with self.assertRaises(RPCConnectionError):
            await pool.validate_address("bcrt1qplausibleaddr")

    async def test_address_cache_is_bounded(self):
        # Past the cap the cache clears rather than growing without bound.
        rpc = _RecordingRPC()
        pool = self._pool_with_rpc(rpc)
        for i in range(MAX_ADDRESS_CACHE + 5):
            await pool.validate_address(f"addr{i}")
        self.assertLessEqual(len(pool._address_cache), MAX_ADDRESS_CACHE)


class TestDonationResolution(unittest.IsolatedAsyncioTestCase):
    """_resolve_donation wiring: a valid address enables the donation output, an
    invalid one disables donation WITHOUT breaking work, and 0% never calls the node."""

    def _pool(self, rpc, **settings):
        pool = Pool(Settings(**settings))
        pool.rpc = rpc
        return pool

    async def test_valid_address_enables_donation(self):
        rpc = _RecordingRPC(isvalid=True)
        pool = self._pool(rpc, donation_percent=2.0, donation_address="bcrt1qexample")
        await pool._resolve_donation()
        self.assertTrue(pool._donation_script)          # non-empty script -> donation enabled
        self.assertEqual(rpc.calls, ["bcrt1qexample"])  # resolved once, via the node

    async def test_invalid_address_disables_donation_not_work(self):
        rpc = _RecordingRPC(isvalid=False)
        pool = self._pool(rpc, donation_percent=2.0, donation_address="bcrt1qbadbutplausible")
        await pool._resolve_donation()
        self.assertEqual(pool._donation_script, b"")    # donation off...
        self.assertTrue(pool._donation_resolved)        # ...marked resolved (no retry storm, work unaffected)

    async def test_zero_percent_short_circuits_without_rpc(self):
        rpc = _RecordingRPC()
        pool = self._pool(rpc, donation_percent=0.0, donation_address="bcrt1qexample")
        await pool._resolve_donation()
        self.assertEqual(pool._donation_script, b"")
        self.assertEqual(rpc.calls, [])                 # 0% never touches the node


class TestRecentJobJunkLookups(unittest.TestCase):
    def test_unknown_job_id_is_none(self):
        pool = Pool(Settings())
        for junk in ("", "does-not-exist", "deadbeef", "1"):
            self.assertIsNone(pool.recent_job(junk))

    def test_non_string_job_id_is_none_not_crash(self):
        # A non-string job_id is just a dict miss -> None, never a crash.
        pool = Pool(Settings())
        for junk in (123, None, 3.14, ("tuple",)):
            self.assertIsNone(pool.recent_job(junk))


class TestRedactUrlAdversarial(unittest.TestCase):
    def test_strips_userinfo(self):
        self.assertEqual(redact_url("http://user:pass@node:8332/"), "http://node:8332/")

    def test_no_credentials_unchanged(self):
        self.assertEqual(redact_url("http://node:8332"), "http://node:8332")

    def test_malformed_url_returned_as_is(self):
        for url in ("node:8332", "http://[bad", "", "not a url at all", "://missing-scheme"):
            # Never raises; either redacts or returns the input unchanged.
            self.assertIsInstance(redact_url(url), str)


if __name__ == "__main__":
    unittest.main()
