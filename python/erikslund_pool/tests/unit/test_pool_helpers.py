"""Unit tests for Pool's pure helpers (no bitcoind / event loop)."""

import asyncio
import unittest

from erikslund_pool.config import Settings
from erikslund_pool.constants import MAX_RECENT_JOBS
from erikslund_pool.pool import Pool
from erikslund_pool.util import redact_url


class TestPlausibleAddress(unittest.TestCase):
    def test_accepts_real_address_shapes(self):
        self.assertTrue(Pool._plausible_address("bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7k"))
        self.assertTrue(Pool._plausible_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"))
        self.assertTrue(Pool._plausible_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"))
        self.assertTrue(Pool._plausible_address("addr.worker_1"))  # suffix separators

    def test_rejects_junk(self):
        self.assertFalse(Pool._plausible_address(""))
        self.assertFalse(Pool._plausible_address("a" * 101))      # too long
        self.assertFalse(Pool._plausible_address("has space"))
        self.assertFalse(Pool._plausible_address("bang!"))
        self.assertFalse(Pool._plausible_address("semi;colon"))
        self.assertFalse(Pool._plausible_address("pct%20"))

    def test_boundary_length(self):
        self.assertTrue(Pool._plausible_address("a" * 100))       # exactly 100 ok
        self.assertFalse(Pool._plausible_address("a" * 101))


class TestAdmitInFlight(unittest.TestCase):
    """The accept gate counts in-flight (pre-register) connections toward max_clients, so a
    burst of slow PROXY-header reads can't overshoot the memory bound."""

    def test_inflight_counts_toward_max_clients(self):
        pool = Pool(Settings(max_clients=2))
        self.assertTrue(pool._admit())    # 0 registered + 0 in-flight -> reserve, in-flight=1
        self.assertTrue(pool._admit())    # in-flight=2
        self.assertFalse(pool._admit())   # at cap (0 + 2) -> rejected, no reservation
        self.assertEqual(pool._inflight, 2)
        pool._release_inflight()
        self.assertTrue(pool._admit())     # a freed slot is reusable

    def test_registered_clients_plus_inflight_hit_the_cap(self):
        pool = Pool(Settings(max_clients=2))
        pool.register(object())            # 1 registered client
        self.assertTrue(pool._admit())     # 1 registered + 0 in-flight -> reserve
        self.assertFalse(pool._admit())    # 1 + 1 = 2 = cap
        self.assertEqual(pool._inflight, 1)

    def test_release_balances_the_counter(self):
        pool = Pool(Settings(max_clients=5))
        pool._admit()
        pool._admit()
        self.assertEqual(pool._inflight, 2)
        pool._release_inflight()
        self.assertEqual(pool._inflight, 1)


class TestRedactUrl(unittest.TestCase):
    def test_strips_userinfo(self):
        self.assertEqual(redact_url("http://user:pass@node:8332/"), "http://node:8332/")

    def test_keeps_url_without_credentials(self):
        self.assertEqual(redact_url("http://node:8332"), "http://node:8332")

    def test_unparseable_returns_input(self):
        self.assertEqual(redact_url("node:8332"), "node:8332")
        self.assertEqual(redact_url("http://[bad"), "http://[bad")

    def test_password_containing_at_is_fully_stripped(self):
        # Cut at the LAST '@' of the authority so a '@' inside the password can't leak a tail.
        redacted = redact_url("http://u:p@ss@host:8332")
        self.assertEqual(redacted, "http://host:8332")
        self.assertNotIn("@", redacted)

    def test_scheme_less_credentials_are_stripped(self):
        # urlsplit leaves these intact (no '//' authority) -- the manual strip must still redact.
        self.assertEqual(redact_url("user:pass@host:8332"), "host:8332")

    def test_at_in_path_is_not_treated_as_userinfo(self):
        self.assertEqual(redact_url("http://host:8332/path@x"), "http://host:8332/path@x")

    def test_at_in_query_or_fragment_is_not_treated_as_userinfo(self):
        # The authority ends at the first '/', '?', or '#', so '@' in a query/fragment is left intact.
        self.assertEqual(redact_url("http://host:8332?a=@x"), "http://host:8332?a=@x")
        self.assertEqual(redact_url("http://host:8332#frag@x"), "http://host:8332#frag@x")
        # Credentials before a query are still stripped.
        self.assertEqual(redact_url("http://u:p@host:8332?a=1"), "http://host:8332?a=1")


class _StatsSession:
    """Minimal session stand-in for connector/client stats aggregation."""

    def __init__(self, address, *, accepted=0, rejected=0, best=0.0, ts=0,
                 subscribed=True, authorized=True):
        self.address = address
        self.shares_accepted = accepted
        self.shares_rejected = rejected
        self.best_diff = best
        self.last_share_ts = ts
        self.subscribed = subscribed
        self.authorized = authorized

    def stats(self):
        return {"shares_rejected": self.shares_rejected, "last_share_ts": self.last_share_ts}


class TestConnectorAndClientStats(unittest.TestCase):
    def test_connector_stats_has_no_event_loops(self):
        # The API connector block is exactly {workers, subscribed, authorized}; the internal
        # event-loop count is not exposed.
        pool = Pool(Settings())
        self.assertEqual(set(pool.connector_stats([])), {"workers", "subscribed", "authorized"})

    def test_client_stats_has_top_level_shares_rejected_and_int_ts(self):
        pool = Pool(Settings())
        pool.register(_StatsSession("bc1qexample", accepted=5, rejected=2, best=9.0, ts=1700000000))
        stats = pool.client_stats("bc1qexample")
        self.assertEqual(stats["shares_accepted"], 5)
        self.assertEqual(stats["shares_rejected"], 2)   # top-level rollup present (matches C++)
        self.assertIsInstance(stats["last_share_ts"], int)
        self.assertEqual(stats["last_share_ts"], 1700000000)


class TestAssignExtranonce1(unittest.TestCase):
    def test_size_and_monotonic_increment(self):
        pool = Pool(Settings(extranonce1_size=4))
        first = pool.assign_extranonce1()
        second = pool.assign_extranonce1()
        self.assertEqual(len(first), 4)
        self.assertEqual(first.hex(), "00000001")
        self.assertEqual(second.hex(), "00000002")

    def test_wraps_within_byte_width(self):
        # Seed the counter at the top of the 32-bit space; the next assignments wrap to 0, 1.
        pool = Pool(Settings(extranonce1_size=4))
        pool._extranonce1_counter = (1 << 32) - 2
        self.assertEqual(pool.assign_extranonce1().hex(), "ffffffff")
        self.assertEqual(pool.assign_extranonce1().hex(), "00000000")  # wrapped
        self.assertEqual(pool.assign_extranonce1().hex(), "00000001")


class TestRecentJobs(unittest.TestCase):
    TEMPLATE = {
        "height": 100, "version": 0x20000000, "curtime": 1700000000,
        "bits": "207fffff", "coinbasevalue": 5_000_000_000,
        "previousblockhash": "00" * 32, "transactions": [],
    }

    def _broadcast(self, pool, template, clean=False):
        """Build and publish a job as the pool does (_make_job + _broadcast)."""
        job = pool._make_job(template, clean=clean)
        asyncio.run(pool._broadcast(job, clean))   # no clients registered -> just publishes
        return job

    def test_broadcast_registers_recent_and_current(self):
        pool = Pool(Settings())
        job = self._broadcast(pool, self.TEMPLATE, clean=True)
        self.assertIs(pool.current_job, job)
        self.assertIs(pool.recent_job(job.job_id), job)
        self.assertIsNone(pool.recent_job("does-not-exist"))

    def test_recent_jobs_are_bounded(self):
        pool = Pool(Settings())
        ids = []
        for i in range(MAX_RECENT_JOBS + 4):
            # Distinct curtime -> distinct work_key, so none are deduped away.
            template = {**self.TEMPLATE, "curtime": self.TEMPLATE["curtime"] + i}
            ids.append(self._broadcast(pool, template).job_id)
        self.assertLessEqual(len(pool._recent), MAX_RECENT_JOBS)
        # The most recent job is always retrievable; the oldest was evicted.
        self.assertIsNotNone(pool.recent_job(ids[-1]))
        self.assertIsNone(pool.recent_job(ids[0]))


class TestStatsShapes(unittest.TestCase):
    def test_status_keys_when_idle(self):
        status = Pool(Settings()).status()
        self.assertNotIn("mode", status)             # dropped: always "solo"
        self.assertFalse(status["ready"])           # no job yet
        for key in ("name", "version", "pid", "uptime", "bitcoind_connected"):
            self.assertIn(key, status)

    def test_pool_stats_idle(self):
        stats = Pool(Settings()).pool_stats()
        self.assertIsNone(stats["height"])
        self.assertIsNone(stats["network_diff"])
        self.assertEqual(stats["workers"], 0)
        self.assertEqual(stats["hashrate_estimate"], 0.0)
        self.assertEqual(stats["best_share"], 0.0)

    def test_metrics_aggregates_subsections(self):
        metrics = Pool(Settings()).metrics()
        for key in ("pool", "stratifier", "connector", "generator"):
            self.assertIn(key, metrics)
        self.assertIn("bitcoind_connected", metrics)

    def test_generator_stats_redacts_rpc_url(self):
        pool = Pool(Settings(rpc_url="http://secret:hunter2@node:8332"))
        self.assertEqual(pool.generator_stats()["rpc_url"], "http://node:8332")
