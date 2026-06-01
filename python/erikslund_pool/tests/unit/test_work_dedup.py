"""The pool must not re-broadcast byte-identical work under a new job id.

Doing so resets every miner's search to extranonce2=0, so an unchanged template
must leave miners grinding their current job.
"""
from __future__ import annotations

from erikslund_pool.config import Settings
from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.exceptions import RPCResponseError
from erikslund_pool.pool import Pool
from erikslund_pool.tests.base import AsyncSoloPoolTestCase


class TestWorkKey(AsyncSoloPoolTestCase):
    def test_identity_and_change(self):
        template = self.make_template(txns=2)
        a = self.make_job(template, job_id="a")
        b = self.make_job(template, job_id="b")
        self.assertEqual(a.work_key, b.work_key)  # only the job id differs -> same work

        later = dict(template, curtime=template["curtime"] + 1)
        self.assertNotEqual(a.work_key, self.make_job(later, job_id="c").work_key)

        more = self.make_template(txns=3)
        more["previousblockhash"] = template["previousblockhash"]
        more["curtime"] = template["curtime"]
        self.assertNotEqual(a.work_key, self.make_job(more, job_id="d").work_key)


class TestJobId(AsyncSoloPoolTestCase):
    async def test_job_id_is_prefix_plus_counter(self):
        # 16-hex job id: stable per-process prefix (high 8) + incrementing counter (low 8).
        pool = Pool(Settings())
        template = self.make_template(txns=1)
        a = pool._make_job(template, clean=True)
        b = pool._make_job(template, clean=True)
        self.assertEqual(len(a.job_id), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in a.job_id))
        self.assertEqual(a.job_id[:8], b.job_id[:8])               # same per-process prefix
        self.assertNotEqual(a.job_id, b.job_id)                    # distinct jobs
        self.assertEqual(int(b.job_id[8:], 16), int(a.job_id[8:], 16) + 1)  # counter advances


class TestDuplicateWorkSuppression(AsyncSoloPoolTestCase):
    def _pool(self, template) -> Pool:
        pool = Pool(Settings())
        # Deterministic work, no bitcoind: every poll returns the same template.
        pool.rpc.getblocktemplate = lambda validate=None: template
        return pool

    async def test_identical_rebroadcast_is_suppressed(self):
        template = self.make_template(txns=1)
        pool = self._pool(template)

        await pool._refresh_template(force=True)  # first job (new tip -> clean)
        first = pool.current_job
        self.assertIsNotNone(first)

        await pool._refresh_template(force=True)  # identical template
        self.assertIs(pool.current_job, first)    # same job object kept

    async def test_clean_duplicate_after_fastblock_is_suppressed(self):
        # Fastblock published empty work; GBT returns that same empty work as a clean job.
        # Identical work must be suppressed even when clean.
        template = self.make_template(txns=0)
        pool = self._pool(template)
        current = pool._make_job(template, clean=True)  # built with the pool's own config
        pool.current_job = current
        pool._last_prevhash = "00" * 32  # older tip => the refresh looks like a clean new tip
        await pool._refresh_template(force=False)
        self.assertIs(pool.current_job, current)  # identical clean GBT work was suppressed

    async def test_lower_height_template_is_ignored(self):
        # A template below the current height (lagging node) would yank miners onto an
        # orphan-doomed parent; skip it, keeping current work.
        template = self.make_template(txns=0)  # height 500001
        pool = self._pool(template)
        await pool._refresh_template(force=True)
        current = pool.current_job
        self.assertIsNotNone(current)

        lagging = self.make_template(txns=0, height=500000)
        lagging["previousblockhash"] = "11" * 32  # presents as a "new tip" too
        pool.rpc.getblocktemplate = lambda validate=None: lagging
        await pool._refresh_template(force=True)
        self.assertIs(pool.current_job, current)  # lagging template ignored

    async def test_readiness_unlatches_when_every_endpoint_is_unreachable(self):
        # Unreachable bitcoind degrades readiness; a node that answers an RPC error stays
        # latched (it is connected).
        template = self.make_template(txns=0)
        pool = self._pool(template)
        await pool._refresh_template(force=True)
        self.assertTrue(pool.generator_ready)

        def unreachable(validate=None):
            raise RPCConnectionError("all bitcoind endpoints unreachable")
        pool.rpc.getblocktemplate = unreachable
        await pool._refresh_template(force=True)
        self.assertFalse(pool.generator_ready)   # un-latched: outage is visible

        pool.rpc.getblocktemplate = lambda validate=None: template
        await pool._refresh_template(force=True)
        self.assertTrue(pool.generator_ready)    # re-latched on recovery

        def answers_with_error(validate=None):
            raise RPCResponseError({"code": -10, "message": "warming up"})
        pool.rpc.getblocktemplate = answers_with_error
        await pool._refresh_template(force=True)
        self.assertTrue(pool.generator_ready)    # node answered -> still connected

    async def test_changed_transactions_are_rebroadcast(self):
        template = self.make_template(txns=1)
        pool = self._pool(template)
        await pool._refresh_template(force=True)
        first = pool.current_job

        # Same tip, new transaction set -> fresh work -> must rebroadcast.
        changed = self.make_template(txns=2)
        changed["previousblockhash"] = template["previousblockhash"]
        pool.rpc.getblocktemplate = lambda validate=None: changed
        await pool._refresh_template(force=True)
        self.assertIsNotNone(pool.current_job)
        self.assertIsNot(pool.current_job, first)
