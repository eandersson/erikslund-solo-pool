"""Durable block submission: atomic spool, retry, archival, and accounting."""

import asyncio
import os
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

from erikslund_pool.config import Settings
from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.pool import Pool
from erikslund_pool.pool import _PendingBlock


class _FakeRPC:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes or (None,))
        self.submitted: list[str] = []
        self._lock = threading.Lock()

    def submitblock(self, block_hex):
        with self._lock:
            self.submitted.append(block_hex)
            outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _BlockingRPC:
    def __init__(self):
        self.started = threading.Event()
        self.release = threading.Event()

    def submitblock(self, _block_hex):
        self.started.set()
        self.release.wait()


def _pool(temp_dir, rpc=None):
    pool = Pool(Settings())
    pool.block_spool_dir = os.path.join(temp_dir, "blocks")
    if rpc is not None:
        pool.rpc = rpc
    return pool


def _wait_for(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    raise AssertionError("timed out waiting for block submission")


class _PoolCleanupMixin:
    def make_pool(self, temp_dir, rpc=None):
        pool = _pool(temp_dir, rpc)
        self.addCleanup(pool._validate_executor.shutdown, wait=False)
        self.addCleanup(pool._stop_submit_worker)
        return pool


class TestSpoolBlock(_PoolCleanupMixin, unittest.TestCase):
    def test_spool_is_atomic_and_readable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = self.make_pool(temp_dir)
            block_hash = "aa" * 32
            path = pool._spool_block(101, block_hash, "e06ae06a")

            self.assertTrue(os.path.exists(path))
            with open(path, encoding="ascii") as spool:
                self.assertEqual(spool.read().strip(), "e06ae06a")
            leftovers = [name for name in os.listdir(pool.block_spool_dir) if ".tmp" in name]
            self.assertEqual(leftovers, [])


class TestSubmitQueue(_PoolCleanupMixin, unittest.TestCase):
    def _recover(self, temp_dir, rpc, *, height, block_hash, block_hex):
        pool = self.make_pool(temp_dir, rpc)
        path = pool._spool_block(height, block_hash, block_hex)
        pool._enqueue_spooled_blocks()
        pool._start_submit_worker()
        return pool, path

    def test_missing_spool_dir_is_a_noop(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = self.make_pool(temp_dir, _FakeRPC())

            pool._enqueue_spooled_blocks()

            self.assertEqual(pool.rpc.submitted, [])
            self.assertEqual(pool._submit_queue, [])

    def test_recovered_accepted_block_is_archived_without_double_credit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool, path = self._recover(
                temp_dir,
                _FakeRPC(None),
                height=200,
                block_hash="bb" * 32,
                block_hex="abc123",
            )

            _wait_for(lambda: os.path.exists(path + ".submitted"))

            self.assertEqual(pool.rpc.submitted, ["abc123"])
            self.assertEqual(pool.blocks_found, 0)

    def test_recovered_duplicate_is_archived_without_double_credit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool, path = self._recover(
                temp_dir,
                _FakeRPC("duplicate"),
                height=201,
                block_hash="cc" * 32,
                block_hex="dup",
            )

            _wait_for(lambda: os.path.exists(path + ".submitted"))

            self.assertEqual(pool.blocks_found, 0)

    def test_rejected_block_is_archived_as_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            _pool_instance, path = self._recover(
                temp_dir,
                _FakeRPC("stale-prevblk"),
                height=202,
                block_hash="dd" * 32,
                block_hex="stale",
            )

            _wait_for(lambda: os.path.exists(path + ".rejected"))

            self.assertFalse(os.path.exists(path + ".submitted"))

    def test_rpc_failure_retries_without_waiting_for_restart(self):
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("erikslund_pool.pool.BLOCK_SUBMIT_RETRY_INITIAL_SECONDS", 0.01),
        ):
            rpc = _FakeRPC(RPCConnectionError("down"), None)
            _pool_instance, path = self._recover(
                temp_dir,
                rpc,
                height=203,
                block_hash="ee" * 32,
                block_hex="retry",
            )

            _wait_for(lambda: os.path.exists(path + ".submitted"))

            self.assertEqual(rpc.submitted, ["retry", "retry"])

    def test_inconclusive_submission_retries_until_confirmed(self):
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("erikslund_pool.pool.BLOCK_SUBMIT_RETRY_INITIAL_SECONDS", 0.01),
        ):
            rpc = _FakeRPC("inconclusive", None)
            _pool_instance, path = self._recover(
                temp_dir,
                rpc,
                height=204,
                block_hash="ef" * 32,
                block_hex="inconclusive",
            )

            _wait_for(lambda: os.path.exists(path + ".submitted"))

            self.assertEqual(rpc.submitted, ["inconclusive", "inconclusive"])

    def test_live_duplicate_credits_the_local_block_exactly_once(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            address = "bc1qtest"
            block_hash = "ab" * 32
            pool = self.make_pool(temp_dir, _FakeRPC("duplicate"))
            path = pool._spool_block(205, block_hash, "duplicate")
            block = _PendingBlock(
                205,
                block_hash,
                "duplicate",
                address,
                "worker",
                path,
            )

            self.assertFalse(pool._submit_block(block))
            self.assertFalse(pool._submit_block(block))

            self.assertEqual(pool.blocks_found, 1)
            self.assertEqual(pool._blocks_by_address, {address: 1})

    def test_duplicate_inconclusive_is_retryable_and_not_credited(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = self.make_pool(temp_dir, _FakeRPC("duplicate-inconclusive"))
            block_hash = "ac" * 32
            path = pool._spool_block(206, block_hash, "pending")
            block = _PendingBlock(
                206,
                block_hash,
                "pending",
                "bc1qtest",
                "worker",
                path,
            )

            self.assertTrue(pool._submit_block(block))

            self.assertEqual(pool.blocks_found, 0)
            self.assertTrue(os.path.exists(path))

    def test_shutdown_does_not_wait_forever_for_a_stuck_rpc(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rpc = _BlockingRPC()
            pool = self.make_pool(temp_dir, rpc)
            block_hash = "ad" * 32
            path = pool._spool_block(207, block_hash, "blocked")
            pool._enqueue_block(
                _PendingBlock(207, block_hash, "blocked", "bc1qtest", "worker", path)
            )
            pool._start_submit_worker()
            self.assertTrue(rpc.started.wait(timeout=1))

            try:
                with patch(
                    "erikslund_pool.pool.BLOCK_SUBMIT_SHUTDOWN_WAIT_SECONDS",
                    0.01,
                ):
                    started = time.monotonic()
                    pool._stop_submit_worker()
                    elapsed = time.monotonic() - started

                self.assertLess(elapsed, 0.5)
                self.assertTrue(pool._submit_thread.is_alive())
                self.assertTrue(os.path.exists(path))
            finally:
                rpc.release.set()
                pool._submit_thread.join(timeout=1)


class TestLiveBlockSubmission(_PoolCleanupMixin, unittest.IsolatedAsyncioTestCase):
    async def test_winner_returns_after_spooling_without_waiting_for_rpc(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            rpc = _BlockingRPC()
            pool = self.make_pool(temp_dir, rpc)
            pool._start_submit_worker()
            block_hash = "ae" * 32
            session = types.SimpleNamespace(address="bc1qtest", worker="worker")
            job = types.SimpleNamespace(
                height=208,
                build_block_hex=lambda _coinbase, _header: "live",
            )
            result = types.SimpleNamespace(
                block_hash_hex=block_hash,
                legacy_coinbase=b"coinbase",
                header=b"header",
            )

            try:
                await asyncio.wait_for(pool.on_block_found(session, job, result), timeout=0.5)
                self.assertTrue(rpc.started.wait(timeout=1))
                self.assertTrue(
                    os.path.exists(
                        os.path.join(pool.block_spool_dir, f"208_{block_hash}.hex")
                    )
                )
            finally:
                rpc.release.set()


if __name__ == "__main__":
    unittest.main()
