"""Block-spool durability: atomic spool write, startup re-submit + archive."""

import os
import tempfile
import unittest

from erikslund_pool.config import Settings
from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.pool import Pool


class _FakeRPC:
    def __init__(self, results=None, raise_exc=None):
        self.results = results or {}   # block_hex -> reason (None = accepted, str = rejected)
        self.raise_exc = raise_exc     # exception to raise from submitblock (node down)
        self.submitted: list[str] = []

    def submitblock(self, block_hex):
        self.submitted.append(block_hex)
        if self.raise_exc is not None:
            raise self.raise_exc
        return self.results.get(block_hex)


def _pool(temp_dir, rpc=None):
    pool = Pool(Settings())  # constructs offline (no bitcoind connection in __init__)
    pool.block_spool_dir = os.path.join(temp_dir, "blocks")
    if rpc is not None:
        pool.rpc = rpc
    return pool


class TestSpoolBlock(unittest.TestCase):
    def test_spool_is_atomic_and_readable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = _pool(temp_dir)
            block_hash = "aa" * 32
            pool._spool_block(101, block_hash, "deadbeef")
            path = os.path.join(pool.block_spool_dir, f"101_{block_hash}.hex")
            self.assertTrue(os.path.exists(path))
            with open(path, encoding="ascii") as f:
                self.assertEqual(f.read().strip(), "deadbeef")
            # The atomic tmp+rename must not leave a stray temp file behind.
            leftovers = [n for n in os.listdir(pool.block_spool_dir) if ".tmp" in n]
            self.assertEqual(leftovers, [])


class TestResubmitSpooledBlocks(unittest.TestCase):
    def test_missing_spool_dir_is_a_noop(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = _pool(temp_dir, _FakeRPC())  # block_spool_dir does not exist yet
            pool._resubmit_spooled_blocks()     # must not raise
            self.assertEqual(pool.rpc.submitted, [])

    def test_accepted_block_is_resubmitted_and_archived(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = _pool(temp_dir, _FakeRPC(results={"abc123": None}))  # accepted
            block_hash = "bb" * 32
            pool._spool_block(200, block_hash, "abc123")
            pool._resubmit_spooled_blocks()
            self.assertEqual(pool.rpc.submitted, ["abc123"])
            name = os.path.join(pool.block_spool_dir, f"200_{block_hash}.hex")
            self.assertFalse(os.path.exists(name))
            self.assertTrue(os.path.exists(name + ".submitted"))

    def test_duplicate_is_treated_as_confirmed(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = _pool(temp_dir, _FakeRPC(results={"dup": "duplicate"}))
            block_hash = "cc" * 32
            pool._spool_block(201, block_hash, "dup")
            pool._resubmit_spooled_blocks()
            name = os.path.join(pool.block_spool_dir, f"201_{block_hash}.hex")
            self.assertTrue(os.path.exists(name + ".submitted"))

    def test_rejected_block_is_archived_as_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = _pool(temp_dir, _FakeRPC(results={"stale": "stale-prevblk"}))
            block_hash = "dd" * 32
            pool._spool_block(202, block_hash, "stale")
            pool._resubmit_spooled_blocks()
            name = os.path.join(pool.block_spool_dir, f"202_{block_hash}.hex")
            self.assertTrue(os.path.exists(name + ".rejected"))
            self.assertFalse(os.path.exists(name + ".submitted"))

    def test_unreachable_node_leaves_file_for_next_restart(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = _pool(temp_dir, _FakeRPC(raise_exc=RPCConnectionError("down")))
            block_hash = "ee" * 32
            pool._spool_block(203, block_hash, "hex203")
            pool._resubmit_spooled_blocks()
            name = os.path.join(pool.block_spool_dir, f"203_{block_hash}.hex")
            self.assertTrue(os.path.exists(name))             # still there, will retry
            self.assertFalse(os.path.exists(name + ".submitted"))
            self.assertFalse(os.path.exists(name + ".rejected"))


if __name__ == "__main__":
    unittest.main()
