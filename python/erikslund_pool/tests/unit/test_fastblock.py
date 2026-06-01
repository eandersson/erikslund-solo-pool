"""fastblock: on a new tip, build empty 'stop work' for the next block.

The empty job is grounded in a getblockheader call on the notified hash for the
true next height, the new tip's nBits, and its median-time-past (ntime floor).
"""
import time
import unittest

from erikslund_pool.config import Settings
from erikslund_pool.pool import Pool
from erikslund_pool.pool import block_subsidy
from erikslund_pool.work import Job

TEMPLATE = {
    "height": 100,
    "version": 0x20000000,
    "curtime": 1700000000,
    "bits": "1d00ffff",
    "coinbasevalue": 5000000000,
    "previousblockhash": "00" * 32,
    "transactions": [],
}


class _FakeHeaderRPC:
    """Serves getblockheader for the notified hash; records the calls."""

    def __init__(self, height: int, mediantime: int = 1699999000, bits: str = "1d00ffff",
                 confirmations: int = 1):
        self.height = height
        self.mediantime = mediantime
        self.bits = bits
        self.confirmations = confirmations
        self.calls: list[str] = []

    def getblockheader(self, block_hash: str) -> dict:
        self.calls.append(block_hash)
        return {"hash": block_hash, "height": self.height,
                "mediantime": self.mediantime, "bits": self.bits,
                "confirmations": self.confirmations}


def _pool_at(height: int, chain: str | None = "main", *,
             header_height: int | None = None, mediantime: int = 1699999000,
             bits: str = "1d00ffff", confirmations: int = 1) -> Pool:
    pool = Pool(Settings())
    if chain is not None:
        pool.chain_info = {"chain": chain}
    pool.current_job = Job("1", dict(TEMPLATE, height=height), tag=b"/x/",
                           extranonce1_size=4, extranonce2_size=8, coinbase_version=1)
    # The notified block normally lands at the height the current job was mining.
    pool.rpc = _FakeHeaderRPC(header_height if header_height is not None else height,
                              mediantime=mediantime, bits=bits, confirmations=confirmations)
    return pool


class FastblockTests(unittest.IsolatedAsyncioTestCase):
    async def test_builds_empty_next_block_work(self):
        pool = _pool_at(100, chain="main")
        new_tip = "11" * 32
        await pool._fastblock(new_tip)  # no clients -> broadcast is a no-op

        empty = pool.current_job
        self.assertIsNotNone(empty)
        self.assertEqual(empty.height, 101)                    # header height + 1
        self.assertEqual(empty.txn_count, 0)                   # empty block
        self.assertEqual(empty.coinbasevalue, 5_000_000_000)   # exact subsidy at height 101
        self.assertEqual(empty.prevhash_internal, bytes.fromhex(new_tip)[::-1])
        self.assertEqual(pool.rpc.calls, [new_tip])            # grounded in the real header
        self.assertGreater(pool._last_broadcast_time, 0)       # rebroadcast timer reset

    async def test_height_comes_from_the_header_not_the_cached_job(self):
        # On a multi-block advance/reorg job.height+1 is wrong; the header's height is
        # authoritative, else a bad-cb-height invalid block.
        pool = _pool_at(100, chain="main", header_height=104)  # tip advanced 5 blocks
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 105)         # header+1, not job.height+1

    async def test_noop_without_a_current_job(self):
        pool = Pool(Settings())
        self.assertIsNone(pool.current_job)
        await pool._fastblock("22" * 32)  # nothing to derive from
        self.assertIsNone(pool.current_job)

    async def test_floors_curtime_at_the_new_tips_mediantime(self):
        # ntime must exceed the new tip's median-time-past, else a time-too-old block.
        pool = _pool_at(100, chain="main", mediantime=4_000_000_000)  # far ahead of wall clock
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.curtime, 4_000_000_001)     # MTP + 1

    async def test_uses_the_new_tips_bits(self):
        pool = _pool_at(100, chain="main", bits="1a2b3c4d")
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.nbits_hex, "1a2b3c4d")

    async def test_skips_when_notification_matches_the_held_tip(self):
        # block_hash == _last_prevhash: the GBT already advanced to this tip.
        pool = _pool_at(100)
        pool._last_prevhash = "33" * 32
        await pool._fastblock("33" * 32)
        self.assertEqual(pool.current_job.height, 100)  # unchanged: skipped
        self.assertEqual(pool.rpc.calls, [])            # gated before any RPC

    async def test_skips_a_second_fastblock_until_the_next_gbt(self):
        pool = _pool_at(100)
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 101)
        self.assertTrue(pool._fastblock_pending)
        await pool._fastblock("22" * 32)
        self.assertEqual(pool.current_job.height, 101)  # unchanged: second one skipped

    async def test_skips_at_a_difficulty_retarget_boundary(self):
        # Next block 2016 retargets difficulty -> the new tip's nBits don't apply.
        pool = _pool_at(2015, chain="main")
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 2015)  # unchanged: skipped

    async def test_skips_on_testnet_chains(self):
        # The 20-minute rule makes required nBits timestamp-dependent at EVERY height.
        for chain in ("test", "testnet4"):
            pool = _pool_at(100, chain=chain)
            await pool._fastblock("11" * 32)
            self.assertEqual(pool.current_job.height, 100, chain)  # skipped
            self.assertEqual(pool.rpc.calls, [], chain)            # gated before any RPC

    async def test_subsidy_is_exact_across_a_halving_boundary(self):
        # regtest halves every 150: the next block (150) pays the halved subsidy.
        pool = _pool_at(149, chain="regtest")
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 150)
        self.assertEqual(pool.current_job.coinbasevalue, 2_500_000_000)

    async def test_resetting_pending_after_a_gbt_lets_fastblock_resume(self):
        pool = _pool_at(100)
        pool._fastblock_pending = True
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 100)  # skipped while pending
        pool._fastblock_pending = False                  # next GBT clears it
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 101)  # now issues

    async def test_fastblock_resets_the_rebroadcast_timer_not_the_template_age(self):
        pool = _pool_at(100)
        pool._last_broadcast_time = time.monotonic() - 1000  # rebroadcast long overdue
        timer_before = pool._last_broadcast_time
        age_before = pool._last_template_time
        await pool._fastblock("11" * 32)
        self.assertGreater(pool._last_broadcast_time, timer_before)
        self.assertEqual(pool._last_template_time, age_before)  # metric untouched

    async def test_skips_a_stale_notification(self):
        pool = _pool_at(100, confirmations=2)
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 100)  # unchanged: skipped
        # Reorged away entirely (-1): same.
        pool = _pool_at(100, confirmations=-1)
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 100)

    async def test_skips_while_the_chain_is_unknown(self):
        # Empty chain_info would fail the testnet/halving gates open, so skip until known.
        pool = _pool_at(100, chain=None)
        await pool._fastblock("11" * 32)
        self.assertEqual(pool.current_job.height, 100)  # unchanged: skipped
        self.assertEqual(pool.rpc.calls, [])            # gated before any RPC

    async def test_empty_job_never_replaces_a_full_job_for_the_same_tip(self):
        # If a concurrent GBT already published a full job on the notified tip, the
        # empty job must be suppressed (require_new_prevhash) or fees are lost.
        new_tip = "11" * 32
        pool = _pool_at(100)
        full = Job("2", dict(TEMPLATE, height=101, previousblockhash=new_tip), tag=b"/x/",
                   extranonce1_size=4, extranonce2_size=8, coinbase_version=1)
        pool.current_job = full  # the full job for the notified tip won the race
        await pool._fastblock(new_tip)
        self.assertIs(pool.current_job, full)  # empty job suppressed, fees kept


class BlockSubsidyTests(unittest.TestCase):
    def test_mirrors_consensus_getblocksubsidy(self):
        self.assertEqual(block_subsidy(0, 210000), 5_000_000_000)
        self.assertEqual(block_subsidy(209999, 210000), 5_000_000_000)
        self.assertEqual(block_subsidy(210000, 210000), 2_500_000_000)
        self.assertEqual(block_subsidy(420000, 210000), 1_250_000_000)
        self.assertEqual(block_subsidy(840000, 210000), 312_500_000)  # 3.125 BTC (2024)
        self.assertEqual(block_subsidy(33 * 210000, 210000), 0)
        self.assertEqual(block_subsidy(64 * 210000, 210000), 0)
        self.assertEqual(block_subsidy(100 * 210000, 210000), 0)
        # Regtest halves every 150.
        self.assertEqual(block_subsidy(149, 150), 5_000_000_000)
        self.assertEqual(block_subsidy(150, 150), 2_500_000_000)


if __name__ == "__main__":
    unittest.main()
