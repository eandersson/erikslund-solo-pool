"""A stalled/high-latency client must not hold up the work broadcast to everyone else.

Regression for the head-of-line stall: _fan_out awaits every local client's send, and template_loop
awaits _broadcast, so without a per-send bound one peer with a full send buffer (a latency spike)
delays fresh work to all co-located miners for up to TCP_USER_TIMEOUT.
"""
import asyncio
import time
import unittest
from unittest.mock import patch

from erikslund_pool import pool as pool_module
from erikslund_pool.config import Settings
from erikslund_pool.pool import Pool
from erikslund_pool.stratum import ClientSession
from erikslund_pool.work import Job

_P2WPKH = bytes.fromhex("0014" + "11" * 20)


def _make_job() -> Job:
    now = int(time.time())
    template = {
        "height": 500_001, "version": 0x20000000, "curtime": now, "bits": "207fffff",
        "coinbasevalue": 1_250_000_000, "previousblockhash": "aa" * 32,
        "default_witness_commitment": "6a24aa21a9ed" + "00" * 32, "transactions": [],
    }
    return Job("j", template, tag=b"/t/", extranonce1_size=4, extranonce2_size=8, coinbase_version=1)


class _LatentWriter:
    def __init__(self, drain_delay: float):
        self.drain_delay = drain_delay
        self.frames: list[bytes] = []

    def write(self, data: bytes):
        self.frames.append(data)

    async def drain(self):
        if self.drain_delay:
            await asyncio.sleep(self.drain_delay)

    def get_extra_info(self, key):
        return ("1.2.3.4", 3333) if key == "peername" else None

    def close(self):
        pass


class BroadcastLatencyTests(unittest.IsolatedAsyncioTestCase):
    def _session(self, pool: Pool, drain_delay: float) -> ClientSession:
        session = ClientSession(pool, None, _LatentWriter(drain_delay), b"\x00\x00\x00\x01")
        session.loop = asyncio.get_running_loop()
        session.subscribed = session.authorized = True
        session.payout_script = _P2WPKH
        pool.register(session)
        return session

    async def test_slow_client_does_not_stall_the_broadcast(self):
        pool = Pool(Settings(variable_difficulty=False))
        pool._primary_loop = asyncio.get_running_loop()
        fast = self._session(pool, 0.0)
        slow = self._session(pool, 1.0)   # would block _broadcast for 1s without the per-send bound
        job = _make_job()
        with patch.object(pool_module, "NOTIFY_SEND_TIMEOUT_SECONDS", 0.05):
            start = time.monotonic()
            await pool._broadcast(job, clean=True)
            elapsed = time.monotonic() - start
        # Bounded to ~0.05s -- nowhere near the slow client's 1s drain.
        self.assertLess(elapsed, 0.5)
        # Both clients still had the notify written to their socket buffer (it goes out regardless).
        self.assertTrue(fast.writer.frames)
        self.assertTrue(slow.writer.frames)
