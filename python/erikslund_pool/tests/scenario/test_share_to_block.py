"""Scenario: subscribe -> authorize -> submit a winning share -> block handoff."""
from __future__ import annotations

import json

from erikslund_pool.config import Settings
from erikslund_pool.stratum import ClientSession
from erikslund_pool.tests.base import P2WPKH_SPK
from erikslund_pool.tests.base import AsyncSoloPoolTestCase


class FakeWriter:
    """Captures everything the session writes, decoded back into messages."""
    def __init__(self):
        self.sent: list[bytes] = []

    def get_extra_info(self, _key):
        return ("test", 0)

    def write(self, data: bytes):
        self.sent.append(data)

    async def drain(self):
        pass

    def close(self):
        pass

    def messages(self) -> list[dict]:
        return [json.loads(b) for b in self.sent]

    def by_id(self, message_id):
        return next(m for m in self.messages() if m.get("id") == message_id)


class FakePool:
    """Minimal Pool surface the ClientSession depends on."""
    def __init__(self, job, config):
        self.config = config
        self.current_job = job
        self._job = job
        self.block_calls = []

    def assign_extranonce1(self):
        return b"\x00\x00\x00\x01"

    def register(self, _session):
        pass

    def unregister(self, _session):
        pass

    def recent_job(self, job_id):
        return self._job if job_id == self._job.job_id else None

    def _current_job_locked(self):
        return self.current_job

    def attach_worker(self, _address, _worker):
        pass

    def note_accepted_share(self, _address, _worker, _credited, _best):
        pass

    def note_rejected_share(self, _address, _worker):
        pass

    async def validate_address(self, _address):
        return (True, P2WPKH_SPK)

    async def on_block_found(self, session, job, result):
        self.block_calls.append((session, job, result))


class TestShareToBlock(AsyncSoloPoolTestCase):
    async def test_full_session_finds_block(self):
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        pool = FakePool(job, config)
        writer = FakeWriter()
        session = ClientSession(pool, None, writer, pool.assign_extranonce1())

        # subscribe -> [[(set_difficulty,id),(notify,id)], extranonce1, extranonce2_size]
        await session.handle_subscribe(1, ["cpuminer/test"])
        subscription = writer.by_id(1)["result"]
        self.assertEqual(subscription[1], session.extranonce1_hex)
        self.assertEqual(subscription[2], config.extranonce2_size)

        # authorize -> true, then the server pushes difficulty + first job
        await session.handle_authorize(2, ["bcrt1qexampleworkeraddress"])
        self.assertIs(writer.by_id(2)["result"], True)
        self.assertTrue(session.authorized)
        methods = [m.get("method") for m in writer.messages()]
        self.assertIn("mining.set_difficulty", methods)
        self.assertIn("mining.notify", methods)

        # mine a winning share off the same job and submit it
        _result, extranonce2, ntime, nonce = self.find_block_share(
            job, extranonce1=session.extranonce1)
        await session.handle_submit(
            3, ["bcrt1qexampleworkeraddress", job.job_id, extranonce2, ntime, nonce])
        self.assertIs(writer.by_id(3)["result"], True)
        self.assertEqual(len(pool.block_calls), 1)

    async def test_stale_job_rejected(self):
        config = Settings(variable_difficulty=False)
        job = self.make_job()
        pool = FakePool(job, config)
        writer = FakeWriter()
        session = ClientSession(pool, None, writer, pool.assign_extranonce1())
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["addr"])
        await session.handle_submit(3, ["addr", "no-such-job", "00" * 8, job.ntime_hex, "00000000"])
        response = writer.by_id(3)
        self.assertIsNone(response["result"])
        self.assertEqual(response["error"][0], 21)  # ERR_STALE

    async def test_duplicate_share_rejected(self):
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        pool = FakePool(job, config)
        writer = FakeWriter()
        session = ClientSession(pool, None, writer, pool.assign_extranonce1())
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["addr"])
        _result, extranonce2, ntime, nonce = self.find_block_share(
            job, extranonce1=session.extranonce1)
        await session.handle_submit(3, ["addr", job.job_id, extranonce2, ntime, nonce])
        await session.handle_submit(4, ["addr", job.job_id, extranonce2, ntime, nonce])
        self.assertEqual(writer.by_id(4)["error"][0], 22)  # ERR_DUPLICATE
