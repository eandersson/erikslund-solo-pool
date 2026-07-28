"""SV2 Standard/Extended Channel behavior and issued-work invariants."""

import time
from unittest import mock

from erikslund_pool import constants
from erikslund_pool import util
from erikslund_pool import work
from erikslund_pool.config import Settings
from erikslund_pool.sv2 import codec as sv2_codec
from erikslund_pool.sv2 import messages as sv2_messages
from erikslund_pool.sv2.session import SV2_CHANNEL_DISCRIMINATOR_BYTES
from erikslund_pool.sv2.session import SV2_GROUP_CHANNEL_ID
from erikslund_pool.sv2.session import IssuedExtendedJob
from erikslund_pool.sv2.session import Sv2Session
from erikslund_pool.tests.base import P2WPKH_SPK
from erikslund_pool.tests.base import AsyncSoloPoolTestCase

FIRST_CHANNEL_ID = 1


class _WireWriter:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    def get_extra_info(self, key: str, default: object = None):
        if key == "peername":
            return ("test", 3_334)
        return default

    def write(self, data: bytes) -> None:
        self.sent.append(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass

    def messages(self) -> list[sv2_messages.Message]:
        decoder = sv2_codec.FrameDecoder()
        frames: list[sv2_codec.Frame] = []
        for wire in self.sent:
            frames.extend(decoder.feed(wire))
        decoder.finish()
        return [sv2_messages.decode_message(frame) for frame in frames]


class _WireReader:
    def __init__(self, *chunks: bytes) -> None:
        self._chunks = list(chunks)

    async def read(self, _size: int = -1) -> bytes:
        return self._chunks.pop(0) if self._chunks else b""


class _FakePool:
    def __init__(self, job: work.Job | None, config: Settings) -> None:
        self.config = config
        self.current_job = job
        self.attached_workers: list[tuple[str, str]] = []
        self.accepted_shares: list[tuple[str, str, float, float]] = []
        self.rejected_shares: list[tuple[str, str, str]] = []
        self.block_calls: list[
            tuple[Sv2Session, work.Job, work.ShareResult, str | None, str | None]
        ] = []

    def register(self, _session: Sv2Session) -> None:
        pass

    def unregister(self, _session: Sv2Session) -> None:
        pass

    def _current_job_locked(self) -> work.Job | None:
        return self.current_job

    def attach_worker(self, address: str, worker_name: str) -> None:
        self.attached_workers.append((address, worker_name))

    def note_accepted_share(
            self, address: str, worker_name: str, credited: float, best: float) -> None:
        self.accepted_shares.append((address, worker_name, credited, best))

    def note_rejected_share(self, address: str, worker_name: str, reason: str) -> None:
        self.rejected_shares.append((address, worker_name, reason))

    async def validate_address(self, _address: str) -> tuple[bool, bytes]:
        return True, P2WPKH_SPK

    async def on_block_found(
            self, session: Sv2Session, job: work.Job, result: work.ShareResult, *,
            address: str | None = None, worker: str | None = None) -> None:
        self.block_calls.append((session, job, result, address, worker))


def _setup_message(
        flags: int = sv2_messages.REQUIRES_STANDARD_JOBS_FLAG
        ) -> sv2_messages.SetupConnection:
    return sv2_messages.SetupConnection(
        protocol=sv2_messages.MINING_PROTOCOL,
        min_version=sv2_messages.PROTOCOL_VERSION,
        max_version=sv2_messages.PROTOCOL_VERSION,
        flags=flags,
        endpoint_host="127.0.0.1",
        endpoint_port=3_334,
        vendor="test",
        hardware_version="miner",
        firmware="1",
        device_id="rig",
    )


def _open_message(
        request_id: int = 7, nominal_hash_rate: float = 1_000_000.0
        ) -> sv2_messages.OpenStandardMiningChannel:
    return sv2_messages.OpenStandardMiningChannel(
        request_id=request_id,
        user_identity="bcrt1qexampleworkeraddress.rig",
        nominal_hash_rate=nominal_hash_rate,
        max_target=((1 << 256) - 1).to_bytes(32, "little"),
    )


def _open_extended_message(
        request_id: int = 9, nominal_hash_rate: float = 1_000_000.0,
        min_extranonce_size: int = 2,
        user_identity: str = "bcrt1qexampleworkeraddress.proxy",
        ) -> sv2_messages.OpenExtendedMiningChannel:
    return sv2_messages.OpenExtendedMiningChannel(
        request_id=request_id,
        user_identity=user_identity,
        nominal_hash_rate=nominal_hash_rate,
        max_target=((1 << 256) - 1).to_bytes(32, "little"),
        min_extranonce_size=min_extranonce_size,
    )


def _only_channel(session: Sv2Session):
    return next(iter(session._channels.values()))


class TestSv2ChannelOpening(AsyncSoloPoolTestCase):
    def _session(
            self, job: work.Job | None, config: Settings | None = None
            ) -> tuple[Sv2Session, _FakePool, _WireWriter]:
        settings = config or Settings(variable_difficulty=False)
        pool = _FakePool(job, settings)
        writer = _WireWriter()
        session = Sv2Session(pool, None, writer, b"\x00\x00\x00\x01")
        return session, pool, writer

    async def test_setup_then_open_sends_first_job_in_required_order(self) -> None:
        job = self.make_job()
        session, pool, writer = self._session(job)

        await session._dispatch(_setup_message())
        await session._dispatch(_open_message())

        messages = writer.messages()
        self.assertEqual(
            [type(message) for message in messages],
            [
                sv2_messages.SetupConnectionSuccess,
                sv2_messages.OpenStandardMiningChannelSuccess,
                sv2_messages.NewMiningJob,
                sv2_messages.SetNewPrevHash,
            ],
        )
        open_success = messages[1]
        new_job = messages[2]
        new_prev_hash = messages[3]
        self.assertIsInstance(open_success, sv2_messages.OpenStandardMiningChannelSuccess)
        self.assertIsInstance(new_job, sv2_messages.NewMiningJob)
        self.assertIsInstance(new_prev_hash, sv2_messages.SetNewPrevHash)
        self.assertIsNone(new_job.min_ntime)
        self.assertEqual(new_job.job_id, new_prev_hash.job_id)
        self.assertEqual(new_prev_hash.prev_hash, job.prevhash_internal)
        self.assertTrue(session.authorized)
        self.assertEqual(pool.attached_workers, [("bcrt1qexampleworkeraddress", "rig")])

        await session._dispatch(_open_message(request_id=8))
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.OpenMiningChannelError(
                request_id=8,
                error_code="channel-limit-reached",
            ),
        )
        self.assertEqual(session.protocol_errors, 0)

    async def test_open_without_current_work_is_rejected(self) -> None:
        session, pool, writer = self._session(None)

        await session._dispatch(_setup_message())
        await session._dispatch(_open_message())

        messages = writer.messages()
        self.assertIsInstance(messages[0], sv2_messages.SetupConnectionSuccess)
        self.assertEqual(
            messages[1],
            sv2_messages.OpenMiningChannelError(
                request_id=7,
                error_code="work-not-ready",
            ),
        )
        self.assertFalse(session.authorized)
        self.assertEqual(pool.attached_workers, [])

    async def test_extended_open_sends_immutable_coinbase_work_in_order(self) -> None:
        job = self.make_job()
        session, pool, writer = self._session(job)

        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message())

        messages = writer.messages()
        self.assertEqual(
            [type(message) for message in messages],
            [
                sv2_messages.SetupConnectionSuccess,
                sv2_messages.OpenExtendedMiningChannelSuccess,
                sv2_messages.NewExtendedMiningJob,
                sv2_messages.SetNewPrevHash,
            ],
        )
        success = messages[1]
        new_job = messages[2]
        self.assertIsInstance(success, sv2_messages.OpenExtendedMiningChannelSuccess)
        self.assertIsInstance(new_job, sv2_messages.NewExtendedMiningJob)
        self.assertEqual(success.channel_id, FIRST_CHANNEL_ID)
        self.assertEqual(success.extranonce_prefix, b"\x00\x00\x00\x01\x00\x01")
        self.assertEqual(
            success.extranonce_size,
            pool.config.extranonce2_size - SV2_CHANNEL_DISCRIMINATOR_BYTES,
        )
        self.assertEqual(new_job.coinbase_tx_prefix, job.coinbase1)
        self.assertEqual(new_job.coinbase_tx_suffix, job.build_coinbase2(P2WPKH_SPK))
        self.assertEqual(new_job.merkle_path, tuple(job.merkle_branch))
        self.assertTrue(new_job.version_rolling_allowed)
        self.assertEqual(_only_channel(session).job_refresh_interval, 0)
        self.assertEqual(
            pool.attached_workers,
            [("bcrt1qexampleworkeraddress", "proxy")],
        )

    async def test_extended_open_respects_setup_and_extranonce_constraints(self) -> None:
        session, _pool, writer = self._session(self.make_job())
        await session._dispatch(_setup_message())
        await session._dispatch(_open_extended_message())

        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.OpenMiningChannelError(
                request_id=9,
                error_code="requires-standard-jobs",
            ),
        )
        self.assertFalse(session.authorized)

        session, pool, writer = self._session(self.make_job())
        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message(
            min_extranonce_size=pool.config.extranonce2_size + 1))

        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.OpenMiningChannelError(
                request_id=9,
                error_code="insufficient-extranonce-size",
            ),
        )
        self.assertFalse(session.authorized)

    async def test_pre_open_broadcast_does_not_consume_publication_order(self) -> None:
        first_job = self.make_job()
        next_job = self.make_job(job_id="2")
        next_job.publication_sequence = 2
        session, pool, writer = self._session(first_job)

        await session._dispatch(_setup_message())
        await session.send_notify(next_job, clean=True)

        self.assertEqual(session._next_channel_id, 1)
        self.assertEqual(len(writer.messages()), 1)
        pool.current_job = next_job
        await session._dispatch(_open_message())
        self.assertEqual(_only_channel(session).last_publication_sequence, 2)

    async def test_sv1_line_limit_above_u24_is_clamped_for_sv2_frames(self) -> None:
        config = Settings(max_line_bytes=sv2_codec.MAX_WIRE_PAYLOAD_SIZE + 1)
        session, _pool, _writer = self._session(self.make_job(), config)

        self.assertEqual(
            session._maximum_payload_size, sv2_codec.MAX_WIRE_PAYLOAD_SIZE)

    async def test_configured_frame_limit_applies_only_to_inbound_messages(self) -> None:
        config = Settings(max_line_bytes=1)
        session, _pool, writer = self._session(self.make_job(), config)

        await session._dispatch(_setup_message())

        self.assertIsInstance(writer.messages()[0], sv2_messages.SetupConnectionSuccess)

    async def test_nominal_hashrate_calibrates_the_initial_vardiff_target(self) -> None:
        nominal_hash_rate = 200_000_000_000_000.0
        config = Settings(
            initial_difficulty=1,
            minimum_difficulty=0.001,
            variable_difficulty=True,
            vardiff_target_shares_per_minute=12,
        )
        session, _pool, writer = self._session(self.make_job(), config)

        await session._dispatch(_setup_message())
        await session._dispatch(_open_message(nominal_hash_rate=nominal_hash_rate))

        expected_difficulty = (
            nominal_hash_rate * 60
            / (constants.NONCES * config.vardiff_target_shares_per_minute)
        )
        expected_target = util.difficulty_to_target(expected_difficulty)
        open_success = writer.messages()[1]
        self.assertIsInstance(open_success, sv2_messages.OpenStandardMiningChannelSuccess)
        self.assertEqual(int.from_bytes(open_success.target, "little"), expected_target)

    async def test_tiny_configured_difficulty_opens_with_a_bounded_target(self) -> None:
        config = Settings(
            initial_difficulty=1e-12,
            minimum_difficulty=1e-12,
            variable_difficulty=False,
        )
        session, _pool, writer = self._session(self.make_job(), config)

        await session._dispatch(_setup_message())
        await session._dispatch(_open_message())

        open_success = writer.messages()[1]
        self.assertIsInstance(open_success, sv2_messages.OpenStandardMiningChannelSuccess)
        self.assertEqual(open_success.target, b"\xff" * 32)

    async def test_high_hashrate_channel_receives_fresh_standard_work(self) -> None:
        session, _pool, writer = self._session(
            self.make_job(), Settings(variable_difficulty=False))

        await session._dispatch(_setup_message())
        await session._dispatch(_open_message(
            nominal_hash_rate=2 * session._standard_job_hashes()))
        initial_root = writer.messages()[2].merkle_root
        _only_channel(session).next_job_refresh = 0

        self.assertTrue(await session.maybe_refresh_job())

        messages = writer.messages()
        self.assertIsInstance(messages[-2], sv2_messages.SetExtranoncePrefix)
        self.assertIsInstance(messages[-1], sv2_messages.NewMiningJob)
        self.assertIsNotNone(messages[-1].min_ntime)
        self.assertNotEqual(messages[-1].merkle_root, initial_root)

    async def test_update_enabling_rapid_refresh_replaces_work_immediately(self) -> None:
        session, _pool, writer = self._session(
            self.make_job(), Settings(variable_difficulty=False))

        await session._dispatch(_setup_message())
        await session._dispatch(_open_message())
        initial_root = writer.messages()[2].merkle_root

        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=FIRST_CHANNEL_ID,
            nominal_hash_rate=2 * session._standard_job_hashes(),
            maximum_target=((1 << 256) - 1).to_bytes(32, "little"),
        ))

        messages = writer.messages()
        self.assertIsInstance(messages[-2], sv2_messages.SetExtranoncePrefix)
        self.assertIsInstance(messages[-1], sv2_messages.NewMiningJob)
        self.assertNotEqual(messages[-1].merkle_root, initial_root)

        sent_count = len(messages)
        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=FIRST_CHANNEL_ID,
            nominal_hash_rate=2 * session._standard_job_hashes(),
            maximum_target=((1 << 256) - 1).to_bytes(32, "little"),
        ))
        self.assertEqual(len(writer.messages()), sent_count)

    async def test_extended_hash_space_does_not_need_standard_job_refreshes(self) -> None:
        session, _pool, writer = self._session(
            self.make_job(), Settings(variable_difficulty=False))

        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message(
            nominal_hash_rate=2 * session._standard_job_hashes()))
        sent_count = len(writer.messages())
        _only_channel(session).next_job_refresh = 0

        self.assertFalse(await session.maybe_refresh_job())
        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=FIRST_CHANNEL_ID,
            nominal_hash_rate=4 * session._standard_job_hashes(),
            maximum_target=((1 << 256) - 1).to_bytes(32, "little"),
        ))

        self.assertEqual(_only_channel(session).job_refresh_interval, 0)
        self.assertEqual(len(writer.messages()), sent_count)

    async def test_extended_hashrate_cannot_outrun_one_extranonce_space_per_second(
            self) -> None:
        session, _pool, writer = self._session(
            self.make_job(extranonce2_size=3),
            Settings(extranonce2_size=3, variable_difficulty=False),
        )

        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message(
            nominal_hash_rate=2 * session._extended_job_hashes(),
            min_extranonce_size=1,
        ))

        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.OpenMiningChannelError(
                request_id=9,
                error_code="invalid-nominal-hash-rate",
            ),
        )
        self.assertFalse(session.authorized)


class TestSv2ExtendedMultiChannel(AsyncSoloPoolTestCase):
    def _session(self, job: work.Job) -> tuple[Sv2Session, _FakePool, _WireWriter]:
        pool = _FakePool(job, Settings(initial_difficulty=1, variable_difficulty=False))
        writer = _WireWriter()
        return Sv2Session(pool, None, writer, b"\x00\x00\x00\x01"), pool, writer

    async def _open_two(
            self,
            session: Sv2Session,
            writer: _WireWriter,
            *,
            second_hash_rate: float = 1_000_000.0,
            ) -> tuple[int, int]:
        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message(
            request_id=10,
            user_identity="bcrt1qaddressa.worker-a",
            nominal_hash_rate=0,
        ))
        await session._dispatch(_open_extended_message(
            request_id=11,
            user_identity="bcrt1qaddressb.worker-b",
            nominal_hash_rate=second_hash_rate,
        ))
        successes = [
            message
            for message in writer.messages()
            if isinstance(message, sv2_messages.OpenExtendedMiningChannelSuccess)
        ]
        self.assertEqual(len(successes), 2)
        return successes[0].channel_id, successes[1].channel_id

    async def test_open_two_allocates_unique_channels_and_routes_initial_jobs(self) -> None:
        session, pool, writer = self._session(self.make_job())

        first_id, second_id = await self._open_two(session, writer)

        self.assertEqual((first_id, second_id), (1, 2))
        self.assertEqual(session.channel_count, 2)
        self.assertTrue(session.authorized)
        self.assertEqual(
            session.connected_workers(),
            (
                ("bcrt1qaddressa", "worker-a"),
                ("bcrt1qaddressb", "worker-b"),
            ),
        )
        self.assertEqual(
            pool.attached_workers,
            [
                ("bcrt1qaddressa", "worker-a"),
                ("bcrt1qaddressb", "worker-b"),
            ],
        )
        success_messages = [
            message
            for message in writer.messages()
            if isinstance(message, sv2_messages.OpenExtendedMiningChannelSuccess)
        ]
        self.assertEqual(
            success_messages[0].extranonce_prefix,
            b"\x00\x00\x00\x01\x00\x01",
        )
        self.assertEqual(
            success_messages[1].extranonce_prefix,
            b"\x00\x00\x00\x01\x00\x02",
        )
        self.assertEqual(
            {message.channel_id
             for message in writer.messages()
             if isinstance(message, sv2_messages.NewExtendedMiningJob)},
            {first_id, second_id},
        )
        self.assertEqual(
            session._channels[first_id].difficulty,
            session._initial_difficulty,
        )
        now = time.monotonic()
        session.connected_at = now - 100
        session._channels[second_id].opened_at = now - 5
        second_stats = session.stats_for_address("bcrt1qaddressb")
        self.assertEqual(len(second_stats), 1)
        self.assertGreaterEqual(second_stats[0]["connected_for"], 4)
        self.assertLess(second_stats[0]["connected_for"], 10)

    async def test_update_and_share_affect_only_the_selected_worker(self) -> None:
        job = self.make_job()
        session, pool, writer = self._session(job)
        first_id, second_id = await self._open_two(session, writer)
        first = session._channels[first_id]
        second = session._channels[second_id]
        first_target = first.target
        harder_target = second.target // 2

        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=second_id,
            nominal_hash_rate=0,
            maximum_target=harder_target.to_bytes(32, "little"),
        ))

        self.assertEqual(first.target, first_target)
        self.assertEqual(second.target, harder_target)
        set_target = writer.messages()[-1]
        self.assertIsInstance(set_target, sv2_messages.SetTarget)
        self.assertEqual(set_target.channel_id, second_id)

        issued = max(second.jobs.values(), key=lambda value: value.job_id)
        self.assertIsInstance(issued, IssuedExtendedJob)
        accepted = work.ShareResult(
            valid=True,
            reason=None,
            difficulty=3.0,
            is_block=True,
            block_hash_hex="00" * 32,
            header=b"header",
            legacy_coinbase=b"coinbase",
        )
        with mock.patch.object(job, "validate_extended_share", return_value=accepted):
            await session._handle_submit(sv2_messages.SubmitSharesExtended(
                channel_id=second_id,
                sequence_number=1,
                job_id=issued.job_id,
                nonce=1,
                ntime=job.curtime,
                version=job.version,
                extranonce=b"\x00" * issued.extranonce_size,
            ))

        self.assertEqual(first.shares_accepted, 0)
        self.assertEqual(second.shares_accepted, 1)
        self.assertEqual(pool.accepted_shares[0][:2], ("bcrt1qaddressb", "worker-b"))
        self.assertEqual(pool.block_calls[0][3:], ("bcrt1qaddressb", "worker-b"))

    async def test_publish_close_and_reopen_route_by_live_channel(self) -> None:
        initial = self.make_job()
        session, pool, writer = self._session(initial)
        first_id, second_id = await self._open_two(session, writer)
        first_job_id = next(iter(session._channels[first_id].jobs))

        await session._dispatch(sv2_messages.CloseChannel(
            channel_id=first_id,
            reason_code="worker-stopped",
        ))

        self.assertNotIn(first_id, session._channels)
        self.assertIn(second_id, session._channels)
        self.assertTrue(session.authorized)
        self.assertFalse(session._close_after_response)
        self.assertTrue(session._ever_opened_channel)

        await session._handle_submit(sv2_messages.SubmitSharesExtended(
            channel_id=first_id,
            sequence_number=2,
            job_id=first_job_id,
            nonce=0,
            ntime=initial.curtime,
            version=initial.version,
            extranonce=b"\x00" * (
                pool.config.extranonce2_size - SV2_CHANNEL_DISCRIMINATOR_BYTES
            ),
        ))
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=first_id,
                sequence_number=2,
                error_code="invalid-channel",
            ),
        )
        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=first_id,
            nominal_hash_rate=0,
            maximum_target=b"\xff" * 32,
        ))
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.UpdateChannelError(
                channel_id=first_id,
                error_code="invalid-channel",
            ),
        )

        next_job = self.make_job(job_id="2")
        next_job.publication_sequence = 2
        pool.current_job = next_job
        writer.sent.clear()
        await session.send_notify(next_job, clean=False)
        routed = [
            message.channel_id
            for message in writer.messages()
            if isinstance(message, sv2_messages.NewExtendedMiningJob)
        ]
        self.assertEqual(routed, [second_id])

        await session._dispatch(_open_extended_message(
            request_id=12,
            user_identity="bcrt1qaddressc.worker-c",
        ))
        success = next(
            message
            for message in reversed(writer.messages())
            if isinstance(message, sv2_messages.OpenExtendedMiningChannelSuccess)
        )
        self.assertEqual(success.channel_id, 3)

    async def test_group_close_releases_all_channels_without_closing_connection(self) -> None:
        session, _pool, writer = self._session(self.make_job())
        first_id, second_id = await self._open_two(session, writer)

        await session._dispatch(sv2_messages.CloseChannel(
            channel_id=SV2_GROUP_CHANNEL_ID,
            reason_code="proxy-stopped",
        ))

        self.assertNotIn(first_id, session._channels)
        self.assertNotIn(second_id, session._channels)
        self.assertEqual(session.channel_count, 0)
        self.assertFalse(session.authorized)
        self.assertFalse(session._close_after_response)

        await session._dispatch(_open_extended_message(
            request_id=12,
            user_identity="bcrt1qaddressc.worker-c",
        ))
        reopened = next(
            message
            for message in reversed(writer.messages())
            if isinstance(message, sv2_messages.OpenExtendedMiningChannelSuccess)
        )
        self.assertEqual(reopened.channel_id, 3)

    async def test_opening_second_channel_keeps_first_channel_duplicate_history(self) -> None:
        job = self.make_job()
        session, _pool, writer = self._session(job)
        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message(
            request_id=10,
            user_identity="bcrt1qaddressa.worker-a",
        ))
        first_id = next(iter(session._channels))
        issued = next(iter(session._channels[first_id].jobs.values()))
        self.assertIsInstance(issued, IssuedExtendedJob)
        submit = sv2_messages.SubmitSharesExtended(
            channel_id=first_id,
            sequence_number=1,
            job_id=issued.job_id,
            nonce=1,
            ntime=job.curtime,
            version=job.version,
            extranonce=b"\x00" * issued.extranonce_size,
        )
        accepted = work.ShareResult(
            valid=True,
            reason=None,
            difficulty=3.0,
            is_block=False,
            block_hash_hex="00" * 32,
            header=b"header",
            legacy_coinbase=b"coinbase",
        )

        with mock.patch.object(
                job, "validate_extended_share", return_value=accepted) as validate:
            await session._handle_submit(submit)
            await session._dispatch(_open_extended_message(
                request_id=11,
                user_identity="bcrt1qaddressb.worker-b",
            ))
            await session._handle_submit(submit)

        self.assertEqual(validate.call_count, 1)
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=first_id,
                sequence_number=1,
                error_code="duplicate-share",
            ),
        )

    async def test_channel_type_can_change_after_last_channel_closes(self) -> None:
        session, _pool, writer = self._session(self.make_job())
        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message(request_id=10))
        first_id = next(iter(session._channels))
        await session._dispatch(sv2_messages.CloseChannel(
            channel_id=first_id,
            reason_code="switching",
        ))

        await session._dispatch(_open_message(request_id=11))

        success = next(
            message
            for message in reversed(writer.messages())
            if isinstance(message, sv2_messages.OpenStandardMiningChannelSuccess)
        )
        self.assertEqual(success.channel_id, 2)
        self.assertEqual(
            [channel.channel_type for channel in session._channels.values()],
            ["standard"],
        )

    async def test_new_session_restarts_channel_ids(self) -> None:
        first, _first_pool, first_writer = self._session(self.make_job())
        second, _second_pool, second_writer = self._session(self.make_job())

        first_id, _ = await self._open_two(first, first_writer)
        second_id, _ = await self._open_two(second, second_writer)

        self.assertEqual(first_id, 1)
        self.assertEqual(second_id, 1)


class TestSv2IssuedWork(AsyncSoloPoolTestCase):
    async def _open_session(
            self, job: work.Job, config: Settings
            ) -> tuple[Sv2Session, _FakePool, _WireWriter]:
        pool = _FakePool(job, config)
        writer = _WireWriter()
        session = Sv2Session(pool, None, writer, b"\x00\x00\x00\x01")
        await session._dispatch(_setup_message())
        await session._dispatch(_open_message())
        return session, pool, writer

    async def _open_extended_session(
            self, job: work.Job, config: Settings
            ) -> tuple[Sv2Session, _FakePool, _WireWriter]:
        pool = _FakePool(job, config)
        writer = _WireWriter()
        session = Sv2Session(pool, None, writer, b"\x00\x00\x00\x01")
        await session._dispatch(_setup_message(flags=0))
        await session._dispatch(_open_extended_message())
        return session, pool, writer

    async def test_retarget_updates_future_jobs_but_keeps_active_job_target(self) -> None:
        config = Settings(
            initial_difficulty=1,
            minimum_difficulty=1,
            variable_difficulty=True,
            vardiff_target_shares_per_minute=12,
            vardiff_retarget_seconds=60,
        )
        job = self.make_job()
        session, pool, _writer = await self._open_session(job, config)
        channel = _only_channel(session)
        future_job_id = next(iter(channel.jobs))
        old_target = channel.jobs[future_job_id].target

        await session.send_notify(job, clean=False)
        active_job_id = max(channel.jobs)
        self.assertFalse(channel.jobs[active_job_id].follows_channel_target)

        channel.last_retarget = time.monotonic() - 120
        channel.shares_since_retarget = 100
        await session.maybe_retarget()

        self.assertEqual(max(channel.jobs), active_job_id)
        self.assertEqual(channel.jobs[future_job_id].target, channel.target)
        self.assertEqual(channel.jobs[active_job_id].target, old_target)
        self.assertLess(channel.target, old_target)

        accepted = work.ShareResult(
            valid=True,
            reason=None,
            difficulty=3.0,
            is_block=False,
            block_hash_hex="00" * 32,
            header=b"header",
            legacy_coinbase=channel.jobs[active_job_id].legacy_coinbase,
        )
        with mock.patch.object(
                job, "validate_standard_share", return_value=accepted) as validate:
            await session._handle_submit(sv2_messages.SubmitSharesStandard(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=1,
                job_id=active_job_id,
                nonce=1,
                ntime=job.curtime,
                version=job.version,
            ))

        self.assertEqual(validate.call_args.kwargs["share_target"], old_target)
        self.assertEqual(pool.accepted_shares[0][2], util.target_to_difficulty(old_target))

    async def test_update_channel_applies_target_and_standard_channel_can_reopen(
            self) -> None:
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        session, _pool, writer = await self._open_session(job, config)
        channel = _only_channel(session)
        old_target = channel.target
        harder_target = util.difficulty_to_target(
            util.target_to_difficulty(old_target) * 2)

        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=FIRST_CHANNEL_ID,
            nominal_hash_rate=2_000_000.0,
            maximum_target=harder_target.to_bytes(32, "little"),
        ))

        self.assertEqual(channel.target, harder_target)
        self.assertIsInstance(writer.messages()[-1], sv2_messages.SetTarget)

        await session._dispatch(sv2_messages.CloseChannel(
            channel_id=FIRST_CHANNEL_ID,
            reason_code="done",
        ))
        self.assertFalse(session._close_after_response)
        self.assertFalse(session.authorized)

        await session._dispatch(_open_message(request_id=8))

        reopened = next(
            message
            for message in reversed(writer.messages())
            if isinstance(message, sv2_messages.OpenStandardMiningChannelSuccess)
        )
        self.assertEqual(reopened.channel_id, 2)
        self.assertTrue(session.authorized)

    async def test_target_change_does_not_duplicate_a_pending_publication(self) -> None:
        job = self.make_job()
        session, pool, writer = await self._open_session(
            job, Settings(initial_difficulty=1, variable_difficulty=False))
        next_job = self.make_job(job_id="2")
        next_job.publication_sequence = 2
        pool.current_job = next_job
        channel = _only_channel(session)
        harder_target = channel.target // 2
        writer.sent.clear()

        await session._dispatch(sv2_messages.UpdateChannel(
            channel_id=FIRST_CHANNEL_ID,
            nominal_hash_rate=1_000_000.0,
            maximum_target=harder_target.to_bytes(32, "little"),
        ))
        await session.send_notify(next_job, clean=True)

        messages = writer.messages()
        self.assertEqual(
            sum(isinstance(message, sv2_messages.NewMiningJob)
                for message in messages),
            1,
        )
        self.assertIsInstance(messages[0], sv2_messages.SetTarget)
        self.assertEqual(channel.last_publication_sequence, 2)

    async def test_new_prevhash_makes_old_jobs_stale(self) -> None:
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        first_job = self.make_job()
        session, _pool, writer = await self._open_session(first_job, config)
        channel = _only_channel(session)
        old_job_id = next(iter(channel.jobs))

        next_template = self.make_template(height=first_job.height + 1)
        next_template["previousblockhash"] = f"{0x1234:064x}"
        next_job = self.make_job(next_template, job_id="2")
        await session.send_notify(next_job, clean=True)

        self.assertNotIn(old_job_id, channel.jobs)
        await session._handle_submit(sv2_messages.SubmitSharesStandard(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=2,
            job_id=old_job_id,
            nonce=0,
            ntime=first_job.curtime,
            version=first_job.version,
        ))

        response = writer.messages()[-1]
        self.assertEqual(
            response,
            sv2_messages.SubmitSharesError(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=2,
                error_code="stale-share",
            ),
        )

    async def test_new_bits_on_same_prevhash_replaces_the_prevhash_context(self) -> None:
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        first_job = self.make_job()
        session, pool, writer = await self._open_session(first_job, config)
        channel = _only_channel(session)
        old_job_id = next(iter(channel.jobs))

        next_template = self.make_template(height=first_job.height)
        next_template["previousblockhash"] = first_job.prevhash_internal[::-1].hex()
        next_template["bits"] = "1d00fffe"
        next_job = self.make_job(next_template, job_id="2")
        pool.current_job = next_job
        await session.send_notify(next_job, clean=False)

        messages = writer.messages()
        self.assertIsInstance(messages[-2], sv2_messages.NewMiningJob)
        self.assertIsNone(messages[-2].min_ntime)
        self.assertEqual(
            messages[-1],
            sv2_messages.SetNewPrevHash(
                channel_id=FIRST_CHANNEL_ID,
                job_id=messages[-2].job_id,
                prev_hash=next_job.prevhash_internal,
                min_ntime=next_job.curtime,
                nbits=next_job.bits,
            ),
        )
        self.assertNotIn(old_job_id, channel.jobs)

    async def test_valid_standard_share_reaches_block_handoff(self) -> None:
        config = Settings(initial_difficulty=2.5, variable_difficulty=False)
        job = self.make_job()
        session, pool, writer = await self._open_session(job, config)
        issued = next(iter(_only_channel(session).jobs.values()))

        winning_nonce = None
        for nonce in range(1_000):
            result = job.validate_standard_share(
                legacy_coinbase=issued.legacy_coinbase,
                merkle_root_bytes=issued.merkle_root,
                ntime=job.curtime,
                nonce=nonce,
                version=job.version,
                share_target=issued.target,
                version_mask=session._version_mask,
            )
            if result.valid and result.is_block:
                winning_nonce = nonce
                break
        self.assertIsNotNone(winning_nonce)

        await session._handle_submit(sv2_messages.SubmitSharesStandard(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=3,
            job_id=issued.job_id,
            nonce=winning_nonce,
            ntime=job.curtime,
            version=job.version,
        ))

        response = writer.messages()[-1]
        self.assertIsInstance(response, sv2_messages.SubmitSharesSuccess)
        self.assertEqual(response.last_sequence_number, 3)
        self.assertEqual(response.new_shares_sum, 3)
        self.assertEqual(len(pool.block_calls), 1)
        self.assertIs(pool.block_calls[0][1], job)
        self.assertEqual(pool.block_calls[0][2].legacy_coinbase, issued.legacy_coinbase)

        await session._handle_submit(sv2_messages.SubmitSharesStandard(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=4,
            job_id=issued.job_id,
            nonce=winning_nonce,
            ntime=job.curtime,
            version=job.version,
        ))

        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=4,
                error_code="duplicate-share",
            ),
        )
        self.assertEqual(len(pool.accepted_shares), 1)
        self.assertEqual(len(pool.rejected_shares), 1)
        self.assertEqual(len(pool.block_calls), 1)

    async def test_block_share_preceding_oversized_frame_is_not_dropped(self) -> None:
        config = Settings(initial_difficulty=2.5, variable_difficulty=False)
        job = self.make_job()
        session, pool, writer = await self._open_session(job, config)
        issued = next(iter(_only_channel(session).jobs.values()))

        winning_nonce = next(
            nonce
            for nonce in range(1_000)
            if job.validate_standard_share(
                legacy_coinbase=issued.legacy_coinbase,
                merkle_root_bytes=issued.merkle_root,
                ntime=job.curtime,
                nonce=nonce,
                version=job.version,
                share_target=issued.target,
                version_mask=session._version_mask,
            ).is_block
        )
        share = sv2_messages.SubmitSharesStandard(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=3,
            job_id=issued.job_id,
            nonce=winning_nonce,
            ntime=job.curtime,
            version=job.version,
        )
        ignored_extension = sv2_codec.encode_frame(
            sv2_codec.Frame(extension_type=1, message_type=0x7F, payload=b"")
        )
        valid_share = sv2_codec.encode_frame(sv2_messages.encode_message(share))
        oversized_header = (
            b"\x00\x00\x7f"
            + (session._maximum_payload_size + 1).to_bytes(3, "little")
        )
        session.reader = _WireReader(ignored_extension + valid_share + oversized_header)
        writer.sent.clear()

        await session.run()

        self.assertEqual(len(pool.block_calls), 1)
        self.assertIs(pool.block_calls[0][1], job)
        self.assertIsInstance(writer.messages()[0], sv2_messages.SubmitSharesSuccess)
        self.assertEqual(session.protocol_errors, 1)

    async def test_valid_extended_share_reaches_block_handoff(self) -> None:
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        session, pool, writer = await self._open_extended_session(job, config)
        issued = next(iter(_only_channel(session).jobs.values()))
        self.assertIsInstance(issued, IssuedExtendedJob)
        extranonce = b"\x2a" * issued.extranonce_size

        winning_nonce = None
        winning_result = None
        for nonce in range(1_000):
            result = job.validate_extended_share(
                issued_work=issued.extended_work,
                extranonce_prefix=issued.extranonce_prefix,
                extranonce=extranonce,
                extranonce_size=issued.extranonce_size,
                ntime=job.curtime,
                nonce=nonce,
                version=job.version,
                share_target=issued.target,
                version_mask=session._version_mask,
            )
            if result.valid and result.is_block:
                winning_nonce = nonce
                winning_result = result
                break
        self.assertIsNotNone(winning_nonce)
        self.assertIsNotNone(winning_result)

        await session._handle_submit(sv2_messages.SubmitSharesExtended(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=10,
            job_id=issued.job_id,
            nonce=winning_nonce,
            ntime=job.curtime,
            version=job.version,
            extranonce=extranonce,
        ))

        response = writer.messages()[-1]
        self.assertIsInstance(response, sv2_messages.SubmitSharesSuccess)
        self.assertEqual(response.last_sequence_number, 10)
        self.assertEqual(len(pool.block_calls), 1)
        self.assertEqual(
            pool.block_calls[0][2].legacy_coinbase,
            (
                issued.extended_work.coinbase_tx_prefix
                + issued.extranonce_prefix
                + extranonce
                + issued.extended_work.coinbase_tx_suffix
            ),
        )

    async def test_extended_submit_enforces_channel_and_extranonce_shape(self) -> None:
        job = self.make_job()
        session, pool, writer = await self._open_extended_session(
            job, Settings(variable_difficulty=False))
        issued = next(iter(_only_channel(session).jobs.values()))
        self.assertIsInstance(issued, IssuedExtendedJob)

        await session._handle_submit(sv2_messages.SubmitSharesExtended(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=11,
            job_id=issued.job_id,
            nonce=0,
            ntime=job.curtime,
            version=job.version,
            extranonce=b"\x00" * (issued.extranonce_size - 1),
        ))
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=11,
                error_code="invalid-extranonce-size",
            ),
        )

        await session._handle_submit(sv2_messages.SubmitSharesStandard(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=12,
            job_id=issued.job_id,
            nonce=0,
            ntime=job.curtime,
            version=job.version,
        ))
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=12,
                error_code="invalid-channel-type",
            ),
        )
        self.assertEqual(len(pool.accepted_shares), 0)
        self.assertEqual(len(pool.rejected_shares), 2)

    async def test_extended_duplicate_key_includes_extranonce(self) -> None:
        job = self.make_job()
        session, pool, writer = await self._open_extended_session(
            job, Settings(variable_difficulty=False))
        issued = next(iter(_only_channel(session).jobs.values()))
        self.assertIsInstance(issued, IssuedExtendedJob)
        accepted = work.ShareResult(
            valid=True,
            reason=None,
            difficulty=2.0,
            is_block=False,
            block_hash_hex="00" * 32,
            header=b"header",
            legacy_coinbase=b"coinbase",
        )
        first_extranonce = b"\x00" * issued.extranonce_size
        second_extranonce = b"\x01" * issued.extranonce_size

        with mock.patch.object(
                job, "validate_extended_share", return_value=accepted) as validate:
            for sequence_number, extranonce in (
                    (13, first_extranonce),
                    (14, second_extranonce),
                    (15, second_extranonce),
            ):
                await session._handle_submit(sv2_messages.SubmitSharesExtended(
                    channel_id=FIRST_CHANNEL_ID,
                    sequence_number=sequence_number,
                    job_id=issued.job_id,
                    nonce=7,
                    ntime=job.curtime,
                    version=job.version,
                    extranonce=extranonce,
                ))

        self.assertEqual(validate.call_count, 2)
        self.assertEqual(len(pool.accepted_shares), 2)
        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=15,
                error_code="duplicate-share",
            ),
        )

    async def test_extended_target_changes_do_not_reprice_active_work(self) -> None:
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        session, pool, _writer = await self._open_extended_session(job, config)
        channel = _only_channel(session)
        future_job_id = next(iter(channel.jobs))
        old_target = channel.jobs[future_job_id].target

        await session.send_notify(job, clean=False)
        active_job_id = max(channel.jobs)
        self.assertFalse(channel.jobs[active_job_id].follows_channel_target)
        harder_target = old_target // 2
        flight = session._change_target(channel, harder_target)

        self.assertEqual(len(flight), 1)
        self.assertIsInstance(flight[0], sv2_messages.SetTarget)
        self.assertEqual(channel.jobs[future_job_id].target, harder_target)
        self.assertEqual(channel.jobs[active_job_id].target, old_target)
        self.assertEqual(max(channel.jobs), active_job_id)

        accepted = work.ShareResult(
            valid=True,
            reason=None,
            difficulty=3.0,
            is_block=False,
            block_hash_hex="00" * 32,
            header=b"header",
            legacy_coinbase=b"coinbase",
        )
        issued = channel.jobs[active_job_id]
        self.assertIsInstance(issued, IssuedExtendedJob)
        with mock.patch.object(
                job, "validate_extended_share", return_value=accepted) as validate:
            await session._handle_submit(sv2_messages.SubmitSharesExtended(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=16,
                job_id=active_job_id,
                nonce=1,
                ntime=job.curtime,
                version=job.version,
                extranonce=b"\x00" * issued.extranonce_size,
            ))

        self.assertEqual(validate.call_args.kwargs["share_target"], old_target)
        self.assertEqual(pool.accepted_shares[0][2], util.target_to_difficulty(old_target))

    async def test_standard_rejects_ntime_ahead_of_latest_prevhash_window(self) -> None:
        job = self.make_job()
        session, _pool, writer = await self._open_session(
            job, Settings(variable_difficulty=False))
        previous_hash = next(
            message for message in writer.messages()
            if isinstance(message, sv2_messages.SetNewPrevHash)
        )

        await session._handle_submit(sv2_messages.SubmitSharesStandard(
            channel_id=FIRST_CHANNEL_ID,
            sequence_number=20,
            job_id=previous_hash.job_id,
            nonce=20,
            ntime=previous_hash.min_ntime + 60,
            version=job.version,
        ))

        self.assertEqual(
            writer.messages()[-1],
            sv2_messages.SubmitSharesError(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=20,
                error_code="invalid-ntime",
            ),
        )

    async def test_extended_rejects_ntime_outside_latest_prevhash_window(self) -> None:
        initial = self.make_job()
        session, pool, writer = await self._open_extended_session(
            initial, Settings(variable_difficulty=False))

        async def publish_and_submit(curtime: int, sequence_number: int) -> None:
            template = self.make_template(height=initial.height)
            template["previousblockhash"] = initial.prevhash_internal[::-1].hex()
            template["bits"] = f"{initial.bits:08x}"
            template["curtime"] = curtime
            candidate = self.make_job(template, job_id=str(sequence_number))
            pool.current_job = candidate
            await session.send_notify(candidate, clean=False)
            issued = max(
                _only_channel(session).jobs.values(), key=lambda value: value.job_id)
            self.assertIsInstance(issued, IssuedExtendedJob)
            await session._handle_submit(sv2_messages.SubmitSharesExtended(
                channel_id=FIRST_CHANNEL_ID,
                sequence_number=sequence_number,
                job_id=issued.job_id,
                nonce=sequence_number,
                ntime=curtime,
                version=candidate.version,
                extranonce=b"\x00" * issued.extranonce_size,
            ))
            self.assertEqual(
                writer.messages()[-1],
                sv2_messages.SubmitSharesError(
                    channel_id=FIRST_CHANNEL_ID,
                    sequence_number=sequence_number,
                    error_code="invalid-ntime",
                ),
            )

        await publish_and_submit(initial.curtime - 1, 21)
        await publish_and_submit(initial.curtime + 10, 22)

    async def test_extended_same_parent_bits_change_replaces_prevhash_context(self) -> None:
        first_job = self.make_job()
        session, pool, writer = await self._open_extended_session(
            first_job, Settings(variable_difficulty=False))
        channel = _only_channel(session)
        old_job_id = next(iter(channel.jobs))

        next_template = self.make_template(height=first_job.height)
        next_template["previousblockhash"] = first_job.prevhash_internal[::-1].hex()
        next_template["bits"] = "1d00fffe"
        next_job = self.make_job(next_template, job_id="2")
        pool.current_job = next_job
        await session.send_notify(next_job, clean=False)

        messages = writer.messages()
        self.assertIsInstance(messages[-2], sv2_messages.NewExtendedMiningJob)
        self.assertIsNone(messages[-2].min_ntime)
        self.assertEqual(
            messages[-1],
            sv2_messages.SetNewPrevHash(
                channel_id=FIRST_CHANNEL_ID,
                job_id=messages[-2].job_id,
                prev_hash=next_job.prevhash_internal,
                min_ntime=next_job.curtime,
                nbits=next_job.bits,
            ),
        )
        self.assertNotIn(old_job_id, channel.jobs)
