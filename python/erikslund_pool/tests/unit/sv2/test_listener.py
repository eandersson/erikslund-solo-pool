"""Black-box plaintext and authenticated SV2 listener smoke tests."""

import asyncio
import contextlib
import dataclasses
import pathlib
import tempfile
from unittest.mock import Mock
from unittest.mock import patch

from erikslund_pool.config import Settings
from erikslund_pool.pool import Pool
from erikslund_pool.sv2 import codec as sv2_codec
from erikslund_pool.sv2 import messages as sv2_messages
from erikslund_pool.sv2 import noise as sv2_noise
from erikslund_pool.sv2 import noise_stream as sv2_noise_stream
from erikslund_pool.sv2.session import SV2_CHANNEL_DISCRIMINATOR_BYTES
from erikslund_pool.tests.base import P2WPKH_SPK
from erikslund_pool.tests.base import AsyncSoloPoolTestCase


class _PassThroughNoiseStream:
    def __init__(self, reader, writer):
        self._reader = reader
        self._writer = writer

    @classmethod
    async def accept(cls, reader, writer, credentials, **_kwargs):
        if credentials is None:
            raise AssertionError("secure listener did not pass responder credentials")
        return cls(reader, writer)

    async def read(self, size=-1):
        return await self._reader.read(size)

    def write(self, data):
        self._writer.write(data)

    async def drain(self):
        await self._writer.drain()

    def close(self):
        self._writer.close()

    async def wait_closed(self):
        await self._writer.wait_closed()

    def get_extra_info(self, name, default=None):
        if name == "sv2_noise":
            return True
        return self._writer.get_extra_info(name, default)

    def is_closing(self):
        return self._writer.is_closing()


class _TrackingWriter:
    def __init__(self) -> None:
        self.closed = False
        self.wait_closed_count = 0

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.wait_closed_count += 1

    def get_extra_info(self, name, default=None):
        if name == "peername":
            return ("127.0.0.1", 3336)
        return default


class TestSv2Listener(AsyncSoloPoolTestCase):
    async def test_setup_open_and_close_over_loopback(self) -> None:
        await self._run_channel_smoke(extended=False)

    async def test_extended_setup_open_and_close_over_loopback(self) -> None:
        await self._run_channel_smoke(extended=True)

    async def test_secure_listener_wraps_before_protocol_dispatch(self) -> None:
        await self._run_channel_smoke(extended=True, secure=True)

    async def test_invalid_credentials_skip_only_authenticated_sv2(self) -> None:
        expiry_timestamp = 1_900_000_000
        native_error = sv2_noise.NoiseNativeError(
            "load responder credentials",
            sv2_noise.STATUS_CERTIFICATE_EXPIRED,
            "certificate expired",
        )
        bound_listener_count = 0
        start_server = asyncio.start_server

        async def track_start_server(*args, **kwargs):
            nonlocal bound_listener_count
            server = await start_server(*args, **kwargs)
            bound_listener_count += 1
            return server

        def reject_credentials(*_args, **_kwargs):
            self.assertEqual(bound_listener_count, 1)
            raise native_error

        servers = []
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = pathlib.Path(temp_dir)
            static_path = directory / "static.key"
            authority_path = directory / "authority.pub"
            certificate_path = directory / "server.cert"
            static_path.write_bytes(b"s" * sv2_noise.SECRET_KEY_SIZE)
            authority_path.write_bytes(b"a" * sv2_noise.PUBLIC_KEY_SIZE)
            certificate_path.write_bytes(
                sv2_noise.CERTIFICATE_FORMAT_VERSION.to_bytes(2, "little")
                + (1_800_000_000).to_bytes(4, "little")
                + expiry_timestamp.to_bytes(4, "little")
                + b"s" * 64
            )
            pool = Pool(
                Settings(
                    bind_host="127.0.0.1",
                    bind_port=0,
                    sv2_host="127.0.0.1",
                    sv2_ports=[0],
                    sv2_plaintext_host="127.0.0.1",
                    sv2_plaintext_ports=[0],
                    sv2_static_secret_key_file=str(static_path),
                    sv2_authority_public_key_file=str(authority_path),
                    sv2_certificate_file=str(certificate_path),
                )
            )
            backend = Mock()
            backend.load_credentials.side_effect = reject_credentials
            try:
                with (
                    patch("erikslund_pool.pool.asyncio.start_server", track_start_server),
                    patch(
                        "erikslund_pool.pool.sv2_noise.NativeNoiseBackend",
                        return_value=backend,
                    ),
                    patch("erikslund_pool.pool.LOG.warning") as warning,
                ):
                    servers = await pool._start_servers(
                        reuse_port=False,
                        report_startup=False,
                    )

                self.assertEqual(len(servers), 2)
                self.assertFalse(pool.status()["sv2_authenticated_ready"])
                self.assertEqual(
                    pool.status()["sv2_certificate_expiry_timestamp"],
                    expiry_timestamp,
                )
                self.assertEqual(
                    native_error.certificate_expiry_timestamp,
                    expiry_timestamp,
                )
                warning.assert_called_once()
                self.assertIn("certificate expired", str(warning.call_args))

                sv1_port = servers[0].sockets[0].getsockname()[1]
                _reader, writer = await asyncio.open_connection("127.0.0.1", sv1_port)
                writer.close()
                await writer.wait_closed()
            finally:
                for server in servers:
                    server.close()
                    await server.wait_closed()
                pool._validate_executor.shutdown(wait=False)

    async def test_authenticated_sv2_bind_failure_leaves_sv1_serving(self) -> None:
        occupied = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "127.0.0.1",
            0,
        )
        occupied_port = occupied.sockets[0].getsockname()[1]
        pool = Pool(
            Settings(
                bind_host="127.0.0.1",
                bind_port=0,
                sv2_host="127.0.0.1",
                sv2_ports=[0, occupied_port],
            )
        )
        credentials = Mock()
        pool._sv2_noise_credentials = credentials
        created_servers = []
        start_server = asyncio.start_server

        async def track_start_server(*args, **kwargs):
            server = await start_server(*args, **kwargs)
            created_servers.append(server)
            return server

        servers = []
        try:
            with (
                patch("erikslund_pool.pool.asyncio.start_server", track_start_server),
                patch("erikslund_pool.pool.LOG.warning") as warning,
            ):
                servers = await pool._start_servers(
                    reuse_port=False,
                    report_startup=True,
                )

            self.assertEqual(len(servers), 1)
            self.assertEqual(len(created_servers), 2)
            self.assertFalse(created_servers[1].is_serving())
            self.assertFalse(pool.status()["sv2_authenticated_ready"])
            self.assertIsNone(pool._sv2_noise_credentials)
            credentials.close.assert_called_once_with()
            warning.assert_called_once()

            sv1_port = servers[0].sockets[0].getsockname()[1]
            _reader, writer = await asyncio.open_connection("127.0.0.1", sv1_port)
            writer.close()
            await writer.wait_closed()
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()
            occupied.close()
            await occupied.wait_closed()
            pool._validate_executor.shutdown(wait=False)

    async def test_plaintext_sv2_bind_failure_leaves_sv1_serving(self) -> None:
        occupied = await asyncio.start_server(
            lambda _reader, writer: writer.close(),
            "127.0.0.1",
            0,
        )
        occupied_port = occupied.sockets[0].getsockname()[1]
        pool = Pool(
            Settings(
                bind_host="127.0.0.1",
                bind_port=0,
                sv2_plaintext_host="127.0.0.1",
                sv2_plaintext_ports=[0, occupied_port],
            )
        )
        created_servers = []
        start_server = asyncio.start_server

        async def track_start_server(*args, **kwargs):
            server = await start_server(*args, **kwargs)
            created_servers.append(server)
            return server

        servers = []
        try:
            with (
                patch("erikslund_pool.pool.asyncio.start_server", track_start_server),
                patch("erikslund_pool.pool.LOG.warning") as warning,
            ):
                servers = await pool._start_servers(
                    reuse_port=False,
                    report_startup=True,
                )

            self.assertEqual(len(servers), 1)
            self.assertEqual(len(created_servers), 2)
            self.assertFalse(created_servers[1].is_serving())
            self.assertIsNone(pool.status()["sv2_authenticated_ready"])
            warning.assert_called_once()

            sv1_port = servers[0].sockets[0].getsockname()[1]
            _reader, writer = await asyncio.open_connection("127.0.0.1", sv1_port)
            writer.close()
            await writer.wait_closed()
        finally:
            for server in servers:
                server.close()
                await server.wait_closed()
            occupied.close()
            await occupied.wait_closed()
            pool._validate_executor.shutdown(wait=False)

    def test_sv2_readiness_expires_after_inclusive_certificate_deadline(self) -> None:
        pool = Pool(Settings(sv2_ports=[3334]))
        pool._authenticated_sv2_ready = True
        pool._sv2_certificate_expiry_timestamp = 100

        with patch("erikslund_pool.pool.time.time", return_value=100):
            self.assertTrue(pool.status()["sv2_authenticated_ready"])
        with patch("erikslund_pool.pool.time.time", return_value=101):
            self.assertFalse(pool.status()["sv2_authenticated_ready"])

        pool._validate_executor.shutdown(wait=False)

    def test_loaded_certificate_expiry_is_exported_and_logged(self) -> None:
        expiry_timestamp = 1_900_000_000
        pool = Pool(
            Settings(
                sv2_ports=[3334],
                sv2_static_secret_key_file="static.key",
                sv2_authority_public_key_file="authority.pub",
                sv2_certificate_file="server.cert",
            )
        )
        credentials = Mock(certificate_expiry_timestamp=expiry_timestamp)
        with (
            patch("erikslund_pool.pool.sv2_noise.NativeNoiseBackend"),
            patch(
                "erikslund_pool.pool.sv2_noise.NoiseCredentials.from_files",
                return_value=credentials,
            ),
            patch("erikslund_pool.pool.LOG.info") as info,
        ):
            pool._load_sv2_noise_credentials()

        self.assertEqual(
            pool.status()["sv2_certificate_expiry_timestamp"],
            expiry_timestamp,
        )
        info.assert_called_once_with(
            "SV2 Noise certificate expires at Unix timestamp %d",
            expiry_timestamp,
        )
        credentials.close()
        pool._validate_executor.shutdown(wait=False)

    async def test_cancelled_noise_handshake_releases_admission_and_closes_socket(self) -> None:
        pool = Pool(Settings(max_clients=4))
        writer = _TrackingWriter()
        handshake_started = asyncio.Event()

        async def blocked_accept(*_args, **_kwargs):
            handshake_started.set()
            await asyncio.Future()

        with patch.object(sv2_noise_stream.NoiseStream, "accept", blocked_accept):
            handler_task = asyncio.create_task(
                pool._make_sv2_handler(object())(object(), writer)
            )
            await asyncio.wait_for(handshake_started.wait(), timeout=1)
            self.assertEqual(pool._inflight, 1)
            self.assertEqual(pool._pending_sv2_noise_handshakes, 1)

            handler_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await handler_task

        self.assertEqual(pool._inflight, 0)
        self.assertEqual(pool._pending_sv2_noise_handshakes, 0)
        self.assertTrue(writer.closed)
        self.assertEqual(writer.wait_closed_count, 1)

    async def test_post_handshake_failure_closes_the_owning_noise_stream(self) -> None:
        pool = Pool(Settings(max_clients=2))
        raw_writer = _TrackingWriter()
        owning_stream = _TrackingWriter()

        async def accept_stream(*_args, **_kwargs):
            return owning_stream

        with (
            patch.object(sv2_noise_stream.NoiseStream, "accept", accept_stream),
            patch.object(
                pool,
                "_mark_authenticated_sv2_ready",
                side_effect=MemoryError("simulated readiness failure"),
            ),
            self.assertRaisesRegex(MemoryError, "simulated readiness failure"),
        ):
            await pool._make_sv2_handler(object())(object(), raw_writer)

        self.assertTrue(owning_stream.closed)
        self.assertEqual(owning_stream.wait_closed_count, 1)
        self.assertEqual(pool._inflight, 0)
        self.assertEqual(pool._pending_sv2_noise_handshakes, 0)

    async def test_expired_noise_certificate_marks_listener_unavailable_and_warns_once(
        self,
    ) -> None:
        pool = Pool(Settings(max_clients=2))
        pool._mark_authenticated_sv2_ready()
        native_error = sv2_noise.NoiseNativeError(
            "complete responder handshake",
            sv2_noise.STATUS_CERTIFICATE_EXPIRED,
            "certificate expired",
        )

        async def reject_handshake(*_args, **_kwargs):
            raise native_error

        handler = pool._make_sv2_handler(object())
        with (
            patch.object(sv2_noise_stream.NoiseStream, "accept", reject_handshake),
            patch("erikslund_pool.pool.LOG") as log,
        ):
            await handler(object(), _TrackingWriter())
            await handler(object(), _TrackingWriter())

        status = pool._authenticated_sv2_status()
        self.assertFalse(status.ready)
        self.assertEqual(status.failure_reason, str(native_error))
        log.warning.assert_called_once_with(
            "SV2 Noise credentials rejected handshake from %s: %s",
            "127.0.0.1:3336",
            native_error,
        )
        log.debug.assert_not_called()

    async def _run_channel_smoke(self, *, extended: bool, secure: bool = False) -> None:
        config = Settings(
            bind_host="127.0.0.1",
            bind_port=0,
            sv2_host="127.0.0.1",
            sv2_ports=[0] if secure else [],
            sv2_plaintext_host="127.0.0.1",
            sv2_plaintext_ports=[] if secure else [0],
            extranonce1_size=4,
            extranonce2_size=8,
            variable_difficulty=False,
            auth_timeout_seconds=0,
            drop_idle_seconds=0,
        )
        pool = Pool(config)
        if secure:
            pool._sv2_noise_credentials = object()
        expected_connection_prefix = b"\x01\x02\x03\x04"
        pool._extranonce1_counter = int.from_bytes(expected_connection_prefix, "big") - 1
        job = self.make_job()
        job.publication_sequence = 1
        address = "bcrt1qexampleworkeraddress"
        with pool._jobs_lock:
            pool.current_job = job
            pool._recent[job.job_id] = job
            pool._address_cache[address] = (True, P2WPKH_SPK)

        transport_patch = (
            patch.object(sv2_noise_stream, "NoiseStream", _PassThroughNoiseStream)
            if secure
            else contextlib.nullcontext()
        )
        with transport_patch:
            servers = await pool._start_servers(
                reuse_port=False,
                report_startup=False,
            )
            writer = None
            try:
                sv2_server = servers[-1]
                port = sv2_server.sockets[0].getsockname()[1]
                reader, writer = await asyncio.open_connection("127.0.0.1", port)

                setup = sv2_messages.SetupConnection(
                    protocol=sv2_messages.MINING_PROTOCOL,
                    min_version=sv2_messages.PROTOCOL_VERSION,
                    max_version=sv2_messages.PROTOCOL_VERSION,
                    flags=0 if extended else sv2_messages.REQUIRES_STANDARD_JOBS_FLAG,
                    endpoint_host="127.0.0.1",
                    endpoint_port=port,
                    vendor="test",
                    hardware_version="loopback",
                    firmware="1",
                    device_id="rig",
                )
                if extended:
                    open_channel = sv2_messages.OpenExtendedMiningChannel(
                        request_id=7,
                        user_identity=f"{address}.rig",
                        nominal_hash_rate=1_000_000.0,
                        max_target=b"\xff" * 32,
                        min_extranonce_size=(
                            config.extranonce2_size - SV2_CHANNEL_DISCRIMINATOR_BYTES
                        ),
                    )
                    open_success_type = sv2_messages.OpenExtendedMiningChannelSuccess
                    new_job_type = sv2_messages.NewExtendedMiningJob
                else:
                    open_channel = sv2_messages.OpenStandardMiningChannel(
                        request_id=7,
                        user_identity=f"{address}.rig",
                        nominal_hash_rate=1_000_000.0,
                        max_target=b"\xff" * 32,
                    )
                    open_success_type = sv2_messages.OpenStandardMiningChannelSuccess
                    new_job_type = sv2_messages.NewMiningJob
                writer.write(
                    b"".join(
                        sv2_codec.encode_frame(sv2_messages.encode_message(message))
                        for message in (setup, open_channel)
                    )
                )
                await writer.drain()

                decoder = sv2_codec.FrameDecoder()
                responses: list[sv2_messages.Message] = []
                while len(responses) < 4:
                    data = await asyncio.wait_for(reader.read(4096), timeout=2)
                    self.assertTrue(data)
                    responses.extend(
                        sv2_messages.decode_message(frame) for frame in decoder.feed(data)
                    )
                self.assertEqual(
                    [type(response) for response in responses],
                    [
                        sv2_messages.SetupConnectionSuccess,
                        open_success_type,
                        new_job_type,
                        sv2_messages.SetNewPrevHash,
                    ],
                )

                open_success = responses[1]
                new_job = responses[2]
                new_prev_hash = responses[3]
                self.assertIsInstance(open_success, open_success_type)
                self.assertIsInstance(new_job, new_job_type)
                self.assertIsInstance(new_prev_hash, sv2_messages.SetNewPrevHash)
                self.assertEqual(open_success.request_id, 7)
                self.assertEqual(new_job.channel_id, open_success.channel_id)
                self.assertEqual(new_prev_hash.channel_id, open_success.channel_id)
                self.assertEqual(new_prev_hash.job_id, new_job.job_id)

                if extended:
                    self.assertEqual(
                        open_success.extranonce_prefix,
                        expected_connection_prefix + b"\x00\x01",
                    )
                    self.assertEqual(
                        open_success.extranonce_size,
                        config.extranonce2_size - SV2_CHANNEL_DISCRIMINATOR_BYTES,
                    )
                    self.assertEqual(new_job.coinbase_tx_prefix, job.coinbase1)
                    self.assertEqual(new_job.coinbase_tx_suffix, job.build_coinbase2(P2WPKH_SPK))
                    self.assertEqual(new_job.merkle_path, tuple(job.merkle_branch))
                else:
                    expected_standard_prefix = expected_connection_prefix + (1).to_bytes(
                        config.extranonce2_size, "big"
                    )
                    self.assertEqual(open_success.extranonce_prefix, expected_standard_prefix)

                channel_id = open_success.channel_id
                writer.write(
                    b"".join(
                        sv2_codec.encode_frame(sv2_messages.encode_message(message))
                        for message in (
                            sv2_messages.CloseChannel(
                                channel_id=channel_id,
                                reason_code="done",
                            ),
                            dataclasses.replace(open_channel, request_id=8),
                        )
                    )
                )
                await writer.drain()
                reopened: list[sv2_messages.Message] = []
                while len(reopened) < 3:
                    data = await asyncio.wait_for(reader.read(4096), timeout=2)
                    self.assertTrue(data)
                    reopened.extend(
                        sv2_messages.decode_message(frame) for frame in decoder.feed(data)
                    )
                self.assertIsInstance(reopened[0], open_success_type)
                self.assertEqual(reopened[0].request_id, 8)
                self.assertEqual(reopened[0].channel_id, 2)
                writer.close()
                await writer.wait_closed()
                writer = None
                self.assertEqual(await asyncio.wait_for(reader.read(), timeout=2), b"")
                async with asyncio.timeout(2):
                    while pool._client_count():
                        await asyncio.sleep(0)
                self.assertEqual(pool._client_count(), 0)
            finally:
                if writer is not None:
                    writer.close()
                    await writer.wait_closed()
                for server in servers:
                    server.close()
                    await server.wait_closed()
                pool._stop_submit_worker()
                pool._validate_executor.shutdown(wait=False)
