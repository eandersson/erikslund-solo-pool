"""Adversarial tests for the complete-frame SV2 Noise asyncio facade."""

import asyncio
import collections
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from erikslund_pool.sv2 import codec as sv2_codec
from erikslund_pool.sv2 import noise as sv2_noise
from erikslund_pool.sv2 import noise_stream as sv2_noise_stream

HEADER_TAG = b"h" * sv2_noise.TAG_SIZE
PAYLOAD_TAG = b"p" * sv2_noise.TAG_SIZE


class FakeNoiseBackend:
    def __init__(
        self,
        *,
        call_delay: float = 0.0,
        handshake_error: sv2_noise.NoiseNativeError | None = None,
        handshake_gate: threading.Event | None = None,
    ) -> None:
        self.call_delay = call_delay
        self.handshake_error = handshake_error
        self.handshake_gate = handshake_gate
        self.operations: list[str] = []
        self.freed_credentials: list[int] = []
        self.freed_sessions: list[int] = []
        self.maximum_active_calls = 0
        self._active_calls = 0
        self._activity_lock = threading.Lock()

    def load_credentials(
        self,
        static_secret_key: bytearray,
        authority_public_key: bytes,
        certificate: bytes,
        unix_timestamp: int,
    ) -> int:
        raise AssertionError(
            (static_secret_key, authority_public_key, certificate, unix_timestamp)
        )

    def free_credentials(self, credentials_handle: int) -> None:
        self.freed_credentials.append(credentials_handle)

    def responder_handshake(
        self,
        credentials_handle: int,
        act1: bytes,
        unix_timestamp: int,
    ) -> tuple[bytes, int]:
        self.assert_operation("handshake")
        if self.handshake_gate is not None and not self.handshake_gate.wait(timeout=2):
            raise AssertionError("timed out waiting to release handshake")
        if self.handshake_error is not None:
            raise self.handshake_error
        if credentials_handle != 1 or act1 != b"1" * sv2_noise.ACT1_SIZE:
            raise sv2_noise.NoiseNativeError(
                "complete responder handshake",
                1,
                "invalid argument",
            )
        if unix_timestamp <= 0:
            raise AssertionError(unix_timestamp)
        return b"2" * sv2_noise.ACT2_SIZE, 2

    def free_session(self, session_handle: int) -> None:
        self.freed_sessions.append(session_handle)

    def encrypt_header(self, session_handle: int, plaintext: bytes) -> bytes:
        self.assert_operation("encrypt_header")
        self._require_session(session_handle)
        return plaintext + HEADER_TAG

    def decrypt_header(self, session_handle: int, ciphertext: bytes) -> bytes:
        self.assert_operation("decrypt_header")
        self._require_session(session_handle)
        if len(ciphertext) != sv2_noise.ENCRYPTED_HEADER_SIZE:
            raise AssertionError(len(ciphertext))
        if ciphertext[-sv2_noise.TAG_SIZE:] != HEADER_TAG:
            raise sv2_noise.NoiseAuthenticationError(
                "authenticate frame header",
                sv2_noise.STATUS_AUTHENTICATION_FAILURE,
                "authentication failure",
            )
        return ciphertext[:-sv2_noise.TAG_SIZE]

    def encrypt_payload(self, session_handle: int, plaintext: bytes) -> bytes:
        self.assert_operation("encrypt_payload")
        self._require_session(session_handle)
        return _tag_payload(plaintext)

    def decrypt_payload(
        self,
        session_handle: int,
        ciphertext: bytes,
        plaintext_length: int,
    ) -> bytes:
        self.assert_operation("decrypt_payload")
        self._require_session(session_handle)
        plaintext = bytearray()
        ciphertext_offset = 0
        plaintext_remaining = plaintext_length
        while plaintext_remaining:
            chunk_size = min(plaintext_remaining, sv2_noise.MAX_PAYLOAD_CHUNK_SIZE)
            tag_offset = ciphertext_offset + chunk_size
            next_offset = tag_offset + sv2_noise.TAG_SIZE
            if ciphertext[tag_offset:next_offset] != PAYLOAD_TAG:
                raise sv2_noise.NoiseAuthenticationError(
                    "authenticate frame payload",
                    sv2_noise.STATUS_AUTHENTICATION_FAILURE,
                    "authentication failure",
                )
            plaintext.extend(ciphertext[ciphertext_offset:tag_offset])
            ciphertext_offset = next_offset
            plaintext_remaining -= chunk_size
        if ciphertext_offset != len(ciphertext):
            raise AssertionError((ciphertext_offset, len(ciphertext)))
        return bytes(plaintext)

    def assert_operation(self, operation: str) -> None:
        with self._activity_lock:
            self._active_calls += 1
            self.maximum_active_calls = max(
                self.maximum_active_calls,
                self._active_calls,
            )
            self.operations.append(operation)
        try:
            if self.call_delay:
                time.sleep(self.call_delay)
        finally:
            with self._activity_lock:
                self._active_calls -= 1

    @staticmethod
    def _require_session(session_handle: int) -> None:
        if session_handle != 2:
            raise AssertionError(session_handle)


class FragmentReader:
    def __init__(self, fragments: list[bytes]) -> None:
        self.fragments = collections.deque(fragments)
        self.read_count = 0

    async def read(self, size: int = -1) -> bytes:
        self.read_count += 1
        if not self.fragments:
            return b""
        fragment = self.fragments.popleft()
        if size >= 0 and len(fragment) > size:
            self.fragments.appendleft(fragment[size:])
            return fragment[:size]
        return fragment


class FeedReader:
    def __init__(self) -> None:
        self._queue: asyncio.Queue[bytes | None] = asyncio.Queue()
        self._pending = bytearray()

    def feed_data(self, data: bytes) -> None:
        self._queue.put_nowait(data)

    def feed_eof(self) -> None:
        self._queue.put_nowait(None)

    async def read(self, size: int = -1) -> bytes:
        while not self._pending:
            item = await self._queue.get()
            if item is None:
                return b""
            self._pending.extend(item)
        selected_size = len(self._pending) if size < 0 else min(size, len(self._pending))
        selected = bytes(self._pending[:selected_size])
        del self._pending[:selected_size]
        return selected


class FakeWriter:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.drain_count = 0
        self.closed = False
        self._write_lock = threading.Lock()

    def write(self, data: bytes) -> None:
        with self._write_lock:
            self.writes.append(data)

    async def drain(self) -> None:
        self.drain_count += 1

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return

    def get_extra_info(self, name: str, default: object = None) -> object:
        if name == "peername":
            return ("127.0.0.1", 3336)
        return default

    def is_closing(self) -> bool:
        return self.closed


class BlockingDrainWriter(FakeWriter):
    def __init__(self) -> None:
        super().__init__()
        self.drain_started = asyncio.Event()

    async def drain(self) -> None:
        self.drain_count += 1
        self.drain_started.set()
        await asyncio.Future()


class MemoryErrorWriter(FakeWriter):
    def write(self, data: bytes) -> None:
        if self.writes:
            raise MemoryError("simulated allocation failure")
        super().write(data)


class TestNoiseStream(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_handshake_and_frame_return_complete_plaintext(self) -> None:
        plaintext = _frame(b"fragmented")
        ciphertext = _encrypt_inbound(plaintext)
        fragments = [b"1"] * sv2_noise.ACT1_SIZE + [
            ciphertext[offset:offset + 1] for offset in range(len(ciphertext))
        ]
        backend = FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 1)
        writer = FakeWriter()
        stream = await sv2_noise_stream.NoiseStream.accept(
            FragmentReader(fragments),
            writer,
            credentials,
            timeout=1,
        )

        self.assertEqual(await stream.read(1), plaintext)
        self.assertEqual(writer.writes, [b"2" * sv2_noise.ACT2_SIZE])
        self.assertEqual(writer.drain_count, 1)
        self.assertIs(stream.get_extra_info("sv2_noise"), True)
        self.assertEqual(stream.get_extra_info("peername"), ("127.0.0.1", 3336))
        stream.close()
        credentials.close()

    async def test_native_handshake_status_is_preserved_for_listener_logging(self) -> None:
        native_error = sv2_noise.NoiseNativeError(
            "complete responder handshake",
            sv2_noise.STATUS_CERTIFICATE_EXPIRED,
            "certificate expired",
        )
        backend = FakeNoiseBackend(handshake_error=native_error)
        credentials = sv2_noise.NoiseCredentials(backend, 1)

        with self.assertRaises(sv2_noise.NoiseNativeError) as raised:
            await sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                FakeWriter(),
                credentials,
                timeout=1,
            )

        self.assertIs(raised.exception, native_error)
        self.assertEqual(raised.exception.status, sv2_noise.STATUS_CERTIFICATE_EXPIRED)
        self.assertIn("certificate expired (status 9)", str(raised.exception))
        credentials.close()

    async def test_stream_constructor_failure_frees_authenticated_session(self) -> None:
        backend = FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 1)

        with (
            patch.object(
                sv2_noise_stream.NoiseStream,
                "__init__",
                side_effect=MemoryError("simulated stream allocation failure"),
            ),
            self.assertRaisesRegex(MemoryError, "simulated stream allocation failure"),
        ):
            await sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                FakeWriter(),
                credentials,
                timeout=1,
            )

        self.assertEqual(backend.freed_sessions, [2])
        credentials.close()

    async def test_clean_eof_is_allowed_only_before_encrypted_header(self) -> None:
        clean_stream, clean_credentials, _backend, _writer = await self._accept(
            FragmentReader([b"1" * sv2_noise.ACT1_SIZE])
        )
        self.assertEqual(await clean_stream.read(), b"")
        self.assertEqual(await clean_stream.read(), b"")
        clean_stream.close()
        clean_credentials.close()

        partial_stream, partial_credentials, _backend, writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    b"x" * (sv2_noise.ENCRYPTED_HEADER_SIZE - 1),
                ]
            )
        )
        with self.assertRaises(sv2_noise_stream.NoiseUnexpectedEofError):
            await partial_stream.read()
        self.assertTrue(writer.closed)
        partial_credentials.close()

    async def test_partial_payload_eof_is_connection_error(self) -> None:
        plaintext = _frame(b"payload")
        ciphertext = _encrypt_inbound(plaintext)
        stream, credentials, _backend, writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    ciphertext[:sv2_noise.ENCRYPTED_HEADER_SIZE],
                    ciphertext[sv2_noise.ENCRYPTED_HEADER_SIZE:-1],
                ]
            )
        )

        with self.assertRaises(sv2_noise_stream.NoiseUnexpectedEofError):
            await stream.read()

        self.assertTrue(writer.closed)
        credentials.close()

    async def test_tampered_payload_never_returns_plaintext(self) -> None:
        plaintext = _frame(b"authenticated")
        ciphertext = bytearray(_encrypt_inbound(plaintext))
        ciphertext[-1] ^= 1
        stream, credentials, backend, writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    bytes(ciphertext),
                ]
            )
        )

        with self.assertRaises(sv2_noise.NoiseAuthenticationError):
            await stream.read()

        self.assertEqual(backend.freed_sessions, [2])
        self.assertTrue(writer.closed)
        credentials.close()

    async def test_authenticated_oversize_header_aborts_before_body_read(self) -> None:
        header = (
            b"\x00\x00\x10"
            + (17).to_bytes(3, "little")
        )
        stream, credentials, _backend, writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    header + HEADER_TAG,
                ]
            ),
            max_payload_size=16,
        )
        reader = stream._reader

        with self.assertRaises(sv2_noise_stream.NoiseFrameTooLargeError):
            await stream.read()

        self.assertIsInstance(reader, FragmentReader)
        self.assertEqual(reader.read_count, 2)
        self.assertTrue(writer.closed)
        credentials.close()

    async def test_valid_frame_preceding_oversize_header_is_returned_first(self) -> None:
        valid_frame = _frame(b"valid")
        oversized_header = b"\x00\x00\x10" + (17).to_bytes(3, "little")
        stream, credentials, _backend, writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    _encrypt_inbound(valid_frame) + oversized_header + HEADER_TAG,
                ]
            ),
            max_payload_size=16,
        )

        self.assertEqual(await stream.read(), valid_frame)
        with self.assertRaises(sv2_noise_stream.NoiseFrameTooLargeError):
            await stream.read()

        self.assertTrue(writer.closed)
        credentials.close()

    async def test_zero_payload_reads_no_tag_and_consumes_no_payload_call(self) -> None:
        plaintext = _frame(b"")
        stream, credentials, backend, _writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    _encrypt_inbound(plaintext),
                ]
            )
        )

        self.assertEqual(await stream.read(), plaintext)
        self.assertNotIn("decrypt_payload", backend.operations)
        stream.close()
        credentials.close()

    async def test_write_encrypts_complete_multiframe_flight_in_one_write(self) -> None:
        stream, credentials, backend, writer = await self._accept(
            FragmentReader([b"1" * sv2_noise.ACT1_SIZE])
        )
        first = _frame(b"first")
        second = _frame(b"")

        stream.write(first + second)

        self.assertEqual(
            writer.writes,
            [b"2" * sv2_noise.ACT2_SIZE, _encrypt_inbound(first) + _encrypt_inbound(second)],
        )
        self.assertEqual(
            backend.operations,
            ["handshake", "encrypt_header", "encrypt_payload", "encrypt_header"],
        )
        stream.close()
        credentials.close()

    async def test_write_uses_wire_limit_not_configured_inbound_limit(self) -> None:
        stream, credentials, _backend, writer = await self._accept(
            FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
            max_payload_size=1,
        )
        frame = _frame(b"trusted pool output")

        stream.write(frame)

        self.assertEqual(
            writer.writes,
            [b"2" * sv2_noise.ACT2_SIZE, _encrypt_inbound(frame)],
        )
        stream.close()
        credentials.close()

    async def test_write_rejects_truncated_flight_before_native_or_socket_call(self) -> None:
        stream, credentials, backend, writer = await self._accept(
            FragmentReader([b"1" * sv2_noise.ACT1_SIZE])
        )
        plaintext = _frame(b"partial")

        with self.assertRaises(sv2_codec.TruncatedFrameError):
            stream.write(plaintext[:-1])

        self.assertEqual(backend.operations, ["handshake"])
        self.assertEqual(writer.writes, [b"2" * sv2_noise.ACT2_SIZE])
        stream.close()
        credentials.close()

    async def test_memory_error_after_encrypt_aborts_transport_and_frees_session(self) -> None:
        backend = FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 1)
        writer = MemoryErrorWriter()
        stream = await sv2_noise_stream.NoiseStream.accept(
            FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
            writer,
            credentials,
            timeout=1,
        )

        with self.assertRaisesRegex(MemoryError, "simulated allocation failure"):
            stream.write(_frame(b"nonce consumed"))

        self.assertTrue(writer.closed)
        self.assertEqual(backend.freed_sessions, [2])
        with self.assertRaisesRegex(
            sv2_noise_stream.NoiseTransportError,
            "stream is closed",
        ):
            stream.write(_frame(b"must not reuse transport"))
        credentials.close()

    async def test_handshake_timeout_does_not_create_native_session(self) -> None:
        reader = FeedReader()
        backend = FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 1)

        with self.assertRaises(TimeoutError):
            await sv2_noise_stream.NoiseStream.accept(
                reader,
                FakeWriter(),
                credentials,
                timeout=0.01,
            )

        self.assertEqual(backend.operations, [])
        self.assertEqual(backend.freed_sessions, [])
        credentials.close()

    async def test_timeout_during_native_handshake_frees_the_late_session(self) -> None:
        handshake_gate = threading.Event()
        backend = FakeNoiseBackend(handshake_gate=handshake_gate)
        credentials = sv2_noise.NoiseCredentials(backend, 1)

        handshake_task = asyncio.create_task(
            sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                FakeWriter(),
                credentials,
                timeout=0.01,
            )
        )
        while "handshake" not in backend.operations:
            await asyncio.sleep(0)
        completed, _pending = await asyncio.wait({handshake_task}, timeout=0.5)
        returned_before_native_handshake = handshake_task in completed

        handshake_gate.set()
        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(handshake_task, timeout=1)

        for _ in range(200):
            if backend.freed_sessions:
                break
            await asyncio.sleep(0.01)
        self.assertTrue(returned_before_native_handshake)
        self.assertEqual(backend.freed_sessions, [2])
        credentials.close()

    async def test_native_handshake_does_not_block_the_event_loop(self) -> None:
        backend = FakeNoiseBackend(call_delay=0.05)
        credentials = sv2_noise.NoiseCredentials(backend, 1)
        handshake = asyncio.create_task(
            sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                FakeWriter(),
                credentials,
                timeout=1,
            )
        )

        while "handshake" not in backend.operations:
            await asyncio.sleep(0)
        self.assertFalse(handshake.done())

        stream = await handshake
        stream.close()
        credentials.close()

    async def test_handshake_timeout_while_draining_act2_frees_session(self) -> None:
        backend = FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 1)
        writer = BlockingDrainWriter()

        with self.assertRaises(TimeoutError):
            await sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                writer,
                credentials,
                timeout=0.5,
            )

        self.assertEqual(writer.writes, [b"2" * sv2_noise.ACT2_SIZE])
        self.assertEqual(writer.drain_count, 1)
        self.assertEqual(backend.freed_sessions, [2])
        credentials.close()

    async def test_cancelled_handshake_while_draining_act2_frees_session(self) -> None:
        backend = FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(backend, 1)
        writer = BlockingDrainWriter()
        handshake_task = asyncio.create_task(
            sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                writer,
                credentials,
                timeout=None,
            )
        )
        await asyncio.wait_for(writer.drain_started.wait(), timeout=1)
        self.assertEqual(writer.drain_count, 1)

        handshake_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await handshake_task

        self.assertEqual(backend.freed_sessions, [2])
        credentials.close()

    async def test_twice_cancelled_handshake_still_frees_session(self) -> None:
        # A second cancel arriving while the offloaded handshake is still running must not strand
        # the session it goes on to produce.
        backend = FakeNoiseBackend(call_delay=0.2)
        credentials = sv2_noise.NoiseCredentials(backend, 1)
        handshake_task = asyncio.create_task(
            sv2_noise_stream.NoiseStream.accept(
                FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
                FakeWriter(),
                credentials,
                timeout=None,
            )
        )
        await asyncio.sleep(0.05)

        handshake_task.cancel()
        await asyncio.sleep(0)
        handshake_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await handshake_task

        for _ in range(200):
            if backend.freed_sessions:
                break
            await asyncio.sleep(0.01)

        self.assertEqual(backend.freed_sessions, [2])
        credentials.close()

    async def test_cancelled_read_resumes_same_partially_consumed_frame(self) -> None:
        plaintext = _frame(b"resume-after-timeout")
        ciphertext = _encrypt_inbound(plaintext)
        header_end = sv2_noise.ENCRYPTED_HEADER_SIZE
        reader = FeedReader()
        reader.feed_data(b"1" * sv2_noise.ACT1_SIZE)
        reader.feed_data(ciphertext[:header_end])
        reader.feed_data(ciphertext[header_end:header_end + 2])
        stream, credentials, backend, _writer = await self._accept(reader)

        with self.assertRaises(TimeoutError):
            await asyncio.wait_for(stream.read(), timeout=0.01)

        reader.feed_data(ciphertext[header_end + 2:])
        self.assertEqual(await asyncio.wait_for(stream.read(), timeout=1), plaintext)
        self.assertEqual(backend.operations.count("decrypt_header"), 1)
        self.assertEqual(backend.operations.count("decrypt_payload"), 1)
        stream.close()
        credentials.close()

    async def test_concurrent_writes_serialize_each_native_flight(self) -> None:
        backend = FakeNoiseBackend(call_delay=0.005)
        stream, credentials, _backend, writer = await self._accept(
            FragmentReader([b"1" * sv2_noise.ACT1_SIZE]),
            backend=backend,
        )
        first = _frame(b"first")
        second = _frame(b"second")
        barrier = threading.Barrier(3)

        def write_frame(frame: bytes) -> None:
            barrier.wait()
            stream.write(frame)

        with ThreadPoolExecutor(max_workers=2) as executor:
            first_result = executor.submit(write_frame, first)
            second_result = executor.submit(write_frame, second)
            barrier.wait()
            first_result.result()
            second_result.result()

        self.assertEqual(backend.maximum_active_calls, 1)
        self.assertIn(
            backend.operations[1:],
            [
                ["encrypt_header", "encrypt_payload", "encrypt_header", "encrypt_payload"],
            ],
        )
        self.assertEqual(len(writer.writes), 3)
        stream.close()
        credentials.close()

    async def test_concurrent_read_and_write_serialize_native_session_calls(self) -> None:
        plaintext = _frame(b"inbound")
        backend = FakeNoiseBackend(call_delay=0.01)
        stream, credentials, _backend, _writer = await self._accept(
            FragmentReader(
                [
                    b"1" * sv2_noise.ACT1_SIZE,
                    _encrypt_inbound(plaintext),
                ]
            ),
            backend=backend,
        )
        outbound = _frame(b"outbound")
        write_thread = threading.Thread(target=stream.write, args=(outbound,))

        write_thread.start()
        await asyncio.sleep(0)
        self.assertEqual(await stream.read(), plaintext)
        write_thread.join()

        self.assertEqual(backend.maximum_active_calls, 1)
        stream.close()
        credentials.close()

    async def _accept(
        self,
        reader: sv2_noise_stream.AsyncReader,
        *,
        max_payload_size: int = sv2_codec.DEFAULT_MAX_FRAME_PAYLOAD_SIZE,
        backend: FakeNoiseBackend | None = None,
    ) -> tuple[
        sv2_noise_stream.NoiseStream,
        sv2_noise.NoiseCredentials,
        FakeNoiseBackend,
        FakeWriter,
    ]:
        selected_backend = backend or FakeNoiseBackend()
        credentials = sv2_noise.NoiseCredentials(selected_backend, 1)
        writer = FakeWriter()
        stream = await sv2_noise_stream.NoiseStream.accept(
            reader,
            writer,
            credentials,
            timeout=1,
            max_payload_size=max_payload_size,
        )
        return stream, credentials, selected_backend, writer


def _frame(payload: bytes) -> bytes:
    return sv2_codec.encode_frame(
        sv2_codec.Frame(
            extension_type=sv2_codec.CHANNEL_MESSAGE_BIT,
            message_type=0x10,
            payload=payload,
        )
    )


def _encrypt_inbound(plaintext_frame: bytes) -> bytes:
    header = plaintext_frame[:sv2_codec.FRAME_HEADER_SIZE]
    payload = plaintext_frame[sv2_codec.FRAME_HEADER_SIZE:]
    return header + HEADER_TAG + _tag_payload(payload)


def _tag_payload(payload: bytes) -> bytes:
    ciphertext = bytearray()
    offset = 0
    while offset < len(payload):
        end = min(offset + sv2_noise.MAX_PAYLOAD_CHUNK_SIZE, len(payload))
        ciphertext.extend(payload[offset:end])
        ciphertext.extend(PAYLOAD_TAG)
        offset = end
    return bytes(ciphertext)


if __name__ == "__main__":
    unittest.main()
