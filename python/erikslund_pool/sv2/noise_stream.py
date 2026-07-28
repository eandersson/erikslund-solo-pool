"""Expose an authenticated SV2 Noise connection as a complete-frame asyncio stream."""

import asyncio
import concurrent.futures
import contextlib
import threading
import typing

from erikslund_pool.sv2 import codec as sv2_codec
from erikslund_pool.sv2 import noise as sv2_noise

_HANDSHAKE_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="sv2-noise",
)


class AsyncReader(typing.Protocol):
    async def read(self, size: int = -1) -> bytes: ...


class AsyncWriter(typing.Protocol):
    def write(self, plaintext: bytes) -> None: ...

    async def drain(self) -> None: ...

    def close(self) -> None: ...

    async def wait_closed(self) -> None: ...

    def get_extra_info(self, name: str, default: object = None) -> object: ...

    def is_closing(self) -> bool: ...


class NoiseTransportError(ConnectionError):
    """The ordered transport failed before a complete authenticated frame."""


class NoiseUnexpectedEofError(NoiseTransportError):
    pass


class NoiseFrameTooLargeError(NoiseTransportError):
    pass


class NoiseStream:
    """A reader/writer facade that exchanges only complete authenticated SV2 frames."""

    def __init__(
        self,
        reader: AsyncReader,
        writer: AsyncWriter,
        session: sv2_noise.NoiseSession,
        *,
        max_payload_size: int,
    ) -> None:
        sv2_codec.check_payload_limit(max_payload_size)
        self._reader = reader
        self._writer = writer
        self._session = session
        self._max_payload_size = max_payload_size
        self._read_lock = asyncio.Lock()
        self._write_lock = threading.Lock()
        self._frame_task: asyncio.Task[bytes] | None = None
        self._closed = False
        self._eof = False

    @classmethod
    async def accept(
        cls,
        reader: AsyncReader,
        writer: AsyncWriter,
        credentials: sv2_noise.NoiseCredentials,
        *,
        timeout: float | None,
        max_payload_size: int = sv2_codec.DEFAULT_MAX_FRAME_PAYLOAD_SIZE,
    ) -> typing.Self:
        """Complete a timed responder handshake before exposing transport state."""
        sv2_codec.check_payload_limit(max_payload_size)
        session: sv2_noise.NoiseSession | None = None
        try:
            try:
                async with asyncio.timeout(timeout):
                    act1 = await _read_exact(
                        reader,
                        sv2_noise.ACT1_SIZE,
                        allow_clean_eof=False,
                        description="Noise Act1",
                    )
                    if act1 is None:
                        raise NoiseUnexpectedEofError("EOF before Noise Act1")
                    act2, session = await _complete_handshake(credentials, act1)
                    if len(act2) != sv2_noise.ACT2_SIZE:
                        raise sv2_noise.NoiseLibraryError(
                            f"responder produced {len(act2)} Act2 bytes; "
                            f"expected {sv2_noise.ACT2_SIZE}"
                        )
                    writer.write(act2)
                    await writer.drain()
            except (TimeoutError, asyncio.CancelledError):
                raise
            except (ConnectionError, OSError) as error:
                if isinstance(error, ConnectionError):
                    raise
                raise NoiseTransportError(f"Noise handshake transport failed: {error}") from error
            if session is None:
                raise sv2_noise.NoiseLibraryError(
                    "Noise handshake returned no transport session"
                )
            return cls(
                reader,
                writer,
                session,
                max_payload_size=max_payload_size,
            )
        except BaseException:
            if session is not None:
                try:
                    session.close()
                except (OSError, RuntimeError, MemoryError):
                    pass
            raise

    async def read(self, size: int = -1) -> bytes:
        """Return one complete authenticated plaintext frame, or clean EOF."""
        if size == 0:
            return b""
        if size < -1:
            raise ValueError("size must be -1 or non-negative")
        async with self._read_lock:
            if self._eof:
                return b""
            if self._closed:
                raise NoiseTransportError("SV2 Noise stream is closed")
            if self._frame_task is None:
                self._frame_task = asyncio.create_task(self._read_frame())
                self._frame_task.add_done_callback(_observe_task_exception)
            frame_task = self._frame_task
            try:
                frame = await asyncio.shield(frame_task)
            except asyncio.CancelledError:
                # Retain the task so cancellation cannot split an encrypted frame across reads.
                raise
            except BaseException:
                self._frame_task = None
                self.close()
                raise
            self._frame_task = None
            if not frame:
                self._eof = True
                self._session.close()
            return frame

    def write(self, plaintext_frames: bytes) -> None:
        """Encrypt every complete frame in one plaintext flight and write it atomically."""
        if not isinstance(plaintext_frames, bytes):
            raise TypeError("plaintext_frames must be bytes")
        if self._closed:
            raise NoiseTransportError("SV2 Noise stream is closed")

        # Pool-generated outbound frames need only obey the SV2 wire limit.
        decoder = sv2_codec.FrameDecoder(
            max_payload_size=sv2_codec.MAX_WIRE_PAYLOAD_SIZE
        )
        frames = decoder.feed(plaintext_frames)
        decoder.finish()

        ciphertext_parts: list[bytes] = []
        try:
            with self._write_lock:
                for frame in frames:
                    plaintext_frame = sv2_codec.encode_frame(
                        frame,
                        max_payload_size=sv2_codec.MAX_WIRE_PAYLOAD_SIZE,
                    )
                    header = plaintext_frame[:sv2_codec.FRAME_HEADER_SIZE]
                    payload = plaintext_frame[sv2_codec.FRAME_HEADER_SIZE:]
                    ciphertext_parts.append(self._session.encrypt_header(header))
                    if payload:
                        ciphertext_parts.append(self._session.encrypt_payload(payload))
                ciphertext_flight = b"".join(ciphertext_parts)
                if ciphertext_flight:
                    self._writer.write(ciphertext_flight)
        except BaseException as error:
            self.close()
            if isinstance(error, ConnectionError):
                raise
            if isinstance(error, OSError):
                raise NoiseTransportError(f"SV2 Noise write failed: {error}") from error
            raise

    async def drain(self) -> None:
        if self._closed:
            raise NoiseTransportError("SV2 Noise stream is closed")
        try:
            await self._writer.drain()
        except OSError as error:
            self.close()
            raise NoiseTransportError(f"SV2 Noise drain failed: {error}") from error

    def get_extra_info(self, name: str, default: object = None) -> object:
        if name == "sv2_noise":
            return True
        return self._writer.get_extra_info(name, default)

    def is_closing(self) -> bool:
        return self._closed or self._writer.is_closing()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._cancel_inflight_read()
        self._session.close()
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()

    async def _read_frame(self) -> bytes:
        encrypted_header = await _read_exact(
            self._reader,
            sv2_noise.ENCRYPTED_HEADER_SIZE,
            allow_clean_eof=True,
            description="encrypted SV2 header",
        )
        if encrypted_header is None:
            return b""

        header = self._session.decrypt_header(encrypted_header)
        if len(header) != sv2_codec.FRAME_HEADER_SIZE:
            raise sv2_noise.NoiseLibraryError(
                f"authenticated header has {len(header)} bytes; "
                f"expected {sv2_codec.FRAME_HEADER_SIZE}"
            )
        payload_size = sv2_codec.decode_frame_header(header)[2]
        if payload_size > self._max_payload_size:
            raise NoiseFrameTooLargeError(
                f"authenticated SV2 payload is {payload_size} bytes; configured limit is "
                f"{self._max_payload_size}"
            )
        if payload_size == 0:
            return header

        encrypted_payload_size = sv2_noise.encrypted_payload_size(payload_size)
        encrypted_payload = await _read_exact(
            self._reader,
            encrypted_payload_size,
            allow_clean_eof=False,
            description="encrypted SV2 payload",
        )
        if encrypted_payload is None:
            raise NoiseUnexpectedEofError("EOF before encrypted SV2 payload")
        payload = self._session.decrypt_payload(encrypted_payload, payload_size)
        if len(payload) != payload_size:
            raise sv2_noise.NoiseLibraryError(
                f"authenticated payload has {len(payload)} bytes; expected {payload_size}"
            )
        return header + payload

    def _cancel_inflight_read(self) -> None:
        frame_task = self._frame_task
        if frame_task is None:
            return
        try:
            current_task = asyncio.current_task()
        except RuntimeError:
            current_task = None
        if frame_task is current_task:
            return
        task_loop = frame_task.get_loop()
        if current_task is None and task_loop.is_running():
            task_loop.call_soon_threadsafe(frame_task.cancel)
        else:
            frame_task.cancel()


async def _read_exact(
    reader: AsyncReader,
    size: int,
    *,
    allow_clean_eof: bool,
    description: str,
) -> bytes | None:
    received_bytes = bytearray()
    remaining = size
    while remaining:
        try:
            chunk = await reader.read(remaining)
        except OSError as error:
            raise NoiseTransportError(f"{description} read failed: {error}") from error
        if not chunk:
            if allow_clean_eof and not received_bytes:
                return None
            raise NoiseUnexpectedEofError(
                f"EOF after {len(received_bytes)} of {size} bytes in {description}"
            )
        if len(chunk) > remaining:
            raise NoiseTransportError(
                f"{description} reader returned {len(chunk)} bytes after requesting {remaining}"
            )
        received_bytes.extend(chunk)
        remaining -= len(chunk)
    return bytes(received_bytes)


async def _complete_handshake(
    credentials: sv2_noise.NoiseCredentials,
    act1: bytes,
) -> tuple[bytes, sv2_noise.NoiseSession]:
    handshake_future = _HANDSHAKE_EXECUTOR.submit(credentials.handshake, act1)
    pending_handshake = asyncio.wrap_future(handshake_future)
    try:
        return await asyncio.shield(pending_handshake)
    except asyncio.CancelledError:
        handshake_future.add_done_callback(_close_orphaned_session)
        pending_handshake.cancel()
        raise


def _close_orphaned_session(
    handshake_future: concurrent.futures.Future[tuple[bytes, sv2_noise.NoiseSession]],
) -> None:
    """Free the native session of a handshake whose waiter was cancelled."""
    with contextlib.suppress(BaseException):
        _act2, session = handshake_future.result()
        session.close()


def _observe_task_exception(task: asyncio.Task[bytes]) -> None:
    if not task.cancelled():
        task.exception()
