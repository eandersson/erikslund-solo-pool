#!/usr/bin/env python3
"""Plaintext Stratum V2 test miner for local development."""

import argparse
import hashlib
import logging
import socket
import struct
import sys
import time
from dataclasses import dataclass

DIFF1_TARGET = 0xFFFF << 208
CHANNEL_MESSAGE_FLAG = 0x8000
EXTENSION_ID_MASK = 0x7FFF
FRAME_HEADER_SIZE = 6
REQUIRES_STANDARD_JOBS = 1 << 0
DEFAULT_PORT = 34_254
SOCKET_READ_SIZE = 65_536
NONCE_BATCH_SIZE = 200_000
HASHRATE_REPORT_SECONDS = 5.0
IDLE_SLEEP_SECONDS = 0.05
NOMINAL_HASH_RATE = 1_000_000.0

_PACK_LITTLE_ENDIAN_U32 = struct.Struct("<I").pack

LOG = logging.getLogger(__name__)


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def target_from_difficulty(difficulty: float) -> int:
    if difficulty <= 0:
        return DIFF1_TARGET
    return int(DIFF1_TARGET / difficulty)


def build_header(
    version: int, previous_hash: bytes, merkle_root: bytes, ntime: int, nbits: int, nonce: int
) -> bytes:
    """Build an 80-byte header from fields already in Bitcoin wire byte order."""
    return b"".join(
        (
            struct.pack("<I", version & 0xFFFFFFFF),
            previous_hash,
            merkle_root,
            struct.pack("<I", ntime & 0xFFFFFFFF),
            struct.pack("<I", nbits & 0xFFFFFFFF),
            struct.pack("<I", nonce & 0xFFFFFFFF),
        )
    )


def header_hash_int(header: bytes) -> int:
    return int.from_bytes(double_sha256(header), "little")


class Writer:
    __slots__ = ("_buffer",)

    def __init__(self) -> None:
        self._buffer = bytearray()

    def getvalue(self) -> bytes:
        return bytes(self._buffer)

    def u8(self, value: int) -> None:
        self._buffer += struct.pack("<B", value)

    def u16(self, value: int) -> None:
        self._buffer += struct.pack("<H", value)

    def u24(self, value: int) -> None:
        self._buffer += struct.pack("<I", value)[:3]

    def u32(self, value: int) -> None:
        self._buffer += struct.pack("<I", value)

    def u64(self, value: int) -> None:
        self._buffer += struct.pack("<Q", value)

    def f32(self, value: float) -> None:
        self._buffer += struct.pack("<f", value)

    def boolean(self, value: bool) -> None:
        self._buffer += struct.pack("<B", 1 if value else 0)

    def u256(self, value: bytes) -> None:
        if len(value) != 32:
            raise ValueError(f"U256 must be 32 bytes, got {len(value)}")
        self._buffer += value

    def b0_32(self, value: bytes) -> None:
        if len(value) > 32:
            raise ValueError(f"B0_32 must be <= 32 bytes, got {len(value)}")
        self.u8(len(value))
        self._buffer += value

    def b0_255(self, value: bytes) -> None:
        if len(value) > 255:
            raise ValueError(f"B0_255 must be <= 255 bytes, got {len(value)}")
        self.u8(len(value))
        self._buffer += value

    def b0_64k(self, value: bytes) -> None:
        if len(value) > 0xFFFF:
            raise ValueError(f"B0_64K must be <= 65535 bytes, got {len(value)}")
        self.u16(len(value))
        self._buffer += value

    def str0_255(self, value: str) -> None:
        self.b0_255(value.encode("utf-8"))

    def option_u32(self, value: int | None) -> None:
        if value is None:
            self.u8(0)
        else:
            self.u8(1)
            self.u32(value)


class Reader:
    __slots__ = ("_buffer", "_position")

    def __init__(self, data: bytes) -> None:
        self._buffer = data
        self._position = 0

    def remaining(self) -> int:
        return len(self._buffer) - self._position

    def _take(self, length: int) -> bytes:
        end = self._position + length
        if end > len(self._buffer):
            raise ValueError(f"short read: need {length} bytes, have {self.remaining()}")
        chunk = self._buffer[self._position : end]
        self._position = end
        return chunk

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self._take(2))[0]

    def u24(self) -> int:
        return struct.unpack("<I", self._take(3) + b"\x00")[0]

    def u32(self) -> int:
        return struct.unpack("<I", self._take(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self._take(8))[0]

    def f32(self) -> float:
        return struct.unpack("<f", self._take(4))[0]

    def boolean(self) -> bool:
        return self._take(1)[0] != 0

    def u256(self) -> bytes:
        return self._take(32)

    def b0_32(self) -> bytes:
        return self._take(self.u8())

    def b0_255(self) -> bytes:
        return self._take(self.u8())

    def b0_64k(self) -> bytes:
        return self._take(self.u16())

    def str0_255(self) -> str:
        return self._take(self.u8()).decode("utf-8")

    def option_u32(self) -> int | None:
        return self.u32() if self.u8() else None


def encode_frame(
    extension_id: int, channel_message: bool, message_type: int, payload: bytes
) -> bytes:
    extension_type = extension_id & EXTENSION_ID_MASK
    if channel_message:
        extension_type |= CHANNEL_MESSAGE_FLAG
    writer = Writer()
    writer.u16(extension_type)
    writer.u8(message_type)
    writer.u24(len(payload))
    return writer.getvalue() + payload


def decode_frame_header(header: bytes) -> tuple[int, bool, int, int]:
    if len(header) != FRAME_HEADER_SIZE:
        raise ValueError(f"frame header must be {FRAME_HEADER_SIZE} bytes")
    reader = Reader(header)
    extension_type = reader.u16()
    message_type = reader.u8()
    message_length = reader.u24()
    channel_message = bool(extension_type & CHANNEL_MESSAGE_FLAG)
    extension_id = extension_type & EXTENSION_ID_MASK
    return extension_id, channel_message, message_type, message_length


@dataclass(slots=True)
class SetupConnection:
    MESSAGE_TYPE = 0x00
    CHANNEL_MESSAGE = False

    protocol: int
    min_version: int
    max_version: int
    flags: int
    endpoint_host: str
    endpoint_port: int
    vendor: str
    hardware_version: str
    firmware: str
    device_id: str

    def serialize(self) -> bytes:
        w = Writer()
        w.u8(self.protocol)
        w.u16(self.min_version)
        w.u16(self.max_version)
        w.u32(self.flags)
        w.str0_255(self.endpoint_host)
        w.u16(self.endpoint_port)
        w.str0_255(self.vendor)
        w.str0_255(self.hardware_version)
        w.str0_255(self.firmware)
        w.str0_255(self.device_id)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SetupConnection:
        r = Reader(payload)
        return cls(
            protocol=r.u8(),
            min_version=r.u16(),
            max_version=r.u16(),
            flags=r.u32(),
            endpoint_host=r.str0_255(),
            endpoint_port=r.u16(),
            vendor=r.str0_255(),
            hardware_version=r.str0_255(),
            firmware=r.str0_255(),
            device_id=r.str0_255(),
        )


@dataclass(slots=True)
class SetupConnectionSuccess:
    MESSAGE_TYPE = 0x01
    CHANNEL_MESSAGE = False

    used_version: int
    flags: int

    def serialize(self) -> bytes:
        w = Writer()
        w.u16(self.used_version)
        w.u32(self.flags)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SetupConnectionSuccess:
        r = Reader(payload)
        return cls(used_version=r.u16(), flags=r.u32())


@dataclass(slots=True)
class SetupConnectionError:
    MESSAGE_TYPE = 0x02
    CHANNEL_MESSAGE = False

    flags: int
    error_code: str

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.flags)
        w.str0_255(self.error_code)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SetupConnectionError:
        r = Reader(payload)
        return cls(flags=r.u32(), error_code=r.str0_255())


@dataclass(slots=True)
class OpenStandardMiningChannel:
    MESSAGE_TYPE = 0x10
    CHANNEL_MESSAGE = False

    request_id: int
    user_identity: str
    nominal_hash_rate: float
    max_target: bytes

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.request_id)
        w.str0_255(self.user_identity)
        w.f32(self.nominal_hash_rate)
        w.u256(self.max_target)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> OpenStandardMiningChannel:
        r = Reader(payload)
        return cls(
            request_id=r.u32(),
            user_identity=r.str0_255(),
            nominal_hash_rate=r.f32(),
            max_target=r.u256(),
        )


@dataclass(slots=True)
class OpenStandardMiningChannelSuccess:
    MESSAGE_TYPE = 0x11
    CHANNEL_MESSAGE = False

    request_id: int
    channel_id: int
    target: bytes
    extranonce_prefix: bytes
    group_channel_id: int

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.request_id)
        w.u32(self.channel_id)
        w.u256(self.target)
        w.b0_32(self.extranonce_prefix)
        w.u32(self.group_channel_id)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> OpenStandardMiningChannelSuccess:
        r = Reader(payload)
        return cls(
            request_id=r.u32(),
            channel_id=r.u32(),
            target=r.u256(),
            extranonce_prefix=r.b0_32(),
            group_channel_id=r.u32(),
        )


@dataclass(slots=True)
class OpenMiningChannelError:
    MESSAGE_TYPE = 0x12
    CHANNEL_MESSAGE = False

    request_id: int
    error_code: str

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.request_id)
        w.str0_255(self.error_code)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> OpenMiningChannelError:
        r = Reader(payload)
        return cls(request_id=r.u32(), error_code=r.str0_255())


@dataclass(slots=True)
class NewMiningJob:
    MESSAGE_TYPE = 0x15
    CHANNEL_MESSAGE = True

    channel_id: int
    job_id: int
    min_ntime: int | None
    version: int
    merkle_root: bytes

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u32(self.job_id)
        w.option_u32(self.min_ntime)
        w.u32(self.version)
        w.u256(self.merkle_root)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> NewMiningJob:
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            job_id=r.u32(),
            min_ntime=r.option_u32(),
            version=r.u32(),
            merkle_root=r.u256(),
        )


@dataclass(slots=True)
class SetNewPrevHash:
    MESSAGE_TYPE = 0x20
    CHANNEL_MESSAGE = True

    channel_id: int
    job_id: int
    prev_hash: bytes
    min_ntime: int
    nbits: int

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u32(self.job_id)
        w.u256(self.prev_hash)
        w.u32(self.min_ntime)
        w.u32(self.nbits)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SetNewPrevHash:
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            job_id=r.u32(),
            prev_hash=r.u256(),
            min_ntime=r.u32(),
            nbits=r.u32(),
        )


@dataclass(slots=True)
class SetTarget:
    MESSAGE_TYPE = 0x21
    CHANNEL_MESSAGE = True

    channel_id: int
    maximum_target: bytes

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u256(self.maximum_target)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SetTarget:
        r = Reader(payload)
        return cls(channel_id=r.u32(), maximum_target=r.u256())


@dataclass(slots=True)
class SubmitSharesStandard:
    MESSAGE_TYPE = 0x1A
    CHANNEL_MESSAGE = True

    channel_id: int
    sequence_number: int
    job_id: int
    nonce: int
    ntime: int
    version: int

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u32(self.sequence_number)
        w.u32(self.job_id)
        w.u32(self.nonce)
        w.u32(self.ntime)
        w.u32(self.version)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SubmitSharesStandard:
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            sequence_number=r.u32(),
            job_id=r.u32(),
            nonce=r.u32(),
            ntime=r.u32(),
            version=r.u32(),
        )


@dataclass(slots=True)
class SubmitSharesSuccess:
    MESSAGE_TYPE = 0x1C
    CHANNEL_MESSAGE = True

    channel_id: int
    last_sequence_number: int
    new_submits_accepted_count: int
    new_shares_sum: int

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u32(self.last_sequence_number)
        w.u32(self.new_submits_accepted_count)
        w.u64(self.new_shares_sum)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SubmitSharesSuccess:
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            last_sequence_number=r.u32(),
            new_submits_accepted_count=r.u32(),
            new_shares_sum=r.u64(),
        )


@dataclass(slots=True)
class SubmitSharesError:
    MESSAGE_TYPE = 0x1D
    CHANNEL_MESSAGE = True

    channel_id: int
    sequence_number: int
    error_code: str

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u32(self.sequence_number)
        w.str0_255(self.error_code)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> SubmitSharesError:
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            sequence_number=r.u32(),
            error_code=r.str0_255(),
        )


MESSAGE_TYPES = (
    SetupConnection,
    SetupConnectionSuccess,
    SetupConnectionError,
    OpenStandardMiningChannel,
    OpenStandardMiningChannelSuccess,
    OpenMiningChannelError,
    NewMiningJob,
    SetNewPrevHash,
    SetTarget,
    SubmitSharesStandard,
    SubmitSharesSuccess,
    SubmitSharesError,
)


def frame_message(message: object) -> bytes:
    return encode_frame(
        extension_id=0,
        channel_message=type(message).CHANNEL_MESSAGE,
        message_type=type(message).MESSAGE_TYPE,
        payload=message.serialize(),
    )


@dataclass(frozen=True, slots=True)
class Frame:
    extension_id: int
    channel_message: bool
    message_type: int
    payload: bytes


class FrameTransport:
    __slots__ = ("_buffer", "_connection")

    def __init__(self, connection: socket.socket) -> None:
        self._connection = connection
        self._buffer = b""

    def send_frame(self, frame: bytes) -> None:
        self._connection.sendall(frame)

    def set_nonblocking(self) -> None:
        self._connection.setblocking(False)

    def receive_frame(self) -> Frame | None:
        """Return the next decoded inbound frame, or None on a clean close."""
        while True:
            if len(self._buffer) >= FRAME_HEADER_SIZE:
                extension_id, channel_message, message_type, payload_length = decode_frame_header(
                    self._buffer[:FRAME_HEADER_SIZE]
                )
                frame_size = FRAME_HEADER_SIZE + payload_length
                if len(self._buffer) >= frame_size:
                    payload = self._buffer[FRAME_HEADER_SIZE:frame_size]
                    self._buffer = self._buffer[frame_size:]
                    return Frame(extension_id, channel_message, message_type, payload)
            chunk = self._connection.recv(SOCKET_READ_SIZE)
            if not chunk:
                return None
            self._buffer += chunk


@dataclass(slots=True)
class MiningState:
    channel_id: int = 0
    target: int = DIFF1_TARGET
    job_id: int = 0
    version: int = 0
    merkle_root: bytes = b""
    prev_hash: bytes = b""
    nbits: int = 0
    min_ntime: int = 0
    have_job: bool = False
    have_previous_hash: bool = False
    sequence_number: int = 0
    work_generation: int = 0

    def has_work(self) -> bool:
        return self.have_job and self.have_previous_hash


@dataclass(frozen=True, slots=True)
class PreparedWork:
    header_prefix: bytes
    header_tail: bytes
    target: int
    job_id: int
    version: int
    ntime: int


class Sv2Miner:
    __slots__ = (
        "accepted",
        "host",
        "max_target",
        "port",
        "rejected",
        "roll_ntime",
        "state",
        "transport",
        "user",
    )

    def __init__(
        self, host: str, port: int, user: str, *, max_target: int, roll_ntime: bool
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.max_target = max_target
        self.roll_ntime = roll_ntime
        self.transport: FrameTransport | None = None
        self.state = MiningState(target=max_target)
        self.accepted = 0
        self.rejected = 0

    def connect(self) -> None:
        LOG.info("connecting to %s:%d", self.host, self.port)
        connection = socket.create_connection((self.host, self.port), timeout=30)
        connection.settimeout(None)
        self.transport = FrameTransport(connection)

    def setup_connection(self) -> bool:
        device_id = socket.gethostname()
        setup = SetupConnection(
            protocol=0,
            min_version=2,
            max_version=2,
            flags=REQUIRES_STANDARD_JOBS,
            endpoint_host=self.host,
            endpoint_port=self.port,
            vendor="erikslund",
            hardware_version="",
            firmware="sv2_miner",
            device_id=device_id,
        )
        self.transport.send_frame(frame_message(setup))
        frame = self.transport.receive_frame()
        if frame is None:
            LOG.error("pool closed before SetupConnection response")
            return False
        match frame.message_type:
            case SetupConnectionSuccess.MESSAGE_TYPE:
                success = SetupConnectionSuccess.parse(frame.payload)
                LOG.info(
                    "connection set up: used_version=%d flags=0x%08x",
                    success.used_version,
                    success.flags,
                )
                return True
            case SetupConnectionError.MESSAGE_TYPE:
                error = SetupConnectionError.parse(frame.payload)
                LOG.error(
                    "SetupConnection rejected: %s (flags=0x%08x)", error.error_code, error.flags
                )
                return False
            case _:
                LOG.error(
                    "received message type 0x%02x in response to SetupConnection",
                    frame.message_type,
                )
                return False

    def open_channel(self) -> bool:
        request = OpenStandardMiningChannel(
            request_id=1,
            user_identity=self.user,
            nominal_hash_rate=NOMINAL_HASH_RATE,
            max_target=self.max_target.to_bytes(32, "little"),
        )
        self.transport.send_frame(frame_message(request))
        frame = self.transport.receive_frame()
        if frame is None:
            LOG.error("pool closed before channel-open response")
            return False
        match frame.message_type:
            case OpenStandardMiningChannelSuccess.MESSAGE_TYPE:
                success = OpenStandardMiningChannelSuccess.parse(frame.payload)
                self.state.channel_id = success.channel_id
                self.state.target = int.from_bytes(success.target, "little")
                LOG.info(
                    "channel %d opened: target=%s extranonce_prefix=%s",
                    success.channel_id,
                    success.target.hex(),
                    success.extranonce_prefix.hex(),
                )
                return True
            case OpenMiningChannelError.MESSAGE_TYPE:
                error = OpenMiningChannelError.parse(frame.payload)
                LOG.error("OpenStandardMiningChannel rejected: %s", error.error_code)
                return False
            case _:
                LOG.error(
                    "received message type 0x%02x in response to channel open",
                    frame.message_type,
                )
                return False

    def handle_frame(self, frame: Frame) -> None:
        match frame.message_type:
            case NewMiningJob.MESSAGE_TYPE:
                self._on_new_job(NewMiningJob.parse(frame.payload))
            case SetNewPrevHash.MESSAGE_TYPE:
                self._on_set_previous_hash(SetNewPrevHash.parse(frame.payload))
            case SetTarget.MESSAGE_TYPE:
                self._on_set_target(SetTarget.parse(frame.payload))
            case SubmitSharesSuccess.MESSAGE_TYPE:
                success = SubmitSharesSuccess.parse(frame.payload)
                self.accepted += 1
                LOG.info(
                    "share ACCEPTED (seq=%d, %d accepted / %d rejected)",
                    success.last_sequence_number,
                    self.accepted,
                    self.rejected,
                )
            case SubmitSharesError.MESSAGE_TYPE:
                error = SubmitSharesError.parse(frame.payload)
                self.rejected += 1
                LOG.warning(
                    "share REJECTED: %s (%d accepted / %d rejected)",
                    error.error_code,
                    self.accepted,
                    self.rejected,
                )
            case _:
                LOG.debug("unhandled message type 0x%02x", frame.message_type)

    def _on_new_job(self, job: NewMiningJob) -> None:
        self.state.job_id = job.job_id
        self.state.version = job.version
        self.state.merkle_root = job.merkle_root
        self.state.min_ntime = job.min_ntime if job.min_ntime is not None else self.state.min_ntime
        self.state.have_job = True
        self.state.work_generation += 1
        LOG.info(
            "new job %d (version=0x%08x, merkle_root=%s)",
            job.job_id,
            job.version,
            job.merkle_root.hex(),
        )

    def _on_set_previous_hash(self, message: SetNewPrevHash) -> None:
        self.state.prev_hash = message.prev_hash
        self.state.nbits = message.nbits
        self.state.min_ntime = message.min_ntime
        self.state.job_id = message.job_id
        self.state.have_previous_hash = True
        self.state.work_generation += 1
        LOG.info(
            "set prev_hash for job %d (nbits=0x%08x, min_ntime=%d)",
            message.job_id,
            message.nbits,
            message.min_ntime,
        )

    def _on_set_target(self, message: SetTarget) -> None:
        self.state.target = int.from_bytes(message.maximum_target, "little")
        LOG.info("target set to %s", message.maximum_target.hex())

    def mine(self) -> int:
        if not self.setup_connection():
            return 1
        if not self.open_channel():
            return 1

        pack_nonce = _PACK_LITTLE_ENDIAN_U32
        sha256 = hashlib.sha256
        self.transport.set_nonblocking()

        current_generation = -1
        nonce = 0
        prepared_work: PreparedWork | None = None
        last_report_time = time.monotonic()
        hash_count = 0

        while True:
            try:
                while (frame := self.transport.receive_frame()) is not None:
                    self.handle_frame(frame)
            except BlockingIOError:
                pass
            except OSError as exc:
                LOG.warning("receive loop ended: %s", exc)
                return 0

            if not self.state.has_work():
                time.sleep(IDLE_SLEEP_SECONDS)
                continue

            if prepared_work is None or self.state.work_generation != current_generation:
                current_generation = self.state.work_generation
                nonce = 0
                prepared_work = self._prepare_search()
                copy_header_prefix_hash = hashlib.sha256(prepared_work.header_prefix).copy

            target_high_word = prepared_work.target >> 240
            batch_end = nonce + NONCE_BATCH_SIZE
            while nonce < batch_end:
                header_hash = copy_header_prefix_hash()
                header_hash.update(prepared_work.header_tail + pack_nonce(nonce))
                digest = sha256(header_hash.digest()).digest()
                if (digest[31] << 8 | digest[30]) <= target_high_word and int.from_bytes(
                    digest, "little"
                ) <= prepared_work.target:
                    self._submit(
                        prepared_work.job_id,
                        nonce,
                        prepared_work.ntime,
                        prepared_work.version,
                    )
                nonce += 1
            hash_count += NONCE_BATCH_SIZE

            report_time = time.monotonic()
            report_interval = report_time - last_report_time
            if report_interval >= HASHRATE_REPORT_SECONDS:
                hash_rate = hash_count / report_interval
                LOG.info(
                    "hashrate ~%.0f H/s | accepted %d rejected %d",
                    hash_rate,
                    self.accepted,
                    self.rejected,
                )
                hash_count = 0
                last_report_time = report_time

            if nonce > 0xFFFFFFFF:
                if self.roll_ntime:
                    self.state.min_ntime += 1
                    self.state.work_generation += 1
                else:
                    nonce = 0

    def _prepare_search(self) -> PreparedWork:
        ntime = max(self.state.min_ntime, int(time.time()))
        header_without_nonce = build_header(
            self.state.version,
            self.state.prev_hash,
            self.state.merkle_root,
            ntime,
            self.state.nbits,
            0,
        )[:76]
        return PreparedWork(
            header_prefix=header_without_nonce[:64],
            header_tail=header_without_nonce[64:76],
            target=self.state.target,
            job_id=self.state.job_id,
            version=self.state.version,
            ntime=ntime,
        )

    def _submit(self, job_id: int, nonce: int, ntime: int, version: int) -> None:
        self.state.sequence_number += 1
        share = SubmitSharesStandard(
            channel_id=self.state.channel_id,
            sequence_number=self.state.sequence_number,
            job_id=job_id,
            nonce=nonce,
            ntime=ntime,
            version=version,
        )
        self.transport.send_frame(frame_message(share))
        LOG.info(
            "submitted share: job=%d nonce=0x%08x ntime=%d seq=%d",
            job_id,
            nonce,
            ntime,
            self.state.sequence_number,
        )


def _codec_test_messages() -> list[object]:
    target = DIFF1_TARGET.to_bytes(32, "little")
    return [
        SetupConnection(
            0, 2, 2, 0, "pool.example.com", 34254, "erikslund", "", "sv2_miner", "host-1"
        ),
        SetupConnection(0, 2, 2, 0x1, "", 0, "", "hw", "fw", ""),
        SetupConnectionSuccess(2, 0x0),
        SetupConnectionError(0x2, "unsupported-feature-flags"),
        OpenStandardMiningChannel(7, "bc1qexampleaddress", NOMINAL_HASH_RATE, target),
        OpenStandardMiningChannelSuccess(7, 42, target, b"", 0),
        OpenStandardMiningChannelSuccess(7, 42, target, b"\xab" * 32, 9),
        OpenMiningChannelError(7, "max-target-out-of-range"),
        NewMiningJob(42, 100, None, 0x20000000, b"\x00" * 32),
        NewMiningJob(42, 101, 1715000000, 0x20000000, b"\x11" * 32),
        SetNewPrevHash(42, 100, b"\x22" * 32, 1715000000, 0x1D00FFFF),
        SetTarget(42, target),
        SubmitSharesStandard(42, 1, 100, 0xABBAABBA, 1715000123, 0x20000000),
        SubmitSharesSuccess(42, 5, 5, 1234567890123),
        SubmitSharesError(42, 6, "stale-share"),
    ]


def _selftest_codec() -> bool:
    messages = _codec_test_messages()
    for message in messages:
        serialized = message.serialize()
        roundtripped = type(message).parse(serialized)
        if roundtripped != message:
            LOG.error(
                "codec FAILED for %s:\n  in  %r\n  out %r",
                type(message).__name__,
                message,
                roundtripped,
            )
            return False
    LOG.info("codec OK: %d message instances round-tripped", len(messages))
    return True


def _selftest_framing() -> bool:
    cases = [
        (0, False, 0x00, b""),
        (0, True, 0x15, b"\x01\x02\x03\x04"),
        (0, True, 0x20, b"\x7e" * 70_000),
        (0x1234, True, 0x21, b"\xaa" * 5),
    ]
    for extension_id, channel_message, message_type, payload in cases:
        frame = encode_frame(extension_id, channel_message, message_type, payload)
        decoded_header = decode_frame_header(frame[:FRAME_HEADER_SIZE])
        decoded = (*decoded_header, frame[FRAME_HEADER_SIZE:])
        expected = (extension_id, channel_message, message_type, len(payload), payload)
        if decoded != expected:
            LOG.error(
                "framing FAILED for message_type=0x%02x length=%d",
                message_type,
                len(payload),
            )
            return False
    LOG.info("framing OK: %d frames round-tripped (channel flag and U24 length)", len(cases))
    return True


def _selftest_hashing() -> bool:
    genesis = build_header(
        version=1,
        previous_hash=b"\x00" * 32,
        merkle_root=bytes.fromhex(
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"
        ),
        ntime=0x495FAB29,
        nbits=0x1D00FFFF,
        nonce=2083236893,
    )
    actual_hash = double_sha256(genesis)[::-1].hex()
    expected_hash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    if actual_hash != expected_hash:
        LOG.error("hashing FAILED: actual %s expected %s", actual_hash, expected_hash)
        return False
    assert header_hash_int(genesis) <= DIFF1_TARGET
    assert target_from_difficulty(1) == DIFF1_TARGET
    assert target_from_difficulty(2) == DIFF1_TARGET // 2
    LOG.info("hashing OK: genesis block hash reproduced (%s)", expected_hash)
    return True


def selftest() -> bool:
    results = [
        ("codec", _selftest_codec()),
        ("framing", _selftest_framing()),
        ("hashing", _selftest_hashing()),
    ]
    all_ok = True
    for name, result in results:
        if result:
            print(f"  {name:8s} PASS")
        else:
            print(f"  {name:8s} FAIL")
            all_ok = False
    print("selftest:", "PASS" if all_ok else "FAIL")
    return all_ok


def _resolve_max_target(arguments: argparse.Namespace) -> int:
    if arguments.target:
        return int(arguments.target, 16)
    return target_from_difficulty(arguments.difficulty)


def run_miner(arguments: argparse.Namespace) -> int:
    host, _, port_text = arguments.url.partition(":")
    port = int(port_text or DEFAULT_PORT)

    miner = Sv2Miner(
        host=host,
        port=port,
        user=arguments.user,
        max_target=_resolve_max_target(arguments),
        roll_ntime=True,
    )
    try:
        miner.connect()
        return miner.mine()
    except KeyboardInterrupt:
        LOG.info("interrupted; stopping the miner")
        return 0
    except (OSError, RuntimeError) as exc:
        LOG.error("miner stopped: %s", exc)
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stratum V2 (SV2) test client for erikslund-pool")
    parser.add_argument(
        "--url",
        default=f"127.0.0.1:{DEFAULT_PORT}",
        help=f"pool host:port (default 127.0.0.1:{DEFAULT_PORT})",
    )
    parser.add_argument(
        "--user", default="", help="user_identity; a valid BTC address for solo pools"
    )
    parser.add_argument(
        "--pass",
        dest="password",
        default="",
        help="ignored (SV2 has no per-connection password); accepted for parity with the V1 miner",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="channel max_target as a 256-bit hex integer (overrides --difficulty)",
    )
    parser.add_argument(
        "--difficulty",
        type=float,
        default=1.0,
        help="channel max_target as diff-1/difficulty (default 1)",
    )
    parser.add_argument("--quiet", action="store_true", help="suppress hashrate lines")
    parser.add_argument(
        "--selftest", action="store_true", help="run codec/framing/hashing checks offline and exit"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    arguments = parser.parse_args(argv)

    level = (
        logging.DEBUG
        if arguments.verbose
        else (logging.WARNING if arguments.quiet else logging.INFO)
    )
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if arguments.selftest:
        return 0 if selftest() else 1

    if not selftest():
        LOG.error("refusing to mine: offline self-test failed")
        return 1
    if not arguments.user:
        LOG.error("--user is required (a valid BTC address for solo pools)")
        return 1
    return run_miner(arguments)


if __name__ == "__main__":
    sys.exit(main())
