"""Encode and incrementally decode bounded Stratum V2 frames and payload primitives."""

from __future__ import annotations

import dataclasses
import struct

FRAME_HEADER_SIZE = 6
CHANNEL_MESSAGE_BIT = 0x8000
EXTENSION_ID_MASK = 0x7FFF
MAX_WIRE_PAYLOAD_SIZE = 0xFF_FFFF
DEFAULT_MAX_FRAME_PAYLOAD_SIZE = 1_048_576
UINT8_MAX = 0xFF
UINT16_MAX = 0xFFFF
UINT24_MAX = 0xFF_FFFF
UINT32_MAX = 0xFFFF_FFFF
UINT64_MAX = 0xFFFF_FFFF_FFFF_FFFF
UINT256_SIZE = 32
B0_32_MAX_SIZE = 32
B0_64K_MAX_SIZE = UINT16_MAX
SEQUENCE_MAX_COUNT = UINT8_MAX
STRING_MAX_SIZE = 255


class Sv2CodecError(ValueError):
    """Base class for malformed or unsupported Stratum V2 wire data."""

    def __init__(
        self,
        message: str,
        *,
        completed_frames: list[Frame] | None = None,
    ) -> None:
        super().__init__(message)
        self.completed_frames = completed_frames or []


class FrameTooLargeError(Sv2CodecError):
    pass


class TruncatedFrameError(Sv2CodecError):
    pass


class MessageDecodeError(Sv2CodecError):
    pass


def check_payload_limit(max_payload_size: int) -> None:
    if not 0 <= max_payload_size <= MAX_WIRE_PAYLOAD_SIZE:
        raise ValueError(f"max_payload_size must be between 0 and {MAX_WIRE_PAYLOAD_SIZE}")


@dataclasses.dataclass(frozen=True, slots=True)
class Frame:
    """One decoded SV2 frame, including the routing bits in ``extension_type``."""

    extension_type: int
    message_type: int
    payload: bytes

    def __post_init__(self) -> None:
        _check_unsigned("extension_type", self.extension_type, UINT16_MAX)
        _check_unsigned("message_type", self.message_type, UINT8_MAX)
        if not isinstance(self.payload, bytes):
            raise TypeError("payload must be bytes")
        if len(self.payload) > MAX_WIRE_PAYLOAD_SIZE:
            raise FrameTooLargeError(
                f"payload is {len(self.payload)} bytes; SV2 U24 permits at most "
                f"{MAX_WIRE_PAYLOAD_SIZE}"
            )

    @property
    def extension_id(self) -> int:
        return self.extension_type & EXTENSION_ID_MASK

    @property
    def channel_message(self) -> bool:
        return bool(self.extension_type & CHANNEL_MESSAGE_BIT)


class FrameDecoder:
    def __init__(self, max_payload_size: int = DEFAULT_MAX_FRAME_PAYLOAD_SIZE) -> None:
        check_payload_limit(max_payload_size)
        self._max_payload_size = max_payload_size
        self._buffer = bytearray()

    @property
    def buffered_size(self) -> int:
        return len(self._buffer)

    def feed(self, received_bytes: bytes) -> list[Frame]:
        """Return complete frames, attaching any valid prefix to a later decode error."""
        if not isinstance(received_bytes, bytes):
            raise TypeError("received_bytes must be bytes")
        self._buffer.extend(received_bytes)
        frames: list[Frame] = []
        offset = 0
        buffered_size = len(self._buffer)

        while buffered_size - offset >= FRAME_HEADER_SIZE:
            extension_type, message_type, payload_size = decode_frame_header(
                bytes(self._buffer[offset:offset + FRAME_HEADER_SIZE])
            )
            if payload_size > self._max_payload_size:
                self._buffer.clear()
                raise FrameTooLargeError(
                    f"declared payload is {payload_size} bytes; configured limit is "
                    f"{self._max_payload_size}",
                    completed_frames=frames,
                )

            frame_size = FRAME_HEADER_SIZE + payload_size
            if buffered_size - offset < frame_size:
                break

            payload_start = offset + FRAME_HEADER_SIZE
            payload = bytes(self._buffer[payload_start:offset + frame_size])
            offset += frame_size
            frames.append(Frame(extension_type, message_type, payload))

        if offset:
            del self._buffer[:offset]
        return frames

    def finish(self) -> None:
        if not self._buffer:
            return
        buffered_size = len(self._buffer)
        self._buffer.clear()
        raise TruncatedFrameError(
            f"transport ended with {buffered_size} byte(s) of an incomplete SV2 frame"
        )


class PayloadWriter:
    """Append little-endian primitives to one SV2 message payload."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def to_bytes(self) -> bytes:
        return bytes(self._buffer)

    def write_u8(self, value: int) -> None:
        self._write_unsigned("U8", value, UINT8_MAX, 1)

    def write_u16(self, value: int) -> None:
        self._write_unsigned("U16", value, UINT16_MAX, 2)

    def write_u24(self, value: int) -> None:
        self._write_unsigned("U24", value, UINT24_MAX, 3)

    def write_u32(self, value: int) -> None:
        self._write_unsigned("U32", value, UINT32_MAX, 4)

    def write_u64(self, value: int) -> None:
        self._write_unsigned("U64", value, UINT64_MAX, 8)

    def write_float32(self, value: float) -> None:
        try:
            self._buffer.extend(struct.pack("<f", value))
        except (OverflowError, struct.error) as error:
            raise Sv2CodecError(f"F32 value cannot be encoded: {value!r}") from error

    def write_bool(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise TypeError("BOOL value must be bool")
        self.write_u8(1 if value else 0)

    def write_u256(self, value: bytes) -> None:
        if not isinstance(value, bytes):
            raise TypeError("U256 value must be bytes")
        if len(value) != UINT256_SIZE:
            raise Sv2CodecError(f"U256 must be exactly {UINT256_SIZE} bytes")
        self._buffer.extend(value)

    def write_b0_32(self, value: bytes) -> None:
        self._write_length_prefixed_bytes("B0_32", value, B0_32_MAX_SIZE, 1)

    def write_b0_64k(self, value: bytes) -> None:
        self._write_length_prefixed_bytes("B0_64K", value, B0_64K_MAX_SIZE, 2)

    def write_string(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("STR0_255 value must be str")
        # SV2 strings allow arbitrary bytes; surrogateescape preserves them through str.
        encoded = value.encode("utf-8", errors="surrogateescape")
        self._write_length_prefixed_bytes("STR0_255", encoded, STRING_MAX_SIZE, 1)

    def write_sequence_u256(self, values: tuple[bytes, ...]) -> None:
        if not isinstance(values, tuple):
            raise TypeError("SEQ0_255[U256] value must be a tuple")
        if len(values) > SEQUENCE_MAX_COUNT:
            raise Sv2CodecError(
                f"SEQ0_255[U256] must contain at most {SEQUENCE_MAX_COUNT} elements"
            )
        self.write_u8(len(values))
        for value in values:
            self.write_u256(value)

    def write_option_u32(self, value: int | None) -> None:
        if value is None:
            self.write_u8(0)
            return
        self.write_u8(1)
        self.write_u32(value)

    def _write_unsigned(self, name: str, value: int, maximum: int, size: int) -> None:
        _check_unsigned(name, value, maximum)
        self._buffer.extend(value.to_bytes(size, "little"))

    def _write_length_prefixed_bytes(
        self,
        name: str,
        value: bytes,
        maximum: int,
        length_size: int,
    ) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} value must be bytes")
        if len(value) > maximum:
            raise Sv2CodecError(f"{name} must contain at most {maximum} bytes")
        self._write_unsigned(f"{name} length", len(value), maximum, length_size)
        self._buffer.extend(value)


class PayloadReader:
    """Read little-endian primitives from one fixed SV2 message payload."""

    def __init__(self, payload: bytes) -> None:
        if not isinstance(payload, bytes):
            raise TypeError("payload must be bytes")
        self._payload = payload
        self._offset = 0

    @property
    def remaining_size(self) -> int:
        return len(self._payload) - self._offset

    def finish(self) -> None:
        if self.remaining_size:
            raise MessageDecodeError(
                f"message has {self.remaining_size} unexpected trailing byte(s)"
            )

    def read_u8(self) -> int:
        return int.from_bytes(self._take(1), "little")

    def read_u16(self) -> int:
        return int.from_bytes(self._take(2), "little")

    def read_u24(self) -> int:
        return int.from_bytes(self._take(3), "little")

    def read_u32(self) -> int:
        return int.from_bytes(self._take(4), "little")

    def read_u64(self) -> int:
        return int.from_bytes(self._take(8), "little")

    def read_float32(self) -> float:
        return struct.unpack("<f", self._take(4))[0]

    def read_bool(self) -> bool:
        return bool(self.read_u8() & 1)

    def read_u256(self) -> bytes:
        return self._take(UINT256_SIZE)

    def read_b0_32(self) -> bytes:
        size = self.read_u8()
        if size > B0_32_MAX_SIZE:
            raise MessageDecodeError(
                f"B0_32 declares {size} bytes; maximum is {B0_32_MAX_SIZE}"
            )
        return self._take(size)

    def read_b0_64k(self) -> bytes:
        return self._take(self.read_u16())

    def read_string(self) -> str:
        encoded = self._take(self.read_u8())
        return encoded.decode("utf-8", errors="surrogateescape")

    def read_sequence_u256(self) -> tuple[bytes, ...]:
        return tuple(self.read_u256() for _ in range(self.read_u8()))

    def read_option_u32(self) -> int | None:
        count = self.read_u8()
        if count == 0:
            return None
        if count == 1:
            return self.read_u32()
        raise MessageDecodeError(f"OPTION[U32] count must be 0 or 1, got {count}")

    def _take(self, size: int) -> bytes:
        end = self._offset + size
        if end > len(self._payload):
            raise MessageDecodeError(
                f"truncated payload: need {size} byte(s), have {self.remaining_size}"
            )
        value = self._payload[self._offset:end]
        self._offset = end
        return value


def encode_frame(
    frame: Frame,
    max_payload_size: int = DEFAULT_MAX_FRAME_PAYLOAD_SIZE,
) -> bytes:
    """Encode one plaintext SV2 frame after applying the local payload limit."""
    check_payload_limit(max_payload_size)
    payload_size = len(frame.payload)
    if payload_size > max_payload_size:
        raise FrameTooLargeError(
            f"payload is {payload_size} bytes; configured limit is {max_payload_size}"
        )
    return (
        frame.extension_type.to_bytes(2, "little")
        + frame.message_type.to_bytes(1, "little")
        + payload_size.to_bytes(3, "little")
        + frame.payload
    )


def decode_frame_header(header: bytes) -> tuple[int, int, int]:
    """Decode ``(extension_type, message_type, payload_size)`` from six bytes."""
    if len(header) != FRAME_HEADER_SIZE:
        raise MessageDecodeError(
            f"frame header must be exactly {FRAME_HEADER_SIZE} bytes, got {len(header)}"
        )
    extension_type = int.from_bytes(header[0:2], "little")
    message_type = header[2]
    payload_size = int.from_bytes(header[3:6], "little")
    return extension_type, message_type, payload_size


def _check_unsigned(name: str, value: int, maximum: int) -> None:
    if not isinstance(value, int):
        raise TypeError(f"{name} value must be int")
    if not 0 <= value <= maximum:
        raise Sv2CodecError(f"{name} value must be between 0 and {maximum}")
