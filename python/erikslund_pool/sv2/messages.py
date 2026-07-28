"""Typed wire representations for the supported Stratum V2 common and mining messages."""

from __future__ import annotations

import dataclasses
import typing

from erikslund_pool.sv2 import codec as sv2_codec

CORE_EXTENSION_ID = 0
MINING_PROTOCOL = 0
PROTOCOL_VERSION = 2
REQUIRES_STANDARD_JOBS_FLAG = 1 << 0
REQUIRES_VERSION_ROLLING_FLAG = 1 << 2
REQUIRES_FIXED_VERSION_FLAG = 1 << 0


class UnsupportedMessageError(sv2_codec.MessageDecodeError):
    pass


class WireMessage(typing.Protocol):
    MESSAGE_TYPE: typing.ClassVar[int]
    CHANNEL_MESSAGE: typing.ClassVar[bool]

    def encode_payload(self) -> bytes:
        """Encode the message-specific bytes without the six-byte frame header."""

    @classmethod
    def decode_payload(cls, payload: bytes) -> typing.Self:
        ...


@dataclasses.dataclass(frozen=True, slots=True)
class SetupConnection:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x00
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

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

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u8(self.protocol)
        writer.write_u16(self.min_version)
        writer.write_u16(self.max_version)
        writer.write_u32(self.flags)
        writer.write_string(self.endpoint_host)
        writer.write_u16(self.endpoint_port)
        writer.write_string(self.vendor)
        writer.write_string(self.hardware_version)
        writer.write_string(self.firmware)
        writer.write_string(self.device_id)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SetupConnection:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            protocol=reader.read_u8(),
            min_version=reader.read_u16(),
            max_version=reader.read_u16(),
            flags=reader.read_u32(),
            endpoint_host=reader.read_string(),
            endpoint_port=reader.read_u16(),
            vendor=reader.read_string(),
            hardware_version=reader.read_string(),
            firmware=reader.read_string(),
            device_id=reader.read_string(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SetupConnectionSuccess:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x01
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    used_version: int
    flags: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u16(self.used_version)
        writer.write_u32(self.flags)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SetupConnectionSuccess:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(used_version=reader.read_u16(), flags=reader.read_u32())
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SetupConnectionError:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x02
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    flags: int
    error_code: str

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.flags)
        writer.write_string(self.error_code)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SetupConnectionError:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(flags=reader.read_u32(), error_code=reader.read_string())
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class OpenStandardMiningChannel:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x10
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    request_id: int
    user_identity: str
    nominal_hash_rate: float
    max_target: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.request_id)
        writer.write_string(self.user_identity)
        writer.write_float32(self.nominal_hash_rate)
        writer.write_u256(self.max_target)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> OpenStandardMiningChannel:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            request_id=reader.read_u32(),
            user_identity=reader.read_string(),
            nominal_hash_rate=reader.read_float32(),
            max_target=reader.read_u256(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class OpenStandardMiningChannelSuccess:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x11
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    request_id: int
    channel_id: int
    target: bytes
    extranonce_prefix: bytes
    group_channel_id: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.request_id)
        writer.write_u32(self.channel_id)
        writer.write_u256(self.target)
        writer.write_b0_32(self.extranonce_prefix)
        writer.write_u32(self.group_channel_id)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> OpenStandardMiningChannelSuccess:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            request_id=reader.read_u32(),
            channel_id=reader.read_u32(),
            target=reader.read_u256(),
            extranonce_prefix=reader.read_b0_32(),
            group_channel_id=reader.read_u32(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class OpenMiningChannelError:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x12
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    request_id: int
    error_code: str

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.request_id)
        writer.write_string(self.error_code)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> OpenMiningChannelError:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(request_id=reader.read_u32(), error_code=reader.read_string())
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class OpenExtendedMiningChannel:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x13
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    request_id: int
    user_identity: str
    nominal_hash_rate: float
    max_target: bytes
    min_extranonce_size: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.request_id)
        writer.write_string(self.user_identity)
        writer.write_float32(self.nominal_hash_rate)
        writer.write_u256(self.max_target)
        writer.write_u16(self.min_extranonce_size)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> OpenExtendedMiningChannel:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            request_id=reader.read_u32(),
            user_identity=reader.read_string(),
            nominal_hash_rate=reader.read_float32(),
            max_target=reader.read_u256(),
            min_extranonce_size=reader.read_u16(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class OpenExtendedMiningChannelSuccess:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x14
    CHANNEL_MESSAGE: typing.ClassVar[bool] = False

    request_id: int
    channel_id: int
    target: bytes
    extranonce_size: int
    extranonce_prefix: bytes
    group_channel_id: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.request_id)
        writer.write_u32(self.channel_id)
        writer.write_u256(self.target)
        writer.write_u16(self.extranonce_size)
        writer.write_b0_32(self.extranonce_prefix)
        writer.write_u32(self.group_channel_id)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> OpenExtendedMiningChannelSuccess:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            request_id=reader.read_u32(),
            channel_id=reader.read_u32(),
            target=reader.read_u256(),
            extranonce_size=reader.read_u16(),
            extranonce_prefix=reader.read_b0_32(),
            group_channel_id=reader.read_u32(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class NewMiningJob:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x15
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    job_id: int
    min_ntime: int | None
    version: int
    merkle_root: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.job_id)
        writer.write_option_u32(self.min_ntime)
        writer.write_u32(self.version)
        writer.write_u256(self.merkle_root)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> NewMiningJob:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            job_id=reader.read_u32(),
            min_ntime=reader.read_option_u32(),
            version=reader.read_u32(),
            merkle_root=reader.read_u256(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class UpdateChannel:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x16
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    nominal_hash_rate: float
    maximum_target: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_float32(self.nominal_hash_rate)
        writer.write_u256(self.maximum_target)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> UpdateChannel:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            nominal_hash_rate=reader.read_float32(),
            maximum_target=reader.read_u256(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class UpdateChannelError:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x17
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    error_code: str

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_string(self.error_code)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> UpdateChannelError:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(channel_id=reader.read_u32(), error_code=reader.read_string())
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class CloseChannel:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x18
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    reason_code: str

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_string(self.reason_code)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> CloseChannel:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(channel_id=reader.read_u32(), reason_code=reader.read_string())
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SetExtranoncePrefix:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x19
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    extranonce_prefix: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_b0_32(self.extranonce_prefix)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SetExtranoncePrefix:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            extranonce_prefix=reader.read_b0_32(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SetNewPrevHash:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x20
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    job_id: int
    prev_hash: bytes
    min_ntime: int
    nbits: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.job_id)
        writer.write_u256(self.prev_hash)
        writer.write_u32(self.min_ntime)
        writer.write_u32(self.nbits)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SetNewPrevHash:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            job_id=reader.read_u32(),
            prev_hash=reader.read_u256(),
            min_ntime=reader.read_u32(),
            nbits=reader.read_u32(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SetTarget:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x21
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    maximum_target: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u256(self.maximum_target)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SetTarget:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(channel_id=reader.read_u32(), maximum_target=reader.read_u256())
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SubmitSharesStandard:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x1A
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    sequence_number: int
    job_id: int
    nonce: int
    ntime: int
    version: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.sequence_number)
        writer.write_u32(self.job_id)
        writer.write_u32(self.nonce)
        writer.write_u32(self.ntime)
        writer.write_u32(self.version)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SubmitSharesStandard:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            sequence_number=reader.read_u32(),
            job_id=reader.read_u32(),
            nonce=reader.read_u32(),
            ntime=reader.read_u32(),
            version=reader.read_u32(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SubmitSharesExtended:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x1B
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    sequence_number: int
    job_id: int
    nonce: int
    ntime: int
    version: int
    extranonce: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.sequence_number)
        writer.write_u32(self.job_id)
        writer.write_u32(self.nonce)
        writer.write_u32(self.ntime)
        writer.write_u32(self.version)
        writer.write_b0_32(self.extranonce)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SubmitSharesExtended:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            sequence_number=reader.read_u32(),
            job_id=reader.read_u32(),
            nonce=reader.read_u32(),
            ntime=reader.read_u32(),
            version=reader.read_u32(),
            extranonce=reader.read_b0_32(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SubmitSharesSuccess:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x1C
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    last_sequence_number: int
    new_submits_accepted_count: int
    new_shares_sum: int

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.last_sequence_number)
        writer.write_u32(self.new_submits_accepted_count)
        writer.write_u64(self.new_shares_sum)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SubmitSharesSuccess:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            last_sequence_number=reader.read_u32(),
            new_submits_accepted_count=reader.read_u32(),
            new_shares_sum=reader.read_u64(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class SubmitSharesError:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x1D
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    sequence_number: int
    error_code: str

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.sequence_number)
        writer.write_string(self.error_code)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> SubmitSharesError:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            sequence_number=reader.read_u32(),
            error_code=reader.read_string(),
        )
        reader.finish()
        return message


@dataclasses.dataclass(frozen=True, slots=True)
class NewExtendedMiningJob:
    MESSAGE_TYPE: typing.ClassVar[int] = 0x1F
    CHANNEL_MESSAGE: typing.ClassVar[bool] = True

    channel_id: int
    job_id: int
    min_ntime: int | None
    version: int
    version_rolling_allowed: bool
    merkle_path: tuple[bytes, ...]
    coinbase_tx_prefix: bytes
    coinbase_tx_suffix: bytes

    def encode_payload(self) -> bytes:
        writer = sv2_codec.PayloadWriter()
        writer.write_u32(self.channel_id)
        writer.write_u32(self.job_id)
        writer.write_option_u32(self.min_ntime)
        writer.write_u32(self.version)
        writer.write_bool(self.version_rolling_allowed)
        writer.write_sequence_u256(self.merkle_path)
        writer.write_b0_64k(self.coinbase_tx_prefix)
        writer.write_b0_64k(self.coinbase_tx_suffix)
        return writer.to_bytes()

    @classmethod
    def decode_payload(cls, payload: bytes) -> NewExtendedMiningJob:
        reader = sv2_codec.PayloadReader(payload)
        message = cls(
            channel_id=reader.read_u32(),
            job_id=reader.read_u32(),
            min_ntime=reader.read_option_u32(),
            version=reader.read_u32(),
            version_rolling_allowed=reader.read_bool(),
            merkle_path=reader.read_sequence_u256(),
            coinbase_tx_prefix=reader.read_b0_64k(),
            coinbase_tx_suffix=reader.read_b0_64k(),
        )
        reader.finish()
        return message


type Message = (
    SetupConnection
    | SetupConnectionSuccess
    | SetupConnectionError
    | OpenStandardMiningChannel
    | OpenStandardMiningChannelSuccess
    | OpenMiningChannelError
    | OpenExtendedMiningChannel
    | OpenExtendedMiningChannelSuccess
    | NewMiningJob
    | UpdateChannel
    | UpdateChannelError
    | CloseChannel
    | SetExtranoncePrefix
    | SetNewPrevHash
    | SetTarget
    | SubmitSharesStandard
    | SubmitSharesExtended
    | SubmitSharesSuccess
    | SubmitSharesError
    | NewExtendedMiningJob
)


MESSAGE_CLASSES_BY_TYPE: dict[int, type[WireMessage]] = {
    message_class.MESSAGE_TYPE: message_class
    for message_class in (
        SetupConnection,
        SetupConnectionSuccess,
        SetupConnectionError,
        OpenStandardMiningChannel,
        OpenStandardMiningChannelSuccess,
        OpenMiningChannelError,
        OpenExtendedMiningChannel,
        OpenExtendedMiningChannelSuccess,
        NewMiningJob,
        UpdateChannel,
        UpdateChannelError,
        CloseChannel,
        SetExtranoncePrefix,
        SetNewPrevHash,
        SetTarget,
        SubmitSharesStandard,
        SubmitSharesExtended,
        SubmitSharesSuccess,
        SubmitSharesError,
        NewExtendedMiningJob,
    )
}


def encode_message(message: WireMessage) -> sv2_codec.Frame:
    extension_type = (
        sv2_codec.CHANNEL_MESSAGE_BIT if message.CHANNEL_MESSAGE else CORE_EXTENSION_ID
    )
    return sv2_codec.Frame(
        extension_type=extension_type,
        message_type=message.MESSAGE_TYPE,
        payload=message.encode_payload(),
    )


def decode_message(frame: sv2_codec.Frame) -> Message:
    if frame.extension_id != CORE_EXTENSION_ID:
        raise UnsupportedMessageError(
            f"unsupported extension identifier 0x{frame.extension_id:04x}"
        )

    message_class = MESSAGE_CLASSES_BY_TYPE.get(frame.message_type)
    if message_class is None:
        raise UnsupportedMessageError(f"unsupported message type 0x{frame.message_type:02x}")
    if frame.channel_message != message_class.CHANNEL_MESSAGE:
        raise sv2_codec.MessageDecodeError(
            f"message type 0x{frame.message_type:02x} has the wrong channel routing bit"
        )
    return typing.cast(Message, message_class.decode_payload(frame.payload))
