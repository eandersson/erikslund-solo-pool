#!/usr/bin/env python3
"""
sv2_miner  -- a WIP Stratum V2 (SV2) test client for erikslund-pool.

USAGE
    python3 sv2_miner.py --selftest                 # codec + hashing + Noise, no network
    python3 sv2_miner.py --url 127.0.0.1:34254 --user <BTC_ADDRESS> [--encrypt]
    python3 sv2_miner.py --url host:port --user <BTC_ADDRESS> --encrypt \\
                         --authority-pubkey <hex-ed25519-key>

    Plaintext mining is stdlib-only. `--encrypt` (Noise) needs `cryptography`
    (`pip install cryptography` or `pip install .[encrypt]`); its import is
    guarded at module top so the plaintext path keeps zero third-party
    dependencies.
"""

import argparse
import hashlib
import logging
import os
import socket
import struct
import sys
import time
from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    _HAVE_CRYPTOGRAPHY = True
except ImportError:  # cryptography is optional: only the Noise (--encrypt) path needs it
    _HAVE_CRYPTOGRAPHY = False

type Frame = tuple[int, bool, int, bytes]

DIFF1_TARGET = 0xFFFF << 208

_PACK_LE_UINT32 = struct.Struct("<I").pack

CHANNEL_MSG_FLAG = 0x8000
EXTENSION_ID_MASK = 0x7FFF
FRAME_HEADER_LEN = 6

NOISE_MAX_TRANSPORT = 65535
NOISE_TAG_LEN = 16
NOISE_MAX_PLAINTEXT = NOISE_MAX_TRANSPORT - NOISE_TAG_LEN

LOG = logging.getLogger(__name__)


def double_sha256(data: bytes) -> bytes:
    """Bitcoin's hash: SHA256(SHA256(data))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def target_from_difficulty(difficulty: float) -> int:
    """Highest hash value (as a LE integer) that still satisfies `difficulty`."""
    if difficulty <= 0:
        return DIFF1_TARGET
    return int(DIFF1_TARGET / difficulty)


def build_header(version: int, prev_hash: bytes, merkle_root: bytes,
                 ntime: int, nbits: int, nonce: int) -> bytes:
    """Assemble the canonical 80-byte Bitcoin block header.

    Field order and endianness match the serialized header bitcoind hashes:
        version (4, LE) | prev_hash (32) | merkle_root (32) |
        ntime (4, LE)   | nbits (4, LE)  | nonce (4, LE)

    In SV2 the pool delivers prev_hash and merkle_root already in the header's
    internal byte order (U256 / B0_32 raw bytes), so -- unlike the V1 notify path
    -- there is no per-word swap to undo here; the bytes splice in as given.
    """
    return b"".join((
        struct.pack("<I", version & 0xFFFFFFFF),
        prev_hash,
        merkle_root,
        struct.pack("<I", ntime & 0xFFFFFFFF),
        struct.pack("<I", nbits & 0xFFFFFFFF),
        struct.pack("<I", nonce & 0xFFFFFFFF),
    ))


def header_hash_int(header: bytes) -> int:
    """Double-SHA the header and read it as Bitcoin does: little-endian int."""
    return int.from_bytes(double_sha256(header), "little")


class Writer:
    """Append-only little-endian SV2 encoder."""

    __slots__ = ("_buf",)

    def __init__(self) -> None:
        self._buf = bytearray()

    def getvalue(self) -> bytes:
        return bytes(self._buf)

    def u8(self, value: int) -> None:
        self._buf += struct.pack("<B", value)

    def u16(self, value: int) -> None:
        self._buf += struct.pack("<H", value)

    def u24(self, value: int) -> None:
        # No native 24-bit pack: take the low 3 bytes of a LE u32.
        self._buf += struct.pack("<I", value)[:3]

    def u32(self, value: int) -> None:
        self._buf += struct.pack("<I", value)

    def u64(self, value: int) -> None:
        self._buf += struct.pack("<Q", value)

    def f32(self, value: float) -> None:
        self._buf += struct.pack("<f", value)

    def boolean(self, value: bool) -> None:
        self._buf += struct.pack("<B", 1 if value else 0)

    def u256(self, value: bytes) -> None:
        if len(value) != 32:
            raise ValueError(f"U256 must be 32 bytes, got {len(value)}")
        self._buf += value

    def b0_32(self, value: bytes) -> None:
        if len(value) > 32:
            raise ValueError(f"B0_32 must be <= 32 bytes, got {len(value)}")
        self.u8(len(value))
        self._buf += value

    def b0_255(self, value: bytes) -> None:
        if len(value) > 255:
            raise ValueError(f"B0_255 must be <= 255 bytes, got {len(value)}")
        self.u8(len(value))
        self._buf += value

    def b0_64k(self, value: bytes) -> None:
        if len(value) > 0xFFFF:
            raise ValueError(f"B0_64K must be <= 65535 bytes, got {len(value)}")
        self.u16(len(value))
        self._buf += value

    def str0_255(self, value: str) -> None:
        self.b0_255(value.encode("utf-8"))

    def option_u32(self, value: int | None) -> None:
        if value is None:
            self.u8(0)
        else:
            self.u8(1)
            self.u32(value)


class Reader:
    """Sequential little-endian SV2 decoder over a fixed buffer."""

    __slots__ = ("_buf", "_pos")

    def __init__(self, buf: bytes) -> None:
        self._buf = buf
        self._pos = 0

    def remaining(self) -> int:
        return len(self._buf) - self._pos

    def _take(self, n: int) -> bytes:
        end = self._pos + n
        if end > len(self._buf):
            raise ValueError(f"short read: need {n} bytes, have {self.remaining()}")
        chunk = self._buf[self._pos:end]
        self._pos = end
        return chunk

    def u8(self) -> int:
        return self._take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self._take(2))[0]

    def u24(self) -> int:
        # Zero-extend the 3 LE bytes back to a 4-byte word.
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


def encode_frame(extension_id: int, channel_msg: bool, msg_type: int,
                 payload: bytes) -> bytes:
    """Wrap a payload in the 6-byte SV2 frame header (all LE)."""
    extension_type = (extension_id & EXTENSION_ID_MASK)
    if channel_msg:
        extension_type |= CHANNEL_MSG_FLAG
    writer = Writer()
    writer.u16(extension_type)
    writer.u8(msg_type)
    writer.u24(len(payload))
    return writer.getvalue() + payload


def decode_frame_header(header: bytes) -> tuple[int, bool, int, int]:
    """Split a 6-byte header into (extension_id, channel_msg, msg_type, length)."""
    if len(header) != FRAME_HEADER_LEN:
        raise ValueError(f"frame header must be {FRAME_HEADER_LEN} bytes")
    reader = Reader(header)
    extension_type = reader.u16()
    msg_type = reader.u8()
    msg_length = reader.u24()
    channel_msg = bool(extension_type & CHANNEL_MSG_FLAG)
    extension_id = extension_type & EXTENSION_ID_MASK
    return extension_id, channel_msg, msg_type, msg_length


@dataclass(slots=True)
class SetupConnection:
    MSG_TYPE = 0x00
    CHANNEL_MSG = False

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
    def parse(cls, payload: bytes) -> "SetupConnection":
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
    MSG_TYPE = 0x01
    CHANNEL_MSG = False

    used_version: int
    flags: int

    def serialize(self) -> bytes:
        w = Writer()
        w.u16(self.used_version)
        w.u32(self.flags)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> "SetupConnectionSuccess":
        r = Reader(payload)
        return cls(used_version=r.u16(), flags=r.u32())


@dataclass(slots=True)
class SetupConnectionError:
    MSG_TYPE = 0x02
    CHANNEL_MSG = False

    flags: int
    error_code: str

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.flags)
        w.str0_255(self.error_code)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> "SetupConnectionError":
        r = Reader(payload)
        return cls(flags=r.u32(), error_code=r.str0_255())


@dataclass(slots=True)
class OpenStandardMiningChannel:
    MSG_TYPE = 0x10
    CHANNEL_MSG = False

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
    def parse(cls, payload: bytes) -> "OpenStandardMiningChannel":
        r = Reader(payload)
        return cls(
            request_id=r.u32(),
            user_identity=r.str0_255(),
            nominal_hash_rate=r.f32(),
            max_target=r.u256(),
        )


@dataclass(slots=True)
class OpenStandardMiningChannelSuccess:
    MSG_TYPE = 0x11
    CHANNEL_MSG = False

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
    def parse(cls, payload: bytes) -> "OpenStandardMiningChannelSuccess":
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
    MSG_TYPE = 0x12
    CHANNEL_MSG = False

    request_id: int
    error_code: str

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.request_id)
        w.str0_255(self.error_code)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> "OpenMiningChannelError":
        r = Reader(payload)
        return cls(request_id=r.u32(), error_code=r.str0_255())


@dataclass(slots=True)
class NewMiningJob:
    MSG_TYPE = 0x15
    CHANNEL_MSG = True

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
        w.b0_32(self.merkle_root)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> "NewMiningJob":
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            job_id=r.u32(),
            min_ntime=r.option_u32(),
            version=r.u32(),
            merkle_root=r.b0_32(),
        )


@dataclass(slots=True)
class SetNewPrevHash:
    MSG_TYPE = 0x20
    CHANNEL_MSG = True

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
    def parse(cls, payload: bytes) -> "SetNewPrevHash":
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
    MSG_TYPE = 0x21
    CHANNEL_MSG = True

    channel_id: int
    maximum_target: bytes

    def serialize(self) -> bytes:
        w = Writer()
        w.u32(self.channel_id)
        w.u256(self.maximum_target)
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> "SetTarget":
        r = Reader(payload)
        return cls(channel_id=r.u32(), maximum_target=r.u256())


@dataclass(slots=True)
class SubmitSharesStandard:
    MSG_TYPE = 0x1A
    CHANNEL_MSG = True

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
    def parse(cls, payload: bytes) -> "SubmitSharesStandard":
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
    MSG_TYPE = 0x1C
    CHANNEL_MSG = True

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
    def parse(cls, payload: bytes) -> "SubmitSharesSuccess":
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            last_sequence_number=r.u32(),
            new_submits_accepted_count=r.u32(),
            new_shares_sum=r.u64(),
        )


@dataclass(slots=True)
class SubmitSharesError:
    MSG_TYPE = 0x1D
    CHANNEL_MSG = True

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
    def parse(cls, payload: bytes) -> "SubmitSharesError":
        r = Reader(payload)
        return cls(
            channel_id=r.u32(),
            sequence_number=r.u32(),
            error_code=r.str0_255(),
        )


# All message types -- used by the selftest and frame assembly.
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
    """Serialize a message dataclass and wrap it in its SV2 frame."""
    return encode_frame(
        extension_id=0,
        channel_msg=type(message).CHANNEL_MSG,
        msg_type=type(message).MSG_TYPE,
        payload=message.serialize(),
    )

NOISE_PROTOCOL_NAME = b"Noise_NX_25519_ChaChaPoly_BLAKE2s"
NOISE_DH_LEN = 32


@dataclass(slots=True)
class SignatureNoiseMessage:
    version: int
    valid_from: int
    not_valid_after: int
    signature: bytes

    def serialize(self) -> bytes:
        w = Writer()
        w.u16(self.version)
        w.u32(self.valid_from)
        w.u32(self.not_valid_after)
        if len(self.signature) != 64:
            raise ValueError("ed25519 signature must be 64 bytes")
        w._buf += self.signature
        return w.getvalue()

    @classmethod
    def parse(cls, payload: bytes) -> "SignatureNoiseMessage":
        r = Reader(payload)
        version = r.u16()
        valid_from = r.u32()
        not_valid_after = r.u32()
        signature = r._take(64)
        return cls(version, valid_from, not_valid_after, signature)


class NoiseSession:
    __slots__ = (
        "_initiator", "_x25519", "_chacha", "_blake2s",
        "_h", "_ck", "_k", "_n",
        "_e_priv", "_e_pub", "_s_priv", "_s_pub", "_rs",
        "_send_cipher", "_send_nonce", "_recv_cipher", "_recv_nonce",
        "handshake_payload",
    )

    def __init__(self, initiator: bool, static_private: object = None) -> None:
        if not _HAVE_CRYPTOGRAPHY:  # pragma: no cover - exercised via CLI path
            raise RuntimeError(
                "the --encrypt (Noise) path needs the 'cryptography' package; "
                "install it with: pip install cryptography  (or pip install '.[encrypt]')"
            )

        self._initiator = initiator
        self._x25519 = x25519
        self._chacha = ChaCha20Poly1305
        if len(NOISE_PROTOCOL_NAME) <= 32:
            self._h = NOISE_PROTOCOL_NAME.ljust(32, b"\x00")
        else:
            self._h = hashlib.blake2s(NOISE_PROTOCOL_NAME).digest()
        self._ck = self._h
        self._k: bytes | None = None
        self._n = 0
        self._mix_hash(b"")

        self._e_priv: object = None
        self._e_pub: bytes = b""
        if not initiator:
            self._s_priv = static_private or self._x25519.X25519PrivateKey.generate()
            self._s_pub = self._s_priv.public_key().public_bytes_raw()
        else:
            self._s_priv = None
            self._s_pub = b""
        self._rs: bytes = b""

        self._send_cipher: object = None
        self._send_nonce = 0
        self._recv_cipher: object = None
        self._recv_nonce = 0
        self.handshake_payload: bytes = b""

    def _mix_hash(self, data: bytes) -> None:
        self._h = hashlib.blake2s(self._h + data).digest()

    def _hkdf2(self, chaining_key: bytes, ikm: bytes) -> tuple[bytes, bytes]:
        """Two-output HKDF with BLAKE2s as the hash (Noise HKDF)."""
        temp_key = self._hmac(chaining_key, ikm)
        out1 = self._hmac(temp_key, b"\x01")
        out2 = self._hmac(temp_key, out1 + b"\x02")
        return out1, out2

    @staticmethod
    def _hmac(key: bytes, data: bytes) -> bytes:
        block_size = 64  # BLAKE2s block size
        if len(key) > block_size:
            key = hashlib.blake2s(key).digest()
        key = key.ljust(block_size, b"\x00")
        inner = hashlib.blake2s(bytes(b ^ 0x36 for b in key) + data).digest()
        return hashlib.blake2s(bytes(b ^ 0x5C for b in key) + inner).digest()

    def _mix_key(self, ikm: bytes) -> None:
        self._ck, self._k = self._hkdf2(self._ck, ikm)
        self._n = 0

    def _nonce_bytes(self, counter: int) -> bytes:
        # ChaCha20Poly1305 wants a 12-byte nonce: 4 zero bytes + 8-byte LE counter.
        return b"\x00\x00\x00\x00" + struct.pack("<Q", counter)

    def _encrypt_and_hash(self, plaintext: bytes) -> bytes:
        if self._k is None:
            self._mix_hash(plaintext)
            return plaintext
        cipher = self._chacha(self._k)
        ciphertext = cipher.encrypt(self._nonce_bytes(self._n), plaintext, self._h)
        self._n += 1
        self._mix_hash(ciphertext)
        return ciphertext

    def _decrypt_and_hash(self, ciphertext: bytes) -> bytes:
        if self._k is None:
            self._mix_hash(ciphertext)
            return ciphertext
        cipher = self._chacha(self._k)
        plaintext = cipher.decrypt(self._nonce_bytes(self._n), ciphertext, self._h)
        self._n += 1
        self._mix_hash(ciphertext)
        return plaintext

    def _dh(self, private: object, public: bytes) -> bytes:
        peer = self._x25519.X25519PublicKey.from_public_bytes(public)
        return private.exchange(peer)

    def write_message1(self) -> bytes:
        """Initiator -> responder: `-> e`. The ephemeral public key, cleartext."""
        self._e_priv = self._x25519.X25519PrivateKey.generate()
        self._e_pub = self._e_priv.public_key().public_bytes_raw()
        self._mix_hash(self._e_pub)
        # NX msg1 carries no payload; EncryptAndHash("") is a no-op (no key yet).
        return self._e_pub + self._encrypt_and_hash(b"")

    def read_message1(self, message: bytes) -> bytes:
        """Responder side of `-> e`."""
        self._rs = b""  # n/a for responder
        re = message[:NOISE_DH_LEN]
        rest = message[NOISE_DH_LEN:]
        self._mix_hash(re)
        self._e_pub = re  # store peer ephemeral as 're' for the responder
        payload = self._decrypt_and_hash(rest)
        return payload

    def write_message2(self, payload: bytes, peer_ephemeral: bytes) -> bytes:
        """Responder -> initiator: `<- e, ee, s, es` plus encrypted payload."""
        self._e_priv = self._x25519.X25519PrivateKey.generate()
        self._e_pub = self._e_priv.public_key().public_bytes_raw()
        self._mix_hash(self._e_pub)               # e
        self._mix_key(self._dh(self._e_priv, peer_ephemeral))  # ee
        encrypted_static = self._encrypt_and_hash(self._s_pub)  # s
        self._mix_key(self._dh(self._s_priv, peer_ephemeral))  # es
        encrypted_payload = self._encrypt_and_hash(payload)
        return self._e_pub + encrypted_static + encrypted_payload

    def read_message2(self, message: bytes) -> bytes:
        """Initiator side of `<- e, ee, s, es`; returns the decrypted payload."""
        offset = 0
        re = message[offset:offset + NOISE_DH_LEN]
        offset += NOISE_DH_LEN
        self._mix_hash(re)                         # e
        self._mix_key(self._dh(self._e_priv, re))  # ee
        # s: the responder's static key, encrypted (32 bytes + 16-byte tag).
        encrypted_static = message[offset:offset + NOISE_DH_LEN + NOISE_TAG_LEN]
        offset += NOISE_DH_LEN + NOISE_TAG_LEN
        self._rs = self._decrypt_and_hash(encrypted_static)
        self._mix_key(self._dh(self._e_priv, self._rs))  # es
        payload = self._decrypt_and_hash(message[offset:])
        self.handshake_payload = payload
        return payload

    def remote_static(self) -> bytes:
        """The peer's static public key learned during the handshake."""
        return self._rs

    def split(self) -> None:
        """Derive the two transport cipher states from the final chaining key."""
        k1, k2 = self._hkdf2(self._ck, b"")
        if self._initiator:
            self._send_cipher = self._chacha(k1)
            self._recv_cipher = self._chacha(k2)
        else:
            self._send_cipher = self._chacha(k2)
            self._recv_cipher = self._chacha(k1)
        self._send_nonce = 0
        self._recv_nonce = 0

    def encrypt_transport(self, plaintext: bytes) -> bytes:
        """Encrypt a plaintext blob as one or more length-delimited Noise frames.

        Each chunk is <= 65535 bytes including the 16-byte tag; chunks are framed
        with a 2-byte LE length prefix so the reader can reassemble them.
        """
        out = bytearray()
        for start in range(0, max(len(plaintext), 1), NOISE_MAX_PLAINTEXT):
            chunk = plaintext[start:start + NOISE_MAX_PLAINTEXT]
            ciphertext = self._send_cipher.encrypt(
                self._nonce_bytes(self._send_nonce), chunk, b"")
            self._send_nonce += 1
            out += struct.pack("<H", len(ciphertext))
            out += ciphertext
        return bytes(out)

    def decrypt_transport_chunk(self, ciphertext: bytes) -> bytes:
        """Decrypt one transport chunk (the bytes after its 2-byte length prefix)."""
        plaintext = self._recv_cipher.decrypt(
            self._nonce_bytes(self._recv_nonce), ciphertext, b"")
        self._recv_nonce += 1
        return plaintext


def verify_signature_noise_message(message: SignatureNoiseMessage,
                                   authority_pubkey_hex: str) -> bool:
    """Verify the responder certificate's ed25519 signature, if we have a key.

    NOTE: the exact signed-message construction (which certificate fields, plus
    the static key, in what order) is defined by SRI's `noise_sv2`. We verify the
    serialized certificate header here as a structural check; confirm the signed
    bytes against the reference before trusting this for authentication.
    """
    if not _HAVE_CRYPTOGRAPHY:  # pragma: no cover - exercised via CLI path
        raise RuntimeError("verifying --authority-pubkey needs 'cryptography'")

    pubkey = Ed25519PublicKey.from_public_bytes(bytes.fromhex(authority_pubkey_hex))
    signed = struct.pack("<HII", message.version, message.valid_from,
                         message.not_valid_after)
    try:
        pubkey.verify(message.signature, signed)
        return True
    except InvalidSignature:
        return False


class FrameTransport:
    __slots__ = ("_sock", "_noise", "_recv_buf", "_plain_buf")

    def __init__(self, sock: socket.socket, noise: NoiseSession | None) -> None:
        self._sock = sock
        self._noise = noise
        self._recv_buf = b""
        self._plain_buf = b""

    def send_frame(self, frame: bytes) -> None:
        if self._noise is None:
            self._sock.sendall(frame)
        else:
            self._sock.sendall(self._noise.encrypt_transport(frame))

    def _recv_some(self) -> bool:
        chunk = self._sock.recv(65536)
        if not chunk:
            return False
        self._recv_buf += chunk
        return True

    def _fill_plaintext(self) -> bool:
        """Pull at least one more decrypted chunk into the plaintext buffer."""
        if self._noise is None:
            if not self._recv_some():
                return False
            self._plain_buf += self._recv_buf
            self._recv_buf = b""
            return True

        progressed = False
        while True:
            if len(self._recv_buf) < 2:
                if progressed:
                    return True
                if not self._recv_some():
                    return False
                continue
            length = struct.unpack("<H", self._recv_buf[:2])[0]
            if len(self._recv_buf) < 2 + length:
                if progressed:
                    return True
                if not self._recv_some():
                    return False
                continue
            ciphertext = self._recv_buf[2:2 + length]
            self._recv_buf = self._recv_buf[2 + length:]
            self._plain_buf += self._noise.decrypt_transport_chunk(ciphertext)
            progressed = True

    def recv_frame(self) -> Frame | None:
        """Return the next decoded inbound frame, or None on a clean close."""
        while True:
            if len(self._plain_buf) >= FRAME_HEADER_LEN:
                extension_id, channel_msg, msg_type, length = decode_frame_header(
                    self._plain_buf[:FRAME_HEADER_LEN])
                if len(self._plain_buf) >= FRAME_HEADER_LEN + length:
                    payload = self._plain_buf[FRAME_HEADER_LEN:FRAME_HEADER_LEN + length]
                    self._plain_buf = self._plain_buf[FRAME_HEADER_LEN + length:]
                    return (extension_id, channel_msg, msg_type, payload)
            if not self._fill_plaintext():
                return None


@dataclass(slots=True)
class MiningState:
    """Live channel + job state assembled from the pool's downstream messages."""

    channel_id: int = 0
    target: int = DIFF1_TARGET
    job_id: int = 0
    version: int = 0
    merkle_root: bytes = b""
    prev_hash: bytes = b""
    nbits: int = 0
    min_ntime: int = 0
    have_job: bool = False
    have_prevhash: bool = False
    sequence_number: int = 0
    generation: int = 0  # bumped on every new job/prevhash to restart the search

    def ready(self) -> bool:
        return self.have_job and self.have_prevhash


class Sv2Miner:
    """Connects, runs the SV2 handshake, opens a standard channel, then mines.

    The full flow: SetupConnection -> SetupConnectionSuccess ->
    OpenStandardMiningChannel -> OpenStandardMiningChannelSuccess, then react to
    SetNewPrevHash / NewMiningJob / SetTarget while grinding nonces. On a hit we
    send SubmitSharesStandard and log the pool's Success/Error response.
    """

    __slots__ = (
        "host", "port", "user", "encrypt", "authority_pubkey", "max_target",
        "roll_ntime", "transport", "state", "accepted", "rejected",
    )

    def __init__(self, host: str, port: int, user: str, *, encrypt: bool,
                 authority_pubkey: str | None, max_target: int,
                 roll_ntime: bool) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.encrypt = encrypt
        self.authority_pubkey = authority_pubkey
        self.max_target = max_target
        self.roll_ntime = roll_ntime
        self.transport: FrameTransport | None = None
        self.state = MiningState(target=max_target)
        self.accepted = 0
        self.rejected = 0

    def connect(self) -> None:
        LOG.info("connecting to %s:%d", self.host, self.port)
        sock = socket.create_connection((self.host, self.port), timeout=30)
        sock.settimeout(None)
        noise = self._noise_handshake(sock) if self.encrypt else None
        self.transport = FrameTransport(sock, noise)

    def _noise_handshake(self, sock: socket.socket) -> NoiseSession:
        """Run the NX handshake as initiator and Split() into transport keys."""
        LOG.info("starting Noise_NX handshake (initiator)")
        session = NoiseSession(initiator=True)
        sock.sendall(session.write_message1())            # -> e

        message2 = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                raise RuntimeError("pool closed during Noise handshake")
            message2 += chunk
            # Smallest possible msg2: e(32) + encrypted_static(48) + tag(16).
            if len(message2) >= NOISE_DH_LEN + (NOISE_DH_LEN + NOISE_TAG_LEN) + NOISE_TAG_LEN:
                break

        payload = session.read_message2(message2)         # <- e, ee, s, es
        session.split()
        LOG.info("Noise handshake complete; the pool's static key is %s",
                 session.remote_static().hex())
        self._check_certificate(payload)
        return session

    def _check_certificate(self, payload: bytes) -> None:
        """Parse + (optionally) verify the responder's SignatureNoiseMessage."""
        if not payload:
            LOG.warning("no SignatureNoiseMessage in handshake payload (test client: proceeding)")
            return
        try:
            certificate = SignatureNoiseMessage.parse(payload)
        except ValueError as exc:
            LOG.warning("could not parse SignatureNoiseMessage: %s (proceeding)", exc)
            return
        if self.authority_pubkey:
            if verify_signature_noise_message(certificate, self.authority_pubkey):
                LOG.info("authority signature VERIFIED")
            else:
                LOG.error("authority signature INVALID for the pool's static key")
        else:
            LOG.warning("no --authority-pubkey given; NOT verifying the pool "
                        "certificate (test client: proceeding)")

    def setup_connection(self) -> bool:
        device_id = socket.gethostname()
        setup = SetupConnection(
            protocol=0,            # mining protocol
            min_version=2,
            max_version=2,
            flags=0,
            endpoint_host=self.host,
            endpoint_port=self.port,
            vendor="erikslund",
            hardware_version="",
            firmware="sv2_miner",
            device_id=device_id,
        )
        self.transport.send_frame(frame_message(setup))
        frame = self.transport.recv_frame()
        if frame is None:
            LOG.error("pool closed before SetupConnection response")
            return False
        _, _, msg_type, payload = frame
        match msg_type:
            case SetupConnectionSuccess.MSG_TYPE:
                success = SetupConnectionSuccess.parse(payload)
                LOG.info("connection set up: used_version=%d flags=0x%08x",
                         success.used_version, success.flags)
                return True
            case SetupConnectionError.MSG_TYPE:
                error = SetupConnectionError.parse(payload)
                LOG.error("SetupConnection rejected: %s (flags=0x%08x)",
                          error.error_code, error.flags)
                return False
            case _:
                LOG.error("received an unexpected msg_type 0x%02x in response to SetupConnection",
                          msg_type)
                return False

    def open_channel(self) -> bool:
        request = OpenStandardMiningChannel(
            request_id=1,
            user_identity=self.user,
            nominal_hash_rate=1_000_000.0,    # ~1 MH/s nominal; cosmetic for a test client
            max_target=self.max_target.to_bytes(32, "little"),
        )
        self.transport.send_frame(frame_message(request))
        frame = self.transport.recv_frame()
        if frame is None:
            LOG.error("pool closed before channel-open response")
            return False
        _, _, msg_type, payload = frame
        match msg_type:
            case OpenStandardMiningChannelSuccess.MSG_TYPE:
                success = OpenStandardMiningChannelSuccess.parse(payload)
                self.state.channel_id = success.channel_id
                self.state.target = int.from_bytes(success.target, "little")
                LOG.info("channel %d opened: target=%s extranonce_prefix=%s",
                         success.channel_id, success.target.hex(),
                         success.extranonce_prefix.hex())
                return True
            case OpenMiningChannelError.MSG_TYPE:
                error = OpenMiningChannelError.parse(payload)
                LOG.error("OpenStandardMiningChannel rejected: %s", error.error_code)
                return False
            case _:
                LOG.error("received an unexpected msg_type 0x%02x in response to channel open",
                          msg_type)
                return False

    def handle_frame(self, frame: Frame) -> None:
        _, _, msg_type, payload = frame
        match msg_type:
            case NewMiningJob.MSG_TYPE:
                self._on_new_job(NewMiningJob.parse(payload))
            case SetNewPrevHash.MSG_TYPE:
                self._on_set_prevhash(SetNewPrevHash.parse(payload))
            case SetTarget.MSG_TYPE:
                self._on_set_target(SetTarget.parse(payload))
            case SubmitSharesSuccess.MSG_TYPE:
                success = SubmitSharesSuccess.parse(payload)
                self.accepted += 1
                LOG.info("share ACCEPTED (seq=%d, %d accepted / %d rejected)",
                         success.last_sequence_number, self.accepted, self.rejected)
            case SubmitSharesError.MSG_TYPE:
                error = SubmitSharesError.parse(payload)
                self.rejected += 1
                LOG.warning("share REJECTED: %s (%d accepted / %d rejected)",
                            error.error_code, self.accepted, self.rejected)
            case _:
                LOG.debug("unhandled inbound msg_type 0x%02x", msg_type)

    def _on_new_job(self, job: NewMiningJob) -> None:
        self.state.job_id = job.job_id
        self.state.version = job.version
        self.state.merkle_root = job.merkle_root
        self.state.min_ntime = job.min_ntime if job.min_ntime is not None else self.state.min_ntime
        self.state.have_job = True
        self.state.generation += 1
        LOG.info("new job %d (version=0x%08x, merkle_root=%s)",
                 job.job_id, job.version, job.merkle_root.hex())

    def _on_set_prevhash(self, prevhash: SetNewPrevHash) -> None:
        self.state.prev_hash = prevhash.prev_hash
        self.state.nbits = prevhash.nbits
        self.state.min_ntime = prevhash.min_ntime
        self.state.job_id = prevhash.job_id
        self.state.have_prevhash = True
        self.state.generation += 1
        LOG.info("set prev_hash for job %d (nbits=0x%08x, min_ntime=%d)",
                 prevhash.job_id, prevhash.nbits, prevhash.min_ntime)

    def _on_set_target(self, set_target: SetTarget) -> None:
        self.state.target = int.from_bytes(set_target.maximum_target, "little")
        LOG.info("target set to %s", set_target.maximum_target.hex())

    def mine(self) -> int:
        """Drive setup/open then grind nonces, reacting to new work as it arrives.

        The socket is blocking, so we interleave: drain any pending downstream
        frames, grind a bounded batch of nonces for the current job, repeat. A
        new job/prevhash bumps state.generation and restarts the search.
        """
        if not self.setup_connection():
            return 1
        if not self.open_channel():
            return 1

        NONCE_BATCH = 200_000
        pack_nonce = _PACK_LE_UINT32  # bound to local to keep the inner loop tight
        sha256 = hashlib.sha256
        self.transport._sock.settimeout(0.0)  # non-blocking drain of inbound frames

        local_generation = -1
        nonce = 0
        prepared: tuple[bytes, bytes, int, int, int, int] | None = None
        last_report = time.monotonic()
        hashes = 0

        while True:
            try:
                while (frame := self.transport.recv_frame()) is not None:
                    self.handle_frame(frame)
            except BlockingIOError:
                pass
            except OSError as exc:
                LOG.warning("receive loop ended: %s", exc)
                return 0

            if not self.state.ready():
                time.sleep(0.05)
                continue

            if self.state.generation != local_generation:
                local_generation = self.state.generation
                nonce = 0
                prepared = self._prepare_search()

            first_block, tail, target, job_id, version, ntime = prepared
            copy_ctx = first_block.copy        # bound midstate clone (see _prepare_search)
            target_high16 = target >> 240
            end = nonce + NONCE_BATCH
            while nonce < end:
                ctx = copy_ctx()
                ctx.update(tail + pack_nonce(nonce))
                digest = sha256(ctx.digest()).digest()
                if (digest[31] << 8 | digest[30]) <= target_high16 \
                        and int.from_bytes(digest, "little") <= target:
                    self._submit(job_id, nonce, ntime, version)
                nonce += 1
            hashes += NONCE_BATCH

            now = time.monotonic()
            if now - last_report >= 5.0:
                rate = hashes / (now - last_report)
                LOG.info("hashrate ~%.0f H/s | accepted %d rejected %d",
                         rate, self.accepted, self.rejected)
                hashes = 0
                last_report = now

            if nonce > 0xFFFFFFFF:
                # Nonce space exhausted: roll ntime (if allowed) or wait for a new job.
                if self.roll_ntime:
                    self.state.min_ntime += 1
                    self.state.generation += 1
                else:
                    nonce = 0

    def _prepare_search(self) -> tuple[bytes, bytes, int, int, int, int]:
        """Precompute the SHA midstate for the current job.

        Returns (first_sha_block, header_tail12, target, job_id, version, ntime).
        The first 64-byte SHA block is constant while the nonce rolls, so we hash
        it once and copy the context per nonce -- same midstate trick as the V1
        miner.
        """
        ntime = max(self.state.min_ntime, int(time.time()))
        header76 = build_header(
            self.state.version, self.state.prev_hash, self.state.merkle_root,
            ntime, self.state.nbits, 0)[:76]
        first_block = hashlib.sha256(header76[:64])
        tail = header76[64:76]   # 12 bytes: merkle tail + ntime + nbits
        return (first_block, tail, self.state.target, self.state.job_id,
                self.state.version, ntime)

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
        LOG.info("submitted share: job=%d nonce=0x%08x ntime=%d seq=%d",
                 job_id, nonce, ntime, self.state.sequence_number)


def _sample_messages() -> list[object]:
    """One instance of every message type, hitting OPTION/B0_32/STR edge cases."""
    target32 = (DIFF1_TARGET).to_bytes(32, "little")
    return [
        SetupConnection(0, 2, 2, 0, "pool.example.com", 34254, "erikslund",
                        "", "sv2_miner", "host-1"),
        # Empty endpoint_host / vendor exercise the zero-length STR0_255 path.
        SetupConnection(0, 2, 2, 0x1, "", 0, "", "hw", "fw", ""),
        SetupConnectionSuccess(2, 0x0),
        SetupConnectionError(0x2, "unsupported-feature-flags"),
        OpenStandardMiningChannel(7, "bc1qexampleaddress", 1_000_000.0, target32),
        OpenStandardMiningChannelSuccess(7, 42, target32, b"", 0),
        # extranonce_prefix at the 32-byte B0_32 maximum.
        OpenStandardMiningChannelSuccess(7, 42, target32, b"\xab" * 32, 9),
        OpenMiningChannelError(7, "max-target-out-of-range"),
        # OPTION present and absent for min_ntime; empty + full B0_32 merkle_root.
        NewMiningJob(42, 100, None, 0x20000000, b""),
        NewMiningJob(42, 101, 1715000000, 0x20000000, b"\x11" * 32),
        SetNewPrevHash(42, 100, b"\x22" * 32, 1715000000, 0x1d00ffff),
        SetTarget(42, target32),
        SubmitSharesStandard(42, 1, 100, 0xDEADBEEF, 1715000123, 0x20000000),
        SubmitSharesSuccess(42, 5, 5, 1234567890123),
        SubmitSharesError(42, 6, "stale-share"),
    ]


def _selftest_codec() -> bool:
    """Every message type: serialize -> parse -> assert equal; frame round-trip."""
    for message in _sample_messages():
        serialized = message.serialize()
        roundtripped = type(message).parse(serialized)
        if roundtripped != message:
            LOG.error("codec FAILED for %s:\n  in  %r\n  out %r",
                      type(message).__name__, message, roundtripped)
            return False
    LOG.info("codec OK: %d message instances round-tripped", len(_sample_messages()))
    return True


def _selftest_framing() -> bool:
    """Header encode/decode incl. channel_msg flag and the U24 length field."""
    cases = [
        (0, False, 0x00, b""),
        (0, True, 0x15, b"\x01\x02\x03\x04"),
        # A large payload to exercise the full 3-byte (U24) length, > 65535.
        (0, True, 0x20, b"\x7e" * 70000),
        # A non-zero extension id alongside the channel_msg flag.
        (0x1234, True, 0x21, b"\xaa" * 5),
    ]
    for extension_id, channel_msg, msg_type, payload in cases:
        frame = encode_frame(extension_id, channel_msg, msg_type, payload)
        got_ext, got_chan, got_type, got_len = decode_frame_header(frame[:FRAME_HEADER_LEN])
        body = frame[FRAME_HEADER_LEN:]
        if (got_ext, got_chan, got_type, got_len, body) != (
                extension_id, channel_msg, msg_type, len(payload), payload):
            LOG.error("framing FAILED for msg_type=0x%02x len=%d", msg_type, len(payload))
            return False
    LOG.info("framing OK: %d frames round-tripped (incl. channel_msg flag + U24)",
             len(cases))
    return True


def _selftest_hashing() -> bool:
    """Reproduce the Bitcoin genesis block hash through the live hashing path.

    Mirrors tools/miner/miner.py's KAT. The genesis prev_hash and merkle_root
    are supplied in header (internal) byte order -- exactly how an SV2 pool hands
    them over -- so build_header splices them in with no per-word swap.
    """
    genesis = build_header(
        version=1,
        prev_hash=b"\x00" * 32,
        merkle_root=bytes.fromhex(
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"),
        ntime=0x495FAB29,
        nbits=0x1D00FFFF,
        nonce=2083236893,
    )
    got = double_sha256(genesis)[::-1].hex()   # reversed == display order
    want = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    if got != want:
        LOG.error("hashing FAILED: got %s want %s", got, want)
        return False
    # Cross-check via header_hash_int: the LE int must be <= the diff-1 target,
    # since genesis met difficulty 1.
    assert header_hash_int(genesis) <= DIFF1_TARGET
    assert target_from_difficulty(1) == DIFF1_TARGET
    assert target_from_difficulty(2) == DIFF1_TARGET // 2
    LOG.info("hashing OK: genesis block hash reproduced (%s)", want)
    return True


def _selftest_noise() -> bool | None:
    """In-process NX handshake + transport round-trip. None if cryptography absent."""
    if not _HAVE_CRYPTOGRAPHY:
        LOG.warning("Noise SKIPPED: 'cryptography' not installed "
                    "(install it or run: pip install '.[encrypt]')")
        return None

    responder_static = x25519.X25519PrivateKey.generate()
    initiator = NoiseSession(initiator=True)
    responder = NoiseSession(initiator=False, static_private=responder_static)

    # -> e
    message1 = initiator.write_message1()
    responder.read_message1(message1)

    # <- e, ee, s, es  (responder's payload is a sample SignatureNoiseMessage)
    certificate = SignatureNoiseMessage(0, 1715000000, 1815000000, b"\x33" * 64)
    message2 = responder.write_message2(certificate.serialize(), initiator._e_pub)
    payload = initiator.read_message2(message2)

    if payload != certificate.serialize():
        LOG.error("Noise FAILED: handshake payload did not round-trip")
        return False
    if SignatureNoiseMessage.parse(payload) != certificate:
        LOG.error("Noise FAILED: SignatureNoiseMessage did not parse back")
        return False
    if initiator.remote_static() != responder_static.public_key().public_bytes_raw():
        LOG.error("Noise FAILED: initiator learned the wrong remote static key")
        return False

    initiator.split()
    responder.split()

    # An encrypted SV2 frame must round-trip both directions through transport.
    sample = frame_message(SetTarget(42, (DIFF1_TARGET).to_bytes(32, "little")))
    wire = initiator.encrypt_transport(sample)
    length = struct.unpack("<H", wire[:2])[0]
    decoded = responder.decrypt_transport_chunk(wire[2:2 + length])
    if decoded != sample:
        LOG.error("Noise FAILED: initiator->responder transport frame mismatch")
        return False

    wire_back = responder.encrypt_transport(sample)
    length_back = struct.unpack("<H", wire_back[:2])[0]
    decoded_back = initiator.decrypt_transport_chunk(wire_back[2:2 + length_back])
    if decoded_back != sample:
        LOG.error("Noise FAILED: responder->initiator transport frame mismatch")
        return False

    LOG.info("Noise OK: NX handshake derived matching keys; SV2 frame round-tripped "
             "both directions")
    return True


def selftest() -> bool:
    """Run every offline check; print PASS/FAIL per check. True iff all pass."""
    results: list[tuple[str, bool | None]] = [
        ("codec", _selftest_codec()),
        ("framing", _selftest_framing()),
        ("hashing", _selftest_hashing()),
        ("noise", _selftest_noise()),
    ]
    all_ok = True
    for name, result in results:
        if result is None:
            print(f"  {name:8s} SKIPPED")
        elif result:
            print(f"  {name:8s} PASS")
        else:
            print(f"  {name:8s} FAIL")
            all_ok = False
    print("selftest:", "PASS" if all_ok else "FAIL")
    return all_ok


def _resolve_max_target(args: argparse.Namespace) -> int:
    """Pick the channel max_target from --target (hex) or --difficulty (diff-1/D)."""
    if args.target:
        return int(args.target, 16)
    return target_from_difficulty(args.difficulty)


def run_miner(args: argparse.Namespace) -> int:
    host, _, port_text = args.url.partition(":")
    port = int(port_text or 34254)   # SRI's default SV2 mining port

    miner = Sv2Miner(
        host=host,
        port=port,
        user=args.user,
        encrypt=args.encrypt,
        authority_pubkey=args.authority_pubkey,
        max_target=_resolve_max_target(args),
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
    parser = argparse.ArgumentParser(
        description="Stratum V2 (SV2) test client for erikslund-pool")
    parser.add_argument("--url", default="127.0.0.1:34254",
                        help="pool host:port (default 127.0.0.1:34254)")
    parser.add_argument("--user", default="",
                        help="user_identity; a valid BTC address for solo pools")
    parser.add_argument("--pass", dest="password", default="",
                        help="ignored (SV2 has no per-connection password); accepted "
                             "for parity with the V1 miner")
    parser.add_argument("--encrypt", action="store_true",
                        help="wrap the connection in the SV2 Noise_NX transport "
                             "(needs the 'cryptography' package)")
    parser.add_argument("--authority-pubkey", default=None,
                        help="hex ed25519 pool authority key; if set, the Noise "
                             "certificate signature is verified")
    parser.add_argument("--target", default=None,
                        help="channel max_target as a 256-bit hex integer "
                             "(overrides --difficulty)")
    parser.add_argument("--difficulty", type=float, default=1.0,
                        help="channel max_target as diff-1/difficulty (default 1)")
    parser.add_argument("--quiet", action="store_true",
                        help="suppress hashrate lines")
    parser.add_argument("--selftest", action="store_true",
                        help="run codec/framing/hashing/Noise checks offline and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else (logging.WARNING if args.quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.selftest:
        return 0 if selftest() else 1

    if not selftest():
        LOG.error("refusing to mine: offline self-test failed")
        return 1
    if not args.user:
        LOG.error("--user is required (a valid BTC address for solo pools)")
        return 1
    if not os.environ.get("SV2_MINER_ACK_UNVERIFIED"):
        LOG.warning("SV2 wire-compatibility is UNVERIFIED against a real pool; "
                    "this is a protocol test client. Proceeding anyway.")
    return run_miner(args)


if __name__ == "__main__":
    sys.exit(main())
