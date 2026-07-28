"""Golden-vector and adversarial tests for the Python Stratum V2 wire layer."""

import unittest

from erikslund_pool.sv2 import codec as sv2_codec
from erikslund_pool.sv2 import messages as sv2_messages

# Cross-language golden vectors.
#
# Every constant in this block is pinned byte-for-byte with the SAME field values in the C++
# suite, in cpp/tests/test_sv2_codec.cpp ("cross-language golden vector" test cases). The two
# pools must produce byte-identical wire output, so a vector is only a cross-check when both
# sides encode identical inputs -- keep the field values and the bytes in lockstep across the
# two files, or the check silently degrades into two unrelated regression pins.
SETUP_CONNECTION_FRAME_HEX = (
    "000000220000"
    "00020002000500000004706f6f6cce85046572696b046173696303312e3003726967"
)
# Same message with an empty STR0_255 (hardware_version) to pin the zero-length string encoding.
SETUP_CONNECTION_EMPTY_STRING_FRAME_HEX = (
    "0000001c0000"
    "00020002000100000004706f6f6cce85046572696b00026677026964"
)
OPEN_STANDARD_CHANNEL_SUCCESS_FRAME_HEX = (
    "000011300000"
    "0403020144332211"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "03aabbccd4c3b2a1"
)
SUBMIT_SHARES_SUCCESS_FRAME_HEX = (
    "00801c140000"
    "0403020144332211887766550807060504030201"
)
SUBMIT_SHARES_ERROR_FRAME_HEX = (
    "00801d140000"
    "04030201443322110b7374616c652d7368617265"
)
SET_NEW_PREV_HASH_FRAME_HEX = (
    "008020300000"
    "0403020144332211"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    "3bd3386619420317"
)
SET_TARGET_FRAME_HEX = (
    "008021240000"
    "04030201"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
OPEN_STANDARD_CHANNEL_FRAME_HEX = (
    "0000102e0000"
    "04030201056d696e65720000c03f"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
OPEN_EXTENDED_CHANNEL_FRAME_HEX = (
    "000013300000"
    "04030201056d696e65720000c03f"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "2211"
)
OPEN_EXTENDED_CHANNEL_SUCCESS_FRAME_HEX = (
    "000014320000"
    "0403020144332211"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "060503aabbccd4c3b2a1"
)
NEW_MINING_JOB_FRAME_HEX = (
    "0080152d0000"
    "44332211d4c3b2a10000000020"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
SUBMIT_SHARES_STANDARD_FRAME_HEX = (
    "00801a180000"
    "040302011413121124232221343332314443424154535251"
)
SUBMIT_SHARES_EXTENDED_FRAME_HEX = (
    "00801b1c0000"
    "04030201141312112423222134333231444342415453525103aabbcc"
)
NEW_EXTENDED_MINING_JOB_FRAME_HEX = (
    "00801f580000"
    "44332211d4c3b2a100000000200102"
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
    "0300aabbcc0200ddee"
)
SET_EXTRANONCE_PREFIX_FRAME_HEX = "0080190700000403020102aabb"


def _encode_message(message: sv2_messages.WireMessage) -> bytes:
    return sv2_codec.encode_frame(sv2_messages.encode_message(message))


class TestSv2GoldenVectors(unittest.TestCase):
    def test_setup_connection_matches_fixed_vector(self) -> None:
        message = sv2_messages.SetupConnection(
            protocol=0,
            min_version=2,
            max_version=2,
            flags=5,
            endpoint_host="pool",
            endpoint_port=34_254,
            vendor="erik",
            hardware_version="asic",
            firmware="1.0",
            device_id="rig",
        )
        self.assertEqual(_encode_message(message).hex(), SETUP_CONNECTION_FRAME_HEX)

    def test_setup_connection_empty_string_matches_fixed_vector(self) -> None:
        message = sv2_messages.SetupConnection(
            protocol=0,
            min_version=2,
            max_version=2,
            flags=1,
            endpoint_host="pool",
            endpoint_port=34_254,
            vendor="erik",
            hardware_version="",
            firmware="fw",
            device_id="id",
        )
        self.assertEqual(
            _encode_message(message).hex(), SETUP_CONNECTION_EMPTY_STRING_FRAME_HEX
        )

    def test_open_standard_channel_success_matches_cross_language_vector(self) -> None:
        message = sv2_messages.OpenStandardMiningChannelSuccess(
            request_id=0x0102_0304,
            channel_id=0x1122_3344,
            target=bytes(range(32)),
            extranonce_prefix=b"\xaa\xbb\xcc",
            group_channel_id=0xA1B2_C3D4,
        )
        self.assertEqual(
            _encode_message(message).hex(), OPEN_STANDARD_CHANNEL_SUCCESS_FRAME_HEX
        )

    def test_submit_shares_success_matches_cross_language_vector(self) -> None:
        message = sv2_messages.SubmitSharesSuccess(
            channel_id=0x0102_0304,
            last_sequence_number=0x1122_3344,
            new_submits_accepted_count=0x5566_7788,
            new_shares_sum=0x0102_0304_0506_0708,
        )
        self.assertEqual(_encode_message(message).hex(), SUBMIT_SHARES_SUCCESS_FRAME_HEX)

    def test_submit_shares_error_matches_cross_language_vector(self) -> None:
        message = sv2_messages.SubmitSharesError(
            channel_id=0x0102_0304,
            sequence_number=0x1122_3344,
            error_code="stale-share",
        )
        self.assertEqual(_encode_message(message).hex(), SUBMIT_SHARES_ERROR_FRAME_HEX)

    def test_set_new_prev_hash_matches_cross_language_vector(self) -> None:
        message = sv2_messages.SetNewPrevHash(
            channel_id=0x0102_0304,
            job_id=0x1122_3344,
            prev_hash=bytes(range(32, 64)),
            min_ntime=1_715_000_123,
            nbits=0x1703_4219,
        )
        self.assertEqual(_encode_message(message).hex(), SET_NEW_PREV_HASH_FRAME_HEX)

    def test_set_target_matches_cross_language_vector(self) -> None:
        message = sv2_messages.SetTarget(
            channel_id=0x0102_0304,
            maximum_target=bytes(range(32)),
        )
        self.assertEqual(_encode_message(message).hex(), SET_TARGET_FRAME_HEX)

    def test_open_standard_channel_matches_fixed_vector(self) -> None:
        message = sv2_messages.OpenStandardMiningChannel(
            request_id=0x0102_0304,
            user_identity="miner",
            nominal_hash_rate=1.5,
            max_target=bytes(range(32)),
        )
        self.assertEqual(_encode_message(message).hex(), OPEN_STANDARD_CHANNEL_FRAME_HEX)

    def test_open_extended_channel_matches_cross_language_vector(self) -> None:
        message = sv2_messages.OpenExtendedMiningChannel(
            request_id=0x0102_0304,
            user_identity="miner",
            nominal_hash_rate=1.5,
            max_target=bytes(range(32)),
            min_extranonce_size=0x1122,
        )
        self.assertEqual(_encode_message(message).hex(), OPEN_EXTENDED_CHANNEL_FRAME_HEX)

    def test_open_extended_channel_success_matches_cross_language_vector(self) -> None:
        message = sv2_messages.OpenExtendedMiningChannelSuccess(
            request_id=0x0102_0304,
            channel_id=0x1122_3344,
            target=bytes(range(32)),
            extranonce_size=0x0506,
            extranonce_prefix=b"\xaa\xbb\xcc",
            group_channel_id=0xA1B2_C3D4,
        )
        self.assertEqual(
            _encode_message(message).hex(),
            OPEN_EXTENDED_CHANNEL_SUCCESS_FRAME_HEX,
        )

    def test_new_mining_job_matches_fixed_vector(self) -> None:
        message = sv2_messages.NewMiningJob(
            channel_id=0x1122_3344,
            job_id=0xA1B2_C3D4,
            min_ntime=None,
            version=0x2000_0000,
            merkle_root=bytes(range(32)),
        )
        self.assertEqual(_encode_message(message).hex(), NEW_MINING_JOB_FRAME_HEX)

    def test_submit_shares_standard_matches_fixed_vector(self) -> None:
        message = sv2_messages.SubmitSharesStandard(
            channel_id=0x0102_0304,
            sequence_number=0x1112_1314,
            job_id=0x2122_2324,
            nonce=0x3132_3334,
            ntime=0x4142_4344,
            version=0x5152_5354,
        )
        self.assertEqual(_encode_message(message).hex(), SUBMIT_SHARES_STANDARD_FRAME_HEX)

    def test_submit_shares_extended_matches_cross_language_vector(self) -> None:
        message = sv2_messages.SubmitSharesExtended(
            channel_id=0x0102_0304,
            sequence_number=0x1112_1314,
            job_id=0x2122_2324,
            nonce=0x3132_3334,
            ntime=0x4142_4344,
            version=0x5152_5354,
            extranonce=b"\xaa\xbb\xcc",
        )
        self.assertEqual(_encode_message(message).hex(), SUBMIT_SHARES_EXTENDED_FRAME_HEX)

    def test_new_extended_mining_job_matches_cross_language_vector(self) -> None:
        message = sv2_messages.NewExtendedMiningJob(
            channel_id=0x1122_3344,
            job_id=0xA1B2_C3D4,
            min_ntime=None,
            version=0x2000_0000,
            version_rolling_allowed=True,
            merkle_path=(bytes(range(32)), bytes(range(32, 64))),
            coinbase_tx_prefix=b"\xaa\xbb\xcc",
            coinbase_tx_suffix=b"\xdd\xee",
        )
        self.assertEqual(_encode_message(message).hex(), NEW_EXTENDED_MINING_JOB_FRAME_HEX)

    def test_set_extranonce_prefix_matches_cross_language_vector(self) -> None:
        message = sv2_messages.SetExtranoncePrefix(
            channel_id=0x0102_0304,
            extranonce_prefix=b"\xaa\xbb",
        )
        self.assertEqual(_encode_message(message).hex(), SET_EXTRANONCE_PREFIX_FRAME_HEX)


class TestSv2MessageRoundTrips(unittest.TestCase):
    def test_every_supported_message_round_trips(self) -> None:
        hash_bytes = bytes(range(32))
        messages: list[sv2_messages.Message] = [
            sv2_messages.SetupConnection(
                protocol=sv2_messages.MINING_PROTOCOL,
                min_version=sv2_messages.PROTOCOL_VERSION,
                max_version=sv2_messages.PROTOCOL_VERSION,
                flags=sv2_messages.REQUIRES_STANDARD_JOBS_FLAG,
                endpoint_host="127.0.0.1",
                endpoint_port=3_333,
                vendor="vendor",
                hardware_version="hardware",
                firmware="firmware",
                device_id="device",
            ),
            sv2_messages.SetupConnectionSuccess(used_version=2, flags=0),
            sv2_messages.SetupConnectionError(flags=4, error_code="unsupported-flags"),
            sv2_messages.OpenStandardMiningChannel(
                request_id=7,
                user_identity="worker",
                nominal_hash_rate=1_000_000.0,
                max_target=hash_bytes,
            ),
            sv2_messages.OpenStandardMiningChannelSuccess(
                request_id=7,
                channel_id=42,
                target=hash_bytes,
                extranonce_prefix=b"\xaa" * 32,
                group_channel_id=9,
            ),
            sv2_messages.OpenMiningChannelError(
                request_id=7,
                error_code="invalid-user",
            ),
            sv2_messages.OpenExtendedMiningChannel(
                request_id=8,
                user_identity="proxy",
                nominal_hash_rate=10_000_000.0,
                max_target=hash_bytes,
                min_extranonce_size=8,
            ),
            sv2_messages.OpenExtendedMiningChannelSuccess(
                request_id=8,
                channel_id=43,
                target=hash_bytes,
                extranonce_size=8,
                extranonce_prefix=b"\xbb" * 4,
                group_channel_id=10,
            ),
            sv2_messages.NewMiningJob(
                channel_id=42,
                job_id=100,
                min_ntime=None,
                version=0x2000_0000,
                merkle_root=hash_bytes,
            ),
            sv2_messages.UpdateChannel(
                channel_id=42,
                nominal_hash_rate=2_000_000.0,
                maximum_target=hash_bytes,
            ),
            sv2_messages.UpdateChannelError(
                channel_id=42,
                error_code="invalid-channel",
            ),
            sv2_messages.CloseChannel(channel_id=42, reason_code="shutdown"),
            sv2_messages.SetExtranoncePrefix(
                channel_id=42,
                extranonce_prefix=b"\xaa\xbb\xcc",
            ),
            sv2_messages.NewMiningJob(
                channel_id=42,
                job_id=101,
                min_ntime=1_715_000_000,
                version=0x2000_0000,
                merkle_root=hash_bytes,
            ),
            sv2_messages.SetNewPrevHash(
                channel_id=42,
                job_id=100,
                prev_hash=hash_bytes,
                min_ntime=1_715_000_000,
                nbits=0x1D00_FFFF,
            ),
            sv2_messages.SetTarget(channel_id=42, maximum_target=hash_bytes),
            sv2_messages.SubmitSharesStandard(
                channel_id=42,
                sequence_number=1,
                job_id=100,
                nonce=0xABBA_ABBA,
                ntime=1_715_000_123,
                version=0x2000_0000,
            ),
            sv2_messages.SubmitSharesExtended(
                channel_id=43,
                sequence_number=2,
                job_id=102,
                nonce=0xCAFE_BABE,
                ntime=1_715_000_124,
                version=0x2000_0000,
                extranonce=b"\x01\x02\x03\x04\x05\x06\x07\x08",
            ),
            sv2_messages.SubmitSharesSuccess(
                channel_id=42,
                last_sequence_number=5,
                new_submits_accepted_count=5,
                new_shares_sum=1_234_567_890_123,
            ),
            sv2_messages.SubmitSharesError(
                channel_id=42,
                sequence_number=6,
                error_code="stale-share",
            ),
            sv2_messages.NewExtendedMiningJob(
                channel_id=43,
                job_id=102,
                min_ntime=1_715_000_000,
                version=0x2000_0000,
                version_rolling_allowed=False,
                merkle_path=(hash_bytes, hash_bytes[::-1]),
                coinbase_tx_prefix=b"\x01" * 300,
                coinbase_tx_suffix=b"\x02" * 400,
            ),
        ]

        for message in messages:
            with self.subTest(message=type(message).__name__):
                frame = sv2_messages.encode_message(message)
                wire = sv2_codec.encode_frame(frame)
                decoded_frames = sv2_codec.FrameDecoder().feed(wire)
                self.assertEqual(len(decoded_frames), 1)
                self.assertEqual(sv2_messages.decode_message(decoded_frames[0]), message)


class TestSv2ExtendedPrimitives(unittest.TestCase):
    def test_bool_encodes_canonically_and_ignores_padding_bits(self) -> None:
        writer = sv2_codec.PayloadWriter()
        writer.write_bool(False)
        writer.write_bool(True)
        self.assertEqual(writer.to_bytes(), b"\x00\x01")
        self.assertFalse(sv2_codec.PayloadReader(b"\xfe").read_bool())
        self.assertTrue(sv2_codec.PayloadReader(b"\xff").read_bool())

        with self.assertRaises(TypeError):
            sv2_codec.PayloadWriter().write_bool(1)  # type: ignore[arg-type]

    def test_b0_64k_enforces_its_u16_bound(self) -> None:
        maximum_value = b"\x5a" * sv2_codec.B0_64K_MAX_SIZE
        writer = sv2_codec.PayloadWriter()
        writer.write_b0_64k(maximum_value)
        encoded = writer.to_bytes()
        self.assertEqual(encoded[:2], b"\xff\xff")
        self.assertEqual(sv2_codec.PayloadReader(encoded).read_b0_64k(), maximum_value)

        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_codec.PayloadWriter().write_b0_64k(maximum_value + b"\x5a")

    def test_sequence_u256_enforces_count_and_element_sizes(self) -> None:
        value = bytes(range(32))
        maximum_sequence = (value,) * sv2_codec.SEQUENCE_MAX_COUNT
        writer = sv2_codec.PayloadWriter()
        writer.write_sequence_u256(maximum_sequence)
        encoded = writer.to_bytes()
        self.assertEqual(encoded[0], 0xFF)
        self.assertEqual(
            sv2_codec.PayloadReader(encoded).read_sequence_u256(),
            maximum_sequence,
        )

        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_codec.PayloadWriter().write_sequence_u256(maximum_sequence + (value,))
        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_codec.PayloadWriter().write_sequence_u256((bytes(31),))


class TestSv2StreamingDecoder(unittest.TestCase):
    def test_fragmented_frame_is_retained_until_complete(self) -> None:
        wire = bytes.fromhex(NEW_MINING_JOB_FRAME_HEX)
        decoder = sv2_codec.FrameDecoder()
        decoded_frames: list[sv2_codec.Frame] = []

        for octet in wire:
            decoded_frames.extend(decoder.feed(bytes([octet])))

        self.assertEqual(len(decoded_frames), 1)
        self.assertIsInstance(
            sv2_messages.decode_message(decoded_frames[0]),
            sv2_messages.NewMiningJob,
        )
        self.assertEqual(decoder.buffered_size, 0)
        decoder.finish()

    def test_multiple_frames_in_one_chunk_are_all_returned(self) -> None:
        wire = bytes.fromhex(SETUP_CONNECTION_FRAME_HEX + SUBMIT_SHARES_STANDARD_FRAME_HEX)
        decoded_frames = sv2_codec.FrameDecoder().feed(wire)
        self.assertEqual([frame.message_type for frame in decoded_frames], [0x00, 0x1A])

    def test_large_frame_batch_is_consumed_in_order(self) -> None:
        frame = sv2_codec.Frame(extension_type=0, message_type=0x7F, payload=b"")
        wire = sv2_codec.encode_frame(frame) * 4096
        decoder = sv2_codec.FrameDecoder()

        self.assertEqual(decoder.feed(wire), [frame] * 4096)
        self.assertEqual(decoder.buffered_size, 0)

    def test_full_u24_length_is_little_endian(self) -> None:
        payload = b"\x5a" * 70_000
        frame = sv2_codec.Frame(extension_type=0, message_type=0x7F, payload=payload)
        wire = sv2_codec.encode_frame(frame)
        self.assertEqual(wire[3:6], bytes.fromhex("701101"))
        self.assertEqual(sv2_codec.FrameDecoder().feed(wire), [frame])

    def test_eof_rejects_partial_header(self) -> None:
        decoder = sv2_codec.FrameDecoder()
        self.assertEqual(decoder.feed(b"\x00\x00\x15"), [])
        with self.assertRaises(sv2_codec.TruncatedFrameError):
            decoder.finish()
        self.assertEqual(decoder.buffered_size, 0)

    def test_eof_rejects_partial_payload(self) -> None:
        decoder = sv2_codec.FrameDecoder()
        self.assertEqual(decoder.feed(b"\x00\x00\x00\x03\x00\x00ab"), [])
        with self.assertRaises(sv2_codec.TruncatedFrameError):
            decoder.finish()

    def test_declared_oversize_is_rejected_from_header(self) -> None:
        decoder = sv2_codec.FrameDecoder(max_payload_size=8)
        header = b"\x00\x00\x00\x09\x00\x00"
        with self.assertRaises(sv2_codec.FrameTooLargeError):
            decoder.feed(header)
        self.assertEqual(decoder.buffered_size, 0)

    def test_complete_prefix_survives_a_later_oversized_header(self) -> None:
        frame = sv2_codec.Frame(extension_type=0, message_type=0x21, payload=b"x")
        wire = sv2_codec.encode_frame(frame) + b"\x00\x00\x00\x09\x00\x00"
        decoder = sv2_codec.FrameDecoder(max_payload_size=8)

        with self.assertRaises(sv2_codec.FrameTooLargeError) as raised:
            decoder.feed(wire)

        self.assertEqual(raised.exception.completed_frames, [frame])
        self.assertEqual(decoder.buffered_size, 0)

    def test_encoder_applies_same_payload_limit(self) -> None:
        frame = sv2_codec.Frame(extension_type=0, message_type=0, payload=b"x" * 9)
        with self.assertRaises(sv2_codec.FrameTooLargeError):
            sv2_codec.encode_frame(frame, max_payload_size=8)


class TestSv2MalformedMessages(unittest.TestCase):
    def test_truncated_payload_is_rejected(self) -> None:
        message = sv2_messages.SetupConnectionSuccess(used_version=2, flags=0)
        frame = sv2_messages.encode_message(message)
        truncated = _replace_frame_payload(frame, payload=frame.payload[:-1])
        with self.assertRaises(sv2_codec.MessageDecodeError):
            sv2_messages.decode_message(truncated)

    def test_trailing_payload_is_rejected(self) -> None:
        message = sv2_messages.SetupConnectionSuccess(used_version=2, flags=0)
        frame = sv2_messages.encode_message(message)
        extended = _replace_frame_payload(frame, payload=frame.payload + b"\x00")
        with self.assertRaises(sv2_codec.MessageDecodeError):
            sv2_messages.decode_message(extended)

    def test_invalid_option_count_is_rejected(self) -> None:
        payload = (
            (1).to_bytes(4, "little")
            + (2).to_bytes(4, "little")
            + b"\x02"
            + (0x2000_0000).to_bytes(4, "little")
            + bytes(32)
        )
        frame = sv2_codec.Frame(
            extension_type=sv2_codec.CHANNEL_MESSAGE_BIT,
            message_type=sv2_messages.NewMiningJob.MESSAGE_TYPE,
            payload=payload,
        )
        with self.assertRaisesRegex(sv2_codec.MessageDecodeError, r"count must be 0 or 1"):
            sv2_messages.decode_message(frame)

    def test_invalid_b0_32_length_is_rejected(self) -> None:
        reader = sv2_codec.PayloadReader(b"\x21" + bytes(33))
        with self.assertRaises(sv2_codec.MessageDecodeError):
            reader.read_b0_32()

    def test_truncated_b0_64k_is_rejected(self) -> None:
        reader = sv2_codec.PayloadReader(b"\x03\x00ab")
        with self.assertRaises(sv2_codec.MessageDecodeError):
            reader.read_b0_64k()

    def test_truncated_sequence_u256_is_rejected(self) -> None:
        reader = sv2_codec.PayloadReader(b"\x02" + bytes(32))
        with self.assertRaises(sv2_codec.MessageDecodeError):
            reader.read_sequence_u256()

    def test_non_utf8_string_bytes_round_trip_losslessly(self) -> None:
        payload = (0).to_bytes(4, "little") + b"\x01\xff"
        frame = sv2_codec.Frame(
            extension_type=0,
            message_type=sv2_messages.SetupConnectionError.MESSAGE_TYPE,
            payload=payload,
        )
        decoded = sv2_messages.decode_message(frame)
        self.assertEqual(decoded.error_code.encode("utf-8", errors="surrogateescape"), b"\xff")
        self.assertEqual(sv2_messages.encode_message(decoded), frame)

    def test_wrong_channel_routing_bit_is_rejected(self) -> None:
        frame = sv2_codec.Frame(
            extension_type=0,
            message_type=sv2_messages.SetTarget.MESSAGE_TYPE,
            payload=(1).to_bytes(4, "little") + bytes(32),
        )
        with self.assertRaisesRegex(sv2_codec.MessageDecodeError, "routing bit"):
            sv2_messages.decode_message(frame)

    def test_extended_messages_reject_wrong_routing_bits(self) -> None:
        cases = (
            (sv2_messages.OpenExtendedMiningChannel.MESSAGE_TYPE, True),
            (sv2_messages.OpenExtendedMiningChannelSuccess.MESSAGE_TYPE, True),
            (sv2_messages.SubmitSharesExtended.MESSAGE_TYPE, False),
            (sv2_messages.NewExtendedMiningJob.MESSAGE_TYPE, False),
        )
        for message_type, channel_message in cases:
            with self.subTest(message_type=message_type):
                extension_type = (
                    sv2_codec.CHANNEL_MESSAGE_BIT if channel_message else 0
                )
                frame = sv2_codec.Frame(
                    extension_type=extension_type,
                    message_type=message_type,
                    payload=b"",
                )
                with self.assertRaisesRegex(sv2_codec.MessageDecodeError, "routing bit"):
                    sv2_messages.decode_message(frame)

    def test_non_core_extension_is_rejected(self) -> None:
        frame = sv2_codec.Frame(extension_type=1, message_type=0, payload=b"")
        with self.assertRaises(sv2_messages.UnsupportedMessageError):
            sv2_messages.decode_message(frame)

    def test_unknown_core_message_is_rejected(self) -> None:
        frame = sv2_codec.Frame(extension_type=0, message_type=0x7F, payload=b"")
        with self.assertRaises(sv2_messages.UnsupportedMessageError):
            sv2_messages.decode_message(frame)

    def test_fixed_u256_and_bounded_strings_are_enforced(self) -> None:
        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_messages.SetTarget(channel_id=1, maximum_target=bytes(31)).encode_payload()
        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_messages.SetupConnectionError(
                flags=0,
                error_code="x" * 256,
            ).encode_payload()

    def test_unsigned_integer_ranges_are_enforced(self) -> None:
        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_messages.SubmitSharesStandard(
                channel_id=-1,
                sequence_number=0,
                job_id=0,
                nonce=0,
                ntime=0,
                version=0,
            ).encode_payload()
        with self.assertRaises(sv2_codec.Sv2CodecError):
            sv2_messages.SubmitSharesStandard(
                channel_id=0,
                sequence_number=0,
                job_id=0,
                nonce=0x1_0000_0000,
                ntime=0,
                version=0,
            ).encode_payload()


def _replace_frame_payload(frame: sv2_codec.Frame, *, payload: bytes) -> sv2_codec.Frame:
    return sv2_codec.Frame(
        extension_type=frame.extension_type,
        message_type=frame.message_type,
        payload=payload,
    )
