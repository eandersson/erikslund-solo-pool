"""Known-answer tests for erikslund_pool.util encoders."""

from erikslund_pool.constants import DIFF1_TARGET
from erikslund_pool.tests.base import SoloPoolTestCase
from erikslund_pool.util import ascii_worker
from erikslund_pool.util import bits_to_target
from erikslund_pool.util import difficulty_to_target
from erikslund_pool.util import display_hash
from erikslund_pool.util import dsha256
from erikslund_pool.util import format_difficulty
from erikslund_pool.util import hash_to_int
from erikslund_pool.util import prevhash_to_stratum
from erikslund_pool.util import sanitize
from erikslund_pool.util import ser_uint32
from erikslund_pool.util import ser_uint64
from erikslund_pool.util import ser_varint
from erikslund_pool.util import serialize_height
from erikslund_pool.util import target_to_difficulty
from erikslund_pool.util import unhex


class TestDoubleSha(SoloPoolTestCase):
    def test_known_answer(self):
        self.assertEqual(
            dsha256(b"").hex(),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")

    def test_length_and_determinism(self):
        self.assertEqual(len(dsha256(b"x")), 32)
        self.assertEqual(dsha256(b"abc"), dsha256(b"abc"))
        self.assertNotEqual(dsha256(b"a"), dsha256(b"b"))


class TestIntSerialization(SoloPoolTestCase):
    def test_uint32(self):
        self.assertEqual(ser_uint32(1).hex(), "01000000")
        self.assertEqual(ser_uint32(0xDEADBEEF).hex(), "efbeadde")

    def test_uint64(self):
        self.assertEqual(ser_uint64(1).hex(), "0100000000000000")
        self.assertEqual(ser_uint64(0xDEADBEEFCAFEBABE).hex(), "bebafecaefbeadde")


class TestSerializeHeight(SoloPoolTestCase):
    def test_op_n_and_push_forms(self):
        # BIP34 / CScript() << height: OP_0, OP_1..OP_16, then minimal pushes.
        self.assertEqual(serialize_height(0).hex(), "00")
        self.assertEqual(serialize_height(1).hex(), "51")
        self.assertEqual(serialize_height(16).hex(), "60")
        self.assertEqual(serialize_height(17).hex(), "0111")
        self.assertEqual(serialize_height(127).hex(), "017f")
        self.assertEqual(serialize_height(256).hex(), "020001")
        self.assertEqual(serialize_height(500000).hex(), "0320a107")
        self.assertEqual(serialize_height(840000).hex(), "0340d10c")

    def test_sign_byte_appended(self):
        # When the top byte's high bit is set, a 0x00 keeps the value positive.
        self.assertEqual(serialize_height(128).hex(), "028000")
        self.assertEqual(serialize_height(255).hex(), "02ff00")
        self.assertEqual(serialize_height(0xFFFF).hex(), "03ffff00")


class TestVarint(SoloPoolTestCase):
    def test_compactsize_boundaries(self):
        self.assertEqual(ser_varint(0).hex(), "00")
        self.assertEqual(ser_varint(252).hex(), "fc")
        self.assertEqual(ser_varint(253).hex(), "fdfd00")
        self.assertEqual(ser_varint(0xFFFF).hex(), "fdffff")
        self.assertEqual(ser_varint(0x10000).hex(), "fe00000100")
        self.assertEqual(ser_varint(0x100000000).hex(), "ff0000000001000000")

    def test_four_byte_upper_boundary(self):
        # 0xFFFFFFFF is the last value that fits the 0xFE 4-byte form.
        self.assertEqual(ser_varint(0xFFFFFFFF).hex(), "feffffffff")
        # One past it crosses into the 0xFF 8-byte form.
        self.assertEqual(ser_varint(0x1_0000_0000).hex(), "ff0000000001000000")


class TestUnhex(SoloPoolTestCase):
    def test_decodes_hex(self):
        self.assertEqual(unhex("deadbeef"), b"\xde\xad\xbe\xef")
        self.assertEqual(unhex(""), b"")

    def test_rejects_odd_length(self):
        with self.assertRaises(ValueError):
            unhex("abc")


class TestTargets(SoloPoolTestCase):
    def test_bits_to_target(self):
        self.assertEqual(bits_to_target(0x1D00FFFF), DIFF1_TARGET)
        self.assertEqual(bits_to_target(0x207FFFFF), 0x7FFFFF << 232)
        self.assertEqual(bits_to_target(0x1B0404CB), 0x0404CB << 192)

    def test_bits_to_target_low_exponent(self):
        self.assertEqual(bits_to_target(0x03001234), 0x1234)
        self.assertEqual(bits_to_target(0x02001234), 0x12)

    def test_bits_to_target_exponent_three_is_identity_mantissa(self):
        # exponent == 3 is the no-shift case (8*(3-3) == 8*(3-3)).
        self.assertEqual(bits_to_target(0x03123456), 0x123456)
        self.assertEqual(bits_to_target(0x04123456), 0x12345600)

    def test_bits_to_target_strips_sign_bit_of_mantissa(self):
        # Only the low 23 bits are the mantissa; the 0x800000 sign bit is masked off.
        self.assertEqual(bits_to_target(0x0300FFFF), bits_to_target(0x0380FFFF))

    def test_difficulty_roundtrip(self):
        self.assertEqual(difficulty_to_target(1), DIFF1_TARGET)
        self.assertAlmostEqual(target_to_difficulty(DIFF1_TARGET), 1.0)
        self.assertGreater(difficulty_to_target(0.001), difficulty_to_target(1))

    def test_difficulty_roundtrip_recovers_input(self):
        # target_to_difficulty(difficulty_to_target(d)) ~= d across a wide range.
        for difficulty in (0.5, 1.0, 16.0, 1024.0, 1e6, 1e9):
            target = difficulty_to_target(difficulty)
            self.assertAlmostEqual(target_to_difficulty(target), difficulty,
                                   delta=difficulty * 1e-9 + 1e-9)

    def test_higher_difficulty_is_a_smaller_target(self):
        self.assertGreater(difficulty_to_target(1), difficulty_to_target(2))
        self.assertEqual(difficulty_to_target(2), int(DIFF1_TARGET / 2))

    def test_difficulty_edge_cases(self):
        self.assertEqual(difficulty_to_target(0), DIFF1_TARGET)
        self.assertEqual(difficulty_to_target(-5), DIFF1_TARGET)
        self.assertEqual(target_to_difficulty(0), float("inf"))

    def test_hash_to_int_is_little_endian(self):
        self.assertEqual(hash_to_int(bytes([0x01]) + bytes(31)), 1)
        self.assertEqual(hash_to_int(bytes(31) + bytes([0x01])), 1 << 248)


class TestFormatDifficulty(SoloPoolTestCase):
    def test_no_scientific_notation(self):
        # Large difficulties render in full, never as "2e+04".
        self.assertEqual(format_difficulty(20000.0), "20000")
        self.assertEqual(format_difficulty(1_500_000.0), "1500000")
        self.assertEqual(format_difficulty(16384.0), "16384")

    def test_fractions_and_small(self):
        self.assertEqual(format_difficulty(10.0), "10")
        self.assertEqual(format_difficulty(1.5), "1.5")
        self.assertEqual(format_difficulty(16.25), "16.25")
        self.assertEqual(format_difficulty(0.001), "0.001")

    def test_sub_unit_uses_four_significant_figures(self):
        self.assertEqual(format_difficulty(0.0), "0")
        self.assertEqual(format_difficulty(0.5), "0.5")
        self.assertEqual(format_difficulty(0.0001), "0.0001")
        self.assertEqual(format_difficulty(0.00012345), "0.0001234")

    def test_rounds_to_two_decimals_then_strips(self):
        # >=1 non-integers print with 2 decimals, trailing zeros stripped.
        self.assertEqual(format_difficulty(1.005), "1")     # 1.00 -> "1"
        self.assertEqual(format_difficulty(1.999), "2")     # rounds up
        self.assertEqual(format_difficulty(2.999), "3")

    def test_never_scientific_for_huge_values(self):
        rendered = format_difficulty(1e15)
        self.assertNotIn("e", rendered)
        self.assertEqual(rendered, "1000000000000000")


class TestDisplayHash(SoloPoolTestCase):
    def test_reverses_bytes(self):
        self.assertEqual(display_hash(bytes.fromhex("0102")), "0201")
        internal = bytes(range(32))
        self.assertEqual(display_hash(internal), internal[::-1].hex())


class TestPrevhash(SoloPoolTestCase):
    def test_wire_decodes_to_internal(self):
        # A miner per-32-bit-word byteswaps the wire prevhash to recover the
        # canonical internal prevhash (reverse of the RPC display hash).
        display = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        internal = bytes.fromhex(display)[::-1]
        wire = bytes.fromhex(prevhash_to_stratum(display))
        reconstructed = b"".join(wire[i:i + 4][::-1] for i in range(0, 32, 4))
        self.assertEqual(reconstructed, internal)

    def test_known_answer_genesis(self):
        # Pinned wire form for the mainnet genesis block hash.
        display = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        self.assertEqual(
            prevhash_to_stratum(display),
            "0a8ce26f72b3f1b646a2a6c14ff763ae65831e939c085ae10019d66800000000")

    def test_known_answer_distinct_words(self):
        # Eight distinct 4-byte words make the reverse-then-word-swap explicit.
        display = "00112233445566778899aabbccddeeff102030405060708090a0b0c0d0e0f000"
        self.assertEqual(
            prevhash_to_stratum(display),
            "d0e0f00090a0b0c05060708010203040ccddeeff8899aabb4455667700112233")

    def test_output_is_32_bytes(self):
        display = "%064x" % 1
        self.assertEqual(len(bytes.fromhex(prevhash_to_stratum(display))), 32)


class TestSanitize(SoloPoolTestCase):
    def test_normal_worker_passes_through(self):
        self.assertEqual(sanitize("bcrt1qexample.rig1"), "bcrt1qexample.rig1")
        self.assertEqual(sanitize("worker_2"), "worker_2")

    def test_empty_or_none_becomes_placeholder(self):
        self.assertEqual(sanitize(""), "?")
        self.assertEqual(sanitize(None), "?")

    def test_control_chars_are_replaced(self):
        self.assertEqual(sanitize("a\nb"), "a?b")
        self.assertNotIn("\n", sanitize("addr\nINFO BLOCK ACCEPTED height=999"))
        self.assertNotIn("\r", sanitize("a\r\nb"))
        self.assertNotIn("\t", sanitize("a\tb"))

    def test_length_is_hard_capped_without_ellipsis(self):
        out = sanitize("x" * 200, limit=64)
        self.assertEqual(out, "x" * 64)

    def test_printable_unicode_is_kept(self):
        self.assertEqual(sanitize("rig-é"), "rig-é")  # printable non-ASCII is fine


class TestAsciiWorker(SoloPoolTestCase):
    def test_plain_ascii_passes_through(self):
        self.assertEqual(ascii_worker("rig1"), "rig1")
        self.assertEqual(ascii_worker("worker_2.sub"), "worker_2.sub")
        self.assertEqual(ascii_worker(""), "")

    def test_non_ascii_is_dropped_not_replaced(self):
        # Non-ASCII is dropped, not "?"-replaced: "rigé" -> "rig".
        self.assertEqual(ascii_worker("rigé"), "rig")
        self.assertEqual(ascii_worker("aéb"), "ab")     # interleaved
        self.assertEqual(ascii_worker("中文"), "")           # all non-ASCII -> empty
        self.assertEqual(ascii_worker("rig\U0001f600"), "rig")  # emoji dropped

    def test_keeps_only_printable_ascii_range(self):
        self.assertEqual(ascii_worker("a\x7fb"), "ab")       # DEL dropped
        self.assertEqual(ascii_worker("a\x1fb"), "ab")       # control dropped
        # The full printable-ASCII span 0x20-0x7e survives unchanged.
        printable = "".join(chr(c) for c in range(0x20, 0x7f))
        self.assertEqual(ascii_worker(printable), printable)

    def test_unicode_printable_nonascii_codepoints_are_dropped(self):
        # NBSP / ZWSP / soft-hyphen are valid UTF-8 but not ASCII, so ascii_worker drops them.
        self.assertEqual(ascii_worker("rig a"), "riga")   # NBSP (utf-8 c2 a0)
        self.assertEqual(ascii_worker("rig​a"), "riga")   # zero-width space (e2 80 8b)
        self.assertEqual(ascii_worker("rig­a"), "riga")   # soft hyphen (c2 ad)

    def test_caps_length_after_dropping_non_ascii(self):
        self.assertEqual(ascii_worker("a" * 200), "a" * 128)            # default cap 128
        self.assertEqual(ascii_worker("a" * 200, limit=10), "a" * 10)
        # Non-ASCII is dropped before the cap, so char-count == byte-count.
        self.assertEqual(ascii_worker("a " * 200, limit=10), "a" * 10)
