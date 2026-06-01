"""Adversarial edge inputs for erikslund_pool.util encoders/decoders."""
from __future__ import annotations

import math
import unittest

from erikslund_pool.constants import DIFF1_TARGET
from erikslund_pool.util import bits_to_target
from erikslund_pool.util import difficulty_to_target
from erikslund_pool.util import hash_to_int
from erikslund_pool.util import target_to_difficulty
from erikslund_pool.util import unhex


class TestUnhexAdversarial(unittest.TestCase):
    def test_odd_length_raises_value_error(self):
        for bad in ("a", "abc", "0", "fff"):
            with self.assertRaises(ValueError):
                unhex(bad)

    def test_non_hex_raises_value_error(self):
        # bytes.fromhex skips ASCII spaces, so malformed cases are non-hex chars.
        for bad in ("zz", "gg", "0x10", "hello", "g0g0"):
            with self.assertRaises(ValueError):
                unhex(bad)

    def test_embedded_ascii_space_is_skipped_not_an_error(self):
        # bytes.fromhex ignores interior spaces.
        self.assertEqual(unhex("de ad"), b"\xde\xad")

    def test_empty_is_empty_bytes(self):
        self.assertEqual(unhex(""), b"")

    def test_uppercase_accepted(self):
        self.assertEqual(unhex("DEADBEEF"), b"\xde\xad\xbe\xef")


class TestBitsToTargetAdversarial(unittest.TestCase):
    def test_zero_bits_is_zero_target(self):
        self.assertEqual(bits_to_target(0), 0)

    def test_negative_bits_is_zero_target(self):
        # exponent = -1 >> 24 stays negative; mantissa of 0 -> 0. No crash.
        self.assertEqual(bits_to_target(-1), 0)

    def test_exponent_zero_shifts_mantissa_down(self):
        # exponent 0 -> mantissa >> 24, i.e. the low bits drop entirely.
        self.assertEqual(bits_to_target(0x00123456), 0x123456 >> 24)

    def test_sign_bit_of_mantissa_masked(self):
        # The 0x800000 mantissa sign bit is stripped: 0x80xxxx == 0x00xxxx.
        self.assertEqual(bits_to_target(0x0380FFFF), bits_to_target(0x0300FFFF))

    def test_huge_exponent_is_a_huge_int_no_overflow(self):
        # Python ints don't overflow; an absurd exponent yields a giant int.
        value = bits_to_target(0xFF7FFFFF)
        self.assertIsInstance(value, int)
        self.assertGreater(value, DIFF1_TARGET)


class TestDifficultyTargetGuards(unittest.TestCase):
    def test_zero_and_negative_difficulty_clamp_to_diff1(self):
        self.assertEqual(difficulty_to_target(0), DIFF1_TARGET)
        self.assertEqual(difficulty_to_target(0.0), DIFF1_TARGET)
        self.assertEqual(difficulty_to_target(-1), DIFF1_TARGET)
        self.assertEqual(difficulty_to_target(-1e18), DIFF1_TARGET)

    def test_positive_infinity_difficulty_is_zero_target(self):
        # 1/inf -> 0.0 -> int(0.0) == 0; no exception.
        self.assertEqual(difficulty_to_target(float("inf")), 0)

    def test_nan_difficulty_raises_value_error(self):
        # int(nan) raises; clamp helpers reject NaN upstream, so this stays hard.
        with self.assertRaises(ValueError):
            difficulty_to_target(float("nan"))

    def test_target_to_difficulty_zero_is_inf(self):
        self.assertEqual(target_to_difficulty(0), float("inf"))

    def test_target_to_difficulty_tiny_target_is_large(self):
        self.assertGreater(target_to_difficulty(1), DIFF1_TARGET / 2)

    def test_roundtrip_extremes(self):
        for difficulty in (1e-3, 1.0, 1e6, 1e12):
            recovered = target_to_difficulty(difficulty_to_target(difficulty))
            self.assertTrue(math.isclose(recovered, difficulty, rel_tol=1e-6))


class TestHashToIntEdge(unittest.TestCase):
    def test_all_zero_is_zero(self):
        self.assertEqual(hash_to_int(b"\x00" * 32), 0)

    def test_all_ff_is_max(self):
        self.assertEqual(hash_to_int(b"\xff" * 32), (1 << 256) - 1)

    def test_little_endian_orientation(self):
        self.assertEqual(hash_to_int(b"\x01" + b"\x00" * 31), 1)
        self.assertEqual(hash_to_int(b"\x00" * 31 + b"\x01"), 1 << 248)

    def test_empty_bytes_is_zero(self):
        self.assertEqual(hash_to_int(b""), 0)


if __name__ == "__main__":
    unittest.main()
