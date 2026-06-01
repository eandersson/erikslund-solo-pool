"""Unit tests for the decaying-rate model (hashrate.py)."""

import math
import unittest

from erikslund_pool.hashrate import HASHRATE_LABELS
from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.hashrate import SPS_LABELS
from erikslund_pool.hashrate import SPS_WINDOWS
from erikslund_pool.hashrate import DecayingWindows
from erikslund_pool.hashrate import decay_time


class TestDecayTime(unittest.TestCase):
    def test_nonpositive_elapsed_returns_value_unchanged(self):
        self.assertEqual(decay_time(5.0, 100.0, 0.0, 60.0), 5.0)
        self.assertEqual(decay_time(5.0, 100.0, -1.0, 60.0), 5.0)

    def test_zero_addend_decays_toward_zero(self):
        # Aging an idle gap (addend=0) only ever shrinks the value.
        aged = decay_time(10.0, 0.0, 60.0, 60.0)
        self.assertLess(aged, 10.0)
        self.assertGreater(aged, 0.0)

    def test_repeated_idle_decay_is_monotonic(self):
        value = 100.0
        previous = value
        for _ in range(5):
            value = decay_time(value, 0.0, 30.0, 60.0)
            self.assertLess(value, previous)
            previous = value

    def test_matches_closed_form(self):
        value, addend, elapsed, interval = 3.0, 120.0, 30.0, 60.0
        proportion = 1.0 - 1.0 / math.exp(elapsed / interval)
        expected = (value + (addend / elapsed) * proportion) / (1.0 + proportion)
        self.assertAlmostEqual(decay_time(value, addend, elapsed, interval), expected)

    def test_exponent_is_clamped(self):
        # A huge elapsed/interval ratio must not overflow exp(); proportion -> 1.
        result = decay_time(0.0, 60.0, 1e9, 1.0)
        self.assertTrue(math.isfinite(result))
        self.assertGreaterEqual(result, 0.0)

    def test_steady_input_converges_to_rate(self):
        # Folding a steady `interval`-worth of work each step approaches that rate.
        rate = 0.0
        for _ in range(400):
            rate = decay_time(rate, 50.0, 60.0, 60.0)  # 50 units every 60s
        # Per-second rate should approach ~50/60.
        self.assertAlmostEqual(rate, 50.0 / 60.0, places=2)


class TestDecayingWindows(unittest.TestCase):
    def test_starts_at_zero(self):
        windows = DecayingWindows(SPS_WINDOWS, start=1000.0)
        snap = windows.snapshot(1000.0)
        self.assertEqual(set(snap), set(SPS_WINDOWS))
        for value in snap.values():
            self.assertEqual(value, 0.0)

    def test_snapshot_does_not_mutate(self):
        windows = DecayingWindows(SPS_WINDOWS, start=0.0)
        windows.add(10.0, now=60.0)
        first = windows.snapshot(120.0)
        second = windows.snapshot(120.0)
        self.assertEqual(first, second)  # same now -> identical, no internal drift
        third = windows.snapshot(120.0)
        self.assertEqual(first, third)

    def test_add_with_nonpositive_gap_is_ignored(self):
        windows = DecayingWindows(SPS_WINDOWS, start=100.0)
        windows.add(10.0, now=100.0)   # zero gap
        windows.add(10.0, now=90.0)    # negative gap
        for value in windows.snapshot(100.0).values():
            self.assertEqual(value, 0.0)

    def test_short_window_reads_higher_than_long_after_burst(self):
        # A burst of work reads hotter on the short window than the long one.
        windows = DecayingWindows(HASHRATE_WINDOWS, start=0.0)
        windows.add(1e6, now=60.0)
        snap = windows.snapshot(60.0)
        self.assertGreater(snap[60], snap[604800])

    def test_idle_snapshot_decays_below_recorded(self):
        windows = DecayingWindows(SPS_WINDOWS, start=0.0)
        windows.add(100.0, now=60.0)
        hot = windows.snapshot(60.0)[60]
        cold = windows.snapshot(60.0 + 3600.0)[60]  # an hour idle on the 1m window
        self.assertLess(cold, hot)

    def test_all_windows_present_after_add(self):
        windows = DecayingWindows(HASHRATE_WINDOWS, start=0.0)
        windows.add(5.0, now=10.0)
        self.assertEqual(set(windows.snapshot(10.0)), set(HASHRATE_WINDOWS))


class TestWindowLabels(unittest.TestCase):
    def test_every_hashrate_window_has_a_label(self):
        for window in HASHRATE_WINDOWS:
            self.assertIn(window, HASHRATE_LABELS)

    def test_every_sps_window_has_a_label(self):
        for window in SPS_WINDOWS:
            self.assertIn(window, SPS_LABELS)

    def test_label_values_are_expected(self):
        self.assertEqual(HASHRATE_LABELS[60], "1m")
        self.assertEqual(HASHRATE_LABELS[604800], "7d")
        self.assertEqual(SPS_LABELS[3600], "1h")


if __name__ == "__main__":
    unittest.main()
