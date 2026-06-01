"""Unit tests for the dashboard's pure helpers (formatting + safe rendering)."""

import unittest

from erikslund_pool.dashboard import _format_difficulty
from erikslund_pool.dashboard import _format_duration
from erikslund_pool.dashboard import _format_hashrate
from erikslund_pool.dashboard import _format_height
from erikslund_pool.dashboard import render
from erikslund_pool.dashboard import render_dashboard
from erikslund_pool.hashrate import HASHRATE_LABELS
from erikslund_pool.hashrate import HASHRATE_WINDOWS


class _FakePool:
    """Minimal surface render_dashboard reads (status/pool_stats/generator_stats)."""
    def __init__(self, *, ready=True, height=101, chain="regtest",
                 network_diff=1.5, connected=3, name="erikslund-solo-pool",
                 uptime=5, windows=None, last_block="2026-06-04T11:31:24Z[UTC]",
                 best_share=0.0):
        self._ready = ready
        self._best_share = best_share
        self._height = height
        self._chain = chain
        self._network_diff = network_diff
        self._connected = connected
        self._name = name
        self._uptime = uptime
        self._windows = windows  # dict[window_seconds -> decaying diff/s], or None -> zeros
        self._last_block = last_block

    def status(self):
        return {"name": self._name, "version": "0.1.0", "pid": 1,
                "ready": self._ready, "uptime": self._uptime}

    def pool_stats(self):
        return {"network_diff": self._network_diff, "height": self._height,
                "blocks_found": 0, "last_block_found": self._last_block,
                "shares_accepted": 0, "shares_rejected": 0, "best_share": self._best_share,
                "workers": self._connected, "users": 0, "hashrate_estimate": 1234.0}

    def generator_stats(self):
        return {"chain": self._chain}

    def hashrate_windows(self, now):
        return self._windows if self._windows is not None else {w: 0.0 for w in HASHRATE_WINDOWS}


class TestFormatHashrate(unittest.TestCase):
    def test_scales(self):
        self.assertEqual(_format_hashrate(0), "0.00 H/s")
        self.assertEqual(_format_hashrate(999), "999.00 H/s")
        self.assertEqual(_format_hashrate(1000), "1.00 KH/s")
        self.assertEqual(_format_hashrate(1500), "1.50 KH/s")
        self.assertEqual(_format_hashrate(2_500_000), "2.50 MH/s")
        self.assertEqual(_format_hashrate(2.5e12), "2.50 TH/s")

    def test_beyond_exa_uses_zetta(self):
        self.assertEqual(_format_hashrate(2.5e21), "2.50 ZH/s")


class TestFormatDuration(unittest.TestCase):
    def test_units(self):
        self.assertEqual(_format_duration(0), "0s")
        self.assertEqual(_format_duration(45), "45s")
        self.assertEqual(_format_duration(65), "1m 5s")
        self.assertEqual(_format_duration(3661), "1h 1m 1s")
        self.assertEqual(_format_duration(90061), "1d 1h 1m 1s")
        self.assertEqual(_format_duration(-5), "0s")  # negative clamps to zero


class TestFormatHeight(unittest.TestCase):
    def test_abbrev_with_raw_value(self):
        self.assertEqual(_format_height(None), "--")
        self.assertEqual(_format_height(200), "200")            # < 1000 -> plain
        self.assertEqual(_format_height(88531), "88.5K (88,531)")
        self.assertEqual(_format_height(870123), "870K (870,123)")


class TestFormatDifficulty(unittest.TestCase):
    def test_abbrev_with_raw_value(self):
        self.assertEqual(_format_difficulty(None), "--")
        self.assertEqual(_format_difficulty(4.657e-10), "4.657e-10")  # tiny (regtest)
        self.assertEqual(_format_difficulty(42), "42")                # 1..1000 -> plain
        self.assertEqual(_format_difficulty(1.24e9), "1.24G (1,240,000,000)")
        self.assertEqual(_format_difficulty(1.1e14), "110T (110,000,000,000,000)")


class TestRenderDashboard(unittest.TestCase):
    def test_ready_state(self):
        html = render_dashboard(_FakePool(ready=True))
        self.assertIn("READY", html)
        self.assertNotIn("NOT READY", html)
        self.assertIn('class="ok"', html)
        self.assertIn("regtest", html)
        self.assertIn("erikslund-solo-pool", html)

    def test_not_ready_state(self):
        html = render_dashboard(_FakePool(ready=False))
        self.assertIn("NOT READY", html)
        self.assertIn('class="bad"', html)

    def test_zero_clients_and_missing_fields(self):
        # height/network_diff/chain all None -> em dashes, no crash.
        html = render_dashboard(
            _FakePool(ready=False, height=None, chain=None, network_diff=None, connected=0))
        self.assertIn("--", html)
        self.assertIn("<table>", html)

    def test_miner_supplied_name_is_escaped(self):
        # The pool name flows through render()'s escaping.
        html = render_dashboard(_FakePool(name="<script>x</script>"))
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_human_readable_fields(self):
        html = render_dashboard(_FakePool(height=88531, uptime=90061, best_share=1.1e14,
                                          windows={60: 1.0, 300: 1.0, 900: 1.0, 3600: 1.0}))
        self.assertIn("88.5K (88,531)", html)   # height: abbreviated + raw value
        self.assertIn("1d 1h 1m 1s", html)      # uptime: human-readable
        self.assertIn("hashrate (1m)", html)    # per-window hashrate, window labeled
        self.assertIn("hashrate (15m)", html)
        self.assertIn("hashrate (1hr)", html)
        self.assertIn("4.29 GH/s", html)        # 1.0 diff/s * 2^32 ~= 4.29 GH/s
        self.assertIn("best share", html)                      # best-share row label
        self.assertIn("110T (110,000,000,000,000)", html)      # best share: abbreviated + raw

    def test_hashrate_window_labels_match_canonical(self):
        html = render_dashboard(_FakePool())
        for window in (60, 300, 900, 3600):
            self.assertIn(f"hashrate ({HASHRATE_LABELS[window]})", html)


class TestRender(unittest.TestCase):
    def test_static_passthrough(self):
        self.assertEqual(render(t"plain text"), "plain text")

    def test_multiple_interpolations(self):
        a, b = "x", "y"
        self.assertEqual(render(t"{a}-{b}"), "x-y")

    def test_interpolations_are_escaped(self):
        evil = "<script>alert(1)</script>&"
        out = render(t"<b>{evil}</b>")
        self.assertIn("<b>", out)             # static markup passes through
        self.assertIn("</b>", out)
        self.assertNotIn("<script>", out)     # the interpolated value is escaped
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("&amp;", out)

    def test_non_string_values_coerced(self):
        self.assertEqual(render(t"{42}"), "42")
