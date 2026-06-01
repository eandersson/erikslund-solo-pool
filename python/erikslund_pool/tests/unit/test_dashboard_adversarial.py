"""Adversarial dashboard rendering: missing/None/garbage fields + XSS escaping.

Some interpolated fields are attacker-influenced (e.g. `chain` from bitcoind), so
render must never crash and must HTML-escape every interpolation.
"""
from __future__ import annotations

import unittest

from erikslund_pool.dashboard import _format_hashrate
from erikslund_pool.dashboard import render
from erikslund_pool.dashboard import render_dashboard
from erikslund_pool.hashrate import HASHRATE_WINDOWS


class _StubPool:
    """A pool stand-in whose three stat dicts are fully caller-controlled."""

    def __init__(self, status, pool_stats, generator_stats):
        self._status = status
        self._pool_stats = pool_stats
        self._generator_stats = generator_stats

    def status(self):
        return self._status

    def pool_stats(self):
        return self._pool_stats

    def generator_stats(self):
        return self._generator_stats

    def hashrate_windows(self, now):
        return {w: 0.0 for w in HASHRATE_WINDOWS}


def _base_status(**over):
    s = {"name": "erikslund-solo-pool", "version": "0.1.0", "mode": "solo",
         "pid": 1, "ready": True, "uptime": 5}
    s.update(over)
    return s


def _base_pool_stats(**over):
    s = {"network_diff": 1.5, "height": 101, "blocks_found": 0, "last_block_found": None,
         "shares_accepted": 0, "shares_rejected": 0, "best_share": 0.0, "workers": 0, "users": 0,
         "hashrate_estimate": 0.0}
    s.update(over)
    return s


def _base_generator_stats(**over):
    s = {"chain": "regtest"}
    s.update(over)
    return s


class TestRenderDashboardMissingFields(unittest.TestCase):
    def _render(self, *, status=None, pool_stats=None, generator_stats=None):
        return render_dashboard(_StubPool(
            status or _base_status(),
            pool_stats or _base_pool_stats(),
            generator_stats or _base_generator_stats()))

    def test_all_none_optionals_render_em_dash(self):
        html = self._render(
            status=_base_status(ready=False),
            pool_stats=_base_pool_stats(network_diff=None, height=None),
            generator_stats=_base_generator_stats(chain=None))
        self.assertIsInstance(html, str)
        self.assertIn("--", html)
        self.assertIn("NOT READY", html)
        self.assertIn("<table>", html)

    def test_zero_fields_render(self):
        html = self._render(pool_stats=_base_pool_stats(
            network_diff=0.0, height=0, connected=0, users=0, hashrate_estimate=0.0))
        self.assertIsInstance(html, str)
        self.assertIn("0.00 H/s", html)

    def test_none_name_and_version_do_not_crash(self):
        html = self._render(status=_base_status(name=None, version=None, mode=None, pid=None))
        self.assertIsInstance(html, str)
        self.assertIn("None", html)

    def test_not_ready_uses_bad_class(self):
        html = self._render(status=_base_status(ready=False))
        self.assertIn('class="bad"', html)
        self.assertIn("NOT READY", html)


class TestDashboardXssEscaping(unittest.TestCase):
    """Every interpolated, externally-influenced value must be HTML-escaped."""

    def _render(self, *, status=None, pool_stats=None, generator_stats=None):
        return render_dashboard(_StubPool(
            status or _base_status(),
            pool_stats or _base_pool_stats(),
            generator_stats or _base_generator_stats()))

    def test_malicious_pool_name_is_escaped(self):
        html = self._render(status=_base_status(name="<script>alert(1)</script>"))
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_malicious_chain_from_bitcoind_is_escaped(self):
        # `chain` is whatever bitcoind reports; treat it as untrusted.
        html = self._render(generator_stats=_base_generator_stats(
            chain="<img src=x onerror=alert(1)>"))
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertIn("&lt;img", html)

    def test_attribute_breakout_is_escaped(self):
        # Name attempting to break out of the <title>/attribute context.
        html = self._render(status=_base_status(name='"></title><script>x</script>'))
        self.assertNotIn("<script>x</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_ampersand_and_quotes_escaped(self):
        html = self._render(status=_base_status(name='Tom & "Jerry"'))
        self.assertIn("&amp;", html)
        self.assertNotIn('"Jerry"', html)   # the raw double-quote pair is escaped


class TestRenderHelper(unittest.TestCase):
    def test_static_text_passthrough(self):
        self.assertEqual(render(t"hello world"), "hello world")

    def test_each_interpolation_escaped(self):
        evil = "<b>&'\""
        out = render(t"x{evil}y")
        self.assertNotIn("<b>", out)
        self.assertIn("&lt;b&gt;", out)
        self.assertIn("&amp;", out)

    def test_non_string_interpolation_coerced(self):
        self.assertEqual(render(t"{None}"), "None")
        self.assertEqual(render(t"{12345}"), "12345")
        self.assertEqual(render(t"{[1, 2]}"), "[1, 2]")

    def test_object_repr_is_escaped(self):
        class Evil:
            def __str__(self):
                return "<x>"

        self.assertEqual(render(t"{Evil()}"), "&lt;x&gt;")


class TestFormatHashrateAdversarial(unittest.TestCase):
    def test_zero(self):
        self.assertEqual(_format_hashrate(0), "0.00 H/s")

    def test_negative_does_not_crash(self):
        # A negative estimate shouldn't occur, but must still format as a string.
        self.assertIsInstance(_format_hashrate(-5.0), str)
        self.assertIn("H/s", _format_hashrate(-5.0))

    def test_beyond_exa_is_zetta(self):
        self.assertEqual(_format_hashrate(2.5e21), "2.50 ZH/s")

    def test_extreme_value_is_a_string(self):
        self.assertIsInstance(_format_hashrate(1e40), str)


if __name__ == "__main__":
    unittest.main()
