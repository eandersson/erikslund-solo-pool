"""Unit tests for the Prometheus text exposition (metrics.py)."""

import unittest

from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.metrics import _metric
from erikslund_pool.metrics import render_prometheus


class _FakePool:
    def __init__(
        self,
        *,
        ready=True,
        network_diff=1.5,
        height=101,
        nodes=None,
        sv2_ready=None,
        sv2_expiry=None,
    ):
        self._data = {
            "uptime_seconds": 5, "ready": ready,
            "bitcoind_connected": ready, "work_ready": ready, "accepting_connections": True,
            "pool": {"network_diff": network_diff, "height": height, "blocks_found": 2,
                     "shares_accepted": 10, "shares_rejected": 6, "best_share": 4.2,
                     "users": 1, "workers": 3, "hashrate_estimate": 1234.0},
        }
        if nodes is not None:
            self._data["generator"] = {"bitcoind_nodes": nodes}
        if sv2_ready is not None:
            self._data["sv2_authenticated_ready"] = sv2_ready
        if sv2_expiry is not None:
            self._data["sv2_certificate_expiry_timestamp"] = sv2_expiry

    def metrics(self):
        return self._data

    def rejected_by_reason(self):
        return {"stale": 1, "duplicate": 2, "malformed": 0,
                "ntime": 0, "version": 0, "low_difficulty": 3}

    def hashrate_windows(self, now):
        return {window: 0.0 for window in HASHRATE_WINDOWS}


class TestMetricHelper(unittest.TestCase):
    def test_none_value_emits_nothing(self):
        self.assertEqual(_metric("x", "gauge", "h", None), "")

    def test_bool_is_coerced_to_int(self):
        self.assertIn("x 1\n", _metric("x", "gauge", "h", True))
        self.assertIn("x 0\n", _metric("x", "gauge", "h", False))

    def test_includes_help_and_type(self):
        out = _metric("erikslundpool_demo", "counter", "a demo", 7)
        self.assertIn("# HELP erikslundpool_demo a demo\n", out)
        self.assertIn("# TYPE erikslundpool_demo counter\n", out)
        self.assertTrue(out.rstrip().endswith("erikslundpool_demo 7"))


class TestRenderPrometheus(unittest.TestCase):
    def test_ready_pool_emits_core_metrics(self):
        out = render_prometheus(_FakePool(ready=True))
        self.assertIn("erikslundpool_up 1", out)
        self.assertIn("erikslundpool_ready 1", out)
        self.assertIn("erikslundpool_network_difficulty 1.5", out)
        self.assertIn('erikslundpool_subsystem_ready{subsystem="bitcoind"} 1', out)
        self.assertIn("erikslundpool_info{", out)
        self.assertIn('erikslundpool_hashrate_hashes_per_second{window="estimate"} 1234.0', out)

    def test_not_ready_zeroes_ready_gauge(self):
        out = render_prometheus(_FakePool(ready=False))
        self.assertIn("erikslundpool_ready 0", out)
        self.assertIn('erikslundpool_subsystem_ready{subsystem="bitcoind"} 0', out)

    def test_none_pool_values_skip_their_metrics(self):
        out = render_prometheus(_FakePool(network_diff=None, height=None))
        self.assertNotIn("erikslundpool_network_difficulty", out)
        self.assertNotIn("erikslundpool_block_height", out)
        self.assertIn("erikslundpool_blocks_found_total 2", out)

    def test_bitcoind_node_active_gauge_per_node(self):
        out = render_prometheus(_FakePool(nodes=[
            {"address": "http://primary:8332", "active": True},
            {"address": "http://backup:8332", "active": False},
        ]))
        self.assertIn("# TYPE erikslundpool_bitcoind_node_active gauge", out)
        self.assertIn('erikslundpool_bitcoind_node_active{url="http://primary:8332"} 1', out)
        self.assertIn('erikslundpool_bitcoind_node_active{url="http://backup:8332"} 0', out)

    def test_no_node_gauge_without_nodes(self):
        self.assertNotIn("erikslundpool_bitcoind_node_active", render_prometheus(_FakePool()))

    def test_sv2_readiness_and_certificate_expiry_gauges(self):
        out = render_prometheus(_FakePool(sv2_ready=False, sv2_expiry=1_900_000_000))

        self.assertIn("erikslundpool_sv2_authenticated_ready 0", out)
        self.assertIn(
            "erikslundpool_sv2_certificate_expiry_timestamp_seconds 1900000000",
            out,
        )

    def test_sv2_gauges_are_omitted_when_disabled(self):
        out = render_prometheus(_FakePool())

        self.assertNotIn("erikslundpool_sv2_authenticated_ready", out)
        self.assertNotIn("erikslundpool_sv2_certificate_expiry_timestamp_seconds", out)

    def test_reject_by_reason_series_sums_to_total(self):
        out = render_prometheus(_FakePool())
        self.assertIn("# TYPE erikslundpool_shares_rejected_by_reason_total counter", out)
        # Every label present (zeros included), in REJECT_REASONS order; sums to the total (6).
        self.assertIn('erikslundpool_shares_rejected_by_reason_total{reason="stale"} 1', out)
        self.assertIn('erikslundpool_shares_rejected_by_reason_total{reason="duplicate"} 2', out)
        self.assertIn('erikslundpool_shares_rejected_by_reason_total{reason="malformed"} 0', out)
        self.assertIn('erikslundpool_shares_rejected_by_reason_total{reason="ntime"} 0', out)
        self.assertIn('erikslundpool_shares_rejected_by_reason_total{reason="version"} 0', out)
        self.assertIn('erikslundpool_shares_rejected_by_reason_total{reason="low_difficulty"} 3', out)


if __name__ == "__main__":
    unittest.main()
