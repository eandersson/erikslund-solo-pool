"""Unit tests for the Prometheus text exposition (metrics.py)."""

import unittest

from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.metrics import _metric
from erikslund_pool.metrics import render_prometheus


class _FakePool:
    def __init__(self, *, ready=True, network_diff=1.5, height=101, nodes=None):
        self._data = {
            "uptime_seconds": 5, "ready": ready,
            "bitcoind_connected": ready, "work_ready": ready, "accepting_connections": True,
            "pool": {"network_diff": network_diff, "height": height, "blocks_found": 2,
                     "shares_accepted": 10, "shares_rejected": 1, "best_share": 4.2,
                     "users": 1, "workers": 3, "hashrate_estimate": 1234.0},
        }
        if nodes is not None:
            self._data["generator"] = {"bitcoind_nodes": nodes}

    def metrics(self):
        return self._data

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


if __name__ == "__main__":
    unittest.main()
