"""Functional tests for the FastAPI HTTP API, driven by Starlette's TestClient."""

import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.routers import stats

_KNOWN_ADDR = "bcrt1qexampleaddr"


class FakePool:
    def __init__(self, ready: bool = True):
        self._ready = ready

    def health(self):
        return self._ready

    def status(self):
        return {"name": "erikslund-solo-pool", "version": "0.1.0", "pid": 1,
                "starttime": 0, "uptime": 5, "bitcoind_connected": self._ready,
                "work_ready": self._ready, "accepting_connections": True, "ready": self._ready}

    def pool_stats(self):
        return {"runtime": 5, "height": 101, "network_diff": 1.0, "current_job": "a",
                "workers": 1, "users": 1, "blocks_found": 2,
                "last_block_found": "2026-06-04T11:31:24Z[UTC]", "shares_accepted": 10,
                "shares_rejected": 0, "best_share": 1.1e14, "hashrate_estimate": 1234.0}

    def hashrate_windows(self, now):
        return {window: 0.0 for window in HASHRATE_WINDOWS}

    def stratifier_stats(self):
        return {"jobs_created": 3, "recent_jobs_cached": 3, "current_job": "a",
                "height": 101, "txns_in_job": 0, "merkle_branch_len": 0}

    def connector_stats(self):
        return {"workers": 1, "subscribed": 1, "authorized": 1}

    def generator_stats(self):
        return {"bitcoind_reachable": True, "chain": "regtest", "tip_height": 100,
                "last_template_age_sec": 1, "rpc_url": "http://node"}

    def client_stats(self, address):
        if address == _KNOWN_ADDR:
            return {"address": address, "workers": 1, "shares_accepted": 10,
                    "best_diff": 0.5, "last_share_ts": 0, "sessions": []}
        return None

    def metrics(self):
        return {"uptime_seconds": 5, "ready": self._ready,
                "pool": self.pool_stats(), "connector": self.connector_stats(),
                "generator": self.generator_stats()}


def make_client(ready: bool = True) -> TestClient:
    app = FastAPI()
    app.include_router(stats.ROUTER)
    app.state.pool = FakePool(ready=ready)
    return TestClient(app)


class TestAPI(unittest.TestCase):
    def setUp(self):
        self.client = make_client()

    def test_health_ok(self):
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.text, "ok\n")

    def test_health_degraded(self):
        r = make_client(ready=False).get("/health")
        self.assertEqual(r.status_code, 503)
        self.assertIn("degraded", r.text)

    def test_status(self):
        body = self.client.get("/status").json()
        self.assertEqual(body["name"], "erikslund-solo-pool")
        self.assertTrue(body["ready"])

    def test_pool_stats(self):
        self.assertEqual(self.client.get("/stats/pool").json()["blocks_found"], 2)

    def test_subsystem_stats(self):
        for path in ("/stats/stratifier", "/stats/connector", "/stats/generator"):
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_metrics_json_aggregates(self):
        body = self.client.get("/metrics.json").json()
        self.assertIn("pool", body)
        self.assertIn("connector", body)

    def test_metrics_prometheus(self):
        r = self.client.get("/metrics")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["content-type"].startswith("text/plain"))
        self.assertIn("erikslundpool_up 1", r.text)
        self.assertIn("# TYPE erikslundpool_ready gauge", r.text)

    def test_client_stats_known(self):
        r = self.client.get(f"/stats/client/{_KNOWN_ADDR}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["address"], _KNOWN_ADDR)

    def test_client_stats_unknown_404(self):
        self.assertEqual(self.client.get("/stats/client/bcrt1qnobody").status_code, 404)

    def test_client_stats_invalid_400(self):
        self.assertEqual(self.client.get("/stats/client/bad!addr").status_code, 400)

    def test_dashboard_is_html(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("text/html", r.headers["content-type"])
        self.assertIn("erikslund-solo-pool", r.text)

    def test_unknown_path_404(self):
        self.assertEqual(self.client.get("/nope").status_code, 404)

    def test_method_not_allowed_405(self):
        self.assertEqual(self.client.post("/status").status_code, 405)
