"""Unit tests for Settings defaults and in-place apply (no file I/O)."""

import unittest

from erikslund_pool.config import MAX_AUTO_WORKERS
from erikslund_pool.config import Settings
from erikslund_pool.config import resolve_worker_count


class TestSettings(unittest.TestCase):
    def test_defaults(self):
        s = Settings()
        self.assertEqual(s.bind_port, 3333)
        self.assertEqual(s.api_port, 7777)
        self.assertEqual(s.max_clients, 1024)
        self.assertEqual(s.max_line_bytes, 16384)
        self.assertEqual(s.auth_timeout_seconds, 30)
        self.assertEqual(s.max_protocol_errors, 100)
        self.assertTrue(s.variable_difficulty)
        self.assertEqual(s.worker_threads, 0)


class TestResolveWorkerCount(unittest.TestCase):
    def test_explicit_value_is_honored(self):
        self.assertEqual(resolve_worker_count(4), 4)
        self.assertEqual(resolve_worker_count(100), 100)  # explicit is unclamped

    def test_auto_is_clamped_and_positive(self):
        n = resolve_worker_count(0)
        self.assertGreaterEqual(n, 1)
        self.assertLessEqual(n, MAX_AUTO_WORKERS)

    def test_apply_copies_every_field(self):
        s = Settings()
        other = Settings(bind_port=9001, rpc_user="bob", max_clients=5, variable_difficulty=False)
        s.apply(other)
        self.assertEqual(s.bind_port, 9001)
        self.assertEqual(s.rpc_user, "bob")
        self.assertEqual(s.max_clients, 5)
        self.assertFalse(s.variable_difficulty)
