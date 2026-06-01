"""Tests for the accepted-connection TCP keepalive tuning."""

import socket
import unittest

from erikslund_pool.stratum import KEEPALIVE_WINDOW_SECONDS
from erikslund_pool.stratum import keepalive_user_timeout_ms
from erikslund_pool.stratum import tune_keepalive


class TestUserTimeout(unittest.TestCase):
    def test_floored_at_keepalive_window(self):
        # A short work-rebroadcast leaves the keepalive detection window as the floor.
        self.assertEqual(keepalive_user_timeout_ms(30), KEEPALIVE_WINDOW_SECONDS * 1000)
        self.assertEqual(keepalive_user_timeout_ms(0), KEEPALIVE_WINDOW_SECONDS * 1000)

    def test_scales_above_a_large_rebroadcast(self):
        # Timeout must clear 2x the rebroadcast so a quiet miner behind a
        # keepalive-stripping middlebox isn't dropped before the next push.
        self.assertEqual(keepalive_user_timeout_ms(600), 600 * 2 * 1000)
        self.assertGreater(keepalive_user_timeout_ms(600), 600 * 1000)

    def test_crossover_is_at_half_the_window(self):
        # 2*rebroadcast overtakes the 160s window exactly at rebroadcast == 80.
        half_window = KEEPALIVE_WINDOW_SECONDS / 2   # 80s
        self.assertEqual(keepalive_user_timeout_ms(half_window - 1), KEEPALIVE_WINDOW_SECONDS * 1000)
        self.assertEqual(keepalive_user_timeout_ms(half_window), KEEPALIVE_WINDOW_SECONDS * 1000)
        self.assertEqual(keepalive_user_timeout_ms(half_window + 10),
                         int(2 * (half_window + 10) * 1000))

    def test_returns_an_int(self):
        # setsockopt(TCP_USER_TIMEOUT, ...) needs an int even for fractional inputs.
        self.assertIsInstance(keepalive_user_timeout_ms(30.5), int)


class TestTuneKeepalive(unittest.TestCase):
    def test_none_is_noop(self):
        tune_keepalive(None, 30)  # a non-socket transport must not raise

    def test_enables_keepalive_on_a_real_socket(self):
        # The options are settable on an unconnected TCP socket, so no peer needed.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        tune_keepalive(sock, 30)
        self.assertEqual(sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE), 1)
        # Linux-only options: assert only where the platform exposes them.
        if hasattr(socket, "TCP_KEEPIDLE"):
            self.assertEqual(
                sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE), 60)
        if hasattr(socket, "TCP_USER_TIMEOUT"):
            self.assertEqual(
                sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT),
                keepalive_user_timeout_ms(30))


if __name__ == "__main__":
    unittest.main()
