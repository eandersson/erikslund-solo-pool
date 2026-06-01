"""Unit tests for the `python -m erikslund_pool` CLI bootstrap (__main__)."""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

from erikslund_pool import __main__ as cli
from erikslund_pool.config import SETTINGS
from erikslund_pool.config import Settings


class TestCli(unittest.TestCase):
    def setUp(self):
        # main() mutates the SETTINGS singleton and os.environ in place; snapshot
        # and restore both to keep cases isolated.
        snapshot = Settings()
        snapshot.apply(SETTINGS)
        self.addCleanup(SETTINGS.apply, snapshot)
        env = os.environ.copy()
        self.addCleanup(lambda e=env: (os.environ.clear(), os.environ.update(e)))
        os.environ.pop("LOG_LEVEL", None)
        os.environ.pop("LOG_FORMAT", None)
        os.environ.pop("LOG_FILE", None)

    def _main(self, argv):
        with (
            patch("sys.argv", ["erikslund_pool", *argv]),
            patch("erikslund_pool.__main__.run") as mock_run,
        ):
            cli.main()
        return mock_run

    def test_flags_applied_and_run_called(self):
        mock_run = self._main([
            "--rpc-url", "http://node:8332", "--rpc-user", "u", "--rpc-password", "p",
            "--bind-host", "127.0.0.1", "--bind-port", "4444",
            "--api-host", "127.0.0.1", "--api-port", "8888",
            "--difficulty", "16", "--no-vardiff",
            "--zmq-block", "tcp://node:28332", "--stats-dir", "/tmp/x",
            "--log-level", "DEBUG", "--log-format", "json",
        ])
        mock_run.assert_called_once()
        self.assertEqual(SETTINGS.rpc_url, "http://node:8332")
        self.assertEqual(SETTINGS.bind_port, 4444)
        self.assertEqual(SETTINGS.api_port, 8888)
        self.assertEqual(SETTINGS.initial_difficulty, 16.0)
        self.assertFalse(SETTINGS.variable_difficulty)
        self.assertEqual(SETTINGS.zmq_block_endpoint, "tcp://node:28332")
        self.assertEqual(os.environ["LOG_LEVEL"], "DEBUG")
        self.assertEqual(os.environ["LOG_FORMAT"], "json")

    def test_config_file_loaded(self):
        # Config loads as YAML; a .json file is valid YAML, so this covers both.
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"stratum_listen": ["0.0.0.0:5555"],
                       "bitcoin_nodes": [{"address": "127.0.0.1:8332",
                                          "username": "fromfile", "password": "x"}]}, f)
            path = f.name
        self.addCleanup(os.unlink, path)
        self._main(["--config", path])
        self.assertEqual(SETTINGS.bind_port, 5555)
        self.assertEqual(SETTINGS.rpc_user, "fromfile")

    def test_minimal_invocation_runs(self):
        mock_run = self._main([])
        mock_run.assert_called_once()

    def test_bad_config_exits(self):
        with self.assertRaises(SystemExit):
            self._main(["--config", "/nonexistent/erikslund_pool.json"])

    def test_partial_flags_leave_other_fields_default(self):
        defaults = Settings()
        self._main(["--bind-port", "9001"])
        self.assertEqual(SETTINGS.bind_port, 9001)
        self.assertEqual(SETTINGS.rpc_url, defaults.rpc_url)     # untouched
        self.assertEqual(SETTINGS.api_port, defaults.api_port)   # untouched

    def test_log_level_defaults_to_info(self):
        self._main([])
        self.assertEqual(os.environ.get("LOG_LEVEL"), "INFO")

    def test_log_format_unset_when_flag_absent(self):
        self._main([])
        self.assertNotIn("LOG_FORMAT", os.environ)

    def test_log_file_sets_env(self):
        self._main(["--log-file", "/var/lib/erikslund-pool/pool.log"])
        self.assertEqual(os.environ["LOG_FILE"], "/var/lib/erikslund-pool/pool.log")

    def test_log_file_unset_when_flag_absent(self):
        self._main([])
        self.assertNotIn("LOG_FILE", os.environ)

    def test_difficulty_only_sets_initial_difficulty(self):
        self._main(["--difficulty", "32"])
        self.assertEqual(SETTINGS.initial_difficulty, 32.0)
        self.assertTrue(SETTINGS.variable_difficulty)   # --no-vardiff not passed

    def test_bad_config_message_mentions_config_error(self):
        with self.assertRaises(SystemExit) as ctx:
            self._main(["--config", "/nonexistent/erikslund_pool.json"])
        self.assertIn("config error", str(ctx.exception))
