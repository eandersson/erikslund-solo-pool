"""Adversarial config tests: malformed / wrong-type / out-of-range inputs.

Contract: reject cleanly with ConfigError, never an unhandled crash.
"""
from __future__ import annotations

import os
import tempfile
import unittest

import yaml

from erikslund_pool.config import MAX_AUTO_WORKERS
from erikslund_pool.config import Settings
from erikslund_pool.config import resolve_worker_count
from erikslund_pool.exceptions import ConfigError
from erikslund_pool.tests.base import SoloPoolTestCase


class TestFromDictNonMapping(SoloPoolTestCase):
    """from_dict must reject anything that isn't a dict with ConfigError."""

    def test_none_rejected(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict(None)

    def test_scalars_and_sequences_rejected(self):
        for bad in (1, 1.5, True, "string", b"bytes", [1, 2], (1, 2), {1, 2}):
            with self.assertRaises(ConfigError):
                Settings.from_dict(bad)


class TestCoinbaseScriptSigBudget(SoloPoolTestCase):
    """coinbase_signature must leave room in the 100-byte scriptSig for the height push (worst
    case 10) + extranonces, rejected at load -- else the pool starts but silently never mines."""

    def test_overlong_coinbase_signature_rejected(self):
        # Default extranonces 4 + 8 = 12, + 10 height = 22 -> 78 bytes left for the signature.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"coinbase_signature": "x" * 79})

    def test_signature_that_fits_is_accepted(self):
        cfg = Settings.from_dict({"coinbase_signature": "x" * 78})
        self.assertEqual(cfg.coinbase_signature, "x" * 78)

    def test_budget_accounts_for_larger_extranonces(self):
        # enonce 8 + 8 = 16, + 10 = 26 -> only 74 bytes left.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"extranonce1_size": 8, "extranonce2_size": 8,
                                "coinbase_signature": "x" * 75})


class TestFromDictUnknownKeys(SoloPoolTestCase):
    def test_single_unknown_key(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"definitely_not_a_key": 1})

    def test_unknown_keys_listed_in_message(self):
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_dict({"zeta_bad": 1, "alpha_bad": 2})
        message = str(ctx.exception)
        self.assertIn("alpha_bad", message)
        self.assertIn("zeta_bad", message)

    def test_typo_of_real_key_is_rejected(self):
        # A near-miss typo of a real key is still unknown -> rejected, not ignored.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"initial_dificulty": 8})  # missing an 'f'


class TestFalsyOptionalsKeepDefaults(SoloPoolTestCase):
    """Empty/falsy optional containers are skipped, not error -- defaults stand."""

    def test_empty_bitcoin_nodes_keeps_default_rpc(self):
        config = Settings.from_dict({"bitcoin_nodes": []})
        self.assertEqual(config.rpc_url, Settings().rpc_url)
        self.assertEqual(config.rpc_failover, [])

    def test_empty_stratum_listen_keeps_default_bind(self):
        config = Settings.from_dict({"stratum_listen": []})
        self.assertEqual(config.bind_port, Settings().bind_port)

    def test_empty_api_listen_keeps_default(self):
        config = Settings.from_dict({"api_listen": []})
        self.assertEqual(config.api_port, Settings().api_port)


class TestWrongTypeScalarsDoNotCrash(SoloPoolTestCase):
    """A wrong-typed scalar is rejected cleanly: range-validated fields reject a non-number;
    un-validated pass-through fields land verbatim. Either way, no unhandled crash."""

    def test_string_for_validated_int_field_is_rejected(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"extranonce1_size": "four"})

    def test_string_for_bool_field_is_stored_verbatim(self):
        # variable_difficulty is not range-validated, so it lands as-is.
        config = Settings.from_dict({"variable_difficulty": "yes"})
        self.assertEqual(config.variable_difficulty, "yes")

    def test_null_zmq_endpoint_is_accepted(self):
        config = Settings.from_dict({"zmq_block_endpoint": None})
        self.assertIsNone(config.zmq_block_endpoint)


class TestVersionRollingMaskParsing(SoloPoolTestCase):
    def test_valid_hex_string_parsed(self):
        self.assertEqual(Settings.from_dict({"version_rolling_mask": "1fffe000"}).version_rolling_mask,
                         0x1FFFE000)

    def test_int_passes_through(self):
        self.assertEqual(Settings.from_dict({"version_rolling_mask": 0xFF0000}).version_rolling_mask,
                         0xFF0000)

    def test_uppercase_and_0x_prefixed_hex(self):
        self.assertEqual(Settings.from_dict({"version_rolling_mask": "0x1FFFE000"}).version_rolling_mask,
                         0x1FFFE000)


class TestResolveWorkerCountAdversarial(SoloPoolTestCase):
    """Out-of-range worker counts: <=0 auto-clamps; explicit huge is honoured."""

    def test_negative_auto_clamps_into_band(self):
        for value in (-1, -5, -10_000):
            n = resolve_worker_count(value)
            self.assertGreaterEqual(n, 1)
            self.assertLessEqual(n, MAX_AUTO_WORKERS)

    def test_zero_auto_clamps_into_band(self):
        n = resolve_worker_count(0)
        self.assertGreaterEqual(n, 1)
        self.assertLessEqual(n, MAX_AUTO_WORKERS)

    def test_huge_explicit_is_honoured_unclamped(self):
        # An explicit positive value is trusted as-is.
        self.assertEqual(resolve_worker_count(10_000), 10_000)
        self.assertEqual(resolve_worker_count(1_000_000_000), 1_000_000_000)


class TestLoadAdversarial(SoloPoolTestCase):
    """Settings.load is the operator-facing path; bad files -> ConfigError."""

    def _write_text(self, text: str) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def _write_yaml(self, obj) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(obj, f)
        self.addCleanup(os.unlink, path)
        return path

    def test_missing_path(self):
        with self.assertRaises(ConfigError):
            Settings.load("/nonexistent/does/not/exist.yaml")

    def test_directory_instead_of_file(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError):
                Settings.load(d)

    def test_empty_file_is_none_mapping(self):
        # An empty YAML doc parses to None -> "config must be a mapping".
        with self.assertRaises(ConfigError):
            Settings.load(self._write_text(""))

    def test_scalar_yaml(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_text("42"))

    def test_sequence_yaml(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_yaml([1, 2, 3]))

    def test_malformed_yaml_unclosed_flow(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_text("a: [1, 2"))

    def test_malformed_yaml_bad_indent(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_text("a:\n  b: 1\n bad-dedent: 2\n"))

    def test_unknown_key_via_file(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_yaml({"not_a_real_key": True}))


class TestMalformedValuesShouldBeConfigError(SoloPoolTestCase):
    def test_stratum_listen_host_without_port(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"stratum_listen": "justhost"})

    def test_stratum_listen_non_numeric_port(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"stratum_listen": "0.0.0.0:notaport"})

    def test_stratum_listen_port_zero_or_out_of_range_rejected(self):
        # Port 0 binds an unreachable ephemeral port; >65535, "3333x", -1 are invalid.
        for bad in ("0.0.0.0:0", "0.0.0.0:70000", "0.0.0.0:3333x", "0.0.0.0:-1"):
            with self.assertRaises(ConfigError, msg=bad):
                Settings.from_dict({"stratum_listen": bad})

    def test_stratum_listen_mixed_hosts_rejected(self):
        # Only one bind host is honored; differing per-entry hosts are rejected, else a
        # loopback high-diff port could leak onto 0.0.0.0.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"stratum_listen": ["0.0.0.0:3333", "127.0.0.1:4001"]})
        # Same host across entries still loads fine.
        config = Settings.from_dict({"stratum_listen": ["0.0.0.0:3333", "0.0.0.0:4001"]})
        self.assertEqual(config.bind_ports, [3333, 4001])

    def test_api_listen_host_without_port(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"api_listen": "justhost"})

    def test_version_rolling_mask_bad_hex(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"version_rolling_mask": "nothex"})

    def test_version_rolling_mask_empty_string(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"version_rolling_mask": ""})

    def test_block_poll_milliseconds_non_numeric(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"block_poll_milliseconds": "soon"})

    def test_bitcoin_nodes_is_a_mapping_not_a_list(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"bitcoin_nodes": {"address": "a:1"}})

    def test_bitcoin_nodes_node_missing_address(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"bitcoin_nodes": [{"username": "u", "password": "p"}]})

    def test_bitcoin_nodes_node_is_a_string(self):
        with self.assertRaises(ConfigError):
            Settings.from_dict({"bitcoin_nodes": ["host:8332"]})


class TestLoadFileWithMalformedValueShouldBeConfigError(SoloPoolTestCase):
    def _write_yaml(self, obj) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(obj, f)
        self.addCleanup(os.unlink, path)
        return path

    def test_load_bad_port_file_is_config_error(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_yaml({"stratum_listen": "justhost"}))

    def test_load_bad_mask_file_is_config_error(self):
        with self.assertRaises(ConfigError):
            Settings.load(self._write_yaml({"version_rolling_mask": "nothex"}))


if __name__ == "__main__":
    unittest.main()
