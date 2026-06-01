"""Functional tests for Settings config parsing (conf/pool.schema.json).

Config files load as YAML (a superset of JSON); fixtures are written as YAML.
"""
from __future__ import annotations

import os
import tempfile

import yaml

from erikslund_pool.config import Settings
from erikslund_pool.exceptions import ConfigError
from erikslund_pool.tests.base import SoloPoolTestCase


class TestSettings(SoloPoolTestCase):
    def _write(self, obj) -> str:
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            yaml.safe_dump(obj, f)
        self.addCleanup(os.unlink, path)
        return path

    def test_load_overrides_and_keeps_defaults(self):
        path = self._write({"stratum_listen": ["0.0.0.0:4444"], "initial_difficulty": 8})
        config = Settings.load(path)
        self.assertEqual(config.bind_port, 4444)
        self.assertEqual(config.initial_difficulty, 8)
        self.assertEqual(config.rpc_user, "erikslund")  # untouched default

    def test_unknown_key_rejected(self):
        path = self._write({"bogus_key": 1})
        with self.assertRaises(ConfigError):
            Settings.load(path)

    def test_missing_file_raises_config_error(self):
        with self.assertRaises(ConfigError):
            Settings.load("/nonexistent/erikslund_pool.json")

    def test_non_object_json_raises_config_error(self):
        path = self._write([1, 2, 3])
        with self.assertRaises(ConfigError):
            Settings.load(path)


class TestConfigSchema(SoloPoolTestCase):
    def test_schema_parses(self):
        config = Settings.from_dict({
            "$schema": "../conf/pool.schema.json",
            "bitcoin_nodes": [
                {"address": "bitcoind:8332", "username": "u", "password": "p", "notify": True},
                {"address": "backup:8332", "username": "u2", "password": "p2"},
            ],
            "stratum_listen": ["0.0.0.0:3333", "0.0.0.0:4001"],
            "coinbase_signature": "/erikslund/",
            "initial_difficulty": 10000,
            "minimum_difficulty": 1,
            "maximum_difficulty": 1000000,
            "extranonce1_size": 4,
            "extranonce2_size": 8,
            "api_listen": ["127.0.0.1:7777"],
            "zmq_block_endpoint": "tcp://bitcoind:28332",
            "block_poll_milliseconds": 250,
            "work_rebroadcast_seconds": 20,
            "max_clients": 50,
            "drop_idle_seconds": 900,
            "version_rolling_mask": "1fffe000",
        })
        self.assertEqual(config.rpc_url, "bitcoind:8332")
        self.assertEqual(config.rpc_user, "u")
        self.assertEqual(config.rpc_password, "p")
        self.assertEqual(len(config.rpc_failover), 1)
        self.assertEqual(config.rpc_failover[0]["url"], "backup:8332")
        self.assertEqual(config.bind_host, "0.0.0.0")
        self.assertEqual(config.bind_ports, [3333, 4001])
        self.assertEqual(config.bind_port, 3333)
        self.assertEqual(config.coinbase_signature, "/erikslund/")
        self.assertEqual(config.initial_difficulty, 10000)
        self.assertEqual(config.minimum_difficulty, 1)
        self.assertEqual(config.maximum_difficulty, 1000000)
        self.assertEqual(config.extranonce1_size, 4)
        self.assertEqual(config.extranonce2_size, 8)
        self.assertEqual(config.api_host, "127.0.0.1")
        self.assertEqual(config.api_port, 7777)
        self.assertEqual(config.zmq_block_endpoint, "tcp://bitcoind:28332")
        self.assertAlmostEqual(config.poll_interval, 0.25)   # block_poll_milliseconds -> seconds
        self.assertEqual(config.work_rebroadcast_seconds, 20)
        self.assertEqual(config.max_clients, 50)
        self.assertEqual(config.drop_idle_seconds, 900)
        self.assertEqual(config.version_rolling_mask, 0x1FFFE000)

    def test_single_stratum_listen_string(self):
        config = Settings.from_dict({"stratum_listen": "0.0.0.0:3333"})
        self.assertEqual(config.bind_host, "0.0.0.0")
        self.assertEqual(config.bind_ports, [3333])
        self.assertEqual(config.bind_port, 3333)

    def test_flat_schema_is_rejected(self):
        # A flat (non-nested) schema is not accepted.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"rpc_url": "http://node:8332", "bind_port": 4444})

    def test_pool_extra_knobs_pass_through(self):
        config = Settings.from_dict({"vardiff_target_shares_per_minute": 30, "status_interval_seconds": 45.0})
        self.assertEqual(config.vardiff_target_shares_per_minute, 30)
        self.assertEqual(config.status_interval_seconds, 45.0)

    def test_empty_dict_keeps_all_defaults(self):
        config = Settings.from_dict({})
        defaults = Settings()
        self.assertEqual(config.rpc_url, defaults.rpc_url)
        self.assertEqual(config.bind_port, defaults.bind_port)
        self.assertEqual(config.api_port, defaults.api_port)
        self.assertEqual(config.version_rolling_mask, defaults.version_rolling_mask)

    def test_three_node_failover_ordering(self):
        # nodes[0] is primary; the rest are failover in declared order; missing
        # credentials yield empty user/password.
        config = Settings.from_dict({"bitcoin_nodes": [
            {"address": "a:1", "username": "ua", "password": "pa"},
            {"address": "b:2"},
            {"address": "c:3", "username": "uc", "password": "pc"},
        ]})
        self.assertEqual(config.rpc_url, "a:1")
        self.assertEqual(config.rpc_user, "ua")
        self.assertEqual([f["url"] for f in config.rpc_failover], ["b:2", "c:3"])
        self.assertEqual(config.rpc_failover[0], {"url": "b:2", "user": "", "password": ""})
        self.assertEqual(config.rpc_failover[1]["user"], "uc")

    def test_single_node_has_no_failover(self):
        config = Settings.from_dict({"bitcoin_nodes": [{"address": "only:8332"}]})
        self.assertEqual(config.rpc_url, "only:8332")
        self.assertEqual(config.rpc_failover, [])

    def test_api_listen_bare_string(self):
        config = Settings.from_dict({"api_listen": "0.0.0.0:9999"})
        self.assertEqual(config.api_host, "0.0.0.0")
        self.assertEqual(config.api_port, 9999)

    def test_stratum_listen_host_defaults_when_omitted(self):
        # ":3333" has no host component -> falls back to 0.0.0.0.
        config = Settings.from_dict({"stratum_listen": ":3333"})
        self.assertEqual(config.bind_host, "0.0.0.0")
        self.assertEqual(config.bind_ports, [3333])

    def test_version_rolling_mask_accepts_int(self):
        config = Settings.from_dict({"version_rolling_mask": 0x00FF0000})
        self.assertEqual(config.version_rolling_mask, 0x00FF0000)

    def test_max_workers_per_address_loads_and_rejects_negative(self):
        self.assertEqual(
            Settings.from_dict({"max_workers_per_address": 32}).max_workers_per_address, 32)
        self.assertEqual(Settings.from_dict({}).max_workers_per_address, 256)  # default
        self.assertEqual(
            Settings.from_dict({"max_workers_per_address": 0}).max_workers_per_address, 0)
        with self.assertRaises(ConfigError):
            Settings.from_dict({"max_workers_per_address": -1})

    def test_user_stats_retention_days_loads_and_rejects_negative(self):
        self.assertEqual(
            Settings.from_dict({"user_stats_retention_days": 30}).user_stats_retention_days, 30)
        self.assertEqual(Settings.from_dict({}).user_stats_retention_days, 90)  # default
        self.assertEqual(
            Settings.from_dict({"user_stats_retention_days": 0}).user_stats_retention_days, 0)
        with self.assertRaises(ConfigError):
            Settings.from_dict({"user_stats_retention_days": -1})
        # Upper bound (~100 years): beyond it the cutoff arithmetic would overflow.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"user_stats_retention_days": 36501})

    def test_version_rolling_mask_is_clamped_to_the_bip320_range(self):
        self.assertEqual(
            Settings.from_dict({"version_rolling_mask": 0xFFFFFFFF}).version_rolling_mask,
            0x1FFFE000)
        self.assertEqual(
            Settings.from_dict({"version_rolling_mask": 0x00003000}).version_rolling_mask,
            0x00002000)

    def test_block_poll_milliseconds_converts_to_seconds(self):
        self.assertAlmostEqual(
            Settings.from_dict({"block_poll_milliseconds": 1500}).poll_interval, 1.5)
        self.assertAlmostEqual(
            Settings.from_dict({"block_poll_milliseconds": 250}).poll_interval, 0.25)
        # 0 ms is rejected: it would busy-loop the poller.
        with self.assertRaises(ConfigError):
            Settings.from_dict({"block_poll_milliseconds": 0})

    def test_donation_fields_and_boolean_flags(self):
        config = Settings.from_dict({
            "donation_percent": 1.5, "donation_address": "bc1qexample",
            "fast_block_notify": False, "variable_difficulty": False,
        })
        self.assertEqual(config.donation_percent, 1.5)
        self.assertEqual(config.donation_address, "bc1qexample")
        self.assertFalse(config.fast_block_notify)
        self.assertFalse(config.variable_difficulty)

    def test_worker_threads_and_size_knobs(self):
        config = Settings.from_dict({
            "worker_threads": 8, "max_line_bytes": 65536, "drop_idle_seconds": 0,
            "auth_timeout_seconds": 45, "max_protocol_errors": 7,
            "extranonce1_size": 6, "extranonce2_size": 4, "coinbase_version": 2,
        })
        self.assertEqual(config.worker_threads, 8)
        self.assertEqual(config.max_line_bytes, 65536)
        self.assertEqual(config.drop_idle_seconds, 0)
        self.assertEqual(config.auth_timeout_seconds, 45)
        self.assertEqual(config.max_protocol_errors, 7)
        self.assertEqual(config.extranonce1_size, 6)
        self.assertEqual(config.extranonce2_size, 4)
        self.assertEqual(config.coinbase_version, 2)

    def test_schema_hint_key_is_ignored(self):
        # The "$schema" editor hint produces no field.
        config = Settings.from_dict({"$schema": "../conf/pool.schema.json"})
        self.assertEqual(config.bind_port, Settings().bind_port)

    def test_unknown_key_names_are_reported(self):
        with self.assertRaises(ConfigError) as ctx:
            Settings.from_dict({"totally_made_up": 1, "another_bad": 2})
        message = str(ctx.exception)
        self.assertIn("another_bad", message)
        self.assertIn("totally_made_up", message)

    def test_non_mapping_rejected(self):
        for bad in ([1, 2, 3], "a string", 42):
            with self.assertRaises(ConfigError):
                Settings.from_dict(bad)


class TestConfigValidation(SoloPoolTestCase):
    """Schema range bounds are enforced.

    These values would otherwise load and then busy-loop, divide by zero, or
    silently reject every share.
    """

    def test_out_of_range_values_rejected(self):
        for cfg in (
            {"initial_difficulty": 0}, {"initial_difficulty": -1},
            {"minimum_difficulty": 0}, {"minimum_difficulty": -0.5},
            {"maximum_difficulty": -0.1},
            {"vardiff_target_shares_per_minute": 0},
            {"vardiff_retarget_seconds": 0},
            {"work_rebroadcast_seconds": 0},
            {"block_poll_milliseconds": 0},
            # extranonce1 min is 4: a 2-3 byte space can wrap and hand two miners the
            # same search space.
            {"extranonce1_size": 1}, {"extranonce1_size": 2},
            {"extranonce1_size": 3}, {"extranonce1_size": 9},
            {"extranonce2_size": 0}, {"extranonce2_size": 9},
            {"donation_percent": -1}, {"donation_percent": 101},
            {"max_clients": -1}, {"drop_idle_seconds": -1},
            {"auth_timeout_seconds": -1}, {"max_protocol_errors": -1},
            {"status_interval_seconds": -1},
        ):
            with self.subTest(cfg=cfg), self.assertRaises(ConfigError):
                Settings.from_dict(cfg)

    def test_boundary_values_accepted(self):
        for cfg in (
            {"extranonce1_size": 4}, {"extranonce1_size": 8}, {"extranonce2_size": 8},
            {"vardiff_retarget_seconds": 1}, {"work_rebroadcast_seconds": 1},
            {"block_poll_milliseconds": 1}, {"maximum_difficulty": 0},
            {"drop_idle_seconds": 0}, {"auth_timeout_seconds": 0},
            {"status_interval_seconds": 0}, {"donation_percent": 0},
            {"donation_percent": 100},
        ):
            with self.subTest(cfg=cfg):
                Settings.from_dict(cfg)  # must not raise
