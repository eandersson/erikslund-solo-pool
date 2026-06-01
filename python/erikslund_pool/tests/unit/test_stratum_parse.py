"""Unit tests for the pure Stratum parsing helpers (no session/socket needed)."""

import unittest

import msgspec

from erikslund_pool.stratum import ClientSession
from erikslund_pool.stratum import StratumRequest


class TestParseSubmit(unittest.TestCase):
    def test_five_params(self):
        self.assertEqual(
            ClientSession._parse_submit(["worker", "jobid", "ee", "tt", "nn"]),
            ("jobid", "ee", "tt", "nn", None),
        )

    def test_with_version_bits(self):
        self.assertEqual(
            ClientSession._parse_submit(["w", "j", "e", "t", "n", "vvvv"]),
            ("j", "e", "t", "n", "vvvv"),
        )

    def test_extra_params_ignored(self):
        # Only the first six positions are meaningful.
        self.assertEqual(
            ClientSession._parse_submit(["w", "j", "e", "t", "n", "vv", "junk"]),
            ("j", "e", "t", "n", "vv"),
        )

    def test_too_few_params(self):
        self.assertIsNone(ClientSession._parse_submit(["w", "j"]))
        self.assertIsNone(ClientSession._parse_submit([]))


class TestClampSuggested(unittest.TestCase):
    """mining.suggest_difficulty clamp helper."""

    def test_in_band_passes_through(self):
        self.assertEqual(ClientSession._clamp_suggested(64.0, 1.0, 1000.0), 64.0)

    def test_below_min_clamps_up(self):
        self.assertEqual(ClientSession._clamp_suggested(0.5, 1.0, 0.0), 1.0)

    def test_above_max_clamps_down(self):
        self.assertEqual(ClientSession._clamp_suggested(1e9, 1.0, 1000.0), 1000.0)

    def test_no_max_means_no_cap(self):
        self.assertEqual(ClientSession._clamp_suggested(1e9, 1.0, 0.0), 1e9)

    def test_string_numeric_is_accepted(self):
        self.assertEqual(ClientSession._clamp_suggested("16", 1.0, 0.0), 16.0)

    def test_rejects_nonpositive_and_garbage(self):
        # 0/negative would zero or invert the share target.
        for bad in (0, -5, float("nan"), float("inf"), "abc", None, [1]):
            self.assertIsNone(ClientSession._clamp_suggested(bad, 1.0, 0.0))


class TestStratumRequestDecode(unittest.TestCase):
    @staticmethod
    def _decode(raw: bytes) -> StratumRequest:
        return msgspec.json.decode(raw, type=StratumRequest)

    def test_full_request(self):
        r = self._decode(b'{"id":7,"method":"mining.submit","params":["a","b"]}')
        self.assertEqual(r.id, 7)
        self.assertEqual(r.method, "mining.submit")
        self.assertEqual(r.params, ["a", "b"])

    def test_defaults_applied(self):
        r = self._decode(b'{"method":"mining.subscribe"}')
        self.assertIsNone(r.id)
        self.assertEqual(r.params, [])

    def test_string_id(self):
        self.assertEqual(self._decode(b'{"id":"abc"}').id, "abc")

    def test_response_has_no_method(self):
        # Unknown fields (result/error) are ignored; method stays None.
        r = self._decode(b'{"id":1,"result":true,"error":null}')
        self.assertIsNone(r.method)
