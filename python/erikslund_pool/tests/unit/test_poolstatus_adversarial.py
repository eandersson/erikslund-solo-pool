"""Adversarial poolstatus reads: missing / empty / corrupt / wrong-shape files.

Contract: read_pool_status/read_user_stats/parse_suffix return None or a clean
default and never crash, so a corrupt stats file can't stop the pool booting.
"""
from __future__ import annotations

import os
import tempfile
import unittest

from erikslund_pool import poolstatus


class _StatusDir:
    """Build a temp stats dir whose pool/pool.status holds arbitrary text."""

    def __init__(self, test, text=None, *, make_pool_dir=True):
        self.dir = tempfile.mkdtemp()
        test.addCleanup(self._cleanup)
        if make_pool_dir:
            os.makedirs(os.path.join(self.dir, "pool"), exist_ok=True)
        if text is not None:
            with open(os.path.join(self.dir, "pool", "pool.status"), "w", encoding="ascii") as f:
                f.write(text)

    def _cleanup(self):
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)


class TestReadPoolStatusCorrupt(unittest.TestCase):
    def _read(self, text=None, **kw):
        return poolstatus.read_pool_status(_StatusDir(self, text, **kw).dir)

    def test_missing_dir_entirely(self):
        self.assertIsNone(poolstatus.read_pool_status("/nonexistent/stats/dir"))

    def test_dir_without_pool_file(self):
        self.assertIsNone(self._read())  # pool/ exists, pool.status absent

    def test_empty_file(self):
        self.assertIsNone(self._read(""))

    def test_whitespace_only_file(self):
        self.assertIsNone(self._read("   \n\t\n"))

    def test_scalar_document(self):
        for text in ("42", "true", "just a bare string"):
            self.assertIsNone(self._read(text))

    def test_sequence_document(self):
        self.assertIsNone(self._read("- 1\n- 2\n- 3\n"))

    def test_truncated_json(self):
        self.assertIsNone(self._read('{"hashrate": {"hashrate1m":'))

    def test_garbage_bytes_as_yaml(self):
        self.assertIsNone(self._read(":\n  - ["))

    def test_tab_indented_yaml_is_rejected_cleanly(self):
        # Tabs are illegal YAML indentation -> YAMLError -> None.
        self.assertIsNone(self._read("a:\n\tb: 1\n"))

    def test_json_shaped_but_missing_sections_defaults(self):
        # A valid mapping with no expected subsections -> zeroed defaults, not None.
        result = self._read("{}")
        self.assertIsNotNone(result)
        self.assertEqual(result["accepted"], 0.0)
        self.assertEqual(result["bestshare"], 0.0)
        self.assertEqual(result["hashrate"], {})
        self.assertEqual(result["lastupdate"], 0)

    def test_wrong_typed_values_handled_where_guarded(self):
        # Guarded fields cope with junk: non-numeric -> 0, null -> 0.0,
        # non-string hashrate entry filtered out.
        text = (
            "pool_stat:\n  lastupdate: not-a-number\n"
            "hashrate:\n  hashrate1m: 43.4M\n  hashrate5m: 12345\n"  # one str, one int
            "shares:\n  accepted: null\n  bestshare: 7\n"
        )
        result = self._read(text)
        self.assertIsNotNone(result)
        self.assertEqual(result["lastupdate"], 0)
        self.assertEqual(result["accepted"], 0.0)
        self.assertEqual(result["bestshare"], 7.0)
        self.assertEqual(result["hashrate"]["hashrate1m"], 43_400_000.0)
        self.assertNotIn("hashrate5m", result["hashrate"])   # non-str dropped

    def test_non_numeric_share_count_should_not_crash(self):
        # A non-numeric count must yield None, not crash.
        text = "shares:\n  rejected: 'not-a-number'\n"
        self.assertIsNone(self._read(text))


class TestReadUserStatsCorrupt(unittest.TestCase):
    def _write_user(self, address, text):
        d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        os.makedirs(os.path.join(d, "users"), exist_ok=True)
        if text is not None:
            with open(os.path.join(d, "users", address), "w", encoding="ascii") as f:
                f.write(text)
        return d

    def test_missing_user_file(self):
        d = self._write_user("bc1qa", None)
        self.assertIsNone(poolstatus.read_user_stats(d, "bc1qa"))

    def test_empty_user_file(self):
        d = self._write_user("bc1qa", "")
        self.assertIsNone(poolstatus.read_user_stats(d, "bc1qa"))

    def test_sequence_user_file(self):
        d = self._write_user("bc1qa", "- 1\n- 2\n")
        self.assertIsNone(poolstatus.read_user_stats(d, "bc1qa"))

    def test_user_file_missing_dir(self):
        self.assertIsNone(poolstatus.read_user_stats("/nonexistent/zzz", "bc1qa"))

    def test_user_file_partial_mapping_defaults(self):
        d = self._write_user("bc1qa", "shares_accepted: 5\n")
        result = poolstatus.read_user_stats(d, "bc1qa")
        self.assertIsNotNone(result)
        self.assertEqual(result["shares_accepted"], 5)
        self.assertEqual(result["bestshare"], 0.0)
        self.assertEqual(result["hashrate1m"], 0.0)


class TestParseSuffixAdversarial(unittest.TestCase):
    def test_empty_and_none_like(self):
        self.assertEqual(poolstatus.parse_suffix(""), 0.0)
        self.assertEqual(poolstatus.parse_suffix("   "), 0.0)

    def test_no_leading_number(self):
        for text in ("abc", "M", "G/s", "++", "NaN-ish"):
            self.assertEqual(poolstatus.parse_suffix(text), 0.0)

    def test_unknown_suffix_is_unit_multiplier(self):
        # A suffix not in the table multiplies by 1.0.
        self.assertEqual(poolstatus.parse_suffix("12x"), 12.0)
        self.assertEqual(poolstatus.parse_suffix("12 H/s"), 12.0)

    def test_signed_and_decimal_and_exponent(self):
        self.assertEqual(poolstatus.parse_suffix("-3K"), -3000.0)
        self.assertEqual(poolstatus.parse_suffix(".5K"), 500.0)
        self.assertEqual(poolstatus.parse_suffix("1e3"), 1000.0)

    def test_trailing_exa_suffix_not_broken_exponent(self):
        self.assertEqual(poolstatus.parse_suffix("5E"), 5e18)


class TestSuffixStringExtremes(unittest.TestCase):
    def test_zero_and_tiny(self):
        self.assertEqual(poolstatus.suffix_string(0), "0")
        self.assertEqual(poolstatus.suffix_string(0.0), "0")

    def test_does_not_crash_on_huge(self):
        # Beyond exa it keeps dividing by peta; must still produce a string.
        self.assertIsInstance(poolstatus.suffix_string(1e30), str)
        self.assertIn("E", poolstatus.suffix_string(1e30))

    def test_significant_digits_on_zero_does_not_crash(self):
        # log10(0) would blow up; the formatter guards display_value <= 0.
        self.assertIsInstance(poolstatus.suffix_string(0, 3), str)


if __name__ == "__main__":
    unittest.main()
