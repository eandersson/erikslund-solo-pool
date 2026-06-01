"""Tests for the on-disk stats format (poolstatus)."""

import os
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

import yaml

from erikslund_pool import poolstatus
from erikslund_pool.constants import DIFF1_TARGET
from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.hashrate import SPS_WINDOWS
from erikslund_pool.hashrate import DecayingWindows


def _session(address, *, diff=0.0, shares=0, rejected=0, best=0.0, last=0.0, worker=None,
             authorized=True, peer=None):
    now = time.monotonic()
    hashrate = DecayingWindows(HASHRATE_WINDOWS, now - 600)
    if diff:
        hashrate.add(diff, now)
    return SimpleNamespace(address=address, total_share_diff=diff, difficulty=diff,
                           shares_accepted=shares, shares_rejected=rejected, best_diff=best,
                           last_share_ts=last, worker=worker or address,
                           peer=peer or f"{worker or address}:0",
                           authorized=authorized, hashrate=hashrate)


def _rows_from_sessions(sessions, now):
    """Synthesize registry rows (Pool._snapshot_user_stats) by grouping sessions
    on (address, worker name) and summing."""
    groups: dict = {}
    for c in sessions:
        if not (c.authorized and c.address):
            continue
        # A worker name equal to the address (the _session default) is the bare-address bucket "".
        worker = "" if (c.worker or "") in ("", c.address) else c.worker
        key = (c.address, worker)
        g = groups.setdefault(key, {"address": c.address, "worker": worker, "connected": True,
                                    "shares_accepted": 0, "shares_rejected": 0, "best_diff": 0.0,
                                    "last_share_ts": 0,
                                    "hashrate": {w: 0.0 for w in HASHRATE_WINDOWS}})
        sw = c.hashrate.snapshot(now)
        for w in HASHRATE_WINDOWS:
            g["hashrate"][w] += sw[w]
        g["shares_accepted"] += int(c.shares_accepted)
        g["shares_rejected"] += int(c.shares_rejected)
        g["best_diff"] = max(g["best_diff"], c.best_diff)
        g["last_share_ts"] = max(g["last_share_ts"], int(c.last_share_ts))
    return list(groups.values())


def _pool(clients=(), *, total_diff=0.0, best=0.0, baseline=0.0, shares=0,
          rejected=0, network_difficulty=None, started=None, blocks_found=0,
          blocks_by_address=None, last_block_found=0):
    now = time.monotonic()
    started = started if started is not None else now - 3600   # monotonic base
    job = None
    if network_difficulty is not None:
        job = SimpleNamespace(network_target=DIFF1_TARGET / network_difficulty)
    hashrate = DecayingWindows(HASHRATE_WINDOWS, started)
    shares_per_second = DecayingWindows(SPS_WINDOWS, started)
    if total_diff:
        hashrate.add(total_diff, now)
        shares_per_second.add(1.0, now)
    client_list = list(clients)
    # poolstatus reads clients via _snapshot_clients(); stats fields are under _stats_lock.
    return SimpleNamespace(
        started=time.time(), _started_monotonic=started, clients=client_list,
        _snapshot_clients=lambda: list(client_list), _stats_lock=threading.Lock(),
        _snapshot_user_stats=lambda now, now_wall: _rows_from_sessions(client_list, now),
        blocks_found=blocks_found, last_block_found=last_block_found,
        _blocks_by_address=dict(blocks_by_address or {}),
        total_share_diff=total_diff, best_diff=best, _baseline_diff=baseline,
        shares_accepted=shares, shares_rejected=rejected, current_job=job,
        # build_pool_status reads the job via _current_job_locked() (under the jobs lock).
        _current_job_locked=lambda: job,
        hashrate_windows=hashrate.snapshot, sps_windows=shares_per_second.snapshot)


class TestSuffixString(unittest.TestCase):
    def test_matches_known_outputs(self):
        cases = {
            0: "0", 500: "500", 999: "999",
            1000: "1K", 1500: "1.5K",
            1_000_000: "1M", 43_400_000: "43.4M",
            2_500_000_000: "2.5G",
            1_230_000_000_000: "1.23T",
            1_000_000_000_000_000: "1P",
            1_000_000_000_000_000_000: "1E",
        }
        for value, expected in cases.items():
            self.assertEqual(poolstatus.suffix_string(value), expected, f"value={value}")

    def test_parse_suffix_roundtrip(self):
        for value in (0.0, 500.0, 1000.0, 43_400_000.0, 2.5e9, 1.23e12, 1e15, 1e18):
            text = poolstatus.suffix_string(value)
            # %.3g keeps 3 significant figures, so allow that rounding.
            self.assertAlmostEqual(poolstatus.parse_suffix(text), value,
                                   delta=abs(value) * 0.005 + 1)

    def test_parse_known_strings(self):
        self.assertEqual(poolstatus.parse_suffix("43.4M"), 43_400_000.0)
        self.assertEqual(poolstatus.parse_suffix("1K"), 1000.0)
        self.assertEqual(poolstatus.parse_suffix("2.5G"), 2.5e9)
        self.assertEqual(poolstatus.parse_suffix("500"), 500.0)
        self.assertEqual(poolstatus.parse_suffix(""), 0.0)

    def test_parse_suffix_edge_cases(self):
        # A trailing "E" with no exponent digits is the exa suffix, not a float exponent.
        self.assertEqual(poolstatus.parse_suffix("5E"), 5e18)
        self.assertEqual(poolstatus.parse_suffix("  2.5G  "), 2.5e9)   # whitespace
        self.assertEqual(poolstatus.parse_suffix("5m"), 5e6)           # suffix upcased
        self.assertEqual(poolstatus.parse_suffix(".5K"), 500.0)        # leading dot
        self.assertEqual(poolstatus.parse_suffix("-3K"), -3000.0)      # signed
        self.assertEqual(poolstatus.parse_suffix("abc"), 0.0)          # no number
        self.assertEqual(poolstatus.parse_suffix("1e3"), 1000.0)       # real exponent

    def test_suffix_string_with_significant_digits(self):
        self.assertEqual(poolstatus.suffix_string(43_400_000, 3), "43.4M")
        self.assertEqual(poolstatus.suffix_string(1500, 4), "1.500K")

    def test_suffix_string_sub_kilo_has_no_suffix(self):
        self.assertEqual(poolstatus.suffix_string(0), "0")
        self.assertEqual(poolstatus.suffix_string(42), "42")
        self.assertEqual(poolstatus.suffix_string(999), "999")


class TestPoolStatusShape(unittest.TestCase):
    def test_keys_and_types(self):
        pool = _pool([_session("bc1qa", diff=100.0, best=5000.0)],
                     total_diff=100.0, best=5000.0, shares=10, rejected=2,
                     network_difficulty=1_000_000.0)
        status = poolstatus.build_pool_status(pool)

        self.assertEqual(list(status), ["pool_stat", "blocks_by_address", "hashrate", "shares"])
        self.assertEqual(list(status["pool_stat"]),
                         ["runtime", "lastupdate", "users", "workers", "blocks_found",
                          "last_block_found"])
        self.assertEqual(list(status["hashrate"]),
                         ["hashrate1m", "hashrate5m", "hashrate15m", "hashrate1hr",
                          "hashrate6hr", "hashrate1d", "hashrate7d"])
        self.assertEqual(list(status["shares"]),
                         ["best_share_percent", "accepted", "rejected", "bestshare",
                          "shares_per_second_1m", "shares_per_second_5m",
                          "shares_per_second_15m", "shares_per_second_1h"])

        for k in ("accepted", "rejected", "bestshare"):
            self.assertIsInstance(status["shares"][k], int)
        self.assertIsInstance(status["pool_stat"]["lastupdate"], str)  # human date-time
        for k in ("runtime", "users", "workers"):
            self.assertIsInstance(status["pool_stat"][k], int)
        for v in status["hashrate"].values():
            self.assertIsInstance(v, str)  # suffix strings ("43.4M")

    def test_windows_differ(self):
        # Decaying windows: short-span work reads higher on the short window.
        pool = _pool([], total_diff=1e6, network_difficulty=1_000_000.0,
                     started=time.monotonic() - 7200)
        status = poolstatus.build_pool_status(pool)
        one_min = poolstatus.parse_suffix(status["hashrate"]["hashrate1m"])
        seven_day = poolstatus.parse_suffix(status["hashrate"]["hashrate7d"])
        self.assertGreater(one_min, seven_day)

    def test_baseline_and_best_fold_in(self):
        pool = _pool([_session("bc1qa", diff=50.0, best=9000.0)],
                     total_diff=50.0, best=1000.0, baseline=12345.0,
                     shares=5, network_difficulty=1_000_000.0)
        status = poolstatus.build_pool_status(pool)
        self.assertEqual(status["shares"]["accepted"], int(12345.0 + 50.0))
        self.assertEqual(status["shares"]["bestshare"], 9000)


def _user_stats(address, sessions, now, blocks=0):
    """Render an address's file from rows synthesized from `sessions`; the
    connection count is the authorized sessions."""
    rows = [r for r in _rows_from_sessions(sessions, now) if r["address"] == address]
    conns = sum(1 for c in sessions if c.authorized and c.address == address)
    return poolstatus.build_user_stats(address, rows, conns, blocks)


class TestBuildUserStats(unittest.TestCase):
    def test_empty_rows_yield_zeroed_stats(self):
        stats = poolstatus.build_user_stats("bc1qa", [], 0)
        self.assertEqual(stats["workers"], 0)
        self.assertEqual(stats["shares_accepted"], 0)
        self.assertEqual(stats["bestshare"], 0.0)
        self.assertEqual(stats["worker"], [])
        self.assertEqual(stats["blocks"], 0)

    def test_blocks_count_is_passed_through(self):
        stats = poolstatus.build_user_stats("bc1qa", [], 0, blocks=3)
        self.assertEqual(stats["blocks"], 3)

    def test_sums_and_maxes_across_workers(self):
        now = time.monotonic()
        sessions = [
            _session("bc1qa", diff=100.0, shares=10, best=500.0, last=1700.0, worker="bc1qa.w1"),
            _session("bc1qa", diff=50.0, shares=5, best=900.0, last=1800.0, worker="bc1qa.w2"),
        ]
        stats = _user_stats("bc1qa", sessions, now)
        self.assertEqual(stats["workers"], 2)             # live connection count
        self.assertEqual(stats["shares_accepted"], 15)    # summed
        self.assertEqual(stats["bestshare"], 900.0)       # max
        self.assertEqual(stats["lastshare"], poolstatus._format_rfc9557(1800))
        self.assertEqual(len(stats["worker"]), 2)
        self.assertEqual({w["workername"] for w in stats["worker"]}, {"bc1qa.w1", "bc1qa.w2"})

    def test_per_worker_hashrate_fields_present(self):
        now = time.monotonic()
        stats = _user_stats("bc1qa", [_session("bc1qa", diff=100.0, worker="bc1qa.w1")], now)
        worker = stats["worker"][0]
        for window in ("1m", "5m", "15m", "1hr", "6hr", "1d", "7d"):
            self.assertIn(f"hashrate{window}", worker)
        self.assertNotIn("difficulty", worker)  # deliberately absent: not unique per name

    def test_sessions_sharing_a_worker_name_merge_into_one_row(self):
        # Worker names are not unique: w1 from three machines is one row, summed.
        now = time.monotonic()
        sessions = [
            _session("bc1qa", shares=5, rejected=1, best=9.0, last=130, worker="w1",
                     peer="192.168.0.2:1"),
            _session("bc1qa", shares=1, rejected=1, best=2.0, last=100, worker="w1",
                     peer="192.168.0.3:1"),
            _session("bc1qa", shares=1, rejected=1, best=3.0, last=140, worker="w1",
                     peer="192.168.0.4:1"),
            _session("bc1qa", shares=1, rejected=1, best=4.0, last=110, worker="w2"),
            _session("bc1qa", shares=1, rejected=1, best=5.0, last=120, worker="w2",
                     peer="192.168.0.6:1"),
            _session("bc1qa", shares=1, rejected=1, best=6.0, last=125, worker="w3"),
        ]
        stats = _user_stats("bc1qa", sessions, now)
        self.assertEqual(len(stats["worker"]), 3)  # w1, w2, w3 -- one row per NAME
        self.assertEqual(stats["workers"], 6)      # ...while the connection count stays truthful
        w1, w2, w3 = stats["worker"]
        self.assertEqual(w1["workername"], "w1")
        self.assertEqual(w1["shares_accepted"], 7)               # 5 + 1 + 1
        self.assertEqual(w1["shares_rejected"], 3)
        self.assertNotIn("difficulty", w1)  # deliberately absent: not unique per name
        self.assertEqual(w1["bestshare"], 9.0)                   # max
        self.assertEqual(w1["lastshare"], poolstatus._format_rfc9557(140))  # latest
        self.assertEqual(w2["shares_accepted"], 2)
        self.assertEqual(w3["shares_accepted"], 1)
        self.assertEqual(stats["shares_accepted"], 10)           # address total: everyone


class TestEmptyPoolStatus(unittest.TestCase):
    def test_no_clients_no_job(self):
        status = poolstatus.build_pool_status(_pool([]))
        self.assertEqual(status["pool_stat"]["users"], 0)
        self.assertEqual(status["pool_stat"]["workers"], 0)
        self.assertEqual(status["shares"]["accepted"], 0)
        self.assertEqual(status["shares"]["bestshare"], 0)


class TestRoundTrip(unittest.TestCase):
    def test_document_roundtrips_as_yaml(self):
        pool = _pool([_session("bc1qa", diff=200.0, best=7777.0)],
                     total_diff=200.0, best=7777.0, network_difficulty=2_000_000.0)
        status = poolstatus.build_pool_status(pool)
        text = yaml.safe_dump(status, sort_keys=False, default_flow_style=False)
        self.assertEqual(yaml.safe_load(text), status)

    def test_pool_status_write_then_read(self):
        pool = _pool([_session("bc1qa", diff=200.0, best=7777.0)],
                     total_diff=200.0, best=7777.0, baseline=1000.0,
                     shares=20, network_difficulty=2_000_000.0)
        with tempfile.TemporaryDirectory() as temp_dir:
            poolstatus.write_pool_status(pool, temp_dir)
            path = os.path.join(temp_dir, "pool", "pool.status")
            self.assertTrue(os.path.exists(path))
            self.assertTrue(open(path, encoding="ascii").read().endswith("\n"))

            result = poolstatus.read_pool_status(temp_dir)
            self.assertEqual(result["accepted"], 1200.0)
            self.assertEqual(result["bestshare"], 7777.0)
            self.assertGreater(result["hashrate"]["hashrate1m"], 0.0)

    def test_read_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertIsNone(poolstatus.read_pool_status(temp_dir))

    def test_blocks_found_and_addresses_persist(self):
        # blocks_found, last-block timestamp, and per-address tallies survive a write/read cycle.
        pool = _pool(blocks_found=4, last_block_found=1700000000,
                     blocks_by_address={"bc1qa": 3, "bc1qb": 1})
        with tempfile.TemporaryDirectory() as temp_dir:
            poolstatus.write_pool_status(pool, temp_dir)
            result = poolstatus.read_pool_status(temp_dir)
            self.assertEqual(result["blocks_found"], 4)
            self.assertEqual(result["last_block_found"], 1700000000)  # RFC 9557 round-trip
            self.assertEqual(result["blocks_by_address"], {"bc1qa": 3, "bc1qb": 1})

    def test_missing_blocks_fields_default_to_zero_and_empty(self):
        # A pool.status without these fields recovers gracefully.
        pool = _pool()  # blocks_found=0, no addresses, no last block
        with tempfile.TemporaryDirectory() as temp_dir:
            poolstatus.write_pool_status(pool, temp_dir)
            result = poolstatus.read_pool_status(temp_dir)
            self.assertEqual(result["blocks_found"], 0)
            self.assertEqual(result["last_block_found"], 0)
            self.assertEqual(result["blocks_by_address"], {})

    def test_user_files_write_then_read(self):
        session1 = _session("bc1qa", diff=100.0, shares=10, best=500.0, last=1700.0, worker="bc1qa.w1")
        session2 = _session("bc1qa", diff=50.0, shares=5, best=900.0, last=1800.0, worker="bc1qa.w2")
        pool = _pool([session1, session2], started=time.monotonic() - 3600)
        with tempfile.TemporaryDirectory() as temp_dir:
            poolstatus.write_user_files(pool, temp_dir)
            result = poolstatus.read_user_stats(temp_dir, "bc1qa")
            self.assertEqual(result["shares_accepted"], 15)        # summed across workers
            self.assertEqual(result["bestshare"], 900.0)  # max across workers
            self.assertEqual(result["workers"], 2)


class TestRfc9557(unittest.TestCase):
    def test_format_is_utc_rfc9557(self):
        self.assertEqual(poolstatus._format_rfc9557(1700000000), "2023-11-14T22:13:20Z[UTC]")
        self.assertEqual(poolstatus._format_rfc9557(0), "")     # never -> empty
        self.assertEqual(poolstatus._format_rfc9557(-5), "")

    def test_parse_round_trips(self):
        self.assertEqual(poolstatus._parse_rfc9557("2023-11-14T22:13:20Z[UTC]"), 1700000000)
        self.assertEqual(poolstatus._parse_rfc9557("2023-11-14T22:13:20Z"), 1700000000)  # bare Z
        self.assertEqual(poolstatus._parse_rfc9557(""), 0)
        self.assertEqual(poolstatus._parse_rfc9557("not a date"), 0)
        self.assertEqual(poolstatus._parse_rfc9557(None), 0)


class TestUserFilePathSafety(unittest.TestCase):
    """A miner-supplied username flows into the users/<address> filename, so it must
    never escape the users/ directory or be written for an unauthorized client."""

    def test_is_safe_address(self):
        for ok in ("bc1qexample", "1A2b3C", "addr_1.worker", "x" * 100):
            self.assertTrue(poolstatus._is_safe_address(ok), ok)
        for bad in ("", "a/b", "/abs/path", "..", ".", "x" * 101, "a\\b", "a b", None, 123):
            self.assertFalse(poolstatus._is_safe_address(bad), repr(bad))

    def test_stale_user_files_are_pruned_but_active_miners_never_are(self):
        # Files older than the retention window are pruned (mtime == last activity);
        # a connected miner's file survives an old mtime, and pruning frees a cap slot.
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(poolstatus, "MAX_USER_FILES", 2):
            users = os.path.join(temp_dir, "users")
            pool = _pool([_session("bc1qgone", shares=1, worker="bc1qgone.w"),
                          _session("bc1qstays", shares=1, worker="bc1qstays.w")])
            poolstatus.write_user_files(pool, temp_dir)  # mint both files (cap now full)
            self.assertEqual(sorted(os.listdir(users)), ["bc1qgone", "bc1qstays"])

            # Backdate BOTH beyond the 1-day retention; bc1qgone disconnects, bc1qstays stays.
            stale = time.time() - 2 * 86400
            os.utime(os.path.join(users, "bc1qgone"), (stale, stale))
            os.utime(os.path.join(users, "bc1qstays"), (stale, stale))
            pool = _pool([_session("bc1qstays", shares=2, worker="bc1qstays.w"),
                          _session("bc1qnew", shares=1, worker="bc1qnew.w")])
            poolstatus.write_user_files(pool, temp_dir, retention_seconds=86400.0,
                                        prune_sweep_seconds=0.0)
            self.assertEqual(sorted(os.listdir(users)), ["bc1qstays"])  # gone pruned; cap was full
            # ...and the freed slot lets the next new address mint a file.
            poolstatus.write_user_files(pool, temp_dir, retention_seconds=86400.0,
                                        prune_sweep_seconds=0.0)
            self.assertEqual(sorted(os.listdir(users)), ["bc1qnew", "bc1qstays"])

    def test_retention_zero_never_prunes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            users = os.path.join(temp_dir, "users")
            pool = _pool([_session("bc1qold", shares=1, worker="bc1qold.w")])
            poolstatus.write_user_files(pool, temp_dir)
            stale = time.time() - 365 * 86400
            os.utime(os.path.join(users, "bc1qold"), (stale, stale))
            poolstatus.write_user_files(_pool([]), temp_dir, retention_seconds=0.0,
                                        prune_sweep_seconds=0.0)
            self.assertEqual(os.listdir(users), ["bc1qold"])  # 0 = keep forever

    def test_write_user_files_seeds_cap_registry_from_existing_dir(self):
        # On first visit the cap registry is seeded from files already on disk.
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(poolstatus, "MAX_USER_FILES", 2), \
                mock.patch.dict(poolstatus._known_user_files, {}, clear=True):
            users = os.path.join(temp_dir, "users")
            os.makedirs(users)
            for name in ("addrA", "addrB"):  # pre-existing from a prior run
                with open(os.path.join(users, name), "w", encoding="ascii") as f:
                    f.write("x")
            # Cap full from the seeded files -> a NEW address is refused, a seeded one updates.
            poolstatus.write_user_files(_pool([_session("addrNEW", shares=1, worker="addrNEW.w")]),
                                        temp_dir)
            self.assertNotIn("addrNEW", os.listdir(users))
            poolstatus.write_user_files(_pool([_session("addrA", shares=1, worker="addrA.w")]),
                                        temp_dir)
            self.assertEqual(sorted(os.listdir(users)), ["addrA", "addrB"])

    def test_write_user_files_caps_new_file_creation(self):
        # Creation is capped so an address-cycling attacker can't grow users/ unbounded;
        # addresses with an existing file keep updating.
        from unittest import mock
        with tempfile.TemporaryDirectory() as temp_dir, \
                mock.patch.object(poolstatus, "MAX_USER_FILES", 2):
            users = os.path.join(temp_dir, "users")
            pool = _pool([_session("bc1qa", shares=1, worker="bc1qa.w"),
                          _session("bc1qb", shares=1, worker="bc1qb.w")])
            poolstatus.write_user_files(pool, temp_dir)
            self.assertEqual(sorted(os.listdir(users)), ["bc1qa", "bc1qb"])

            # At the cap: a NEW address is refused, while a known one still updates.
            pool = _pool([_session("bc1qa", shares=2, worker="bc1qa.w"),
                          _session("bc1qnew", shares=1, worker="bc1qnew.w")])
            poolstatus.write_user_files(pool, temp_dir)
            self.assertEqual(sorted(os.listdir(users)), ["bc1qa", "bc1qb"])
            self.assertEqual(poolstatus.read_user_stats(temp_dir, "bc1qa")["shares_accepted"], 2)

    def test_write_user_files_skips_unsafe_and_unauthorized(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            escaped = os.path.join(temp_dir, "pwned")
            pool = _pool([
                _session("bc1qgood", shares=1, worker="bc1qgood.w"),       # written
                _session("evil/escape", shares=1),                         # '/' -> skipped
                _session(escaped, shares=1),                               # absolute -> must not escape
                _session("..", shares=1),                                  # parent ref -> skipped
                _session("bc1qunauth", shares=1, authorized=False),        # unauthorized -> skipped
            ])
            poolstatus.write_user_files(pool, temp_dir)

            users = os.path.join(temp_dir, "users")
            self.assertTrue(os.path.exists(os.path.join(users, "bc1qgood")))
            self.assertFalse(os.path.exists(os.path.join(users, "bc1qunauth")))
            self.assertFalse(os.path.exists(escaped))   # absolute-path address did NOT escape
            self.assertFalse(os.path.exists(os.path.join(users, "evil", "escape")))
            self.assertEqual(os.listdir(users), ["bc1qgood"])   # exactly the one safe address


class TestCrossLoad(unittest.TestCase):
    # A JSON-shaped status file; the reader must ingest it (YAML superset of JSON).
    SAMPLE = """{
 "pool_stat": {
  "runtime": 3600,
  "lastupdate": 1700000000,
  "Users": 2,
  "Workers": 3,
  "Idle": 0,
  "Disconnected": 1
 },
 "hashrate": {
  "hashrate1m": "43.4M",
  "hashrate5m": "40.1M",
  "hashrate15m": "38M",
  "hashrate1hr": "35M",
  "hashrate6hr": "30M",
  "hashrate1d": "25M",
  "hashrate7d": "20M"
 },
 "shares": {
  "diff": 12.34,
  "accepted": 123456,
  "rejected": 12,
  "bestshare": 98765,
  "shares_per_second_1m": 1.5,
  "shares_per_second_5m": 1.2,
  "shares_per_second_15m": 1,
  "shares_per_second_1h": 0.8
 }
}
"""

    def test_reads_json_shaped_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            os.makedirs(os.path.join(temp_dir, "pool"))
            with open(os.path.join(temp_dir, "pool", "pool.status"), "w", encoding="ascii") as f:
                f.write(self.SAMPLE)
            result = poolstatus.read_pool_status(temp_dir)
            self.assertEqual(result["lastupdate"], 1700000000)
            self.assertEqual(result["accepted"], 123456.0)
            self.assertEqual(result["rejected"], 12.0)
            self.assertEqual(result["bestshare"], 98765.0)
            self.assertEqual(result["hashrate"]["hashrate1m"], 43_400_000.0)
            self.assertEqual(result["sps1m"], 1.5)


if __name__ == "__main__":
    unittest.main()
