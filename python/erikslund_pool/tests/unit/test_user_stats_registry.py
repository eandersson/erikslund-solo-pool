"""The persistent per-(address, worker-name) stats registry: survives worker
disconnects (rows aren't tied to a live session) and restarts (recover_user_stats
re-seeds from users/ files, decaying each hashrate by the file's age)."""
import os
import tempfile
import time
import unittest

from erikslund_pool import poolstatus
from erikslund_pool.config import Settings
from erikslund_pool.pool import Pool

ADDR = "bcrt1qlk935ze2fsu86zjp395uvtegztrkaezawxx0wf"


class _FakeSession:
    """Minimal ClientSession stand-in: only address/worker/authorized are read."""

    def __init__(self, address, worker, authorized=True):
        self.address = address
        self.worker = worker
        self.authorized = authorized


def _rows(pool, address):
    now = time.monotonic()
    rows = [r for r in pool._snapshot_user_stats(now, time.time()) if r["address"] == address]
    return sorted(rows, key=lambda r: r["worker"])


class TestRegistry(unittest.TestCase):
    def test_shares_accumulate_and_one_name_merges(self):
        pool = Pool(Settings())
        # Two connections share "w1"; a third is "w2" -- they MERGE by name.
        pool.note_accepted_share(ADDR, "w1", 5.0, 5.0)
        pool.note_accepted_share(ADDR, "w1", 3.0, 3.0)
        pool.note_rejected_share(ADDR, "w1")
        pool.note_accepted_share(ADDR, "w2", 1.0, 1.0)

        rows = _rows(pool, ADDR)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["worker"], "w1")
        self.assertEqual(rows[0]["shares_accepted"], 2)
        self.assertEqual(rows[0]["shares_rejected"], 1)
        self.assertEqual(rows[0]["best_diff"], 5.0)
        self.assertGreater(rows[0]["hashrate"][60], 0.0)
        self.assertEqual(rows[1]["worker"], "w2")

    def test_best_diff_is_the_actual_hash_difficulty_not_credited(self):
        # best_diff records the actual difficulty met, not the credited share value.
        pool = Pool(Settings())
        pool.note_accepted_share(ADDR, "w1", 8.0, 5000.0)   # credited 8, actual 5000
        pool.note_accepted_share(ADDR, "w1", 8.0, 120.0)
        rows = _rows(pool, ADDR)
        self.assertEqual(rows[0]["best_diff"], 5000.0)      # max actual, not the 8.0 credited
        self.assertEqual(rows[0]["shares_accepted"], 2)

    def test_row_persists_after_the_connection_ends(self):
        pool = Pool(Settings())
        pool.note_accepted_share(ADDR, "rig", 4.0, 4.0)
        # No live clients, yet the row persists (not connected).
        rows = _rows(pool, ADDR)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["shares_accepted"], 1)
        self.assertFalse(rows[0]["connected"])

    def test_attach_worker_creates_a_zero_row(self):
        pool = Pool(Settings())
        pool.attach_worker(ADDR, "idle")
        rows = _rows(pool, ADDR)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["worker"], "idle")
        self.assertEqual(rows[0]["shares_accepted"], 0)

    def test_names_beyond_the_cap_fold_into_the_bare_address_bucket(self):
        pool = Pool(Settings(max_workers_per_address=2))
        pool.note_accepted_share(ADDR, "w1", 1.0, 1.0)
        pool.note_accepted_share(ADDR, "w2", 1.0, 1.0)
        pool.note_accepted_share(ADDR, "w3", 7.0, 7.0)  # over the cap -> bucket
        pool.note_accepted_share(ADDR, "w4", 1.0, 1.0)  # also bucket
        rows = _rows(pool, ADDR)
        self.assertEqual(len(rows), 3)  # "", w1, w2
        self.assertEqual(rows[0]["worker"], "")
        self.assertEqual(rows[0]["shares_accepted"], 2)  # w3 + w4
        self.assertEqual(rows[0]["best_diff"], 7.0)

    def test_prune_evicts_idle_rows_but_keeps_recent_ones(self):
        pool = Pool(Settings(user_stats_retention_days=1))
        pool.note_accepted_share(ADDR, "old", 1.0, 1.0)
        pool.note_accepted_share(ADDR, "new", 1.0, 1.0)
        # Backdate "old" beyond the 1-day window.
        with pool._user_stats_lock:
            pool._user_stats[ADDR]["old"].last_activity_ts = time.time() - 2 * 86400
        pool.prune_user_stats()
        self.assertEqual({r["worker"] for r in _rows(pool, ADDR)}, {"new"})

    def test_never_mined_row_ages_out_even_with_retention_disabled(self):
        # retention_days=0 keeps mined rows forever, but a never-mined disconnected
        # row must still age out after the ghost grace, else authorize-churn pins the cap.
        pool = Pool(Settings(user_stats_retention_days=0))
        pool.attach_worker(ADDR, "ghost")                  # never mined
        pool.note_accepted_share(ADDR, "real", 1.0, 1.0)   # mined
        with pool._user_stats_lock:
            stale = time.time() - 10 * 86400               # well past the ghost grace
            pool._user_stats[ADDR]["ghost"].last_activity_ts = stale
            pool._user_stats[ADDR]["real"].last_activity_ts = stale
        pool.prune_user_stats()
        # ghost evicted despite retention=0; the mined row is kept forever.
        self.assertEqual({r["worker"] for r in _rows(pool, ADDR)}, {"real"})

    def test_connected_never_mined_row_is_not_evicted(self):
        # A live authorized-but-not-yet-mining worker stays visible even past the grace.
        pool = Pool(Settings(user_stats_retention_days=0))
        pool.attach_worker(ADDR, "live")
        with pool._user_stats_lock:
            pool._user_stats[ADDR]["live"].last_activity_ts = time.time() - 10 * 86400
        pool.register(_FakeSession(ADDR, "live"))  # now connected
        pool.prune_user_stats()
        self.assertEqual({r["worker"] for r in _rows(pool, ADDR)}, {"live"})

    def test_rejected_only_active_rig_still_gets_a_file(self):
        # A rig with only rejected shares (0 accepted) is still active and must get a file.
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = Pool(Settings(stats_directory=temp_dir))
            pool.note_rejected_share(ADDR, "badrig")
            poolstatus.write_user_files(pool, temp_dir)
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "users", ADDR)))

    def test_authorize_and_never_mine_row_is_prunable(self):
        # last_activity_ts (not last_share_ts) is the prune clock, so an
        # attach-created row (last_share_ts == 0) still ages out.
        pool = Pool(Settings(user_stats_retention_days=1))
        pool.attach_worker(ADDR, "ghost")
        self.assertEqual(len(_rows(pool, ADDR)), 1)
        with pool._user_stats_lock:
            pool._user_stats[ADDR]["ghost"].last_activity_ts = time.time() - 2 * 86400
        pool.prune_user_stats()  # no live connection -> evicted despite last_share_ts == 0
        self.assertEqual(len(_rows(pool, ADDR)), 0)

    def test_recover_reseeds_from_users_files_with_decay(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            writer = Pool(Settings(stats_directory=temp_dir))
            for _ in range(20):
                writer.note_accepted_share(ADDR, "rig", 1000.0, 1000.0)
            poolstatus.write_user_files(writer, temp_dir)
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "users", ADDR)))

            reader = Pool(Settings(stats_directory=temp_dir))
            reader.recover_user_stats()
            rows = _rows(reader, ADDR)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["worker"], "rig")
            self.assertEqual(rows[0]["shares_accepted"], 20)  # shares recovered exactly
            self.assertEqual(rows[0]["best_diff"], 1000.0)
            self.assertGreater(rows[0]["hashrate"][60], 0.0)  # hashrate recovered (decayed)

    def test_recover_does_not_launder_the_prune_clock_through_file_mtime(self):
        # A recovered row's prune clock must derive from its last share, not the
        # fresh file mtime, else an aging row never ages out across restarts.
        with tempfile.TemporaryDirectory() as temp_dir:
            writer = Pool(Settings(stats_directory=temp_dir, user_stats_retention_days=3))
            writer.note_accepted_share(ADDR, "rig", 1000.0, 1000.0)
            last_share = int(time.time() - 2 * 86400)  # 2 days ago: within the 3-day window
            with writer._user_stats_lock:
                writer._user_stats[ADDR]["rig"].last_share_ts = last_share
            poolstatus.write_user_files(writer, temp_dir)  # file mtime is "now"

            reader = Pool(Settings(stats_directory=temp_dir, user_stats_retention_days=3))
            reader.recover_user_stats()
            self.assertEqual(len(_rows(reader, ADDR)), 1)  # within retention -> recovered
            # The prune clock tracks the real last share (2 days ago), NOT the fresh file mtime.
            with reader._user_stats_lock:
                recovered = reader._user_stats[ADDR]["rig"].last_activity_ts
            self.assertEqual(recovered, last_share)
            self.assertGreater(time.time() - recovered, 86400)  # clearly not reset to ~now

    def test_recover_skips_never_mined_and_expired_rows(self):
        # recover must not resurrect a never-mined row (last_share_ts == 0) or one
        # whose last share is past the retention window.
        with tempfile.TemporaryDirectory() as temp_dir:
            writer = Pool(Settings(stats_directory=temp_dir))
            writer.attach_worker(ADDR, "ghost")             # never mined
            writer.note_accepted_share(ADDR, "stale", 1.0, 1.0)
            writer.note_accepted_share(ADDR, "fresh", 1.0, 1.0)
            with writer._user_stats_lock:
                writer._user_stats[ADDR]["stale"].last_share_ts = time.time() - 10 * 86400
            poolstatus.write_user_files(writer, temp_dir)

            reader = Pool(Settings(stats_directory=temp_dir, user_stats_retention_days=1))
            reader.recover_user_stats()
            # Only "fresh" survives: "ghost" never mined, "stale" is past retention.
            self.assertEqual({r["worker"] for r in _rows(reader, ADDR)}, {"fresh"})

    def test_prune_unlinks_the_users_file_on_full_eviction(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = Pool(Settings(stats_directory=temp_dir, user_stats_retention_days=1))
            pool.note_accepted_share(ADDR, "rig", 1.0, 1.0)
            poolstatus.write_user_files(pool, temp_dir)
            path = os.path.join(temp_dir, "users", ADDR)
            self.assertTrue(os.path.exists(path))
            with pool._user_stats_lock:
                pool._user_stats[ADDR]["rig"].last_activity_ts = time.time() - 2 * 86400
            pool.prune_user_stats()  # whole address evicted -> file removed with the row
            self.assertEqual(len(_rows(pool, ADDR)), 0)
            self.assertFalse(os.path.exists(path))

    def test_zero_stat_address_gets_no_file_until_its_first_share(self):
        # Authorize-then-disconnect (0 accepted) must not create a users/ file (write
        # amplification / churn vector); the file appears on the first share.
        with tempfile.TemporaryDirectory() as temp_dir:
            pool = Pool(Settings(stats_directory=temp_dir))
            pool.attach_worker(ADDR, "idle")
            poolstatus.write_user_files(pool, temp_dir)
            self.assertFalse(os.path.exists(os.path.join(temp_dir, "users", ADDR)))
            pool.note_accepted_share(ADDR, "idle", 1.0, 1.0)
            poolstatus.write_user_files(pool, temp_dir)
            self.assertTrue(os.path.exists(os.path.join(temp_dir, "users", ADDR)))


if __name__ == "__main__":
    unittest.main()
