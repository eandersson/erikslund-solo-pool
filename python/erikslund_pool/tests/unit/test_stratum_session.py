"""Async ClientSession handler tests (subscribe/configure/authorize/suggest/submit)."""

import time

from erikslund_pool.config import Settings
from erikslund_pool.constants import ERR_DUPLICATE
from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.stratum import ClientSession
from erikslund_pool.stratum import StratumRequest
from erikslund_pool.tests.base import AsyncSoloPoolTestCase
from erikslund_pool.tests.scenario.test_share_to_block import FakePool
from erikslund_pool.tests.scenario.test_share_to_block import FakeWriter


def _session(config, *, extranonce1=b"\x00\x00\x00\x01", job=None, pool=None):
    pool = pool or FakePool(job, config)
    return ClientSession(pool, None, FakeWriter(), extranonce1)


class TestSubscribe(AsyncSoloPoolTestCase):
    async def test_subscribe_returns_extranonce_and_size(self):
        config = Settings(extranonce2_size=8)
        session = _session(config, extranonce1=b"\xaa\xbb\xcc\xdd")
        await session.handle_subscribe(1, ["cgminer/4.10"])
        result = session.writer.by_id(1)["result"]
        self.assertEqual(result[1], "aabbccdd")        # extranonce1
        self.assertEqual(result[2], 8)                  # extranonce2_size
        self.assertEqual(result[0][0][0], "mining.set_difficulty")
        self.assertTrue(session.subscribed)
        self.assertEqual(session.user_agent, "cgminer/4.10")

    async def test_subscribe_without_params_uses_default_agent(self):
        session = _session(Settings())
        await session.handle_subscribe(1, [])
        self.assertTrue(session.subscribed)
        self.assertEqual(session.user_agent, "?")

    async def test_non_string_user_agent_keeps_default(self):
        # A non-string params[0] keeps the default "?" rather than being str()-coerced.
        session = _session(Settings())
        await session.handle_subscribe(1, [12345])
        self.assertTrue(session.subscribed)
        self.assertEqual(session.user_agent, "?")


class TestConfigure(AsyncSoloPoolTestCase):
    async def test_version_rolling_intersects_with_server_mask(self):
        config = Settings(version_rolling_mask=0x1FFFE000)
        session = _session(config)
        await session.handle_configure(1, [["version-rolling"],
                                           {"version-rolling.mask": "ffffffff"}])
        result = session.writer.by_id(1)["result"]
        self.assertTrue(result["version-rolling"])
        self.assertEqual(result["version-rolling.mask"], "1fffe000")
        self.assertEqual(session.version_mask, 0x1FFFE000)

    async def test_narrower_client_mask_is_honored(self):
        config = Settings(version_rolling_mask=0x1FFFE000)
        session = _session(config)
        await session.handle_configure(1, [["version-rolling"],
                                           {"version-rolling.mask": "00006000"}])
        self.assertEqual(session.version_mask, 0x00006000)
        self.assertEqual(session.writer.by_id(1)["result"]["version-rolling.mask"], "00006000")

    async def test_malformed_client_mask_yields_zero(self):
        config = Settings(version_rolling_mask=0x1FFFE000)
        session = _session(config)
        await session.handle_configure(1, [["version-rolling"],
                                           {"version-rolling.mask": "not-hex"}])
        self.assertEqual(session.version_mask, 0)

    async def test_no_version_rolling_extension_returns_empty(self):
        session = _session(Settings())
        await session.handle_configure(1, [[], {}])
        self.assertEqual(session.writer.by_id(1)["result"], {})
        self.assertEqual(session.version_mask, 0)

    async def test_empty_params_does_not_raise(self):
        session = _session(Settings())
        await session.handle_configure(1, [])
        self.assertEqual(session.writer.by_id(1)["result"], {})


class TestAuthorize(AsyncSoloPoolTestCase):
    async def test_valid_address_authorizes_and_pushes_difficulty(self):
        config = Settings(initial_difficulty=4)
        session = _session(config)
        await session.handle_authorize(2, ["bcrt1qworker.rig1"])
        self.assertIs(session.writer.by_id(2)["result"], True)
        self.assertTrue(session.authorized)
        self.assertEqual(session.address, "bcrt1qworker")   # before the first dot
        self.assertEqual(session.worker, "rig1")            # worker name = suffix
        methods = [m.get("method") for m in session.writer.messages()]
        self.assertIn("mining.set_difficulty", methods)

    async def test_empty_or_absent_worker_name_is_allowed(self):
        # No worker suffix or an empty one (trailing dot) authorizes fine;
        # only the payout address is validated.
        for username, expect_worker in [("bcrt1qworker", ""), ("bcrt1qworker.", "")]:
            session = _session(Settings())
            await session.handle_authorize(2, [username])
            self.assertIs(session.writer.by_id(2)["result"], True, username)
            self.assertTrue(session.authorized, username)
            self.assertEqual(session.address, "bcrt1qworker", username)
            self.assertEqual(session.worker, expect_worker, username)

    async def test_invalid_address_is_refused(self):
        class BadAddrPool(FakePool):
            async def validate_address(self, _address):
                return (False, None)

        session = _session(Settings(), pool=BadAddrPool(None, Settings()))
        await session.handle_authorize(2, ["badaddr.worker"])
        self.assertIs(session.writer.by_id(2)["result"], False)
        self.assertFalse(session.authorized)

    async def test_invalid_address_counts_toward_the_abuse_budget(self):
        # A definite invalid address increments protocol_errors so an authorize flood self-disconnects.
        class BadAddrPool(FakePool):
            async def validate_address(self, _address):
                return (False, None)

        session = _session(Settings(), pool=BadAddrPool(None, Settings()))
        self.assertEqual(session.protocol_errors, 0)
        await session.handle_authorize(2, ["badaddr.worker"])
        self.assertEqual(session.protocol_errors, 1)
        await session.handle_authorize(3, ["otherbad.worker"])
        self.assertEqual(session.protocol_errors, 2)  # each distinct invalid counts

    async def test_rpc_error_during_authorize_does_not_count_as_abuse(self):
        # A transient node failure must not be charged to the miner (else a bitcoind hiccup
        # mass-disconnects honest re-authorizing miners).
        class DownNodePool(FakePool):
            async def validate_address(self, _address):
                raise RPCConnectionError("node down")

        session = _session(Settings(), pool=DownNodePool(None, Settings()))
        await session.handle_authorize(2, ["bcrt1qworker.rig"])
        self.assertIs(session.writer.by_id(2)["result"], False)  # rejected this attempt
        self.assertFalse(session.authorized)
        self.assertEqual(session.protocol_errors, 0)             # but NOT penalized

    async def test_non_ascii_worker_name_is_ascii_gated(self):
        # The worker name reaches the ASCII-only users/ file; non-ASCII is dropped.
        session = _session(Settings())
        await session.handle_authorize(2, ["bcrt1qworker.rig工\U0001f600"])
        self.assertIs(session.writer.by_id(2)["result"], True)
        self.assertEqual(session.address, "bcrt1qworker")
        self.assertEqual(session.worker, "rig")  # CJK + emoji dropped, ASCII skeleton kept
        self.assertTrue(session.worker.isascii())

    async def test_worker_gated_from_raw_suffix_drops_unprintable_codepoints(self):
        # NBSP/ZWSP are dropped from the raw suffix (not "?"-replaced).
        session = _session(Settings())
        await session.handle_authorize(2, ["bcrt1qworker.rig ​farm"])
        self.assertIs(session.writer.by_id(2)["result"], True)
        self.assertEqual(session.worker, "rigfarm")  # NBSP + ZWSP dropped, no "?" inserted
        self.assertNotIn("?", session.worker)

    async def test_no_params_errors(self):
        session = _session(Settings())
        await session.handle_authorize(2, [])
        self.assertEqual(session.writer.by_id(2)["error"][0], 20)  # ERR_OTHER

    async def test_empty_username_is_protocol_error_not_authorize_false(self):
        # An empty-string username is ERR_OTHER (+budget), not an authorize-false reply.
        session = _session(Settings())
        await session.handle_authorize(2, [""])
        reply = session.writer.by_id(2)
        self.assertEqual(reply["error"][0], 20)  # ERR_OTHER (not an authorize-false result)
        self.assertIsNone(reply["result"])
        self.assertFalse(session.authorized)
        self.assertEqual(session.protocol_errors, 1)

    async def test_reauthorize_with_new_address_uses_the_new_payout(self):
        # Distinct payout script per address so a re-authorize genuinely changes the payout.
        class VaryingPool(FakePool):
            async def validate_address(self, address):
                return (True, b"\x00\x14" + address.encode()[:20].ljust(20, b"\x00"))

        config = Settings()
        pool = VaryingPool(self.make_job(), config)
        session = ClientSession(pool, None, FakeWriter(), pool.assign_extranonce1())
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["addr-one.rig"])
        old_cb2 = session._coinbase2[1]                 # cached for addr-one during its notify
        # Re-authorize to a different payout: stale cache dropped and rebuilt for the new one.
        await session.handle_authorize(3, ["addr-two.rig"])
        self.assertEqual(session.address, "addr-two")
        new_cb2 = pool.current_job.build_coinbase2(b"\x00\x14" + b"addr-two".ljust(20, b"\x00"))
        self.assertEqual(session._coinbase2[1], new_cb2)   # refreshed to the new payout
        self.assertNotEqual(session._coinbase2[1], old_cb2)

    async def test_failed_reauthorize_keeps_previous_state(self):
        class PickyPool(FakePool):
            async def validate_address(self, address):
                if address.startswith("bad"):
                    return (False, None)
                return (True, b"\x00\x14" + address.encode()[:20].ljust(20, b"\x00"))

        session = _session(Settings(), pool=PickyPool(self.make_job(), Settings()))
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["good-one.rig"])
        good_script = session.payout_script
        # A failed re-authorize must not overwrite the already-good address/payout.
        await session.handle_authorize(3, ["bad-addr.rig"])
        self.assertIs(session.writer.by_id(3)["result"], False)
        self.assertTrue(session.authorized)
        self.assertEqual(session.address, "good-one")
        self.assertEqual(session.payout_script, good_script)


class TestSuggestDifficulty(AsyncSoloPoolTestCase):
    async def test_in_band_value_changes_difficulty(self):
        config = Settings(initial_difficulty=4, minimum_difficulty=1, maximum_difficulty=1000)
        session = _session(config)
        session.subscribed = True
        await session.handle_suggest_difficulty(5, [64])
        self.assertEqual(session.difficulty, 64.0)
        self.assertIs(session.writer.by_id(5)["result"], True)
        methods = [m.get("method") for m in session.writer.messages()]
        self.assertIn("mining.set_difficulty", methods)   # pushed because subscribed

    async def test_junk_is_acked_without_changing_difficulty(self):
        config = Settings(initial_difficulty=4, minimum_difficulty=1)
        session = _session(config)
        session.subscribed = True
        before = session.difficulty
        await session.handle_suggest_difficulty(6, ["garbage"])
        self.assertEqual(session.difficulty, before)
        self.assertIs(session.writer.by_id(6)["result"], True)

    async def test_boolean_is_acked_without_changing_difficulty(self):
        # A JSON bool is not a number: ack + ignore, not a float(True)==1.0 difficulty change.
        config = Settings(initial_difficulty=4, minimum_difficulty=1)
        session = _session(config)
        session.subscribed = True
        before = session.difficulty
        await session.handle_suggest_difficulty(6, [True])
        self.assertEqual(session.difficulty, before)
        self.assertIs(session.writer.by_id(6)["result"], True)

    async def test_below_minimum_clamps_up(self):
        config = Settings(initial_difficulty=4, minimum_difficulty=2)
        session = _session(config)
        session.subscribed = True
        await session.handle_suggest_difficulty(7, [0.1])
        self.assertEqual(session.difficulty, 2.0)


class TestSubmitGuards(AsyncSoloPoolTestCase):
    async def test_unauthorized_submit_rejected(self):
        session = _session(Settings())
        await session.handle_submit(9, ["w", "j", "00" * 8, "00000000", "00000000"])
        self.assertEqual(session.writer.by_id(9)["error"][0], 24)  # ERR_UNAUTHORIZED

    async def test_authorization_checked_before_subscription(self):
        session = _session(Settings())
        session.subscribed = True   # subscribed but not authorized -> still 24
        await session.handle_submit(9, ["w", "j", "00" * 8, "00000000", "00000000"])
        self.assertEqual(session.writer.by_id(9)["error"][0], 24)

    async def test_not_subscribed_submit_rejected(self):
        session = _session(Settings())
        session.authorized = True
        await session.handle_submit(9, ["w", "j", "00" * 8, "00000000", "00000000"])
        self.assertEqual(session.writer.by_id(9)["error"][0], 25)  # ERR_NOT_SUBSCRIBED

    async def test_malformed_params_rejected(self):
        session = _session(Settings())
        session.authorized = True
        session.subscribed = True
        await session.handle_submit(9, ["w", "j"])   # too few -> ERR_OTHER
        self.assertEqual(session.writer.by_id(9)["error"][0], 20)


class TestDispatch(AsyncSoloPoolTestCase):
    async def test_extranonce_subscribe_acks_true(self):
        session = _session(Settings())
        await session._dispatch(
            StratumRequest(id=11, method="mining.extranonce.subscribe", params=[]))
        self.assertIs(session.writer.by_id(11)["result"], True)

    async def test_unknown_method_with_id_errors(self):
        session = _session(Settings())
        await session._dispatch(StratumRequest(id=12, method="mining.bogus", params=[]))
        self.assertEqual(session.writer.by_id(12)["error"][0], 20)

    async def test_unknown_method_without_id_is_silent(self):
        session = _session(Settings())
        await session._dispatch(StratumRequest(id=None, method="mining.bogus", params=[]))
        self.assertEqual(session.writer.sent, [])   # notification: no response


class TestStats(AsyncSoloPoolTestCase):
    async def test_stats_shape_after_authorize(self):
        session = _session(Settings(initial_difficulty=8))
        await session.handle_authorize(2, ["bcrt1qaddr.w1"])
        stats = session.stats()
        self.assertEqual(stats["address"], "bcrt1qaddr")
        self.assertEqual(stats["worker"], "w1")   # worker name = suffix after the first dot
        self.assertEqual(stats["peer"], "test:0")    # FakeWriter peername tuple
        self.assertEqual(stats["difficulty"], 8.0)
        self.assertEqual(stats["shares_accepted"], 0)
        self.assertIsInstance(stats["connected_for"], int)


class TestVardiffRetarget(AsyncSoloPoolTestCase):
    """maybe_retarget nudges difficulty toward the target share rate.

    last_retarget is seeded into the past for a deterministic elapsed window.
    """

    def _ready_session(self, **config_overrides):
        settings = dict(initial_difficulty=16, minimum_difficulty=1, maximum_difficulty=0,
                        variable_difficulty=True, vardiff_target_shares_per_minute=12,
                        vardiff_retarget_seconds=60)
        settings.update(config_overrides)
        session = _session(Settings(**settings))
        session.authorized = True
        session.subscribed = True
        return session

    async def test_too_fast_doubles_difficulty(self):
        session = self._ready_session()
        session.last_retarget = time.monotonic() - 120   # ~120s window
        session.shares_since_retarget = 200              # ~100 shares/min >> target*2
        await session.maybe_retarget()
        self.assertEqual(session.difficulty, 32.0)

    async def test_too_slow_halves_difficulty(self):
        session = self._ready_session()
        session.last_retarget = time.monotonic() - 120
        session.shares_since_retarget = 2                # ~1 share/min < target/2
        await session.maybe_retarget()
        self.assertEqual(session.difficulty, 8.0)

    async def test_within_window_no_change(self):
        session = self._ready_session()
        session.last_retarget = time.monotonic() - 5     # below retarget interval
        session.shares_since_retarget = 1000
        await session.maybe_retarget()
        self.assertEqual(session.difficulty, 16.0)

    async def test_slow_clamped_at_minimum(self):
        session = self._ready_session(initial_difficulty=1, minimum_difficulty=1)
        session.last_retarget = time.monotonic() - 120
        session.shares_since_retarget = 0                # would halve, but floor is 1
        await session.maybe_retarget()
        self.assertEqual(session.difficulty, 1.0)

    async def test_unauthorized_is_noop(self):
        session = self._ready_session()
        session.authorized = False
        session.last_retarget = time.monotonic() - 120
        session.shares_since_retarget = 999
        await session.maybe_retarget()
        self.assertEqual(session.difficulty, 16.0)

    async def test_disabled_vardiff_is_noop(self):
        session = self._ready_session(variable_difficulty=False)
        session.last_retarget = time.monotonic() - 120
        session.shares_since_retarget = 999
        await session.maybe_retarget()
        self.assertEqual(session.difficulty, 16.0)


class TestSeenShares(AsyncSoloPoolTestCase):
    async def test_remember_detects_duplicates(self):
        session = _session(Settings())
        key = ("j", "ee", "tt", "nn", None)
        self.assertTrue(session._remember(key))
        self.assertFalse(session._remember(key))   # second time: duplicate

    async def test_remember_rotates_at_cap_and_keeps_one_lookback_generation(self):
        from erikslund_pool.constants import MAX_SEEN_SHARES
        session = _session(Settings())
        for i in range(MAX_SEEN_SHARES):
            session._remember((i,))
        self.assertEqual(len(session._seen_shares), MAX_SEEN_SHARES)
        session._remember(("overflow",))           # rotates current -> previous, then adds
        self.assertEqual(len(session._seen_shares), 1)
        self.assertEqual(len(session._seen_shares_previous), MAX_SEEN_SHARES)
        # Keys from the rotated-out generation are still detected as duplicates...
        self.assertFalse(session._remember((0,)))
        # ...and the total footprint stays bounded at 2 generations.
        self.assertLessEqual(
            len(session._seen_shares) + len(session._seen_shares_previous), 2 * MAX_SEEN_SHARES)

    async def test_duplicate_across_a_clean_job_is_still_rejected(self):
        # Old-job shares are accepted for the whole late-share window, so a duplicate
        # resubmitted just after a clean notify must still be caught.
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        session = _session(config, pool=FakePool(job, config))
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["addr"])
        _result, en2, ntime, nonce = self.find_block_share(job, extranonce1=session.extranonce1)
        await session.handle_submit(3, ["w", job.job_id, en2, ntime, nonce])
        self.assertIs(session.writer.by_id(3)["result"], True)
        await session.send_notify(job, clean=True)   # rotation point (new clean work)
        await session.handle_submit(4, ["w", job.job_id, en2, ntime, nonce])
        self.assertEqual(session.writer.by_id(4)["error"][0], ERR_DUPLICATE[0])

    async def test_dedup_key_is_canonical(self):
        session = _session(Settings(extranonce2_size=4))
        # Hex case + missing leading zeros on fixed-width fields canonicalize to one key;
        # trailing element is the version_mask (0 here).
        a = session._dedup_key("J1", "0A0B0C0D", "6553F100", "2A", "00002000")
        b = session._dedup_key("j1", "0a0b0c0d", "6553f100", "0000002a", "00002000")
        self.assertEqual(a, b)
        self.assertEqual(a, ("j1", "0a0b0c0d", "6553f100", "0000002a", "00002000", 0))
        # A genuinely different nonce stays distinct.
        self.assertNotEqual(a, session._dedup_key("j1", "0a0b0c0d", "6553f100", "0000002b",
                                                  "00002000"))
        # Absent version bits is distinct from present ones.
        self.assertIsNone(session._dedup_key("j1", "0a0b0c0d", "6553f100", "2a", None)[4])

    async def test_dedup_key_does_not_pad_extranonce2(self):
        # extranonce2's length is meaningful (raw into the coinbase), so a short value
        # must not pad onto a full-width one and shadow a later valid share.
        session = _session(Settings(extranonce2_size=4))
        short = session._dedup_key("j1", "0102", "6553f100", "2a", None)
        full = session._dedup_key("j1", "00000102", "6553f100", "2a", None)
        self.assertNotEqual(short, full)

    async def test_dedup_key_includes_version_mask(self):
        # Same version bits under a different mask is a different header, so the mask
        # is part of the work identity.
        session = _session(Settings(extranonce2_size=4))
        before = session._dedup_key("j1", "0a0b0c0d", "6553f100", "2a", "00002000")
        session.version_mask = 0x1FFFE000
        after = session._dedup_key("j1", "0a0b0c0d", "6553f100", "2a", "00002000")
        self.assertNotEqual(before, after)

    async def test_canonical_key_blocks_recredit_of_respelled_share(self):
        session = _session(Settings(extranonce2_size=4))
        self.assertTrue(session._remember(
            session._dedup_key("j", "00000001", "6553f100", "2a2a2a2a", None)))
        # The same share, upper-cased, must be seen as a duplicate (not credited again).
        self.assertFalse(session._remember(
            session._dedup_key("j", "00000001", "6553F100", "2A2A2A2A", None)))


class TestDifficultyGraceWindow(AsyncSoloPoolTestCase):
    """A difficulty change takes effect only from the next job: in-flight shares are credited at
    the difficulty they were actually mined at."""

    class _RecordingPool(FakePool):
        def __init__(self, job, config):
            super().__init__(job, config)
            self.credited: list[float] = []

        def note_accepted_share(self, _address, _worker, credited, _best):
            self.credited.append(credited)

    async def test_change_takes_effect_only_from_next_job(self):
        config = Settings(initial_difficulty=1, variable_difficulty=True)
        job = self.make_job()
        pool = self._RecordingPool(job, config)
        session = ClientSession(pool, None, FakeWriter(), pool.assign_extranonce1())
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["addr"])

        # Three distinct block-quality nonces, so each submit has its own dedup key.
        coinbase2 = job.build_coinbase2(self.P2WPKH_SPK)
        ntime = format(job.curtime, "08x")
        nonces = []
        for n in range(4096):
            nonce_hex = format(n, "08x")
            r = job.validate_share(coinbase2=coinbase2, extranonce1=session.extranonce1,
                                   extranonce2_hex="00" * 8, ntime_hex=ntime, nonce_hex=nonce_hex,
                                   share_target=job.network_target)
            if r.valid and r.is_block:
                nonces.append(nonce_hex)
                if len(nonces) == 3:
                    break
        self.assertEqual(len(nonces), 3)

        async def submit(mid, nonce):
            await session.handle_submit(mid, ["addr", job.job_id, "00" * 8, ntime, nonce])

        # Baseline: no pending change -> credited at the current difficulty.
        await submit(10, nonces[0])
        self.assertIs(session.writer.by_id(10)["result"], True)
        self.assertEqual(pool.credited[-1], 1)

        # Raise difficulty far above the share with NO new job: the in-flight share still
        # credits at the OLD difficulty.
        await session.handle_suggest_difficulty(11, [1_000_000])
        self.assertEqual(session.difficulty, 1_000_000)
        self.assertTrue(session.pending_difficulty_change)
        await submit(12, nonces[1])
        self.assertIs(session.writer.by_id(12)["result"], True)
        self.assertEqual(pool.credited[-1], 1)

        # The next job ends the grace window -> subsequent shares credit the NEW difficulty.
        await session.send_notify(job, clean=True)
        self.assertFalse(session.pending_difficulty_change)
        await submit(13, nonces[2])
        self.assertIs(session.writer.by_id(13)["result"], True)
        self.assertEqual(pool.credited[-1], 1_000_000)

    async def test_lower_change_credits_both_branches(self):
        # Lower change (hi=previous, lo=new): a share meeting the harder old target credits
        # at hi, an easier one at lo. A low floor puts shares on both sides.
        config = Settings(initial_difficulty=1e-9, minimum_difficulty=1e-12, variable_difficulty=True)
        job = self.make_job()
        pool = self._RecordingPool(job, config)
        session = ClientSession(pool, None, FakeWriter(), pool.assign_extranonce1())
        await session.handle_subscribe(1, ["x"])
        await session.handle_authorize(2, ["addr"])

        hi = session.difficulty
        lo = 5e-10
        self.assertGreater(hi, lo)

        cb2 = job.build_coinbase2(self.P2WPKH_SPK)
        ntime = format(job.curtime, "08x")
        loosest = (1 << 256) - 1
        lucky = easy = None
        for n in range(16384):
            nh = format(n, "08x")
            d = job.validate_share(coinbase2=cb2, extranonce1=session.extranonce1,
                                   extranonce2_hex="00" * 8, ntime_hex=ntime, nonce_hex=nh,
                                   share_target=loosest).difficulty
            if lucky is None and d >= hi:
                lucky = nh
            elif easy is None and lo <= d < hi:
                easy = nh
            if lucky and easy:
                break
        self.assertIsNotNone(lucky)
        self.assertIsNotNone(easy)

        async def submit(mid, nonce):
            await session.handle_submit(mid, ["addr", job.job_id, "00" * 8, ntime, nonce])

        # Lower the difficulty (hi -> lo) with NO new job: pending, previous > difficulty.
        await session.handle_suggest_difficulty(20, [lo])
        self.assertEqual(session.difficulty, lo)
        self.assertTrue(session.pending_difficulty_change)

        # Meets the harder OLD target -> credited at hi.
        await submit(21, lucky)
        self.assertIs(session.writer.by_id(21)["result"], True)
        self.assertEqual(pool.credited[-1], hi)

        # Only meets the easier NEW target -> credited at lo.
        await submit(22, easy)
        self.assertIs(session.writer.by_id(22)["result"], True)
        self.assertEqual(pool.credited[-1], lo)
