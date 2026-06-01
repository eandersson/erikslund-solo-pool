"""Adversarial Stratum tests: malformed / wrong-type / hostile protocol input."""
from __future__ import annotations

import asyncio
import unittest

import msgspec

from erikslund_pool.config import Settings
from erikslund_pool.constants import ERR_DUPLICATE
from erikslund_pool.constants import ERR_LOW_DIFF
from erikslund_pool.constants import ERR_NOT_SUBSCRIBED
from erikslund_pool.constants import ERR_OTHER
from erikslund_pool.constants import ERR_STALE
from erikslund_pool.constants import ERR_UNAUTHORIZED
from erikslund_pool.stratum import ClientSession
from erikslund_pool.stratum import StratumRequest
from erikslund_pool.stratum import tune_keepalive
from erikslund_pool.tests.base import AsyncSoloPoolTestCase
from erikslund_pool.tests.scenario.test_share_to_block import FakePool
from erikslund_pool.tests.scenario.test_share_to_block import FakeWriter

_DECODER = msgspec.json.Decoder(StratumRequest)


def _session(config=None, *, job=None, pool=None, extranonce1=b"\x00\x00\x00\x01"):
    config = config or Settings()
    pool = pool or FakePool(job, config)
    return ClientSession(pool, None, FakeWriter(), extranonce1)


class TestParseSubmitAdversarial(unittest.TestCase):
    """_parse_submit: None for a non-list / short list / any non-string field;
    an over-long list keeps the first six."""

    def test_none_and_non_list_are_none(self):
        self.assertIsNone(ClientSession._parse_submit(None))
        self.assertIsNone(ClientSession._parse_submit(5))
        self.assertIsNone(ClientSession._parse_submit(3.14))
        self.assertIsNone(ClientSession._parse_submit(True))

    def test_empty_and_short_lists_are_none(self):
        for params in ([], ["w"], ["w", "j"], ["w", "j", "e"], ["w", "j", "e", "t"]):
            self.assertIsNone(ClientSession._parse_submit(params))

    def test_exactly_five_parses(self):
        self.assertEqual(ClientSession._parse_submit(["w", "j", "e", "t", "n"]),
                         ("j", "e", "t", "n", None))

    def test_overlong_list_keeps_first_six(self):
        self.assertEqual(
            ClientSession._parse_submit(["w", "j", "e", "t", "n", "v", "x", "y", "z"]),
            ("j", "e", "t", "n", "v"))

    def test_non_string_required_fields_are_rejected(self):
        # Non-string required fields -> None so handle_submit replies ERR_OTHER.
        self.assertIsNone(ClientSession._parse_submit(["w", 1, None, [], {}]))
        self.assertIsNone(ClientSession._parse_submit(["w", "j", None, "t", "n"]))
        self.assertIsNone(ClientSession._parse_submit(["w", "j", "e", 5, "n"]))
        self.assertIsNone(ClientSession._parse_submit(["w", "j", "e", "t", ["x"]]))

    def test_empty_or_non_string_version_field_means_no_rolling(self):
        self.assertEqual(ClientSession._parse_submit(["w", "j", "e", "t", "n", ""]),
                         ("j", "e", "t", "n", None))
        self.assertEqual(ClientSession._parse_submit(["w", "j", "e", "t", "n", 7]),
                         ("j", "e", "t", "n", None))
        self.assertEqual(ClientSession._parse_submit(["w", "j", "e", "t", "n", None]),
                         ("j", "e", "t", "n", None))


class TestClampSuggestedAdversarial(unittest.TestCase):
    """Every non-finite / non-positive / non-numeric suggestion -> None."""

    def test_non_finite_rejected(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            self.assertIsNone(ClientSession._clamp_suggested(bad, 1.0, 0.0))

    def test_nonpositive_rejected(self):
        for bad in (0, 0.0, -1, -1e-9, -1e30):
            self.assertIsNone(ClientSession._clamp_suggested(bad, 1.0, 0.0))

    def test_non_numeric_rejected(self):
        for bad in ("", "abc", "0x10", None, [1], {"a": 1}, (), object()):
            self.assertIsNone(ClientSession._clamp_suggested(bad, 1.0, 0.0))

    def test_numeric_strings_and_bytes_accepted(self):
        self.assertEqual(ClientSession._clamp_suggested("16", 1.0, 0.0), 16.0)
        self.assertEqual(ClientSession._clamp_suggested(b"16", 1.0, 0.0), 16.0)
        self.assertEqual(ClientSession._clamp_suggested("2.5", 1.0, 0.0), 2.5)

    def test_clamps_into_band(self):
        self.assertEqual(ClientSession._clamp_suggested(0.001, 1.0, 100.0), 1.0)
        self.assertEqual(ClientSession._clamp_suggested(1e9, 1.0, 100.0), 100.0)
        self.assertEqual(ClientSession._clamp_suggested(1e9, 1.0, 0.0), 1e9)  # no cap


class TestSubmitGuardsAdversarial(AsyncSoloPoolTestCase):
    """handle_submit's pre-validation guards reject before any hashing."""

    async def test_unauthorized_blocks_even_with_valid_looking_params(self):
        session = _session()
        await session.handle_submit(1, ["w", "j", "00" * 8, "00000000", "00000000"])
        self.assertEqual(session.writer.by_id(1)["error"][0], ERR_UNAUTHORIZED[0])

    async def test_authorized_but_unsubscribed_rejected(self):
        session = _session()
        session.authorized = True
        await session.handle_submit(1, ["w", "j", "00" * 8, "00000000", "00000000"])
        self.assertEqual(session.writer.by_id(1)["error"][0], ERR_NOT_SUBSCRIBED[0])

    async def test_too_few_params_after_auth_is_err_other(self):
        session = _session()
        session.authorized = True
        session.subscribed = True
        for params in ([], ["w"], ["w", "j"], ["w", "j", "e", "t"]):
            session.writer.sent.clear()
            await session.handle_submit(2, params)
            self.assertEqual(session.writer.by_id(2)["error"][0], ERR_OTHER[0])

    async def test_unknown_job_id_is_stale_not_crash(self):
        # A job_id that doesn't match the live job -> ERR_STALE (21), not a crash.
        job = self.make_job()
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        session = _session(config, pool=FakePool(job, config))
        session.authorized = True
        session.subscribed = True
        for job_id in ("no-such-job", "", "deadbeef"):
            session.writer.sent.clear()
            await session.handle_submit(3, ["w", job_id, "00" * 8, "00000000", "00000000"])
            self.assertEqual(session.writer.by_id(3)["error"][0], 21)


class TestConfigureAdversarial(AsyncSoloPoolTestCase):
    """mining.configure tolerates malformed extension params without raising."""

    async def test_empty_params(self):
        session = _session()
        await session.handle_configure(1, [])
        self.assertEqual(session.writer.by_id(1)["result"], {})

    async def test_non_iterable_or_non_list_extensions_do_not_crash(self):
        # A non-list extensions[0] must not be honoured: empty result, mask untouched,
        # no throw.
        for bad in (42, None, True, "version-rolling", {"version-rolling": 1}):
            session = _session(Settings(version_rolling_mask=0x1FFFE000))
            await session.handle_configure(1, [bad, {"version-rolling.mask": "ffffffff"}])
            self.assertEqual(session.writer.by_id(1)["result"], {})
            self.assertEqual(session.version_mask, 0)

    async def test_mask_value_not_hex_yields_zero_mask(self):
        session = _session(Settings(version_rolling_mask=0x1FFFE000))
        await session.handle_configure(1, [["version-rolling"], {"version-rolling.mask": "zzzz"}])
        self.assertEqual(session.version_mask, 0)
        self.assertEqual(session.writer.by_id(1)["result"]["version-rolling.mask"], "00000000")

    async def test_mask_value_wrong_type_yields_zero_mask(self):
        session = _session(Settings(version_rolling_mask=0x1FFFE000))
        await session.handle_configure(1, [["version-rolling"], {"version-rolling.mask": ["x"]}])
        self.assertEqual(session.version_mask, 0)

    async def test_present_but_invalid_masks_all_disable_rolling(self):
        for bad in ("", "1fffe0000", 536813568, None):
            session = _session(Settings(version_rolling_mask=0x1FFFE000))
            await session.handle_configure(
                1, [["version-rolling"], {"version-rolling.mask": bad}])
            self.assertEqual(session.version_mask, 0, f"mask {bad!r} should disable rolling")
            result = session.writer.by_id(1)["result"]
            self.assertFalse(result["version-rolling"])
            self.assertEqual(result["version-rolling.mask"], "00000000")

    async def test_extension_params_missing_uses_default_mask(self):
        session = _session(Settings(version_rolling_mask=0x1FFFE000))
        await session.handle_configure(1, [["version-rolling"]])
        self.assertEqual(session.version_mask, 0x1FFFE000)

    async def test_extension_params_is_a_list_does_not_crash(self):
        session = _session(Settings(version_rolling_mask=0x1FFFE000))
        await session.handle_configure(1, [["version-rolling"], ["notadict"]])
        self.assertEqual(session.version_mask, 0x1FFFE000)
        self.assertIn("result", session.writer.by_id(1))


class TestSubscribeAfterAuthorize(AsyncSoloPoolTestCase):
    """A client that authorizes before subscribing has no work yet; on subscribe the
    pool must push set_difficulty + exactly one clean mining.notify so work flows."""

    async def test_subscribe_after_authorize_pushes_difficulty_and_one_clean_job(self):
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        session = _session(config, job=job)
        await session.handle_authorize(1, ["bcrt1qexampleworkeraddress"])
        self.assertTrue(session.authorized)
        await session.handle_subscribe(2, ["cpuminer/test"])
        self.assertIn("result", session.writer.by_id(2))            # subscribe reply
        methods = [m.get("method") for m in session.writer.messages()]
        self.assertIn("mining.set_difficulty", methods)
        notifies = [m for m in session.writer.messages() if m.get("method") == "mining.notify"]
        self.assertEqual(len(notifies), 1)                          # no double work
        self.assertIs(notifies[0]["params"][8], True)               # clean_jobs flag


class TestAuthorizeAdversarial(AsyncSoloPoolTestCase):
    async def test_no_params_is_err_other(self):
        session = _session()
        await session.handle_authorize(1, [])
        self.assertEqual(session.writer.by_id(1)["error"][0], ERR_OTHER[0])

    async def test_rejected_address_results_false_not_error(self):
        class RejectingPool(FakePool):
            async def validate_address(self, _address):
                return (False, None)

        session = _session(pool=RejectingPool(None, Settings()))
        await session.handle_authorize(1, ["whatever.worker"])
        self.assertIs(session.writer.by_id(1)["result"], False)
        self.assertFalse(session.authorized)

    async def test_non_string_username_is_coerced(self):
        # params[0] is coerced with str().
        session = _session()
        await session.handle_authorize(1, [12345])
        self.assertTrue(session.authorized)
        self.assertEqual(session.address, "12345")


class TestDispatchAdversarial(AsyncSoloPoolTestCase):
    """_dispatch routes hostile / unknown methods without raising."""

    async def test_method_none_is_silent_noop(self):
        session = _session()
        before = len(session.writer.sent)
        await session._dispatch(StratumRequest(id=1, method=None, params=[]))
        self.assertEqual(len(session.writer.sent), before)  # response objects have no method

    async def test_unknown_method_with_id_errors(self):
        session = _session()
        await session._dispatch(StratumRequest(id=9, method="mining.nonsense", params=[]))
        self.assertEqual(session.writer.by_id(9)["error"][0], ERR_OTHER[0])

    async def test_unknown_method_without_id_silent(self):
        session = _session()
        await session._dispatch(StratumRequest(id=None, method="mining.nonsense", params=[]))
        self.assertEqual(session.writer.sent, [])

    async def test_oversized_integer_id_is_echoed_as_null(self):
        session = _session()
        await session._dispatch(StratumRequest(id=2**70, method="mining.subscribe", params=["ua"]))
        replies = [m for m in session.writer.messages() if "result" in m]
        self.assertEqual(len(replies), 1)
        self.assertIsNone(replies[0]["id"])

    async def test_in_range_integer_id_is_preserved(self):
        # The clamp must only touch out-of-int64 ids.
        session = _session()
        await session._dispatch(StratumRequest(id=42, method="mining.subscribe", params=["ua"]))
        self.assertEqual(session.writer.by_id(42)["id"], 42)

    async def test_known_methods_with_empty_params_do_not_crash(self):
        for method in ("mining.subscribe", "mining.authorize", "mining.configure",
                       "mining.submit", "mining.suggest_difficulty",
                       "mining.extranonce.subscribe"):
            session = _session()
            await session._dispatch(StratumRequest(id=1, method=method, params=[]))
            self.assertTrue(any(m.get("id") == 1 for m in session.writer.messages()),
                            f"{method} produced no response")


class TestLineDecoderSwallowsGarbage(unittest.TestCase):
    """Every malformed/truncated/wrong-shape line raises a MsgspecError subclass,
    which ClientSession.run swallows so the read loop continues."""

    def test_malformed_json_is_msgspec_error(self):
        for raw in (b"not json", b"{bad", b"{,}", b'{"a":}', b"\xff\xfe", b"   "):
            with self.assertRaises(msgspec.MsgspecError):
                _DECODER.decode(raw)

    def test_truncated_input_is_msgspec_error(self):
        for raw in (b"", b'{"id":1', b'{"params":[1,2'):
            with self.assertRaises(msgspec.MsgspecError):
                _DECODER.decode(raw)

    def test_wrong_shape_is_msgspec_error(self):
        # Genuinely undecodable: not an object, or a non-string method.
        for raw in (b"[]", b"123", b'"a string"', b"true", b'{"method":123}'):
            with self.assertRaises(msgspec.MsgspecError):
                _DECODER.decode(raw)

    def test_offspec_id_and_params_decode_for_coercion(self):
        # An object id or non-list params must decode so _dispatch can coerce
        # (id -> null, params -> []) and still answer.
        for raw in (b'{"id":{"nested":1},"method":"mining.subscribe"}',
                    b'{"params":"notalist","method":"mining.subscribe"}'):
            request = _DECODER.decode(raw)  # must not raise
            self.assertEqual(request.method, "mining.subscribe")

    def test_valid_request_still_decodes(self):
        request = _DECODER.decode(b'{"id":1,"method":"mining.subscribe","params":["ua"]}')
        self.assertEqual(request.method, "mining.subscribe")
        self.assertEqual(request.params, ["ua"])


class TestTuneKeepaliveAdversarial(unittest.TestCase):
    """tune_keepalive is best-effort: a non-socket transport must never raise."""

    def test_none(self):
        self.assertIsNone(tune_keepalive(None, 30))

    def test_object_without_setsockopt(self):
        class NoSock:
            pass

        self.assertIsNone(tune_keepalive(NoSock(), 30))

    def test_object_with_non_callable_setsockopt(self):
        class FakeSock:
            setsockopt = 123  # present attribute, but not callable

        # The guard catches only missing-attr and OSError, not a non-callable -> TypeError.
        with self.assertRaises(TypeError):
            tune_keepalive(FakeSock(), 30)

    def test_setsockopt_raising_oserror_is_swallowed(self):
        import socket as _socket

        class FlakySock:
            def setsockopt(self, *_a):
                raise OSError("setsockopt not permitted")

        # OSError is explicitly caught -> no raise.
        self.assertIsNone(tune_keepalive(FlakySock(), 30))
        del _socket


class TestNonStringSubmitFieldsShouldRejectGracefully(AsyncSoloPoolTestCase):
    async def _assert_graceful(self, build_params):
        # A real job so the job_id lookup succeeds and we reach validation (not stale).
        job = self.make_job()
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        session = _session(config, pool=FakePool(job, config), extranonce1=b"\x00\x00\x00\x01")
        session.authorized = True
        session.subscribed = True
        session.payout_script = self.P2WPKH_SPK
        # A wrong-typed field must reject as ERR_OTHER, never an unhandled exception.
        await session.handle_submit(1, build_params(job))
        self.assertEqual(session.writer.by_id(1)["error"][0], ERR_OTHER[0])

    async def test_null_extranonce2(self):
        await self._assert_graceful(lambda job: ["w", job.job_id, None, "00000000", "00000000"])

    async def test_null_ntime(self):
        await self._assert_graceful(lambda job: ["w", job.job_id, "00" * 8, None, "00000000"])

    async def test_numeric_nonce(self):
        await self._assert_graceful(lambda job: ["w", job.job_id, "00" * 8, "00000000", 12345])

    async def test_list_extranonce2_is_unhashable(self):
        await self._assert_graceful(lambda job: ["w", job.job_id, ["x"], "00000000", "00000000"])


class TestMalformedStringSubmitFieldsRejected(AsyncSoloPoolTestCase):
    async def _assert_err_other(self, build_params):
        job = self.make_job()
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        session = _session(config, pool=FakePool(job, config), extranonce1=b"\x00\x00\x00\x01")
        session.authorized = True
        session.subscribed = True
        session.payout_script = self.P2WPKH_SPK
        await session.handle_submit(1, build_params(job))
        self.assertEqual(session.writer.by_id(1)["error"][0], ERR_OTHER[0])

    async def test_non_hex_extranonce2(self):  # 16 chars (right size), not hex
        await self._assert_err_other(lambda job: ["w", job.job_id, "zz" * 8, "00000000", "00000000"])

    async def test_wrong_length_extranonce2(self):  # valid hex, wrong byte count
        await self._assert_err_other(lambda job: ["w", job.job_id, "00", "00000000", "00000000"])

    async def test_non_hex_ntime(self):
        await self._assert_err_other(lambda job: ["w", job.job_id, "00" * 8, "zzzzzzzz", "00000000"])

    async def test_non_hex_nonce(self):
        await self._assert_err_other(lambda job: ["w", job.job_id, "00" * 8, "00000000", "zzzzzzzz"])


class _ScriptedReader:
    """Minimal asyncio.StreamReader stand-in: yields queued lines, then EOF."""
    def __init__(self, *lines):
        self._lines = list(lines)

    async def readline(self):
        return self._lines.pop(0) if self._lines else b""


class TestRunLoopContainsHandlerErrors(AsyncSoloPoolTestCase):
    """run() must never let a handler exception escape: it logs and serves the next line."""

    async def test_handler_exception_is_contained_and_loop_continues(self):
        config = Settings(drop_idle_seconds=0)
        reader = _ScriptedReader(
            b'{"id":1,"method":"mining.subscribe","params":[]}\n',
            b'{"id":2,"method":"mining.subscribe","params":[]}\n')
        session = ClientSession(FakePool(None, config), reader, FakeWriter(), b"\x00\x00\x00\x01")
        calls = []

        async def boom(_request):
            calls.append(1)
            raise RuntimeError("handler blew up")

        session._dispatch = boom
        await session.run()  # returns normally; the catch-all swallowed both errors
        self.assertEqual(len(calls), 2)  # first exception did not kill the read loop


class _BlockingReader:
    """asyncio.StreamReader stand-in whose readline never completes."""
    async def readline(self):
        await asyncio.sleep(3600)


class TestAuthDeadline(AsyncSoloPoolTestCase):
    """A connection that never authorizes is dropped after auth_timeout_seconds;
    an already-authorized connection is left alone."""

    async def test_unauthorized_connection_dropped_after_auth_timeout(self):
        config = Settings(auth_timeout_seconds=1, drop_idle_seconds=0)
        session = ClientSession(FakePool(None, config), _BlockingReader(),
                                FakeWriter(), b"\x00\x00\x00\x01")
        # run() must return on its own (auth deadline fired), not hang on readline.
        await asyncio.wait_for(session.run(), timeout=10)
        self.assertFalse(session.authorized)

    async def test_authorized_connection_not_dropped_by_auth_timeout(self):
        config = Settings(auth_timeout_seconds=1, drop_idle_seconds=0)
        session = ClientSession(FakePool(None, config), _BlockingReader(),
                                FakeWriter(), b"\x00\x00\x00\x01")
        session.authorized = True
        # Authorized + idle disabled -> no deadline applies -> run() blocks until cancelled.
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(session.run(), timeout=2)


class TestProtocolErrorBudget(AsyncSoloPoolTestCase):
    """Egregious errors (malformed / out-of-order) count toward the disconnect
    budget; normal-mining races (stale / duplicate / low-difficulty) never do."""

    async def test_only_abuse_errors_count(self):
        session = _session()
        for err in (ERR_OTHER, ERR_UNAUTHORIZED, ERR_NOT_SUBSCRIBED):
            await session._error(1, err)
        self.assertEqual(session.protocol_errors, 3)
        for err in (ERR_STALE, ERR_DUPLICATE, ERR_LOW_DIFF):
            await session._error(2, err)
        self.assertEqual(session.protocol_errors, 3)  # normal races leave it untouched

    async def test_run_disconnects_after_budget(self):
        config = Settings(max_protocol_errors=2, auth_timeout_seconds=0, drop_idle_seconds=0)
        # mining.submit before authorize -> ERR_UNAUTHORIZED, which counts toward the budget.
        submit = b'{"id":%d,"method":"mining.submit","params":["w","j","00000000","00000000","00000000"]}\n'
        reader = _ScriptedReader(
            submit % 1,
            submit % 2,
            submit % 3)  # never reached: dropped at #2
        session = ClientSession(FakePool(None, config), reader, FakeWriter(), b"\x00\x00\x00\x01")
        await asyncio.wait_for(session.run(), timeout=10)
        self.assertEqual(session.protocol_errors, 2)

    async def test_a_good_share_resets_the_budget(self):
        # A valid share clears accumulated garbage: "sustained", not "lifetime".
        config = Settings(initial_difficulty=1, variable_difficulty=False)
        job = self.make_job()
        session = _session(config, pool=FakePool(job, config), extranonce1=b"\x00\x00\x00\x01")
        session.subscribed = True
        session.authorized = True
        session.payout_script = self.P2WPKH_SPK
        session.protocol_errors = 5
        _result, en2, ntime, nonce = self.find_block_share(job, extranonce1=session.extranonce1)
        await session.handle_submit(1, ["w", job.job_id, en2, ntime, nonce])
        self.assertIs(session.writer.by_id(1)["result"], True)  # share accepted
        self.assertEqual(session.protocol_errors, 0)            # ...and the budget cleared


if __name__ == "__main__":
    unittest.main()
