"""Stratum v1 server: one ClientSession per TCP connection; shared state lives on the Pool."""

import asyncio
import logging
import math
import socket
import threading
import time
from typing import Any

import msgspec

from erikslund_pool.constants import ERR_DUPLICATE
from erikslund_pool.constants import ERR_LOW_DIFF
from erikslund_pool.constants import ERR_NOT_SUBSCRIBED
from erikslund_pool.constants import ERR_OTHER
from erikslund_pool.constants import ERR_STALE
from erikslund_pool.constants import ERR_UNAUTHORIZED
from erikslund_pool.constants import MAX_SEEN_SHARES
from erikslund_pool.exceptions import RPCError
from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.hashrate import DecayingWindows
from erikslund_pool.util import ascii_worker
from erikslund_pool.util import difficulty_to_target
from erikslund_pool.util import format_difficulty
from erikslund_pool.util import sanitize

LOG = logging.getLogger(__name__)

KEEPALIVE_IDLE_SECONDS = 60
KEEPALIVE_INTERVAL_SECONDS = 20
KEEPALIVE_PROBE_COUNT = 5
# Dead-peer detection window: idle + interval * count.
KEEPALIVE_WINDOW_SECONDS = (
    KEEPALIVE_IDLE_SECONDS + KEEPALIVE_INTERVAL_SECONDS * KEEPALIVE_PROBE_COUNT)

# Counted toward the disconnect budget: misbehaviour + protocol-order, never normal-mining races.
_ABUSE_ERROR_CODES = frozenset({ERR_OTHER[0], ERR_UNAUTHORIZED[0], ERR_NOT_SUBSCRIBED[0]})


def keepalive_user_timeout_ms(work_rebroadcast_seconds: float) -> int:
    # >= 2x rebroadcast so a quiet miner behind a keepalive-stripping middlebox survives to next push.
    return int(max(KEEPALIVE_WINDOW_SECONDS, 2 * work_rebroadcast_seconds) * 1000)


def tune_keepalive(sock, work_rebroadcast_seconds: float) -> None:
    # Best-effort: the transport may be None or a test double, not a real socket.
    if sock is None or not hasattr(sock, "setsockopt"):
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for name, value in (
            ("TCP_KEEPIDLE", KEEPALIVE_IDLE_SECONDS),
            ("TCP_KEEPINTVL", KEEPALIVE_INTERVAL_SECONDS),
            ("TCP_KEEPCNT", KEEPALIVE_PROBE_COUNT),
            ("TCP_USER_TIMEOUT", keepalive_user_timeout_ms(work_rebroadcast_seconds)),
        ):
            option = getattr(socket, name, None)
            if option is not None:
                sock.setsockopt(socket.IPPROTO_TCP, option, value)
    except OSError:
        pass


class StratumRequest(msgspec.Struct):
    id: Any = None
    method: str | None = None
    params: Any = msgspec.field(default_factory=list)


_DECODER = msgspec.json.Decoder(StratumRequest)


class ClientSession:
    def __init__(self, pool, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 extranonce1: bytes, peer_override: str | None = None, prebuffer: bytes = b""):
        self.pool = pool
        self.reader = reader
        self.writer = writer
        self.extranonce1 = extranonce1
        self.extranonce1_hex = extranonce1.hex()
        if peer_override:
            self.peer = peer_override
        else:
            peername = writer.get_extra_info("peername")
            self.peer = f"{peername[0]}:{peername[1]}" if peername else "unknown"
        self._prebuffer = prebuffer
        tune_keepalive(writer.get_extra_info("socket"), pool.config.work_rebroadcast_seconds)
        self.loop: asyncio.AbstractEventLoop | None = None  # set in run(); for cross-loop notify

        self.subscribed = False
        self.authorized = False
        self.protocol_errors = 0   # counted toward the disconnect budget
        self.address: str | None = None
        self.worker: str | None = None
        self.payout_script: bytes | None = None

        self.min_difficulty = float(pool.config.minimum_difficulty)
        self.difficulty = max(float(pool.config.initial_difficulty), self.min_difficulty)
        self.previous_difficulty = 0.0
        self.pending_difficulty_change = False
        self.version_mask = 0
        self.user_agent = "?"

        self.connected_at = time.monotonic()  # durations only, never displayed
        # Guards the counters below: this loop writes, other threads read. hashrate self-locks.
        self._stats_lock = threading.Lock()
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.total_share_diff = 0.0
        self.hashrate = DecayingWindows(HASHRATE_WINDOWS, self.connected_at)
        self.best_diff = 0.0
        self.last_share_ts = 0

        self._coinbase2: tuple[str, bytes, str] | None = None   # (job_id, coinbase2, coinbase2_hex)
        # Two-generation dedup: on a clean job (and at MAX_SEEN_SHARES) current rotates into previous
        # instead of clearing, so a duplicate just after a clean notify is still caught. Bounded 2x.
        self._seen_shares: set[tuple] = set()
        self._seen_shares_previous: set[tuple] = set()
        self.shares_since_retarget = 0
        self.last_retarget = time.monotonic()
        self._write_lock = asyncio.Lock()

    def _coinbase2_for(self, job) -> bytes:
        """This miner's coinbase2 for `job` (and its hex), cached once per job."""
        if self._coinbase2 is None or self._coinbase2[0] != job.job_id:
            coinbase2 = job.build_coinbase2(self.payout_script)
            self._coinbase2 = (job.job_id, coinbase2, coinbase2.hex())
        return self._coinbase2[1]

    async def _send(self, message: dict) -> bool:
        data = msgspec.json.encode(message) + b"\n"
        try:
            async with self._write_lock:
                self.writer.write(data)
                await self.writer.drain()
            return True
        except (ConnectionError, OSError):
            return False

    async def _result(self, message_id, result):
        await self._send({"id": message_id, "result": result, "error": None})

    async def _error(self, message_id, error):
        code, message = error
        if code in _ABUSE_ERROR_CODES:
            self.protocol_errors += 1
        await self._send({"id": message_id, "result": None, "error": [code, message, None]})

    async def send_set_difficulty(self):
        await self._send({"id": None, "method": "mining.set_difficulty", "params": [self.difficulty]})

    def _begin_difficulty_change(self, new_difficulty: float) -> None:
        if not self.pending_difficulty_change:
            self.previous_difficulty = self.difficulty
        self.difficulty = new_difficulty
        self.pending_difficulty_change = True

    async def send_notify(self, job, clean: bool):
        if not (self.subscribed and self.authorized and self.payout_script is not None):
            return
        self._coinbase2_for(job)             # populate the cache for this job
        coinbase2_hex = self._coinbase2[2]
        # Keep one generation of lookback on a clean job; skip when empty so a cap rotation's
        # demoted generation isn't discarded.
        if clean and self._seen_shares:
            self._rotate_seen_shares()
        await self._send({
            "id": None,
            "method": "mining.notify",
            "params": [job.job_id, job.prevhash_stratum, job.coinbase1_hex, coinbase2_hex,
                       job.merkle_branch_hex, job.version_hex, job.nbits_hex,
                       job.ntime_hex, clean],
        })
        # New difficulty is in effect from this job on; stop honoring the old one.
        self.pending_difficulty_change = False

    async def handle_subscribe(self, message_id, params):
        # Only a non-empty string sets the user-agent; anything else keeps the default "?".
        if params and isinstance(params[0], str) and params[0]:
            self.user_agent = sanitize(params[0])
        self.subscribed = True
        subscription_id = self.extranonce1_hex
        await self._result(message_id, [
            [["mining.set_difficulty", subscription_id], ["mining.notify", subscription_id]],
            self.extranonce1_hex,
            self.pool.config.extranonce2_size,
        ])
        # Authorized before subscribe: no job sent yet, so send difficulty + work now.
        if self.authorized and self.payout_script is not None:
            await self.send_set_difficulty()
            job = self.pool._current_job_locked()
            if job is not None:
                await self.send_notify(job, clean=True)

    async def handle_configure(self, message_id, params):
        result = {}
        try:
            extensions = params[0] if params else []
            extension_params = params[1] if len(params) > 1 else {}
        except (IndexError, TypeError):
            extensions, extension_params = [], {}
        # extensions must be a real list of names (a non-iterable would crash the membership test).
        if not isinstance(extensions, (list, tuple)):
            extensions = []
        if not isinstance(extension_params, dict):
            extension_params = {}
        if "version-rolling" in extensions:
            if "version-rolling.mask" not in extension_params:
                client_mask = 0xFFFFFFFF
            else:
                mask_value = extension_params["version-rolling.mask"]
                if (isinstance(mask_value, str) and 1 <= len(mask_value) <= 8
                        and all(c in "0123456789abcdefABCDEF" for c in mask_value)):
                    client_mask = int(mask_value, 16)
                else:
                    client_mask = 0
            self.version_mask = client_mask & self.pool.config.version_rolling_mask
            # BIP310: empty negotiated mask -> answer false so the miner won't send rejectable bits.
            result["version-rolling"] = self.version_mask != 0
            result["version-rolling.mask"] = format(self.version_mask, "08x")
        # BIP310: answer every requested extension; only version-rolling is supported, false for rest.
        for extension in extensions:
            if isinstance(extension, str) and extension != "version-rolling" and extension not in result:
                result[extension] = False
        await self._result(message_id, result)

    async def handle_authorize(self, message_id, params):
        # Empty/absent username is a protocol error (ERR_OTHER, +budget), not authorize-false. Gate
        # on the RAW param: sanitize("") yields "?", which would slip past.
        if not params or not str(params[0]):
            await self._error(message_id, ERR_OTHER)
            return
        # Username is "<address>[.<worker>]"; only the payout address is validated.
        username = sanitize(params[0])
        # Validate into locals first: a failed re-authorize must not overwrite the already-good state.
        address, _, _ = username.partition(".")
        # Gate the worker to ASCII from the RAW suffix so the ASCII-only users/<address> file can't be
        # corrupted (sanitize would map a non-printable to "?").
        worker = ascii_worker(str(params[0]).partition(".")[2])
        try:
            valid, script = await self.pool.validate_address(address)
        except RPCError as e:
            # Transient bitcoind failure: reject but don't charge the abuse budget, so a node hiccup
            # can't mass-disconnect honest (re)authorizing miners.
            LOG.warning("Rejecting worker %s: address check unavailable (%s)", self.peer, e)
            await self._result(message_id, False)
            return
        if not valid or script is None:
            # A flood of distinct invalid addresses is the authorize-amplification vector: charge the
            # budget, but the wire response stays a protocol-correct authorize-false.
            LOG.warning("Rejecting worker %s: invalid payout address %r", self.peer, address)
            self.protocol_errors += 1
            await self._result(message_id, False)
            return
        # Re-authorize may change the payout address; the coinbase2 cache is keyed only by job_id.
        if self.payout_script != script:
            self._coinbase2 = None
        self.address, self.worker = address, worker
        self.payout_script = script
        self.authorized = True
        # Register so an idle authorized rig appears (and persists) before its first share.
        self.pool.attach_worker(self.address, self.worker or "")
        await self._result(message_id, True)
        LOG.info("Authorized %s (addr=%s, ua=%s, enonce1=%s)",
                 self.peer, self.address, self.user_agent, self.extranonce1_hex)
        await self.send_set_difficulty()
        job = self.pool._current_job_locked()   # cross-loop read
        if job is not None:
            await self.send_notify(job, clean=True)

    @staticmethod
    def _clamp_suggested(value, minimum: float, maximum: float) -> float | None:
        """Clamp a suggested difficulty to [minimum, maximum] (maximum <= 0: no cap); None if bad."""
        if isinstance(value, bool):
            return None  # a JSON bool is not a number; ack + ignore
        try:
            suggested = float(value)
        except (TypeError, ValueError):
            return None
        if not math.isfinite(suggested) or suggested <= 0:
            return None
        clamped = max(suggested, minimum)
        if maximum > 0:
            clamped = min(clamped, maximum)
        return clamped

    async def handle_suggest_difficulty(self, message_id, params):
        """Adopt the miner's suggested starting difficulty (clamped); advisory, junk is acked."""
        suggested = params[0] if params else None
        new_difficulty = self._clamp_suggested(
            suggested, self.min_difficulty, self.pool.config.maximum_difficulty)
        if new_difficulty is not None and new_difficulty != self.difficulty:
            self._begin_difficulty_change(new_difficulty)
            self.shares_since_retarget = 0
            self.last_retarget = time.monotonic()
            LOG.info("Suggest-difficulty %s -> %s", self.peer, format_difficulty(new_difficulty))
            if self.subscribed:
                await self.send_set_difficulty()
        await self._result(message_id, True)

    @staticmethod
    def _parse_submit(params: list):
        """Extract (job_id, extranonce2, ntime, nonce, version_bits|None), or None."""
        try:
            _worker, job_id, extranonce2_hex, ntime_hex, nonce_hex = params[:5]
        except (ValueError, TypeError):
            return None
        # Reject non-string required fields: a null/number/array would crash the validator.
        if not all(isinstance(f, str)
                   for f in (job_id, extranonce2_hex, ntime_hex, nonce_hex)):
            return None
        version_bits_hex = params[5] if len(params) > 5 else None
        if not isinstance(version_bits_hex, str) or version_bits_hex == "":
            version_bits_hex = None
        return job_id, extranonce2_hex, ntime_hex, nonce_hex, version_bits_hex

    def _dedup_key(self, job_id, extranonce2_hex, ntime_hex, nonce_hex, version_bits_hex) -> tuple:
        """Canonical dedup key collapsing hex-casing/leading-zero spellings of the same share.
        job_id and extranonce2 are length-meaningful (raw into coinbase): lower only, never pad.
        ntime/nonce/version are 4-byte fields -> pad to 8. version_mask is part of work identity."""
        return (
            job_id.lower(),
            extranonce2_hex.lower(),
            ntime_hex.lower().rjust(8, "0"),
            nonce_hex.lower().rjust(8, "0"),
            version_bits_hex.lower().rjust(8, "0") if version_bits_hex is not None else None,
            self.version_mask,
        )

    def _rotate_seen_shares(self) -> None:
        """Live set becomes the lookback set (only the prior generation is discarded)."""
        self._seen_shares_previous = self._seen_shares
        self._seen_shares = set()

    def _remember(self, share_key: tuple) -> bool:
        """Record a share key; return False if already seen (a duplicate)."""
        if share_key in self._seen_shares or share_key in self._seen_shares_previous:
            return False
        if len(self._seen_shares) >= MAX_SEEN_SHARES:
            self._rotate_seen_shares()
        self._seen_shares.add(share_key)
        return True

    def _record_accepted(self, result):
        self.protocol_errors = 0   # a valid share clears the protocol-error budget
        now_wall = time.time()
        credited = self.difficulty
        if self.pending_difficulty_change:
            hi = max(self.difficulty, self.previous_difficulty)
            lo = min(self.difficulty, self.previous_difficulty)
            credited = hi if result.difficulty >= hi else lo
        self.hashrate.add(credited, time.monotonic())  # has its own lock
        with self._stats_lock:
            self.shares_since_retarget += 1
            self.shares_accepted += 1
            self.total_share_diff += credited
            self.last_share_ts = int(now_wall)  # whole epoch seconds
            self.best_diff = max(self.best_diff, result.difficulty)
        # result.difficulty is the actual hash difficulty met (for the per-worker best-share).
        self.pool.note_accepted_share(self.address or "", self.worker or "", credited,
                                      result.difficulty)
        LOG.debug("Accepted share from %s diff %s/%s", self.address,
                  format_difficulty(result.difficulty), format_difficulty(credited))

    def _record_rejected(self):
        with self._stats_lock:
            self.shares_rejected += 1
        self.pool.note_rejected_share(self.address or "", self.worker or "")

    async def handle_submit(self, message_id, params):
        if not self.authorized:
            await self._error(message_id, ERR_UNAUTHORIZED)
            return
        if not self.subscribed:
            await self._error(message_id, ERR_NOT_SUBSCRIBED)
            return
        parsed = self._parse_submit(params)
        if parsed is None:
            await self._error(message_id, ERR_OTHER)
            return
        job_id, extranonce2_hex, ntime_hex, nonce_hex, version_bits_hex = parsed

        job = self.pool.recent_job(job_id)
        if job is None:
            self._record_rejected()
            await self._error(message_id, ERR_STALE)
            return
        if not self._remember(self._dedup_key(*parsed)):
            self._record_rejected()
            await self._error(message_id, ERR_DUPLICATE)
            return

        # Validate inline: scaling comes from N event loops, not per-share offload (dispatch
        # overhead dwarfs the ~17us validation).
        accept_difficulty = (min(self.difficulty, self.previous_difficulty)
                             if self.pending_difficulty_change else self.difficulty)
        result = job.validate_share(
            coinbase2=self._coinbase2_for(job), extranonce1=self.extranonce1,
            extranonce2_hex=extranonce2_hex, ntime_hex=ntime_hex, nonce_hex=nonce_hex,
            share_target=difficulty_to_target(accept_difficulty),
            version_bits_hex=version_bits_hex, version_mask=self.version_mask,
        )
        if not result.valid:
            self._record_rejected()
            LOG.debug("Rejected share from %s (%s)", self.address, result.reason)
            await self._error(message_id, ERR_LOW_DIFF if result.reason == "above target" else ERR_OTHER)
            return

        self._record_accepted(result)
        await self._result(message_id, True)
        if result.is_block:
            LOG.info("BLOCK CANDIDATE height=%d hash=%s diff=%.3f address=%s worker=%s",
                     job.height, result.block_hash_hex, result.difficulty,
                     self.address, self.worker)
            await self.pool.on_block_found(self, job, result)

    async def maybe_retarget(self):
        """Vardiff: nudge difficulty toward the target share rate."""
        config = self.pool.config
        if not config.variable_difficulty or not self.authorized:
            return
        now = time.monotonic()
        elapsed = now - self.last_retarget
        if elapsed < config.vardiff_retarget_seconds:
            return
        shares_per_minute = (self.shares_since_retarget / elapsed) * 60.0 if elapsed > 0 else 0.0
        difficulty_cap = config.maximum_difficulty if config.maximum_difficulty > 0 else 1e12
        new_difficulty = self.difficulty
        if (shares_per_minute > config.vardiff_target_shares_per_minute * 2
                and self.difficulty < difficulty_cap):
            new_difficulty = min(difficulty_cap, self.difficulty * 2)
        elif shares_per_minute < config.vardiff_target_shares_per_minute / 2:
            new_difficulty = max(self.min_difficulty, self.difficulty / 2)
        self.shares_since_retarget = 0
        self.last_retarget = now
        if new_difficulty != self.difficulty:
            self._begin_difficulty_change(new_difficulty)
            LOG.debug("Vardiff %s -> %s (%.1f shares/min)", self.peer,
                      format_difficulty(new_difficulty), shares_per_minute)
            await self.send_set_difficulty()

    def stats(self) -> dict:
        peer = self.peer
        with self._stats_lock:   # consistent cross-thread snapshot
            return {
                "address": self.address, "worker": self.worker, "peer": peer,
                "user_agent": self.user_agent, "difficulty": self.difficulty,
                "shares_accepted": self.shares_accepted, "shares_rejected": self.shares_rejected,
                "best_diff": self.best_diff, "last_share_ts": self.last_share_ts,
                "connected_for": int(time.monotonic() - self.connected_at),
            }

    async def run(self):
        self.loop = asyncio.get_running_loop()
        self.pool.register(self)
        LOG.info("Client connected: %s (enonce1=%s)", self.peer, self.extranonce1_hex)
        auth_timeout = self.pool.config.auth_timeout_seconds
        max_protocol_errors = self.pool.config.max_protocol_errors
        connected_at = time.monotonic()
        try:
            while True:
                idle_timeout = self.pool.config.drop_idle_seconds
                timeout = idle_timeout if idle_timeout > 0 else None
                # Drop a connection that never authorizes (anti connection-parking).
                if auth_timeout > 0 and not self.authorized:
                    remaining = connected_at + auth_timeout - time.monotonic()
                    if remaining <= 0:
                        LOG.info("Client %s did not authorize within %ds; disconnecting",
                                 self.peer, auth_timeout)
                        break
                    timeout = remaining if timeout is None else min(timeout, remaining)
                try:
                    if timeout is not None:
                        line = await asyncio.wait_for(self.reader.readline(), timeout=timeout)
                    else:
                        line = await self.reader.readline()
                except asyncio.TimeoutError:
                    if (auth_timeout > 0 and not self.authorized
                            and time.monotonic() - connected_at >= auth_timeout):
                        LOG.info("Client %s did not authorize within %ds; disconnecting",
                                 self.peer, auth_timeout)
                    else:
                        LOG.info("Client %s idle for over %ds; disconnecting", self.peer, idle_timeout)
                    break
                except (ConnectionError, OSError, ValueError):
                    break               # ValueError: line exceeded the stream limit
                if self._prebuffer:
                    line = self._prebuffer + line
                    self._prebuffer = b""
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    request = _DECODER.decode(line)
                except msgspec.MsgspecError:
                    LOG.debug("Malformed Stratum line from %s", self.peer)
                    continue
                try:
                    await self._dispatch(request)
                except Exception:
                    # Untrusted input must never crash the read loop; log and keep serving.
                    LOG.exception("Error handling %s from %s", request.method, self.peer)
                if max_protocol_errors and self.protocol_errors >= max_protocol_errors:
                    LOG.info("Client %s exceeded the protocol-error budget (%d); disconnecting",
                             self.peer, max_protocol_errors)
                    break
        finally:
            self.pool.unregister(self)
            LOG.info("Client disconnected: %s", self.peer)
            try:
                self.writer.close()
            except OSError:
                pass

    async def _dispatch(self, request: StratumRequest):
        method = request.method
        message_id = request.id if (isinstance(request.id, str)
                                    or (isinstance(request.id, int)
                                        and not isinstance(request.id, bool))) else None
        if isinstance(message_id, int) and not -(2**63) <= message_id <= 2**63 - 1:
            message_id = None
        params = request.params if isinstance(request.params, list) else []
        if method == "mining.subscribe":
            await self.handle_subscribe(message_id, params)
        elif method == "mining.authorize":
            await self.handle_authorize(message_id, params)
        elif method == "mining.configure":
            await self.handle_configure(message_id, params)
        elif method == "mining.submit":
            await self.handle_submit(message_id, params)
        elif method == "mining.suggest_difficulty":
            await self.handle_suggest_difficulty(message_id, params)
        elif method == "mining.extranonce.subscribe":
            await self._result(message_id, True)
        elif method is not None:
            LOG.debug("Unknown method %r from %s", method, self.peer)
            if message_id is not None:
                # Answer but don't charge the budget: benign legacy methods (mining.ping,
                # get_transactions, multi_version, suggest_target) are real firmware.
                code, message = ERR_OTHER
                await self._send({"id": message_id, "result": None, "error": [code, message, None]})
