"""SV2 Standard and Extended Mining Channel session."""

import asyncio
import dataclasses
import logging
import math
import threading
import time

from erikslund_pool import constants
from erikslund_pool import util
from erikslund_pool import work
from erikslund_pool.exceptions import RPCError
from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.hashrate import DecayingWindows
from erikslund_pool.stratum import tune_keepalive
from erikslund_pool.sv2 import codec as sv2_codec
from erikslund_pool.sv2 import messages as sv2_messages

LOG = logging.getLogger(__name__)

SV2_SUPPORTED_SETUP_FLAGS = (
    sv2_messages.REQUIRES_STANDARD_JOBS_FLAG
    | sv2_messages.REQUIRES_VERSION_ROLLING_FLAG
)
SV2_GROUP_CHANNEL_ID = 0
# Reserve two bytes for non-reused channel IDs; remaining extranonce bytes stay proxy-controlled.
SV2_CHANNEL_DISCRIMINATOR_BYTES = 2
SV2_MAX_CHANNEL_ID = (1 << (8 * SV2_CHANNEL_DISCRIMINATOR_BYTES)) - 1
SV2_MAX_ACTIVE_CHANNELS = 255
MAX_ISSUED_JOBS = 8
SV2_NONCE_SPACE = 1 << 32
SV2_MINIMUM_JOB_REFRESH_SECONDS = 0.25
SV2_MAXIMUM_JOB_SPACE_UTILIZATION = 0.8


@dataclasses.dataclass(frozen=True, slots=True)
class IssuedStandardJob:
    job_id: int
    source_job: work.Job
    legacy_coinbase: bytes
    merkle_root: bytes
    target: int
    min_ntime: int
    follows_channel_target: bool


@dataclasses.dataclass(frozen=True, slots=True)
class IssuedExtendedJob:
    job_id: int
    source_job: work.Job
    extended_work: work.ExtendedWork
    extranonce_prefix: bytes
    extranonce_size: int
    target: int
    min_ntime: int
    follows_channel_target: bool


type IssuedJob = IssuedStandardJob | IssuedExtendedJob
type ShareSubmit = (
    sv2_messages.SubmitSharesStandard | sv2_messages.SubmitSharesExtended
)
type ShareKey = tuple[int, int, int, int, int, bytes]


@dataclasses.dataclass(frozen=True, slots=True)
class BlockCandidate:
    job: work.Job
    share_result: work.ShareResult
    address: str
    worker: str


@dataclasses.dataclass(slots=True)
class MiningChannel:
    channel_id: int
    channel_type: str
    address: str
    worker: str
    payout_script: bytes
    device_maximum_target: int
    target: int
    difficulty: float
    extranonce_prefix: bytes
    extranonce_size: int
    last_publication_sequence: int
    opened_at: float
    last_retarget: float
    job_refresh_interval: float = 0.0
    next_job_refresh: float = 0.0
    shares_since_retarget: int = 0
    shares_accepted: int = 0
    shares_rejected: int = 0
    best_difficulty: float = 0.0
    last_share_timestamp: int = 0
    jobs: dict[int, IssuedJob] = dataclasses.field(default_factory=dict)
    prevhash: bytes | None = None
    prevhash_bits: int | None = None
    prevhash_min_ntime: int = 0
    prevhash_received: float = 0.0


class Sv2Session:
    """One SV2 connection with one Standard Channel or multiple Extended Channels."""

    def __init__(self, pool, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 extranonce1: bytes):
        self.pool = pool
        self.reader = reader
        self.writer = writer
        self._extranonce1 = extranonce1
        peername = writer.get_extra_info("peername")
        self.peer = f"{peername[0]}:{peername[1]}" if peername else "unknown"
        tune_keepalive(writer.get_extra_info("socket"), pool.config.work_rebroadcast_seconds)

        self.loop: asyncio.AbstractEventLoop | None = None
        self.protocol_errors = 0
        self.user_agent = "?"

        self._initial_difficulty = max(
            float(pool.config.initial_difficulty),
            float(pool.config.minimum_difficulty),
        )
        self._version_mask = (
            constants.SERVER_VERSION_MASK
            if pool.config.version_rolling_mask == constants.SERVER_VERSION_MASK
            else 0
        )
        self._channels: dict[int, MiningChannel] = {}
        self._next_channel_id = 1
        self._ever_opened_channel = False
        self._extranonce_counter = 0
        self._next_job_id = 1
        self._seen_shares: set[ShareKey] = set()
        self._seen_shares_previous: set[ShareKey] = set()

        self.connected_at = time.monotonic()
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.total_share_difficulty = 0.0
        self.best_difficulty = 0.0
        self.last_share_timestamp = 0
        self.hashrate = DecayingWindows(HASHRATE_WINDOWS, self.connected_at)
        self._stats_lock = threading.Lock()

        self._setup_complete = False
        self._setup_flags = 0
        self._close_after_response = False
        self._maximum_payload_size = min(
            pool.config.max_line_bytes, sv2_codec.MAX_WIRE_PAYLOAD_SIZE)
        self._decoder = sv2_codec.FrameDecoder(
            max_payload_size=self._maximum_payload_size)
        self._state_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()

    @property
    def channel_count(self) -> int:
        with self._stats_lock:
            return len(self._channels)

    @property
    def subscribed(self) -> bool:
        return self.channel_count > 0

    @property
    def authorized(self) -> bool:
        return self.channel_count > 0

    def _primary_channel_locked(self) -> MiningChannel | None:
        return next(iter(self._channels.values()), None)

    @property
    def address(self) -> str | None:
        with self._stats_lock:
            channel = self._primary_channel_locked()
            return channel.address if channel is not None else None

    @property
    def worker(self) -> str | None:
        with self._stats_lock:
            channel = self._primary_channel_locked()
            return channel.worker if channel is not None else None

    @property
    def payout_script(self) -> bytes | None:
        with self._stats_lock:
            channel = self._primary_channel_locked()
            return channel.payout_script if channel is not None else None

    @property
    def difficulty(self) -> float:
        with self._stats_lock:
            channel = self._primary_channel_locked()
            return channel.difficulty if channel is not None else self._initial_difficulty

    def connected_workers(self) -> tuple[tuple[str, str], ...]:
        """Return every payout identity with an active channel on this connection."""
        with self._stats_lock:
            return tuple(
                (channel.address, channel.worker) for channel in self._channels.values())

    async def _send_frames(self, *messages: sv2_messages.WireMessage) -> bool:
        encoded_frames = b"".join(
            sv2_codec.encode_frame(sv2_messages.encode_message(message),
                                   max_payload_size=sv2_codec.MAX_WIRE_PAYLOAD_SIZE)
            for message in messages
        )
        try:
            async with self._write_lock:
                self.writer.write(encoded_frames)
                await self.writer.drain()
            return True
        except (ConnectionError, OSError):
            self._close_after_response = True
            return False

    def _difficulty_for_hashrate(self, nominal_hash_rate: float) -> float:
        config = self.pool.config
        difficulty = max(
            float(config.initial_difficulty),
            float(config.minimum_difficulty),
        )
        if config.variable_difficulty and nominal_hash_rate > 0:
            hashrate_difficulty = (
                nominal_hash_rate * 60.0
                / (constants.NONCES * config.vardiff_target_shares_per_minute)
            )
            difficulty = max(difficulty, hashrate_difficulty)
            if config.maximum_difficulty > 0:
                difficulty = min(difficulty, config.maximum_difficulty)
        return difficulty

    def _standard_job_hashes(self) -> int:
        return SV2_NONCE_SPACE << self._version_mask.bit_count()

    def _extended_job_hashes(self) -> int:
        downstream_size = max(
            0,
            self.pool.config.extranonce2_size - SV2_CHANNEL_DISCRIMINATOR_BYTES,
        )
        return self._standard_job_hashes() << (8 * downstream_size)

    def _maximum_nominal_hash_rate(self, channel_type: str) -> float:
        if channel_type == "extended":
            # Extended channels must not exhaust their extranonce space within one nTime second.
            return self._extended_job_hashes() * SV2_MAXIMUM_JOB_SPACE_UTILIZATION
        return (
            self._standard_job_hashes()
            * SV2_MAXIMUM_JOB_SPACE_UTILIZATION
            / SV2_MINIMUM_JOB_REFRESH_SECONDS
        )

    def _set_job_refresh_rate(
            self, channel: MiningChannel, nominal_hash_rate: float) -> None:
        if channel.channel_type != "standard":
            channel.job_refresh_interval = 0.0
            channel.next_job_refresh = 0.0
            return
        job_hashes = self._standard_job_hashes()
        if nominal_hash_rate <= job_hashes:
            channel.job_refresh_interval = 0.0
            channel.next_job_refresh = 0.0
            return
        channel.job_refresh_interval = SV2_MINIMUM_JOB_REFRESH_SECONDS
        channel.next_job_refresh = time.monotonic() + channel.job_refresh_interval

    def _allocate_extranonce_prefix(self) -> bytes:
        suffix_size = self.pool.config.extranonce2_size
        self._extranonce_counter = (
            self._extranonce_counter + 1) % (1 << (8 * suffix_size))
        return self._extranonce1 + self._extranonce_counter.to_bytes(suffix_size, "big")

    def _allocate_job_id(self) -> int:
        job_id = self._next_job_id
        self._next_job_id = (self._next_job_id + 1) & sv2_codec.UINT32_MAX
        if self._next_job_id == 0:
            self._next_job_id = 1
        return job_id

    def _allocate_channel_id(self) -> int | None:
        if self._next_channel_id > SV2_MAX_CHANNEL_ID:
            return None
        channel_id = self._next_channel_id
        self._next_channel_id += 1
        return channel_id

    def _channel_limit_reached(self, channel_type: str) -> bool:
        if self._next_channel_id > SV2_MAX_CHANNEL_ID:
            return True
        if channel_type == "standard":
            return bool(self._channels)
        if any(channel.channel_type == "standard"
               for channel in self._channels.values()):
            return True
        return len(self._channels) >= SV2_MAX_ACTIVE_CHANNELS

    @staticmethod
    def _requires_new_prevhash(channel: MiningChannel, job: work.Job) -> bool:
        return (
            channel.prevhash != job.prevhash_internal
            or channel.prevhash_bits != job.bits
        )

    def _prepare_job(self, channel: MiningChannel, job: work.Job, *, clean: bool,
                     announced_prefix: bytes | None = None
                     ) -> list[sv2_messages.WireMessage]:
        if channel.channel_id not in self._channels:
            return []

        clean = clean or self._requires_new_prevhash(channel, job)
        job_id = self._allocate_job_id()
        prefix_message: sv2_messages.SetExtranoncePrefix | None = None
        if channel.channel_type == "standard":
            prefix = (
                announced_prefix
                if announced_prefix is not None else self._allocate_extranonce_prefix()
            )
            if announced_prefix is None:
                prefix_message = sv2_messages.SetExtranoncePrefix(
                    channel_id=channel.channel_id,
                    extranonce_prefix=prefix,
                )
            channel.extranonce_prefix = prefix
            standard_work = job.build_standard_work(channel.payout_script, prefix)
            issued_job: IssuedJob = IssuedStandardJob(
                job_id=job_id,
                source_job=job,
                legacy_coinbase=standard_work.legacy_coinbase,
                merkle_root=standard_work.merkle_root,
                target=channel.target,
                min_ntime=job.curtime,
                follows_channel_target=clean,
            )
            new_job: sv2_messages.WireMessage = sv2_messages.NewMiningJob(
                channel_id=channel.channel_id,
                job_id=job_id,
                min_ntime=None if clean else job.curtime,
                version=job.version,
                merkle_root=standard_work.merkle_root,
            )
        else:
            extended_work = job.build_extended_work(channel.payout_script)
            issued_job = IssuedExtendedJob(
                job_id=job_id,
                source_job=job,
                extended_work=extended_work,
                extranonce_prefix=channel.extranonce_prefix,
                extranonce_size=channel.extranonce_size,
                target=channel.target,
                min_ntime=job.curtime,
                follows_channel_target=clean,
            )
            new_job = sv2_messages.NewExtendedMiningJob(
                channel_id=channel.channel_id,
                job_id=job_id,
                min_ntime=None if clean else job.curtime,
                version=job.version,
                version_rolling_allowed=self._version_mask != 0,
                merkle_path=extended_work.merkle_path,
                coinbase_tx_prefix=extended_work.coinbase_tx_prefix,
                coinbase_tx_suffix=extended_work.coinbase_tx_suffix,
            )

        if clean:
            channel.jobs.clear()
        channel.jobs[job_id] = issued_job
        while len(channel.jobs) > MAX_ISSUED_JOBS:
            channel.jobs.pop(next(iter(channel.jobs)))

        messages: list[sv2_messages.WireMessage] = []
        if prefix_message is not None:
            messages.append(prefix_message)
        messages.append(new_job)
        if clean:
            messages.append(sv2_messages.SetNewPrevHash(
                channel_id=channel.channel_id,
                job_id=job_id,
                prev_hash=job.prevhash_internal,
                min_ntime=job.curtime,
                nbits=job.bits,
            ))
            channel.prevhash = job.prevhash_internal
            channel.prevhash_bits = job.bits
            channel.prevhash_min_ntime = job.curtime
            channel.prevhash_received = time.monotonic()
        if channel.job_refresh_interval > 0:
            channel.next_job_refresh = time.monotonic() + channel.job_refresh_interval
        return messages

    async def send_notify(self, job: work.Job, clean: bool) -> None:
        """Pool fan-out hook shared with the SV1 session."""
        async with self._state_lock:
            if not self._channels:
                return
            publication_sequence = job.publication_sequence
            channels = [
                channel
                for channel in self._channels.values()
                if (
                    not publication_sequence
                    or publication_sequence > channel.last_publication_sequence
                )
            ]
            if not channels:
                return
            if clean or any(self._requires_new_prevhash(channel, job) for channel in channels):
                self._rotate_share_generation()
            messages: list[sv2_messages.WireMessage] = []
            for channel in channels:
                channel.last_publication_sequence = max(
                    channel.last_publication_sequence,
                    publication_sequence,
                )
                messages.extend(self._prepare_job(channel, job, clean=clean))
            if messages:
                await self._send_frames(*messages)

    async def _handle_setup(self, message: sv2_messages.SetupConnection) -> None:
        supported_flags = SV2_SUPPORTED_SETUP_FLAGS
        if self._version_mask == 0:
            supported_flags &= ~sv2_messages.REQUIRES_VERSION_ROLLING_FLAG
        unsupported_flags = message.flags & ~supported_flags
        if message.protocol != sv2_messages.MINING_PROTOCOL:
            await self._send_frames(sv2_messages.SetupConnectionError(
                flags=0, error_code="unsupported-protocol"))
            self._close_after_response = True
            return
        if not (
            message.min_version
            <= sv2_messages.PROTOCOL_VERSION
            <= message.max_version
        ):
            await self._send_frames(sv2_messages.SetupConnectionError(
                flags=0, error_code="protocol-version-mismatch"))
            self._close_after_response = True
            return
        if unsupported_flags:
            await self._send_frames(sv2_messages.SetupConnectionError(
                flags=unsupported_flags, error_code="unsupported-feature-flags"))
            self._close_after_response = True
            return

        self._setup_complete = True
        self._setup_flags = message.flags
        self.user_agent = util.sanitize(
            "/".join(part for part in (
                message.vendor, message.hardware_version, message.firmware) if part))
        await self._send_frames(sv2_messages.SetupConnectionSuccess(
            used_version=sv2_messages.PROTOCOL_VERSION,
            flags=(sv2_messages.REQUIRES_FIXED_VERSION_FLAG
                   if self._version_mask == 0 else 0),
        ))

    async def _reject_open(
            self, request_id: int, error_code: str, *, protocol_error: bool = True) -> None:
        if protocol_error:
            self.protocol_errors += 1
        await self._send_frames(sv2_messages.OpenMiningChannelError(
            request_id=request_id, error_code=error_code))

    async def _reject_channel_limit(self, request_id: int) -> None:
        await self._reject_open(request_id, "channel-limit-reached", protocol_error=False)
        if self._next_channel_id > SV2_MAX_CHANNEL_ID:
            self._close_after_response = True

    async def _handle_open(
            self, message: (
                sv2_messages.OpenStandardMiningChannel
                | sv2_messages.OpenExtendedMiningChannel
            )) -> None:
        channel_type = (
            "extended"
            if isinstance(message, sv2_messages.OpenExtendedMiningChannel)
            else "standard"
        )
        if self._channel_limit_reached(channel_type):
            await self._reject_channel_limit(message.request_id)
            return
        if (channel_type == "extended"
                and self._setup_flags & sv2_messages.REQUIRES_STANDARD_JOBS_FLAG):
            await self._reject_open(message.request_id, "requires-standard-jobs")
            return
        downstream_extranonce_size = (
            self.pool.config.extranonce2_size - SV2_CHANNEL_DISCRIMINATOR_BYTES)
        if (channel_type == "extended"
                and (downstream_extranonce_size < 0
                     or not 0 <= message.min_extranonce_size
                     <= downstream_extranonce_size)):
            await self._reject_open(message.request_id, "insufficient-extranonce-size")
            return
        if (not math.isfinite(message.nominal_hash_rate)
                or message.nominal_hash_rate < 0
                or message.nominal_hash_rate
                > self._maximum_nominal_hash_rate(channel_type)):
            await self._reject_open(message.request_id, "invalid-nominal-hash-rate")
            return

        maximum_target = int.from_bytes(message.max_target, "little")
        if maximum_target == 0:
            await self._reject_open(message.request_id, "too-low-difficulty")
            return

        username = util.sanitize(message.user_identity)
        address, _, _ = username.partition(".")
        worker_name = util.ascii_worker(message.user_identity.partition(".")[2])
        try:
            address_is_valid, payout_script = await self.pool.validate_address(address)
        except RPCError as error:
            LOG.warning("Rejecting SV2 channel from %s: address check unavailable (%s)",
                        self.peer, error)
            await self._reject_open(
                message.request_id, "temporary-unavailable", protocol_error=False)
            return
        if not address_is_valid or payout_script is None:
            await self._reject_open(message.request_id, "unknown-user")
            return

        async with self._state_lock:
            if self._channel_limit_reached(channel_type):
                await self._reject_channel_limit(message.request_id)
                return
            current_job = self.pool._current_job_locked()
            if current_job is None:
                await self._reject_open(
                    message.request_id, "work-not-ready", protocol_error=False)
                return
            channel_id = self._allocate_channel_id()
            if channel_id is None:
                await self._reject_open(
                    message.request_id, "channel-limit-reached", protocol_error=False)
                return
            target = min(
                util.difficulty_to_target(
                    self._difficulty_for_hashrate(message.nominal_hash_rate)
                ),
                maximum_target,
            )
            if channel_type == "standard":
                extranonce_prefix = self._allocate_extranonce_prefix()
                extranonce_size = 0
            else:
                extranonce_prefix = (
                    self._extranonce1
                    + channel_id.to_bytes(SV2_CHANNEL_DISCRIMINATOR_BYTES, "big")
                )
                extranonce_size = downstream_extranonce_size
            now = time.monotonic()
            channel = MiningChannel(
                channel_id=channel_id,
                channel_type=channel_type,
                address=address,
                worker=worker_name,
                payout_script=payout_script,
                device_maximum_target=maximum_target,
                target=target,
                difficulty=util.target_to_difficulty(target),
                extranonce_prefix=extranonce_prefix,
                extranonce_size=extranonce_size,
                last_publication_sequence=current_job.publication_sequence,
                opened_at=now,
                last_retarget=now,
            )
            self._set_job_refresh_rate(channel, message.nominal_hash_rate)
            with self._stats_lock:
                self._channels[channel_id] = channel
            self._ever_opened_channel = True
            self.pool.attach_worker(address, worker_name)

            if channel_type == "standard":
                success: sv2_messages.WireMessage = (
                    sv2_messages.OpenStandardMiningChannelSuccess(
                        request_id=message.request_id,
                        channel_id=channel_id,
                        target=target.to_bytes(32, "little"),
                        extranonce_prefix=extranonce_prefix,
                        group_channel_id=SV2_GROUP_CHANNEL_ID,
                    )
                )
            else:
                success = sv2_messages.OpenExtendedMiningChannelSuccess(
                    request_id=message.request_id,
                    channel_id=channel_id,
                    target=target.to_bytes(32, "little"),
                    extranonce_size=extranonce_size,
                    extranonce_prefix=extranonce_prefix,
                    group_channel_id=SV2_GROUP_CHANNEL_ID,
                )
            job_messages = self._prepare_job(
                channel,
                current_job,
                clean=True,
                announced_prefix=extranonce_prefix,
            )
            await self._send_frames(success, *job_messages)
        LOG.info("Authorized SV2 %s channel %d on %s (address=%s, user_agent=%s)",
                 channel_type, channel_id, self.peer, address, self.user_agent)

    def _remember_share(self, share_key: ShareKey) -> bool:
        if share_key in self._seen_shares or share_key in self._seen_shares_previous:
            return False
        if len(self._seen_shares) >= constants.MAX_SEEN_SHARES:
            self._seen_shares_previous = self._seen_shares
            self._seen_shares = set()
        self._seen_shares.add(share_key)
        return True

    def _rotate_share_generation(self) -> None:
        if self._seen_shares:
            self._seen_shares_previous = self._seen_shares
            self._seen_shares = set()

    def _record_rejected(self, channel: MiningChannel | None, reason: str) -> None:
        with self._stats_lock:
            self.shares_rejected += 1
            if channel is not None:
                channel.shares_rejected += 1
        self.pool.note_rejected_share(
            channel.address if channel is not None else "",
            channel.worker if channel is not None else "",
            constants.reject_class_of(reason),
        )

    def _record_accepted(
        self,
        channel: MiningChannel,
        share_result: work.ShareResult,
        credited_difficulty: float,
    ) -> None:
        now_wall = int(time.time())
        now_steady = time.monotonic()
        with self._stats_lock:
            self.protocol_errors = 0
            channel.shares_since_retarget += 1
            channel.shares_accepted += 1
            channel.best_difficulty = max(
                channel.best_difficulty,
                share_result.difficulty,
            )
            channel.last_share_timestamp = now_wall
            self.shares_accepted += 1
            self.total_share_difficulty += credited_difficulty
            self.best_difficulty = max(self.best_difficulty, share_result.difficulty)
            self.last_share_timestamp = now_wall
        self.hashrate.add(credited_difficulty, now_steady)
        self.pool.note_accepted_share(
            channel.address,
            channel.worker,
            credited_difficulty,
            share_result.difficulty,
        )

    async def _reject_submit(self, message: ShareSubmit, channel: MiningChannel | None,
                             error_code: str, reason: str) -> None:
        self._record_rejected(channel, reason)
        await self._send_frames(sv2_messages.SubmitSharesError(
            channel_id=message.channel_id,
            sequence_number=message.sequence_number,
            error_code=error_code,
        ))

    async def _handle_submit(self, message: ShareSubmit) -> None:
        async with self._state_lock:
            block_candidate = await self._handle_submit_locked(message)
        # Submit RPCs must not hold the session lock.
        if block_candidate is not None:
            await self.pool.on_block_found(
                self,
                block_candidate.job,
                block_candidate.share_result,
                address=block_candidate.address,
                worker=block_candidate.worker,
            )

    async def _reject_update(self, channel_id: int, error_code: str) -> None:
        self.protocol_errors += 1
        await self._send_frames(sv2_messages.UpdateChannelError(
            channel_id=channel_id, error_code=error_code))

    async def _handle_update(self, message: sv2_messages.UpdateChannel) -> None:
        async with self._state_lock:
            channel = self._channels.get(message.channel_id)
            if channel is None:
                await self._reject_update(message.channel_id, "invalid-channel")
                return
            if (not math.isfinite(message.nominal_hash_rate)
                    or message.nominal_hash_rate < 0
                    or message.nominal_hash_rate
                    > self._maximum_nominal_hash_rate(channel.channel_type)):
                await self._reject_update(message.channel_id, "invalid-nominal-hash-rate")
                return
            maximum_target = int.from_bytes(message.maximum_target, "little")
            if maximum_target == 0:
                await self._reject_update(message.channel_id, "too-low-difficulty")
                return
            rapid_refresh_was_enabled = channel.job_refresh_interval > 0
            channel.device_maximum_target = maximum_target
            self._set_job_refresh_rate(channel, message.nominal_hash_rate)
            requested_target = channel.target
            if self.pool.config.variable_difficulty and message.nominal_hash_rate > 0:
                requested_target = util.difficulty_to_target(
                    self._difficulty_for_hashrate(message.nominal_hash_rate)
                )
            requested_target = min(requested_target, maximum_target)
            if requested_target != channel.target:
                await self._send_frames(*self._change_target(channel, requested_target))
            elif not rapid_refresh_was_enabled and channel.job_refresh_interval > 0:
                current_job = self.pool._current_job_locked()
                if current_job is not None:
                    await self._send_frames(*self._prepare_job(
                        channel,
                        current_job,
                        clean=self._requires_new_prevhash(channel, current_job),
                    ))

    async def _handle_close(self, message: sv2_messages.CloseChannel) -> None:
        reason = util.sanitize(message.reason_code)
        async with self._state_lock:
            if message.channel_id == SV2_GROUP_CHANNEL_ID:
                with self._stats_lock:
                    closed_channels = tuple(self._channels.values())
                    self._channels.clear()
                if not closed_channels:
                    self.protocol_errors += 1
                    return
                LOG.info(
                    "Closed SV2 group %d on %s (%d channels, reason=%s)",
                    message.channel_id,
                    self.peer,
                    len(closed_channels),
                    reason,
                )
                return
            with self._stats_lock:
                channel = self._channels.pop(message.channel_id, None)
            if channel is None:
                self.protocol_errors += 1
                return
        LOG.info("Closed SV2 %s channel %d on %s (reason=%s)",
                 channel.channel_type, channel.channel_id, self.peer, reason)

    async def _handle_submit_locked(
            self, message: ShareSubmit
            ) -> BlockCandidate | None:
        channel = self._channels.get(message.channel_id)
        if channel is None:
            self.protocol_errors += 1
            await self._reject_submit(
                message, None, "invalid-channel", "malformed share field")
            return None
        is_extended_submit = isinstance(message, sv2_messages.SubmitSharesExtended)
        if is_extended_submit != (channel.channel_type == "extended"):
            self.protocol_errors += 1
            await self._reject_submit(message, channel, "invalid-channel-type",
                                      "malformed share field")
            return None
        issued_job = channel.jobs.get(message.job_id)
        if issued_job is None:
            await self._reject_submit(message, channel, "stale-share", "stale")
            return None
        if is_extended_submit != isinstance(issued_job, IssuedExtendedJob):
            self.protocol_errors += 1
            await self._reject_submit(
                message, channel, "invalid-share", "malformed share field")
            return None
        if (
            isinstance(issued_job, IssuedExtendedJob)
            and len(message.extranonce) != issued_job.extranonce_size
        ):
            await self._reject_submit(
                message, channel, "invalid-extranonce-size", "invalid extranonce2 size")
            return None
        extranonce = message.extranonce if is_extended_submit else b""
        share_key = (
            message.channel_id,
            message.job_id,
            message.nonce,
            message.ntime,
            message.version,
            extranonce,
        )
        if not self._remember_share(share_key):
            await self._reject_submit(message, channel, "duplicate-share", "duplicate")
            return None

        seconds_since_prevhash = max(0, int(time.monotonic() - channel.prevhash_received))
        minimum_ntime = max(issued_job.min_ntime, channel.prevhash_min_ntime)
        maximum_ntime = channel.prevhash_min_ntime + seconds_since_prevhash
        if (channel.prevhash is None or message.ntime < minimum_ntime
                or message.ntime > maximum_ntime):
            await self._reject_submit(
                message, channel, "invalid-ntime", "ntime out of range")
            return None

        if isinstance(issued_job, IssuedExtendedJob):
            share_result = issued_job.source_job.validate_extended_share(
                issued_work=issued_job.extended_work,
                extranonce_prefix=issued_job.extranonce_prefix,
                extranonce=message.extranonce,
                extranonce_size=issued_job.extranonce_size,
                ntime=message.ntime,
                nonce=message.nonce,
                version=message.version,
                share_target=issued_job.target,
                version_mask=self._version_mask,
            )
        else:
            share_result = issued_job.source_job.validate_standard_share(
                legacy_coinbase=issued_job.legacy_coinbase,
                merkle_root_bytes=issued_job.merkle_root,
                ntime=message.ntime,
                nonce=message.nonce,
                version=message.version,
                share_target=issued_job.target,
                version_mask=self._version_mask,
            )
        if not share_result.valid:
            if share_result.reason == "above target":
                error_code = "too-low-difficulty"
            elif share_result.reason == "invalid extranonce2 size":
                error_code = "invalid-extranonce-size"
            else:
                error_code = "invalid-share"
            await self._reject_submit(
                message,
                channel,
                error_code,
                share_result.reason or "malformed share field",
            )
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.debug("Rejected SV2 share from %s peer=%s channel=%d job=%d (%s)",
                          channel.address, self.peer, channel.channel_id,
                          message.job_id, share_result.reason)
            return None

        credited_difficulty = util.target_to_difficulty(issued_job.target)
        self._record_accepted(channel, share_result, credited_difficulty)
        # Round half up; a positive share must not report zero in the integral protocol field.
        share_sum = max(
            1,
            min(
                sv2_codec.UINT64_MAX,
                math.floor(credited_difficulty + 0.5),
            ),
        )
        await self._send_frames(sv2_messages.SubmitSharesSuccess(
            channel_id=message.channel_id,
            last_sequence_number=message.sequence_number,
            new_submits_accepted_count=1,
            new_shares_sum=share_sum,
        ))
        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Accepted SV2 share from %s peer=%s channel=%d diff %s/%s",
                      channel.address, self.peer, channel.channel_id,
                      util.format_difficulty(share_result.difficulty),
                      util.format_difficulty(credited_difficulty))
        if share_result.is_block:
            LOG.info("BLOCK CANDIDATE height=%d hash=%s diff=%.3f address=%s worker=%s",
                     issued_job.source_job.height,
                     share_result.block_hash_hex,
                     share_result.difficulty,
                     channel.address, channel.worker)
            return BlockCandidate(
                job=issued_job.source_job,
                share_result=share_result,
                address=channel.address,
                worker=channel.worker,
            )
        return None

    async def _dispatch(self, message: sv2_messages.Message) -> None:
        if not self._setup_complete:
            if not isinstance(message, sv2_messages.SetupConnection):
                self.protocol_errors += 1
                self._close_after_response = True
                await self._send_frames(sv2_messages.SetupConnectionError(
                    flags=0, error_code="setup-connection-required"))
                return
            await self._handle_setup(message)
            return
        if isinstance(message, sv2_messages.SetupConnection):
            self.protocol_errors += 1
            self._close_after_response = True
            await self._send_frames(sv2_messages.SetupConnectionError(
                flags=0, error_code="setup-connection-already-complete"))
        elif isinstance(message, (
                sv2_messages.OpenStandardMiningChannel,
                sv2_messages.OpenExtendedMiningChannel,
        )):
            await self._handle_open(message)
        elif isinstance(message, sv2_messages.UpdateChannel):
            await self._handle_update(message)
        elif isinstance(message, sv2_messages.CloseChannel):
            await self._handle_close(message)
        elif isinstance(message, (
                sv2_messages.SubmitSharesStandard,
                sv2_messages.SubmitSharesExtended,
        )):
            await self._handle_submit(message)
        else:
            self.protocol_errors += 1

    async def maybe_retarget(self) -> None:
        async with self._state_lock:
            await self._maybe_retarget_locked()

    async def maybe_refresh_job(self) -> bool:
        """Refresh a Standard Job before a high-hash channel exhausts its header space."""
        async with self._state_lock:
            now = time.monotonic()
            channels = [
                channel
                for channel in self._channels.values()
                if channel.job_refresh_interval > 0
                and now >= channel.next_job_refresh
            ]
            if not channels:
                return False
            current_job = self.pool._current_job_locked()
            if current_job is None:
                return True
            messages: list[sv2_messages.WireMessage] = []
            rotate_shares = any(
                self._requires_new_prevhash(channel, current_job)
                for channel in channels
            )
            if rotate_shares:
                self._rotate_share_generation()
            for channel in channels:
                channel.next_job_refresh = now + channel.job_refresh_interval
                channel.last_publication_sequence = max(
                    channel.last_publication_sequence,
                    current_job.publication_sequence,
                )
                messages.extend(self._prepare_job(
                    channel,
                    current_job,
                    clean=self._requires_new_prevhash(channel, current_job),
                ))
            if messages:
                await self._send_frames(*messages)
            return True

    async def _maybe_retarget_locked(self) -> None:
        config = self.pool.config
        if not config.variable_difficulty or not self._channels:
            return
        now = time.monotonic()
        messages: list[sv2_messages.WireMessage] = []
        for channel in self._channels.values():
            elapsed = now - channel.last_retarget
            if elapsed < config.vardiff_retarget_seconds:
                continue
            with self._stats_lock:
                shares = channel.shares_since_retarget
                channel.shares_since_retarget = 0
            channel.last_retarget = now
            shares_per_minute = (shares / elapsed) * 60.0 if elapsed > 0 else 0.0
            difficulty_cap = (
                config.maximum_difficulty if config.maximum_difficulty > 0 else 1e12)
            requested_difficulty = channel.difficulty
            if shares_per_minute > config.vardiff_target_shares_per_minute * 2:
                requested_difficulty = min(difficulty_cap, channel.difficulty * 2)
            elif shares_per_minute < config.vardiff_target_shares_per_minute / 2:
                requested_difficulty = max(
                    config.minimum_difficulty,
                    channel.difficulty / 2,
                )
            new_target = min(
                util.difficulty_to_target(requested_difficulty),
                channel.device_maximum_target,
            )
            if new_target == channel.target:
                continue
            messages.extend(self._change_target(channel, new_target))
            LOG.debug("SV2 vardiff %s channel=%d -> %s (%.1f shares/min)",
                      self.peer, channel.channel_id,
                      util.format_difficulty(channel.difficulty), shares_per_minute)
        if messages:
            await self._send_frames(*messages)

    def _change_target(
            self, channel: MiningChannel, new_target: int) -> list[sv2_messages.WireMessage]:
        # Future jobs follow SetTarget; active jobs keep their issued target.
        channel.jobs = {
            job_id: (
                dataclasses.replace(issued_job, target=new_target)
                if issued_job.follows_channel_target
                else issued_job
            )
            for job_id, issued_job in channel.jobs.items()
        }
        with self._stats_lock:
            channel.target = new_target
            channel.difficulty = util.target_to_difficulty(new_target)
        return [sv2_messages.SetTarget(
            channel_id=channel.channel_id,
            maximum_target=new_target.to_bytes(32, "little"),
        )]

    def _channel_stats_locked(self, channel: MiningChannel) -> dict:
        return {
            "address": channel.address,
            "worker": channel.worker,
            "peer": self.peer,
            "user_agent": f"SV2/{self.user_agent}",
            "channel_id": channel.channel_id,
            "difficulty": channel.difficulty,
            "shares_accepted": channel.shares_accepted,
            "shares_rejected": channel.shares_rejected,
            "best_diff": channel.best_difficulty,
            "last_share_ts": channel.last_share_timestamp,
            "connected_for": int(time.monotonic() - channel.opened_at),
        }

    def stats_for_address(self, address: str) -> list[dict]:
        with self._stats_lock:
            return [
                self._channel_stats_locked(channel)
                for channel in self._channels.values()
                if channel.address == address
            ]

    def stats(self) -> dict:
        with self._stats_lock:
            channel = self._primary_channel_locked()
            return {
                "address": channel.address if channel is not None else None,
                "worker": channel.worker if channel is not None else None,
                "peer": self.peer,
                "user_agent": f"SV2/{self.user_agent}",
                "channels": len(self._channels),
                "difficulty": (
                    channel.difficulty if channel is not None else self._initial_difficulty),
                "shares_accepted": self.shares_accepted,
                "shares_rejected": self.shares_rejected,
                "best_diff": self.best_difficulty,
                "last_share_ts": self.last_share_timestamp,
                "connected_for": int(time.monotonic() - self.connected_at),
            }

    async def run(self) -> None:
        self.loop = asyncio.get_running_loop()
        self.pool.register(self)
        if self.writer.get_extra_info("sv2_noise", False):
            LOG.debug("Authenticated SV2 client connected: %s", self.peer)
        else:
            LOG.warning("Plaintext SV2 client connected: %s (development transport)", self.peer)
        connected_at = time.monotonic()
        last_activity = connected_at
        try:
            while not self._close_after_response:
                now = time.monotonic()
                deadlines: list[float] = []
                idle_timeout = self.pool.config.drop_idle_seconds
                if idle_timeout > 0:
                    deadlines.append(last_activity + idle_timeout)
                authorization_timeout = self.pool.config.auth_timeout_seconds
                if authorization_timeout > 0 and not self._ever_opened_channel:
                    deadlines.append(connected_at + authorization_timeout)
                deadlines.extend(
                    channel.next_job_refresh
                    for channel in self._channels.values()
                    if channel.job_refresh_interval > 0
                )
                deadline = min(deadlines) if deadlines else None
                timeout = None if deadline is None else max(0.0, deadline - now)
                try:
                    received_bytes = await asyncio.wait_for(
                        self.reader.read(64 * 1024), timeout=timeout)
                except TimeoutError:
                    now = time.monotonic()
                    if idle_timeout > 0 and now >= last_activity + idle_timeout:
                        break
                    if (
                        authorization_timeout > 0
                        and not self._ever_opened_channel
                        and now >= connected_at + authorization_timeout
                    ):
                        break
                    if await self.maybe_refresh_job():
                        continue
                    break
                except (ConnectionError, OSError, ValueError) as error:
                    LOG.debug("SV2 transport failed for %s: %s", self.peer, error)
                    break
                if not received_bytes:
                    break
                last_activity = time.monotonic()
                decode_error: sv2_codec.Sv2CodecError | None = None
                try:
                    frames = self._decoder.feed(received_bytes)
                except sv2_codec.Sv2CodecError as error:
                    frames = error.completed_frames
                    decode_error = error

                for frame in frames:
                    try:
                        message = sv2_messages.decode_message(frame)
                    except sv2_messages.UnsupportedMessageError:
                        # Ignore extensions; unsupported core messages count as protocol errors.
                        if frame.extension_id == sv2_messages.CORE_EXTENSION_ID:
                            self.protocol_errors += 1
                        continue
                    except sv2_codec.Sv2CodecError as error:
                        decode_error = error
                        break
                    try:
                        await self._dispatch(message)
                    except sv2_codec.Sv2CodecError as error:
                        decode_error = error
                        break
                    if self._close_after_response:
                        break

                if decode_error is not None:
                    LOG.debug("Malformed SV2 frame from %s: %s", self.peer, decode_error)
                    self.protocol_errors += 1
                    self._close_after_response = True
                    break
                error_limit = self.pool.config.max_protocol_errors
                if error_limit and self.protocol_errors >= error_limit:
                    break
        finally:
            self.pool.unregister(self)
            if self._ever_opened_channel:
                LOG.info("SV2 client disconnected: %s", self.peer)
            else:
                LOG.debug("SV2 client disconnected before opening a channel: %s", self.peer)
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except (ConnectionError, OSError):
                pass
