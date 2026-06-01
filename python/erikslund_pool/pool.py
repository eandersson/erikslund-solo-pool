"""Pool orchestrator: owns bitcoind, the current job, and all client sessions.

Free-threaded builds serve connections across N SO_REUSEPORT event-loop threads;
singletons run on the primary loop. Cross-loop state is lock-guarded.
"""

import asyncio
import concurrent.futures
import logging
import os
import sys
import threading
import time

import zmq
import zmq.asyncio

from erikslund_pool import __version__
from erikslund_pool import poolstatus
from erikslund_pool import proxy_protocol
from erikslund_pool.config import Settings
from erikslund_pool.config import resolve_worker_count
from erikslund_pool.constants import _ADDRESS_CHARS
from erikslund_pool.constants import DIFF1_TARGET
from erikslund_pool.constants import MAX_ADDRESS_CACHE
from erikslund_pool.constants import MAX_RECENT_JOBS
from erikslund_pool.exceptions import RPCConnectionError
from erikslund_pool.exceptions import RPCError
from erikslund_pool.exceptions import WorkError
from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.hashrate import SPS_WINDOWS
from erikslund_pool.hashrate import DecayingWindows
from erikslund_pool.rpc import BitcoindRPC
from erikslund_pool.stratum import ClientSession
from erikslund_pool.util import dsha256
from erikslund_pool.util import redact_url
from erikslund_pool.work import Job

LOG = logging.getLogger(__name__)

# Grace before a disconnected never-mined (authorize-only) registry row is pruned, applied
# regardless of user_stats_retention_days so authorize-churn can't pin the registry cap.
GHOST_ROW_GRACE_SECONDS = 3600.0


def block_subsidy(height: int, halving_interval: int) -> int:
    """Consensus GetBlockSubsidy: 50 BTC halved every interval, zero after 64 halvings."""
    halvings = height // halving_interval if halving_interval > 0 else 0
    if halvings >= 64:
        return 0
    return 5_000_000_000 >> halvings


class _WorkerStat:
    """One persistent (address, worker-name) stats row; survives disconnect and restart."""

    def __init__(self, start: float):
        self.hashrate = DecayingWindows(HASHRATE_WINDOWS, start)
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.best_diff = 0.0          # max actual hash difficulty met, not the credited target
        self.last_share_ts = 0        # wall: last accepted share
        self.last_activity_ts = 0     # wall: last attach/accept/reject (prune clock)


def classify_submit(reason: str | None) -> str:
    """Classify submitblock's reply (BIP22): None/"inconclusive" => valid block we produced;
    "duplicate"/"duplicate-inconclusive" => already in a chain (a win); else rejected."""
    if reason is None or reason == "inconclusive":
        return "accepted"
    if reason in ("duplicate", "duplicate-inconclusive"):
        return "already_known"
    return "rejected"


class Pool:
    def __init__(self, settings: Settings):
        self.config = settings
        self.rpc = BitcoindRPC(
            settings.rpc_url, settings.rpc_user, settings.rpc_password,
            failover=[(e["url"], e.get("user", settings.rpc_user),
                       e.get("password", settings.rpc_password))
                      for e in settings.rpc_failover])
        self.clients: set[ClientSession] = set()

        self.current_job: Job | None = None
        self._recent: dict[str, Job] = {}
        self._job_counter = 0
        # Random high half of job ids -> unique across restarts and non-sequential; low half is
        # the counter (see _make_job).
        self._job_id_prefix = int.from_bytes(os.urandom(4), "big")
        self._extranonce1_counter = 0
        self._address_cache: dict[str, tuple[bool, bytes | None]] = {}
        self._donation_script: bytes = b""
        self._donation_resolved = False

        self._last_prevhash: str | None = None
        self._last_template_time = 0.0   # last real GBT build (feeds last_template_age_sec metric)
        self._last_broadcast_time = 0.0
        self._fastblock_pending = False
        self._new_block_event = asyncio.Event()

        self.started = time.time()
        self._started_monotonic = time.monotonic()
        self.blocks_found = 0
        self.last_block_found = 0  # wall epoch of most recent accepted block (0 = none)
        self._blocks_by_address: dict[str, int] = {}
        self.shares_accepted = 0
        self.shares_rejected = 0
        self.total_share_diff = 0.0
        self._hashrate = DecayingWindows(HASHRATE_WINDOWS, self._started_monotonic)
        self._sps = DecayingWindows(SPS_WINDOWS, self._started_monotonic)
        self.best_diff = 0.0          # survives restarts via pool.status
        self._baseline_diff = 0.0     # accepted diff recovered from a prior pool.status
        self.chain_info: dict = {}
        self.generator_ready = False
        self.connector_ready = False
        self._empty_commitment = "6a24aa21a9ed" + dsha256(b"\x00" * 64).hex()

        self.block_spool_dir = os.path.join(settings.stats_directory, "blocks")
        self._servers: list = []
        self._tasks: list[asyncio.Task] = []
        # Dedicated pool so a validateaddress flood on a hung node can't starve a block submit.
        self._submit_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=2, thread_name_prefix="submitblock")
        # validateaddress on its own bounded pool so an authorize flood (one RPC per novel
        # username) can't stall new-job delivery; pending calls bounded by max_clients.
        self._validate_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="validateaddr")

        # Free-threaded builds validate across N loops; a GIL build uses one.
        self.free_threaded = not getattr(sys, "_is_gil_enabled", lambda: True)()
        self.num_loops = resolve_worker_count(settings.worker_threads) if self.free_threaded else 1
        self._primary_loop: asyncio.AbstractEventLoop | None = None
        self._loops: list[asyncio.AbstractEventLoop] = []
        self._worker_threads: list[threading.Thread] = []
        # Each guards the state its name implies; all held only briefly.
        self._jobs_lock = threading.Lock()
        self._clients_lock = threading.Lock()
        self._extranonce1_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._loops_lock = threading.Lock()
        # Serializes _write_stats so the off-loop status writer and the shutdown flush never
        # overlap (poolstatus holds single-writer prune state and temp files).
        self._stats_write_lock = threading.Lock()
        # Persistent per-(address, worker-name) stats backing the users/ files.
        self._user_stats: dict[str, dict[str, _WorkerStat]] = {}
        self._user_stats_lock = threading.Lock()
        # Connections past the accept gate but not yet registered (e.g. in the ~2s PROXY-header
        # read). Counted toward max_clients; guarded by _clients_lock with len(self.clients).
        self._inflight = 0

    def assign_extranonce1(self) -> bytes:
        size = self.config.extranonce1_size
        with self._extranonce1_lock:
            self._extranonce1_counter = (self._extranonce1_counter + 1) % (1 << (8 * size))
            value = self._extranonce1_counter
        return value.to_bytes(size, "big")

    def register(self, session: ClientSession):
        with self._clients_lock:
            self.clients.add(session)

    def unregister(self, session: ClientSession):
        with self._clients_lock:
            self.clients.discard(session)

    def _snapshot_clients(self) -> list[ClientSession]:
        with self._clients_lock:
            return list(self.clients)

    def _client_count(self) -> int:
        with self._clients_lock:
            return len(self.clients)

    def _admit(self) -> bool:
        """Reserve an accept slot if registered + in-flight connections are under max_clients."""
        with self._clients_lock:
            if len(self.clients) + self._inflight >= self.config.max_clients:
                return False
            self._inflight += 1
            return True

    def _release_inflight(self) -> None:
        with self._clients_lock:
            self._inflight -= 1

    def _resolve_worker_key(self, workers: dict, worker: str) -> str:
        """The key a worker name resolves to without creating a row (caller holds the lock): an
        existing name keeps its key; a new name beyond max_workers_per_address folds into ""."""
        if worker in workers:
            return worker
        cap = self.config.max_workers_per_address
        if worker and cap > 0 and sum(1 for name in workers if name) >= cap:
            return ""  # at the cap: fold into the bare-address bucket
        return worker

    def _worker_entry(self, address: str, worker: str):
        """Resolve the persistent stat row for a worker name under the admission cap (caller holds
        _user_stats_lock). None when a new address would exceed the registry address cap."""
        new_address = address not in self._user_stats
        if new_address and len(self._user_stats) >= poolstatus.MAX_USER_FILES:
            return None  # registry address cap (defense vs an address-cycling attacker)
        workers = self._user_stats.setdefault(address, {})
        key = self._resolve_worker_key(workers, worker)
        stat = workers.get(key)
        if stat is None:
            stat = _WorkerStat(self._started_monotonic)
            workers[key] = stat
        return stat

    def attach_worker(self, address: str, worker: str) -> None:
        """Register a worker on authorize so an idle authorized rig appears and persists."""
        if not address:
            return
        now_wall = time.time()
        with self._user_stats_lock:
            stat = self._worker_entry(address, worker)
            if stat is not None:
                stat.last_activity_ts = max(stat.last_activity_ts, now_wall)

    def note_accepted_share(self, address: str, worker: str, credited: float,
                            share_difficulty: float):
        now = time.monotonic()
        now_wall = time.time()
        with self._stats_lock:
            self.shares_accepted += 1
            self.total_share_diff += credited
            self._hashrate.add(credited, now)
            self._sps.add(1.0, now)
            # Ratchet pool-wide best (actual hash difficulty) on every accepted share so a
            # disconnect between status cycles can't lose it.
            self.best_diff = max(self.best_diff, share_difficulty)
        if not address:
            return
        with self._user_stats_lock:
            stat = self._worker_entry(address, worker)
            if stat is None:
                return  # address-capped: counted pool-wide, not per-worker
            stat.hashrate.add(credited, now)
            stat.shares_accepted += 1
            # best_diff is the actual hash difficulty met, not the credited target.
            stat.best_diff = max(stat.best_diff, share_difficulty)
            stat.last_share_ts = now_wall
            stat.last_activity_ts = now_wall

    def note_rejected_share(self, address: str, worker: str):
        with self._stats_lock:
            self.shares_rejected += 1
        if not address:
            return
        now_wall = time.time()
        with self._user_stats_lock:
            stat = self._worker_entry(address, worker)
            if stat is not None:
                stat.shares_rejected += 1
                stat.last_activity_ts = now_wall  # a reject counts as activity

    def _connected_keys(self) -> set:
        """The (address, resolved-key) pairs currently mining, so prune/snapshot don't treat a
        live "" bucket as idle. Caller holds _user_stats_lock."""
        keys = set()
        for client in self._snapshot_clients():
            if client.authorized and client.address:
                workers = self._user_stats.get(client.address, {})
                key = self._resolve_worker_key(workers, client.worker or "")
                keys.add((client.address, key))
        return keys

    def _snapshot_user_stats(self, now: float, now_wall: float) -> list[dict]:
        """Sample the persistent registry: one row per (address, worker), hashrate aged to `now`."""
        rows = []
        with self._user_stats_lock:
            connected = self._connected_keys()
            for address, workers in self._user_stats.items():
                for worker, stat in workers.items():
                    rows.append({
                        "address": address,
                        "worker": worker,
                        "connected": (address, worker) in connected,
                        "shares_accepted": stat.shares_accepted,
                        "shares_rejected": stat.shares_rejected,
                        "best_diff": stat.best_diff,
                        "last_share_ts": stat.last_share_ts,
                        "hashrate": stat.hashrate.snapshot(now),
                    })
        return rows

    def prune_user_stats(self) -> None:
        """Evict registry rows that are idle and disconnected.

        A mined row ages out once last activity is beyond user_stats_retention_days
        (retention_days <= 0 keeps it forever). A never-mined (authorize-only) row ages out after
        GHOST_ROW_GRACE regardless of retention. A connected row is never evicted."""
        retention_days = self.config.user_stats_retention_days
        now = time.time()
        ghost_cutoff = now - GHOST_ROW_GRACE_SECONDS
        retention_cutoff = now - retention_days * 86400 if retention_days > 0 else None
        evicted_addresses: list[str] = []
        with self._user_stats_lock:
            connected = self._connected_keys()
            for address in list(self._user_stats):
                workers = self._user_stats[address]
                for worker in list(workers):
                    if (address, worker) in connected:
                        continue  # live: never evict
                    stat = workers[worker]
                    if stat.last_activity_ts <= 0:
                        continue  # no activity clock yet: nothing to age against
                    if stat.last_share_ts == 0:
                        expired = stat.last_activity_ts < ghost_cutoff       # never mined
                    elif retention_cutoff is not None:
                        expired = stat.last_activity_ts < retention_cutoff   # mined, retention on
                    else:
                        expired = False                                      # mined, keep forever
                    if expired:
                        del workers[worker]
                if not workers:
                    del self._user_stats[address]
                    evicted_addresses.append(address)
        # Unlink the users/<address> file for a fully-evicted address (else recovery reads it back
        # in). Outside the lock: filesystem I/O.
        users_dir = os.path.join(self.config.stats_directory, "users")
        for address in evicted_addresses:
            try:
                os.unlink(os.path.join(users_dir, address))
            except OSError:
                pass  # already gone / unwritable: the file retention sweep is the backstop

    def recover_user_stats(self) -> None:
        """Seed the registry from a prior run's users/ files, decaying each hashrate by file age.
        Two-pass so a restart can't launder the prune clock or double-decay:
          * Skip never-mined (last_share_ts == 0) or past-retention rows.
          * Accumulate raw file values per resolved key first (cap applied once), then seed each
            window once -- folding rows into "" via repeated snapshot()/seed() would decay twice.
          * last_activity_ts derives from last_share_ts only, never file mtime.
        """
        recovered = poolstatus.read_all_worker_stats(self.config.stats_directory)
        if not recovered:
            return
        retention_days = self.config.user_stats_retention_days
        cutoff = (time.time() - retention_days * 86400) if retention_days > 0 else float("-inf")

        # Pass 1: accumulate raw file values per (address, resolved key), applying the cap against
        # the keys seen so far.
        class _Accum:
            __slots__ = ("windows", "shares_accepted", "shares_rejected", "best_diff",
                         "last_share_ts", "max_age")

            def __init__(self):
                self.windows = {window: 0.0 for window in HASHRATE_WINDOWS}
                self.shares_accepted = 0
                self.shares_rejected = 0
                self.best_diff = 0.0
                self.last_share_ts = 0
                self.max_age = 0.0

        by_address: dict[str, dict[str, _Accum]] = {}
        cap = self.config.max_workers_per_address
        for rw in recovered:
            address = rw["address"]
            if not address:
                continue
            if rw["last_share_ts"] == 0 or rw["last_share_ts"] < cutoff:
                continue  # never mined, or expired past retention: do not resurrect
            keys = by_address.setdefault(address, {})
            worker = rw["worker"]
            if worker not in keys and worker and cap > 0 and sum(1 for k in keys if k) >= cap:
                worker = ""  # at the cap: fold into the bare-address bucket
            acc = keys.get(worker)
            if acc is None:
                acc = keys[worker] = _Accum()
            for window in HASHRATE_WINDOWS:
                acc.windows[window] += rw["hashrate"][window]
            acc.shares_accepted += rw["shares_accepted"]
            acc.shares_rejected += rw["shares_rejected"]
            acc.best_diff = max(acc.best_diff, rw["best_diff"])
            acc.last_share_ts = max(acc.last_share_ts, rw["last_share_ts"])
            acc.max_age = max(acc.max_age, rw["file_age_seconds"])

        # Pass 2: apply each accumulated key to the registry, seeding the windows exactly once.
        rows = 0
        with self._user_stats_lock:
            for address, keys in by_address.items():
                for key, acc in keys.items():
                    stat = self._worker_entry(address, key)
                    if stat is None:
                        continue  # registry address cap hit during recovery
                    stat.shares_accepted += acc.shares_accepted
                    stat.shares_rejected += acc.shares_rejected
                    stat.best_diff = max(stat.best_diff, acc.best_diff)
                    stat.last_share_ts = max(stat.last_share_ts, acc.last_share_ts)
                    stat.last_activity_ts = max(stat.last_activity_ts, acc.last_share_ts)
                    stat.hashrate.seed(acc.windows, self._started_monotonic, acc.max_age)
                    rows += 1
        LOG.info("Recovered %d worker stat row(s) from %s/users (hashrates decayed by file age)",
                 rows, self.config.stats_directory)

    def hashrate_windows(self, now: float) -> dict[int, float]:
        """Decaying hashrate weight (accepted diff/s) per window, aged to `now`."""
        with self._stats_lock:
            return self._hashrate.snapshot(now)

    def sps_windows(self, now: float) -> dict[int, float]:
        """Decaying shares/second per window, aged to `now`."""
        with self._stats_lock:
            return self._sps.snapshot(now)

    def _current_job_locked(self) -> "Job | None":
        """Read current_job under the jobs lock; use from a worker loop (other paths read it on
        the primary loop, which writes it)."""
        with self._jobs_lock:
            return self.current_job

    @staticmethod
    def _plausible_address(address: str) -> bool:
        return 0 < len(address) <= 100 and all(char in _ADDRESS_CHARS for char in address)

    async def validate_address(self, address: str) -> tuple[bool, bytes | None]:
        """Resolve a payout address to its scriptPubKey via bitcoind. Returns (False, None) for a
        well-formed-but-invalid address; raises RPCError on a transient node failure so callers can
        tell "address invalid" from "node down". Runs on _validate_executor."""
        with self._jobs_lock:  # also guards the address cache dict
            cached = self._address_cache.get(address)
        if cached is not None:
            return cached
        # Gate on format before hitting bitcoind: junk usernames mustn't amplify into RPC load or
        # grow the cache unbounded.
        if not self._plausible_address(address):
            return False, None
        loop = asyncio.get_running_loop()
        address_info = await loop.run_in_executor(
            self._validate_executor, self.rpc.validateaddress, address)
        script_hex = address_info.get("scriptPubKey")
        result = (bool(address_info.get("isvalid")) and bool(script_hex),
                  bytes.fromhex(script_hex) if script_hex else None)
        with self._jobs_lock:
            if len(self._address_cache) >= MAX_ADDRESS_CACHE:
                self._address_cache.clear()
            self._address_cache[address] = result
        return result

    def recent_job(self, job_id: str) -> Job | None:
        with self._jobs_lock:
            return self._recent.get(job_id)

    async def _resolve_donation(self) -> None:
        """Resolve donation_address -> script once; a bad address (or a node error at resolve time)
        disables donation, not work."""
        if self._donation_resolved:
            return
        self._donation_resolved = True
        if self.config.donation_percent <= 0.0 or not self.config.donation_address:
            return
        try:
            valid, script = await self.validate_address(self.config.donation_address)
        except RPCError as e:
            # Node failure resolving our own donation address: leave donation off, never crash work.
            LOG.warning("Donation disabled: address check failed (%s)", e)
            return
        if valid and script:
            self._donation_script = script
            LOG.info("Donation enabled: %.4g%% of each block to %s",
                     self.config.donation_percent, self.config.donation_address)
        else:
            LOG.warning("Donation disabled: invalid donation_address %r",
                        self.config.donation_address)

    def _make_job(self, template: dict, clean: bool) -> Job:
        with self._jobs_lock:
            self._job_counter += 1
            job_id = f"{self._job_id_prefix:08x}{self._job_counter:08x}"
        job = Job(
            job_id,
            template,
            tag=self.config.coinbase_signature.encode(),
            extranonce1_size=self.config.extranonce1_size,
            extranonce2_size=self.config.extranonce2_size,
            coinbase_version=self.config.coinbase_version,
            clean=clean,
            donation_script=self._donation_script,
            donation_percent=self.config.donation_percent if self._donation_script else 0.0,
        )
        return job

    def _validate_template(self, template: dict) -> None:
        """Raise if a GBT can't be assembled into work. Passed to rpc.getblocktemplate so failover
        sticks only after the template proves usable. Builds a throwaway Job (no counter side
        effect, no lock)."""
        Job("0" * 16, template, tag=self.config.coinbase_signature.encode(),
            extranonce1_size=self.config.extranonce1_size,
            extranonce2_size=self.config.extranonce2_size,
            coinbase_version=self.config.coinbase_version, clean=False,
            donation_script=self._donation_script,
            donation_percent=self.config.donation_percent if self._donation_script else 0.0)

    async def _fan_out(self, make_coroutine) -> None:
        """Run make_coroutine(client) on each client's own loop (the only thread allowed to touch
        its writer): same-loop awaited here, others dispatched cross-thread."""
        current_loop = asyncio.get_running_loop()
        local_coroutines = []
        for client in self._snapshot_clients():
            loop = client.loop
            if loop is None or not loop.is_running():
                continue
            coroutine = make_coroutine(client)
            if loop is current_loop:
                local_coroutines.append(coroutine)
            else:
                try:
                    asyncio.run_coroutine_threadsafe(coroutine, loop)
                except RuntimeError:
                    coroutine.close()
        if local_coroutines:
            await asyncio.gather(*local_coroutines, return_exceptions=True)

    async def _broadcast(self, job: Job, clean: bool, require_new_prevhash: bool = False) -> bool:
        # Suppress a broadcast byte-identical to current_job, atomically with publishing it under
        # _jobs_lock, so the GBT refresh and fastblock paths can't re-issue the same work (which
        # resets every miner to extranonce2=0). Returns True only if actually sent.
        # require_new_prevhash (fastblock only): suppress if a full job for this tip was published
        # while the empty job was being built.
        with self._jobs_lock:
            if self.current_job is not None and job.work_key == self.current_job.work_key:
                return False
            if (require_new_prevhash and self.current_job is not None
                    and job.prevhash_stratum == self.current_job.prevhash_stratum):
                return False
            self.current_job = job
            self._recent[job.job_id] = job
            while len(self._recent) > MAX_RECENT_JOBS:
                self._recent.pop(next(iter(self._recent)))
        await self._fan_out(lambda client: client.send_notify(job, clean))
        return True

    async def _refresh_template(self, force: bool = False):
        try:
            template = await asyncio.to_thread(self.rpc.getblocktemplate,
                                               validate=self._validate_template)
        except RPCConnectionError as e:
            self.generator_ready = False  # every endpoint down: /health degrades, re-latches on next RPC
            LOG.error("getblocktemplate failed: %s", e)
            return
        except RPCError as e:
            LOG.error("getblocktemplate failed: %s", e)
            return
        self.generator_ready = True
        await self._resolve_donation()
        # Malformed template or un-assemblable work is skipped like an RPC failure, never unwinds the loop.
        try:
            prevhash = template["previousblockhash"]
            new_tip = prevhash != self._last_prevhash
            if not (new_tip or force):
                return
            # Height monotonicity: a template below the current job's height comes from a behind
            # node (e.g. lagging failover); broadcasting it would yank miners onto an orphan parent.
            job_now = self.current_job
            if job_now is not None and template["height"] < job_now.height:
                LOG.warning("Ignoring a GBT at height %d below the current job's height %d "
                            "(lagging bitcoind?); keeping the current work",
                            template["height"], job_now.height)
                return
            clean = new_tip
            job = self._make_job(template, clean=clean)
        except (KeyError, ValueError, TypeError, WorkError) as e:
            LOG.error("getblocktemplate produced unusable work: %s", e)
            return
        self._last_prevhash = prevhash
        self._last_template_time = time.monotonic()   # metric: a real template was fetched
        self._last_broadcast_time = time.monotonic()  # timer: fresh work went out
        self._fastblock_pending = False  # a fresh GBT re-bases the fastblock fields
        # _broadcast suppresses a byte-identical rebroadcast: covers an unchanged template
        # (testnet/signet pin GBT curtime to MTP+1, freezing ntime) and any fastblock race.
        if await self._broadcast(job, clean):
            LOG.debug("New job %s height=%d txns=%d clean=%s",
                      job.job_id, job.height, job.txn_count, clean)
        else:
            LOG.debug("Work unchanged; not rebroadcasting a duplicate (job %s)", job.job_id)

    async def template_loop(self):
        while True:
            try:
                # The fastblock chain gate + halving interval need the chain name; retry until
                # bitcoind answers once.
                if not self.chain_info:
                    try:
                        self.chain_info = await asyncio.to_thread(self.rpc.getblockchaininfo)
                    except RPCError:
                        pass  # the probe/GBT below will log the outage
                # A mainnet template is multi-MB; gate the heavy call on a ~100-byte tip probe,
                # fetching the full template only when the tip moved, a rebroadcast is due, or
                # there is no work.
                job = self.current_job
                force = (job is None
                         or time.monotonic() - self._last_broadcast_time
                         >= self.config.work_rebroadcast_seconds)
                fetch = force
                if not fetch:
                    try:
                        tip = await asyncio.to_thread(self.rpc.getbestblockhash)
                    except RPCConnectionError as e:
                        self.generator_ready = False  # all endpoints down: /health degrades
                        LOG.error("getbestblockhash failed: %s", e)
                    except RPCError as e:
                        LOG.error("getbestblockhash failed: %s", e)
                    else:
                        self.generator_ready = True
                        # Fetch when the tip moved, or when the current job isn't mining on the
                        # probed tip (self-heal: work/tip divergence corrected within one poll).
                        fetch = (tip != self._last_prevhash
                                 or job.prevhash_internal != bytes.fromhex(tip)[::-1])
                if fetch:
                    await self._refresh_template(force=force)
                try:
                    await asyncio.wait_for(self._new_block_event.wait(),
                                           timeout=self.config.poll_interval)
                except asyncio.TimeoutError:
                    pass
                else:
                    self._new_block_event.clear()
            except Exception:
                # Work production must never die: a bad poll is retried.
                LOG.exception("template refresh failed")
                await asyncio.sleep(self.config.poll_interval)

    async def vardiff_loop(self):
        while True:
            try:
                await asyncio.sleep(max(5, self.config.vardiff_retarget_seconds // 2))
                await self._fan_out(lambda c: c.maybe_retarget())
            except Exception:
                LOG.exception("vardiff loop failed")
                await asyncio.sleep(max(5, self.config.vardiff_retarget_seconds // 2))

    async def _fastblock(self, block_hash_hex: str):
        """Broadcast empty 'stop work' for the next block before the slower getblocktemplate."""
        job = self.current_job
        if job is None or self._fastblock_pending or block_hash_hex == self._last_prevhash:
            return
        chain = self.chain_info.get("chain")
        if chain is None:
            # Unknown chain (bitcoind down at startup): the gates below would fail open; the normal
            # GBT path still serves the block.
            return
        if chain in ("test", "testnet4"):
            # Testnet's 20-minute rule makes required nBits depend on the new block's own timestamp,
            # so the tip's bits could mint bad-diffbits work.
            return
        # One header fetch grounds the empty job in consensus: the true next height (else a
        # multi-block advance/reorg mints a wrong BIP34 height), confirmations == 1 proving this
        # hash is the active tip, the tip's nBits, and its median-time-past for the ntime floor.
        header = await asyncio.to_thread(self.rpc.getblockheader, block_hash_hex)
        # Re-check the gates after the await: a concurrent _refresh_template may have broadcast a
        # full job for this tip (require_new_prevhash below also closes this with publication).
        if self._fastblock_pending or block_hash_hex == self._last_prevhash:
            return
        if header.get("confirmations") != 1:
            return  # stale notification (>= 2) or reorged away (-1): not the active tip
        next_height = header["height"] + 1
        if next_height % 2016 == 0:
            return  # difficulty retarget: the new tip's nBits don't apply to the next block
        halving = 150 if chain == "regtest" else 210000
        empty_template = {
            "height": next_height,
            "version": job.version,
            # ntime must exceed the new tip's MTP; floor at MTP+1 so a lagging clock can't
            # synthesize a "time-too-old" block.
            "curtime": max(int(time.time()), header["mediantime"] + 1),
            "bits": header["bits"],
            "coinbasevalue": block_subsidy(next_height, halving),
            "previousblockhash": block_hash_hex,
            "default_witness_commitment": self._empty_commitment,
            "transactions": [],
        }
        self._fastblock_pending = True
        empty_job = self._make_job(empty_template, clean=True)
        if await self._broadcast(empty_job, clean=True, require_new_prevhash=True):
            # Reset the rebroadcast timer (not the template-age metric -- no template was fetched)
            # so a timer-forced GBT from a lagging failover node can't yank miners onto the dead tip.
            self._last_broadcast_time = time.monotonic()
            LOG.debug("fastblock: empty work for height %d on new block %s", next_height, block_hash_hex)

    async def zmq_loop(self):
        """Optional instant new-tip notification when zmq_block_endpoint is configured."""
        if not self.config.zmq_block_endpoint:
            return
        context = zmq.asyncio.Context.instance()
        socket = context.socket(zmq.SUB)
        socket.connect(self.config.zmq_block_endpoint)
        socket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
        LOG.info("Subscribed to ZMQ hashblock at %s", self.config.zmq_block_endpoint)
        while True:
            try:
                parts = await socket.recv_multipart()
            except Exception:
                LOG.exception("zmq recv failed")
                await asyncio.sleep(1)
                continue
            block_hash = parts[1].hex() if len(parts) >= 2 and len(parts[1]) == 32 else None
            LOG.info("ZMQ: new-block notification %s", block_hash or "")
            if block_hash and self.config.fast_block_notify:
                try:
                    await self._fastblock(block_hash)
                except Exception:
                    LOG.exception("Fastblock failed")
            self._new_block_event.set()

    def _wake_template_loop(self) -> None:
        """Set the new-block event on the primary loop (safe from any thread)."""
        loop = self._primary_loop
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(self._new_block_event.set)

    def _spool_block(self, height: int, block_hash: str, block_hex: str,
                     address: str = "?", worker: str = "?"):
        try:
            os.makedirs(self.block_spool_dir, exist_ok=True)
            path = os.path.join(self.block_spool_dir, f"{height}_{block_hash}.hex")
            # Temp file, fsync, atomic rename: a crash mid-write must never leave a truncated .hex.
            tmp = f"{path}.tmp.{os.getpid()}"
            with open(tmp, "w", encoding="ascii") as f:
                f.write(block_hex + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
            LOG.info("Spooled block to %s (address=%s worker=%s; "
                     "recover with: bitcoin-cli submitblock <contents>)", path, address, worker)
        except OSError as e:
            LOG.error("CRITICAL: could not spool block hex (%s); HEX FOLLOWS: %s", e, block_hex)

    def _resubmit_spooled_blocks(self) -> None:
        """Re-submit any block a previous run spooled but never confirmed; bitcoind safely rejects
        a stale/duplicate. Each file is archived after handling so it is never retried. Synchronous
        (call via asyncio.to_thread)."""
        try:
            names = sorted(n for n in os.listdir(self.block_spool_dir) if n.endswith(".hex"))
        except OSError:
            return  # no spool dir yet
        for name in names:
            path = os.path.join(self.block_spool_dir, name)
            try:
                with open(path, "r", encoding="ascii") as f:
                    block_hex = f.read().strip()
            except OSError:
                continue
            if not block_hex:
                continue
            LOG.warning("Resubmitting block %s spooled by a previous run", name)
            try:
                reason = self.rpc.submitblock(block_hex)
            except RPCError as e:
                LOG.error("Could not resubmit spooled block %s (bitcoind unreachable: %s); "
                          "leaving it on disk for the next restart", name, e)
                continue
            if classify_submit(reason) != "rejected":
                LOG.info("Spooled block %s accepted/already known; archiving", name)
                self._archive_spooled(path, ".submitted")
            else:
                LOG.warning("Spooled block %s rejected by bitcoind (%s); archiving", name, reason)
                self._archive_spooled(path, ".rejected")

    @staticmethod
    def _archive_spooled(path: str, suffix: str) -> None:
        try:
            os.replace(path, path + suffix)
        except OSError:
            pass

    async def on_block_found(self, session: ClientSession, job: Job, result):
        address = session.address or "?"
        worker = session.worker or ""
        block_hex = job.build_block_hex(result.legacy_coinbase, result.header)
        self._spool_block(job.height, result.block_hash_hex, block_hex, address, worker)
        try:
            reason = await asyncio.get_running_loop().run_in_executor(
                self._submit_executor, self.rpc.submitblock, block_hex)
        except RPCError as e:
            LOG.error("submitblock failed: %s", e)
            return
        outcome = classify_submit(reason)
        if outcome == "accepted":
            with self._stats_lock:
                self.blocks_found += 1
                self.last_block_found = int(time.time())
                if session.address:
                    self._blocks_by_address[session.address] = \
                        self._blocks_by_address.get(session.address, 0) + 1
            LOG.info("BLOCK ACCEPTED height=%d hash=%s address=%s worker=%s",
                     job.height, result.block_hash_hex, address, worker)
        elif outcome == "already_known":
            # Already in a chain (double-submit or retry): a win, not a rejection.
            LOG.info("Block %s already known (submitblock: %s)", result.block_hash_hex, reason)
        else:
            LOG.error("Block %s REJECTED by bitcoind: %s", result.block_hash_hex, reason)
        self._wake_template_loop()

    def _recover_stats(self):
        """Seed cumulative counters from a prior pool.status."""
        prior = poolstatus.read_pool_status(self.config.stats_directory)
        if not prior:
            return
        self._baseline_diff = prior["accepted"]
        self.best_diff = max(self.best_diff, prior["bestshare"])
        self.blocks_found = int(prior.get("blocks_found", 0))
        self.last_block_found = int(prior.get("last_block_found", 0))
        self._blocks_by_address = dict(prior.get("blocks_by_address", {}))
        LOG.info("Recovered stats from %s/pool/pool.status: accepted_diff=%.0f best=%.0f "
                 "blocks_found=%d", self.config.stats_directory, self._baseline_diff,
                 self.best_diff, self.blocks_found)

    def _write_stats(self):
        # Serialize so the off-loop status writer and the shutdown flush don't overlap (poolstatus
        # holds single-writer prune state and temp files).
        with self._stats_write_lock:
            try:
                # Prune before rendering: a row evicted this cycle must not be written back out,
                # or the next recovery would resurrect it.
                self.prune_user_stats()
                poolstatus.write_pool_status(self, self.config.stats_directory)
                poolstatus.write_user_files(
                    self, self.config.stats_directory,
                    retention_seconds=self.config.user_stats_retention_days * 86400.0)
            except Exception as e:
                LOG.warning("Failed to write stats to %s: %s", self.config.stats_directory, e)

    async def status_loop(self):
        while True:
            try:
                await asyncio.sleep(self.config.status_interval_seconds)
                # Off-loop: the write is file I/O and the retention sweep can stat/unlink the whole
                # users/ dir, which would stall the primary loop. Only caller, so poolstatus prune
                # state stays single-writer.
                await asyncio.to_thread(self._write_stats)
                # Probe the primary bitcoind for fail-back here: not latency-critical, so blocking
                # up to the RPC timeout is harmless (work/submit keep the current endpoint).
                expected_tip = self._last_prevhash
                if expected_tip:
                    await asyncio.to_thread(self.rpc.maybe_failback, expected_tip)
            except Exception:
                LOG.exception("status loop failed")
                await asyncio.sleep(self.config.status_interval_seconds)

    def _make_handler(self):
        async def handler(reader, writer):
            # Reserve an in-flight slot before the (up to ~2s) PROXY-header read so a burst can't
            # overshoot max_clients while connections sit unregistered. Released once the session
            # registers into self.clients, or in the finally if dropped first.
            if not self._admit():
                LOG.warning("Max clients (%d) reached; dropping connection", self.config.max_clients)
                writer.close()
                return
            inflight_held = True
            try:
                peer_override: str | None = None
                prebuffer = b""
                trusted = self.config.proxy_protocol_from
                if trusted:
                    peername = writer.get_extra_info("peername")
                    ip = peername[0] if peername else ""
                    if proxy_protocol.source_trusted(ip, trusted):
                        result = await proxy_protocol.read_proxy_header(reader)
                        if result.kind is proxy_protocol.ProxyKind.MALFORMED:
                            LOG.warning("PROXY protocol: malformed header from %s; dropping "
                                        "(first bytes: %s)", ip, result.detail)
                            writer.close()
                            return
                        if result.kind is proxy_protocol.ProxyKind.REAL_ADDRESS:
                            peer_override = result.address
                        else:  # DIRECT / UNKNOWN / LOCAL health check -> keep TCP peer
                            prebuffer = result.prebuffer
                # Hand the slot off to self.clients: session.run() registers synchronously below.
                self._release_inflight()
                inflight_held = False
                session = ClientSession(self, reader, writer, self.assign_extranonce1(),
                                        peer_override=peer_override, prebuffer=prebuffer)
                await session.run()
            finally:
                if inflight_held:
                    self._release_inflight()
        return handler

    async def _start_servers(self, *, reuse_port: bool, log: bool) -> list:
        servers = []
        for port in (self.config.bind_ports or [self.config.bind_port]):
            # `limit` caps a single buffered line, bounding per-connection memory.
            server = await asyncio.start_server(
                self._make_handler(), self.config.bind_host, port,
                limit=self.config.max_line_bytes, reuse_port=reuse_port)
            servers.append(server)
            if log:
                LOG.info("Stratum listening on %s:%d", self.config.bind_host, port)
        if log:
            trusted = self.config.proxy_protocol_from
            if not trusted:
                LOG.info("PROXY protocol: disabled (all connections direct)")
            else:
                LOG.info("PROXY protocol: trusting headers from %d source(s): %s",
                         len(trusted), ", ".join(trusted))
                for src in trusted:
                    if not proxy_protocol.valid_trusted_source(src):
                        LOG.warning("PROXY protocol: trusted source %r is not a valid IP or CIDR; "
                                    "it will never match (check for stray characters)", src)
        return servers

    def _register_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._loops_lock:
            self._loops.append(loop)

    def _worker_thread_main(self) -> None:
        """Body of an extra connection-serving loop thread (free-threaded builds only)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        servers: list = []
        try:
            servers = loop.run_until_complete(self._start_servers(reuse_port=True, log=False))
            self._register_loop(loop)
            for server in servers:
                loop.create_task(server.serve_forever())
            loop.run_forever()
        except Exception:
            LOG.exception("worker event loop crashed")
        finally:
            for server in servers:
                server.close()
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    async def start(self):
        self._recover_stats()
        self.recover_user_stats()
        self._primary_loop = asyncio.get_running_loop()
        self._register_loop(self._primary_loop)
        try:
            self.chain_info = await asyncio.to_thread(self.rpc.getblockchaininfo)
            self.generator_ready = True
            LOG.info("Connected to bitcoind: chain=%s blocks=%s",
                     self.chain_info.get("chain"), self.chain_info.get("blocks"))
        except RPCError as e:
            LOG.error("Bitcoind not reachable at startup (%s); will keep retrying", e)

        # Re-submit any block a previous run couldn't confirm (only with bitcoind up). Off-loop:
        # submitblock is a blocking RPC.
        if self.generator_ready:
            await asyncio.to_thread(self._resubmit_spooled_blocks)

        # Primary loop serves connections (SO_REUSEPORT shares the port with worker loops) and runs
        # the singleton background tasks.
        self._servers = await self._start_servers(reuse_port=self.num_loops > 1, log=True)
        self.connector_ready = True
        if self.num_loops > 1:
            for _ in range(self.num_loops - 1):
                thread = threading.Thread(target=self._worker_thread_main, daemon=True,
                                          name="stratum-loop")
                thread.start()
                self._worker_threads.append(thread)
            LOG.info("Free-threaded build: serving stratum across %d event loops", self.num_loops)
        else:
            LOG.info("Single event loop (GIL build or one core): validation runs inline")

        self._tasks = [
            asyncio.create_task(self.template_loop()),
            asyncio.create_task(self.vardiff_loop()),
            asyncio.create_task(self.zmq_loop()),
            asyncio.create_task(self.status_loop()),
        ] + [asyncio.create_task(server.serve_forever()) for server in self._servers]

    async def stop(self):
        # Cancel and await all tasks before the final flush so no off-loop _write_stats can be
        # scheduled afterward; the flush still takes _stats_write_lock to serialize against a
        # cancelled-but-not-yet-joined to_thread write.
        for task in self._tasks:
            task.cancel()
        for server in self._servers:
            server.close()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        self._write_stats()   # flush so a restart resumes from the latest stats
        with self._loops_lock:
            worker_loops = [loop for loop in self._loops if loop is not self._primary_loop]
        for loop in worker_loops:
            loop.call_soon_threadsafe(loop.stop)
        for thread in self._worker_threads:
            thread.join(timeout=2)
        self._worker_threads = []
        # Don't block shutdown on an in-flight submit to a hung node; the block hex was spooled
        # before submission, so it's recoverable.
        self._submit_executor.shutdown(wait=False)
        self._validate_executor.shutdown(wait=False)

    @property
    def ready(self) -> bool:
        return self.generator_ready and self.connector_ready and self.current_job is not None

    def health(self) -> bool:
        return self.ready

    def status(self) -> dict:
        return {
            "name": "erikslund-solo-pool",
            "version": __version__,
            "pid": os.getpid(),
            "starttime": int(self.started),
            "uptime": int(time.monotonic() - self._started_monotonic),
            "bitcoind_connected": self.generator_ready,
            "work_ready": self.current_job is not None,
            "accepting_connections": self.connector_ready,
            "ready": self.ready,
        }

    def pool_stats(self, clients: list[ClientSession] | None = None) -> dict:
        uptime = time.monotonic() - self._started_monotonic
        if clients is None:
            clients = self._snapshot_clients()
        addresses = {client.address for client in clients if client.address}
        job = self.current_job
        # Counters mutated by the share path under _stats_lock; read consistently.
        with self._stats_lock:
            total_share_diff = self.total_share_diff
            shares_accepted = self.shares_accepted
            shares_rejected = self.shares_rejected
            blocks_found = self.blocks_found
            last_block_found = self.last_block_found
            best_diff = self.best_diff
        hashrate = total_share_diff * 2 ** 32 / uptime if uptime > 0 else 0.0
        network_diff = DIFF1_TARGET / job.network_target if job else None
        best_share = max([best_diff] + [client.best_diff for client in clients])
        return {
            "runtime": int(uptime),
            "height": job.height if job else None,
            "network_diff": network_diff,
            "current_job": job.job_id if job else None,
            "workers": len(clients),
            "users": len(addresses),
            "blocks_found": blocks_found,
            "last_block_found": poolstatus._format_rfc9557(last_block_found) or None,
            "shares_accepted": shares_accepted,
            "shares_rejected": shares_rejected,
            "accepted_diff": self._baseline_diff + total_share_diff,
            "best_share": best_share,
            "best_share_percent": best_share / network_diff * 100 if network_diff else None,
            "hashrate_estimate": hashrate,
        }

    def stratifier_stats(self) -> dict:
        job = self.current_job
        with self._jobs_lock:
            jobs_created = self._job_counter
        return {
            "jobs_created": jobs_created,
            "recent_jobs_cached": len(self._recent),
            "current_job": job.job_id if job else None,
            "height": job.height if job else None,
            "txns_in_job": job.txn_count if job else None,
            "merkle_branch_len": len(job.merkle_branch) if job else None,
        }

    def connector_stats(self, clients: list[ClientSession] | None = None) -> dict:
        if clients is None:
            clients = self._snapshot_clients()
        return {
            "workers": len(clients),
            "subscribed": sum(1 for client in clients if client.subscribed),
            "authorized": sum(1 for client in clients if client.authorized),
        }

    def generator_stats(self) -> dict:
        now = time.monotonic()
        job = self.current_job
        active = self.rpc.active_index
        return {
            "bitcoind_reachable": self.generator_ready,
            "chain": self.chain_info.get("chain"),
            "tip_height": job.height - 1 if job else self.chain_info.get("blocks"),
            "last_template_age_sec": int(now - self._last_template_time) if self._last_template_time else None,
            "rpc_url": redact_url(self.config.rpc_url),
            "bitcoind_nodes": [
                {"address": redact_url(url), "active": i == active}
                for i, url in enumerate(self.rpc.endpoint_urls())
            ],
        }

    def client_stats(self, address: str) -> dict | None:
        address = address.split(".", 1)[0]
        sessions = [client for client in self._snapshot_clients() if client.address == address]
        if not sessions:
            return None
        return {
            "address": address,
            "workers": len(sessions),
            "shares_accepted": sum(client.shares_accepted for client in sessions),
            "shares_rejected": sum(client.shares_rejected for client in sessions),
            "best_diff": max((client.best_diff for client in sessions), default=0.0),
            "last_share_ts": max((client.last_share_ts for client in sessions), default=0),
            "sessions": [client.stats() for client in sessions],
        }

    def metrics(self) -> dict:
        clients = self._snapshot_clients()   # one snapshot, shared by pool+connector stats
        return {
            "uptime_seconds": int(time.monotonic() - self._started_monotonic),
            "ready": self.ready,
            "bitcoind_connected": self.generator_ready,
            "work_ready": self.current_job is not None,
            "accepting_connections": self.connector_ready,
            "pool": self.pool_stats(clients),
            "stratifier": self.stratifier_stats(),
            "connector": self.connector_stats(clients),
            "generator": self.generator_stats(),
        }
