#!/usr/bin/env python3
"""
erikslund-miner - a Stratum v1 test miner for erikslund-pool.

USAGE
    python3 miner.py --url 127.0.0.1:3333 --user <BTC_ADDRESS> [--workers N]
    python3 miner.py --url 127.0.0.1:3333 --user <BTC_ADDRESS> --connections 4 --audit-work
    python3 miner.py --url 127.0.0.1:3333 --user <BTC_ADDRESS> --audit-work --duration 600
    python3 miner.py --selftest
"""

import argparse
import hashlib
import json
import logging
import multiprocessing as mp
import queue
import socket
import struct
import sys
import threading
import time

type WorkerJob = dict[str, object]  # flat job dict sent across the process boundary
type FoundShare = tuple[str, str, str, str, bool]  # (job_id, extranonce2_hex, ntime, nonce, is_block)

# Stratum "pool difficulty 1" target: hash <= DIFF1_TARGET / D satisfies difficulty D.
# == 0x00000000FFFF0000...0000 (pdiff convention).
DIFF1_TARGET = 0xFFFF << 208

_PACK_LE_UINT32 = struct.Struct("<I").pack  # bound once; avoids re-parsing per nonce

LOG = logging.getLogger(__name__)


def double_sha256(data: bytes) -> bytes:
    """Bitcoin's hash: SHA256(SHA256(data))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def build_coinbase(coinbase1_hex: str, extranonce1_hex: str,
                   extranonce2_hex: str, coinbase2_hex: str) -> bytes:
    """Reassemble the full coinbase transaction the pool split for us.

    The pool sends coinbase1 and coinbase2 with a gap in the middle that the
    miner fills with extranonce1 (assigned by the pool) + extranonce2 (chosen by
    the miner). Concatenating the four hex chunks and decoding yields the exact
    coinbase bytes the pool will rebuild on its side.
    """
    return bytes.fromhex(coinbase1_hex + extranonce1_hex + extranonce2_hex + coinbase2_hex)


def merkle_root_from_coinbase(coinbase: bytes, merkle_branches: list[str]) -> bytes:
    """Fold the coinbase hash up the merkle branch the pool provided.

    Returns 32 bytes in internal byte order, ready to splice into the header.
    """
    root = double_sha256(coinbase)
    for branch_hex in merkle_branches:
        root = double_sha256(root + bytes.fromhex(branch_hex))
    return root


def _prevhash_to_header_bytes(prevhash_hex: str) -> bytes:
    """Convert the notify prevhash into block-header byte order.

    Stratum sends prevhash as eight 32-bit words with the bytes of each word
    in display (big-endian) order. The header wants each word's bytes reversed
    (little-endian) with the word order preserved.
    """
    raw = bytes.fromhex(prevhash_hex)
    return b"".join(raw[i:i + 4][::-1] for i in range(0, 32, 4))


def build_header(version_hex: str, prevhash_hex: str, merkle_root: bytes,
                 ntime_hex: str, nbits_hex: str, nonce: int) -> bytes:
    """Assemble the canonical 80-byte Bitcoin block header.

    Field order and endianness match the serialized header that bitcoind (and
    therefore erikslund-pool, after its internal word-flip) hashes:
        version (4, LE) | prevhash (32, word-swapped) | merkle_root (32) |
        ntime (4, LE)   | nbits (4, LE)               | nonce (4, LE)
    """
    return b"".join((
        struct.pack("<I", int(version_hex, 16)),
        _prevhash_to_header_bytes(prevhash_hex),
        merkle_root,
        struct.pack("<I", int(ntime_hex, 16)),
        struct.pack("<I", int(nbits_hex, 16)),
        struct.pack("<I", nonce),
    ))


def target_from_difficulty(difficulty: float) -> int:
    """Highest hash value (as a LE integer) that still satisfies `difficulty`."""
    if difficulty <= 0:
        return DIFF1_TARGET
    return int(DIFF1_TARGET / difficulty)


def block_target_from_nbits(nbits_hex: str) -> int:
    """Decode the compact 'nbits' field into the full 256-bit block target.

    Format: the top byte is the exponent, the lower 23 bits are the coefficient.
    target = coefficient * 2^(8*(exponent-3))

    A hash (read as a little-endian integer) at or below this value satisfies the
    full network difficulty and constitutes a valid block.
    """
    nbits = int(nbits_hex, 16)
    exponent = nbits >> 24
    coefficient = nbits & 0x007fffff
    return coefficient << (8 * (exponent - 3))


def header_hash_int(header: bytes) -> int:
    """Double-SHA the header and read it as Bitcoin does: little-endian int."""
    return int.from_bytes(double_sha256(header), "little")


def selftest() -> bool:
    """Verify the hashing pipeline against the genesis block.

    If this passes, our double-SHA256 and every endianness conversion match
    Bitcoin exactly, so a share we accept locally is a share the pool accepts.
    """
    genesis = build_header(
        version_hex="00000001",
        # genesis prevhash is all zeroes; the word-swap is a no-op here, but we
        # still exercise the code path.
        prevhash_hex="00" * 32,
        # genesis merkle root, in header (little-endian) byte order:
        merkle_root=bytes.fromhex(
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a"),
        ntime_hex="495fab29",
        nbits_hex="1d00ffff",
        nonce=2083236893,
    )
    got = double_sha256(genesis)[::-1].hex()   # reversed == display order
    want = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    ok = got == want
    if ok:
        LOG.info("selftest OK: genesis block hash reproduced (%s)", want)
    else:
        LOG.error("selftest FAILED: got %s want %s", got, want)

    # Sanity-check the difficulty/target relationship too.
    assert target_from_difficulty(1) == DIFF1_TARGET
    assert target_from_difficulty(2) == DIFF1_TARGET // 2

    # WorkAuditor: the same job to two connections (distinct extranonce1) is fine; a
    # repeat of the same (extranonce1, work) -- within or across connections -- is tallied.
    auditor = WorkAuditor()
    base = ["1", "pp", "c1", "c2", ["aa"], "20000000", "1d00ffff", "6553f100", False]
    auditor.record_subscribe(0, "aaaa")
    auditor.record_subscribe(1, "bbbb")
    auditor.record_notify(0, "aaaa", base)
    auditor.record_notify(1, "bbbb", base)          # same job, different en1 -> OK
    moved = ["2", "pp", "c1", "c2", ["aa"], "20000000", "1d00ffff", "6553f101", False]  # ntime++
    auditor.record_notify(0, "aaaa", moved)         # genuinely fresh work for conn 0 -> OK
    assert auditor.duplicate_count == 0
    dup = ["3", "pp", "c1", "c2", ["aa"], "20000000", "1d00ffff", "6553f100", False]  # == job 1
    assert auditor.record_notify(0, "aaaa", dup) is not None  # conn 0 re-does job 1's work
    assert auditor.duplicate_count == 1
    again = ["4", "pp", "c1", "c2", ["aa"], "20000000", "1d00ffff", "6553f100", False]  # == job 1
    auditor.record_notify(0, "aaaa", again)         # counted again; the run does NOT stop
    assert auditor.duplicate_count == 2

    collision = WorkAuditor()                        # two connections, one extranonce1
    collision.record_subscribe(0, "cccc")
    assert collision.record_subscribe(1, "cccc") is not None
    assert len(collision.extranonce1_collisions) == 1
    return ok


class Job:
    """One unit of work from mining.notify, plus the session extranonce data."""

    __slots__ = ("job_id", "prevhash", "coinbase1", "coinbase2", "merkle_branches",
                 "version", "nbits", "ntime", "clean",
                 "extranonce1", "extranonce2_size", "target", "block_target", "difficulty")

    def __init__(self, notify_params: list, extranonce1: str,
                 extranonce2_size: int, difficulty: float):
        (self.job_id, self.prevhash, self.coinbase1, self.coinbase2,
         self.merkle_branches, self.version, self.nbits, self.ntime,
         self.clean) = notify_params
        self.extranonce1 = extranonce1
        self.extranonce2_size = extranonce2_size
        self.difficulty = difficulty
        self.target = target_from_difficulty(difficulty)
        self.block_target = block_target_from_nbits(self.nbits)

    def as_dict(self) -> WorkerJob:
        """Plain dict for handing across the process boundary to workers."""
        return {name: getattr(self, name) for name in self.__slots__}


class WorkAuditor:
    """Cross-connection work-duplication sanity check (enabled by --audit-work).

    The pool assigns each connection a unique extranonce1, so the *effective* work a
    connection mines is the pair (extranonce1, work_signature): the header inputs --
    prevhash, coinbase1/2, merkle branch, version, nbits, ntime -- combined with the
    per-connection coinbase space that extranonce1 selects. A correct pool never lets
    that pair repeat:
      * within one connection, a new job id over the same work_signature is the
        rebroadcast-of-identical-work bug (the miner restarts the same search); and
      * across connections, two workers sharing an extranonce1 -- or being handed the
        same effective work -- means they grind the identical space.
    The *same* job sent to *different* connections with *different* extranonce1 is
    normal work distribution and is NOT counted. Each repeat is tallied; with --duration
    the run keeps going and reports the total at the end (exit 3 if any), otherwise it
    stops at the first.

    Shared by every connection's reader thread, so all methods take a lock.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._extranonce1_owner: dict[str, int] = {}  # extranonce1 -> first connection id
        self._seen: dict[bytes, str] = {}             # (extranonce1, work) digest -> "connN/jobX"
        self.notifies_seen = 0
        self.duplicate_events: list[str] = []         # one entry per re-issued (extranonce1, work)
        self.extranonce1_collisions: list[str] = []   # connections handed a shared extranonce1
        self.failure: str | None = None               # first problem seen (kept for logging)

    @staticmethod
    def work_digest(notify_params: list) -> bytes:
        """A stable fingerprint of the *work*, ignoring the job id and clean flag."""
        (_job_id, prevhash, coinbase1, coinbase2, merkle_branches,
         version, nbits, ntime, _clean) = notify_params
        parts = [prevhash, coinbase1, coinbase2, version, nbits, ntime, *merkle_branches]
        # \x1f (unit separator) can't appear in the hex fields, so the join is
        # unambiguous and two distinct field splittings can never collide.
        joined = "\x1f".join(str(p) for p in parts).encode()
        return hashlib.sha256(joined).digest()

    def record_subscribe(self, conn_id: int, extranonce1: str) -> str | None:
        """Register a connection's extranonce1; count it if another connection shares it."""
        with self._lock:
            owner = self._extranonce1_owner.get(extranonce1)
            if owner is not None and owner != conn_id:
                message = (
                    f"EXTRANONCE1 COLLISION: connections {owner} and {conn_id} were both "
                    f"assigned extranonce1={extranonce1} -- they will mine the identical "
                    f"search space")
                self.extranonce1_collisions.append(message)
                self.failure = self.failure or message
                return message
            self._extranonce1_owner.setdefault(extranonce1, conn_id)
            return None

    def record_notify(self, conn_id: int, extranonce1: str, notify_params: list) -> str | None:
        """Record one job; if its effective work repeats, tally it and return the message."""
        job_id = str(notify_params[0])
        digest = hashlib.sha256(
            extranonce1.encode() + b"\x1f" + self.work_digest(notify_params)).digest()
        label = f"conn{conn_id}/job{job_id}"
        with self._lock:
            self.notifies_seen += 1
            prior = self._seen.get(digest)
            if prior is not None and prior != label:
                message = (
                    f"DUPLICATE WORK: {label} got the same (extranonce1, work) as earlier "
                    f"{prior} -- the identical search space is being mined twice")
                self.duplicate_events.append(message)
                self.failure = self.failure or message
                return message
            self._seen.setdefault(digest, label)
            return None

    @property
    def unique_work_units(self) -> int:
        return len(self._seen)

    @property
    def duplicate_count(self) -> int:
        return len(self.duplicate_events)


def _prepare_search(job: WorkerJob, extranonce2: int) -> tuple:
    """Precompute everything constant for a (job, extranonce2) pair.

    The returned tuple feeds the per-nonce inner loop:
    (first_sha_block, header_tail12, target, block_target, job_id, ntime_hex, extranonce2_hex).
    """
    extranonce2_size = job["extranonce2_size"]
    extranonce2_hex = "%0*x" % (extranonce2_size * 2,
                                extranonce2 & ((1 << (extranonce2_size * 8)) - 1))
    coinbase = build_coinbase(job["coinbase1"], job["extranonce1"],
                              extranonce2_hex, job["coinbase2"])
    root = merkle_root_from_coinbase(coinbase, job["merkle_branches"])
    header76 = build_header(job["version"], job["prevhash"], root,
                            job["ntime"], job["nbits"], 0)[:76]
    # Midstate trick: the first 64-byte SHA block never changes while we roll
    # the nonce, so hash it once and copy the context per nonce.
    first_block = hashlib.sha256(header76[:64])
    tail = header76[64:76]    # 12 bytes: merkle tail + ntime + nbits
    return (first_block, tail, job["target"], job["block_target"],
            job["job_id"], job["ntime"], extranonce2_hex)


def _search_worker(worker_id: int, num_workers: int, shared, found_queue,
                   hash_counter, stop_event):
    """Grind nonces for the current job and report shares that meet target.

    Each worker owns a disjoint slice of the extranonce2 space (it starts at
    its worker_id and steps by num_workers), so no two workers ever grind the
    same header - the same "don't waste hashrate on overlapping search" rule
    the pool itself cares about.
    """
    NONCE_BATCH = 2_000_000
    pack_nonce = _PACK_LE_UINT32
    sha256 = hashlib.sha256
    local_generation = -1
    prepared = None
    extranonce2 = worker_id
    nonce = 0

    while not stop_event.is_set():
        generation = shared["gen"]
        if generation < 0:
            time.sleep(0.05)
            continue
        if generation != local_generation:
            local_generation = generation
            job = shared["job"]
            if not job:
                time.sleep(0.05)
                continue
            extranonce2 = worker_id
            nonce = 0
            prepared = _prepare_search(job, extranonce2)

        first_block, tail, target, block_target, job_id, ntime_hex, extranonce2_hex = prepared
        copy_ctx = first_block.copy
        target_high16 = target >> 240
        end = nonce + NONCE_BATCH
        while nonce < end:
            ctx = copy_ctx()
            ctx.update(tail + pack_nonce(nonce))
            digest = sha256(ctx.digest()).digest()
            if (digest[31] << 8 | digest[30]) <= target_high16:
                hash_int = int.from_bytes(digest, "little")
                if hash_int <= target:
                    # Nonces are submitted big-endian (Stratum convention).
                    # is_block is True when the hash also meets the full network target.
                    is_block = hash_int <= block_target
                    found_queue.put((job_id, extranonce2_hex, ntime_hex, "%08x" % nonce, is_block))
            nonce += 1
        with hash_counter.get_lock():
            hash_counter.value += NONCE_BATCH

        if nonce > 0xFFFFFFFF:
            # Exhausted this extranonce2's nonce space; move to our next slice.
            extranonce2 += num_workers
            nonce = 0
            prepared = _prepare_search(shared["job"], extranonce2)


class StratumClient:
    """Minimal Stratum v1 client: connect, subscribe, authorize, run.

    Socket reads happen on a background thread that keeps the shared job state
    current; the caller's main loop submits shares and prints stats.
    """

    def __init__(self, host: str, port: int, username: str, password: str,
                 shared, num_workers: int, suggest_diff: float = 0.0,
                 auditor: WorkAuditor | None = None, conn_id: int = 0):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.shared = shared
        self.num_workers = num_workers
        self.suggest_diff = suggest_diff
        self.conn_id = conn_id
        # Shared across every connection (or None): checks for re-issued / overlapping work.
        self.work_auditor = auditor

        self.sock: socket.socket | None = None
        self._send_lock = threading.Lock()
        self._recv_buf = b""
        self._next_id = 1
        self._generation = 0

        self.extranonce1 = ""
        self.extranonce2_size = 0
        self.difficulty = 1.0
        self.accepted = 0
        self.rejected = 0
        self.subscribed = threading.Event()
        self.authorized = threading.Event()
        self._subscribe_id: int | None = None
        self._authorize_id: int | None = None
        self._suggest_diff_id: int | None = None  # acknowledged by pool but not a real share

    def connect(self) -> None:
        LOG.info("[conn %d] connecting to %s:%d", self.conn_id, self.host, self.port)
        self.sock = socket.create_connection((self.host, self.port), timeout=30)
        self.sock.settimeout(None)

    def _send(self, method: str, params: list) -> int:
        message_id = self._next_id
        self._next_id += 1
        line = json.dumps({"id": message_id, "method": method, "params": params}) + "\n"
        with self._send_lock:
            self.sock.sendall(line.encode())
        return message_id

    def subscribe(self) -> None:
        self._subscribe_id = self._send("mining.subscribe", ["erikslund-miner/1.0"])

    def authorize(self) -> None:
        self._authorize_id = self._send("mining.authorize",
                                        [self.username, self.password])

    def suggest_difficulty(self) -> None:
        """Ask the pool to start us at a specific difficulty instead of initial_difficulty.

        erikslund-pool clamps the suggestion to [minimum_difficulty, maximum_difficulty],
        so the effective floor is the pool's minimum_difficulty (default 1). Useful to
        skip the wait for vardiff to converge downward from a high initial_difficulty.
        A no-op if suggest_diff <= 0.
        """
        if self.suggest_diff > 0:
            self._suggest_diff_id = self._send("mining.suggest_difficulty", [self.suggest_diff])
            LOG.info("suggested difficulty %s (the pool clamps it to its allowed range)",
                     self.suggest_diff)

    def submit(self, job_id: str, extranonce2: str, ntime: str, nonce: str) -> None:
        self._send("mining.submit",
                   [self.username, job_id, extranonce2, ntime, nonce])

    def read_forever(self) -> None:
        """Background thread: parse newline-delimited JSON messages."""
        try:
            while True:
                chunk = self.sock.recv(8192)
                print(chunk)
                if not chunk:
                    LOG.warning("pool closed the connection")
                    return
                self._recv_buf += chunk
                while b"\n" in self._recv_buf:
                    line, self._recv_buf = self._recv_buf.split(b"\n", 1)
                    if line := line.strip():
                        self._dispatch(json.loads(line.decode()))
        except (OSError, ValueError) as exc:
            LOG.warning("stopped reading from the pool: %s", exc)

    def _dispatch(self, message: dict) -> None:
        if method := message.get("method"):
            self._handle_notification(method, message.get("params", []))
        else:
            self._handle_response(message)

    def _handle_response(self, message: dict) -> None:
        message_id = message.get("id")
        result = message.get("result")
        error = message.get("error")

        match message_id:
            case self._subscribe_id:
                self.extranonce1 = result[1]
                self.extranonce2_size = int(result[2])
                self.shared["extranonce1"] = self.extranonce1
                self.shared["extranonce2_size"] = self.extranonce2_size
                LOG.info("[conn %d] subscribed: extranonce1=%s extranonce2_size=%d",
                         self.conn_id, self.extranonce1, self.extranonce2_size)
                if self.work_auditor is not None:
                    if error := self.work_auditor.record_subscribe(self.conn_id, self.extranonce1):
                        LOG.error("work audit: %s", error)
                self.subscribed.set()
            case self._authorize_id:
                if result is True:
                    LOG.info("[conn %d] authorized as %s", self.conn_id, self.username)
                    self.authorized.set()
                else:
                    LOG.error("[conn %d] authorization rejected for %s: %s",
                              self.conn_id, self.username, error)
            case self._suggest_diff_id if self._suggest_diff_id is not None:
                LOG.debug("pool acknowledged mining.suggest_difficulty: %s", result)
            case _:
                if result is True:
                    self.accepted += 1
                    LOG.info("[conn %d] share accepted (%d accepted / %d rejected)",
                             self.conn_id, self.accepted, self.rejected)
                else:
                    self.rejected += 1
                    LOG.warning("[conn %d] share rejected: %s (%d accepted / %d rejected)",
                                self.conn_id, error, self.accepted, self.rejected)

    def _handle_notification(self, method: str, params: list) -> None:
        match method:
            case "mining.set_difficulty":
                self.difficulty = float(params[0])
                LOG.info("difficulty set to %s", self.difficulty)
                self._republish_job()      # re-target current job if we have one
            case "mining.notify":
                self._on_notify(params)
            case "client.reconnect":
                LOG.warning("pool requested reconnect")
            case "client.show_message":
                LOG.info("pool message: %s", params[0] if params else "")
            case _:
                LOG.debug("unhandled notification: %s", method)

    def _on_notify(self, params: list) -> None:
        if not self.subscribed.is_set():
            return
        if self.work_auditor is not None:
            if error := self.work_auditor.record_notify(self.conn_id, self.extranonce1, params):
                LOG.warning("work audit (dup #%d): %s", self.work_auditor.duplicate_count, error)
        job = Job(params, self.extranonce1, self.extranonce2_size, self.difficulty)
        LOG.info("[conn %d] new job %s (clean=%s, difficulty=%s)",
                 self.conn_id, job.job_id, job.clean, self.difficulty)
        self._publish(job)

    def _republish_job(self) -> None:
        """Difficulty changed: refresh the target on the live job, if any."""
        if self.shared.get("job"):
            job = dict(self.shared["job"])
            job["difficulty"] = self.difficulty
            job["target"] = target_from_difficulty(self.difficulty)
            self.shared["job"] = job
            self._generation += 1
            self.shared["gen"] = self._generation

    def _publish(self, job: Job) -> None:
        self.shared["job"] = job.as_dict()
        self._generation += 1
        self.shared["gen"] = self._generation


class _Connection:
    """One pool connection: a Stratum client (with its reader thread) plus its own
    CPU search workers. Every connection shares a single WorkAuditor."""

    def __init__(self, conn_id: int, host: str, port: int, args: argparse.Namespace,
                 manager, auditor: WorkAuditor | None):
        self.conn_id = conn_id
        self.args = args
        self.shared = manager.dict()
        self.shared["gen"] = -1
        self.shared["job"] = None
        self.shared["extranonce1"] = ""
        self.shared["extranonce2_size"] = 0
        self.found_queue: mp.Queue = mp.Queue()
        self.hash_counter = mp.Value("Q", 0)
        self.stop_event = mp.Event()
        self.workers: list[mp.Process] = []
        self.client = StratumClient(host, port, args.user, args.password, self.shared,
                                    args.workers, args.suggest_diff,
                                    auditor=auditor, conn_id=conn_id)
        self.reader = threading.Thread(target=self.client.read_forever, daemon=True)

    def start(self) -> bool:
        """Connect, subscribe, authorize, and spawn search workers. False on failure."""
        self.client.connect()
        self.reader.start()
        self.client.subscribe()
        if not self.client.subscribed.wait(timeout=30):
            LOG.error("[conn %d] no subscribe response from pool", self.conn_id)
            return False
        self.client.authorize()
        if not self.client.authorized.wait(timeout=30):
            LOG.error("[conn %d] not authorized; is --user a valid BTC address?", self.conn_id)
            return False
        self.client.suggest_difficulty()
        for worker_id in range(self.args.workers):
            process = mp.Process(target=_search_worker,
                                 args=(worker_id, self.args.workers, self.shared,
                                       self.found_queue, self.hash_counter, self.stop_event),
                                 daemon=True)
            process.start()
            self.workers.append(process)
        return True

    def drain_and_submit(self) -> None:
        """Submit any shares this connection's workers have found."""
        try:
            while True:
                job_id, extranonce2, ntime, nonce, is_block = self.found_queue.get_nowait()
                if is_block:
                    LOG.warning("*** BLOCK FOUND *** conn=%d job=%s nonce=%s -- submitting",
                                self.conn_id, job_id, nonce)
                self.client.submit(job_id, extranonce2, ntime, nonce)
        except queue.Empty:
            pass

    def hashes(self) -> int:
        with self.hash_counter.get_lock():
            return self.hash_counter.value

    def stop(self) -> None:
        self.stop_event.set()
        for process in self.workers:
            process.join(timeout=1)
            if process.is_alive():
                process.terminate()


def run_miner(args: argparse.Namespace) -> int:
    host, _, port_text = args.url.partition(":")
    port = int(port_text or 3333)
    num_connections = max(1, args.connections)
    duration = max(0.0, args.duration)

    auditor = WorkAuditor() if args.audit_work else None
    manager = mp.Manager()
    connections = [_Connection(i, host, port, args, manager, auditor)
                   for i in range(num_connections)]
    for connection in connections:
        if not connection.start():
            for started in connections:
                started.stop()
            return 1
    LOG.info("running %d connection(s) x %d search worker(s)%s%s",
             num_connections, args.workers,
             "; auditing work across them" if auditor else "",
             f"; for {duration:.0f}s" if duration else "")

    start = time.monotonic()
    last_report = start
    last_hashes = 0
    exit_code = 0
    try:
        while any(connection.reader.is_alive() for connection in connections):
            now = time.monotonic()
            if duration and now - start >= duration:
                LOG.info("reached --duration (%.0fs); stopping", duration)
                break
            # Without --duration, behave as a gate: stop at the first duplicate.
            if not duration and auditor is not None and auditor.failure:
                LOG.error("WORK SANITY CHECK FAILED -- stopping: %s", auditor.failure)
                exit_code = 3
                break
            for connection in connections:
                connection.drain_and_submit()

            if now - last_report >= 5.0:
                total = sum(connection.hashes() for connection in connections)
                rate = (total - last_hashes) / (now - last_report)
                last_hashes, last_report = total, now
                if not args.quiet:
                    accepted = sum(c.client.accepted for c in connections)
                    rejected = sum(c.client.rejected for c in connections)
                    dups = f" | dup-work {auditor.duplicate_count}" if auditor else ""
                    LOG.info("hashrate ~%.0f H/s | %d conns | accepted %d rejected %d%s",
                             rate, num_connections, accepted, rejected, dups)
            time.sleep(0.05)
    except KeyboardInterrupt:
        LOG.info("stopping")
    finally:
        for connection in connections:
            connection.stop()
        if auditor is not None:
            elapsed = time.monotonic() - start
            dups = auditor.duplicate_count
            collisions = len(auditor.extranonce1_collisions)
            if dups or collisions:
                LOG.error("work audit: FAILED -- %d duplicate-work event(s)%s in %.0fs: "
                          "%d jobs across %d connection(s), %d unique work units",
                          dups, f" + {collisions} extranonce1 collision(s)" if collisions else "",
                          elapsed, auditor.notifies_seen, num_connections,
                          auditor.unique_work_units)
                exit_code = 3
            else:
                LOG.info("work audit: OK -- 0 duplicate-work events in %.0fs: %d jobs across "
                         "%d connection(s), %d unique work units, no overlap",
                         elapsed, auditor.notifies_seen, num_connections,
                         auditor.unique_work_units)
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Stratum v1 test miner for erikslund-pool")
    parser.add_argument("--url", default="127.0.0.1:3333",
                        help="pool host:port (default 127.0.0.1:3333)")
    parser.add_argument("--user", default="",
                        help="username; a valid BTC address for btcsolo pools")
    parser.add_argument("--pass", dest="password", default="x", help="password")
    parser.add_argument("--connections", type=int, default=1,
                        help="number of simultaneous pool connections; each gets its own "
                             "extranonce1, and --audit-work then checks for overlapping work "
                             "across all of them")
    parser.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 1) // 4,
                        help="CPU search processes per connection")
    parser.add_argument("--suggest-diff", type=float, default=0.001,
                        help="difficulty to request via mining.suggest_difficulty "
                             "(the pool clamps it to its minimum difficulty; 0 to not suggest)")
    parser.add_argument("--quiet", action="store_true", help="suppress hashrate lines")
    parser.add_argument("--duration", type=float, default=0.0,
                        help="run for this many seconds, then stop and print the audit summary "
                             "(0 = until the pool disconnects or Ctrl-C). With --audit-work the "
                             "run keeps going and tallies every duplicate; without --duration it "
                             "stops at the first duplicate instead.")
    parser.add_argument("--audit-work", action="store_true",
                        help="track (extranonce1, work) across all connections and count how often "
                             "the pool re-issues identical work (the duplicate-work bug) or hands "
                             "two connections the same search space. With --duration, runs the full "
                             "time and reports the tally; otherwise stops at the first duplicate. "
                             "Exit code 3 if any duplicates/collisions were seen.")
    parser.add_argument("--selftest", action="store_true",
                        help="verify hashing against the genesis block and exit")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if args.selftest:
        return 0 if selftest() else 1

    if not selftest():
        LOG.error("refusing to mine: hashing self-test failed")
        return 1
    if not args.user:
        LOG.error("--user is required (a valid BTC address for btcsolo pools)")
        return 1
    return run_miner(args)


if __name__ == "__main__":
    sys.exit(main())
