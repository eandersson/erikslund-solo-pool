"""On-disk pool/user stats serialized as YAML.

Two file kinds under the stats directory: ``pool/pool.status`` (pool-wide
``{pool_stat, hashrate, shares}``, hashrates as human strings like "43.4M") and
``users/<address>`` (one mapping per payout address).
"""

import itertools
import logging
import math
import os
import time
from datetime import datetime
from datetime import timezone

import yaml

from erikslund_pool.constants import _ADDRESS_CHARS
from erikslund_pool.constants import _FLOAT_RE
from erikslund_pool.constants import _SUFFIX_MULTIPLIERS
from erikslund_pool.constants import DIFF1_TARGET
from erikslund_pool.constants import NONCES
from erikslund_pool.hashrate import HASHRATE_LABELS
from erikslund_pool.hashrate import HASHRATE_WINDOWS
from erikslund_pool.hashrate import SPS_LABELS
from erikslund_pool.hashrate import SPS_WINDOWS

LOG = logging.getLogger(__name__)

# Process-unique suffix for atomic-write temp files so concurrent writers never collide.
_TMP_COUNTER = itertools.count()


def suffix_string(value: float, significant_digits: int = 0) -> str:
    """Format a magnitude with a K/M/G/T/P/E suffix; round-trips through parse_suffix."""
    kilo, mega, giga = 1e3, 1e6, 1e9
    tera, peta, exa = 1e12, 1e15, 1e18
    suffix = ""
    decimal = True

    if value >= exa:
        value /= peta
        display_value = value / kilo
        suffix = "E"
    elif value >= peta:
        value /= tera
        display_value = value / kilo
        suffix = "P"
    elif value >= tera:
        value /= giga
        display_value = value / kilo
        suffix = "T"
    elif value >= giga:
        value /= mega
        display_value = value / kilo
        suffix = "G"
    elif value >= mega:
        value /= kilo
        display_value = value / kilo
        suffix = "M"
    elif value >= kilo:
        display_value = value / kilo
        suffix = "K"
    else:
        display_value = value
        decimal = False

    if not significant_digits:
        if decimal:
            return "%.3g%s" % (display_value, suffix)
        return "%d%s" % (int(display_value), suffix)
    decimal_digits = significant_digits - 1 - (
        math.floor(math.log10(display_value)) if display_value > 0.0 else 0)
    return "%*.*f%s" % (significant_digits + 1, decimal_digits, display_value, suffix)


def parse_suffix(text) -> float:
    """Inverse of :func:`suffix_string` ("43.4M" -> 43400000.0); a malformed field -> 0.0."""
    if isinstance(text, (int, float)):
        return float(text)
    if not isinstance(text, str) or not text:
        return 0.0
    match = _FLOAT_RE.match(text.strip())
    if not match:
        return 0.0
    number = float(match.group())
    suffix = text.strip()[match.end():match.end() + 1].upper()
    return number * _SUFFIX_MULTIPLIERS.get(suffix, 1.0)


def _format_rfc9557(epoch: float) -> str:
    """Render an epoch as an RFC 9557 UTC timestamp ("2026-06-04T11:31:24Z[UTC]"); "" for epoch <= 0."""
    if not epoch or epoch <= 0:
        return ""
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "Z[UTC]"


def _parse_rfc9557(value) -> int:
    """Parse an RFC 9557 / RFC 3339 UTC timestamp to an epoch int (0 if unparseable); bare = UTC."""
    if not isinstance(value, str) or not value:
        return 0
    text = value.split("[", 1)[0]  # drop the [time-zone] annotation
    try:
        parsed = datetime.fromisoformat(text)  # handles a trailing 'Z' on 3.11+
    except ValueError:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _hashrate_fields(windows: dict[int, float]) -> dict[str, str]:
    """Map ``{60: diff_per_sec, ...}`` to ``{"hashrate1m": "43.4M", ...}`` (H/s)."""
    return {f"hashrate{HASHRATE_LABELS[window]}": suffix_string(windows[window] * NONCES)
            for window in HASHRATE_WINDOWS}


def build_pool_status(pool) -> dict:
    """Build the ``{pool_stat, hashrate, shares}`` object written to pool.status."""
    now_wall = time.time()       # lastupdate timestamp
    now = time.monotonic()       # uptime + decaying-window snapshots
    uptime = max(now - pool._started_monotonic, 1e-9)
    clients = pool._snapshot_clients()
    addresses = {client.address for client in clients if client.address}

    # Fold live sessions into the best share under the stats lock (RMW races note_accepted_share).
    with pool._stats_lock:
        best_share = pool.best_diff
        for client in clients:
            if client.best_diff > best_share:
                best_share = client.best_diff
        pool.best_diff = best_share
        blocks_found = pool.blocks_found
        last_block_found = pool.last_block_found
        blocks_by_address = dict(pool._blocks_by_address)

    accepted_diff = pool._baseline_diff + pool.total_share_diff
    network_difficulty = None
    # Worker thread, not the event loop, so read current_job under the jobs lock.
    current_job = pool._current_job_locked()
    if current_job is not None and current_job.network_target:
        network_difficulty = DIFF1_TARGET / current_job.network_target
    # round half-away-from-zero (math.floor(x+0.5), values non-negative), not banker's round().
    best_share_percent = (math.floor(best_share / network_difficulty * 1e8 + 0.5) / 1e6
                          if network_difficulty else 0.0)
    shares_per_second = pool.sps_windows(now)
    return {
        "pool_stat": {
            "runtime": int(uptime),
            "lastupdate": _format_rfc9557(now_wall),
            "users": len(addresses),
            "workers": len(clients),
            "blocks_found": blocks_found,
            "last_block_found": _format_rfc9557(last_block_found),
        },
        # Per-address tallies persist here (recovered on restart) so a finder's per-user
        # `blocks` survives.
        "blocks_by_address": blocks_by_address,
        "hashrate": _hashrate_fields(pool.hashrate_windows(now)),
        "shares": {
            "best_share_percent": best_share_percent,
            "accepted": int(accepted_diff),
            "rejected": int(pool.shares_rejected),
            "bestshare": int(best_share),
            **{f"shares_per_second_{SPS_LABELS[window]}":
               math.floor(shares_per_second[window] * 1e5 + 0.5) / 1e5
               for window in SPS_WINDOWS},
        },
    }


def _atomic_write(path: str, text: str) -> bool:
    """Write ``text`` to ``path`` atomically (temp + rename). Returns False without touching the file
    when its contents already equal ``text`` (avoids mtime-bumping unchanged idle rows every tick)."""
    try:
        with open(path, "r", encoding="ascii") as existing:
            if existing.read() == text:
                return False
    except OSError:
        pass  # absent / unreadable: fall through and write
    os.makedirs(os.path.dirname(path), exist_ok=True)
    temp_path = f"{path}.tmp.{os.getpid()}.{next(_TMP_COUNTER)}"
    with open(temp_path, "w", encoding="ascii") as f:
        f.write(text)
    os.replace(temp_path, path)
    return True


def write_pool_status(pool, stats_dir: str) -> None:
    """Write ``<stats_dir>/pool/pool.status`` as a block-style YAML mapping."""
    status = build_pool_status(pool)
    text = yaml.safe_dump(status, sort_keys=False, default_flow_style=False)
    _atomic_write(os.path.join(stats_dir, "pool", "pool.status"), text)


def read_pool_status(stats_dir: str) -> dict | None:
    """Decode a ``pool.status`` (hashrates to H/s floats); ``None`` if absent/bad."""
    path = os.path.join(stats_dir, "pool", "pool.status")
    try:
        with open(path, "r", encoding="ascii") as f:
            value = yaml.safe_load(f)
        if not isinstance(value, dict):
            return None
        hashrate = value.get("hashrate") or {}
        shares = value.get("shares") or {}
        pool_stat = value.get("pool_stat") or {}
        last_update = pool_stat.get("lastupdate", 0)
        blocks_raw = value.get("blocks_by_address")
        blocks_by_address = ({str(k): int(v) for k, v in blocks_raw.items()
                              if isinstance(v, (int, float))}
                             if isinstance(blocks_raw, dict) else {})
        return {
            # lastupdate is written as a date string; only numeric values decode.
            "lastupdate": int(last_update) if isinstance(last_update, (int, float)) else 0,
            "hashrate": {window: parse_suffix(text) for window, text in hashrate.items()
                         if isinstance(text, str)},
            "accepted": float(shares.get("accepted", 0) or 0),
            "rejected": float(shares.get("rejected", 0) or 0),
            "bestshare": float(shares.get("bestshare", 0) or 0),
            "sps1m": float(shares.get("shares_per_second_1m", 0) or 0),
            "blocks_found": int(pool_stat.get("blocks_found", 0) or 0),
            "last_block_found": _parse_rfc9557(pool_stat.get("last_block_found")),
            "blocks_by_address": blocks_by_address,
        }
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError):
        return None  # corrupt file recovers as "no prior stats" rather than crashing startup


def build_user_stats(address: str, worker_rows: list, connection_count: int = 0,
                     blocks: int = 0) -> dict:
    """Build the per-address ``users/<address>`` object from registry rows. One row per worker name,
    rendered in name order; an empty name renders under the bare address. Rows persist past
    disconnect, so ``connection_count`` (live connections) feeds the ``workers`` field separately."""
    wall_now = time.time()  # for last-share age (last_share_ts is wall)
    user_windows = {window: 0.0 for window in HASHRATE_WINDOWS}
    total_shares = total_rejected = 0
    best_share = 0.0
    last_share = 0

    workers = []
    for row in sorted(worker_rows, key=lambda r: r["worker"]):
        windows = row["hashrate"]
        for window in HASHRATE_WINDOWS:
            user_windows[window] += windows[window]
        total_shares += int(row["shares_accepted"])
        total_rejected += int(row["shares_rejected"])
        best_share = max(best_share, row["best_diff"])
        last_share = max(last_share, int(row["last_share_ts"]))
        ts = int(row["last_share_ts"])
        worker = {"workername": row["worker"] or address}
        worker.update(_hashrate_fields(windows))
        worker.update({
            "shares_accepted": int(row["shares_accepted"]),
            "shares_rejected": int(row["shares_rejected"]),
            "bestshare": row["best_diff"],
            "lastshare": _format_rfc9557(ts),
            "last_share_age": max(0, int(wall_now - ts)) if ts else 0,
        })
        workers.append(worker)

    stats = _hashrate_fields(user_windows)
    stats.update({
        "lastshare": _format_rfc9557(last_share),
        "last_share_age": max(0, int(wall_now - last_share)) if last_share else 0,
        "workers": connection_count,  # live connections (rows persist past disconnect)
        "shares_accepted": total_shares,
        "shares_rejected": total_rejected,
        "bestshare": best_share,
        "blocks": blocks,
        "worker": workers,
    })
    return stats


def _is_safe_address(address) -> bool:
    """Address is used as a filename; require a single safe path component (charset, never '.'/'..')
    to prevent writing outside users/."""
    return (isinstance(address, str) and 0 < len(address) <= 100 and address not in (".", "..")
            and all(char in _ADDRESS_CHARS for char in address))


# users/ file-creation cap: bounds disk/inode growth an address-cycling attacker can force.
MAX_USER_FILES = 100_000
# Retention sweeps run at most this often (the retention window is days-scale).
USER_PRUNE_SWEEP_SECONDS = 3600.0
# Known addresses + last-prune time, keyed by stats dir; seeded once from disk. Single writer
# (the pool's stats loop).
_known_user_files: dict[str, set[str]] = {}
_last_user_prune: dict[str, float] = {}
_last_cap_warning = float("-inf")


def write_user_files(pool, stats_dir: str, *, retention_seconds: float = 0.0,
                     prune_sweep_seconds: float = USER_PRUNE_SWEEP_SECONDS) -> None:
    """Write one ``<stats_dir>/users/<address>`` per address from the persistent registry rows (not
    live sessions), so a disconnected worker keeps its decaying row until retention evicts it. With
    ``retention_seconds`` > 0, prune stale files whose address no longer has a row."""
    global _last_cap_warning
    now = time.monotonic()
    now_wall = time.time()
    by_address: dict[str, list] = {}
    for row in pool._snapshot_user_stats(now, now_wall):
        if _is_safe_address(row["address"]):  # defense-in-depth on the filename
            by_address.setdefault(row["address"], []).append(row)
    connections: dict[str, int] = {}
    for client in pool._snapshot_clients():
        if client.authorized and _is_safe_address(client.address):
            connections[client.address] = connections.get(client.address, 0) + 1
    with pool._stats_lock:
        blocks_by_address = dict(pool._blocks_by_address)

    users_dir = os.path.join(stats_dir, "users")
    known = _known_user_files.get(stats_dir)
    if known is None:
        try:
            # Exclude in-flight temp files from the cap seed: partial writes, not real addresses.
            known = {name for name in os.listdir(users_dir) if ".tmp." not in name}
        except FileNotFoundError:
            known = set()  # dir not created yet
        except OSError as e:
            # A read error must not cache an empty registry forever (resets cap accounting); skip
            # this cycle and retry next tick.
            LOG.warning("Cannot read %s to seed the user-file registry (%s); retrying next cycle",
                        users_dir, e)
            return
        _known_user_files[stats_dir] = known

    for address, worker_rows in by_address.items():
        # Skip an address with no share activity (authorize-then-disconnect, or an address-cycling
        # probe): writing a file is pure amplification. A rig submitting -- even all-rejected --
        # still surfaces on its first share.
        if sum(int(row["shares_accepted"]) + int(row["shares_rejected"])
               for row in worker_rows) == 0:
            continue
        if address not in known:
            # Stop creating files past the cap; existing addresses keep updating.
            if len(known) >= MAX_USER_FILES:
                if now - _last_cap_warning > 600.0:  # rate-limited: once per 10 min
                    _last_cap_warning = now
                    LOG.warning("users/ stats directory is at its cap (%d); not creating stats "
                                "files for new addresses (existing ones keep updating)",
                                MAX_USER_FILES)
                continue
            known.add(address)
        stats = build_user_stats(address, worker_rows, connections.get(address, 0),
                                 blocks_by_address.get(address, 0))
        text = yaml.safe_dump(stats, sort_keys=False, default_flow_style=False)
        _atomic_write(os.path.join(users_dir, address), text)

    if retention_seconds > 0 and now - _last_user_prune.get(stats_dir, float("-inf")) >= prune_sweep_seconds:
        _last_user_prune[stats_dir] = now
        cutoff = time.time() - retention_seconds
        pruned = 0
        survivors: set[str] = set()
        scan_ok = True
        try:
            entries = list(os.scandir(users_dir))
        except OSError:
            entries, scan_ok = [], False  # unreadable dir: keep the registry as-is
        for entry in entries:
            if ".tmp." in entry.name:
                continue  # in-flight temp write, not a real address
            try:
                if entry.name not in by_address and entry.stat().st_mtime < cutoff:
                    os.unlink(entry.path)
                    pruned += 1
                    continue
            except OSError:
                pass  # raced/unstatable: treat as surviving; the next sweep retries
            survivors.add(entry.name)
        if scan_ok:
            _known_user_files[stats_dir] = survivors
        if pruned:
            LOG.info("Pruned %d stale users/ stats file(s) inactive beyond the retention window",
                     pruned)


def read_all_worker_stats(stats_dir: str) -> list[dict]:
    """Parse every ``users/<address>`` file into worker rows for restart recovery (a malformed file
    is skipped). file_age_seconds is the mtime age, used for decay backdating."""
    users_dir = os.path.join(stats_dir, "users")
    out: list[dict] = []
    try:
        entries = list(os.scandir(users_dir))
    except OSError:
        return out  # no users/ dir yet
    now = time.time()
    for entry in entries:
        address = entry.name
        # Skip an in-flight temp file (partial, not-yet-renamed write).
        if ".tmp." in address:
            continue
        try:
            file_age = max(0.0, now - entry.stat().st_mtime)
        except OSError:
            file_age = 0.0
        try:
            with open(entry.path, "r", encoding="ascii") as f:
                value = yaml.safe_load(f)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        if not isinstance(value, dict) or not isinstance(value.get("worker"), list):
            continue
        for row in value["worker"]:
            if not isinstance(row, dict):
                continue
            try:
                name = str(row.get("workername") or "")
                if name == address:  # the bucket renders as the address -> map back to ""
                    name = ""
                out.append({
                    "address": address,
                    "worker": name,
                    "shares_accepted": int(row.get("shares_accepted", 0) or 0),
                    "shares_rejected": int(row.get("shares_rejected", 0) or 0),
                    "best_diff": float(row.get("bestshare", 0) or 0),
                    "last_share_ts": _parse_rfc9557(row.get("lastshare")),
                    # Files store H/s strings; the registry holds diff/s.
                    "hashrate": {window: parse_suffix(row.get(f"hashrate{HASHRATE_LABELS[window]}",
                                                              "")) / NONCES
                                 for window in HASHRATE_WINDOWS},
                    "file_age_seconds": file_age,
                })
            except (ValueError, TypeError):
                continue  # one malformed row is skipped
    return out


def read_user_stats(stats_dir: str, address: str) -> dict | None:
    """Decode a ``users/<address>`` file (hashrate to H/s); ``None`` if absent/bad."""
    path = os.path.join(stats_dir, "users", address)
    try:
        with open(path, "r", encoding="ascii") as f:
            value = yaml.safe_load(f)
    except (OSError, ValueError, yaml.YAMLError):
        return None
    if not isinstance(value, dict):
        return None
    return {
        "hashrate1m": parse_suffix(value.get("hashrate1m", "")),
        "shares_accepted": int(value.get("shares_accepted", 0) or 0),
        "bestshare": float(value.get("bestshare", 0) or 0),
        "bestever": float(value.get("bestever", 0) or 0),
        "workers": int(value.get("workers", 0) or 0),
        "lastshare": str(value.get("lastshare", "") or ""),  # RFC 9557 UTC string ("" = never)
    }
