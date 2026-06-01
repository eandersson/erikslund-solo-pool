"""Prometheus text exposition for ``/metrics``."""

import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version

from erikslund_pool.hashrate import HASHRATE_LABELS
from erikslund_pool.hashrate import HASHRATE_WINDOWS

try:
    _VERSION = version("erikslund_pool")
except PackageNotFoundError:  # source tree with no install metadata
    _VERSION = "0"


def _prom_label(value: str) -> str:
    """Escape a Prometheus label value: backslash, double-quote, newline (backslash first)."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _metric(name: str, metric_type: str, help_text: str, value, labels: str = "") -> str:
    """One metric with its HELP/TYPE preamble. Returns "" when value is None."""
    if value is None:
        return ""
    if isinstance(value, bool):
        value = int(value)
    return f"# HELP {name} {help_text}\n# TYPE {name} {metric_type}\n{name}{labels} {value}\n"


def render_prometheus(pool) -> str:
    data = pool.metrics()
    pool_section = data.get("pool") or {}
    lines: list[str] = [
        _metric("erikslundpool_up", "gauge",
                "1 if the pool process is serving the API", 1),
        _metric("erikslundpool_ready", "gauge",
                "1 when all required subsystems are ready", int(bool(data.get("ready")))),
        _metric("erikslundpool_uptime_seconds", "gauge",
                "Seconds since process start", data.get("uptime_seconds", 0)),
        "# HELP erikslundpool_subsystem_ready 1 when a subsystem is ready\n"
        "# TYPE erikslundpool_subsystem_ready gauge\n",
    ]
    for subsystem, key in (("bitcoind", "bitcoind_connected"),
                           ("work", "work_ready"),
                           ("connections", "accepting_connections")):
        lines.append(
            f'erikslundpool_subsystem_ready{{subsystem="{subsystem}"}} {int(bool(data.get(key)))}\n')

    lines.append(
        "# HELP erikslundpool_info Build and runtime info\n"
        "# TYPE erikslundpool_info gauge\n"
        f'erikslundpool_info{{version="{_VERSION}"}} 1\n'
    )

    nodes = (data.get("generator") or {}).get("bitcoind_nodes") or []
    if nodes:
        lines.append(
            "# HELP erikslundpool_bitcoind_node_active 1 for the bitcoind RPC endpoint currently "
            "in use, 0 for standby\n"
            "# TYPE erikslundpool_bitcoind_node_active gauge\n"
        )
        for node in nodes:  # node["address"] is already credential-redacted
            lines.append(f'erikslundpool_bitcoind_node_active{{url="{_prom_label(str(node.get("address", "")))}"}} '
                         f'{int(bool(node.get("active")))}\n')

    lines += [
        _metric("erikslundpool_network_difficulty", "gauge",
                "Bitcoin network difficulty", pool_section.get("network_diff")),
        _metric("erikslundpool_block_height", "gauge",
                "Block height currently being mined", pool_section.get("height")),
        _metric("erikslundpool_blocks_found_total", "counter",
                "Blocks solved by this pool", pool_section.get("blocks_found")),
        _metric("erikslundpool_shares_accepted_total", "counter",
                "Accepted shares", pool_section.get("shares_accepted")),
        _metric("erikslundpool_shares_rejected_total", "counter",
                "Rejected shares", pool_section.get("shares_rejected")),
        _metric("erikslundpool_best_share", "gauge",
                "Best share difficulty seen", pool_section.get("best_share")),
        _metric("erikslundpool_users", "gauge",
                "Distinct users (addresses)", pool_section.get("users")),
        _metric("erikslundpool_workers", "gauge",
                "Connected workers", pool_section.get("workers")),
    ]

    lines.append(
        "# HELP erikslundpool_hashrate_hashes_per_second Pool hashrate (H/s)\n"
        "# TYPE erikslundpool_hashrate_hashes_per_second gauge\n"
    )
    hashrate = pool_section.get("hashrate_estimate")
    if hashrate is not None:
        lines.append(
            f'erikslundpool_hashrate_hashes_per_second{{window="estimate"}} {hashrate}\n')
    windows = pool.hashrate_windows(time.monotonic())
    for window in HASHRATE_WINDOWS:
        lines.append(f'erikslundpool_hashrate_hashes_per_second{{window="{HASHRATE_LABELS[window]}"}} '
                     f'{windows[window] * 2 ** 32}\n')

    return "".join(lines)
