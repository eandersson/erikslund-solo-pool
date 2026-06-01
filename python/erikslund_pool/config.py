"""Pool configuration: a `Settings` dataclass and the `SETTINGS` singleton.

Config files follow conf/pool.schema.json and load as YAML (a superset of JSON).
"""

import dataclasses
import logging
import os
from dataclasses import dataclass

import yaml

from erikslund_pool.exceptions import ConfigError

LOG = logging.getLogger(__name__)

# Accepted top-level keys; `$schema` is accepted and ignored.
_SCHEMA_KEYS = frozenset({
    "$schema", "bitcoin_nodes", "stratum_listen", "api_listen",
    "coinbase_signature", "coinbase_version",
    "initial_difficulty", "minimum_difficulty", "maximum_difficulty",
    "variable_difficulty", "vardiff_target_shares_per_minute", "vardiff_retarget_seconds",
    "extranonce1_size", "extranonce2_size",
    "zmq_block_endpoint", "fast_block_notify",
    "block_poll_milliseconds", "work_rebroadcast_seconds",
    "version_rolling_mask", "donation_percent", "donation_address",
    "max_clients", "max_workers_per_address",
    "drop_idle_seconds", "auth_timeout_seconds", "max_protocol_errors",
    "max_line_bytes", "stats_directory", "status_interval_seconds",
    "user_stats_retention_days", "worker_threads",
    "proxy_protocol_from",
})

# Clamp for auto worker count: cpu_count reports host cores, not a container's cgroup quota.
MAX_AUTO_WORKERS = 16


def _split_host_port(host_port: str) -> tuple[str, int]:
    host, colon, port_str = host_port.rpartition(":")
    if not colon:
        raise ConfigError(
            f"listen address has no port (expected host:port or :port): {host_port}")
    if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
        raise ConfigError(f"invalid port in listen address: {host_port}")
    return host, int(port_str)


def resolve_worker_count(configured: int) -> int:
    """Resolve worker_threads: explicit value as-is; 0 = one per usable CPU, clamped."""
    if configured > 0:
        return configured
    cores = os.process_cpu_count() if hasattr(os, "process_cpu_count") else None
    cores = cores or os.cpu_count() or 1
    return min(cores, MAX_AUTO_WORKERS)


@dataclass
class Settings:
    rpc_url: str = "http://127.0.0.1:18443"
    rpc_user: str = "erikslund"
    rpc_password: str = "erikslundpass"
    # Extra bitcoind endpoints tried in order after the primary; each a
    # {"url", "user", "password"} dict (user/password optional).
    rpc_failover: list = dataclasses.field(default_factory=list)

    bind_host: str = "0.0.0.0"
    bind_port: int = 3333
    # Extra stratum ports to bind (all behave identically).
    bind_ports: list = dataclasses.field(default_factory=list)
    api_host: str = "127.0.0.1"
    api_port: int = 7777

    initial_difficulty: float = 1.0
    minimum_difficulty: float = 0.001
    maximum_difficulty: float = 0.0  # vardiff upper clamp (0 = no maximum)
    variable_difficulty: bool = True
    vardiff_target_shares_per_minute: float = 12.0
    vardiff_retarget_seconds: int = 60
    version_rolling_mask: int = 0x1FFFE000  # BIP320 bits a client may roll (negotiation cap)

    extranonce1_size: int = 4
    extranonce2_size: int = 8

    coinbase_signature: str = "/erikslund-pool/"
    coinbase_version: int = 1
    # Optional donation output paying this percent of the reward (0 = disabled).
    donation_percent: float = 0.0
    donation_address: str = ""

    poll_interval: float = 1.0
    work_rebroadcast_seconds: float = 30.0
    zmq_block_endpoint: str | None = None
    # On a ZMQ block notification, broadcast empty next-block work before the
    # slower getblocktemplate (minimizes mining on a stale block).
    fast_block_notify: bool = True

    stats_directory: str = "stats"
    status_interval_seconds: float = 30.0   # how often to rewrite pool.status / users/
    # Prune a users/<address> file after the address has been disconnected this many days.
    # Connected miners are never pruned. 0 = keep forever.
    user_stats_retention_days: int = 90

    max_clients: int = 1024          # reject connections past this
    # Max worker rows itemized in one address's stats file; beyond this, per-worker stats fold
    # into one bucket under the bare address. Connections still mine and count toward address
    # totals -- not a connection cap. 0 = unlimited.
    max_workers_per_address: int = 256
    max_line_bytes: int = 16384      # cap one Stratum line (anti-OOM)
    drop_idle_seconds: int = 3600    # drop a client idle this long (0 = never)
    auth_timeout_seconds: int = 30   # drop a client that never authorizes (0 = never)
    max_protocol_errors: int = 100   # drop after this many bad requests since the last accepted share (0 = never)

    # Connection-serving event loops on a free-threaded build (0 = auto, clamped).
    # Ignored on a GIL build, which uses one loop.
    worker_threads: int = 0

    # Trusted upstreams (exact IP or CIDR) allowed to send a PROXY-protocol v1/v2 header.
    # Empty = disabled (all connections direct).
    proxy_protocol_from: list = dataclasses.field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Settings":
        """Parse a pool config object (conf/pool.schema.json) into Settings."""
        if not isinstance(data, dict):
            raise ConfigError("config must be a mapping")
        unknown = set(data) - _SCHEMA_KEYS
        if unknown:
            raise ConfigError(f"unknown config keys: {sorted(unknown)}")
        try:
            settings = cls._parse(data)
            settings._validate()
        except (ValueError, KeyError, TypeError, AttributeError, IndexError) as e:
            # Surface a malformed value as ConfigError, not a traceback.
            raise ConfigError(f"invalid config value: {e}") from e
        return settings

    def _validate(self) -> None:
        """Reject values _parse accepts but that break at runtime (e.g. zero intervals busy-loop,
        zero difficulty divides by zero)."""
        if self.initial_difficulty <= 0:
            raise ConfigError("initial_difficulty must be > 0")
        if self.minimum_difficulty <= 0:
            raise ConfigError("minimum_difficulty must be > 0")
        if self.maximum_difficulty < 0:
            raise ConfigError("maximum_difficulty must be >= 0 (0 = no maximum)")
        if self.vardiff_target_shares_per_minute <= 0:
            raise ConfigError("vardiff_target_shares_per_minute must be > 0")
        if self.vardiff_retarget_seconds < 1:
            raise ConfigError("vardiff_retarget_seconds must be >= 1")
        if self.work_rebroadcast_seconds < 1:
            raise ConfigError("work_rebroadcast_seconds must be >= 1")
        if self.poll_interval <= 0:
            raise ConfigError("block_poll_milliseconds must be >= 1")
        # Min 4: extranonce1 is a wrapping counter; a 2-byte space (65k) can lap under connection
        # churn and hand two concurrent miners identical search space.
        if not 4 <= self.extranonce1_size <= 8:
            raise ConfigError("extranonce1_size must be in [4, 8]")
        if not 2 <= self.extranonce2_size <= 8:
            raise ConfigError("extranonce2_size must be in [2, 8]")
        # coinbase_signature must leave room in the 100-byte scriptSig for the height push (worst
        # case 10) + extranonces, else every template raises WorkError. Byte length (tag is bytes).
        scriptsig_budget = (10 + self.extranonce1_size + self.extranonce2_size
                            + len(self.coinbase_signature.encode()))
        if scriptsig_budget > 100:
            raise ConfigError("coinbase_signature too long: it must leave room in the 100-byte "
                              "coinbase scriptSig for the height push and extranonces")
        if not 0 <= self.donation_percent <= 100:
            raise ConfigError("donation_percent must be in [0, 100]")
        if self.status_interval_seconds < 0:
            raise ConfigError("status_interval_seconds must be >= 0")
        # Upper bound ~100 years.
        if not 0 <= self.user_stats_retention_days <= 36500:
            raise ConfigError(
                "user_stats_retention_days must be in [0, 36500] (0 keeps files forever)")
        if self.max_clients < 0:
            raise ConfigError("max_clients must be >= 0")
        if self.max_workers_per_address < 0:
            raise ConfigError("max_workers_per_address must be >= 0 (0 = unlimited)")
        if self.drop_idle_seconds < 0:
            raise ConfigError("drop_idle_seconds must be >= 0")
        if self.auth_timeout_seconds < 0:
            raise ConfigError("auth_timeout_seconds must be >= 0")
        if self.max_protocol_errors < 0:
            raise ConfigError("max_protocol_errors must be >= 0")
        if self.version_rolling_mask & ~0x1FFFE000:
            LOG.warning("version_rolling_mask %08x has bits outside the BIP320 range; clamping to "
                        "1fffe000", self.version_rolling_mask)
            self.version_rolling_mask &= 0x1FFFE000

    @classmethod
    def _parse(cls, data: dict) -> "Settings":
        fields: dict = {}
        nodes = data.get("bitcoin_nodes")
        if nodes:  # nodes[0] is the primary bitcoind; the rest are failover, in order.
            fields["rpc_url"] = nodes[0]["address"]
            fields["rpc_user"] = nodes[0].get("username", "")
            fields["rpc_password"] = nodes[0].get("password", "")
            fields["rpc_failover"] = [
                {"url": node["address"], "user": node.get("username", ""),
                 "password": node.get("password", "")}
                for node in nodes[1:]
            ]
        listen = data.get("stratum_listen")
        if listen:
            urls = [listen] if isinstance(listen, str) else list(listen)
            first_host = _split_host_port(urls[0])[0]
            fields["bind_host"] = first_host or "0.0.0.0"
            fields["bind_ports"] = []
            for url in urls:
                host, port = _split_host_port(url)
                # Only the first bind host is honored; reject a differing per-entry host rather than
                # silently misbinding (e.g. an intended-loopback port exposed on 0.0.0.0).
                if host != first_host:
                    raise ConfigError("stratum_listen entries must all use the same host "
                                      f"(per-port hosts are not supported): {url}")
                fields["bind_ports"].append(port)
            fields["bind_port"] = fields["bind_ports"][0]
        api_listen = data.get("api_listen")
        if api_listen:
            host_port = api_listen if isinstance(api_listen, str) else api_listen[0]
            host, port = _split_host_port(host_port)
            fields["api_host"] = host or "127.0.0.1"
            fields["api_port"] = port
        if "block_poll_milliseconds" in data:
            fields["poll_interval"] = data["block_poll_milliseconds"] / 1000.0
        if "version_rolling_mask" in data:
            mask = data["version_rolling_mask"]
            fields["version_rolling_mask"] = int(mask, 16) if isinstance(mask, str) else mask

        proxy_from = data.get("proxy_protocol_from")
        if proxy_from is not None:  # accept a single string or a list
            fields["proxy_protocol_from"] = (
                [proxy_from] if isinstance(proxy_from, str) else list(proxy_from))

        # Every remaining scalar key maps straight onto the identically-named field.
        for key in (
            "coinbase_signature", "coinbase_version",
            "initial_difficulty", "minimum_difficulty", "maximum_difficulty",
            "variable_difficulty", "vardiff_target_shares_per_minute", "vardiff_retarget_seconds",
            "extranonce1_size", "extranonce2_size",
            "zmq_block_endpoint", "fast_block_notify",
            "work_rebroadcast_seconds", "donation_percent", "donation_address",
            "max_clients", "max_workers_per_address",
    "drop_idle_seconds", "auth_timeout_seconds", "max_protocol_errors",
            "max_line_bytes", "stats_directory", "status_interval_seconds",
            "user_stats_retention_days", "worker_threads",
        ):
            if key in data:
                fields[key] = data[key]
        return cls(**fields)

    @classmethod
    def load(cls, path: str) -> "Settings":
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (OSError, yaml.YAMLError) as e:
            raise ConfigError(f"cannot load config {path!r}: {e}") from e
        return cls.from_dict(data)

    def apply(self, other: "Settings") -> None:
        """Copy every field from `other` into this instance in place."""
        for field in dataclasses.fields(self):
            setattr(self, field.name, getattr(other, field.name))


SETTINGS = Settings()
