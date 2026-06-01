"""Centralized constants -- pure values, no package imports (avoids import cycles)."""

import logging
import re

# -- util: difficulty / target math -----------------------------------------
# Difficulty-1 target (bits 0x1d00ffff); a hash meets difficulty d when <= this/d.
DIFF1_TARGET = 0xFFFF * (1 << 208)

# -- coinbase: serialization -------------------------------------------------
# BIP141 witness reserved value; default_witness_commitment assumes 32 zero bytes.
WITNESS_RESERVED_VALUE = b"\x00" * 32
_PREVOUT_NULL = b"\x00" * 32 + b"\xff\xff\xff\xff"   # coinbase has no real prevout
_SEQUENCE = b"\xff\xff\xff\xff"
_LOCKTIME = b"\x00\x00\x00\x00"

# -- work: share validation --------------------------------------------------
# Consensus caps block ntime at now+7200s; allow that future slack so a legitimately
# rolled-forward ntime is never dropped. Floor is the job's curtime (miners only roll forward).
NTIME_SLACK = 7200
# Margin below the +7200 ceiling: a block at exactly now+7200 is rejected "time-too-new" by any
# peer whose clock lags ours. No real miner rolls within 2 minutes of the cap.
NTIME_SUBMIT_MARGIN = 120
_UINT32_MAX = 0xFFFFFFFF

# -- pool: job/cache bounds + address gate -----------------------------------
# Late-share window: superseded jobs that still accept shares. Depth must cover at least a
# mean block interval (10 min) or a still-valid share on an older same-tip job false-rejects
# as stale. At 30s rotation, 24 x 30s = 12 min.
MAX_RECENT_JOBS = 24
MAX_ADDRESS_CACHE = 4096  # bound the validateaddress result cache
# base58 + bech32 + worker-suffix separators; gates usernames before any RPC.
_ADDRESS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._")

# -- stratum: protocol limits + mining.submit error tuples -------------------
SERVER_VERSION_MASK = 0x1FFFE000   # BIP320; intersected with the miner's mask
MAX_SEEN_SHARES = 16_384  # per-session dup-guard generation size (2 generations -> 2x bound)

# mining.submit errors: error = [code, message, null].
ERR_OTHER = (20, "Other/unknown")
ERR_STALE = (21, "Job not found / stale")
ERR_DUPLICATE = (22, "Duplicate share")
ERR_LOW_DIFF = (23, "Low difficulty share")
ERR_UNAUTHORIZED = (24, "Unauthorized worker")
ERR_NOT_SUBSCRIBED = (25, "Not subscribed")

# -- poolstatus: stats format ------------------------------------------------
# strtod-style float prefix: the exponent group only matches when real digits follow,
# so a trailing "E" reads as the exa suffix, not a broken exponent.
_FLOAT_RE = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?")
NONCES = 2 ** 32  # hashes per diff-1 share
_SUFFIX_MULTIPLIERS = {"K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "": 1.0}

# -- routers.stats: API address charset --------------------------------------
# Charset accepted on /stats/client/<address> (base58 + bech32 + separators).
_API_ADDRESS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._")

# -- logging_config: reserved LogRecord fields for the JSON formatter --------
_RESERVED = frozenset(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "taskName"}
