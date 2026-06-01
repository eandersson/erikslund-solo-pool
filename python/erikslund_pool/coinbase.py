"""Coinbase assembly and the coinbase1/coinbase2 Stratum split.

    full_legacy_coinbase = coinbase1 || extranonce1 || extranonce2 || coinbase2

coinbase1 is shared; coinbase2 carries the miner's own payout. The merkle-root
txid uses this legacy form; the submitted block re-serializes it as segwit.
"""

from erikslund_pool.constants import _LOCKTIME
from erikslund_pool.constants import _PREVOUT_NULL
from erikslund_pool.constants import _SEQUENCE
from erikslund_pool.constants import WITNESS_RESERVED_VALUE
from erikslund_pool.exceptions import WorkError
from erikslund_pool.util import ser_uint32
from erikslund_pool.util import ser_uint64
from erikslund_pool.util import ser_varint
from erikslund_pool.util import serialize_height


def build_coinbase1(height: int, extranonce_total: int, tag: bytes, version: int = 1) -> bytes:
    """coinbase1 prefix, ending where extranonce1 begins (scriptSig = height||enonce||tag)."""
    height_push = serialize_height(height)
    scriptsig_len = len(height_push) + extranonce_total + len(tag)
    if scriptsig_len > 100:
        raise WorkError(f"coinbase scriptSig too long ({scriptsig_len} > 100)")
    return ser_uint32(version) + b"\x01" + _PREVOUT_NULL + ser_varint(scriptsig_len) + height_push


def build_coinbase2(payout_script: bytes, value: int, witness_commitment_script: bytes | None,
                 tag: bytes, donation_script: bytes = b"", donation_percent: float = 0.0) -> bytes:
    """Per-miner coinbase2: scriptSig tail, sequence, outputs, locktime.

    With a donation, that percent of the reward goes to donation_script.
    """
    if donation_percent > 0.0 and donation_script:
        donation_amount = int(value * donation_percent / 100.0)
        outputs = [(value - donation_amount, payout_script), (donation_amount, donation_script)]
    else:
        outputs = [(value, payout_script)]
    if witness_commitment_script is not None:
        outputs.append((0, witness_commitment_script))
    coinbase2 = bytearray(tag)
    coinbase2 += _SEQUENCE
    coinbase2 += ser_varint(len(outputs))
    for amount, script in outputs:
        coinbase2 += ser_uint64(amount) + ser_varint(len(script)) + script
    coinbase2 += _LOCKTIME
    return bytes(coinbase2)


def legacy_to_witness(legacy_coinbase: bytes) -> bytes:
    """Re-serialize a legacy coinbase as segwit: marker+flag after nVersion, the
    input's 32-byte reserved-value witness before nLockTime."""
    version, body, locktime = legacy_coinbase[:4], legacy_coinbase[4:-4], legacy_coinbase[-4:]
    witness = ser_varint(1) + ser_varint(len(WITNESS_RESERVED_VALUE)) + WITNESS_RESERVED_VALUE
    return version + b"\x00\x01" + body + witness + locktime
