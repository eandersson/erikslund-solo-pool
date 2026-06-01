"""Turn a getblocktemplate into mineable work, validate shares, assemble blocks.

A `Job` holds per-template state shared across miners; coinbase2 is per-miner since
solo pays each their own payout address.
"""

import time
from dataclasses import dataclass

from erikslund_pool import coinbase as cb
from erikslund_pool.constants import _UINT32_MAX
from erikslund_pool.constants import DIFF1_TARGET
from erikslund_pool.constants import NTIME_SLACK
from erikslund_pool.constants import NTIME_SUBMIT_MARGIN
from erikslund_pool.exceptions import WorkError
from erikslund_pool.merkle import merkle_branch
from erikslund_pool.merkle import merkle_root
from erikslund_pool.util import bits_to_target
from erikslund_pool.util import dsha256
from erikslund_pool.util import hash_to_int
from erikslund_pool.util import prevhash_to_stratum
from erikslund_pool.util import ser_uint32
from erikslund_pool.util import ser_varint
from erikslund_pool.util import unhex


@dataclass
class ShareResult:
    valid: bool
    reason: str | None
    difficulty: float            # pool difficulty this hash satisfies
    is_block: bool               # hash <= network target
    block_hash_hex: str          # canonical (display) hash
    header: bytes
    legacy_coinbase: bytes


def _rejected(reason: str) -> ShareResult:
    return ShareResult(False, reason, 0.0, False, "", b"", b"")


class Job:
    def __init__(self, job_id: str, template: dict, *, tag: bytes,
                 extranonce1_size: int, extranonce2_size: int,
                 coinbase_version: int, clean: bool = True,
                 donation_script: bytes = b"", donation_percent: float = 0.0):
        self.job_id = job_id
        self.clean = clean
        self.created = time.time()
        self.donation_script = donation_script
        self.donation_percent = donation_percent

        for rule in template.get("rules", []):
            if isinstance(rule, str) and rule.startswith("!") and rule != "!segwit":
                raise WorkError(f"unsupported mandatory template rule: {rule}")

        self.height = template["height"]
        self.version = template["version"]
        self.curtime = template["curtime"]
        self.bits = int(template["bits"], 16)
        self.network_target = bits_to_target(self.bits)
        self.coinbasevalue = template["coinbasevalue"]

        self.prevhash_internal = unhex(template["previousblockhash"])[::-1]
        self.prevhash_stratum = prevhash_to_stratum(template["previousblockhash"])

        # Present whenever segwit is active (always, on modern mainnet/regtest).
        commitment = template.get("default_witness_commitment")
        self.witness_commitment = unhex(commitment) if commitment else None
        self.has_witness = self.witness_commitment is not None
        self._segwit_gbt = isinstance(commitment, str)

        self.tag = tag
        self.extranonce2_size = extranonce2_size
        self._load_transactions(template.get("transactions", []))

        self.coinbase1 = cb.build_coinbase1(self.height, extranonce1_size + extranonce2_size,
                                      tag, coinbase_version)
        self.coinbase1_hex = self.coinbase1.hex()
        self.version_hex = format(self.version, "08x")
        self.nbits_hex = template["bits"]
        self.ntime_hex = format(self.curtime, "08x")

    @property
    def work_key(self) -> tuple:
        """Identity of the mining work minus the job id. Equal keys yield byte-identical
        headers for any extranonce/nonce, so rebroadcasting only resets miners' search."""
        return (self.prevhash_internal, self.version, self.bits, self.curtime,
                self.coinbasevalue, self.witness_commitment, self.coinbase1,
                tuple(self.merkle_branch))

    def _txid(self, t: dict) -> str:
        """Prefer `txid`. The legacy `hash` field is the txid only on a pre-segwit GBT; on a
        segwit template it is the WTXID, which would build a wrong merkle root, so reject."""
        txid = t.get("txid")
        if txid is not None:
            return txid
        if not self._segwit_gbt:
            return t["hash"]
        raise WorkError("segwit template transaction missing txid (refusing wtxid fallback)")

    def _txid_internal(self, t: dict) -> bytes:
        decoded = unhex(self._txid(t))
        if len(decoded) != 32:
            raise WorkError("template txid is not 32 bytes")
        return decoded[::-1]

    def _load_transactions(self, txns: list[dict]) -> None:
        """Concatenate raw txn data and build the merkle branch (txids display -> internal)."""
        self.txn_count = len(txns)
        self.txn_data = b"".join(unhex(t["data"]) for t in txns)
        txids = [self._txid_internal(t) for t in txns]
        self.merkle_branch = merkle_branch(txids)
        self.merkle_branch_hex = [h.hex() for h in self.merkle_branch]

    def build_coinbase2(self, payout_script: bytes) -> bytes:
        return cb.build_coinbase2(payout_script, self.coinbasevalue, self.witness_commitment,
                               self.tag, self.donation_script, self.donation_percent)

    def _header(self, merkle_root_bytes: bytes, ntime: int, nonce: int, version: int) -> bytes:
        return (ser_uint32(version) + self.prevhash_internal + merkle_root_bytes
                + ser_uint32(ntime) + ser_uint32(self.bits) + ser_uint32(nonce))

    def _rolled_version(self, version_bits_hex: str | None, version_mask: int) -> tuple[int, str | None]:
        """Fold a miner's version-rolling bits into nVersion within the mask."""
        if version_bits_hex is None:
            return self.version, None
        if len(version_bits_hex) > 8:
            return 0, "malformed version bits"
        try:
            rolled = int(version_bits_hex, 16)
        except ValueError:
            return 0, "malformed version bits"
        if version_mask == 0:
            if rolled != 0:
                return 0, "version rolling not negotiated"
            return self.version, None
        if rolled & ~version_mask:
            return 0, "version bits outside negotiated mask"
        return (self.version & ~version_mask) | (rolled & version_mask), None

    def validate_share(self, *, coinbase2: bytes, extranonce1: bytes, extranonce2_hex: str,
                       ntime_hex: str, nonce_hex: str, share_target: int,
                       version_bits_hex: str | None = None, version_mask: int = 0,
                       now: float | None = None) -> ShareResult:
        """Test the reconstructed header against the share (and network) target.
        Every field is untrusted; all hex is parsed defensively. Pure: no side effects."""
        now = time.time() if now is None else now

        if len(extranonce2_hex) != self.extranonce2_size * 2:
            return _rejected("invalid extranonce2 size")
        if len(ntime_hex) > 8 or len(nonce_hex) > 8:
            return _rejected("malformed share field")
        try:
            extranonce2 = unhex(extranonce2_hex)
            ntime = int(ntime_hex, 16)
            nonce = int(nonce_hex, 16)
        except ValueError:
            return _rejected("malformed share field")
        if len(extranonce2) != self.extranonce2_size:
            return _rejected("invalid extranonce2 size")
        if not (0 <= nonce <= _UINT32_MAX and 0 <= ntime <= _UINT32_MAX):
            return _rejected("nonce/ntime out of range")
        if not (self.curtime <= ntime <= now + NTIME_SLACK - NTIME_SUBMIT_MARGIN):
            return _rejected("ntime out of range")

        version, version_error = self._rolled_version(version_bits_hex, version_mask)
        if version_error:
            return _rejected(version_error)

        coinbase = self.coinbase1 + extranonce1 + extranonce2 + coinbase2
        root = merkle_root(dsha256(coinbase), self.merkle_branch)
        header = self._header(root, ntime, nonce, version)
        block_hash = dsha256(header)
        hash_value = hash_to_int(block_hash)
        difficulty = DIFF1_TARGET / hash_value if hash_value else float("inf")
        display_hash = block_hash[::-1].hex()

        is_block = hash_value <= self.network_target
        if not is_block and hash_value > share_target:
            return ShareResult(False, "above target", difficulty, False, display_hash, header, coinbase)
        return ShareResult(True, None, difficulty, is_block, display_hash, header, coinbase)

    def build_block_hex(self, legacy_coinbase: bytes, header: bytes) -> str:
        """Assemble the full block for submitblock; coinbase re-serialized as segwit if witnessed."""
        coinbase = cb.legacy_to_witness(legacy_coinbase) if self.has_witness else legacy_coinbase
        return (header + ser_varint(self.txn_count + 1) + coinbase + self.txn_data).hex()
