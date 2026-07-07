"""WorkSource: the seam that decouples the pool core from HOW it (a) learns a new tip exists,
(b) obtains a block template, and (c) submits a solved block. The one backend is `RpcWorkSource`
(getblocktemplate + optional ZMQ). Mirrors the RPC path of cpp/src/bitcoin/work_source.hpp so the
C++ and Python pools share one design. (The C++ pool ALSO has a Cap'n Proto IPC backend; the Python
pool does not -- pycapnp re-enables the GIL, which the free-threaded pool forbids, so IPC is a
C++-pool-only feature.)

The pool PULLS: its template_loop owns the poll cadence, the tip-probe gate and the dedup; the
backend only supplies primitives. get_template() returns the GBT-shaped dict work.Job already
consumes, so the pool keeps building its own coinbase. Tip notifications are the pool's zmq_loop.

Address validation is deliberately NOT part of this seam -- it always goes over JSON-RPC
(Pool.validate_address).
"""

from abc import ABC
from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass

from erikslund_pool.rpc import BitcoindRPC


@dataclass
class SolvedBlock:
    """A pool-solved block crossing to a backend: the structured header + legacy coinbase (both
    straight off work.ShareResult) plus a lazy hex serializer that RpcWorkSource submits."""

    height: int
    block_hash: str
    header: bytes
    legacy_coinbase: bytes
    to_block_hex: Callable[[], str]


class WorkSource(ABC):
    @abstractmethod
    def get_chain_info(self) -> dict:
        """Startup/loop chain probe: a dict with at least {"chain", "blocks"}. May raise RPCError."""

    @abstractmethod
    def get_tip(self) -> str:
        """Cheap best-block-hash probe -- the gate before the heavy template fetch. May raise."""

    @abstractmethod
    def get_template(self, validate: Callable[[dict], None] | None = None) -> dict:
        """The heavy fetch: a GBT-shaped template dict work.Job consumes unchanged. `validate`, if
        given, must raise on unusable work. May raise."""

    @abstractmethod
    def get_header(self, block_hash: str) -> dict:
        """Header facts grounding the fastblock empty job:
        {"confirmations", "height", "bits", "mediantime"}. May raise."""

    @abstractmethod
    def submit_block(self, block: SolvedBlock) -> str | None:
        """Submit a pool-solved block. Returns bitcoind's rejection token (None == accepted)."""

    def submit_block_hex(self, block_hex: str) -> str | None:
        """Spool replay: a previous run's already-serialized block hex. Default wraps it in a
        SolvedBlock and forwards to submit_block."""
        return self.submit_block(SolvedBlock(0, "", b"", b"", lambda: block_hex))

    def maybe_failback(self, expected_tip: str) -> None:
        """RPC-only reverse failover (status_loop). No-op for single-endpoint backends."""

    def active_index(self) -> int:
        return 0

    def endpoint_urls(self) -> list[str]:
        return []


class RpcWorkSource(WorkSource):
    """The backend: forwards to `BitcoindRPC` with its existing validate/failover semantics. Reads
    the rpc through a getter so tests that swap Pool.rpc keep working."""

    def __init__(self, get_rpc: Callable[[], BitcoindRPC]):
        self._get_rpc = get_rpc

    @property
    def _rpc(self) -> BitcoindRPC:
        return self._get_rpc()

    def get_chain_info(self) -> dict:
        return self._rpc.getblockchaininfo()

    def get_tip(self) -> str:
        return self._rpc.getbestblockhash()

    def get_template(self, validate: Callable[[dict], None] | None = None) -> dict:
        return self._rpc.getblocktemplate(validate=validate)

    def get_header(self, block_hash: str) -> dict:
        return self._rpc.getblockheader(block_hash)

    def submit_block(self, block: SolvedBlock) -> str | None:
        return self._rpc.submitblock(block.to_block_hex())

    def submit_block_hex(self, block_hex: str) -> str | None:
        return self._rpc.submitblock(block_hex)

    def maybe_failback(self, expected_tip: str) -> None:
        self._rpc.maybe_failback(expected_tip)

    def active_index(self) -> int:
        return self._rpc.active_index

    def endpoint_urls(self) -> list[str]:
        return self._rpc.endpoint_urls()
