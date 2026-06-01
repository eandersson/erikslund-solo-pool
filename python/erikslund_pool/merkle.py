"""Merkle branch construction and folding for Stratum (all hashes internal order)."""
from erikslund_pool.util import dsha256


def merkle_branch(txids: list[bytes]) -> list[bytes]:
    """Stratum merkle branch for a coinbase at leaf 0 (the siblings mining.notify carries).

    `txids` are the non-coinbase ids in internal byte order, in block order.
    """
    branch: list[bytes] = []
    # Index 0 is the coinbase placeholder (its hash needs the miner's extranonce2).
    level: list[bytes | None] = [None] + list(txids)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate the last node if odd
        branch.append(level[1])      # sibling of the coinbase-path node
        next_level: list[bytes | None] = [None]  # index 0 depends on the coinbase
        for i in range(2, len(level), 2):
            next_level.append(dsha256(level[i] + level[i + 1]))
        level = next_level
    return branch


def merkle_root(coinbase_txid: bytes, branch: list[bytes]) -> bytes:
    """Fold a coinbase txid through a merkle branch to the root (internal order)."""
    node = coinbase_txid
    for sibling in branch:
        node = dsha256(node + sibling)
    return node
