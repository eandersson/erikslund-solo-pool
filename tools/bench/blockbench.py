#!/usr/bin/env python3
"""Micro-benchmark the pool-controlled part of the block-submission critical path.

Two phases, by *when* they run:
  - Job() creation  -> happens when a TEMPLATE arrives (off the critical path);
    this is where the O(block-size) transaction concatenation lives.
  - build_block_hex  -> happens when a WINNING SHARE is found (the critical path);
    it must be fast because every millisecond here is orphan risk.

Run on the GIL (python:3.14-slim) and free-threaded (3.14t) interpreters.
"""
import sys
import time

from erikslund_pool.work import Job

TAG = b"/bench/"
PAYOUT_SPK = bytes.fromhex("0014" + "11" * 20)  # P2WPKH scriptPubKey


def make_template(n_txns: int) -> dict:
    return {
        "height": 800000,
        "version": 0x20000000,
        "curtime": 1700000000,
        "bits": "17034219",
        "coinbasevalue": 625000000,
        "previousblockhash": "00" * 32,
        "default_witness_commitment": "6a24aa21a9ed" + "00" * 32,
        # ~250-byte transactions, the rough average on a real block.
        "transactions": [{"data": "00" * 250, "txid": "%064x" % i} for i in range(n_txns)],
    }


def bench(n_txns: int) -> tuple:
    template = make_template(n_txns)

    reps = max(3, 300 // (n_txns // 250 + 1))
    t0 = time.perf_counter()
    for _ in range(reps):
        job = Job("1", template, tag=TAG, extranonce1_size=4, extranonce2_size=8,
                  coinbase_version=1)
    create_ms = (time.perf_counter() - t0) / reps * 1000

    coinbase2 = job.build_coinbase2(PAYOUT_SPK)
    legacy_coinbase = job.coinbase1 + b"\x00" * 4 + b"\x00" * 8 + coinbase2
    header = b"\x00" * 80
    iters = 3000
    t0 = time.perf_counter()
    for _ in range(iters):
        block_hex = job.build_block_hex(legacy_coinbase, header)
    submit_ms = (time.perf_counter() - t0) / iters * 1000
    return create_ms, submit_ms, len(block_hex) / 2 / 1024


def main():
    gil = getattr(sys, "_is_gil_enabled", lambda: True)()
    print(f"python {sys.version.split()[0]}  GIL={'on' if gil else 'off'}")
    print(f"{'txns':>6} {'block':>10} {'Job() [template]':>18} {'build_block_hex [submit]':>26}")
    for n in (0, 250, 1000, 4000):
        create_ms, submit_ms, block_kb = bench(n)
        print(f"{n:>6} {block_kb:>8.0f}KiB {create_ms:>15.3f}ms {submit_ms:>23.4f}ms")


if __name__ == "__main__":
    main()
