"""Shared fixtures and TestCase bases for the erikslund_pool suite."""
from __future__ import annotations

import logging
import time
import unittest

from erikslund_pool.util import display_hash
from erikslund_pool.util import dsha256
from erikslund_pool.work import Job

# P2WPKH scriptPubKey: OP_0 <20-byte hash>.
P2WPKH_SPK = bytes.fromhex("0014" + "11" * 20)
# bitcoind default_witness_commitment: OP_RETURN 0x24 aa21a9ed <32>.
WITNESS_COMMITMENT = "6a24aa21a9ed" + "00" * 32
# Regtest nBits: near-2^255 target, so almost every hash is a block.
REGTEST_BITS = "207fffff"


def make_txn(i: int) -> dict:
    """A synthetic getblocktemplate `transactions` entry."""
    internal = dsha256(b"erikslund_pool-test-txn-%d" % i)
    return {
        "data": (b"\x02\x00\x00\x00" + bytes([i & 0xFF]) * 8).hex(),
        "txid": display_hash(internal),
        "hash": display_hash(dsha256(b"erikslund_pool-test-wtxid-%d" % i)),
    }


class _Helpers:
    P2WPKH_SPK = P2WPKH_SPK

    def setUp(self):
        # Silence WARNING-level block-candidate logs for clean suite output.
        super().setUp()
        logging.disable(logging.CRITICAL)
        self.addCleanup(logging.disable, logging.NOTSET)

    def make_template(self, *, height=500001, txns=0, bits=REGTEST_BITS,
                      with_commitment=True, coinbasevalue=1_250_000_000):
        now = int(time.time())
        template = {
            "height": height,
            "version": 0x20000000,
            "curtime": now,
            "mintime": now - 600,
            "bits": bits,
            "coinbasevalue": coinbasevalue,
            "previousblockhash": "%064x" % 0x00000000000000000007A1B2C3D4E5F6,
            "transactions": [make_txn(i) for i in range(txns)],
        }
        if with_commitment:
            template["default_witness_commitment"] = WITNESS_COMMITMENT
        return template

    def make_job(self, template=None, *, job_id="1", tag=b"/test/",
                 extranonce1_size=4, extranonce2_size=8, version=1, clean=True) -> Job:
        return Job(job_id, template or self.make_template(), tag=tag,
                   extranonce1_size=extranonce1_size, extranonce2_size=extranonce2_size,
                   coinbase_version=version, clean=clean)

    def find_block_share(self, job, *, payout_script=None, extranonce1=b"\x00\x00\x00\x01"):
        """Brute-force a nonce yielding a block-quality share.

        Returns (ShareResult, extranonce2_hex, ntime_hex, nonce_hex).
        """
        script = payout_script or self.P2WPKH_SPK
        coinbase2 = job.build_coinbase2(script)
        extranonce2_hex = "00" * job.extranonce2_size
        ntime_hex = format(job.curtime, "08x")
        for nonce in range(1_000_000):
            nonce_hex = format(nonce, "08x")
            result = job.validate_share(
                coinbase2=coinbase2, extranonce1=extranonce1, extranonce2_hex=extranonce2_hex,
                ntime_hex=ntime_hex, nonce_hex=nonce_hex,
                share_target=job.network_target,
            )
            if result.valid and result.is_block:
                return result, extranonce2_hex, ntime_hex, nonce_hex
        raise AssertionError("no block-quality share found (target math wrong?)")


class SoloPoolTestCase(_Helpers, unittest.TestCase):
    """Base for synchronous tests."""


class AsyncSoloPoolTestCase(_Helpers, unittest.IsolatedAsyncioTestCase):
    """Base for tests that drive coroutines (stratum sessions, pool methods)."""
