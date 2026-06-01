"""Functional tests for Job: template parsing, share validation, block assembly."""
from __future__ import annotations

from erikslund_pool.merkle import merkle_branch
from erikslund_pool.tests.base import SoloPoolTestCase
from erikslund_pool.util import bits_to_target
from erikslund_pool.util import prevhash_to_stratum
from erikslund_pool.util import unhex


class TestJobFields(SoloPoolTestCase):
    def test_header_fields_from_template(self):
        template = self.make_template(height=500001)
        job = self.make_job(template)
        self.assertEqual(job.height, 500001)
        self.assertEqual(job.version_hex, "20000000")
        self.assertEqual(job.nbits_hex, "207fffff")
        self.assertEqual(job.ntime_hex, format(template["curtime"], "08x"))
        self.assertEqual(job.network_target, bits_to_target(0x207FFFFF))
        self.assertEqual(job.prevhash_stratum, prevhash_to_stratum(template["previousblockhash"]))
        self.assertTrue(job.has_witness)

    def test_merkle_branch_matches_txids(self):
        template = self.make_template(txns=3)
        job = self.make_job(template)
        internal = [unhex(t["txid"])[::-1] for t in template["transactions"]]
        self.assertEqual(job.merkle_branch, merkle_branch(internal))
        self.assertEqual(job.txn_count, 3)


class TestShareValidation(SoloPoolTestCase):
    def test_valid_block_share(self):
        job = self.make_job()  # regtest bits => block-quality shares are easy
        result, _, _, _ = self.find_block_share(job)
        self.assertTrue(result.valid)
        self.assertTrue(result.is_block)
        self.assertEqual(len(result.block_hash_hex), 64)
        self.assertLessEqual(int(result.block_hash_hex, 16), job.network_target)

    def test_low_difficulty_share_rejected(self):
        # Hard network target + tiny share target: a single nonce is above both.
        job = self.make_job(self.make_template(bits="1d00ffff"))
        coinbase2 = job.build_coinbase2(self.P2WPKH_SPK)
        result = job.validate_share(
            coinbase2=coinbase2, extranonce1=b"\x00\x00\x00\x01", extranonce2_hex="00" * 8,
            ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=job.network_target // (1 << 40),
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "above target")
        self.assertFalse(result.is_block)

    def test_bad_extranonce2_size(self):
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 4,  # wrong: job expects 8
            ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=job.network_target,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "invalid extranonce2 size")

    def test_ntime_out_of_range(self):
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex="ffffffff",  # year 2106, far future
            nonce_hex="00000000", share_target=job.network_target,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")

    def test_version_bits_outside_mask_rejected(self):
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=job.network_target,
            version_bits_hex="e0000000", version_mask=0x1FFFE000,
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "version bits outside negotiated mask")

    def test_valid_non_block_share(self):
        # Hard network target (not a block) + loosest share target (any hash validates).
        job = self.make_job(self.make_template(bits="1d00ffff"))
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=(1 << 256) - 1,
        )
        self.assertTrue(result.valid)
        self.assertFalse(result.is_block)
        self.assertIsNone(result.reason)
        self.assertEqual(len(result.header), 80)
        self.assertEqual(len(result.block_hash_hex), 64)

    def test_version_rolling_within_mask_is_accepted_and_alters_header(self):
        job = self.make_job()
        # Loosest share target isolates the mask logic from the target comparison.
        common = dict(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=(1 << 256) - 1)
        rolled = job.validate_share(**common, version_bits_hex="00002000", version_mask=0x1FFFE000)
        plain = job.validate_share(**common)
        self.assertTrue(rolled.valid)
        # The rolled bit lands in nVersion, so the first 4 header bytes differ.
        self.assertNotEqual(rolled.header[:4], plain.header[:4])

    def test_malformed_version_bits_rejected(self):
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=job.network_target, version_bits_hex="zzzz", version_mask=0x1FFFE000)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "malformed version bits")

    def test_rolled_version_helper(self):
        job = self.make_job()
        # No bits -> version untouched.
        self.assertEqual(job._rolled_version(None, 0), (job.version, None))
        # Zero bits without a mask: harmless no-op.
        self.assertEqual(job._rolled_version("00000000", 0), (job.version, None))
        # Non-zero bits without a mask: rejected, else a real block would be lost.
        self.assertEqual(job._rolled_version("ffff", 0), (0, "version rolling not negotiated"))
        # Bits within the mask fold into nVersion.
        version, error = job._rolled_version("00002000", 0x1FFFE000)
        self.assertIsNone(error)
        self.assertEqual(version, (job.version & ~0x1FFFE000) | (0x00002000 & 0x1FFFE000))

    def test_ntime_below_lower_bound_rejected(self):
        # Floor is the job's curtime; one second below must be rejected.
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=format(job.curtime - 1, "08x"),
            nonce_hex="00000000", share_target=job.network_target)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")

    def test_over_length_nonce_rejected_as_malformed(self):
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=job.ntime_hex, nonce_hex="1ffffffff",
            share_target=job.network_target)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "malformed share field")

    def test_malformed_share_fields_rejected(self):
        job = self.make_job()
        base = dict(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            share_target=job.network_target)
        # Bad ntime hex, bad nonce hex, and bad (but correctly-sized) extranonce2 hex.
        for bad in (
            dict(extranonce2_hex="00" * 8, ntime_hex="zz", nonce_hex="00000000"),
            dict(extranonce2_hex="00" * 8, ntime_hex=job.ntime_hex, nonce_hex="zz"),
            dict(extranonce2_hex="zz" * 8, ntime_hex=job.ntime_hex, nonce_hex="00000000"),
        ):
            result = job.validate_share(**base, **bad)
            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "malformed share field")

    def test_extranonce2_wrong_length_rejected_before_decode(self):
        job = self.make_job()
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 7, ntime_hex=job.ntime_hex, nonce_hex="00000000",
            share_target=job.network_target)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "invalid extranonce2 size")

    def test_validate_share_accepts_injected_now(self):
        # Injectable `now` makes the ntime upper bound deterministic; loose target
        # isolates the ntime check.
        job = self.make_job()
        future_ntime = job.curtime + 100
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=format(future_ntime, "08x"),
            nonce_hex="00000000", share_target=(1 << 256) - 1,
            now=float(job.curtime))   # curtime+100 is within now+7200 slack
        self.assertTrue(result.valid)

    def test_validate_share_rejects_ntime_past_now_slack(self):
        # With now pinned, an ntime more than NTIME_SLACK in the future is rejected.
        job = self.make_job()
        far_future = job.curtime + 7200 + 100
        result = job.validate_share(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK), extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * 8, ntime_hex=format(far_future, "08x"),
            nonce_hex="00000000", share_target=(1 << 256) - 1,
            now=float(job.curtime))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")


class TestBlockAssembly(SoloPoolTestCase):
    def test_block_structure_empty_mempool(self):
        job = self.make_job()
        result, _, _, _ = self.find_block_share(job)
        block_hex = job.build_block_hex(result.legacy_coinbase, result.header)
        # header(80) || varint(txcount=1) || witness-serialized coinbase || (no txns)
        self.assertEqual(len(result.header), 80)
        self.assertTrue(block_hex.startswith(result.header.hex()))
        self.assertEqual(block_hex[160:162], "01")            # 1 transaction
        self.assertEqual(block_hex[170:174], "0001")          # coinbase segwit marker/flag

    def test_block_includes_txn_data(self):
        job = self.make_job(self.make_template(txns=2))
        result, _, _, _ = self.find_block_share(job)
        block_hex = job.build_block_hex(result.legacy_coinbase, result.header)
        self.assertEqual(block_hex[160:162], "03")            # 2 txns + coinbase
        self.assertTrue(block_hex.endswith(job.txn_data.hex()))

    def test_block_without_witness_keeps_legacy_coinbase(self):
        # No witness commitment -> coinbase is not re-serialized as segwit.
        job = self.make_job(self.make_template(with_commitment=False))
        self.assertFalse(job.has_witness)
        result, _, _, _ = self.find_block_share(job)
        block_hex = job.build_block_hex(result.legacy_coinbase, result.header)
        self.assertEqual(block_hex[160:162], "01")            # one (coinbase) transaction
        # Bytes after the txcount are the legacy coinbase nVersion, not a 0001 marker.
        self.assertEqual(block_hex[162:170], result.legacy_coinbase[:4].hex())
        self.assertNotEqual(block_hex[170:174], "0001")

    def test_no_witness_commitment_when_absent_from_template(self):
        job = self.make_job(self.make_template(with_commitment=False))
        self.assertIsNone(job.witness_commitment)
        # coinbase2 = tag(6) | nSequence(4) | varint(output_count) | ... ; with no
        # witness commitment the output count is a single payout output.
        coinbase2 = job.build_coinbase2(self.P2WPKH_SPK)   # tag is b"/test/" (6 bytes)
        self.assertEqual(coinbase2[10:11].hex(), "01")
