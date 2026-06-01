"""Adversarial Job.validate_share tests -- every field is hostile.

Contract: string fields are parsed defensively, so a bad share yields a
ShareResult(valid=False), never an exception.
"""
from __future__ import annotations

from erikslund_pool.constants import _UINT32_MAX
from erikslund_pool.exceptions import WorkError
from erikslund_pool.tests.base import SoloPoolTestCase
from erikslund_pool.tests.base import make_txn


class _ValidateMixin(SoloPoolTestCase):
    def _validate(self, job, **overrides):
        params = dict(
            coinbase2=job.build_coinbase2(self.P2WPKH_SPK),
            extranonce1=b"\x00\x00\x00\x01",
            extranonce2_hex="00" * job.extranonce2_size,
            ntime_hex=job.ntime_hex,
            nonce_hex="00000000",
            share_target=job.network_target,
        )
        params.update(overrides)
        return job.validate_share(**params)


class TestExtranonce2Adversarial(_ValidateMixin):
    def test_empty_extranonce2(self):
        result = self._validate(self.make_job(), extranonce2_hex="")
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "invalid extranonce2 size")

    def test_too_short_and_too_long(self):
        job = self.make_job()  # expects 8 bytes
        for hex_str in ("00" * 7, "00" * 9, "00" * 1, "00" * 64):
            result = self._validate(job, extranonce2_hex=hex_str)
            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "invalid extranonce2 size")

    def test_correct_length_but_non_hex(self):
        # Right length (16 chars) but not hex -> caught at decode, not length.
        result = self._validate(self.make_job(), extranonce2_hex="zz" * 8)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "malformed share field")

    def test_odd_length_is_size_reject(self):
        # 15 chars != 16 -> size reject fires before the odd-length hex decode.
        result = self._validate(self.make_job(), extranonce2_hex="0" * 15)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "invalid extranonce2 size")

    def test_uppercase_hex_is_accepted_as_size(self):
        # Uppercase hex of the right length decodes fine; it's not the rejection.
        result = self._validate(self.make_job(), extranonce2_hex="AB" * 8,
                                share_target=(1 << 256) - 1)
        self.assertTrue(result.valid)


class TestNonceNtimeBounds(_ValidateMixin):
    def test_over_length_nonce_is_malformed(self):
        for nonce_hex in ("100000000", "1ffffffff", "ffffffffff", "000000001"):
            result = self._validate(self.make_job(), nonce_hex=nonce_hex)
            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "malformed share field")

    def test_nonce_at_uint32_max_is_in_range(self):
        # 0xffffffff is the largest legal nonce and must pass the range gate.
        job = self.make_job()
        result = self._validate(job, nonce_hex=format(_UINT32_MAX, "08x"),
                                share_target=(1 << 256) - 1)
        self.assertNotEqual(result.reason, "nonce/ntime out of range")

    def test_ntime_far_future_rejected(self):
        result = self._validate(self.make_job(), ntime_hex="ffffffff")
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")

    def test_ntime_far_past_rejected(self):
        job = self.make_job()
        result = self._validate(job, ntime_hex=format(job.curtime - 100000, "08x"))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")

    def test_over_length_ntime_is_malformed(self):
        result = self._validate(self.make_job(), ntime_hex="1ffffffff")
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "malformed share field")


class TestMalformedHexFields(_ValidateMixin):
    def test_malformed_nonce_hex(self):
        # int(s, 16) accepts "0x" and strips whitespace, so only non-hex tokens fail.
        for nonce_hex in ("zz", "  ", "gg00gg00", "nothex"):
            result = self._validate(self.make_job(), nonce_hex=nonce_hex)
            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "malformed share field")

    def test_malformed_ntime_hex(self):
        for ntime_hex in ("zz", "nothex", "gg", "  "):
            result = self._validate(self.make_job(), ntime_hex=ntime_hex)
            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "malformed share field")

    def test_empty_nonce_hex_is_zero_not_malformed(self):
        # int("", 16) raises -> malformed; empty string is not a silent zero.
        result = self._validate(self.make_job(), nonce_hex="")
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "malformed share field")


class TestVersionRollingAdversarial(_ValidateMixin):
    def test_bits_outside_mask_rejected(self):
        result = self._validate(self.make_job(), version_bits_hex="e0000000",
                                version_mask=0x1FFFE000)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "version bits outside negotiated mask")

    def test_malformed_version_bits_rejected(self):
        # "0x.." would parse as a number; use genuinely non-hex tokens.
        for bits in ("zzzz", "nothex", "gg", "  "):
            result = self._validate(self.make_job(), version_bits_hex=bits,
                                    version_mask=0x1FFFE000)
            self.assertFalse(result.valid)
            self.assertEqual(result.reason, "malformed version bits")

    def test_over_length_version_bits_is_malformed(self):
        result = self._validate(self.make_job(), version_bits_hex="000002000",
                                version_mask=0x1FFFE000)
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "malformed version bits")

    def test_unnegotiated_version_bits_are_handled_not_silently_ignored(self):
        job = self.make_job()
        loose = (1 << 256) - 1
        # Zero bits without a mask: harmless no-op, still valid.
        self.assertTrue(self._validate(job, version_bits_hex="00000000", version_mask=0,
                                       share_target=loose).valid)
        # Non-zero bits without a mask: reject visibly, else a real block would be lost.
        rolled = self._validate(job, version_bits_hex="ffffffff", version_mask=0, share_target=loose)
        self.assertFalse(rolled.valid)
        self.assertEqual(rolled.reason, "version rolling not negotiated")
        # Malformed bits are rejected as malformed regardless of the mask.
        bad = self._validate(job, version_bits_hex="zzzz", version_mask=0, share_target=loose)
        self.assertFalse(bad.valid)
        self.assertEqual(bad.reason, "malformed version bits")

    def test_version_bits_none_with_mask_is_fine(self):
        job = self.make_job()
        result = self._validate(job, version_bits_hex=None, version_mask=0x1FFFE000,
                                share_target=(1 << 256) - 1)
        self.assertTrue(result.valid)

    def test_rolled_version_helper_rejects_out_of_mask(self):
        job = self.make_job()
        version, error = job._rolled_version("e0000000", 0x1FFFE000)
        self.assertEqual(version, 0)
        self.assertEqual(error, "version bits outside negotiated mask")

    def test_rolled_version_helper_malformed(self):
        job = self.make_job()
        version, error = job._rolled_version("nothex", 0x1FFFE000)
        self.assertEqual(version, 0)
        self.assertEqual(error, "malformed version bits")


class TestAboveTargetIsNotException(_ValidateMixin):
    def test_low_diff_share_is_clean_reject(self):
        # Hard network target + tiny share target: the single nonce is above both,
        # which must be a clean ShareResult(valid=False, reason="above target").
        job = self.make_job(self.make_template(bits="1d00ffff"))
        result = self._validate(job, share_target=job.network_target // (1 << 40))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "above target")
        self.assertFalse(result.is_block)


class TestHostileTemplates(SoloPoolTestCase):
    """Job construction must reject (never silently mis-build) malformed templates."""

    def test_segwit_template_missing_txid_is_rejected(self):
        # With a witness commitment, `hash` is the WTXID; using it as txid would
        # build a wrong merkle root and an invalid block.
        template = self.make_template(txns=1, with_commitment=True)
        del template["transactions"][0]["txid"]
        with self.assertRaises(WorkError):
            self.make_job(template)

    def test_presegwit_template_falls_back_to_hash(self):
        # No witness commitment -> pre-segwit GBT server, where hash == txid.
        template = self.make_template(txns=0, with_commitment=False)
        txn = make_txn(1)
        txn["hash"] = txn.pop("txid")  # pre-segwit servers emit only `hash` (== txid)
        template["transactions"] = [txn]
        job = self.make_job(template)
        self.assertEqual(job.txn_count, 1)  # built fine; merkle uses hash-as-txid

    def test_segwit_template_with_txid_prefers_it(self):
        template = self.make_template(txns=1, with_commitment=True)
        self.assertEqual(self.make_job(template).txn_count, 1)

    def test_wrong_length_txid_is_rejected(self):
        for bad in ("ab" * 31, "ab" * 33):
            template = self.make_template(txns=1, with_commitment=True)
            template["transactions"][0]["txid"] = bad
            with self.assertRaises(WorkError):
                self.make_job(template)

    def test_empty_string_commitment_still_blocks_the_hash_fallback(self):
        template = self.make_template(txns=1, with_commitment=False)
        template["default_witness_commitment"] = ""
        del template["transactions"][0]["txid"]
        with self.assertRaises(WorkError):
            self.make_job(template)

    def test_wrong_length_previousblockhash_is_rejected(self):
        # A wrong-length hash must raise, not yield a malformed prevhash / bad header.
        for bad in ("ab" * 31, "ab" * 33, ""):
            template = self.make_template()
            template["previousblockhash"] = bad
            with self.assertRaises(ValueError):
                self.make_job(template)

    def test_unknown_mandatory_rule_is_refused(self):
        # BIP9: a '!' prefix means the miner MUST understand the rule. We only
        # understand segwit, so refuse anything else rather than mis-assemble a block.
        template = self.make_template()
        template["rules"] = ["!unknownfork"]
        with self.assertRaises(WorkError):
            self.make_job(template)

    def test_known_and_optional_rules_are_accepted(self):
        # '!segwit' (mandatory, understood), plain 'segwit', and a non-'!' rule ('csv') all build.
        template = self.make_template()
        template["rules"] = ["segwit", "!segwit", "csv"]
        self.make_job(template)  # must not raise

    def test_non_string_rule_is_skipped_not_crashed_on(self):
        template = self.make_template()
        template["rules"] = [123, "!segwit"]  # 123 skipped; !segwit allowed
        self.make_job(template)  # must not raise
        template["rules"] = [123, "!unknownfork"]  # skip 123, still catch the bad rule
        with self.assertRaises(WorkError):
            self.make_job(template)


class TestNtimeSubmitMargin(_ValidateMixin):
    BASE = 1700000000

    def _fixed_job(self):
        template = self.make_template()
        template["curtime"] = self.BASE
        return self.make_job(template)

    def test_ntime_at_the_submit_margin_ceiling_is_accepted(self):
        result = self._validate(self._fixed_job(), now=self.BASE,
                                ntime_hex=format(self.BASE + 7080, "08x"),
                                share_target=(1 << 256) - 1)
        self.assertTrue(result.valid)

    def test_ntime_one_second_above_the_margin_is_rejected(self):
        result = self._validate(self._fixed_job(), now=self.BASE,
                                ntime_hex=format(self.BASE + 7081, "08x"))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")

    def test_old_now_plus_7200_ceiling_is_now_forbidden(self):
        result = self._validate(self._fixed_job(), now=self.BASE,
                                ntime_hex=format(self.BASE + 7200, "08x"))
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "ntime out of range")


if __name__ == "__main__":
    import unittest
    unittest.main()
