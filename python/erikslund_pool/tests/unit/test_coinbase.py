"""Tests for coinbase assembly, the coinbase1/coinbase2 split, and segwit framing."""

from erikslund_pool.coinbase import build_coinbase1
from erikslund_pool.coinbase import build_coinbase2
from erikslund_pool.coinbase import legacy_to_witness
from erikslund_pool.exceptions import WorkError
from erikslund_pool.tests.base import P2WPKH_SPK
from erikslund_pool.tests.base import WITNESS_COMMITMENT
from erikslund_pool.tests.base import SoloPoolTestCase


class TestCoinbase(SoloPoolTestCase):
    def _legacy(self, extranonce_total=12, tag=b"/test/"):
        coinbase1 = build_coinbase1(500000, extranonce_total, tag, version=1)
        coinbase2 = build_coinbase2(P2WPKH_SPK, 5_000_000_000,
                              bytes.fromhex(WITNESS_COMMITMENT), tag)
        return coinbase1 + b"\xaa" * extranonce_total + coinbase2

    def test_coinbase1_exact_bytes(self):
        # version | vin=1 | null prevout | scriptSig len | BIP34 height push
        expected = ("01000000" "01" + "00" * 32 + "ffffffff"
                    + "13"            # scriptSig len = 4 (height) + 12 (extranonce) + 3 (tag)
                    + "0320a107")     # serialize_height(500000)
        self.assertEqual(build_coinbase1(500000, 12, b"/x/", 1).hex(), expected)

    def test_coinbase2_exact_single_output(self):
        coinbase2 = build_coinbase2(P2WPKH_SPK, 5_000_000_000, None, b"/x/")
        expected = ("2f782f"              # tag "/x/" (scriptSig tail)
                    + "ffffffff"          # nSequence
                    + "01"                # one output
                    + "00f2052a01000000"  # value 50 BTC, little-endian
                    + "16" + P2WPKH_SPK.hex()   # scriptPubKey: length + bytes
                    + "00000000")         # nLockTime
        self.assertEqual(coinbase2.hex(), expected)

    def test_output_count_depends_on_commitment(self):
        # coinbase2 (empty tag): nSequence(4) | varint output-count | outputs | locktime.
        with_commit = build_coinbase2(P2WPKH_SPK, 1, bytes.fromhex(WITNESS_COMMITMENT), b"")
        without = build_coinbase2(P2WPKH_SPK, 1, None, b"")
        self.assertEqual(with_commit[4:5].hex(), "02")
        self.assertEqual(without[4:5].hex(), "01")

    def test_legacy_layout(self):
        legacy = self._legacy()
        self.assertEqual(legacy[:4].hex(), "01000000")        # nVersion = 1
        self.assertEqual(legacy[4:5].hex(), "01")             # one input
        self.assertEqual(legacy[-4:].hex(), "00000000")       # nLockTime = 0

    def test_witness_reserialization(self):
        legacy = self._legacy()
        w = legacy_to_witness(legacy)
        self.assertEqual(w[4:6].hex(), "0001")                # segwit marker+flag
        # Witness = varint(1) + varint(32) + 32 zero bytes, before nLockTime.
        self.assertEqual(w[-38:-4].hex(), "0120" + "00" * 32)
        # Stripping the framing must recover the legacy bytes exactly.
        self.assertEqual(w[:4] + w[6:-38] + w[-4:], legacy)

    def test_scriptsig_length_cap(self):
        with self.assertRaises(WorkError):
            build_coinbase1(500000, extranonce_total=200, tag=b"", version=1)

    def test_donation_splits_reward_into_two_outputs(self):
        # 2% of 50 BTC to the donation script, the rest to the miner.
        value = 5_000_000_000
        donation_script = bytes.fromhex("0014") + b"\x11" * 20
        coinbase2 = build_coinbase2(P2WPKH_SPK, value, None, b"",
                              donation_script=donation_script, donation_percent=2.0)
        self.assertEqual(coinbase2[4:5].hex(), "02")  # two outputs, no witness commitment
        donation_amount = int(value * 2.0 / 100.0)
        miner_value = int.from_bytes(coinbase2[5:13], "little")
        self.assertEqual(miner_value, value - donation_amount)

    def test_zero_donation_is_single_output(self):
        coinbase2 = build_coinbase2(P2WPKH_SPK, 5_000_000_000, None, b"",
                              donation_script=b"", donation_percent=0.0)
        self.assertEqual(coinbase2[4:5].hex(), "01")

    @staticmethod
    def _outputs(coinbase2: bytes):
        # Empty-tag coinbase2: nSequence(4) | varint count | outputs | locktime(4).
        # All counts/lengths here are < 0xfd, so each varint is one byte.
        i = 4
        count = coinbase2[i]
        i += 1
        outs = []
        for _ in range(count):
            value = int.from_bytes(coinbase2[i:i + 8], "little")
            i += 8
            length = coinbase2[i]
            i += 1
            outs.append((value, coinbase2[i:i + length]))
            i += length
        return outs

    def test_donation_conserves_total_value(self):
        value = 5_000_000_000
        donation_script = bytes.fromhex("0014") + b"\x22" * 20
        outs = self._outputs(build_coinbase2(P2WPKH_SPK, value, None, b"",
                                             donation_script=donation_script, donation_percent=2.0))
        self.assertEqual(len(outs), 2)
        donation_amount = int(value * 2.0 / 100.0)
        self.assertEqual(outs[0], (value - donation_amount, P2WPKH_SPK))
        self.assertEqual(outs[1], (donation_amount, donation_script))
        self.assertEqual(outs[0][0] + outs[1][0], value)                  # no satoshi created/lost

    def test_donation_floors_remainder_to_miner(self):
        # Reward that doesn't divide evenly: donation floors, miner keeps the rest.
        value = 1_234_567_891
        donation_script = bytes.fromhex("0014") + b"\x33" * 20
        outs = self._outputs(build_coinbase2(P2WPKH_SPK, value, None, b"",
                                             donation_script=donation_script, donation_percent=7.0))
        self.assertEqual(outs[1][0], 86_419_752)          # floor(1_234_567_891 * 7 / 100)
        self.assertEqual(outs[0][0], value - 86_419_752)
        self.assertEqual(outs[0][0] + outs[1][0], value)

    def test_percent_set_but_no_script_is_single_output(self):
        # A percent with an empty script must not create a zero-script output;
        # it falls back to a single full-reward miner output.
        value = 5_000_000_000
        outs = self._outputs(build_coinbase2(P2WPKH_SPK, value, None, b"",
                                             donation_script=b"", donation_percent=10.0))
        self.assertEqual(len(outs), 1)
        self.assertEqual(outs[0], (value, P2WPKH_SPK))
