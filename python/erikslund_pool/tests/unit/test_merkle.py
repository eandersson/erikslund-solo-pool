"""Tests for the Stratum merkle branch and fold."""
from __future__ import annotations

from erikslund_pool.merkle import merkle_branch
from erikslund_pool.merkle import merkle_root
from erikslund_pool.tests.base import SoloPoolTestCase
from erikslund_pool.util import dsha256


class TestMerkle(SoloPoolTestCase):
    def setUp(self):
        self.cb = dsha256(b"coinbase")
        self.t1 = dsha256(b"tx1")
        self.t2 = dsha256(b"tx2")
        self.t3 = dsha256(b"tx3")

    def test_no_transactions(self):
        # Coinbase-only block: empty branch, root is just the coinbase txid.
        self.assertEqual(merkle_branch([]), [])
        self.assertEqual(merkle_root(self.cb, []), self.cb)

    def test_single_transaction(self):
        branch = merkle_branch([self.t1])
        self.assertEqual(branch, [self.t1])
        self.assertEqual(merkle_root(self.cb, branch), dsha256(self.cb + self.t1))

    def test_two_transactions_odd_duplication(self):
        # Odd level [cb, t1, t2] duplicates t2; branch = [t1, dSHA(t2|t2)].
        branch = merkle_branch([self.t1, self.t2])
        self.assertEqual(branch[0], self.t1)
        self.assertEqual(branch[1], dsha256(self.t2 + self.t2))
        expect = dsha256(dsha256(self.cb + self.t1) + dsha256(self.t2 + self.t2))
        self.assertEqual(merkle_root(self.cb, branch), expect)

    def test_three_transactions(self):
        branch = merkle_branch([self.t1, self.t2, self.t3])
        # Fold must reproduce a hand-rolled root over [cb, t1, t2, t3].
        lvl = [self.cb, self.t1, self.t2, self.t3]
        while len(lvl) > 1:
            if len(lvl) % 2:
                lvl.append(lvl[-1])
            lvl = [dsha256(lvl[i] + lvl[i + 1]) for i in range(0, len(lvl), 2)]
        self.assertEqual(merkle_root(self.cb, branch), lvl[0])
