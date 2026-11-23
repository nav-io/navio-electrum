import math
import unittest

from electrum import blsct_privacy as bp
from electrum.util import NotEnoughFunds


class TestPrivacyScore(unittest.TestCase):

    def test_no_own_inputs_is_zero(self):
        # plain receive, staking reward, coinbase: the sender knows the coin
        self.assertEqual(bp.privacy_mbits(0, []), 0)
        self.assertEqual(bp.privacy_mbits(5, []), 0)

    def test_zero_foreign_keeps_min(self):
        # our own send's change
        self.assertEqual(bp.privacy_mbits(0, [2500]), 2500)
        self.assertEqual(bp.privacy_mbits(0, [0]), 0)

    def test_min_of_several_own_inputs(self):
        self.assertEqual(bp.privacy_mbits(0, [3000, 1585, 7000]), 1585)
        self.assertEqual(bp.privacy_mbits(3, [3000, 1585, 7000]), 2000 + 1585)

    def test_unknown_input_makes_unknown(self):
        self.assertIsNone(bp.privacy_mbits(0, [None]))
        self.assertIsNone(bp.privacy_mbits(4, [1000, None]))

    def test_aggregates_with_n_foreign_inputs(self):
        for n in range(0, 40):
            self.assertEqual(bp.privacy_mbits(n, [0]), round(1000 * math.log2(n + 1)))
        self.assertEqual(bp.privacy_mbits(1, [0]), 1000)
        self.assertEqual(bp.privacy_mbits(2, [0]), 1585)   # log2(3) = 1.58496
        self.assertEqual(bp.privacy_mbits(7, [500]), 3500)
        self.assertEqual(bp.privacy_mbits(9, [0]), 3322)   # log2(10) = 3.32193

    def test_mixing_rounds_accumulate(self):
        # a served cover's returned coin: log2(foreign + 1) + our coin's score
        s = 0
        for _ in range(3):
            s = bp.privacy_mbits(3, [s])
        self.assertEqual(s, 6000)

    def test_negative_foreign_rejected(self):
        with self.assertRaises(ValueError):
            bp.privacy_mbits(-1, [0])

    def test_score_for_inputs(self):
        outs = {'a': {'privacy_mbits': 2000}, 'b': {'privacy_mbits': 1000}, 'c': {}}
        self.assertEqual(bp.score_for_inputs([], outs), 0)
        self.assertEqual(bp.score_for_inputs(['x', 'y'], outs), 0)
        self.assertEqual(bp.score_for_inputs(['a', 'b'], outs), 1000)
        self.assertEqual(bp.score_for_inputs(['a', 'x', 'y', 'z'], outs), 4000)
        self.assertIsNone(bp.score_for_inputs(['a', 'c', 'x'], outs))

    def test_display_and_helpers(self):
        self.assertEqual(bp.format_bits(None), '–')
        self.assertEqual(bp.format_bits(1585), '1.58')   # 1.585 is 1.58499.. as a float
        self.assertEqual(bp.format_bits(3322), '3.32')
        self.assertEqual(bp.format_bits(0), '0.00')
        self.assertEqual(bp.bits_to_mbits(1.5), 1500)
        self.assertIsNone(bp.bits_to_mbits(None))
        self.assertEqual(bp.bucket(None), bp.UNKNOWN_BUCKET)
        self.assertEqual(bp.bucket(999), 0)
        self.assertEqual(bp.bucket(1000), 1)
        self.assertEqual(bp.result_mbits([3000, 1200]), 1200)
        self.assertIsNone(bp.result_mbits([3000, None]))
        self.assertFalse(bp.spread_exceeds([1000, 2000]))
        self.assertTrue(bp.spread_exceeds([1000, 2001]))
        self.assertFalse(bp.spread_exceeds([None, 5000]))

    def test_not_enough_private_funds_is_not_enough_funds(self):
        e = bp.NotEnoughPrivateFunds(2.5)
        self.assertIsInstance(e, NotEnoughFunds)
        self.assertIn('>= 2.5 bits', str(e))


def _greedy(need):
    def g(coins):
        sel, amt = [], 0
        for c in coins:
            if amt >= need:
                break
            sel.append(c)
            amt += c[1]
        return sel if amt >= need else None
    return g


def _mbits(c):
    return c[2]


class TestSelectByPrivacy(unittest.TestCase):
    # (name, amount, mbits), in the existing preference order
    COINS = [('big_hi', 50, 4200), ('mid_lo', 30, 300), ('mid_unk', 20, None),
             ('small_lo', 10, 800), ('small_hi', 5, 4900)]

    def names(self, sel):
        return None if sel is None else [c[0] for c in sel]

    def test_lowest_bucket_that_pays(self):
        # unknown (20) cannot pay 25; bucket 0 (30 + 10) can
        sel = bp.select_by_privacy(self.COINS, _greedy(25), _mbits)
        self.assertEqual(self.names(sel), ['mid_lo'])

    def test_unknown_bucket_used_first(self):
        sel = bp.select_by_privacy(self.COINS, _greedy(15), _mbits)
        self.assertEqual(self.names(sel), ['mid_unk'])

    def test_falls_back_across_buckets(self):
        # no single bucket holds 100: existing selection over all coins
        sel = bp.select_by_privacy(self.COINS, _greedy(100), _mbits)
        self.assertEqual(self.names(sel), ['big_hi', 'mid_lo', 'mid_unk'])

    def test_not_enough_at_all(self):
        self.assertIsNone(bp.select_by_privacy(self.COINS, _greedy(1000), _mbits))

    def test_min_floor_excludes_low_and_unknown(self):
        sel = bp.select_by_privacy(self.COINS, _greedy(52), _mbits, min_mbits=4000)
        self.assertEqual(self.names(sel), ['big_hi', 'small_hi'])
        self.assertIsNone(bp.select_by_privacy(self.COINS, _greedy(60), _mbits, min_mbits=4000))
        # a floor of 0 still drops unknown scores
        sel = bp.select_by_privacy(self.COINS, _greedy(110), _mbits, min_mbits=0)
        self.assertIsNone(sel)

    def test_single_bucket_is_plain_greedy(self):
        coins = [('a', 5, 1000), ('b', 5, 1999)]
        self.assertEqual(self.names(bp.select_by_privacy(coins, _greedy(7), _mbits)), ['a', 'b'])
