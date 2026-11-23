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
        # floor(1000 * log2(n + 1)), like navio-core's Log2MilliBits
        for n in range(0, 2000):
            self.assertEqual(bp.privacy_mbits(n, [0]), math.floor(1000 * math.log2(n + 1)))
        self.assertEqual(bp.privacy_mbits(1, [0]), 1000)
        self.assertEqual(bp.privacy_mbits(2, [0]), 1584)   # log2(3) = 1.58496
        self.assertEqual(bp.privacy_mbits(7, [500]), 3500)
        self.assertEqual(bp.privacy_mbits(9, [0]), 3321)   # log2(10) = 3.32193

    def test_log2_mbits(self):
        self.assertEqual(bp.log2_mbits(1), 0)
        self.assertEqual(bp.log2_mbits(2 ** 40), 40000)
        self.assertEqual(bp.log2_mbits(2 ** 40 + 1), 40000)
        self.assertEqual(bp.log2_mbits(2 ** 40 - 1), 39999)
        with self.assertRaises(ValueError):
            bp.log2_mbits(0)

    def test_saturates(self):
        self.assertEqual(bp.privacy_mbits(3, [bp.MBITS_MAX - 1]), bp.MBITS_MAX)
        self.assertEqual(bp.privacy_mbits(0, [2 ** 40]), bp.MBITS_MAX)

    def test_mixing_rounds_accumulate(self):
        # a served cover's returned coin: log2(foreign + 1) + our coin's score
        s = 0
        for _ in range(3):
            s = bp.privacy_mbits(3, [s])
        self.assertEqual(s, 6000)

    def test_output_made_by_us_rule(self):
        # no foreign inputs: every output of ours takes the tx score
        self.assertEqual(bp.output_mbits(2500, 0, False), 2500)
        # foreign inputs: only change / a cover return keeps it
        self.assertEqual(bp.output_mbits(2500, 3, True), 2500)
        self.assertEqual(bp.output_mbits(2500, 3, False), 0)
        self.assertEqual(bp.output_mbits(None, 3, False), 0)
        self.assertIsNone(bp.output_mbits(None, 3, True))

    def test_negative_foreign_rejected(self):
        with self.assertRaises(ValueError):
            bp.privacy_mbits(-1, [0])

    def test_tx_privacy_score(self):
        outs = {'a': {'privacy_mbits': 2000}, 'b': {'privacy_mbits': 1000}, 'c': {}}
        tx = lambda ins, created=(): bp.TxPrivacy(ins, outs, created).tx_mbits
        self.assertEqual(tx([]), 0)
        self.assertEqual(tx(['x', 'y']), 0)
        self.assertEqual(tx(['a', 'b']), 1000)
        self.assertEqual(tx(['a', 'x', 'y', 'z']), 4000)
        self.assertIsNone(tx(['a', 'c', 'x']))
        # an input spending an output of the same (merged block) tx is
        # neither own nor foreign
        self.assertEqual(tx(['a', 'x', 'm1'], created=['m1', 'm2']), 3000)

    def test_tx_privacy_outputs(self):
        outs = {'mine': {'privacy_mbits': 2000, 'address': 'A', 'amount': 5},
                'tok': {'privacy_mbits': 2000, 'address': 'A', 'amount': 7, 'token_id': 'ff'}}
        ctx = bp.TxPrivacy(['mine', 'tok', 'x', 'y', 'z'], outs)
        self.assertEqual(ctx.tx_mbits, 4000)
        kw = dict(is_change=False, memo='candidate', address='A', amount=5, token_id=None)
        # paid to us by a foreign input's owner: 0
        self.assertEqual(ctx.score_output(**dict(kw, memo='hi')), 0)
        # change keeps the tx score
        self.assertEqual(ctx.score_output(**dict(kw, is_change=True, memo='')), 4000)
        # token outputs and wrong amounts are no cover return
        self.assertEqual(ctx.score_output(**dict(kw, amount=7)), 0)
        self.assertEqual(ctx.score_output(**dict(kw, token_id='ff')), 0)
        # the cover return of our spent NAV coin matches once
        self.assertEqual(ctx.score_output(**kw), 4000)
        self.assertEqual(ctx.score_output(**kw), 0)

    def test_display_and_helpers(self):
        self.assertEqual(bp.format_bits(None), '–')
        self.assertEqual(bp.format_bits(1585), '1.58')   # 1.585 is 1.58499.. as a float
        self.assertEqual(bp.format_bits(None), '\u2013')
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


try:
    from electrum import navio_blsct as nb
    nb.get_blsct()
    HAVE_BLSCT = True
except Exception:
    HAVE_BLSCT = False

import os

from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestWalletPrivacySelection(ElectrumTestCase):
    # output hash -> (amount in NAV, privacy mbits or None)
    COINS = {'11' * 32: (5, 4200), '22' * 32: (3, 300), '33' * 32: (2, None),
             '44' * 32: (1, 800), '55' * 32: (4, 4900)}

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def _wallet(self):
        from electrum.blsct_wallet import restore_blsct_wallet_from_text
        w = restore_blsct_wallet_from_text(
            'ab' * 32, path=os.path.join(self.electrum_path, 'w'),
            config=self.config)['wallet']
        bk = w.keyring.spend_pub.serialize()
        for i, (oh, (nav, mbits)) in enumerate(self.COINS.items()):
            d = {'tx_hash': 'aa' * 32, 'height': 100 + i, 'amount': nav * 1_0000_0000,
                 'gamma': format(12345 + i, '064x'), 'blinding_key': bk,
                 'account': 0, 'addr_index': i,
                 'address': w.get_receiving_addresses()[i], 'memo': '',
                 'token_id': None, 'staked': False, 'delegation': None,
                 'spent_by': None, 'spent_height': None}
            if mbits is not None:
                d['privacy_mbits'] = mbits
            w.blsct_outputs[oh] = d
        return w

    def plan(self, w, nav, **kw):
        utxos, _recs, _fee = w._plan_send([(w.keyring.address(0, 9), int(nav * 1_0000_0000), '')], **kw)
        return sorted(u.output_hash[:2] for u in utxos)

    def test_prefers_lowest_bucket_that_pays(self):
        w = self._wallet()
        self.assertEqual(self.plan(w, 1.5), ['33'])          # unknown bucket (2 NAV)
        self.assertEqual(self.plan(w, 2.5), ['22'])          # bucket 0: 3 + 1 NAV
        self.assertEqual(self.plan(w, 3.5), ['22', '44'])
        self.assertEqual(self.plan(w, 8.5), ['11', '55'])    # bucket 4: 5 + 4 NAV
        # no bucket pays 12 NAV alone: the old order across all coins
        self.assertEqual(self.plan(w, 12), ['11', '22', '33', '55'])

    def test_min_privacy_floor(self):
        from electrum.blsct_privacy import NotEnoughPrivateFunds
        w = self._wallet()
        self.assertEqual(self.plan(w, 2.5, min_privacy=4), ['11'])
        with self.assertRaises(NotEnoughPrivateFunds) as ctx:
            self.plan(w, 10, min_privacy=4)
        self.assertIn('privacy score >= 4 bits', str(ctx.exception))
        # not enough funds at all: the plain error
        with self.assertRaises(NotEnoughFunds) as ctx:
            self.plan(w, 100, min_privacy=4)
        self.assertNotIsInstance(ctx.exception, NotEnoughPrivateFunds)
        self.assertEqual(
            sorted(c.output_hash[:2] for c in w.send_candidate_coins(min_privacy=0.5)),
            ['11', '44', '55'])

    def test_manual_selection_overrides_and_warns(self):
        w = self._wallet()
        manual = ['22' * 32, '55' * 32]
        # below the floor and across buckets: used as given
        self.assertEqual(self.plan(w, 6, domain_coins=manual, min_privacy=10), ['22', '55'])
        self.assertIn('0.30 to 4.90', w.privacy_mix_warning(manual))
        self.assertIsNone(w.privacy_mix_warning(['11' * 32, '55' * 32]))
        self.assertEqual(w.send_result_privacy_mbits(manual), 300)
        self.assertIsNone(w.send_result_privacy_mbits(['11' * 32, '33' * 32]))

    def test_own_send_change_and_listunspent(self):
        w = self._wallet()
        w.config.BLSCT_AGGREGATE_SENDS = False
        built = w.create_blsct_transaction([(w.keyring.address(0, 9), 8_0000_0000, '')])
        w.process_own_transaction(built.raw_hex, built.txid)
        new = [u for u in w.get_utxos() if u.d['tx_hash'] == built.txid]
        self.assertTrue(new)
        # spent 11 (4.2 bits) and 55 (4.9 bits), no foreign inputs
        self.assertTrue(all(u.privacy_mbits == 4200 for u in new))
        self.assertEqual(new[0].to_json()['privacy_bits'], 4.2)
        self.assertIsNone(w.blsct_outputs['33' * 32].get('privacy_mbits'))
        self.assertIsNone(
            [u for u in w.get_utxos() if u.output_hash == '33' * 32][0].to_json()['privacy_bits'])

    async def test_commands(self):
        from electrum.commands import Commands
        from electrum.blsct_privacy import NotEnoughPrivateFunds
        w = self._wallet()
        w.config.BLSCT_AGGREGATE_SENDS = False
        cmds = Commands(config=self.config)
        coins = {c['output_hash'][:2]: c for c in await cmds.listunspent(wallet=w)}
        self.assertEqual(coins['11']['privacy_bits'], 4.2)
        self.assertIsNone(coins['33']['privacy_bits'])
        dest = w.keyring.address(0, 9)
        with self.assertRaises(NotEnoughPrivateFunds):
            await cmds.payto(dest, '10', min_privacy='4', wallet=w)
        res = await cmds.payto(dest, '!', min_privacy='4', wallet=w)
        p = nb.parse_tx_hex(res['hex'])
        self.assertEqual({'11' * 32, '55' * 32}, {i.prevout_hash for i in p.inputs})
        res = await cmds.paytomany([[dest, '2.5']], min_privacy='4.5', wallet=w)
        self.assertEqual({'55' * 32}, {i.prevout_hash for i in nb.parse_tx_hex(res['hex']).inputs})
        self.assertEqual(await cmds.rescan(wallet=w), {'rescan_requested': True, 'unscored_coins': 1})
        self.assertTrue(w.blsct_sync['rescan_requested'])
