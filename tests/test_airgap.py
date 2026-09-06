import copy
import os
import random
import tempfile
import unittest

from electrum import util
from electrum.airgap import (cbor_encode, cbor_decode, payload_to_fragments,
                             FragmentCollector, parse_fragment)
from electrum.simple_config import SimpleConfig
from electrum.util import UserFacingException

from . import ElectrumTestCase


class TestCbor(unittest.TestCase):

    def test_roundtrip(self):
        cases = [0, 1, -1, 23, 24, 255, 65536, 2**40, -500,
                 b'', b'\x00' * 64, 'text', '', True, False, None,
                 [1, b'x', 'y', None, [2, 3]],
                 {'a': 1, 'b': [b'z', {'c': False}], 'z': None}]
        for obj in cases:
            self.assertEqual(cbor_decode(cbor_encode(obj)), obj)

    def test_truncated(self):
        raw = cbor_encode({'k': b'\x01' * 100})
        with self.assertRaises(ValueError):
            cbor_decode(raw[:-5])


class TestFragments(unittest.TestCase):

    PAYLOAD = {'v': 1, 't': 'prop', 'net': b'\x01' * 32, 'fp': b'\x02' * 8,
               'ts': 1, 'ins': [[os.urandom(32), 10**8, os.urandom(32),
                                 os.urandom(48), 0, i, False, None]
                                for i in range(6)],
               'outs': [['nav1xyz', 5 * 10**7, 'memo', 'Normal', 0, None, None]],
               'fee': 400000, 'sub': False}

    def test_roundtrip_shuffled(self):
        frags = payload_to_fragments(self.PAYLOAD)
        self.assertGreater(len(frags), 1)
        collector = FragmentCollector()
        order = frags * 3
        random.shuffle(order)
        for f in order:
            collector.add(f)
        self.assertTrue(collector.is_complete())
        self.assertEqual(collector.payload(), self.PAYLOAD)

    def test_non_fragment_ignored(self):
        collector = FragmentCollector()
        self.assertFalse(collector.add('nav1notafragment'))
        self.assertIsNone(parse_fragment('bitcoin:xyz'))

    def test_new_message_resets(self):
        frags_a = payload_to_fragments(self.PAYLOAD)
        other = dict(self.PAYLOAD, ts=2)
        frags_b = payload_to_fragments(other)
        collector = FragmentCollector()
        collector.add(frags_a[0])
        for f in frags_b:
            collector.add(f)
        self.assertTrue(collector.is_complete())
        self.assertEqual(collector.payload(), other)


class TestAirgapFlow(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def _make_wallets(self):
        from electrum.blsct_wallet import restore_blsct_wallet_from_text
        full = restore_blsct_wallet_from_text(
            'ab' * 32, path=os.path.join(self.electrum_path, 'full'),
            config=self.config)['wallet']
        watch = restore_blsct_wallet_from_text(
            full.get_view_key_str(),
            path=os.path.join(self.electrum_path, 'watch'),
            config=self.config)['wallet']
        # fund with structurally valid outputs
        bk = full.keyring.spend_pub.serialize()
        for i, oh in enumerate(['11' * 32, '22' * 32]):
            d = {'tx_hash': 'aa' * 32, 'height': 100 + i,
                 'amount': 5_0000_0000,
                 'gamma': format(12345 + i, '064x'),
                 'blinding_key': bk, 'account': 0, 'addr_index': i,
                 'address': watch.get_receiving_addresses()[i], 'memo': '',
                 'token_id': None, 'staked': False, 'delegation': None,
                 'spent_by': None, 'spent_height': None}
            watch.blsct_outputs[oh] = dict(d)
            full.blsct_outputs[oh] = dict(d)
        return full, watch

    def test_send_roundtrip(self):
        full, watch = self._make_wallets()
        dest = full.keyring.address(0, 5)
        proposal = watch.make_send_proposal([(dest, 3_0000_0000, 'hi')])
        # over the air
        collector = FragmentCollector()
        for f in payload_to_fragments(proposal):
            collector.add(f)
        scanned = collector.payload()
        # offline: verify + summarize
        summary = full.check_airgap_proposal(scanned)
        self.assertEqual(len(summary['outputs']), 1)
        self.assertEqual(summary['outputs'][0]['amount'], 3_0000_0000)
        self.assertTrue(summary['outputs'][0]['is_mine'])  # paying own addr
        self.assertGreater(summary['fee'], 0)
        # offline: sign
        reply = full.sign_airgap_proposal(scanned)
        collector2 = FragmentCollector()
        for f in payload_to_fragments(reply):
            collector2.add(f)
        txid, raw_hex = watch.check_airgap_reply(collector2.payload())
        self.assertEqual(len(txid), 64)
        self.assertGreater(len(raw_hex), 1000)

    def test_envelope_rejections(self):
        full, watch = self._make_wallets()
        dest = full.keyring.address(0, 5)
        proposal = watch.make_send_proposal([(dest, 1_0000_0000, '')])
        bad_fp = copy.deepcopy(proposal)
        bad_fp['fp'] = b'\x00' * 8
        with self.assertRaises(UserFacingException):
            full.check_airgap_proposal(bad_fp)
        bad_net = copy.deepcopy(proposal)
        bad_net['net'] = b'\x00' * 32
        with self.assertRaises(UserFacingException):
            full.check_airgap_proposal(bad_net)
        bad_type = copy.deepcopy(proposal)
        bad_type['t'] = 'signed'
        with self.assertRaises(UserFacingException):
            full.check_airgap_proposal(bad_type)
        dup = copy.deepcopy(proposal)
        dup['ins'] = dup['ins'] + [dup['ins'][0]]
        with self.assertRaises(UserFacingException):
            full.check_airgap_proposal(dup)

    def test_hostile_proposal_structures_rejected(self):
        """A compromised online device knows the fingerprint, so payloads
        passing the envelope check must still be structurally validated."""
        full, watch = self._make_wallets()
        dest = full.keyring.address(0, 5)
        base = watch.make_send_proposal([(dest, 1_0000_0000, '')])
        mutations = [
            lambda p: p['ins'][0].__setitem__(5, 2**40),   # keypool DoS
            lambda p: p['ins'][0].__setitem__(4, 'x'),
            lambda p: p['ins'].__setitem__(0, p['ins'][0][:5]),
            lambda p: p['ins'].__setitem__(0, 7),
            lambda p: p['ins'][0].__setitem__(2, 7),
            lambda p: p['outs'][0].__setitem__(5, 7),
            lambda p: p['outs'][0].__setitem__(1, -5),
            lambda p: p['outs'][0].__setitem__(2, 9),
        ]
        for mut in mutations:
            p = copy.deepcopy(base)
            mut(p)
            with self.assertRaises(UserFacingException):
                full.check_airgap_proposal(p)

    def test_collector_inconsistent_totals(self):
        c = FragmentCollector()
        c.add('NAV-AG/1/abcd1234/1/3/AAAA')
        c.add('NAV-AG/1/abcd1234/2/10/BBBB')
        self.assertFalse(c.is_complete())

    def test_change_and_staking_inputs_accepted(self):
        """Real wallets spend change (account -1) and unstaked
        (account -2) outputs; validation must not reject them
        (regression: v4.9.1 hardening only allowed account >= 0)."""
        full, watch = self._make_wallets()
        bk = full.keyring.spend_pub.serialize()
        for i, (oh, acct) in enumerate([('44' * 32, -1), ('55' * 32, -2)]):
            addr = full.keyring.address(acct, i)
            d = {'tx_hash': 'bb' * 32, 'height': 200 + i,
                 'amount': 5_0000_0000,
                 'gamma': format(777 + i, '064x'), 'blinding_key': bk,
                 'account': acct, 'addr_index': i, 'address': addr,
                 'memo': '', 'token_id': None, 'staked': False,
                 'delegation': None, 'spent_by': None, 'spent_height': None}
            watch.blsct_outputs[oh] = dict(d)
            full.blsct_outputs[oh] = dict(d)
        # spend enough that the change/staking outputs must be selected
        dest = full.keyring.address(0, 5)
        proposal = watch.make_send_proposal([(dest, 18_0000_0000, '')])
        accounts = {i[4] for i in proposal['ins']}
        self.assertTrue({-1, -2} & accounts, accounts)
        summary = full.check_airgap_proposal(proposal)
        self.assertEqual(len(summary['outputs']), 1)
        reply = full.sign_airgap_proposal(proposal)
        txid, raw_hex = watch.check_airgap_reply(reply)
        self.assertEqual(len(txid), 64)

    def test_stable_output_hash_references(self):
        """BLSCT txids mutate when a block aggregates transactions, so
        history items must be referenced by destination output hash."""
        full, watch = self._make_wallets()
        dest = full.keyring.address(0, 9)
        built = full.create_blsct_transaction([(dest, 2_0000_0000, '')])
        from electrum.navio_blsct import parse_tx_hex
        parsed = parse_tx_hex(built.raw_hex)
        ref = full.blsct_tx_reference(parsed)
        self.assertTrue(ref and len(ref) == 64)
        full.process_own_transaction(built.raw_hex, built.txid)
        items = full.get_history_items()
        # the outgoing event is referenced by the destination output hash,
        # not by the (mutable) txid
        ids = {it['txid'] for it in items}
        self.assertIn(ref, ids)
        # simulate the block scan seeing the tx under an aggregated hash
        for oh, d in full.blsct_outputs.items():
            if d.get('spent_by') == built.txid:
                full._mark_spent(oh, 'ff' * 32, 500, ref='99' * 32)
        items2 = full.get_history_items()
        ids2 = {it['txid'] for it in items2}
        # the reference recorded at broadcast survives the txid mutation
        self.assertIn(ref, ids2)
        self.assertNotIn('99' * 32, ids2)

    def test_incoming_referenced_by_output_hash(self):
        full, watch = self._make_wallets()
        items = watch.get_history_items()
        # funded outputs share tx 'aa'*32; the item must reference one of
        # the received output hashes, not the funding txid
        self.assertEqual(len(items), 1)
        self.assertIn(items[0]['txid'], ('11' * 32, '22' * 32))

    def test_multi_token_registry(self):
        full, _watch = self._make_wallets()
        kr = full.keyring
        k1 = kr.token_key_for({'name': 'Alpha'}, 1000)
        k1b = kr.token_key_for({'name': 'Alpha'}, 1000)
        k2 = kr.token_key_for({'name': 'Beta'}, 1000)
        k3 = kr.token_key_for({'name': 'Alpha'}, 2000)
        self.assertEqual(k1.serialize(), k1b.serialize())
        self.assertNotEqual(k1.serialize(), k2.serialize())
        self.assertNotEqual(k1.serialize(), k3.serialize())
        self.assertNotEqual(k1.serialize(), kr.token_key.serialize())
        # create two tokens; both are registered independently
        full.create_token({'name': 'Alpha'}, 1000)
        full.create_token({'name': 'Beta'}, 500, is_nft=True)
        tokens = full.get_created_tokens()
        self.assertEqual(len(tokens), 2)
        names = {(e['metadata'].get('name'), e['is_nft']) for e in tokens.values()}
        self.assertEqual(names, {('Alpha', False), ('Beta', True)})
        # selection by name works; ambiguity without a selector errors
        key, entry = full._resolve_created_token('beta')
        self.assertTrue(entry['is_nft'])
        with self.assertRaises(UserFacingException):
            full._resolve_created_token(None)
        with self.assertRaises(UserFacingException):
            full._resolve_created_token('nope')
        # mint against a selected token builds successfully
        dest = full.keyring.address(0, 3)
        built = full.mint_token(dest, 10, token='alpha')
        self.assertTrue(built.raw_hex)

    def test_birthday_mnemonic(self):
        """26-word Navio mnemonic: 24 BIP39 words + birthday + check word.
        Same keys as the 24-word base; restore learns the scan height."""
        import time
        from electrum.navio_blsct import (birthday_mnemonic_from_entropy,
                                          parse_birthday_mnemonic,
                                          is_birthday_mnemonic,
                                          BIRTHDAY_EPOCH, BIRTHDAY_WEEK)
        ent = bytes(range(32))
        ts = 1783000000
        m = birthday_mnemonic_from_entropy(ent, ts)
        self.assertEqual(len(m.split()), 26)
        base, ent2, birthday = parse_birthday_mnemonic(m)
        self.assertEqual(ent2, ent)
        self.assertEqual(len(base.split()), 24)
        # birthday floors to the week; never later than the true time
        self.assertLessEqual(birthday, ts)
        self.assertLess(ts - birthday, BIRTHDAY_WEEK)
        self.assertEqual((birthday - BIRTHDAY_EPOCH) % BIRTHDAY_WEEK, 0)
        self.assertTrue(is_birthday_mnemonic(m))
        self.assertFalse(is_birthday_mnemonic(base))
        # legacy 24 words parse with no birthday
        self.assertIsNone(parse_birthday_mnemonic(base)[2])
        # tampering with either extra word is detected
        for i in (24, 25):
            bad = m.split()
            bad[i] = 'abandon' if bad[i] != 'abandon' else 'ability'
            with self.assertRaises(ValueError):
                parse_birthday_mnemonic(' '.join(bad))
        # a different seed with the same birthday words is rejected
        m_other = birthday_mnemonic_from_entropy(bytes(range(1, 33)), ts)
        mixed = ' '.join(base.split() + m_other.split()[24:])
        with self.assertRaises(ValueError):
            parse_birthday_mnemonic(mixed)

    def test_birthday_mnemonic_restore_sets_height(self):
        import time
        from electrum.navio_blsct import birthday_mnemonic_from_entropy
        from electrum.blsct_wallet import (restore_blsct_wallet_from_text,
                                           estimate_height_for_timestamp)
        ts = int(time.time())
        m = birthday_mnemonic_from_entropy(os.urandom(32), ts)
        w = restore_blsct_wallet_from_text(
            m, path=os.path.join(self.electrum_path, 'bday'),
            config=self.config)['wallet']
        h = w.blsct_sync.get('creation_height')
        self.assertGreater(h, 0)
        self.assertLessEqual(h, estimate_height_for_timestamp(ts))
        # full 26-word phrase preserved for backup display
        self.assertEqual(len(w.keystore.get_mnemonic(None).split()), 26)
        # keys identical to the 24-word base restore
        base = ' '.join(m.split()[:24])
        w2 = restore_blsct_wallet_from_text(
            base, path=os.path.join(self.electrum_path, 'bday2'),
            config=self.config)['wallet']
        self.assertEqual(w.get_view_key_str(), w2.get_view_key_str())

    def test_watch_wallet_cannot_sign(self):
        full, watch = self._make_wallets()
        dest = full.keyring.address(0, 5)
        proposal = watch.make_send_proposal([(dest, 1_0000_0000, '')])
        with self.assertRaises(UserFacingException):
            watch.sign_airgap_proposal(proposal)


class TestBlsctHistoryRewardSplit(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def _wallet(self):
        from electrum.blsct_wallet import restore_blsct_wallet_from_text
        return restore_blsct_wallet_from_text(
            'cd' * 32, path=os.path.join(self.electrum_path, 'w'),
            config=self.config)['wallet']

    def _out(self, w, i, amount, memo, tx_hash, height=500, spent_by=None,
             spent_ref=None):
        return {'tx_hash': tx_hash, 'height': height, 'amount': amount,
                'gamma': format(777 + i, '064x'),
                'blinding_key': w.keyring.spend_pub.serialize(),
                'account': 0, 'addr_index': i,
                'address': w.get_receiving_addresses()[i], 'memo': memo,
                'token_id': None, 'staked': False, 'delegation': None,
                'spent_by': spent_by, 'spent_height': height if spent_by else None,
                'spent_ref': spent_ref}

    def test_reward_is_its_own_item_in_aggregated_tx(self):
        """A block aggregates the reward with our other outputs under one
        txid: the reward must still be a separate history item."""
        w = self._wallet()
        agg = 'ee' * 32
        # funding output spent by the aggregated tx (our own send + change)
        w.blsct_outputs['11' * 32] = self._out(
            w, 0, 5_0000_0000, '', 'aa' * 32, height=100,
            spent_by=agg, spent_ref='33' * 32)
        w.blsct_outputs['22' * 32] = self._out(w, 1, 4_9500_0000, 'Change', agg)
        w.blsct_outputs['33' * 32] = self._out(w, 2, 8_0000_0000, 'Reward', agg)
        items = {it['txid']: it for it in w.get_history_items()}
        self.assertEqual(len(items), 3, items)
        reward = items['33' * 32]
        self.assertEqual(reward['amount_sat'], 8_0000_0000)
        self.assertEqual(reward['memos'], ['Reward'])
        rest = [it for k, it in items.items() if k not in ('33' * 32, '11' * 32)]
        self.assertEqual(len(rest), 1)
        self.assertEqual(rest[0]['amount_sat'], -500_0000)
        self.assertEqual(rest[0]['memos'], ['Change'])
        # spent_ref collided with the reward's hash: the rest item still
        # gets a distinct, stable reference
        self.assertEqual(rest[0]['txid'], '22' * 32)
        # the wallet view keys by reference, so both rows survive
        full = w.get_full_history()
        self.assertIn('33' * 32, full)
        self.assertIn('22' * 32, full)

    def test_plain_reward_unchanged(self):
        w = self._wallet()
        w.blsct_outputs['44' * 32] = self._out(w, 0, 8_0000_0000, 'Reward', 'bb' * 32)
        items = w.get_history_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]['txid'], '44' * 32)
        self.assertEqual(items[0]['amount_sat'], 8_0000_0000)


class TestBlsctCoinbaseMaturity(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def _wallet(self):
        from electrum.blsct_wallet import restore_blsct_wallet_from_text
        w = restore_blsct_wallet_from_text(
            'ef' * 32, path=os.path.join(self.electrum_path, 'w'),
            config=self.config)['wallet']

        class FakeNetwork:
            def __init__(self, h):
                self.h = h

            def get_local_height(self):
                return self.h
        w.network = FakeNetwork(1000)
        return w

    def _out(self, w, i, amount, memo, height, coinbase=None):
        d = {'tx_hash': format(i, '064x'), 'height': height, 'amount': amount,
             'gamma': format(999 + i, '064x'),
             'blinding_key': w.keyring.spend_pub.serialize(),
             'account': 0, 'addr_index': i,
             'address': w.get_receiving_addresses()[i], 'memo': memo,
             'token_id': None, 'staked': False, 'delegation': None,
             'spent_by': None, 'spent_height': None}
        if coinbase is not None:
            d['coinbase'] = coinbase
        return d

    def test_immature_coinbase_not_spendable(self):
        from electrum.bitcoin import COINBASE_MATURITY
        w = self._wallet()
        tip = w.network.get_local_height()
        # depth 99 at the next block: still immature
        w.blsct_outputs['a1' * 32] = self._out(
            w, 0, 8_0000_0000, 'Reward', tip + 1 - (COINBASE_MATURITY - 1), coinbase=True)
        # depth 100 at the next block: mature
        w.blsct_outputs['a2' * 32] = self._out(
            w, 1, 8_0000_0000, 'Reward', tip + 1 - COINBASE_MATURITY, coinbase=True)
        # legacy record without the flag: recognised by the memo
        w.blsct_outputs['a3' * 32] = self._out(w, 2, 8_0000_0000, 'Reward', tip)
        # plain payment at the tip: spendable
        w.blsct_outputs['a4' * 32] = self._out(w, 3, 1_0000_0000, '', tip, coinbase=False)
        spendable = {c.output_hash for c in w.get_spendable_coins()}
        self.assertEqual(spendable, {'a2' * 32, 'a4' * 32})
        confirmed, unconfirmed, unmatured = w.get_balance()
        self.assertEqual(confirmed, 9_0000_0000)
        self.assertEqual(unconfirmed, 0)
        self.assertEqual(unmatured, 16_0000_0000)
        p_bal = w.get_balances_for_piechart()
        self.assertEqual(p_bal.unmatured, 16_0000_0000)
        self.assertEqual(p_bal.total(), 25_0000_0000)

    def test_staked_split_in_piechart(self):
        w = self._wallet()
        tip = w.network.get_local_height()
        w.blsct_outputs['b1' * 32] = self._out(w, 0, 3_0000_0000, '', tip - 5)
        d = self._out(w, 1, 7_0000_0000, '', tip - 5)
        d['staked'] = True
        w.blsct_outputs['b2' * 32] = d
        p_bal = w.get_balances_for_piechart()
        self.assertEqual(p_bal.staked, 7_0000_0000)
        self.assertEqual(p_bal.confirmed, 3_0000_0000)
        self.assertEqual(p_bal.total(), 10_0000_0000)
