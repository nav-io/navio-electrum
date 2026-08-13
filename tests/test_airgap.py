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

    def test_watch_wallet_cannot_sign(self):
        full, watch = self._make_wallets()
        dest = full.keyring.address(0, 5)
        proposal = watch.make_send_proposal([(dest, 1_0000_0000, '')])
        with self.assertRaises(UserFacingException):
            watch.sign_airgap_proposal(proposal)
