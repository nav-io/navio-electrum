import os
import threading
import time
import unittest

from electrum.simple_config import SimpleConfig

from tests import ElectrumTestCase

try:
    from electrum import navio_blsct as nb
    nb.get_blsct()
    HAVE_BLSCT = True
except Exception:
    HAVE_BLSCT = False


class _QEWalletStub:
    def __init__(self, wallet):
        self.wallet = wallet
        self.password = None


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestBlsctFinalizerPrivacy(ElectrumTestCase):
    COINS = {'11' * 32: (5, 4200), '22' * 32: (3, 300), '55' * 32: (4, 4900)}

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
            w.blsct_outputs[oh] = {
                'tx_hash': 'aa' * 32, 'height': 100 + i, 'amount': nav * 1_0000_0000,
                'gamma': format(12345 + i, '064x'), 'blinding_key': bk,
                'account': 0, 'addr_index': i,
                'address': w.get_receiving_addresses()[i], 'memo': '',
                'token_id': None, 'staked': False, 'delegation': None,
                'spent_by': None, 'spent_height': None, 'privacy_mbits': mbits}
        w.config.BLSCT_AGGREGATE_SENDS = False
        return w

    def _finalizer(self, w, *, max_amount=False, sats=1_0000_0000):
        from electrum.gui.qml.qeblsctfinalizer import QEBlsctFinalizer
        from electrum.gui.qml.qetypes import QEAmount
        f = QEBlsctFinalizer()
        f._wallet = _QEWalletStub(w)
        f._min_privacy = float(w.config.BLSCT_MIN_PRIVACY or 0)
        f._address = w.keyring.address(0, 9)
        f._amount = QEAmount(amount_sat=sats, is_max=max_amount)
        return f

    @staticmethod
    def _wait(f):
        for _ in range(600):
            if not f.busy and not f._update_pending:
                return
            time.sleep(0.05)
        raise AssertionError('finalizer still busy')

    def inputs(self, f):
        return {i.prevout_hash[:2] for i in nb.parse_tx_hex(f._built.raw_hex).inputs}

    def test_min_privacy_and_result_text(self):
        w = self._wallet()
        f = self._finalizer(w)
        f.doUpdate()
        self._wait(f)
        self.assertTrue(f.valid)
        self.assertEqual(self.inputs(f), {'22'})          # lowest bucket that pays
        self.assertEqual(f.privacyText, '0.30')
        f.minPrivacy = 4.5                                # rebuilds, persists
        self._wait(f)
        self.assertEqual(w.config.BLSCT_MIN_PRIVACY, 4.5)
        self.assertEqual(self.inputs(f), {'55'})
        self.assertEqual(f.privacyText, '4.90')
        f.minPrivacy = 16
        self._wait(f)
        self.assertFalse(f.valid)
        self.assertIn('privacy score >= 16 bits', f.warning)

    def test_max_uses_eligible_coins(self):
        w = self._wallet()
        w.config.BLSCT_MIN_PRIVACY = 4.0
        f = self._finalizer(w, max_amount=True)
        f.doUpdate()
        self._wait(f)
        self.assertTrue(f.valid)
        self.assertEqual(self.inputs(f), {'11', '55'})
        self.assertEqual(f.effectiveAmount.satsInt, 9_0000_0000 - f.fee.satsInt)

    def test_change_while_busy_reruns(self):
        w = self._wallet()
        f = self._finalizer(w)
        f.doUpdate()
        f.minPrivacy = 4.5     # arrives while the first build runs
        self._wait(f)
        self.assertEqual(self.inputs(f), {'55'})
