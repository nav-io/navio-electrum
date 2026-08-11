import asyncio
import threading
from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QVariant

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import get_asyncio_loop, UserFacingException

from .auth import AuthMixin, auth_protect
from .qewallet import QEWallet
from .qetypes import QEAmount


class QEStaking(AuthMixin, QObject):
    """Staking backend for Navio BLSCT wallets: list staked outputs and
    build/broadcast stake and unstake transactions."""
    _logger = get_logger(__name__)

    stakedOutputsChanged = pyqtSignal()
    busyChanged = pyqtSignal()
    stakingSuccess = pyqtSignal([str, str], arguments=['message', 'txid'])
    stakingFailed = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)
        self._wallet = None  # type: Optional[QEWallet]
        self._busy = False
        self._staked_balance = QEAmount()
        self._spendable_balance = QEAmount()
        self._pending = None  # (make_tx, success_message)

    walletChanged = pyqtSignal()
    @pyqtProperty(QVariant, notify=walletChanged)
    def wallet(self) -> QEWallet:
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        assert wallet is None or isinstance(wallet, QEWallet)
        if self._wallet != wallet:
            self._wallet = wallet
            self.walletChanged.emit()
            self.stakedOutputsChanged.emit()

    @pyqtProperty('QVariantList', notify=stakedOutputsChanged)
    def stakedOutputs(self):
        if not self._wallet:
            return []
        result = []
        for u in self._wallet.wallet.get_staked_outputs():
            d = u.d
            deleg = d.get('delegation') or {}
            result.append({
                'amount': d['amount'],
                'delegate_key': deleg.get('delegate_key', ''),
                'reward_address': deleg.get('reward_address', ''),
                'height': d.get('height', 0),
                'output_hash': u.output_hash,
            })
        return result

    @pyqtProperty('QVariantList', notify=stakedOutputsChanged)
    def unstakeGroups(self):
        if not self._wallet:
            return []
        groups = {}
        for u in self._wallet.wallet.get_staked_outputs():
            if u.d.get('height', 0) <= 0:
                continue
            deleg = u.d.get('delegation') or {}
            key = deleg.get('delegate_key', '')
            groups.setdefault(key, 0)
            groups[key] += u.d['amount']
        return [
            {'key': k, 'amount': groups[k]}
            for k in sorted(groups, key=lambda k: (k != '', k))
        ]

    @pyqtProperty(QEAmount, notify=stakedOutputsChanged)
    def stakedBalance(self):
        sats = self._wallet.wallet.get_staked_balance_sat() if self._wallet else 0
        self._staked_balance.satsInt = sats
        return self._staked_balance

    @pyqtProperty(QEAmount, notify=stakedOutputsChanged)
    def spendableBalance(self):
        sats = self._wallet.wallet.get_spendable_balance_sat() if self._wallet else 0
        self._spendable_balance.satsInt = sats
        return self._spendable_balance

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    def set_busy(self, busy: bool):
        if self._busy != busy:
            self._busy = busy
            self.busyChanged.emit()

    @pyqtSlot()
    def updateList(self):
        self.stakedOutputsChanged.emit()

    @pyqtSlot(QEAmount, str, str)
    def stake(self, amount: QEAmount, delegate_key: str, reward_address: str):
        if self._busy:
            return
        amount_sats = amount.satsInt
        if amount_sats <= 0:
            self.stakingFailed.emit(_('Invalid amount'))
            return
        delegate_key = delegate_key.strip() or None
        reward_address = reward_address.strip() or None
        if reward_address and not delegate_key:
            self.stakingFailed.emit(_('A reward address requires an operator delegation key'))
            return

        wallet = self._wallet.wallet

        def make_tx(password):
            return wallet.create_stake_transaction(
                amount_sats, password=password,
                delegate_key_hex=delegate_key,
                reward_address=reward_address)

        self._pending = (make_tx, _('Stake transaction broadcast.'))
        self._do_broadcast()

    @pyqtSlot(QEAmount, str)
    def unstake(self, amount: QEAmount, delegate_key: str):
        if self._busy:
            return
        amount_sats = amount.satsInt or None  # empty = all

        wallet = self._wallet.wallet

        def make_tx(password):
            return wallet.create_unstake_transaction(
                amount_sats, password=password,
                delegate_key_hex=delegate_key or None)

        self._pending = (make_tx, _('Unstake transaction broadcast.'))
        self._do_broadcast()

    @auth_protect(message=_('Sign staking transaction?'))
    def _do_broadcast(self):
        make_tx, success_message = self._pending
        self._pending = None
        self.set_busy(True)

        wallet = self._wallet.wallet
        password = self._wallet.password
        qewallet = self._wallet

        def task():
            try:
                built = make_tx(password)
                coro = wallet.broadcast_blsct_transaction(built.raw_hex)
                fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
                txid = fut.result(timeout=60)
            except UserFacingException as e:
                self._logger.error(f'staking tx failed: {e!r}')
                self.stakingFailed.emit(str(e))
            except Exception as e:
                self._logger.exception('staking tx failed')
                self.stakingFailed.emit(str(e) or repr(e))
            else:
                self.stakingSuccess.emit(success_message, txid)
                qewallet.historyModel.requestRefresh.emit()  # via qt thread
            finally:
                self.set_busy(False)
                self.stakedOutputsChanged.emit()

        threading.Thread(target=task, daemon=True).start()
