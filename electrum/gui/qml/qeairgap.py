import asyncio
import threading
from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QVariant

from electrum import airgap
from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import get_asyncio_loop, UserFacingException

from .auth import AuthMixin, auth_protect
from .qewallet import QEWallet


class QEAirgapRequest(QObject):
    """Online (watch-only) side: build a proposal, show its fragments,
    collect the signed reply, broadcast."""
    _logger = get_logger(__name__)

    fragmentsChanged = pyqtSignal()
    replyProgressChanged = pyqtSignal()
    proposalError = pyqtSignal([str], arguments=['message'])
    broadcastSuccess = pyqtSignal([str], arguments=['txid'])
    broadcastFailed = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)
        self._wallet = None  # type: Optional[QEWallet]
        self._fragments = []
        self._collector = airgap.FragmentCollector()

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

    @pyqtProperty('QVariantList', notify=fragmentsChanged)
    def fragments(self):
        return self._fragments

    def _set_proposal(self, make):
        try:
            payload = make()
            fragments = airgap.payload_to_fragments(payload)
        except Exception as e:
            if not isinstance(e, UserFacingException):
                self._logger.exception('could not build proposal')
            # clear any previous proposal so a caller that opens the sign
            # dialog anyway shows nothing signable instead of a stale one
            self._fragments = []
            self._collector = airgap.FragmentCollector()
            self.fragmentsChanged.emit()
            self.replyProgressChanged.emit()
            self.proposalError.emit(str(e) or repr(e))
            return
        self._fragments = fragments
        self._collector = airgap.FragmentCollector()
        self.fragmentsChanged.emit()
        self.replyProgressChanged.emit()

    @pyqtSlot(str, QVariant, str, bool)
    def makeSendProposal(self, address, amount, memo, is_max):
        w = self._wallet.wallet
        if is_max:
            amt = w.get_spendable_balance_sat()
            self._set_proposal(lambda: w.make_send_proposal(
                [(address, amt, memo)], subtract_fee_from_amount=True))
        else:
            self._set_proposal(lambda: w.make_send_proposal(
                [(address, amount.satsInt, memo)]))

    @pyqtSlot(QVariant, str, str)
    def makeStakeProposal(self, amount, delegate_key, reward_address):
        w = self._wallet.wallet
        self._set_proposal(lambda: w.make_stake_proposal(
            amount.satsInt,
            delegate_key_hex=delegate_key.strip() or None,
            reward_address=reward_address.strip() or None))

    @pyqtSlot(QVariant, str)
    def makeUnstakeProposal(self, amount, delegate_key):
        w = self._wallet.wallet
        self._set_proposal(lambda: w.make_unstake_proposal(
            amount.satsInt or None, delegate_key_hex=delegate_key or None))

    @pyqtSlot(str, str, str, str)
    def makeTokenSendProposal(self, token_id, address, amount_str, memo):
        w = self._wallet.wallet
        try:
            amount = int(amount_str)
        except ValueError:
            self.proposalError.emit(_('Invalid amount'))
            return
        self._set_proposal(lambda: w.make_token_send_proposal(
            token_id, [(address, amount, memo)]))

    # ---- signed-reply collection

    @pyqtProperty(int, notify=replyProgressChanged)
    def replyReceived(self):
        return self._collector.received

    @pyqtProperty(int, notify=replyProgressChanged)
    def replyTotal(self):
        return self._collector.total

    @pyqtSlot(str)
    def addReplyScan(self, text):
        if not self._collector.add(text):
            return
        self.replyProgressChanged.emit()
        if not self._collector.is_complete():
            return
        try:
            payload = self._collector.payload()
            txid, raw_hex = self._wallet.wallet.check_airgap_reply(payload)
        except Exception as e:
            self._logger.exception('bad signed reply')
            self._collector = airgap.FragmentCollector()
            self.replyProgressChanged.emit()
            self.broadcastFailed.emit(str(e) or repr(e))
            return
        self._broadcast(txid, raw_hex)

    def _broadcast(self, txid, raw_hex):
        wallet = self._wallet.wallet
        qewallet = self._wallet

        async def broadcast_coro():
            try:
                sent_txid = await wallet.broadcast_blsct_transaction(raw_hex)
            except Exception as e:
                self._logger.error(f'airgap broadcast failed: {e!r}')
                self.broadcastFailed.emit(str(e) or repr(e))
            else:
                self.broadcastSuccess.emit(sent_txid)
                qewallet.historyModel.requestRefresh.emit()

        asyncio.run_coroutine_threadsafe(broadcast_coro(), get_asyncio_loop())


class QEAirgapSigner(AuthMixin, QObject):
    """Offline (full wallet) side: collect a proposal, verify + summarize,
    sign after confirmation, show the reply fragments."""
    _logger = get_logger(__name__)

    progressChanged = pyqtSignal()
    proposalReady = pyqtSignal()
    proposalError = pyqtSignal([str], arguments=['message'])
    signedReady = pyqtSignal()
    signFailed = pyqtSignal([str], arguments=['message'])
    busyChanged = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._wallet = None  # type: Optional[QEWallet]
        self._collector = airgap.FragmentCollector()
        self._payload = None
        self._summary = {}
        self._reply_fragments = []
        self._busy = False

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

    @pyqtProperty(int, notify=progressChanged)
    def received(self):
        return self._collector.received

    @pyqtProperty(int, notify=progressChanged)
    def total(self):
        return self._collector.total

    @pyqtProperty('QVariantMap', notify=proposalReady)
    def summary(self):
        return self._summary

    @pyqtProperty('QVariantList', notify=signedReady)
    def replyFragments(self):
        return self._reply_fragments

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    def set_busy(self, busy):
        if self._busy != busy:
            self._busy = busy
            self.busyChanged.emit()

    @pyqtSlot()
    def reset(self):
        self._collector = airgap.FragmentCollector()
        self._payload = None
        self._summary = {}
        self._reply_fragments = []
        self.progressChanged.emit()
        self.proposalReady.emit()
        self.signedReady.emit()

    @pyqtSlot(str)
    def addScan(self, text):
        if self._payload is not None:
            return
        if not self._collector.add(text):
            return
        self.progressChanged.emit()
        if not self._collector.is_complete():
            return
        try:
            payload = self._collector.payload()
            summary = self._wallet.wallet.check_airgap_proposal(payload)
        except Exception as e:
            self._logger.exception('bad proposal')
            self._collector = airgap.FragmentCollector()
            self.progressChanged.emit()
            self.proposalError.emit(str(e) or repr(e))
            return
        self._payload = payload
        self._summary = summary
        self.proposalReady.emit()

    @pyqtSlot()
    @auth_protect(message=_('Sign air-gapped transaction?'))
    def sign(self):
        if self._payload is None or self._busy:
            return
        self.set_busy(True)
        wallet = self._wallet.wallet
        password = self._wallet.password
        payload = self._payload

        def task():
            try:
                reply = wallet.sign_airgap_proposal(payload, password=password)
                fragments = airgap.payload_to_fragments(reply)
            except UserFacingException as e:
                self._logger.error(f'airgap sign failed: {e!r}')
                self.signFailed.emit(str(e))
            except Exception as e:
                self._logger.exception('airgap sign failed')
                self.signFailed.emit(str(e) or repr(e))
            else:
                self._reply_fragments = fragments
                self.signedReady.emit()
            finally:
                self.set_busy(False)

        threading.Thread(target=task, daemon=True).start()
