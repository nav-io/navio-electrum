import asyncio
import threading
from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QVariant

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import get_asyncio_loop
from electrum import blsct_privacy

from .auth import AuthMixin, auth_protect
from .qewallet import QEWallet
from .qetypes import QEAmount


class QEBlsctFinalizer(AuthMixin, QObject):
    """Builds and broadcasts BLSCT transactions.

    BLSCT transactions are built and signed in one step by the native
    bindings, with the fee determined at build time, so the regular
    QETxFinalizer (make_unsigned_transaction / fee slider / PSBT) flow
    does not apply.
    """
    _logger = get_logger(__name__)

    validChanged = pyqtSignal()
    busyChanged = pyqtSignal()
    feeChanged = pyqtSignal()
    effectiveAmountChanged = pyqtSignal()
    warningChanged = pyqtSignal()
    privacyChanged = pyqtSignal()
    finished = pyqtSignal([str], arguments=['txid'])
    sendFailed = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)
        self._wallet = None  # type: Optional[QEWallet]
        self._address = ''
        self._message = ''
        self._amount = QEAmount()
        self._effectiveAmount = QEAmount()
        self._fee = QEAmount()
        self._warning = ''
        self._valid = False
        self._busy = False
        self._built = None
        self._update_pending = False
        self._min_privacy = 0.0   # bits; 0 = off
        self._privacy_text = ''

    walletChanged = pyqtSignal()
    @pyqtProperty(QVariant, notify=walletChanged)
    def wallet(self) -> QEWallet:
        return self._wallet

    @wallet.setter
    def wallet(self, wallet: QEWallet):
        assert wallet is None or isinstance(wallet, QEWallet)
        if self._wallet != wallet:
            self._wallet = wallet
            if wallet is not None:
                self._min_privacy = float(wallet.wallet.config.BLSCT_MIN_PRIVACY or 0)
                self.minPrivacyChanged.emit()
            self.walletChanged.emit()

    addressChanged = pyqtSignal()
    @pyqtProperty(str, notify=addressChanged)
    def address(self):
        return self._address

    @address.setter
    def address(self, address):
        if self._address != address:
            self._address = address
            self.addressChanged.emit()

    messageChanged = pyqtSignal()
    @pyqtProperty(str, notify=messageChanged)
    def message(self):
        return self._message

    @message.setter
    def message(self, message):
        if self._message != message:
            self._message = message
            self.messageChanged.emit()

    amountChanged = pyqtSignal()
    @pyqtProperty(QVariant, notify=amountChanged)
    def amount(self) -> QEAmount:
        return self._amount

    @amount.setter
    def amount(self, amount: QEAmount):
        assert amount is None or isinstance(amount, QEAmount)
        if self._amount != amount:
            self._amount.copyFrom(amount)
            self.amountChanged.emit()

    @pyqtProperty(QEAmount, notify=effectiveAmountChanged)
    def effectiveAmount(self):
        return self._effectiveAmount

    @pyqtProperty(QEAmount, notify=feeChanged)
    def fee(self):
        return self._fee

    @pyqtProperty(str, notify=warningChanged)
    def warning(self):
        return self._warning

    def set_warning(self, warning: str):
        if self._warning != warning:
            self._warning = warning
            self.warningChanged.emit()

    minPrivacyChanged = pyqtSignal()
    @pyqtProperty(float, notify=minPrivacyChanged)
    def minPrivacy(self):
        """Only spend coins with at least this privacy score (bits); 0 = off.
        Kept in the blsct_min_privacy config, like the desktop send tab."""
        return self._min_privacy

    @minPrivacy.setter
    def minPrivacy(self, bits: float):
        bits = max(0.0, float(bits))
        if self._min_privacy != bits:
            self._min_privacy = bits
            if self._wallet:
                self._wallet.wallet.config.BLSCT_MIN_PRIVACY = bits
            self.minPrivacyChanged.emit()
            self.doUpdate()

    @pyqtProperty(str, notify=privacyChanged)
    def privacyText(self):
        """Privacy score (bits, 2 decimals) our new outputs (change) will
        get, '' while unknown or not built."""
        return self._privacy_text

    def set_privacy_text(self, text: str):
        if self._privacy_text != text:
            self._privacy_text = text
            self.privacyChanged.emit()

    @pyqtProperty(bool, notify=validChanged)
    def valid(self):
        return self._valid

    def set_valid(self, valid: bool):
        if self._valid != valid:
            self._valid = valid
            self.validChanged.emit()

    @pyqtProperty(str, notify=validChanged)
    def builtTxid(self):
        return self._built.txid if self._built else ''

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    def set_busy(self, busy: bool):
        if self._busy != busy:
            self._busy = busy
            self.busyChanged.emit()

    @pyqtSlot()
    def doUpdate(self):
        if not self._wallet or not self._address:
            return
        if not self._amount.isMax and self._amount.satsInt <= 0:
            return
        if self._busy:
            self._update_pending = True   # inputs changed while building
            return

        self.set_valid(False)
        self.set_warning('')
        self.set_privacy_text('')
        self.set_busy(True)
        self._built = None

        wallet = self._wallet.wallet
        password = self._wallet.password
        address = self._address
        memo = self._message
        is_max = self._amount.isMax
        min_privacy = self._min_privacy or None
        if is_max:
            amount = sum(c.d['amount'] for c in wallet.send_candidate_coins(None, min_privacy))
        else:
            amount = self._amount.satsInt

        def build_task():
            try:
                built = wallet.create_blsct_transaction(
                    [(address, amount, memo)],
                    password=password,
                    subtract_fee_from_amount=is_max,
                    min_privacy=min_privacy,
                )
            except Exception as e:
                self._logger.error(f'could not build blsct tx: {e!r}')
                self.set_warning(str(e) or repr(e))
                self.set_busy(False)
                self._maybe_rerun()
                return
            self._built = built
            self.set_privacy_text(self._result_privacy_text(wallet, built))
            self._fee.satsInt = built.fee
            self.feeChanged.emit()
            self._effectiveAmount.satsInt = amount - built.fee if is_max else amount
            self.effectiveAmountChanged.emit()
            self.set_busy(False)
            self.set_valid(True)
            self._maybe_rerun()

        threading.Thread(target=build_task, daemon=True).start()

    def _maybe_rerun(self):
        if self._update_pending:
            self._update_pending = False
            self.doUpdate()

    @staticmethod
    def _result_privacy_text(wallet, built) -> str:
        """Score our new outputs will get, from the built tx's inputs (covers
        of an aggregate count as foreign inputs)."""
        from electrum.navio_blsct import parse_tx_hex
        try:
            inputs = [i.prevout_hash for i in parse_tx_hex(built.raw_hex).inputs]
        except Exception:
            return ''
        mbits = wallet.privacy_score_for_inputs(inputs)
        return '' if mbits is None else blsct_privacy.format_bits(mbits)

    @pyqtSlot()
    @auth_protect(message=_('Send Navio transaction?'))
    def signAndSend(self):
        if not self._valid or not self._built:
            self._logger.debug('no valid blsct tx')
            return

        built = self._built
        wallet = self._wallet.wallet
        qewallet = self._wallet

        async def broadcast_coro():
            try:
                txid = await wallet.broadcast_blsct_transaction(built.raw_hex)
            except Exception as e:
                self._logger.error(f'blsct broadcast failed: {e!r}')
                self.sendFailed.emit(str(e) or repr(e))
            else:
                self._logger.info(f'blsct broadcast success: {txid}')
                self.finished.emit(txid)
                qewallet.broadcastSucceeded.emit(txid)
                qewallet.historyModel.requestRefresh.emit()  # via qt thread

        asyncio.run_coroutine_threadsafe(broadcast_coro(), get_asyncio_loop())
