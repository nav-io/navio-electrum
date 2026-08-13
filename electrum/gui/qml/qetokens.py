import asyncio
import threading
from typing import Optional

from PyQt6.QtCore import pyqtProperty, pyqtSignal, pyqtSlot, QObject, QVariant

from electrum.i18n import _
from electrum.logging import get_logger
from electrum.util import get_asyncio_loop, UserFacingException

from .auth import AuthMixin, auth_protect
from .qewallet import QEWallet


class QETokens(AuthMixin, QObject):
    """Token/NFT backend for Navio BLSCT wallets: balances, NFTs and
    token transfers."""
    _logger = get_logger(__name__)

    tokensChanged = pyqtSignal()
    busyChanged = pyqtSignal()
    sendSuccess = pyqtSignal([str], arguments=['txid'])
    sendFailed = pyqtSignal([str], arguments=['message'])

    def __init__(self, parent=None):
        super().__init__(parent)
        self._wallet = None  # type: Optional[QEWallet]
        self._busy = False
        self._pending = None

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
            self.tokensChanged.emit()

    @pyqtProperty('QVariantList', notify=tokensChanged)
    def tokens(self):
        if not self._wallet:
            return []
        w = self._wallet.wallet
        return [
            {'token_id': tid,
             'name': w.get_token_display_name(tid),
             'balance': balance}
            for tid, balance in sorted(w.get_token_balances().items())
        ]

    @pyqtProperty('QVariantList', notify=tokensChanged)
    def nfts(self):
        if not self._wallet:
            return []
        w = self._wallet.wallet
        return [
            {**nft, 'name': w.get_token_display_name(nft['token_id'])}
            for nft in w.get_nfts()
        ]

    @pyqtProperty(bool, notify=busyChanged)
    def busy(self):
        return self._busy

    def set_busy(self, busy: bool):
        if self._busy != busy:
            self._busy = busy
            self.busyChanged.emit()

    @pyqtSlot()
    def updateTokens(self):
        self.tokensChanged.emit()

    @pyqtSlot(str, str, str, str)
    def sendToken(self, token_id: str, address: str, amount_str: str, memo: str):
        if self._busy:
            return
        try:
            amount = int(amount_str)
        except ValueError:
            self.sendFailed.emit(_('Invalid amount'))
            return
        if amount <= 0:
            self.sendFailed.emit(_('Invalid amount'))
            return
        self._pending = (token_id, address.strip(), amount, memo)
        self._do_send()

    @auth_protect(message=_('Send tokens?'))
    def _do_send(self):
        token_id, address, amount, memo = self._pending
        self._pending = None
        self.set_busy(True)

        wallet = self._wallet.wallet
        password = self._wallet.password
        qewallet = self._wallet

        def task():
            try:
                built = wallet.create_token_transaction(
                    token_id, [(address, amount, memo)], password=password)
                coro = wallet.broadcast_blsct_transaction(built.raw_hex)
                fut = asyncio.run_coroutine_threadsafe(coro, get_asyncio_loop())
                txid = fut.result(timeout=60)
            except UserFacingException as e:
                self._logger.error(f'token send failed: {e!r}')
                self.sendFailed.emit(str(e))
            except Exception as e:
                self._logger.exception('token send failed')
                self.sendFailed.emit(str(e) or repr(e))
            else:
                self.sendSuccess.emit(txid)
                qewallet.historyModel.requestRefresh.emit()  # via qt thread
            finally:
                self.set_busy(False)
                self.tokensChanged.emit()

        threading.Thread(target=task, daemon=True).start()
