# -*- coding: utf-8 -*-
#
# Desktop dialogs for air-gapped QR signing (see electrum/airgap.py).

import asyncio
from typing import TYPE_CHECKING, List, Optional

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                             QTreeWidget, QTreeWidgetItem)

from electrum import airgap
from electrum.i18n import _
from electrum.util import UserFacingException

from .util import WindowModalDialog, WaitingDialog, ColorScheme
from .qrcodewidget import QRCodeWidget

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class AnimatedQRWidget(QRCodeWidget):
    """Cycles through the fragments of an air-gap payload."""

    def __init__(self, fragments: List[str], interval_ms: int = 400):
        QRCodeWidget.__init__(self, fragments[0] if fragments else None)
        self.fragments = fragments
        self._index = 0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._advance)
        if len(fragments) > 1:
            self.timer.start(interval_ms)
        self.setMinimumSize(300, 300)

    def _advance(self):
        self._index = (self._index + 1) % len(self.fragments)
        self.setData(self.fragments[self._index])


def _scan_multipart(parent, config, on_payload, on_error):
    """Open the camera dialog with a validator that keeps scanning until all
    payload fragments were seen, then call on_payload(dict)."""
    from .qrreader.qtmultimedia import QrReaderCameraDialog
    from .qrreader.qtmultimedia.validator import (
        QrReaderValidatorColorizing, QrReaderValidatorResult)

    collector = airgap.FragmentCollector()

    class FragmentValidator(QrReaderValidatorColorizing):
        def validate_results(self, results):
            res = super().validate_results(results)
            for result in results:
                collector.add(result.data)
            if collector.total:
                res.message = _('Received {} of {} parts').format(
                    collector.received, collector.total)
                res.message_color = ColorScheme.GREEN.as_color()
            if collector.is_complete():
                res.accepted = True
                if results:
                    res.selected_results.append(results[0])
            return res

    class MultipartCameraDialog(QrReaderCameraDialog):
        def start_scan(self, device: str = ''):
            super().start_scan(device)
            self.validator = FragmentValidator()

    def on_finished(success: bool, error_message: Optional[str], _data):
        if not success and error_message:
            on_error(error_message)
            return
        if not collector.is_complete():
            return  # user cancelled
        try:
            payload = collector.payload()
        except Exception as e:
            on_error(str(e))
            return
        on_payload(payload)

    dialog = _scan_multipart._dialog = MultipartCameraDialog(parent=parent, config=config)
    dialog.qr_finished.connect(on_finished)
    dialog.start_scan(config.VIDEO_DEVICE_PATH)


class AirgapSignDialog(WindowModalDialog):
    """Online (watch-only) side: show the proposal, scan the signed reply,
    broadcast."""

    def __init__(self, window: 'ElectrumWindow', proposal: dict,
                 subtitle: str = ''):
        WindowModalDialog.__init__(self, window, _('Sign with offline device'))
        self.window = window
        self.wallet = window.wallet
        fragments = airgap.payload_to_fragments(proposal)

        vbox = QVBoxLayout(self)
        if subtitle:
            lb = QLabel(subtitle)
            lb.setWordWrap(True)
            vbox.addWidget(lb)
        vbox.addWidget(QLabel(_(
            'On the offline device, open Wallet menu > Air-gapped signer '
            'and scan this code:')))
        self.qr = AnimatedQRWidget(fragments)
        vbox.addWidget(self.qr, 1)
        if len(fragments) > 1:
            vbox.addWidget(QLabel(_('The code loops through {} parts.')
                                  .format(len(fragments))))

        buttons = QHBoxLayout()
        scan_b = QPushButton(_('Scan signed transaction...'))
        scan_b.clicked.connect(self._scan_reply)
        buttons.addWidget(scan_b)
        buttons.addStretch()
        close_b = QPushButton(_('Close'))
        close_b.clicked.connect(self.reject)
        buttons.addWidget(close_b)
        vbox.addLayout(buttons)

    def _scan_reply(self):
        _scan_multipart(
            self, self.window.config,
            on_payload=self._on_reply,
            on_error=lambda msg: self.window.show_error(msg))

    def _on_reply(self, payload: dict):
        try:
            txid, raw_hex = self.wallet.check_airgap_reply(payload)
        except UserFacingException as e:
            self.window.show_error(str(e))
            return

        def task():
            coro = self.wallet.broadcast_blsct_transaction(raw_hex)
            fut = asyncio.run_coroutine_threadsafe(
                coro, self.wallet.network.asyncio_loop)
            return fut.result(timeout=60)

        def on_success(sent_txid):
            self.accept()
            self.window.show_message(
                _('Payment sent.') + '\n\n' + _('Transaction ID:') + ' ' + sent_txid)

        def on_error(exc_info):
            e = exc_info[1]
            if isinstance(e, UserFacingException):
                self.window.show_error(str(e))
            else:
                self.window.on_error(exc_info)

        WaitingDialog(self, _('Broadcasting transaction...'), task,
                      on_success=on_success, on_error=on_error)


class AirgapSignerDialog(WindowModalDialog):
    """Offline (full wallet) side: scan a proposal, confirm, sign, display
    the signed transaction."""

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Air-gapped signer'))
        self.window = window
        self.wallet = window.wallet
        self.payload = None
        self.setMinimumSize(560, 460)

        self.vbox = QVBoxLayout(self)
        self.info_label = QLabel(_(
            'Scan the transaction proposal shown on the online device.'))
        self.info_label.setWordWrap(True)
        self.vbox.addWidget(self.info_label)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([_('Output'), _('Amount'), _('Address')])
        self.tree.setRootIsDecorated(False)
        self.tree.hide()
        self.vbox.addWidget(self.tree, 1)

        self.fee_label = QLabel('')
        self.vbox.addWidget(self.fee_label)

        self.qr_holder = QVBoxLayout()
        self.vbox.addLayout(self.qr_holder, 1)

        buttons = QHBoxLayout()
        self.scan_b = QPushButton(_('Scan proposal...'))
        self.scan_b.clicked.connect(self._scan)
        buttons.addWidget(self.scan_b)
        self.sign_b = QPushButton(_('Sign'))
        self.sign_b.clicked.connect(self._sign)
        self.sign_b.hide()
        buttons.addWidget(self.sign_b)
        buttons.addStretch()
        close_b = QPushButton(_('Close'))
        close_b.clicked.connect(self.reject)
        buttons.addWidget(close_b)
        self.vbox.addLayout(buttons)

    def _scan(self):
        _scan_multipart(
            self, self.window.config,
            on_payload=self._on_proposal,
            on_error=lambda msg: self.window.show_error(msg))

    def _on_proposal(self, payload: dict):
        try:
            summary = self.wallet.check_airgap_proposal(payload)
        except UserFacingException as e:
            self.window.show_error(str(e))
            return
        self.payload = payload
        self.tree.clear()
        for o in summary['outputs']:
            if o['type'] == 'StakedCommitment':
                kind = (_('Stake (delegated)') if o['delegate_key']
                        else _('Stake'))
            elif o['is_mine']:
                kind = _('To this wallet')
            else:
                kind = _('Payment')
            if o['token_id']:
                amount_str = f"{o['amount']} [{o['token_id'][:16]}...]"
            else:
                amount_str = self.window.format_amount_and_units(o['amount'])
            item = QTreeWidgetItem([kind, amount_str, o['address']])
            item.setToolTip(2, o['address'])
            self.tree.addTopLevelItem(item)
        self.tree.show()
        age_warn = ''
        if summary['age_seconds'] > airgap.PROPOSAL_AGE_WARN_SECONDS:
            age_warn = '  ' + _('Warning: this proposal is more than a day old.')
        self.fee_label.setText(
            _('Fee: {}').format(self.window.format_amount_and_units(summary['fee']))
            + '  -  ' + _('Change returns to this wallet automatically.')
            + age_warn)
        self.info_label.setText(_('Review the transaction, then press Sign.'))
        self.sign_b.show()

    def _sign(self):
        if self.payload is None:
            return
        password = None
        if self.wallet.has_keystore_encryption():
            password = self.window.password_dialog(parent=self)
            if password is None:
                return
        payload = self.payload

        def task():
            reply = self.wallet.sign_airgap_proposal(payload, password=password)
            return airgap.payload_to_fragments(reply)

        def on_success(fragments):
            self.tree.hide()
            self.fee_label.setText('')
            self.sign_b.hide()
            self.info_label.setText(_(
                'Signed. Scan this with the online device to broadcast:'))
            qr = AnimatedQRWidget(fragments)
            self.qr_holder.addWidget(qr)

        def on_error(exc_info):
            e = exc_info[1]
            if isinstance(e, UserFacingException):
                self.window.show_error(str(e))
            else:
                self.window.on_error(exc_info)

        WaitingDialog(self, _('Signing transaction...'), task,
                      on_success=on_success, on_error=on_error)
