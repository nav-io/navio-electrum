# -*- coding: utf-8 -*-
#
# Tokens dialog for Navio BLSCT wallets: list token balances and NFTs,
# send them, and create/mint the wallet's own token or NFT collection.

import asyncio
from typing import TYPE_CHECKING, Optional

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
                             QTreeWidget, QTreeWidgetItem, QPushButton,
                             QLineEdit, QGridLayout, QCheckBox)

from electrum.i18n import _
from electrum.util import UserFacingException

from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   WaitingDialog)

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class TokensDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Tokens'))
        self.window = window
        self.wallet = window.wallet
        self.setMinimumSize(720, 420)

        vbox = QVBoxLayout(self)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            _('Type'), _('Name'), _('Balance / #'), _('Token id')])
        self.tree.setRootIsDecorated(False)
        vbox.addWidget(self.tree)

        buttons = QHBoxLayout()
        b = QPushButton(_('Send...'))
        b.clicked.connect(self._send_dialog)
        buttons.addWidget(b)
        if not self.wallet.is_watching_only():
            b = QPushButton(_('Create token...'))
            b.clicked.connect(self._create_dialog)
            buttons.addWidget(b)
            b = QPushButton(_('Mint...'))
            b.clicked.connect(self._mint_dialog)
            buttons.addWidget(b)
        buttons.addStretch()
        close = QPushButton(_('Close'))
        close.clicked.connect(self.close)
        buttons.addWidget(close)
        vbox.addLayout(buttons)

        self.update_list()

    # ------------------------------------------------------------------ data

    def update_list(self):
        self.tree.clear()
        for tid, balance in sorted(self.wallet.get_token_balances().items()):
            item = QTreeWidgetItem([
                _('Token'),
                self.wallet.get_token_display_name(tid),
                str(balance),
                tid[:24] + '...',
            ])
            item.setToolTip(3, tid)
            item.setData(0, 0x0100, tid)  # Qt.UserRole
            self.tree.addTopLevelItem(item)
        for nft in self.wallet.get_nfts():
            item = QTreeWidgetItem([
                _('NFT'),
                '{} #{}'.format(self.wallet.get_token_display_name(nft['token_id']),
                                nft['subid']),
                '1',
                nft['token_id'][:24] + '...',
            ])
            item.setToolTip(3, nft['token_id'])
            item.setData(0, 0x0100, nft['token_id'])
            self.tree.addTopLevelItem(item)

    # --------------------------------------------------------------- actions

    def _get_password(self) -> Optional[str]:
        if not self.wallet.has_keystore_encryption():
            return None
        return self.window.password_dialog(parent=self)

    def _broadcast(self, make_tx, on_done_msg: str):
        password = self._get_password()
        if password is None and self.wallet.has_keystore_encryption():
            return

        def task():
            built = make_tx(password)
            coro = self.wallet.broadcast_blsct_transaction(built.raw_hex)
            fut = asyncio.run_coroutine_threadsafe(coro, self.wallet.network.asyncio_loop)
            txid = fut.result(timeout=60)
            return built, txid

        def on_success(result):
            built, txid = result
            self.update_list()
            self.window.show_message(
                on_done_msg + '\n\n' + _('Transaction ID:') + ' ' + txid
                + '\n' + _('Fee:') + ' ' + self.window.format_amount_and_units(built.fee))

        def on_error(exc_info):
            e = exc_info[1]
            if isinstance(e, UserFacingException):
                self.window.show_error(str(e))
            else:
                self.window.on_error(exc_info)

        WaitingDialog(self, _('Creating transaction...'), task,
                      on_success=on_success, on_error=on_error)

    def _selected_token_id(self) -> Optional[str]:
        item = self.tree.currentItem()
        return item.data(0, 0x0100) if item else None

    def _send_dialog(self):
        tid = self._selected_token_id()
        if not tid:
            self.window.show_error(_('Select a token or NFT first'))
            return
        is_nft = self.wallet._is_nft_token_id(tid)
        d = WindowModalDialog(self, _('Send tokens'))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Token')), 0, 0)
        grid.addWidget(QLabel(self.wallet.get_token_display_name(tid)), 0, 1)
        grid.addWidget(QLabel(_('Recipient')), 1, 0)
        addr_e = QLineEdit()
        addr_e.setMinimumWidth(420)
        grid.addWidget(addr_e, 1, 1)
        grid.addWidget(QLabel(_('Amount')), 2, 0)
        amount_e = QLineEdit('1' if is_nft else '')
        amount_e.setReadOnly(is_nft)
        grid.addWidget(amount_e, 2, 1)
        vbox = QVBoxLayout(d)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec():
            return
        try:
            amount = int(amount_e.text())
        except ValueError:
            self.window.show_error(_('Invalid amount'))
            return
        dest = addr_e.text().strip()

        if self.wallet.is_watching_only():
            from .airgap_dialogs import AirgapSignDialog
            try:
                proposal = self.wallet.make_token_send_proposal(
                    tid, [(dest, amount, '')])
            except UserFacingException as e:
                self.window.show_error(str(e))
                return
            AirgapSignDialog(self.window, proposal, _('Send tokens')).exec()
            self.update_list()
            return

        self._broadcast(
            lambda password: self.wallet.create_token_transaction(
                tid, [(dest, amount, '')], password=password),
            _('Tokens sent.'))

    def _create_dialog(self):
        d = WindowModalDialog(self, _('Create token'))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Name')), 0, 0)
        name_e = QLineEdit()
        name_e.setMinimumWidth(300)
        grid.addWidget(name_e, 0, 1)
        grid.addWidget(QLabel(_('Total supply')), 1, 0)
        supply_e = QLineEdit()
        grid.addWidget(supply_e, 1, 1)
        nft_cb = QCheckBox(_('NFT collection'))
        grid.addWidget(nft_cb, 2, 1)
        vbox = QVBoxLayout(d)
        vbox.addLayout(grid)
        note = QLabel(_('Each wallet controls exactly one token, derived from '
                        'its seed. After creating it, use Mint to issue units.'))
        note.setWordWrap(True)
        vbox.addWidget(note)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec():
            return
        name = name_e.text().strip()
        try:
            supply = int(supply_e.text())
        except ValueError:
            self.window.show_error(_('Invalid supply'))
            return
        if not name:
            self.window.show_error(_('Name required'))
            return

        self._broadcast(
            lambda password: self.wallet.create_token(
                {'name': name}, supply, nft_cb.isChecked(), password=password),
            _('Token created.'))

    def _mint_dialog(self):
        meta = self.wallet.db.get('blsct_token_meta') or {}
        is_nft = bool(meta.get('is_nft'))
        d = WindowModalDialog(self, _('Mint'))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Destination')), 0, 0)
        addr_e = QLineEdit(self.wallet.get_receiving_address())
        addr_e.setMinimumWidth(420)
        grid.addWidget(addr_e, 0, 1)
        if is_nft:
            grid.addWidget(QLabel(_('NFT number')), 1, 0)
            id_e = QLineEdit()
            grid.addWidget(id_e, 1, 1)
            grid.addWidget(QLabel(_('NFT name')), 2, 0)
            name_e = QLineEdit()
            grid.addWidget(name_e, 2, 1)
        else:
            grid.addWidget(QLabel(_('Amount')), 1, 0)
            amount_e = QLineEdit()
            grid.addWidget(amount_e, 1, 1)
        vbox = QVBoxLayout(d)
        vbox.addLayout(grid)
        if not meta:
            note = QLabel(_('Note: no created token found in this wallet; '
                            'minting only works after Create token.'))
            note.setWordWrap(True)
            vbox.addWidget(note)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec():
            return
        dest = addr_e.text().strip()
        if is_nft:
            try:
                nft_id = int(id_e.text())
            except ValueError:
                self.window.show_error(_('Invalid NFT number'))
                return
            nft_meta = {'name': name_e.text().strip()} if name_e.text().strip() else {}
            self._broadcast(
                lambda password: self.wallet.mint_nft(
                    dest, nft_id, nft_meta, password=password),
                _('NFT minted.'))
        else:
            try:
                amount = int(amount_e.text())
            except ValueError:
                self.window.show_error(_('Invalid amount'))
                return
            self._broadcast(
                lambda password: self.wallet.mint_token(
                    dest, amount, password=password),
                _('Tokens minted.'))
