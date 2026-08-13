# -*- coding: utf-8 -*-
#
# Staking dialog for Navio BLSCT wallets: list staked outputs, lock new
# stakes (optionally delegated to a third-party operator, i.e. cold
# staking) and unlock them again.

import asyncio
from typing import TYPE_CHECKING, Optional

from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
                             QTreeWidget, QTreeWidgetItem, QPushButton,
                             QLineEdit, QGridLayout)

from electrum.i18n import _
from electrum.util import UserFacingException, NotEnoughFunds

from .util import (WindowModalDialog, Buttons, OkButton, CancelButton,
                   WaitingDialog)
from .amountedit import BTCAmountEdit

if TYPE_CHECKING:
    from .main_window import ElectrumWindow


class StakingDialog(WindowModalDialog):

    def __init__(self, window: 'ElectrumWindow'):
        WindowModalDialog.__init__(self, window, _('Staking'))
        self.window = window
        self.wallet = window.wallet
        self.setMinimumSize(720, 420)

        vbox = QVBoxLayout(self)
        self.balance_label = QLabel()
        vbox.addWidget(self.balance_label)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels([
            _('Amount'), _('Delegated to'), _('Reward address'),
            _('Height'), _('Output')])
        self.tree.setRootIsDecorated(False)
        vbox.addWidget(self.tree)

        note = QLabel(_(
            'Delegated stakes let a staking operator produce blocks with '
            'your coins; the operator can never spend or unstake them. '
            'Reward routing is honored at the discretion of the operator.'))
        note.setWordWrap(True)
        vbox.addWidget(note)

        buttons = QHBoxLayout()
        b = QPushButton(_('Stake...'))
        b.clicked.connect(self._stake_dialog)
        buttons.addWidget(b)
        b = QPushButton(_('Unstake...'))
        b.clicked.connect(self._unstake_dialog)
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
        staked = self.wallet.get_staked_outputs()
        for u in staked:
            d = u.d
            deleg = d.get('delegation') or {}
            key = deleg.get('delegate_key', '')
            item = QTreeWidgetItem([
                self.window.format_amount(d['amount']),
                (key[:16] + '...') if key else _('(not delegated)'),
                deleg.get('reward_address', ''),
                str(d.get('height', 0)),
                u.output_hash[:16] + '...',
            ])
            item.setToolTip(1, key)
            item.setToolTip(4, u.output_hash)
            self.tree.addTopLevelItem(item)
        total = sum(u.d['amount'] for u in staked)
        spendable = self.wallet.get_spendable_balance_sat()
        rewards = self.wallet.get_staking_rewards_sat()
        self.balance_label.setText(
            _('Staked: {}').format(self.window.format_amount_and_units(total))
            + '    '
            + _('Available to stake: {}').format(self.window.format_amount_and_units(spendable))
            + '    '
            + _('Rewards earned: {}').format(self.window.format_amount_and_units(rewards)))

    # --------------------------------------------------------------- staking

    def _get_password(self) -> Optional[str]:
        if not self.wallet.has_keystore_encryption():
            return None
        return self.window.password_dialog(parent=self)

    def _broadcast(self, make_tx, on_done_msg: str):
        """Run make_tx(password) off the GUI thread, then broadcast."""
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

    def _stake_dialog(self):
        d = WindowModalDialog(self, _('Stake'))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Amount')), 0, 0)
        amount_e = BTCAmountEdit(self.window.get_decimal_point)
        grid.addWidget(amount_e, 0, 1)
        grid.addWidget(QLabel(_('Operator delegation key')), 1, 0)
        key_e = QLineEdit()
        key_e.setPlaceholderText(_('published by the staking operator; leave empty to stake without delegating'))
        key_e.setMinimumWidth(420)
        grid.addWidget(key_e, 1, 1)
        grid.addWidget(QLabel(_('Reward address')), 2, 0)
        reward_e = QLineEdit()
        reward_e.setPlaceholderText(_('optional; defaults to a fresh address of this wallet'))
        grid.addWidget(reward_e, 2, 1)
        vbox = QVBoxLayout(d)
        vbox.addLayout(grid)
        note = QLabel(_(
            'Without an operator key the coins are only locked: this wallet '
            'does not produce blocks itself. Delegate to a staking operator '
            'to have the coins actually stake.'))
        note.setWordWrap(True)
        vbox.addWidget(note)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec():
            return
        amount = amount_e.get_amount()
        if not amount:
            self.window.show_error(_('Invalid amount'))
            return
        delegate_key = key_e.text().strip() or None
        reward_addr = reward_e.text().strip() or None
        if reward_addr and not delegate_key:
            self.window.show_error(_('A reward address requires an operator delegation key'))
            return

        if self.wallet.is_watching_only():
            from .airgap_dialogs import AirgapSignDialog
            try:
                proposal = self.wallet.make_stake_proposal(
                    amount, delegate_key_hex=delegate_key,
                    reward_address=reward_addr)
            except (UserFacingException, NotEnoughFunds) as e:
                self.window.show_error(str(e))
                return
            AirgapSignDialog(self.window, proposal, _('Stake'), parent=self).exec()
            self.update_list()
            return

        def make_tx(password):
            return self.wallet.create_stake_transaction(
                amount, password=password,
                delegate_key_hex=delegate_key,
                reward_address=reward_addr)

        self._broadcast(make_tx, _('Stake transaction broadcast.'))

    def _unstake_dialog(self):
        groups = {}
        for u in self.wallet.get_staked_outputs():
            if u.d.get('height', 0) <= 0:
                continue
            deleg = u.d.get('delegation') or {}
            key = deleg.get('delegate_key', '')
            groups.setdefault(key, 0)
            groups[key] += u.d['amount']
        if not groups:
            self.window.show_error(_('No confirmed staked outputs'))
            return
        d = WindowModalDialog(self, _('Unstake'))
        grid = QGridLayout()
        grid.addWidget(QLabel(_('Delegation group')), 0, 0)
        group_cb = QComboBox()
        keys = sorted(groups, key=lambda k: (k != '', k))
        for k in keys:
            label = _('(not delegated)') if not k else k[:24] + '...'
            label += '  -  ' + self.window.format_amount_and_units(groups[k])
            group_cb.addItem(label, k)
        grid.addWidget(group_cb, 0, 1)
        grid.addWidget(QLabel(_('Amount (empty = all)')), 1, 0)
        amount_e = BTCAmountEdit(self.window.get_decimal_point)
        grid.addWidget(amount_e, 1, 1)
        vbox = QVBoxLayout(d)
        vbox.addLayout(grid)
        vbox.addLayout(Buttons(CancelButton(d), OkButton(d)))
        if not d.exec():
            return
        key = group_cb.currentData()
        amount = amount_e.get_amount() or None

        if self.wallet.is_watching_only():
            from .airgap_dialogs import AirgapSignDialog
            try:
                proposal = self.wallet.make_unstake_proposal(
                    amount, delegate_key_hex=key or None)
            except (UserFacingException, NotEnoughFunds) as e:
                self.window.show_error(str(e))
                return
            AirgapSignDialog(self.window, proposal, _('Unstake'), parent=self).exec()
            self.update_list()
            return

        def make_tx(password):
            return self.wallet.create_unstake_transaction(
                amount, password=password,
                delegate_key_hex=key or None)

        self._broadcast(make_tx, _('Unstake transaction broadcast.'))
