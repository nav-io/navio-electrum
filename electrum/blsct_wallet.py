# -*- coding: utf-8 -*-
#
# Navio BLSCT wallet for Electrum.
#
# BLSCT (confidential) outputs cannot be discovered through scripthash
# subscriptions: amounts are hidden and outputs are addressed to one-time
# keys. Instead, the wallet downloads per-block BLSCT key material from the
# (Navio) electrumx server (blockchain.block.get_range_txs_keys) and
# trial-matches every output against its view key, mirroring navio-core and
# the navio-sdk reference implementation.

import asyncio
import threading
from typing import Optional, Dict, Tuple, List, Sequence, TYPE_CHECKING

from aiorpcx import run_in_thread, ignore_after

from . import util
from .i18n import _
from .util import (NetworkJobOnDefaultServer, NotEnoughFunds,
                   UserFacingException, OldTaskGroup)
from .crypto import pw_encode, pw_decode
from .keystore import KeyStore
from .logging import Logger
from .wallet import (Abstract_Wallet, register_wallet_type,
                     register_constructor)
from . import navio_blsct
from . import stake_delegation
from .navio_blsct import (BlsctKeyRing, SpendableOutput, Recipient, parse_tx_hex,
                          parse_output_hex, ParsedTxOut,
                          MAIN_ACCOUNT, CHANGE_ACCOUNT, STAKING_ACCOUNT,
                          MIN_STAKE_AMOUNT,
                          bip39_entropy_to_mnemonic, bip39_mnemonic_to_entropy)

if TYPE_CHECKING:
    from .network import Network
    from .wallet_db import WalletDB
    from .simple_config import SimpleConfig

DEFAULT_KEYPOOL = 20
GAP_LIMIT = 20
# how many recent block hashes to retain for reorg detection
BLOCK_HASH_RETENTION = 500


class BlsctKeyStore(KeyStore):
    """Keystore holding the BLSCT master seed (a 32-byte scalar).

    The seed doubles as BIP39 entropy for the 24-word mnemonic. The view key
    and public spend key stay accessible without a password (they are
    required for scanning); only the seed itself is password-protected.
    """
    type = 'blsct'

    def __init__(self, d: dict):
        KeyStore.__init__(self)
        self.seed = d.get('seed')                    # hex str; possibly encrypted
        self.mnemonic = d.get('mnemonic')            # str; possibly encrypted
        self.passphrase = d.get('passphrase') or ''  # BIP39 passphrase; possibly encrypted
        self.view_key_hex = d.get('view_key')        # cleartext (needed to scan)
        self.spend_pub_hex = d.get('spend_pub')      # cleartext (needed to scan)
        self.pw_hash_version = d.get('pw_hash_version', 1)
        self._encrypted = bool(d.get('encrypted', False))

    def dump(self) -> dict:
        return {
            'type': self.type,
            'seed': self.seed,
            'mnemonic': self.mnemonic,
            'passphrase': self.passphrase,
            'view_key': self.view_key_hex,
            'spend_pub': self.spend_pub_hex,
            'pw_hash_version': self.pw_hash_version,
            'encrypted': self._encrypted,
        }

    # -- password handling ---------------------------------------------------

    def may_have_password(self):
        return not self.is_watching_only()

    def has_password(self):
        return self._encrypted

    def check_password(self, password):
        if not self._encrypted:
            if password:
                raise util.InvalidPassword()
            return
        self.get_seed_hex(password)

    def update_password(self, old_password, new_password):
        if self.is_watching_only():
            return  # nothing secret to encrypt; view key must stay cleartext to scan
        self.check_password(old_password)
        if new_password == '':
            new_password = None
        seed = self.get_seed_hex(old_password)
        mnemonic = self.get_mnemonic(old_password)
        passphrase = self.get_passphrase(old_password)
        if new_password:
            self.seed = pw_encode(seed, new_password, version=self.pw_hash_version)
            self.mnemonic = pw_encode(mnemonic, new_password, version=self.pw_hash_version)
            self.passphrase = (pw_encode(passphrase, new_password, version=self.pw_hash_version)
                               if passphrase else '')
            self._encrypted = True
        else:
            self.seed = seed
            self.mnemonic = mnemonic
            self.passphrase = passphrase
            self._encrypted = False

    def get_seed_hex(self, password) -> str:
        if not self._encrypted:
            if password:
                raise util.InvalidPassword()
            return self.seed
        try:
            return pw_decode(self.seed, password, version=self.pw_hash_version)
        except Exception:
            raise util.InvalidPassword()

    def get_seed(self, password) -> str:
        """Electrum convention: 'seed' is the human backup phrase."""
        return self.get_mnemonic(password)

    def get_mnemonic(self, password) -> str:
        if not self._encrypted:
            return self.mnemonic
        try:
            return pw_decode(self.mnemonic, password, version=self.pw_hash_version)
        except Exception:
            raise util.InvalidPassword()

    def get_passphrase(self, password) -> str:
        if not self.passphrase:
            return ''
        if not self._encrypted:
            return self.passphrase
        try:
            return pw_decode(self.passphrase, password, version=self.pw_hash_version)
        except Exception:
            raise util.InvalidPassword()

    # -- KeyStore abstract methods --------------------------------------------

    def has_seed(self):
        return bool(self.mnemonic)

    def is_deterministic(self):
        return True

    def is_watching_only(self):
        # view-key-only keystore: can scan and see balances, cannot spend
        return not bool(self.seed)

    def sign_message(self, sequence, message, password, *, script_type=None) -> bytes:
        raise UserFacingException('message signing is not implemented for BLSCT wallets')

    def decrypt_message(self, sequence, message, password) -> bytes:
        raise UserFacingException('message decryption is not implemented for BLSCT wallets')

    def sign_transaction(self, tx, password):
        # BLSCT transactions are built and signed atomically in
        # Blsct_Wallet.create_blsct_transaction
        raise UserFacingException('use create_blsct_transaction for BLSCT wallets')

    def get_pubkey_derivation(self, pubkey, txinout, *, only_der_suffix=True):
        return None

    def get_pubkey_provider(self, sequence):
        return None

    # deterministic-keystore introspection used by wallet info GUIs;
    # BLSCT keys are not bip32, so there is nothing meaningful to show
    def get_derivation_prefix(self):
        return None

    def get_master_public_key(self):
        return None

    def get_root_fingerprint(self):
        return None

    @classmethod
    def from_seed_hex(cls, seed_hex: str, passphrase: str = '') -> 'BlsctKeyStore':
        ring = BlsctKeyRing(seed_hex, passphrase=passphrase or None)
        mnemonic = bip39_entropy_to_mnemonic(bytes.fromhex(seed_hex))
        return cls({
            'seed': seed_hex,
            'mnemonic': mnemonic,
            'passphrase': passphrase or '',
            'view_key': ring.view_key.serialize(),
            'spend_pub': ring.spend_pub.serialize(),
        })

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = '') -> 'BlsctKeyStore':
        entropy = bip39_mnemonic_to_entropy(mnemonic)
        ks = cls.from_seed_hex(entropy.hex(), passphrase=passphrase)
        ks.mnemonic = ' '.join(mnemonic.split())
        return ks

    @classmethod
    def from_view_key(cls, view_key_hex: str, spend_pub_hex: str) -> 'BlsctKeyStore':
        """Watch-only keystore: private view key + public spend key.
        Can scan the chain and recover amounts, but cannot spend."""
        # validate by constructing a scanning ring
        BlsctKeyRing.from_view_key(view_key_hex, spend_pub_hex)
        return cls({
            'view_key': view_key_hex,
            'spend_pub': spend_pub_hex,
        })


class BlsctUtxo:
    """Minimal coin object so generic commands (listunspent) can render
    BLSCT outputs."""

    def __init__(self, output_hash: str, d: dict):
        self.output_hash = output_hash
        self.d = d

    def value_sats(self):
        return self.d.get('amount')

    @property
    def address(self):
        return self.d.get('address')

    @property
    def block_height(self):
        return self.d.get('height') or 0

    @property
    def short_id(self):
        return self.output_hash[:10] + '…'

    def to_json(self):
        return {
            'output_hash': self.output_hash,
            'tx_hash': self.d.get('tx_hash'),
            'height': self.d.get('height'),
            'value_sats': self.d.get('amount'),
            'memo': self.d.get('memo') or '',
            'address': self.d.get('address'),
            'account': self.d.get('account'),
            'address_index': self.d.get('addr_index'),
            'token_id': self.d.get('token_id'),
            'staked': bool(self.d.get('staked')),
            'delegation': self.d.get('delegation'),
        }


class Blsct_Wallet(Abstract_Wallet):
    wallet_type = 'blsct'
    txin_type = 'blsct'

    def __init__(self, db: 'WalletDB', *, config: 'SimpleConfig'):
        self.keyring = None  # type: Optional[BlsctKeyRing]
        self._blsct_lock = threading.RLock()
        self._addr_to_pair = {}  # type: Dict[str, Tuple[int, int]]
        # {output_hash: {...}} see _store_output for the schema
        self.blsct_outputs = db.get_dict('blsct_outputs')
        self.blsct_sync = db.get_dict('blsct_sync')
        self.blsct_synchronizer = None  # type: Optional[BlsctSynchronizer]
        Abstract_Wallet.__init__(self, db, config=config)
        self._rebuild_address_index()
        self._ensure_addresses()

    # ------------------------------------------------------------------ setup

    def load_keystore(self):
        d = self.db.get('keystore')
        if not d or d.get('type') != 'blsct':
            raise Exception('missing/invalid blsct keystore')
        self.keystore = BlsctKeyStore(d)
        if not self.keystore._encrypted and self.keystore.seed:
            self.keyring = BlsctKeyRing(self.keystore.seed,
                                        passphrase=self.keystore.passphrase or None)
        elif self.keystore.view_key_hex and self.keystore.spend_pub_hex:
            # encrypted keystore: scan with the cleartext view key; the full
            # (spending) ring is derived from the seed at signing time
            self.keyring = BlsctKeyRing.from_view_key(
                self.keystore.view_key_hex, self.keystore.spend_pub_hex)
        else:
            raise UserFacingException(
                'BLSCT keystore is encrypted and missing scanning keys')

    def save_keystore(self):
        self.db.put('keystore', self.keystore.dump())

    def _update_password_for_keystore(self, old_pw, new_pw):
        if self.keystore and self.keystore.may_have_password():
            self.keystore.update_password(old_pw, new_pw)
            self.save_keystore()

    def _rebuild_address_index(self):
        counts = self.db.get('blsct_addr_counts') or {'main': DEFAULT_KEYPOOL,
                                                      'change': 5}
        self.db.put('blsct_addr_counts', counts)
        self.keyring.ensure_keypool(MAIN_ACCOUNT, counts['main'] + GAP_LIMIT)
        self.keyring.ensure_keypool(CHANGE_ACCOUNT, counts['change'] + GAP_LIMIT)
        self.keyring.ensure_keypool(STAKING_ACCOUNT, GAP_LIMIT)

    def _ensure_addresses(self):
        """Mirror derived addresses into the db receiving/change lists so
        generic address commands work."""
        counts = self.db.get('blsct_addr_counts')
        recv = self.db.get_dict('addresses').get('receiving')
        chg = self.db.get_dict('addresses').get('change')
        while len(recv) < counts['main']:
            recv.append(self.keyring.address(MAIN_ACCOUNT, len(recv)))
        while len(chg) < counts['change']:
            chg.append(self.keyring.address(CHANGE_ACCOUNT, len(chg)))
        self._addr_to_pair = {}
        for i, a in enumerate(recv):
            self._addr_to_pair[a] = (MAIN_ACCOUNT, i)
        for i, a in enumerate(chg):
            self._addr_to_pair[a] = (CHANGE_ACCOUNT, i)

    def synchronize(self):
        return 0

    def is_watching_only(self):
        return self.keystore.is_watching_only()

    def has_seed(self):
        return self.keystore.has_seed()

    def get_seed(self, password):
        return self.keystore.get_mnemonic(password)

    def get_seed_type(self):
        return 'blsct'

    def get_fingerprint(self):
        return self.keyring.view_key.serialize()[:16]

    def check_address_for_corruption(self, addr):
        pass

    # ------------------------------------------------------------- addresses

    def get_receiving_addresses(self, *, slice_start=None, slice_stop=None):
        return list(self.db.get_dict('addresses')['receiving'])[slice_start:slice_stop]

    def get_change_addresses(self, *, slice_start=None, slice_stop=None):
        return list(self.db.get_dict('addresses')['change'])[slice_start:slice_stop]

    def get_addresses(self):
        return self.get_receiving_addresses() + self.get_change_addresses()

    def is_mine(self, address) -> bool:
        return address in self._addr_to_pair

    def get_address_index(self, address):
        return self._addr_to_pair.get(address)

    def get_address_path_str(self, address):
        pair = self._addr_to_pair.get(address)
        return f'blsct/{pair[0]}/{pair[1]}' if pair else None

    def get_redeem_script(self, address):
        return None

    def get_witness_script(self, address):
        return None

    def get_txin_type(self, address):
        return 'blsct'

    def get_public_keys(self, address):
        return []

    def get_public_key(self, address):
        return None

    def pubkeys_to_address(self, pubkeys):
        return None

    def derive_pubkeys(self, c, i):
        return []

    def _add_input_sig_info(self, txin, address, *, only_der_suffix):
        pass

    def get_all_known_addresses_beyond_gap_limit(self):
        return set()

    def create_new_address(self, for_change: bool = False) -> str:
        with self._blsct_lock:
            counts = self.db.get('blsct_addr_counts')
            key = 'change' if for_change else 'main'
            account = CHANGE_ACCOUNT if for_change else MAIN_ACCOUNT
            index = counts[key]
            counts[key] = index + 1
            self.db.put('blsct_addr_counts', dict(counts))
            addr = self.keyring.address(account, index)
            lst = self.db.get_dict('addresses')['change' if for_change else 'receiving']
            lst.append(addr)
            self._addr_to_pair[addr] = (account, index)
            self.keyring.ensure_keypool(account, index + 1 + GAP_LIMIT)
            self.save_db()
            return addr

    def is_used(self, address) -> bool:
        pair = self._addr_to_pair.get(address)
        if pair is None:
            return False
        account, index = pair
        for d in self.blsct_outputs.values():
            if d.get('account') == account and d.get('addr_index') == index:
                return True
        return False

    def get_unused_addresses(self) -> Sequence[str]:
        return [addr for addr in self.get_receiving_addresses()
                if not self.is_used(addr)]

    def get_unused_address(self) -> Optional[str]:
        addrs = self.get_unused_addresses()
        if addrs:
            return addrs[0]
        return self.create_new_address(False)

    def get_receiving_address(self) -> str:
        return self.get_unused_address()

    # --------------------------------------------------------------- balance

    def get_balance(self, **kwargs) -> Tuple[int, int, int]:
        confirmed = unconfirmed = 0
        with self._blsct_lock:
            for d in self.blsct_outputs.values():
                if d.get('spent_by'):
                    continue
                if d.get('token_id'):
                    continue  # token balances tracked separately
                if d.get('height', 0) > 0:
                    confirmed += d['amount']
                else:
                    unconfirmed += d['amount']
        return confirmed, unconfirmed, 0

    def get_addr_balance(self, address):
        pair = self._addr_to_pair.get(address)
        c = u = 0
        if pair:
            with self._blsct_lock:
                for d in self.blsct_outputs.values():
                    if d.get('spent_by') or d.get('token_id'):
                        continue
                    if (d.get('account'), d.get('addr_index')) != pair:
                        continue
                    if d.get('height', 0) > 0:
                        c += d['amount']
                    else:
                        u += d['amount']
        return c, u, 0

    def get_spendable_balance_sat(self, **kwargs) -> int:
        return sum(c.d['amount'] for c in self.get_spendable_coins())

    def get_frozen_balance(self) -> Tuple[int, int, int]:
        # freezing coins/addresses is not supported for BLSCT outputs
        return 0, 0, 0

    def is_frozen_coin(self, utxo) -> bool:
        return False

    def get_utxos(self, domain=None, **kwargs):
        utxos = []
        with self._blsct_lock:
            for ohash, d in self.blsct_outputs.items():
                if d.get('spent_by') or d.get('token_id'):
                    continue
                utxos.append(BlsctUtxo(ohash, dict(d)))
        return utxos

    def get_spendable_coins(self, domain=None, **kwargs):
        # staked commitments are locked for staking; they are spent via
        # unstaking (create_unstake_transaction), never as regular inputs
        return [u for u in self.get_utxos()
                if u.d.get('height', 0) > 0 and not u.d.get('staked')]

    def get_staked_outputs(self):
        """Unspent staked commitments (confirmed and unconfirmed)."""
        return [u for u in self.get_utxos() if u.d.get('staked')]

    # -------------------------------------------------------------- tokens

    _NFT_NO_SUBID = 'ffffffffffffffff'  # subid of fungible outputs (-1 le)

    @classmethod
    def _is_nft_token_id(cls, token_id_hex: str) -> bool:
        return len(token_id_hex) == 80 and token_id_hex[64:] != cls._NFT_NO_SUBID

    def get_token_utxos(self, token_id_hex: Optional[str] = None):
        """Unspent token outputs, optionally filtered to one token id."""
        utxos = []
        with self._blsct_lock:
            for ohash, d in self.blsct_outputs.items():
                if d.get('spent_by') or not d.get('token_id') or d.get('staked'):
                    continue
                if token_id_hex and d['token_id'] != token_id_hex:
                    continue
                utxos.append(BlsctUtxo(ohash, dict(d)))
        return utxos

    def get_token_balances(self) -> Dict[str, int]:
        """{token_id_hex: amount} over unspent fungible token outputs."""
        balances = {}  # type: Dict[str, int]
        for u in self.get_token_utxos():
            tid = u.d['token_id']
            if self._is_nft_token_id(tid):
                continue
            balances[tid] = balances.get(tid, 0) + u.d['amount']
        return balances

    def get_nfts(self) -> List[dict]:
        """Unspent NFT outputs (token outputs with a concrete subid)."""
        nfts = []
        for u in self.get_token_utxos():
            tid = u.d['token_id']
            if not self._is_nft_token_id(tid):
                continue
            nfts.append({
                'token_id': tid,
                'token': tid[:64],
                'subid': int.from_bytes(bytes.fromhex(tid[64:]), 'little'),
                'amount': u.d['amount'],
                'output_hash': u.output_hash,
                'height': u.d.get('height', 0),
                'memo': u.d.get('memo', ''),
            })
        nfts.sort(key=lambda n: (n['token'], n['subid']))
        return nfts

    def create_token_transaction(self, token_id_hex: str,
                                 recipients: Sequence[Tuple[str, int, str]],
                                 password=None,
                                 fixed_fee: Optional[int] = None):
        """Send a token (or an NFT: amount 1 of an NFT token id).
        The fee is paid in NAV from the wallet's spendable coins.
        Returns navio_blsct.BuiltTx."""
        utxos, recs, _fee = self._plan_token_send(token_id_hex, recipients)
        keyring = self._spending_keyring(password)
        return navio_blsct.build_signed_tx(
            keyring, utxos, recs, fixed_fee=fixed_fee)

    def _plan_token_send(self, token_id_hex: str,
                         recipients: Sequence[Tuple[str, int, str]]):
        total_out = sum(a for (_, a, _) in recipients)
        # token inputs
        token_coins = [u for u in self.get_token_utxos(token_id_hex)
                       if u.d.get('height', 0) > 0]
        token_coins.sort(key=lambda c: -c.d['amount'])
        t_selected = []
        t_amt = 0
        for c in token_coins:
            if t_amt >= total_out:
                break
            t_selected.append(c)
            t_amt += c.d['amount']
        if t_amt < total_out:
            raise NotEnoughFunds()
        # NAV inputs for the fee
        nav_coins = self.get_spendable_coins()
        nav_coins.sort(key=lambda c: -c.d['amount'])
        est_fee = lambda n: (n + len(recipients) + 4) * navio_blsct.DEFAULT_FEE_PER_COMPONENT
        n_selected = []
        n_amt = 0
        for c in nav_coins:
            if n_amt >= est_fee(len(t_selected) + len(n_selected)):
                break
            n_selected.append(c)
            n_amt += c.d['amount']
        if n_amt < est_fee(len(t_selected) + len(n_selected)):
            raise NotEnoughFunds()
        utxos = ([self._coin_to_spendable(c) for c in t_selected]
                 + [self._coin_to_spendable(c) for c in n_selected])
        recs = [Recipient(addr, amount, memo or '', token_id_hex=token_id_hex)
                for (addr, amount, memo) in recipients]
        return utxos, recs, est_fee(len(t_selected) + len(n_selected))

    def get_token_display_name(self, token_id_hex: str) -> str:
        names = self.db.get('blsct_token_names') or {}
        name = names.get(token_id_hex) or names.get(token_id_hex[:64])
        return name or (token_id_hex[:16] + '...')

    def _remember_token_name(self, token_id_hex: str, name: str):
        names = self.db.get('blsct_token_names') or {}
        if names.get(token_id_hex[:64]) != name:
            names[token_id_hex[:64]] = name
            self.db.put('blsct_token_names', names)

    def get_created_tokens(self) -> Dict[str, dict]:
        """Tokens/collections created by this wallet, keyed by the token's
        public key (hex). A wallet can create any number of tokens; each
        token key is derived from the seed's master token key and the
        token's metadata + total supply (navio-core KeyMan::GetTokenKey)."""
        # deep-convert: db.get returns StoredDicts (not deepcopy-able),
        # and we hand this dict back to db.put after modifying it
        def plain(o):
            if isinstance(o, dict):
                return {k: plain(v) for k, v in o.items()}
            if isinstance(o, (list, tuple)):
                return [plain(v) for v in o]
            return o
        tokens = plain(dict(self.db.get('blsct_tokens') or {}))
        legacy = plain(dict(self.db.get('blsct_token_meta') or {})) or None
        if legacy and not tokens:
            # migrate the old single-token record
            try:
                pub = self.keyring.token_pubkey_for(
                    legacy.get('metadata') or {}, legacy.get('total_supply') or 0)
                key = pub.serialize()
                key = key.hex() if isinstance(key, bytes) else key
            except Exception:
                key = 'legacy'
            tokens[key] = dict(legacy)
            self.db.put('blsct_tokens', tokens)
        return tokens

    def _resolve_created_token(self, token: Optional[str]) -> Tuple[str, dict]:
        tokens = self.get_created_tokens()
        if not tokens:
            raise UserFacingException('this wallet has not created any tokens')
        if token:
            t = token.lower()
            for key, entry in tokens.items():
                if t in (key.lower(), (entry.get('token_id') or '').lower(),
                         (entry.get('metadata') or {}).get('name', '').lower()):
                    return key, entry
            raise UserFacingException(f'unknown token: {token}')
        if len(tokens) == 1:
            return next(iter(tokens.items()))
        names = ', '.join((e.get('metadata') or {}).get('name', k[:16])
                          for k, e in tokens.items())
        raise UserFacingException(
            f'this wallet created several tokens ({names}); specify which one')

    def create_token(self, metadata: Dict[str, str], total_supply: int,
                     is_nft: bool = False, password=None):
        """Create a token / NFT collection. A wallet can create many; the
        per-token key is derived from the seed and the token's metadata +
        supply, so the same metadata always maps to the same token.
        Returns BuiltTx."""
        keyring = self._spending_keyring(password)
        coins = self.get_spendable_coins()
        coins.sort(key=lambda c: -c.d['amount'])
        est = 4 * navio_blsct.DEFAULT_FEE_PER_COMPONENT
        selected, amt = [], 0
        for c in coins:
            if amt >= est:
                break
            selected.append(c)
            amt += c.d['amount']
        if amt < est:
            raise NotEnoughFunds()
        built = navio_blsct.build_create_token_tx(
            keyring, [self._coin_to_spendable(c) for c in selected],
            metadata, total_supply, is_nft)
        tokens = self.get_created_tokens()
        pub = keyring.token_pubkey_for(metadata, total_supply)
        key = pub.serialize()
        key = key.hex() if isinstance(key, bytes) else key
        tokens[key] = {
            'metadata': dict(metadata or {}),
            'total_supply': int(total_supply),
            'is_nft': bool(is_nft),
            'create_txid': built.txid,
            'token_id': None,  # learned from the first mint output
        }
        self.db.put('blsct_tokens', tokens)
        return built

    def _mint_common(self, build, password, token_entry_key=None):
        keyring = self._spending_keyring(password)
        coins = self.get_spendable_coins()
        coins.sort(key=lambda c: -c.d['amount'])
        est = 4 * navio_blsct.DEFAULT_FEE_PER_COMPONENT
        selected, amt = [], 0
        for c in coins:
            if amt >= est:
                break
            selected.append(c)
            amt += c.d['amount']
        if amt < est:
            raise NotEnoughFunds()
        built = build(keyring, [self._coin_to_spendable(c) for c in selected])
        # learn the token id from the mint output and bind the stored metadata
        try:
            parsed = navio_blsct.parse_tx_hex(built.raw_hex)
            for out in parsed.outputs:
                if out.token_id and out.token_id != bytes(32):
                    tid = (out.token_id.hex()
                           + out.token_nft_id.to_bytes(8, 'little', signed=True).hex())
                    tokens = self.get_created_tokens()
                    entry = tokens.get(token_entry_key) if token_entry_key else None
                    if entry is not None:
                        entry['token_id'] = out.token_id.hex()
                        self.db.put('blsct_tokens', tokens)
                    meta = (entry or {}).get('metadata') or {}
                    if meta.get('name'):
                        self._remember_token_name(tid, meta['name'])
                    break
        except Exception:
            self.logger.exception('could not extract token id from mint tx')
        return built

    def mint_token(self, dest_address: str, amount: int, password=None,
                   token: Optional[str] = None):
        """Mint units of one of this wallet's fungible tokens. `token`
        selects by name, token id, or token public key; may be omitted when
        the wallet created exactly one token. Returns BuiltTx."""
        key, entry = self._resolve_created_token(token)
        return self._mint_common(
            lambda keyring, utxos: navio_blsct.build_mint_token_tx(
                keyring, utxos, dest_address, amount,
                token_key=keyring.token_key_for(
                    entry.get('metadata') or {}, entry.get('total_supply') or 0)),
            password, token_entry_key=key)

    def mint_nft(self, dest_address: str, nft_id: int,
                 metadata: Dict[str, str], password=None,
                 token: Optional[str] = None):
        """Mint one NFT of one of this wallet's collections. `metadata` is
        the NFT item's own metadata; `token` selects the collection (name,
        token id, or public key), optional when there is exactly one.
        Returns BuiltTx."""
        key, entry = self._resolve_created_token(token)
        return self._mint_common(
            lambda keyring, utxos: navio_blsct.build_mint_nft_tx(
                keyring, utxos, dest_address, nft_id, metadata,
                token_key=keyring.token_key_for(
                    entry.get('metadata') or {}, entry.get('total_supply') or 0)),
            password, token_entry_key=key)

    def get_staking_rewards_sat(self) -> int:
        """Total staking rewards ever received: outputs on the staking
        sub-account that are not staked commitments, plus outputs to any
        delegation reward address. Includes already-spent rewards."""
        with self._blsct_lock:
            reward_addrs = set()
            for d in self.blsct_outputs.values():
                deleg = d.get('delegation') or {}
                if deleg.get('reward_address'):
                    reward_addrs.add(deleg['reward_address'])
            total = 0
            for d in self.blsct_outputs.values():
                if d.get('token_id') or d.get('staked'):
                    continue
                if d.get('account') == STAKING_ACCOUNT or d.get('address') in reward_addrs:
                    total += d['amount']
        return total

    def get_staked_balance_sat(self) -> int:
        return sum(u.d['amount'] for u in self.get_staked_outputs())

    # --------------------------------------------------------------- history

    def get_history_items(self) -> List[dict]:
        """Synthesize a wallet history from the recorded outputs.
        One item per txid: received minus spent."""
        events = {}
        with self._blsct_lock:
            for ohash, d in self.blsct_outputs.items():
                if d.get('token_id'):
                    continue  # token amounts are not NAV; shown in the tokens view
                rtx = d.get('tx_hash')
                if rtx:
                    ev = events.setdefault(rtx, {'height': d.get('height', 0), 'delta': 0, 'memos': [],
                                                 'recv_hashes': [], 'spent_ref': None})
                    ev['delta'] += d['amount']
                    ev['height'] = d.get('height', 0)
                    ev['recv_hashes'].append(ohash)
                    if d.get('memo'):
                        ev['memos'].append(d['memo'])
                stx = d.get('spent_by')
                if stx:
                    ev = events.setdefault(stx, {'height': d.get('spent_height', 0), 'delta': 0, 'memos': [],
                                                 'recv_hashes': [], 'spent_ref': None})
                    ev['delta'] -= d['amount']
                    ev['height'] = d.get('spent_height', 0)
                    if d.get('spent_ref') and not ev['spent_ref']:
                        ev['spent_ref'] = d['spent_ref']
        items = []
        for txid, ev in events.items():
            # user-facing reference: an output hash, not the txid. BLSCT
            # txids mutate when a block aggregates transactions; output
            # hashes are stable, and navio-core references transactions
            # the same way. Outgoing: the destination output hash recorded
            # when the tx was built/seen; incoming: our received output.
            if ev['delta'] < 0 and ev['spent_ref']:
                ref = ev['spent_ref']
            elif ev['recv_hashes']:
                ref = sorted(ev['recv_hashes'])[0]
            else:
                ref = ev['spent_ref'] or txid
            items.append({
                'txid': ref,
                'height': ev['height'],
                'amount_sat': ev['delta'],
                'memos': ev['memos'],
            })
        items.sort(key=lambda x: (x['height'] if x['height'] > 0 else 10**9))
        return items

    def get_detailed_history(self, from_timestamp=None, to_timestamp=None,
                             fx=None, show_addresses=False,
                             from_height=None, to_height=None):
        items = self.get_history_items()
        local_height = self.network.get_local_height() if self.network else 0
        out = []
        for it in items:
            if from_height is not None and it['height'] < from_height:
                continue
            if to_height is not None and it['height'] > to_height:
                continue
            out.append({
                'txid': it['txid'],
                'height': it['height'],
                'confirmations': max(0, local_height - it['height'] + 1) if it['height'] > 0 else 0,
                'value': str(util.Satoshis(it['amount_sat'])),
                'memos': it['memos'],
            })
        end_balance = sum(self.get_balance()[:2])
        return {'transactions': out,
                'end_balance': str(util.Satoshis(end_balance))}

    def get_onchain_history(self, *, domain=None):
        for it in self.get_history_items():
            yield {
                'txid': it['txid'],
                'tx_hash': it['txid'],
                'height': it['height'],
                'amount_sat': it['amount_sat'],
            }

    def is_onchain_invoice_paid(self, invoice) -> Tuple[bool, Optional[int]]:
        """Payment detection for receive requests: sum our recorded outputs
        to the request address (the base implementation walks adb structures
        a BLSCT wallet does not populate)."""
        addr = invoice.get_address()
        if not addr:
            return False, None
        amount_sat = invoice.get_amount_sat() or 0
        local_height = self.network.get_local_height() if self.network else 0
        total = 0
        confs = []
        with self._blsct_lock:
            for d in self.blsct_outputs.values():
                if d.get('address') != addr or d.get('token_id'):
                    continue
                total += d['amount']
                h = d.get('height') or 0
                confs.append(max(0, local_height - h + 1) if h > 0 else 0)
        if total <= 0 or (amount_sat and total < amount_sat):
            return False, None
        return True, (min(confs) if confs else 0)

    def _on_incoming_output(self, *, address: str, amount: int, account: int,
                            staked: bool, token_id: Optional[str],
                            near_tip: bool):
        """Called by the synchronizer when a new output of ours is recorded."""
        if account != MAIN_ACCOUNT or staked or token_id:
            return
        try:
            req = self.get_request_by_addr(address)
            if req:
                util.trigger_callback(
                    'request_status', self, req.get_id(), self.get_invoice_status(req))
        except Exception:
            self.logger.exception('request status update failed')
        if near_tip:
            # live payment (not initial catch-up scan): notify the GUI
            util.trigger_callback('blsct_payment_received', self, address, amount)

    def get_tx_status(self, tx_hash, tx_mined_info):
        # raw txs are not stored locally, so the base implementation would
        # report unconfirmed txs as "unknown"
        if tx_mined_info.conf == 0:
            return 0, _('Unconfirmed')
        return super().get_tx_status(tx_hash, tx_mined_info)

    def get_num_parents(self, txid: str):
        # no public parent-tx graph for confidential outputs
        return None

    def get_tx_parents(self, txid: str):
        return {}

    def _header_timestamp(self, height: int) -> Optional[int]:
        """Timestamp of the block at `height`, from the locally stored
        header chain (None if unconfirmed or header not downloaded yet)."""
        if height <= 0 or not self.network:
            return None
        header = self.network.blockchain().read_header(height)
        return header.get('timestamp') if header else None

    def get_full_history(self, *, fx=None, onchain_domain=None,
                         include_lightning=True):
        """Qt/QML history model entry point. The Abstract_Wallet version
        walks adb/lightning structures a BLSCT wallet does not have, so
        synthesize the same shape from our recorded outputs."""
        from .util import OrderedDictWithIndex, Satoshis, timestamp_to_datetime
        local_height = self.network.get_local_height() if self.network else 0
        out = OrderedDictWithIndex()
        for it in self.get_history_items():
            height = it['height']
            conf = max(0, local_height - height + 1) if height > 0 else 0
            amount = Satoshis(it['amount_sat'])
            timestamp = self._header_timestamp(height)
            out[it['txid']] = {
                'txid': it['txid'],
                'lightning': False,
                'incoming': it['amount_sat'] > 0,
                'complete': True,
                'value': amount,
                'bc_value': amount,
                'ln_value': Satoshis(0),
                'timestamp': timestamp,
                'date': timestamp_to_datetime(timestamp),
                'height': height,
                'confirmations': conf,
                'label': ', '.join(it.get('memos') or []),
                'fee_sat': None,
                'monotonic_timestamp': timestamp,
            }
        return out

    # ------------------------------------------------------------ networking

    async def main_loop(self):
        self.logger.info("starting blsct wallet taskgroup.")
        try:
            async with self.taskgroup as group:
                await group.spawn(asyncio.Event().wait)  # run forever
        except Exception:
            self.logger.exception("taskgroup died.")
        finally:
            util.trigger_callback('wallet_updated', self)
            self.logger.info("taskgroup stopped.")

    def start_network(self, network):
        assert self.network is None, "already started"
        self.taskgroup = OldTaskGroup()
        self.network = network
        if network:
            asyncio.run_coroutine_threadsafe(self.main_loop(), network.asyncio_loop)
            self.blsct_synchronizer = BlsctSynchronizer(self, network)

    async def stop(self):
        self.unregister_callbacks()
        try:
            async with ignore_after(5):
                if self.blsct_synchronizer:
                    await self.blsct_synchronizer.stop()
                    self.blsct_synchronizer = None
                if self.network:
                    self.network = None
                if self.taskgroup:
                    await self.taskgroup.cancel_remaining()
                    self.taskgroup = None
                await self.adb.stop()
        finally:
            self.save_db()

    def is_up_to_date(self) -> bool:
        return self._up_to_date

    def set_blsct_up_to_date(self, b: bool):
        self._up_to_date = b
        if b:
            self.save_db()
        util.trigger_callback('wallet_updated', self)
        util.trigger_callback('status')

    # ----------------------------------------------------- output bookkeeping

    def _store_output(self, output_hash: str, *, tx_hash: str, height: int,
                      amount: int, gamma_hex: str, blinding_key_hex: str,
                      account: int, addr_index: int, memo: str,
                      token_id: Optional[str], staked: bool = False,
                      delegation: Optional[dict] = None):
        with self._blsct_lock:
            existing = self.blsct_outputs.get(output_hash)
            if existing:
                existing['tx_hash'] = tx_hash
                existing['height'] = height
                return
            self.blsct_outputs[output_hash] = {
                'tx_hash': tx_hash,
                'height': height,
                'amount': amount,
                'gamma': gamma_hex,
                'blinding_key': blinding_key_hex,
                'account': account,
                'addr_index': addr_index,
                'address': self.keyring.address(account, addr_index),
                'memo': memo or '',
                'token_id': token_id,
                'staked': staked,
                # {'delegate_key': hex, 'reward_address': str} for outputs
                # whose stake is delegated to a third-party staker
                'delegation': delegation,
                'spent_by': None,
                'spent_height': None,
            }

    def _classify_output(self, parsed: ParsedTxOut) -> Tuple[bool, Optional[dict]]:
        """Detect whether a (recovered, ours) output is a staked commitment
        and, if so, whether it carries a cold-staking delegation we can
        recover with our view key."""
        s = parsed.script
        # CTxOut::IsStakedCommitment(): OP_STAKED_COMMITMENT OP_PUSHDATA2
        # <proof> OP_TRUE
        staked = (len(s) > 7 and s[0] == 0xb9 and s[1] == 0x4d and s[-1] == 0x51)
        delegation = None
        if staked and parsed.vdata:
            blob = stake_delegation.data_from_predicate(parsed.vdata)
            if blob is not None and stake_delegation.is_delegation_data(blob):
                try:
                    nonce_obj = self.keyring.calc_nonce(parsed.blinding_key.hex())
                    nonce = bytes.fromhex(nonce_obj.get_point().serialize())
                    req = stake_delegation.recover_owner_info(blob, nonce)
                except Exception:
                    self.logger.exception('could not decode delegation payload')
                    req = None
                if req is not None:
                    delegation = {
                        'delegate_key': req.delegate_key.hex(),
                        'reward_address': req.reward_address,
                    }
        return staked, delegation

    def _mark_spent(self, output_hash: str, tx_hash: str, height: int,
                    ref: Optional[str] = None):
        with self._blsct_lock:
            d = self.blsct_outputs.get(output_hash)
            if d is not None:
                d['spent_by'] = tx_hash
                d['spent_height'] = height
                # stable reference for the spending tx: the destination
                # output hash. BLSCT txids mutate when a block aggregates
                # transactions; output hashes do not. First write wins so
                # the reference recorded at broadcast survives confirmation.
                if ref and not d.get('spent_ref'):
                    d['spent_ref'] = ref

    def _unspend_above(self, height: int):
        with self._blsct_lock:
            for ohash in list(self.blsct_outputs.keys()):
                d = self.blsct_outputs[ohash]
                if d.get('height', 0) > height:
                    self.blsct_outputs.pop(ohash)
                    continue
                if d.get('spent_by') and (d.get('spent_height') or 0) > height:
                    d['spent_by'] = None
                    d['spent_height'] = None

    # ------------------------------------------------------------------ send

    def get_view_key_pair(self) -> Tuple[str, str]:
        """(private view key hex, public spend key hex) -- enough to create a
        watch-only wallet that sees this wallet's history and balances."""
        return (self.keystore.view_key_hex, self.keystore.spend_pub_hex)

    def get_view_key_str(self) -> str:
        """navio-core compatible: 160 hex chars, view key (32 bytes)
        followed by the public spending key (48 bytes). Can be passed
        directly to navio-core's createwallet seed parameter."""
        vk, sp = self.get_view_key_pair()
        return f'{vk}{sp}'

    def _spending_keyring(self, password) -> BlsctKeyRing:
        if self.is_watching_only():
            raise UserFacingException(
                _('This is a watching-only wallet: it cannot spend or stake.'))
        keyring = self.keyring
        if self.keystore.has_password():
            self.keystore.check_password(password)
        if not keyring.can_spend():
            keyring = BlsctKeyRing(
                self.keystore.get_seed_hex(password),
                passphrase=self.keystore.get_passphrase(password) or None)
            keyring.subaddr_by_hashid = dict(self.keyring.subaddr_by_hashid)
        return keyring

    @staticmethod
    def _coin_to_spendable(c: 'BlsctUtxo') -> SpendableOutput:
        d = c.d
        return SpendableOutput(
            output_hash=c.output_hash,
            amount=d['amount'],
            gamma_hex=d['gamma'],
            blinding_key_hex=d['blinding_key'],
            account=d['account'],
            index=d['addr_index'],
            staked_commitment=bool(d.get('staked')),
            token_id_hex=d.get('token_id'),
        )

    def _plan_send(self, recipients: Sequence[Tuple[str, int, str]],
                   domain_coins: Optional[Sequence[str]] = None,
                   subtract_fee_from_amount: bool = False):
        """Coin selection for a plain send; keyring-independent.
        -> (utxos, recipients, est_fee)"""
        coins = self.get_spendable_coins()
        if domain_coins:
            coins = [c for c in coins if c.output_hash in domain_coins]
        coins.sort(key=lambda c: -c.d['amount'])
        total_out = sum(a for (_, a, _) in recipients)
        selected = []
        selected_amt = 0
        est_fee = lambda n: (n + len(recipients) + 2) * navio_blsct.DEFAULT_FEE_PER_COMPONENT
        for c in coins:
            if selected_amt >= total_out + (0 if subtract_fee_from_amount else est_fee(len(selected))):
                break
            selected.append(c)
            selected_amt += c.d['amount']
        if selected_amt < total_out + (0 if subtract_fee_from_amount else est_fee(len(selected))):
            if not (subtract_fee_from_amount and selected_amt >= total_out):
                raise NotEnoughFunds()
        utxos = [self._coin_to_spendable(c) for c in selected]
        recs = [r if isinstance(r, Recipient) else Recipient(r[0], r[1], r[2] or '')
                for r in recipients]
        return utxos, recs, est_fee(len(selected))

    def create_blsct_transaction(self, recipients: Sequence[Tuple[str, int, str]],
                                 password=None, fixed_fee: Optional[int] = None,
                                 domain_coins: Optional[Sequence[str]] = None,
                                 subtract_fee_from_amount: bool = False):
        """recipients: [(nav1 address, amount_sats, memo)]
        Returns navio_blsct.BuiltTx."""
        keyring = self._spending_keyring(password)
        utxos, recs, _fee = self._plan_send(
            recipients, domain_coins, subtract_fee_from_amount)
        built = navio_blsct.build_signed_tx(
            keyring, utxos, recs,
            fixed_fee=fixed_fee,
            subtract_fee_from_amount=subtract_fee_from_amount)
        return built

    # ---------------------------------------------------------------- staking

    @staticmethod
    def _delegation_id(d: Optional[dict]) -> str:
        """Group identity of a stake: same delegate key and reward address
        (or '' for undelegated stakes). Mirrors DelegationRequest::GetId()."""
        if not d:
            return ''
        return d['delegate_key'] + ':' + d['reward_address']

    def _next_staking_address(self) -> str:
        used = set()
        with self._blsct_lock:
            for d in self.blsct_outputs.values():
                if d.get('account') == STAKING_ACCOUNT:
                    used.add(d.get('addr_index'))
        index = 0
        while index in used:
            index += 1
        self.keyring.ensure_keypool(STAKING_ACCOUNT, index + 1 + GAP_LIMIT)
        return self.keyring.address(STAKING_ACCOUNT, index)

    def _parse_delegate_key(self, delegate_key_hex: str) -> bytes:
        b = navio_blsct.get_blsct()
        try:
            key_bytes = bytes.fromhex(delegate_key_hex)
            if len(key_bytes) != stake_delegation.POINT_SIZE:
                raise ValueError
            if not b.Point.deserialize(delegate_key_hex).is_valid():
                raise ValueError
        except Exception:
            raise UserFacingException('delegate key is not a valid 48-byte G1 point')
        return key_bytes

    def create_stake_transaction(self, amount: int, password=None, *,
                                 delegate_key_hex: Optional[str] = None,
                                 reward_address: Optional[str] = None,
                                 consolidate: bool = True,
                                 fixed_fee: Optional[int] = None):
        """Lock `amount` sats for staking (a staked-commitment output to our
        own staking sub-address).

        With `delegate_key_hex`, block production is delegated to that
        staking operator (cold staking): the output carries the commitment
        opening encrypted to the operator, who can then stake it but never
        spend it. Block rewards are requested to be paid to `reward_address`
        (default: a fresh address of this wallet); note the reward routing is
        advisory - the operator controls its own coinbase.

        Existing confirmed stakes with the same delegation identity (same
        delegate key + reward address; or undelegated, for a plain stake) are
        consolidated into the new output. Returns navio_blsct.BuiltTx."""
        if amount <= 0:
            raise UserFacingException('amount must be positive')
        delegation = None
        if delegate_key_hex:
            if not navio_blsct.supports_data_predicate():
                raise UserFacingException(
                    'stake delegation is not supported by the installed '
                    'navio-blsct bindings; please upgrade')
            key_bytes = self._parse_delegate_key(delegate_key_hex)
            if not reward_address:
                reward_address = self.get_unused_address()
            try:
                navio_blsct.get_blsct().Address.decode(reward_address)
            except Exception:
                raise UserFacingException('invalid reward address')
            delegation = stake_delegation.DelegationRequest(key_bytes, reward_address)
        elif reward_address:
            raise UserFacingException('reward_address requires a delegate key')

        utxos, recs, _fee = self._plan_stake(
            amount, delegation=delegation, consolidate=consolidate)
        keyring = self._spending_keyring(password)
        return navio_blsct.build_signed_tx(keyring, utxos, recs,
                                           fixed_fee=fixed_fee)

    def _plan_stake(self, amount: int, *, delegation, consolidate: bool = True):
        staked_inputs = []
        if consolidate:
            want_id = delegation.id() if delegation else ''
            staked_inputs = [
                u for u in self.get_staked_outputs()
                if u.d.get('height', 0) > 0
                and self._delegation_id(u.d.get('delegation')) == want_id
            ]
        consolidated = sum(u.d['amount'] for u in staked_inputs)
        total_staked = amount + consolidated
        if total_staked < MIN_STAKE_AMOUNT:
            raise UserFacingException(
                f'total stake must be at least {MIN_STAKE_AMOUNT} sats')

        coins = self.get_spendable_coins()
        coins.sort(key=lambda c: -c.d['amount'])
        est_fee = lambda n: (n + 3) * navio_blsct.DEFAULT_FEE_PER_COMPONENT
        selected = []
        selected_amt = 0
        for c in coins:
            if selected_amt >= amount + est_fee(len(selected) + len(staked_inputs)):
                break
            selected.append(c)
            selected_amt += c.d['amount']
        if selected_amt < amount + est_fee(len(selected) + len(staked_inputs)):
            raise NotEnoughFunds()

        utxos = [self._coin_to_spendable(c) for c in selected + staked_inputs]
        stake_addr = self._next_staking_address()
        rec = Recipient(stake_addr, total_staked, '', 'StakedCommitment',
                        MIN_STAKE_AMOUNT, delegation)
        return utxos, [rec], est_fee(len(selected) + len(staked_inputs))

    def _parse_stake_delegation(self, delegate_key_hex, reward_address):
        """Shared validation for stake/delegate params; -> DelegationRequest|None"""
        if not delegate_key_hex:
            if reward_address:
                raise UserFacingException('reward_address requires a delegate key')
            return None
        if not navio_blsct.supports_data_predicate():
            raise UserFacingException(
                'stake delegation is not supported by the installed '
                'navio-blsct bindings; please upgrade')
        key_bytes = self._parse_delegate_key(delegate_key_hex)
        if not reward_address:
            reward_address = self.get_unused_address()
        try:
            navio_blsct.get_blsct().Address.decode(reward_address)
        except Exception:
            raise UserFacingException('invalid reward address')
        return stake_delegation.DelegationRequest(key_bytes, reward_address)

    def create_unstake_transaction(self, amount: Optional[int] = None,
                                   password=None, *,
                                   delegate_key_hex: Optional[str] = None,
                                   fixed_fee: Optional[int] = None):
        """Unlock staked funds. Operates on one delegation group at a time:
        by default the undelegated stakes; pass `delegate_key_hex` to unstake
        coins delegated to that operator. `amount=None` unstakes the whole
        group. The unstaked amount (minus the fee) becomes a normal spendable
        output; any remainder stays staked with the same delegation. Returns
        navio_blsct.BuiltTx."""
        group = [u for u in self.get_staked_outputs() if u.d.get('height', 0) > 0]
        if delegate_key_hex:
            key = delegate_key_hex.lower()
            group = [u for u in group
                     if (u.d.get('delegation') or {}).get('delegate_key') == key]
        else:
            group = [u for u in group if not u.d.get('delegation')]
        if not group:
            raise UserFacingException('no matching staked outputs')
        total_group = sum(u.d['amount'] for u in group)
        if amount is None:
            amount = total_group
        if amount <= 0 or amount > total_group:
            raise UserFacingException(
                f'invalid unstake amount (staked in this group: {total_group} sats)')

        group.sort(key=lambda u: -u.d['amount'])
        selected = []
        selected_amt = 0
        for u in group:
            if selected_amt >= amount:
                break
            selected.append(u)
            selected_amt += u.d['amount']
        remainder = selected_amt - amount

        recipients = []
        if remainder > 0:
            if remainder < MIN_STAKE_AMOUNT:
                raise UserFacingException(
                    f'the remaining stake would fall below the minimum '
                    f'({MIN_STAKE_AMOUNT} sats); unstake less or everything')
            deleg = selected[0].d.get('delegation')
            delegation = None
            if deleg:
                if not navio_blsct.supports_data_predicate():
                    raise UserFacingException(
                        'stake delegation is not supported by the installed '
                        'navio-blsct bindings; please upgrade')
                delegation = stake_delegation.DelegationRequest(
                    bytes.fromhex(deleg['delegate_key']), deleg['reward_address'])
            stake_addr = self._next_staking_address()
            recipients.append(Recipient(stake_addr, remainder, '',
                                        'StakedCommitment', MIN_STAKE_AMOUNT,
                                        delegation))

        keyring = self._spending_keyring(password)
        utxos = [self._coin_to_spendable(u) for u in selected]
        return navio_blsct.build_signed_tx(keyring, utxos, recipients,
                                           fixed_fee=fixed_fee)

    def _plan_unstake(self, amount: Optional[int] = None, *,
                      delegate_key_hex: Optional[str] = None):
        """Same selection logic as create_unstake_transaction, without the
        keyring. -> (utxos, recipients, est_fee)"""
        group = [u for u in self.get_staked_outputs() if u.d.get('height', 0) > 0]
        if delegate_key_hex:
            key = delegate_key_hex.lower()
            group = [u for u in group
                     if (u.d.get('delegation') or {}).get('delegate_key') == key]
        else:
            group = [u for u in group if not u.d.get('delegation')]
        if not group:
            raise UserFacingException('no matching staked outputs')
        total_group = sum(u.d['amount'] for u in group)
        if amount is None:
            amount = total_group
        if amount <= 0 or amount > total_group:
            raise UserFacingException(
                f'invalid unstake amount (staked in this group: {total_group} sats)')
        group.sort(key=lambda u: -u.d['amount'])
        selected = []
        selected_amt = 0
        for u in group:
            if selected_amt >= amount:
                break
            selected.append(u)
            selected_amt += u.d['amount']
        remainder = selected_amt - amount
        recipients = []
        if remainder > 0:
            if remainder < MIN_STAKE_AMOUNT:
                raise UserFacingException(
                    f'the remaining stake would fall below the minimum '
                    f'({MIN_STAKE_AMOUNT} sats); unstake less or everything')
            deleg = selected[0].d.get('delegation')
            delegation = None
            if deleg:
                if not navio_blsct.supports_data_predicate():
                    raise UserFacingException(
                        'stake delegation is not supported by the installed '
                        'navio-blsct bindings; please upgrade')
                delegation = stake_delegation.DelegationRequest(
                    bytes.fromhex(deleg['delegate_key']), deleg['reward_address'])
            stake_addr = self._next_staking_address()
            recipients.append(Recipient(stake_addr, remainder, '',
                                        'StakedCommitment', MIN_STAKE_AMOUNT,
                                        delegation))
        utxos = [self._coin_to_spendable(u) for u in selected]
        est_fee = (len(utxos) + len(recipients) + 3) * navio_blsct.DEFAULT_FEE_PER_COMPONENT
        return utxos, recipients, est_fee

    # ------------------------------------------------------------- air-gap

    def _airgap_env(self) -> dict:
        from . import constants
        return {
            'genesis_hex': constants.net.GENESIS,
            'fingerprint_hex': self.get_fingerprint(),
        }

    def _proposal_from_plan(self, plan) -> dict:
        from . import airgap
        utxos, recipients, fee = plan
        return airgap.make_proposal_payload(
            **self._airgap_env(), utxos=utxos, recipients=recipients, fee=fee)

    def make_send_proposal(self, recipients, *, domain_coins=None,
                           subtract_fee_from_amount: bool = False) -> dict:
        from . import airgap
        utxos, recs, fee = self._plan_send(
            recipients, domain_coins, subtract_fee_from_amount)
        return airgap.make_proposal_payload(
            **self._airgap_env(), utxos=utxos, recipients=recs, fee=fee,
            subtract_fee_from_amount=subtract_fee_from_amount)

    def make_stake_proposal(self, amount: int, *,
                            delegate_key_hex: Optional[str] = None,
                            reward_address: Optional[str] = None,
                            consolidate: bool = True) -> dict:
        if amount <= 0:
            raise UserFacingException('amount must be positive')
        delegation = self._parse_stake_delegation(delegate_key_hex, reward_address)
        return self._proposal_from_plan(
            self._plan_stake(amount, delegation=delegation, consolidate=consolidate))

    def make_unstake_proposal(self, amount: Optional[int] = None, *,
                              delegate_key_hex: Optional[str] = None) -> dict:
        return self._proposal_from_plan(
            self._plan_unstake(amount, delegate_key_hex=delegate_key_hex))

    def make_token_send_proposal(self, token_id_hex: str, recipients) -> dict:
        return self._proposal_from_plan(
            self._plan_token_send(token_id_hex, recipients))

    def check_airgap_proposal(self, payload: dict) -> dict:
        """Offline-signer side: validate the envelope and structure and
        return a display summary. Raises UserFacingException on mismatch."""
        from . import airgap
        airgap.check_envelope(payload, expected_type='prop', **self._airgap_env())
        utxos, recipients, fee, subtract = airgap.proposal_to_plan(payload)
        # classify each proposed output: does it pay this wallet?
        own = set(self.get_addresses())
        outputs = []
        for r in recipients:
            outputs.append({
                'address': r.address,
                'amount': r.amount,
                'memo': r.memo,
                'type': r.output_type,
                'is_mine': r.address in own,
                'token_id': r.token_id_hex or '',
                'delegate_key': (r.delegation.delegate_key.hex()
                                 if r.delegation else ''),
                'reward_address': (r.delegation.reward_address
                                   if r.delegation else ''),
            })
        return {
            'outputs': outputs,
            'fee': fee,
            'subtract_fee_from_amount': subtract,
            'total_in': sum(u.amount for u in utxos),
            'num_inputs': len(utxos),
            'age_seconds': airgap.proposal_age_seconds(payload),
        }

    def sign_airgap_proposal(self, payload: dict, password=None) -> dict:
        """Offline-signer side: build and sign the transaction described by a
        (checked) proposal; change is derived by this wallet's own builder.
        Returns the reply payload."""
        from . import airgap
        airgap.check_envelope(payload, expected_type='prop', **self._airgap_env())
        utxos, recipients, fee, subtract = airgap.proposal_to_plan(payload)
        # make sure the keypool covers every referenced index
        for u in utxos:
            self.keyring.ensure_keypool(u.account, u.index + 1)
        keyring = self._spending_keyring(password)
        built = navio_blsct.build_signed_tx(
            keyring, utxos, recipients, fixed_fee=fee,
            subtract_fee_from_amount=subtract)
        return airgap.make_reply_payload(
            **self._airgap_env(), txid_hex=built.txid, raw_hex=built.raw_hex)

    def check_airgap_reply(self, payload: dict) -> Tuple[str, str]:
        """Online side: validate a signed reply; -> (txid_hex, raw_hex)."""
        from . import airgap
        airgap.check_envelope(payload, expected_type='signed', **self._airgap_env())
        raw = payload.get('raw')
        txid = payload.get('txid')
        if not (isinstance(raw, bytes) and raw and isinstance(txid, bytes)
                and len(txid) == 32):
            raise UserFacingException(_('Malformed signed transaction payload'))
        parsed = navio_blsct.parse_tx_hex(raw.hex())
        if parsed.txid != txid.hex():
            raise UserFacingException(_('Signed transaction id mismatch'))
        return txid.hex(), raw.hex()

    async def broadcast_blsct_transaction(self, raw_hex: str) -> str:
        if not self.network or not self.network.interface:
            raise UserFacingException('not connected')
        txid = await self.network.interface.session.send_request(
            'blockchain.transaction.broadcast', [raw_hex], timeout=30)
        ref = self.process_own_transaction(raw_hex, txid)
        self.save_db()
        util.trigger_callback('wallet_updated', self)
        # return the stable output-hash reference (txids mutate on
        # aggregation); callers display this to the user
        return ref or txid

    def blsct_tx_reference(self, parsed) -> Optional[str]:
        """Stable user-facing reference for a tx we built: the hash of the
        destination output (first output not recovered by our view key),
        falling back to the first output. Same convention as navio-core,
        which references transactions by output hash because BLSCT txids
        mutate when transactions are aggregated into a block."""
        fallback = None
        for out in parsed.outputs:
            if not out.has_blsct:
                continue
            if fallback is None:
                fallback = out.output_hash
            pair = self.keyring.match_output(
                out.blinding_key.hex(), out.spending_key.hex(), out.view_tag)
            if not pair:
                return out.output_hash
        return fallback

    def process_own_transaction(self, raw_hex: str, txid: str) -> Optional[str]:
        """Mark inputs spent and pick up our own (change) outputs from a tx
        we just broadcast. Returns the stable output-hash reference."""
        parsed = parse_tx_hex(raw_hex)
        ref = self.blsct_tx_reference(parsed)
        for tin in parsed.inputs:
            self._mark_spent(tin.prevout_hash, txid, 0, ref=ref)
        for out in parsed.outputs:
            if not out.has_blsct:
                continue
            pair = self.keyring.match_output(
                out.blinding_key.hex(), out.spending_key.hex(), out.view_tag)
            if not pair:
                continue
            rec = self.keyring.try_recover_output(out)
            if not rec:
                continue
            token_id = out.token_id.hex() if (out.token_id and out.token_id != bytes(32)) else None
            staked, delegation = self._classify_output(out)
            self._store_output(out.output_hash,
                               tx_hash=txid, height=0, amount=rec.amount,
                               gamma_hex=rec.gamma_hex,
                               blinding_key_hex=out.blinding_key.hex(),
                               account=pair[0], addr_index=pair[1],
                               memo=rec.memo, token_id=token_id,
                               staked=staked, delegation=delegation)
        return ref


class BlsctSynchronizer(NetworkJobOnDefaultServer):
    """Linear block scanner: downloads BLSCT key material for every block
    and trial-matches outputs against the wallet's view key."""

    def __init__(self, wallet: Blsct_Wallet, network: 'Network'):
        self.wallet = wallet
        NetworkJobOnDefaultServer.__init__(self, network)

    async def _run_tasks(self, *, taskgroup):
        await super()._run_tasks(taskgroup=taskgroup)
        async with taskgroup as group:
            await group.spawn(self.main())

    def diagnostic_name(self):
        return f'{self.wallet.diagnostic_name()}-blsct-sync'

    def _last_synced(self) -> int:
        return self.wallet.blsct_sync.get('last_height', -1)

    def _set_last_synced(self, height: int):
        self.wallet.blsct_sync['last_height'] = height

    def _stored_hash(self, height: int) -> Optional[str]:
        return self.wallet.blsct_sync.get('hashes', {}).get(str(height))

    def _store_hash(self, height: int, h: str):
        hashes = self.wallet.blsct_sync.get('hashes')
        if hashes is None:
            self.wallet.blsct_sync['hashes'] = {}
            hashes = self.wallet.blsct_sync['hashes']
        hashes[str(height)] = h
        old = height - BLOCK_HASH_RETENTION
        if old >= 0 and str(old) in hashes:
            hashes.pop(str(old))

    def _local_hash(self, height: int) -> Optional[str]:
        blockchain = self.network.blockchain()
        try:
            return blockchain.get_hash(height)
        except Exception:
            return None

    async def _check_reorg(self):
        last = self._last_synced()
        local_height = self.network.get_local_height()
        if local_height > 0 and last > local_height:
            self.logger.info(f'scan pointer {last} above local tip {local_height}; rewinding')
            self.wallet._unspend_above(local_height)
            last = local_height
            self._set_last_synced(last)
        while last >= 0:
            stored = self._stored_hash(last)
            if stored is None:
                break
            local = self._local_hash(last)
            if local is None:
                break
            if stored == local:
                break
            self.logger.info(f'reorg detected at height {last}')
            self.wallet._unspend_above(last - 1)
            hashes = self.wallet.blsct_sync.get('hashes', {})
            hashes.pop(str(last), None)
            last -= 1
            self._set_last_synced(last)

    async def main(self):
        wallet = self.wallet
        start = wallet.blsct_sync.get('creation_height', 0)
        if self._last_synced() < start - 1:
            self._set_last_synced(start - 1)
        while True:
            try:
                await self._sync_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception('blsct sync iteration failed')
                await asyncio.sleep(5)
            await asyncio.sleep(2)

    async def _sync_once(self):
        wallet = self.wallet
        server_height = self.network.get_server_height()
        local_height = self.network.get_local_height()
        tip = min(server_height, local_height) if server_height else local_height
        if tip <= 0:
            return
        await self._check_reorg()
        progressed = False
        while self._last_synced() < tip:
            start = self._last_synced() + 1
            res = await self.session.send_request(
                'blockchain.block.get_range_txs_keys', [start], timeout=120)
            blocks = res.get('blocks') or []
            next_height = res.get('next_height', start + len(blocks))
            if not blocks and next_height <= start:
                break
            for i, block_txs in enumerate(blocks):
                height = start + i
                await self._process_block(height, block_txs or [])
                self._store_hash(height, self._local_hash(height) or '')
                self._set_last_synced(height)
            progressed = True
            if next_height > start + len(blocks):
                self._set_last_synced(next_height - 1)
            await asyncio.sleep(0)
        if progressed:
            wallet.save_db()
            util.trigger_callback('wallet_updated', wallet)
        if not wallet.is_up_to_date() and self._last_synced() >= tip > 0:
            wallet.set_blsct_up_to_date(True)

    async def _process_block(self, height: int, block_txs: list):
        wallet = self.wallet
        keyring = wallet.keyring

        for entry in block_txs:
            try:
                tx_hash, keys = entry[0], entry[1]
            except (IndexError, TypeError):
                continue
            if not isinstance(keys, dict):
                continue
            vouts = keys.get('vout') or keys.get('outputs') or []
            vins = keys.get('vin') or keys.get('inputs') or []

            for v in vouts:
                bk = v.get('blindingKey') or v.get('blinding_key') or ''
                sk = v.get('spendingKey') or v.get('spending_key') or ''
                vt = v.get('viewTag') if v.get('viewTag') is not None else v.get('view_tag')
                ohash = v.get('outputHash') or v.get('output_hash')
                if not (bk and sk and ohash) or vt is None:
                    continue
                pair = await run_in_thread(keyring.match_output, bk, sk, int(vt))
                if not pair:
                    continue
                await self._fetch_and_store_output(tx_hash, height, ohash, bk, pair)

            vout_hashes = [v.get('outputHash') or v.get('output_hash')
                           for v in vouts]
            vout_hashes = [h for h in vout_hashes if h]
            for v in vins:
                prevout = (v.get('prevoutHash') or v.get('prevout_hash')
                           or v.get('outputHash') or v.get('output_hash'))
                if not prevout:
                    continue
                if prevout in wallet.blsct_outputs:
                    wallet._mark_spent(prevout, tx_hash, height,
                                       ref=vout_hashes[0] if vout_hashes else None)

    async def _fetch_and_store_output(self, tx_hash: str, height: int,
                                      output_hash: str, blinding_key_hex: str,
                                      pair: Tuple[int, int]):
        wallet = self.wallet
        keyring = wallet.keyring
        existing = wallet.blsct_outputs.get(output_hash)
        if existing is not None:
            with wallet._blsct_lock:
                existing['tx_hash'] = tx_hash
                existing['height'] = height
            return
        try:
            out_hex = await self.session.send_request(
                'blockchain.transaction.get_output', [output_hash], timeout=30)
        except Exception as e:
            self.logger.info(f'get_output({output_hash}) failed: {e!r}')
            return
        try:
            parsed = parse_output_hex(out_hex)
        except Exception:
            self.logger.exception(f'could not parse output {output_hash}')
            return
        rec = await run_in_thread(keyring.try_recover_output, parsed)
        if rec is None:
            self.logger.info(f'output {output_hash} matched but did not recover')
            return
        # full TokenId serialization (token 32B + subid 8B le, signed subid:
        # fungible outputs carry -1), matching TokenId.serialize()
        token_id = None
        if parsed.token_id and parsed.token_id != bytes(32):
            token_id = (parsed.token_id.hex()
                        + parsed.token_nft_id.to_bytes(8, 'little', signed=True).hex())
        staked, delegation = wallet._classify_output(parsed)
        wallet._store_output(output_hash,
                             tx_hash=tx_hash, height=height, amount=rec.amount,
                             gamma_hex=rec.gamma_hex,
                             blinding_key_hex=blinding_key_hex,
                             account=pair[0], addr_index=pair[1],
                             memo=rec.memo, token_id=token_id,
                             staked=staked, delegation=delegation)
        self.logger.info(f'found output {output_hash[:16]} amount={rec.amount} '
                         f'height={height} acct={pair} staked={staked}')
        local_height = wallet.network.get_local_height() if wallet.network else 0
        near_tip = height == 0 or height >= local_height - 2
        d = wallet.blsct_outputs.get(output_hash) or {}
        wallet._on_incoming_output(
            address=d.get('address', ''), amount=rec.amount, account=pair[0],
            staked=staked, token_id=token_id, near_tip=near_tip)


# ---------------------------------------------------------------------------
# wallet creation / restore
# ---------------------------------------------------------------------------

def create_new_blsct_wallet(*, path, config, password=None, encrypt_file=True,
                            creation_height: Optional[int] = None,
                            passphrase: str = '') -> dict:
    import os
    return _create_blsct_wallet(os.urandom(32).hex(), path=path, config=config,
                                password=password, encrypt_file=encrypt_file,
                                creation_height=creation_height or 0,
                                passphrase=passphrase)


def estimate_height_for_date(date_str: str) -> int:
    """Estimate the chain height at a 'YYYY-MM-DD' date, with a one-day
    safety margin, for use as a scan starting point. Returns 0 on any
    parse problem or pre-genesis date."""
    from . import constants
    import datetime
    try:
        d = datetime.datetime.strptime(date_str.strip(), '%Y-%m-%d')
        ts = d.replace(tzinfo=datetime.timezone.utc).timestamp()
    except Exception:
        return 0
    genesis_ts = constants.net.GENESIS_TIMESTAMP
    if not genesis_ts or ts <= genesis_ts:
        return 0
    margin = 24 * 3600
    return max(0, int((ts - genesis_ts - margin) // constants.net.BLOCK_INTERVAL))


def split_blsct_view_key_str(text: str):
    """Accepts both view key formats and returns (view_key_hex, spend_pub_hex):
    - navio-core / canonical: 160 hex chars, view key (32B) + spend pubkey (48B)
    - legacy colon-separated: '<view_key_hex(64)>:<spend_pub_hex(96)>'
    Returns None if the text is not a view key string."""
    text = text.strip()
    if ':' in text:
        parts = text.split(':')
        if len(parts) != 2:
            return None
        vk, sp = parts
    elif len(text) == 160:
        vk, sp = text[:64], text[64:]
    else:
        return None
    if len(vk) != 64 or len(sp) != 96:
        return None
    if not all(c in '0123456789abcdefABCDEF' for c in vk + sp):
        return None
    return vk.lower(), sp.lower()


def is_blsct_view_key_str(text: str) -> bool:
    parts = split_blsct_view_key_str(text)
    if parts is None:
        return False
    try:
        BlsctKeyRing.from_view_key(*parts)
        return True
    except Exception:
        return False


def restore_blsct_wallet_from_text(text: str, *, path, config, password=None,
                                   encrypt_file=True,
                                   creation_height: int = 0,
                                   passphrase: str = '') -> dict:
    text = ' '.join(text.split())
    if is_blsct_view_key_str(text):
        vk, sp = split_blsct_view_key_str(text)
        return _create_blsct_watch_wallet(vk, sp, path=path, config=config,
                                          password=password,
                                          encrypt_file=encrypt_file,
                                          creation_height=creation_height)
    if len(text) == 64 and all(ch in '0123456789abcdefABCDEF' for ch in text):
        seed_hex = text.lower()
    else:
        seed_hex = bip39_mnemonic_to_entropy(text).hex()
    return _create_blsct_wallet(seed_hex, path=path, config=config,
                                password=password, encrypt_file=encrypt_file,
                                creation_height=creation_height,
                                passphrase=passphrase)


def _create_blsct_watch_wallet(view_key_hex, spend_pub_hex, *, path, config,
                               password, encrypt_file, creation_height) -> dict:
    from .storage import WalletStorage, StorageEncryptionVersion
    from .wallet_db import WalletDB
    from .wallet import Wallet
    storage = WalletStorage(path, allow_partial_writes=config.WALLET_PARTIAL_WRITES)
    if storage.file_exists():
        raise UserFacingException("Remove the existing wallet first!")
    if encrypt_file and password:
        storage.set_password(password, StorageEncryptionVersion.USER_PASSWORD)
    db = WalletDB('', storage=storage, upgrade=True)
    ks = BlsctKeyStore.from_view_key(view_key_hex, spend_pub_hex)
    db.put('keystore', ks.dump())
    db.put('wallet_type', 'blsct')
    db.set_keystore_encryption(False)
    wallet = Wallet(db, config=config)
    wallet.blsct_sync['creation_height'] = creation_height
    wallet.save_db()
    return {'wallet': wallet, 'watching_only': True,
            'msg': 'Watch-only BLSCT wallet created. It can see balances and '
                   'history but cannot spend or stake.'}


def _create_blsct_wallet(seed_hex, *, path, config, password, encrypt_file,
                         creation_height, passphrase: str = ''):
    from .storage import WalletStorage, StorageEncryptionVersion
    from .wallet_db import WalletDB
    from .wallet import Wallet
    storage = WalletStorage(path, allow_partial_writes=config.WALLET_PARTIAL_WRITES)
    if storage.file_exists():
        raise UserFacingException("Remove the existing wallet first!")
    if encrypt_file and password:
        storage.set_password(password, StorageEncryptionVersion.USER_PASSWORD)
    db = WalletDB('', storage=storage, upgrade=True)
    ks = BlsctKeyStore.from_seed_hex(seed_hex, passphrase=passphrase or '')
    if password:
        ks.update_password(None, password)
    db.put('keystore', ks.dump())
    db.put('wallet_type', 'blsct')
    db.set_keystore_encryption(bool(password))
    wallet = Wallet(db, config=config)
    wallet.blsct_sync['creation_height'] = creation_height
    wallet.save_db()
    mnemonic = bip39_entropy_to_mnemonic(bytes.fromhex(seed_hex))
    return {'seed': mnemonic, 'wallet': wallet,
            'msg': 'BLSCT wallet created. Keep the seed safe.'}


register_wallet_type('blsct')
register_constructor('blsct', Blsct_Wallet)
