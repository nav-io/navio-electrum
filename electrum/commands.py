#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2011 thomasv@gitorious
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import io
import sys
import datetime
import time
import argparse
import json
import ast
import binascii
import base64
import asyncio
import inspect
from asyncio import CancelledError
from collections import defaultdict
from functools import wraps
from decimal import Decimal, InvalidOperation
from typing import Optional, TYPE_CHECKING, Dict, List, Any, Union
import os
import re

import electrum_ecc as ecc

from . import util
from .lnmsg import OnionWireSerializer
from .lnworker import LN_P2P_NETWORK_TIMEOUT
from .logging import Logger
from .onion_message import create_blinded_path, send_onion_message_to
from .submarine_swaps import NostrTransport
from .util import (
    bfh, json_decode, json_normalize, is_hash256_str, is_hex_str, to_bytes, parse_max_spend, to_decimal,
    UserFacingException, InvalidPassword
)
from . import bitcoin
from .bitcoin import is_address,  hash_160, COIN
from .bip32 import BIP32Node
from .i18n import _
from .transaction import (
    Transaction, multisig_script, PartialTransaction, PartialTxOutput, tx_from_any, PartialTxInput, TxOutpoint,
    convert_raw_tx_to_hex
)
from . import transaction
from .invoices import Invoice, PR_PAID, PR_UNPAID, PR_EXPIRED
from .synchronizer import Notifier
from .wallet import (
    Abstract_Wallet, create_new_wallet, restore_wallet_from_text, Deterministic_Wallet, BumpFeeStrategy,
    Imported_Wallet
)
from .address_synchronizer import TX_HEIGHT_LOCAL
from .mnemonic import Mnemonic
from .lnutil import (channel_id_from_funding_tx, LnFeatures, SENT, RECEIVED, MIN_FINAL_CLTV_DELTA_ACCEPTED,
                     PaymentFeeBudget, NBLOCK_CLTV_DELTA_TOO_FAR_INTO_FUTURE)
from .plugin import run_hook, DeviceMgr, Plugins
from .version import ELECTRUM_VERSION
from .simple_config import SimpleConfig
from .fee_policy import FeePolicy, FEE_ETA_TARGETS, FEERATE_DEFAULT_RELAY
from . import GuiImportError
from . import crypto
from . import constants
from . import descriptor

if TYPE_CHECKING:
    from .network import Network
    from .daemon import Daemon
    from electrum.lnworker import PaymentInfo


known_commands = {}  # type: Dict[str, Command]


class NotSynchronizedException(UserFacingException):
    pass


def satoshis_or_max(amount):
    return satoshis(amount) if not parse_max_spend(amount) else amount


def satoshis(amount):
    # satoshi conversion must not be performed by the parser
    return int(COIN*to_decimal(amount)) if amount is not None else None


def format_satoshis(x: Union[float, int, Decimal, None]) -> Optional[str]:
    """
    input: satoshis as a Number
    output: str formatted as bitcoin amount
    """
    if x is None:
        return None
    return util.format_satoshis_plain(x, is_max_allowed=False)


class Command:
    def __init__(self, func, name, s):
        self.name = name
        self.requires_network = 'n' in s  # better name would be "requires daemon"
        self.requires_wallet = 'w' in s
        self.requires_password = 'p' in s
        self.requires_lightning = 'l' in s
        self.parse_docstring(func.__doc__)
        varnames = func.__code__.co_varnames[1:func.__code__.co_argcount]
        self.defaults = func.__defaults__
        if self.defaults:
            n = len(self.defaults)
            self.params = list(varnames[:-n])
            self.options = list(varnames[-n:])
        else:
            self.params = list(varnames)
            self.options = []
            self.defaults = []

        # sanity checks
        if self.requires_password:
            assert self.requires_wallet
        for varname in ('wallet_path', 'wallet'):
            if varname in varnames:
                assert varname in self.options, f"cmd: {self.name}: {varname} not in options {self.options}"
        assert not ('wallet_path' in varnames and 'wallet' in varnames)
        if self.requires_wallet:
            assert 'wallet' in varnames

    def parse_docstring(self, docstring):
        docstring = docstring or ''
        docstring = docstring.strip()
        self.description = docstring
        self.arg_descriptions = {}
        self.arg_types = {}
        for x in re.finditer(r'arg:(.*?):(.*?):(.*)$', docstring, flags=re.MULTILINE):
            self.arg_descriptions[x.group(2)] = x.group(3)
            self.arg_types[x.group(2)] = x.group(1)
            self.description = self.description.replace(x.group(), '')
        self.short_description = self.description.split('.')[0]


def command(s):
    def decorator(func):
        if hasattr(func, '__wrapped__'):
            # plugin command function
            name = func.plugin_name + '_' + func.__name__
            known_commands[name] = Command(func.__wrapped__, name, s)
        else:
            # regular command function
            name = func.__name__
            known_commands[name] = Command(func, name, s)

        @wraps(func)
        async def func_wrapper(*args, **kwargs):
            cmd_runner = args[0]  # type: Commands
            cmd = known_commands[name]  # type: Command
            password = kwargs.get('password')
            daemon = cmd_runner.daemon
            if daemon:
                if 'wallet_path' in cmd.options or cmd.requires_wallet:
                    kwargs['wallet_path'] = daemon.config.maybe_complete_wallet_path(kwargs.get('wallet_path'))
                if 'wallet' in cmd.options:
                    wallet_path = kwargs.pop('wallet_path', None) # unit tests may set wallet and not wallet_path
                    wallet = kwargs.get('wallet', None)           # run_offline_command sets both
                    if wallet is None and wallet_path is not None:
                        wallet = daemon.get_wallet(wallet_path)
                        if wallet is None:
                            raise UserFacingException('wallet not loaded')
                        kwargs['wallet'] = wallet
                    if cmd.requires_password and password is None and wallet and wallet.has_password():
                        password = wallet.get_unlocked_password()
                        if password:
                            kwargs['password'] = password
                        else:
                            raise UserFacingException('Password required. Unlock the wallet, or add a --password option to your command')
            wallet = kwargs.get('wallet')  # type: Optional[Abstract_Wallet]
            if cmd.requires_wallet and not wallet:
                raise UserFacingException('wallet not loaded')
            if cmd.requires_password and wallet.has_password():
                if password is None:
                    raise UserFacingException('Password required')
                try:
                    wallet.check_password(password)
                except InvalidPassword as e:
                    raise UserFacingException(str(e)) from None
            if cmd.requires_lightning and (not wallet or not wallet.has_lightning()):
                raise UserFacingException('Lightning not enabled in this wallet')
            return await func(*args, **kwargs)
        return func_wrapper
    return decorator


class Commands(Logger):

    def __init__(self, *, config: 'SimpleConfig',
                 network: 'Network' = None,
                 daemon: 'Daemon' = None, callback=None):
        Logger.__init__(self)
        self.config = config
        self.daemon = daemon
        self.network = network
        self._callback = callback

    def _run(self, method, args, password_getter=None, **kwargs):
        """This wrapper is called from unit tests and the Qt python console."""
        cmd = known_commands[method]
        password = kwargs.get('password', None)
        wallet = kwargs.get('wallet', None)
        if (cmd.requires_password and wallet and wallet.has_password()
                and password is None):
            password = password_getter()
            if password is None:
                return

        f = getattr(self, method)
        if cmd.requires_password:
            kwargs['password'] = password

        if 'wallet' in kwargs:
            sig = inspect.signature(f)
            if 'wallet' not in sig.parameters:
                kwargs.pop('wallet')

        coro = f(*args, **kwargs)
        fut = asyncio.run_coroutine_threadsafe(coro, util.get_asyncio_loop())
        result = fut.result()

        if self._callback:
            self._callback()
        return result

    @command('n')
    async def getinfo(self):
        """ network info """
        net_params = self.network.get_parameters()
        response = {
            'network': constants.net.NET_NAME,
            'path': self.network.config.path,
            'server': net_params.server.host,
            'blockchain_height': self.network.get_local_height(),
            'server_height': self.network.get_server_height(),
            'spv_nodes': len(self.network.get_interfaces()),
            'connected': self.network.is_connected(),
            'auto_connect': net_params.auto_connect,
            'version': ELECTRUM_VERSION,
            'fee_estimates': self.network.fee_estimates.get_data()
        }
        return response

    @command('n')
    async def stop(self):
        """Stop daemon"""
        await self.daemon.stop()
        return "Daemon stopped"

    @command('n')
    async def list_wallets(self):
        """List wallets open in daemon"""
        return [
            {
                'path': w.storage.get_path(),
                'synchronized': w.is_up_to_date(),
                'unlocked': not w.has_password() or (w.get_unlocked_password() is not None),
            }
            for w in self.daemon.get_wallets().values()
        ]

    @command('n')
    async def load_wallet(self, wallet_path=None, password=None):
        """
        Load the wallet in memory
        """
        wallet = self.daemon.load_wallet(wallet_path, password, upgrade=True)
        if wallet is None:
            raise UserFacingException('could not load wallet')
        run_hook('load_wallet', wallet, None)
        return wallet_path

    @command('n')
    async def close_wallet(self, wallet_path=None):
        """Close wallet"""
        return await self.daemon._stop_wallet(wallet_path)

    @command('')
    async def create(self, password=None, encrypt_file=True, wallet_path=None, creation_height=None, seed_passphrase=None):
        """Create a new Navio BLSCT wallet.
        If you want to be prompted for an argument, type '?' or ':' (concealed)

        arg:bool:encrypt_file:Whether the file on disk should be encrypted with the provided password
        arg:int:creation_height:Block height to start scanning from (default: 0)
        arg:str:seed_passphrase:Optional BIP39 passphrase extending the seed (navio-core compatible)
        """
        from .blsct_wallet import create_new_blsct_wallet
        d = create_new_blsct_wallet(
            path=wallet_path,
            password=password,
            encrypt_file=encrypt_file,
            creation_height=creation_height,
            passphrase=seed_passphrase or '',
            config=self.config)
        return {
            'seed': d['seed'],
            'path': d['wallet'].storage.get_path(),
            'msg': d['msg'],
        }

    @command('')
    async def restore(self, text, password=None, encrypt_file=True, wallet_path=None, creation_height=0, seed_passphrase=None):
        """Restore a Navio BLSCT wallet from a 24-word seed phrase, a
        64-char hex seed, or a view key string ('viewkey:spendpub', as shown
        by getviewkey) for a watch-only wallet.
        If you want to be prompted for an argument, type '?' or ':' (concealed)

        arg:str:text:24-word seed phrase, hex seed, or view key string
        arg:bool:encrypt_file:Whether the file on disk should be encrypted with the provided password
        arg:int:creation_height:Block height to start scanning from (0 = full rescan)
        arg:str:seed_passphrase:Optional BIP39 passphrase the seed was extended with (navio-core compatible)
        """
        from .blsct_wallet import restore_blsct_wallet_from_text
        d = restore_blsct_wallet_from_text(
            text,
            path=wallet_path,
            password=password,
            encrypt_file=encrypt_file,
            creation_height=creation_height,
            passphrase=seed_passphrase or '',
            config=self.config)
        return {
            'path': d['wallet'].storage.get_path(),
            'msg': d['msg'],
        }

    @command('wp')
    async def password(self, password=None, new_password=None, encrypt_file=None, wallet: Abstract_Wallet = None):
        """
        Change wallet password.

        arg:bool:encrypt_file:Whether the file on disk should be encrypted with the provided password (default=true)
        arg:str:new_password:New Password
        """
        if wallet.storage.is_encrypted_with_hw_device() and new_password:
            raise UserFacingException("Can't change the password of a wallet encrypted with a hw device.")
        if encrypt_file is None:
            if not password and new_password:
                # currently no password, setting one now: we encrypt by default
                encrypt_file = True
            else:
                encrypt_file = wallet.storage.is_encrypted()
        wallet.update_password(password, new_password, encrypt_storage=encrypt_file)
        wallet.save_db()
        return {'password': wallet.has_password()}

    @command('w')
    async def get(self, key, wallet: Abstract_Wallet = None):
        """
        Return item from wallet storage

        arg:str:key:storage key
        """
        return wallet.db.get(key)

    @command('')
    async def getconfig(self, key):
        """Return the current value of a configuration variable.

        arg:str:key:name of the configuration variable
        """
        if Plugins.is_plugin_enabler_config_key(key):
            return self.config.get(key)
        else:
            cv = self.config.cv.from_key(key)
            return cv.get()

    @classmethod
    def _setconfig_normalize_value(cls, key, value):
        if key not in (SimpleConfig.RPC_USERNAME.key(), SimpleConfig.RPC_PASSWORD.key()):
            value = json_decode(value)
            # call literal_eval for backward compatibility (see #4225)
            try:
                value = ast.literal_eval(value)
            except Exception:
                pass
        return value

    def _setconfig(self, key, value):
        value = self._setconfig_normalize_value(key, value)
        if self.daemon and key in (
            SimpleConfig.RPC_USERNAME.key(),
            SimpleConfig.RPC_PASSWORD.key(),
            SimpleConfig.RPC_HOST.key(),
            SimpleConfig.RPC_PORT.key(),
            SimpleConfig.RPC_SOCKET_TYPE.key(),
            SimpleConfig.RPC_SOCKET_FILEPATH.key(),
        ):
            raise UserFacingException(
                "error: RPC server settings cannot be changed for already running daemon. "
                "Stop the daemon first, and run 'setconfig' in --offline mode. "
                "\nFor example: '$ electrum -o setconfig rpcport 7777'."
            )
        if Plugins.is_plugin_enabler_config_key(key):
            self.config.set_key(key, value)
        else:
            cv = self.config.cv.from_key(key)
            cv.set(value)

    @command('')
    async def setconfig(self, key, value):
        """
        Set a configuration variable.

        arg:str:key:name of the configuration variable
        arg:str:value:value. may be a string or a Python expression.
        """
        self._setconfig(key, value)

    @command('')
    async def unsetconfig(self, key):
        """
        Clear a configuration variable.
        The variable will be reset to its default value.

        arg:str:key:name of the configuration variable
        """
        self._setconfig(key, None)

    @command('')
    async def listconfig(self):
        """Returns the list of all configuration variables. """
        return self.config.list_config_vars()

    @command('')
    async def helpconfig(self, key):
        """Returns help about a configuration variable.

        arg:str:key:name of the configuration variable
        """
        cv = self.config.cv.from_key(key)
        short = cv.get_short_desc()
        long = cv.get_long_desc()
        if short and long:
            return short + "\n---\n\n" + long
        elif short or long:
            return short or long
        else:
            return f"No description available for '{key}'"

    @command('wp')
    async def unlock(self, wallet: Abstract_Wallet = None, password=None):
        """Unlock the wallet (store the password in memory)."""
        wallet.unlock(password)

    @command('w')
    async def listunspent(self, wallet: Abstract_Wallet = None):
        """List unspent outputs. Returns the list of unspent transaction
        outputs in your wallet."""
        coins = []
        for txin in wallet.get_utxos():
            d = txin.to_json()
            v = d.pop("value_sats")
            d["value"] = format_satoshis(v)
            coins.append(d)
        return coins

    @command('n')
    async def broadcast(self, tx):
        """
        Broadcast a transaction to the network.

        arg:str:tx:Serialized transaction (must be hexadecimal)
        """
        from .blsct_wallet import Blsct_Wallet
        txid = await self.network.interface.session.send_request(
            'blockchain.transaction.broadcast', [tx], timeout=30)
        # let open blsct wallets register their own outputs/spends
        if self.daemon:
            for w in self.daemon.get_wallets().values():
                if isinstance(w, Blsct_Wallet):
                    try:
                        w.process_own_transaction(tx, txid)
                        w.save_db()
                    except Exception:
                        pass
        return txid

    @command('w')
    async def ismine(self, address, wallet: Abstract_Wallet = None):
        """
        Check if address is in wallet. Return true if and only address is in wallet

        arg:str:address:Navio address
        """
        return wallet.is_mine(address)

    @command('')
    async def validateaddress(self, address):
        """Check that an address is valid.

        arg:str:address:Navio address
        """
        try:
            from .navio_blsct import get_blsct
            b = get_blsct()
            b.Address.decode(address)
            return True
        except Exception:
            return False

    @command('w')
    async def getbalance(self, wallet: Abstract_Wallet = None):
        """Return the balance of your wallet. """
        c, u, x = wallet.get_balance()
        l = wallet.lnworker.get_balance() if wallet.lnworker else None
        out = {"confirmed": format_satoshis(c)}
        if u:
            out["unconfirmed"] = format_satoshis(u)
        if x:
            out["unmatured"] = format_satoshis(x)
        if l:
            out["lightning"] = format_satoshis(l)
        return out

    @command('n')
    async def getmerkle(self, txid, height):
        """Get Merkle branch of a transaction included in a block. Electrum
        uses this to verify transactions (Simple Payment Verification).

        arg:txid:txid:Transaction ID
        arg:int:height:Block height
        """
        return await self.network.get_merkle_for_transaction(txid, int(height))

    @command('n')
    async def getservers(self):
        """Return the list of known servers (candidates for connecting)."""
        return self.network.get_servers()

    @command('')
    async def version(self):
        """Return the version of Electrum."""
        return ELECTRUM_VERSION

    @command('')
    async def version_info(self):
        """Return information about dependencies, such as their version and path."""
        ret = {
            "electrum.version": ELECTRUM_VERSION,
            "electrum.path": os.path.dirname(os.path.realpath(__file__)),
            "python.version": sys.version,
            "python.path": sys.executable,
        }
        # add currently running GUI
        if self.daemon and self.daemon.gui_object:
            ret.update(self.daemon.gui_object.version_info())
        # always add Qt GUI, so we get info even when running this from CLI
        try:
            from .gui.qt import ElectrumGui as QtElectrumGui
            ret.update(QtElectrumGui.version_info())
        except GuiImportError:
            pass
        # Add shared libs (.so/.dll), and non-pure-python dependencies.
        # Such deps can be installed in various ways - often via the Linux distro's pkg manager,
        # instead of using pip, hence it is useful to list them for debugging.
        from electrum_ecc import ecc_fast
        ret.update(ecc_fast.version_info())
        from . import qrscanner
        ret.update(qrscanner.version_info())
        ret.update(DeviceMgr.version_info())
        ret.update(crypto.version_info())
        # add some special cases
        import aiohttp
        ret["aiohttp.version"] = aiohttp.__version__
        import aiorpcx
        ret["aiorpcx.version"] = aiorpcx._version_str
        import certifi
        ret["certifi.version"] = certifi.__version__
        import dns
        ret["dnspython.version"] = dns.__version__
        import ssl
        ret["openssl.version"] = ssl.OPENSSL_VERSION

        return ret

    @command('wp')
    async def getseed(self, password=None, wallet: Abstract_Wallet = None):
        """Get seed phrase. Print the generation seed of your wallet."""
        s = wallet.get_seed(password)
        return s

    @command('w')
    async def getviewkey(self, wallet: Abstract_Wallet = None):
        """Get the wallet's view key string ('viewkey:spendpub'). Anyone with
        this string can see the wallet's balances and history (but cannot
        spend); use it with `restore` to create a watch-only wallet."""
        if not hasattr(wallet, 'get_view_key_str'):
            raise UserFacingException('view keys only exist for BLSCT wallets')
        return wallet.get_view_key_str()

    @command('w')
    async def listtokens(self, wallet: Abstract_Wallet = None):
        """List token balances and NFTs held by the wallet."""
        return {
            'tokens': [
                {'token_id': tid,
                 'name': wallet.get_token_display_name(tid),
                 'balance': balance}
                for tid, balance in wallet.get_token_balances().items()
            ],
            'nfts': wallet.get_nfts(),
        }

    @command('wnp')
    async def sendtoken(self, token_id, destination, amount, memo=None,
                        password=None, wallet: Abstract_Wallet = None):
        """Send tokens (or an NFT: pass its token_id and amount 1).
        Broadcasts immediately.

        arg:str:token_id:Token id (hex, as shown by listtokens)
        arg:str:destination:Navio (nav1...) address
        arg:int:amount:Token units to send
        arg:str:memo:Optional encrypted memo attached to the payment
        """
        built = wallet.create_token_transaction(
            token_id, [(destination, int(amount), memo or '')], password=password)
        txid = await wallet.broadcast_blsct_transaction(built.raw_hex)
        return {'txid': txid, 'fee': built.fee}

    @command('wnp')
    async def createtoken(self, name, total_supply, is_nft=False, metadata=None,
                          password=None, wallet: Abstract_Wallet = None):
        """Create a token (or NFT collection with is_nft=1). A wallet can
        create any number of tokens; each token's key is derived from the
        wallet seed and the token's metadata + total supply, so the same
        metadata always maps back to the same token after a restore.

        arg:str:name:Token name (stored in the on-chain metadata)
        arg:int:total_supply:Maximum supply
        arg:bool:is_nft:Create an NFT collection instead of a fungible token
        arg:str:metadata:Optional extra metadata as JSON object
        """
        meta = {'name': name}
        if metadata:
            meta.update(json.loads(metadata))
        built = wallet.create_token(meta, int(total_supply), bool(is_nft),
                                    password=password)
        txid = await wallet.broadcast_blsct_transaction(built.raw_hex)
        return {'txid': txid, 'fee': built.fee}

    @command('wnp')
    async def minttoken(self, destination, amount, token=None, password=None,
                        wallet: Abstract_Wallet = None):
        """Mint units of one of this wallet's fungible tokens to an address.

        arg:str:destination:Navio (nav1...) address
        arg:int:amount:Token units to mint
        arg:str:token:Which token (name, token id, or public key); optional when the wallet created exactly one
        """
        built = wallet.mint_token(destination, int(amount), password=password,
                                  token=token)
        txid = await wallet.broadcast_blsct_transaction(built.raw_hex)
        return {'txid': txid, 'fee': built.fee}

    @command('wnp')
    async def mintnft(self, destination, nft_id, name=None, metadata=None,
                      token=None, password=None,
                      wallet: Abstract_Wallet = None):
        """Mint one NFT of one of this wallet's collections to an address.

        arg:str:destination:Navio (nav1...) address
        arg:int:nft_id:NFT number within the collection
        arg:str:name:Optional NFT name (stored in the on-chain metadata)
        arg:str:metadata:Optional extra metadata as JSON object
        arg:str:token:Which collection (name, token id, or public key); optional when the wallet created exactly one
        """
        meta = {}
        if name:
            meta['name'] = name
        if metadata:
            meta.update(json.loads(metadata))
        built = wallet.mint_nft(destination, int(nft_id), meta, password=password,
                                token=token)
        txid = await wallet.broadcast_blsct_transaction(built.raw_hex)
        return {'txid': txid, 'fee': built.fee}

    @command('wp')
    async def payto(self, destination, amount, fee=None, memo=None, from_coins=None,
                    password=None, wallet: Abstract_Wallet = None):
        """Create and sign a Navio transaction. Returns {'hex','txid','fee'};
        broadcast it with the broadcast command.

        arg:str:destination:Navio (nav1...) address
        arg:decimal_or_max:amount:Amount to be sent (in NAV). Type '!' to send the maximum available.
        arg:decimal:fee:Transaction fee (absolute, in NAV; default: automatic)
        arg:str:memo:Encrypted memo embedded in the output
        arg:json:from_coins:Restrict source coins (list of output hashes)
        """
        tx_fee = satoshis(fee)
        domain_coins = from_coins.split(',') if isinstance(from_coins, str) else from_coins
        amount_sat = satoshis_or_max(amount)
        subtract = amount_sat == '!'
        if subtract:
            coins = wallet.get_spendable_coins()
            if domain_coins:
                coins = [c for c in coins if c.output_hash in domain_coins]
            amount_sat = sum(c.d['amount'] for c in coins)
        built = wallet.create_blsct_transaction(
            [(destination, amount_sat, memo or '')],
            password=password,
            fixed_fee=tx_fee,
            domain_coins=domain_coins,
            subtract_fee_from_amount=subtract)
        return {'hex': built.raw_hex, 'txid': built.txid, 'fee': built.fee}

    @command('wp')
    async def paytomany(self, outputs, fee=None, from_coins=None,
                        password=None, wallet: Abstract_Wallet = None):
        """Create and sign a multi-output Navio transaction.

        arg:json:outputs:json list of ["address", "amount in NAV"]
        arg:decimal:fee:Transaction fee (absolute, in NAV; default: automatic)
        arg:json:from_coins:Restrict source coins (list of output hashes)
        """
        tx_fee = satoshis(fee)
        domain_coins = from_coins.split(',') if isinstance(from_coins, str) else from_coins
        recipients = [(addr, satoshis(amount), '') for addr, amount in outputs]
        built = wallet.create_blsct_transaction(
            recipients,
            password=password,
            fixed_fee=tx_fee,
            domain_coins=domain_coins)
        return {'hex': built.raw_hex, 'txid': built.txid, 'fee': built.fee}

    @command('wp')
    async def stakelock(self, amount, fee=None, password=None,
                        wallet: Abstract_Wallet = None):
        """Lock an amount for staking (creates a staked-commitment output).
        Existing plain stakes are consolidated into the new output. Returns
        {'hex','txid','fee'}; broadcast it with the broadcast command.

        arg:decimal:amount:Amount to stake (in NAV)
        arg:decimal:fee:Transaction fee (absolute, in NAV; default: automatic)
        """
        built = wallet.create_stake_transaction(
            satoshis(amount), password=password, fixed_fee=satoshis(fee))
        return {'hex': built.raw_hex, 'txid': built.txid, 'fee': built.fee}

    @command('wp')
    async def delegatestake(self, amount, delegate_pubkey, reward_address=None,
                            fee=None, password=None,
                            wallet: Abstract_Wallet = None):
        """Lock an amount for staking and delegate block production to a
        third-party staking operator (cold staking). The staked output
        carries its commitment opening encrypted to the operator, who can
        stake it but can never spend or unstake it. Reward routing is
        advisory: the operator controls its own coinbase, so choose operators
        you trust to honor it. Existing stakes with the same delegation are
        consolidated. Revoke at any time with stakeunlock.

        arg:decimal:amount:Amount to stake (in NAV)
        arg:str:delegate_pubkey:The operator's 48-byte G1 delegation public key (hex)
        arg:str:reward_address:Address block rewards should be paid to (default: a fresh address of this wallet)
        arg:decimal:fee:Transaction fee (absolute, in NAV; default: automatic)
        """
        built = wallet.create_stake_transaction(
            satoshis(amount), password=password,
            delegate_key_hex=delegate_pubkey,
            reward_address=reward_address,
            fixed_fee=satoshis(fee))
        return {'hex': built.raw_hex, 'txid': built.txid, 'fee': built.fee}

    @command('wp')
    async def stakeunlock(self, amount=None, delegate_pubkey=None, fee=None,
                          password=None, wallet: Abstract_Wallet = None):
        """Unlock staked funds. By default operates on undelegated stakes;
        pass delegate_pubkey to unstake coins delegated to that operator.
        Omit amount to unstake the whole group.

        arg:decimal:amount:Amount to unstake (in NAV; default: everything in the group)
        arg:str:delegate_pubkey:Unstake coins delegated to this operator key (hex)
        arg:decimal:fee:Transaction fee (absolute, in NAV; default: automatic)
        """
        built = wallet.create_unstake_transaction(
            satoshis(amount) if amount is not None else None,
            password=password,
            delegate_key_hex=delegate_pubkey,
            fixed_fee=satoshis(fee))
        return {'hex': built.raw_hex, 'txid': built.txid, 'fee': built.fee}

    @command('w')
    async def liststaked(self, wallet: Abstract_Wallet = None):
        """List staked outputs, including their delegation (if any)."""
        outs = []
        for u in wallet.get_staked_outputs():
            d = u.to_json()
            v = d.pop('value_sats')
            d['value'] = format_satoshis(v)
            outs.append(d)
        return outs

    @command('w')
    async def onchain_history(
        self, year=None, from_height=None, to_height=None,
        wallet: Abstract_Wallet = None,
    ):
        """Wallet onchain history. Returns the transaction history of your wallet.

        arg:int:year:Show history for a given year
        arg:int:from_height:Only show transactions that confirmed after(inclusive) given block height
        arg:int:to_height:Only show transactions that confirmed before(exclusive) given block height
        """
        return json_normalize(wallet.get_detailed_history(
            from_height=from_height, to_height=to_height))

    @command('w')
    async def setlabel(self, key, label, wallet: Abstract_Wallet = None):
        """
        Assign a label to an item. Item may be a navio address or a
        transaction ID

        arg:str:key:Key
        arg:str:label:Label
        """
        wallet.set_label(key, label)

    @command('w')
    async def listcontacts(self, wallet: Abstract_Wallet = None):
        """Show your list of contacts"""
        return wallet.contacts

    @command('w')
    async def getopenalias(self, key, wallet: Abstract_Wallet = None):
        """
        Retrieve alias. Lookup in your list of contacts, and for an OpenAlias DNS record.

        arg:str:key:the alias to be retrieved
        """
        d = await wallet.contacts.resolve(key)
        if d.get("type") == "openalias":
            # we always validate DNSSEC now
            d["validated"] = True
        return d

    @command('w')
    async def searchcontacts(self, query, wallet: Abstract_Wallet = None):
        """
        Search through your wallet contacts, return matching entries.

        arg:str:query:Search query
        """
        results = {}
        for key, value in wallet.contacts.items():
            if query.lower() in key.lower():
                results[key] = value
        return results

    @command('w')
    async def listaddresses(self, receiving=False, change=False, labels=False, frozen=False, unused=False, funded=False, balance=False, wallet: Abstract_Wallet = None):
        """List wallet addresses. Returns the list of all addresses in your wallet. Use optional arguments to filter the results.

        arg:bool:receiving:Show only receiving addresses
        arg:bool:change:Show only change addresses
        arg:bool:frozen:Show only frozen addresses
        arg:bool:unused:Show only unused addresses
        arg:bool:funded:Show only funded addresses
        arg:bool:balance:Show the balances of listed addresses
        arg:bool:labels:Show the labels of listed addresses
        """
        out = []
        for addr in wallet.get_addresses():
            if frozen and not wallet.is_frozen_address(addr):
                continue
            if receiving and wallet.is_change(addr):
                continue
            if change and not wallet.is_change(addr):
                continue
            if unused and wallet.adb.is_used(addr):
                continue
            if funded and wallet.adb.is_empty(addr):
                continue
            item = addr
            if labels or balance:
                item = (item,)
            if balance:
                item += (format_satoshis(sum(wallet.get_addr_balance(addr))),)
            if labels:
                item += (repr(wallet.get_label_for_address(addr)),)
            out.append(item)
        return out

    @command('n')
    async def gettransaction(self, txid, wallet: Abstract_Wallet = None):
        """Retrieve a transaction.

        arg:txid:txid:Transaction ID
        """
        tx = None
        if wallet:
            tx = wallet.db.get_transaction(txid)
        if tx is None:
            raw = await self.network.get_transaction(txid)
            if raw:
                tx = Transaction(raw)
            else:
                raise UserFacingException("Unknown transaction")
        if tx.txid() != txid:
            raise UserFacingException("Mismatching txid")
        return tx.serialize()

    @command('w')
    async def createnewaddress(self, wallet: Abstract_Wallet = None):
        """Create a new receiving address, beyond the gap limit of the wallet"""
        return wallet.create_new_address(False)

    @command('w')
    async def getunusedaddress(self, wallet: Abstract_Wallet = None):
        """Returns the first unused address of the wallet, or None if all addresses are used.
        An address is considered as used if it has received a transaction, or if it is used in a payment request."""
        return wallet.get_unused_address()

    @command('wn')
    async def is_synchronized(self, wallet: Abstract_Wallet = None):
        """ return wallet synchronization status """
        return wallet.is_up_to_date()

    @command('wn')
    async def wait_for_sync(self, wallet: Abstract_Wallet = None):
        """Block until the wallet synchronization finishes."""
        while True:
            if wallet.is_up_to_date():
                return True
            await wallet.up_to_date_changed_event.wait()

    @command('')
    async def help(self):
        """Show help about a command"""
        # for the python console
        return sorted(known_commands.keys())

    # lightning network commands
def plugin_command(s, plugin_name):
    """Decorator to register a cli command inside a plugin. To be used within a commands.py file
    in the plugins root."""
    # atm all plugin commands require a daemon, cannot be run in 'offline' mode:
    if 'n' not in s:
        s += 'n'
    def decorator(func):
        assert len(plugin_name) > 0, "Plugin name must not be empty"
        func.plugin_name = plugin_name
        name = plugin_name + '_' + func.__name__
        if name in known_commands or hasattr(Commands, name):
            raise Exception(f"Command name {name} already exists. Plugin commands should not overwrite other commands.")
        assert inspect.iscoroutinefunction(func), f"Plugin commands must be a coroutine: {name}"

        @command(s)
        @wraps(func)
        async def func_wrapper(*args, **kwargs):
            cmd_runner = args[0]  # type: Commands
            daemon = cmd_runner.daemon
            assert daemon is not None
            kwargs['plugin'] = daemon._plugins.get_plugin(plugin_name)
            return await func(*args, **kwargs)

        setattr(Commands, name, func_wrapper)
        return func_wrapper
    return decorator


def eval_bool(x: str) -> bool:
    if x == 'false':
        return False
    if x == 'true':
        return True
    # assume python, raise if malformed
    return bool(ast.literal_eval(x))


# don't use floats because of rounding errors
json_loads = lambda x: json.loads(x, parse_float=lambda x: str(to_decimal(x)))


def check_txid(txid):
    if not is_hash256_str(txid):
        raise UserFacingException(f"{repr(txid)} is not a txid")
    return txid


arg_types = {
    'int': int,
    'bool': eval_bool,
    'str': str,
    'txid': check_txid,
    'tx': convert_raw_tx_to_hex,
    'json': json_loads,
    'decimal': lambda x: str(to_decimal(x)),
    'decimal_or_dryrun': lambda x: str(to_decimal(x)) if x != 'dryrun' else x,
    'decimal_or_max': lambda x: str(to_decimal(x)) if not parse_max_spend(x) else x,
}

config_variables = {
    'addrequest': {
        'ssl_privkey': 'Path to your SSL private key, needed to sign the request.',
        'ssl_chain': 'Chain of SSL certificates, needed for signed requests. Put your certificate at the top and the root CA at the end',
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    },
    'listrequests': {
        'url_rewrite': 'Parameters passed to str.replace(), in order to create the r= part of bitcoin: URIs. Example: \"(\'file:///var/www/\',\'https://electrum.org/\')\"',
    }
}


def set_default_subparser(self, name, args=None):
    """see http://stackoverflow.com/questions/5176691/argparse-how-to-specify-a-default-subcommand"""
    subparser_found = False
    for arg in sys.argv[1:]:
        if arg in ['-h', '--help', '--version']:  # global help/version if no subparser
            break
    else:
        for x in self._subparsers._actions:
            if not isinstance(x, argparse._SubParsersAction):
                continue
            for sp_name in x._name_parser_map.keys():
                if sp_name in sys.argv[1:]:
                    subparser_found = True
        if not subparser_found:
            # insert default in first position, this implies no
            # global options without a sub_parsers specified
            if args is None:
                sys.argv.insert(1, name)
            else:
                args.insert(0, name)


argparse.ArgumentParser.set_default_subparser = set_default_subparser


# workaround https://bugs.python.org/issue23058
# see https://github.com/nickstenning/honcho/pull/121

def subparser_call(self, parser, namespace, values, option_string=None):
    from argparse import ArgumentError, SUPPRESS, _UNRECOGNIZED_ARGS_ATTR
    parser_name = values[0]
    arg_strings = values[1:]
    # set the parser name if requested
    if self.dest is not SUPPRESS:
        setattr(namespace, self.dest, parser_name)
    # select the parser
    try:
        parser = self._name_parser_map[parser_name]
    except KeyError:
        tup = parser_name, ', '.join(self._name_parser_map)
        msg = _('unknown parser {!r} (choices: {})').format(*tup)
        raise ArgumentError(self, msg)
    # parse all the remaining options into the namespace
    # store any unrecognized options on the object, so that the top
    # level parser can decide what to do with them
    namespace, arg_strings = parser.parse_known_args(arg_strings, namespace)
    if arg_strings:
        vars(namespace).setdefault(_UNRECOGNIZED_ARGS_ATTR, [])
        getattr(namespace, _UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)


argparse._SubParsersAction.__call__ = subparser_call


def add_network_options(parser):
    group = parser.add_argument_group('network options')
    group.add_argument(
        "-f", "--serverfingerprint", dest=SimpleConfig.NETWORK_SERVERFINGERPRINT.key(), default=None,
        help="only allow connecting to servers with a matching SSL certificate SHA256 fingerprint. " +
        "To calculate this yourself: '$ openssl x509 -noout -fingerprint -sha256 -inform pem -in mycertfile.crt'. Enter as 64 hex chars.")
    group.add_argument(
        "-1", "--oneserver", action="store_true", dest=SimpleConfig.NETWORK_ONESERVER.key(), default=None,
        help="connect to one server only")
    group.add_argument(
        "-s", "--server", dest=SimpleConfig.NETWORK_SERVER.key(), default=None,
        help="set server host:port:protocol, where protocol is either t (tcp) or s (ssl)")
    group.add_argument(
        "-p", "--proxy", dest=SimpleConfig.NETWORK_PROXY.key(), default=None,
        help="set proxy [type:]host:port (or 'none' to disable proxy), where type is socks4 or socks5")
    group.add_argument(
        "--proxyuser", dest=SimpleConfig.NETWORK_PROXY_USER.key(), default=None,
        help="set proxy username")
    group.add_argument(
        "--proxypassword", dest=SimpleConfig.NETWORK_PROXY_PASSWORD.key(), default=None,
        help="set proxy password")
    group.add_argument(
        "--noonion", action="store_true", dest=SimpleConfig.NETWORK_NOONION.key(), default=None,
        help="do not try to connect to onion servers")
    group.add_argument(
        "--skipmerklecheck", action="store_true", dest=SimpleConfig.NETWORK_SKIPMERKLECHECK.key(), default=None,
        help="Tolerate invalid merkle proofs from Electrum server")


def add_global_options(parser, suppress=False):
    group = parser.add_argument_group('global options')
    group.add_argument(
        "-v", dest="verbosity", default='',
        help=argparse.SUPPRESS if suppress else "Set verbosity (log levels)")
    group.add_argument(
        "-D", "--dir", dest="electrum_path",
        help=argparse.SUPPRESS if suppress else "electrum directory")
    group.add_argument(
        "-w", "--wallet", dest="wallet_path",
        help=argparse.SUPPRESS if suppress else "wallet path")
    group.add_argument(
        "-P", "--portable", action="store_true", dest="portable", default=False,
        help=argparse.SUPPRESS if suppress else "Use local 'electrum_data' directory")
    for chain in constants.NETS_LIST:
        group.add_argument(
            f"--{chain.cli_flag()}", action="store_true", dest=chain.config_key(), default=False,
            help=argparse.SUPPRESS if suppress else f"Use {chain.NET_NAME} chain")
    group.add_argument(
        "-o", "--offline", action="store_true", dest=SimpleConfig.NETWORK_OFFLINE.key(), default=None,
        help=argparse.SUPPRESS if suppress else "Run offline")
    group.add_argument(
        "--rpcuser", dest=SimpleConfig.RPC_USERNAME.key(), default=argparse.SUPPRESS,
        help=argparse.SUPPRESS if suppress else "RPC user")
    group.add_argument(
        "--rpcpassword", dest=SimpleConfig.RPC_PASSWORD.key(), default=argparse.SUPPRESS,
        help=argparse.SUPPRESS if suppress else "RPC password")
    group.add_argument(
        "--forgetconfig", action="store_true", dest=SimpleConfig.CONFIG_FORGET_CHANGES.key(), default=None,
        help=argparse.SUPPRESS if suppress else "Forget config on exit")
    group.add_argument(
        # Note: default value is False and not None, so that behaviour cannot be modified by editing the config file
        "--nohardening", action="store_true", dest=SimpleConfig.DISABLE_MEMORY_HARDENING_LINUX.key(), default=False,
        help=argparse.SUPPRESS if suppress else "Disable memory hardening (linux)")


def get_simple_parser():
    """ simple parser that figures out the path of the config file and ignore unknown args """
    from optparse import OptionParser, BadOptionError, AmbiguousOptionError

    class PassThroughOptionParser(OptionParser):
        # see https://stackoverflow.com/questions/1885161/how-can-i-get-optparses-optionparser-to-ignore-invalid-options
        def _process_args(self, largs, rargs, values):
            while rargs:
                try:
                    OptionParser._process_args(self, largs, rargs, values)
                except (BadOptionError, AmbiguousOptionError) as e:
                    largs.append(e.opt_str)

    parser = PassThroughOptionParser()
    parser.add_option("-D", "--dir", dest="electrum_path", help="electrum directory")
    parser.add_option("-P", "--portable", action="store_true", dest="portable", default=False, help="Use local 'electrum_data' directory")
    for chain in constants.NETS_LIST:
        parser.add_option(f"--{chain.cli_flag()}", action="store_true", dest=chain.config_key(), default=False, help=f"Use {chain.NET_NAME} chain")
    return parser


def get_parser():
    # create main parser
    parser = argparse.ArgumentParser(
        epilog="Run 'electrum help <command>' to see the help for a command")
    parser.add_argument("--version", dest="cmd", action='store_const', const='version', help="Return the version of Electrum.")
    add_global_options(parser)
    subparsers = parser.add_subparsers(dest='cmd', metavar='<command>')
    # gui
    parser_gui = subparsers.add_parser('gui', description="Run Electrum's Graphical User Interface.", help="Run GUI (default)")
    parser_gui.add_argument("url", nargs='?', default=None, help="bitcoin URI")
    parser_gui.add_argument("-g", "--gui", dest=SimpleConfig.GUI_NAME.key(), help="select graphical user interface", choices=['qt', 'text', 'stdio', 'qml'])
    parser_gui.add_argument("-m", action="store_true", dest=SimpleConfig.GUI_QT_HIDE_ON_STARTUP.key(), default=False, help="hide GUI on startup")
    parser_gui.add_argument("-L", "--lang", dest=SimpleConfig.LOCALIZATION_LANGUAGE.key(), default=None, help="default language used in GUI")
    parser_gui.add_argument("--daemon", action="store_true", dest="daemon", default=False, help="keep daemon running after GUI is closed")
    parser_gui.add_argument("--nosegwit", action="store_true", dest=SimpleConfig.WIZARD_DONT_CREATE_SEGWIT.key(), default=False, help="Do not create segwit wallets")
    add_network_options(parser_gui)
    add_global_options(parser_gui)
    # daemon
    parser_daemon = subparsers.add_parser('daemon', help="Run Daemon")
    parser_daemon.add_argument("-d", "--detached", action="store_true", dest="detach", default=False, help="run daemon in detached mode")
    # FIXME: all these options are rpc-server-side. The CLI client-side cannot use e.g. --rpcport,
    #        instead it reads it from the daemon lockfile.
    parser_daemon.add_argument("--rpchost", dest=SimpleConfig.RPC_HOST.key(), default=argparse.SUPPRESS, help="RPC host")
    parser_daemon.add_argument("--rpcport", dest=SimpleConfig.RPC_PORT.key(), type=int, default=argparse.SUPPRESS, help="RPC port")
    parser_daemon.add_argument("--rpcsock", dest=SimpleConfig.RPC_SOCKET_TYPE.key(), default=None, help="what socket type to which to bind RPC daemon", choices=['unix', 'tcp', 'auto'])
    parser_daemon.add_argument("--rpcsockpath", dest=SimpleConfig.RPC_SOCKET_FILEPATH.key(), help="where to place RPC file socket")
    add_network_options(parser_daemon)
    add_global_options(parser_daemon)
    # commands
    for cmdname in sorted(known_commands.keys()):
        cmd = known_commands[cmdname]
        p = subparsers.add_parser(
            cmdname,
            description=cmd.description,
            help=cmd.short_description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="Run 'electrum -h' to see the list of global options",
        )
        for optname, default in zip(cmd.options, cmd.defaults):
            if optname in ['wallet_path', 'wallet', 'plugin']:
                continue
            if optname == 'password':
                p.add_argument("--password", dest='password', help="Wallet password. Use '--password :' if you want a prompt.")
                continue
            help = cmd.arg_descriptions.get(optname)
            if not help:
                print(f'undocumented argument {cmdname}::{optname}', file=sys.stderr)
            action = "store_true" if default is False else 'store'
            if action == 'store':
                type_descriptor = cmd.arg_types.get(optname)
                _type = arg_types.get(type_descriptor, str)
                p.add_argument('--' + optname, dest=optname, action=action, default=default, help=help, type=_type)
            else:
                p.add_argument('--' + optname, dest=optname, action=action, default=default, help=help)
        add_global_options(p, suppress=True)

        for param in cmd.params:
            if param in ['wallet_path', 'wallet']:
                continue
            help = cmd.arg_descriptions.get(param)
            if not help:
                print(f'undocumented argument {cmdname}::{param}', file=sys.stderr)
            type_descriptor = cmd.arg_types.get(param)
            _type = arg_types.get(type_descriptor)
            if help is not None and _type is None:
                print(f'unknown type \'{_type}\' for {cmdname}::{param}', file=sys.stderr)
            p.add_argument(param, help=help, type=_type)

        cvh = config_variables.get(cmdname)
        if cvh:
            group = p.add_argument_group('configuration variables', '(set with setconfig/getconfig)')
            for k, v in cvh.items():
                group.add_argument(k, nargs='?', help=v)

    # 'gui' is the default command
    # note: set_default_subparser modifies sys.argv
    parser.set_default_subparser('gui')
    return parser
