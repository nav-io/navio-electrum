# -*- coding: utf-8 -*-
#
# Navio BLSCT support for Electrum.
#
# This module wraps the `navio-blsct` python bindings (import name: blsct)
# and provides:
#   - BIP39 (24 word) mnemonic <-> 32 byte entropy helpers
#   - BlsctKeyRing: HD key derivation (seed -> view/spend keys), sub-address
#     generation, output ownership tests and amount recovery
#   - a parser for Navio's BLSCT transaction/output wire format
#   - construction + signing of BLSCT transactions (unsigned-tx FFI path)
#
# The design follows the reference implementation in navio-sdk (typescript)
# and navio-core's wallet.

import hashlib
import threading
from typing import Optional, Dict, Tuple, List, NamedTuple, Sequence

from .crypto import sha256d, hash_160
from .logging import get_logger
from .util import NotEnoughFunds

_logger = get_logger(__name__)

_blsct_module = None
_blsct_lock = threading.Lock()

# fee rule from navio-core (BLSCT_DEFAULT_FEE_RATE); see navio-sdk client.ts
BLSCT_FEE_RATE = 125
DEFAULT_FEE_PER_COMPONENT = 200_000

MAIN_ACCOUNT = 0
CHANGE_ACCOUNT = -1
STAKING_ACCOUNT = -2


def get_blsct():
    """Lazily import the navio-blsct bindings and set the address chain."""
    global _blsct_module
    with _blsct_lock:
        if _blsct_module is None:
            import blsct as b
            from . import constants
            try:
                if constants.net.TESTNET:
                    b.set_chain(b.Chain.Testnet)
                else:
                    b.set_chain(b.Chain.Mainnet)
            except Exception:
                _logger.exception('could not set blsct chain')
            _blsct_module = b
    return _blsct_module


# ---------------------------------------------------------------------------
# BIP39 helpers (English wordlist, 24 words <-> 32 bytes entropy)
# ---------------------------------------------------------------------------

def _bip39_wordlist():
    from .mnemonic import Wordlist
    return Wordlist.from_file('english.txt')

def bip39_entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError('entropy length must be 16-32 bytes')
    wordlist = _bip39_wordlist()
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = hashlib.sha256(entropy).digest()
    num = int.from_bytes(entropy, 'big')
    num = (num << cs_bits) | (checksum[0] >> (8 - cs_bits))
    total_bits = ent_bits + cs_bits
    words = []
    for i in range(total_bits // 11):
        shift = total_bits - 11 * (i + 1)
        idx = (num >> shift) & 0x7FF
        words.append(wordlist[idx])
    return ' '.join(words)

def bip39_mnemonic_to_entropy(mnemonic: str) -> bytes:
    wordlist = _bip39_wordlist()
    words = mnemonic.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError('invalid mnemonic length: %d words' % len(words))
    indices = []
    for w in words:
        try:
            indices.append(wordlist.index(w))
        except ValueError:
            raise ValueError(f'word not in wordlist: {w!r}')
    total_bits = len(words) * 11
    # standard: ENT+CS where CS = ENT/32; total = 33*ENT/32
    cs_bits = total_bits // 33
    ent_bits = total_bits - cs_bits
    num = 0
    for idx in indices:
        num = (num << 11) | idx
    checksum = num & ((1 << cs_bits) - 1)
    entropy = (num >> cs_bits).to_bytes(ent_bits // 8, 'big')
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if checksum != expected:
        raise ValueError('invalid mnemonic checksum')
    return entropy

def is_bip39_mnemonic(text: str) -> bool:
    try:
        bip39_mnemonic_to_entropy(text)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Navio wire-format parsing (ported from electrumx DeserializerTxNavio)
# ---------------------------------------------------------------------------

class ParsedTxOut(NamedTuple):
    raw: bytes                 # exact serialized bytes of this output
    value: int                 # transparent value (0 for confidential)
    script: bytes              # scriptPubKey
    has_blsct: bool
    range_proof: bytes         # serialized range proof (b'' if none)
    spending_key: bytes        # sk, 48 bytes G1 point
    blinding_key: bytes        # bk, 48 bytes G1 point
    ephemeral_key: bytes       # ek, 48 bytes G1 point
    view_tag: int
    token_id: bytes            # 32 bytes or b''
    token_nft_id: int
    vdata: bytes

    @property
    def output_hash(self) -> str:
        """Output hash in display (reversed) hex, as used by electrumx."""
        return sha256d(self.raw)[::-1].hex()


class ParsedTxIn(NamedTuple):
    prevout_hash: str          # display hex of the spent output hash
    script_sig: bytes
    sequence: int


class ParsedTx(NamedTuple):
    version: int
    inputs: List[ParsedTxIn]
    outputs: List[ParsedTxOut]
    locktime: int
    txid: str                  # display hex


class _Cursor:
    __slots__ = ('buf', 'pos')

    def __init__(self, buf: bytes, pos: int = 0):
        self.buf = buf
        self.pos = pos

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ValueError('tx parse: out of bounds read')
        r = self.buf[self.pos:self.pos + n]
        self.pos += n
        return r

    def read_varint(self) -> int:
        b = self.read(1)[0]
        if b < 0xfd:
            return b
        if b == 0xfd:
            return int.from_bytes(self.read(2), 'little')
        if b == 0xfe:
            return int.from_bytes(self.read(4), 'little')
        return int.from_bytes(self.read(8), 'little')

    def read_varbytes(self) -> bytes:
        return self.read(self.read_varint())

    def read_le_int64(self) -> int:
        return int.from_bytes(self.read(8), 'little', signed=True)

    def read_le_uint32(self) -> int:
        return int.from_bytes(self.read(4), 'little')

    def read_le_uint16(self) -> int:
        return int.from_bytes(self.read(2), 'little')


def _skip_range_proof(c: _Cursor) -> None:
    def points():
        n = c.read_varint()
        c.read(48 * n)
    vs_n = c.read_varint()
    c.read(48 * vs_n)
    if vs_n > 0:
        points()  # Ls
        points()  # Rs
    c.read(48 * 3)   # A, A_wip, B
    c.read(32 * 5)   # r_prime, s_prime, delta_prime, alpha_hat, tau_x


def parse_tx_out(c: _Cursor) -> ParsedTxOut:
    start = c.pos
    value = c.read_le_int64()
    flags = 0
    if value == 0x7FFFFFFFFFFFFFFF:
        value = 0
        flags = c.read_le_int64()
        if flags & (1 << 3):
            value = c.read_le_int64()
    script = c.read_varbytes()
    range_proof = b''
    sk = bk = ek = b''
    view_tag = 0
    token_id = b''
    token_nft_id = 0
    vdata = b''
    has_blsct = bool(flags & 1)
    if has_blsct:
        rp_start = c.pos
        _skip_range_proof(c)
        range_proof = c.buf[rp_start:c.pos]
        sk = c.read(48)
        bk = c.read(48)
        ek = c.read(48)
        view_tag = c.read_le_uint16()
    if flags & (1 << 1):
        token_id = c.read(32)
        token_nft_id = c.read_le_int64()
    if flags & (1 << 2):
        vdata = c.read_varbytes()
    raw = c.buf[start:c.pos]
    return ParsedTxOut(raw, value, script, has_blsct, range_proof,
                       sk, bk, ek, view_tag, token_id, token_nft_id, vdata)


def parse_output_hex(hexstr: str) -> ParsedTxOut:
    """Parse a single serialized CTxOut (as returned by
    blockchain.transaction.get_output)."""
    c = _Cursor(bytes.fromhex(hexstr))
    out = parse_tx_out(c)
    if c.pos != len(c.buf):
        raise ValueError('trailing bytes after output')
    return out


def _parse_inputs(c: _Cursor) -> List[ParsedTxIn]:
    n = c.read_varint()
    ins = []
    for _ in range(n):
        prev_hash = c.read(32)
        script = c.read_varbytes()
        seq = c.read_le_uint32()
        ins.append(ParsedTxIn(prev_hash[::-1].hex(), script, seq))
    return ins


def parse_tx_hex(hexstr: str) -> ParsedTx:
    """Parse a Navio transaction (with or without segwit marker)."""
    buf = bytes.fromhex(hexstr)
    c = _Cursor(buf)
    marker = buf[4] if len(buf) > 4 else 1
    if marker:  # non-segwit
        version = int.from_bytes(c.read(4), 'little', signed=True)
        inputs = _parse_inputs(c)
        n = c.read_varint()
        outputs = [parse_tx_out(c) for _ in range(n)]
        locktime = c.read_le_uint32()
        if version & (1 << 5):
            c.read(96)  # txsig
        txid = sha256d(buf[:c.pos])[::-1].hex()
        return ParsedTx(version, inputs, outputs, locktime, txid)
    # segwit encoding
    version = int.from_bytes(c.read(4), 'little', signed=True)
    ser = buf[0:4]
    c.read(2)  # marker, flag
    seg_start = c.pos
    inputs = _parse_inputs(c)
    n = c.read_varint()
    outputs = [parse_tx_out(c) for _ in range(n)]
    ser += buf[seg_start:c.pos]
    # witness
    for _ in range(len(inputs)):
        for _ in range(c.read_varint()):
            c.read_varbytes()
    tail_start = c.pos
    locktime = c.read_le_uint32()
    if version & (1 << 5):
        c.read(96)  # txsig
    ser += buf[tail_start:c.pos]
    txid = sha256d(ser)[::-1].hex()
    return ParsedTx(version, inputs, outputs, locktime, txid)


# ---------------------------------------------------------------------------
# Key ring
# ---------------------------------------------------------------------------

class RecoveredAmount(NamedTuple):
    amount: int
    memo: str
    gamma_hex: str


class BlsctKeyRing:
    """Holds the wallet's BLSCT key hierarchy and the sub-address lookup map.

    Derivation (matches navio-core / navio-sdk):
      seed (scalar) -> ChildKey -> {blinding key, token key, tx key}
      tx key -> {view key, spending key}
      sub-address (account, index) derived from (view key, spend pubkey)
    """

    def __init__(self, seed_hex: Optional[str], *, view_key_hex: str = None,
                 spend_pub_hex: str = None):
        b = get_blsct()
        self.b = b
        self.seed = None
        self.spend_key = None
        if seed_hex is not None:
            self.seed = b.Scalar.deserialize(seed_hex)
            child = b.ChildKey(self.seed)
            self.master_blinding_key = child.to_blinding_key()
            self.token_key = child.to_token_key()
            tx_key = child.to_tx_key()
            self.view_key = tx_key.to_view_key()
            self.spend_key = tx_key.to_spending_key()
            self.spend_pub = b.PublicKey.from_scalar(self.spend_key)
        else:
            # watch-only (scanning) ring: view key + public spend key only
            if not (view_key_hex and spend_pub_hex):
                raise ValueError('need seed or view_key+spend_pub')
            self.view_key = b.Scalar.deserialize(view_key_hex)
            self.spend_pub = b.PublicKey.deserialize(spend_pub_hex)
        # hash-id (hex of 20 bytes) -> (account, index)
        self.subaddr_by_hashid = {}  # type: Dict[str, Tuple[int, int]]
        self._addr_cache = {}        # type: Dict[Tuple[int, int], str]
        self._lock = threading.RLock()

    @classmethod
    def from_view_key(cls, view_key_hex: str, spend_pub_hex: str) -> 'BlsctKeyRing':
        return cls(None, view_key_hex=view_key_hex, spend_pub_hex=spend_pub_hex)

    def can_spend(self) -> bool:
        return self.spend_key is not None

    # -- addresses ---------------------------------------------------------

    def _dpk(self, account: int, index: int):
        b = self.b
        return b.DoublePublicKey.from_keys_acct_addr(
            self.view_key, self.spend_pub, account, index)

    def hash_id_hex(self, account: int, index: int) -> str:
        """hash160 of the spending part of the sub-address DPK; this is the
        key-id electrumx/navio use to identify the destination sub-address."""
        dpk_ser = bytes.fromhex(self._dpk(account, index).serialize())
        assert len(dpk_ser) == 96, f'unexpected dpk size {len(dpk_ser)}'
        return hash_160(dpk_ser[48:]).hex()

    def address(self, account: int, index: int) -> str:
        with self._lock:
            key = (account, index)
            addr = self._addr_cache.get(key)
            if addr is None:
                b = self.b
                addr = b.Address.encode(self._dpk(account, index),
                                        b.AddressEncoding.Bech32M)
                self._addr_cache[key] = addr
            return addr

    def ensure_keypool(self, account: int, count: int) -> None:
        """Make sure hash-ids for sub-addresses [0, count) of `account` are
        in the lookup map."""
        with self._lock:
            have = sum(1 for v in self.subaddr_by_hashid.values() if v[0] == account)
            if have >= count:
                return
            for index in range(count):
                hid = self.hash_id_hex(account, index)
                self.subaddr_by_hashid[hid] = (account, index)

    def address_to_subaddr(self, addr: str):
        """Decode a nav1... address into a blsct SubAddr object."""
        b = self.b
        dpk = b.Address.decode(addr)
        return b.SubAddr.from_double_public_key(dpk)

    # -- ownership + recovery ----------------------------------------------

    def match_output(self, blinding_key_hex: str, spending_key_hex: str,
                     view_tag: int) -> Optional[Tuple[int, int]]:
        """Return (account, index) if the output (described by its blsct key
        material from the server) belongs to this wallet, else None."""
        b = self.b
        if not blinding_key_hex or not spending_key_hex:
            return None
        try:
            bpk = b.PublicKey.deserialize(blinding_key_hex)
        except Exception:
            return None
        expected_tag = b.ViewTag(bpk, self.view_key).value
        if (expected_tag & 0xFFFF) != (view_tag & 0xFFFF):
            return None
        try:
            spk = b.PublicKey.deserialize(spending_key_hex)
        except Exception:
            return None
        hid = b.HashId(bpk, spk, self.view_key).serialize()
        return self.subaddr_by_hashid.get(hid)

    def calc_nonce(self, blinding_key_hex: str):
        """ECDH shared secret: view_key * blinding pubkey (as raw point obj)."""
        b = self.b
        bpk = b.PublicKey.deserialize(blinding_key_hex)
        return bpk.generate_nonce(self.view_key)

    def recover_amount(self, range_proof_hex_or_bytes, blinding_key_hex: str,
                       token_id_hex: str = None) -> Optional[RecoveredAmount]:
        """Trial-decrypt an output's range proof. Returns amount/memo/gamma
        on success, None if the output can not be recovered with our view key."""
        b = self.b
        rp_hex = (range_proof_hex_or_bytes.hex()
                  if isinstance(range_proof_hex_or_bytes, (bytes, bytearray))
                  else range_proof_hex_or_bytes)
        if not rp_hex:
            return None
        try:
            rp = b.RangeProof.deserialize(rp_hex)
        except Exception:
            _logger.exception('could not deserialize range proof')
            return None
        nonce = self.calc_nonce(blinding_key_hex)
        if token_id_hex:
            token_id = b.TokenId.deserialize(token_id_hex)
        else:
            token_id = b.TokenId()
        # raw FFI (instead of RangeProof.recover_amounts) so we can also get
        # gamma, which is required later to spend the output
        req_vec = b.create_amount_recovery_req_vec()
        req = b.gen_amount_recovery_req(
            rp.value(), rp.obj_size, nonce.get_point().value(), token_id.value())
        b.add_to_amount_recovery_req_vec(req_vec, req)
        rv = b.recover_amount(req_vec)
        try:
            if int(rv.result) != 0:
                return None
            size = b.get_amount_recovery_result_size(rv.value)
            if size < 1:
                return None
            if not b.get_amount_recovery_result_is_succ(rv.value, 0):
                return None
            amount = b.get_amount_recovery_result_amount(rv.value, 0)
            memo = b.get_amount_recovery_result_msg(rv.value, 0)
            gamma_obj = b.get_amount_recovery_result_gamma(rv.value, 0)
            gamma_hex = b.serialize_scalar(gamma_obj)
            return RecoveredAmount(int(amount), memo, gamma_hex)
        finally:
            b.free_amounts_ret_val(rv)

    def try_recover_output(self, out: ParsedTxOut,
                           account_index: Optional[Tuple[int, int]] = None,
                           ) -> Optional[RecoveredAmount]:
        """Full recovery for a parsed output."""
        if not out.has_blsct:
            return None
        token_id_hex = None
        if out.token_id and out.token_id != bytes(32):
            # TokenId serialization: token (32 bytes) + subid (8 bytes le)
            token_id_hex = out.token_id.hex() + out.token_nft_id.to_bytes(8, 'little', signed=False).hex()
        return self.recover_amount(out.range_proof, out.blinding_key.hex(), token_id_hex)

    # -- spending ------------------------------------------------------------

    def priv_spending_key(self, blinding_key_hex: str, account: int, index: int):
        if self.spend_key is None:
            raise ValueError('keyring is watch-only; unlock with the seed to spend')
        b = self.b
        bpk = b.PublicKey.deserialize(blinding_key_hex)
        return b.PrivSpendingKey(bpk, self.view_key, self.spend_key,
                                 account, index)


# ---------------------------------------------------------------------------
# Transaction building
# ---------------------------------------------------------------------------

class SpendableOutput(NamedTuple):
    output_hash: str      # display hex (as indexed by electrumx)
    amount: int
    gamma_hex: str
    blinding_key_hex: str  # blinding pubkey of the output
    account: int
    index: int
    staked_commitment: bool = False


class BuiltTx(NamedTuple):
    raw_hex: str
    txid: str
    fee: int


def _required_fee(tx_bytes_len: int) -> int:
    # navio consensus: nFee >= tx_weight * BLSCT_DEFAULT_FEE_RATE. Our
    # base-serialization length underestimates the node's witness-inclusive
    # weight slightly, so add headroom (same formula as navio-sdk).
    return (tx_bytes_len + max(tx_bytes_len // 10, 256)) * BLSCT_FEE_RATE


def build_signed_tx(keyring: BlsctKeyRing,
                    utxos: Sequence[SpendableOutput],
                    recipients: Sequence[Tuple[str, int, str]],
                    change_address_pair: Tuple[int, int] = (CHANGE_ACCOUNT, 0),
                    fixed_fee: Optional[int] = None,
                    subtract_fee_from_amount: bool = False,
                    ) -> BuiltTx:
    """Build and sign a BLSCT transaction.

    utxos: outputs to spend (all of them are consumed; do coin selection
      before calling this).
    recipients: list of (nav1... address, amount, memo).
    A change output back to `change_address_pair` is added automatically.
    The fee is found iteratively so that fee >= required_fee(size), unless
    fixed_fee is given.
    """
    b = get_blsct()
    total_in = sum(u.amount for u in utxos)
    total_out = sum(a for (_, a, _) in recipients)
    if subtract_fee_from_amount and len(recipients) != 1:
        raise ValueError('subtract_fee_from_amount requires exactly one recipient')

    def build_with_fee(fee: int) -> str:
        send_total = total_out - (fee if subtract_fee_from_amount else 0)
        if send_total <= 0:
            raise NotEnoughFunds()
        change = total_in - total_out - (0 if subtract_fee_from_amount else fee)
        if change < 0:
            raise NotEnoughFunds()
        utx = b.create_unsigned_transaction()
        try:
            for u in utxos:
                psk = keyring.priv_spending_key(u.blinding_key_hex, u.account, u.index)
                out_point = b.OutPoint(b.CTxId.deserialize(u.output_hash))
                txin = b.TxIn(u.amount, b.Scalar.deserialize(u.gamma_hex), psk,
                              b.TokenId(), out_point,
                              staked_commitment=u.staked_commitment)
                rv = b.build_unsigned_input(txin.value())
                if int(rv.result) != 0:
                    b.free_obj(rv)
                    raise ValueError(f'build_unsigned_input failed: {rv.result}')
                b.add_unsigned_transaction_input(utx, rv.value)
                b.free_obj(rv)
            outs = []
            if subtract_fee_from_amount:
                addr, amount, memo = recipients[0]
                outs.append((addr, amount - fee, memo))
            else:
                outs = list(recipients)
            if change > 0:
                change_addr = keyring.address(*change_address_pair)
                outs.append((change_addr, change, ''))
            for addr, amount, memo in outs:
                if amount <= 0:
                    raise ValueError('output amount must be positive')
                sub_addr = keyring.address_to_subaddr(addr)
                txout = b.TxOut(sub_addr, amount, memo or '',
                                b.TokenId(), 'Normal', 0, False, b.Scalar.random())
                rv = b.build_unsigned_output(txout.value())
                if int(rv.result) != 0:
                    b.free_obj(rv)
                    raise ValueError(f'build_unsigned_output failed: {rv.result}')
                b.add_unsigned_transaction_output(utx, rv.value)
                b.free_obj(rv)
            b.set_unsigned_transaction_fee(utx, fee)
            rv = b.sign_unsigned_transaction(utx)
            if int(rv.result) != 0:
                b.free_obj(rv)
                raise ValueError(f'sign_unsigned_transaction failed: {rv.result}')
            # rv.value is a malloc'd C string holding the tx hex; read it by
            # hex-encoding the buffer (value_size includes the NUL terminator)
            buf_hex = b.buf_to_malloced_hex_c_str(
                b.cast_to_uint8_t_ptr(rv.value), rv.value_size - 1)
            raw_hex = bytes.fromhex(buf_hex).decode('ascii')
            b.free_obj(rv)
            return raw_hex
        finally:
            b.delete_unsigned_transaction(utx)

    if fixed_fee is not None:
        raw = build_with_fee(fixed_fee)
        fee = fixed_fee
    else:
        # initial coarse estimate, then fixpoint on actual size
        fee = (len(utxos) + len(recipients) + 2) * DEFAULT_FEE_PER_COMPONENT
        raw = build_with_fee(fee)
        for _ in range(6):
            required = _required_fee(len(raw) // 2)
            if fee >= required:
                break
            fee = required
            raw = build_with_fee(fee)
        else:
            raise ValueError('could not converge on a valid fee')

    parsed = parse_tx_hex(raw)
    return BuiltTx(raw, parsed.txid, fee)
