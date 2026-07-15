# -*- coding: utf-8 -*-
#
# Navio delegated cold staking: the stake-delegation payload.
#
# A delegated stake is a normal staked-commitment output whose DATA predicate
# carries the opening (value, gamma) of the staked Pedersen commitment plus a
# reward address, encrypted to a third-party staking operator ("delegate").
# Knowing the opening lets the delegate build proofs of stake, but not spend
# or unstake the output.
#
# This module is a byte-exact port of navio-core's
# src/blsct/wallet/delegation.{h,cpp} (PR nav-io/navio-core#304):
#
#   blob := MAGIC || E || owner_len (2, LE) || owner_ct || delegate_ct
#
#   MAGIC       = "NVDG" || 0x01                        (5 bytes)
#   E           = fresh ephemeral G1 pubkey             (48 bytes)
#   owner_ct    = AEAD(owner_key,    delegateKey || varstr(rewardAddress))
#   delegate_ct = AEAD(delegate_key, value_le64 || gamma || varstr(rewardAddress))
#
#   owner_key    = SHA256(KDF_TAG_OWNER    || nonce.GetVch()          || E)
#   delegate_key = SHA256(KDF_TAG_DELEGATE || ECDH(e, delegateKey)    || E)
#   AEAD         = ChaCha20-Poly1305, 12-byte zero nonce, AAD = MAGIC || E
#
# `nonce` is the output's BLSCT nonce (view key x blinding key), the same
# shared secret the owner already uses to recover the output's amount, so the
# owner wallet can re-derive its delegations from the chain alone.

import hashlib
from typing import NamedTuple, Optional

from .crypto import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt

MAGIC = b'NVDG\x01'
POINT_SIZE = 48
SCALAR_SIZE = 32
# blsct::PredicateOperation::DATA (predicate_parser.h)
_PREDICATE_DATA = 4
_OWNER_LEN_SIZE = 2
_AEAD_EXPANSION = 16
_AEAD_NONCE = bytes(12)
_KDF_TAG_DELEGATE = b'navio/stake-delegation/delegate/v1'
_KDF_TAG_OWNER = b'navio/stake-delegation/owner/v1'


class DelegationInfo(NamedTuple):
    """What the delegate needs to stake the output: the opening of the staked
    commitment and where to pay block rewards."""
    value: int           # amount in satoshis
    gamma: bytes         # 32-byte scalar, blinding factor of the commitment
    reward_address: str


class DelegationRequest(NamedTuple):
    """Whom a stake is delegated to and where rewards must go. Recoverable by
    the owner wallet from its own outputs (owner section of the blob)."""
    delegate_key: bytes  # 48-byte compressed G1 point
    reward_address: str

    def id(self) -> str:
        """Stable identity of a delegation, used to group staked outputs for
        consolidation. Matches DelegationRequest::GetId() in navio-core."""
        return self.delegate_key.hex() + ':' + self.reward_address


def _derive_key(tag: bytes, secret: bytes, context: bytes) -> bytes:
    return hashlib.sha256(tag + secret + context).digest()


def _write_varstr(s: str) -> bytes:
    data = s.encode('utf-8')
    n = len(data)
    if n < 0xfd:
        return bytes([n]) + data
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little') + data
    return b'\xfe' + n.to_bytes(4, 'little') + data


class _Reader:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ValueError('delegation payload: out of bounds read')
        r = self.buf[self.pos:self.pos + n]
        self.pos += n
        return r

    def read_varstr(self) -> str:
        n = self.read(1)[0]
        if n == 0xfd:
            n = int.from_bytes(self.read(2), 'little')
        elif n == 0xfe:
            n = int.from_bytes(self.read(4), 'little')
        elif n == 0xff:
            n = int.from_bytes(self.read(8), 'little')
        return self.read(n).decode('utf-8')

    def empty(self) -> bool:
        return self.pos == len(self.buf)


def data_predicate_vch(data: bytes) -> bytes:
    """Serialize a DATA predicate carrying `data` (DataPredicate::GetVch())."""
    n = len(data)
    if n < 0xfd:
        size = bytes([n])
    elif n <= 0xffff:
        size = b'\xfd' + n.to_bytes(2, 'little')
    else:
        size = b'\xfe' + n.to_bytes(4, 'little')
    return bytes([_PREDICATE_DATA]) + size + data


def data_from_predicate(vdata: bytes) -> Optional[bytes]:
    """Extract the payload of a serialized DATA predicate (an output's vdata
    field); None if it is not a DATA predicate."""
    if not vdata or vdata[0] != _PREDICATE_DATA:
        return None
    try:
        r = _Reader(vdata[1:])
        n = r.read(1)[0]
        if n == 0xfd:
            n = int.from_bytes(r.read(2), 'little')
        elif n == 0xfe:
            n = int.from_bytes(r.read(4), 'little')
        elif n == 0xff:
            n = int.from_bytes(r.read(8), 'little')
        data = r.read(n)
        if not r.empty():
            return None
        return data
    except Exception:
        return None


def is_delegation_data(data: bytes) -> bool:
    """Cheap filter: does this DATA predicate payload look like a stake
    delegation? Matches IsDelegationData() in navio-core."""
    return (len(data) > len(MAGIC) + POINT_SIZE + _OWNER_LEN_SIZE + 2 * _AEAD_EXPANSION
            and data[:len(MAGIC)] == MAGIC)


class _Sections(NamedTuple):
    aad: bytes
    ephemeral: bytes
    owner_ct: bytes
    delegate_ct: bytes


def _split_sections(data: bytes) -> Optional[_Sections]:
    if not is_delegation_data(data):
        return None
    aad_size = len(MAGIC) + POINT_SIZE
    aad = data[:aad_size]
    ephemeral = data[len(MAGIC):aad_size]
    owner_len = data[aad_size] | (data[aad_size + 1] << 8)
    owner_pos = aad_size + _OWNER_LEN_SIZE
    if owner_pos + owner_len + _AEAD_EXPANSION > len(data):
        return None
    owner_ct = data[owner_pos:owner_pos + owner_len]
    delegate_ct = data[owner_pos + owner_len:]
    return _Sections(aad, ephemeral, owner_ct, delegate_ct)


def _aead_encrypt(key: bytes, plain: bytes, aad: bytes) -> bytes:
    return chacha20_poly1305_encrypt(key=key, nonce=_AEAD_NONCE,
                                     associated_data=aad, data=plain)


def _aead_decrypt(key: bytes, cipher: bytes, aad: bytes) -> Optional[bytes]:
    if len(cipher) < _AEAD_EXPANSION:
        return None
    try:
        return chacha20_poly1305_decrypt(key=key, nonce=_AEAD_NONCE,
                                         associated_data=aad, data=cipher)
    except Exception:
        return None


# -- point arithmetic (via the navio-blsct bindings) -------------------------

def _point_mul(b, point_bytes: bytes, scalar) -> bytes:
    """point * scalar -> serialized point. `scalar` is a bindings Scalar."""
    point = b.Point.deserialize(point_bytes.hex())
    return bytes.fromhex(point.scalar_multiply(scalar).serialize())


def encrypt(b, info: DelegationInfo, request: DelegationRequest,
            nonce_point: bytes) -> bytes:
    """Build the encrypted delegation blob. `b` is the blsct bindings module,
    `nonce_point` the serialized BLSCT nonce of the output being staked
    (destination view pubkey x output blinding key)."""
    if len(request.delegate_key) != POINT_SIZE:
        raise ValueError('delegate_key must be a 48-byte G1 point')
    if len(info.gamma) != SCALAR_SIZE:
        raise ValueError('gamma must be a 32-byte scalar')
    if len(nonce_point) != POINT_SIZE:
        raise ValueError('nonce must be a 48-byte G1 point')

    ephemeral_priv = b.Scalar.random()
    ephemeral_pub = bytes.fromhex(b.Point.from_scalar(ephemeral_priv).serialize())
    aad = MAGIC + ephemeral_pub

    # owner section, keyed on the output nonce
    owner_plain = request.delegate_key + _write_varstr(request.reward_address)
    owner_key = _derive_key(_KDF_TAG_OWNER, nonce_point, ephemeral_pub)
    owner_ct = _aead_encrypt(owner_key, owner_plain, aad)

    # delegate section, keyed on ECDH(ephemeral, delegate key)
    shared = _point_mul(b, request.delegate_key, ephemeral_priv)
    delegate_plain = (info.value.to_bytes(8, 'little', signed=True)
                      + info.gamma
                      + _write_varstr(info.reward_address))
    delegate_key = _derive_key(_KDF_TAG_DELEGATE, shared, ephemeral_pub)
    delegate_ct = _aead_encrypt(delegate_key, delegate_plain, aad)

    if len(owner_ct) > 0xffff:
        raise ValueError('owner section too large')
    return (aad
            + len(owner_ct).to_bytes(2, 'little')
            + owner_ct
            + delegate_ct)


def recover_owner_info(data: bytes, nonce_point: bytes) -> Optional[DelegationRequest]:
    """Owner side: recover (delegate key, reward address) from a delegation
    blob using the output's BLSCT nonce. None if the payload is not a
    delegation or the nonce does not match."""
    sections = _split_sections(data)
    if sections is None:
        return None
    key = _derive_key(_KDF_TAG_OWNER, nonce_point, sections.ephemeral)
    plain = _aead_decrypt(key, sections.owner_ct, sections.aad)
    if plain is None:
        return None
    try:
        r = _Reader(plain)
        delegate_key = r.read(POINT_SIZE)
        reward_address = r.read_varstr()
        if not r.empty():
            return None
        return DelegationRequest(delegate_key, reward_address)
    except Exception:
        return None


def try_decrypt(b, data: bytes, delegate_priv) -> Optional[DelegationInfo]:
    """Delegate side: attempt to decrypt the delegate section. `delegate_priv`
    is a bindings Scalar. Mostly useful for tests; wallets use
    recover_owner_info()."""
    sections = _split_sections(data)
    if sections is None:
        return None
    try:
        shared = _point_mul(b, sections.ephemeral, delegate_priv)
    except Exception:
        return None
    key = _derive_key(_KDF_TAG_DELEGATE, shared, sections.ephemeral)
    plain = _aead_decrypt(key, sections.delegate_ct, sections.aad)
    if plain is None:
        return None
    try:
        r = _Reader(plain)
        value = int.from_bytes(r.read(8), 'little', signed=True)
        gamma = r.read(SCALAR_SIZE)
        reward_address = r.read_varstr()
        if not r.empty():
            return None
        return DelegationInfo(value, gamma, reward_address)
    except Exception:
        return None
