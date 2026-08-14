# -*- coding: utf-8 -*-
#
# Air-gapped QR signing for Navio BLSCT wallets.
#
# A watch-only (view key) wallet composes a *transaction proposal* - the
# exact inputs, outputs and fee it wants - and displays it as a looping
# sequence of QR fragments. The offline wallet (which holds the seed) scans
# it, shows the outputs and fee for confirmation, builds and signs the
# complete transaction itself, and answers with the signed raw tx as another
# QR fragment sequence. The online wallet scans that and broadcasts.
#
# Security model: the online device is assumed compromised.
# - Change never appears in the proposal: the signer's own builder computes
#   the change output to its own derived change address, so a malicious
#   proposal cannot redirect change.
# - The signer refuses proposals for a different network (genesis hash) or a
#   different wallet (view-key fingerprint), and shows every proposed output
#   plus the fee before signing.
#
# Wire format (documented so third-party signers could implement it):
# - Payload: canonical CBOR (subset: uint/nint/bytes/text/array/map/bool/null),
#   zlib-compressed.
# - Fragmenting: 'NAV-AG/<v>/<msgid>/<index>/<count>/<base64url-chunk>'
#   where msgid = first 8 hex chars of sha256(compressed payload). Fragments
#   loop on screen; the receiver collects them in any order.
# - Proposal map keys: v(int) t('prop') net(bytes32 genesis) fp(bytes8
#   view-key fingerprint) ts(int) ins outs fee(int) sub(bool).
#   ins: [outputhash(bytes32) amount(int) gamma(bytes32) blind(bytes48)
#         account(int) index(int) staked(bool) token(bytes40|null)]
#   outs: [address(str) amount(int) memo(str) type(str) minstake(int)
#          deleg([bytes delegate_key, str reward_address]|null)
#          token(bytes40|null)]
# - Reply map keys: v t('signed') net fp txid(bytes32) raw(bytes, the
#   serialized signed transaction).

import base64
import hashlib
import struct
import time
import zlib
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .i18n import _
from .util import UserFacingException
from .logging import get_logger

_logger = get_logger(__name__)

AIRGAP_VERSION = 1
FRAGMENT_PREFIX = 'NAV-AG'
# base64 characters per QR fragment; keeps each QR comfortably scannable
FRAGMENT_DATA_LEN = 280
PROPOSAL_AGE_WARN_SECONDS = 24 * 3600
MAX_FRAGMENTS = 4096                      # bounds collector memory
MAX_PAYLOAD_SIZE = 4 * 1024 * 1024        # decompressed payload cap
# sanity bounds for proposal input key indices (a hostile online device
# could otherwise make the signer derive an absurd keypool)
MAX_ACCOUNT = 2**31
MIN_ACCOUNT = -2                          # change is -1, staking is -2
MAX_ADDR_INDEX = 1_000_000


# ---------------------------------------------------------------------------
# minimal canonical CBOR (RFC 8949 subset)
# ---------------------------------------------------------------------------

def _cbor_head(major: int, arg: int) -> bytes:
    if arg < 24:
        return bytes([(major << 5) | arg])
    for ai, fmt in ((24, 'B'), (25, '>H'), (26, '>I'), (27, '>Q')):
        try:
            return bytes([(major << 5) | ai]) + struct.pack(fmt, arg)
        except struct.error:
            continue
    raise ValueError('integer too large')


def cbor_encode(obj: Any) -> bytes:
    if obj is None:
        return b'\xf6'
    if obj is True:
        return b'\xf5'
    if obj is False:
        return b'\xf4'
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_head(0, obj)
        return _cbor_head(1, -1 - obj)
    if isinstance(obj, bytes):
        return _cbor_head(2, len(obj)) + obj
    if isinstance(obj, str):
        b = obj.encode('utf-8')
        return _cbor_head(3, len(b)) + b
    if isinstance(obj, (list, tuple)):
        return _cbor_head(4, len(obj)) + b''.join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        # canonical: sort by encoded key
        items = sorted((cbor_encode(k), cbor_encode(v)) for k, v in obj.items())
        return _cbor_head(5, len(items)) + b''.join(k + v for k, v in items)
    raise TypeError(f'cannot cbor-encode {type(obj)}')


def _cbor_decode_item(data: bytes, pos: int) -> Tuple[Any, int]:
    if pos >= len(data):
        raise ValueError('truncated cbor')
    initial = data[pos]
    major, ai = initial >> 5, initial & 0x1f
    pos += 1
    if major == 7:
        if ai == 20:
            return False, pos
        if ai == 21:
            return True, pos
        if ai == 22:
            return None, pos
        raise ValueError(f'unsupported simple value {ai}')
    if ai < 24:
        arg = ai
    elif ai in (24, 25, 26, 27):
        n = 1 << (ai - 24)
        if pos + n > len(data):
            raise ValueError('truncated cbor int')
        arg = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    else:
        raise ValueError(f'unsupported additional info {ai}')
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major == 2:
        if pos + arg > len(data):
            raise ValueError('truncated cbor bytes')
        return data[pos:pos + arg], pos + arg
    if major == 3:
        if pos + arg > len(data):
            raise ValueError('truncated cbor text')
        return data[pos:pos + arg].decode('utf-8'), pos + arg
    if major == 4:
        out = []
        for _i in range(arg):
            item, pos = _cbor_decode_item(data, pos)
            out.append(item)
        return out, pos
    if major == 5:
        out = {}
        for _i in range(arg):
            k, pos = _cbor_decode_item(data, pos)
            v, pos = _cbor_decode_item(data, pos)
            out[k] = v
        return out, pos
    raise ValueError(f'unsupported major type {major}')


def cbor_decode(data: bytes) -> Any:
    obj, pos = _cbor_decode_item(data, 0)
    if pos != len(data):
        raise ValueError('trailing cbor data')
    return obj


# ---------------------------------------------------------------------------
# fragmenting
# ---------------------------------------------------------------------------

def payload_to_fragments(payload: dict) -> List[str]:
    """Serialize a payload map into the looping QR fragment strings."""
    raw = zlib.compress(cbor_encode(payload), 9)
    msgid = hashlib.sha256(raw).hexdigest()[:8]
    b64 = base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')
    chunks = [b64[i:i + FRAGMENT_DATA_LEN]
              for i in range(0, len(b64), FRAGMENT_DATA_LEN)] or ['']
    total = len(chunks)
    return [f'{FRAGMENT_PREFIX}/{AIRGAP_VERSION}/{msgid}/{i + 1}/{total}/{c}'
            for i, c in enumerate(chunks)]


def parse_fragment(text: str) -> Optional[Tuple[str, int, int, str]]:
    """-> (msgid, index, total, chunk) or None if not an airgap fragment."""
    if not text.startswith(FRAGMENT_PREFIX + '/'):
        return None
    parts = text.split('/', 5)
    if len(parts) != 6:
        return None
    _prefix, version, msgid, idx, total, chunk = parts
    try:
        if int(version) != AIRGAP_VERSION:
            return None
        idx_i, total_i = int(idx), int(total)
    except ValueError:
        return None
    if not (1 <= idx_i <= total_i):
        return None
    return msgid, idx_i, total_i, chunk


class FragmentCollector:
    """Accumulates scanned fragments (any order, any repetition) until the
    payload is complete, then decodes it."""

    def __init__(self):
        self.msgid = None  # type: Optional[str]
        self.total = 0
        self.chunks = {}  # type: Dict[int, str]

    def add(self, text: str) -> bool:
        """Feed one scanned string. Returns True if it advanced the state."""
        parsed = parse_fragment(text)
        if parsed is None:
            return False
        msgid, idx, total, chunk = parsed
        if total > MAX_FRAGMENTS:
            return False
        if self.msgid != msgid or self.total != total:
            # new (or first) message, or inconsistent framing: reset
            self.msgid = msgid
            self.total = total
            self.chunks = {}
        if idx in self.chunks:
            return False
        self.chunks[idx] = chunk
        return True

    @property
    def received(self) -> int:
        return len(self.chunks)

    def is_complete(self) -> bool:
        return (self.total > 0
                and set(self.chunks.keys()) == set(range(1, self.total + 1)))

    def payload(self) -> dict:
        if not self.is_complete():
            raise ValueError('payload incomplete')
        b64 = ''.join(self.chunks[i] for i in range(1, self.total + 1))
        b64 += '=' * (-len(b64) % 4)
        raw = base64.urlsafe_b64decode(b64)
        if hashlib.sha256(raw).hexdigest()[:8] != self.msgid:
            raise ValueError('fragment checksum mismatch')
        decompressor = zlib.decompressobj()
        data = decompressor.decompress(raw, MAX_PAYLOAD_SIZE)
        if decompressor.unconsumed_tail:
            raise ValueError('payload too large')
        obj = cbor_decode(data)
        if not isinstance(obj, dict):
            raise ValueError('unexpected payload type')
        return obj


# ---------------------------------------------------------------------------
# proposal / reply construction and validation
# ---------------------------------------------------------------------------

def make_proposal_payload(*, genesis_hex: str, fingerprint_hex: str,
                          utxos, recipients, fee: int,
                          subtract_fee_from_amount: bool = False) -> dict:
    """utxos: Sequence[navio_blsct.SpendableOutput];
    recipients: Sequence[navio_blsct.Recipient]."""
    ins = []
    for u in utxos:
        ins.append([
            bytes.fromhex(u.output_hash),
            u.amount,
            bytes.fromhex(u.gamma_hex),
            bytes.fromhex(u.blinding_key_hex),
            u.account,
            u.index,
            bool(u.staked_commitment),
            bytes.fromhex(u.token_id_hex) if u.token_id_hex else None,
        ])
    outs = []
    for r in recipients:
        deleg = None
        if r.delegation is not None:
            deleg = [r.delegation.delegate_key, r.delegation.reward_address]
        outs.append([
            r.address, r.amount, r.memo or '', r.output_type, r.min_stake,
            deleg,
            bytes.fromhex(r.token_id_hex) if r.token_id_hex else None,
        ])
    return {
        'v': AIRGAP_VERSION,
        't': 'prop',
        'net': bytes.fromhex(genesis_hex),
        'fp': bytes.fromhex(fingerprint_hex),
        'ts': int(time.time()),
        'ins': ins,
        'outs': outs,
        'fee': int(fee),
        'sub': bool(subtract_fee_from_amount),
    }


def make_reply_payload(*, genesis_hex: str, fingerprint_hex: str,
                       txid_hex: str, raw_hex: str) -> dict:
    return {
        'v': AIRGAP_VERSION,
        't': 'signed',
        'net': bytes.fromhex(genesis_hex),
        'fp': bytes.fromhex(fingerprint_hex),
        'txid': bytes.fromhex(txid_hex),
        'raw': bytes.fromhex(raw_hex),
    }


def check_envelope(payload: dict, *, expected_type: str,
                   genesis_hex: str, fingerprint_hex: str) -> None:
    """Raises UserFacingException on any envelope mismatch."""
    if payload.get('v') != AIRGAP_VERSION:
        raise UserFacingException(_('Unsupported air-gap payload version'))
    if payload.get('t') != expected_type:
        raise UserFacingException(_('Unexpected air-gap payload type'))
    if payload.get('net') != bytes.fromhex(genesis_hex):
        raise UserFacingException(
            _('This payload is for a different network'))
    if payload.get('fp') != bytes.fromhex(fingerprint_hex):
        raise UserFacingException(
            _('This payload belongs to a different wallet'))


def proposal_age_seconds(payload: dict) -> int:
    return max(0, int(time.time()) - int(payload.get('ts') or 0))


def proposal_to_plan(payload: dict):
    """Decode a (validated) proposal into (utxos, recipients, fee, subtract).
    Structural validation only; the caller checks the envelope."""
    from .navio_blsct import SpendableOutput, Recipient
    from . import stake_delegation
    ins_raw = payload.get('ins')
    outs_raw = payload.get('outs')
    fee = payload.get('fee')
    if not isinstance(ins_raw, list) or not ins_raw:
        raise UserFacingException(_('Proposal has no inputs'))
    if not isinstance(outs_raw, list):
        raise UserFacingException(_('Proposal has no outputs'))
    if not isinstance(fee, int) or fee < 0:
        raise UserFacingException(_('Proposal has an invalid fee'))
    def bad(what):
        raise UserFacingException(_('Malformed proposal') + f' ({what})')

    utxos = []
    seen = set()
    for item in ins_raw:
        if not (isinstance(item, list) and len(item) == 8):
            bad('input arity')
        (ohash, amount, gamma, blind, account, index, staked, token) = item
        if not (isinstance(ohash, bytes) and len(ohash) == 32):
            bad('input hash')
        if not (isinstance(amount, int) and 0 < amount < 2**63):
            bad('input amount')
        if not (isinstance(gamma, bytes) and len(gamma) == 32):
            bad('input gamma')
        if not (isinstance(blind, bytes) and len(blind) == 48):
            bad('input blinding key')
        if not (isinstance(account, int) and MIN_ACCOUNT <= account < MAX_ACCOUNT):
            bad('input account')
        if not (isinstance(index, int) and 0 <= index < MAX_ADDR_INDEX):
            bad('input index')
        if not isinstance(staked, bool):
            bad('input staked flag')
        if token is not None and not (isinstance(token, bytes) and len(token) == 40):
            bad('input token id')
        if ohash in seen:
            bad('duplicate input')
        seen.add(ohash)
        utxos.append(SpendableOutput(
            output_hash=ohash.hex(), amount=amount, gamma_hex=gamma.hex(),
            blinding_key_hex=blind.hex(), account=account, index=index,
            staked_commitment=staked,
            token_id_hex=token.hex() if token else None))
    recipients = []
    for item in outs_raw:
        if not (isinstance(item, list) and len(item) == 7):
            bad('output arity')
        (address, amount, memo, otype, min_stake, deleg, token) = item
        if not isinstance(address, str) or not address:
            bad('output address')
        if not (isinstance(amount, int) and 0 < amount < 2**63):
            bad('output amount')
        if not isinstance(memo, str):
            bad('output memo')
        if otype not in ('Normal', 'StakedCommitment'):
            bad('output type')
        if not (isinstance(min_stake, int) and 0 <= min_stake < 2**63):
            bad('output min stake')
        if token is not None and not (isinstance(token, bytes) and len(token) == 40):
            bad('output token id')
        delegation = None
        if deleg is not None:
            if not (isinstance(deleg, list) and len(deleg) == 2
                    and isinstance(deleg[0], bytes) and isinstance(deleg[1], str)):
                bad('output delegation')
            delegation = stake_delegation.DelegationRequest(deleg[0], deleg[1])
        recipients.append(Recipient(
            address, amount, memo, otype, min_stake, delegation,
            token_id_hex=token.hex() if token else None))
    return utxos, recipients, fee, bool(payload.get('sub'))
