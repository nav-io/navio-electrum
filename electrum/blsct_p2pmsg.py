# Navio p2pmsg leaf client: pulls BLSCT aggregation cover candidates.
#
# navio-core runs an encrypted, PoW-gated broadcast bus ("p2pmsg") over the
# regular P2P network. Wallets use it to collect cover candidates -- fee-0,
# 1-input/1-output self-spends from other wallets -- that an initiator merges
# into its own transaction so the aggregate does not reveal which inputs and
# outputs belong together.
#
# This module speaks just enough of that protocol to act as a receive-only
# LEAF peer (service bit NODE_P2PMSG_LEAF): it connects to a naviod, which then
# floods bus traffic to it, broadcasts AGG_ANN pull requests carrying a fresh
# reply key, and trial-decrypts CANDIDATE_TX replies encrypted 1:1 to that key.
# Only this client can read the candidates it is sent, so neither the node it
# talks to nor the Electrum server learns which covers it will use.
#
# Wire formats mirror navio-core:
#   src/p2pmsg/crypto.{h,cpp}     ECIES over BLS G1 + ChaCha20Poly1305, padding
#   src/p2pmsg/pow.{h,cpp}        hashcash stamp
#   src/p2pmsg/transport.{h,cpp}  Envelope = u8 kind || PoWHeader || EciesPacket
#   src/aggregation/pull.cpp      AGG_ANN body = 48-byte reply pubkey
#   src/init.cpp                  CANDIDATE_TX body = serialized transaction

import asyncio
import functools
import hashlib
import hmac
import random
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from . import navio_blsct
from .crypto import chacha20_poly1305_encrypt, chacha20_poly1305_decrypt
from .logging import Logger


# -- network constants --------------------------------------------------------

MAINNET_MAGIC = bytes([0xbd, 0x5f, 0xc3, 0x00])
TESTNET_MAGIC = bytes([0x24, 0x67, 0xd2, 0xc1])
MAINNET_PORT = 48470
TESTNET_PORT = 33670
MAINNET_SEEDS = ['seed.nav.io']

PROTOCOL_VERSION = 70016
# p2pmsg service bits (navio-core src/protocol.h). NODE_P2PMSG relays the
# legacy v1 envelope, NODE_P2PMSG_V2 the current one (detection flag bound into
# the PoW); the two overlays are disjoint. A leaf advertises LEAF plus the
# format it speaks.
NODE_P2PMSG = 1 << 24
NODE_P2PMSG_LEAF = 1 << 25
NODE_P2PMSG_V2 = 1 << 27

MAX_P2P_PAYLOAD = 4 * 1000 * 1000

# -- p2pmsg constants ---------------------------------------------------------

POW_VERSION_LEGACY = 1
POW_VERSION_FLAGGED = 2
MAX_FLAG_BYTES = 128

KIND_PING = 0
KIND_AGG_ANN = 2
KIND_CANDIDATE_TX = 3

POW_BITS = 23                       # p2pmsg::DEFAULT_POW_BITS
POW_TIMESTAMP_TOLERANCE = 120       # seconds
MAX_JOB_BYTES = 4096                # largest envelope a node accepts
PULL_KEY_TTL = 600                  # aggregation::PULL_KEY_TTL_SECONDS
PULL_INTERVAL = 60                  # aggregation::PULL_INTERVAL_SECONDS
POOL_TARGET = 20                    # aggregation::POOL_TARGET
POOL_MAX = 512
CANDIDATE_MAX_WEIGHT = 6000         # aggregation::CANDIDATE_MAX_WEIGHT
POOL_MAX_COMBINED = 16              # aggregation::POOL_MAX_COMBINED (covers per aggregate)
COVER_INPUT_RATIO = 4               # aggregation::COVER_INPUT_RATIO: 1 cover per 4 own inputs
SERVE_INTERVAL = 20                 # aggregation::SERVE_INTERVAL_SECONDS
SERVE_MAX_PER_TICK = 2              # aggregation::SERVE_MAX_PER_TICK
SERVE_MAX_COINS_PER_WINDOW = 30     # aggregation::SERVE_MAX_COINS_PER_WINDOW
SERVE_WINDOW = 3600                 # aggregation::SERVE_WINDOW_SECONDS
REQUEST_QUEUE_CAP = 64

POINT_SIZE = 48
TAG_SIZE = 16
_HKDF_SALT = b'navio-p2pmsg-ecies-v1'
_HKDF_INFO = b'aead-key'
_ZERO_NONCE = bytes(12)
_PAD_BUCKETS = (64, 256, 1024, 3072, 3584)


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _sha256d(b: bytes) -> bytes:
    return _sha256(_sha256(b))


def _compact_size(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')


class _Reader:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            raise ValueError('truncated')
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def compact_size(self) -> int:
        b = self.read(1)[0]
        if b < 0xfd:
            return b
        return int.from_bytes(self.read({0xfd: 2, 0xfe: 4, 0xff: 8}[b]), 'little')

    def empty(self) -> bool:
        return self.pos == len(self.buf)


# -- BLS helpers (via the navio-blsct bindings) -------------------------------

def _b():
    return navio_blsct.get_blsct()


def new_keypair() -> Tuple[object, bytes]:
    """Fresh (scalar, 48-byte G1 pubkey)."""
    b = _b()
    sk = b.Scalar.random()
    pub = bytes.fromhex(b.Point.from_scalar(sk).serialize())
    return sk, pub


def broadcast_keypair() -> Tuple[object, bytes]:
    """p2pmsg's well-known PUBLIC broadcast key: private scalar 1."""
    b = _b()
    sk = b.Scalar(1)
    return sk, bytes.fromhex(b.Point.from_scalar(sk).serialize())


def _ecdh(point: bytes, scalar) -> Optional[bytes]:
    b = _b()
    try:
        p = b.Point.deserialize(point.hex())
        if not p.is_valid():
            return None
        return bytes.fromhex(p.scalar_multiply(scalar).serialize())
    except Exception:
        return None


def _derive_aead_key(shared: bytes) -> bytes:
    prk = hmac.digest(_HKDF_SALT, shared, 'sha256')
    return hmac.digest(prk, _HKDF_INFO + b'\x01', 'sha256')


def _pad(plain: bytes) -> bytes:
    framed = 4 + len(plain)
    size = next((b for b in _PAD_BUCKETS if framed <= b), framed)
    return len(plain).to_bytes(4, 'little') + plain + bytes(size - framed)


def _unpad(padded: bytes) -> Optional[bytes]:
    if len(padded) < 4:
        return None
    n = int.from_bytes(padded[:4], 'little')
    if n > len(padded) - 4:
        return None
    return padded[4:4 + n]


# -- ECIES packet / PoW / envelope -------------------------------------------

class EciesPacket:
    __slots__ = ('eph', 'ciphertext', 'tag')

    def __init__(self, eph: bytes, ciphertext: bytes, tag: bytes):
        self.eph, self.ciphertext, self.tag = eph, ciphertext, tag

    def serialize(self) -> bytes:
        return self.eph + _compact_size(len(self.ciphertext)) + self.ciphertext + self.tag

    def msg_hash(self) -> bytes:
        return _sha256(self.serialize())


def ecies_encrypt(recipient: bytes, plain: bytes, aad: bytes) -> EciesPacket:
    eph_sk, eph_pub = new_keypair()
    shared = _ecdh(recipient, eph_sk)
    if shared is None:
        raise ValueError('invalid recipient key')
    ct = chacha20_poly1305_encrypt(key=_derive_aead_key(shared), nonce=_ZERO_NONCE,
                                   associated_data=aad, data=_pad(plain))
    return EciesPacket(eph_pub, ct[:-TAG_SIZE], ct[-TAG_SIZE:])


def ecies_decrypt(sk, pkt: EciesPacket, aad: bytes) -> Optional[bytes]:
    shared = _ecdh(pkt.eph, sk)   # rejects invalid / infinity ephemeral keys
    if shared is None:
        return None
    try:
        padded = chacha20_poly1305_decrypt(key=_derive_aead_key(shared), nonce=_ZERO_NONCE,
                                           associated_data=aad, data=pkt.ciphertext + pkt.tag)
    except Exception:
        return None
    return _unpad(padded)


def _pow_ok(h: bytes, bits: int) -> bool:
    # arith_uint256 reads the hash little-endian: `bits` leading zero bits of
    # that integer are the high bits of the LAST bytes.
    return int.from_bytes(h, 'little') >> (256 - bits) == 0


def grind_pow(prefix: bytes, bits: int = POW_BITS,
              should_stop: Callable[[], bool] = None) -> Optional[int]:
    """Find a nonce so SHA256(prefix || u64 nonce) meets `bits`. CPU-bound:
    run it off the event loop."""
    base = hashlib.sha256(prefix)
    nonce = 0
    pack = struct.Struct('<Q').pack
    while True:
        if should_stop is not None and (nonce & 0xffff) == 0 and should_stop():
            return None
        h = base.copy()
        h.update(pack(nonce))
        if _pow_ok(h.digest(), bits):
            return nonce
        nonce += 1


def payload_hash(version: int, msg_hash: bytes, flag: bytes) -> bytes:
    if version == POW_VERSION_LEGACY:
        return msg_hash
    return _sha256(msg_hash + flag)


class Envelope:
    """v1: u8 kind || PoWHeader || EciesPacket
    v2: u8 kind || PoWHeader || CompactSize flen || flag || EciesPacket"""
    __slots__ = ('kind', 'pow_version', 'timestamp', 'session_eph',
                 'payload_hash', 'nonce', 'flag', 'enc')

    def pow_prefix(self) -> bytes:
        return (bytes([self.pow_version]) + struct.pack('<q', self.timestamp)
                + bytes([self.kind]) + self.session_eph + self.payload_hash)

    def serialize(self) -> bytes:
        flag = b''
        if self.pow_version != POW_VERSION_LEGACY:
            flag = _compact_size(len(self.flag)) + self.flag
        return (bytes([self.kind]) + self.pow_prefix()
                + struct.pack('<Q', self.nonce) + flag + self.enc.serialize())

    @classmethod
    def parse(cls, body: bytes) -> 'Envelope':
        if len(body) > MAX_JOB_BYTES:
            raise ValueError('envelope too large')
        r = _Reader(body)
        env = cls()
        env.kind = r.read(1)[0]
        env.pow_version = r.read(1)[0]
        env.timestamp = struct.unpack('<q', r.read(8))[0]
        pow_kind = r.read(1)[0]
        env.session_eph = r.read(POINT_SIZE)
        env.payload_hash = r.read(32)
        env.nonce = struct.unpack('<Q', r.read(8))[0]
        env.flag = b''
        if env.pow_version == POW_VERSION_FLAGGED:
            flen = r.compact_size()
            if flen > MAX_FLAG_BYTES:
                raise ValueError('flag too large')
            env.flag = r.read(flen)
        elif env.pow_version != POW_VERSION_LEGACY:
            raise ValueError(f'unknown PoW version {env.pow_version}')
        eph = r.read(POINT_SIZE)
        ct = r.read(r.compact_size())
        tag = r.read(TAG_SIZE)
        if not r.empty():
            raise ValueError('trailing bytes')
        if pow_kind != env.kind:
            raise ValueError('kind mismatch')
        env.enc = EciesPacket(eph, ct, tag)
        if env.payload_hash != payload_hash(env.pow_version, env.enc.msg_hash(), env.flag):
            raise ValueError('payload hash mismatch')
        return env

    def check_pow(self, bits: int = POW_BITS) -> bool:
        return _pow_ok(_sha256(self.pow_prefix() + struct.pack('<Q', self.nonce)), bits)


def build_envelope(recipient: bytes, kind: int, body: bytes, *,
                   version: int = POW_VERSION_FLAGGED,
                   bits: int = POW_BITS, should_stop=None) -> Optional[Envelope]:
    """Encrypt `body` to `recipient` and stamp it (CPU-heavy: PoW grind).
    No detection flag: bus requests/replies like ours never carry one."""
    env = Envelope()
    env.kind = kind
    env.enc = ecies_encrypt(recipient, body, bytes([kind]))
    env.pow_version = version
    env.timestamp = int(time.time())
    env.session_eph = env.enc.eph
    env.flag = b''
    env.payload_hash = payload_hash(version, env.enc.msg_hash(), env.flag)
    nonce = grind_pow(env.pow_prefix(), bits, should_stop)
    if nonce is None:
        return None
    env.nonce = nonce
    return env


# -- candidate validation -----------------------------------------------------

class Candidate:
    __slots__ = ('raw', 'tx', 'input_hash', 'received')

    def __init__(self, raw: bytes, tx, received: float):
        self.raw, self.tx, self.received = raw, tx, received
        self.input_hash = tx.inputs[0].prevout_hash

    @property
    def weight(self) -> int:
        return len(self.raw) * 4   # BLSCT txs carry no separate witness data


def parse_candidate(raw: bytes) -> Candidate:
    """Structural checks a cover candidate must pass (mirrors
    CandidatePool::AddCandidate): BLSCT, exactly 1 input and 1 output, no fee
    output, bounded weight. Signature validity is only checked when the
    aggregate is accepted by the network."""
    if len(raw) * 4 > CANDIDATE_MAX_WEIGHT:
        raise ValueError('candidate too large')
    tx = navio_blsct.parse_tx_hex(raw.hex())
    if not tx.version & (1 << 5):
        raise ValueError('not a BLSCT transaction')
    if len(tx.inputs) != 1 or len(tx.outputs) != 1:
        raise ValueError('candidate must be 1-in/1-out')
    if not tx.outputs[0].has_blsct:
        raise ValueError('candidate output is not confidential (fee output?)')
    return Candidate(raw, tx, time.time())


# -- P2P connection -----------------------------------------------------------

def _ip_str(net_id: int, raw: bytes) -> Optional[str]:
    import ipaddress
    if net_id == 1 and len(raw) == 4:
        return str(ipaddress.IPv4Address(raw))
    if net_id == 2 and len(raw) == 16:
        ip = ipaddress.IPv6Address(raw)
        return str(ip.ipv4_mapped) if ip.ipv4_mapped else str(ip)
    return None


def _parse_addr(p: bytes) -> List[Tuple[str, int, int]]:
    r = _Reader(p)
    out = []
    for _ in range(r.compact_size()):
        r.read(4)  # time
        services = struct.unpack('<Q', r.read(8))[0]
        ip = r.read(16)
        port = struct.unpack('>H', r.read(2))[0]
        host = _ip_str(2, ip)
        if host:
            out.append((host, port, services))
    return out


def _parse_addrv2(p: bytes) -> List[Tuple[str, int, int]]:
    r = _Reader(p)
    out = []
    for _ in range(r.compact_size()):
        r.read(4)  # time
        services = r.compact_size()
        net_id = r.read(1)[0]
        raw = r.read(r.compact_size())
        port = struct.unpack('>H', r.read(2))[0]
        host = _ip_str(net_id, raw)
        if host:
            out.append((host, port, services))
    return out


class P2PError(Exception):
    pass


class P2PConnection(Logger):
    """Minimal Navio P2P (v1 transport) peer: handshake, ping/pong, and
    delivery of `p2pmsg`/`dp2pmsg` payloads to a callback."""

    def __init__(self, host: str, port: int, *, magic: bytes = MAINNET_MAGIC,
                 on_p2pmsg: Callable[[bytes], None] = None,
                 on_addrs: Callable[[List[Tuple[str, int, int]]], None] = None,
                 open_connection=None, timeout: float = 20):
        Logger.__init__(self)
        self.host, self.port, self.magic = host, port, magic
        self.on_p2pmsg = on_p2pmsg
        self.on_addrs = on_addrs
        self._open = open_connection or asyncio.open_connection
        self.timeout = timeout
        self.reader = self.writer = None
        self.peer_services = 0
        self.peer_user_agent = ''
        self.peer_height = 0
        self.stats = {'p2pmsg_in': 0}

    def __repr__(self):
        return f'<P2PConnection {self.host}:{self.port}>'

    async def connect(self, *, require_p2pmsg: bool = True):
        self.reader, self.writer = await asyncio.wait_for(
            self._open(self.host, self.port), self.timeout)
        self._send('version', self._version_payload())
        got_version = got_verack = False
        while not (got_version and got_verack):
            cmd, payload = await asyncio.wait_for(self._read_msg(), self.timeout)
            if cmd == 'version':
                self._parse_version(payload)
                got_version = True
                # must precede verack (BIP155)
                self._send('sendaddrv2', b'')
                self._send('verack', b'')
            elif cmd == 'verack':
                got_verack = True
        if require_p2pmsg and self.envelope_version is None:
            raise P2PError(f'peer does not relay p2pmsg (services={self.peer_services:#x})')

    @property
    def envelope_version(self) -> Optional[int]:
        if self.peer_services & NODE_P2PMSG_V2:
            return POW_VERSION_FLAGGED
        if self.peer_services & NODE_P2PMSG:
            return POW_VERSION_LEGACY
        return None

    async def get_addrs(self, wait: float = 10) -> List[Tuple[str, int, int]]:
        """Ask the peer for addresses: [(host, port, services)] (IPv4/IPv6
        only)."""
        self._send('getaddr', b'')
        out = []
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                cmd, payload = await asyncio.wait_for(
                    self._read_msg(), deadline - time.monotonic())
            except asyncio.TimeoutError:
                break
            if cmd == 'ping':
                self._send('pong', payload)
            elif cmd == 'addrv2':
                out += _parse_addrv2(payload)
                if len(payload) > 100:
                    break
            elif cmd == 'addr':
                out += _parse_addr(payload)
                if len(payload) > 100:
                    break
        return out

    def _version_payload(self) -> bytes:
        def netaddr(services: int) -> bytes:
            return struct.pack('<Q', services) + bytes(10) + b'\xff\xff' + bytes(4) + struct.pack('>H', 0)
        ua = b'/navio-electrum-leaf:0.1/'
        services = NODE_P2PMSG_LEAF | NODE_P2PMSG_V2
        return (struct.pack('<iQq', PROTOCOL_VERSION, services, int(time.time()))
                + netaddr(0) + netaddr(services)
                + struct.pack('<Q', random.getrandbits(64))
                + _compact_size(len(ua)) + ua
                + struct.pack('<i', 0)
                + b'\x00')   # relay=false: no tx inv traffic, p2pmsg is unaffected

    def _parse_version(self, p: bytes):
        r = _Reader(p)
        version, self.peer_services, _ts = struct.unpack('<iQq', r.read(20))
        r.read(26 + 26 + 8)
        self.peer_user_agent = r.read(r.compact_size()).decode('ascii', 'replace')
        self.peer_height = struct.unpack('<i', r.read(4))[0]
        if version < 70016:
            raise P2PError(f'peer protocol version too old: {version}')

    def _send(self, cmd: str, payload: bytes):
        header = (self.magic + cmd.encode('ascii').ljust(12, b'\x00')
                  + struct.pack('<I', len(payload)) + _sha256d(payload)[:4])
        self.writer.write(header + payload)

    async def _read_msg(self) -> Tuple[str, bytes]:
        header = await self.reader.readexactly(24)
        if header[:4] != self.magic:
            raise P2PError('bad network magic')
        cmd = header[4:16].rstrip(b'\x00').decode('ascii', 'replace')
        length = struct.unpack('<I', header[16:20])[0]
        if length > MAX_P2P_PAYLOAD:
            raise P2PError('oversized message')
        payload = await self.reader.readexactly(length)
        if _sha256d(payload)[:4] != header[20:24]:
            raise P2PError('bad checksum')
        return cmd, payload

    async def run(self):
        """Read loop; returns/raises when the connection drops."""
        while True:
            cmd, payload = await self._read_msg()
            if cmd == 'ping':
                self._send('pong', payload)
            elif cmd in ('p2pmsg', 'dp2pmsg'):
                self.stats['p2pmsg_in'] += 1
                if self.on_p2pmsg:
                    self.on_p2pmsg(payload)
            elif cmd in ('addr', 'addrv2') and self.on_addrs:
                try:
                    addrs = (_parse_addrv2 if cmd == 'addrv2' else _parse_addr)(payload)
                except Exception:
                    continue
                self.on_addrs(addrs)

    async def send_p2pmsg(self, env: Envelope, *, stem: bool = True):
        # dp2pmsg asks the peer to continue it on its Dandelion stem; the peer
        # itself still sees that this connection originated it.
        self._send('dp2pmsg' if stem else 'p2pmsg', env.serialize())
        await self.writer.drain()

    def close(self):
        if self.writer:
            self.writer.close()


# -- peer book ----------------------------------------------------------------

MAX_RELAYS = 2          # concurrent relay connections
MAX_BOOK = 1000
CANDIDATE_TTL = 3 * 3600  # drop covers this old: their input is likely spent by now


class PeerBook:
    """Relay addresses we know of, learned from seeds, configuration and the
    addr gossip of the relays we are connected to. Only peers advertising
    NODE_P2PMSG_V2 are kept (or peers of unknown services, e.g. seeds)."""

    def __init__(self):
        self.entries = {}  # type: Dict[Tuple[str, int], dict]

    def add(self, host: str, port: int, services: Optional[int] = None, *,
            good: bool = False):
        if services is not None and not services & NODE_P2PMSG_V2:
            return
        key = (host, int(port))
        e = self.entries.get(key)
        if e is None:
            if len(self.entries) >= MAX_BOOK:
                return
            e = self.entries[key] = {'services': services, 'last_ok': 0.0,
                                     'last_try': 0.0, 'fails': 0}
        elif services is not None:
            e['services'] = services
        if good and not e['last_ok']:
            e['last_ok'] = 1.0  # known good from a previous session

    def mark_try(self, key):
        if key in self.entries:
            self.entries[key]['last_try'] = time.time()

    def mark_ok(self, key, services: int):
        e = self.entries.get(key)
        if e is not None:
            e.update(last_ok=time.time(), fails=0, services=services)

    def mark_fail(self, key):
        e = self.entries.get(key)
        if e is not None:
            e['fails'] += 1

    def candidates(self, exclude=()) -> List[Tuple[str, int]]:
        """Peers worth trying now, best first: known good, then untried, then
        ones that failed (each failure backs a peer off exponentially)."""
        now = time.time()
        ready = []
        for key, e in self.entries.items():
            if key in exclude:
                continue
            if e['fails'] and now - e['last_try'] < min(60 * 2 ** e['fails'], 6 * 3600):
                continue
            ipv6 = ':' in key[0]   # many gossiped v6 addrs are unroutable home links
            ready.append((0 if e['last_ok'] else 1, e['fails'], ipv6, random.random(), key))
        ready.sort()
        return [k for *_rest, k in ready]

    def good_peers(self, n: int = 16) -> List[Tuple[str, int]]:
        good = [(e['last_ok'], k) for k, e in self.entries.items()
                if e['last_ok'] and not e['fails']]
        good.sort(reverse=True)
        return [k for _t, k in good[:n]]


# -- candidate puller ---------------------------------------------------------

class CandidatePuller(Logger):
    """Keeps a local pool of cover candidates topped up from the p2pmsg bus.

    Holds up to `max_relays` connections to p2pmsg relays (found through the
    seeds and then the relays' own addr gossip). Every `interval` seconds,
    while the pool is below POOL_TARGET, a fresh reply keypair is minted and
    an AGG_ANN carrying its pubkey is broadcast through one of them. Wallets
    serving candidates answer with CANDIDATE_TX encrypted 1:1 to that key;
    anything else on the bus is ignored. Reply keys expire after PULL_KEY_TTL
    like on naviod. The pull cadence does not depend on sends, so a request
    does not signal that a send is imminent.

    `open_connection(host, port)` defaults to a direct TCP connection; pass a
    proxy's to route through it (it is looked up again on every connect).
    """

    def __init__(self, *, peers: List[Tuple[str, int]], magic: bytes = MAINNET_MAGIC,
                 interval: float = PULL_INTERVAL, pow_bits: int = POW_BITS,
                 open_connection=None, max_relays: int = MAX_RELAYS,
                 known_good: List[Tuple[str, int]] = (),
                 on_good_peers: Callable[[List[Tuple[str, int]]], None] = None,
                 is_input_spent: Callable[[str], bool] = None,
                 candidate_provider: Callable[[], Optional[bytes]] = None,
                 pull: bool = True):
        Logger.__init__(self)
        self.book = PeerBook()
        for host, port in known_good:
            self.book.add(host, port, good=True)
        for host, port in peers:
            self.book.add(host, port)
        self.magic = magic
        self.interval = interval
        self.pow_bits = pow_bits
        self.open_connection = open_connection
        self.max_relays = max_relays
        self.on_good_peers = on_good_peers
        self.is_input_spent = is_input_spent
        # serving: returns a signed fee-0 candidate of ours (or None); runs in
        # a worker thread. Rate limits and coin reservation are its job.
        self.candidate_provider = candidate_provider
        self.pull = pull   # False: only serve, collect no covers
        self.requests = {}  # type: Dict[bytes, float]   reply key -> queued at (FIFO)
        self.conns = []  # type: List[P2PConnection]
        self.session_keys = []   # type: List[Tuple[object, bytes, float]]  (sk, pub, expiry)
        self.pool = {}  # type: Dict[str, Candidate]   input hash -> candidate
        self.stats = {'requests': 0, 'envelopes': 0, 'replies': 0, 'rejected': 0,
                      'bad_envelopes': 0, 'requests_seen': 0, 'served': 0}
        self._lock = threading.Lock()   # pool is read from GUI/worker threads
        self._stopping = False
        self._seen = set()
        self._tasks = set()

    @property
    def conn(self) -> Optional[P2PConnection]:
        return self.conns[0] if self.conns else None

    @property
    def peers(self) -> List[Tuple[str, int]]:
        return list(self.book.entries)

    # pool access ------------------------------------------------------------

    def pool_size(self) -> int:
        with self._lock:
            return len(self.pool)

    def take(self, n: int, exclude_inputs=()) -> List[Candidate]:
        """Remove and return up to `n` random candidates. Taken candidates are
        not handed out again: each cover must be used by at most one
        aggregate."""
        cutoff = time.time() - CANDIDATE_TTL
        with self._lock:
            for k in [k for k, c in self.pool.items() if c.received < cutoff]:
                del self.pool[k]
            keys = [k for k in self.pool if k not in exclude_inputs]
            random.shuffle(keys)
            return [self.pool.pop(k) for k in keys[:n]]

    def put_back(self, cands: List['Candidate']):
        """Return covers that were taken but not broadcast."""
        with self._lock:
            for c in cands:
                if len(self.pool) < POOL_MAX:
                    self.pool.setdefault(c.input_hash, c)

    def evict_input(self, input_hash: str):
        with self._lock:
            self.pool.pop(input_hash, None)

    # inbound ----------------------------------------------------------------

    def _on_p2pmsg(self, body: bytes):
        self.stats['envelopes'] += 1
        if self.stats['envelopes'] % 50 == 0:
            self.logger.info(f'bus traffic: {self.stats}')
        try:
            env = Envelope.parse(body)
        except Exception:
            self.stats['bad_envelopes'] += 1
            return
        if env.kind not in (KIND_CANDIDATE_TX, KIND_AGG_ANN):
            return
        key = env.enc.msg_hash()
        if key in self._seen:   # the same envelope arrives over every relay
            return
        if len(self._seen) > 10000:
            self._seen.clear()
        self._seen.add(key)
        if env.kind == KIND_AGG_ANN:
            self._on_pull_request(env)
            return
        now = time.time()
        self.session_keys = [k for k in self.session_keys if k[2] > now]
        aad = bytes([env.kind])
        for sk, _pub, _exp in self.session_keys:
            plain = ecies_decrypt(sk, env.enc, aad)
            if plain is not None:
                break
        else:
            return
        self.stats['replies'] += 1
        try:
            cand = parse_candidate(plain)
        except Exception as e:
            self.stats['rejected'] += 1
            self.logger.info(f'rejected candidate: {e!r}')
            return
        with self._lock:
            if cand.input_hash in self.pool or len(self.pool) >= POOL_MAX:
                self.stats['rejected'] += 1
                return
            self.pool[cand.input_hash] = cand
            size = len(self.pool)
        self.logger.info(f'pooled candidate {cand.tx.txid} input={cand.input_hash[:16]} '
                         f'pool={size}')

    def _on_pull_request(self, env: Envelope):
        """Queue another wallet's AGG_ANN for serving: its body is the reply
        key, encrypted to the public broadcast key."""
        if self.candidate_provider is None:
            return
        bsk, _bpub = broadcast_keypair()
        body = ecies_decrypt(bsk, env.enc, bytes([env.kind]))
        if body is None or len(body) != POINT_SIZE:
            return
        if any(body == pub for _sk, pub, _exp in self.session_keys):
            return   # our own request, relayed back to us
        if _ecdh(body, _b().Scalar(1)) is None:
            return   # not a valid G1 point: nothing could be sent to it
        now = time.time()
        for k in [k for k, t in self.requests.items() if t + PULL_KEY_TTL <= now]:
            del self.requests[k]
        if body in self.requests or len(self.requests) >= REQUEST_QUEUE_CAP:
            return
        self.requests[body] = now
        self.stats['requests_seen'] += 1

    def claim_requests(self, n: int) -> List[bytes]:
        """Oldest first, as naviod does: keys are requester-chosen, so any
        order derived from them could be gamed."""
        now = time.time()
        live = sorted((t, k) for k, t in self.requests.items() if t + PULL_KEY_TTL > now)
        claimed = [k for _t, k in live[:n]]
        for k in claimed:
            del self.requests[k]
        return claimed

    async def serve_once(self):
        loop = asyncio.get_running_loop()
        for reply_key in self.claim_requests(SERVE_MAX_PER_TICK):
            conn = random.choice(self.conns) if self.conns else None
            if conn is None or conn.envelope_version is None:
                return
            raw = await loop.run_in_executor(None, self.candidate_provider)
            if not raw:
                return   # nothing to serve (locked, no free coin, budget spent)
            env = await loop.run_in_executor(
                None, functools.partial(build_envelope, reply_key, KIND_CANDIDATE_TX, raw,
                                        version=conn.envelope_version,
                                        bits=self.pow_bits,
                                        should_stop=lambda: self._stopping))
            if env is None or conn not in self.conns:
                return
            await conn.send_p2pmsg(env, stem=True)
            self.stats['served'] += 1
            self.logger.info(f'served a cover candidate via {conn.host}')

    async def _serve_loop(self):
        while not self._stopping:
            await asyncio.sleep(SERVE_INTERVAL)
            if self.conns and self.requests:
                try:
                    await self.serve_once()
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    self.logger.info(f'serving failed: {e!r}')

    def _on_addrs(self, addrs: List[Tuple[str, int, int]]):
        before = len(self.book.entries)
        for host, port, services in addrs:
            self.book.add(host, port, services)
        if len(self.book.entries) != before:
            self.logger.info(f'peer book: {len(self.book.entries)} relays')

    # outbound ---------------------------------------------------------------

    async def pull_once(self, conn: P2PConnection = None):
        conn = conn or (random.choice(self.conns) if self.conns else None)
        version = conn.envelope_version if conn else None
        if version is None:
            return
        sk, pub = new_keypair()
        loop = asyncio.get_running_loop()
        t0 = time.time()
        _bsk, bpub = broadcast_keypair()
        env = await loop.run_in_executor(
            None, lambda: build_envelope(bpub, KIND_AGG_ANN, pub, version=version,
                                         bits=self.pow_bits,
                                         should_stop=lambda: self._stopping))
        if env is None or conn not in self.conns:
            return
        self.session_keys.append((sk, pub, time.time() + PULL_KEY_TTL))
        await conn.send_p2pmsg(env, stem=True)
        self.stats['requests'] += 1
        self.logger.info(f'sent AGG_ANN via {conn.host} (pow {time.time() - t0:.1f}s, '
                         f'pool={self.pool_size()})')

    def _prune_spent(self):
        if not self.is_input_spent:
            return
        with self._lock:
            hashes = list(self.pool)
        for h in hashes:
            try:
                if self.is_input_spent(h):
                    self.evict_input(h)
            except Exception:
                pass

    async def _pull_loop(self):
        while not self._stopping:
            if not self.conns:
                await asyncio.sleep(5)
                continue
            self._prune_spent()
            if self.pool_size() < POOL_TARGET:
                try:
                    await self.pull_once()
                except Exception as e:
                    self.logger.info(f'pull failed: {e!r}')
            await asyncio.sleep(self.interval)

    # connections ------------------------------------------------------------

    async def _connect(self, host: str, port: int) -> P2PConnection:
        conn = P2PConnection(host, port, magic=self.magic, on_p2pmsg=self._on_p2pmsg,
                             on_addrs=self._on_addrs,
                             open_connection=self.open_connection, timeout=10)
        self.book.mark_try((host, port))
        try:
            await conn.connect()
        except BaseException:
            conn.close()
            self.book.mark_fail((host, port))
            raise
        self.book.mark_ok((host, port), conn.peer_services)
        self.logger.info(f'connected to {host}:{port} {conn.peer_user_agent} '
                         f'height={conn.peer_height} services={conn.peer_services:#x}')
        if self.on_good_peers:
            try:
                self.on_good_peers(self.book.good_peers())
            except Exception:
                pass
        return conn

    async def _connect_batch(self, want: int, batch: int = 8) -> List[P2PConnection]:
        """Try the next `batch` peers concurrently; keep up to `want`."""
        busy = {(c.host, c.port) for c in self.conns}
        peers = self.book.candidates(exclude=busy)[:batch]

        async def attempt(host, port):
            try:
                return await self._connect(host, port)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                self.logger.debug(f'peer {host}:{port} unusable: {e!r}')
                return None
        got = [c for c in await asyncio.gather(*(attempt(h, p) for h, p in peers)) if c]
        for extra in got[want:]:
            extra.close()
        return got[:want]

    async def _serve(self, conn: P2PConnection):
        if conn not in self.conns:
            self.conns.append(conn)
        try:
            conn._send('getaddr', b'')   # the answer arrives in run() as addr(v2)
            await conn.run()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self.logger.info(f'connection to {conn.host}:{conn.port} lost: {e!r}')
            self.book.mark_fail((conn.host, conn.port))
        finally:
            conn.close()
            if conn in self.conns:
                self.conns.remove(conn)

    def _spawn(self, coro):
        t = asyncio.ensure_future(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    async def run(self):
        """Keep up to `max_relays` relay connections and keep pulling until
        stop()."""
        if self.pull:
            self._spawn(self._pull_loop())
        if self.candidate_provider is not None:
            self._spawn(self._serve_loop())
        backoff = 5
        try:
            while not self._stopping:
                for _ in range(4):   # up to 4 batches per round
                    want = self.max_relays - len(self.conns)
                    if want <= 0 or self._stopping:
                        break
                    got = await self._connect_batch(want)
                    for conn in got:
                        self.conns.append(conn)   # before the task runs: no duplicate dial
                        self._spawn(self._serve(conn))
                        backoff = 5
                if self.conns:
                    await asyncio.sleep(30)
                else:
                    self.logger.info(f'no p2pmsg relay reachable; retry in {backoff}s')
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 300)
        finally:
            for t in list(self._tasks):
                t.cancel()
            for c in list(self.conns):
                c.close()

    def disconnect_all(self):
        """Drop current connections (e.g. after a proxy change); run() opens
        new ones."""
        for c in list(self.conns):
            c.close()

    def stop(self):
        self._stopping = True
        self.disconnect_all()


def resolve_seeds(seeds=MAINNET_SEEDS, port: int = MAINNET_PORT) -> List[Tuple[str, int]]:
    import socket
    out = []
    for s in seeds:
        try:
            for info in socket.getaddrinfo(s, port, type=socket.SOCK_STREAM):
                addr = (info[4][0], port)
                if addr not in out:
                    out.append(addr)
        except OSError:
            pass
    return out
