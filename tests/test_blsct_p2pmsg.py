import json
import os
import struct
import time
import unittest

from electrum import blsct_p2pmsg as pm
from electrum.simple_config import SimpleConfig

from . import ElectrumTestCase

_FIXTURE = os.path.join(os.path.dirname(__file__), 'blsct-cover-candidates.json')


def _real_candidates():
    with open(_FIXTURE) as f:
        return [bytes.fromhex(h) for h in json.load(f)['candidates']]

try:
    from electrum import navio_blsct as nb
    nb.get_blsct()
    HAVE_BLSCT = True
except Exception:
    HAVE_BLSCT = False


class TestPadding(ElectrumTestCase):

    def test_buckets(self):
        self.assertEqual(64, len(pm._pad(b'')))
        self.assertEqual(64, len(pm._pad(b'x' * 60)))
        self.assertEqual(256, len(pm._pad(b'x' * 61)))
        self.assertEqual(4 + 5000, len(pm._pad(b'x' * 5000)))  # above top bucket: unpadded

    def test_roundtrip(self):
        for n in (0, 1, 48, 1238, 4000):
            data = bytes(range(256)) * (n // 256) + bytes(n % 256)
            self.assertEqual(data, pm._unpad(pm._pad(data)))

    def test_unpad_rejects_bad_length(self):
        self.assertIsNone(pm._unpad(b'\xff\xff\x00\x00' + bytes(60)))
        self.assertIsNone(pm._unpad(b'\x00'))


class TestPoW(ElectrumTestCase):

    def test_pow_ok_reads_hash_little_endian(self):
        # arith_uint256 is little-endian: the high bits live in the last bytes
        self.assertTrue(pm._pow_ok(b'\xff' * 31 + b'\x00', 8))
        self.assertFalse(pm._pow_ok(b'\x00' * 31 + b'\x01', 8))
        self.assertTrue(pm._pow_ok(b'\xff' * 29 + b'\x01\x00\x00', 23))
        self.assertFalse(pm._pow_ok(b'\xff' * 29 + b'\x02\x00\x00', 23))
        self.assertFalse(pm._pow_ok(b'\x00' * 29 + b'\x00\x00\x01', 23))

    def test_grind(self):
        prefix = b'navio' * 10
        nonce = pm.grind_pow(prefix, 12)
        self.assertTrue(pm._pow_ok(pm._sha256(prefix + struct.pack('<Q', nonce)), 12))

    def test_grind_stops(self):
        self.assertIsNone(pm.grind_pow(b'x', 64, should_stop=lambda: True))


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestEcies(ElectrumTestCase):

    def test_roundtrip(self):
        sk, pub = pm.new_keypair()
        pkt = pm.ecies_encrypt(pub, b'hello', b'\x03')
        self.assertEqual(64, len(pkt.ciphertext))  # padded bucket
        self.assertEqual(b'hello', pm.ecies_decrypt(sk, pkt, b'\x03'))

    def test_wrong_key_or_aad(self):
        sk, pub = pm.new_keypair()
        other, _ = pm.new_keypair()
        pkt = pm.ecies_encrypt(pub, b'hello', b'\x03')
        self.assertIsNone(pm.ecies_decrypt(other, pkt, b'\x03'))
        self.assertIsNone(pm.ecies_decrypt(sk, pkt, b'\x02'))

    def test_rejects_infinity_ephemeral(self):
        sk, pub = pm.new_keypair()
        pkt = pm.ecies_encrypt(pub, b'hello', b'\x03')
        pkt.eph = b'\xc0' + bytes(47)  # compressed point at infinity
        self.assertIsNone(pm.ecies_decrypt(sk, pkt, b'\x03'))

    def test_broadcast_key_is_generator(self):
        b = nb.get_blsct()
        _sk, pub = pm.broadcast_keypair()
        self.assertEqual(pub.hex(), b.Point.from_scalar(b.Scalar(1)).serialize())


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestEnvelope(ElectrumTestCase):

    def _build(self, version):
        sk, pub = pm.new_keypair()
        env = pm.build_envelope(pub, pm.KIND_CANDIDATE_TX, b'payload',
                                version=version, bits=8)
        return sk, env

    def test_roundtrip_v2(self):
        sk, env = self._build(pm.POW_VERSION_FLAGGED)
        raw = env.serialize()
        parsed = pm.Envelope.parse(raw)
        self.assertEqual(raw, parsed.serialize())
        self.assertTrue(parsed.check_pow(8))
        self.assertEqual(b'payload', pm.ecies_decrypt(sk, parsed.enc, bytes([parsed.kind])))
        # v2 binds the (empty) flag: payload hash differs from the bare packet hash
        self.assertEqual(parsed.payload_hash, pm._sha256(parsed.enc.msg_hash()))

    def test_roundtrip_v1(self):
        sk, env = self._build(pm.POW_VERSION_LEGACY)
        parsed = pm.Envelope.parse(env.serialize())
        self.assertEqual(parsed.payload_hash, parsed.enc.msg_hash())
        self.assertEqual(b'payload', pm.ecies_decrypt(sk, parsed.enc, bytes([parsed.kind])))

    def test_v2_flag_is_covered(self):
        _sk, env = self._build(pm.POW_VERSION_FLAGGED)
        env.flag = b'\x01' * 4
        with self.assertRaises(ValueError):
            pm.Envelope.parse(env.serialize())

    def test_rejects_tampering(self):
        _sk, env = self._build(pm.POW_VERSION_FLAGGED)
        raw = bytearray(env.serialize())
        raw[0] ^= 1  # kind no longer matches the PoW header
        with self.assertRaises(ValueError):
            pm.Envelope.parse(bytes(raw))
        raw = bytearray(env.serialize())
        raw[-1] ^= 1  # tag byte: payload hash mismatch
        with self.assertRaises(ValueError):
            pm.Envelope.parse(bytes(raw))
        with self.assertRaises(ValueError):
            pm.Envelope.parse(env.serialize() + b'\x00')


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestPullerInbound(ElectrumTestCase):

    def test_only_session_key_replies_are_pooled(self):
        puller = pm.CandidatePuller(peers=[])
        sk, pub = pm.new_keypair()
        puller.session_keys.append((sk, pub, time.time() + 60))
        accepted = []
        orig = pm.parse_candidate
        pm.parse_candidate = lambda raw: accepted.append(raw) or (_ for _ in ()).throw(ValueError('stub'))
        try:
            # addressed to our session key -> decrypted and handed to validation
            env = pm.build_envelope(pub, pm.KIND_CANDIDATE_TX, b'tx-bytes', bits=1)
            puller._on_p2pmsg(env.serialize())
            # public (broadcast key) candidate -> ignored
            _bsk, bpub = pm.broadcast_keypair()
            env = pm.build_envelope(bpub, pm.KIND_CANDIDATE_TX, b'public', bits=1)
            puller._on_p2pmsg(env.serialize())
            # duplicate delivery -> ignored
            puller._on_p2pmsg(pm.build_envelope(pub, pm.KIND_CANDIDATE_TX, b'tx2', bits=1).serialize())
        finally:
            pm.parse_candidate = orig
        self.assertEqual([b'tx-bytes', b'tx2'], accepted)
        self.assertEqual(2, puller.stats['rejected'])

    def test_take_removes(self):
        puller = pm.CandidatePuller(peers=[])

        class C:
            def __init__(self, h):
                self.input_hash, self.received = h, time.time()
        puller.pool = {k: C(k) for k in 'abc'}
        got = puller.take(2, exclude_inputs={'a'})
        self.assertEqual({'b', 'c'}, {c.input_hash for c in got})
        self.assertEqual(['a'], list(puller.pool))


class TestAddr(ElectrumTestCase):

    def test_parse_addrv2(self):
        def entry(net_id, ip, port, services):
            return (b'\x00' * 4 + pm._compact_size(services) + bytes([net_id])
                    + pm._compact_size(len(ip)) + ip + struct.pack('>H', port))
        p = (pm._compact_size(3)
             + entry(1, bytes([1, 2, 3, 4]), 48470, pm.NODE_P2PMSG_V2)
             + entry(2, bytes(15) + b'\x01', 48470, 1)
             + entry(4, b'\x00' * 32, 1, 1))  # tor v3: skipped
        self.assertEqual([('1.2.3.4', 48470, pm.NODE_P2PMSG_V2), ('::1', 48470, 1)],
                         pm._parse_addrv2(p))


class TestPeerBook(ElectrumTestCase):

    def test_only_v2_relays_kept(self):
        book = pm.PeerBook()
        book.add('1.1.1.1', 1, pm.NODE_P2PMSG)          # legacy overlay only
        book.add('2.2.2.2', 1, pm.NODE_P2PMSG_V2)
        book.add('seed.example', 1)                     # services unknown
        self.assertEqual({('2.2.2.2', 1), ('seed.example', 1)}, set(book.entries))

    def test_order_and_backoff(self):
        book = pm.PeerBook()
        book.add('2001:db8::1', 1, pm.NODE_P2PMSG_V2)
        book.add('3.3.3.3', 1, pm.NODE_P2PMSG_V2)
        book.add('4.4.4.4', 1, pm.NODE_P2PMSG_V2)
        book.add('5.5.5.5', 1, good=True)
        cands = book.candidates()
        self.assertEqual(('5.5.5.5', 1), cands[0])          # known good first
        self.assertEqual(('2001:db8::1', 1), cands[-1])     # IPv6 after IPv4
        book.mark_try(('3.3.3.3', 1))
        book.mark_fail(('3.3.3.3', 1))
        self.assertNotIn(('3.3.3.3', 1), book.candidates())  # backing off
        self.assertNotIn(('4.4.4.4', 1), book.candidates(exclude={('4.4.4.4', 1)}))
        book.mark_ok(('4.4.4.4', 1), pm.NODE_P2PMSG_V2)
        self.assertEqual([('4.4.4.4', 1), ('5.5.5.5', 1)], book.good_peers())


class TestPullerPool(ElectrumTestCase):

    def test_take_drops_stale(self):
        puller = pm.CandidatePuller(peers=[])

        class C:
            def __init__(self, h, age):
                self.input_hash, self.received = h, time.time() - age
        puller.pool = {'a': C('a', 0), 'b': C('b', pm.CANDIDATE_TTL + 1)}
        got = puller.take(5)
        self.assertEqual(['a'], [c.input_hash for c in got])
        self.assertEqual({}, puller.pool)
        puller.put_back(got)
        self.assertEqual(['a'], list(puller.pool))


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestCombine(ElectrumTestCase):

    def _own_half(self, n_inputs=2, covers=()):
        b = nb.get_blsct()
        kr = nb.BlsctKeyRing('cd' * 32)
        utxos = [nb.SpendableOutput(
            output_hash=format(i + 1, '064x'), amount=10 ** 9,
            gamma_hex=format(777 + i, '064x'),
            blinding_key_hex=kr.spend_pub.serialize(), account=0, index=i)
            for i in range(n_inputs)]
        return nb.build_signed_tx(
            kr, utxos, [(kr.address(0, 3), 5 * 10 ** 8, '')], transcript_v2=True,
            extra_size=nb.cover_extra_size(covers), cover_count=len(covers))

    def test_split_roundtrip_real_candidates(self):
        for raw in _real_candidates():
            t = nb.split_blsct_tx(raw)
            self.assertEqual((1, 1), (len(t.inputs), len(t.outputs)))
            self.assertEqual(raw, nb.serialize_split_tx(t))
            pm.parse_candidate(raw)   # passes the pool's structural checks

    def test_combine(self):
        covers = _real_candidates()
        own = self._own_half(covers=covers)
        agg_hex = nb.combine_with_covers(own.raw_hex, covers)
        agg = nb.parse_tx_hex(agg_hex)
        own_p = nb.parse_tx_hex(own.raw_hex)
        # every input and output of every half, exactly one fee output
        want_in = {i.prevout_hash for i in own_p.inputs} | {
            nb.parse_tx_hex(c.hex()).inputs[0].prevout_hash for c in covers}
        self.assertEqual(want_in, {i.prevout_hash for i in agg.inputs})
        want_out = {o.raw for o in own_p.outputs} | {
            nb.parse_tx_hex(c.hex()).outputs[0].raw for c in covers}
        self.assertEqual(want_out, {o.raw for o in agg.outputs})
        self.assertEqual(1, sum(1 for o in agg.outputs if not o.has_blsct))
        # the merged size is what the fee was sized for, and the fee covers it
        self.assertEqual(len(own.raw_hex) // 2 + nb.cover_extra_size(covers),
                         len(agg_hex) // 2)
        self.assertGreaterEqual(own.fee, nb._required_fee(len(agg_hex) // 2))
        # priced like a plain send of the same shape: 5 inputs, 4 recipients
        self.assertEqual((5 + 4 + 2) * nb.DEFAULT_FEE_PER_COMPONENT, own.fee)
        self.assertTrue(agg.version & (1 << 5))

    def test_combine_shuffles(self):
        covers = _real_candidates()
        own = self._own_half(covers=covers)
        orders = {tuple(i.prevout_hash for i in nb.parse_tx_hex(
            nb.combine_with_covers(own.raw_hex, covers)).inputs) for _ in range(12)}
        self.assertGreater(len(orders), 1)

    def test_combine_rejects_bad_covers(self):
        covers = _real_candidates()
        own = self._own_half()
        with self.assertRaises(ValueError):
            nb.combine_with_covers(own.raw_hex, [covers[0], covers[0]])
        with self.assertRaises(ValueError):   # a cover with a fee output
            nb.combine_with_covers(own.raw_hex, [bytes.fromhex(own.raw_hex)])


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestAggregatedSend(ElectrumTestCase):

    def setUp(self):
        super().setUp()
        self.config = SimpleConfig({'electrum_path': self.electrum_path})

    def _wallet(self):
        from electrum.blsct_wallet import restore_blsct_wallet_from_text
        w = restore_blsct_wallet_from_text(
            'ab' * 32, path=os.path.join(self.electrum_path, 'w'),
            config=self.config)['wallet']
        bk = w.keyring.spend_pub.serialize()
        for i, oh in enumerate(['11' * 32, '22' * 32]):
            w.blsct_outputs[oh] = {
                'tx_hash': 'aa' * 32, 'height': 100 + i, 'amount': 5_0000_0000,
                'gamma': format(12345 + i, '064x'), 'blinding_key': bk,
                'account': 0, 'addr_index': i,
                'address': w.get_receiving_addresses()[i], 'memo': '',
                'token_id': None, 'staked': False, 'delegation': None,
                'spent_by': None, 'spent_height': None}
        puller = pm.CandidatePuller(peers=[])
        for raw in _real_candidates():
            c = pm.parse_candidate(raw)
            puller.pool[c.input_hash] = c
        w.cover_puller = puller
        return w

    def _fake_network(self, w, reject_first: bool):
        sent = []

        class Session:
            async def send_request(self, method, params, timeout=None):
                from aiorpcx import RPCError
                sent.append(params[0])
                if reject_first and len(sent) == 1:
                    raise RPCError(1, 'bad-txns-inputs-missingorspent')
                return nb.parse_tx_hex(params[0]).txid

        class Iface:
            session = Session()

        class Net:
            interface = Iface()

            def get_local_height(self):
                return 90000
        w.network = Net()
        return sent

    async def test_send_is_aggregated(self):
        w = self._wallet()
        dest = w.keyring.address(0, 9)
        built = w.create_blsct_transaction([(dest, 7_0000_0000, '')])
        p = nb.parse_tx_hex(built.raw_hex)
        self.assertEqual(3, len(p.inputs))   # 2 own coins + ceil(2/4) = 1 cover
        self.assertEqual(2, w.cover_puller.pool_size())
        sent = self._fake_network(w, reject_first=False)
        ref = await w.broadcast_blsct_transaction(built.raw_hex)
        self.assertEqual([built.raw_hex], sent)
        # the reference is our destination output, not the cover's output
        own_outputs = {o.output_hash for o in p.outputs if o.has_blsct and
                       w.keyring.match_output(o.blinding_key.hex(),
                                              o.spending_key.hex(), o.view_tag)}
        self.assertIn(ref, own_outputs)
        self.assertTrue(all(w.blsct_outputs[h]['spent_by'] for h in ('11' * 32, '22' * 32)))

    async def test_rejected_aggregate_falls_back_to_plain(self):
        w = self._wallet()
        built = w.create_blsct_transaction([(w.keyring.address(0, 9), 7_0000_0000, '')])
        sent = self._fake_network(w, reject_first=True)
        await w.broadcast_blsct_transaction(built.raw_hex)
        self.assertEqual(2, len(sent))
        plain = nb.parse_tx_hex(sent[1])
        self.assertEqual(2, len(plain.inputs))
        self.assertEqual({'11' * 32, '22' * 32}, {i.prevout_hash for i in plain.inputs})

    async def test_cli_broadcast_uses_wallet_fallback(self):
        # `payto` then `broadcast` (CLI): the aggregate goes through the
        # wallet that built it, so a rejection still falls back to plain
        from electrum.commands import Commands
        w = self._wallet()
        built = w.create_blsct_transaction([(w.keyring.address(0, 9), 7_0000_0000, '')])
        sent = self._fake_network(w, reject_first=True)

        class Daemon:
            def get_wallets(self):
                return {'w': w}
        cmds = Commands(config=self.config, network=w.network, daemon=Daemon())
        await cmds.broadcast(built.raw_hex)
        self.assertEqual(2, len(sent))
        self.assertEqual(2, len(nb.parse_tx_hex(sent[1]).inputs))
        self.assertTrue(all(w.blsct_outputs[h]['spent_by'] for h in ('11' * 32, '22' * 32)))

    def test_no_aggregation_with_fixed_fee_or_disabled(self):
        w = self._wallet()
        dest = w.keyring.address(0, 9)
        for kw in ({'fixed_fee': 2_000_000}, {'aggregate': False}):
            built = w.create_blsct_transaction([(dest, 7_0000_0000, '')], **kw)
            self.assertEqual(2, len(nb.parse_tx_hex(built.raw_hex).inputs))
        self.assertEqual(3, w.cover_puller.pool_size())

    def test_served_cover_hidden_from_history(self):
        w = self._wallet()
        # coin '11' was used as a cover in someone's aggregate 'cc': same
        # amount back to us, no fee paid by us
        w.blsct_outputs['11' * 32].update(spent_by='cc' * 32, spent_height=200)
        w.blsct_outputs['33' * 32] = dict(w.blsct_outputs['22' * 32], tx_hash='cc' * 32,
                                          height=200, memo='candidate')
        amounts = [it['amount_sat'] for it in w.get_history_items()]
        self.assertNotIn(0, amounts)
        self.assertEqual(1, len(w.get_history_items()))   # the funding tx only
        # a self-transfer of ours pays a fee: still shown
        w.blsct_outputs['33' * 32]['amount'] -= 1000
        self.assertIn(-1000, [it['amount_sat'] for it in w.get_history_items()])


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestServing(ElectrumTestCase):

    def test_pull_requests_queued_fifo_and_own_ignored(self):
        puller = pm.CandidatePuller(peers=[], candidate_provider=lambda: None)
        _bsk, bpub = pm.broadcast_keypair()
        keys = [pm.new_keypair()[1] for _ in range(3)]
        own_sk, own_pub = pm.new_keypair()
        puller.session_keys.append((own_sk, own_pub, time.time() + 60))
        for k in keys + [own_pub, b'\x00' * 48]:
            puller._on_p2pmsg(pm.build_envelope(bpub, pm.KIND_AGG_ANN, k, bits=1).serialize())
        self.assertEqual(3, puller.stats['requests_seen'])
        self.assertEqual(keys[:2], puller.claim_requests(2))
        self.assertEqual(keys[2:], puller.claim_requests(5))

    def test_not_queued_without_provider(self):
        puller = pm.CandidatePuller(peers=[])
        _bsk, bpub = pm.broadcast_keypair()
        puller._on_p2pmsg(pm.build_envelope(bpub, pm.KIND_AGG_ANN, pm.new_keypair()[1],
                                            bits=1).serialize())
        self.assertEqual({}, puller.requests)

    @unittest.skipUnless(HAVE_BLSCT and nb.supports_fee_free_signing(),
                         "navio-blsct bindings cannot sign without a fee output")
    def test_wallet_serves_fee_free_self_spend(self):
        from electrum.blsct_wallet import restore_blsct_wallet_from_text
        config = SimpleConfig({'electrum_path': self.electrum_path})
        w = restore_blsct_wallet_from_text(
            'ab' * 32, path=os.path.join(self.electrum_path, 'srv'), config=config)['wallet']
        bk = w.keyring.spend_pub.serialize()
        for i, oh in enumerate(['11' * 32, '22' * 32]):
            w.blsct_outputs[oh] = {
                'tx_hash': 'aa' * 32, 'height': 100 + i, 'amount': 5_0000_0000 + i,
                'gamma': format(12345 + i, '064x'), 'blinding_key': bk,
                'account': 0, 'addr_index': i,
                'address': w.get_receiving_addresses()[i], 'memo': '',
                'token_id': None, 'staked': False, 'delegation': None,
                'spent_by': None, 'spent_height': None}
        served = [w.make_served_candidate() for _ in range(3)]
        self.assertIsNone(served[2])   # each live candidate spends a distinct coin
        inputs = set()
        for raw in served[:2]:
            cand = pm.parse_candidate(raw)   # what a requester's pool accepts
            inputs.add(cand.input_hash)
            out = cand.tx.outputs[0]
            # back to the sub-address the coin came from, same amount
            pair = w.keyring.match_output(out.blinding_key.hex(), out.spending_key.hex(),
                                          out.view_tag)
            src = w.blsct_outputs[cand.input_hash]
            self.assertEqual((src['account'], src['addr_index']), tuple(pair))
            self.assertEqual(src['amount'], w.keyring.try_recover_output(out).amount)
        self.assertEqual({'11' * 32, '22' * 32}, inputs)
        # hourly budget
        w._served_inputs.clear()
        w._served_times = [time.time()] * pm.SERVE_MAX_COINS_PER_WINDOW
        self.assertIsNone(w.make_served_candidate())
