import asyncio
import threading

from aiorpcx import RPCError
from aiorpcx.jsonrpc import JSONRPC

from electrum import blsct_wallet
from electrum.logging import get_logger
from electrum.blsct_wallet import BlsctSynchronizer, Blsct_Wallet

from tests import ElectrumTestCase


class _FakeSession:
    """Answers get_output(s) after a delay, tracking how many requests are
    in flight at once. Without `batch`, get_outputs is an unknown method;
    with it, at most `batch` items are returned per request."""

    def __init__(self, fail=(), batch=None):
        self.in_flight = 0
        self.max_in_flight = 0
        self.calls = 0
        self.fail = set(fail)
        self.batch = batch
        self.methods = []

    async def send_request(self, method, params, timeout=None):
        self.methods.append(method)
        if method == 'blockchain.transaction.get_outputs':
            if self.batch is None:
                raise RPCError(JSONRPC.METHOD_NOT_FOUND, 'unknown method')
            await asyncio.sleep(0.01)
            return [None if h in self.fail else 'hex-' + h
                    for h in params[0][:self.batch]]
        assert method == 'blockchain.transaction.get_output'
        self.calls += 1
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0.01)
            if params[0] in self.fail:
                raise Exception('boom')
            return 'hex-' + params[0]
        finally:
            self.in_flight -= 1


class _FakeKeyRing:
    def __init__(self, mine):
        self.mine = mine

    def match_output(self, bk, sk, vt):
        return (0, 1) if bk in self.mine else None


class _FakeWallet:
    def __init__(self, mine):
        self.keyring = _FakeKeyRing(mine)
        self.blsct_outputs = {}
        self.blsct_sync = {}
        self._blsct_lock = threading.RLock()

    privacy_score_for_inputs = Blsct_Wallet.privacy_score_for_inputs
    _set_privacy_score = staticmethod(Blsct_Wallet._set_privacy_score)

    def _mark_spent(self, output_hash, tx_hash, height, ref=None):
        self.blsct_outputs[output_hash]['spent_by'] = tx_hash


def _sync(session=None, mine=()):
    s = object.__new__(BlsctSynchronizer)
    s.wallet = _FakeWallet(set(mine))
    s.interface = type("Iface", (), {"session": session})()
    s.logger = get_logger(__name__)
    s._batch_outputs_unsupported = None
    return s


def _out(h, bk):
    return {'outputHash': h, 'blindingKey': bk, 'spendingKey': 'sk', 'viewTag': 1}


class TestBlsctSync(ElectrumTestCase):

    async def test_prefetch_is_concurrent_and_skips_failures(self):
        session = _FakeSession(fail={'h3'})
        s = _sync(session)
        hashes = [f'h{i}' for i in range(50)]
        res = await s._prefetch_outputs(hashes)
        self.assertEqual(session.calls, 50)
        self.assertGreater(session.max_in_flight, 1)
        self.assertLessEqual(session.max_in_flight, blsct_wallet.OUTPUT_FETCH_CONCURRENCY)
        self.assertNotIn('h3', res)
        self.assertEqual(res['h7'], 'hex-h7')
        self.assertEqual(len(res), 49)

    async def test_prefetch_batched(self):
        # the server caps each response at 30 items; the rest is asked again
        session = _FakeSession(fail={'h3'}, batch=30)
        s = _sync(session)
        hashes = [f'h{i}' for i in range(600)]
        res = await s._prefetch_outputs(hashes)
        self.assertEqual(len(res), 599)
        self.assertNotIn('h3', res)
        self.assertEqual(res['h599'], 'hex-h599')
        self.assertEqual(session.calls, 0)  # no single-output requests
        self.assertEqual(set(session.methods), {'blockchain.transaction.get_outputs'})

    async def test_prefetch_falls_back_once_per_session(self):
        session = _FakeSession()
        s = _sync(session)
        res = await s._prefetch_outputs(['a', 'b'])
        self.assertEqual(res, {'a': 'hex-a', 'b': 'hex-b'})
        await s._prefetch_outputs(['c'])
        self.assertEqual(session.methods.count('blockchain.transaction.get_outputs'), 1)

    async def test_batch_matching_and_prefetched_processing(self):
        blocks = [
            [['tx1', {'vout': [_out('o1', 'mine'), _out('o2', 'other')], 'vin': []}]],
            [],
            [['tx2', {'vout': [_out('o3', 'mine')], 'vin': [{'prevoutHash': 'x'}]}],
             ['bad'], ['tx3', 'notadict']],
        ]
        s = _sync(mine={'mine'})
        matches = s._match_batch(blocks)
        self.assertEqual(matches, {'o1': (0, 1), 'o3': (0, 1)})

        stored = []

        async def fake_store(tx_hash, height, ohash, bk, pair, *, coinbase=False, out_hex=None,
                             privacy_mbits=None):
            stored.append((tx_hash, height, ohash, coinbase, out_hex))

        s._fetch_and_store_output = fake_store
        prefetched = {'o1': 'hex-o1'}  # o3's download failed: fetched again later
        for i, b in enumerate(blocks):
            await s._process_block(100 + i, b, matches=matches, prefetched=prefetched)
        self.assertEqual(stored, [
            ('tx1', 100, 'o1', True, 'hex-o1'),
            ('tx2', 102, 'o3', False, None),
        ])


def _store_into(wallet, stored=None):
    """_fetch_and_store_output stand-in: keeps the given score like the
    real one (new and existing outputs alike)."""
    async def store(tx_hash, height, ohash, bk, pair, *, coinbase=False, out_hex=None,
                    privacy_mbits=blsct_wallet._SCORE_NOT_GIVEN):
        d = wallet.blsct_outputs.setdefault(ohash, {'spent_by': None})
        d.update(tx_hash=tx_hash, height=height)
        wallet._set_privacy_score(d, privacy_mbits)
        if stored is not None:
            stored.append(ohash)
    return store


def _vin(h):
    return {'prevoutHash': h}


class TestBlsctSyncPrivacy(ElectrumTestCase):

    async def _run(self, s, blocks, start=100):
        for i, b in enumerate(blocks):
            await s._process_block(start + i, b, matches=s._match_batch([b]))

    def score(self, s, h):
        return s.wallet.blsct_outputs[h].get('privacy_mbits')

    async def test_scores_along_a_chain(self):
        s = _sync(mine={'mine'})
        s._fetch_and_store_output = _store_into(s.wallet)
        await self._run(s, [
            # coinbase / staking reward: no inputs
            [['cb', {'vout': [_out('r1', 'mine')], 'vin': []}]],
            # a plain receive: only foreign inputs
            [['rx', {'vout': [_out('r2', 'mine'), _out('f1', 'x')],
                     'vin': [_vin('a'), _vin('b')]}]],
            # someone else's aggregate spends our served candidate (r1)
            # with 3 foreign inputs: our coin comes back with log2(4) = 2 bits
            [['agg', {'vout': [_out('c1', 'mine'), _out('f2', 'x')],
                      'vin': [_vin('r1'), _vin('p'), _vin('q'), _vin('r')]}]],
            # our own send spends c1 (2 bits) and r2 (0 bits): change keeps 0
            [['send', {'vout': [_out('ch', 'mine'), _out('dst', 'x')],
                       'vin': [_vin('c1'), _vin('r2')]}]],
        ])
        self.assertEqual(self.score(s, 'r1'), 0)
        self.assertEqual(self.score(s, 'r2'), 0)
        self.assertEqual(self.score(s, 'c1'), 2000)
        self.assertEqual(self.score(s, 'ch'), 0)
        self.assertEqual(s.wallet.blsct_outputs['r1']['spent_by'], 'agg')

    async def test_same_block_chain_and_unknown_inputs(self):
        s = _sync(mine={'mine'})
        s._fetch_and_store_output = _store_into(s.wallet)
        s.wallet.blsct_outputs['old'] = {'spent_by': None}   # synced before scores
        s.wallet.blsct_outputs['good'] = {'spent_by': None, 'privacy_mbits': 3000}
        await self._run(s, [[
            ['t1', {'vout': [_out('o1', 'mine')], 'vin': [_vin('good'), _vin('z')]}],
            # spends t1's output in the same block, 1 foreign input
            ['t2', {'vout': [_out('o2', 'mine')], 'vin': [_vin('o1'), _vin('y')]}],
            ['t3', {'vout': [_out('o3', 'mine')], 'vin': [_vin('old'), _vin('o2')]}],
        ]])
        self.assertEqual(self.score(s, 'o1'), 4000)
        self.assertEqual(self.score(s, 'o2'), 5000)
        self.assertIsNone(self.score(s, 'o3'))   # 'old' is unknown

    async def test_block_view_replaces_mempool_score(self):
        # our broadcast stored change at 1.5 bits (process_own_transaction);
        # the staker merged our send with 7 more foreign inputs
        s = _sync(mine={'mine'})
        s._fetch_and_store_output = _store_into(s.wallet)
        w = s.wallet.blsct_outputs
        w['in1'] = {'spent_by': 'mempool', 'privacy_mbits': 1500}
        w['ch'] = {'spent_by': None, 'height': 0, 'privacy_mbits': 1500}
        await self._run(s, [[
            ['blocktx', {'vout': [_out('ch', 'mine')],
                         'vin': [_vin('in1')] + [_vin(f'x{i}') for i in range(7)]}],
        ]])
        self.assertEqual(self.score(s, 'ch'), 1500 + 3000)
        self.assertEqual(w['ch']['height'], 100)

    async def test_rescan_request_rewinds(self):
        s = _sync()
        s.wallet.blsct_sync.update(creation_height=50, last_height=900,
                                   hashes={'900': 'h'}, rescan_requested=True)
        s.network = type('N', (), {'get_server_height': lambda self: 1000,
                                   'get_local_height': lambda self: 1000})()
        seen = []

        async def stop_at_reorg_check():
            seen.append(s._last_synced())
            raise asyncio.CancelledError()
        s._check_reorg = stop_at_reorg_check
        with self.assertRaises(asyncio.CancelledError):
            await s._sync_once()
        self.assertEqual(seen, [49])
        self.assertEqual(s.wallet.blsct_sync['hashes'], {})
        self.assertNotIn('rescan_requested', s.wallet.blsct_sync)
