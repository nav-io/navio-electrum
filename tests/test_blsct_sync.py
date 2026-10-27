import asyncio

from electrum import blsct_wallet
from electrum.logging import get_logger
from electrum.blsct_wallet import BlsctSynchronizer

from tests import ElectrumTestCase


class _FakeSession:
    """Answers get_output after a delay, tracking how many requests are in
    flight at once."""

    def __init__(self, fail=()):
        self.in_flight = 0
        self.max_in_flight = 0
        self.calls = 0
        self.fail = set(fail)

    async def send_request(self, method, params, timeout=None):
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


def _sync(session=None, mine=()):
    s = object.__new__(BlsctSynchronizer)
    s.wallet = _FakeWallet(set(mine))
    s.interface = type("Iface", (), {"session": session})()
    s.logger = get_logger(__name__)
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

        async def fake_store(tx_hash, height, ohash, bk, pair, *, coinbase=False, out_hex=None):
            stored.append((tx_hash, height, ohash, coinbase, out_hex))

        s._fetch_and_store_output = fake_store
        prefetched = {'o1': 'hex-o1'}  # o3's download failed: fetched again later
        for i, b in enumerate(blocks):
            await s._process_block(100 + i, b, matches=matches, prefetched=prefetched)
        self.assertEqual(stored, [
            ('tx1', 100, 'o1', True, 'hex-o1'),
            ('tx2', 102, 'o3', False, None),
        ])
