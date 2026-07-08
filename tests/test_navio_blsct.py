import unittest

try:
    import blsct  # noqa: F401
    HAVE_BLSCT = True
except ImportError:
    HAVE_BLSCT = False

from electrum import navio_blsct as nb

from tests import ElectrumTestCase


class TestBip39Helpers(ElectrumTestCase):

    def test_roundtrip_32_bytes(self):
        ent = bytes(range(32))
        m = nb.bip39_entropy_to_mnemonic(ent)
        self.assertEqual(24, len(m.split()))
        self.assertEqual(ent, nb.bip39_mnemonic_to_entropy(m))

    def test_known_vector(self):
        # all-zero entropy -> "abandon ... art" (standard BIP39 test vector)
        ent = bytes(32)
        m = nb.bip39_entropy_to_mnemonic(ent)
        self.assertTrue(m.startswith('abandon abandon abandon'))
        self.assertTrue(m.endswith('art'))
        self.assertEqual(ent, nb.bip39_mnemonic_to_entropy(m))

    def test_bad_checksum_rejected(self):
        ent = bytes(32)
        words = nb.bip39_entropy_to_mnemonic(ent).split()
        words[-1] = 'abandon'  # break the checksum
        with self.assertRaises(ValueError):
            nb.bip39_mnemonic_to_entropy(' '.join(words))

    def test_is_bip39_mnemonic(self):
        self.assertFalse(nb.is_bip39_mnemonic('not a seed'))
        m = nb.bip39_entropy_to_mnemonic(bytes(range(32)))
        self.assertTrue(nb.is_bip39_mnemonic(m))


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestBlsctKeyRing(ElectrumTestCase):

    SEED = bytes(range(32)).hex()

    def test_deterministic_addresses(self):
        kr1 = nb.BlsctKeyRing(self.SEED)
        kr2 = nb.BlsctKeyRing(self.SEED)
        self.assertEqual(kr1.address(0, 0), kr2.address(0, 0))
        self.assertEqual(kr1.address(-1, 3), kr2.address(-1, 3))
        self.assertNotEqual(kr1.address(0, 0), kr1.address(0, 1))
        self.assertTrue(kr1.address(0, 0).startswith('nav1'))

    def test_hash_id_lookup(self):
        kr = nb.BlsctKeyRing(self.SEED)
        kr.ensure_keypool(0, 3)
        hid = kr.hash_id_hex(0, 2)
        self.assertEqual((0, 2), kr.subaddr_by_hashid.get(hid))
        self.assertEqual(40, len(hid))

    def test_tx_roundtrip_and_recovery(self):
        import secrets
        b = nb.get_blsct()
        kr = nb.BlsctKeyRing(self.SEED)
        kr.ensure_keypool(0, 3)
        kr.ensure_keypool(-1, 3)
        utxo = nb.SpendableOutput(
            output_hash=secrets.token_hex(32),
            amount=500_000_000,
            gamma_hex=b.Scalar(777).serialize(),
            blinding_key_hex=b.PublicKey.random().serialize(),
            account=0, index=1)
        built = nb.build_signed_tx(
            kr, [utxo], [(kr.address(0, 2), 100_000_000, 'unit test')])
        self.assertGreaterEqual(built.fee, nb._required_fee(len(built.raw_hex) // 2))
        parsed = nb.parse_tx_hex(built.raw_hex)
        self.assertEqual(1, len(parsed.inputs))
        self.assertEqual(utxo.output_hash, parsed.inputs[0].prevout_hash)
        # 2 blsct outputs (dest + change) + 1 transparent fee output
        blsct_outs = [o for o in parsed.outputs if o.has_blsct]
        fee_outs = [o for o in parsed.outputs if not o.has_blsct]
        self.assertEqual(2, len(blsct_outs))
        self.assertEqual(1, len(fee_outs))
        self.assertEqual(built.fee, fee_outs[0].value)
        recovered = {}
        for o in blsct_outs:
            pair = kr.match_output(o.blinding_key.hex(), o.spending_key.hex(), o.view_tag)
            self.assertIsNotNone(pair)
            rec = kr.try_recover_output(o)
            self.assertIsNotNone(rec)
            recovered[pair] = rec
        self.assertEqual(100_000_000, recovered[(0, 2)].amount)
        self.assertEqual('unit test', recovered[(0, 2)].memo)
        self.assertEqual(500_000_000 - 100_000_000 - built.fee,
                         recovered[(-1, 0)].amount)
        # amounts balance
        self.assertEqual(utxo.amount,
                         sum(r.amount for r in recovered.values()) + built.fee)

    def test_foreign_output_not_matched(self):
        b = nb.get_blsct()
        kr = nb.BlsctKeyRing(self.SEED)
        kr.ensure_keypool(0, 3)
        other = nb.BlsctKeyRing(bytes([7] * 32).hex())
        other.ensure_keypool(0, 1)
        import secrets
        utxo = nb.SpendableOutput(
            output_hash=secrets.token_hex(32),
            amount=400_000_000,
            gamma_hex=b.Scalar(5).serialize(),
            blinding_key_hex=b.PublicKey.random().serialize(),
            account=0, index=0)
        kr.ensure_keypool(-1, 1)
        built = nb.build_signed_tx(
            kr, [utxo], [(other.address(0, 0), 100_000_000, 'x')])
        parsed = nb.parse_tx_hex(built.raw_hex)
        their = 0
        for o in parsed.outputs:
            if not o.has_blsct:
                continue
            mine = kr.match_output(o.blinding_key.hex(), o.spending_key.hex(), o.view_tag)
            theirs = other.match_output(o.blinding_key.hex(), o.spending_key.hex(), o.view_tag)
            self.assertFalse(mine and theirs)
            if theirs:
                their += 1
                rec = other.try_recover_output(o)
                self.assertEqual(100_000_000, rec.amount)
        self.assertEqual(1, their)

    def test_not_enough_funds(self):
        import secrets
        b = nb.get_blsct()
        kr = nb.BlsctKeyRing(self.SEED)
        kr.ensure_keypool(0, 2)
        kr.ensure_keypool(-1, 1)
        utxo = nb.SpendableOutput(
            output_hash=secrets.token_hex(32),
            amount=1000,
            gamma_hex=b.Scalar(1).serialize(),
            blinding_key_hex=b.PublicKey.random().serialize(),
            account=0, index=0)
        from electrum.util import NotEnoughFunds
        with self.assertRaises(NotEnoughFunds):
            nb.build_signed_tx(kr, [utxo], [(kr.address(0, 1), 900, '')])


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestKeyStore(ElectrumTestCase):

    def test_keystore_password(self):
        from electrum.blsct_wallet import BlsctKeyStore
        ks = BlsctKeyStore.from_seed_hex(bytes(range(32)).hex())
        self.assertFalse(ks.has_password())
        seed_before = ks.get_seed(None)
        mnemonic_before = ks.get_mnemonic(None)
        ks.update_password(None, 'hunter2')
        self.assertTrue(ks.has_password())
        self.assertEqual(seed_before, ks.get_seed('hunter2'))
        self.assertEqual(mnemonic_before, ks.get_mnemonic('hunter2'))
        from electrum.util import InvalidPassword
        with self.assertRaises(InvalidPassword):
            ks.get_seed('wrong')
        ks.update_password('hunter2', None)
        self.assertFalse(ks.has_password())
        self.assertEqual(seed_before, ks.get_seed(None))


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestNavioCoreCompat(ElectrumTestCase):
    """Derivation must match navio-core (EIP-2333 derive_master_SK applied to
    the BIP39 entropy before FromSeedToChildKey). Vectors captured from
    navio-core `createwallet ... mnemonic=<phrase>` + `getnewaddress "" blsct`."""

    ENTROPY = '0f0e0d0c0b0a09080706050403020100ffeeddccbbaa99887766554433221100'
    # navio-core getnewaddress results for accounts 0, indices 0..2
    CORE_ADDRS = [
        'nav13f3qtju9pwrsme3lyfjyrwqf23vh2jfak37qh8f6qfpp0ra269uky5uykj0kja5fmy09p2tv3ctdmtc9yuha3nrmh0xzq5hgy6ddgs4rhmpghu8rrenfqcqzajxspk9ggrnessnadkcw8e453526qzszpgrdja0jak',
        'nav13zef7mnctl0e95yujcvra66ev6farqxad4663n80nkprytwwwfl66eun2gyavkntz8wvqghxclje8gmq5w2dt8neh5m2g35k9z4qvwp7jse56upsu7dgknh9x3754zuhlp6sqzlaml7wksrk7a7z63qv2cztxhphgs',
        'nav1kk33966kynrr3h65za8ur9ll3tdy03pc6thaad7ga5qz06sz099ud0hpv8mga4ncll2k0suf6cc5rxykkhx5yc0e8k70l3gzed56ztdt7mpv9r0l9yue84j03phptdw9vtyr2xj6r9pj77xtsts7m660yuy08hqcz2',
    ]

    def test_derive_master_sk_nonzero(self):
        m = nb.derive_master_sk(bytes.fromhex(self.ENTROPY))
        self.assertEqual(32, len(m))

    def test_addresses_match_navio_core(self):
        kr = nb.BlsctKeyRing(self.ENTROPY)
        kr.ensure_keypool(0, len(self.CORE_ADDRS))
        for i, expected in enumerate(self.CORE_ADDRS):
            self.assertEqual(expected, kr.address(0, i),
                             f'address (0,{i}) does not match navio-core')
