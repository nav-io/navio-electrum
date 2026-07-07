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
