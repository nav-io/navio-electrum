import unittest

try:
    import blsct  # noqa: F401
    HAVE_BLSCT = True
except ImportError:
    HAVE_BLSCT = False

from electrum import stake_delegation as sd

from tests import ElectrumTestCase


class TestPayloadFormat(ElectrumTestCase):
    """Format checks that need no crypto backend or bindings."""

    def test_is_delegation_data(self):
        self.assertFalse(sd.is_delegation_data(b''))
        self.assertFalse(sd.is_delegation_data(b'NVDG\x01'))
        # long enough but wrong magic
        self.assertFalse(sd.is_delegation_data(b'\x00' * 120))
        # wrong version byte
        self.assertFalse(sd.is_delegation_data(b'NVDG\x02' + b'\x00' * 120))
        self.assertTrue(sd.is_delegation_data(b'NVDG\x01' + b'\x00' * 120))

    def test_split_sections_bounds(self):
        # owner_len that overruns the payload must be rejected
        blob = sd.MAGIC + bytes(48) + (1000).to_bytes(2, 'little') + bytes(64)
        self.assertIsNone(sd._split_sections(blob))

    def test_varstr_roundtrip(self):
        for s in ('', 'a', 'nav1' + 'q' * 100, 'x' * 300):
            r = sd._Reader(sd._write_varstr(s))
            self.assertEqual(s, r.read_varstr())
            self.assertTrue(r.empty())


@unittest.skipUnless(HAVE_BLSCT, "navio-blsct bindings not installed")
class TestDelegationCrypto(ElectrumTestCase):

    REWARD_ADDR = 'nav1exampleexampleexampleexampleexampleexampleexample'

    def setUp(self):
        super().setUp()
        from electrum.navio_blsct import get_blsct
        self.b = get_blsct()
        b = self.b
        self.delegate_priv = b.Scalar.random()
        self.delegate_pub = bytes.fromhex(
            b.Point.from_scalar(self.delegate_priv).serialize())
        self.nonce = bytes.fromhex(b.Point.random().serialize())
        self.info = sd.DelegationInfo(
            value=12_3456_7890,
            gamma=bytes(range(32)),
            reward_address=self.REWARD_ADDR,
        )
        self.request = sd.DelegationRequest(
            delegate_key=self.delegate_pub,
            reward_address=self.REWARD_ADDR,
        )

    def test_roundtrip_delegate(self):
        blob = sd.encrypt(self.b, self.info, self.request, self.nonce)
        self.assertTrue(sd.is_delegation_data(blob))
        got = sd.try_decrypt(self.b, blob, self.delegate_priv)
        self.assertEqual(self.info, got)

    def test_roundtrip_owner(self):
        blob = sd.encrypt(self.b, self.info, self.request, self.nonce)
        got = sd.recover_owner_info(blob, self.nonce)
        self.assertEqual(self.request, got)

    def test_wrong_delegate_key_fails(self):
        blob = sd.encrypt(self.b, self.info, self.request, self.nonce)
        wrong = self.b.Scalar.random()
        self.assertIsNone(sd.try_decrypt(self.b, blob, wrong))

    def test_wrong_nonce_fails(self):
        blob = sd.encrypt(self.b, self.info, self.request, self.nonce)
        wrong = bytes.fromhex(self.b.Point.random().serialize())
        self.assertIsNone(sd.recover_owner_info(blob, wrong))

    def test_tampering_detected(self):
        blob = sd.encrypt(self.b, self.info, self.request, self.nonce)
        owner_len = blob[53] | (blob[54] << 8)
        # (position, owner section must fail, delegate section must fail)
        cases = [
            (len(sd.MAGIC) + 1, True, True),       # ephemeral key: breaks both
            (55, True, False),                     # inside owner ciphertext
            (55 + owner_len, False, True),         # inside delegate ciphertext
            (len(blob) - 1, False, True),          # delegate auth tag
        ]
        for pos, owner_fails, delegate_fails in cases:
            tampered = bytearray(blob)
            tampered[pos] ^= 0x01
            tampered = bytes(tampered)
            self.assertTrue(sd.is_delegation_data(tampered))
            if delegate_fails:
                self.assertIsNone(
                    sd.try_decrypt(self.b, tampered, self.delegate_priv),
                    f'tamper at {pos} not detected (delegate)')
            if owner_fails:
                self.assertIsNone(
                    sd.recover_owner_info(tampered, self.nonce),
                    f'tamper at {pos} not detected (owner)')

    def test_unlinkability(self):
        # same delegation encrypted twice must not produce equal blobs
        # (fresh ephemeral key each time)
        a = sd.encrypt(self.b, self.info, self.request, self.nonce)
        c = sd.encrypt(self.b, self.info, self.request, self.nonce)
        self.assertNotEqual(a, c)

    def test_delegation_id(self):
        self.assertEqual(
            self.delegate_pub.hex() + ':' + self.REWARD_ADDR,
            self.request.id())
