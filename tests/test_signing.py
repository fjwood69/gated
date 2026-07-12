"""The measurement/receipt signing seam (merge-ready #2, corrected). Run:
python3 -m unittest discover -s tests

Backed by a VETTED library (PyNaCl / libsodium) — no custom cryptography on the security path. The
defect the hand-rolled Ed25519 had (accepting malleable S+L signatures) is REJECTED here. The security
property: a holder of only the public key cannot forge; a KMS deployment swaps the Signer behind the seam.
"""
from __future__ import annotations

import unittest

from gate.signing import KeyVerifier, SeedSigner, public_key, sign, verify

_L = 2 ** 252 + 27742317777372353535851937790883648493  # Ed25519 group order


class SigningTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        seed = bytes(range(32))
        pk = public_key(seed)
        sig = sign(b"measurement", seed)
        self.assertEqual(len(sig), 64)
        self.assertTrue(verify(b"measurement", sig, pk))

    def test_tamper_and_wrong_key_rejected(self) -> None:
        seed = bytes(range(32))
        pk = public_key(seed)
        sig = sign(b"m", seed)
        self.assertFalse(verify(b"m-tampered", sig, pk))
        self.assertFalse(verify(b"m", sig, public_key(bytes(range(1, 33)))))

    def test_malleable_signature_is_rejected(self) -> None:
        # the custom-impl defect: S+L verified. A vetted library REJECTS the non-canonical S.
        seed = bytes(range(32))
        pk = public_key(seed)
        sig = sign(b"m", seed)
        s_mal = int.from_bytes(sig[32:], "little") + _L
        if s_mal < 2 ** 256:
            mal = sig[:32] + s_mal.to_bytes(32, "little")
            self.assertFalse(verify(b"m", mal, pk))  # REJECTED (was accepted by the hand-rolled impl)

    def test_verifier_holds_no_signing_capability(self) -> None:
        signer = SeedSigner(bytes(range(32)))
        verifier = KeyVerifier(signer.public_key)
        sig = signer.sign(b"authorised")
        self.assertTrue(verifier.verify(b"authorised", sig))
        self.assertFalse(verifier.verify(b"forged", sig))  # only the public key -> cannot forge
        self.assertFalse(hasattr(verifier, "sign"))         # the Verifier has no sign method

    def test_no_custom_crypto_on_the_security_path(self) -> None:
        # the pure-Python Ed25519 is removed; nothing imports a hand-rolled primitive.
        from pathlib import Path
        core = Path(__file__).resolve().parent.parent / "core"
        self.assertFalse((core / "ed25519.py").exists(), "custom Ed25519 must be removed")


if __name__ == "__main__":
    unittest.main()
