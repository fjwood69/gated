"""Pure-stdlib Ed25519 signer/verifier (merge-ready condition #2). Run:
python3 -m unittest discover -s tests

Correctness is pinned by a curve-order known-answer (l·B == identity holds ONLY if q, d, L, B are the
genuine Ed25519 constants — a mis-transcription fails it), plus sign/verify/determinism/tamper round-
trips. The security property that matters for measurement≠governance: a holder of ONLY the public key
cannot forge a signature (verifier-only trust).
"""
from __future__ import annotations

import unittest

from core import ed25519


class Ed25519Tests(unittest.TestCase):
    def test_curve_constants_are_genuine(self) -> None:
        # l·B == identity AND B on-curve — the known-answer that pins the transcribed constants.
        self.assertTrue(ed25519._curve_order_holds())

    def test_sign_verify_round_trip(self) -> None:
        seed = bytes(range(32))
        pk = ed25519.public_key(seed)
        msg = b"the signed measurement payload"
        sig = ed25519.sign(msg, seed)
        self.assertEqual(len(sig), 64)
        self.assertEqual(len(pk), 32)
        self.assertTrue(ed25519.verify(msg, sig, pk))

    def test_signing_is_deterministic(self) -> None:
        seed = bytes(range(32))
        self.assertEqual(ed25519.sign(b"m", seed), ed25519.sign(b"m", seed))

    def test_tampered_message_rejected(self) -> None:
        seed = bytes(range(32))
        pk = ed25519.public_key(seed)
        sig = ed25519.sign(b"m", seed)
        self.assertFalse(ed25519.verify(b"m-tampered", sig, pk))

    def test_wrong_public_key_rejected(self) -> None:
        sig = ed25519.sign(b"m", bytes(range(32)))
        other_pk = ed25519.public_key(bytes(range(1, 33)))
        self.assertFalse(ed25519.verify(b"m", sig, other_pk))

    def test_verifier_cannot_forge_without_the_seed(self) -> None:
        # the security property: given ONLY the public key, no signature over a NEW message verifies.
        seed = bytes(range(32))
        pk = ed25519.public_key(seed)
        # a forger has pk + a valid (msg, sig) but no seed -> cannot make a sig for a different msg.
        sig = ed25519.sign(b"authorised", seed)
        self.assertFalse(ed25519.verify(b"forged", sig, pk))

    def test_malformed_lengths_rejected(self) -> None:
        seed = bytes(range(32))
        pk = ed25519.public_key(seed)
        self.assertFalse(ed25519.verify(b"m", b"short", pk))
        self.assertFalse(ed25519.verify(b"m", ed25519.sign(b"m", seed), b"shortkey"))


if __name__ == "__main__":
    unittest.main()
