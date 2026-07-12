"""gate/signing.py — the measurement/receipt signing seam (merge-ready #2, corrected).

Security rule: NO custom cryptography on a security path. The measurement≠governance spine is signed with
Ed25519, but via a VETTED library (PyNaCl / libsodium) — constant-time, canonical, and rejecting the
malleable (S≥L) and non-canonical signatures a hand-rolled implementation accepts. The earlier pure-Python
Ed25519 is removed from the security path entirely.

The trust model is unchanged and now real: the runner signs with a PRIVATE seed; the restore controller /
report verifier holds ONLY the PUBLIC key, so it can verify but cannot forge. A DEPLOYMENT replaces the
in-process seed with a KMS/HSM behind the same ``Signer`` seam (the private key never enters the gate
process); the verifier still holds only the public key. ``Signer`` / ``Verifier`` are the injection
points; ``public_key`` / ``sign`` / ``verify`` are the concrete PyNaCl-backed helpers for the in-process
reference + tests.
"""
from __future__ import annotations

from typing import Protocol

from nacl.exceptions import BadSignatureError, CryptoError  # type: ignore[import-not-found]
from nacl.signing import SigningKey, VerifyKey  # type: ignore[import-not-found]


class Signer(Protocol):
    """Produces a detached 64-byte signature over a message. A deployment implements this against a
    KMS/HSM so the signing key never lives in the gate process."""

    def sign(self, message: bytes) -> bytes: ...


class Verifier(Protocol):
    """Verifies a detached signature under a fixed public key. Holds NO signing capability."""

    def verify(self, message: bytes, signature: bytes) -> bool: ...


def public_key(seed: bytes) -> bytes:
    """The 32-byte Ed25519 public key for a 32-byte private ``seed`` (via PyNaCl)."""
    return bytes(SigningKey(seed).verify_key)


def sign(message: bytes, seed: bytes) -> bytes:
    """A detached 64-byte Ed25519 signature over ``message`` under private ``seed`` (PyNaCl/libsodium —
    constant-time, deterministic per RFC 8032)."""
    return bytes(SigningKey(seed).sign(message).signature)


def verify(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    """True iff ``signature`` is a VALID canonical Ed25519 signature over ``message`` under ``pubkey``.
    libsodium rejects malleable (S≥L) and non-canonical signatures — the defect the custom impl had."""
    try:
        VerifyKey(pubkey).verify(message, signature)
        return True
    except (BadSignatureError, CryptoError, ValueError):
        return False


class SeedSigner:
    """In-process reference ``Signer`` holding the private seed. Deployments swap this for a KMS signer."""

    def __init__(self, seed: bytes) -> None:
        self._seed = seed

    def sign(self, message: bytes) -> bytes:
        return sign(message, self._seed)

    @property
    def public_key(self) -> bytes:
        return public_key(self._seed)


class KeyVerifier:
    """A ``Verifier`` holding ONLY a public key — no signing capability, cannot forge."""

    def __init__(self, public_key_bytes: bytes) -> None:
        self._pub = public_key_bytes

    def verify(self, message: bytes, signature: bytes) -> bool:
        return verify(message, signature, self._pub)


__all__ = ["Signer", "Verifier", "SeedSigner", "KeyVerifier", "public_key", "sign", "verify"]
