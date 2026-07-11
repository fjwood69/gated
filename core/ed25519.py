"""core/ed25519.py — a pure-stdlib Ed25519 signer/verifier (zero third-party deps).

3.5 merge-ready condition #2: the measurement≠governance spine must be CRYPTOGRAPHICALLY real, not a
symmetric HMAC the verifier could forge. With Ed25519 the runner signs with a PRIVATE seed and the
restore controller holds ONLY the PUBLIC key — so a compromised controller cannot forge a PASS
attestation (it has no signing key). This is verifier-only trust, in-process, with no dependency: the
reference algorithm of RFC 8032 (§5.1), transcribed from the canonical public-domain reference. A
deployment binds a real KMS/HSM behind the same ``sign``/``verify`` seam; the SEPARATION is the point.

The affine reference is slow (fine for our low-frequency signing — one per measurement); correctness is
what matters and is checked by a curve-order known-answer test (l·B == identity) plus sign/verify/tamper
round-trips. Pure functions over ``hashlib.sha512``; ``core`` imports nothing here that reaches gate/engine.
"""
from __future__ import annotations

import hashlib

_b = 256
_q = 2 ** 255 - 19
# group order of the base point
_L = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m: bytes) -> bytes:
    return hashlib.sha512(m).digest()


def _inv(x: int) -> int:
    return pow(x, _q - 2, _q)


_d = (-121665 * _inv(121666)) % _q
_I = pow(2, (_q - 1) // 4, _q)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x


_By = (4 * _inv(5)) % _q
_Bx = _xrecover(_By)
_B = (_Bx % _q, _By % _q)


def _edwards(p: tuple[int, int], qy: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = p
    x2, y2 = qy
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return (x3 % _q, y3 % _q)


def _scalarmult(p: tuple[int, int], e: int) -> tuple[int, int]:
    # iterative double-and-add (avoids deep recursion; the affine ops stay the reference ones).
    result = (0, 1)  # neutral element
    addend = p
    while e > 0:
        if e & 1:
            result = _edwards(result, addend)
        addend = _edwards(addend, addend)
        e >>= 1
    return result


def _bit(h: bytes, i: int) -> int:
    return (h[i // 8] >> (i % 8)) & 1


def _encodeint(y: int) -> bytes:
    return bytes((y >> (8 * i)) & 0xFF for i in range(_b // 8))


def _encodepoint(pt: tuple[int, int]) -> bytes:
    x, y = pt
    bits = [(y >> i) & 1 for i in range(_b - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_b // 8))


def _decodeint(s: bytes) -> int:
    return sum(2 ** i * _bit(s, i) for i in range(_b))


def _isoncurve(pt: tuple[int, int]) -> bool:
    x, y = pt
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _q == 0


def _decodepoint(s: bytes) -> tuple[int, int]:
    y = sum(2 ** i * _bit(s, i) for i in range(_b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, _b - 1):
        x = _q - x
    pt = (x, y)
    if not _isoncurve(pt):
        raise ValueError("decoding a point that is not on the curve")
    return pt


def _secret_scalar(h: bytes) -> int:
    return int(2 ** (_b - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _b - 2)))


def _Hint(m: bytes) -> int:
    h = _H(m)
    return int(sum(2 ** i * _bit(h, i) for i in range(2 * _b)))


def public_key(seed: bytes) -> bytes:
    """The 32-byte Ed25519 public key for a 32-byte secret ``seed``. The seed is the SIGNING secret
    (kept by the signer / runner); the returned public key is what a verifier holds."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _H(seed)
    a = _secret_scalar(h)
    return _encodepoint(_scalarmult(_B, a))


def sign(message: bytes, seed: bytes) -> bytes:
    """A 64-byte Ed25519 signature over ``message`` under the secret ``seed`` (deterministic — no RNG,
    so it is reproducible and testable). Only a holder of the seed can produce this."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    h = _H(seed)
    a = _secret_scalar(h)
    pk = _encodepoint(_scalarmult(_B, a))
    r = _Hint(h[_b // 8:_b // 4] + message)
    rpt = _scalarmult(_B, r)
    s = (r + _Hint(_encodepoint(rpt) + pk + message) * a) % _L
    return _encodepoint(rpt) + _encodeint(s)


def verify(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    """True iff ``signature`` is a valid Ed25519 signature over ``message`` under ``pubkey``. The
    verifier holds ONLY ``pubkey`` and cannot produce a signature — verifier-only trust."""
    if len(signature) != 64 or len(pubkey) != 32:
        return False
    try:
        rpt = _decodepoint(signature[:32])
        a_pt = _decodepoint(pubkey)
    except ValueError:
        return False
    s = _decodeint(signature[32:])
    h = _Hint(signature[:32] + pubkey + message)
    return _scalarmult(_B, s) == _edwards(rpt, _scalarmult(a_pt, h))


# The base point's order (l·B == identity) is the known-answer that pins q, d, L, and B together — a
# mis-transcribed constant fails it. Exposed for the test to assert at import-adjacent cost.
def _curve_order_holds() -> bool:
    return _isoncurve(_B) and _scalarmult(_B, _L) == (0, 1)


__all__ = ["public_key", "sign", "verify"]
