"""tests/test_canonical_bytes.py — A2a: the public canonical BYTE encoding (``gated.canonical.v1``). Run:
python3 -m unittest discover -s tests

A2a extracts the byte encoding that ``canonical_digest`` already computed internally and exposes it as
``canonical_bytes``, with ``canonical_digest = sha256(canonical_bytes(...))``. This is behaviour-preserving
BY CONSTRUCTION (same computation, factored), so the profile digest is a fixed point and A2a touches no
signed structure — it lands standalone before the S3 identity-plane bump.

Board caveats locked here:
  * a DIFFERENTIAL PROPERTY test over generated (not merely fixed-corpus) type-valid payloads asserting
    ``canonical_digest(x) == sha256(canonical_bytes(x))`` — proves the CONSTRUCTION, not the sample;
  * BYTE-level golden vectors pin the ``gated.canonical.v1`` encoding (the cross-repo contract);
  * the error path is preserved — floats / non-str keys / unknown types reject at the SAME point.
The pre-existing ``test_canonical_digest.py`` is the behaviour-preservation proof for the digest itself
(it pins the digest semantics; if this refactor changed any output, those tests break).
"""
from __future__ import annotations

import hashlib
import unittest

from core.chain import (
    CANONICAL_DIGEST_VERSION,
    NonCanonicalValueError,
    canonical_bytes,
    canonical_digest,
)

# BYTE golden vectors — the gated.canonical.v1 contract. (encoded bytes, sha256 hex) keyed by (domain,
# payload). A companion repo pins the SAME vectors; changing the encoding must bump the version + these.
_GOLDENS = [
    (
        "gated.detector.profile:v1",
        {"detector_id": "retry", "module_bytes_hash": "aaaa",
         "entrypoint_argv": ["python3", "/x"], "behavioral_config": None},
        '{"domain":"gated.detector.profile:v1","payload":{"behavioral_config":null,'
        '"detector_id":"retry","entrypoint_argv":["python3","/x"],"module_bytes_hash":"aaaa"},"version":1}',
        "0db460c5b703646570f1864421e02364078d5de2375ccca4f42382a53995487a",
    ),
    (
        "gated.detector.profile:v1",
        {"behavioral_config": {}},
        '{"domain":"gated.detector.profile:v1","payload":{"behavioral_config":{}},"version":1}',
        "fd90da585ddf89b54c196c89b971911c318f12cedd0e1ac1730a285953af8573",
    ),
    (
        "d",
        {"i": 0, "neg": -5, "t": True, "f": False, "n": None, "s": "café"},
        '{"domain":"d","payload":{"f":false,"i":0,"n":null,"neg":-5,"s":"café","t":true},"version":1}',
        "4e7506142964aa10ca54a58d4353504d966e7c233cca37b2fe3077005f2660d4",
    ),
]


def _gen_payloads() -> "list[dict]":
    """A spread of type-valid payloads (str/int/bool/None/list/nested dict), deterministically generated —
    no RNG (the harness forbids Math.random-style nondeterminism). Includes empties, nesting, ordering
    permutations, and Unicode NFC/NFD forms."""
    import unicodedata

    out: list[dict] = [{}, {"a": None}, {"a": {}}, {"z": 1, "a": 2, "m": 3}]
    for i in range(12):
        out.append({
            f"k{i}": i, "neg": -i, "flag": bool(i % 2), "none": None,
            "nested": {"list": list(range(i % 4)), "inner": {"deep": i, "s": f"v{i}"}},
            "uni": unicodedata.normalize("NFD" if i % 2 else "NFC", "caféü"),
            "items": [{"x": j, "y": None} for j in range(i % 3)],
        })
    return out


class CanonicalBytesConstructionTests(unittest.TestCase):
    def test_digest_is_sha256_of_bytes_for_generated_payloads(self) -> None:
        # the differential PROPERTY: canonical_digest == sha256(canonical_bytes) for every generated
        # payload. Proves the factoring is byte-for-byte consistent, not just on the fixed corpus.
        for p in _gen_payloads():
            for domain in ("gated.detector.profile:v1", "gated.acceptance.envelope:v1", "x"):
                self.assertEqual(
                    canonical_digest(domain, p),
                    hashlib.sha256(canonical_bytes(domain, p)).hexdigest(),
                    f"digest != sha256(bytes) for {domain} {p}",
                )

    def test_bytes_are_deterministic_and_order_invariant(self) -> None:
        a = canonical_bytes("d", {"z": 1, "a": 2, "nested": {"y": 9, "x": 8}})
        b = canonical_bytes("d", {"a": 2, "z": 1, "nested": {"x": 8, "y": 9}})
        self.assertEqual(a, b)  # reordered maps -> identical bytes
        self.assertEqual(a, canonical_bytes("d", {"z": 1, "a": 2, "nested": {"y": 9, "x": 8}}))

    def test_nfc_nfd_coincide(self) -> None:
        import unicodedata
        nfc = canonical_bytes("d", {"k": unicodedata.normalize("NFC", "café")})
        nfd = canonical_bytes("d", {"k": unicodedata.normalize("NFD", "café")})
        self.assertEqual(nfc, nfd)


class CanonicalBytesGoldenTests(unittest.TestCase):
    def test_byte_golden_vectors(self) -> None:
        # the gated.canonical.v1 cross-repo byte contract — pin the exact emitted bytes AND their sha256.
        for domain, payload, want_bytes, want_hex in _GOLDENS:
            got = canonical_bytes(domain, payload)
            self.assertEqual(got.decode("utf-8"), want_bytes, f"byte drift for {domain}")
            self.assertEqual(hashlib.sha256(got).hexdigest(), want_hex)
            self.assertEqual(canonical_digest(domain, payload), want_hex)  # digest == sha256(bytes)


class CanonicalBytesErrorPathTests(unittest.TestCase):
    """The exposed bytes path rejects the SAME non-canonical inputs at the SAME point (preserved timing)."""

    def test_float_rejected(self) -> None:
        with self.assertRaises(NonCanonicalValueError):
            canonical_bytes("d", {"x": 1.5})

    def test_nested_float_rejected(self) -> None:
        with self.assertRaises(NonCanonicalValueError):
            canonical_bytes("d", {"a": {"b": [1, 2, 3.0]}})

    def test_non_str_key_rejected(self) -> None:
        with self.assertRaises(NonCanonicalValueError):
            canonical_bytes("d", {1: "x"})  # type: ignore[dict-item]

    def test_version_default_is_the_canonical_version(self) -> None:
        # the version stays a defaulted parameter (compatibility — the public API is not silently
        # converted to an internal-only constant); the default is the canonical version.
        self.assertEqual(
            canonical_bytes("d", {"a": 1}),
            canonical_bytes("d", {"a": 1}, version=CANONICAL_DIGEST_VERSION),
        )


if __name__ == "__main__":
    unittest.main()
