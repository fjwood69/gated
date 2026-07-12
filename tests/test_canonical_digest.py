"""3.5-close — the canonical + deterministic identity digest (the crypto backbone of every 3.5-close
identity binding: profile, envelope, trust-policy). If this is non-deterministic every binding is
vacuous, so it ships with an adversarial golden suite. Run: python3 -m unittest discover -s tests
"""
from __future__ import annotations

import unicodedata
import unittest

from core.chain import NonCanonicalValueError, canonical_digest


class CanonicalDigestTests(unittest.TestCase):
    def test_reordered_maps_hash_identically(self) -> None:
        self.assertEqual(
            canonical_digest("d", {"a": 1, "b": 2}),
            canonical_digest("d", {"b": 2, "a": 1}),
        )

    def test_type_confusion_differs(self) -> None:
        self.assertNotEqual(canonical_digest("d", {"a": 1}), canonical_digest("d", {"a": "1"}))
        self.assertNotEqual(canonical_digest("d", {"a": True}), canonical_digest("d", {"a": 1}))

    def test_null_differs_from_absent_and_from_empty(self) -> None:
        null = canonical_digest("d", {"a": None})
        absent = canonical_digest("d", {})
        empty_map = canonical_digest("d", {"a": {}})
        self.assertNotEqual(null, absent)          # explicit null != absent key
        self.assertNotEqual(null, empty_map)       # null != {}
        self.assertNotEqual(absent, empty_map)

    def test_nfc_and_nfd_coincide(self) -> None:
        # "é" as NFC (single codepoint) vs NFD (e + combining accent) must hash the SAME.
        nfc = unicodedata.normalize("NFC", "café")
        nfd = unicodedata.normalize("NFD", "café")
        self.assertNotEqual(nfc.encode(), nfd.encode())  # genuinely different byte sequences
        self.assertEqual(canonical_digest("d", {"name": nfc}), canonical_digest("d", {"name": nfd}))

    def test_nested_and_empty_containers(self) -> None:
        a = canonical_digest("d", {"x": [1, {"y": [2, 3]}], "z": []})
        b = canonical_digest("d", {"z": [], "x": [1, {"y": [2, 3]}]})
        self.assertEqual(a, b)  # nested + reordered still coincide
        self.assertNotEqual(canonical_digest("d", {"z": []}), canonical_digest("d", {"z": [None]}))

    def test_floats_are_rejected_at_hash_time(self) -> None:
        with self.assertRaises(NonCanonicalValueError):
            canonical_digest("d", {"threshold": 0.5})           # use integer units (threshold_milli)
        with self.assertRaises(NonCanonicalValueError):
            canonical_digest("d", {"nested": {"list": [1, 2.0]}})

    def test_unsupported_type_rejected(self) -> None:
        with self.assertRaises(NonCanonicalValueError):
            canonical_digest("d", {"o": object()})
        with self.assertRaises(NonCanonicalValueError):
            canonical_digest("d", {"b": b"bytes"})

    def test_domain_separation(self) -> None:
        # the same payload under different domains must NOT collide (a profile digest can never be
        # confused with an envelope/policy digest).
        self.assertNotEqual(canonical_digest("profile", {"a": 1}), canonical_digest("envelope", {"a": 1}))

    def test_version_change_alters_digest(self) -> None:
        self.assertNotEqual(
            canonical_digest("d", {"a": 1}, version=1),
            canonical_digest("d", {"a": 1}, version=2),
        )

    def test_deterministic_across_calls(self) -> None:
        payload = {"a": 1, "b": [1, 2, {"c": None}], "d": "text"}
        self.assertEqual(canonical_digest("x", payload), canonical_digest("x", dict(payload)))


if __name__ == "__main__":
    unittest.main()
