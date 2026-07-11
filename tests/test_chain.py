"""core/chain.py — the shared tamper-evident hash-chain primitive (3.2 foundation).

BYTE-LEVEL GOLDEN TESTS. The chain math was extracted hash-preserving from gate/ledger.py (C3).
These pin the EXACT sha256 output for fixed inputs — if the canonicalisation ever drifts (key
order, separators, encoding), the golden hex changes and this suite FAILS, which is the point:
a silent drift would re-hash every historical C3 override record on disk and break its
tamper-evidence. The unchanged test_override_ledger suite is the second proof (the C3 chain still
verifies against the extracted primitive).
"""
from __future__ import annotations

import unittest

from core.chain import CHAIN_VERSION, GENESIS_HASH, chain_hash, content_digest

# Golden values computed from the extracted primitive (frozen wire format).
_SIMPLE = {"a": 1, "b": "x", "c": None, "z": 2.5}
_SIMPLE_DIGEST = "19f66f0b51c025180fd4cd115e0e0f3658e86862b2cc4b6fa71d21cd7bc88925"
_SIMPLE_CHAIN = "8b3b383b28e11344133ed00ca94132c943ab74fa55823517f7b6263bc4da4351"

# The EXACT C3 override-record field shape — pins the C3 wire format's hash-preservation.
_C3_SHAPE = {
    "delivery_id": "d-golden", "kind": "HUMAN_OVERRIDE", "repo_full_name": "acme/widgets",
    "pr": 7, "sha": "a" * 40, "verdict": "fail", "reason": "egress==1", "sub_reason": None,
    "merged_by": "admin", "merged_at": "2026-07-11T00:00:00Z", "policy_version": None,
    "captured_at": 1700000000.0,
}
_C3_DIGEST = "128e7bc21449812be671ee6a6d49646fa322a552a64f11469e4dcf350dda972c"
_C3_CHAIN = "63191acb4717313e29b738cd2ec4198c062d5b2c0c62f4164e2942f85279df8f"


class GoldenTests(unittest.TestCase):
    def test_genesis_constant(self) -> None:
        self.assertEqual(GENESIS_HASH, "0" * 64)
        self.assertEqual(CHAIN_VERSION, 1)

    def test_content_digest_golden(self) -> None:
        self.assertEqual(content_digest(_SIMPLE), _SIMPLE_DIGEST)

    def test_chain_hash_golden(self) -> None:
        self.assertEqual(chain_hash(GENESIS_HASH, _SIMPLE_DIGEST), _SIMPLE_CHAIN)

    def test_c3_record_shape_hash_preserved(self) -> None:
        # If this hex changes, the extraction moved the C3 wire format — a silent break of
        # every HUMAN_OVERRIDE record already on disk. It must not change.
        self.assertEqual(content_digest(_C3_SHAPE), _C3_DIGEST)
        self.assertEqual(chain_hash(GENESIS_HASH, _C3_DIGEST), _C3_CHAIN)

    def test_key_order_independent(self) -> None:
        # sort_keys canonicalisation: insertion order must not change the digest.
        reordered = {"z": 2.5, "c": None, "b": "x", "a": 1}
        self.assertEqual(content_digest(reordered), _SIMPLE_DIGEST)


class ChainPropertyTests(unittest.TestCase):
    def _link(self, prev: str, fields: dict[str, object]) -> tuple[str, str]:
        d = content_digest(fields)
        return d, chain_hash(prev, d)

    def test_append_preserves_validity_and_edit_breaks_it(self) -> None:
        # Build a 3-record chain; verify each record_hash links to the prior; then edit a
        # middle record's content and confirm every downstream record_hash no longer matches.
        recs = [{"i": 0}, {"i": 1}, {"i": 2}]
        prev = GENESIS_HASH
        chain: list[tuple[dict[str, object], str, str]] = []  # (fields, digest, record_hash)
        for r in recs:
            d, h = self._link(prev, r)
            chain.append((r, d, h))
            prev = h
        # verify walk
        prev = GENESIS_HASH
        for fields, d, h in chain:
            self.assertEqual(content_digest(fields), d)
            self.assertEqual(chain_hash(prev, d), h)
            prev = h
        # tamper: edit record 1's content -> its digest changes -> its record_hash (and every
        # subsequent one, which chained off the old hash) no longer matches.
        tampered_digest = content_digest({"i": 99})
        self.assertNotEqual(tampered_digest, chain[1][1])
        recomputed = chain_hash(chain[0][2], tampered_digest)
        self.assertNotEqual(recomputed, chain[1][2])  # the edit is detectable


if __name__ == "__main__":
    unittest.main()
