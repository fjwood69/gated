"""3.4 — the append-only candidate log. Run: python3 -m unittest discover -s tests

Load-bearing: proposing is UNPRIVILEGED (safe-to-be-wrong); the log is append-only with NO mutable
status field (a flippable pending->approved status IS the auto-persist bypass); and the candidate
store has NO reference to the fixture store — proposal cannot become persistence in this module.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.candidate_store import Candidate, CandidateKind, CandidateSource, CandidateStore


def _store() -> CandidateStore:
    d = Path(tempfile.mkdtemp(prefix="mv-cand-"))
    return CandidateStore(d / "candidates.db")


def _cand(cid: str = "c1", kind: CandidateKind = CandidateKind.KNOWN_BAD,
          payload: bytes = b"print('x')\n", **kw) -> Candidate:
    return Candidate(candidate_id=cid, kind=kind, payload=payload,
                     source=kw.pop("source", CandidateSource.RED_TEAM), **kw)


class CandidateStoreTests(unittest.TestCase):
    def test_propose_and_get_roundtrip(self) -> None:
        s = _store()
        s.propose(_cand("c1", evasion_class="env-keying"))
        got = s.get("c1")
        self.assertEqual(got.candidate_id, "c1")
        self.assertEqual(got.payload, b"print('x')\n")
        self.assertEqual(got.evasion_class, "env-keying")
        self.assertEqual(got.content_hash, _cand("c1").content_hash)

    def test_missing_returns_none(self) -> None:
        self.assertIsNone(_store().get("nope"))

    def test_propose_is_idempotent_and_count_grows(self) -> None:
        s = _store()
        s.propose(_cand("c1"))
        s.propose(_cand("c1"))  # idempotent by id
        s.propose(_cand("c2"))
        self.assertEqual(s.count(), 2)

    def test_no_mutable_status_or_delete_path(self) -> None:
        # structural: no status flip (pending->approved is the auto-persist bypass), no delete/update.
        s = _store()
        for attr in ("approve", "set_status", "update", "delete", "remove", "promote"):
            self.assertFalse(hasattr(s, attr), f"candidate store must not expose {attr}")

    def test_store_does_not_import_the_fixture_store(self) -> None:
        # structural floor: the candidate log cannot write a fixture — it never IMPORTS the store
        # (the docstring may name it; imports are what matter).
        src = (Path(__file__).resolve().parent.parent / "gate" / "candidate_store.py").read_text()
        self.assertNotIn("from gate.calibration_store", src)
        self.assertNotIn("import gate.calibration_store", src)
        self.assertNotIn("from .calibration_store", src)


if __name__ == "__main__":
    unittest.main()
