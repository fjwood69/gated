"""3.4 — the fixture ADMISSION GATE: the structural floor of the calibration oracle. Run:
python3 -m unittest discover -s tests

The non-negotiable done-tests (closed by construction, like 3.3's C3->tier absence):
  * PROPOSE cannot become PERSIST without two DISTINCT governance principals (no LLM/single-principal).
  * A candidate that does not execute cleanly (ERROR/crash) is REFUSED (malformed-fixture wedge).
  * A known-bad that PASSES the baseline is refused unless the mislabel is acknowledged.
  * A known-good without a canonical system-computed merged-tree hash is refused (reject PR-tree).
  * A C3 override becomes a READ-ONLY candidate, NEVER a fixture write (structural absence).
  * No batch / auto-promote path exists (admit is per-candidate, dual-gated).
"""
from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path

from core import VerdictType
from gate.admission import (
    AdmissionCheck,
    AdmissionError,
    admit,
    emit_c3_triage_candidate,
)
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore
from gate.candidate_store import Candidate, CandidateKind, CandidateSource, CandidateStore

_GOOD_TREE = "a" * 64  # a canonical 64-hex merged-tree hash


def _cal() -> CalibrationStore:
    d = Path(tempfile.mkdtemp(prefix="mv-adm-cal-"))
    return CalibrationStore(d / "cal.db")


def _cands() -> CandidateStore:
    d = Path(tempfile.mkdtemp(prefix="mv-adm-cand-"))
    return CandidateStore(d / "cand.db")


def _dual(op: str = "op") -> GovernanceApproval:
    return GovernanceApproval(principals=("gov1", "gov2"), purpose="admit", rationale="reviewed",
                              operation_id=op)


def _validator(verdict: VerdictType, clean: bool = True):  # type: ignore[no-untyped-def]
    def v(payload: bytes) -> AdmissionCheck:
        return AdmissionCheck(executes_cleanly=clean, baseline_verdict=verdict, detail="ok")
    return v


def _bad_candidate(cid: str = "b1") -> Candidate:
    return Candidate(cid, CandidateKind.KNOWN_BAD, b"evade()\n", CandidateSource.RED_TEAM,
                     evasion_class="proxy-bypass")


def _good_candidate(cid: str = "g1", tree: str = _GOOD_TREE) -> Candidate:
    return Candidate(cid, CandidateKind.KNOWN_GOOD, b"ok()\n", CandidateSource.C3_TRIAGE,
                     c3_override_ref="ovr-1", merged_tree_hash=tree)


class DualControlTests(unittest.TestCase):
    def test_single_principal_cannot_admit(self) -> None:
        cal = _cal()
        one = GovernanceApproval(("gov1",), purpose="admit", rationale="r", operation_id="o")
        with self.assertRaises(AdmissionError):
            admit(_bad_candidate(), approval=one, validator=_validator(VerdictType.FAIL),
                  calibration_store=cal, revoke_fallback=lambda _s: None)

    def test_dual_admits_and_records_provenance(self) -> None:
        cal = _cal()
        admit(_bad_candidate("b1"), approval=_dual(), validator=_validator(VerdictType.FAIL),
              calibration_store=cal, revoke_fallback=lambda _s: None)
        cset = cal.load_current_set()
        self.assertEqual({f.fixture_id for f in cset.known_bad}, {"b1"})


class ValidationTests(unittest.TestCase):
    def test_unclean_fixture_refused(self) -> None:
        cal = _cal()
        with self.assertRaises(AdmissionError):
            admit(_bad_candidate(), approval=_dual(),
                  validator=_validator(VerdictType.ERROR, clean=False), calibration_store=cal, revoke_fallback=lambda _s: None)

    def test_known_bad_that_passes_baseline_is_admitted_not_refused(self) -> None:
        # a known-bad the CURRENT detector PASSES is normally the DISCOVERED EVASION — exactly what
        # we capture. The detector cannot define ground truth for its own calibration fixtures, so
        # admission does NOT gate on the detector-verdict-vs-label; it only checks executability.
        cal = _cal()
        admit(_bad_candidate("b1"), approval=_dual(), validator=_validator(VerdictType.PASS),
              calibration_store=cal, revoke_fallback=lambda _s: None)
        self.assertEqual({f.fixture_id for f in cal.load_current_set().known_bad}, {"b1"})

    def test_known_good_requires_canonical_merged_tree_hash(self) -> None:
        cal = _cal()
        with self.assertRaises(AdmissionError):  # missing
            admit(_good_candidate(tree=None), approval=_dual(), validator=_validator(VerdictType.PASS),
                  calibration_store=cal, revoke_fallback=lambda _s: None)
        with self.assertRaises(AdmissionError):  # non-canonical (PR-tree-ish short hash)
            admit(_good_candidate(tree="deadbeef"), approval=_dual(),
                  validator=_validator(VerdictType.PASS), calibration_store=cal, revoke_fallback=lambda _s: None)
        admit(_good_candidate(), approval=_dual(), validator=_validator(VerdictType.PASS),
              calibration_store=cal, revoke_fallback=lambda _s: None)
        self.assertEqual({f.fixture_id for f in cal.load_current_set().known_good}, {"g1"})


class C3ReadOnlyTests(unittest.TestCase):
    def test_c3_override_emits_candidate_only_never_a_fixture(self) -> None:
        cands, cal = _cands(), _cal()
        cid = emit_c3_triage_candidate(cands, c3_override_ref="ovr-9", payload=b"clean()\n",
                                       merged_tree_hash=_GOOD_TREE)
        self.assertIsNotNone(cands.get(cid))                       # candidate exists
        self.assertEqual(cal.load_current_set().known_good, ())    # NO fixture written
        self.assertEqual(cal.load_current_set().known_bad, ())

    def test_emit_has_no_calibration_store_parameter(self) -> None:
        # structural: the C3 path CANNOT write a fixture — it takes only the candidate store.
        params = set(inspect.signature(emit_c3_triage_candidate).parameters)
        self.assertNotIn("calibration_store", params)


class NoAutoPromoteTests(unittest.TestCase):
    def test_admission_exposes_no_batch_or_auto_path(self) -> None:
        import gate.admission as adm
        for name in ("admit_all", "batch_admit", "auto_admit", "promote_all", "admit_pending"):
            self.assertFalse(hasattr(adm, name), f"admission must not expose {name}")


class SafeAppendMandatoryTests(unittest.TestCase):
    """Board blocker #5: admission must land the fixture through the SAFE append — revoke the fallback
    for the set FIRST, then commit the fixture ATOMICALLY with its re-calibration outbox trigger."""

    def test_admit_revokes_fallback_then_enqueues_outbox(self) -> None:
        cal = _cal()
        revoked: list[str] = []
        seq = admit(_bad_candidate("b1"), approval=_dual(), validator=_validator(VerdictType.FAIL),
                    calibration_store=cal, set_id="X", revoke_fallback=lambda sid: revoked.append(sid))
        self.assertGreater(seq, 0)
        self.assertEqual(revoked, ["X"])                     # fallback revoked, for the right set
        self.assertEqual({f.fixture_id for f in cal.load_current_set().known_bad}, {"b1"})
        outbox = cal.undrained_outbox()                      # re-calibration trigger enqueued atomically
        self.assertEqual(len(outbox), 1)
        self.assertEqual(outbox[0].set_id, "X")
        self.assertEqual(outbox[0].oracle_head_after, cal.set_head("X"))

    def test_admit_requires_a_revoke_fallback_hook(self) -> None:
        # the safe append is MANDATORY, not optional — revoke_fallback is a required keyword.
        params = inspect.signature(admit).parameters
        self.assertIn("revoke_fallback", params)
        self.assertIs(params["revoke_fallback"].default, inspect.Parameter.empty)  # required

    def test_revocation_failure_aborts_admission(self) -> None:
        # if the fallback revocation fails, the fixture must NOT land (over-block, fail-closed).
        cal = _cal()

        def boom(_sid: str) -> None:
            raise OSError("cannot revoke fallback")

        with self.assertRaises(OSError):
            admit(_bad_candidate("b1"), approval=_dual(), validator=_validator(VerdictType.FAIL),
                  calibration_store=cal, set_id="X", revoke_fallback=boom)
        self.assertEqual(cal.record_count(), 0)              # nothing landed
        self.assertEqual(cal.undrained_outbox(), ())


if __name__ == "__main__":
    unittest.main()
