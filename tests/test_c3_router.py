"""3.5 job-2 — the C3 -> calibration router / provenance notary. Run:
python3 -m unittest discover -s tests

Board done-tests: (a) fuzz all router outputs -> none is accepted as a valid fixture write; (b) route a
C3 output straight at a mutator -> the router has no such capability (ACL isolation); (c) a C3 candidate
that was never admitted is not a fixture (type isolation). Plus the careful-voice point: the machine
provenance stamp is NOT authority — it never counts toward admission's two HUMAN approvals.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import VerdictType
from gate.admission import AdmissionCheck, AdmissionError, admit
from gate.authority import AuthorityDomain, GovernanceApproval
from gate.c3_router import C3Router, C3RoutingError, verify_provenance
from gate.calibration_store import CalibrationStore
from gate.candidate_store import CandidateSource, CandidateStore
from gate.ledger import OverrideKind, OverrideRecord

_ROUTER_KEY = b"c3-router-machine-key"
_TREE = "a" * 64  # a canonical 64-hex system-computed merged-tree hash


def _override(kind: OverrideKind = OverrideKind.HUMAN_OVERRIDE, *, delivery_id: str = "d1") -> OverrideRecord:
    return OverrideRecord(
        seq=1, delivery_id=delivery_id, kind=kind, repo_full_name="o/r", pr=7, sha="abc123",
        verdict="FAIL", reason="egress==1", sub_reason=None, merged_by="alice", merged_at="t",
        policy_version=None, captured_at=1.0, prev_hash="p", record_hash="rh-" + delivery_id,
    )


def _candidates() -> CandidateStore:
    return CandidateStore(Path(tempfile.mkdtemp(prefix="mv-c3-cand-")) / "c.db")


def _router(cs: CandidateStore) -> C3Router:
    return C3Router(cs, router_key=_ROUTER_KEY)


def _human(*principals: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose="admit", rationale="reviewed",
                              operation_id=op, domain=AuthorityDomain.GOVERNANCE)


def _clean_validator(_payload: bytes) -> AdmissionCheck:
    return AdmissionCheck(executes_cleanly=True, baseline_verdict=VerdictType.PASS)


class C3RouterTests(unittest.TestCase):
    def test_route_produces_c3_triage_candidate_with_verifiable_provenance(self) -> None:
        cs = _candidates()
        cid, stamp = _router(cs).route(_override(), payload=b"clean code",
                                       merged_tree_hash=_TREE, routed_at=10.0)
        cand = cs.get(cid)
        assert cand is not None
        self.assertIs(cand.source, CandidateSource.C3_TRIAGE)
        self.assertEqual(cand.merged_tree_hash, _TREE)
        self.assertTrue(verify_provenance(stamp, router_key=_ROUTER_KEY))
        self.assertFalse(verify_provenance(stamp, router_key=b"WRONG"))  # provenance is signed

    def test_only_human_override_routes(self) -> None:
        cs = _candidates()
        with self.assertRaises(C3RoutingError):
            _router(cs).route(_override(OverrideKind.UNVERIFIABLE), payload=b"x",
                              merged_tree_hash=_TREE, routed_at=1.0)

    def test_acl_isolation_router_holds_no_mutator(self) -> None:
        # (b) the router has NO calibration/policy/ledger store — routing to a mutator is a capability
        # it does not possess. Structural: its imports name no such store, and it exposes no admit/append.
        src = (Path(__file__).resolve().parent.parent / "gate" / "c3_router.py").read_text()
        imports = [ln for ln in src.splitlines() if ln.startswith(("import ", "from "))]
        joined = "\n".join(imports)
        self.assertNotIn("calibration_store", joined)
        self.assertNotIn("policy_store", joined)
        self.assertFalse(hasattr(C3Router, "admit"))
        self.assertFalse(hasattr(C3Router, "append"))
        self.assertFalse(hasattr(C3Router, "transition"))

    def test_router_output_is_not_a_fixture(self) -> None:
        # (c) a routed candidate is a PROPOSAL, not a fixture — it never reaches the calibration store
        # without admission. seal_set over the (empty) calibration store excludes it.
        cs = _candidates()
        cal = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-c3-cal-")) / "cal.db")
        cid, _stamp = _router(cs).route(_override(), payload=b"clean", merged_tree_hash=_TREE,
                                        routed_at=1.0)
        self.assertIsNotNone(cs.get(cid))                       # it IS a candidate
        self.assertEqual(cal.seal_set("default").fixture_ids, ())  # NOT a fixture
        self.assertEqual(cal.record_count(), 0)

    def test_provenance_stamp_is_not_authority(self) -> None:
        # (a) the machine stamp never substitutes for a human approval. A routed candidate + ONE human
        # is still refused; only TWO distinct humans admit it (the stamp is irrelevant to admission).
        cs = _candidates()
        cal = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-c3-cal2-")) / "cal.db")
        cid, _stamp = _router(cs).route(_override(), payload=b"clean", merged_tree_hash=_TREE,
                                        routed_at=1.0)
        cand = cs.get(cid)
        assert cand is not None
        with self.assertRaises(AdmissionError):  # one principal is not enough — the stamp adds nothing
            admit(cand, approval=_human("only-alice", op="o1"), validator=_clean_validator,
                  calibration_store=cal, revoke_fallback=lambda _s: None)
        # two DISTINCT humans (+ the canonical merged-tree hash the router carried) -> admitted.
        seq = admit(cand, approval=_human("alice", "bob", op="o2"), validator=_clean_validator,
                    calibration_store=cal, revoke_fallback=lambda _s: None)
        self.assertGreater(seq, 0)
        self.assertEqual(cal.record_count(), 1)  # NOW it is a fixture — by human dual control, not the stamp

    def test_calibration_governance_approval_cannot_admit_a_fixture(self) -> None:
        # cross-check the domain separation: a CALIBRATION_GOVERNANCE approval (the measurement side)
        # cannot admit a fixture — admission is a GOVERNANCE-domain act (meets(2) defaults GOVERNANCE).
        cs = _candidates()
        cal = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-c3-cal3-")) / "cal.db")
        cid, _stamp = _router(cs).route(_override(), payload=b"clean", merged_tree_hash=_TREE,
                                        routed_at=1.0)
        cand = cs.get(cid)
        assert cand is not None
        cal_gov = GovernanceApproval(principals=("a", "b"), purpose="p", rationale="r",
                                     operation_id="o", domain=AuthorityDomain.CALIBRATION_GOVERNANCE)
        with self.assertRaises(AdmissionError):
            admit(cand, approval=cal_gov, validator=_clean_validator, calibration_store=cal, revoke_fallback=lambda _s: None)


if __name__ == "__main__":
    unittest.main()
