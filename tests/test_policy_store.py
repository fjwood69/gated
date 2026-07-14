"""3.3 — the tier-transition ledger (gate-side, 3rd core.chain consumer). Run:
python3 -m unittest discover -s tests

Load-bearing: genesis law (no jump to ENABLED); dual control is REAL (two DISTINCT principals — an
enum or a repeated principal does NOT satisfy it, addition #2); ENABLED requires the anchors
(cal-result-ref + fixture-set version + detector identity, addition #3); illegal edges refused;
tamper-evident (reuses core.chain) and fails CLOSED on a broken chain; deletes forbidden.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState
from gate.policy_store import (
    ChainIntegrityError,
    IllegalTransitionError,
    PolicyStore,
    PrivilegedOperationError,
)


def _store() -> PolicyStore:
    d = Path(tempfile.mkdtemp(prefix="mv-polstore-"))
    return PolicyStore(d / "tier.db")


def _appr(*principals: str, op: str, purpose: str = "test", rationale: str = "because") -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose=purpose, rationale=rationale, operation_id=op)


def _enable(store: PolicyStore, pid: str, *, detector: str = "det-1") -> None:
    """Walk a policy PROPOSED->PENDING->CALIBRATING->ENABLED with valid single-principal approvals.
    Records a matching calibration_pass so the (gap-1) ENABLED binding is satisfied."""
    store.transition(pid, PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op=f"{pid}-1"))
    store.enter_calibrating(pid, approval=_appr("gov1", op=f"{pid}-2"), set_id="default",
                            pinned_set_version="fx-head", detector_id=detector, expected_profile_digest="pd",
                            expected_trust_policy_digest="tp", expected_guard_policy_digest="gp",
                            identity_contract_version=1)
    store.record_calibration_pass("cal-1", policy_id=pid, pinned_set_version="fx-head",
                                  detector_identity=detector, identity_contract_version=1)
    store.transition(pid, PolicyState.ENABLED, approval=_appr("gov1", op=f"{pid}-3"),
                     calibration_result_ref="cal-1", set_id="default", pinned_set_version="fx-head",
                     detector_identity=detector, identity_contract_version=1)


class EnablePathTests(unittest.TestCase):
    def test_full_enable_path(self) -> None:
        s = _store()
        _enable(s, "p1")
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)
        self.assertTrue(s.verify_chain())

    def test_genesis_cannot_jump_to_enabled(self) -> None:
        s = _store()
        with self.assertRaises(IllegalTransitionError):
            s.transition("p1", PolicyState.ENABLED, approval=_appr("gov1", op="x"),
                         calibration_result_ref="c", pinned_set_version="v", detector_identity="d", identity_contract_version=1)

    def test_enabled_requires_anchors(self) -> None:
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="1"))
        s.enter_calibrating("p1", approval=_appr("gov1", op="2"), set_id="default", pinned_set_version="v",
                            detector_id="d", expected_profile_digest="pd", expected_trust_policy_digest="tp",
                            expected_guard_policy_digest="gp", identity_contract_version=1)
        with self.assertRaises(PrivilegedOperationError):  # missing all three anchors
            s.transition("p1", PolicyState.ENABLED, approval=_appr("gov1", op="3"))
        with self.assertRaises(PrivilegedOperationError):  # missing detector_identity
            s.transition("p1", PolicyState.ENABLED, approval=_appr("gov1", op="3"),
                         calibration_result_ref="c", pinned_set_version="v")

    def test_illegal_edge_refused(self) -> None:
        s = _store()
        _enable(s, "p1")
        with self.assertRaises(IllegalTransitionError):
            s.transition("p1", PolicyState.CALIBRATING, approval=_appr("gov1", op="z"))

    def test_fabricated_reference_cannot_enable(self) -> None:
        # gap-1: a non-null but FABRICATED calibration_result_ref (no matching persisted PASS) is
        # refused — enablement binds mechanically to a recorded pass, not an opaque string.
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="1"))
        s.enter_calibrating("p1", approval=_appr("gov1", op="2"), set_id="default",
                            pinned_set_version="fx-head", detector_id="det-1", expected_profile_digest="pd",
                            expected_trust_policy_digest="tp", expected_guard_policy_digest="gp",
                            identity_contract_version=1)
        with self.assertRaises(PrivilegedOperationError):
            s.transition("p1", PolicyState.ENABLED, approval=_appr("gov1", op="3"),
                         calibration_result_ref="fabricated", pinned_set_version="fx-head",
                         detector_identity="det-1", identity_contract_version=1)
        # a pass for a DIFFERENT detector does not satisfy it either (identity must match).
        s.record_calibration_pass("real", policy_id="p1", pinned_set_version="fx-head",
                                  detector_identity="det-OTHER", identity_contract_version=1)
        with self.assertRaises(PrivilegedOperationError):
            s.transition("p1", PolicyState.ENABLED, approval=_appr("gov1", op="3b"),
                         calibration_result_ref="real", pinned_set_version="fx-head",
                         detector_identity="det-1", identity_contract_version=1)


class RealDualControlTests(unittest.TestCase):
    def test_weakening_needs_two_distinct_principals(self) -> None:
        s = _store()
        _enable(s, "p1")
        # ENABLED->ADVISORY is weakening -> needs 2 distinct principals. One principal is refused.
        with self.assertRaises(PrivilegedOperationError):
            s.transition("p1", PolicyState.ADVISORY, approval=_appr("gov1", op="w1"))
        # two DISTINCT principals succeed.
        s.transition("p1", PolicyState.ADVISORY, approval=_appr("gov1", "gov2", op="w2"))
        self.assertIs(s.current_state("p1"), PolicyState.ADVISORY)

    def test_dual_not_satisfied_by_repeating_one_principal(self) -> None:
        # the acceptance gate: a caller cannot fake dual control by naming the same principal twice.
        s = _store()
        _enable(s, "p1")
        with self.assertRaises(PrivilegedOperationError):
            s.transition("p1", PolicyState.ADVISORY, approval=_appr("gov1", "gov1", op="w"))

    def test_runtime_with_no_principal_cannot_append(self) -> None:
        # 1b: a RUNTIME caller authenticates no governance principal -> cannot meet even 1.
        s = _store()
        with self.assertRaises(PrivilegedOperationError):
            s.transition("p1", PolicyState.PENDING_CALIBRATION,
                         approval=GovernanceApproval(principals=(), purpose="p", rationale="r", operation_id="o"))

    def test_missing_mandatory_fields_refused(self) -> None:
        s = _store()
        with self.assertRaises(PrivilegedOperationError):  # empty rationale
            s.transition("p1", PolicyState.PENDING_CALIBRATION,
                         approval=GovernanceApproval(principals=("g",), purpose="p", rationale="", operation_id="o"))


class TamperAndAppendOnlyTests(unittest.TestCase):
    def test_edit_detected_and_read_fails_closed(self) -> None:
        s = _store()
        _enable(s, "p1")
        self.assertTrue(s.verify_chain())
        s._conn().execute("UPDATE tier_transition_chain SET new_state=? WHERE seq=1",
                          (PolicyState.ENABLED.value,))
        self.assertFalse(s.verify_chain())
        with self.assertRaises(ChainIntegrityError):
            s.current_state("p1")

    def test_no_delete_or_update_method(self) -> None:
        s = _store()
        self.assertFalse(hasattr(s, "delete"))
        self.assertFalse(hasattr(s, "remove"))
        self.assertFalse(hasattr(s, "update"))

    def test_record_count_grows(self) -> None:
        s = _store()
        _enable(s, "p1")
        self.assertEqual(s.record_count(), 3)  # PENDING + CALIBRATING + ENABLED

    def test_reuses_core_chain_primitive(self) -> None:
        src = (Path(__file__).resolve().parent.parent / "gate" / "policy_store.py").read_text()
        self.assertIn("from core.chain import", src)


if __name__ == "__main__":
    unittest.main()
