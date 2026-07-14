"""tests/test_intent_completion.py — 3.5 S3-completion CP4 Slice C (L1): the atomic intent completion +
distinct-head reactivation + reconcile scan.

``satisfy_intent_with_pass`` is the UNIFIED completion: validate the active intent's full triple, insert the
idempotent pass, store the ref on the intent, and terminalize to ``satisfied`` — ONE transaction, so a
lease-lost/re-leased worker can never orphan a pass. ``reactivate_failed_detector`` is the ONLY way a
``failed_detector`` intent re-activates (a DISTINCT new oracle head — never a same-head redispatch).
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState
from gate.policy_store import IntentSatisfyOutcome, PolicyStore, PrivilegedOperationError

_ROUTING = dict(set_id="setA", pinned_set_version="oracle-head-1", detector_id="retry",
                expected_profile_digest="pd", expected_trust_policy_digest="tp",
                expected_guard_policy_digest="gp", identity_contract_version=IDENTITY_CONTRACT_VERSION)


def _appr(*p: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="p", rationale="r", operation_id=op)


def _store() -> PolicyStore:
    return PolicyStore(Path(tempfile.mkdtemp(prefix="mv-cp4c-")) / "p.db")


def _calibrating(s: PolicyStore, pid: str = "p1", **over: object):  # type: ignore[no-untyped-def]
    s.transition(pid, PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op=f"{pid}-1"))
    s.enter_calibrating(pid, approval=_appr("g1", op=f"{pid}-2"), **{**_ROUTING, **over})  # type: ignore[arg-type]
    return s.active_intent(pid)


def _fence(intent):  # type: ignore[no-untyped-def]
    return dict(policy_generation=intent["policy_generation"],
                target_revision=int(intent["target_revision"]), target_head=intent["target_head"])


def _satisfy(s: PolicyStore, pid: str, fence, *, ref="ref-1", subject="subj-1"):  # type: ignore[no-untyped-def]
    return s.satisfy_intent_with_pass(
        pid, calibration_result_ref=ref, pinned_set_version=fence["target_head"], detector_identity=subject,
        identity_contract_version=IDENTITY_CONTRACT_VERSION, set_id="setA", **fence)


class SatisfyIntentWithPassTests(unittest.TestCase):
    def test_satisfied_records_pass_and_stores_ref_atomically(self) -> None:
        s = _store()
        f = _fence(_calibrating(s))
        self.assertIs(_satisfy(s, "p1", f), IntentSatisfyOutcome.SATISFIED)
        row = s._conn().execute("SELECT status, calibration_result_ref FROM refresh_intent "
                                "WHERE policy_id='p1'").fetchone()
        self.assertEqual(row["status"], "satisfied")
        self.assertEqual(row["calibration_result_ref"], "ref-1")   # ref durably on the intent
        binding = s.pass_binding("ref-1", "p1", f["target_head"])   # the pass exists + binds the subject
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding[0], "subj-1")

    def test_redelivery_same_ref_is_already_satisfied(self) -> None:
        s = _store()
        f = _fence(_calibrating(s))
        _satisfy(s, "p1", f)
        self.assertIs(_satisfy(s, "p1", f), IntentSatisfyOutcome.ALREADY_SATISFIED)  # idempotent crash-redeliver

    def test_advanced_fence_is_stale_no_mutation(self) -> None:
        s = _store()
        intent = _calibrating(s)
        f = _fence(intent)
        # a churn advance bumps the revision; the OLD fence no longer matches an active row -> STALE.
        s.advance_intent("p1", expect_policy_generation=f["policy_generation"],
                         expect_target_revision=f["target_revision"], expect_target_head=f["target_head"],
                         new_target_head="oracle-head-2", churn_bound=8)
        self.assertIs(_satisfy(s, "p1", f), IntentSatisfyOutcome.STALE)
        # nothing recorded under the stale ref
        self.assertIsNone(s.pass_binding("ref-1", "p1", f["target_head"]))

    def test_satisfied_under_a_different_ref_raises_no_mutation(self) -> None:
        s = _store()
        f = _fence(_calibrating(s))
        _satisfy(s, "p1", f, ref="ref-1")
        with self.assertRaises(PrivilegedOperationError):
            _satisfy(s, "p1", f, ref="ref-2")                       # rebinding a satisfied intent refused
        row = s._conn().execute("SELECT calibration_result_ref FROM refresh_intent "
                                "WHERE policy_id='p1'").fetchone()
        self.assertEqual(row["calibration_result_ref"], "ref-1")    # unchanged

    def test_conflicting_pass_metadata_rolls_back_leaving_intent_active(self) -> None:
        s = _store()
        f = _fence(_calibrating(s))
        # a pass already bound to ref-1 for a DIFFERENT detector identity: the bundled record must conflict
        # and the WHOLE satisfy rolls back — the intent stays active, no partial write.
        s.record_calibration_pass("ref-1", policy_id="p1", pinned_set_version=f["target_head"],
                                  detector_identity="OTHER", identity_contract_version=IDENTITY_CONTRACT_VERSION,
                                  set_id="setA")
        with self.assertRaises(PrivilegedOperationError):
            _satisfy(s, "p1", f, ref="ref-1", subject="subj-1")
        row = s._conn().execute("SELECT status, calibration_result_ref FROM refresh_intent "
                                "WHERE policy_id='p1'").fetchone()
        self.assertIn(row["status"], ("pending", "dispatched"))     # rolled back — still active
        self.assertIsNone(row["calibration_result_ref"])


class ReactivateFailedDetectorTests(unittest.TestCase):
    def _to_failed_detector(self, s: PolicyStore):  # type: ignore[no-untyped-def]
        f = _fence(_calibrating(s))
        ok = s.mark_intent_failed_detector("p1", **f)
        self.assertTrue(ok)
        return f

    def test_distinct_head_reactivates_to_pending_incrementing_revision(self) -> None:
        s = _store()
        f = self._to_failed_detector(s)
        self.assertEqual(
            s.reactivate_failed_detector("p1", expect_policy_generation=f["policy_generation"],
                                         expect_target_revision=f["target_revision"],
                                         expect_target_head=f["target_head"], new_target_head="oracle-head-2",
                                         churn_bound=8), "reactivated")
        row = s.active_intent("p1")
        self.assertIsNotNone(row)
        assert row is not None
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["target_head"], "oracle-head-2")
        self.assertEqual(int(row["target_revision"]), f["target_revision"] + 1)
        self.assertEqual(int(row["churn_count"]), 1)

    def test_same_head_reactivation_is_rejected(self) -> None:
        s = _store()
        f = self._to_failed_detector(s)
        with self.assertRaises(ValueError):
            s.reactivate_failed_detector("p1", expect_policy_generation=f["policy_generation"],
                                         expect_target_revision=f["target_revision"],
                                         expect_target_head=f["target_head"],
                                         new_target_head=f["target_head"], churn_bound=8)

    def test_stale_fence_is_no_op(self) -> None:
        s = _store()
        self._to_failed_detector(s)
        self.assertEqual(
            s.reactivate_failed_detector("p1", expect_policy_generation="WRONG", expect_target_revision=0,
                                         expect_target_head="oracle-head-1", new_target_head="oracle-head-2",
                                         churn_bound=8), "no_op")

    def test_churn_bound_exhaustion_fails_churn(self) -> None:
        s = _store()
        f = self._to_failed_detector(s)
        # churn_count is 0; a bound of 0 means +1 > 0 -> failed_churn, never reactivated.
        self.assertEqual(
            s.reactivate_failed_detector("p1", expect_policy_generation=f["policy_generation"],
                                         expect_target_revision=f["target_revision"],
                                         expect_target_head=f["target_head"], new_target_head="oracle-head-2",
                                         churn_bound=0), "failed_churn")
        self.assertTrue(s.has_failed_churn("p1"))


class IntentsToReconcileTests(unittest.TestCase):
    def test_scan_includes_active_and_failed_detector_excludes_terminal_and_failed_churn(self) -> None:
        s = _store()
        # p1 pending (active)
        _calibrating(s, "p1")
        # p2 failed_detector
        f2 = _fence(_calibrating(s, "p2"))
        s.mark_intent_failed_detector("p2", **f2)
        # p3 satisfied (terminal) -> excluded
        f3 = _fence(_calibrating(s, "p3"))
        _satisfy(s, "p3", f3, ref="ref-3")
        # p4 failed_churn -> excluded
        f4 = _fence(_calibrating(s, "p4"))
        s.mark_intent_failed_churn("p4", **f4)
        pids = {r["policy_id"] for r in s.intents_to_reconcile()}
        self.assertEqual(pids, {"p1", "p2"})


if __name__ == "__main__":
    unittest.main()
