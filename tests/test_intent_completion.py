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
        self.assertEqual(int(row["set_churn_count"]), 1)

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
        # set_churn_count is 0; a bound of 0 means +1 > 0 -> failed_churn, never reactivated.
        self.assertEqual(
            s.reactivate_failed_detector("p1", expect_policy_generation=f["policy_generation"],
                                         expect_target_revision=f["target_revision"],
                                         expect_target_head=f["target_head"], new_target_head="oracle-head-2",
                                         churn_bound=0), "failed_churn")
        self.assertTrue(s.has_failed_churn("p1"))


class ReactivateSatisfiedTests(unittest.TestCase):
    def _satisfied(self, s: PolicyStore):  # type: ignore[no-untyped-def]
        f = _fence(_calibrating(s))
        _satisfy(s, "p1", f, ref="ref-1")
        return f

    def test_distinct_head_rearms_to_pending_clearing_ref_incrementing_set_churn(self) -> None:
        s = _store()
        f = self._satisfied(s)
        self.assertEqual(
            s.reactivate_satisfied("p1", expect_policy_generation=f["policy_generation"],
                                   expect_target_revision=f["target_revision"],
                                   expect_target_head=f["target_head"], new_target_head="oracle-head-2",
                                   churn_bound=32), "reactivated")
        row = s.active_intent("p1")
        assert row is not None
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["target_head"], "oracle-head-2")
        self.assertEqual(int(row["target_revision"]), f["target_revision"] + 1)
        self.assertEqual(int(row["set_churn_count"]), 1)          # counts SET churn once
        self.assertIsNone(row["calibration_result_ref"])          # stale H1 ref cleared

    def test_race_guard_no_op_when_policy_no_longer_calibrating(self) -> None:
        # between the reconciler's read and this CAS a human ratified the pass -> policy ENABLED. Reactivating
        # would arm a pending intent for an ENABLED policy; the in-lock current_state check no-ops instead.
        s = _store()
        f = self._satisfied(s)
        from gate.gatekeeper import ratify_enable  # noqa: PLC0415 — test-local to avoid a cycle
        ratify_enable("p1", store=s, approval=_appr("g1", op="p1-ratify"),
                      calibration_result_ref="ref-1", pinned_set_version=f["target_head"])
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)
        self.assertEqual(
            s.reactivate_satisfied("p1", expect_policy_generation=f["policy_generation"],
                                   expect_target_revision=f["target_revision"],
                                   expect_target_head=f["target_head"], new_target_head="oracle-head-2",
                                   churn_bound=32), "no_op")

    def test_same_head_rejected(self) -> None:
        s = _store()
        f = self._satisfied(s)
        with self.assertRaises(ValueError):
            s.reactivate_satisfied("p1", expect_policy_generation=f["policy_generation"],
                                   expect_target_revision=f["target_revision"],
                                   expect_target_head=f["target_head"], new_target_head=f["target_head"],
                                   churn_bound=32)


class SetChurnBudgetTests(unittest.TestCase):
    def test_replayed_advance_does_not_double_increment(self) -> None:
        # crash replay: an advance under the OLD fence after a newer advance already landed no-ops (the fence
        # moved), so set_churn_count is not double-incremented.
        s = _store()
        f = _fence(_calibrating(s))
        self.assertEqual(
            s.advance_intent("p1", expect_policy_generation=f["policy_generation"],
                             expect_target_revision=f["target_revision"], expect_target_head=f["target_head"],
                             new_target_head="oracle-head-2", churn_bound=32), "advanced")
        self.assertEqual(int(s.active_intent("p1")["set_churn_count"]), 1)  # type: ignore[index]
        # replay of the SAME (now-stale) advance -> no_op, no double count
        self.assertEqual(
            s.advance_intent("p1", expect_policy_generation=f["policy_generation"],
                             expect_target_revision=f["target_revision"], expect_target_head=f["target_head"],
                             new_target_head="oracle-head-2", churn_bound=32), "no_op")
        self.assertEqual(int(s.active_intent("p1")["set_churn_count"]), 1)  # type: ignore[index]


class MigrationTests(unittest.TestCase):
    def test_pre_slice_c_database_migrates_in_place(self) -> None:
        import sqlite3
        d = Path(tempfile.mkdtemp(prefix="mv-mig-")) / "p.db"
        # hand-build a PRE-Slice-C refresh_intent (old churn_count, no calibration_result_ref).
        conn = sqlite3.connect(str(d))
        conn.execute(
            "CREATE TABLE refresh_intent (seq INTEGER PRIMARY KEY AUTOINCREMENT, policy_id TEXT NOT NULL, "
            "set_id TEXT NOT NULL, target_head TEXT NOT NULL, policy_generation TEXT NOT NULL, "
            "target_revision INTEGER NOT NULL DEFAULT 0, detector_id TEXT NOT NULL, "
            "expected_profile_digest TEXT NOT NULL, expected_trust_policy_digest TEXT NOT NULL, "
            "expected_guard_policy_digest TEXT NOT NULL, identity_contract_version INTEGER NOT NULL, "
            "churn_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL, created_at REAL NOT NULL, "
            "updated_at REAL NOT NULL)")
        conn.execute(
            "INSERT INTO refresh_intent (policy_id, set_id, target_head, policy_generation, target_revision, "
            "detector_id, expected_profile_digest, expected_trust_policy_digest, expected_guard_policy_digest, "
            "identity_contract_version, churn_count, status, created_at, updated_at) "
            "VALUES ('p1','s','h','g',0,'d','pd','tp','gp',?,7,'pending',0,0)", (IDENTITY_CONTRACT_VERSION,))
        conn.commit()
        conn.close()
        # opening it via PolicyStore runs the migrations in place.
        s = PolicyStore(d)
        cols = {r["name"] for r in s._conn().execute("PRAGMA table_info(refresh_intent)").fetchall()}
        self.assertIn("set_churn_count", cols)         # renamed
        self.assertNotIn("churn_count", cols)
        self.assertIn("calibration_result_ref", cols)  # added
        row = s._conn().execute("SELECT set_churn_count FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertEqual(int(row["set_churn_count"]), 7)  # value PRESERVED across the rename


class IntentsToReconcileTests(unittest.TestCase):
    def test_scan_includes_active_failed_detector_and_satisfied_excludes_failed_churn(self) -> None:
        s = _store()
        # p1 pending (active) — included
        _calibrating(s, "p1")
        # p2 failed_detector — included (a distinct head can retry it)
        f2 = _fence(_calibrating(s, "p2"))
        s.mark_intent_failed_detector("p2", **f2)
        # p3 satisfied — INCLUDED (board P1: a candidate awaiting ratify is still driftable)
        f3 = _fence(_calibrating(s, "p3"))
        _satisfy(s, "p3", f3, ref="ref-3")
        # p4 failed_churn — EXCLUDED (human clear_failed_churn required)
        f4 = _fence(_calibrating(s, "p4"))
        s.mark_intent_failed_churn("p4", **f4)
        pids = {r["policy_id"] for r in s.intents_to_reconcile()}
        self.assertEqual(pids, {"p1", "p2", "p3"})


if __name__ == "__main__":
    unittest.main()
