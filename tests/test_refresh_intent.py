"""tests/test_refresh_intent.py — 3.5 S3-completion CP4 combined Slice 1+A: the CALIBRATING recovery intent
lifecycle. Run: python3 -m unittest discover -s tests

``enter_calibrating`` is the SOLE path into CALIBRATING; it atomically (one BEGIN IMMEDIATE) appends the
tier transition AND creates the pending re-calibration recovery intent, so a CALIBRATING policy — invisible
to the ENABLED-only relay — is never silently stranded. Properties pinned:
  * the intent carries model-(b) ROUTING (detector registry name + expected profile/trust/guard digests),
    NOT a measured subject; ``policy_generation`` is DERIVED from the appended record_hash; the tier row is
    byte-identical (routing on the intent, the tier row's measured-subject column stays NULL until ENABLED);
  * SPLIT GENERATIONS: an advance is an in-place CAS on (policy_generation, target_revision, target_head) —
    a stale/delayed advance no-ops (no double-increment, no stale overwrite); completion fences on the same
    triple; churn increments only on a distinct advance;
  * a transition OUT of CALIBRATING atomically supersedes the active intent IN THE SAME transaction;
  * ``ActiveCalibrationIntentExists`` refuses a second active intent; ``failed_detector`` is non-blocking,
    ``failed_churn`` blocks new autos until human recovery clears it;
  * crash boundary (i): an intent-insert failure rolls BOTH the tier row and the intent back.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState
from gate.policy_store import (
    ActiveCalibrationIntentExists,
    FailedChurnNotCleared,
    IllegalTransitionError,
    PolicyStore,
    PrivilegedOperationError,
)

_ROUTING = dict(set_id="setA", pinned_set_version="oracle-head-1", detector_id="retry",
                expected_profile_digest="pd", expected_trust_policy_digest="tp",
                expected_guard_policy_digest="gp", identity_contract_version=IDENTITY_CONTRACT_VERSION)


def _appr(*principals: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose="p", rationale="r", operation_id=op)


def _store() -> PolicyStore:
    return PolicyStore(Path(tempfile.mkdtemp(prefix="mv-cp4-")) / "p.db")


def _pending(s: PolicyStore, pid: str = "p1") -> None:
    s.transition(pid, PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op=f"{pid}-1"))


def _enter(s: PolicyStore, pid: str = "p1", op: str = "p1-2", **over: object) -> int:
    return s.enter_calibrating(pid, approval=_appr("g1", op=op), **{**_ROUTING, **over})  # type: ignore[arg-type]


def _rows(s: PolicyStore, pid: str = "p1"):  # type: ignore[no-untyped-def]
    return s._conn().execute("SELECT * FROM refresh_intent WHERE policy_id=? ORDER BY seq", (pid,)).fetchall()


class EnterCalibratingTests(unittest.TestCase):
    def test_atomically_creates_calibrating_and_a_pending_routing_intent(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        self.assertIs(s.current_state("p1"), PolicyState.CALIBRATING)
        rows = _rows(s)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["set_id"], "setA")
        self.assertEqual(row["target_head"], "oracle-head-1")
        self.assertEqual(row["target_revision"], 0)
        self.assertEqual(row["detector_id"], "retry")
        self.assertEqual(row["expected_profile_digest"], "pd")
        self.assertEqual(row["expected_trust_policy_digest"], "tp")
        self.assertEqual(row["expected_guard_policy_digest"], "gp")
        self.assertEqual(row["churn_count"], 0)
        # no measured subject on the intent — routing only.
        self.assertNotIn("detector_identity", row.keys())

    def test_policy_generation_is_the_derived_policy_head(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        self.assertEqual(_rows(s)[0]["policy_generation"], s.policy_head("p1"))

    def test_tier_row_is_byte_identical_routing_not_on_the_chain(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        trow = s._conn().execute(
            "SELECT * FROM tier_transition_chain WHERE policy_id='p1' AND new_state='calibrating'"
        ).fetchone()
        self.assertEqual(trow["pinned_set_version"], "oracle-head-1")
        self.assertIsNone(trow["set_id"])
        self.assertIsNone(trow["detector_identity"])
        self.assertIsNone(trow["identity_contract_version"])
        self.assertTrue(s.verify_chain())

    def test_degenerate_routing_inputs_refused(self) -> None:
        for bad in ({"set_id": ""}, {"pinned_set_version": ""}, {"detector_id": ""},
                    {"expected_profile_digest": ""}, {"expected_trust_policy_digest": ""},
                    {"expected_guard_policy_digest": ""}):
            with self.subTest(bad=next(iter(bad))):
                s = _store()
                _pending(s)
                with self.assertRaises(PrivilegedOperationError):
                    _enter(s, **bad)

    def test_degenerate_icv_refused(self) -> None:
        for bad_icv in (True, False, "1", IDENTITY_CONTRACT_VERSION + 1, 0):
            with self.subTest(icv=repr(bad_icv)):
                s = _store()
                _pending(s)
                with self.assertRaises(PrivilegedOperationError):
                    _enter(s, identity_contract_version=bad_icv)

    def test_illegal_entry_writes_nothing(self) -> None:
        s = _store()
        with self.assertRaises(IllegalTransitionError):
            _enter(s)  # PROPOSED -> CALIBRATING is illegal
        self.assertEqual(_rows(s), [])
        self.assertIsNone(s.current_state("p1"))

    def test_bare_calibrating_transition_is_refused(self) -> None:
        # the sole-path guard: a bare transition into CALIBRATING is refused (use enter_calibrating).
        s = _store()
        _pending(s)
        with self.assertRaises(IllegalTransitionError):
            s.transition("p1", PolicyState.CALIBRATING, approval=_appr("g1", op="x"),
                         pinned_set_version="v")

    def test_dangling_active_intent_refused_explicitly(self) -> None:
        # a policy legal to enter (PENDING_CALIBRATION) that already has a DANGLING active intent is refused
        # with an explicit ActiveCalibrationIntentExists, not a raw DB-unique violation. Inject the dangling
        # intent directly (the normal atomic path never leaves one, but a crash/future path could).
        s = _store()
        _pending(s)
        s._conn().execute(
            "INSERT INTO refresh_intent (policy_id, set_id, target_head, policy_generation, target_revision,"
            " detector_id, expected_profile_digest, expected_trust_policy_digest, expected_guard_policy_digest,"
            " identity_contract_version, churn_count, status, created_at, updated_at) "
            "VALUES ('p1','setA','h','gen',0,'d','pd','tp','gp',1,0,'pending',0,0)")
        with self.assertRaises(ActiveCalibrationIntentExists):
            _enter(s)

    def test_atomic_rollback_on_intent_insert_failure(self) -> None:
        # crash boundary (i): an aborting trigger makes the intent INSERT fail AFTER the tier row is
        # inserted, inside the BEGIN IMMEDIATE — proving BOTH roll back (no half-written CALIBRATING).
        s = _store()
        _pending(s)
        s._conn().execute("CREATE TEMP TRIGGER _boom BEFORE INSERT ON refresh_intent "
                          "BEGIN SELECT RAISE(ABORT, 'boom'); END")
        try:
            with self.assertRaises(Exception):
                _enter(s)
        finally:
            s._conn().execute("DROP TRIGGER _boom")
        self.assertEqual(_rows(s), [])
        n = s._conn().execute(
            "SELECT COUNT(*) AS n FROM tier_transition_chain WHERE policy_id='p1' AND new_state='calibrating'"
        ).fetchone()["n"]
        self.assertEqual(n, 0)
        self.assertIs(s.current_state("p1"), PolicyState.PENDING_CALIBRATION)


class SupersedeTests(unittest.TestCase):
    def test_transition_out_of_calibrating_atomically_supersedes(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        # CALIBRATING -> REJECTED exits CALIBRATING; the active intent is superseded in the SAME transaction.
        s.transition("p1", PolicyState.REJECTED, approval=_appr("g1", op="rej"))
        self.assertIs(s.current_state("p1"), PolicyState.REJECTED)
        self.assertEqual(_rows(s)[0]["status"], "superseded")
        self.assertIsNone(s.active_intent("p1"))

    def test_full_recovery_reentry(self) -> None:
        # the human recovery path: CALIBRATING -> REJECTED (atomic supersede) -> PENDING_CALIBRATION -> a
        # fresh enter_calibrating succeeds (the prior intent is terminal, so no active intent blocks it).
        s = _store()
        _pending(s)
        _enter(s)
        s.transition("p1", PolicyState.REJECTED, approval=_appr("g1", op="rej"))
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="re-pend"))
        _enter(s, op="p1-again")
        self.assertIs(s.current_state("p1"), PolicyState.CALIBRATING)
        self.assertEqual(s.active_intent("p1")["status"], "pending")


class CompletionCasTests(unittest.TestCase):
    def test_satisfied_under_matching_triple(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        i = s.active_intent("p1")
        ok = s.mark_intent_satisfied("p1", policy_generation=i["policy_generation"],
                                     target_revision=i["target_revision"], target_head=i["target_head"])
        self.assertTrue(ok)
        self.assertEqual(_rows(s)[0]["status"], "satisfied")

    def test_stale_completion_no_ops(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        i = s.active_intent("p1")
        # a completion under a STALE revision (the intent was advanced meanwhile) matches 0 rows.
        ok = s.mark_intent_satisfied("p1", policy_generation=i["policy_generation"],
                                     target_revision=i["target_revision"] + 1, target_head=i["target_head"])
        self.assertFalse(ok)
        self.assertEqual(_rows(s)[0]["status"], "pending")  # untouched


class ChurnAdvanceTests(unittest.TestCase):
    def _adv(self, s: PolicyStore, rev: int, head: str, new: str, bound: int = 100) -> str:
        gen = s.active_intent("p1")["policy_generation"]
        return s.advance_intent("p1", expect_policy_generation=gen, expect_target_revision=rev,
                                expect_target_head=head, new_target_head=new, churn_bound=bound)

    def test_distinct_successive_heads_each_increment(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        self.assertEqual(self._adv(s, 0, "oracle-head-1", "H2"), "advanced")
        r1 = s.active_intent("p1")
        self.assertEqual((r1["target_head"], r1["target_revision"], r1["churn_count"]), ("H2", 1, 1))
        # a genuinely-distinct successive head increments again.
        self.assertEqual(self._adv(s, 1, "H2", "H3"), "advanced")
        r2 = s.active_intent("p1")
        self.assertEqual((r2["target_head"], r2["target_revision"], r2["churn_count"]), ("H3", 2, 2))

    def test_stale_delayed_advance_no_ops(self) -> None:
        # the split-generation fence: a lagging advance (still expecting revision 0 / the old head) after the
        # row already reached revision 2 matches 0 rows -> "no_op" (no double-increment, no stale overwrite).
        s = _store()
        _pending(s)
        _enter(s)
        self._adv(s, 0, "oracle-head-1", "H2")
        self._adv(s, 1, "H2", "H3")
        self.assertEqual(self._adv(s, 0, "oracle-head-1", "H2-again"), "no_op")
        r = s.active_intent("p1")
        self.assertEqual((r["target_head"], r["target_revision"], r["churn_count"]), ("H3", 2, 2))

    def test_same_head_advance_rejected(self) -> None:
        # a same-head advance does not churn — rejected (the coalescing invariant: only DISTINCT heads churn).
        s = _store()
        _pending(s)
        _enter(s)
        with self.assertRaises(ValueError):
            self._adv(s, 0, "oracle-head-1", "oracle-head-1")

    def test_churn_bound_exceeded_transitions_failed_churn(self) -> None:
        # with a bound of 1, the SECOND distinct advance would push churn to 2 > 1 -> atomically failed_churn.
        s = _store()
        _pending(s)
        _enter(s)
        self.assertEqual(self._adv(s, 0, "oracle-head-1", "H2", bound=1), "advanced")  # churn 0 -> 1
        self.assertEqual(self._adv(s, 1, "H2", "H3", bound=1), "failed_churn")           # 1+1 > 1
        self.assertEqual(_rows(s)[0]["status"], "failed_churn")
        self.assertTrue(s.has_failed_churn("p1"))


class FailedStateTests(unittest.TestCase):
    def _fence(self, s: PolicyStore) -> dict[str, object]:
        i = s.active_intent("p1")
        return dict(policy_generation=i["policy_generation"], target_revision=i["target_revision"],
                    target_head=i["target_head"])

    def test_failure_primitives_are_triple_cas_fenced(self) -> None:
        # a stale worker (wrong revision) cannot terminalize a newer target.
        s = _store()
        _pending(s)
        _enter(s)
        f = self._fence(s)
        stale = dict(f, target_revision=int(f["target_revision"]) + 1)  # type: ignore[call-overload]
        self.assertFalse(s.mark_intent_failed_detector("p1", **stale))  # type: ignore[arg-type]
        self.assertFalse(s.mark_intent_failed_churn("p1", **stale))  # type: ignore[arg-type]
        self.assertEqual(_rows(s)[0]["status"], "pending")  # untouched by the stale terminalisation

    def test_failed_detector_is_non_blocking(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        self.assertTrue(s.mark_intent_failed_detector("p1", **self._fence(s)))  # type: ignore[arg-type]
        self.assertEqual(_rows(s)[0]["status"], "failed_detector")
        self.assertIsNone(s.active_intent("p1"))
        self.assertFalse(s.has_failed_churn("p1"))  # failed_detector does NOT block new autos

    def test_failed_churn_blocks_enter_until_governance_clear(self) -> None:
        s = _store()
        _pending(s)
        _enter(s)
        self.assertTrue(s.mark_intent_failed_churn("p1", **self._fence(s)))  # type: ignore[arg-type]
        self.assertTrue(s.has_failed_churn("p1"))
        # recovery states: exit CALIBRATING then back to PENDING — but the failed_churn block persists.
        s.transition("p1", PolicyState.REJECTED, approval=_appr("g1", op="rej"))
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="re-pend"))
        with self.assertRaises(FailedChurnNotCleared):
            _enter(s, op="p1-blocked")
        # clearing is GOVERNANCE-gated (requires an approval) — a bare call is refused.
        with self.assertRaises(PrivilegedOperationError):
            s.clear_failed_churn("p1", approval=GovernanceApproval((), purpose="", rationale="",
                                                                   operation_id=""))
        self.assertEqual(s.clear_failed_churn("p1", approval=_appr("g1", op="clear")), 1)
        self.assertFalse(s.has_failed_churn("p1"))
        # now re-entry succeeds.
        _enter(s, op="p1-recovered")
        self.assertEqual(s.active_intent("p1")["status"], "pending")


if __name__ == "__main__":
    unittest.main()
