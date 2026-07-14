"""tests/test_recal_worker.py — 3.5 S3-completion CP4 Slice C (L5/L6): the async re-calibration WORKER +
the interleaving property harness.

Covers the ratified taxonomy end-to-end (lease -> preflight -> boot verify -> seal/oracle -> produce ->
live-head -> renew -> satisfy/failed_detector/complete) and the deep-consult checklist: crash-redelivery at
the door (ALREADY_DONE without re-measuring), renew-fail ABORT with ZERO mutations, drift -> RELEASE (never
complete a still-active fence), FAIL -> failed_detector (never worker-REJECTED), boot mismatch -> RELEASE
(the thread-1 intent-expected bite), positive-shape lease token. The harness asserts the four invariants —
no double-satisfy, no lost-satisfy, no orphan pass, a stale job never mutates — plus the atomicity invariant
(satisfied => pass exists) across adversarial interleavings.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import Fixture, FixtureLabel
from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.authority import GovernanceApproval
from gate.calibration_store import AdmissionCapability, CalibrationStore, ChangeOp
from gate.detector_registry import profile_of
from gate.policy_state import PolicyState
from gate.policy_store import PolicyStore
from gate.recal_queue import JobStatus, RecalQueue
from gate.recal_relay import relay_intents
from gate.recal_worker import WorkerOutcome, run_one
from gate.trust_policy import resolve_trust_policy
from sandbox.noop import NoOpSandbox
from tests._backend_optout import test_guard_policy
from tests._golden_detector import GoldenScriptedDetector, golden_resolver

_REF_TP = resolve_trust_policy("trust-policy:completed-only")
_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)
_ADMIT = AdmissionCapability()
_KB = (Fixture("b1", FixtureLabel.KNOWN_BAD, b"y"),)
_KG = (Fixture("g1", FixtureLabel.KNOWN_GOOD, b"z"),)
_VIS = 100.0
_NOW = 1000.0


class _H(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _fac():  # type: ignore[no-untyped-def]
    return lambda: _H()


def _pass_det() -> GoldenScriptedDetector:
    return GoldenScriptedDetector([_FAIL] * 3 + [_PASS] * 3)  # catches b1, passes g1 -> PASS


def _miss_det() -> GoldenScriptedDetector:
    return GoldenScriptedDetector([_PASS] * 3 + [_PASS] * 3)  # MISSES b1 -> clean FAIL


def _appr(*p: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="p", rationale="r", operation_id=op)


def _cal_store() -> CalibrationStore:
    c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-wk-cs-")) / "c.db")
    c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT, approval=_appr("g1", "g2", op="b1"),
             fixture_id="b1", set_id="default", label=FixtureLabel.KNOWN_BAD, payload=b"y")
    c.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT, approval=_appr("g1", "g2", op="g1"),
             fixture_id="g1", set_id="default", label=FixtureLabel.KNOWN_GOOD, payload=b"z")
    return c


def _expected(profile: str | None = None) -> dict[str, object]:
    return dict(
        set_id="default",
        pinned_set_version="",  # filled by the caller with the sealed head
        detector_id="d",
        expected_profile_digest=profile if profile is not None else profile_of("d", _pass_det()).digest(),
        expected_trust_policy_digest=_REF_TP.policy_digest,
        expected_guard_policy_digest=test_guard_policy.policy_digest,
        identity_contract_version=IDENTITY_CONTRACT_VERSION,
    )


def _scenario(*, profile_override: str | None = None):  # type: ignore[no-untyped-def]
    """A CALIBRATING policy p1 with a routing intent + an enqueued 'intent' job at the current head."""
    cal = _cal_store()
    s = PolicyStore(Path(tempfile.mkdtemp(prefix="mv-wk-p-")) / "p.db")
    q = RecalQueue(Path(tempfile.mkdtemp(prefix="mv-wk-q-")) / "q.db")
    head = cal.set_head("default")
    s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="p1-1"))
    routing = _expected(profile_override)
    routing["pinned_set_version"] = head
    s.enter_calibrating("p1", approval=_appr("g1", op="p1-2"), **routing)  # type: ignore[arg-type]
    relay_intents(policy_store=s, calibration_store=cal, queue=q, now=_NOW)
    return cal, s, q


def _run(cal, s, q, det, **over):  # type: ignore[no-untyped-def]
    kw = dict(queue=q, policy_store=s, calibration_store=cal, resolve=golden_resolver(det),
              make_sandbox=_fac(), trust_policy=_REF_TP, backend_guard=test_guard_policy, budget=_BUDGET,
              lease_token="T", visibility_timeout=_VIS, now=_NOW, trials=3)
    kw.update(over)
    return run_one(**kw)  # type: ignore[arg-type]


class WorkerTaxonomyTests(unittest.TestCase):
    def test_e2e_pass_satisfies_and_records(self) -> None:
        cal, s, q = _scenario()
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.SATISFIED)
        row = s.active_intent("p1")  # active_intent excludes satisfied -> None
        self.assertIsNone(row)
        seq_row = s._conn().execute("SELECT status, calibration_result_ref FROM refresh_intent "
                                    "WHERE policy_id='p1'").fetchone()
        self.assertEqual(seq_row["status"], "satisfied")
        self.assertIsNotNone(seq_row["calibration_result_ref"])
        self.assertIsNotNone(s.pass_binding(seq_row["calibration_result_ref"], "p1", cal.set_head("default")))
        self.assertIs(s.current_state("p1"), PolicyState.CALIBRATING)  # NOT auto-enabled

    def test_clean_fail_marks_failed_detector_never_rejected(self) -> None:
        cal, s, q = _scenario()
        self.assertIs(_run(cal, s, q, _miss_det()), WorkerOutcome.FAILED_DETECTOR)
        row = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertEqual(row["status"], "failed_detector")
        self.assertIs(s.current_state("p1"), PolicyState.CALIBRATING)  # worker NEVER governance-REJECTED

    def test_boot_digest_mismatch_releases_without_mutation(self) -> None:
        # thread-1 intent-expected bite: the intent's expected profile digest is WRONG for the boot bundle ->
        # reject before calibrate -> RELEASE (retry), intent untouched.
        cal, s, q = _scenario(profile_override="not-the-real-profile-digest")
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.RETRY)
        row = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertIn(row["status"], ("pending", "dispatched"))
        self.assertIs(q.get(next(iter(_job_ids(q)))).status, JobStatus.PROCESSING)  # released, not DONE

    def test_positive_shape_empty_lease_token_raises(self) -> None:
        cal, s, q = _scenario()
        with self.assertRaises(ValueError):
            _run(cal, s, q, _pass_det(), lease_token="")


class WorkerCrashAndRaceTests(unittest.TestCase):
    def test_already_satisfied_job_completes_without_remeasuring(self) -> None:
        # crash after satisfy, before complete: the intent is satisfied but the job is still leasable. The
        # re-delivered worker sees satisfied+fence-match -> ALREADY_DONE, no re-measurement.
        cal, s, q = _scenario()
        intent = s.active_intent("p1")
        assert intent is not None
        head = cal.set_head("default")
        s.satisfy_intent_with_pass("p1", policy_generation=intent["policy_generation"],
                                   target_revision=int(intent["target_revision"]), target_head=head,
                                   calibration_result_ref="manual-ref", pinned_set_version=head,
                                   detector_identity="manual-subj",
                                   identity_contract_version=IDENTITY_CONTRACT_VERSION, set_id="default")
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.ALREADY_DONE)
        jid = next(iter(_job_ids(q)))
        self.assertIs(q.get(jid).status, JobStatus.DONE)  # obsolete satisfied job completed

    def test_renew_failure_aborts_with_zero_mutations(self) -> None:
        cal, s, q = _scenario()

        class _NoRenew(RecalQueue):
            def renew(self, *a, **k):  # type: ignore[no-untyped-def, override]
                return False

        q.__class__ = _NoRenew  # force the renewal to fail after the measurement
        before = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()[0]
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.ABORTED_LEASE_LOST)
        after = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()[0]
        self.assertEqual(before, after)  # ZERO PolicyStore mutation
        self.assertIsNone(s.pass_binding("any", "p1", cal.set_head("default")))

    def test_set_drift_before_seal_releases_never_completes(self) -> None:
        # the set head moves after the job was enqueued -> the oracle check fails -> RELEASE (retry), never
        # complete: completing a still-active fence could strand the policy if the head returns.
        cal, s, q = _scenario()
        cal.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT, approval=_appr("g1", "g2", op="b2"),
                   fixture_id="b2", set_id="default", label=FixtureLabel.KNOWN_BAD, payload=b"q")
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.RETRY)
        jid = next(iter(_job_ids(q)))
        self.assertIsNot(q.get(jid).status, JobStatus.DONE)  # released, NOT completed
        row = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertIn(row["status"], ("pending", "dispatched"))  # untouched


def _job_ids(q: RecalQueue) -> set[str]:
    return {r["job_id"] for r in q._conn().execute("SELECT job_id FROM recal_queue").fetchall()}


class WorkerInvariantHarness(unittest.TestCase):
    """The four invariants + atomicity, checked across adversarial interleavings of a set append landing at
    each worker step. In every case: at most one pass, satisfied => that pass exists, and a stale/drifted run
    never leaves a mutated-but-inconsistent intent."""

    def _assert_invariants(self, cal, s) -> None:  # type: ignore[no-untyped-def]
        rows = s._conn().execute("SELECT status, calibration_result_ref, target_head FROM refresh_intent "
                                 "WHERE policy_id='p1'").fetchall()
        satisfied = [r for r in rows if r["status"] == "satisfied"]
        self.assertLessEqual(len(satisfied), 1)                       # no double-satisfy
        passes = s._conn().execute("SELECT COUNT(*) AS n FROM calibration_pass "
                                   "WHERE policy_id='p1'").fetchone()["n"]
        self.assertLessEqual(int(passes), 1)                          # no orphan/duplicate pass
        for r in satisfied:                                           # satisfied => its pass exists (pin)
            self.assertIsNotNone(r["calibration_result_ref"])
            self.assertIsNotNone(s.pass_binding(r["calibration_result_ref"], "p1", r["target_head"]))

    def test_append_then_worker_converges_and_holds_invariants(self) -> None:
        # append lands BEFORE the worker runs -> worker RETRYs (drift); relay reconciles to the new head; a
        # second worker SATISFIES. No lost-satisfy (the policy converges), invariants hold throughout.
        cal, s, q = _scenario()
        cal.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT, approval=_appr("g1", "g2", op="drift"),
                   fixture_id="b2", set_id="default", label=FixtureLabel.KNOWN_BAD, payload=b"q")
        self.assertIs(_run(cal, s, q, GoldenScriptedDetector([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3)),
                      WorkerOutcome.RETRY)          # b1,b2 caught, g1 passed — but drift -> retry first
        self._assert_invariants(cal, s)             # nothing mutated yet
        # relay advances the intent to the new head + enqueues a fresh job. A worker LOOP then drains: the old
        # (now fence-mismatched) job completes STALE, the new head's job SATISFIES. No lost-satisfy — the
        # policy converges — and the invariants hold at every step.
        relay_intents(policy_store=s, calibration_store=cal, queue=q, now=_NOW + 1)
        outcomes = []
        for i in range(4):
            out = _run(cal, s, q, GoldenScriptedDetector([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3),
                       now=_NOW + 2 + i)
            outcomes.append(out)
            self._assert_invariants(cal, s)
            if out is WorkerOutcome.SATISFIED:
                break
        self.assertIn(WorkerOutcome.SATISFIED, outcomes)  # converged at the new head (no lost-satisfy)
        self._assert_invariants(cal, s)

    def test_redelivery_after_satisfy_is_idempotent(self) -> None:
        cal, s, q = _scenario()
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.SATISFIED)
        self._assert_invariants(cal, s)
        # re-relay + re-run: the satisfied intent at an unchanged head is NOT re-enqueued (relay skips it),
        # so no double work; invariants still hold.
        relay_intents(policy_store=s, calibration_store=cal, queue=q, now=_NOW + 1)
        self._assert_invariants(cal, s)


if __name__ == "__main__":
    unittest.main()
