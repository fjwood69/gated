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
from gate.policy_store import PolicyStore, PrivilegedOperationError
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


def _scenario(*, profile_override: str | None = None, cal=None, s=None):  # type: ignore[no-untyped-def]
    """A CALIBRATING policy p1 with a routing intent + an enqueued 'intent' job at the current head. ``cal`` /
    ``s`` may be injected wrapper stores (for drift-injection interleaving tests)."""
    cal = _cal_store() if cal is None else cal
    s = PolicyStore(Path(tempfile.mkdtemp(prefix="mv-wk-p-")) / "p.db") if s is None else s
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
              lease_token="T", visibility_timeout=_VIS, clock=lambda: _NOW, trials=3)
    kw.update(over)
    return run_one(**kw)  # type: ignore[arg-type]


class _AdvancingClock:
    """A deterministic clock returning successive values (repeating the last). run_one reads it once at the
    lease and once AFTER measurement, so [lease_t, post_measure_t] controls whether the lease expired."""

    def __init__(self, values: list[float]) -> None:
        self._v = list(values)
        self._i = 0

    def __call__(self) -> float:
        v = self._v[min(self._i, len(self._v) - 1)]
        self._i += 1
        return v


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


class _ErrDet(GoldenScriptedDetector):
    """A detector whose known-bad fixture ERRORs (harness error) while the environment stays attestable — so
    the measurement has ALL FOUR coordinates + a non-null subject, yet is an ERROR. `subject is None` alone
    would misclassify it; classify_measurement must check harness_errors."""


class WorkerClassifierAndClockTests(unittest.TestCase):
    def test_harness_error_with_measurable_subject_retries_not_failed_detector(self) -> None:
        # P1-1: a harness ERROR can carry a non-null subject; the worker must classify ERROR -> RETRY, NOT
        # terminalize failed_detector. (Verified separately: this scenario yields subject!=None, harness_errors
        # non-empty.)
        cal, s, q = _scenario()
        err = _ErrDet([Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING)] * 3 + [_PASS] * 3)
        self.assertIs(_run(cal, s, q, err), WorkerOutcome.RETRY)
        row = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertIn(row["status"], ("pending", "dispatched"))     # NOT failed_detector
        self.assertIs(q.get(next(iter(_job_ids(q)))).status, JobStatus.PROCESSING)  # released, not DONE

    def test_lease_expiry_during_measurement_fails_renewal_zero_mutation(self) -> None:
        # P1-2: the clock advances beyond the visibility timeout DURING measurement (no other worker claimed
        # the job). Renewal reads the FRESH time, sees the lease expired, refuses -> ABORTED, zero mutation.
        cal, s, q = _scenario()
        clock = _AdvancingClock([_NOW, _NOW + _VIS + 1.0])  # lease at _NOW; renew reads _NOW+_VIS+1 (expired)
        before = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()[0]
        self.assertIs(_run(cal, s, q, _pass_det(), clock=clock), WorkerOutcome.ABORTED_LEASE_LOST)
        after = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()[0]
        self.assertEqual(before, after)                              # ZERO PolicyStore mutation
        cnt = s._conn().execute("SELECT COUNT(*) AS n FROM calibration_pass WHERE policy_id='p1'").fetchone()
        self.assertEqual(int(cnt["n"]), 0)                           # no pass recorded


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


class _FailBeforeTerminalize(PolicyStore):
    """Once ARMED, terminalizes the intent's fence ``failed_detector`` the next time
    ``terminalize_intent_failed_detector`` runs, BEFORE delegating — simulating worker B terminalizing this
    EXACT fence while worker A was paused past its lease. A's real terminalize then sees the already-failed
    fence WITHIN its transaction and must return ALREADY_FAILED (the board D3 race, closed structurally)."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.arm = False

    def terminalize_intent_failed_detector(self, policy_id: str, **kw: object):  # type: ignore[no-untyped-def, override]
        if self.arm:
            self.arm = False
            self.mark_intent_failed_detector(policy_id, **kw)  # type: ignore[arg-type]  # worker B, same fence
        return super().terminalize_intent_failed_detector(policy_id, **kw)  # type: ignore[arg-type]


class WorkerFailedTerminalTaxonomyTests(unittest.TestCase):
    """CP3 formal terminal taxonomy: the FAILED terminal is recognised on crash-redelivery (ALREADY_FAILED,
    the mirror of ALREADY_DONE) and under the pause-race, and the taxonomy does not LEAK (a non-worker terminal
    stays STALE). Exact-enum assertions are mandatory (board): a 'no-measure+no-mutation' check alone would
    pass for BOTH STALE and ALREADY_FAILED."""

    def test_already_failed_job_completes_without_remeasuring(self) -> None:
        # crash after failed_detector, before queue.complete: the re-delivered worker sees failed_detector +
        # fence-match at the DOOR -> ALREADY_FAILED, no re-measurement (a PASS detector must NOT satisfy it).
        cal, s, q = _scenario()
        intent = s.active_intent("p1")
        assert intent is not None
        head = cal.set_head("default")
        s.mark_intent_failed_detector("p1", policy_generation=intent["policy_generation"],
                                      target_revision=int(intent["target_revision"]), target_head=head)
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.ALREADY_FAILED)
        row = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertEqual(row["status"], "failed_detector")           # unchanged, not satisfied
        self.assertEqual(int(s._conn().execute(                      # NO pass recorded
            "SELECT COUNT(*) AS n FROM calibration_pass WHERE policy_id='p1'").fetchone()["n"]), 0)
        self.assertIs(q.get(next(iter(_job_ids(q)))).status, JobStatus.DONE)  # obsolete job completed

    def test_pause_race_other_worker_terminalized_same_fence_is_already_failed(self) -> None:
        # THE board D3 proof-by-construction: A measures a clean FAIL, renews, then (paused) worker B
        # terminalizes this EXACT fence; A's atomic terminalize returns ALREADY_FAILED, not a mis-mapped STALE
        # and not a second mutation.
        s0 = _FailBeforeTerminalize(Path(tempfile.mkdtemp(prefix="mv-wk-race-")) / "p.db")
        cal, s, q = _scenario(s=s0)
        s0.arm = True
        self.assertIs(_run(cal, s, q, _miss_det()), WorkerOutcome.ALREADY_FAILED)
        row = s._conn().execute("SELECT status FROM refresh_intent WHERE policy_id='p1'").fetchone()
        self.assertEqual(row["status"], "failed_detector")
        self.assertEqual(int(s._conn().execute(                      # no pass, no double mutation
            "SELECT COUNT(*) AS n FROM calibration_pass WHERE policy_id='p1'").fetchone()["n"]), 0)
        self.assertIs(q.get(next(iter(_job_ids(q)))).status, JobStatus.DONE)

    def test_failed_churn_at_fence_is_stale_not_already_failed(self) -> None:
        # taxonomy DOES NOT LEAK: a failed_churn fence (a NON-worker, human-gated terminal) redelivered is
        # STALE, never ALREADY_FAILED — only worker-produced terminals get ALREADY_* recognition.
        cal, s, q = _scenario()
        intent = s.active_intent("p1")
        assert intent is not None
        head = cal.set_head("default")
        s.mark_intent_failed_churn("p1", policy_generation=intent["policy_generation"],
                                   target_revision=int(intent["target_revision"]), target_head=head)
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.STALE)  # exact enum: STALE, not ALREADY_FAILED
        self.assertIs(q.get(next(iter(_job_ids(q)))).status, JobStatus.DONE)

    def test_already_done_over_missing_pass_raises_corruption(self) -> None:
        # ALREADY_DONE integrity pin: a satisfied fence whose pass row is GONE is corruption — the preflight
        # must RAISE, never complete-as-done over a vanished pass.
        cal, s, q = _scenario()
        intent = s.active_intent("p1")
        assert intent is not None
        head = cal.set_head("default")
        s.satisfy_intent_with_pass("p1", policy_generation=intent["policy_generation"],
                                   target_revision=int(intent["target_revision"]), target_head=head,
                                   calibration_result_ref="ref-1", pinned_set_version=head,
                                   detector_identity="subj", identity_contract_version=IDENTITY_CONTRACT_VERSION,
                                   set_id="default")
        s._conn().execute("DELETE FROM calibration_pass WHERE calibration_result_ref='ref-1'")
        with self.assertRaises(PrivilegedOperationError):
            _run(cal, s, q, _pass_det())


def _job_ids(q: RecalQueue) -> set[str]:
    return {r["job_id"] for r in q._conn().execute("SELECT job_id FROM recal_queue").fetchall()}


def _drift(cal: CalibrationStore, tag: str) -> None:
    cal.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT, approval=_appr("g1", "g2", op=f"drift-{tag}"),
               fixture_id=f"d{tag}", set_id="default", label=FixtureLabel.KNOWN_BAD, payload=b"q")


class _DriftOnSetHead(CalibrationStore):
    """Once ARMED, appends a fixture the next time ``set_head`` is read — injects a set-head DRIFT precisely at
    the worker's LIVE-HEAD recheck (``seal_set`` computes the head directly, not via ``set_head``, so the
    pre-run oracle check still passes; only the post-measure live-head read observes the drift)."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.arm = False

    def set_head(self, set_id: str) -> str:
        if self.arm:
            self.arm = False
            _drift(self, "lh")
        return super().set_head(set_id)


class _AdvanceBeforeSatisfy(PolicyStore):
    """Once ARMED, advances the intent to a new head the next time ``satisfy_intent_with_pass`` runs — injects
    a concurrent relay advance BETWEEN the worker's renew and its completion CAS. The CAS then fences on the
    stale fence and MISSES → STALE, recording no wrong-head pass."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.arm = False

    def satisfy_intent_with_pass(self, policy_id: str, **kw: object):  # type: ignore[no-untyped-def, override]
        if self.arm:
            self.arm = False
            intent = self.active_intent(policy_id)
            if intent is not None:
                self.advance_intent(
                    policy_id, expect_policy_generation=str(intent["policy_generation"]),
                    expect_target_revision=int(intent["target_revision"]),
                    expect_target_head=str(intent["target_head"]),
                    new_target_head="drifted-" + str(intent["target_head"]), churn_bound=32)
        return super().satisfy_intent_with_pass(policy_id, **kw)  # type: ignore[arg-type]


class _AppendBeforeSatisfy(PolicyStore):
    """Once ARMED, appends a fixture to the linked calibration store the next time ``satisfy_intent_with_pass``
    runs — WITHOUT advancing the intent. Injects the IRREDUCIBLE cross-DB window: the set moves to H2 after
    the worker's live-head check but the relay has NOT advanced the intent off H1, so the H1 triple-CAS still
    succeeds (it fences PolicyStore movement, and the intent has not moved). An H1 pass therefore satisfies
    while the live head is already H2 — safe because reconciliation, not the CAS, supersedes it."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.arm = False
        self.cal: CalibrationStore | None = None

    def satisfy_intent_with_pass(self, policy_id: str, **kw: object):  # type: ignore[no-untyped-def, override]
        if self.arm and self.cal is not None:
            self.arm = False
            _drift(self.cal, "win")  # append ONLY — the intent is deliberately NOT advanced
        return super().satisfy_intent_with_pass(policy_id, **kw)  # type: ignore[arg-type]


def _measure_drift_sandbox(cal: CalibrationStore):  # type: ignore[no-untyped-def]
    """A make_sandbox that appends a fixture on its FIRST call — a set drift landing DURING measurement (after
    prepare, while calibrate runs on the frozen sealed set); the post-measure live-head recheck catches it."""
    state = {"done": False}

    def make() -> _H:
        if not state["done"]:
            state["done"] = True
            _drift(cal, "meas")
        return _H()
    return make


class WorkerInvariantHarness(unittest.TestCase):
    """Interleaving harness: a set-head DRIFT is INJECTED at the worker's interposition points — during
    measurement, at the live-head recheck, and (as a concurrent relay advance) between renew and the
    completion CAS — plus the pre-run drift and post-satisfy redelivery. At every step the invariants hold:
    **no double-satisfy** (≤1 satisfied intent), **no orphan/duplicate pass** (≤1 distinct ref PER LOGICAL
    TARGET head — historical H1/H2 passes legitimately coexist), **satisfied ⟺ pass** (every satisfied intent's
    current ref resolves exactly), **no lost-satisfy** (the policy converges once drift stops), and a
    stale/drifted run never mutates. The interior points with no injected dependency (between renew and the
    CAS beyond the advance case; after satisfy before queue-complete) are covered by the CAS-authority and
    ALREADY_DONE / reactivate_satisfied tests rather than claimed here."""

    def _assert_invariants(self, cal, s) -> None:  # type: ignore[no-untyped-def]
        rows = s._conn().execute("SELECT status, calibration_result_ref, target_head FROM refresh_intent "
                                 "WHERE policy_id='p1'").fetchall()
        self.assertLessEqual(sum(1 for r in rows if r["status"] == "satisfied"), 1)  # no double-satisfy
        for r in rows:                                       # satisfied => its CURRENT ref resolves exactly
            if r["status"] == "satisfied":
                self.assertIsNotNone(r["calibration_result_ref"])
                self.assertIsNotNone(s.pass_binding(r["calibration_result_ref"], "p1", r["target_head"]))
        # no DUPLICATE/conflicting pass PER LOGICAL TARGET (policy, head): at most one distinct ref per head.
        for row in s._conn().execute(
                "SELECT pinned_set_version, COUNT(DISTINCT calibration_result_ref) AS n FROM calibration_pass "
                "WHERE policy_id='p1' GROUP BY pinned_set_version").fetchall():
            self.assertLessEqual(int(row["n"]), 1)

    def test_drift_during_measurement_retries_no_mutation(self) -> None:
        cal, s, q = _scenario()
        out = _run(cal, s, q, _pass_det(), make_sandbox=_measure_drift_sandbox(cal))
        self.assertIs(out, WorkerOutcome.RETRY)              # live-head recheck caught the mid-measure drift
        self._assert_invariants(cal, s)
        self.assertIsNot(q.get(next(iter(_job_ids(q)))).status, JobStatus.DONE)  # released, not completed

    def test_drift_at_live_head_recheck_retries_no_mutation(self) -> None:
        cal = _DriftOnSetHead(Path(tempfile.mkdtemp(prefix="mv-wk-dlh-")) / "c.db")
        cal.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT, approval=_appr("g1", "g2", op="b1"),
                   fixture_id="b1", set_id="default", label=FixtureLabel.KNOWN_BAD, payload=b"y")
        cal.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT, approval=_appr("g1", "g2", op="g1"),
                   fixture_id="g1", set_id="default", label=FixtureLabel.KNOWN_GOOD, payload=b"z")
        cal, s, q = _scenario(cal=cal)
        cal.arm = True                                       # drift fires at the worker's live-head set_head
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.RETRY)
        self._assert_invariants(cal, s)

    def test_concurrent_advance_between_renew_and_cas_is_stale_no_pass(self) -> None:
        s = _AdvanceBeforeSatisfy(Path(tempfile.mkdtemp(prefix="mv-wk-adv-")) / "p.db")
        cal, s, q = _scenario(s=s)
        s.arm = True                                         # advance the intent inside satisfy (post-renew)
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.STALE)  # CAS misses -> stale, no wrong pass
        self._assert_invariants(cal, s)
        self.assertEqual(int(s._conn().execute(
            "SELECT COUNT(*) AS n FROM calibration_pass WHERE policy_id='p1'").fetchone()["n"]), 0)

    def test_pre_run_drift_converges_and_holds_invariants(self) -> None:
        cal, s, q = _scenario()
        _drift(cal, "pre")                                   # append lands BEFORE the worker runs
        self.assertIs(_run(cal, s, q, GoldenScriptedDetector([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3)),
                      WorkerOutcome.RETRY)
        self._assert_invariants(cal, s)
        # relay reconciles to the new head; a worker LOOP drains the stale job then SATISFIES the new one.
        relay_intents(policy_store=s, calibration_store=cal, queue=q, now=_NOW + 1)
        outcomes = []
        for i in range(4):
            out = _run(cal, s, q, GoldenScriptedDetector([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3),
                       clock=(lambda v=_NOW + 2 + i: v))
            outcomes.append(out)
            self._assert_invariants(cal, s)
            if out is WorkerOutcome.SATISFIED:
                break
        self.assertIn(WorkerOutcome.SATISFIED, outcomes)     # converged (no lost-satisfy)
        self._assert_invariants(cal, s)

    def test_redelivery_after_satisfy_is_idempotent(self) -> None:
        cal, s, q = _scenario()
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.SATISFIED)
        self._assert_invariants(cal, s)
        relay_intents(policy_store=s, calibration_store=cal, queue=q, now=_NOW + 1)  # satisfied+unchanged: skip
        self._assert_invariants(cal, s)

    def test_append_before_cas_no_relay_satisfies_h1_then_reconciles_to_h2(self) -> None:
        # THE irreducible cross-DB window (board): a fixture appends AFTER the worker's live-head check but
        # BEFORE the intent CAS, and the relay has NOT advanced the intent. The triple-CAS fences PolicyStore
        # movement, and the intent is still H1 -> so an H1 pass SATISFIES while the live head is already H2.
        # This is SAFE not because the CAS blocked it but because RECONCILIATION supersedes it.
        s0 = _AppendBeforeSatisfy(Path(tempfile.mkdtemp(prefix="mv-wk-win-")) / "p.db")
        cal, s, q = _scenario(s=s0)
        s0.cal = cal
        h1 = cal.set_head("default")
        s0.arm = True
        self.assertIs(_run(cal, s, q, _pass_det()), WorkerOutcome.SATISFIED)  # H1 satisfies in the window
        h2 = cal.set_head("default")
        self.assertNotEqual(h1, h2)                                            # the set is now H2
        intent = s._conn().execute("SELECT status, calibration_result_ref FROM refresh_intent "
                                   "WHERE policy_id='p1'").fetchone()
        self.assertEqual(intent["status"], "satisfied")
        h1_ref = intent["calibration_result_ref"]
        self.assertIsNotNone(s.pass_binding(h1_ref, "p1", h1))                 # H1 pass persisted (bound to H1)
        self._assert_invariants(cal, s)
        # RECONCILIATION repairs the drift: satisfied@H1 vs live-head H2 -> reactivate_satisfied re-arms at H2,
        # CLEARS the stale H1 ref, and enqueues an H2 job.
        relay_intents(policy_store=s, calibration_store=cal, queue=q, now=_NOW + 1)
        rearmed = s.active_intent("p1")
        assert rearmed is not None
        self.assertEqual(rearmed["status"], "pending")
        self.assertEqual(rearmed["target_head"], h2)
        self.assertIsNone(rearmed["calibration_result_ref"])                   # stale H1 ref cleared
        # the H2 worker converges (H2 set = b1 + appended dwin + g1 -> catch both bad, pass good).
        outs = []
        for i in range(4):
            o = _run(cal, s, q, GoldenScriptedDetector([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3),
                     clock=(lambda v=_NOW + 2 + i: v))
            outs.append(o)
            self._assert_invariants(cal, s)
            if o is WorkerOutcome.SATISFIED:
                break
        self.assertIn(WorkerOutcome.SATISFIED, outs)                          # converged at H2 (no lost-satisfy)
        current = s._conn().execute("SELECT calibration_result_ref, target_head FROM refresh_intent "
                                    "WHERE policy_id='p1' AND status='satisfied'").fetchone()
        self.assertEqual(current["target_head"], h2)
        self.assertNotEqual(current["calibration_result_ref"], h1_ref)        # current candidate is H2, not H1
        self.assertIsNotNone(s.pass_binding(h1_ref, "p1", h1))                # H1 pass PRESERVED as historical
        self._assert_invariants(cal, s)


if __name__ == "__main__":
    unittest.main()
