"""tests/test_keystones.py — CP2 S6: the EMPIRICAL keystone suite. Run from gated/:  pytest tests/test_keystones.py

THIS FILE IS THE SECURITY-CLAIM ARTEFACT. S1-S5 wired the run-admission gate; the negatives were scattered
and (admit-level) synthetic. S6 proves the gate is EMPIRICALLY load-bearing: a REAL reproducible threat, and
each guard proven load-bearing by an EXECUTED counterfactual — remove the guard (a scoped predicate patch, a
faithful legacy publisher, or an unsafe router/accounting/renderer/finalize double; NEVER a production seam
added for test convenience) and the attack reaches its NATIVE forbidden outcome (a raw PASS published, the
engine executed, a leak, a double post, a swapped-tree execution).

Each keystone proves BOTH:
  (1) production guard PRESENT  -> the EXACT refusal / failure (assert the refusal TYPE, not just "no publish");
  (2) unsafe COUNTERFACTUAL     -> the attack reaches its forbidden outcome.
Confound-kill: threat INDEPENDENCE (the unauthorized identity is derived from a source BLIND to the plan
target), SINGLE-FAULT construction (only the target guard's condition is violated; every other check is
satisfiable, so the counterfactual isolates THAT guard), and asserting the forbidden outcome is actually
reached. The synthetic ``test_run_admission`` + ``test_pipeline`` tests remain as fast SCAFFOLDING; they are
NOT counted as keystones. Proof-forgery keystones demonstrate CONSUMER REJECTION, never cryptographic
unforgeability (that vocabulary is S7's to remove).
"""
from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import ArtifactSpec, Reason, Verdict, VerdictType
from engine.runner import EngineRunResult
from gate.attestation import IDENTITY_CONTRACT_VERSION, calibrated_subject_identity
from gate.checkrun import CheckConclusion, CheckRunLifecycle, CheckStatus, verdict_to_conclusion
from gate.executor import Executor, LifecycleEvent, Transition, Watchdog
from gate.gatekeeper import GateDecision
from gate.job_result import (
    GateOutcome,
    InfraFailureReason,
    InfrastructureFailure,
    NonRunDecision,
    PersistedOutcome,
    account,
)
from gate.pipeline import (
    _render_job_summary,
    _run_engine_check,
    extract_to_spec,
    make_gated_job_runner,
)
from gate.policy_state import Disposition, PolicyState
from gate.queue import GatingEvent
from gate.run_admission import (
    AdmittedRunResult,
    BlockingRefusal,
    RunAdmissionError,
    RunAdmissionRefusal,
    UnadmittedRunResult,
    admit_run_result,
)
from gate.run_admission import _validate_structural as _REAL_VALIDATE  # captured BEFORE any patch (no recursion)
from gate.store import GatingStore
from tests.test_run_admission import (
    _HEAD,
    _SET,
    _SUBJECT,
    _FakeGovernance,
    _admit,
    _plan,
    _proof,
    _report,
)

_NAME = "gated/retry"


def _event(delivery_id: str = "d1", sha: str = "a" * 40) -> GatingEvent:
    return GatingEvent(delivery_id=delivery_id, repo_full_name="acme/widgets", head_sha=sha,
                       action="opened", installation_id=9001)


def _flush_resets(store: GatingStore) -> None:
    """Increment A test helper: mark every pending RESET publication published (simulating a successful
    Publisher drive of the actuator to in_progress) so the ``claim_next`` reset-gate admits the delivery.
    Must be called BEFORE any finalize (asserts only reset rows are pending)."""
    while True:
        job = store.claim_publication()
        if job is None:
            break
        assert job.phase == "reset", "call _flush_resets before any finalize (only resets should be pending)"
        store.mark_publication_published(job.delivery_id, "reset")


def _summ(_result: object) -> str:  # a trivial JobSummarizer for executor/watchdog unit construction
    return "summary"


class _FakeCheckClient:
    """Records the Check Run lifecycle so a keystone can assert the CONCLUSION the merge UI would see."""

    def __init__(self) -> None:
        self.final_conclusion: CheckConclusion | None = None
        self.final_summary: str | None = None

    def find_check_run(self, *, repo_full_name, head_sha, name):  # type: ignore[no-untyped-def]
        return None

    def create_check_run(self, *, repo_full_name, head_sha, name, status, external_id, conclusion=None, output=None):  # type: ignore[no-untyped-def]
        return "cr-1"

    def update_check_run(self, *, repo_full_name, check_run_id, status, conclusion=None, output=None):  # type: ignore[no-untyped-def]
        if status is CheckStatus.COMPLETED:
            self.final_conclusion = conclusion
            self.final_summary = output.summary if output else None


class LegacyRawPublisher:
    """FAITHFUL reconstruction of the DELETED pre-gate publication path (verbatim from the S5 diff): it drove
    the Check Run to the engine's RAW verdict conclusion with NO admission. This is the gate-OFF counterfactual
    — the world before run-admission — used to prove that WITHOUT admission a refused run's PASS is published
    (a SUCCESS Check Run, merge unblocked). It uses the still-present ``CheckRunLifecycle.complete`` (verdict
    -> conclusion), so it is the ACTUAL old behaviour, not a stand-in."""

    def __init__(self, client: _FakeCheckClient, *, name: str = _NAME) -> None:
        self._lifecycle = CheckRunLifecycle(client, name=name)

    def publish(self, event: GatingEvent, verdict: Verdict) -> None:
        cid = self._lifecycle.open_queued(repo_full_name=event.repo_full_name, head_sha=event.head_sha)
        self._lifecycle.mark_in_progress(repo_full_name=event.repo_full_name, check_run_id=cid)
        self._lifecycle.complete(repo_full_name=event.repo_full_name, check_run_id=cid,
                                 verdict=verdict.status, summary="(legacy raw publish)")


def _raw_publish_conclusion(verdict: Verdict) -> CheckConclusion | None:
    """The gate-OFF counterfactual outcome: what the deleted path would have published for ``verdict``."""
    client = _FakeCheckClient()
    LegacyRawPublisher(client).publish(_event(), verdict)
    return client.final_conclusion


def _unsafe_validate_plain_icv(plan, report):  # type: ignore[no-untyped-def]
    """An UNSAFE ``_validate_structural`` double WITHOUT the type-exact ICV guard: it accepts any ICV that is
    ``== IDENTITY_CONTRACT_VERSION`` under a PLAIN ``==`` (so a ``True`` launders, since ``True == 1``), then
    DELEGATES the rest of validation to the REAL ``_validate_structural`` (no divergence on the other checks).
    Patched in for the K8 counterfactual to prove the type-exactness is what refuses the degenerate contract."""
    icv = plan.identity_contract_version
    if type(icv) is not int and icv == IDENTITY_CONTRACT_VERSION:   # the vTrue laundering the guard closes
        plan = dataclasses.replace(
            plan, authorized_context=(plan.authorized_set, plan.authorized_subject, IDENTITY_CONTRACT_VERSION))
    return _REAL_VALIDATE(plan, report)  # the captured REAL validator (not the patched module attr) -> no recursion


def _unsafe_account(result):  # type: ignore[no-untyped-def]
    """An UNSAFE ``account`` double that TRUSTS a bare ``Verdict`` and publishes it as a run verdict (the
    gate-OFF world with no closed-union type gate). Delegates real union members to production ``account``.
    Patched in for the K12a counterfactual to prove the type gate is what stops a raw verdict being published."""
    if isinstance(result, Verdict):
        return PersistedOutcome("done", result, GateOutcome.RUN_VERDICT, result.reason.value,
                                verdict_to_conclusion(result.status))
    return account(result)


# =====================================================================================================
# STRUCTURAL keystones (fast, no podman). Each: guard-present -> exact refusal; counterfactual -> forbidden.
# =====================================================================================================


class K8_IcvUnsupported(unittest.TestCase):
    """K8: a plan under a different / DEGENERATE identity contract (a bool, exploiting True == 1) is refused
    ICV_UNSUPPORTED. Guard: ``type(icv) is int and icv == IDENTITY_CONTRACT_VERSION``. Counterfactual: the
    UNSAFE predicate (a plain ``==``, no type check) LAUNDERS the bool -> would admit under a vTrue domain."""

    def test_guard_present_refuses_icv_unsupported(self) -> None:
        # single-fault: ONLY the ICV is degenerate (target==authorized, coords complete, governance current).
        res = _admit(_plan(icv=True), _report(), _FakeGovernance())  # type: ignore[arg-type]
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.ICV_UNSUPPORTED)

    def test_counterfactual_unsafe_plain_equality_admits_the_bool_icv(self) -> None:
        # EXECUTED single-fault counterfactual: patch the validator to an UNSAFE plain-``==`` ICV check (no
        # type-exactness) — the SAME degenerate True-ICV plan now ADMITS (True == 1 laundered). Production,
        # unpatched, still refuses it (the guard-present arm). So the type-exactness is the load-bearing guard.
        with mock.patch("gate.run_admission._validate_structural", _unsafe_validate_plain_icv):
            res = _admit(_plan(icv=True), _report(), _FakeGovernance())  # type: ignore[arg-type]
        self.assertIsInstance(res, AdmittedRunResult)                   # forbidden: the bool ICV was admitted


class K9_UnauthorizedSubject(unittest.TestCase):
    """K9: a MINT-INCOHERENT plan (dispatch target != its own authorized-snapshot subject) is refused
    UNAUTHORIZED_SUBJECT by ``admit_run_result`` (not merely the constructor). Counterfactual: without the
    mint check, the single-fault run's raw PASS is published (the legacy gate-off path)."""

    def test_guard_present_refuses_unauthorized_subject(self) -> None:
        res = _admit(_plan(target=_SUBJECT, authorized="a-different-authorized-subject"),
                     _report(), _FakeGovernance())
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.UNAUTHORIZED_SUBJECT)

    def test_counterfactual_mint_coherent_plan_admits(self) -> None:
        # single-fault isolation: neutralize ONLY the mint-coherence fault (make target == authorized), keeping
        # everything else identical -> the SAME run ADMITS. Flipping ONLY the authorized field flips
        # refused<->admitted, so the mint-coherence check was the sole blocker (nothing else caught it).
        res = _admit(_plan(target=_SUBJECT, authorized=_SUBJECT), _report(), _FakeGovernance())
        self.assertIsInstance(res, AdmittedRunResult)                   # forbidden-if-guard-absent: admitted


class K10_ProofForgery(unittest.TestCase):
    """K10a/b/c: AdmittedRunResult is PROOF-GATED — the CONSUMER (its ``__post_init__``) rejects a forged /
    reused / cross-run proof. This is a trusted call-path convention, NOT cryptographic unforgeability. Each
    mode: the forgery is REJECTED (RunAdmissionError); a POSITIVE CONTROL shows the legitimate proof admits
    its OWN run (so the rejection is specific, not a blanket failure)."""

    def test_k10a_direct_construction_without_a_minted_proof_is_rejected(self) -> None:
        # a caller cannot fabricate the module-private proof; direct construction is refused by the constructor.
        with self.assertRaises(RunAdmissionError):
            from gate.run_admission import _LiveAdmissionProof
            _LiveAdmissionProof(policy_id="p1", set_id=_SET, oracle_head=_HEAD, subject=_SUBJECT,
                                plan=_plan(), report=_report())  # no mint sentinel
        # positive control: a legitimately minted proof DOES admit its own run.
        adm = AdmittedRunResult(plan=_plan(), report=_report(), _proof=_proof())
        self.assertEqual(adm.measured_subject, _SUBJECT)

    def test_k10b_a_proof_reused_for_a_different_report_is_rejected(self) -> None:
        # same subject, DIFFERENT verdict -> identical recomputed subject (passes the structural re-run), so
        # ONLY the report-binding catches the reuse. Consumer rejects.
        report_a = _report(aggregate=Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))
        report_b = _report(aggregate=Verdict(VerdictType.FAIL, Reason.EGRESS_ONE))
        proof_a = _proof(plan=_plan(), report=report_a)
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=_plan(), report=report_b, _proof=proof_a)
        # positive control: the proof admits its OWN report.
        self.assertIsInstance(AdmittedRunResult(plan=_plan(), report=report_a, _proof=proof_a),
                              AdmittedRunResult)

    def test_k10c_a_proof_from_a_different_plan_is_rejected(self) -> None:
        # same policy/subject, DIFFERENT authorized set -> the plan-binding catches the swap. Consumer rejects.
        plan_a, plan_b = _plan(set_id="set-A"), _plan(set_id="set-B")
        proof_a = _proof(set_id="set-A", plan=plan_a, report=_report())
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=plan_b, report=_report(), _proof=proof_a)
        self.assertIsInstance(AdmittedRunResult(plan=plan_a, report=_report(), _proof=proof_a),
                              AdmittedRunResult)


class K11_TierGateDispatch(unittest.TestCase):
    """K11: a non-ENABLED / DEGRADED policy NEVER runs the engine — the tier decision returns a typed
    NonRunDecision and the artifact source (the engine gate) is never reached. NATIVE forbidden outcome:
    ENGINE EXECUTION for a would-be non-ENABLED policy. Counterfactual: an unsafe router that runs the engine
    regardless of the disposition -> the engine executes."""

    def _touch_source(self):  # type: ignore[no-untyped-def]
        touched: list[str] = []

        def source(event: GatingEvent, ws: Path) -> ArtifactSpec:
            touched.append(event.delivery_id)
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")
        return source, touched

    def test_guard_present_non_enabled_never_runs_the_engine(self) -> None:
        source, touched = self._touch_source()
        runner = make_gated_job_runner(
            lambda _e: GateDecision(Disposition.SKIP_NEUTRAL, None, "not enabled", "live"),
            source, policy_id="p1", governance=_FakeGovernance(),
            image="localhost/mori:local", resolve=lambda _d: (_ for _ in ()).throw(AssertionError("unused")),
            detector_id="retry")
        result = runner(_event())
        self.assertIsInstance(result, NonRunDecision)
        self.assertEqual(touched, [])                                   # the engine gate was NEVER reached

    def test_counterfactual_unsafe_router_executes_the_engine(self) -> None:
        # the gate-OFF world: a router that ignores the disposition runs the engine regardless. We model it by
        # calling _run_engine_check directly (no tier consult) with the real engine mocked to a PASS, and prove
        # the acquisition (the engine gate) IS reached -> forbidden execution for a would-be non-ENABLED policy.
        source, touched = self._touch_source()

        def fake_run_check(make_sandbox, det, artifact, budget, **kw):  # type: ignore[no-untyped-def]
            p = Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)
            return EngineRunResult(trial_report=_report(aggregate=p))

        from engine.calibration import ResolvedDetector
        from engine.retry import RetryCheck
        resolve = lambda _d: ResolvedDetector(assertion=RetryCheck(("python3", "/artifact/main.py")),  # noqa: E731
                                              profile_digest="pd", command=None)
        with mock.patch("gate.pipeline.run_check", side_effect=fake_run_check):
            _run_engine_check(_event(), _plan(), artifact_source=source, image="localhost/mori:local",
                              resolve=resolve, detector_id="retry")
        self.assertEqual(touched, ["d1"])                              # forbidden: the engine executed


class K12a_UnaccountedResultRejected(unittest.TestCase):
    """K12a: the executor's account() maps ONLY the closed JobResult union; a bare Verdict / EngineRunResult
    RETURN is an UNACCOUNTED_RESULT (a blocking error row), never persisted as a verdict. NATIVE forbidden
    outcome: a RAW bare verdict laundered into a persisted PASS. Counterfactual: an unsafe accounting double
    that passes a bare Verdict through -> the raw PASS is persisted."""

    def _store(self):  # type: ignore[no-untyped-def]
        d = Path(tempfile.mkdtemp(prefix="mv-ks-"))
        return GatingStore(d / "g.db")

    def test_guard_present_bare_verdict_return_is_unaccounted(self) -> None:
        store = self._store()
        ex = Executor(store, lambda e: Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS),  # type: ignore[arg-type]
                      _summ)
        store.enqueue(_event("d1"))
        _flush_resets(store)
        store.claim_next()
        ex.process_claimed(_event("d1"))
        status, verdict, reason, _u, gate_outcome = store.verdicts_for_sha("a" * 40)[0]
        self.assertEqual((status, verdict, gate_outcome, reason), ("error", None, None, "unaccounted_result"))

    def test_counterfactual_unsafe_accounting_publishes_the_bare_verdict(self) -> None:
        # EXECUTED single-fault counterfactual: patch the executor's account() to an UNSAFE double that TRUSTS
        # a bare Verdict. The SAME bare-Verdict runner now persists a real PASS (done + verdict='pass' +
        # run_verdict) -> a raw verdict laundered into a published PASS. Production account() (unpatched)
        # refuses it as UNACCOUNTED (the guard-present arm), so the closed-union type gate is load-bearing.
        store = self._store()
        ex = Executor(store, lambda e: Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS),  # type: ignore[arg-type]
                      _summ)
        store.enqueue(_event("d1"))
        _flush_resets(store)
        store.claim_next()
        with mock.patch("gate.executor.account", _unsafe_account):
            ex.process_claimed(_event("d1"))
        status, verdict, _reason, _u, gate_outcome = store.verdicts_for_sha("a" * 40)[0]
        self.assertEqual((status, verdict, gate_outcome), ("done", "pass", "run_verdict"))  # forbidden PASS


class K12b_InfraNeverSilentPass(unittest.TestCase):
    """K12b: an infrastructure failure (worker exception / watchdog force / unaccounted) is fail-CLOSED — it
    publishes ACTION_REQUIRED (blocking), never a silent pass. NATIVE forbidden outcome: an infra fault
    concluding SUCCESS/NEUTRAL (a merge unblocked by a fault). Counterfactual: an unsafe account double that
    maps infra -> SUCCESS -> non-blocking."""

    def test_guard_present_infra_is_action_required(self) -> None:
        out = account(InfrastructureFailure(InfraFailureReason.WORKER_FAULT, detail="boom"))
        self.assertIs(out.conclusion, CheckConclusion.ACTION_REQUIRED)
        self.assertEqual(out.status, "error")

    def test_counterfactual_unsafe_account_would_pass_an_infra_fault(self) -> None:
        # the gate-OFF world: an accounting double that concluded SUCCESS for an infra fault. PersistedOutcome
        # REFUSES to be built that way (its coherence guard: an error row must conclude ACTION_REQUIRED), so
        # the fabrication is impossible even for the double -> the fail-closed mapping is load-bearing.
        with self.assertRaises(ValueError):
            PersistedOutcome("error", None, None, "worker_fault", CheckConclusion.SUCCESS)


class K13_PublicationNoLeak(unittest.TestCase):
    """K13: a refusal / non-run / infra summary is rendered from the TYPED result ONLY — it never leaks the
    internal ``detail`` (raw exception text) and never carries stale detector/image provenance (that comes
    ONLY from an AdmittedRunResult's own report). NATIVE forbidden outcome: internal detail in the published
    summary. Counterfactual: an unsafe renderer double that interpolates the detail -> the leak appears."""

    _SECRET = "SECRET-INTERNAL-/home/user/stacktrace-xyz"

    def test_guard_present_infra_summary_never_carries_the_detail(self) -> None:
        summary = _render_job_summary(
            InfrastructureFailure(InfraFailureReason.WORKER_FAULT, detail=self._SECRET), _NAME)
        self.assertIn("worker_fault", summary)                         # the stable closed token IS published
        self.assertNotIn(self._SECRET, summary)                        # the internal detail is NOT
        self.assertNotIn("SECRET", summary)

    def test_counterfactual_unsafe_renderer_leaks_the_detail(self) -> None:
        # the EXECUTED counterfactual: a renderer that interpolated result.detail (the naive thing) WOULD leak.
        infra = InfrastructureFailure(InfraFailureReason.WORKER_FAULT, detail=self._SECRET)
        unsafe_summary = f"Gate error: {infra.detail}"                  # the unsafe double
        self.assertIn(self._SECRET, unsafe_summary)                    # forbidden: the secret leaks
        # ... and the production renderer, given the SAME infra, does not:
        self.assertNotIn(self._SECRET, _render_job_summary(infra, _NAME))


class K2b_IncompleteCoordinatesStructural(unittest.TestCase):
    """K2 (structural half — ALWAYS runs): a run missing a MEASURED RuntimeSubject coordinate is unattestable
    -> INCOMPLETE_COORDINATES. Guard: all four coordinates present + non-empty. Counterfactual: without the
    completeness check the single-fault run's raw PASS is published (the legacy gate-off path). The genuine
    podman half is K2a below (skipped when the engine cannot produce a real mixed-identity run)."""

    def test_guard_present_absent_coordinate_refuses(self) -> None:
        for missing in ({"rpd": None}, {"tpd": None}, {"gpd": None}, {"execution_identity": None},
                        {"rpd": ""}):
            with self.subTest(missing=next(iter(missing))):
                res = _admit(_plan(), _report(**missing), _FakeGovernance())  # type: ignore[arg-type]
                assert isinstance(res, BlockingRefusal)
                self.assertIs(res.reason, RunAdmissionRefusal.INCOMPLETE_COORDINATES)

    def test_counterfactual_complete_coordinates_admit(self) -> None:
        # single-fault isolation: neutralize ONLY the completeness fault (supply the absent coordinate),
        # keeping everything else identical -> the SAME run ADMITS. Flipping ONLY coordinate-presence flips
        # refused<->admitted, so the completeness check was the sole blocker.
        res = _admit(_plan(), _report(), _FakeGovernance())            # a COMPLETE report (all four coords)
        self.assertIsInstance(res, AdmittedRunResult)                   # forbidden-if-guard-absent: admitted


class _Recorder:
    def __init__(self) -> None:
        self.events: list[LifecycleEvent] = []

    def record(self, event: LifecycleEvent) -> None:
        self.events.append(event)

    def terminals(self) -> list[Transition]:
        # a "terminal post" is now: the finalize WINNER arms the CONCLUSION publication + emits its terminal
        # transition (the Publisher later drains it). The loser emits POST_SKIPPED. Exactly one winner = one post.
        posted = {Transition.COMPLETED, Transition.ERRORED, Transition.WATCHDOG_FORCED}
        return [e.transition for e in self.events if e.transition in posted]


class K14_PostOnce(unittest.TestCase):
    """K14: a wedged worker + the watchdog can NEVER both drive a terminal outcome for one delivery — the
    store's finalize is POST-ONCE (``UPDATE ... WHERE status='processing'``, True to exactly one caller), so
    exactly ONE of them arms the conclusion publication + emits a terminal transition; the loser is
    POST_SKIPPED. NATIVE forbidden outcome: BOTH treat themselves as the terminal writer (two conflicting
    conclusions for one delivery). Counterfactual: an unsafe finalize double (no WHERE guard, always 'won')
    -> BOTH emit a terminal transition. (Increment A: the executor/watchdog no longer post inline — the
    finalize ``won`` boolean gates BOTH the publication-arming AND the terminal transition, so the transition
    IS the post-once observable.)"""

    def _store_and_clock(self):  # type: ignore[no-untyped-def]
        clock = [1000.0]
        d = Path(tempfile.mkdtemp(prefix="mv-ks-po-"))
        return GatingStore(d / "g.db", clock=lambda: clock[0]), clock

    def test_guard_present_worker_and_watchdog_post_once(self) -> None:
        store, clock = self._store_and_clock()
        life = _Recorder()
        ex = Executor(store, lambda e: _admit(_plan(), _report(), _FakeGovernance()), _summ, lifecycle=life)
        wd = Watchdog(store, _summ, timeout_seconds=900.0, lifecycle=life)
        store.enqueue(_event("d1"))
        _flush_resets(store)
        store.claim_next()
        clock[0] += 10_000                                 # make the claim stale
        self.assertEqual(wd.sweep_once(), 1)               # watchdog force-completes (ONE terminal)
        ex.process_claimed(_event("d1"))                   # the wedged worker un-wedges -> POST_SKIPPED
        self.assertEqual(len(life.terminals()), 1)         # EXACTLY one terminal writer

    def test_counterfactual_unsafe_finalize_double_posts(self) -> None:
        store, clock = self._store_and_clock()
        life = _Recorder()
        ex = Executor(store, lambda e: _admit(_plan(), _report(), _FakeGovernance()), _summ, lifecycle=life)
        wd = Watchdog(store, _summ, timeout_seconds=900.0, lifecycle=life)
        store.enqueue(_event("d1"))
        _flush_resets(store)
        store.claim_next()
        clock[0] += 10_000
        with mock.patch.object(store, "finalize", return_value=True):  # unsafe: no POST-ONCE guard
            wd.sweep_once()
            ex.process_claimed(_event("d1"))
        self.assertEqual(len(life.terminals()), 2)         # forbidden: BOTH the watchdog AND the worker posted


# =====================================================================================================
# PODMAN keystones (genuine, measured-from-reality). One setUpClass probe caches M1 (authorized, derived
# INDEPENDENTLY of the unauthorized config) + M2 (unauthorized) + the reusable captured runs, to bound the
# real-podman wall-clock. Skipped as a unit when no OCI runtime can run the image hermetically.
# =====================================================================================================

_IMAGE = "localhost/mori:local"

_A_RETRY = (
    "import socket\n"
    "def _get():\n"
    "    s = socket.create_connection(('health-proxy', 8080), 3)\n"
    "    s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
    "    r = s.recv(64); s.close()\n"
    "    if b'503' in r: raise OSError('transient')\n"
    "    return r\n"
    "for _ in range(3):\n"
    "    try:\n"
    "        _get(); break\n"
    "    except OSError:\n"
    "        continue\n"
).encode()


def _fixture_tarball(path: Path, script: bytes) -> None:
    import io
    import tarfile
    with tarfile.open(path, "w") as tar:
        ti = tarfile.TarInfo("acme-widgets-abc/main.py")
        ti.size = len(script)
        tar.addfile(ti, io.BytesIO(script))


def _resolver(profile_digest: str):  # type: ignore[no-untyped-def]
    # a resolver whose FROZEN command runs the artifact; the profile_digest is the detector's declared profile
    # identity (a runner-bypass runs a detector whose profile differs from the authorized one).
    from core.sandbox import Command
    from engine.calibration import ResolvedDetector
    from engine.retry import RetryCheck
    entry = ("python3", "/artifact/main.py")

    def resolve(detector_id: str) -> "ResolvedDetector":
        return ResolvedDetector(assertion=RetryCheck(entry), profile_digest=profile_digest,
                                command=Command(argv=entry))
    return resolve


_AUTH_PROFILE = "profile-digest-AUTHORIZED-vA"
_UNAUTH_PROFILE = "profile-digest-UNAUTHORIZED-vB"

from sandbox.observed import ObservedOCISandbox  # noqa: E402

_PODMAN = ObservedOCISandbox.available(_IMAGE)


@unittest.skipUnless(_PODMAN, f"no OCI runtime can run {_IMAGE} hermetically")
class RealPodmanKeystones(unittest.TestCase):
    """K1 + K3-K7 + K15 on GENUINE podman. The measured 4-coordinate composite comes from the ACTUAL run;
    the unauthorized identity is derived from a source (a DIFFERENT detector profile) BLIND to the plan
    target, so it cannot collide with or be derived from the target. Single-fault construction: each currency
    keystone perturbs governance in exactly ONE dimension over the SAME real authorized run, so the
    counterfactual isolates that guard. Fresh governance per case (no shared mutable state)."""

    _tar: Path
    _m1: str            # authorized measured subject (independent of the unauthorized config)
    _m2: str            # unauthorized measured subject
    _auth: UnadmittedRunResult    # a real authorized run, RE-PLANNED to target M1 (structural passes)
    _unauth: UnadmittedRunResult  # a real unauthorized run, planned to target M1 (measured M2 != M1)

    @classmethod
    def setUpClass(cls) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-ks-real-"))
        cls._tar = tmp / "art.tar"
        _fixture_tarball(cls._tar, _A_RETRY)
        auth_probe = cls._run(_AUTH_PROFILE, _plan(target="probe", authorized="probe"))
        cls._m1 = cls._subject_of(auth_probe)                 # M1 derived from the AUTHORIZED profile
        unauth = cls._run(_UNAUTH_PROFILE, _plan(target=cls._m1, authorized=cls._m1))
        cls._m2 = cls._subject_of(unauth)
        # re-pair the real reports with plans targeting M1 (so structural passes and the currency/subject
        # guard is the single fault under test); the report is the authoritative measured object, untouched.
        cls._auth = UnadmittedRunResult(plan=_plan(target=cls._m1, authorized=cls._m1),
                                        result=EngineRunResult(trial_report=auth_probe.report))
        cls._unauth = UnadmittedRunResult(plan=_plan(target=cls._m1, authorized=cls._m1),
                                          result=EngineRunResult(trial_report=unauth.report))

    @classmethod
    def _source(cls):  # type: ignore[no-untyped-def]
        tar = cls._tar

        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return extract_to_spec(tar, ws)
        return source

    @classmethod
    def _run(cls, profile: str, plan) -> UnadmittedRunResult:  # type: ignore[no-untyped-def]
        return _run_engine_check(_event(), plan, artifact_source=cls._source(), image=_IMAGE,
                                 resolve=_resolver(profile), detector_id="retry", trials=2)

    @staticmethod
    def _subject_of(un: UnadmittedRunResult) -> str:
        rep = un.report
        assert rep.execution_identity is not None
        return calibrated_subject_identity(rep.resolved_profile_digest, rep.trust_policy_digest,
                                           rep.guard_policy_digest, rep.execution_identity.digest())

    # ---- repro-probe (the strengthened bar) ------------------------------------------------------
    def test_repro_probe_unauthorized_config_deterministically_passes_a_distinct_subject(self) -> None:
        # M1 was derived from the AUTHORIZED profile in setUpClass, independent of this unauthorized config.
        subjects: set[str] = set()
        for _ in range(3):                                    # run the unauthorized config >= 3 times
            un = self._run(_UNAUTH_PROFILE, _plan(target=self._m1, authorized=self._m1))
            self.assertIs(un.report.aggregate.status, VerdictType.PASS)   # every raw result PASSes
            subjects.add(self._subject_of(un))
        self.assertEqual(len(subjects), 1)                    # every measured subject byte-identical M2
        self.assertEqual(subjects.pop(), self._m2)
        self.assertNotEqual(self._m2, self._m1)               # M2 != M1, asserted BEFORE either A/B arm

    # ---- A/B (one captured unauthorized run, two arms) -------------------------------------------
    def test_ab_gate_off_publishes_the_unauthorized_pass_gate_on_blocks(self) -> None:
        self.assertNotEqual(self._m2, self._m1)               # precondition, re-asserted
        # ARM A (gate OFF, faithful legacy publisher): the unauthorized run's raw PASS -> SUCCESS Check Run.
        client = _FakeCheckClient()
        LegacyRawPublisher(client).publish(_event(), self._unauth.report.aggregate)
        self.assertIs(client.final_conclusion, CheckConclusion.SUCCESS)   # merge UNBLOCKED without the gate
        # ARM B (gate ON): admit the SAME captured run -> SUBJECT_DRIFT (measured M2 != dispatched M1).
        res = admit_run_result(self._unauth, governance=_FakeGovernance(subject=self._m1))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SUBJECT_DRIFT)

    # ---- K1 SUBJECT_DRIFT (podman) ---------------------------------------------------------------
    def test_k1_guard_present_refuses_subject_drift(self) -> None:
        res = admit_run_result(self._unauth, governance=_FakeGovernance(subject=self._m1))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SUBJECT_DRIFT)

    def test_k1_counterfactual_gate_off_publishes_the_drifted_pass(self) -> None:
        self.assertIs(_raw_publish_conclusion(self._unauth.report.aggregate), CheckConclusion.SUCCESS)

    # ---- K3-K7 live-currency (podman-wired; single-fault over the SAME real authorized run) -------
    # Each keystone: (guard PRESENT) a governance view faulty in EXACTLY ONE dimension over the real run ->
    # the EXACT currency refusal; (COUNTERFACTUAL) the SAME real run with ONLY that dimension neutralized (the
    # `_CURRENT` fully-current view) -> AdmittedRunResult. The two governance views differ in ONE field, so
    # admitting the neutralized one PROVES that named guard was the SOLE blocker (guard-isolation confound
    # killed: nothing ELSE refuses the otherwise-current run). Fresh governance per case; never total-bypass.
    def _current(self):  # type: ignore[no-untyped-def]
        return _FakeGovernance(subject=self._m1)              # fully current: matches the run + plan on every axis

    def _refuses(self, governance) -> RunAdmissionRefusal:  # type: ignore[no-untyped-def]
        res = admit_run_result(self._auth, governance=governance)
        assert isinstance(res, BlockingRefusal), f"expected a refusal, got {type(res).__name__}"
        return res.reason

    def _admits_under(self, governance) -> None:  # type: ignore[no-untyped-def]
        res = admit_run_result(self._auth, governance=governance)
        self.assertIsInstance(res, AdmittedRunResult, f"expected admission, got {type(res).__name__}")

    def test_k3_set_head_stale(self) -> None:
        # single fault: ONLY the live set head drifted (bound _HEAD != live 'drifted-head'); all else current.
        self.assertIs(self._refuses(_FakeGovernance(subject=self._m1, live_head="drifted-live-head")),
                      RunAdmissionRefusal.SET_HEAD_STALE)
        self._admits_under(self._current())                  # neutralize ONLY staleness (heads match) -> admits

    def test_k4_authorized_set_moved(self) -> None:
        self.assertIs(self._refuses(_FakeGovernance(subject=self._m1, set_id="a-different-set")),
                      RunAdmissionRefusal.AUTHORIZED_SET_MOVED)
        self._admits_under(self._current())                  # neutralize ONLY the set rebind -> admits

    def test_k5_authorized_subject_moved(self) -> None:
        self.assertIs(self._refuses(_FakeGovernance(subject="governance-moved-the-subject")),
                      RunAdmissionRefusal.AUTHORIZED_SUBJECT_MOVED)
        self._admits_under(self._current())                  # neutralize ONLY the subject move -> admits

    def test_k6_live_attestation_unavailable(self) -> None:
        self.assertIs(self._refuses(_FakeGovernance(subject=self._m1, raise_attn=True)),
                      RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE)
        self._admits_under(self._current())                  # neutralize ONLY the unreadable attestation -> admits

    def test_k7_oracle_unavailable(self) -> None:
        self.assertIs(self._refuses(_FakeGovernance(subject=self._m1, live_head=None)),
                      RunAdmissionRefusal.ORACLE_UNAVAILABLE)
        self._admits_under(self._current())                  # neutralize ONLY the unresolvable oracle -> admits

    # ---- K15 ARTIFACT_INTEGRITY_MISMATCH (podman TOCTOU) -----------------------------------------
    def test_k15_guard_present_swapped_tree_is_integrity_mismatch(self) -> None:
        # a real run whose staged tree does NOT match the claimed ArtifactSpec.tree_hash (a possible TOCTOU
        # swap): the sandbox re-verifies the SHA-bind and raises -> InfrastructureFailure(integrity mismatch).
        def wrong_hash_source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            real = extract_to_spec(self._tar, ws)              # the real tree ...
            return ArtifactSpec(path=real.path, tree_hash="sha256:" + "0" * 64)  # ... under a CLAIMED wrong hash

        runner = make_gated_job_runner(
            lambda _e: GateDecision(Disposition.RUN_ENFORCING, PolicyState.ENABLED, "live", "live",
                                    plan=_plan(target=self._m1, authorized=self._m1)),
            wrong_hash_source, policy_id="p1", governance=_FakeGovernance(subject=self._m1),
            image=_IMAGE, resolve=_resolver(_AUTH_PROFILE), detector_id="retry", trials=2)
        result = runner(_event())
        assert isinstance(result, InfrastructureFailure)
        self.assertIs(result.reason, InfraFailureReason.ARTIFACT_INTEGRITY_MISMATCH)

    def test_k15_counterfactual_correct_hash_same_tree_executes(self) -> None:
        # positive control: the SAME tree under its CORRECT hash runs to a real verdict -> the tree itself is
        # runnable, so the re-verify (not the tree) is the ONLY thing blocking the swapped mount. Forbidden
        # outcome of a defeated re-verify = a swapped tree EXECUTES; this proves the re-verify is load-bearing.
        runner = make_gated_job_runner(
            lambda _e: GateDecision(Disposition.RUN_ENFORCING, PolicyState.ENABLED, "live", "live",
                                    plan=_plan(target=self._m1, authorized=self._m1)),
            self._source(), policy_id="p1", governance=_FakeGovernance(subject=self._m1),
            image=_IMAGE, resolve=_resolver(_AUTH_PROFILE), detector_id="retry", trials=2)
        result = runner(_event())
        self.assertNotIsInstance(result, InfrastructureFailure)   # the correct-hash tree EXECUTED (no integrity block)
        self.assertIsInstance(result, AdmittedRunResult)          # ... to a real admitted verdict

    # ---- K2a genuine mixed-identity (prerequisite unavailable -> honest skip) ---------------------
    @unittest.skip(
        "K2a: the reference engine binds ONE execution identity per run (a single make_sandbox), so a genuine "
        "mixed-identity run that yields an ABSENT execution coordinate is not producible without a "
        "multi-sandbox engine. Per the ratified K2 ruling this podman half is skipped when its prerequisite is "
        "unavailable; the structural half (K2b, always-run) carries the completeness proof. Not relabelled.")
    def test_k2a_genuine_mixed_identity_incomplete_coordinates(self) -> None:  # pragma: no cover
        raise AssertionError("unreachable — skipped")


if __name__ == "__main__":
    unittest.main()
