"""Increment 2.4 + CP2 S5 — engine integration, tier-decision + run-admission, verdict->Check Run.

Run from the gated/ root:  python3 -m unittest discover -s tests

CP2 S5 (the coupled widening): the job runner is now ``make_gated_job_runner`` — the FULL
tier-decision -> engine -> run-admission path returning a TYPED ``JobResult``. This module proves:
  * ROUTING: a non-enforcing disposition returns a ``NonRunDecision`` and NEVER touches the engine; an
    enforce runs the engine under the minted plan and ADMITS the result;
  * the DISPATCH-TIME invariant recheck (a mis-routed plan raises, fail-closed);
  * PUBLICATION (make_check_updater from the typed result): detector/image ONLY from an AdmittedRunResult,
    a refusal/non-run/infra NEVER leaks internal detail (C4 pin), and a bare Verdict is runtime-rejected;
  * the GENUINE-BITE (real podman): the measured 4-coordinate composite comes from the ACTUAL run, so a
    plan dispatched to a WRONG subject is refused SUBJECT_DRIFT (the run measured reality, not the target).

BEHAVIOUR DELTA vs the pre-S5 live path:
  | aspect              | before (vestigial)                | after (S5)                                  |
  | tier gate           | NONE — engine ran on EVERY delivery | resolve_disposition INSIDE the job runner |
  | non-enforce         | (unreachable / static_poster)      | typed NonRunDecision, engine untouched      |
  | run admission       | none — verdict published raw       | admit_run_result gates publication          |
  | runner return       | bare Verdict                       | typed JobResult (union)                      |
  | infra fault         | ERROR_VERDICT                      | InfrastructureFailure (WORKER_FAULT/...)     |
  | summary provenance  | mutable report_capture (stale risk)| AdmittedRunResult's own report only         |
"""
from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    Reason,
    Verdict,
    VerdictType,
    tree_hash,
)

from engine.runner import EngineRunResult
from gate.checkrun import CheckConclusion, CheckStatus
from gate.gatekeeper import GateDecision, GateDecisionError
from gate.job_result import (
    InfraFailureReason,
    InfrastructureFailure,
    JobResult,
    NonRunDecision,
)
from gate.pipeline import (
    _render_job_summary,
    _run_engine_check,
    assert_budget_fits_watchdog,
    assert_detector_registered,
    default_detector_registry,
    extract_to_spec,
    make_check_updater,
    make_gated_job_runner,
)
from gate.policy_state import Disposition, PolicyState
from gate.run_admission import (
    AdmittedRunResult,
    BlockingRefusal,
    RunAdmissionRefusal,
    UnadmittedRunResult,
    admit_run_result,
)
from gate.queue import GatingEvent
from gate.summary import render_check_summary
from tests.test_run_admission import _FakeGovernance, _plan, _report

_NAME = "gated/retry"
_IMAGE = "localhost/mori:local"
_REGISTRY = default_detector_registry()   # 3.5-close #1.3: the accepted "retry" detector, registered
_RESOLVE = _REGISTRY.resolve
_RESOLVE_BUNDLE = _REGISTRY.resolve_bundle
_DETECTOR_ID = "retry"
_POLICY = "p1"


def _event(delivery_id: str = "d1", sha: str = "a" * 40) -> GatingEvent:
    return GatingEvent(
        delivery_id=delivery_id, repo_full_name="acme/widgets", head_sha=sha,
        action="opened", installation_id=9001,
    )


def _enforce(plan) -> GateDecision:  # type: ignore[no-untyped-def]
    return GateDecision(Disposition.RUN_ENFORCING, PolicyState.ENABLED, "live ENABLED", "live", plan=plan)


def _nonrun(disposition: Disposition, reason: str = "not enabled") -> GateDecision:
    return GateDecision(disposition, None, reason, "live")


class SummaryTests(unittest.TestCase):
    def test_pass_summary_readable(self) -> None:
        out = render_check_summary(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS), _NAME)
        self.assertIn("PASSED", out.title)
        self.assertIn("all trials passed", out.summary)

    def test_error_summary_says_blocked_and_human(self) -> None:
        out = render_check_summary(Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING), _NAME)
        self.assertIn("ERRORED", out.title)
        self.assertIn("human must review", out.summary)
        self.assertIn("blocked", out.summary)


class _FakeCheckClient:
    """Records the check-run lifecycle calls incl. the final conclusion + summary."""

    def __init__(self) -> None:
        self.statuses: list[CheckStatus] = []
        self.final_conclusion: CheckConclusion | None = None
        self.final_summary: str | None = None

    def find_check_run(self, *, repo_full_name, head_sha, name):  # type: ignore[no-untyped-def]
        return None

    def create_check_run(self, *, repo_full_name, head_sha, name, status, external_id, conclusion=None, output=None):  # type: ignore[no-untyped-def]
        self.statuses.append(status)
        return "cr-1"

    def update_check_run(self, *, repo_full_name, check_run_id, status, conclusion=None, output=None):  # type: ignore[no-untyped-def]
        self.statuses.append(status)
        if status is CheckStatus.COMPLETED:
            self.final_conclusion = conclusion
            self.final_summary = output.summary if output else None


def _admitted_pass() -> AdmittedRunResult:
    """A genuine AdmittedRunResult carrying a PASS verdict + a report with an execution identity (so the
    updater can render detector/image), minted through admit_run_result (proof-gated)."""
    res = admit_run_result(
        UnadmittedRunResult(plan=_plan(), result=EngineRunResult(trial_report=_report())),
        governance=_FakeGovernance())
    assert isinstance(res, AdmittedRunResult)
    return res


class TypedPublicationTests(unittest.TestCase):
    """make_check_updater drives the Check Run from the TYPED JobResult; C4: detector/image ONLY from an
    AdmittedRunResult; a refusal/non-run/infra NEVER leaks internal detail; a bare Verdict is rejected."""

    def _publish(self, result: JobResult) -> _FakeCheckClient:
        client = _FakeCheckClient()
        make_check_updater(client, name=_NAME)(_event(), result)
        return client

    def test_admitted_run_publishes_success_with_provenance(self) -> None:
        c = self._publish(_admitted_pass())
        self.assertIs(c.final_conclusion, CheckConclusion.SUCCESS)
        self.assertIn("detector=retry", c.final_summary or "")
        self.assertIn("image=sha256:abc", c.final_summary or "")
        self.assertEqual(c.statuses, [CheckStatus.QUEUED, CheckStatus.IN_PROGRESS, CheckStatus.COMPLETED])

    def test_blocking_refusal_publishes_action_required_no_provenance(self) -> None:
        c = self._publish(BlockingRefusal(RunAdmissionRefusal.SET_HEAD_STALE, "the set drifted"))
        self.assertIs(c.final_conclusion, CheckConclusion.ACTION_REQUIRED)   # fail-closed block
        self.assertIn("admission: set_head_stale", c.final_summary or "")     # the controlled token
        self.assertNotIn("detector=", c.final_summary or "")                  # no stale provenance
        self.assertNotIn("the set drifted", c.final_summary or "")            # the detail is not published

    def test_non_run_neutral_publishes_neutral(self) -> None:
        c = self._publish(NonRunDecision(Disposition.SKIP_NEUTRAL, "policy not enabled"))
        self.assertIs(c.final_conclusion, CheckConclusion.NEUTRAL)
        self.assertIn("Policy not enforced", c.final_summary or "")

    def test_non_run_block_publishes_action_required(self) -> None:
        c = self._publish(NonRunDecision(Disposition.BLOCK_ACTION_REQUIRED, "degraded"))
        self.assertIs(c.final_conclusion, CheckConclusion.ACTION_REQUIRED)

    def test_infra_failure_publishes_action_required_and_never_leaks_detail(self) -> None:
        # the publication-no-leak pin: the internal detail (raw exception text) must NEVER reach the summary;
        # only the stable, closed reason token is published.
        secret = "SECRET-INTERNAL-STACKTRACE-/home/user/x"
        c = self._publish(InfrastructureFailure(InfraFailureReason.WORKER_FAULT, detail=secret))
        self.assertIs(c.final_conclusion, CheckConclusion.ACTION_REQUIRED)
        self.assertIn("worker_fault", c.final_summary or "")   # the closed token IS published
        self.assertNotIn(secret, c.final_summary or "")        # the detail is NOT
        self.assertNotIn("SECRET", c.final_summary or "")

    def test_render_rejects_a_bare_verdict(self) -> None:
        with self.assertRaises(TypeError):
            _render_job_summary(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS), _NAME)  # type: ignore[arg-type]


class GatedRoutingTests(unittest.TestCase):
    """make_gated_job_runner routing WITHOUT the engine: a non-enforce disposition returns a typed
    NonRunDecision and never touches the artifact source / engine; a mis-routed plan fails closed."""

    def _runner(self, decision: GateDecision, *, governance=None, policy_id: str = _POLICY):  # type: ignore[no-untyped-def]
        touched: list[str] = []

        def source(event: GatingEvent, ws: Path) -> ArtifactSpec:
            touched.append(event.delivery_id)  # a non-run must NEVER reach here
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        runner = make_gated_job_runner(
            lambda _e: decision, source, policy_id=policy_id,
            governance=governance if governance is not None else _FakeGovernance(),
            image=_IMAGE, resolve=_RESOLVE_BUNDLE, detector_id=_DETECTOR_ID)
        return runner, touched

    def test_skip_neutral_returns_non_run_and_never_runs_the_engine(self) -> None:
        runner, touched = self._runner(_nonrun(Disposition.SKIP_NEUTRAL))
        result = runner(_event())
        self.assertIsInstance(result, NonRunDecision)
        assert isinstance(result, NonRunDecision)
        self.assertIs(result.disposition, Disposition.SKIP_NEUTRAL)
        self.assertEqual(touched, [])  # the artifact source (engine gate) was NEVER reached

    def test_block_action_required_returns_blocking_non_run_no_engine(self) -> None:
        runner, touched = self._runner(_nonrun(Disposition.BLOCK_ACTION_REQUIRED, "degraded"))
        result = runner(_event())
        self.assertIsInstance(result, NonRunDecision)
        assert isinstance(result, NonRunDecision)
        self.assertIs(result.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(touched, [])

    def test_dispatch_invariant_rejects_a_mis_routed_plan(self) -> None:
        # a coherent RUN_ENFORCING decision whose plan authorizes a DIFFERENT policy than this deployment —
        # the dispatch-time recheck refuses to run it (fail-closed), the executor maps the raise to WORKER_FAULT.
        wrong = _enforce(_plan())  # _plan().policy_id == "p1"
        runner, touched = self._runner(wrong, policy_id="a-different-policy")
        with self.assertRaises(GateDecisionError):
            runner(_event())
        self.assertEqual(touched, [])  # never reached the engine

    def test_detector_unresolved_is_infrastructure_failure(self) -> None:
        # the enforced detector is registered under a DRIFTED content-address -> resolve refuses inside
        # _run_engine_check -> make_gated_job_runner maps it to a blocking InfrastructureFailure, never a pass.
        from gate.detector_registry import DetectorRegistry
        from engine.retry import RetryCheck
        drifted = DetectorRegistry()
        drifted.register("retry", lambda: RetryCheck(("python3", "/artifact/main.py")),
                         accepted_profile_digest="accepted-addr-that-will-not-match")

        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        runner = make_gated_job_runner(
            lambda _e: _enforce(_plan()), source, policy_id=_POLICY, governance=_FakeGovernance(),
            image=_IMAGE, resolve=drifted.resolve_bundle, detector_id="retry")
        result = runner(_event())
        self.assertIsInstance(result, InfrastructureFailure)
        assert isinstance(result, InfrastructureFailure)
        self.assertIs(result.reason, InfraFailureReason.DETECTOR_UNRESOLVED)

    def test_artifact_hash_mismatch_is_integrity_infrastructure_failure(self) -> None:
        # _run_engine_check raising ArtifactHashMismatchError (a possible TOCTOU) -> a DISTINCT blocking
        # InfrastructureFailure(ARTIFACT_INTEGRITY_MISMATCH), never a silent pass.
        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:whatever")

        runner = make_gated_job_runner(
            lambda _e: _enforce(_plan()), source, policy_id=_POLICY, governance=_FakeGovernance(),
            image=_IMAGE, resolve=_RESOLVE_BUNDLE, detector_id=_DETECTOR_ID)
        with mock.patch("gate.pipeline._run_engine_check", side_effect=ArtifactHashMismatchError("swap")):
            result = runner(_event())
        self.assertIsInstance(result, InfrastructureFailure)
        assert isinstance(result, InfrastructureFailure)
        self.assertIs(result.reason, InfraFailureReason.ARTIFACT_INTEGRITY_MISMATCH)

    def test_artifact_fetch_failure_is_infrastructure_failure(self) -> None:
        # dissent P2 (ARTIFACT_FETCH_FAILED wired): a SafeExtractError (malformed / path-traversing /
        # oversized tarball rejected by safe_extract_tarball) during acquisition -> a typed blocking
        # InfrastructureFailure(ARTIFACT_FETCH_FAILED), never a pass.
        from gate.artifact import SafeExtractError

        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        runner = make_gated_job_runner(
            lambda _e: _enforce(_plan()), source, policy_id=_POLICY, governance=_FakeGovernance(),
            image=_IMAGE, resolve=_RESOLVE_BUNDLE, detector_id=_DETECTOR_ID)
        with mock.patch("gate.pipeline._run_engine_check", side_effect=SafeExtractError("path traversal")):
            result = runner(_event())
        self.assertIsInstance(result, InfrastructureFailure)
        assert isinstance(result, InfrastructureFailure)
        self.assertIs(result.reason, InfraFailureReason.ARTIFACT_FETCH_FAILED)

    def test_acquisition_fetch_error_is_artifact_fetch_failed(self) -> None:
        # Increment B / F3: an ArtifactFetchError (a live fetch/network/token-exchange failure, normalised
        # at the artifact-source boundary) -> InfrastructureFailure(ARTIFACT_FETCH_FAILED), never a
        # misclassified WORKER_FAULT.
        from gate.artifact import ArtifactFetchError

        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        runner = make_gated_job_runner(
            lambda _e: _enforce(_plan()), source, policy_id=_POLICY, governance=_FakeGovernance(),
            image=_IMAGE, resolve=_RESOLVE_BUNDLE, detector_id=_DETECTOR_ID)
        with mock.patch("gate.pipeline._run_engine_check", side_effect=ArtifactFetchError("404")):
            result = runner(_event())
        self.assertIsInstance(result, InfrastructureFailure)
        assert isinstance(result, InfrastructureFailure)
        self.assertIs(result.reason, InfraFailureReason.ARTIFACT_FETCH_FAILED)

    def test_non_acquisition_oserror_is_not_relabelled_fetch_failure(self) -> None:
        # F3 no-over-catch (mirror of F4): a bare OSError from EXTRACTION or an unrelated fs op is NOT
        # caught by the acquisition/extract handlers -> it PROPAGATES (the executor maps it to
        # WORKER_FAULT), never relabelled ARTIFACT_FETCH_FAILED. The fetch normalisation cannot reach
        # past acquisition.
        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        runner = make_gated_job_runner(
            lambda _e: _enforce(_plan()), source, policy_id=_POLICY, governance=_FakeGovernance(),
            image=_IMAGE, resolve=_RESOLVE_BUNDLE, detector_id=_DETECTOR_ID)
        with mock.patch("gate.pipeline._run_engine_check",
                        side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(OSError):
                runner(_event())

    def test_resolve_decision_oserror_propagates_to_worker_fault(self) -> None:
        # F4 end-to-end confinement: a store outage surfacing as a bare OSError from resolve_decision (the
        # pre-run tier read, OUTSIDE the runner's try) is NOT laundered -> it propagates so the executor
        # classifies it WORKER_FAULT (a disk/permission fault is a worker fault, not unattestability).
        def _raising_decision(_e: GatingEvent) -> GateDecision:
            raise OSError(13, "Permission denied")

        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        runner = make_gated_job_runner(
            _raising_decision, source, policy_id=_POLICY, governance=_FakeGovernance(),
            image=_IMAGE, resolve=_RESOLVE_BUNDLE, detector_id=_DETECTOR_ID)
        with self.assertRaises(OSError):
            runner(_event())

    def test_dispatch_invariant_rejects_a_non_run_decision_carrying_a_plan(self) -> None:
        # dissent P1: the OTHER direction of the biconditional. A (forged) non-RUN decision that CARRIES a
        # plan must be refused, NOT silently returned as a NonRunDecision. GateDecision.__post_init__ forbids
        # constructing this, so we forge a decision-shaped object to prove the runner's OWN fail-closed
        # recheck catches RUN_ENFORCING != (plan is not None) before branching.
        from types import SimpleNamespace
        forged = SimpleNamespace(disposition=Disposition.SKIP_NEUTRAL, plan=_plan(), reason="forged")
        runner, touched = self._runner(forged)  # type: ignore[arg-type]
        with self.assertRaises(GateDecisionError):
            runner(_event())
        self.assertEqual(touched, [])  # never reached the engine


class Increment_B_F3_AcquisitionBoundaryTests(unittest.TestCase):
    """Increment B / F3 (boundary): the LIVE artifact_source's acquisition helper ``_acquire_head_tarball``
    normalises a GitHub-adapter ``CheckRunError`` (token exchange / fetch / HTTP / 404 / oversized) and an
    ``OSError`` on the local tar WRITE into a typed ``ArtifactFetchError``. POSITIONAL: only acquisition is
    guarded — the caller's separate ``extract_to_spec`` keeps its own ``SafeExtractError`` path."""

    def _event_ws(self) -> "tuple[GatingEvent, Path]":
        import tempfile
        return _event(), Path(tempfile.mkdtemp(prefix="mv-acq-"))

    def test_token_exchange_checkrunerror_normalised(self) -> None:
        from gate.artifact import ArtifactFetchError
        from gate.checkrun import CheckRunError
        from gate.live_app import _acquire_head_tarball

        class _P:
            def get_valid_token(self, _iid: int) -> str:
                raise CheckRunError("token exchange gave no token")

        ev, ws = self._event_ws()
        with self.assertRaises(ArtifactFetchError):
            _acquire_head_tarball(_P(), ev, ws, fork_fetch=False)  # type: ignore[arg-type]

    def test_download_checkrunerror_normalised(self) -> None:
        from gate.artifact import ArtifactFetchError
        from gate.checkrun import CheckRunError
        from gate.live_app import _acquire_head_tarball

        class _P:
            def get_valid_token(self, _iid: int) -> str:
                return "tok"

        ev, ws = self._event_ws()
        with mock.patch("gate.live_app.download_tarball", side_effect=CheckRunError("404 not found")):
            with self.assertRaises(ArtifactFetchError):
                _acquire_head_tarball(_P(), ev, ws, fork_fetch=False)  # type: ignore[arg-type]

    def test_download_oserror_write_normalised(self) -> None:
        from gate.artifact import ArtifactFetchError
        from gate.live_app import _acquire_head_tarball

        class _P:
            def get_valid_token(self, _iid: int) -> str:
                return "tok"

        ev, ws = self._event_ws()
        with mock.patch("gate.live_app.download_tarball",
                        side_effect=OSError(28, "No space left on device")):
            with self.assertRaises(ArtifactFetchError):
                _acquire_head_tarball(_P(), ev, ws, fork_fetch=False)  # type: ignore[arg-type]


class RunEngineCheckPlumbingTests(unittest.TestCase):
    """_run_engine_check pairs the AUTHORITATIVE EngineRunResult with the REQUIRED plan into an
    UnadmittedRunResult, and supplies run_check the frozen command + the full 4-coordinate provenance."""

    def test_pairs_the_plan_and_supplies_frozen_command_and_provenance(self) -> None:
        from core.sandbox import Command
        from engine.calibration import ResolvedDetector
        from engine.retry import RetryCheck
        from engine.runner import TrialReport

        frozen = Command(argv=("frozen-live-cmd", "/artifact/main.py"))
        detector = RetryCheck(("entrypoint-value-must-not-run", "/artifact/main.py"))
        self.assertNotEqual(detector.entrypoint(), frozen)

        def resolver(detector_id: str) -> ResolvedDetector:
            return ResolvedDetector(assertion=detector, profile_digest="pd-frozen", command=frozen)

        captured: dict[str, object] = {}

        def fake_run_check(make_sandbox, det, artifact, budget, **kw):  # type: ignore[no-untyped-def]
            captured.update(kw)
            p = Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)
            return EngineRunResult(trial_report=TrialReport(
                trials=(p,), trials_configured=1, short_circuited=False, aggregate=p))

        def source(_e: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:x")

        plan = _plan()
        with mock.patch("gate.pipeline.run_check", side_effect=fake_run_check):
            un = _run_engine_check(_event(), plan, artifact_source=source, image=_IMAGE,
                                   resolve=resolver, detector_id="retry")
        self.assertIsInstance(un, UnadmittedRunResult)
        self.assertIs(un.plan, plan)                                   # the REQUIRED plan is paired in
        self.assertEqual(captured.get("command"), frozen)             # the FROZEN command reached run_check
        self.assertNotEqual(captured.get("command"), detector.entrypoint())
        self.assertEqual(captured.get("resolved_profile_digest"), "pd-frozen")
        trust = captured.get("trust_policy")
        self.assertTrue(getattr(trust, "policy_digest", None))         # a measured trust OBJECT, not a string
        guard = captured.get("backend_guard")
        self.assertTrue(getattr(guard, "policy_digest", None))         # a measured guard OBJECT
        self.assertNotIn("guard_policy_digest", captured)              # no caller-string guard digest


class BudgetOrderingTests(unittest.TestCase):
    def test_accepts_aggregate_within_watchdog(self) -> None:
        assert_budget_fits_watchdog(trials=3, per_trial_wall_clock=120.0, watchdog_timeout=900.0)

    def test_rejects_aggregate_exceeding_watchdog(self) -> None:
        with self.assertRaises(ValueError):
            assert_budget_fits_watchdog(trials=8, per_trial_wall_clock=120.0, watchdog_timeout=900.0)


class DetectorRegistryEnforcementTests(unittest.TestCase):
    def test_boot_assertion_passes_for_registered_detector(self) -> None:
        assert_detector_registered(_RESOLVE, _DETECTOR_ID)

    def test_boot_assertion_fails_for_unregistered_detector(self) -> None:
        from gate.preflight import ConfigurationError
        with self.assertRaises(ConfigurationError):
            assert_detector_registered(_RESOLVE, "not-the-accepted-detector")

    def test_boot_fails_against_a_mismatched_accepted_profile_digest(self) -> None:
        from gate.preflight import ConfigurationError
        registry = default_detector_registry(
            detector_id="retry", accepted_profile_digest="not-the-accepted-profile-digest")
        with self.assertRaises(ConfigurationError):
            assert_detector_registered(registry.resolve, "retry")

    def test_production_boot_requires_external_accepted_profile_digest(self) -> None:
        import importlib
        from gate.preflight import ConfigurationError
        with mock.patch.dict("os.environ", {"GATED_ACCEPTED_PROFILE_DIGEST": ""}, clear=False):
            live_app = importlib.reload(importlib.import_module("gate.live_app"))
            with self.assertRaises(ConfigurationError):
                live_app.required_accepted_profile_digest()
        with mock.patch.dict("os.environ", {"GATED_ACCEPTED_PROFILE_DIGEST": "profile-digest-xyz"}, clear=False):
            live_app = importlib.reload(importlib.import_module("gate.live_app"))
            self.assertEqual(live_app.required_accepted_profile_digest(), "profile-digest-xyz")
        importlib.reload(importlib.import_module("gate.live_app"))

    def test_production_boot_requires_policy_id(self) -> None:
        # CP2 S5 D1: GATED_POLICY_ID unset -> fail boot CLOSED; a real value passes.
        import importlib
        from gate.preflight import ConfigurationError
        with mock.patch.dict("os.environ", {"GATED_POLICY_ID": ""}, clear=False):
            live_app = importlib.reload(importlib.import_module("gate.live_app"))
            with self.assertRaises(ConfigurationError):
                live_app.required_policy_id()
        with mock.patch.dict("os.environ", {"GATED_POLICY_ID": "policy-42"}, clear=False):
            live_app = importlib.reload(importlib.import_module("gate.live_app"))
            self.assertEqual(live_app.required_policy_id(), "policy-42")
        importlib.reload(importlib.import_module("gate.live_app"))

    def test_require_distinct_db_paths_rejects_a_collision(self) -> None:
        # dissent P2: the queue / policy / calibration DB paths must be DISTINCT; a collision fails boot.
        import importlib
        from gate.preflight import ConfigurationError
        live_app = importlib.import_module("gate.live_app")
        q, p, c = Path("/tmp/mv-q.db"), Path("/tmp/mv-p.db"), Path("/tmp/mv-c.db")
        with self.assertRaises(ConfigurationError):
            live_app.require_distinct_db_paths(q, q, c)   # queue == policy
        with self.assertRaises(ConfigurationError):
            live_app.require_distinct_db_paths(q, p, p)   # policy == calibration
        live_app.require_distinct_db_paths(q, p, c)       # all distinct: does not raise

    def test_boot_refuses_when_engine_budget_races_the_watchdog(self) -> None:
        # S7 (dissent): assert_budget_fits_watchdog is now WIRED into build() — the enforced startup
        # invariant. A per-trial budget x trials x margin that would race the watchdog fails boot CLOSED
        # (previously only tests called it, so the "App MUST call this at startup" claim was a real gap).
        import importlib
        env = {"GATED_ACCEPTED_PROFILE_DIGEST": "pd-xyz", "GATED_POLICY_ID": "p1", "GATED_TRIALS": "8"}
        with mock.patch.dict("os.environ", env, clear=False):
            live_app = importlib.reload(importlib.import_module("gate.live_app"))
            with self.assertRaises(ValueError):   # 8 x 120 x 1.2 = 1152 >= 900s watchdog -> boot refused
                live_app.build(Path(tempfile.mkdtemp(prefix="mv-boot-")) / "g.db")
        importlib.reload(importlib.import_module("gate.live_app"))  # restore module-level defaults


def _fixture_tarball(path: Path, script: bytes) -> None:
    with tarfile.open(path, "w") as tar:
        ti = tarfile.TarInfo("acme-widgets-abc/main.py")
        ti.size = len(script)
        tar.addfile(ti, io.BytesIO(script))


class ExtractToSpecTests(unittest.TestCase):
    def test_extract_to_spec_hashes_shared_canon(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-e2s-"))
        tar = tmp / "a.tar"
        _fixture_tarball(tar, b"print('hi')\n")
        with tempfile.TemporaryDirectory() as ws:
            spec = extract_to_spec(tar, Path(ws))
            self.assertIsInstance(spec, ArtifactSpec)
            self.assertEqual(spec.tree_hash, tree_hash(spec.path))



if __name__ == "__main__":
    unittest.main()
