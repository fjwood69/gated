"""gate/pipeline.py — engine integration (2.4): wire the real engine to the executor.

The job-runner back-half: ``GatingEvent -> ArtifactSpec -> real hermetic engine ->
Verdict``, and the updater: ``Verdict -> Check Run (queued->in_progress->completed)``
with an out-of-band summary. This is where Step-1's engine (``ObservedOCISandbox`` +
``RetryCheck`` + multi-trial ``run_check``) and Step-2's gate finally meet.

Fail-closed all the way:
  * the sandbox RE-VERIFIES ``ArtifactSpec.tree_hash`` in ``prepare()`` and raises
    ``ArtifactHashMismatchError`` (TOCTOU) — the job-runner does NOT catch it, so the
    executor maps it to ERROR (a corrupted/altered tarball is an INFRA fault -> block +
    escalate, never a silent pass);
  * ``ERROR -> action_required`` (blocks) via ``verdict_to_conclusion``;
  * the summary is rendered from the typed ``Verdict`` only (never artifact output).

Layered timeouts (must stay ordered): the ENGINE budget (wall-clock, default 120s) kills
a wedged podman run -> ERROR; the 2.3 executor Watchdog (default 900s) is the OUTER net
if the engine fails to. Engine << Watchdog, so they never race on a clean ERROR.

Aggregation lives in the engine (``run_check``); the App consumes one authoritative
``Verdict`` and never re-interprets per-trial data.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    ResourceBudget,
)
from engine.calibration import BundleResolver, DetectorResolver
from engine.retry import RetryCheck
from engine.runner import TrialReport, TrialReportSink, run_check

from .artifact import (
    ArtifactFetchError,
    SafeExtractError,
    build_artifact_spec,
    extraction_workspace,
    safe_extract_tarball,
)
from .backends import guarded_backend
from .trust_policy import resolve_trust_policy
from .detector_registry import (
    DetectorRegistry,
    DetectorResolutionError,
    profile_of,
)
from .preflight import ConfigurationError
from .checkrun import (
    CheckRunLifecycle,
    GitHubCheckClient,
)
from .executor import CheckUpdater, JobRunner
from .gatekeeper import GateDecision, GateDecisionError
from .job_result import (
    InfraFailureReason,
    InfrastructureFailure,
    JobResult,
    NonRunDecision,
    account,
)
from .policy_state import Disposition
from .queue import GatingEvent
from .run_admission import (
    AdmissionGovernanceView,
    AdmittedRunResult,
    AuthorizedRunPlan,
    BlockingRefusal,
    UnadmittedRunResult,
    admit_run_result,
)
from .summary import render_check_summary

# Engine wall-clock << the 2.3 Watchdog (900s) so the engine's own ERROR wins cleanly.
DEFAULT_ENGINE_BUDGET = ResourceBudget(wall_clock_seconds=120.0)
DEFAULT_TRIALS = 3
DEFAULT_ENTRYPOINT = ("python3", "/artifact/main.py")
# S3-completion: the reference observation-trust policy the LIVE enforcement path applies (untrusted
# observations -> ERROR before the detector; measured provenance from the APPLIED policy). completed-only:v1.
_REFERENCE_TRUST_POLICY = "trust-policy:completed-only"

# artifact_source(event, workspace) -> ArtifactSpec: fetch + extract the PR head into the
# RAII workspace. Faked in 2.4 (local fixture); the real tarball download lands at 2.5.
ArtifactSource = Callable[[GatingEvent, Path], ArtifactSpec]


def assert_budget_fits_watchdog(
    *,
    trials: int,
    per_trial_wall_clock: float,
    watchdog_timeout: float,
    margin: float = 1.2,
) -> None:
    """Fail-closed startup invariant (completeness-pass P5, refined by the multi-trial
    reality): ``run_check`` applies the budget PER TRIAL, so the MODELED aggregate engine time is
    ``trials × per_trial_wall_clock``. That modeled aggregate (× a safety margin) MUST fit inside
    the 2.3 watchdog window, else even the engine's own MODELED worst case would reach the watchdog.

    ``live_app.build()`` invokes this at startup and REFUSES TO BOOT when the bounded timing inequality
    (``trials × per_trial_wall_clock × margin >= watchdog_timeout``) holds — an ENFORCED startup invariant
    (not a documented request). This enforces ordering for the MODELED aggregate trial budget plus margin
    ONLY; the watchdog remains the fail-closed OUTER bound for artifact acquisition, sandbox setup/teardown,
    scheduling, and other UNMODELED stalls."""
    aggregate = trials * per_trial_wall_clock
    if aggregate * margin >= watchdog_timeout:
        raise ValueError(
            f"engine aggregate budget {aggregate}s (trials={trials} x "
            f"{per_trial_wall_clock}s) x margin {margin} must be < watchdog "
            f"{watchdog_timeout}s — reduce trials/per-trial budget or raise the watchdog"
        )


def extract_to_spec(tar_path: Path, workspace: Path) -> ArtifactSpec:
    """Safe-extract a tarball into ``workspace/src`` and bind its shared-canon hash."""
    dest = workspace / "src"
    safe_extract_tarball(tar_path, dest)
    return build_artifact_spec(dest)


def default_detector_registry(
    *,
    detector_id: str = "retry",
    entrypoint: tuple[str, ...] = DEFAULT_ENTRYPOINT,
    accepted_profile_digest: str | None = None,
) -> DetectorRegistry:
    """Build a ``DetectorRegistry`` with the first-party ``RetryCheck`` registered under ``detector_id``,
    bound to an ACCEPTED PROFILE DIGEST (module bytes + entrypoint + config — 3.5-close P1-1/P1-3).

    ``accepted_profile_digest`` (injected) is the digest from an INDEPENDENT acceptance ceremony — a
    DEPLOYMENT must supply it so the live gate enforces the exact profile that was accepted (see
    ``build_live_app``, which fails boot if it is absent). If ``None`` the registry SELF-COMPUTES it from
    the current ``RetryCheck`` bytes — a DEMONSTRATION of the mechanism for the reference / tests, NOT
    enforcement (it is circular: current-bytes vs a hash of current-bytes). ``resolve`` refuses an
    unregistered id or a profile-digest drift on every resolve."""
    registry = DetectorRegistry()
    digest = accepted_profile_digest or profile_of(detector_id, RetryCheck(entrypoint)).digest()
    registry.register(detector_id, lambda: RetryCheck(entrypoint), accepted_profile_digest=digest)
    return registry


def assert_detector_registered(resolve: DetectorResolver, detector_id: str) -> None:
    """3.5-close #1.3 boot assertion: the enforced detector must RESOLVE (registered + its content-address
    matches the accepted one) at STARTUP — fail at boot, not per-PR. A misconfigured / drifted live
    detector otherwise ERRORs on every PR (a fail-closed availability incident); catch it at boot."""
    try:
        resolve(detector_id)
    except DetectorResolutionError as exc:
        raise ConfigurationError(
            f"live detector {detector_id!r} does not resolve at boot (unregistered or drifted from the "
            f"accepted content-address): {exc}"
        ) from exc


def _run_engine_check(
    event: GatingEvent,
    plan: AuthorizedRunPlan,
    *,
    artifact_source: ArtifactSource,
    image: str,
    resolve: BundleResolver,
    detector_id: str,
    trials: int = DEFAULT_TRIALS,
    budget: ResourceBudget = DEFAULT_ENGINE_BUDGET,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
) -> UnadmittedRunResult:
    """Run the REAL hermetic engine (ObservedOCISandbox + multi-trial) under the REQUIRED pre-run ``plan``
    and pair the AUTHORITATIVE ``EngineRunResult`` with it into an ``UnadmittedRunResult`` — the sole input
    to ``admit_run_result``. PRIVATE (CP2 S5): the engine cannot be run without a plan, so every enforcement
    run is admission-gated by construction. The measured 4-coordinate subject travels ON the authoritative
    return; admission recomputes it and requires it to equal ``plan.target_subject`` (post-run SUBJECT_DRIFT).

    Fetch+extract inside a RAII workspace (purged on every exit path) while the sandbox mounts the artifact.
    3.5-close #1.3: the detector is resolved through the SAME trusted registry calibration uses (enforced ==
    accepted); an unregistered / content-address-DRIFTED detector raises ``DetectorResolutionError``, which
    the caller maps to a blocking infra failure (never runs an unverified detector). The sandbox re-verifies
    the artifact SHA-bind; a mismatch raises ``ArtifactHashMismatchError`` (possible TOCTOU) and propagates.
    ``first_fail`` short-circuits the FAIL path (C1)."""
    with extraction_workspace() as ws:
        artifact = artifact_source(event, ws)
        # v5 P1a: resolve the ATOMIC bundle and execute its FROZEN command — the LIVE enforcement path must
        # run exactly the entrypoint the accepted profile bound, never a fresh detector.entrypoint() a stateful
        # detector could answer differently.
        bundle = resolve(detector_id)  # trusted registry: unregistered / drifted -> raises -> infra block
        detector = bundle.assertion
        # S3-completion (live 4-tuple): the AUDITED, token-stamped factory + reference guard from the closed
        # composition root, runtime PINNED to "podman", + the reference observation-trust policy. The runner
        # invokes the guard on every token-stamped sandbox and derives the guard/trust digests OFF the applied
        # objects, so the authoritative report carries all FOUR measured coordinates (profile/trust/guard/exec).
        make_sandbox, backend_guard = guarded_backend("observed", image, runtime="podman")
        trust_policy = resolve_trust_policy(_REFERENCE_TRUST_POLICY)
        result = run_check(
            make_sandbox, detector, artifact, budget,
            trials=trials, first_fail=first_fail, report_sink=report_sink, detector_id=detector_id,
            command=bundle.command, resolved_profile_digest=bundle.profile_digest,
            trust_policy=trust_policy, backend_guard=backend_guard,
        )
    return UnadmittedRunResult(plan=plan, result=result)


# resolve_decision(event) -> GateDecision: the injected tier read (live_app closes it over the configured
# policy_id + PolicyStore + snapshot + oracle_head_for). Keeps pipeline free of the policy-store import.
DecisionResolver = Callable[[GatingEvent], GateDecision]


def make_gated_job_runner(
    resolve_decision: DecisionResolver,
    artifact_source: ArtifactSource,
    *,
    policy_id: str,
    governance: AdmissionGovernanceView,
    image: str,
    resolve: BundleResolver,
    detector_id: str,
    trials: int = DEFAULT_TRIALS,
    budget: ResourceBudget = DEFAULT_ENGINE_BUDGET,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
) -> JobRunner:
    """Build the executor's ``job_runner`` — the FULL tier-decision + engine + run-admission path, returning
    a TYPED ``JobResult`` (CP2 S5; de-vestigialises ``dispatch_gated``). Per delivery:

      1. ``resolve_decision(event)`` -> ``GateDecision``. A non-``RUN_ENFORCING`` disposition returns a
         ``NonRunDecision`` (SKIP_NEUTRAL -> neutral; BLOCK_ACTION_REQUIRED -> blocking) and NEVER touches
         the engine (a degraded/unattestable policy blocks without a silent fall-open to neutral).
      2. DISPATCH-TIME INVARIANT RECHECK (board D5, the first plan consumer; the plan is NOT unforgeable):
         re-assert RUN_ENFORCING <=> ``plan is not None`` (defence-in-depth vs a future refactor) AND bind
         ``plan.policy_id == policy_id`` — a mis-routed / absent plan reaching the engine raises
         ``GateDecisionError`` (the executor maps it to a blocking WORKER_FAULT). NOT a live-currency recheck
         — that is ``admit_run_result``'s job (governance may legitimately have moved since mint).
      3. run the engine under the plan (``_run_engine_check``) and ADMIT the result
         (``admit_run_result``) -> ``AdmittedRunResult`` (post the measured verdict) | ``BlockingRefusal``
         (fail-closed block). A ``DetectorResolutionError`` / ``ArtifactHashMismatchError`` from the run is a
         typed ``InfrastructureFailure`` (blocking), never an unverified pass."""

    def run(event: GatingEvent) -> JobResult:
        decision = resolve_decision(event)
        # DISPATCH-TIME INVARIANT RECHECK (board D5 + dissent P1): re-assert the BICONDITIONAL
        # RUN_ENFORCING <=> plan is not None in BOTH directions BEFORE branching. GateDecision.__post_init__
        # enforces it at construction, but the recheck is the first plan consumer's fail-closed guard: a
        # forged non-RUN decision CARRYING a plan (or a RUN_ENFORCING carrying none) is refused here, not
        # silently accepted by returning early on the non-run branch.
        enforcing = decision.disposition is Disposition.RUN_ENFORCING
        if enforcing != (decision.plan is not None):
            raise GateDecisionError(
                f"dispatch-time invariant: RUN_ENFORCING ({enforcing}) must hold IFF a plan is present "
                f"({decision.plan is not None}) — refusing an incoherent decision")
        if not enforcing:
            # the tier says do NOT run the engine -> typed non-run publication (neutral or blocking).
            return NonRunDecision(decision.disposition, decision.reason)
        plan = decision.plan
        assert plan is not None  # the biconditional above guarantees this (narrowing for the type checker)
        if plan.policy_id != policy_id:
            raise GateDecisionError(
                f"dispatch-time invariant: a RUN_ENFORCING decision for {policy_id!r} carried a plan for "
                f"{plan.policy_id!r} — refusing to run a mis-routed plan")
        try:
            unadmitted = _run_engine_check(
                event, plan, artifact_source=artifact_source, image=image, resolve=resolve,
                detector_id=detector_id, trials=trials, budget=budget, first_fail=first_fail,
                report_sink=report_sink,
            )
        except ArtifactHashMismatchError:
            # the SHA-bind caught the mounted tree differing from its verified hash — a possible TOCTOU
            # tamper. Blocking infra fault (action_required), a distinct forensic reason; never a pass.
            return InfrastructureFailure(
                InfraFailureReason.ARTIFACT_INTEGRITY_MISMATCH,
                detail=f"artifact tree hash mismatch for {event.head_sha}")
        except ArtifactFetchError:
            # Increment B / F3: the artifact could not be ACQUIRED (a live fetch/network/token-exchange
            # failure normalised at the artifact-source boundary) -> a typed blocking acquisition failure,
            # never a misclassified WORKER_FAULT and never a pass. Same bucket as the extract failure below
            # (the reason already reads "fetch/extract"); the detail distinguishes acquisition from extract.
            return InfrastructureFailure(
                InfraFailureReason.ARTIFACT_FETCH_FAILED,
                detail=f"artifact acquisition (fetch) failed for {event.head_sha}")
        except SafeExtractError:
            # the artifact could not be safely fetched/extracted (a malformed / path-traversing / oversized
            # tarball rejected by safe_extract_tarball) -> a typed blocking acquisition failure, never a pass.
            return InfrastructureFailure(
                InfraFailureReason.ARTIFACT_FETCH_FAILED,
                detail=f"artifact extract failed for {event.head_sha}")
        except DetectorResolutionError:
            # the enforced detector is unregistered or DRIFTED from the accepted identity -> block, never
            # enforce an unauthorized / rolled-back detector.
            return InfrastructureFailure(
                InfraFailureReason.DETECTOR_UNRESOLVED,
                detail=f"detector {detector_id!r} unresolved/drifted")
        return admit_run_result(unadmitted, governance=governance)

    return run


class CapturingTrialReportSink:
    """A ``TrialReportSink`` that keeps the LAST report so the Check Run updater can render the attested
    ``detector_id`` + ``image_digest`` (3.5-close #1.5). Single-writer: the executor runs job_runner then
    updater on ONE thread per job (max_workers=1 in the live app), so ``last`` is this job's report. A
    multi-worker executor would need a per-event capture; documented, not assumed."""

    def __init__(self) -> None:
        self.last: TrialReport | None = None

    def record(self, report: TrialReport) -> None:
        self.last = report


def _render_job_summary(result: JobResult, name: str) -> str:
    """Render the Check Run summary from the TYPED ``JobResult``. C4 publication pin: the attested
    ``detector_id`` + ``image_digest`` are pulled ONLY from an ``AdmittedRunResult``'s OWN authoritative
    report — never a mutable capture sink that could contaminate a refusal / non-run / infra summary with a
    previous job's detector/image. A refusal / non-run / infra publishes a stable typed message and NEVER
    the internal ``detail`` (log-only). Runtime-rejects a bare ``Verdict`` / unknown type."""
    if isinstance(result, AdmittedRunResult):
        report = result.report
        image_digest = (report.execution_identity.image_ref
                        if report.execution_identity is not None else None)
        return render_check_summary(
            result.verdict, name, detector_id=report.detector_id, image_digest=image_digest).summary
    if isinstance(result, BlockingRefusal):
        # a fail-closed admission refusal — a real (admission) ERROR verdict, but NO detector/image (the run
        # was not admitted). ``reason`` is a controlled admission-layer token (never raw detail).
        return render_check_summary(result.verdict, name).summary + f" [admission: {result.reason.value}]"
    if isinstance(result, NonRunDecision):
        return f"Policy not enforced ({result.disposition.value}): {result.reason}"
    if isinstance(result, InfrastructureFailure):
        # NEVER ``result.detail`` (internal-log-only) — only the stable, closed reason token.
        return (
            f"Gate infrastructure error ({result.reason.value}): the check could not complete; "
            "this blocks the merge and a maintainer must investigate.")
    raise TypeError(
        f"cannot render a Check Run summary for {type(result).__name__} — the updater accepts only a "
        "JobResult (a bare Verdict/EngineRunResult is rejected)")


def make_check_updater(client: GitHubCheckClient, *, name: str) -> CheckUpdater:
    """Build the executor's ``updater``: drive the Check Run queued->in_progress->completed from the TYPED
    ``JobResult`` (CP2 S5). The conclusion is ``account(result).conclusion`` (fail-closed by construction,
    and a runtime reject of a bare ``Verdict`` — the closed union is the contract); the summary is rendered
    from the typed result via ``_render_job_summary`` (C4: detector/image only from an ``AdmittedRunResult``,
    never from a mutable capture sink; infra ``detail`` is never published)."""
    lifecycle = CheckRunLifecycle(client, name=name)

    def update(event: GatingEvent, result: JobResult) -> None:
        conclusion = account(result).conclusion  # closed-union + fail-closed; rejects a bare Verdict
        summary = _render_job_summary(result, name)
        check_run_id = lifecycle.open_queued(
            repo_full_name=event.repo_full_name, head_sha=event.head_sha)
        lifecycle.mark_in_progress(
            repo_full_name=event.repo_full_name, check_run_id=check_run_id)
        lifecycle.complete_with_conclusion(
            repo_full_name=event.repo_full_name, check_run_id=check_run_id,
            conclusion=conclusion, summary=summary)

    return update


__all__ = [
    "ArtifactSource",
    "DecisionResolver",
    "extract_to_spec",
    "default_detector_registry",
    "assert_detector_registered",
    "make_gated_job_runner",
    "make_check_updater",
    "CapturingTrialReportSink",
    "DEFAULT_ENGINE_BUDGET",
    "DEFAULT_TRIALS",
    "DEFAULT_ENTRYPOINT",
]
