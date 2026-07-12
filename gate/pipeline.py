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
    Reason,
    ResourceBudget,
    Verdict,
    VerdictType,
)
from engine.calibration import BundleResolver, DetectorResolver
from engine.retry import RetryCheck
from engine.runner import TrialReport, TrialReportSink, run_check
from sandbox.observed import ObservedOCISandbox

from .artifact import build_artifact_spec, extraction_workspace, safe_extract_tarball
from .detector_registry import (
    DetectorRegistry,
    DetectorResolutionError,
    profile_of,
)
from .preflight import ConfigurationError
from .checkrun import (
    CheckConclusion,
    CheckOutput,
    CheckRunLifecycle,
    CheckStatus,
    GitHubCheckClient,
    upsert_check_run,
)
from .executor import CheckUpdater, JobRunner
from .gatekeeper import GateDecision
from .policy_state import Disposition, nonrun_conclusion_for
from .queue import GatingEvent
from .summary import render_check_summary

# Engine wall-clock << the 2.3 Watchdog (900s) so the engine's own ERROR wins cleanly.
DEFAULT_ENGINE_BUDGET = ResourceBudget(wall_clock_seconds=120.0)
DEFAULT_TRIALS = 3
DEFAULT_ENTRYPOINT = ("python3", "/artifact/main.py")

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
    reality): ``run_check`` applies the budget PER TRIAL, so the aggregate engine time is
    ``trials × per_trial_wall_clock``. That aggregate (× a safety margin) MUST fit inside
    the 2.3 watchdog window, else a slow multi-trial run races the watchdog's force-ERROR.

    The App MUST call this at startup and refuse to boot on violation — an ENFORCED
    invariant, not a documented request (a race in the verdict engine must be
    impossible-by-construction, not avoided-by-documentation)."""
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


def run_engine_check(
    artifact: ArtifactSpec,
    *,
    image: str,
    resolve: BundleResolver,
    detector_id: str,
    trials: int = DEFAULT_TRIALS,
    budget: ResourceBudget = DEFAULT_ENGINE_BUDGET,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
) -> Verdict:
    """Run the REAL hermetic engine (ObservedOCISandbox + multi-trial) and return the aggregated Verdict.

    3.5-close #1.3: the detector is resolved through the SAME trusted registry calibration uses
    (enforced == accepted). The registry refuses an unregistered id or a detector whose content-address
    DRIFTED from the accepted one, so the live gate cannot enforce an unauthorized / rolled-back detector.
    (Single accepted detector; per-policy detector SELECTION + full anti-rollback is a named-next
    increment — see ARCHITECTURE.md.) A resolution failure raises ``DetectorResolutionError``, caught by
    the job-runner and mapped to a blocking ERROR (never run an unverified detector). The sandbox verifies
    the SHA-bind; a mismatch raises + propagates. ``first_fail`` short-circuits the FAIL path (C1)."""
    # v5 P1a: resolve the ATOMIC bundle and execute its FROZEN command — the LIVE enforcement path must
    # run exactly the entrypoint the accepted profile bound, never a fresh detector.entrypoint() a stateful
    # detector could answer differently. (Was: resolve() + run_check without command -> re-called entrypoint.)
    bundle = resolve(detector_id)  # trusted registry: unregistered / drifted -> raises -> ERROR
    detector = bundle.assertion

    def make_sandbox() -> ObservedOCISandbox:
        return ObservedOCISandbox(image=image, runtime="podman")

    return run_check(
        make_sandbox, detector, artifact, budget,
        trials=trials, first_fail=first_fail, report_sink=report_sink, detector_id=detector_id,
        command=bundle.command,
    )


def make_job_runner(
    artifact_source: ArtifactSource,
    *,
    image: str,
    resolve: BundleResolver,
    detector_id: str,
    trials: int = DEFAULT_TRIALS,
    budget: ResourceBudget = DEFAULT_ENGINE_BUDGET,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
) -> JobRunner:
    """Build the executor's ``job_runner``: fetch+extract inside a RAII workspace, then
    run the real engine. The workspace wraps the run so the artifact is on disk while the
    sandbox mounts it, and is purged on every exit path. ``report_sink`` carries the C1
    trial-report audit up to the gate. 3.5-close #1.3: the detector is resolved by NAME through the
    trusted registry (enforced == accepted); a resolution failure blocks (ERROR), never runs."""

    def run(event: GatingEvent) -> Verdict:
        with extraction_workspace() as ws:
            artifact = artifact_source(event, ws)
            try:
                return run_engine_check(
                    artifact, image=image, resolve=resolve, detector_id=detector_id, trials=trials,
                    budget=budget, first_fail=first_fail, report_sink=report_sink,
                )
            except ArtifactHashMismatchError:
                # NOT a generic infra ERROR: the SHA-bind caught the mounted tree
                # differing from its verified hash — a possible TOCTOU tamper. Blocks
                # (ERROR -> action_required) AND surfaces as a distinct security event.
                return Verdict(VerdictType.ERROR, Reason.ARTIFACT_INTEGRITY_MISMATCH)
            except DetectorResolutionError:
                # 3.5-close #1.3: the enforced detector is unregistered or has DRIFTED from the accepted
                # identity -> refuse to run it (block), never enforce an unauthorized / rolled-back detector.
                return Verdict(VerdictType.ERROR, Reason.DETECTOR_UNRESOLVED)

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


def make_check_updater(
    client: GitHubCheckClient, *, name: str,
    report_capture: CapturingTrialReportSink | None = None,
) -> CheckUpdater:
    """Build the executor's ``updater``: drive the Check Run queued->in_progress->completed with the
    mapped (fail-closed) conclusion and the out-of-band summary. 3.5-close #1.5: if a ``report_capture``
    is wired (the same sink the job-runner records to), the summary carries the ATTESTED ``detector_id``
    + resolved ``image_digest`` — non-repudiation of {which detector, which image} on the existing
    merge-blocking path (not a new heavy signed local receipt)."""
    lifecycle = CheckRunLifecycle(client, name=name)

    def update(event: GatingEvent, verdict: Verdict) -> None:
        check_run_id = lifecycle.open_queued(
            repo_full_name=event.repo_full_name, head_sha=event.head_sha
        )
        lifecycle.mark_in_progress(
            repo_full_name=event.repo_full_name, check_run_id=check_run_id
        )
        detector_id: str | None = None
        image_digest: str | None = None
        if report_capture is not None and report_capture.last is not None:
            report = report_capture.last
            detector_id = report.detector_id
            image_digest = (report.execution_identity.image_ref
                            if report.execution_identity is not None else None)
        summary = render_check_summary(
            verdict, name, detector_id=detector_id, image_digest=image_digest).summary
        lifecycle.complete(
            repo_full_name=event.repo_full_name,
            check_run_id=check_run_id,
            verdict=verdict.status,
            summary=summary,
        )

    return update


# static_poster(event, conclusion, summary): post a terminal Check Run WITHOUT running the engine
# — used for non-ENABLED policies (neutral) and DEGRADED (action_required). Kept separate from the
# engine path so a non-enforcing disposition CANNOT accidentally run the sandbox.
StaticPoster = Callable[[GatingEvent, CheckConclusion, str], None]


def make_static_poster(client: GitHubCheckClient, *, name: str) -> StaticPoster:
    """Build a poster that drives queued->completed with a STATIC conclusion (no engine, no
    Verdict). Idempotent via upsert (find-then-PATCH by sha,name), same as the enforcing path."""

    def post(event: GatingEvent, conclusion: CheckConclusion, summary: str) -> None:
        upsert_check_run(
            client, repo_full_name=event.repo_full_name, head_sha=event.head_sha,
            name=name, status=CheckStatus.QUEUED,
        )
        upsert_check_run(
            client, repo_full_name=event.repo_full_name, head_sha=event.head_sha,
            name=name, status=CheckStatus.COMPLETED, conclusion=conclusion,
            output=CheckOutput(title=name, summary=summary),
        )

    return post


def dispatch_gated(
    event: GatingEvent,
    decision: GateDecision,
    *,
    job_runner: JobRunner,
    updater: CheckUpdater,
    static_poster: StaticPoster,
) -> None:
    """The 3.3 dispatch seam: consult the tier decision BEFORE the engine. Only RUN_ENFORCING
    (a live/attested ENABLED policy) runs the sandbox and posts the real Verdict. Every other
    disposition posts a static conclusion and NEVER touches the engine:
      * SKIP_NEUTRAL          -> neutral (non-blocking; not-yet-enabled / advisory / rejected);
      * BLOCK_ACTION_REQUIRED -> action_required (BLOCKING; DEGRADED — un-attestable, fail-closed).
    A DEGRADED policy therefore blocks the merge WITHOUT running the engine and WITHOUT a silent
    fall-open to neutral (#1)."""
    if decision.disposition is Disposition.RUN_ENFORCING:
        verdict = job_runner(event)
        updater(event, verdict)
        return
    conclusion = nonrun_conclusion_for(decision.disposition)
    static_poster(event, conclusion, f"Policy not enforced ({decision.disposition.value}): {decision.reason}")


__all__ = [
    "ArtifactSource",
    "extract_to_spec",
    "run_engine_check",
    "default_detector_registry",
    "assert_detector_registered",
    "make_job_runner",
    "make_check_updater",
    "CapturingTrialReportSink",
    "make_static_poster",
    "dispatch_gated",
    "StaticPoster",
    "DEFAULT_ENGINE_BUDGET",
    "DEFAULT_TRIALS",
    "DEFAULT_ENTRYPOINT",
]
