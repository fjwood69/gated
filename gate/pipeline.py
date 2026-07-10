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
from engine.retry import RetryCheck
from engine.runner import TrialReportSink, run_check
from sandbox.observed import ObservedOCISandbox

from .artifact import build_artifact_spec, extraction_workspace, safe_extract_tarball
from .checkrun import CheckRunLifecycle, GitHubCheckClient
from .executor import CheckUpdater, JobRunner
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


def run_engine_check(
    artifact: ArtifactSpec,
    *,
    image: str,
    entrypoint: tuple[str, ...] = DEFAULT_ENTRYPOINT,
    trials: int = DEFAULT_TRIALS,
    budget: ResourceBudget = DEFAULT_ENGINE_BUDGET,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
) -> Verdict:
    """Run the REAL hermetic engine (ObservedOCISandbox + RetryCheck, multi-trial) and
    return the aggregated Verdict. The sandbox verifies the SHA-bind; a mismatch raises
    and propagates (-> ERROR at the executor). ``first_fail`` short-circuits the FAIL
    path (C1); ``report_sink`` records the TrialReport (the gate wires the audit here)."""

    def make_sandbox() -> ObservedOCISandbox:
        return ObservedOCISandbox(image=image, runtime="podman")

    return run_check(
        make_sandbox, RetryCheck(entrypoint), artifact, budget,
        trials=trials, first_fail=first_fail, report_sink=report_sink,
    )


def make_job_runner(
    artifact_source: ArtifactSource,
    *,
    image: str,
    entrypoint: tuple[str, ...] = DEFAULT_ENTRYPOINT,
    trials: int = DEFAULT_TRIALS,
    budget: ResourceBudget = DEFAULT_ENGINE_BUDGET,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
) -> JobRunner:
    """Build the executor's ``job_runner``: fetch+extract inside a RAII workspace, then
    run the real engine. The workspace wraps the run so the artifact is on disk while the
    sandbox mounts it, and is purged on every exit path. ``report_sink`` carries the C1
    trial-report audit up to the gate."""

    def run(event: GatingEvent) -> Verdict:
        with extraction_workspace() as ws:
            artifact = artifact_source(event, ws)
            try:
                return run_engine_check(
                    artifact, image=image, entrypoint=entrypoint, trials=trials,
                    budget=budget, first_fail=first_fail, report_sink=report_sink,
                )
            except ArtifactHashMismatchError:
                # NOT a generic infra ERROR: the SHA-bind caught the mounted tree
                # differing from its verified hash — a possible TOCTOU tamper. Blocks
                # (ERROR -> action_required) AND surfaces as a distinct security event.
                return Verdict(VerdictType.ERROR, Reason.ARTIFACT_INTEGRITY_MISMATCH)

    return run


def make_check_updater(client: GitHubCheckClient, *, name: str) -> CheckUpdater:
    """Build the executor's ``updater``: drive the Check Run queued->in_progress->
    completed with the mapped (fail-closed) conclusion and the out-of-band summary."""
    lifecycle = CheckRunLifecycle(client, name=name)

    def update(event: GatingEvent, verdict: Verdict) -> None:
        check_run_id = lifecycle.open_queued(
            repo_full_name=event.repo_full_name, head_sha=event.head_sha
        )
        lifecycle.mark_in_progress(
            repo_full_name=event.repo_full_name, check_run_id=check_run_id
        )
        summary = render_check_summary(verdict, name).summary
        lifecycle.complete(
            repo_full_name=event.repo_full_name,
            check_run_id=check_run_id,
            verdict=verdict.status,
            summary=summary,
        )

    return update


__all__ = [
    "ArtifactSource",
    "extract_to_spec",
    "run_engine_check",
    "make_job_runner",
    "make_check_updater",
    "DEFAULT_ENGINE_BUDGET",
    "DEFAULT_TRIALS",
    "DEFAULT_ENTRYPOINT",
]
