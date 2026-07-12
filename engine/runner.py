"""engine/runner.py — the multi-trial assertion runner (Gap-4: unanimity).

Runs a RuntimeAssertion across N ISOLATED trials — a FRESH sandbox + network +
proxy + container per trial, so fail-once state can never leak between trials — and
aggregates. Multi-trial lives in the ENGINE, not the check (the check returns one
Verdict per run).

Aggregation (board-ratified, GLM correction): a flaky artifact is a DEFECT (FAIL),
never an ERROR. ERROR is reserved strictly for broken telemetry — the observer, not
the artifact, failing.

    any trial FAIL          -> FAIL   (mixed pass/fail = NON_DETERMINISTIC, still FAIL)
    else any trial ERROR    -> ERROR  (some trial un-observable, no fail seen)
    else all PASS           -> PASS

First-fail short-circuit (C1): with ``first_fail=True`` (default), the loop stops as
soon as a trial returns FAIL and aggregates the trials run so far. Under unanimity a
FAIL is unrescuable (no later trial flips it), so the remaining trials are pure waste
on the FAIL path — the fast rejection goes to the developer who has something to fix.
ERROR does NOT short-circuit (observed-FAIL beats ERROR — a later trial could still
FAIL, and we must hunt for it, not mask an exploit behind an infra blip). PASS never
short-circuits (unanimity needs all N).

REASON FIDELITY TRADE (documented, not a bug): a short-circuited FAIL reports the
FIRST-observed failure reason (e.g. ``EGRESS_ONE``), NOT the full-distribution reason
(``NON_DETERMINISTIC``). Same VERDICT (FAIL), more actionable REASON for a merge gate.
Distribution-level reasoning (flaky vs systematic) needs the full run — set
``first_fail=False`` (Calibration Mode, Step 3, does this).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable, Protocol, Sequence

from core import (
    ArtifactSpec,
    Reason,
    ResourceBudget,
    RuntimeAssertion,
    Sandbox,
    Verdict,
    VerdictType,
)
from core.chain import content_digest

_log = logging.getLogger("gated.engine")


@dataclass(frozen=True)
class ExecutionIdentity:
    """3.5 #3: the PARENT-MEASURED identity of the environment a trial actually ran in. Measured by the
    runner FROM THE SANDBOX OBJECT IT CONSTRUCTED — never self-reported by the child/run (a child can
    lie about its own image). Binds backend, the (optionally digest-pinned) image ref, the isolation
    level, and an observer/config hash. The calibration + acceptance receipt attest THIS, and reject a
    run whose trials do not all share it (a sandbox that changed environment mid-run)."""

    backend: str
    image_ref: str
    isolation_level: str
    observer_config_hash: str = ""

    def digest(self) -> str:
        return content_digest({
            "backend": self.backend, "image_ref": self.image_ref,
            "isolation_level": self.isolation_level, "observer_config_hash": self.observer_config_hash,
        })


def _raw_identity(sandbox: Sandbox) -> tuple[str, object, str, str]:
    """The cheap per-trial identity tuple read PARENT-SIDE from the sandbox object (no image pin)."""
    return (
        type(sandbox).__name__, getattr(sandbox, "image", None),
        sandbox.isolation_level.value, str(getattr(sandbox, "observer_config_hash", "") or ""),
    )


@dataclass(frozen=True)
class TrialReport:
    """The forensic record of a multi-trial run — emitted to a ``TrialReportSink`` so a
    verdict showing ``trials_run < trials_configured`` is EXPLAINED, never a mystery.
    Carries the per-trial verdicts (not just counts) so the audit trail + UI have the
    concrete reasons, and Step-3 Calibration has the distribution without re-deriving.

    ``execution_identity`` (3.5 #3) is the PARENT-MEASURED identity all trials shared, or None if the
    trials' environments DIFFERED (a mixed-identity run, which the aggregate reports as ERROR)."""

    trials: tuple[Verdict, ...]        # the verdicts of the trials actually run
    trials_configured: int
    short_circuited: bool
    aggregate: Verdict
    execution_identity: ExecutionIdentity | None = None

    @property
    def trials_run(self) -> int:
        return len(self.trials)


class TrialReportSink(Protocol):
    """Where a ``TrialReport`` is recorded. Defined ENGINE-side (dependency inversion:
    the engine must not import the gate) — the gate wires its lifecycle audit to it."""

    def record(self, report: TrialReport) -> None: ...


def aggregate(verdicts: Sequence[Verdict]) -> Verdict:
    statuses = [v.status for v in verdicts]
    if VerdictType.FAIL in statuses:
        # FAIL takes precedence (fail-closed): a definitely-observed non-compliance
        # blocks, even if another trial's telemetry broke. Mixed pass/fail = flaky.
        reason = (
            Reason.NON_DETERMINISTIC
            if VerdictType.PASS in statuses
            else next(v.reason for v in verdicts if v.status is VerdictType.FAIL)
        )
        return Verdict(VerdictType.FAIL, reason)
    if VerdictType.ERROR in statuses:
        return Verdict(VerdictType.ERROR, Reason.OBSERVATION_INCOMPLETE)
    return Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)


def run_check(
    make_sandbox: Callable[[], Sandbox],
    check: RuntimeAssertion,
    artifact: ArtifactSpec,
    budget: ResourceBudget,
    trials: int = 3,
    *,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
    pin_image: Callable[[str], str] | None = None,
) -> Verdict:
    """Run ``check`` on ``artifact`` across up to ``trials`` isolated trials -> one
    Verdict. ``make_sandbox`` is a factory so each trial gets a fresh sandbox instance
    (and, via its prepare(), a fresh network/proxy/container).

    ``first_fail`` (default True) stops after the first FAIL (see module docstring).
    ``report_sink`` receives a ``TrialReport`` (the audit record of what ran).

    3.5 #3: the runner PARENT-MEASURES each trial's execution identity from the sandbox object it
    constructed and asserts all trials SHARE it. A mixed-identity run (a sandbox whose environment
    changed between trials — image/backend/isolation drift) is fail-closed to ERROR, and the attested
    identity is None. ``pin_image`` (optional) resolves the sandbox's image tag to an immutable digest
    (deploy: ``podman image inspect``); it is called ONCE for the attested identity, not per trial."""
    verdicts: list[Verdict] = []
    raws: list[tuple[str, object, str, str]] = []
    for _ in range(trials):
        sb = make_sandbox()
        raws.append(_raw_identity(sb))  # parent-measured, before running the artifact
        with sb.session(artifact, check.fixtures) as handle:
            result = sb.run(handle, check.entrypoint(), budget)
        verdict = check.assert_invariant(result)
        verdicts.append(verdict)
        if first_fail and verdict.status is VerdictType.FAIL:
            break  # unanimity: a FAIL is unrescuable — the rest are pure waste

    consistent = len(set(raws)) <= 1
    identity: ExecutionIdentity | None = None
    if raws and consistent:
        backend, image, iso, obs = raws[0]
        image_ref = (pin_image(str(image)) if (pin_image and image is not None)
                     else str(image) if image is not None else f"<{backend}>")
        identity = ExecutionIdentity(backend=backend, image_ref=image_ref,
                                     isolation_level=iso, observer_config_hash=obs)
    result_verdict = aggregate(verdicts)
    if not consistent:
        # 3.5 #3: trials ran in DIFFERENT environments -> the run's identity is not attestable ->
        # fail-closed (a downstream calibration/acceptance must not trust a mixed-identity run).
        result_verdict = Verdict(VerdictType.ERROR, Reason.OBSERVATION_INCOMPLETE)
    if report_sink is not None:
        report = TrialReport(
            trials=tuple(verdicts),
            trials_configured=trials,
            short_circuited=len(verdicts) < trials,
            aggregate=result_verdict,
            execution_identity=identity,
        )
        # The audit sink is an OBSERVER — it must never crash the engine or suppress the
        # Verdict (the merge gate's source of truth). Emit-failure is logged, not
        # swallowed: a missing audit record is an operational alert, not a dev halt.
        try:
            report_sink.record(report)
        except Exception:
            _log.warning("trial-report sink failed to record; verdict still returned", exc_info=True)
    return result_verdict
