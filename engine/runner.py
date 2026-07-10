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

_log = logging.getLogger("gated.engine")


@dataclass(frozen=True)
class TrialReport:
    """The forensic record of a multi-trial run — emitted to a ``TrialReportSink`` so a
    verdict showing ``trials_run < trials_configured`` is EXPLAINED, never a mystery.
    Carries the per-trial verdicts (not just counts) so the audit trail + UI have the
    concrete reasons, and Step-3 Calibration has the distribution without re-deriving."""

    trials: tuple[Verdict, ...]        # the verdicts of the trials actually run
    trials_configured: int
    short_circuited: bool
    aggregate: Verdict

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
) -> Verdict:
    """Run ``check`` on ``artifact`` across up to ``trials`` isolated trials -> one
    Verdict. ``make_sandbox`` is a factory so each trial gets a fresh sandbox instance
    (and, via its prepare(), a fresh network/proxy/container).

    ``first_fail`` (default True) stops after the first FAIL (see module docstring).
    ``report_sink`` receives a ``TrialReport`` (the audit record of what ran)."""
    verdicts: list[Verdict] = []
    for _ in range(trials):
        sb = make_sandbox()
        with sb.session(artifact, check.fixtures) as handle:
            result = sb.run(handle, check.entrypoint(), budget)
        verdict = check.assert_invariant(result)
        verdicts.append(verdict)
        if first_fail and verdict.status is VerdictType.FAIL:
            break  # unanimity: a FAIL is unrescuable — the rest are pure waste

    result_verdict = aggregate(verdicts)
    if report_sink is not None:
        report = TrialReport(
            trials=tuple(verdicts),
            trials_configured=trials,
            short_circuited=len(verdicts) < trials,
            aggregate=result_verdict,
        )
        # The audit sink is an OBSERVER — it must never crash the engine or suppress the
        # Verdict (the merge gate's source of truth). Emit-failure is logged, not
        # swallowed: a missing audit record is an operational alert, not a dev halt.
        try:
            report_sink.record(report)
        except Exception:
            _log.warning("trial-report sink failed to record; verdict still returned", exc_info=True)
    return result_verdict
