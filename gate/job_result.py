"""gate/job_result.py — CP2 S5: the TYPED terminal outcome of one gated job + the EXHAUSTIVE accounting map.

The Executor's job runner returns exactly ONE ``JobResult`` — never a bare ``Verdict`` or ``EngineRunResult``.
Persistence + publication fields are derived by the exhaustive ``account`` mapper, NOT by a ``.verdict`` on
every member (board S5 correction): a neutral governance decision and an infrastructure failure produced NO
admitted run, so forcing a ``.verdict`` would FABRICATE an engine verdict that never existed. ``account`` maps
each member to its HONEST fields (``status`` done/error, a ``verdict`` present ONLY for an admitted run or an
admission refusal, and the merge-blocking ``conclusion``), and REJECTS any non-union type — so the Executor
can never persist an unaccounted publication.
"""
from __future__ import annotations

from dataclasses import dataclass

from core import Verdict
from gate.checkrun import CheckConclusion, verdict_to_conclusion
from gate.policy_state import Disposition, nonrun_conclusion_for
from gate.run_admission import AdmittedRunResult, BlockingRefusal


@dataclass(frozen=True)
class NonRunDecision:
    """A governance decision NOT to run the engine — the typed publication of a non-RUN ``GateDecision``.
    ``SKIP_NEUTRAL`` publishes NEUTRAL (non-blocking); ``BLOCK_ACTION_REQUIRED`` publishes ACTION_REQUIRED
    (blocking, recorded so a merge-past-block stays auditable). Carries NO engine verdict — nothing ran."""

    disposition: Disposition
    reason: str

    def __post_init__(self) -> None:
        if self.disposition is Disposition.RUN_ENFORCING:
            raise ValueError("NonRunDecision cannot carry RUN_ENFORCING — that disposition runs the engine")

    @property
    def conclusion(self) -> CheckConclusion:
        return nonrun_conclusion_for(self.disposition)


@dataclass(frozen=True)
class InfrastructureFailure:
    """A blocking INFRASTRUCTURE fault — NEITHER an admission refusal NOR a governance non-run: artifact
    fetch/extract failure, a detector-resolution failure, a TOCTOU artifact-hash mismatch, an unexpected
    worker exception, or watchdog force-completion. Publishes ACTION_REQUIRED (blocking) and records NO gate
    verdict — no admitted run produced one, and mislabelling it a ``BlockingRefusal`` would claim the
    admission gate refused when in fact the machinery never reached a verdict."""

    reason: str    # a short machine token for the audit + summary (e.g. "detector_unresolved")
    detail: str


# The closed publication union. A bare ``Verdict`` / ``EngineRunResult`` is deliberately NOT a member — the
# Executor runtime-rejects anything else (see ``account``).
JobResult = AdmittedRunResult | BlockingRefusal | NonRunDecision | InfrastructureFailure


@dataclass(frozen=True)
class PersistedOutcome:
    """What the Executor persists (``store.finalize``) + tells the updater to publish, derived HONESTLY per
    type: ``status`` is ``error`` ONLY for an infra fault; ``verdict`` is present ONLY when an admitted run
    or an admission refusal produced one (``None`` for a neutral/blocking non-run — no fabrication); ``reason``
    is always a machine token for the audit trail; ``conclusion`` is the merge outcome GitHub is told."""

    status: str                  # "done" | "error"
    verdict: Verdict | None      # ONLY an admitted run / admission refusal has one; else None
    reason: str                  # audit token (never a fabricated verdict)
    conclusion: CheckConclusion


def account(result: JobResult) -> PersistedOutcome:
    """The EXHAUSTIVE typed accounting map (board): every ``JobResult`` member -> its honest persistence +
    publication fields. A bare ``Verdict`` / ``EngineRunResult`` (or any non-union type) is REJECTED — the
    Executor never persists or publishes an unaccounted outcome."""
    if isinstance(result, AdmittedRunResult):
        v = result.verdict
        return PersistedOutcome("done", v, v.reason.value, verdict_to_conclusion(v.status))
    if isinstance(result, BlockingRefusal):
        v = result.verdict  # Verdict(ERROR, RUN_UNADMITTED) — the fail-closed publication verdict
        return PersistedOutcome("done", v, v.reason.value, verdict_to_conclusion(v.status))
    if isinstance(result, NonRunDecision):
        return PersistedOutcome("done", None, result.disposition.value, result.conclusion)
    if isinstance(result, InfrastructureFailure):
        return PersistedOutcome("error", None, result.reason, CheckConclusion.ACTION_REQUIRED)
    raise TypeError(
        f"not a JobResult: {type(result).__name__} — the Executor accepts only "
        "AdmittedRunResult|BlockingRefusal|NonRunDecision|InfrastructureFailure "
        "(a bare Verdict/EngineRunResult is rejected: no unaccounted publication)")


__all__ = [
    "NonRunDecision",
    "InfrastructureFailure",
    "JobResult",
    "PersistedOutcome",
    "account",
]
