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
from enum import Enum

from core import Verdict
from gate.checkrun import CheckConclusion, verdict_to_conclusion
from gate.policy_state import Disposition, nonrun_conclusion_for
from gate.run_admission import AdmittedRunResult, BlockingRefusal


class InfraFailureReason(Enum):
    """The CLOSED set of infrastructure-failure causes (board S5: never a free string). Only this stable
    token — or a trusted message keyed by it — is ever PUBLISHED; the ``detail`` field (raw exception text /
    artifact-derived output) is INTERNAL-LOG-ONLY and must never reach the Check Run summary."""

    WORKER_FAULT = "worker_fault"                          # an unexpected worker exception
    DETECTOR_UNRESOLVED = "detector_unresolved"            # the enforced detector did not resolve
    ARTIFACT_INTEGRITY_MISMATCH = "artifact_integrity_mismatch"  # TOCTOU: staged tree != verified hash
    ARTIFACT_FETCH_FAILED = "artifact_fetch_failed"        # could not fetch/extract the artifact
    WATCHDOG_TIMEOUT = "watchdog_timeout"                  # a wedged worker force-completed by the watchdog
    UNACCOUNTED_RESULT = "unaccounted_result"             # the job runner returned a non-JobResult type


class GateOutcome(Enum):
    """The CLOSED gate-outcome discriminator persisted ALONGSIDE (and independently of) the engine verdict
    (board S5, closure 1) — so the override classifier can tell a merge-past-a-BLOCKING-non-run from a clean
    merge WITHOUT a fabricated verdict. ``RUN_VERDICT`` = a real engine/admission verdict was produced;
    ``BLOCK_GATE`` = a blocking governance non-run (no verdict); ``NEUTRAL_GATE`` = a non-blocking governance
    non-run (no verdict). An infra/error row carries NO gate outcome (None)."""

    RUN_VERDICT = "run_verdict"
    BLOCK_GATE = "block_gate"
    NEUTRAL_GATE = "neutral_gate"


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

    reason: InfraFailureReason  # the CLOSED cause (the only thing published); NEVER a free string
    detail: str                 # raw diagnostic (exception text etc.) — INTERNAL LOGS ONLY, never published

    def __post_init__(self) -> None:
        # board hardening: the reason MUST be the closed enum (a stray string would slip a free token — and
        # potentially raw/injected text — into the published summary).
        if type(self.reason) is not InfraFailureReason:
            raise TypeError(
                f"InfrastructureFailure.reason must be an InfraFailureReason, got {type(self.reason).__name__}")


# The closed publication union. A bare ``Verdict`` / ``EngineRunResult`` is deliberately NOT a member — the
# Executor runtime-rejects anything else (see ``account``).
JobResult = AdmittedRunResult | BlockingRefusal | NonRunDecision | InfrastructureFailure


@dataclass(frozen=True)
class PersistedOutcome:
    """What the Executor persists (``store.finalize``) + tells the updater to publish, derived HONESTLY per
    type. ``status`` is ``error`` ONLY for an infra fault; ``verdict`` is present ONLY when an admitted run
    or an admission refusal produced one; ``gate_outcome`` is the closed discriminator persisted INDEPENDENTLY
    of the verdict (so the override classifier need not read a fabricated verdict); ``reason`` is a stable
    audit token; ``conclusion`` is the merge outcome GitHub is told.

    VALID COMBINATIONS enforced (board S5): ``RUN_VERDICT`` requires a real verdict; ``BLOCK_GATE`` /
    ``NEUTRAL_GATE`` require NO verdict; an infra/error row carries NEITHER a gate outcome NOR a verdict."""

    status: str                        # "done" | "error"
    verdict: Verdict | None            # ONLY an admitted run / admission refusal has one; else None
    gate_outcome: GateOutcome | None   # closed discriminator, independent of the verdict (None for infra)
    reason: str                        # stable audit token (never a fabricated verdict)
    conclusion: CheckConclusion

    def __post_init__(self) -> None:
        # EXHAUSTIVE coherence (board): each freshly-minted outcome carries a COHERENT (status, gate_outcome,
        # verdict, conclusion) tuple — a done row carries EXACTLY ONE GateOutcome, an error row carries none.
        # (Only PERSISTED historical VerdictRows may lack a gate outcome; a minted PersistedOutcome never can.)
        if self.status not in ("done", "error"):
            raise ValueError(f"status must be done|error, got {self.status!r}")
        if self.gate_outcome is not None and type(self.gate_outcome) is not GateOutcome:
            raise TypeError(
                f"gate_outcome must be a GateOutcome, got {type(self.gate_outcome).__name__}")
        if self.status == "error":
            if self.gate_outcome is not None or self.verdict is not None:
                raise ValueError("an infra/error row carries NEITHER a gate outcome NOR a verdict")
            if self.conclusion is not CheckConclusion.ACTION_REQUIRED:
                raise ValueError("an infra/error row must publish ACTION_REQUIRED (blocking)")
            return
        if self.gate_outcome is None:
            raise ValueError("a done outcome must carry exactly one GateOutcome")
        if self.gate_outcome is GateOutcome.RUN_VERDICT:
            if self.verdict is None:
                raise ValueError("RUN_VERDICT requires a real verdict")
            if self.conclusion is not verdict_to_conclusion(self.verdict.status):
                raise ValueError("RUN_VERDICT conclusion must match the verdict's conclusion")
        elif self.gate_outcome is GateOutcome.BLOCK_GATE:
            if self.verdict is not None:
                raise ValueError("BLOCK_GATE must NOT carry a verdict (a non-run produced none)")
            if self.conclusion is not CheckConclusion.ACTION_REQUIRED:
                raise ValueError("BLOCK_GATE must publish ACTION_REQUIRED")
        elif self.gate_outcome is GateOutcome.NEUTRAL_GATE:
            if self.verdict is not None:
                raise ValueError("NEUTRAL_GATE must NOT carry a verdict (a non-run produced none)")
            if self.conclusion is not CheckConclusion.NEUTRAL:
                raise ValueError("NEUTRAL_GATE must publish NEUTRAL")


def account(result: JobResult) -> PersistedOutcome:
    """The EXHAUSTIVE typed accounting map (board): every ``JobResult`` member -> its honest persistence +
    publication fields, with a CLOSED ``gate_outcome`` discriminator so a merge-past-a-blocking-non-run is
    recorded WITHOUT a fabricated verdict. A bare ``Verdict`` / ``EngineRunResult`` (or any non-union type) is
    REJECTED — the Executor never persists or publishes an unaccounted outcome."""
    if isinstance(result, AdmittedRunResult):
        v = result.verdict
        return PersistedOutcome("done", v, GateOutcome.RUN_VERDICT, v.reason.value,
                                verdict_to_conclusion(v.status))
    if isinstance(result, BlockingRefusal):
        v = result.verdict  # Verdict(ERROR, RUN_UNADMITTED) — a real (admission) verdict was produced
        return PersistedOutcome("done", v, GateOutcome.RUN_VERDICT, v.reason.value,
                                verdict_to_conclusion(v.status))
    if isinstance(result, NonRunDecision):
        blocking = result.disposition is Disposition.BLOCK_ACTION_REQUIRED
        gate = GateOutcome.BLOCK_GATE if blocking else GateOutcome.NEUTRAL_GATE
        return PersistedOutcome("done", None, gate, result.disposition.value, result.conclusion)
    if isinstance(result, InfrastructureFailure):
        return PersistedOutcome("error", None, None, result.reason.value, CheckConclusion.ACTION_REQUIRED)
    raise TypeError(
        f"not a JobResult: {type(result).__name__} — the Executor accepts only "
        "AdmittedRunResult|BlockingRefusal|NonRunDecision|InfrastructureFailure "
        "(a bare Verdict/EngineRunResult is rejected: no unaccounted publication)")


__all__ = [
    "InfraFailureReason",
    "GateOutcome",
    "NonRunDecision",
    "InfrastructureFailure",
    "JobResult",
    "PersistedOutcome",
    "account",
]
