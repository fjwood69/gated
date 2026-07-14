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
    Command,
    ExecutionResult,
    ImageResolutionError,
    Reason,
    ResourceBudget,
    RuntimeAssertion,
    Sandbox,
    Verdict,
    VerdictType,
)
from core.chain import content_digest
from engine.observation_trust import TrustPolicy

_log = logging.getLogger("gated.engine")


@dataclass(frozen=True)
class ExecutionIdentity:
    """The PARENT-MEASURED identity of the environment a trial actually ran in (3.5 #3 + 3.5-close #1.1).
    Backend, isolation level and observer-config hash are read parent-side from the trusted sandbox
    OBJECT; ``image_ref`` is the IMMUTABLE digest the sandbox resolved before run and executed (the bytes
    that ran, not the mutable tag) — never self-reported by the artifact/child. This is an IDENTITY /
    ANTI-DRIFT coordinate (which environment), NOT runtime-behaviour assurance (a compromised host could
    match the digest and run something else — the unattested-TCB ceiling, ARCHITECTURE.md). The
    calibration + acceptance receipt attest THIS and reject a run whose trials do not all share it."""

    backend: str
    image_ref: str
    isolation_level: str
    observer_config_hash: str = ""

    def digest(self) -> str:
        return content_digest({
            "backend": self.backend, "image_ref": self.image_ref,
            "isolation_level": self.isolation_level, "observer_config_hash": self.observer_config_hash,
        })


def _raw_identity(sandbox: Sandbox, result: ExecutionResult) -> tuple[str, object, str, str]:
    """The per-trial identity tuple. Backend + isolation + observer-config are read PARENT-SIDE from the
    trusted sandbox object; the IMAGE coordinate is the immutable digest the sandbox resolved before run
    and RECORDED in the result (3.5-close #1.1 — the bytes that ran, not the mutable tag). A None
    image_digest = a backend with no image (NoOp/Subprocess); an AUDITED HERMETIC backend that could not
    resolve raises ImageResolutionError before reaching here (§1.6 confines security-relevant calibration
    to audited backends, so a None digest is never a security-relevant attested run)."""
    return (
        type(sandbox).__name__, result.image_digest,
        result.isolation_level.value, str(getattr(sandbox, "observer_config_hash", "") or ""),
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
    # B1: the digest of the observation trust policy APPLIED to these trials (None if no policy was applied).
    # It is measured PROVENANCE — the digest of the policy that actually governed the observation, carried up
    # so calibration can bind it into the signed identity (only when consistent across all trials).
    trust_policy_digest: str | None = None
    # S3-completion: the remaining two RuntimeSubject coordinates, carried on the report so the LIVE path's
    # authoritative return supplies the FULL measured 4-tuple to admission (not just calibration). Both are
    # FROZEN provenance resolved ONCE by the caller before the trial loop — ``resolved_profile_digest`` is
    # the digest of the bundle actually run (never re-resolved per trial), and ``guard_policy_digest`` is
    # read off the guard object ACTUALLY APPLIED to every sandbox (None for the test-only opt-out). ICV is
    # NOT here: it is contract metadata (checked against the process constant), not a measured coordinate.
    resolved_profile_digest: str | None = None
    guard_policy_digest: str | None = None
    # 3.5-close #1.1 (board amendment 3): the NAME of the detector that judged these trials. Lives HERE
    # (enforcement metadata), NOT on ExecutionResult — the sandbox produces facts about the run and does
    # not know which detector judged its result. Set by the caller (calibration / live enforcement) that
    # resolved the detector through the trusted registry; carried into the Check Run payload (§1.5).
    detector_id: str | None = None

    @property
    def trials_run(self) -> int:
        return len(self.trials)


@dataclass(frozen=True)
class EngineRunResult:
    """S3-completion: the AUTHORITATIVE, immutable result of an engine run — the ``TrialReport`` returned
    DIRECTLY up the call stack (not emitted to a swallowable observer sink). Admission evidence travels via
    the return value, immune to a sink's ``try/except`` or a mutable capture's staleness. There is ONE
    source of truth: ``verdict`` is a DERIVED property (``trial_report.aggregate``), never a stored second
    copy that could diverge from the report the admission layer inspects. Being frozen prevents ordinary
    accidental mutation in trusted code (it is not an absolute runtime immutability boundary)."""

    trial_report: TrialReport

    @property
    def verdict(self) -> Verdict:
        # single source of truth: the report's aggregate IS the verdict — no duplication to diverge.
        return self.trial_report.aggregate


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
        # preserve a UNANIMOUS specific ERROR reason (IMAGE_UNRESOLVED, ARTIFACT_INTEGRITY_MISMATCH,
        # TELEMETRY_MISSING) — a distinct fatal cause is more actionable than the generic multi-trial
        # OBSERVATION_INCOMPLETE, which is reserved for mixed/partial un-observability.
        error_reasons = {v.reason for v in verdicts if v.status is VerdictType.ERROR}
        reason = error_reasons.pop() if len(error_reasons) == 1 else Reason.OBSERVATION_INCOMPLETE
        return Verdict(VerdictType.ERROR, reason)
    return Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)


def _judge(
    check: RuntimeAssertion, result: ExecutionResult, trust_policy: TrustPolicy | None,
) -> Verdict:
    """Apply the observation trust policy (if any) BEFORE the detector. An untrusted observation is mapped
    MECHANICALLY to ``Verdict(ERROR)`` — the detector's ``assert_invariant`` is NEVER consulted for it, so an
    always-PASS detector cannot launder a timeout / error / malformed run into a PASS (board B1). Only a
    TRUSTED observation reaches the detector; a non-zero ``completed`` exit code is trusted (the detector
    decides its meaning)."""
    if trust_policy is not None:
        decision = trust_policy.evaluate(result)
        if not decision.trusted:
            reason = (
                Reason.TELEMETRY_MISSING if decision.code == "MALFORMED"
                else Reason.OBSERVATION_INCOMPLETE
            )
            return Verdict(VerdictType.ERROR, reason)
    return check.assert_invariant(result)


def run_check(
    make_sandbox: Callable[[], Sandbox],
    check: RuntimeAssertion,
    artifact: ArtifactSpec,
    budget: ResourceBudget,
    trials: int = 3,
    *,
    first_fail: bool = True,
    report_sink: TrialReportSink | None = None,
    detector_id: str | None = None,
    command: Command | None = None,
    trust_policy: TrustPolicy | None = None,
    resolved_profile_digest: str | None = None,
    backend_guard: Callable[[Sandbox], None] | None = None,
) -> EngineRunResult:
    """Run ``check`` on ``artifact`` across up to ``trials`` isolated trials -> one
    Verdict. ``make_sandbox`` is a factory so each trial gets a fresh sandbox instance
    (and, via its prepare(), a fresh network/proxy/container).

    ``first_fail`` (default True) stops after the first FAIL (see module docstring).

    S3-completion: returns an AUTHORITATIVE, immutable ``EngineRunResult`` carrying the always-constructed
    ``TrialReport`` DIRECTLY (the verdict is a derived property of that report — one source of truth). The
    ``report_sink`` is now a SECONDARY audit copy: it receives the SAME report AFTER it is built, and a
    sink failure is logged, never affecting the returned evidence.

    S3-completion (measured-not-declared): ``backend_guard`` is the guard OBJECT — the runner INVOKES it on
    EVERY constructed sandbox (it raises on rejection) and derives ``guard_policy_digest`` internally by
    reading ``policy_digest`` OFF THAT INVOKED OBJECT. The digest is NEVER accepted as a caller string, so a
    caller cannot declare a guard it did not apply. ``resolved_profile_digest`` is the digest of the bundle
    resolved ONCE by the caller (the runner runs the frozen ``command``, never re-resolving per trial), and
    ``trust_policy``'s digest is read off the policy actually applied in ``_judge`` — so the report's
    measured 4-tuple originates from the applied objects, not declarations.

    3.5 #3 + 3.5-close #1.1: the runner PARENT-MEASURES each trial's execution identity — backend +
    isolation + observer-config from the trusted sandbox object, and the IMMUTABLE image digest the
    sandbox resolved-before-run and recorded in the result (the bytes that ran, not the tag). It asserts
    all trials SHARE one identity; a mixed-identity run is fail-closed to ERROR with a None attested
    identity. An image that cannot be resolved before run (absent / GC'd) raises ``ImageResolutionError``
    -> ``Verdict(ERROR, IMAGE_UNRESOLVED)`` for that trial, NEVER a silent pass."""
    verdicts: list[Verdict] = []
    raws: list[tuple[str, object, str, str] | None] = []
    # v4 P1-c: execute the FROZEN resolved command if one was captured at resolution (the trusted-registry
    # profile's entrypoint), computed ONCE. Falls back to a single ``check.entrypoint()`` for callers that
    # do not resolve through the registry — but the value is fixed before the loop, never re-called per
    # trial (a stateful detector must not resolve one command and run another).
    cmd = command if command is not None else check.entrypoint()
    for _ in range(trials):
        sb = make_sandbox()
        if backend_guard is not None:
            # S3-completion: the RUNNER invokes the guard on EVERY constructed sandbox (it RAISES on
            # rejection, fail-closed) — so the guard whose digest is bound to the report is the guard that
            # actually ran on every trial (measured, not a caller declaration).
            backend_guard(sb)
        try:
            with sb.session(artifact, check.fixtures) as handle:
                result = sb.run(handle, cmd, budget)
        except ImageResolutionError:
            # 3.5-close #1.1 (finding A): the image digest could not be resolved BEFORE run -> the run
            # is UNATTESTABLE -> fail-closed ERROR, never a silent pass / "the detector did not fire".
            # No identity for this trial (a None raw -> the run is not consistently attestable -> ERROR).
            verdicts.append(Verdict(VerdictType.ERROR, Reason.IMAGE_UNRESOLVED))
            raws.append(None)
            if first_fail:
                break  # re-attempting an unresolvable image gains nothing
            continue
        verdict = _judge(check, result, trust_policy)  # trust policy applied BEFORE the detector
        verdicts.append(verdict)
        raws.append(_raw_identity(sb, result))  # image coord = the digest the sandbox actually ran
        if first_fail and verdict.status is VerdictType.FAIL:
            break  # unanimity: a FAIL is unrescuable — the rest are pure waste

    # attestable ONLY if every trial produced an identity AND they all agree. A None raw (resolution
    # failure) or differing raws -> not consistently attestable -> the run's identity is None.
    consistent = bool(raws) and all(r is not None for r in raws) and len(set(raws)) <= 1
    identity: ExecutionIdentity | None = None
    if consistent:
        backend, image, iso, obs = raws[0]  # type: ignore[misc]
        image_ref = str(image) if image is not None else f"<{backend}>"
        identity = ExecutionIdentity(backend=str(backend), image_ref=image_ref,
                                     isolation_level=str(iso), observer_config_hash=str(obs))
    result_verdict = aggregate(verdicts)
    if not consistent and result_verdict.status is not VerdictType.ERROR:
        # trials ran in DIFFERENT environments but none ERRORed (e.g. all PASS on drifting images) ->
        # the run's identity is not attestable -> fail-closed. A resolution failure already ERRORs
        # (IMAGE_UNRESOLVED) and is preserved; this only covers the mixed-identity-but-all-observed case.
        result_verdict = Verdict(VerdictType.ERROR, Reason.OBSERVATION_INCOMPLETE)
    # S3-completion: the report is ALWAYS constructed — it is the AUTHORITATIVE return, not an audit
    # artifact contingent on a sink being wired. Every measured coordinate lives on it: the aggregate
    # verdict, the parent-measured execution identity, and the frozen profile / trust / guard provenance.
    report = TrialReport(
        trials=tuple(verdicts),
        trials_configured=trials,
        short_circuited=len(verdicts) < trials,
        aggregate=result_verdict,
        execution_identity=identity,
        detector_id=detector_id,
        trust_policy_digest=trust_policy.policy_digest if trust_policy is not None else None,
        resolved_profile_digest=resolved_profile_digest,
        # DERIVED from the guard object the runner actually invoked above — never a caller string.
        guard_policy_digest=getattr(backend_guard, "policy_digest", None),
    )
    if report_sink is not None:
        # The audit sink is now a SECONDARY consumer of a COPY — it receives the authoritative report but
        # its failure can NEVER remove admission evidence (the report is already the return value). An
        # emit-failure is logged, not swallowed: a missing audit record is an operational alert, not a halt.
        try:
            report_sink.record(report)
        except Exception:
            _log.warning("trial-report sink failed to record; authoritative result still returned",
                         exc_info=True)
    return EngineRunResult(trial_report=report)
