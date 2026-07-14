"""gate/run_admission.py — 3.5 S3-completion: the LIVE-PATH run-result admission typestate + currency.

AUTHORITY BOUNDARY (this module): run-result admission — it controls what ENFORCEMENT EVIDENCE is
PUBLISHABLE (an engine run result → an admitted verdict on the merge-blocking Check Run). This is DISTINCT
from ``gate/admission.py``, the 3.4 FIXTURE admission gate, which controls what enters the CALIBRATION
ORACLE (a candidate → a fixture). Two different boundaries; do not conflate them.

WHY (dissent1 P1-1, the deepest). SPEC1 gave the CALIBRATION path a currency re-check (the restore
controller re-reads the live oracle head + authorized context before it re-attests) and the ENABLE path a
sealed-context proof — but an ORDINARY PR verdict does NEITHER. It runs the engine and publishes the
Verdict with no point at which the run is proven to have executed under the identity the policy actually
authorizes, and under a calibration set that is still CURRENT. A pre-run tier decision cannot see mid-run
drift. This module is the missing RUN-ADMISSION VALIDATION POINT for the routine path.

MEASURED ≠ DECLARED, in two dimensions:
  * CP0 (structural): the four RuntimeSubject coordinates travel by the STEP-1 authoritative immutable
    return (``EngineRunResult``); admission recomputes the MEASURED subject from that return and requires it
    to equal the subject the run was DISPATCHED to enforce (``plan.target_subject``) — the runner-bypass
    catch (the run measured what the plan authorized), NOT a plan-vs-plan check.
  * CP1 (live currency): admission then performs its OWN LIVE governance reads (never caller-asserted) and
    requires the run to be current — the calibration set has not drifted AND the dispatched subject is still
    the governance-authorized subject. This is the live-path analogue of ``restore_controller`` /
    ``gatekeeper._enforce_if_oracle_current``.

LIVE READS (CP1). Admission reads, POST-run, via an injected ``AdmissionGovernanceView`` (admission's OWN
read, fail-closed on None/exception):
  * ``current_attestation(policy_id)`` → ``(set_id, bound_oracle_head, subject)`` — ONE row-snapshot of the
    policy's current ENABLED calibration binding (a non-None return internally GUARANTEES ICV==constant +
    a matching persisted pass). This ALONE carries subject + bound head + the ICV guarantee — reading the
    sibling ``current_authorized_context`` too would add no information (same row, same gates) and would
    reintroduce a subject-vs-head read-then-read race.
  * ``oracle_head_for(set_id)`` → the LIVE ``set_head`` — a SEPARATE read of the calibration store.
    ``current_attestation`` + ``set_head`` are NOT an atomic cross-store snapshot; a set can move between
    them. That window is fail-closed + self-correcting (a drift visible at read time is refused
    SET_HEAD_STALE; a drift between the two reads is caught on the NEXT PR event) — the same posture
    ``_enforce_if_oracle_current`` already runs pre-run.

Why set currency matters (dissent premise corrected): a non-None ``current_attestation`` does NOT prove the
set is current — between a fixture-append (which moves ``set_head``) and the re-cal worker transitioning the
tier, the policy stays ENABLED bound to the OLD head. So admission MUST compare ``bound_head`` vs live
``set_head`` (SET_HEAD_STALE) and the plan's authorized set vs the live set (AUTHORIZED_SET_MOVED — a
different-set governance rebind must not silently upgrade an old plan).

TYPESTATE. ``AuthorizedRunPlan`` (minted before the run) + ``EngineRunResult`` pair into
``UnadmittedRunResult``; ``admit_run_result(unadmitted, governance=…)`` maps that to
``AdmittedRunResult | BlockingRefusal``. The publication path (CP2) accepts ONLY this union — an
``AdmittedRunResult`` authorizes posting the measured Verdict; a ``BlockingRefusal`` is itself a BLOCKING
outcome (fail-closed ``Verdict(ERROR, RUN_UNADMITTED)`` → action_required), so a refusal never silently
drops a run to neutral. The typestate is API cohesion (sequencing + pairing), NOT a load-bearing authority.

VALIDATION SPLIT + PROOF-GATED CONSTRUCTION. ``_validate_structural`` is PURE (ICV typing, mint coherence,
coordinate completeness, measured-recompute == target) — re-runnable, so ``AdmittedRunResult``'s constructor
re-runs it (closing the report-recomputed-subject forge). The LIVE currency checks require I/O and are
``admit_run_result``'s alone (a frozen constructor cannot redo I/O). To stop a DIRECT construction bypassing
the live checks, ``AdmittedRunResult`` requires a ``_LiveAdmissionGrant`` minted ONLY by
``admit_run_result`` — an in-process call-path convention (the structural no-bypass test asserts
``admit_run_result`` is the sole minter), not an unforgeable boundary. Gate-side: imports the engine's
authoritative return + the attestation identity function + core; ``core`` and the engine runner never
import this.
"""
from __future__ import annotations

from dataclasses import InitVar, dataclass
from enum import Enum
from typing import Protocol

from core import Reason, Verdict, VerdictType
from engine.runner import EngineRunResult, TrialReport
from gate.attestation import IDENTITY_CONTRACT_VERSION, calibrated_subject_identity


def _measured_coordinates(report: TrialReport) -> tuple[str | None, str | None, str | None, str | None]:
    """The four RuntimeSubject coordinates as MEASURED, read SOLELY off the authoritative engine return
    (``EngineRunResult.trial_report``) — never a pre-run bundle or guard OBJECT. STEP 1 threaded the
    profile / trust / guard digests ONTO the report at run time (the values actually in effect during
    execution), and the execution coordinate is the digest of the parent-measured ``execution_identity``
    (None if the trials did not share one identity — a mixed-identity run the engine aggregated to ERROR).
    Derived exactly as the calibration path derives them (``recalibration.py``), so a legitimately-measured
    identity recomputes to the SAME composite the calibration path signs."""
    eid = report.execution_identity.digest() if report.execution_identity is not None else None
    return (
        report.resolved_profile_digest,
        report.trust_policy_digest,
        report.guard_policy_digest,
        eid,
    )


def _present(coord: str | None) -> str:
    return "present" if isinstance(coord, str) and coord != "" else "ABSENT"


class RunAdmissionError(RuntimeError):
    """An ``AdmittedRunResult`` was constructed incoherently — without the live-admission grant, or with a
    report that does not structurally re-admit (its stored subject is not the report-recomputed one).
    Raised by the constructor's defence-in-depth check so a mis-assembled admitted result fails closed
    rather than publishing an enforcement verdict for the wrong identity."""


class RunAdmissionRefusal(Enum):
    """The CLOSED, NON-OVERLAPPING taxonomy of why a run result was refused admission. Distinct members
    (like the attestation module's layer-tagged errors) so a negative test can assert EXACTLY which layer
    refused and cannot pass for the wrong reason. All map to the same fail-closed published verdict
    (``RUN_UNADMITTED`` → blocks); this records the forensic cause. Split STRUCTURAL (pure, from the
    authoritative return + the plan) vs LIVE (governance currency, admission's own reads)."""

    # --- structural (pure: plan + authoritative return) ---
    ICV_UNSUPPORTED = "icv_unsupported"              # plan ICV is not this build's int contract
    UNAUTHORIZED_SUBJECT = "unauthorized_subject"    # plan mint-incoherent: target != the plan's own authorized snapshot subject
    INCOMPLETE_COORDINATES = "incomplete_coordinates"  # a measured RuntimeSubject coordinate is absent — the run is unattestable
    SUBJECT_DRIFT = "subject_drift"                  # the MEASURED subject != the dispatched target (the runner did not execute the planned detector)
    # --- live (governance currency: admission's own reads) ---
    LIVE_ATTESTATION_UNAVAILABLE = "live_attestation_unavailable"  # no current ENABLED attestation / policy-store unreadable — fail-closed
    ORACLE_UNAVAILABLE = "oracle_unavailable"        # cannot resolve the live set_head — fail-closed
    AUTHORIZED_SET_MOVED = "authorized_set_moved"    # plan's authorized set != the live attestation's set (a different-set rebind)
    SET_HEAD_STALE = "set_head_stale"                # bound oracle_head != live set_head (the set drifted since calibration)
    AUTHORIZED_SUBJECT_MOVED = "authorized_subject_moved"  # dispatched target != the live-authorized subject (governance moved the subject)


class AdmissionGovernanceView(Protocol):
    """Admission's OWN read surface onto live governance (never caller-asserted). Both reads may RAISE (a
    broken chain / unreachable store) — ``admit_run_result`` catches and fails closed. Structurally
    satisfied by the production ``PolicyStore.current_attestation`` + a ``set_head`` wrapper; tests inject a
    fake. No write surface — admission never mutates governance state (this is a read-only validation
    point, not a policy commit point)."""

    def current_attestation(self, policy_id: str) -> tuple[str, str, str] | None:
        """``(set_id, bound_oracle_head, subject)`` for the policy's CURRENT ENABLED calibration binding,
        or None if the policy is not ENABLED / has no matching pass. A non-None return GUARANTEES the
        binding is under the current identity contract (an internal gate)."""
        ...

    def oracle_head_for(self, set_id: str) -> str | None:
        """The LIVE ``set_head`` of ``set_id`` (the current sealed membership digest), or None if it cannot
        be resolved (fail-closed convention)."""
        ...


@dataclass(frozen=True)
class AuthorizedRunPlan:
    """The pre-run authorization for a single enforcement run: WHICH policy, WHICH calibrated subject the
    run is DISPATCHED to enforce (``target_subject``), under WHICH governance context (``authorized_context``
    = ``(set_id, authorized_subject, ICV)``, the same 3-tuple shape ``current_authorized_context`` returns).

    ``target_subject`` and ``authorized_subject`` are DISTINCT operands: the former is the subject THIS run
    was dispatched to enforce, the latter is what governance authorized AT MINT (a static snapshot). The
    snapshot is NOT the admission authority — the LIVE governance read is. But it is not purely audit either:
    its SET is a BLOCKING operand (``AUTHORIZED_SET_MOVED`` — a different-set governance rebind must not
    silently upgrade an old plan), and its SUBJECT is a structural mint-coherence check.

    ``authorized_context`` is the SINGLE SOURCE for set / authorized-subject / ICV: exposed as derived
    properties, never stored as separate fields that could diverge from the tuple (STEP 1 single-source)."""

    policy_id: str
    target_subject: str                       # the calibrated-subject identity THIS run was dispatched to enforce
    authorized_context: tuple[str, str, int]  # (set_id, authorized_subject, ICV) — the governance mint snapshot

    @property
    def authorized_set(self) -> str:
        return self.authorized_context[0]

    @property
    def authorized_subject(self) -> str:
        return self.authorized_context[1]

    @property
    def identity_contract_version(self) -> int:
        return self.authorized_context[2]


@dataclass(frozen=True)
class UnadmittedRunResult:
    """The typestate pairing an ``AuthorizedRunPlan`` with the engine's AUTHORITATIVE ``EngineRunResult``,
    BEFORE admission. It is the sole input to ``admit_run_result`` — you cannot admit a run without first
    pairing its plan with its authoritative return. Every MEASURED coordinate is derived SOLELY from
    ``result.trial_report`` (never from the plan, never from a post-run supplementary source)."""

    plan: AuthorizedRunPlan
    result: EngineRunResult

    @property
    def report(self) -> TrialReport:
        return self.result.trial_report

    def measured_coordinates(self) -> tuple[str | None, str | None, str | None, str | None]:
        """The four MEASURED RuntimeSubject coordinates, read SOLELY off the authoritative return (delegates
        to ``_measured_coordinates`` — the single derivation shared with admission's validator)."""
        return _measured_coordinates(self.report)


@dataclass(frozen=True)
class BlockingRefusal:
    """A run result REFUSED admission. It is not a silent drop: it carries a fail-closed blocking verdict
    (``Verdict(ERROR, RUN_UNADMITTED)`` → action_required on the Check Run), so the merge is BLOCKED, never
    fallen open to neutral. ``reason`` records the specific admission layer that refused (forensics); the
    published verdict is uniformly ERROR regardless of layer (the layer is not leaked to the merge UI)."""

    reason: RunAdmissionRefusal
    detail: str

    @property
    def verdict(self) -> Verdict:
        # single fail-closed publication verdict for EVERY refusal layer — the merge blocks; the specific
        # ``reason`` is the forensic record, not a distinct merge outcome.
        return Verdict(VerdictType.ERROR, Reason.RUN_UNADMITTED)


def _validate_structural(plan: AuthorizedRunPlan, report: TrialReport) -> BlockingRefusal | str:
    """The PURE (no-I/O) admission validator — deterministic, layered, fail-closed, re-runnable. Returns the
    recomputed MEASURED subject (a ``str``) on success, or a ``BlockingRefusal``. Run by BOTH
    ``admit_run_result`` (before the live checks) AND ``AdmittedRunResult.__post_init__`` (so a direct
    construction is re-validated — the report-recomputed-subject forge stays closed).

      1. ICV — EXACT typing + equality: ``type(icv) is int and icv == IDENTITY_CONTRACT_VERSION`` (a plain
         ``==`` would accept ``True`` since ``True == 1``, composing under a ``vTrue`` domain).
      2. MINT COHERENCE: the plan's dispatch ``target_subject`` == its own ``authorized_subject`` snapshot —
         a mis-minted plan is structurally incoherent. (The GOVERNANCE-currency of the subject is the LIVE
         check ``AUTHORIZED_SUBJECT_MOVED``, not this.)
      3. COMPLETE COORDINATES: all four MEASURED coordinates present and non-empty (an unattestable run).
      4. SUBJECT DRIFT (the RUNNER-BYPASS catch, ordered FIRST vs the live subject check): recompute the
         MEASURED subject from the four coordinates and require it to equal the dispatched ``target_subject``.
         If the runner deviated from the plan, it is caught HERE regardless of the live state — the execution
         was unauthorized even if it happens to match live governance. NEGATIVES mutate the MEASURED
         coordinate (the report), never the plan."""
    icv = plan.identity_contract_version
    if type(icv) is not int or icv != IDENTITY_CONTRACT_VERSION:
        return BlockingRefusal(
            RunAdmissionRefusal.ICV_UNSUPPORTED,
            f"plan identity_contract_version {icv!r} (type {type(icv).__name__}) is not this build's int "
            f"{IDENTITY_CONTRACT_VERSION!r} — cannot admit under a different / degenerate identity contract",
        )
    if plan.target_subject != plan.authorized_subject:
        return BlockingRefusal(
            RunAdmissionRefusal.UNAUTHORIZED_SUBJECT,
            f"plan target_subject {plan.target_subject!r} != its authorized-snapshot subject "
            f"{plan.authorized_subject!r} — the plan is mint-incoherent",
        )
    rpd, tpd, gpd, eid = _measured_coordinates(report)
    if not all(isinstance(c, str) and c != "" for c in (rpd, tpd, gpd, eid)):
        return BlockingRefusal(
            RunAdmissionRefusal.INCOMPLETE_COORDINATES,
            "a measured RuntimeSubject coordinate is absent "
            f"(profile={_present(rpd)} trust={_present(tpd)} guard={_present(gpd)} execution={_present(eid)}) "
            "— the run is not attestable to a single identity; fail-closed",
        )
    measured_subject = calibrated_subject_identity(rpd, tpd, gpd, eid, icv=icv)
    if measured_subject != plan.target_subject:
        return BlockingRefusal(
            RunAdmissionRefusal.SUBJECT_DRIFT,
            f"measured subject {measured_subject[:12]}.. != dispatched target "
            f"{plan.target_subject[:12]}.. — the runner did not execute the planned detector",
        )
    return measured_subject


class _LiveAdmissionGrant:
    """Proof that ``admit_run_result`` ran the LIVE governance-currency checks. Its sole instance
    ``_LIVE_GRANT`` is module-private; ``AdmittedRunResult`` refuses construction without it, so a DIRECT
    construction cannot bypass the live checks. An in-process call-path convention (the structural
    no-bypass test asserts ``admit_run_result`` is the only minter), NOT an unforgeable authority."""

    __slots__ = ()


_LIVE_GRANT = _LiveAdmissionGrant()


@dataclass(frozen=True)
class AdmittedRunResult:
    """A run result ADMITTED to publication: its MEASURED subject was recomputed from the authoritative
    return and matches the dispatched target (structural), AND the run was proven CURRENT against live
    governance (the set is unchanged and the subject is still authorized). The ONLY type that authorizes
    posting the measured ``verdict`` — the publication path (CP2) accepts ``AdmittedRunResult |
    BlockingRefusal`` and nothing else.

    ``verdict`` is a DERIVED property returning ``report.aggregate`` (no stored copy to diverge). The
    admission METADATA (``admitted_set_id`` + ``bound_oracle_head`` + ``measured_subject``, which IS the
    admitted subject) records the SCOPED live governance the run was admitted against, for CP2 to publish so
    a consumer can detect a stale read.

    Construction is PROOF-GATED: it requires the ``_LiveAdmissionGrant`` minted only by
    ``admit_run_result``, so a direct construction cannot bypass the live checks. The constructor also
    re-runs the PURE ``_validate_structural`` and requires ``measured_subject`` to equal the
    report-recomputed subject — a trusted-code construction check (the live governance authority is
    ``admit_run_result`` alone, since a frozen constructor cannot redo I/O)."""

    plan: AuthorizedRunPlan
    report: TrialReport
    measured_subject: str
    admitted_set_id: str
    bound_oracle_head: str
    grant: InitVar[_LiveAdmissionGrant | None] = None

    def __post_init__(self, grant: _LiveAdmissionGrant | None) -> None:
        if grant is not _LIVE_GRANT:
            raise RunAdmissionError(
                "AdmittedRunResult must be minted by admit_run_result (missing the live-admission grant) — "
                "a direct construction cannot bypass the live governance-currency checks")
        # defence in depth: re-run the PURE structural validator + require the stored subject to be the
        # honestly report-recomputed one (the live checks are admit_run_result's authority; the grant proves
        # they ran, a frozen constructor cannot redo the I/O).
        outcome = _validate_structural(self.plan, self.report)
        if isinstance(outcome, BlockingRefusal):
            raise RunAdmissionError(
                f"AdmittedRunResult failed structural re-validation ({outcome.reason.value}): "
                f"{outcome.detail} — construct it via admit_run_result")
        if self.measured_subject != outcome:
            raise RunAdmissionError(
                "AdmittedRunResult.measured_subject != the subject recomputed from the report — the stored "
                "subject is not the honestly-measured one (construct it via admit_run_result)")

    @property
    def verdict(self) -> Verdict:
        # single source of truth: the admitted verdict IS the report's aggregate — no stored duplicate.
        return self.report.aggregate


def admit_run_result(
    unadmitted: UnadmittedRunResult, *, governance: AdmissionGovernanceView,
) -> AdmittedRunResult | BlockingRefusal:
    """Admit ``unadmitted`` to publication, or refuse it (fail-closed) — the live-path analogue of
    ``restore_controller.attempt_restore`` / ``gatekeeper._enforce_if_oracle_current``, POST-execution.

    STRUCTURAL first (``_validate_structural``): ICV, mint coherence, coordinate completeness, and the
    RUNNER-BYPASS catch (measured == dispatched target). After it passes, ``measured_subject`` equals
    ``plan.target_subject``.

    LIVE currency (admission's OWN reads via ``governance``, fail-closed on None/exception):
      * ``current_attestation(policy_id)`` None / raises → LIVE_ATTESTATION_UNAVAILABLE;
      * ``oracle_head_for(set_id)`` None / raises → ORACLE_UNAVAILABLE;
      * plan's authorized set != the live attestation's set → AUTHORIZED_SET_MOVED (a different-set rebind);
      * bound oracle_head != live set_head → SET_HEAD_STALE (the set drifted since calibration);
      * dispatched target != the live-authorized subject → AUTHORIZED_SUBJECT_MOVED (governance moved the
        subject; since measured == target from the structural pass, this is the single non-dead subject
        currency check).

    On success, an ``AdmittedRunResult`` (proof-gated) carrying the report's aggregate verdict + the scoped
    admission metadata (``admitted_set_id`` + ``bound_oracle_head`` + measured subject)."""
    plan = unadmitted.plan

    structural = _validate_structural(plan, unadmitted.report)
    if isinstance(structural, BlockingRefusal):
        return structural
    measured_subject = structural  # == plan.target_subject (proven by the structural pass)

    # --- LIVE governance currency: admission's OWN reads, fail-closed on None/exception ---
    try:
        attestation = governance.current_attestation(plan.policy_id)
    except Exception as exc:  # a broken chain / unreachable store — never a silent pass
        return BlockingRefusal(
            RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE,
            f"live attestation read failed for {plan.policy_id!r} ({type(exc).__name__}) — fail-closed")
    if attestation is None:
        return BlockingRefusal(
            RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE,
            f"{plan.policy_id!r} has no current ENABLED attestation — not admissible (fail-closed)")
    live_set_id, bound_head, live_subject = attestation

    try:
        live_head = governance.oracle_head_for(live_set_id)
    except Exception as exc:
        return BlockingRefusal(
            RunAdmissionRefusal.ORACLE_UNAVAILABLE,
            f"live set_head read failed for {live_set_id!r} ({type(exc).__name__}) — fail-closed")
    if live_head is None:
        return BlockingRefusal(
            RunAdmissionRefusal.ORACLE_UNAVAILABLE,
            f"cannot resolve the live set_head for {live_set_id!r} — fail-closed")

    # set continuity: the plan's authorized set must be the policy's live attestation set (a different-set
    # governance rebind must not silently upgrade an old plan).
    if plan.authorized_set != live_set_id:
        return BlockingRefusal(
            RunAdmissionRefusal.AUTHORIZED_SET_MOVED,
            f"plan authorized set {plan.authorized_set!r} != the live attestation set {live_set_id!r} — a "
            "different-set governance rebind cannot admit an old plan")
    # set-head currency: the bound calibration head must still be the live set head (else the set drifted
    # since calibration while the policy stayed ENABLED — the D1 hole).
    if bound_head != live_head:
        return BlockingRefusal(
            RunAdmissionRefusal.SET_HEAD_STALE,
            f"bound oracle_head {bound_head[:12]}.. != live set_head {live_head[:12]}.. — the calibration "
            "set drifted since the bound calibration; the run's baseline is stale (fail-closed)")
    # subject currency: the dispatched target (== measured, structurally) must be the live-authorized
    # subject. Governance moved the subject since mint if not.
    if plan.target_subject != live_subject:
        return BlockingRefusal(
            RunAdmissionRefusal.AUTHORIZED_SUBJECT_MOVED,
            f"dispatched target {plan.target_subject[:12]}.. != the live-authorized subject "
            f"{live_subject[:12]}.. — governance moved the authorized subject since the plan was minted")

    return AdmittedRunResult(
        plan=plan, report=unadmitted.report, measured_subject=measured_subject,
        admitted_set_id=live_set_id, bound_oracle_head=live_head, grant=_LIVE_GRANT)


__all__ = [
    "RunAdmissionError",
    "RunAdmissionRefusal",
    "AdmissionGovernanceView",
    "AuthorizedRunPlan",
    "UnadmittedRunResult",
    "BlockingRefusal",
    "AdmittedRunResult",
    "admit_run_result",
]
