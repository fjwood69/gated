"""gate/run_admission.py — 3.5 S3-completion: the LIVE-PATH run-result admission typestate.

AUTHORITY BOUNDARY (this module): run-result admission — it controls what ENFORCEMENT EVIDENCE is
PUBLISHABLE (an engine run result → an admitted verdict on the merge-blocking Check Run). This is DISTINCT
from ``gate/admission.py``, the 3.4 FIXTURE admission gate, which controls what enters the CALIBRATION
ORACLE (a candidate → a fixture). Two different boundaries; do not conflate them.

WHY (dissent1 P1-1, the deepest). SPEC1 gave the CALIBRATION path a currency re-check (the restore
controller re-reads the live oracle head + authorized context before it re-attests) and the ENABLE path a
sealed-context proof — but an ORDINARY PR verdict does NEITHER. It runs the engine and publishes the
Verdict with no point at which the run is proven to have executed under the identity the policy actually
authorizes. A pre-run tier decision cannot see mid-run drift (the guard/trust/profile/execution that
actually governed the trials), so a run whose measured identity diverged from the authorized subject would
still publish an enforcement Verdict. This module is the missing admission point for the routine path: a
run result is admitted to publication ONLY if its MEASURED subject (recomputed from the authoritative
engine return) equals BOTH the subject the run was dispatched to enforce AND the governance-authorized
subject — the live-path analogue of ``restore_controller.attempt_restore``.

MEASURED ≠ DECLARED, one layer deeper than STEP 1. STEP 1 made the four RuntimeSubject coordinates travel
by an AUTHORITATIVE immutable return (``EngineRunResult``) instead of a swallowable observer sink. This
layer consumes that return: ``UnadmittedRunResult`` derives EVERY coordinate SOLELY from
``result.trial_report`` — never from the plan, never from a post-run supplementary source. The recomputed
subject is therefore a MEASURED operand; the plan supplies the AUTHORIZED operands. Comparing the two is a
genuine measured-vs-authorized check, never plan-vs-plan (the anti-pattern where the compared value was
itself derived from the thing it is compared against, making the check vacuous).

TYPESTATE. ``AuthorizedRunPlan`` (minted before the run) + ``EngineRunResult`` (the authoritative return)
pair into ``UnadmittedRunResult``; ``admit_run_result`` maps that to ``AdmittedRunResult | BlockingRefusal``.
The publication path (CP2, a later increment) accepts ONLY this union — an ``AdmittedRunResult`` authorizes
posting the measured Verdict; a ``BlockingRefusal`` is itself a BLOCKING outcome (fail-closed
``Verdict(ERROR, RUN_UNADMITTED)`` → action_required), so a refusal never silently drops a run to neutral.
The typestate is STATIC COHESION (API sequencing + the plan/result pairing), NOT a load-bearing authority:
the recompute-and-compare validator (``_evaluate_admission``, run by BOTH ``admit_run_result`` AND the
``AdmittedRunResult`` constructor) is the authority — a direct construction is re-validated identically.

SCOPE (this isolated checkpoint). ``AuthorizedRunPlan`` carries the authorized context as a STATIC snapshot
(``authorized_context``). Re-reading that context LIVE at the admission commit point (SPEC1 currency, so
drift between mint and admission is caught, not just internal-plan incoherence) is CP1 — this checkpoint
establishes the comparison STRUCTURE and the measured-vs-authorized operand discipline; CP1 makes the
authorized operand a live read. No wiring into the dispatch/updater path here (that is CP2).

BOUNDARY. Statically CHECKED in trusted gate code: ``AdmittedRunResult``'s constructor re-asserts its own
coherence (defence in depth), so a mis-built admitted result raises rather than publishes. This is a
trusted-process construction check, NOT an unforgeable / type-impossible boundary — a caller inside gate
could still assemble one by hand; admission (the recompute-and-compare) is the authority. Gate-side:
imports the engine's authoritative return + the attestation identity function + core; ``core`` and the
engine runner never import this.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

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
    """An ``AdmittedRunResult`` was constructed incoherently (its measured subject does not match the plan
    it claims to admit). Raised by the constructor's defence-in-depth check so a mis-assembled admitted
    result fails closed rather than publishing an enforcement verdict for the wrong identity."""


class RunAdmissionRefusal(Enum):
    """The CLOSED taxonomy of why a run result was refused admission. Distinct members (like the
    attestation module's layer-tagged errors) so a negative test can assert EXACTLY which layer refused and
    cannot pass for the wrong reason. All map to the same fail-closed published verdict
    (``RUN_UNADMITTED`` → blocks); this records the forensic cause."""

    ICV_UNSUPPORTED = "icv_unsupported"              # the plan authorizes an identity contract this build does not implement
    UNAUTHORIZED_SUBJECT = "unauthorized_subject"    # the plan's dispatch target != the governance-authorized subject
    INCOMPLETE_COORDINATES = "incomplete_coordinates"  # a measured RuntimeSubject coordinate is absent — the run is unattestable
    SUBJECT_DRIFT = "subject_drift"                  # the MEASURED subject != the subject the run was dispatched to enforce


@dataclass(frozen=True)
class AuthorizedRunPlan:
    """The pre-run authorization for a single enforcement run: WHICH policy, WHICH calibrated subject the
    run is DISPATCHED to enforce (``target_subject``), under WHICH governance-authorized context
    (``authorized_context`` = ``(set_id, authorized_subject, ICV)``, the same 3-tuple shape the restore
    controller reads via ``current_authorized_context``).

    ``target_subject`` and ``authorized_subject`` are DISTINCT operands, not a duplicated value: the former
    is the subject THIS run was dispatched to enforce, the latter is what governance authorized AT MINT (a
    static snapshot — CP1 replaces it with a LIVE governance read at the admission commit point).
    At mint they are equal; admission CHECKS that equality (a superseded / mis-minted plan whose target no
    longer matches the authorized context is refused). Keeping them separate is what lets CP1 replace
    ``authorized_context`` with a LIVE re-read so drift between mint and admission is caught — the equality
    is a checked invariant across two genuine sources, not a copy that could silently diverge.

    ``authorized_context`` is the SINGLE SOURCE for set / authorized-subject / ICV: exposed as derived
    properties, never stored as separate fields that could diverge from the tuple (STEP 1 single-source)."""

    policy_id: str
    target_subject: str                       # the calibrated-subject identity THIS run was dispatched to enforce
    authorized_context: tuple[str, str, int]  # (set_id, authorized_subject, ICV) — the governance snapshot

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
    pairing its plan with its authoritative return, so the plan can never go missing on the publication
    path. Every MEASURED coordinate is derived SOLELY from ``result.trial_report`` (never from the plan,
    never from a post-run supplementary source) — so the subject admission recomputes is a genuinely
    measured operand."""

    plan: AuthorizedRunPlan
    result: EngineRunResult

    @property
    def report(self) -> TrialReport:
        return self.result.trial_report

    def measured_coordinates(self) -> tuple[str | None, str | None, str | None, str | None]:
        """The four MEASURED RuntimeSubject coordinates, read SOLELY off the authoritative return (delegates
        to ``_measured_coordinates`` — the single derivation shared with admission's validator, so the
        coordinates admission recomputes are exactly the ones this pairing exposes)."""
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


def _evaluate_admission(plan: AuthorizedRunPlan, report: TrialReport) -> BlockingRefusal | str:
    """The ONE admission validator — the single source of the admission logic, called by BOTH
    ``admit_run_result`` (which maps a refusal to a returned ``BlockingRefusal``) AND
    ``AdmittedRunResult.__post_init__`` (which maps it to a raised ``RunAdmissionError``). Returns the
    recomputed MEASURED subject (a ``str``) on success, or a ``BlockingRefusal`` naming the layer that
    refused. Deterministic, layered, fail-closed order — each layer a DISTINCT typed ``RunAdmissionRefusal``
    so a negative cannot pass for the wrong reason:

      1. ICV — EXACT typing + equality: ``type(icv) is int and icv == IDENTITY_CONTRACT_VERSION``. A plain
         ``==`` would accept ``True`` (``True == 1``) and then compose the subject under the ``vTrue`` domain
         — so the type gate rejects a bool / str / any non-``int`` before the value gate. ICV is contract
         metadata (dissent4), not a measured coordinate; the recompute below uses it as the composite domain.
      2. AUTHORIZED SUBJECT (compare vs authorized context): the plan's dispatch ``target_subject`` must
         equal its ``authorized_subject`` (the plan's authorized SNAPSHOT). A mis-minted / superseded plan
         whose target no longer matches its snapshot is refused. (This is plan MINT-COHERENCE in CP0; CP1
         replaces the snapshot with a LIVE governance read at the admission commit point, which is what
         turns this into a currency check — until then it does NOT prove the run is authorized under the
         CURRENT governance state.)
      3. COMPLETE COORDINATES: all four MEASURED coordinates (from the authoritative return) present and
         non-empty. An unattestable run (mixed-identity / image-unresolved, ``execution_identity`` None) is
         refused REGARDLESS of its raw verdict — a Verdict from a run we cannot pin to one identity is not a
         publishable enforcement signal (it still blocks, fail-closed).
      4. SUBJECT DRIFT (compare vs plan): recompute the MEASURED subject from those four coordinates (the
         SAME composite ``calibrated_subject_identity`` the calibration path signs) and require it to equal
         the dispatched ``target_subject``. NEGATIVES mutate the MEASURED coordinate (the report), never the
         plan — a drift is a run that measured differently from its authorization."""
    # 1. identity-contract metadata — EXACT int typing THEN equality (a bool is not an int here).
    icv = plan.identity_contract_version
    if type(icv) is not int or icv != IDENTITY_CONTRACT_VERSION:
        return BlockingRefusal(
            RunAdmissionRefusal.ICV_UNSUPPORTED,
            f"plan identity_contract_version {icv!r} (type {type(icv).__name__}) is not this build's int "
            f"{IDENTITY_CONTRACT_VERSION!r} — cannot admit under a different / degenerate identity contract",
        )

    # 2. the plan's dispatch target must match its authorized SNAPSHOT (mint-coherence; CP1 makes it live).
    if plan.target_subject != plan.authorized_subject:
        return BlockingRefusal(
            RunAdmissionRefusal.UNAUTHORIZED_SUBJECT,
            f"plan target_subject {plan.target_subject!r} != authorized subject {plan.authorized_subject!r} "
            "— dispatched against a subject the plan's authorized snapshot does not authorize (CP1 adds the "
            "live governance read)",
        )

    # 3. all four MEASURED coordinates present (non-empty) — an unattestable run cannot publish a verdict.
    rpd, tpd, gpd, eid = _measured_coordinates(report)
    if not all(isinstance(c, str) and c != "" for c in (rpd, tpd, gpd, eid)):
        return BlockingRefusal(
            RunAdmissionRefusal.INCOMPLETE_COORDINATES,
            "a measured RuntimeSubject coordinate is absent "
            f"(profile={_present(rpd)} trust={_present(tpd)} guard={_present(gpd)} execution={_present(eid)}) "
            "— the run is not attestable to a single identity; fail-closed",
        )

    # 4. recompute the MEASURED subject and compare vs the dispatched target (compare vs plan).
    measured_subject = calibrated_subject_identity(rpd, tpd, gpd, eid, icv=icv)
    if measured_subject != plan.target_subject:
        return BlockingRefusal(
            RunAdmissionRefusal.SUBJECT_DRIFT,
            f"measured subject {measured_subject[:12]}.. != dispatched target "
            f"{plan.target_subject[:12]}.. — the run's identity diverged from its authorization",
        )
    return measured_subject


@dataclass(frozen=True)
class AdmittedRunResult:
    """A run result ADMITTED to publication: its MEASURED subject was recomputed from the authoritative
    return and matches BOTH the dispatched target and the governance-authorized subject. This is the ONLY
    type that authorizes posting the measured ``verdict`` as an enforcement result — the publication path
    (CP2) accepts ``AdmittedRunResult | BlockingRefusal`` and nothing else.

    ``verdict`` is a DERIVED property returning ``report.aggregate`` (the same single-source discipline as
    ``EngineRunResult.verdict``): there is NO stored copy that could diverge from the report the admission
    inspected.

    The constructor RE-RUNS the FULL admission validator (``_evaluate_admission``) against its own
    ``plan`` + ``report`` and additionally requires the stored ``measured_subject`` to equal the
    REPORT-RECOMPUTED subject — NOT merely ``measured_subject == plan.target_subject``. This closes the
    direct-construction bypass: a caller cannot hand-assemble an ``AdmittedRunResult`` whose report drifts
    (recomputes to X) while storing ``measured_subject`` = the target, because the constructor recomputes X
    from the report, sees the drift (or any other refusal layer), and raises ``RunAdmissionError``. It is a
    trusted-code construction check, not an unforgeable boundary — the SAME recompute-and-compare is the
    authority whether reached via ``admit_run_result`` or the constructor; the typestate itself is static
    cohesion (API sequencing + plan/result pairing), not an authority boundary."""

    plan: AuthorizedRunPlan
    report: TrialReport
    measured_subject: str

    def __post_init__(self) -> None:
        # defence in depth: re-run the WHOLE admission validator, not just a stored-field equality. An
        # AdmittedRunResult may exist ONLY for a run that genuinely re-admits (ICV + authorized + coords +
        # report-recomputed subject), and its stored subject must be the honestly-recomputed one.
        outcome = _evaluate_admission(self.plan, self.report)
        if isinstance(outcome, BlockingRefusal):
            raise RunAdmissionError(
                f"AdmittedRunResult constructed for an inadmissible run ({outcome.reason.value}): "
                f"{outcome.detail} — construct it via admit_run_result")
        if self.measured_subject != outcome:
            raise RunAdmissionError(
                "AdmittedRunResult.measured_subject != the subject recomputed from the report — the stored "
                "subject is not the honestly-measured one (construct it via admit_run_result)")

    @property
    def verdict(self) -> Verdict:
        # single source of truth: the admitted verdict IS the report's aggregate — no stored duplicate.
        return self.report.aggregate


def admit_run_result(unadmitted: UnadmittedRunResult) -> AdmittedRunResult | BlockingRefusal:
    """Admit ``unadmitted`` to publication, or refuse it (fail-closed) — the live-path analogue of
    ``restore_controller.attempt_restore``, POST-execution. A thin wrapper over the single admission
    validator ``_evaluate_admission`` (which the ``AdmittedRunResult`` constructor also runs, so the
    admission logic has ONE source): a refusal returns the ``BlockingRefusal`` (itself a blocking outcome);
    a success constructs the ``AdmittedRunResult`` carrying the report's aggregate verdict + the recomputed
    measured subject."""
    outcome = _evaluate_admission(unadmitted.plan, unadmitted.report)
    if isinstance(outcome, BlockingRefusal):
        return outcome
    return AdmittedRunResult(plan=unadmitted.plan, report=unadmitted.report, measured_subject=outcome)


__all__ = [
    "RunAdmissionError",
    "RunAdmissionRefusal",
    "AuthorizedRunPlan",
    "UnadmittedRunResult",
    "BlockingRefusal",
    "AdmittedRunResult",
    "admit_run_result",
]
