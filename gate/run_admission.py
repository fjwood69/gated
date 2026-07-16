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

VALIDATION SPLIT + RESULT-BOUND PROOF. ``_validate_structural`` is PURE (ICV typing, mint coherence,
coordinate completeness, measured-recompute == target) — re-runnable, so ``AdmittedRunResult``'s constructor
re-runs it (closing the report-recomputed-subject forge). The LIVE currency checks require I/O and are
``admit_run_result``'s alone (a frozen constructor cannot redo I/O). To stop a DIRECT construction from
fabricating an admission, ``AdmittedRunResult`` derives its metadata from a RESULT-BOUND
``_LiveAdmissionProof`` — a FRESH instance minted (via ``_mint_live_admission_proof``, called only by
``admit_run_result`` after the live checks) carrying the live-read ``(policy_id, set_id, oracle_head,
subject)``. It is NOT a reusable singleton and there are NO caller-supplied metadata fields: the constructor
verifies the proof coheres with the run (same policy; subject == the report-recomputed subject), so a proof
minted for one run cannot admit another and metadata cannot be forged. An in-process call-path convention
(the structural no-bypass test asserts ``_mint_live_admission_proof`` is called only from
``admit_run_result``), not an unforgeable boundary. Gate-side: imports the engine's authoritative return +
the attestation identity function + core; ``core`` and the engine runner never import this.
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
    """An ``AdmittedRunResult`` was constructed incoherently — without a valid live-admission proof, or with a
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
    published verdict is uniformly ERROR regardless of layer (the layer is not leaked to the merge UI).

    ``sub_reason`` (CP2 board C3) is OPERATIONAL LEGIBILITY only — not a safety distinction (every refusal
    blocks identically). It disambiguates the coarse ``LIVE_ATTESTATION_UNAVAILABLE`` / ``ORACLE_UNAVAILABLE``
    layers so an operator can tell a store outage (``store_unreachable`` — the read raised) from an absent
    attestation (``attestation_absent`` — ``current_attestation`` returned None: the policy is not ENABLED OR
    its contract drifted). The production governance view (``PolicyStore.current_attestation``) returns only
    tuple-or-None, so it CANNOT atomically distinguish ``policy_not_enabled`` from ``icv_mismatch`` (both
    collapse to None); a finer split would need a dedicated atomic diagnostic store API (named-next) and must
    NOT be manufactured through a second racy read. Empty for the structural layers (already precise via
    ``reason``)."""

    reason: RunAdmissionRefusal
    detail: str
    sub_reason: str = ""

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


_PROOF_MINT = object()  # module-private mint sentinel — the proof constructor refuses any other key


@dataclass(frozen=True)
class _LiveAdmissionProof:
    """RESULT-BOUND proof that ``admit_run_result`` ran the LIVE governance-currency checks FOR THIS RUN.
    NOT a reusable singleton: a FRESH instance is minted (by ``_mint_live_admission_proof``) only AFTER the
    live checks pass, carrying the exact live-read metadata — ``(policy_id, set_id, oracle_head, subject)`` —
    AND the EXACT FROZEN ``plan`` + ``report`` it was minted for (CP2 board P1-B). ``AdmittedRunResult``
    DERIVES its public metadata from this proof (never from caller-supplied fields) and verifies the proof
    coheres with the run — same policy, subject == the report-recomputed subject, AND ``proof.plan == plan``
    and ``proof.report == report`` — so a legitimately-minted proof cannot be RE-USED to admit a DIFFERENT
    run: a different report (same subject, different verdict) or a different plan (same policy/subject,
    different authorized set) both change the bound object and fail construction.

    Its constructor refuses any key but the module-private ``_PROOF_MINT`` sentinel, so a caller outside this
    module cannot construct one. In-process call-path convention (the structural no-bypass test asserts
    ``_mint_live_admission_proof`` is CALLED only from ``admit_run_result``), NOT an unforgeable boundary —
    the load-bearing control is that ``admit_run_result`` actually ran the live reads before minting."""

    policy_id: str
    set_id: str
    oracle_head: str
    subject: str
    plan: AuthorizedRunPlan   # the plan this proof was minted for — VALUE-exact (dataclass ==), not identity (P1-B)
    report: TrialReport       # the report this proof was minted for — VALUE-exact (dataclass ==), not identity (P1-B)
    mint: InitVar[object] = None

    def __post_init__(self, mint: object) -> None:
        if mint is not _PROOF_MINT:
            raise RunAdmissionError(
                "_LiveAdmissionProof cannot be constructed outside gate.run_admission "
                "(mint it via admit_run_result's live checks)")


def _mint_live_admission_proof(
    *, policy_id: str, set_id: str, oracle_head: str, subject: str,
    plan: AuthorizedRunPlan, report: TrialReport,
) -> _LiveAdmissionProof:
    """The SOLE mint of a live-admission proof — called ONLY by ``admit_run_result`` (structural no-bypass
    test), only AFTER every live governance-currency check has passed, binding the live-read result AND the
    exact plan + report it admitted (P1-B: the proof cannot be re-paired with a different run)."""
    return _LiveAdmissionProof(
        policy_id=policy_id, set_id=set_id, oracle_head=oracle_head, subject=subject,
        plan=plan, report=report, mint=_PROOF_MINT)


@dataclass(frozen=True)
class AdmittedRunResult:
    """A run result ADMITTED to publication: its MEASURED subject was recomputed from the authoritative
    return and matches the dispatched target (structural), AND the run was proven CURRENT against live
    governance (the set is unchanged and the subject is still authorized). The ONLY type that authorizes
    posting the measured ``verdict`` — the publication path (CP2) accepts ``AdmittedRunResult |
    BlockingRefusal`` and nothing else.

    ``verdict`` is a DERIVED property returning ``report.aggregate`` (no stored copy to diverge). The
    admission METADATA (``admitted_set_id`` + ``bound_oracle_head`` + ``measured_subject``, the admitted
    subject) are DERIVED PROPERTIES of the result-bound ``_LiveAdmissionProof`` — never caller-supplied
    fields — so a caller cannot fabricate the SCOPED live governance the run was admitted against.

    Construction is PROOF-GATED by a RESULT-BOUND proof: the ``_proof`` must be a ``_LiveAdmissionProof``
    (which only ``_mint_live_admission_proof`` — called only by ``admit_run_result`` after the live checks —
    can construct), and the constructor verifies proof↔run COHERENCE: the pure ``_validate_structural`` still
    re-runs (closing the report-recompute forge), the proof's ``policy_id`` must equal the plan's, and the
    proof's ``subject`` must equal the report-recomputed subject. So a proof minted for one run cannot admit
    a different one, and there are no caller-supplied metadata fields to forge. The live governance authority
    is ``admit_run_result`` alone (a frozen constructor cannot redo I/O); this is a trusted-code call-path
    convention, not an unforgeable boundary."""

    plan: AuthorizedRunPlan
    report: TrialReport
    _proof: _LiveAdmissionProof

    def __post_init__(self) -> None:
        # re-run the PURE structural validator (closes the report-recompute forge) ...
        outcome = _validate_structural(self.plan, self.report)
        if isinstance(outcome, BlockingRefusal):
            raise RunAdmissionError(
                f"AdmittedRunResult failed structural re-validation ({outcome.reason.value}): "
                f"{outcome.detail} — construct it via admit_run_result")
        # ... then bind the RESULT proof to THIS run: same policy, the admitted subject IS the
        # report-recomputed subject, AND (P1-B) the proof is bound to the EXACT plan + report — a
        # legitimately-minted proof cannot be re-paired with a different run (a different report with the
        # same subject but a different verdict, or a different plan with the same policy/subject but a
        # different authorized set, both change the bound object and are refused here).
        if self._proof.policy_id != self.plan.policy_id:
            raise RunAdmissionError(
                f"live-admission proof policy_id {self._proof.policy_id!r} != plan.policy_id "
                f"{self.plan.policy_id!r} — the proof was minted for a different policy")
        if self._proof.subject != outcome:
            raise RunAdmissionError(
                "live-admission proof subject != the subject recomputed from the report — the proof was "
                "minted for a different run (construct it via admit_run_result)")
        if self._proof.plan != self.plan:
            raise RunAdmissionError(
                "live-admission proof is bound to a DIFFERENT plan than this result — the proof was minted "
                "for another run (construct it via admit_run_result)")
        if self._proof.report != self.report:
            raise RunAdmissionError(
                "live-admission proof is bound to a DIFFERENT report than this result — the proof was minted "
                "for another run (construct it via admit_run_result)")
        # the live-read set the proof carries MUST be the plan's authorized set (admit_run_result proved
        # plan.authorized_set == live_set_id before minting; assert it so a direct construction cannot pair a
        # proof from set A with a plan authorizing set B).
        if self._proof.set_id != self.plan.authorized_set:
            raise RunAdmissionError(
                f"live-admission proof set_id {self._proof.set_id!r} != plan.authorized_set "
                f"{self.plan.authorized_set!r} — the proof was minted against a different set")

    @property
    def measured_subject(self) -> str:
        # the admitted subject IS the proof's subject (== report-recomputed == dispatched target).
        return self._proof.subject

    @property
    def admitted_set_id(self) -> str:
        return self._proof.set_id

    @property
    def bound_oracle_head(self) -> str:
        return self._proof.oracle_head

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
    # ``structural`` is now the recomputed MEASURED subject (== plan.target_subject, proven).

    # --- LIVE governance currency: admission's OWN reads, fail-closed on None/exception ---
    try:
        attestation = governance.current_attestation(plan.policy_id)
    except Exception as exc:  # a broken chain / unreachable store — never a silent pass
        return BlockingRefusal(
            RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE,
            f"live attestation read failed for {plan.policy_id!r} ({type(exc).__name__}) — fail-closed",
            sub_reason="store_unreachable")
    if attestation is None:
        return BlockingRefusal(
            RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE,
            f"{plan.policy_id!r} has no current ENABLED attestation — not admissible (fail-closed)",
            sub_reason="attestation_absent")
    live_set_id, bound_head, live_subject = attestation

    # set continuity FIRST — BEFORE the oracle query — so a moved set + an unavailable oracle is classified
    # as AUTHORIZED_SET_MOVED, not ORACLE_UNAVAILABLE (forensic ordering). The plan's authorized set must be
    # the policy's live attestation set (a different-set governance rebind must not admit an old plan).
    if plan.authorized_set != live_set_id:
        return BlockingRefusal(
            RunAdmissionRefusal.AUTHORIZED_SET_MOVED,
            f"plan authorized set {plan.authorized_set!r} != the live attestation set {live_set_id!r} — a "
            "different-set governance rebind cannot admit an old plan")

    try:
        live_head = governance.oracle_head_for(live_set_id)
    except Exception as exc:
        return BlockingRefusal(
            RunAdmissionRefusal.ORACLE_UNAVAILABLE,
            f"live set_head read failed for {live_set_id!r} ({type(exc).__name__}) — fail-closed",
            sub_reason="store_unreachable")
    if live_head is None:
        return BlockingRefusal(
            RunAdmissionRefusal.ORACLE_UNAVAILABLE,
            f"cannot resolve the live set_head for {live_set_id!r} — fail-closed",
            sub_reason="unresolved")
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

    # every live check passed — mint a FRESH result-bound proof carrying the live-read values AND bound to
    # the exact plan + report (P1-B), and derive the admitted metadata from it (no caller-supplied metadata).
    proof = _mint_live_admission_proof(
        policy_id=plan.policy_id, set_id=live_set_id, oracle_head=live_head, subject=live_subject,
        plan=plan, report=unadmitted.report)
    return AdmittedRunResult(plan=plan, report=unadmitted.report, _proof=proof)


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
