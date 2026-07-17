"""gate/gatekeeper.py — 3.3: the tier-gatekeeper. Where calibration state binds a check's tier.

Two jobs, both gate-side (this MAY import engine — engine⊥gate is one-directional; the gate is the
top layer):

  1. RESOLVE DISPOSITION (per PR, per policy): read the live tier from the ``PolicyStore``; if the
     store is unreachable, fall back to the signed, IDENTITY-BOUND snapshot; if neither can attest,
     fail CLOSED (UNATTESTABLE -> action_required). This is the seam the dispatcher consults BEFORE
     running the engine — a non-ENABLED (or un-attestable) policy never reaches the sandbox.
     UNATTESTABLE is a TRANSIENT health condition, not a durable tier — a store blip appends NO
     record; durable DEGRADED (proven calibration loss) is reserved for 3.5.

  2. ENABLE-PATH (shadow-first, human-gated): ``run_calibration`` runs the 3.2 BATCH calibrator
     against the out-of-band CalibrationSet and returns the report (the SHADOW RECORD) WITHOUT
     enabling — on failure it records CALIBRATING->REJECTED with the breaking fixtures named
     (legible refuse). A human then reviews the report and calls ``ratify_enable``, the
     approval-gated CALIBRATING->ENABLED transition anchored to the calibration result + fixture-set
     version + detector identity (addition #3). The human gate sits BETWEEN the two calls.

Fail-closed everywhere: a tampered tier chain (ChainIntegrityError) blocks; an unreachable store
with no trustworthy snapshot blocks; a snapshot whose detector identity does not match the detector
about to run blocks (addition #1). Only a live ENABLED state (or a fresh, HMAC-valid,
identity-matching snapshot) runs the engine.

3.3 does NOT own re-calibration triggers or the C3 feedback loop (3.5) — and it deliberately does
NOT import ``gate.ledger`` (the C3 override ledger), so there is structurally no automatic
C3-event -> tier-write path (a done-test asserts the absent import).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable

from core import ResourceBudget, Sandbox
from engine.calibration import (
    BackendGuard,
    BundleResolver,
    CalibrationResult,
    DEFAULT_CALIBRATION_TRIALS,
)
from engine.observation_trust import TrustPolicy
from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.authority import GovernanceApproval
from gate.calibration_identity import calibration_result_ref
from gate.calibration_store import CalibrationStore
from gate.candidate_measurement import (
    WitnessInconsistencyError,
    prepare_candidate,
    produce_candidate_measurement,
)
from gate.policy_state import Disposition, PolicyState, disposition_for
from gate.policy_store import ChainIntegrityError, IntentSatisfyOutcome, PolicyStore
from gate.preflight import ConfigurationError
from gate.run_admission import AuthorizedRunPlan
from gate.snapshot import (
    CalibrationSnapshot,
    SnapshotError,
    attested_record,
    is_provisionable,
    verify_snapshot,
)

# Exceptions that mean "the tier store could not be reached" (vs "the chain is tampered", which is
# ChainIntegrityError and always blocks). A networked/locked store surfaces these; the gatekeeper
# then falls to the signed snapshot. Unreachable is a TRANSIENT availability condition — it appends
# no durable state.
_UNREACHABLE = (sqlite3.OperationalError, OSError)


class GateDecisionError(Exception):
    """A GateDecision was assembled incoherently — RUN_ENFORCING without an AuthorizedRunPlan, or a
    non-RUN disposition carrying one. Raised at construction so an incoherent decision cannot exist for the
    dispatcher to act on (CP2 invariant)."""


@dataclass(frozen=True)
class GateDecision:
    """The dispatcher-facing outcome: what to do, the durable state it was based on (None if the
    decision came from a transient/unattestable condition), why, the source, and (CP2) the pre-run
    ``AuthorizedRunPlan`` the run is dispatched under.

    INVARIANT (CP2, enforced in ``__post_init__``): ``disposition is RUN_ENFORCING`` iff ``plan is not
    None``. Only an enforcing decision carries a plan (minted from the SAME governance snapshot that decided
    to enforce, so mint-coherence holds by construction); every non-run disposition carries ``None``. The
    dispatcher therefore never has to synthesise a plan. (An unplanned enforce cannot arise from a
    WELL-FORMED ``GateDecision``; a forged decision-shaped object is caught by the dispatch-time recheck in
    ``make_gated_job_runner`` — the first plan consumer — not by this constructor.)"""

    disposition: Disposition
    state: PolicyState | None
    reason: str
    source: str  # "live" | "snapshot" | "unattestable"
    plan: AuthorizedRunPlan | None = None

    def __post_init__(self) -> None:
        enforcing = self.disposition is Disposition.RUN_ENFORCING
        if enforcing and self.plan is None:
            raise GateDecisionError(
                "a RUN_ENFORCING decision must carry an AuthorizedRunPlan (CP2 invariant)")
        if not enforcing and self.plan is not None:
            raise GateDecisionError(
                f"a {self.disposition.value} decision must NOT carry an AuthorizedRunPlan (CP2 invariant)")


def _unattestable(reason: str) -> GateDecision:
    """Transient: the tier cannot be attested right now -> block-and-flag (action_required). NOT a
    durable DEGRADED (no record is written); a formerly-enabled check blocks rather than
    silent-neutral or stale-enforce (#1). Durable DEGRADED is 3.5."""
    return GateDecision(Disposition.BLOCK_ACTION_REQUIRED, None, reason, "unattestable")


def resolve_disposition(
    policy_id: str,
    *,
    store: PolicyStore,
    snapshot: CalibrationSnapshot | None,
    snapshot_key: bytes,
    now: float,
    oracle_head_for: Callable[[str], str | None],
) -> GateDecision:
    """Decide the dispatcher's action for ``policy_id``. Order: live store -> signed snapshot ->
    fail-closed UNATTESTABLE. A tampered chain blocks immediately (never falls back — a tamper is
    worse than an outage).

    CP2 S5 (identity treatment): the pre-run DECLARED-detector-identity comparison is REMOVED. The
    4-coordinate runtime subject is UNMEASURABLE before the run, so a pre-run ``expected_detector_identity``
    could only be a declared (spoofable) or tautological operand. The plan's ``target_subject`` is minted
    from the live/snapshot attestation, and the AUTHORITY that the run actually executed that identity is
    the POST-run ``SUBJECT_DRIFT`` check in ``admit_run_result`` (measured composite, from the authoritative
    engine return, == the dispatched target). The boot-time detector-registry PROFILE validation
    (``assert_detector_registered``) is unchanged and orthogonal.

    close-3: a live ENABLED policy is enforced ONLY if its calibration's bound set-head still equals
    the CURRENT set-head (``oracle_head_for(set_id)``). A fixture append to that set moves the head,
    so the policy immediately goes UNATTESTABLE (transient action_required) until 3.5 re-calibrates —
    SCOPED, so an append to set X never touches policies on set Y. Unknown set membership fails
    CLOSED (a policy whose set can't be resolved is not attestable)."""
    try:
        state = store.current_state(policy_id)
    except ChainIntegrityError:
        return _unattestable(
            "tier-transition chain failed verification — refusing to attest any tier"
        )
    except _UNREACHABLE:
        return _from_snapshot(
            policy_id, snapshot=snapshot, key=snapshot_key, now=now, oracle_head_for=oracle_head_for,
        )

    if state is None:
        return GateDecision(
            Disposition.SKIP_NEUTRAL, None, "no policy configured for this check", "live"
        )
    if state is PolicyState.ENABLED:
        return _enforce_if_oracle_current(
            policy_id, store=store, oracle_head_for=oracle_head_for,
        )
    return GateDecision(disposition_for(state), state, f"live state {state.value}", "live")


def _enforce_if_oracle_current(
    policy_id: str,
    *,
    store: PolicyStore,
    oracle_head_for: Callable[[str], str | None],
) -> GateDecision:
    """A live ENABLED policy enforces only if its calibration's bound set-head equals the current
    set-head (scoped oracle invalidation — an append to the policy's set moves the head ->
    UNATTESTABLE; close-3).

    CP2 S5: the pre-run DECLARED-detector-identity comparison is REMOVED (see ``resolve_disposition``).
    The run's actual 4-coordinate identity is unknowable until it runs; a build / host-closure / image /
    eval drift is caught POST-run by ``admit_run_result``'s ``SUBJECT_DRIFT`` (the measured composite,
    off the authoritative engine return, must equal the dispatched target the plan minted from THIS
    attestation) — not by a spoofable pre-run declaration."""
    # CP2: read the SINGLE chain-verified snapshot ``(set_id, bound_head, subject, ICV, generation)`` — the
    # same row the AuthorizedRunPlan mints from, so the oracle check and the mint share ONE governance view.
    snap = store.current_attestation_snapshot(policy_id)
    if snap is None:
        return _unattestable("ENABLED policy has no calibration attestation to check the oracle head")
    set_id, bound_head, bound_identity, icv, generation = snap
    current_head = oracle_head_for(set_id)
    if current_head is None:
        return _unattestable(f"unknown calibration set membership for {set_id!r} — failing closed")
    if current_head != bound_head:
        return _unattestable(
            f"oracle set {set_id!r} has grown since calibration (head {bound_head[:12]}.. -> "
            f"{current_head[:12]}..) — re-calibration pending"
        )
    # S3-completion — ABA close: the snapshot read and the (separate, non-atomic) oracle read above are two
    # reads across two stores. ``set_head`` is a CURRENT-membership digest, so it can ABA (a deprecate→re-add
    # returns an earlier head); a policy could have left ENABLED (an APPEND that moves its generation) while
    # the set membership returned to ``bound_head``, and the oracle check would wrongly pass. Re-read the
    # policy's MONOTONIC generation (``policy_head`` = record_hash of its head row; because the tier chain is
    # APPEND-ONLY — no mutate/delete path — and ``record_hash`` is collision-resistant, a value never repeats
    # once a new record is appended) AFTER the oracle read: if it is unchanged, no transition occurred across
    # [snapshot, re-read], so the same ENABLED generation covered the bracketed oracle observation. A move ->
    # UNATTESTABLE. (A direct-DB tail-truncation that reverts the generation is the deploy-tier adversary, out
    # of the in-process model.)
    if store.policy_head(policy_id) != generation:
        return _unattestable(
            f"policy {policy_id!r} generation {generation[:12]}.. was not stable across the oracle read — "
            "the policy tier moved, so its currency cannot be confirmed; re-dispatch against fresh governance"
        )
    # mint the pre-run plan from the SAME snapshot: mint-coherence (target_subject == authorized_subject ==
    # the bound subject) holds BY CONSTRUCTION, and set/ICV come from the one row (no read-between-reads).
    # admit_run_result re-reads live governance POST-run as the authority; this is the dispatched intent.
    plan = AuthorizedRunPlan(policy_id, target_subject=bound_identity,
                             authorized_context=(set_id, bound_identity, icv))
    return GateDecision(Disposition.RUN_ENFORCING, PolicyState.ENABLED,
                        f"live ENABLED, oracle set {set_id!r} current", "live", plan=plan)


def _from_snapshot(
    policy_id: str,
    *,
    snapshot: CalibrationSnapshot | None,
    key: bytes,
    now: float,
    oracle_head_for: Callable[[str], str | None],
) -> GateDecision:
    """Store unreachable -> consult the signed snapshot. Fresh + HMAC-valid + PROVISIONABLE +
    ORACLE-CURRENT -> enforce. Missing / tampered / stale snapshot, a policy ABSENT from an
    otherwise-valid snapshot, a non-provisionable record, OR (close-4) an oracle-head DRIFT ->
    UNATTESTABLE.

    CP2 S5: the pre-run DECLARED-detector-identity comparison is REMOVED here too (symmetric with the
    live path). The plan's ``target_subject`` is minted from the snapshot record; the run's actual
    identity is validated POST-run by ``admit_run_result``'s ``SUBJECT_DRIFT``.

    close-4 oracle-freshness: the tier store being unreachable does NOT mean the CALIBRATION store
    is — if it is reachable, the fallback compares the snapshot's attested ``oracle_head`` for the
    policy's set to the CURRENT ``set_head`` and blocks on drift, exactly as the live path does. Only
    when the calibration store is ALSO unreachable (oracle_head_for -> None) does the fallback trust
    the snapshot's attested head, bounded by the freshness horizon (outage-freshness)."""
    if snapshot is None:
        return _unattestable("tier store unreachable and no signed snapshot available")
    try:
        verify_snapshot(snapshot, key=key, now=now)
    except SnapshotError as exc:
        return _unattestable(f"tier store unreachable and snapshot untrusted: {exc}")
    record = attested_record(snapshot, policy_id)
    if record is None:
        # gap-2: absence from a valid snapshot is INDISTINGUISHABLE from an incomplete mint. During
        # an outage we cannot prove "not enabled" vs "dropped by a partial mint", so we fail CLOSED.
        return _unattestable(
            "store unreachable; policy absent from snapshot — cannot distinguish not-enabled from "
            "an incomplete mint, failing closed"
        )
    # close-4: oracle-head drift on the fallback path (calibration store still reachable).
    current_head = oracle_head_for(record.set_id)
    if current_head is not None and current_head != record.oracle_head:
        return _unattestable(
            f"store unreachable; snapshot oracle set {record.set_id!r} drifted since mint "
            f"({record.oracle_head[:12]}.. -> {current_head[:12]}..) — re-calibration pending"
        )
    # CP2: the record must be PROVISIONABLE under the CURRENT identity contract to mint a plan — a legacy v2
    # snapshot, an ICV mismatch, or a record not bound to this snapshot CANNOT authorise a current-contract
    # run. Not provisionable -> UNATTESTABLE (an old artifact proves the past; it cannot dictate current
    # authority). ``record`` IS the snapshot's own entry (attested_record), so the binding check holds here.
    if not is_provisionable(snapshot, record, current_icv=IDENTITY_CONTRACT_VERSION):
        return _unattestable(
            f"store unreachable; snapshot record for {policy_id!r} is not provisionable under the current "
            "identity contract (legacy schema or ICV mismatch) — cannot mint an enforcement plan"
        )
    plan = AuthorizedRunPlan(
        policy_id, target_subject=record.detector_identity,
        authorized_context=(record.set_id, record.detector_identity, record.identity_contract_version))
    return GateDecision(
        Disposition.RUN_ENFORCING, PolicyState.ENABLED,
        f"store unreachable; snapshot attests ENABLED for {record.detector_identity!r}", "snapshot",
        plan=plan,
    )


# ---------------------------------------------------------------------------------------------
# Enable path — shadow-first, human-gated. run_calibration produces the shadow record; a human
# reviews it and calls ratify_enable (the approval-gated, anchored grant). The two-call split IS
# the gate.
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CalibrationOutcome:
    """The shadow record a human reviews before ratifying. ``breaking_fixtures`` names EXACTLY what
    refused enablement (legible refuse) — a developer sees which fixture broke it, not a wall.
    ``calibration_result_ref`` (present only on PASS) is the handle a human passes to
    ``ratify_enable`` — it points at the PERSISTED PASS the store binds ENABLED to (gap-1)."""

    policy_id: str
    passed: bool
    report: str
    breaking_fixtures: tuple[str, ...]
    result: CalibrationResult
    calibration_result_ref: str | None


def run_calibration(
    policy_id: str,
    *,
    store: PolicyStore,
    calibration_store: CalibrationStore,
    make_sandbox: Callable[[], Sandbox],
    detector_id: str,
    resolve: BundleResolver,
    budget: ResourceBudget,
    approval: GovernanceApproval,
    set_id: str = "default",
    trials: int = DEFAULT_CALIBRATION_TRIALS,
    backend_guard: BackendGuard,
    trust_policy: TrustPolicy,
) -> CalibrationOutcome:
    """Run the 3.2 BATCH calibrator (shadow-first — full fixture distribution, zero live-PR cost)
    against the SNAPSHOT-SEALED calibration set, and record the state move. Records PENDING->CALIBRATING;
    on FAIL records CALIBRATING->REJECTED with the breaking fixtures in the (tamper-evident) reason;
    on PASS PERSISTS a calibration_pass attestation (the thing ENABLED binds to, gap-1) and LEAVES
    the policy at CALIBRATING (awaiting human ratify). It NEVER enables — enabling is
    ``ratify_enable`` (the human gate).

    v4 P1-a (fold): the enable path no longer trusts a CALLER identity. The calibration_pass binds the
    MEASUREMENT-DERIVED subject — H(resolved_profile_digest, execution_identity) from the SAME calibration
    run, exactly as ``run_recalibration`` — so governance later chooses WHICH persisted pass to ratify but
    cannot define what code it ran.

    3.5 S3-completion CP4 Slice B: the set head is now MEASURED, not declared. run_calibration SEALS the
    set from the ``CalibrationStore`` (one consistent read → ``oracle_head`` + fixtures) and binds
    EVERYTHING — the CALIBRATING intent, the persisted pass, the result ref — to ``sealed.oracle_head``,
    so no caller can record a pass under a head that never co-existed with the fixtures scored. Measurement
    flows through the shared ``candidate_measurement`` spine (prepare → produce), so this path and the
    signed re-calibration runner measure IDENTICALLY and cannot diverge."""
    # SINGLE SEAL: one consistent read yields the fixtures + the MEASURED oracle head. resolve-BEFORE-intent
    # (prepare_candidate resolves the bundle ONCE and captures the policy witnesses) so enter_calibrating's
    # expected-profile digest and the calibration run share one resolution — never resolve-twice. A drifted /
    # unregistered detector raises here (before CALIBRATING is entered) — fail-closed, nothing recorded.
    sealed = calibration_store.seal_set(set_id)
    prepared = prepare_candidate(
        sealed, resolve=resolve, detector_id=detector_id,
        trust_policy=trust_policy, backend_guard=backend_guard,
    )
    # ALL routing digests come from the ONE prepared context — never a SECOND live read of the mutable
    # trust/guard objects between preparation and intent creation (which could shift durable routing under
    # us). Validate each prepared witness is present + non-empty (a None guard witness = a digestless
    # backend guard → unroutable) BEFORE entering CALIBRATING; fail-closed on any absence.
    prof_w, trust_w, guard_w = prepared.profile_witness, prepared.trust_witness, prepared.guard_witness
    if not prof_w or not trust_w or not guard_w:
        raise ConfigurationError(
            "run_calibration: a prepared routing witness is absent "
            f"(profile={prof_w!r}, trust={trust_w!r}, guard={guard_w!r}) — an intent with a null routing "
            "coordinate is unroutable (fail-closed)")
    # enter CALIBRATING via the atomic enter_calibrating (tier transition + the re-calibration RECOVERY
    # INTENT in one transaction), so a crash between the transition and the run cannot strand the policy
    # (the ENABLED-only relay would never re-trigger it). The intent carries model-(b) ROUTING (detector
    # registry name + expected profile/trust/guard digests the worker verifies boot objects against) bound
    # to the MEASURED head — all from the prepared witnesses; the four-tuple is MEASURED by the run.
    store.enter_calibrating(
        policy_id, approval=approval, set_id=set_id, pinned_set_version=sealed.oracle_head,
        detector_id=detector_id, expected_profile_digest=prof_w,
        expected_trust_policy_digest=trust_w, expected_guard_policy_digest=guard_w,
        identity_contract_version=IDENTITY_CONTRACT_VERSION,
    )
    # REQUIRE the active intent (fail-closed on None): a lost intent must not silently skip provenance
    # verification or completion. Its fence coordinates are captured for the sync completion CAS (nothing
    # advances it during the synchronous run — no relay is scanning — so the coordinates are stable).
    _intent = store.active_intent(policy_id)
    if _intent is None:
        raise ConfigurationError(
            f"run_calibration: no active re-calibration intent for {policy_id} after enter_calibrating — "
            "fail-closed (a lost intent must not silently skip verification/completion)")
    # the shared spine calibrates against the sealed fixtures with the frozen bundle and runs the WITNESS
    # self-consistency check (measured vs the digests captured BEFORE the run). A mid-run mutation of the
    # applied trust/guard object — which the prepare-then-enter read ordering would otherwise let the
    # intent's expected digest absorb — is caught HERE; surface it as this path's fail-closed ConfigurationError.
    try:
        measurement = produce_candidate_measurement(
            prepared, make_sandbox=make_sandbox, budget=budget,
            backend_guard=backend_guard, trust_policy=trust_policy, trials=trials,
        )
    except WitnessInconsistencyError as exc:
        raise ConfigurationError(
            f"post-run verify (witness): a measured policy coordinate diverged from the pre-run witness — "
            f"the applied object mutated during calibration ({exc}); refusing to record a wrong-policy run"
        ) from exc
    result = measurement.result
    breaking = (*result.fn_failures, *result.fp_failures, *result.flaky, *result.harness_errors)
    rpd = measurement.resolved_profile_digest
    tpd = measurement.trust_policy_digest
    gpd = measurement.guard_policy_digest
    # cross-process defence-in-depth — the run's MEASURED profile/trust/guard digests MUST equal the DURABLE
    # intent's EXPECTED digests (whenever all three were measured, PASS or FAIL alike). Orthogonal to the
    # witness check above (which compares against the in-process prepare-time capture): this compares against
    # what the intent was ROUTED for, the check the async worker (Slice C) relies on when its boot objects are
    # not the ones prepare captured. Fail-closed on any divergence — a wrong-policy run is never recorded.
    if rpd is not None and tpd is not None and gpd is not None and (rpd, tpd, gpd) != (
        str(_intent["expected_profile_digest"]), str(_intent["expected_trust_policy_digest"]),
        str(_intent["expected_guard_policy_digest"])):
        raise ConfigurationError(
            "post-run verify: the run's MEASURED profile/trust/guard digests do not match the intent's "
            "EXPECTED digests — a wrong-policy run (fail-closed)")
    ref: str | None = None
    _fence = dict(policy_generation=str(_intent["policy_generation"]),
                  target_revision=int(_intent["target_revision"]), target_head=str(_intent["target_head"]))
    if result.passed:
        subject = measurement.subject_identity
        if subject is None:
            # a clean pass implies all four RuntimeSubject coordinates (profile/trust/guard/execution) —
            # fail-closed rather than persist an un-attributable pass.
            raise ConfigurationError(
                "a PASSED calibration lacked one of the four runtime-subject coordinates "
                "(resolved-profile / trust-policy / guard-policy / execution identity) — cannot derive the "
                "measured subject; refusing to persist an un-attributable pass")
        # the pass binds the MEASURED head (sealed.oracle_head), never a caller-declared version.
        ref = calibration_result_ref(
            policy_id, sealed.oracle_head, subject,
            passed=result.passed, n_bad=len(result.outcomes),
            fixture_ids=[o.fixture_id for o in result.outcomes],
        )
        # UNIFIED completion (CP4 Slice C, board): the pass record AND the intent satisfy are ONE atomic
        # store transaction (satisfy_intent_with_pass) — the SAME primitive the async worker uses — so no
        # record-then-mark ordering hole can orphan a pass. No relay advances the intent during a synchronous
        # run, so STALE (the completion CAS missed) means an unexpected concurrent supersede/advance →
        # fail-closed. SATISFIED (or the idempotent ALREADY_SATISFIED) is the success path.
        outcome = store.satisfy_intent_with_pass(
            policy_id, calibration_result_ref=ref, pinned_set_version=sealed.oracle_head,
            detector_identity=subject, identity_contract_version=IDENTITY_CONTRACT_VERSION, set_id=set_id,
            **_fence,  # type: ignore[arg-type]
        )
        if outcome is IntentSatisfyOutcome.STALE:
            raise ConfigurationError(
                f"sync completion CAS missed for {policy_id} — the intent was superseded/advanced during a "
                "synchronous calibration (fail-closed; unexpected concurrency)")
    else:
        # deterministic FAIL → transition REJECTED directly. The REJECTED transition ATOMICALLY supersedes
        # the active intent. NO failed_detector on the SYNC path: a REJECTED policy never receives set-change
        # triggers, so a failed_detector intent would be a dead state — failed_detector is the WORKER path
        # (Slice C), where the policy stays CALIBRATING.
        store.transition(
            policy_id, PolicyState.REJECTED, approval=approval,
            pinned_set_version=sealed.oracle_head,
        )
    return CalibrationOutcome(
        policy_id=policy_id, passed=result.passed, report=result.report(),
        breaking_fixtures=breaking, result=result, calibration_result_ref=ref,
    )


def ratify_enable(
    policy_id: str,
    *,
    store: PolicyStore,
    approval: GovernanceApproval,
    calibration_result_ref: str,
    pinned_set_version: str,
) -> int:
    """The human-gated CALIBRATING->ENABLED grant, ANCHORED to a PERSISTED PASS (addition #3 + gap-1).

    v4 P1-a: governance chooses WHICH persisted pass to ratify (the ``calibration_result_ref``) but does
    NOT supply the identity — the store RECOVERS the measurement-derived subject bound to that ref and
    enables THAT. A caller can no longer rewrite the enabled identity; a fabricated ref recovers no subject
    and cannot enable. ``approval`` carries the ratifier principal(s). The store enforces the legal edge
    (state must be CALIBRATING)."""
    binding = store.pass_binding(calibration_result_ref, policy_id, pinned_set_version)
    if binding is None:
        raise ConfigurationError(
            f"no persisted calibration_pass matches ref={calibration_result_ref!r} for "
            f"({policy_id}, set={pinned_set_version}) — a fabricated reference cannot enable")
    subject, set_id = binding  # S3 ckpt4-fix2c: the set_id is measurement-derived (from the pass), so the
    # ENABLED record binds the set the RUN calibrated against — not a caller-supplied value.
    return store.transition(
        policy_id, PolicyState.ENABLED, approval=approval,
        calibration_result_ref=calibration_result_ref, set_id=set_id,
        pinned_set_version=pinned_set_version,
        detector_identity=subject, identity_contract_version=IDENTITY_CONTRACT_VERSION,
    )


__all__ = [
    "GateDecision",
    "resolve_disposition",
    "CalibrationOutcome",
    "run_calibration",
    "ratify_enable",
]
