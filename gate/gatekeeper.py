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
from gate.policy_store import ChainIntegrityError, PolicyStore
from gate.preflight import ConfigurationError
from gate.snapshot import CalibrationSnapshot, SnapshotError, attested_record, verify_snapshot

# Exceptions that mean "the tier store could not be reached" (vs "the chain is tampered", which is
# ChainIntegrityError and always blocks). A networked/locked store surfaces these; the gatekeeper
# then falls to the signed snapshot. Unreachable is a TRANSIENT availability condition — it appends
# no durable state.
_UNREACHABLE = (sqlite3.OperationalError, OSError)


@dataclass(frozen=True)
class GateDecision:
    """The dispatcher-facing outcome: what to do, the durable state it was based on (None if the
    decision came from a transient/unattestable condition), why, and the source."""

    disposition: Disposition
    state: PolicyState | None
    reason: str
    source: str  # "live" | "snapshot" | "unattestable"


def _unattestable(reason: str) -> GateDecision:
    """Transient: the tier cannot be attested right now -> block-and-flag (action_required). NOT a
    durable DEGRADED (no record is written); a formerly-enabled check blocks rather than
    silent-neutral or stale-enforce (#1). Durable DEGRADED is 3.5."""
    return GateDecision(Disposition.BLOCK_ACTION_REQUIRED, None, reason, "unattestable")


def resolve_disposition(
    policy_id: str,
    *,
    expected_detector_identity: str,
    store: PolicyStore,
    snapshot: CalibrationSnapshot | None,
    snapshot_key: bytes,
    now: float,
    oracle_head_for: Callable[[str], str | None],
) -> GateDecision:
    """Decide the dispatcher's action for ``policy_id``. Order: live store -> identity-bound signed
    snapshot -> fail-closed UNATTESTABLE. A tampered chain blocks immediately (never falls back — a
    tamper is worse than an outage). ``expected_detector_identity`` is the detector about to run.

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
            policy_id, expected_detector_identity=expected_detector_identity,
            snapshot=snapshot, key=snapshot_key, now=now, oracle_head_for=oracle_head_for,
        )

    if state is None:
        return GateDecision(
            Disposition.SKIP_NEUTRAL, None, "no policy configured for this check", "live"
        )
    if state is PolicyState.ENABLED:
        return _enforce_if_oracle_current(
            policy_id, store=store, oracle_head_for=oracle_head_for,
            expected_detector_identity=expected_detector_identity,
        )
    return GateDecision(disposition_for(state), state, f"live state {state.value}", "live")


def _enforce_if_oracle_current(
    policy_id: str,
    *,
    store: PolicyStore,
    oracle_head_for: Callable[[str], str | None],
    expected_detector_identity: str,
) -> GateDecision:
    """A live ENABLED policy enforces only if BOTH bindings still hold: (a) its calibration's bound
    set-head equals the current set-head (scoped oracle invalidation — an append to the policy's set
    moves the head -> UNATTESTABLE; close-3); AND (b) the detector about to run has the SAME 4-tuple
    identity the calibration was bound to (close-2 — a build / host-closure / image / eval drift
    yields a new identity, and enforcing a stale calibration for a drifted detector is the very
    transitive-spoof the identity binding exists to refuse). The identity check is symmetric with the
    signed-snapshot fallback (``_from_snapshot``); without it, the identity invariant held only during
    a store outage and fell open on the primary path."""
    attestation = store.current_attestation(policy_id)
    if attestation is None:
        return _unattestable("ENABLED policy has no calibration attestation to check the oracle head")
    set_id, bound_head, bound_identity = attestation
    if bound_identity != expected_detector_identity:
        return _unattestable(
            f"live ENABLED calibration attests detector {bound_identity!r} but "
            f"{expected_detector_identity!r} is about to run — the detector drifted since "
            "calibration; refusing to enforce an un-calibrated detector"
        )
    current_head = oracle_head_for(set_id)
    if current_head is None:
        return _unattestable(f"unknown calibration set membership for {set_id!r} — failing closed")
    if current_head != bound_head:
        return _unattestable(
            f"oracle set {set_id!r} has grown since calibration (head {bound_head[:12]}.. -> "
            f"{current_head[:12]}..) — re-calibration pending"
        )
    return GateDecision(Disposition.RUN_ENFORCING, PolicyState.ENABLED,
                        f"live ENABLED, oracle set {set_id!r} current", "live")


def _from_snapshot(
    policy_id: str,
    *,
    expected_detector_identity: str,
    snapshot: CalibrationSnapshot | None,
    key: bytes,
    now: float,
    oracle_head_for: Callable[[str], str | None],
) -> GateDecision:
    """Store unreachable -> consult the signed snapshot. Fresh + HMAC-valid + IDENTITY-MATCHING +
    ORACLE-CURRENT -> enforce. Missing / tampered / stale snapshot, a detector-identity mismatch, a
    policy ABSENT from an otherwise-valid snapshot, OR (close-4) an oracle-head DRIFT -> UNATTESTABLE.

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
    if record.detector_identity != expected_detector_identity:
        return _unattestable(
            f"store unreachable; snapshot attests detector {record.detector_identity!r} but "
            f"{expected_detector_identity!r} is about to run — refusing to enforce an "
            "un-calibrated detector"
        )
    # close-4: oracle-head drift on the fallback path (calibration store still reachable).
    current_head = oracle_head_for(record.set_id)
    if current_head is not None and current_head != record.oracle_head:
        return _unattestable(
            f"store unreachable; snapshot oracle set {record.set_id!r} drifted since mint "
            f"({record.oracle_head[:12]}.. -> {current_head[:12]}..) — re-calibration pending"
        )
    return GateDecision(
        Disposition.RUN_ENFORCING, PolicyState.ENABLED,
        f"store unreachable; snapshot attests ENABLED for {record.detector_identity!r}", "snapshot",
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
        store.record_calibration_pass(
            ref, policy_id=policy_id, pinned_set_version=sealed.oracle_head,
            detector_identity=subject, identity_contract_version=IDENTITY_CONTRACT_VERSION, set_id=set_id,
        )
        # sync resolution: PASS → completion CAS. No relay advances the intent during a synchronous run, so
        # the CAS MUST succeed; a miss means the intent was superseded/advanced unexpectedly → fail-closed.
        if not store.mark_intent_satisfied(policy_id, **_fence):  # type: ignore[arg-type]
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
