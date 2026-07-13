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
from core.calibration import CalibrationSet
from core.chain import content_digest
from engine.calibration import (
    BackendGuard,
    BundleResolver,
    CalibrationResult,
    DEFAULT_CALIBRATION_TRIALS,
    calibrate,
)
from engine.observation_trust import TrustPolicy
from gate.attestation import IDENTITY_CONTRACT_VERSION, calibrated_subject_identity
from gate.authority import GovernanceApproval
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


def _result_ref(
    policy_id: str, pinned_set_version: str, detector_identity: str, result: CalibrationResult
) -> str:
    """A deterministic, content-derived handle for a PASS — ties the ref to the exact calibration
    context (policy, fixture-set version, detector identity, the pass shape). Reproducible (NFR6)
    and not guessable without the actual result."""
    return content_digest({
        "policy_id": policy_id, "pinned_set_version": pinned_set_version,
        "detector_identity": detector_identity, "passed": result.passed,
        "n_bad": len(result.outcomes), "fixtures": sorted(o.fixture_id for o in result.outcomes),
    })


def run_calibration(
    policy_id: str,
    *,
    store: PolicyStore,
    make_sandbox: Callable[[], Sandbox],
    detector_id: str,
    resolve: BundleResolver,
    calibration_set: CalibrationSet,
    budget: ResourceBudget,
    calibration_chain_head: str,
    approval: GovernanceApproval,
    set_id: str = "default",
    trials: int = DEFAULT_CALIBRATION_TRIALS,
    backend_guard: BackendGuard,
    trust_policy: TrustPolicy,
) -> CalibrationOutcome:
    """Run the 3.2 BATCH calibrator (shadow-first — full fixture distribution, zero live-PR cost)
    against the out-of-band CalibrationSet, and record the state move. Records PENDING->CALIBRATING;
    on FAIL records CALIBRATING->REJECTED with the breaking fixtures in the (tamper-evident) reason;
    on PASS PERSISTS a calibration_pass attestation (the thing ENABLED binds to, gap-1) and LEAVES
    the policy at CALIBRATING (awaiting human ratify). It NEVER enables — enabling is
    ``ratify_enable`` (the human gate).

    v4 P1-a (fold): the enable path no longer trusts a CALLER identity. The calibration_pass binds the
    MEASUREMENT-DERIVED subject — H(resolved_profile_digest, execution_identity) from the SAME calibration
    run, exactly as ``run_recalibration`` — so governance later chooses WHICH persisted pass to ratify but
    cannot define what code it ran."""
    store.transition(
        policy_id, PolicyState.CALIBRATING, approval=approval,
        pinned_set_version=calibration_chain_head,
    )
    # detector by NAME, resolved only through the trusted registry (never a caller-supplied object).
    result = calibrate(make_sandbox, detector_id, resolve, calibration_set, budget,
                       trials=trials, backend_guard=backend_guard, trust_policy=trust_policy)
    breaking = (*result.fn_failures, *result.fp_failures, *result.flaky, *result.harness_errors)
    ref: str | None = None
    if result.passed:
        rpd = result.resolved_profile_digest
        tpd = result.trust_policy_digest
        gpd = result.guard_policy_digest
        eid = result.execution_identity.digest() if result.execution_identity is not None else None
        if rpd is None or tpd is None or gpd is None or eid is None:
            # a clean pass implies all four RuntimeSubject coordinates (profile/trust/guard/execution) —
            # fail-closed rather than persist an un-attributable pass.
            raise ConfigurationError(
                "a PASSED calibration lacked one of the four runtime-subject coordinates "
                "(resolved-profile / trust-policy / guard-policy / execution identity) — cannot derive the "
                "measured subject; refusing to persist an un-attributable pass")
        subject = calibrated_subject_identity(rpd, tpd, gpd, eid)
        ref = _result_ref(policy_id, calibration_chain_head, subject, result)
        store.record_calibration_pass(
            ref, policy_id=policy_id, pinned_set_version=calibration_chain_head,
            detector_identity=subject, identity_contract_version=IDENTITY_CONTRACT_VERSION, set_id=set_id,
        )
    else:
        store.transition(
            policy_id, PolicyState.REJECTED, approval=approval,
            pinned_set_version=calibration_chain_head,
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
    subject = store.subject_for_pass(calibration_result_ref, policy_id, pinned_set_version)
    if subject is None:
        raise ConfigurationError(
            f"no persisted calibration_pass matches ref={calibration_result_ref!r} for "
            f"({policy_id}, set={pinned_set_version}) — a fabricated reference cannot enable")
    return store.transition(
        policy_id, PolicyState.ENABLED, approval=approval,
        calibration_result_ref=calibration_result_ref, pinned_set_version=pinned_set_version,
        detector_identity=subject, identity_contract_version=IDENTITY_CONTRACT_VERSION,
    )


__all__ = [
    "GateDecision",
    "resolve_disposition",
    "CalibrationOutcome",
    "run_calibration",
    "ratify_enable",
]
