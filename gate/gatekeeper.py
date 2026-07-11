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

from core import ResourceBudget, RuntimeAssertion, Sandbox
from core.calibration import CalibrationSet
from core.chain import content_digest
from engine.calibration import CalibrationResult, DEFAULT_CALIBRATION_TRIALS, calibrate
from gate.authority import GovernanceApproval
from gate.policy_state import Disposition, PolicyState, disposition_for
from gate.policy_store import ChainIntegrityError, PolicyStore
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
        return _enforce_if_oracle_current(policy_id, store=store, oracle_head_for=oracle_head_for)
    return GateDecision(disposition_for(state), state, f"live state {state.value}", "live")


def _enforce_if_oracle_current(
    policy_id: str,
    *,
    store: PolicyStore,
    oracle_head_for: Callable[[str], str | None],
) -> GateDecision:
    """A live ENABLED policy enforces only if its bound set-head equals the current set-head. Scoped
    invalidation: an append to the policy's set moves the head -> UNATTESTABLE until re-calibration."""
    attestation = store.current_attestation(policy_id)
    if attestation is None:
        return _unattestable("ENABLED policy has no calibration attestation to check the oracle head")
    set_id, bound_head = attestation
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
    detector: RuntimeAssertion,
    calibration_set: CalibrationSet,
    budget: ResourceBudget,
    calibration_chain_head: str,
    detector_identity: str,
    approval: GovernanceApproval,
    set_id: str = "default",
    trials: int = DEFAULT_CALIBRATION_TRIALS,
) -> CalibrationOutcome:
    """Run the 3.2 BATCH calibrator (shadow-first — full fixture distribution, zero live-PR cost)
    against the out-of-band CalibrationSet, and record the state move. Records PENDING->CALIBRATING;
    on FAIL records CALIBRATING->REJECTED with the breaking fixtures in the (tamper-evident) reason;
    on PASS PERSISTS a calibration_pass attestation (the thing ENABLED binds to, gap-1) and LEAVES
    the policy at CALIBRATING (awaiting human ratify). It NEVER enables — enabling is
    ``ratify_enable`` (the human gate)."""
    store.transition(
        policy_id, PolicyState.CALIBRATING, approval=approval,
        pinned_set_version=calibration_chain_head,
    )
    result = calibrate(make_sandbox, detector, calibration_set, budget, trials=trials)
    breaking = (*result.fn_failures, *result.fp_failures, *result.flaky, *result.harness_errors)
    ref: str | None = None
    if result.passed:
        ref = _result_ref(policy_id, calibration_chain_head, detector_identity, result)
        store.record_calibration_pass(
            ref, policy_id=policy_id, pinned_set_version=calibration_chain_head,
            detector_identity=detector_identity, set_id=set_id,
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
    detector_identity: str,
) -> int:
    """The human-gated CALIBRATING->ENABLED grant, ANCHORED to a PERSISTED PASS (addition #3 +
    gap-1): the store requires non-null anchors AND that ``calibration_result_ref`` match a recorded
    calibration_pass for (policy, pinned_set_version, detector_identity) — a fabricated reference
    cannot enable. The ``approval`` carries the ratifier principal(s). This is the shadow->binding
    graduation — a governance decision informed by the ``run_calibration`` report, NOT a config flag.
    The store also enforces the legal edge (state must be CALIBRATING)."""
    return store.transition(
        policy_id, PolicyState.ENABLED, approval=approval,
        calibration_result_ref=calibration_result_ref, pinned_set_version=pinned_set_version,
        detector_identity=detector_identity,
    )


__all__ = [
    "GateDecision",
    "resolve_disposition",
    "CalibrationOutcome",
    "run_calibration",
    "ratify_enable",
]
