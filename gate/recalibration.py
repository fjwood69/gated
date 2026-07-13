"""gate/recalibration.py — 3.5 job-1: the re-calibration RUNNER (the meter that cannot move the tier).

Runs the 3.2 batch calibrator against a SNAPSHOT-ISOLATED seal of the calibration set and emits a
SIGNED measurement (``gate.attestation.MeasurementAttestation``). It is the MEASUREMENT half of
measurement≠governance, and the separation is STRUCTURAL, not documented:

  * The runner is handed NO ``PolicyStore`` (and no tier-write capability of any kind). It literally
    cannot change an enforcement tier — the only thing it can produce is signed evidence. A separate
    restore controller / human governance act must consume that evidence to move state.
  * It signs with the MEASUREMENT key (``gate.attestation``), which is NOT the tier-write key.
  * On a FAIL it does NOTHING but surface the failure breakdown in the signed attestation (the
    missed-FN evidence a human uses for the dual-controlled split). No auto-resolve, no auto-degrade
    (board D4).

3.5-close P1-3 — the signed identity is MEASUREMENT-DERIVED, not a caller string (the sign-A-run-B
close). The runner no longer accepts a ``detector_identity`` to sign. It resolves the detector through
the trusted registry, and the attestation's ``subject_identity`` is
``H(resolved_profile_digest, execution_identity_digest)`` where BOTH components come from the SAME
calibration run: ``resolved_profile_digest`` is captured inside ``calibrate`` (no second resolution),
and ``execution_identity_digest`` is the parent-measured environment. A drifted/unregistered detector
yields a signed ERROR attestation (audit evidence, categorically NON-restorable), never a measurement
that could restore a tier. ``expected_subject_identity`` is used ONLY as the deterministic job/dedup key
(governance-provenance, from the policy store via the relay/queue) — it is NEVER signed, so a wrong value
can at worst mis-dedup, never sign-A-run-B.

job_id is DETERMINISTIC in ``(policy_id, set_id, oracle_head, subject_identity)`` so re-triggers for the
SAME measurement dedupe; the per-attempt ``nonce`` stays unique. Gate-side; ``core`` never imports this.
Reads the oracle (allowed); never writes it or any tier.
"""
from __future__ import annotations

from typing import Callable

from core import ResourceBudget, Sandbox, VerdictType
from core.chain import content_digest
from engine.calibration import (
    DEFAULT_CALIBRATION_TRIALS,
    BackendGuard,
    BundleResolver,
    CalibrationResult,
    calibrate,
)
from engine.observation_trust import TrustPolicy
from gate.attestation import (
    MeasurementAttestation,
    calibrated_subject_identity,
    sign_measurement,
)
from gate.calibration_store import CalibrationStore
from gate.detector_registry import DetectorResolutionError
from gate.signing import Signer


def deterministic_job_id(
    *, policy_id: str, set_id: str, oracle_head: str, subject_identity: str
) -> str:
    """The dedup key for a re-calibration: two triggers for the SAME (policy, set, oracle head, subject)
    are the SAME measurement job and must not run twice. The per-attempt nonce (unique) still
    distinguishes retries within the queue. ``subject_identity`` here is the intended (queued) subject
    from the policy store — a routing/dedup value, not signed authority."""
    return content_digest({
        "policy_id": policy_id, "set_id": set_id, "oracle_head": oracle_head,
        "subject_identity": subject_identity,
    })


def _outcome_of(result: CalibrationResult) -> VerdictType:
    """Map a CalibrationResult to the measurement outcome. An INADEQUATE set, any HARNESS ERROR, or an
    UNATTESTABLE environment (the fixtures did not all run under one parent-measured execution identity)
    is ERROR (inconclusive — not a PASS, and not a clean FAIL that would mis-attribute an environment
    problem to the detector); a real miss/false-positive/flake is FAIL; only a clean two-sided pass in a
    single attested environment is PASS."""
    if result.inadequate or result.harness_errors or not result.identity_consistent:
        return VerdictType.ERROR
    return VerdictType.PASS if result.passed else VerdictType.FAIL


def run_recalibration(
    *,
    policy_id: str,
    set_id: str,
    calibration_store: CalibrationStore,
    make_sandbox: Callable[[], Sandbox],
    detector_id: str,
    resolve: BundleResolver,
    requested_subject_identity: str,
    tier_generation: str,
    budget: ResourceBudget,
    issuer: str,
    nonce: str,
    now: float,
    signer: Signer,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
    backend_guard: BackendGuard,
    trust_policy: TrustPolicy,
) -> MeasurementAttestation:
    """Seal the set (snapshot-isolated), run the batch calibrator against the frozen fixtures, and
    return a SIGNED measurement. Emits — never enforces.

    P1-3: the detector arrives by NAME and is resolved ONLY through the trusted registry via an ATOMIC
    ``resolve`` bundle (assertion + profile digest from one resolution). The SIGNED ``subject_identity`` is
    derived from the MEASURED run (the bundle's resolved-profile digest + the parent-measured execution
    identity), NEVER from a caller string. ``requested_subject_identity`` is the GOVERNANCE target this run
    was asked to measure — it is SIGNED (it also selects run_id) but carries no measurement authority: the
    restore controller separately requires measured==requested AND requested==the policy's currently
    authorized target, so measurement can never SELECT the governance target (measurement ≠ governance).
    A drifted / unregistered detector produces a signed ERROR attestation (audit evidence, non-restorable).

    NOTE (no ``PolicyStore`` parameter — by construction): the runner cannot read or write the tier
    store, so it can neither move a tier nor bind a policy-evidence head."""
    sealed = calibration_store.seal_set(set_id)  # one consistent snapshot; released on return
    job_id = deterministic_job_id(
        policy_id=policy_id, set_id=set_id, oracle_head=sealed.oracle_head,
        subject_identity=requested_subject_identity,
    )
    issued_at_ms = int(round(now * 1000))
    try:
        # ATOMIC resolution: calibrate resolves ONCE and carries the exact resolved-profile digest into
        # the CalibrationResult, so the signed subject binds the detector that ACTUALLY ran.
        result = calibrate(
            make_sandbox, detector_id, resolve, sealed.calibration_set, budget,
            trials=trials, backend_guard=backend_guard, trust_policy=trust_policy,
        )
    except DetectorResolutionError as exc:
        # drift / unregistered -> a signed ERROR AUDIT attestation with null components: categorically
        # non-restorable (is_clean_pass False), never a measurement that could restore a tier.
        unsigned = MeasurementAttestation(
            outcome=VerdictType.ERROR, policy_id=policy_id, subject_identity=None,
            requested_subject_identity=requested_subject_identity,
            resolved_profile_digest=None, trust_policy_digest=None, guard_policy_digest=None,
            execution_identity_digest=None, set_id=set_id,
            oracle_head=sealed.oracle_head, coverage_digest=sealed.coverage_digest,
            tier_generation=tier_generation, issuer=issuer, run_id=job_id, nonce=nonce,
            issued_at_ms=issued_at_ms, fixture_coverage=sealed.fixture_ids, short_circuit=False,
            harness_errors=(f"detector-unresolved:{exc.__class__.__name__}",),
        )
        return sign_measurement(unsigned, signer=signer)

    # S3: the four RuntimeSubject coordinates, all measured/derived by the SAME calibration operation.
    rpd = result.resolved_profile_digest
    tpd = result.trust_policy_digest       # the APPLIED observation-trust policy (measured provenance)
    gpd = result.guard_policy_digest       # the APPLIED backend-guard policy (measured provenance)
    eid = result.execution_identity.digest() if result.execution_identity is not None else None
    # conditional validity: a subject exists ONLY when ALL FOUR coordinates are present (a clean PASS/FAIL);
    # an unattestable ERROR (any coordinate missing) carries null coordinates and a null subject.
    _coords = (rpd, tpd, gpd, eid)
    subject = (
        calibrated_subject_identity(rpd, tpd, gpd, eid) if all(c is not None for c in _coords) else None
    )
    unsigned = MeasurementAttestation(
        outcome=_outcome_of(result), policy_id=policy_id, subject_identity=subject,
        requested_subject_identity=requested_subject_identity,
        resolved_profile_digest=rpd, trust_policy_digest=tpd, guard_policy_digest=gpd,
        execution_identity_digest=eid, set_id=set_id,
        oracle_head=sealed.oracle_head, coverage_digest=sealed.coverage_digest,
        tier_generation=tier_generation, issuer=issuer, run_id=job_id, nonce=nonce,
        issued_at_ms=issued_at_ms, fixture_coverage=sealed.fixture_ids,
        short_circuit=False,  # calibrate() runs the full distribution — short-circuit is always OFF
        fn_failures=result.fn_failures, fp_failures=result.fp_failures, flaky=result.flaky,
        harness_errors=result.harness_errors,
    )
    return sign_measurement(unsigned, signer=signer)


__all__ = ["deterministic_job_id", "run_recalibration"]
