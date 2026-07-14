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
)
from engine.observation_trust import TrustPolicy
from gate.attestation import MeasurementAttestation, sign_measurement
from gate.calibration_store import CalibrationStore
from gate.candidate_measurement import (
    CandidateMeasurement,
    WitnessInconsistencyError,
    classify_measurement,
    prepare_candidate,
    produce_candidate_measurement,
)
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


def _outcome_of(measurement: CandidateMeasurement) -> VerdictType:
    """The signed runner's outcome = the SHARED authority-free classifier (``classify_measurement``), so the
    runner and the async worker cannot disagree on what a measurement means. A PASS/FAIL therefore always
    carries the four coordinates + subject that ``sign_measurement`` requires; anything unattestable
    (inadequate / harness error / inconsistent / mixed / invalid-coordinate) is ERROR — signed ERROR
    evidence here, retry on the worker path — never a crash and never a deterministic failure."""
    return classify_measurement(measurement)


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

    def _signed_error(marker: str) -> MeasurementAttestation:
        # a signed ERROR AUDIT attestation with null components: categorically non-restorable
        # (is_clean_pass False), never a measurement that could restore a tier. For the DEFINED measurement
        # failures — detector resolution, a mutated-policy witness mismatch, and (via _outcome_of) a mixed /
        # digestless / otherwise-unattested provenance — the runner emits signed ERROR evidence rather than
        # raising. It does NOT normalise arbitrary execution exceptions (sandbox/budget faults propagate).
        return sign_measurement(MeasurementAttestation(
            outcome=VerdictType.ERROR, policy_id=policy_id, subject_identity=None,
            requested_subject_identity=requested_subject_identity,
            resolved_profile_digest=None, trust_policy_digest=None, guard_policy_digest=None,
            execution_identity_digest=None, set_id=set_id,
            oracle_head=sealed.oracle_head, coverage_digest=sealed.coverage_digest,
            tier_generation=tier_generation, issuer=issuer, run_id=job_id, nonce=nonce,
            issued_at_ms=issued_at_ms, fixture_coverage=sealed.fixture_ids, short_circuit=False,
            harness_errors=(marker,),
        ), signer=signer)

    try:
        # Shared measurement spine (CP4 Slice B): prepare (resolve ONCE, capture witnesses) then produce
        # (calibrate on the frozen bundle + witness self-consistency). ATOMIC resolution is preserved — the
        # resolved-profile digest binds the detector that ACTUALLY ran.
        prepared = prepare_candidate(
            sealed, resolve=resolve, detector_id=detector_id,
            trust_policy=trust_policy, backend_guard=backend_guard,
        )
        measurement = produce_candidate_measurement(
            prepared, make_sandbox=make_sandbox, budget=budget,
            backend_guard=backend_guard, trust_policy=trust_policy, trials=trials,
        )
        result = measurement.result
    except DetectorResolutionError as exc:
        # drift / unregistered detector -> signed ERROR audit evidence.
        return _signed_error(f"detector-unresolved:{exc.__class__.__name__}")
    except WitnessInconsistencyError:
        # an applied trust/guard object mutated between prepare and the run (a consistent-but-shifted
        # policy identity) -> fail-closed as signed ERROR evidence, not an uncaught crash. The runner must
        # never sign a PASS/FAIL under a policy identity that was not the one prepared.
        return _signed_error("policy-witness-inconsistent")

    # S3: the four RuntimeSubject coordinates + composite subject, all measured/derived by the SAME
    # calibration operation and carried on the frozen CandidateMeasurement (conditional validity — the
    # subject is None unless all four coordinates were measured; an unattestable ERROR carries nulls).
    rpd = measurement.resolved_profile_digest
    tpd = measurement.trust_policy_digest   # the APPLIED observation-trust policy (measured provenance)
    gpd = measurement.guard_policy_digest   # the APPLIED backend-guard policy (measured provenance)
    eid = measurement.execution_identity_digest
    subject = measurement.subject_identity
    unsigned = MeasurementAttestation(
        outcome=_outcome_of(measurement), policy_id=policy_id, subject_identity=subject,
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
