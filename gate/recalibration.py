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
    (board D4). The policy is already blocking (transiently UNATTESTABLE via the oracle-head drift);
    the runner does not touch that either.

The fourth-hole fix (board): the runner SEALS the set under one consistent read snapshot
(``CalibrationStore.seal_set`` — head + coverage + fixtures from one pass), RELEASES the transaction,
THEN runs the expensive calibration against the frozen set. The signed PASS therefore binds an
``oracle_head`` and a ``coverage_digest`` that provably co-existed; the restore CAS later rechecks the
head is still current, so a set change mid-run just forces a re-run — it can never smuggle a coverage
that never co-existed with the head into a valid signature.

job_id is DETERMINISTIC in ``(policy_id, set_id, oracle_head, detector_identity)`` so re-triggers for
the SAME measurement dedupe; the per-attempt ``nonce`` stays unique. Gate-side; ``core`` never imports
this. Reads the oracle (allowed); never writes it or any tier.
"""
from __future__ import annotations

from typing import Callable

from core import ResourceBudget, Sandbox, VerdictType
from core.chain import content_digest
from engine.calibration import (
    DEFAULT_CALIBRATION_TRIALS,
    BackendGuard,
    CalibrationResult,
    DetectorResolver,
    calibrate,
)
from gate.attestation import MeasurementAttestation, sign_measurement
from gate.calibration_store import CalibrationStore
from gate.signing import Signer


def deterministic_job_id(
    *, policy_id: str, set_id: str, oracle_head: str, detector_identity: str
) -> str:
    """The dedup key for a re-calibration: two triggers for the SAME (policy, set, oracle head,
    detector) are the SAME measurement job and must not run twice. The per-attempt nonce (unique)
    still distinguishes retries within the queue."""
    return content_digest({
        "policy_id": policy_id, "set_id": set_id, "oracle_head": oracle_head,
        "detector_identity": detector_identity,
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
    resolve: DetectorResolver,
    detector_identity: str,
    tier_generation: str,
    budget: ResourceBudget,
    issuer: str,
    nonce: str,
    now: float,
    signer: Signer,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
    backend_guard: BackendGuard | None = None,
) -> MeasurementAttestation:
    """Seal the set (snapshot-isolated), run the batch calibrator against the frozen fixtures, and
    return a SIGNED measurement. Emits — never enforces. ``detector_identity`` is the caller's 4-tuple
    identity for the exact detector build/host/image/eval; ``tier_generation`` is the tier-chain head
    the trigger observed (the restore CAS rechecks currency). Deterministic ``run_id`` = the job id.

    NOTE (no ``PolicyStore`` parameter — by construction): the runner cannot read or write the tier
    store, so it can neither move a tier nor bind a policy-evidence head. The policy-evidence-head gate
    lives in the restore controller's read-reread CAS (strictly better than binding a value that would
    go stale on any unrelated policy append and thrash re-runs)."""
    sealed = calibration_store.seal_set(set_id)  # one consistent snapshot; released on return
    # the detector arrives by NAME, resolved only through the trusted registry (never a caller object).
    result = calibrate(make_sandbox, detector_id, resolve, sealed.calibration_set, budget,
                       trials=trials, backend_guard=backend_guard)
    job_id = deterministic_job_id(
        policy_id=policy_id, set_id=set_id, oracle_head=sealed.oracle_head,
        detector_identity=detector_identity,
    )
    unsigned = MeasurementAttestation(
        outcome=_outcome_of(result), policy_id=policy_id, detector_identity=detector_identity,
        set_id=set_id, oracle_head=sealed.oracle_head, coverage_digest=sealed.coverage_digest,
        tier_generation=tier_generation, issuer=issuer, run_id=job_id, nonce=nonce, issued_at=now,
        fixture_coverage=sealed.fixture_ids,
        short_circuit=False,  # calibrate() runs the full distribution — short-circuit is always OFF
        fn_failures=result.fn_failures, fp_failures=result.fp_failures, flaky=result.flaky,
        harness_errors=result.harness_errors,
    )
    return sign_measurement(unsigned, signer=signer)


__all__ = ["deterministic_job_id", "run_recalibration"]
