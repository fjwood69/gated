"""gate/candidate_measurement.py — the shared, authority-free MEASUREMENT spine (3.5 S3-completion CP4
Slice B).

One seal, one resolution, one calibration run → a frozen ``CandidateMeasurement``. BOTH the
measurement runner (``gate.recalibration.run_recalibration``, which SIGNS it) and the synchronous enable
path (``gate.gatekeeper.run_calibration``, which PERSISTS the pass) consume this spine so they measure
identically and cannot diverge. The spine decides NOTHING about state: no ``PolicyStore``, no intent, no
CAS, no clock. It measures; the consumers govern.

The structure enforces the board's two structural invariants:

  * SINGLE SEAL — the spine accepts an ALREADY-``SealedSet`` and NEVER reseals (a second seal would be a
    fresh membership read, re-opening the head/coverage TOCTOU the seal closes). The caller seals once,
    upstream, and hands the frozen set in.
  * SINGLE RESOLVE, resolve-BEFORE-anything — ``prepare_candidate`` resolves the detector bundle EXACTLY
    once and freezes it onto a ``PreparedCandidate`` alongside the three policy WITNESSES captured at that
    instant. ``produce_candidate_measurement`` calibrates with a resolver that returns THAT frozen bundle,
    so the expected-profile digest and the calibration run share one resolution — never resolve-for-
    precheck-then-resolve-again. run_calibration then derives its ``enter_calibrating`` expected digests
    from the SAME ``PreparedCandidate``, so the intent's routing and the run's measurement are one object.

WITNESS self-consistency (the teeth): the witnesses are captured in the SAME representation the runner
measures onto each ``TrialReport`` — trust = ``trust_policy.policy_digest``; guard =
``getattr(backend_guard, "policy_digest", None)`` (a plain opt-out guard bears no digest → None). After
the run, any coordinate that WAS measured must equal its witness; a measured-but-divergent coordinate
means the applied policy object MUTATED between prepare and the run (a consistent-but-different digest the
aggregation alone would wave through) → fail closed. A coordinate the run did NOT attest (None — an
inadequate set, a harness error, or a mid-run MIXED policy) is left to the outcome mapping (ERROR), not
the witness check, so the runner still emits its signed ERROR evidence rather than raising.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from core import ResourceBudget, Sandbox, VerdictType
from engine.calibration import (
    DEFAULT_CALIBRATION_TRIALS,
    BackendGuard,
    BundleResolver,
    CalibrationResult,
    ResolvedDetector,
    calibrate,
)
from engine.observation_trust import TrustPolicy
from gate.attestation import calibrated_subject_identity
from gate.calibration_store import SealedSet


class CandidateMeasurementError(RuntimeError):
    """A fail-closed condition in the shared measurement spine (gate-side; the engine's config error is
    not importable here — engine⊥gate)."""


class WitnessInconsistencyError(CandidateMeasurementError):
    """A MEASURED runtime-subject coordinate diverged from the witness captured before the run — the
    applied trust/guard policy object mutated between ``prepare_candidate`` and the calibration run. The
    aggregation alone cannot catch a policy that is CONSISTENT-across-fixtures but DIFFERENT from what was
    prepared/authorised; this check does. Fail closed — never sign or persist a run whose applied policy
    identity does not match the one the intent was routed for."""


@dataclass(frozen=True)
class PreparedCandidate:
    """The single-seal + single-resolve unit. ``sealed_set`` and ``resolved_bundle`` are produced ONCE,
    upstream; the three witnesses pin the policy identities read at resolution time (measured
    representation) so the post-run self-consistency check has an independent reference. Frozen — a
    consumer cannot mutate the prepared context between preparation and measurement."""

    sealed_set: SealedSet
    detector_id: str
    resolved_bundle: ResolvedDetector
    profile_witness: str            # bundle.profile_digest — pinned by the content-addressed bundle
    trust_witness: str | None       # trust_policy.policy_digest at prepare (None if no trust policy)
    guard_witness: str | None       # getattr(backend_guard, "policy_digest", None) at prepare


@dataclass(frozen=True)
class CandidateMeasurement:
    """The frozen measurement both consumers derive their outputs from: the ``CalibrationResult``, the
    four measured RuntimeSubject coordinates and their composite ``subject_identity`` (None unless all
    four are present — a clean PASS/FAIL), and the sealed calibration context (denormalised so the golden
    and the consumers read a flat, self-describing object rather than reaching back through the seal)."""

    result: CalibrationResult
    resolved_profile_digest: str | None
    trust_policy_digest: str | None
    guard_policy_digest: str | None
    execution_identity_digest: str | None
    subject_identity: str | None
    set_id: str
    oracle_head: str
    coverage_digest: str
    fixture_ids: tuple[str, ...]


def prepare_candidate(
    sealed_set: SealedSet,
    *,
    resolve: BundleResolver,
    detector_id: str,
    trust_policy: TrustPolicy | None,
    backend_guard: BackendGuard,
) -> PreparedCandidate:
    """Resolve the detector bundle EXACTLY once and freeze it with the policy witnesses. ``resolve``
    raising (unregistered / integrity mismatch) propagates — the consumers decide what a resolution
    failure means (the recal runner signs an ERROR attestation; run_calibration fails closed). The
    witnesses are read in the runner's representation so the later self-consistency comparison is
    apples-to-apples."""
    bundle = resolve(detector_id)
    return PreparedCandidate(
        sealed_set=sealed_set,
        detector_id=detector_id,
        resolved_bundle=bundle,
        profile_witness=bundle.profile_digest,
        trust_witness=trust_policy.policy_digest if trust_policy is not None else None,
        guard_witness=getattr(backend_guard, "policy_digest", None),
    )


def classify_measurement(measurement: CandidateMeasurement) -> VerdictType:
    """The SHARED, authority-free outcome classifier both consumers use (the signed runner AND the async
    worker), so they cannot disagree on what a measurement MEANS. ERROR (inconclusive — retry / signed-ERROR,
    NEVER a deterministic detector failure) whenever the run is UNATTESTABLE: an INADEQUATE set, ANY harness
    error, an inconsistent execution identity, INCONSISTENT policies, or any absent / present-but-invalid
    (positive-shape) runtime-subject coordinate. Only a fully-attested run is PASS/FAIL — a real
    miss/false-positive/flake is FAIL; a clean two-sided pass is PASS. Note a harness error can leave the
    four coordinates measurable (a non-null subject), so ``subject is None`` alone is NOT a sufficient ERROR
    test — ``harness_errors`` must be checked explicitly."""
    r = measurement.result
    coords = (measurement.resolved_profile_digest, measurement.trust_policy_digest,
              measurement.guard_policy_digest, measurement.execution_identity_digest)
    coords_valid = all(isinstance(c, str) and c != "" for c in coords)
    if (r.inadequate or r.harness_errors or not r.identity_consistent
            or not r.policies_consistent or measurement.subject_identity is None or not coords_valid):
        return VerdictType.ERROR
    return VerdictType.PASS if r.passed else VerdictType.FAIL


def _valid_coord(c: str | None) -> str | None:
    """A runtime-subject coordinate is PRESENT only if it is a non-empty ``str``. Normalise everything
    else — ``None``, ``""``, or a non-str — to ``None`` (present-but-invalid is NOT present). This is the
    positive-shape check: assert the valid shape once, rather than enumerate the degenerate values."""
    return c if (isinstance(c, str) and c != "") else None


def _verify_witnesses(result: CalibrationResult, prepared: PreparedCandidate) -> None:
    """Fail closed if any MEASURED coordinate diverges from its pre-run witness. Only measured (non-None)
    coordinates are checked — a None coordinate means the run did not attest it (inadequate/error/mixed),
    which the outcome mapping already reflects as ERROR; forcing a match there would turn a signed-ERROR
    path into a raise."""
    checks = (
        (result.resolved_profile_digest, prepared.profile_witness, "resolved-profile"),
        (result.trust_policy_digest, prepared.trust_witness, "trust-policy"),
        (result.guard_policy_digest, prepared.guard_witness, "backend-guard"),
    )
    for measured, witness, label in checks:
        if measured is not None and measured != witness:
            raise WitnessInconsistencyError(
                f"{label} digest diverged from the pre-run witness "
                f"(measured={measured!r} != witness={witness!r}) — the applied policy object mutated "
                "between prepare and the run (fail-closed)")


def produce_candidate_measurement(
    prepared: PreparedCandidate,
    *,
    make_sandbox: Callable[[], Sandbox],
    budget: ResourceBudget,
    backend_guard: BackendGuard,
    trust_policy: TrustPolicy | None,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
) -> CandidateMeasurement:
    """Calibrate the prepared candidate against its sealed fixtures with a resolver pinned to the frozen
    bundle, verify witness self-consistency, and return the frozen measurement. ``backend_guard`` and
    ``trust_policy`` are the LIVE objects calibrate applies (so a mid-run mutation is measurable) — the
    witness check compares what actually governed the run against what was frozen at preparation."""

    def _frozen_resolve(_detector_id: str) -> ResolvedDetector:
        return prepared.resolved_bundle

    result = calibrate(
        make_sandbox, prepared.detector_id, _frozen_resolve, prepared.sealed_set.calibration_set, budget,
        trials=trials, backend_guard=backend_guard, trust_policy=trust_policy,
    )
    # witness self-consistency is checked on the RAW measured digests (mutation detection is faithful only
    # against exactly what the run measured), BEFORE validity normalisation below.
    _verify_witnesses(result, prepared)
    # POSITIVE-SHAPE validity (not enumerated degenerates): a coordinate is PRESENT only if it is a
    # non-empty str; anything else — None, "", or a non-str — normalises to None. An empty/malformed digest
    # is present-but-invalid, and ``sign_measurement`` rejects it on the wire; normalising here means a
    # subject is derived (and a PASS/FAIL is possible) ONLY over four wire-valid coordinates, so an empty
    # digest becomes an ERROR carrying nulls rather than a crash at signing.
    rpd = _valid_coord(result.resolved_profile_digest)
    tpd = _valid_coord(result.trust_policy_digest)
    gpd = _valid_coord(result.guard_policy_digest)
    eid = _valid_coord(result.execution_identity.digest() if result.execution_identity is not None else None)
    # a subject exists ONLY when all four coordinates are present AND valid (a clean PASS/FAIL); an
    # unattestable ERROR carries null coordinates and a null subject.
    _coords = (rpd, tpd, gpd, eid)
    subject = (
        calibrated_subject_identity(rpd, tpd, gpd, eid) if all(c is not None for c in _coords) else None
    )
    return CandidateMeasurement(
        result=result,
        resolved_profile_digest=rpd, trust_policy_digest=tpd, guard_policy_digest=gpd,
        execution_identity_digest=eid, subject_identity=subject,
        set_id=prepared.sealed_set.set_id, oracle_head=prepared.sealed_set.oracle_head,
        coverage_digest=prepared.sealed_set.coverage_digest,
        fixture_ids=prepared.sealed_set.fixture_ids,
    )


__all__ = [
    "CandidateMeasurementError",
    "WitnessInconsistencyError",
    "PreparedCandidate",
    "CandidateMeasurement",
    "prepare_candidate",
    "produce_candidate_measurement",
]
