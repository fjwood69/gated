"""engine/calibration.py — Step 3.1: the CalibrationSet contract + the two-sided calibrator.

Calibration Mode's core primitive (FR3.1/FR3.2, Part-2). Given a DETECTOR (a RuntimeAssertion)
and a CalibrationSet (known-good + known-bad fixtures), run the detector against every fixture
and report whether it EARNS enablement: it must CATCH all known-bad (else a false negative —
FR3.1) AND PASS all known-good (else a false positive — the marker-1 two-sided refinement).

Scope of 3.1: the contract + the calibrator ONLY. No tier-granting / policy-state machine
(3.3), no fixture SOURCING (3.4), no re-calibration triggers (3.5). Just: "given a detector and
a set, does it pass, and if not, which sample broke it, and how."

Design invariants:
  * ENGINE-SIDE, dependency-inverted (same as C1's TrialReport): the calibrator takes the
    CalibrationSet as DATA + a ``make_sandbox`` factory; it NEVER imports the gate. The gate/
    policy layer (3.3) consumes the ``CalibrationResult`` and owns enablement.
  * SHORT-CIRCUIT OFF (the ``GATED_SHORT_CIRCUIT=0`` consumer C1 left the seam for): calibration
    runs the FULL N-trial distribution, not first-fail — because HOW a detector fails a fixture
    matters. A detector that catches a known-bad only 3-of-5 trials is FLAKY on ground truth (a
    non-determinism defect), surfaced as its own refusal, never a silent pass (NFR6 / Gap-4).
  * REPRODUCIBLE (NFR6): pinned detector + pinned CalibrationSet (each fixture content-addressed
    by ``ArtifactSpec.tree_hash``) + pinned backend → the same CalibrationResult.
  * VACUITY GUARD (completeness P5): a set with no known-bad "passes" vacuously (nothing to
    miss) — refuse it. A detector calibrated against too few fixtures is the exact theatre-of-
    verification Calibration Mode exists to prevent.

Reframe-2 honesty (woven in situ): a PASSED result is "resists the CURRENT corpus", never
"proven" — the corpus is non-exhaustive and grows (§reframe-2). The report language says so.
"""
from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterator

from core import (
    ArtifactSpec,
    Command,
    IsolationLevel,
    Reason,
    ResourceBudget,
    RuntimeAssertion,
    Sandbox,
    Verdict,
    VerdictType,
    tree_hash,
)
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from engine.observation_trust import TrustPolicy
from engine.runner import ExecutionIdentity, TrialReport, run_check

# The default number of trials a calibration run exercises per fixture. Short-circuit is always
# OFF for calibration, so all TRIALS run and the full distribution (flaky vs consistent) is seen.
DEFAULT_CALIBRATION_TRIALS = 5

# #4 (Option B): the entry points take a detector by NAME + an INJECTED resolver, never a detector
# object — the only way an id becomes runnable code is a TRUSTED registry (gate-side). Defined here,
# engine-side, as a plain Callable so the engine need not import the gate (engine⊥gate preserved).
DetectorResolver = Callable[[str], RuntimeAssertion]


@dataclass(frozen=True)
class ResolvedDetector:
    """3.5-close P1-3 v3 (board HOLD, atomicity): the ATOMIC result of resolving a detector id — the
    runnable ``assertion`` AND its ``profile_digest``, produced by ONE resolution so code and profile are
    inseparable. The old two-call seam (``resolve`` then a separate ``resolve_profile``/``digest``) could
    reference different registries or let the module drift between calls (a TOCTOU); a single
    ``BundleResolver`` returning this closes it. ``calibrate`` carries ``profile_digest`` straight into the
    ``CalibrationResult``, so the signed identity binds exactly the detector that ran."""

    assertion: RuntimeAssertion
    profile_digest: str
    command: Command  # v4 P1-c: the FROZEN entrypoint command captured AT RESOLUTION and part of the
    # profile — security-relevant paths EXECUTE this, never re-call ``assertion.entrypoint()`` (a stateful
    # detector could otherwise resolve one command and run another, separating the signed profile from the
    # executed command).


# The engine-side resolver contract for calibration: a name -> (assertion, profile_digest) bundle. A
# plain Callable so the engine need not import the gate; the gate registry's ``resolve_bundle`` is the
# production implementation.
BundleResolver = Callable[[str], ResolvedDetector]

# 3.5-close #1.6: an INJECTED guard that raises if the RETURNED sandbox is not an audited backend.
# The engine calls it (dependency inversion) but cannot mint the trusted-backend token — the gate holds
# ``gate.backends.trusted_backend_guard``; engine ⊥ gate preserved (a plain Callable over core.Sandbox).
BackendGuard = Callable[[Sandbox], None]


class CalibrationConfigError(RuntimeError):
    """The calibration harness is mis-configured (e.g. a non-HERMETIC sandbox). Engine-side (the
    gate's ConfigurationError is not importable here — engine⊥gate)."""


class FixtureClass(Enum):
    """How the detector behaved on one fixture, relative to its ground-truth label."""

    CAUGHT = "caught"                  # known_bad → deterministic FAIL (correct)
    MISSED = "missed"                  # known_bad → PASS → a FALSE NEGATIVE
    CLEAN = "clean"                    # known_good → deterministic PASS (correct)
    FALSE_POSITIVE = "false_positive"  # known_good → FAIL → a FALSE POSITIVE
    FLAKY = "flaky"                    # non-deterministic across trials → a defect, either side
    HARNESS_ERROR = "harness_error"    # ERROR (infra/timeout) → inconclusive, never a pass


@dataclass(frozen=True)
class FixtureOutcome:
    """The per-fixture record — the raw material for the tamper-evident trace (NFR6 + audit)."""

    fixture_id: str
    label: FixtureLabel
    verdict: Verdict
    classification: FixtureClass
    trials: TrialReport | None  # the full distribution that produced the verdict


def _classify(label: FixtureLabel, verdict: Verdict) -> FixtureClass:
    """Map a detector's aggregate verdict on a fixture to its calibration classification.
    ERROR and non-determinism take precedence over PASS/FAIL — a detector that can't be cleanly
    observed, or that flips across trials, is defective on ground truth regardless of side."""
    if verdict.status is VerdictType.ERROR:
        return FixtureClass.HARNESS_ERROR
    # A mixed distribution aggregates to FAIL with reason NON_DETERMINISTIC (engine.runner). A
    # detector must catch/pass ground truth DETERMINISTICALLY; flakiness is its own defect —
    # never counted as a clean CAUGHT (Gap-4).
    if verdict.reason is Reason.NON_DETERMINISTIC:
        return FixtureClass.FLAKY
    if label is FixtureLabel.KNOWN_BAD:
        return FixtureClass.CAUGHT if verdict.status is VerdictType.FAIL else FixtureClass.MISSED
    return FixtureClass.CLEAN if verdict.status is VerdictType.PASS else FixtureClass.FALSE_POSITIVE


@dataclass(frozen=True)
class CalibrationResult:
    """The calibration verdict for a (detector, CalibrationSet) pair. ``passed`` is True ONLY if
    the detector caught every known-bad, passed every known-good, was deterministic on all, and
    hit no harness error. The failure lists name the SPECIFIC offending fixtures (FR3.1 'reports
    the specific missed sample'). The full ``outcomes`` feed the reproducible trace (NFR6)."""

    passed: bool
    inadequate: bool
    fn_failures: tuple[str, ...]      # known_bad the detector MISSED (false negatives)
    fp_failures: tuple[str, ...]      # known_good the detector FALSE-POSITIVED
    flaky: tuple[str, ...]            # fixtures the detector was non-deterministic on
    harness_errors: tuple[str, ...]   # fixtures that ERRORed (inconclusive)
    outcomes: tuple[FixtureOutcome, ...]
    # 3.5 #3: the single PARENT-MEASURED execution identity every fixture in this run shared (the
    # environment the detector was actually calibrated in), or None if the fixtures did NOT all run
    # under ONE identity — an unattestable run, which forces ``passed`` False. Never self-reported by
    # a fixture; measured by the runner from the sandbox it constructed. The acceptance receipt DERIVES
    # its bound image/identity from THIS (the real calibration environment), never a separate probe.
    execution_identity: ExecutionIdentity | None = None
    identity_consistent: bool = True
    # 3.5-close P1-3 (v2 attestation): the resolved-profile digest of the detector that ACTUALLY ran,
    # captured from the SAME calibration operation (the injected ``resolved_profile_digest_of`` at the
    # point of resolution) — NOT a separate post-hoc resolution, which would open a fresh sign-A/run-B
    # window. None when no digest source was injected, or on the inadequate-set early return (no detector
    # was resolved). The recalibration attestation binds its ``resolved_profile_digest`` from THIS.
    resolved_profile_digest: str | None = None
    # B1 / B3 (S3): the digests of the observation trust policy + backend guard policy that ACTUALLY
    # governed this calibration — measured PROVENANCE, bound into the RuntimeSubject. Set ONLY when
    # consistent across every fixture; a MIXED policy across fixtures fails closed
    # (``policies_consistent`` False -> ``passed`` False), exactly like a mixed execution identity — so a
    # run whose trust/guard identity drifted cannot be attested. None when no policy was applied.
    trust_policy_digest: str | None = None
    guard_policy_digest: str | None = None
    policies_consistent: bool = True

    def report(self) -> str:
        """The human-facing calibration report — FR3.1's 'theatre of verification' language,
        two-sided, with reframe-2 honesty ('resists the current corpus', never 'proven')."""
        if self.inadequate:
            return (
                "REFUSED: inadequate calibration set — need at least one known-good AND one "
                "known-bad fixture. A detector calibrated against too few fixtures is theatre "
                "of verification."
            )
        parts: list[str] = []
        if self.fn_failures:
            parts.append(
                "enabling this would create a theatre of verification — the detector does not "
                f"catch {list(self.fn_failures)}"
            )
        if self.fp_failures:
            parts.append(
                f"the detector produces a false positive on known-good {list(self.fp_failures)} "
                "— it would block correct code"
            )
        if self.flaky:
            parts.append(
                f"the detector is non-deterministic on ground-truth fixtures {list(self.flaky)} "
                "— it must catch/pass deterministically"
            )
        if self.harness_errors:
            parts.append(
                f"calibration inconclusive — harness ERROR on {list(self.harness_errors)}"
            )
        if not self.identity_consistent:
            parts.append(
                "the fixtures did not all run under ONE parent-measured execution identity — the "
                "calibration environment is not attestable, so the run cannot be trusted"
            )
        if parts:
            return "REFUSED: " + "; ".join(parts)
        n_bad = sum(1 for o in self.outcomes if o.label is FixtureLabel.KNOWN_BAD)
        n_good = len(self.outcomes) - n_bad
        return (
            f"PASSED: detector catches all {n_bad} known-bad and passes all {n_good} known-good "
            "fixtures (resists the current corpus — provisional, the corpus grows)."
        )


def _require_hermetic(make_sandbox: Callable[[], Sandbox]) -> None:
    """Board Prescription 2: calibration runs `known_bad` fixtures — ADVERSARIAL code (env-
    fingerprinting, proxy-bypass, state-forge). A WEAK sandbox could let one escape and corrupt
    the calibration itself. Require HERMETIC; refuse WEAK, fail-closed."""
    level = make_sandbox().isolation_level
    if level is not IsolationLevel.HERMETIC:
        raise CalibrationConfigError(
            f"calibration requires HERMETIC isolation, got {level.value} — known-bad fixtures are "
            "adversarial code and must not run in a weak sandbox"
        )


@contextmanager
def _materialised(fixture: Fixture) -> Iterator[ArtifactSpec]:
    """Materialise a fixture's opaque payload into a **randomised-handle** dir (the detector can't
    fingerprint the path), as `main.py`. The LABEL is NEVER written here (1a) — only the payload —
    so a fixture running in the sandbox cannot read whether it is expected to PASS or FAIL. The
    dir is discarded after (and the sandbox mounts it read-only), closing the verify→swap TOCTOU."""
    d = Path(tempfile.mkdtemp(prefix="calfx-"))  # random suffix = the opaque handle
    try:
        (d / "main.py").write_bytes(fixture.payload)
        yield ArtifactSpec(path=d, tree_hash=tree_hash(d))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def calibrate(
    make_sandbox: Callable[[], Sandbox],
    detector_id: str,
    resolve: BundleResolver,
    calibration_set: CalibrationSet,
    budget: ResourceBudget,
    *,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
    backend_guard: BackendGuard,
    trust_policy: TrustPolicy | None = None,
) -> CalibrationResult:
    """Resolve ``detector_id`` through the injected trusted ``resolve`` and run that detector against
    every fixture in ``calibration_set``, returning whether it earns enablement. Two-sided (FR3.1 +
    marker-1): refuse on any missed known-bad OR false-positived known-good; also refuse on
    non-determinism (flaky-on-ground-truth) or harness ERROR.

    #4 (Option B): the detector arrives by NAME, not as an object — the caller cannot smuggle in
    arbitrary detector code (which could game the holdout via the verdict side-channel); only a
    trusted, content-addressed registry can turn the id into runnable code. ``resolve`` raising
    (unregistered / integrity mismatch) propagates — fail-closed, no calibration on untrusted code.

    Oracle-invariant properties (3.2): requires HERMETIC (adversarial fixtures); each fixture is
    materialised from opaque bytes under a randomised handle with its label kept OUT of the sandbox
    (1a); the detector has NO channel to choose which fixtures it faces — the caller injects the
    set, `calibrate` runs ALL of it (1d). Short-circuit ALWAYS OFF (full distribution). No
    tier-granting (3.3). Reproducible from the pinned detector + pinned fixtures (NFR6)."""
    # 3.5-close #1.6 + B3/D3: the trusted-backend guard is MANDATORY (no None opt-out). Wrap the factory
    # so EVERY constructed sandbox (including _require_hermetic's probe and each trial) has its RETURNED
    # object verified by the guard, which RAISES on rejection. The engine stays ignorant of "audited"
    # (engine ⊥ gate) — it just calls the plain Callable it was handed; the gate composition root selects
    # the real guard policy, and tests inject an explicit test-only opt-out (tests/_backend_optout.py),
    # so there is no guard-less LOGIC path in production.
    _base = make_sandbox

    def factory() -> Sandbox:
        sb = _base()
        backend_guard(sb)
        return sb

    _require_hermetic(factory)
    if not calibration_set.is_adequate:
        return CalibrationResult(
            passed=False, inadequate=True, fn_failures=(), fp_failures=(), flaky=(),
            harness_errors=(), outcomes=(), execution_identity=None, identity_consistent=True,
        )
    # P1-3 v3 (atomicity): ONE resolution yields BOTH the runnable assertion and its profile digest — the
    # digest binds exactly the detector object that runs (no second resolution / disk re-read seam).
    bundle = resolve(detector_id)  # trusted registry only — an unregistered id is refused here
    detector = bundle.assertion
    resolved_profile_digest = bundle.profile_digest
    # B3 (S3): the guard PROVENANCE digest is read off the guard object ACTUALLY APPLIED (never separately
    # supplied), resolved ONCE before the loop and passed into every run so it rides the authoritative
    # TrialReport. The test-only opt-out bears no policy_digest -> None (no bound guard identity).
    guard_policy_digest: str | None = getattr(backend_guard, "policy_digest", None)

    outcomes: list[FixtureOutcome] = []
    # v4 P1-c: execute the FROZEN resolved command (bundle.command), not a fresh detector.entrypoint().
    # S3-completion: read the TrialReport from run_check's AUTHORITATIVE return (EngineRunResult), NOT a
    # mutable capture sink — the calibration decision sources its provenance from the direct return.
    for fixture in (*calibration_set.known_bad, *calibration_set.known_good):
        with _materialised(fixture) as artifact:
            # S3-completion: pass the BASE factory + the guard OBJECT — the RUNNER invokes the guard on every
            # sandbox and derives its digest off the invoked object (measured, not a caller string). The
            # local guarded ``factory`` above is retained ONLY for the one-time ``_require_hermetic`` probe.
            run_result = run_check(
                _base, detector, artifact, budget,
                trials=trials, first_fail=False, detector_id=detector_id,
                command=bundle.command, trust_policy=trust_policy,
                resolved_profile_digest=resolved_profile_digest,
                backend_guard=backend_guard,
            )
        outcomes.append(
            FixtureOutcome(
                fixture_id=fixture.fixture_id,
                label=fixture.label,
                verdict=run_result.verdict,
                classification=_classify(fixture.label, run_result.verdict),
                trials=run_result.trial_report,
            )
        )

    fn = tuple(o.fixture_id for o in outcomes if o.classification is FixtureClass.MISSED)
    fp = tuple(o.fixture_id for o in outcomes if o.classification is FixtureClass.FALSE_POSITIVE)
    flaky = tuple(o.fixture_id for o in outcomes if o.classification is FixtureClass.FLAKY)
    errs = tuple(o.fixture_id for o in outcomes if o.classification is FixtureClass.HARNESS_ERROR)
    # 3.5 #3: the whole calibration must have run under ONE parent-measured execution identity. Each
    # fixture's identity is measured by the runner FROM THE SANDBOX (never fixture-reported); a fixture
    # whose own trials drifted has a None identity (the runner already fail-closed it to ERROR above).
    # If the identities are absent or disagree ACROSS fixtures, the calibration environment is not
    # attestable -> refuse (fail-closed), and the receipt has no honest environment to bind.
    identities = [o.trials.execution_identity for o in outcomes if o.trials is not None]
    identity_consistent = (
        len(identities) == len(outcomes)
        and all(i is not None for i in identities)
        and len({i.digest() for i in identities if i is not None}) == 1
    )
    execution_identity = identities[0] if (identity_consistent and identities) else None
    # B1 (S3): the trust policy applied to each fixture (recorded on its TrialReport). Bind its digest ONLY
    # when EVERY fixture ran under the SAME applied policy — a mixed policy is fail-closed like a mixed
    # execution identity. When no policy was applied, there is nothing to bind (consistent, digest None).
    if trust_policy is None:
        trust_policy_digest: str | None = None
        trust_consistent = True
    else:
        tp_digests = [o.trials.trust_policy_digest for o in outcomes if o.trials is not None]
        trust_consistent = (
            len(tp_digests) == len(outcomes)
            and all(d is not None for d in tp_digests)
            and len(set(tp_digests)) == 1
        )
        trust_policy_digest = tp_digests[0] if (trust_consistent and tp_digests) else None
    # B3 (S3): ``guard_policy_digest`` was read off the guard object ACTUALLY APPLIED before the loop and
    # bound into every fixture's TrialReport. One guard governs the whole run, so it is inherently
    # consistent; policy-A-applied-while-digest-B-supplied is impossible by construction.
    policies_consistent = trust_consistent
    passed = not (fn or fp or flaky or errs) and identity_consistent and policies_consistent
    return CalibrationResult(
        passed=passed, inadequate=False, fn_failures=fn, fp_failures=fp, flaky=flaky,
        harness_errors=errs, outcomes=tuple(outcomes),
        execution_identity=execution_identity, identity_consistent=identity_consistent,
        resolved_profile_digest=resolved_profile_digest,
        trust_policy_digest=trust_policy_digest, guard_policy_digest=guard_policy_digest,
        policies_consistent=policies_consistent,
    )


__all__ = [
    "FixtureLabel",
    "Fixture",
    "CalibrationSet",
    "FixtureClass",
    "FixtureOutcome",
    "CalibrationResult",
    "CalibrationConfigError",
    "DetectorResolver",
    "ResolvedDetector",
    "BundleResolver",
    "calibrate",
    "DEFAULT_CALIBRATION_TRIALS",
]
