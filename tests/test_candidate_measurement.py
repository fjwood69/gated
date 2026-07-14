"""3.5 S3-completion CP4 Slice B — the shared measurement spine: frozen contracts + witness teeth.

  * ``PreparedCandidate`` and ``CandidateMeasurement`` are FROZEN (single-seal / single-resolve are
    structural, and a measured result cannot be mutated after the fact).
  * The WITNESS self-consistency check BITES on a mid-run mutation of the applied trust OR guard object —
    a policy that shifts to a CONSISTENT-but-different digest between prepare and the run (the case the
    aggregation alone waves through) fails closed with ``WitnessInconsistencyError``.
  * A guard whose digest is MIXED ACROSS fixtures (inconsistent) is caught by the aggregation itself:
    ``guard_policy_digest`` is None, the run does not attest a clean subject (fail-closed), and — because
    the coordinate was never measured — the witness check does NOT raise (that path is the outcome
    mapping's job, so the signed runner can still emit ERROR evidence rather than crash).
"""
from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError

from core import IsolationLevel, ResourceBudget, Reason, Verdict, VerdictType
from core.calibration import Fixture, FixtureLabel
from gate.candidate_measurement import (
    WitnessInconsistencyError,
    prepare_candidate,
    produce_candidate_measurement,
)
from gate.recalibration import run_recalibration
from gate.trust_policy import resolve_trust_policy
from sandbox.noop import NoOpSandbox
from tests._backend_optout import test_guard_policy
from tests._golden_detector import GoldenScriptedDetector, golden_resolver
from tests.test_gatekeeper import _MutatingTrust, _cal_store

_REF_TP = resolve_trust_policy("trust-policy:completed-only")
_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)
_KB = (Fixture("b1", FixtureLabel.KNOWN_BAD, b"y"),)
_KG = (Fixture("g1", FixtureLabel.KNOWN_GOOD, b"z"),)


class _H(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _fac():  # type: ignore[no-untyped-def]
    return lambda: _H()


def _det() -> GoldenScriptedDetector:
    return GoldenScriptedDetector([_FAIL] * 3 + [_PASS] * 3)


class _MutatingGuard:
    """A guard that accepts any backend but whose ``policy_digest`` SHIFTS after the first read — v1 at
    prepare (the witness), v2 (stable) during the run. Consistent within the run, so the aggregation binds
    it; the witness catches that it is NOT the prepared identity."""

    policy_id = "mut-guard:v1"

    def __init__(self) -> None:
        self._n = 0

    @property
    def policy_digest(self) -> str:
        self._n += 1
        return "g-v1" if self._n == 1 else "g-v2"

    def __call__(self, sandbox: object) -> None:
        return None


class _MixedGuard:
    """A guard whose ``policy_digest`` DIFFERS on every read — so it is inconsistent ACROSS fixtures and the
    aggregation binds None (fail-closed), never reaching the witness comparison."""

    policy_id = "mixed-guard:v1"

    def __init__(self) -> None:
        self._n = 0

    @property
    def policy_digest(self) -> str:
        self._n += 1
        return f"g-{self._n}"

    def __call__(self, sandbox: object) -> None:
        return None


def _prepare_and_produce(*, trust_policy=_REF_TP, backend_guard=test_guard_policy):  # type: ignore[no-untyped-def]
    cal = _cal_store(known_bad=_KB, known_good=_KG)
    sealed = cal.seal_set("default")
    prepared = prepare_candidate(sealed, resolve=golden_resolver(_det()), detector_id="d",
                                 trust_policy=trust_policy, backend_guard=backend_guard)
    return produce_candidate_measurement(
        prepared, make_sandbox=_fac(), budget=_BUDGET,
        backend_guard=backend_guard, trust_policy=trust_policy, trials=3)


class FrozenContractTests(unittest.TestCase):
    def test_prepared_candidate_is_frozen(self) -> None:
        cal = _cal_store(known_bad=_KB, known_good=_KG)
        prepared = prepare_candidate(cal.seal_set("default"), resolve=golden_resolver(_det()),
                                     detector_id="d", trust_policy=_REF_TP, backend_guard=test_guard_policy)
        with self.assertRaises(FrozenInstanceError):
            prepared.detector_id = "other"  # type: ignore[misc]

    def test_candidate_measurement_is_frozen(self) -> None:
        m = _prepare_and_produce()
        with self.assertRaises(FrozenInstanceError):
            m.subject_identity = "forged"  # type: ignore[misc]


class WitnessTeethTests(unittest.TestCase):
    def test_witness_fires_on_midrun_trust_mutation(self) -> None:
        with self.assertRaises(WitnessInconsistencyError):
            _prepare_and_produce(trust_policy=_MutatingTrust(_REF_TP))

    def test_witness_fires_on_midrun_guard_mutation(self) -> None:
        with self.assertRaises(WitnessInconsistencyError):
            _prepare_and_produce(backend_guard=_MutatingGuard())

    def test_stable_policies_do_not_fire_the_witness(self) -> None:
        m = _prepare_and_produce()  # control: stable trust + guard -> clean pass, subject bound
        self.assertTrue(m.result.passed)
        self.assertIsNotNone(m.subject_identity)


class RunnerNeverCrashesTests(unittest.TestCase):
    def test_run_recalibration_emits_signed_error_on_mutating_policy(self) -> None:
        # the runner's contract is "always emit signed evidence, never crash". A mid-run policy mutation
        # (which trips the spine's witness check) must become a SIGNED ERROR attestation, not an uncaught
        # WitnessInconsistencyError. Import locally to keep the spine-unit module free of the recal setup.
        from gate.signing import KeyVerifier, SeedSigner, public_key
        from gate.attestation import verify_measurement
        cal = _cal_store(known_bad=_KB, known_good=_KG)
        seed = bytes(range(32))
        att = run_recalibration(
            policy_id="p1", set_id="default", calibration_store=cal, make_sandbox=_fac(),
            detector_id="d", resolve=golden_resolver(_det()), requested_subject_identity="req-1",
            tier_generation="tier-h", budget=_BUDGET, issuer="cal-gov-1", nonce="n1", now=100.0,
            signer=SeedSigner(seed), trials=3, backend_guard=_MutatingGuard(), trust_policy=_REF_TP,
        )
        verify_measurement(att, verifier=KeyVerifier(public_key(seed)))  # still a valid signed record
        self.assertIs(att.outcome, VerdictType.ERROR)
        self.assertIsNone(att.subject_identity)
        self.assertFalse(att.is_clean_pass)
        self.assertIn("policy-witness-inconsistent", att.harness_errors)


class MixedGuardAggregationTests(unittest.TestCase):
    def test_mixed_guard_fails_closed_without_a_witness_raise(self) -> None:
        # inconsistent across fixtures -> aggregation binds None -> not a clean pass, no subject; the witness
        # does NOT raise (the coordinate was never measured), leaving the fail-closed to the outcome.
        m = _prepare_and_produce(backend_guard=_MixedGuard())
        self.assertIsNone(m.guard_policy_digest)
        self.assertFalse(m.result.passed)
        self.assertIsNone(m.subject_identity)


if __name__ == "__main__":
    unittest.main()
