"""3.5 job-1 step-2 — the re-calibration RUNNER (the meter that cannot move the tier). Run:
python3 -m unittest discover -s tests

Load-bearing: the runner emits a SIGNED measurement and nothing else. It has NO PolicyStore (measurement
≠ governance is structural); it seals the set under one snapshot (fourth-hole) so head+coverage co-exist;
a clean two-sided pass -> PASS, a miss -> FAIL (surfacing the missed fixture as evidence, no auto-resolve),
an inadequate/harness-error -> ERROR; short_circuit is always False; run_id is the deterministic job id.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Command, Fixtures, IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import FixtureLabel
from gate.signing import KeyVerifier, SeedSigner, public_key
from gate.attestation import calibrated_subject_identity, verify_measurement
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore, ChangeOp
from gate.calibration_store import AdmissionCapability
from gate.detector_registry import DetectorRegistry, UnregisteredDetectorError, profile_of
from gate.recalibration import deterministic_job_id, run_recalibration
from sandbox.noop import NoOpSandbox
from tests._backend_optout import allow_any_backend

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_SEED = bytes(range(32))
_PUB = public_key(_SEED)
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


_ADMIT_CAP = AdmissionCapability()


class _HermeticNoOp(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _factory():  # type: ignore[no-untyped-def]
    return lambda: _HermeticNoOp()


class _ScriptedDetector:
    def __init__(self, verdicts: list[Verdict]) -> None:
        self.fixtures = Fixtures()
        self._verdicts = verdicts
        self._i = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        v = self._verdicts[self._i]
        self._i += 1
        return v


def _appr(*p: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="admit", rationale="r", operation_id=op)


def _store_with_set() -> CalibrationStore:
    c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-recal-")) / "c.db")
    c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
             set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad")
    c.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="2"), fixture_id="g1",
             set_id="X", label=FixtureLabel.KNOWN_GOOD, payload=b"good")
    return c


def _run(c: CalibrationStore, det: _ScriptedDetector, *, nonce: str = "n1",  # type: ignore[no-untyped-def]
         requested: str = "det-1", resolve=None):
    # detectors arrive by NAME through a trusted content-addressed registry via the ATOMIC bundle (P1-3
    # v3). The SIGNED subject identity is measurement-derived; ``requested`` is the governance target
    # (signed, but not measurement authority).
    reg = DetectorRegistry()
    reg.register("d", lambda: det, accepted_profile_digest=profile_of("d", det).digest())
    return run_recalibration(
        policy_id="p1", set_id="X", calibration_store=c, make_sandbox=_factory(),
        detector_id="d", resolve=resolve or reg.resolve_bundle,
        requested_subject_identity=requested, tier_generation="tier-h", budget=_BUDGET, issuer="cal-gov-1",
        nonce=nonce, now=100.0, signer=SeedSigner(_SEED), trials=3, backend_guard=allow_any_backend
    )


class RunnerOutcomeTests(unittest.TestCase):
    def test_clean_two_sided_pass(self) -> None:
        c = _store_with_set()
        att = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3))  # catches b1, passes g1
        verify_measurement(att, verifier=KeyVerifier(_PUB))
        self.assertIs(att.outcome, VerdictType.PASS)
        self.assertTrue(att.is_clean_pass)
        self.assertFalse(att.short_circuit)
        self.assertEqual(att.oracle_head, c.set_head("X"))  # co-sealed head is the live head
        self.assertEqual(att.fixture_coverage, ("b1", "g1"))
        # P1-3: the signed subject is measurement-derived from BOTH components (present on a PASS).
        self.assertIsNotNone(att.resolved_profile_digest)
        self.assertIsNotNone(att.execution_identity_digest)
        self.assertEqual(att.subject_identity, calibrated_subject_identity(
            att.resolved_profile_digest, att.execution_identity_digest))  # type: ignore[arg-type]

    def test_missed_known_bad_is_FAIL_and_names_the_fixture(self) -> None:
        c = _store_with_set()
        att = _run(c, _ScriptedDetector([_PASS] * 3 + [_PASS] * 3))  # MISSES b1
        self.assertIs(att.outcome, VerdictType.FAIL)
        self.assertFalse(att.is_clean_pass)
        self.assertIn("b1", att.fn_failures)  # evidence surfaced for the human split — no auto-resolve

    def test_inadequate_set_is_ERROR(self) -> None:
        c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-recal-i-")) / "c.db")
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad")  # no known-good -> inadequate
        att = _run(c, _ScriptedDetector([_FAIL] * 3))
        self.assertIs(att.outcome, VerdictType.ERROR)
        self.assertFalse(att.is_clean_pass)

    def test_run_id_is_deterministic_nonce_is_not(self) -> None:
        c = _store_with_set()
        a1 = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3), nonce="n1")
        a2 = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3), nonce="n2")
        self.assertEqual(a1.run_id, a2.run_id)  # same (policy,set,head,subject) -> same job
        self.assertEqual(a1.run_id, deterministic_job_id(
            policy_id="p1", set_id="X", oracle_head=c.set_head("X"), subject_identity="det-1"))
        self.assertNotEqual(a1.nonce, a2.nonce)  # attempts stay unique

    def test_signed_subject_is_measurement_derived_not_the_caller_dedup_key(self) -> None:
        # P1-3 core close: the SIGNED subject_identity is derived from the MEASURED run (resolved-profile
        # digest + parent-measured execution identity), NEVER from the caller's expected_subject_identity
        # (a dedup key only). A spoofed expected value cannot become the signed identity (no sign-A-run-B).
        c = _store_with_set()
        att = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3), requested="totally-spoofed-identity")
        verify_measurement(att, verifier=KeyVerifier(_PUB))
        self.assertNotEqual(att.subject_identity, "totally-spoofed-identity")
        self.assertEqual(att.requested_subject_identity, "totally-spoofed-identity")  # signed governance value
        self.assertEqual(att.subject_identity, calibrated_subject_identity(
            att.resolved_profile_digest, att.execution_identity_digest))  # type: ignore[arg-type]

    def test_unresolved_detector_is_signed_error_and_non_restorable(self) -> None:
        # P1-3 conditional validity: a drifted / unregistered detector yields a SIGNED ERROR audit
        # attestation with null components and null subject — categorically non-restorable (never a
        # measurement that could restore a tier), and it must still verify as a valid signed record.
        c = _store_with_set()

        def _drift(_id: str) -> object:
            raise UnregisteredDetectorError("the detector is no longer registered")

        att = _run(c, _ScriptedDetector([]), resolve=_drift)
        verify_measurement(att, verifier=KeyVerifier(_PUB))
        self.assertIs(att.outcome, VerdictType.ERROR)
        self.assertIsNone(att.subject_identity)
        self.assertIsNone(att.execution_identity_digest)
        self.assertIsNone(att.resolved_profile_digest)
        self.assertFalse(att.is_clean_pass)


class RunnerStructuralSeparationTests(unittest.TestCase):
    def test_runner_module_does_not_import_policy_store(self) -> None:
        # measurement ≠ governance, structural: the runner cannot touch the tier store at all. Check
        # the IMPORT lines only (the docstring legitimately discusses PolicyStore-absence in prose).
        src = (Path(__file__).resolve().parent.parent / "gate" / "recalibration.py").read_text()
        imports = [ln for ln in src.splitlines()
                   if ln.startswith("import ") or ln.startswith("from ")]
        joined = "\n".join(imports)
        self.assertNotIn("policy_store", joined)
        self.assertNotIn("PolicyStore", joined)
        self.assertNotIn("ledger", joined)


if __name__ == "__main__":
    unittest.main()
