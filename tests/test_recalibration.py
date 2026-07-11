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
from gate.attestation import verify_measurement
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore, ChangeOp
from gate.recalibration import deterministic_job_id, run_recalibration
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_KEY = b"measurement-key"
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


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
    c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
             set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad")
    c.append(ChangeOp.ADD_KNOWN_GOOD, approval=_appr("g1", "g2", op="2"), fixture_id="g1",
             set_id="X", label=FixtureLabel.KNOWN_GOOD, payload=b"good")
    return c


def _run(c: CalibrationStore, det: _ScriptedDetector, *, nonce: str = "n1"):  # type: ignore[no-untyped-def]
    return run_recalibration(
        policy_id="p1", set_id="X", calibration_store=c, make_sandbox=_factory(), detector=det,
        detector_identity="det-1", tier_generation="tier-h", budget=_BUDGET, issuer="cal-gov-1",
        nonce=nonce, now=100.0, measurement_key=_KEY, trials=3,
    )


class RunnerOutcomeTests(unittest.TestCase):
    def test_clean_two_sided_pass(self) -> None:
        c = _store_with_set()
        att = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3))  # catches b1, passes g1
        verify_measurement(att, measurement_key=_KEY)
        self.assertIs(att.outcome, VerdictType.PASS)
        self.assertTrue(att.is_clean_pass)
        self.assertFalse(att.short_circuit)
        self.assertEqual(att.oracle_head, c.set_head("X"))  # co-sealed head is the live head
        self.assertEqual(att.fixture_coverage, ("b1", "g1"))

    def test_missed_known_bad_is_FAIL_and_names_the_fixture(self) -> None:
        c = _store_with_set()
        att = _run(c, _ScriptedDetector([_PASS] * 3 + [_PASS] * 3))  # MISSES b1
        self.assertIs(att.outcome, VerdictType.FAIL)
        self.assertFalse(att.is_clean_pass)
        self.assertIn("b1", att.fn_failures)  # evidence surfaced for the human split — no auto-resolve

    def test_inadequate_set_is_ERROR(self) -> None:
        c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-recal-i-")) / "c.db")
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad")  # no known-good -> inadequate
        att = _run(c, _ScriptedDetector([_FAIL] * 3))
        self.assertIs(att.outcome, VerdictType.ERROR)
        self.assertFalse(att.is_clean_pass)

    def test_run_id_is_deterministic_nonce_is_not(self) -> None:
        c = _store_with_set()
        a1 = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3), nonce="n1")
        a2 = _run(c, _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3), nonce="n2")
        self.assertEqual(a1.run_id, a2.run_id)  # same (policy,set,head,detector) -> same job
        self.assertEqual(a1.run_id, deterministic_job_id(
            policy_id="p1", set_id="X", oracle_head=c.set_head("X"), detector_identity="det-1"))
        self.assertNotEqual(a1.nonce, a2.nonce)  # attempts stay unique


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
