"""Step 3.1 calibrator + 3.2 Oracle-invariant properties. Run: python3 -m unittest discover -s tests

3.1: a detector that MISSES a known-bad is refused (FN); FALSE-POSITIVES a known-good is refused
(FP); a FLAKY-on-ground-truth detector is refused not silently passed (Gap-4); an INADEQUATE set
is refused (P5); calibration runs the FULL distribution (short-circuit OFF).
3.2: calibration REQUIRES HERMETIC (adversarial known-bad); a fixture's LABEL never enters the
materialised artifact (1a); the DETECTOR cannot select which fixtures it faces (1d).
Fixtures are scripted (opaque payloads + a scripted detector) so the CALIBRATOR flow is under test.
"""
from __future__ import annotations

import unittest
from pathlib import Path

from core import (
    Command,
    Fixtures,
    IsolationLevel,
    Reason,
    ResourceBudget,
    Verdict,
    VerdictType,
)
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from engine.calibration import (
    CalibrationConfigError,
    _materialised,
    calibrate,
)
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_TRIALS = 3
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)
_ERROR = Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING)


class _HermeticNoOp(NoOpSandbox):
    """A no-op sandbox that REPORTS hermetic — for calibrator-logic tests (no real execution). The
    real hermeticity is the OCI sandbox's job; here we exercise the calibrator flow, so the double
    is honestly labelled for what it tests."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


_DID = "test-detector"  # the registry NAME the entry point resolves (never a detector object)


def _res(detector: object):  # type: ignore[no-untyped-def]
    """A trivial TRUSTED resolver (the test's trust domain): the entry point takes a detector_id + this
    Callable, never the object directly. The real content-addressed registry is exercised in
    test_detector_registry + test_acceptance."""
    return lambda _id: detector


def _fx(label: FixtureLabel, fid: str, payload: bytes = b"x = 1\n") -> Fixture:
    return Fixture(fixture_id=fid, label=label, payload=payload)


def _hermetic_factory():  # type: ignore[no-untyped-def]
    def make() -> _HermeticNoOp:
        return _HermeticNoOp()
    return make


def _counting_factory(calls: list[int]):  # type: ignore[no-untyped-def]
    def make() -> _HermeticNoOp:
        calls.append(1)
        return _HermeticNoOp()
    return make


class _ScriptedDetector:
    """Returns pre-scripted verdicts in order (calibrator iterates known_bad THEN known_good,
    ``trials`` calls per fixture; the script matches that order). ``fixtures`` is the fault-fixture
    attr of the RuntimeAssertion Protocol — unrelated to the calibration set."""

    def __init__(self, verdicts: list[Verdict], preferred_fixtures: object = None) -> None:
        self.fixtures = Fixtures()
        self.preferred_fixtures = preferred_fixtures  # a hostile "please only test me on X" channel
        self._verdicts = verdicts
        self._i = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        v = self._verdicts[self._i]
        self._i += 1
        return v


def _cal(known_bad, known_good, per_fixture, factory=None, trials=_TRIALS):  # type: ignore[no-untyped-def]
    flat = [v for lst in per_fixture for v in lst]
    cset = CalibrationSet(known_good=tuple(known_good), known_bad=tuple(known_bad))
    return calibrate(factory or _hermetic_factory(), _DID, _res(_ScriptedDetector(flat)),
                     cset, _BUDGET, trials=trials)


class TwoSidedCalibratorTests(unittest.TestCase):
    def test_pass_when_catches_all_bad_and_passes_all_good(self) -> None:
        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        r = _cal([b1], [g1], [[_FAIL] * 3, [_PASS] * 3])
        self.assertTrue(r.passed)
        self.assertIn("PASSED", r.report())
        self.assertIn("resists the current corpus", r.report())

    def test_refuse_on_missed_known_bad_names_the_sample(self) -> None:
        b1, b2, g1 = (_fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_BAD, "b2"),
                      _fx(FixtureLabel.KNOWN_GOOD, "g1"))
        r = _cal([b1, b2], [g1], [[_FAIL] * 3, [_PASS] * 3, [_PASS] * 3])
        self.assertFalse(r.passed)
        self.assertEqual(r.fn_failures, ("b2",))
        self.assertIn("does not catch", r.report())

    def test_refuse_on_false_positive_known_good(self) -> None:
        b1, g1, g2 = (_fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1"),
                      _fx(FixtureLabel.KNOWN_GOOD, "g2"))
        r = _cal([b1], [g1, g2], [[_FAIL] * 3, [_PASS] * 3, [_FAIL] * 3])
        self.assertEqual(r.fp_failures, ("g2",))
        self.assertIn("false positive", r.report())


class GroundTruthDefectTests(unittest.TestCase):
    def test_flaky_detector_refused_not_silent_pass(self) -> None:
        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        r = _cal([b1], [g1], [[_FAIL, _PASS, _FAIL], [_PASS] * 3])
        self.assertFalse(r.passed)
        self.assertEqual(r.flaky, ("b1",))
        self.assertEqual(r.fn_failures, ())
        self.assertIn("non-deterministic", r.report())

    def test_harness_error_inconclusive_never_pass(self) -> None:
        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        r = _cal([b1], [g1], [[_ERROR] * 3, [_PASS] * 3])
        self.assertEqual(r.harness_errors, ("b1",))


class AdequacyGuardTests(unittest.TestCase):
    def test_empty_known_bad_refused_vacuously(self) -> None:
        g1 = _fx(FixtureLabel.KNOWN_GOOD, "g1")
        r = calibrate(_hermetic_factory(), _DID, _res(_ScriptedDetector([])),
                      CalibrationSet(known_good=(g1,), known_bad=()), _BUDGET, trials=_TRIALS)
        self.assertTrue(r.inadequate)
        self.assertIn("inadequate", r.report())


class DistributionAndReproducibilityTests(unittest.TestCase):
    def test_full_trials_run_short_circuit_off(self) -> None:
        # full distribution: a fixture the detector FAILs still runs all trials. +1 for the
        # HERMETIC probe sandbox (created once to read isolation_level).
        calls: list[int] = []
        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        _cal([b1], [g1], [[_FAIL] * 3, [_PASS] * 3], factory=_counting_factory(calls))
        self.assertEqual(len(calls), 1 + 2 * _TRIALS)  # 1 probe + 6 trial sandboxes

    def test_reproducible_same_inputs_same_result(self) -> None:
        b1, b2, g1 = (_fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_BAD, "b2"),
                      _fx(FixtureLabel.KNOWN_GOOD, "g1"))
        script = [[_FAIL] * 3, [_PASS] * 3, [_PASS] * 3]
        r1 = _cal([b1, b2], [g1], script)
        r2 = _cal([b1, b2], [g1], script)
        self.assertEqual((r1.passed, r1.fn_failures), (r2.passed, r2.fn_failures))

    def test_engine_side_no_gate_import(self) -> None:
        for mod in ("calibration.py",):
            src = (Path(__file__).resolve().parent.parent / "engine" / mod).read_text()
            self.assertNotIn("from gate", src)
            self.assertNotIn("import gate", src)


class ExecutionIdentityTests(unittest.TestCase):
    """3.5 #3 — a calibration run carries the single PARENT-MEASURED identity all its fixtures shared,
    and refuses (fail-closed) if the fixtures did not all run under ONE attestable environment."""

    def test_consistent_run_carries_one_execution_identity(self) -> None:
        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        r = _cal([b1], [g1], [[_FAIL] * 3, [_PASS] * 3])
        self.assertTrue(r.passed)
        self.assertTrue(r.identity_consistent)
        self.assertIsNotNone(r.execution_identity)
        self.assertEqual(r.execution_identity.isolation_level, "hermetic")  # type: ignore[union-attr]
        self.assertEqual(r.execution_identity.image_ref, "<_HermeticNoOp>")  # type: ignore[union-attr]

    def test_mixed_identity_across_fixtures_refuses_fail_closed(self) -> None:
        # a factory whose sandbox image DRIFTS every construction -> each fixture's run is itself mixed
        # -> the calibration is unattestable -> passed False + identity None + report says so.
        n = {"i": 0}

        def drift() -> _HermeticNoOp:
            sb = _HermeticNoOp()
            sb.image = f"img-{n['i']}"  # type: ignore[attr-defined]
            n["i"] += 1
            return sb

        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        r = _cal([b1], [g1], [[_FAIL] * 3, [_PASS] * 3], factory=drift)
        self.assertFalse(r.passed)
        self.assertFalse(r.identity_consistent)
        self.assertIsNone(r.execution_identity)
        self.assertIn("not attestable", r.report())


class OracleInvariantTests(unittest.TestCase):
    """3.2 — the Oracle-invariant properties the calibrator must hold."""

    def test_hermetic_required_rejects_weak_sandbox(self) -> None:
        # Board Prescription 2: adversarial known-bad fixtures must not run in a WEAK sandbox.
        def weak_factory() -> NoOpSandbox:
            return NoOpSandbox()  # isolation_level = WEAK
        b1, g1 = _fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_GOOD, "g1")
        cset = CalibrationSet(known_good=(g1,), known_bad=(b1,))
        with self.assertRaises(CalibrationConfigError):
            calibrate(weak_factory, _DID, _res(_ScriptedDetector([_FAIL] * 6)), cset, _BUDGET,
                      trials=_TRIALS)

    def test_1a_fixture_label_never_enters_materialised_artifact(self) -> None:
        # 1a: a fixture executing in the sandbox must not be able to read its own label. The
        # materialised artifact contains ONLY the opaque payload — no known_bad/known_good marker,
        # no fixture_id.
        bad = _fx(FixtureLabel.KNOWN_BAD, "secret-fixture-id", payload=b"print('hi')\n")
        with _materialised(bad) as artifact:
            files = list(artifact.path.rglob("*"))
            self.assertEqual([p.name for p in files if p.is_file()], ["main.py"])
            blob = b"".join(p.read_bytes() for p in files if p.is_file()).lower()
            self.assertNotIn(b"known_bad", blob)
            self.assertNotIn(b"secret-fixture-id", blob)  # the id doesn't leak either
            self.assertEqual((artifact.path / "main.py").read_bytes(), b"print('hi')\n")

    def test_1d_detector_cannot_select_its_fixtures(self) -> None:
        # 1d: a detector that declares a fixture preference is IGNORED — the calibrator runs the
        # FULL set the caller injected. Here the detector "prefers" only b1, but b2 (which it
        # misses) is still run and still refuses enablement.
        b1, b2, g1 = (_fx(FixtureLabel.KNOWN_BAD, "b1"), _fx(FixtureLabel.KNOWN_BAD, "b2"),
                      _fx(FixtureLabel.KNOWN_GOOD, "g1"))
        cset = CalibrationSet(known_good=(g1,), known_bad=(b1, b2))
        # detector catches b1 [FAIL], MISSES b2 [PASS], passes g1 [PASS] — and "prefers" only b1.
        detector = _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3 + [_PASS] * 3, preferred_fixtures=["b1"])
        r = calibrate(_hermetic_factory(), _DID, _res(detector), cset, _BUDGET, trials=_TRIALS)
        self.assertFalse(r.passed)
        self.assertEqual(r.fn_failures, ("b2",))  # b2 was run despite the detector's preference
        self.assertEqual(len(r.outcomes), 3)       # ALL 3 fixtures evaluated


if __name__ == "__main__":
    unittest.main()
