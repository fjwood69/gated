"""tests/test_engine_run_result.py — S3-completion STEP 1: the AUTHORITATIVE ``EngineRunResult`` return.
Run: python3 -m unittest discover -s tests

The measured evidence travels via the DIRECT return, not a swallowable observer sink. Properties pinned:
  * ``verdict`` is a DERIVED property of the single ``TrialReport.aggregate`` — one source of truth, no
    duplicate copy that could diverge from what admission inspects;
  * both ``EngineRunResult`` and ``TrialReport`` are FROZEN (mutation raises ``FrozenInstanceError``) — a
    routing layer cannot alter measured evidence between the run and admission (frozen prevents ordinary
    accidental mutation in trusted code; it is not an absolute runtime immutability boundary);
  * the report is ALWAYS constructed — it is the return value, not an audit artifact contingent on a sink;
  * a THROWING audit sink is logged, never swallows: the authoritative return + its full report survive;
  * the frozen profile / guard provenance the caller resolved ONCE rides the report.
"""
from __future__ import annotations

import dataclasses
import tempfile
import unittest
from pathlib import Path

from core import (
    ArtifactSpec,
    Command,
    Fixtures,
    IsolationLevel,
    Reason,
    ResourceBudget,
    Verdict,
    VerdictType,
    tree_hash,
)
from engine.runner import EngineRunResult, TrialReport, run_check
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _HermeticNoOp(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


class _Scripted:
    """A RuntimeAssertion double returning pre-scripted verdicts (one per trial)."""

    def __init__(self, verdicts: list[Verdict]) -> None:
        self.fixtures = Fixtures()
        self._v = verdicts
        self._i = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        v = self._v[self._i]
        self._i += 1
        return v


class _ThrowingSink:
    def record(self, report: TrialReport) -> None:
        raise RuntimeError("audit sink boom")


def _artifact() -> ArtifactSpec:
    tmp = Path(tempfile.mkdtemp(prefix="mv-err-"))
    return ArtifactSpec(path=tmp, tree_hash=tree_hash(tmp))


def _report() -> TrialReport:
    return TrialReport(trials=(_PASS,), trials_configured=1, short_circuited=False, aggregate=_PASS)


class SingleSourceTests(unittest.TestCase):
    def test_verdict_is_the_reports_aggregate_no_duplicate(self) -> None:
        # THE single-source property: verdict IS the report's aggregate object — cannot diverge.
        rep = _report()
        res = EngineRunResult(trial_report=rep)
        self.assertIs(res.verdict, rep.aggregate)


class FrozenTests(unittest.TestCase):
    def test_engine_run_result_is_frozen(self) -> None:
        res = EngineRunResult(trial_report=_report())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            res.trial_report = _report()  # type: ignore[misc]

    def test_trial_report_is_frozen(self) -> None:
        rep = _report()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            rep.aggregate = _PASS  # type: ignore[misc]


class AuthoritativeReturnTests(unittest.TestCase):
    def test_report_always_constructed_without_a_sink(self) -> None:
        # the report is the AUTHORITATIVE return — present even when NO audit sink is wired.
        res = run_check(lambda: _HermeticNoOp(), _Scripted([_PASS] * 3), _artifact(), _BUDGET, trials=3)
        self.assertIsInstance(res, EngineRunResult)
        self.assertIsInstance(res.trial_report, TrialReport)
        self.assertIs(res.verdict.status, VerdictType.PASS)
        self.assertEqual(res.trial_report.trials_run, 3)

    def test_throwing_sink_cannot_remove_returned_evidence(self) -> None:
        # a throwing AUDIT sink is logged, never swallows: the authoritative return + full report survive.
        with self.assertLogs("gated.engine", level="WARNING"):
            res = run_check(lambda: _HermeticNoOp(), _Scripted([_PASS]), _artifact(), _BUDGET,
                            trials=1, report_sink=_ThrowingSink())
        self.assertIs(res.verdict.status, VerdictType.PASS)
        self.assertEqual(res.trial_report.trials_run, 1)  # full evidence returned despite sink failure

    def test_measured_provenance_rides_the_authoritative_report(self) -> None:
        # the profile + guard digests the caller resolved ONCE (frozen) are recorded on the return's report.
        res = run_check(lambda: _HermeticNoOp(), _Scripted([_PASS]), _artifact(), _BUDGET, trials=1,
                        resolved_profile_digest="pd-frozen", guard_policy_digest="gd-frozen")
        self.assertEqual(res.trial_report.resolved_profile_digest, "pd-frozen")
        self.assertEqual(res.trial_report.guard_policy_digest, "gd-frozen")

    def test_return_report_is_the_same_instance_the_sink_receives(self) -> None:
        # BYTE-IDENTITY PROOF for the calibration-path migration (sink -> authoritative return): the return
        # carries the SAME TrialReport INSTANCE emitted to the now-secondary audit sink. So a consumer moved
        # from ``capture.last`` to ``result.trial_report`` reads identical bytes -> the derived
        # CalibrationResult, and thus the persisted calibration_pass, is byte-identical by construction.
        class _Cap:
            def __init__(self) -> None:
                self.last: TrialReport | None = None

            def record(self, report: TrialReport) -> None:
                self.last = report

        cap = _Cap()
        res = run_check(lambda: _HermeticNoOp(), _Scripted([_PASS]), _artifact(), _BUDGET, trials=1,
                        report_sink=cap)
        self.assertIs(res.trial_report, cap.last)  # identical instance -> byte-identical report content


if __name__ == "__main__":
    unittest.main()
