"""tests/test_job_result.py — CP2 S5a: the EXHAUSTIVE JobResult accounting map.

Every union member maps to HONEST persistence + publication fields (no fabricated verdict), and any
non-union type (a bare Verdict / EngineRunResult) is REJECTED — so the Executor can never persist an
unaccounted outcome.
"""
from __future__ import annotations

import unittest

from core import Reason, Verdict, VerdictType
from engine.runner import EngineRunResult
from gate.checkrun import CheckConclusion
from gate.job_result import (
    InfrastructureFailure,
    NonRunDecision,
    PersistedOutcome,
    account,
)
from gate.policy_state import Disposition
from gate.run_admission import BlockingRefusal, RunAdmissionRefusal
from tests.test_run_admission import _FakeGovernance, _admit, _plan, _report


class AccountMapperTests(unittest.TestCase):
    def test_admitted_run_maps_to_done_with_the_actual_verdict(self) -> None:
        admitted = _admit(_plan(), _report(aggregate=Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)),
                          _FakeGovernance())
        out = account(admitted)
        self.assertEqual(out.status, "done")
        assert out.verdict is not None
        self.assertIs(out.verdict.status, VerdictType.PASS)          # the ACTUAL engine verdict
        self.assertIs(out.conclusion, CheckConclusion.SUCCESS)

    def test_blocking_refusal_maps_to_done_error_run_unadmitted(self) -> None:
        ref = BlockingRefusal(RunAdmissionRefusal.SET_HEAD_STALE, "drift")
        out = account(ref)
        self.assertEqual(out.status, "done")                         # the gate ran to a REFUSAL decision
        assert out.verdict is not None
        self.assertIs(out.verdict.status, VerdictType.ERROR)
        self.assertIs(out.verdict.reason, Reason.RUN_UNADMITTED)
        self.assertIs(out.conclusion, CheckConclusion.ACTION_REQUIRED)

    def test_non_run_neutral_maps_to_done_no_verdict_neutral(self) -> None:
        out = account(NonRunDecision(Disposition.SKIP_NEUTRAL, "not enabled"))
        self.assertEqual(out.status, "done")
        self.assertIsNone(out.verdict)                               # NOTHING ran — no fabricated verdict
        self.assertIs(out.conclusion, CheckConclusion.NEUTRAL)

    def test_non_run_block_maps_to_done_no_verdict_action_required(self) -> None:
        out = account(NonRunDecision(Disposition.BLOCK_ACTION_REQUIRED, "degraded"))
        self.assertEqual(out.status, "done")                         # a blocking gate outcome, recorded
        self.assertIsNone(out.verdict)
        self.assertIs(out.conclusion, CheckConclusion.ACTION_REQUIRED)

    def test_infrastructure_failure_maps_to_error_no_verdict_blocking(self) -> None:
        out = account(InfrastructureFailure("detector_unresolved", "drifted"))
        self.assertEqual(out.status, "error")                        # the machinery FAULTED
        self.assertIsNone(out.verdict)                               # no gate verdict was produced
        self.assertIs(out.conclusion, CheckConclusion.ACTION_REQUIRED)
        self.assertIsInstance(out, PersistedOutcome)

    def test_non_run_decision_refuses_run_enforcing(self) -> None:
        with self.assertRaises(ValueError):
            NonRunDecision(Disposition.RUN_ENFORCING, "x")

    def test_account_rejects_a_bare_verdict(self) -> None:
        with self.assertRaises(TypeError):
            account(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))  # type: ignore[arg-type]

    def test_account_rejects_a_bare_engine_run_result(self) -> None:
        with self.assertRaises(TypeError):
            account(EngineRunResult(trial_report=_report()))          # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
