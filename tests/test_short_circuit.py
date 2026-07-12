"""Increment C1 — first-fail short-circuit in the multi-trial runner.

Run from the gated/ root:  python3 -m unittest discover -s tests

The load-bearing assertions are adversarial-shaped: the short-circuit is PROVEN by the
second sandbox NEVER being created (make_sandbox called exactly once) — not merely by a
FAIL verdict; and the audit sink emitting on the short-circuit path + a throwing sink
being logged-not-swallowed are done-tests, not notes. No podman — the trial verdicts
are scripted so the LOOP FLOW is what's under test.
"""
from __future__ import annotations

import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from core import (
    ArtifactSpec,
    Command,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    Reason,
    ResourceBudget,
    Verdict,
    VerdictType,
    tree_hash,
)
from engine.runner import TrialReport, run_check
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_ERROR = Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


def _artifact() -> ArtifactSpec:
    d = Path(tempfile.mkdtemp(prefix="mv-sc-"))
    (d / "main.py").write_text("x = 1\n", encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


class _ScriptedCheck:
    """A RuntimeAssertion whose assert_invariant returns pre-scripted verdicts in order,
    so the runner's LOOP FLOW (not real observation) is exercised."""

    def __init__(self, verdicts: list[Verdict]) -> None:
        self.fixtures = Fixtures()
        self._verdicts = verdicts
        self._i = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:  # result ignored (scripted)
        v = self._verdicts[self._i]
        self._i += 1
        return v


class _RecordingSink:
    def __init__(self) -> None:
        self.reports: list[TrialReport] = []

    def record(self, report: TrialReport) -> None:
        self.reports.append(report)


class _ThrowingSink:
    def record(self, report: TrialReport) -> None:
        raise RuntimeError("simulated audit-sink failure (locked db)")


def _counting_factory(calls: list[int]):  # type: ignore[no-untyped-def]
    def make() -> NoOpSandbox:
        calls.append(1)
        return NoOpSandbox()
    return make


class _RecordingSandbox:
    """A Sandbox whose session() records prepare/teardown to a shared event log, so a
    test can prove the RAII teardown fired — not just that a sandbox was (or wasn't)
    created. The short-circuit BREAKS out of the trial loop; this catches a teardown
    that was loop-scoped rather than iteration-scoped (a leaked container on the fast
    path). ``session()`` mirrors BaseSandbox's contract: teardown in ``finally``."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC  # required Sandbox coordinate (#3 identity)

    def __init__(self, events: list[str]) -> None:
        self._events = events

    def run(self, handle: object, entrypoint: Command, budget: ResourceBudget) -> ExecutionResult:
        # the check is scripted, but the runner reads result.image_digest for the identity coordinate,
        # so return a conformant ExecutionResult (no image -> None digest).
        return ExecutionResult(outcome="completed", exit_code=0,
                               isolation_level=self.isolation_level, artifact_hash="scripted")

    @contextmanager
    def session(self, artifact: ArtifactSpec, fixtures: Fixtures) -> Iterator[object]:
        self._events.append("prepare")
        try:
            yield object()
        finally:
            self._events.append("teardown")  # RAII: MUST fire on break, return, raise


def _recording_factory(events: list[str], made: list[int]):  # type: ignore[no-untyped-def]
    def make() -> _RecordingSandbox:
        made.append(1)
        return _RecordingSandbox(events)
    return make


class ShortCircuitTests(unittest.TestCase):
    def _run(self, verdicts, calls, **kw):  # type: ignore[no-untyped-def]
        return run_check(
            _counting_factory(calls), _ScriptedCheck(verdicts), _artifact(), _BUDGET, **kw
        )

    def test_first_fail_short_circuits_second_sandbox_never_created(self) -> None:
        calls: list[int] = []
        v = self._run([_FAIL, _PASS], calls, trials=2, first_fail=True)
        self.assertIs(v.status, VerdictType.FAIL)
        self.assertEqual(len(calls), 1)  # THE proof: trial-2 sandbox was never spun up
        self.assertIs(v.reason, Reason.EGRESS_ONE)  # first-observed failure reason

    def test_error_then_fail_runs_both_trials(self) -> None:
        # ERROR must NOT short-circuit — hunt for the behavioural FAIL, don't mask it.
        calls: list[int] = []
        v = self._run([_ERROR, _FAIL], calls, trials=2, first_fail=True)
        self.assertIs(v.status, VerdictType.FAIL)  # observed-FAIL beats ERROR
        self.assertEqual(len(calls), 2)  # both trials ran

    def test_all_error_runs_full_n_and_aggregates_error(self) -> None:
        calls: list[int] = []
        v = self._run([_ERROR, _ERROR], calls, trials=2, first_fail=True)
        self.assertIs(v.status, VerdictType.ERROR)  # not FAIL
        self.assertEqual(len(calls), 2)  # ran to completion

    def test_pass_runs_full_n(self) -> None:
        calls: list[int] = []
        v = self._run([_PASS, _PASS], calls, trials=2, first_fail=True)
        self.assertIs(v.status, VerdictType.PASS)
        self.assertEqual(len(calls), 2)  # unanimity needs all N

    def test_flag_off_runs_full_n_despite_early_fail(self) -> None:
        calls: list[int] = []
        v = self._run([_FAIL, _PASS], calls, trials=2, first_fail=False)
        self.assertIs(v.status, VerdictType.FAIL)
        self.assertIs(v.reason, Reason.NON_DETERMINISTIC)  # full-distribution reason
        self.assertEqual(len(calls), 2)

    def test_verdict_is_order_independent_across_trial_orderings(self) -> None:
        # The short-circuit makes EXECUTION order-sensitive ([FAIL,PASS] stops at 1;
        # [PASS,FAIL] runs both) but the VERDICT must be order-INSENSITIVE: same set of
        # outcomes -> same FAIL. Confirms the optimisation didn't smuggle in an
        # order-dependent verdict — the load-bearing safety property of aggregation.
        fp_calls: list[int] = []
        v_fp = self._run([_FAIL, _PASS], fp_calls, trials=2, first_fail=True)
        pf_calls: list[int] = []
        v_pf = self._run([_PASS, _FAIL], pf_calls, trials=2, first_fail=True)
        self.assertIs(v_fp.status, VerdictType.FAIL)  # short-circuit path
        self.assertIs(v_pf.status, VerdictType.FAIL)  # full-run path
        self.assertEqual(len(fp_calls), 1)  # [FAIL,PASS] stopped at trial 1
        self.assertEqual(len(pf_calls), 2)  # [PASS,FAIL] ran both — PASS doesn't break
        # same verdict STATUS via different execution paths — the invariant that matters


class TeardownOnBreakTests(unittest.TestCase):
    """Board flag #4: 'make_sandbox called once' proves the SECOND sandbox was never
    created — it does NOT prove the FIRST was torn down. A break can orphan a resource
    if teardown was loop-scoped. Prove the fast path leaks nothing."""

    def test_short_circuit_still_tears_down_trial_one_sandbox(self) -> None:
        events: list[str] = []
        made: list[int] = []
        v = run_check(
            _recording_factory(events, made), _ScriptedCheck([_FAIL, _PASS]),
            _artifact(), _BUDGET, trials=2, first_fail=True,
        )
        self.assertIs(v.status, VerdictType.FAIL)
        self.assertEqual(made, [1])  # one sandbox created (short-circuit)
        # THE proof: that one sandbox was prepared AND torn down — no orphan on break.
        self.assertEqual(events, ["prepare", "teardown"])

    def test_every_created_sandbox_is_torn_down_on_full_run(self) -> None:
        events: list[str] = []
        made: list[int] = []
        run_check(
            _recording_factory(events, made), _ScriptedCheck([_PASS, _PASS]),
            _artifact(), _BUDGET, trials=2, first_fail=True,
        )
        self.assertEqual(made, [1, 1])  # two sandboxes
        # perfectly paired teardowns, in order — no leaked container across the full run.
        self.assertEqual(events, ["prepare", "teardown", "prepare", "teardown"])


class TrialReportAuditTests(unittest.TestCase):
    def test_report_emitted_on_short_circuit_path(self) -> None:
        sink = _RecordingSink()
        run_check(
            _counting_factory([]), _ScriptedCheck([_FAIL, _PASS]), _artifact(), _BUDGET,
            trials=2, first_fail=True, report_sink=sink,
        )
        self.assertEqual(len(sink.reports), 1)
        r = sink.reports[0]
        self.assertEqual(r.trials_run, 1)
        self.assertEqual(r.trials_configured, 2)
        self.assertTrue(r.short_circuited)
        self.assertEqual(r.trials[0].reason, Reason.EGRESS_ONE)  # per-trial reason carried
        self.assertIs(r.aggregate.status, VerdictType.FAIL)

    def test_full_run_report_not_short_circuited(self) -> None:
        sink = _RecordingSink()
        run_check(
            _counting_factory([]), _ScriptedCheck([_PASS, _PASS]), _artifact(), _BUDGET,
            trials=2, report_sink=sink,
        )
        r = sink.reports[0]
        self.assertEqual(r.trials_run, 2)
        self.assertFalse(r.short_circuited)

    def test_throwing_sink_is_logged_not_swallowed_verdict_still_returned(self) -> None:
        # the observer must never crash the engine or suppress the Verdict.
        with self.assertLogs("gated.engine", level="WARNING"):
            v = run_check(
                _counting_factory([]), _ScriptedCheck([_FAIL]), _artifact(), _BUDGET,
                trials=1, report_sink=_ThrowingSink(),
            )
        self.assertIs(v.status, VerdictType.FAIL)  # verdict returned despite sink failure


if __name__ == "__main__":
    unittest.main()
