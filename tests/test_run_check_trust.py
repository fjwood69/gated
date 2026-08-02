"""tests/test_run_check_trust.py — S3 checkpoint 2: run_check APPLIES the observation trust policy BEFORE
the detector. Run: python3 -m unittest discover -s tests

The security-critical property: an always-PASS detector is NEVER consulted for an untrusted observation
(timeout / error / malformed), so it cannot launder such a run into a PASS. A trusted ``completed``
observation (zero OR non-zero exit) reaches the detector; ``egress_attempts=None`` reaches it (detector-
semantic). The applied policy digest is recorded on the TrialReport as measured provenance.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import (
    EgressAbsence,
    ArtifactSpec,
    Command,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    Reason,
    ResourceBudget,
    SandboxHandle,
    Verdict,
    VerdictType,
    tree_hash,
)
from engine.runner import TrialReport, run_check
from gate.trust_policy import resolve_trust_policy
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_POLICY = resolve_trust_policy("trust-policy:completed-only")


class _OutcomeNoOp(NoOpSandbox):
    """A hermetic NoOp whose result carries a CHOSEN outcome / exit_code / egress — models a real run that
    completed, timed out, errored, or produced a malformed result.

    ⚠ ``observes_egress = True`` IS LOAD-BEARING AND WAS MISSING. This fake emits COUNTS while inheriting
    NoOpSandbox's ``observes_egress = False``, i.e. it declared "I have no boundary observer" and then
    reported measurements. The runner's capability check caught it on its first full run — six tests in
    this file — which is the check doing its job rather than being decorative: the fake models an
    OBSERVING backend's telemetry, so it must SAY it observes.
    """

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC
    observes_egress: bool = True

    def __init__(self, outcome: str, exit_code: int | None,
                 egress: int | EgressAbsence = 2) -> None:
        self._outcome = outcome
        self._exit = exit_code
        self._egress = egress

    def run(self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget) -> ExecutionResult:
        # CONSTRUCTS ITS OWN RESULT rather than `replace()`-ing NoOpSandbox's. The parent DERIVES its
        # absence from ``observes_egress``, and this fake declares True — so the parent's derivation
        # correctly REFUSES to hand back NOT_OBSERVED, and borrowing its result to overwrite the field
        # was the fake having it both ways: a non-observer's construction wearing an observer's claim.
        return ExecutionResult(
            outcome=self._outcome,  # type: ignore[arg-type]
            exit_code=self._exit,
            isolation_level=self.isolation_level,
            artifact_hash=handle.artifact_hash,
            egress_attempts=self._egress,
            raw_return_code=self._exit,
        )


class _AlwaysPass:
    """A detector that ALWAYS returns PASS and records whether it was consulted — so a test can prove the
    trust policy skipped it on an untrusted observation."""

    def __init__(self) -> None:
        self.fixtures = Fixtures()
        self.called = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: ExecutionResult) -> Verdict:
        self.called += 1
        return Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


def _artifact(tmp: Path) -> ArtifactSpec:
    return ArtifactSpec(path=tmp, tree_hash=tree_hash(tmp))


class _Capture:
    def __init__(self) -> None:
        self.reports: list[TrialReport] = []

    def record(self, report: TrialReport) -> None:
        self.reports.append(report)


class TrustPolicyApplicationTests(unittest.TestCase):
    def _run(self, outcome: str, exit_code: int | None, egress: int | None = 2):  # type: ignore[no-untyped-def]
        tmp = Path(tempfile.mkdtemp(prefix="mv-tp-"))
        det = _AlwaysPass()
        cap = _Capture()
        v = run_check(lambda: _OutcomeNoOp(outcome, exit_code, egress), det, _artifact(tmp), _BUDGET,
                      trials=1, trust_policy=_POLICY, report_sink=cap, backend_guard=None).verdict
        return v, det, cap.reports[0]

    def test_always_pass_not_called_on_timeout(self) -> None:
        v, det, rep = self._run("timeout", None)
        self.assertIs(v.status, VerdictType.ERROR)
        self.assertEqual(det.called, 0)  # detector NEVER consulted -> cannot launder a timeout into a PASS
        self.assertEqual(rep.trust_policy_digest, _POLICY.policy_digest)  # applied policy recorded as provenance

    def test_always_pass_not_called_on_error(self) -> None:
        v, det, _ = self._run("error", None)
        self.assertIs(v.status, VerdictType.ERROR)
        self.assertEqual(det.called, 0)

    def test_always_pass_not_called_on_malformed(self) -> None:
        # completed with exit_code=None fails the schema invariant -> MALFORMED -> ERROR, detector skipped.
        v, det, _ = self._run("completed", None)
        self.assertIs(v.status, VerdictType.ERROR)
        self.assertEqual(det.called, 0)

    def test_completed_zero_reaches_detector(self) -> None:
        v, det, _ = self._run("completed", 0)
        self.assertIs(v.status, VerdictType.PASS)
        self.assertEqual(det.called, 1)

    def test_completed_nonzero_reaches_detector(self) -> None:
        # a non-zero completed exit code is a TRUSTED observation — the detector decides its meaning.
        v, det, _ = self._run("completed", 3)
        self.assertIs(v.status, VerdictType.PASS)
        self.assertEqual(det.called, 1)

    def test_egress_none_reaches_detector(self) -> None:
        # egress_attempts=None is detector-semantic telemetry, not a trust concern -> the detector still runs.
        v, det, _ = self._run("completed", 0, egress=EgressAbsence.OBSERVER_UNREADABLE)
        self.assertIs(v.status, VerdictType.PASS)
        self.assertEqual(det.called, 1)

    def test_no_policy_preserves_current_behaviour(self) -> None:
        # without a trust_policy, run_check consults the detector as before (backward-compatible — the
        # policy is threaded by the calibration/enforcement path, checkpoint 3).
        tmp = Path(tempfile.mkdtemp(prefix="mv-tp-"))
        det = _AlwaysPass()
        run_check(lambda: _OutcomeNoOp("timeout", None), det, _artifact(tmp), _BUDGET, trials=1, backend_guard=None)
        self.assertEqual(det.called, 1)  # detector consulted (no policy gating)


if __name__ == "__main__":
    unittest.main()
