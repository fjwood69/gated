"""3.5 #3 — the runner PARENT-MEASURES each trial's execution identity FROM THE SANDBOX it constructed
(never fixture/child-reported) and fail-closes a MIXED-identity run to ERROR. Run:
python3 -m unittest discover -s tests

The property under test: identity is a coordinate of the ENVIRONMENT the runner enforced, so a run whose
trials drifted (image/backend/isolation changed mid-run) is UNATTESTABLE -> ERROR + no bound identity,
even if every trial PASSed. ``pin_image`` resolves the tag to an immutable digest ONCE for the attested
identity, not once per trial.
"""
from __future__ import annotations

import shutil
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
from engine.runner import ExecutionIdentity, run_check
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


class _Capture:
    def __init__(self) -> None:
        self.last = None  # type: ignore[var-annotated]

    def record(self, report: object) -> None:
        self.last = report  # type: ignore[assignment]


def _drift_factory():  # type: ignore[no-untyped-def]
    """Each trial gets a sandbox reporting a DIFFERENT image -> the run's identity is not consistent."""
    n = {"i": 0}

    def make() -> _HermeticNoOp:
        sb = _HermeticNoOp()
        sb.image = f"img-{n['i']}"  # type: ignore[attr-defined]
        n["i"] += 1
        return sb

    return make


class ParentMeasuredIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self._d = Path(tempfile.mkdtemp(prefix="mv-run-"))
        (self._d / "main.py").write_bytes(b"x = 1\n")
        self._artifact = ArtifactSpec(path=self._d, tree_hash=tree_hash(self._d))

    def tearDown(self) -> None:
        shutil.rmtree(self._d, ignore_errors=True)

    def test_consistent_run_has_attested_parent_measured_identity(self) -> None:
        cap = _Capture()
        v = run_check(lambda: _HermeticNoOp(), _Scripted([_PASS] * 3), self._artifact, _BUDGET,
                      trials=3, first_fail=False, report_sink=cap)
        self.assertEqual(v.status, VerdictType.PASS)
        ident = cap.last.execution_identity  # type: ignore[union-attr]
        self.assertIsInstance(ident, ExecutionIdentity)
        self.assertEqual(ident.backend, "_HermeticNoOp")       # measured from the sandbox TYPE
        self.assertEqual(ident.isolation_level, "hermetic")    # measured from the sandbox isolation
        self.assertEqual(ident.image_ref, "<_HermeticNoOp>")   # no .image attr -> backend token

    def test_mixed_identity_run_is_error_and_unattested(self) -> None:
        # every trial PASSes, but they ran in DIFFERENT environments -> fail-closed ERROR, no identity.
        cap = _Capture()
        v = run_check(_drift_factory(), _Scripted([_PASS] * 3), self._artifact, _BUDGET,
                      trials=3, first_fail=False, report_sink=cap)
        self.assertEqual(v.status, VerdictType.ERROR)
        self.assertEqual(v.reason, Reason.OBSERVATION_INCOMPLETE)
        self.assertIsNone(cap.last.execution_identity)  # type: ignore[union-attr]

    def test_pin_image_resolves_once_for_the_attested_identity(self) -> None:
        calls: list[str] = []

        def pin(tag: str) -> str:
            calls.append(tag)
            return f"sha256:{tag}"

        def make() -> _HermeticNoOp:
            sb = _HermeticNoOp()
            sb.image = "reg/app:tag"  # type: ignore[attr-defined]
            return sb

        cap = _Capture()
        run_check(make, _Scripted([_PASS] * 3), self._artifact, _BUDGET,
                  trials=3, first_fail=False, report_sink=cap, pin_image=pin)
        self.assertEqual(len(calls), 1)  # pinned ONCE for the receipt, not per trial
        self.assertEqual(cap.last.execution_identity.image_ref, "sha256:reg/app:tag")  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
