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
from dataclasses import replace
from pathlib import Path

from core import (
    ArtifactSpec,
    Command,
    ExecutionResult,
    Fixtures,
    ImageResolutionError,
    IsolationLevel,
    Reason,
    ResourceBudget,
    SandboxHandle,
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


class _DigestNoOp(_HermeticNoOp):
    """A hermetic NoOp that RECORDS a given image_digest in its result — models an OCI backend that
    resolved a digest before run and recorded it (3.5-close #1.1), so the runner reads the identity's
    image coordinate from the RESULT, not the tag."""

    def __init__(self, digest: str) -> None:
        self._digest = digest

    def run(self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget) -> ExecutionResult:
        return replace(super().run(handle, entrypoint, budget), image_digest=self._digest)


class _ImageGoneNoOp(_HermeticNoOp):
    """Models an audited backend whose image was GC'd between resolve and run — prepare() raises
    ImageResolutionError (finding A: must be a fatal ERROR, never a silent pass)."""

    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        raise ImageResolutionError("image absent / GC'd before run")


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


def _digest_drift_factory():  # type: ignore[no-untyped-def]
    """Each trial RECORDS a DIFFERENT image digest -> the run's identity is not consistent -> ERROR."""
    n = {"i": 0}

    def make() -> _DigestNoOp:
        sb = _DigestNoOp(f"sha256:img-{n['i']}")
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
                      trials=3, first_fail=False, report_sink=cap, backend_guard=None).verdict
        self.assertEqual(v.status, VerdictType.PASS)
        ident = cap.last.execution_identity  # type: ignore[union-attr]
        self.assertIsInstance(ident, ExecutionIdentity)
        self.assertEqual(ident.backend, "_HermeticNoOp")       # measured from the sandbox TYPE
        self.assertEqual(ident.isolation_level, "hermetic")    # measured from the sandbox isolation
        self.assertEqual(ident.image_ref, "<_HermeticNoOp>")   # no .image attr -> backend token

    def test_mixed_digest_run_is_error_and_unattested(self) -> None:
        # every trial PASSes, but each RECORDED a different image digest -> fail-closed ERROR, no identity.
        cap = _Capture()
        v = run_check(_digest_drift_factory(), _Scripted([_PASS] * 3), self._artifact, _BUDGET,
                      trials=3, first_fail=False, report_sink=cap, backend_guard=None).verdict
        self.assertEqual(v.status, VerdictType.ERROR)
        self.assertEqual(v.reason, Reason.OBSERVATION_INCOMPLETE)
        self.assertIsNone(cap.last.execution_identity)  # type: ignore[union-attr]

    def test_recorded_digest_is_the_attested_image(self) -> None:
        # 3.5-close #1.1: the identity's image coordinate IS the digest the sandbox recorded (bytes that
        # ran), not a tag or a late resolution.
        cap = _Capture()
        v = run_check(lambda: _DigestNoOp("sha256:deadbeef"), _Scripted([_PASS] * 3), self._artifact,
                      _BUDGET, trials=3, first_fail=False, report_sink=cap, backend_guard=None).verdict
        self.assertEqual(v.status, VerdictType.PASS)
        self.assertEqual(cap.last.execution_identity.image_ref, "sha256:deadbeef")  # type: ignore[union-attr]

    # ---- adversarial harness (finding A): unresolvable image -> ERROR, never a silent pass ----
    def test_image_gone_before_run_is_fatal_error_not_silent_pass(self) -> None:
        cap = _Capture()
        v = run_check(lambda: _ImageGoneNoOp(), _Scripted([_PASS] * 3), self._artifact, _BUDGET,
                      trials=3, first_fail=False, report_sink=cap, backend_guard=None).verdict
        self.assertEqual(v.status, VerdictType.ERROR)          # NOT pass — the detector never got to fire
        self.assertEqual(v.reason, Reason.IMAGE_UNRESOLVED)    # distinct fatal identity reason
        self.assertIsNone(cap.last.execution_identity)  # type: ignore[union-attr]


if __name__ == "__main__":
    unittest.main()
