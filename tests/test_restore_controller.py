"""3.5 job-1 step-3 — the RESTORE CONTROLLER + the full re-calibration loop. Run:
python3 -m unittest discover -s tests

The crux of Job 1: a signed clean PASS on an ENABLED-but-drifted policy re-attests it (evidence
advances, tier unchanged) and live enforcement RESUMES; a FAIL is a no-op on governance state (the
policy stays blocking); a stale/untrusted/demoted case is refused. The end-to-end test walks the whole
loop: enable -> fixture append (live UNATTESTABLE) -> runner PASS -> controller RESTORED -> live
RUN_ENFORCING again.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Command, Fixtures, IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import FixtureLabel
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore, ChangeOp
from gate.gatekeeper import resolve_disposition
from gate.policy_state import Disposition, PolicyState
from gate.policy_store import PolicyStore
from gate.recalibration import run_recalibration
from gate.restore_controller import (
    ReAttestCapability,
    RestoreController,
    RestoreResult,
)
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_MEAS_KEY = b"measurement-key-epoch-1"
_ISSUER = "cal-gov-1"
_DET = "det-1"
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


def _cal_store() -> CalibrationStore:
    c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-rc-cal-")) / "c.db")
    c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
             set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad1")
    c.append(ChangeOp.ADD_KNOWN_GOOD, approval=_appr("g1", "g2", op="2"), fixture_id="g1",
             set_id="X", label=FixtureLabel.KNOWN_GOOD, payload=b"good1")
    return c


def _policy_store_enabled(head: str) -> PolicyStore:
    s = PolicyStore(Path(tempfile.mkdtemp(prefix="mv-rc-pol-")) / "t.db")
    s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="a"))
    s.transition("p1", PolicyState.CALIBRATING, approval=_appr("g1", op="b"), pinned_set_version=head)
    s.record_calibration_pass("cal-0", policy_id="p1", pinned_set_version=head,
                              detector_identity=_DET, set_id="X")
    s.transition("p1", PolicyState.ENABLED, approval=_appr("g1", op="c"),
                 calibration_result_ref="cal-0", pinned_set_version=head, detector_identity=_DET)
    return s


def _controller(s: PolicyStore, c: CalibrationStore, *, trusted: bool = True) -> RestoreController:
    return RestoreController(
        ReAttestCapability(s), issuer_keys={_ISSUER: _MEAS_KEY},
        oracle_head_for=c.set_head, identity_trusted=lambda _i: trusted)


def _run(c: CalibrationStore, verdicts: list[Verdict], *, tier_gen: str = "tg", nonce: str = "n1"):  # type: ignore[no-untyped-def]
    return run_recalibration(
        policy_id="p1", set_id="X", calibration_store=c, make_sandbox=_factory(),
        detector=_ScriptedDetector(verdicts), detector_identity=_DET, tier_generation=tier_gen,
        budget=_BUDGET, issuer=_ISSUER, nonce=nonce, now=100.0, measurement_key=_MEAS_KEY, trials=3)


class RestoreControllerTests(unittest.TestCase):
    def test_full_loop_enable_drift_recal_restore_reenforce(self) -> None:
        c = _cal_store()
        h0 = c.set_head("X")
        s = _policy_store_enabled(h0)
        # enabled + head current -> enforcing.
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.RUN_ENFORCING)
        # a security engineer appends a new known-bad -> set_head moves -> live UNATTESTABLE (blocking).
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="drift"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.BLOCK_ACTION_REQUIRED)
        # async re-cal: detector now catches BOTH known-bad (b1,b2) and passes g1 -> clean PASS @ new head.
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3)
        self.assertIs(att.outcome, VerdictType.PASS)
        # the restore controller re-attests.
        outcome = _controller(s, c).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.RESTORED)
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)   # tier NEVER changed
        # live enforcement RESUMES — the evidence now matches the current head.
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.RUN_ENFORCING)

    def test_fail_is_noop_on_governance_state(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="drift"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        head_before = s.policy_head("p1")
        # re-cal MISSES the new known-bad -> FAIL.
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3 + [_PASS] * 3)  # catches b1, MISSES b2, passes g1
        self.assertIs(att.outcome, VerdictType.FAIL)
        outcome = _controller(s, c).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.REFUSED_NOT_CLEAN_PASS)
        self.assertEqual(s.policy_head("p1"), head_before)  # NO record appended — meter didn't move tier
        # still blocking (transiently UNATTESTABLE).
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.BLOCK_ACTION_REQUIRED)

    def test_bad_issuer_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)
        ctrl = RestoreController(ReAttestCapability(s), issuer_keys={"other": _MEAS_KEY},
                                 oracle_head_for=c.set_head)
        self.assertIs(ctrl.attempt_restore(att).result, RestoreResult.REFUSED_UNTRUSTED)

    def test_wrong_key_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)
        ctrl = RestoreController(ReAttestCapability(s), issuer_keys={_ISSUER: b"WRONG-KEY"},
                                 oracle_head_for=c.set_head)
        self.assertIs(ctrl.attempt_restore(att).result, RestoreResult.REFUSED_UNTRUSTED)

    def test_stale_oracle_head_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)  # PASS bound to the CURRENT head
        # the set drifts AGAIN after the measurement, before restore.
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="drift2"), fixture_id="b9",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad9")
        self.assertIs(_controller(s, c).attempt_restore(att).result, RestoreResult.REFUSED_ORACLE_STALE)

    def test_revoked_identity_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)
        self.assertIs(_controller(s, c, trusted=False).attempt_restore(att).result,
                      RestoreResult.REFUSED_UNTRUSTED)

    def test_demoted_policy_cannot_auto_restore(self) -> None:
        # asymmetry: a human-demoted (ADVISORY) policy has no re-attest path — must re-ratify.
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)  # a valid clean PASS
        s.transition("p1", PolicyState.ADVISORY, approval=_appr("g1", "g2", op="demote"))  # human demote
        self.assertIs(_controller(s, c).attempt_restore(att).result, RestoreResult.REFUSED_NOT_ENABLED)


class RestoreControllerStructuralTests(unittest.TestCase):
    def test_controller_does_not_import_engine_or_runner(self) -> None:
        src = (Path(__file__).resolve().parent.parent / "gate" / "restore_controller.py").read_text()
        imports = [ln for ln in src.splitlines() if ln.startswith(("import ", "from "))]
        joined = "\n".join(imports)
        self.assertNotIn("engine", joined)
        self.assertNotIn("recalibration", joined)  # governance half must not import the runner

    def test_capability_exposes_no_arbitrary_transition(self) -> None:
        # board amendment 1: the restore capability is restricted to the RE_ATTESTATION record kind.
        self.assertFalse(hasattr(ReAttestCapability, "transition"))


if __name__ == "__main__":
    unittest.main()
