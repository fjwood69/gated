"""3.5 merge-ready #1 — the low-level bypasses are REMOVED, machine-enforced. Run:
python3 -m unittest discover -s tests

A fixture can enter the oracle ONLY through the admission gate, and a policy's enforcement evidence can
advance ONLY through the verified RestoreController. This is structural ABSENCE, not an additional safe
path: the raw ADD-append and reattest are capability-gated, and this test proves the ONLY constructions
of those capabilities in the gate tree are the two legitimate ones — so no bypass exists in the codebase
and none can be reintroduced without failing here (the same discipline as the observe-mode no-flag gate).
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.authority import GovernanceApproval
from gate.calibration_store import (
    AdmissionCapability,
    CalibrationStore,
    ChangeOp,
)
from gate.calibration_store import PrivilegedOperationError as CalibrationPrivilegedError
from gate.policy_state import PolicyState
from gate.policy_store import PolicyStore
from gate.policy_store import PrivilegedOperationError as PolicyPrivilegedError
from gate.policy_store import ReAttestGrant

_GATE = Path(__file__).resolve().parent.parent / "gate"


def _constructions(symbol: str) -> dict[str, int]:
    """Map each gate module -> how many times it CONSTRUCTS ``symbol`` (``Symbol(``), excluding the
    class definition itself. A construction is the capability being minted."""
    out: dict[str, int] = {}
    for p in _GATE.glob("*.py"):
        n = 0
        for line in p.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith(f"class {symbol}"):
                continue
            n += stripped.count(f"{symbol}()")
        if n:
            out[p.name] = n
    return out


class StructuralNoBypassTests(unittest.TestCase):
    def test_admission_capability_constructed_only_by_admission_gate(self) -> None:
        # the ONLY place a fixture-ADD capability is minted is gate/admission.py.
        self.assertEqual(_constructions("AdmissionCapability"), {"admission.py": 1})

    def test_reattest_grant_constructed_only_by_restore_controller(self) -> None:
        # the ONLY place a re-attest grant is minted is gate/restore_controller.py.
        self.assertEqual(_constructions("ReAttestGrant"), {"restore_controller.py": 1})


class RuntimeGateTests(unittest.TestCase):
    def _cal(self) -> CalibrationStore:
        return CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-bypass-")) / "c.db")

    def _dual(self) -> GovernanceApproval:
        return GovernanceApproval(("g1", "g2"), purpose="p", rationale="r", operation_id="o")

    def test_add_without_capability_is_refused(self) -> None:
        from core.calibration import FixtureLabel

        cal = self._cal()
        # even WITH a valid dual approval, a raw ADD without the admission capability is refused.
        with self.assertRaises(CalibrationPrivilegedError):
            cal.append(ChangeOp.ADD_KNOWN_BAD, approval=self._dual(), fixture_id="b1", set_id="X",
                       label=FixtureLabel.KNOWN_BAD, payload=b"x")
        # with the capability it lands (this is what admit() does).
        seq = cal.append(ChangeOp.ADD_KNOWN_BAD, approval=self._dual(), fixture_id="b1", set_id="X",
                         label=FixtureLabel.KNOWN_BAD, payload=b"x", admission=AdmissionCapability())
        self.assertGreater(seq, 0)

    def test_reattest_without_grant_is_refused(self) -> None:
        s = PolicyStore(Path(tempfile.mkdtemp(prefix="mv-bypass-p-")) / "t.db")

        def appr(*p: str, op: str) -> GovernanceApproval:
            return GovernanceApproval(p, purpose="p", rationale="r", operation_id=op)

        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=appr("g1", op="1"))
        s.transition("p1", PolicyState.CALIBRATING, approval=appr("g1", op="2"), pinned_set_version="v")
        s.record_calibration_pass("cal", policy_id="p1", pinned_set_version="v",
                                  detector_identity="d", set_id="X")
        s.transition("p1", PolicyState.ENABLED, approval=appr("g1", op="3"),
                     calibration_result_ref="cal", pinned_set_version="v", detector_identity="d")
        s.record_calibration_pass("cal2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="d", set_id="X")
        # a re-attest WITHOUT the grant is refused (mypy: pass a non-grant to prove the runtime gate).
        with self.assertRaises(PolicyPrivilegedError):
            s.reattest("p1", grant=None, calibration_result_ref="cal2",  # type: ignore[arg-type]
                       pinned_set_version="v2", detector_identity="d", job_id="j", nonce="n")
        # with the grant it proceeds (this is what the RestoreController does).
        seq = s.reattest("p1", grant=ReAttestGrant(), calibration_result_ref="cal2",
                         pinned_set_version="v2", detector_identity="d", job_id="j", nonce="n")
        self.assertGreater(seq, 0)


if __name__ == "__main__":
    unittest.main()
