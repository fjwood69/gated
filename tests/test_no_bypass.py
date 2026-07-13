"""3.5 merge-ready #1 — the low-level paths are capability-gated by a CALL-PATH convention, machine-
enforced. Run: python3 -m unittest discover -s tests

A fixture enters the oracle through the admission gate, and a policy's enforcement evidence advances
through the verified RestoreController. These capabilities are a trusted-process CALL-PATH convention
(accidental-reintroduction tripwire), NOT an in-process authorization boundary — a co-resident adversary
could mint one, so the load-bearing controls live elsewhere (for re-attest: reattest's MANDATORY
chain-checked expectations; at deploy tier: an authenticated store boundary). What this test proves is
STRUCTURAL: the ONLY minters of those capabilities in the gate tree are the two legitimate ones, so the
low-level path cannot be reintroduced by accident without failing here (the same discipline as the
observe-mode no-flag gate). Honest about scope: structural absence of a second minter, not unforgeability.
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
from gate.policy_store import _mint_reattest_grant

_GATE = Path(__file__).resolve().parent.parent / "gate"


def _constructions(symbol: str) -> dict[str, int]:
    """Map each gate module -> how many times it MINTS ``symbol`` (``Symbol()``), excluding the symbol's
    own class/def line. A mint is the capability being produced."""
    out: dict[str, int] = {}
    for p in _GATE.glob("*.py"):
        n = 0
        for line in p.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith(f"class {symbol}") or stripped.startswith(f"def {symbol}"):
                continue
            n += stripped.count(f"{symbol}()")
        if n:
            out[p.name] = n
    return out


class StructuralNoBypassTests(unittest.TestCase):
    def test_admission_capability_constructed_only_by_admission_gate(self) -> None:
        # the ONLY place a fixture-ADD capability is minted is gate/admission.py.
        self.assertEqual(_constructions("AdmissionCapability"), {"admission.py": 1})

    def test_reattest_grant_minted_only_by_restore_controller(self) -> None:
        # the ONLY caller of the re-attest mint in the gate tree is gate/restore_controller.py. This is
        # a call-path convention (accidental-reintroduction tripwire), NOT an authorization boundary —
        # the load-bearing controls are reattest's mandatory chain-checked expectations.
        self.assertEqual(_constructions("_mint_reattest_grant"), {"restore_controller.py": 1})


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
                                  detector_identity="d", set_id="X", identity_contract_version=1)
        s.transition("p1", PolicyState.ENABLED, approval=appr("g1", op="3"),
                     calibration_result_ref="cal", set_id="X", pinned_set_version="v",
                     detector_identity="d", identity_contract_version=1)
        s.record_calibration_pass("cal2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="d", set_id="X", identity_contract_version=1)
        head = s.policy_head("p1")
        ctx = s.current_authorized_context("p1")  # the policy's currently authorized (set, subject, ICV)
        assert ctx is not None
        # an accidental NON-grant call is refused at the call-path tripwire. Not framed as a bypass —
        # a co-resident adversary could mint a grant; the teeth are the mandatory expectations below.
        with self.assertRaises(PolicyPrivilegedError):
            s.reattest("p1", grant=None, calibration_result_ref="cal2", set_id="X",  # type: ignore[arg-type]
                       pinned_set_version="v2", detector_identity="d", job_id="j", nonce="n",
                       expect_policy_head=head, expect_authorized_context=ctx, identity_contract_version=1)
        # through the mint it proceeds (this is what the RestoreController does).
        seq = s.reattest("p1", grant=_mint_reattest_grant(), calibration_result_ref="cal2", set_id="X",
                         pinned_set_version="v2", detector_identity="d", job_id="j", nonce="n",
                         expect_policy_head=head, expect_authorized_context=ctx, identity_contract_version=1)
        self.assertGreater(seq, 0)


if __name__ == "__main__":
    unittest.main()
