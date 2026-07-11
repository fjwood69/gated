"""3.5 job-1 step-1 — the RE_ATTESTATION primitive on the tier store. Run:
python3 -m unittest discover -s tests

Board D1: a re-attestation is an EVIDENCE refresh, not a state transition. Represented as a
prior==new==ENABLED record (zero schema/digest change — bit-for-bit goldens preserved), appendable ONLY
via reattest() (transition() still refuses ENABLED->ENABLED), advancing which calibration_pass justifies
the UNCHANGED ENABLED tier. verify_chain accepts it without a legal edge but re-validates the referenced
pass (replay guard). policy_head is the policy-scoped evidence head for the restore CAS.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.chain import chain_hash
from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState
from gate.policy_store import (
    IllegalTransitionError,
    PrivilegedOperationError,
    PolicyStore,
    _digest_fields,
)


def _appr(*p: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="t", rationale="r", operation_id=op)


def _store() -> PolicyStore:
    return PolicyStore(Path(tempfile.mkdtemp(prefix="mv-reattest-")) / "t.db")


def _enable(s: PolicyStore, pid: str = "p1", *, det: str = "det-1", head: str = "v1",
            set_id: str = "X", ref: str | None = None) -> str:
    ref = ref or f"cal-{pid}-{head}"
    s.transition(pid, PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op=f"{pid}-{head}-1"))
    s.transition(pid, PolicyState.CALIBRATING, approval=_appr("g1", op=f"{pid}-{head}-2"),
                 pinned_set_version=head)
    s.record_calibration_pass(ref, policy_id=pid, pinned_set_version=head, detector_identity=det,
                              set_id=set_id)
    s.transition(pid, PolicyState.ENABLED, approval=_appr("g1", op=f"{pid}-{head}-3"),
                 calibration_result_ref=ref, pinned_set_version=head, detector_identity=det)
    return ref


class ReAttestPrimitiveTests(unittest.TestCase):
    def test_reattest_advances_evidence_state_unchanged(self) -> None:
        s = _store()
        _enable(s, head="v1")
        self.assertEqual(s.current_attestation("p1"), ("X", "v1", "det-1"))
        # fixture appended -> new head v2; async re-cal PASS -> new persisted pass -> re-attest.
        s.record_calibration_pass("cal-v2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X")
        s.reattest("p1", calibration_result_ref="cal-v2", pinned_set_version="v2",
                   detector_identity="det-1", job_id="job-abc", nonce="n1")
        self.assertEqual(s.current_attestation("p1"), ("X", "v2", "det-1"))  # evidence moved forward
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)            # tier UNCHANGED
        self.assertTrue(s.verify_chain())

    def test_transition_still_refuses_enabled_to_enabled(self) -> None:
        # a re-attest cannot be smuggled through the general governance transition path.
        s = _store()
        _enable(s)
        with self.assertRaises(IllegalTransitionError):
            s.transition("p1", PolicyState.ENABLED, approval=_appr("g1", "g2", op="sneak"),
                         calibration_result_ref="cal-p1-v1", pinned_set_version="v1",
                         detector_identity="det-1")

    def test_reattest_requires_enabled(self) -> None:
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="a"))
        with self.assertRaises(IllegalTransitionError):
            s.reattest("p1", calibration_result_ref="x", pinned_set_version="v1",
                       detector_identity="det-1", job_id="j", nonce="n")

    def test_reattest_forged_ref_rejected_gap1(self) -> None:
        s = _store()
        _enable(s)
        with self.assertRaises(PrivilegedOperationError):
            s.reattest("p1", calibration_result_ref="FORGED", pinned_set_version="v1",
                       detector_identity="det-1", job_id="j", nonce="n")

    def test_reattest_mismatched_identity_rejected(self) -> None:
        s = _store()
        _enable(s, det="det-1", head="v1")
        s.record_calibration_pass("cal-v2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X")
        # the pass is for det-1; a re-attest claiming det-EVIL must not resolve it.
        with self.assertRaises(PrivilegedOperationError):
            s.reattest("p1", calibration_result_ref="cal-v2", pinned_set_version="v2",
                       detector_identity="det-EVIL", job_id="j", nonce="n")

    def test_policy_head_is_policy_scoped(self) -> None:
        s = _store()
        _enable(s, "p1")
        _enable(s, "p2")
        h1 = s.policy_head("p1")
        # an append to p2 must NOT move p1's evidence head (avoids cross-policy CAS thrash).
        s.record_calibration_pass("cal-p2-v2", policy_id="p2", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X")
        s.reattest("p2", calibration_result_ref="cal-p2-v2", pinned_set_version="v2",
                   detector_identity="det-1", job_id="j", nonce="n")
        self.assertEqual(s.policy_head("p1"), h1)              # untouched
        self.assertNotEqual(s.policy_head("p2"), h1)


class ReAttestChainReplayGuardTests(unittest.TestCase):
    """Board: verify_chain must reject a re-attest record whose referenced calibration_pass does not
    match the record's own (pinned_set_version, detector_identity) — the direct-DB replay/forge guard,
    beyond the write-time gap-1 check. We hand-craft a hash-valid record bypassing reattest()."""

    def _craft_reattest_row(self, s: PolicyStore, pid: str, *, ref: str, head: str,
                            det: str, job: str = "j", nonce: str = "n") -> None:
        prev = s.head_hash()
        fields = {
            "policy_id": pid, "prior_state": PolicyState.ENABLED.value,
            "new_state": PolicyState.ENABLED.value, "calibration_result_ref": ref,
            "pinned_set_version": head, "detector_identity": det, "principals": "[]",
            "purpose": "re-attestation", "rationale": job, "operation_id": nonce,
            "added_at": 1234.0,
        }
        rec = chain_hash(prev, _digest_fields(fields))
        s._conn().execute(
            "INSERT INTO tier_transition_chain (policy_id, prior_state, new_state,"
            " calibration_result_ref, pinned_set_version, detector_identity, principals, purpose,"
            " rationale, operation_id, added_at, prev_hash, record_hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, PolicyState.ENABLED.value, PolicyState.ENABLED.value, ref, head, det, "[]",
             "re-attestation", job, nonce, 1234.0, prev, rec),
        )

    def test_hash_valid_reattest_with_unresolvable_ref_fails_verify(self) -> None:
        s = _store()
        _enable(s, head="v1")
        # a re-attest record whose ref points at NO persisted pass — hash chain intact, but the
        # replay guard must still reject it.
        self._craft_reattest_row(s, "p1", ref="GHOST", head="v2", det="det-1")
        self.assertFalse(s.verify_chain())

    def test_hash_valid_reattest_with_mismatched_pass_meta_fails_verify(self) -> None:
        s = _store()
        _enable(s, head="v1")
        # a real pass exists for (v2, det-1), but the crafted record claims det-EVIL @ v2 -> the pass
        # metadata does not match the record -> reject.
        s.record_calibration_pass("cal-v2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X")
        self._craft_reattest_row(s, "p1", ref="cal-v2", head="v2", det="det-EVIL")
        self.assertFalse(s.verify_chain())


if __name__ == "__main__":
    unittest.main()
