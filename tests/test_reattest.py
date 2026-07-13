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
    ReAttestConflict,
    _digest_fields,
    _mint_reattest_grant,
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
                              set_id=set_id, identity_contract_version=1)
    s.transition(pid, PolicyState.ENABLED, approval=_appr("g1", op=f"{pid}-{head}-3"),
                 calibration_result_ref=ref, pinned_set_version=head, detector_identity=det, identity_contract_version=1)
    return ref


_GRANT = _mint_reattest_grant()


def _reattest(s: PolicyStore, pid: str, *, ref: str, psv: str, det: str,
              job: str = "j", nonce: str = "n") -> int:
    """reattest filling the now-MANDATORY CAS expectations from the store's CURRENT state (the
    non-racing happy path a direct caller uses). Stale-expectation negatives call ``s.reattest``
    directly with a deliberately wrong expectation."""
    att = s.current_attestation(pid)
    subj = att[2] if att is not None else "unused"  # unreached: a not-ENABLED policy fails earlier
    return s.reattest(pid, grant=_GRANT, calibration_result_ref=ref, pinned_set_version=psv,
                      detector_identity=det, job_id=job, nonce=nonce,
                      expect_policy_head=s.policy_head(pid), expect_authorized_subject=subj, identity_contract_version=1)


class ReAttestPrimitiveTests(unittest.TestCase):
    def test_reattest_advances_evidence_state_unchanged(self) -> None:
        s = _store()
        _enable(s, head="v1")
        self.assertEqual(s.current_attestation("p1"), ("X", "v1", "det-1"))
        # fixture appended -> new head v2; async re-cal PASS -> new persisted pass -> re-attest.
        s.record_calibration_pass("cal-v2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X", identity_contract_version=1)
        _reattest(s, "p1", ref="cal-v2", psv="v2", det="det-1", job="job-abc", nonce="n1")
        self.assertEqual(s.current_attestation("p1"), ("X", "v2", "det-1"))  # evidence moved forward
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)            # tier UNCHANGED
        self.assertTrue(s.verify_chain())

    def test_subject_for_pass_is_policy_scoped(self) -> None:
        # A4 (v5-neg-only): a calibration_pass minted for p1 cannot recover a subject for p2 —
        # subject_for_pass is scoped by (ref, policy_id, pinned_set_version), so p1's ref can never
        # enable p2 (GLM's cross-policy concern, already closed in code; this pins it with a negative).
        s = _store()
        _enable(s, "p1", det="det-1", head="v1")   # ref cal-p1-v1 bound to p1
        self.assertEqual(s.subject_for_pass("cal-p1-v1", "p1", "v1"), "det-1")
        self.assertIsNone(s.subject_for_pass("cal-p1-v1", "p2", "v1"))   # p1's pass can't enable p2

    def test_pass_from_another_identity_contract_is_invisible(self) -> None:
        # S3 ckpt4-fix: a calibration_pass recorded under a DIFFERENT identity_contract_version is not
        # matchable by the read paths (subject_for_pass) — so a pass composed under another identity
        # contract can never enable / re-attest under the current one (ICV exact-match).
        s = _store()
        s.record_calibration_pass("cal-x", policy_id="p1", pinned_set_version="v1", detector_identity="d",
                                  set_id="X", identity_contract_version=99)
        self.assertIsNone(s.subject_for_pass("cal-x", "p1", "v1"))  # wrong ICV -> not found
        # a matching-ICV pass IS visible (control).
        s.record_calibration_pass("cal-y", policy_id="p1", pinned_set_version="v1", detector_identity="d",
                                  set_id="X", identity_contract_version=1)
        self.assertEqual(s.subject_for_pass("cal-y", "p1", "v1"), "d")

    def test_transition_still_refuses_enabled_to_enabled(self) -> None:
        # a re-attest cannot be smuggled through the general governance transition path.
        s = _store()
        _enable(s)
        with self.assertRaises(IllegalTransitionError):
            s.transition("p1", PolicyState.ENABLED, approval=_appr("g1", "g2", op="sneak"),
                         calibration_result_ref="cal-p1-v1", pinned_set_version="v1",
                         detector_identity="det-1", identity_contract_version=1)

    def test_reattest_requires_enabled(self) -> None:
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="a"))
        with self.assertRaises(IllegalTransitionError):
            _reattest(s, "p1", ref="x", psv="v1", det="det-1")

    def test_reattest_forged_ref_rejected_gap1(self) -> None:
        s = _store()
        _enable(s)
        with self.assertRaises(PrivilegedOperationError):
            _reattest(s, "p1", ref="FORGED", psv="v1", det="det-1")

    def test_reattest_mismatched_identity_rejected(self) -> None:
        s = _store()
        _enable(s, det="det-1", head="v1")
        s.record_calibration_pass("cal-v2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X", identity_contract_version=1)
        # the pass is for det-1; a re-attest claiming det-EVIL must not resolve it.
        with self.assertRaises(PrivilegedOperationError):
            _reattest(s, "p1", ref="cal-v2", psv="v2", det="det-EVIL")

    def test_policy_head_is_policy_scoped(self) -> None:
        s = _store()
        _enable(s, "p1")
        _enable(s, "p2")
        h1 = s.policy_head("p1")
        # an append to p2 must NOT move p1's evidence head (avoids cross-policy CAS thrash).
        s.record_calibration_pass("cal-p2-v2", policy_id="p2", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X", identity_contract_version=1)
        _reattest(s, "p2", ref="cal-p2-v2", psv="v2", det="det-1")
        self.assertEqual(s.policy_head("p1"), h1)              # untouched
        self.assertNotEqual(s.policy_head("p2"), h1)


class ReAttestMandatoryExpectationTests(unittest.TestCase):
    """v5-P1c: the CAS expectations are the LOAD-BEARING tooth (the grant is only a call-path
    convention). They are MANDATORY — omitting one is impossible at the API — and a STALE expectation
    aborts with ReAttestConflict rather than landing a re-attest over a moved head / authorized subject.
    Remove either check and a stale re-attest lands: that is the failure these pin."""

    def _ready(self) -> PolicyStore:
        s = _store()
        _enable(s, head="v1")  # p1 ENABLED, det-1
        s.record_calibration_pass("cal-v2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X", identity_contract_version=1)
        return s

    def test_expectations_are_required_kwargs(self) -> None:
        s = self._ready()
        # no expect_policy_head / expect_authorized_subject -> TypeError at the call boundary (they are
        # mandatory keyword args now); the None opt-out that let a caller skip the CAS is gone.
        with self.assertRaises(TypeError):
            s.reattest("p1", grant=_GRANT, calibration_result_ref="cal-v2",  # type: ignore[call-arg]
                       pinned_set_version="v2", detector_identity="det-1", job_id="j", nonce="n", identity_contract_version=1)

    def test_stale_policy_head_aborts(self) -> None:
        s = self._ready()
        att = s.current_attestation("p1")
        assert att is not None
        with self.assertRaises(ReAttestConflict):
            s.reattest("p1", grant=_GRANT, calibration_result_ref="cal-v2", pinned_set_version="v2",
                       detector_identity="det-1", job_id="j", nonce="n",
                       expect_policy_head="STALE-head-that-never-matches",
                       expect_authorized_subject=att[2], identity_contract_version=1)

    def test_stale_authorized_subject_aborts(self) -> None:
        s = self._ready()
        with self.assertRaises(ReAttestConflict):
            s.reattest("p1", grant=_GRANT, calibration_result_ref="cal-v2", pinned_set_version="v2",
                       detector_identity="det-1", job_id="j", nonce="n",
                       expect_policy_head=s.policy_head("p1"),
                       expect_authorized_subject="a-DIFFERENT-authorized-subject", identity_contract_version=1)


class ChainPassLinkageTests(unittest.TestCase):
    """S3 ckpt4-fix2b: the hash-chained record and its unchained calibration_pass row stay LINKED for
    EVERY ->ENABLED record (initial enable AND re-attest). Tampering the pass beneath an INITIAL enable —
    which the earlier code did NOT check — must break verify_chain."""

    def test_tampering_pass_beneath_initial_enable_breaks_verify(self) -> None:
        for col, val in (("identity_contract_version", 99), ("detector_identity", "det-EVIL"),
                         ("pinned_set_version", "v-EVIL")):
            s = _store()
            _enable(s, head="v1")  # an INITIAL enable (CALIBRATING -> ENABLED)
            self.assertTrue(s.verify_chain())
            s._conn().execute(  # tamper the unchained pass row beneath the enable
                f"UPDATE calibration_pass SET {col}=? WHERE policy_id=?", (val, "p1"))
            self.assertFalse(s.verify_chain(), f"tampering pass.{col} beneath an initial enable not detected")

    def test_tampering_chain_detector_or_ref_breaks_verify(self) -> None:
        for col, val in (("detector_identity", "chain-EVIL"), ("calibration_result_ref", "ref-EVIL")):
            s = _store()
            _enable(s, head="v1")
            s._conn().execute(
                f"UPDATE tier_transition_chain SET {col}=? WHERE new_state=? AND policy_id=?",
                (val, PolicyState.ENABLED.value, "p1"))
            self.assertFalse(s.verify_chain(), f"chain.{col} is not hashed")

    def test_conflicting_pass_metadata_is_rejected(self) -> None:
        s = _store()
        s.record_calibration_pass("cal-x", policy_id="p1", pinned_set_version="v1", detector_identity="d",
                                  set_id="X", identity_contract_version=1)
        s.record_calibration_pass("cal-x", policy_id="p1", pinned_set_version="v1", detector_identity="d",
                                  set_id="X", identity_contract_version=1)  # identical -> idempotent
        with self.assertRaises(PrivilegedOperationError):  # conflicting metadata under the same ref
            s.record_calibration_pass("cal-x", policy_id="p1", pinned_set_version="v1",
                                      detector_identity="DIFFERENT", set_id="X",
                                      identity_contract_version=1)


class MixedIcvChainTests(unittest.TestCase):
    """The replay-against-recorded-ICV path proven for its design scenario: a chain with records under
    DIFFERENT valid ICVs verifies, because each ->ENABLED record is replayed against ITS OWN recorded ICV."""

    def test_chain_with_mixed_icvs_verifies(self) -> None:
        s = _store()
        _enable(s, head="v1")  # initial enable at ICV=1 (+ a pass at ICV=1)
        # a matching pass + a hand-crafted re-attest record recorded under ICV=2 (a future contract).
        s.record_calibration_pass("cal-v2icv2", policy_id="p1", pinned_set_version="v2",
                                  detector_identity="det-1", set_id="X", identity_contract_version=2)
        prev = s.head_hash()
        fields = {
            "policy_id": "p1", "prior_state": PolicyState.ENABLED.value,
            "new_state": PolicyState.ENABLED.value, "calibration_result_ref": "cal-v2icv2",
            "pinned_set_version": "v2", "detector_identity": "det-1", "identity_contract_version": 2,
            "principals": "[]", "purpose": "re-attestation", "rationale": "j", "operation_id": "n",
            "added_at": 1234.0,
        }
        rec = chain_hash(prev, _digest_fields(fields))
        s._conn().execute(
            "INSERT INTO tier_transition_chain (policy_id, prior_state, new_state,"
            " calibration_result_ref, pinned_set_version, detector_identity, identity_contract_version,"
            " principals, purpose, rationale, operation_id, added_at, prev_hash, record_hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("p1", PolicyState.ENABLED.value, PolicyState.ENABLED.value, "cal-v2icv2", "v2", "det-1", 2,
             "[]", "re-attestation", "j", "n", 1234.0, prev, rec),
        )
        # each ->ENABLED record replays against its OWN recorded ICV (1 then 2) -> the whole chain verifies.
        self.assertTrue(s.verify_chain())


class ReAttestChainReplayGuardTests(unittest.TestCase):
    """Board: verify_chain must reject a re-attest record whose referenced calibration_pass does not
    match the record's own (pinned_set_version, detector_identity) — the direct-DB replay/forge guard,
    beyond the write-time gap-1 check. We hand-craft a hash-valid record bypassing reattest()."""

    def _craft_reattest_row(self, s: PolicyStore, pid: str, *, ref: str, head: str,
                            det: str, job: str = "j", nonce: str = "n", icv: int = 1) -> None:
        prev = s.head_hash()
        fields = {
            "policy_id": pid, "prior_state": PolicyState.ENABLED.value,
            "new_state": PolicyState.ENABLED.value, "calibration_result_ref": ref,
            "pinned_set_version": head, "detector_identity": det,
            "identity_contract_version": icv, "principals": "[]",
            "purpose": "re-attestation", "rationale": job, "operation_id": nonce,
            "added_at": 1234.0,
        }
        rec = chain_hash(prev, _digest_fields(fields))
        s._conn().execute(
            "INSERT INTO tier_transition_chain (policy_id, prior_state, new_state,"
            " calibration_result_ref, pinned_set_version, detector_identity, identity_contract_version,"
            " principals, purpose, rationale, operation_id, added_at, prev_hash, record_hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (pid, PolicyState.ENABLED.value, PolicyState.ENABLED.value, ref, head, det, icv, "[]",
             "re-attestation", job, nonce, 1234.0, prev, rec),
        )

    def test_tampering_chain_identity_contract_version_breaks_verify(self) -> None:
        # S3 ckpt4-fix: identity_contract_version is IN the record hash (tamper-evident). Altering it on a
        # stored ENABLED record must break verify_chain — the ICV can no longer be silently changed without
        # detection (the earlier gap: ICV lived only on the unchained calibration_pass).
        s = _store()
        _enable(s, head="v1")
        self.assertTrue(s.verify_chain())
        s._conn().execute(
            "UPDATE tier_transition_chain SET identity_contract_version=99 "
            "WHERE new_state=? AND policy_id=?", (PolicyState.ENABLED.value, "p1"))
        self.assertFalse(s.verify_chain())  # the hash covers ICV -> the edit is detected

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
                                  detector_identity="det-1", set_id="X", identity_contract_version=1)
        self._craft_reattest_row(s, "p1", ref="cal-v2", head="v2", det="det-EVIL")
        self.assertFalse(s.verify_chain())


if __name__ == "__main__":
    unittest.main()
