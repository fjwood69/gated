"""tests/test_refresh_intent.py — 3.5 S3-completion CP4 Slice 1: the atomic CALIBRATING recovery intent.
Run: python3 -m unittest discover -s tests

``enter_calibrating`` is the path into CALIBRATING that atomically (one BEGIN IMMEDIATE) appends the tier
transition AND creates the pending re-calibration recovery intent, so a CALIBRATING policy — invisible to
the ENABLED-only relay — is never silently stranded. Properties pinned:
  * the intent carries ROUTING inputs (detector / trust / guard / set / head / ICV), NOT a measured subject
    (nothing is measured at CALIBRATING entry — a subject here would be declared-not-measured);
  * ``target_generation`` is DERIVED from the appended record_hash (== the new policy head), not caller-supplied;
  * the CALIBRATING tier row is byte-identical to a bare transition (routing is on the INTENT, and the tier
    row's ``detector_identity`` — the MEASURED subject — stays NULL until ENABLED);
  * degenerate routing inputs (empty string / bool-or-str / wrong ICV) are refused;
  * an illegal entry writes NOTHING (neither tier row nor intent).

The intent state machine / CRUD accessor / partial unique index / completion CAS are Slice A; this reads
the table directly.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState
from gate.policy_store import IllegalTransitionError, PolicyStore, PrivilegedOperationError

_ROUTING = dict(set_id="setA", pinned_set_version="oracle-head-1", detector_id="retry",
                trust_policy_ref="tp-digest", guard_policy_ref="gp-digest",
                identity_contract_version=IDENTITY_CONTRACT_VERSION)


def _appr(*principals: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose="p", rationale="r", operation_id=op)


def _store() -> PolicyStore:
    return PolicyStore(Path(tempfile.mkdtemp(prefix="mv-cp4-")) / "p.db")


def _pending(s: PolicyStore, pid: str = "p1") -> None:
    s.transition(pid, PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op=f"{pid}-1"))


def _intent(s: PolicyStore, pid: str = "p1"):  # type: ignore[no-untyped-def]
    return s._conn().execute("SELECT * FROM refresh_intent WHERE policy_id=?", (pid,)).fetchall()


class EnterCalibratingTests(unittest.TestCase):
    def test_atomically_creates_calibrating_and_a_pending_routing_intent(self) -> None:
        s = _store()
        _pending(s)
        s.enter_calibrating("p1", approval=_appr("g1", op="p1-2"), **_ROUTING)  # type: ignore[arg-type]
        self.assertIs(s.current_state("p1"), PolicyState.CALIBRATING)
        rows = _intent(s)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["status"], "pending")
        self.assertEqual(row["set_id"], "setA")
        self.assertEqual(row["target_head"], "oracle-head-1")      # routing: the oracle head to calibrate at
        self.assertEqual(row["detector_id"], "retry")
        self.assertEqual(row["trust_policy_ref"], "tp-digest")
        self.assertEqual(row["guard_policy_ref"], "gp-digest")
        self.assertEqual(row["identity_contract_version"], IDENTITY_CONTRACT_VERSION)
        self.assertEqual(row["churn_count"], 0)                    # cumulative counter starts at 0
        # no measured subject on the intent — its columns are routing only.
        self.assertNotIn("detector_identity", row.keys())
        self.assertNotIn("subject", row.keys())

    def test_target_generation_is_the_derived_new_policy_head(self) -> None:
        # target_generation is DERIVED from the appended record_hash (== policy_head), not caller-supplied.
        s = _store()
        _pending(s)
        s.enter_calibrating("p1", approval=_appr("g1", op="p1-2"), **_ROUTING)  # type: ignore[arg-type]
        self.assertEqual(_intent(s)[0]["target_generation"], s.policy_head("p1"))

    def test_tier_row_is_byte_identical_routing_not_on_the_chain(self) -> None:
        # the CALIBRATING tier row carries ONLY pinned_set_version; set_id / detector_identity / ICV stay
        # NULL (the tier row's detector_identity is the MEASURED subject, absent until ENABLED). Routing
        # lives on the intent, so the tier chain is unchanged from a bare CALIBRATING transition.
        s = _store()
        _pending(s)
        s.enter_calibrating("p1", approval=_appr("g1", op="p1-2"), **_ROUTING)  # type: ignore[arg-type]
        trow = s._conn().execute(
            "SELECT * FROM tier_transition_chain WHERE policy_id='p1' AND new_state='calibrating'"
        ).fetchone()
        self.assertEqual(trow["pinned_set_version"], "oracle-head-1")
        self.assertIsNone(trow["set_id"])
        self.assertIsNone(trow["detector_identity"])
        self.assertIsNone(trow["identity_contract_version"])
        self.assertTrue(s.verify_chain())  # the appended row is well-formed + chained

    def test_degenerate_routing_inputs_refused(self) -> None:
        for bad in ({"set_id": ""}, {"pinned_set_version": ""}, {"detector_id": ""},
                    {"trust_policy_ref": ""}, {"guard_policy_ref": ""}):
            with self.subTest(bad=next(iter(bad))):
                s = _store()
                _pending(s)
                with self.assertRaises(PrivilegedOperationError):
                    s.enter_calibrating("p1", approval=_appr("g1", op="p1-2"),
                                        **{**_ROUTING, **bad})  # type: ignore[arg-type]

    def test_degenerate_icv_refused(self) -> None:
        for bad_icv in (True, False, "1", IDENTITY_CONTRACT_VERSION + 1, 0):
            with self.subTest(icv=repr(bad_icv)):
                s = _store()
                _pending(s)
                with self.assertRaises(PrivilegedOperationError):
                    s.enter_calibrating("p1", approval=_appr("g1", op="p1-2"),
                                        **{**_ROUTING, "identity_contract_version": bad_icv})  # type: ignore[arg-type]

    def test_illegal_entry_writes_nothing(self) -> None:
        # a fresh policy is PROPOSED; PROPOSED -> CALIBRATING is not legal. The pre-check rejects BEFORE the
        # transaction, so neither a tier row nor an intent is written.
        s = _store()
        with self.assertRaises(IllegalTransitionError):
            s.enter_calibrating("p1", approval=_appr("g1", op="p1-x"), **_ROUTING)  # type: ignore[arg-type]
        self.assertEqual(_intent(s), [])
        self.assertIsNone(s.current_state("p1"))


if __name__ == "__main__":
    unittest.main()
