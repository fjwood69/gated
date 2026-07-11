"""3.2/3.4 — the out-of-band CalibrationSet store (gate-side). Run: python3 -m unittest discover -s tests

Load-bearing: the RUNTIME token cannot append (1b); as of 3.4 admitting a fixture (ADD_KNOWN_BAD /
ADD_KNOWN_GOOD) AND deprecating one (DEPRECATE_KNOWN_BAD) require a real GovernanceApproval with two
distinct principals — the enum is not proof of dual control, and this makes the admission gate the
only sufficient-authority path in. DELETES are forbidden (a deprecated known-bad stays in the chain,
excluded from head); the chain is tamper-evident (reusing core.chain) and load fails CLOSED.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core.calibration import FixtureLabel
from gate.authority import Authority, GovernanceApproval
from gate.calibration_store import (
    AdmissionCapability,
    CalibrationStore,
    ChainIntegrityError,
    ChangeOp,
    PrivilegedOperationError,
)


def _store() -> CalibrationStore:
    d = Path(tempfile.mkdtemp(prefix="mv-calstore-"))
    return CalibrationStore(d / "calibration.db")


def _appr(*principals: str, op: str = "op") -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose="admit", rationale="reviewed",
                              operation_id=op)


def _dual() -> GovernanceApproval:
    return _appr("gov1", "gov2")


_ADMIT_CAP = AdmissionCapability()


class LoadAndReplayTests(unittest.TestCase):
    def test_add_and_load_current_set(self) -> None:
        s = _store()
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b1",
                 label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")
        s.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="g1",
                 label=FixtureLabel.KNOWN_GOOD, payload=b"good\n")
        cset = s.load_current_set()
        self.assertEqual({f.fixture_id for f in cset.known_bad}, {"b1"})
        self.assertEqual({f.fixture_id for f in cset.known_good}, {"g1"})
        self.assertEqual(cset.known_bad[0].payload, b"bad\n")  # bytes round-trip

    def test_supersede_known_good_replaces_in_head(self) -> None:
        s = _store()
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b1",
                 label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")
        s.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="g1",
                 label=FixtureLabel.KNOWN_GOOD, payload=b"v1\n")
        # SUPERSEDE keeps the single-GOVERNANCE enum model for now.
        s.append(ChangeOp.SUPERSEDE_KNOWN_GOOD, authority=Authority.GOVERNANCE, fixture_id="g2",
                 label=FixtureLabel.KNOWN_GOOD, payload=b"v2\n", supersedes="g1", reason="poison")
        good = {f.fixture_id: f.payload for f in s.load_current_set().known_good}
        self.assertEqual(good, {"g2": b"v2\n"})  # g1 retired, g2 active


class AuthorityTests(unittest.TestCase):
    def test_add_requires_dual_control(self) -> None:
        # 3.4: admitting a fixture is high-stakes -> two distinct principals. No approval / one
        # principal / a bare RUNTIME token are all refused.
        s = _store()
        with self.assertRaises(PrivilegedOperationError):  # no approval
            s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, authority=Authority.RUNTIME, fixture_id="b1",
                     label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")
        with self.assertRaises(PrivilegedOperationError):  # one principal is not dual
            s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("gov1"), fixture_id="b1",
                     label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b1",
                 label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")  # two distinct -> ok
        self.assertEqual({f.fixture_id for f in s.load_current_set().known_bad}, {"b1"})

    def test_deprecate_known_bad_requires_real_dual_control(self) -> None:
        # 1e: DEPRECATE (the weakening op) needs a real GovernanceApproval with TWO DISTINCT
        # principals — the enum (even GOVERNANCE_DUAL) is not proof; a single principal is refused.
        s = _store()
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b1",
                 label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")
        with self.assertRaises(PrivilegedOperationError):  # enum no longer suffices
            s.append(ChangeOp.DEPRECATE_KNOWN_BAD, authority=Authority.GOVERNANCE_DUAL,
                     fixture_id="b1", reason="patched at kernel")
        with self.assertRaises(PrivilegedOperationError):  # one principal is not dual
            s.append(ChangeOp.DEPRECATE_KNOWN_BAD, approval=_appr("gov1"),
                     fixture_id="b1", reason="patched at kernel")
        s.append(ChangeOp.DEPRECATE_KNOWN_BAD, approval=_dual(),
                 fixture_id="b1", reason="patched at kernel")
        self.assertEqual(s.load_current_set().known_bad, ())  # excluded from head


class AppendOnlyTests(unittest.TestCase):
    def test_deprecate_excludes_from_head_but_stays_in_chain(self) -> None:
        # DELETES FORBIDDEN: deprecation removes from the ACTIVE set but the record STAYS.
        s = _store()
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b1",
                 label=FixtureLabel.KNOWN_BAD, payload=b"b1\n")
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b2",
                 label=FixtureLabel.KNOWN_BAD, payload=b"b2\n")
        s.append(ChangeOp.DEPRECATE_KNOWN_BAD, approval=_dual(),
                 fixture_id="b1", reason="obsolete")
        self.assertEqual({f.fixture_id for f in s.load_current_set().known_bad}, {"b2"})
        self.assertEqual(s.record_count(), 3)  # grew (2 adds + 1 deprecate), did NOT shrink
        self.assertTrue(s.verify_chain())

    def test_no_delete_or_update_method(self) -> None:
        s = _store()
        self.assertFalse(hasattr(s, "delete"))
        self.assertFalse(hasattr(s, "remove"))
        self.assertFalse(hasattr(s, "update"))


class TamperEvidenceTests(unittest.TestCase):
    def test_edit_detected_and_load_fails_closed(self) -> None:
        s = _store()
        s.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="b1",
                 label=FixtureLabel.KNOWN_BAD, payload=b"bad\n")
        s.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT_CAP, approval=_dual(), fixture_id="g1",
                 label=FixtureLabel.KNOWN_GOOD, payload=b"good\n")
        self.assertTrue(s.verify_chain())
        s._conn().execute("UPDATE calibration_chain SET payload=? WHERE seq=1", (b"weakened\n",))
        self.assertFalse(s.verify_chain())
        with self.assertRaises(ChainIntegrityError):
            s.load_current_set()  # fail-closed: a broken chain never yields a (weakened) set

    def test_store_reuses_core_chain_primitive(self) -> None:
        src = (Path(__file__).resolve().parent.parent / "gate" / "calibration_store.py").read_text()
        self.assertIn("from core.chain import", src)  # reuses, does not rebuild


if __name__ == "__main__":
    unittest.main()
