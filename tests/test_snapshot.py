"""3.3 — the signed, identity-bound calibration snapshot. Run:
python3 -m unittest discover -s tests

Load-bearing: HMAC roundtrip; a tampered payload (e.g. swapping a detector identity to attest a
different detector) breaks the MAC; the wrong key fails; a stale snapshot (past the horizon) is
refused regardless of MAC validity; an unsigned snapshot is refused.
"""
from __future__ import annotations

import unittest

from gate.snapshot import (
    AttestationRecord,
    CalibrationSnapshot,
    SnapshotError,
    attested_record,
    issue_snapshot,
    verify_snapshot,
)

_KEY = b"gate-governance-key"


def _rec(pid: str, detector: str = "det-1") -> AttestationRecord:
    return AttestationRecord(
        policy_id=pid, detector_identity=detector, calibration_result_ref="cal-1",
        fixture_set_version="fx-head", tier_chain_head="tier-head", backend="podman",
    )


class SnapshotTests(unittest.TestCase):
    def test_issue_and_verify_roundtrip(self) -> None:
        snap = issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0, valid_for_seconds=300)
        verify_snapshot(snap, key=_KEY, now=1100.0)  # within horizon
        self.assertEqual(attested_record(snap, "p1").detector_identity, "det-1")
        self.assertIsNone(attested_record(snap, "absent"))

    def test_tampered_identity_breaks_mac(self) -> None:
        snap = issue_snapshot({"p1": _rec("p1", "det-A")}, key=_KEY, now=1000.0)
        # forge: keep the MAC but swap the attested detector to det-EVIL.
        forged = CalibrationSnapshot(
            records={"p1": _rec("p1", "det-EVIL")}, issued_at=snap.issued_at,
            valid_until=snap.valid_until, mac=snap.mac,
        )
        with self.assertRaises(SnapshotError):
            verify_snapshot(forged, key=_KEY, now=1100.0)

    def test_wrong_key_refused(self) -> None:
        snap = issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0)
        with self.assertRaises(SnapshotError):
            verify_snapshot(snap, key=b"attacker-key", now=1100.0)

    def test_stale_refused(self) -> None:
        snap = issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0, valid_for_seconds=300)
        with self.assertRaises(SnapshotError):
            verify_snapshot(snap, key=_KEY, now=1000.0 + 300.0)  # now == valid_until -> stale

    def test_unsigned_refused(self) -> None:
        with self.assertRaises(SnapshotError):
            issue_snapshot({"p1": _rec("p1")}, key=b"", now=1000.0)

    def test_out_of_bounds_horizon_refused(self) -> None:
        # completeness prompt 5: a misconfigured huge horizon must be refused (else it defeats
        # fail-closed-on-outage). Zero/negative are refused too.
        from gate.snapshot import MAX_VALID_FOR_SECONDS
        with self.assertRaises(SnapshotError):
            issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0,
                           valid_for_seconds=MAX_VALID_FOR_SECONDS + 1)
        with self.assertRaises(SnapshotError):
            issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0, valid_for_seconds=0)


if __name__ == "__main__":
    unittest.main()
