"""3.3 — the signed, identity-bound calibration snapshot. Run:
python3 -m unittest discover -s tests

Load-bearing: HMAC roundtrip; a tampered payload (e.g. swapping a detector identity to attest a
different detector) breaks the MAC; the wrong key fails; a stale snapshot (past the horizon) is
refused regardless of MAC validity; an unsigned snapshot is refused.
"""
from __future__ import annotations

import unittest

from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.snapshot import (
    SNAPSHOT_SCHEMA_V2,
    SNAPSHOT_SCHEMA_V3,
    AttestationRecord,
    CalibrationSnapshot,
    SnapshotError,
    _LEGACY_ICV,
    _sign,
    assert_snapshot_integrity,
    attested_record,
    is_provisionable,
    issue_snapshot,
    verify_snapshot,
)

_KEY = b"gate-governance-key"


def _rec(pid: str, detector: str = "det-1", *,
         icv: int = IDENTITY_CONTRACT_VERSION) -> AttestationRecord:
    return AttestationRecord(
        policy_id=pid, detector_identity=detector, calibration_result_ref="cal-1",
        fixture_set_version="fx-head", tier_chain_head="tier-head", backend="podman",
        identity_contract_version=icv,
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
            valid_until=snap.valid_until, mac=snap.mac, schema_version=snap.schema_version,
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


class SchemaVersioningTests(unittest.TestCase):
    """CP2 S4a: the vNext (v3) snapshot signs a per-record ICV; a legacy (v2) snapshot stays
    INTEGRITY-verifiable via its exact historical rendering but is NOT admissible for provisioning
    (its sentinel ICV != the current contract), so an old receipt can never mint a plan."""

    def _legacy_v2(self) -> CalibrationSnapshot:
        # a legacy record carries no signed ICV (sentinel); sign it under the V2 rendering (no
        # schema_version, no per-record ICV) exactly as it historically would have been.
        rec = AttestationRecord(
            policy_id="p1", detector_identity="det-1", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman")
        unsigned = CalibrationSnapshot(records={"p1": rec}, issued_at=1000.0, valid_until=1300.0,
                                       mac="", schema_version=SNAPSHOT_SCHEMA_V2)
        return CalibrationSnapshot(records={"p1": rec}, issued_at=1000.0, valid_until=1300.0,
                                   mac=_sign(unsigned._payload(), _KEY), schema_version=SNAPSHOT_SCHEMA_V2)

    def test_new_mint_is_v3_and_provisionable(self) -> None:
        snap = issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0)
        self.assertEqual(snap.schema_version, SNAPSHOT_SCHEMA_V3)
        rec = attested_record(snap, "p1")
        assert rec is not None
        self.assertEqual(rec.identity_contract_version, IDENTITY_CONTRACT_VERSION)
        self.assertTrue(is_provisionable(rec, current_icv=IDENTITY_CONTRACT_VERSION))

    def test_legacy_v2_verifies_but_is_not_provisionable(self) -> None:
        legacy = self._legacy_v2()
        assert_snapshot_integrity(legacy, key=_KEY)          # historical integrity holds
        verify_snapshot(legacy, key=_KEY, now=1100.0)        # ... and within horizon
        rec = attested_record(legacy, "p1")
        assert rec is not None
        self.assertEqual(rec.identity_contract_version, _LEGACY_ICV)
        self.assertFalse(is_provisionable(rec, current_icv=IDENTITY_CONTRACT_VERSION))  # NOT admissible

    def test_mint_refuses_a_legacy_sentinel_record(self) -> None:
        # no compatibility default: fresh evidence MUST carry a real ICV.
        legacy_rec = AttestationRecord(
            policy_id="p1", detector_identity="det-1", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman")
        with self.assertRaises(SnapshotError):
            issue_snapshot({"p1": legacy_rec}, key=_KEY, now=1000.0)


if __name__ == "__main__":
    unittest.main()
