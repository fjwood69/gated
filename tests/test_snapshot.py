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
    from_json,
    is_provisionable,
    issue_snapshot,
    to_json,
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
        self.assertTrue(is_provisionable(snap, rec, current_icv=IDENTITY_CONTRACT_VERSION))

    def test_legacy_v2_verifies_but_is_not_provisionable(self) -> None:
        legacy = self._legacy_v2()
        assert_snapshot_integrity(legacy, key=_KEY)          # historical integrity holds
        verify_snapshot(legacy, key=_KEY, now=1100.0)        # ... and within horizon
        rec = attested_record(legacy, "p1")
        assert rec is not None
        self.assertEqual(rec.identity_contract_version, _LEGACY_ICV)
        self.assertFalse(is_provisionable(legacy, rec, current_icv=IDENTITY_CONTRACT_VERSION))  # v2 schema

    def test_mint_refuses_a_legacy_sentinel_record(self) -> None:
        # no compatibility default: fresh evidence MUST carry a real ICV.
        legacy_rec = AttestationRecord(
            policy_id="p1", detector_identity="det-1", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman")
        with self.assertRaises(SnapshotError):
            issue_snapshot({"p1": legacy_rec}, key=_KEY, now=1000.0)

    def test_injected_icv_into_authentic_v2_verifies_but_is_not_provisionable(self) -> None:
        # BOARD P1: the downgrade bypass. Take an AUTHENTIC v2 snapshot, inject the CURRENT ICV into its
        # record, LEAVE the MAC unchanged. The v2 MAC excludes the ICV, so verify_snapshot still passes
        # (historical integrity is honest — the signed bytes did not change). But provisioning is
        # SCHEMA-ENFORCED: a v2-schema snapshot is unprovisionable regardless of the injected ICV.
        base = self._legacy_v2()
        forged_rec = AttestationRecord(
            policy_id="p1", detector_identity="det-1", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman",
            identity_contract_version=IDENTITY_CONTRACT_VERSION)  # injected current ICV
        forged = CalibrationSnapshot(records={"p1": forged_rec}, issued_at=base.issued_at,
                                     valid_until=base.valid_until, mac=base.mac,  # UNCHANGED MAC
                                     schema_version=SNAPSHOT_SCHEMA_V2)
        verify_snapshot(forged, key=_KEY, now=1100.0)        # historical integrity: PASSES (v2 excludes ICV)
        self.assertFalse(is_provisionable(forged, forged_rec, current_icv=IDENTITY_CONTRACT_VERSION))

    def test_from_json_rejects_injected_icv_on_a_v2_record(self) -> None:
        # strict parsing: the ICV field cannot exist on a v2 record (it is outside the v2 MAC).
        forged = ('{"records":{"p1":{"policy_id":"p1","detector_identity":"det-1",'
                  '"calibration_result_ref":"cal-1","fixture_set_version":"fx","tier_chain_head":"th",'
                  '"backend":"podman","set_id":"default","oracle_head":"","identity_contract_version":1}},'
                  '"issued_at":1000.0,"valid_until":1300.0,"mac":"deadbeef"}')
        with self.assertRaises(SnapshotError):
            from_json(forged)

    def test_from_json_rejects_unknown_schema(self) -> None:
        blob = ('{"schema_version":99,"records":{},"issued_at":1000.0,"valid_until":1300.0,"mac":"x"}')
        with self.assertRaises(SnapshotError):
            from_json(blob)

    def test_from_json_does_not_coerce_signed_discriminators(self) -> None:
        # board P2: a JSON true / 1.9 / "1" must NOT be coerced to integer 1 before the exact-int check.
        for sv in ("true", "1.9", '"2"'):
            with self.assertRaises(SnapshotError):
                from_json('{"schema_version":%s,"records":{},"issued_at":1.0,"valid_until":2.0,"mac":"x"}' % sv)
        # a v3 record whose ICV is a JSON bool/float/string is refused (not coerced).
        for icv in ("true", "1.9", '"1"'):
            blob = ('{"schema_version":3,"records":{"p1":{"policy_id":"p1","detector_identity":"d",'
                    '"calibration_result_ref":"c","fixture_set_version":"f","tier_chain_head":"t",'
                    '"backend":"podman","set_id":"X","oracle_head":"h","identity_contract_version":%s}},'
                    '"issued_at":1.0,"valid_until":2.0,"mac":"x"}') % icv
            with self.assertRaises(SnapshotError):
                from_json(blob)

    def test_issue_snapshot_rejects_a_non_int_icv(self) -> None:
        rec = AttestationRecord(
            policy_id="p1", detector_identity="det-1", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman",
            identity_contract_version=True)  # a bool is not an int identity contract
        with self.assertRaises(SnapshotError):
            issue_snapshot({"p1": rec}, key=_KEY, now=1000.0)

    def test_payload_refuses_to_render_an_unknown_schema(self) -> None:
        rec = _rec("p1")
        bad = CalibrationSnapshot(records={"p1": rec}, issued_at=1.0, valid_until=2.0, mac="",
                                  schema_version=99)
        with self.assertRaises(SnapshotError):
            bad._payload()

    def test_foreign_record_not_bound_to_snapshot_is_unprovisionable(self) -> None:
        # BOARD P1: a valid v3 snapshot containing det-A cannot provision an INDEPENDENTLY-constructed
        # det-EVIL record (even with the current ICV) — the record must be the snapshot's AUTHENTICATED one.
        snap = issue_snapshot({"pA": _rec("pA", "det-A")}, key=_KEY, now=1000.0)
        evil_same_policy = AttestationRecord(
            policy_id="pA", detector_identity="det-EVIL", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman",
            identity_contract_version=IDENTITY_CONTRACT_VERSION)
        self.assertFalse(is_provisionable(snap, evil_same_policy, current_icv=IDENTITY_CONTRACT_VERSION))
        evil_absent_policy = AttestationRecord(
            policy_id="pEVIL", detector_identity="det-EVIL", calibration_result_ref="cal-1",
            fixture_set_version="fx", tier_chain_head="th", backend="podman",
            identity_contract_version=IDENTITY_CONTRACT_VERSION)
        self.assertFalse(is_provisionable(snap, evil_absent_policy, current_icv=IDENTITY_CONTRACT_VERSION))
        own = attested_record(snap, "pA")                    # the snapshot's OWN record IS provisionable
        assert own is not None
        self.assertTrue(is_provisionable(snap, own, current_icv=IDENTITY_CONTRACT_VERSION))

    def test_provisionable_rejects_a_float_schema_version(self) -> None:
        # exact-int: 3.0 == 3 must NOT let a float schema provision.
        rec = _rec("p1")
        snap = CalibrationSnapshot(records={"p1": rec}, issued_at=1.0, valid_until=2.0, mac="",
                                   schema_version=float(SNAPSHOT_SCHEMA_V3))  # type: ignore[arg-type]
        self.assertFalse(is_provisionable(snap, rec, current_icv=IDENTITY_CONTRACT_VERSION))

    def test_issue_snapshot_rejects_a_mapping_key_mismatch(self) -> None:
        with self.assertRaises(SnapshotError):
            issue_snapshot({"pDIFFERENT": _rec("pA")}, key=_KEY, now=1000.0)  # key != record.policy_id

    def test_from_json_rejects_a_mapping_key_mismatch(self) -> None:
        blob = ('{"schema_version":3,"records":{"pKEY":{"policy_id":"pDIFFERENT","detector_identity":"d",'
                '"calibration_result_ref":"c","fixture_set_version":"f","tier_chain_head":"t",'
                '"backend":"podman","set_id":"X","oracle_head":"h","identity_contract_version":1}},'
                '"issued_at":1.0,"valid_until":2.0,"mac":"x"}')
        with self.assertRaises(SnapshotError):
            from_json(blob)

    def test_v3_roundtrips_through_json_and_stays_provisionable(self) -> None:
        snap = issue_snapshot({"p1": _rec("p1")}, key=_KEY, now=1000.0)
        loaded = from_json(to_json(snap))
        verify_snapshot(loaded, key=_KEY, now=1100.0)
        rec = attested_record(loaded, "p1")
        assert rec is not None
        self.assertTrue(is_provisionable(loaded, rec, current_icv=IDENTITY_CONTRACT_VERSION))


if __name__ == "__main__":
    unittest.main()
