"""tests/test_legacy_schema_fixtures.py — CP2 board S4a/P2: HARDCODED pre-S4 golden fixtures.

The compatibility claim is HISTORICAL-BYTE PRESERVATION, not new-renderer self-agreement. The bytes/MAC/
signature below were generated ONCE from the PARENT commit (e4f8946, pre-S4a/S4b) and hard-coded verbatim.
The tests load them through the CURRENT code and prove: (1) a legacy artifact still VERIFIES (its historical
signature is honoured by the current version-branched renderer), and (2) it is NOT ADMISSIBLE for current
provisioning (a legacy artifact proves the past; it cannot dictate current authority). If the current
rendering ever drifts from the historical bytes, these break — which is the point.
"""
from __future__ import annotations

import dataclasses
import json
import unittest

from gate.acceptance import AcceptanceReport, is_acceptance_admissible, verify_report
from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.signing import KeyVerifier
from gate.snapshot import (
    SNAPSHOT_SCHEMA_V2,
    attested_record,
    from_json,
    is_provisionable,
    verify_snapshot,
)

# ---- pre-S4 v2 snapshot (issued at the parent commit; no schema_version, no per-record ICV) ----
_PRE_S4_SNAPSHOT_KEY = b"preS4-golden-key"
_PRE_S4_SNAPSHOT_JSON = (
    '{"issued_at":1000.0,"mac":"1d436f2460ece87c42710a57c80c54ff8311b7ea2c3c78811306551adf265192",'
    '"records":{"p1":{"backend":"podman","calibration_result_ref":"cal-1","detector_identity":"det-1",'
    '"fixture_set_version":"fx","oracle_head":"h1","policy_id":"p1","set_id":"X","tier_chain_head":"th"}},'
    '"valid_until":1300.0}'
)

# ---- pre-S4 v1 acceptance receipt (constructed + signed at the parent commit) ----
_PRE_S4_ACCEPTANCE_FIELDS = json.loads(
    '{"accepted": true, "budget_wall_clock_ms": 1000, "claim": "provisional", '
    '"fn_control_profile_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", '
    '"fp_control_profile_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", '
    '"generalises": true, "holdout_corpus_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", '
    '"holdout_coverage": 2, "honest_passes": true, '
    '"image_ref": "sha256:0000000000000000000000000000000000000000000000000000000000000000", '
    '"issued_at": 100.0, "measured_execution_identity": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", '
    '"refuses_on_fn": true, "refuses_on_fp": true, '
    '"resolved_profile_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", '
    '"sandbox_config_hash": "9999999999999999999999999999999999999999999999999999999999999999", '
    '"short_circuit": false, "signer_principal": "cal-gov-1", "trials": 3, '
    '"trust_policy_id": "trust-policy:completed-only", '
    '"visible_corpus_digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "visible_coverage": 2}'
)
_PRE_S4_ACCEPTANCE_SIG = ("bc9924f64899c31fabcbdb435eb5ae246cae4f6c849260388f2a95ee1309a488"
                          "1a7150b3709bd39e29e5abc5a4649430dec68e4bc0207cea342508480daa7309")
_PRE_S4_ACCEPTANCE_PUB = bytes.fromhex(
    "2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d")


class LegacySnapshotFixtureTests(unittest.TestCase):
    def test_pre_s4_v2_snapshot_verifies_historically(self) -> None:
        snap = from_json(_PRE_S4_SNAPSHOT_JSON)
        self.assertEqual(snap.schema_version, SNAPSHOT_SCHEMA_V2)   # loaded as legacy
        verify_snapshot(snap, key=_PRE_S4_SNAPSHOT_KEY, now=1100.0)  # historical MAC HONOURED by current code

    def test_pre_s4_v2_snapshot_is_not_provisionable(self) -> None:
        snap = from_json(_PRE_S4_SNAPSHOT_JSON)
        rec = attested_record(snap, "p1")
        assert rec is not None
        self.assertFalse(is_provisionable(snap, rec, current_icv=IDENTITY_CONTRACT_VERSION))


class LegacyAcceptanceFixtureTests(unittest.TestCase):
    def _report(self) -> AcceptanceReport:
        # reconstruct the v1 report from the historical fields (v2 fields default => schema_version=1),
        # attach the historical signature.
        return dataclasses.replace(
            AcceptanceReport(**_PRE_S4_ACCEPTANCE_FIELDS), signature=_PRE_S4_ACCEPTANCE_SIG)

    def test_pre_s4_v1_acceptance_verifies_historically(self) -> None:
        report = self._report()
        self.assertEqual(report.schema_version, 1)                  # v1 (defaulted)
        self.assertTrue(verify_report(report, verifier=KeyVerifier(_PRE_S4_ACCEPTANCE_PUB)))

    def test_pre_s4_v1_acceptance_is_not_admissible(self) -> None:
        report = self._report()
        self.assertFalse(is_acceptance_admissible(report, current_icv=IDENTITY_CONTRACT_VERSION))


if __name__ == "__main__":
    unittest.main()
