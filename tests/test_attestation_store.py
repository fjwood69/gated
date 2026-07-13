"""tests/test_attestation_store.py — S3 ckpt4-fix: the MeasurementAttestationStore deserialization
boundary is FAIL-CLOSED. Run: python3 -m unittest discover -s tests

The store must refuse an old/unknown record at the version guard BEFORE it parses any nested field, and
must not crash on malformed stored JSON. These prove the hard-refuse-old migration boundary on ACTUAL
stored rows (not just a newly-malformed object rejected at sign).
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gate.attestation import AttestationError, MeasurementSchemaError
from gate.attestation_store import MeasurementAttestationStore


def _store() -> MeasurementAttestationStore:
    return MeasurementAttestationStore(Path(tempfile.mkdtemp(prefix="mv-attstore-")) / "a.db")


def _raw_insert(store: MeasurementAttestationStore, ref: str, payload_json: str, signature: str) -> None:
    store._conn().execute(
        "INSERT INTO measurement_attestation (ref, payload_json, signature, persisted_at) VALUES (?,?,?,?)",
        (ref, payload_json, signature, 0.0),
    )


class StoreDeserialisationBoundaryTests(unittest.TestCase):
    def test_malformed_json_is_a_schema_error_not_a_crash(self) -> None:
        s = _store()
        _raw_insert(s, "badref", "{not valid json", "00")
        with self.assertRaises(MeasurementSchemaError):  # mapped, not an unhandled ValueError
            s.get("badref")

    def test_non_object_json_is_rejected(self) -> None:
        s = _store()
        _raw_insert(s, "listref", "[1, 2, 3]", "00")
        with self.assertRaises(AttestationError):
            s.get("listref")

    def test_archived_v2_record_is_refused_at_the_schema_guard(self) -> None:
        # a REAL previously-valid v2-shaped stored envelope (flat, schema v2, no nested blocks, no ICV).
        # The store must REFUSE it at the schema guard BEFORE it tries to read the nested runtime_subject /
        # calibration_context blocks — proving hard-refuse-old on a stored record, not just at sign time.
        s = _store()
        v2_envelope = {
            "schema": "measurement-attestation:v2",
            "outcome": "pass", "policy_id": "p1",
            "subject_identity": "some-v2-composite",
            "requested_subject_identity": "requested",
            "resolved_profile_digest": "rpd", "execution_identity_digest": "eid",  # flat, v2-style
            "set_id": "X", "oracle_head": "head", "coverage_digest": "cov", "tier_generation": "tg",
            "issuer": "cal-gov-1", "run_id": "r-1", "nonce": "n-1", "issued_at_ms": 100000,
            "fixture_coverage": ["b1"], "short_circuit": False,
            "fn_failures": [], "fp_failures": [], "flaky": [], "harness_errors": [],
        }
        _raw_insert(s, "v2ref", json.dumps(v2_envelope, sort_keys=True, separators=(",", ":")), "00")
        with self.assertRaises(AttestationError):  # refused at the schema version guard
            s.get("v2ref")

    def test_unknown_icv_record_is_refused_before_field_parsing(self) -> None:
        # a v3-schema record but with an unknown identity_contract_version must be refused at the ICV guard,
        # never partially parsed / defaulted.
        s = _store()
        env = {
            "schema": "measurement-attestation:v3", "identity_contract_version": 99,
            "outcome": "pass", "policy_id": "p1", "subject_identity": "s",
            "requested_subject_identity": "r",
            "runtime_subject": {"resolved_profile_digest": "a", "trust_policy_digest": "b",
                                "guard_policy_digest": "c", "execution_identity_digest": "d"},
            "calibration_context": {"set_id": "X", "oracle_head": "h", "coverage_digest": "cov",
                                    "tier_generation": "tg"},
            "issuer": "i", "run_id": "r", "nonce": "n", "issued_at_ms": 100000,
            "fixture_coverage": ["b1"], "short_circuit": False,
            "fn_failures": [], "fp_failures": [], "flaky": [], "harness_errors": [],
        }
        _raw_insert(s, "icvref", json.dumps(env, sort_keys=True, separators=(",", ":")), "00")
        with self.assertRaises(AttestationError):
            s.get("icvref")


if __name__ == "__main__":
    unittest.main()
