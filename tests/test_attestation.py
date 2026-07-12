"""3.5-close P1-3 — the measurement-attestation v2 wire schema + measurement-derived subject identity.
Run: python3 -m unittest discover -s tests

The signed evidence object is versioned (``measurement-attestation:v2``) and the identity it binds is the
MEASUREMENT-DERIVED calibrated-subject identity — H(resolved_profile_digest, execution_identity_digest) —
never a caller string. These tests pin the v2 vectors and prove the guards: a v1 record is hard-rejected,
tampering EITHER derivation component (or the composite) invalidates verification, a subject claimed
WITHOUT both components is refused, and an unattestable ERROR (null environment) is a valid signed record
but categorically non-restorable.
"""
from __future__ import annotations

import unittest
from dataclasses import replace

from core import VerdictType
from gate.attestation import (
    MEASUREMENT_ATTESTATION_SCHEMA,
    AttestationError,
    MeasurementAttestation,
    attestation_ref,
    calibrated_subject_identity,
    sign_measurement,
    verify_measurement,
)
from gate.signing import KeyVerifier, SeedSigner, public_key

_SEED = bytes(range(32))
_PUB = public_key(_SEED)
_RPD = "blake2b:resolved-profile-A"
_EID = "exec-identity-digest-B"


def _signed(**over: object) -> MeasurementAttestation:
    """A signed PASS-shaped v2 attestation, with per-field overrides for the negative cases."""
    rpd = over.pop("resolved_profile_digest", _RPD)
    eid = over.pop("execution_identity_digest", _EID)
    subject = over.pop(
        "subject_identity",
        calibrated_subject_identity(rpd, eid) if (rpd is not None and eid is not None) else None,
    )
    fields: dict[str, object] = dict(
        outcome=VerdictType.PASS, policy_id="p1", subject_identity=subject,
        requested_subject_identity="requested-target",
        resolved_profile_digest=rpd, execution_identity_digest=eid, set_id="X", oracle_head="head-1",
        coverage_digest="cov-1", tier_generation="tg-1", issuer="cal-gov-1", run_id="r-1", nonce="n-1",
        issued_at_ms=100000, fixture_coverage=("b1", "g1"), short_circuit=False,
    )
    fields.update(over)
    return sign_measurement(MeasurementAttestation(**fields), signer=SeedSigner(_SEED))  # type: ignore[arg-type]


class AttestationV2Tests(unittest.TestCase):
    def test_v2_round_trip_and_clean_pass(self) -> None:
        att = _signed()
        verify_measurement(att, verifier=KeyVerifier(_PUB))  # valid
        self.assertEqual(att.schema, MEASUREMENT_ATTESTATION_SCHEMA)
        self.assertTrue(att.is_clean_pass)
        self.assertEqual(att.subject_identity, calibrated_subject_identity(_RPD, _EID))

    def test_deterministic_envelope_and_signature(self) -> None:
        # NFR6: same inputs -> same signed bytes -> same signature (reproducible, no clock/RNG).
        self.assertEqual(_signed().signature, _signed().signature)
        self.assertEqual(attestation_ref(_signed()), attestation_ref(_signed()))

    def test_v1_schema_is_hard_rejected(self) -> None:
        # a v1-schema record cannot restore a tier — refused by version. v4: rejected at SIGN (validate the
        # complete schema before signing), so a non-v2 record is never even produced.
        with self.assertRaises(AttestationError):
            _signed(schema="measurement-attestation:v1")

    def test_tamper_resolved_profile_digest_is_refused(self) -> None:
        tampered = replace(_signed(), resolved_profile_digest="blake2b:EVIL")  # signature not recomputed
        with self.assertRaises(AttestationError):
            verify_measurement(tampered, verifier=KeyVerifier(_PUB))

    def test_tamper_execution_identity_digest_is_refused(self) -> None:
        tampered = replace(_signed(), execution_identity_digest="exec-EVIL")
        with self.assertRaises(AttestationError):
            verify_measurement(tampered, verifier=KeyVerifier(_PUB))

    def test_tamper_subject_composite_is_refused(self) -> None:
        # even if the components are untouched, a forged composite is caught by the recompute check
        # (guard: verify recomputes H(profile, execution) and compares).
        tampered = replace(_signed(), subject_identity="forged-subject-that-was-not-derived")
        with self.assertRaises(AttestationError):
            verify_measurement(tampered, verifier=KeyVerifier(_PUB))

    def test_subject_without_both_components_is_incoherent(self) -> None:
        # a subject claimed while a derivation component is null is refused — an unattestable ERROR must
        # not smuggle in a calibrated subject. v3 validate-before-sign: it is refused at SIGN time (the
        # runner never produces such a record), which is stronger than only rejecting on read.
        with self.assertRaises(AttestationError):
            _signed(outcome=VerdictType.ERROR, execution_identity_digest=None,
                    subject_identity="orphan-subject")

    def test_error_with_null_environment_is_valid_but_non_restorable(self) -> None:
        # conditional validity: an ERROR whose environment was unattestable carries null components + null
        # subject. It is a VALID signed audit record, but categorically NOT a restore basis.
        att = _signed(outcome=VerdictType.ERROR, resolved_profile_digest=None,
                      execution_identity_digest=None, subject_identity=None,
                      harness_errors=("detector-unresolved:UnregisteredDetectorError",))
        verify_measurement(att, verifier=KeyVerifier(_PUB))  # a valid signed record
        self.assertFalse(att.is_clean_pass)                  # but never restorable
        self.assertTrue(attestation_ref(att))                # still content-addressable audit evidence

    def test_bool_issued_at_ms_is_rejected_at_sign(self) -> None:
        # v4 P2: bool is an int subclass — a strict wire-schema check must reject issued_at_ms=True BEFORE
        # signing (type coercion laundering). Guard = type(...) is int; remove it and True signs cleanly.
        with self.assertRaises(AttestationError):
            _signed(issued_at_ms=True)

    def test_wrong_key_is_refused(self) -> None:
        with self.assertRaises(AttestationError):
            verify_measurement(_signed(), verifier=KeyVerifier(public_key(bytes(range(1, 33)))))


if __name__ == "__main__":
    unittest.main()
