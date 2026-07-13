"""3.5 S3 — the measurement-attestation v3 wire schema + the 4-tuple RuntimeSubject identity. Run:
python3 -m unittest discover -s tests

The signed evidence object is versioned (``measurement-attestation:v3``) and carries an
``IDENTITY_CONTRACT_VERSION``; the identity it binds is the composite over the FOUR RuntimeSubject
coordinates — H_v{ICV}(resolved_profile, trust_policy, guard_policy, execution) — never a caller string.
These tests pin the v3 guards with the LAYER-TAGGED error taxonomy (each negative asserts the EXACT
subclass, so it cannot pass for the wrong reason), re-signing mutated records where the identity layer is
under test, and prove the runtime_subject / calibration_context separation is structural (the
context-isolation test).
"""
from __future__ import annotations

import unittest
from dataclasses import replace

from core import VerdictType
from gate.attestation import (
    IDENTITY_CONTRACT_VERSION,
    MEASUREMENT_ATTESTATION_SCHEMA,
    AttestationError,
    AttestationSignatureError,
    IdentityContractError,
    MeasurementAttestation,
    MeasurementSchemaError,
    SubjectCompositionError,
    SubjectMismatchError,
    attestation_ref,
    calibrated_subject_identity,
    sign_measurement,
    verify_measurement,
)
from gate.signing import KeyVerifier, SeedSigner, public_key

_SEED = bytes(range(32))
_PUB = public_key(_SEED)
_RPD = "blake2b:resolved-profile-A"
_TPD = "trust-policy-digest-C"
_GPD = "guard-policy-digest-D"
_EID = "exec-identity-digest-B"


def _unsigned(**over: object) -> MeasurementAttestation:
    """A PASS-shaped v3 attestation (UNSIGNED), with per-field overrides for the negative cases. The
    subject is the 4-tuple composite over the (possibly-overridden) runtime_subject coordinates."""
    rpd = over.pop("resolved_profile_digest", _RPD)
    tpd = over.pop("trust_policy_digest", _TPD)
    gpd = over.pop("guard_policy_digest", _GPD)
    eid = over.pop("execution_identity_digest", _EID)
    coords = (rpd, tpd, gpd, eid)
    subject = over.pop(
        "subject_identity",
        calibrated_subject_identity(rpd, tpd, gpd, eid) if all(c is not None for c in coords) else None,
    )
    fields: dict[str, object] = dict(
        outcome=VerdictType.PASS, policy_id="p1", subject_identity=subject,
        requested_subject_identity="requested-target",
        resolved_profile_digest=rpd, trust_policy_digest=tpd, guard_policy_digest=gpd,
        execution_identity_digest=eid, set_id="X", oracle_head="head-1",
        coverage_digest="cov-1", tier_generation="tg-1", issuer="cal-gov-1", run_id="r-1", nonce="n-1",
        issued_at_ms=100000, fixture_coverage=("b1", "g1"), short_circuit=False,
    )
    fields.update(over)
    return MeasurementAttestation(**fields)  # type: ignore[arg-type]


def _signed(**over: object) -> MeasurementAttestation:
    return sign_measurement(_unsigned(**over), signer=SeedSigner(_SEED))


class AttestationV3Tests(unittest.TestCase):
    def test_v3_round_trip_and_clean_pass(self) -> None:
        att = _signed()
        verify_measurement(att, verifier=KeyVerifier(_PUB))  # valid
        self.assertEqual(att.schema, MEASUREMENT_ATTESTATION_SCHEMA)
        self.assertEqual(att.identity_contract_version, IDENTITY_CONTRACT_VERSION)
        self.assertTrue(att.is_clean_pass)
        self.assertEqual(att.subject_identity, calibrated_subject_identity(_RPD, _TPD, _GPD, _EID))

    def test_deterministic_envelope_and_signature(self) -> None:
        self.assertEqual(_signed().signature, _signed().signature)
        self.assertEqual(attestation_ref(_signed()), attestation_ref(_signed()))

    # ---- the exact-error-code taxonomy matrix (one mutation per test, re-signed where the identity
    #      layer is under test so signature-rejection does not mask it) ----

    def test_wrong_schema_is_MeasurementSchemaError_at_sign(self) -> None:
        with self.assertRaises(MeasurementSchemaError):
            _signed(schema="measurement-attestation:v2")  # an old schema is refused at SIGN

    def test_wrong_icv_is_IdentityContractError_at_sign(self) -> None:
        with self.assertRaises(IdentityContractError):
            _signed(identity_contract_version=IDENTITY_CONTRACT_VERSION + 1)

    def test_bool_issued_at_ms_is_MeasurementSchemaError(self) -> None:
        with self.assertRaises(MeasurementSchemaError):
            _signed(issued_at_ms=True)  # bool is an int subclass — rejected before signing

    def test_bad_hex_signature_is_AttestationSignatureError(self) -> None:
        bad = replace(_signed(), signature="nothex!!")
        with self.assertRaises(AttestationSignatureError):
            verify_measurement(bad, verifier=KeyVerifier(_PUB))

    def test_wrong_key_is_AttestationSignatureError(self) -> None:
        with self.assertRaises(AttestationSignatureError):
            verify_measurement(_signed(), verifier=KeyVerifier(public_key(bytes(range(1, 33)))))

    def test_pass_missing_a_coordinate_is_SubjectCompositionError_at_sign(self) -> None:
        # a PASS requires ALL FOUR runtime_subject coordinates. Drop the guard digest -> composition error.
        with self.assertRaises(SubjectCompositionError):
            _signed(guard_policy_digest=None)

    def test_empty_string_coordinate_is_rejected(self) -> None:
        # the empty-string identity-downgrade: a coordinate of "" must NOT count as present. It is rejected
        # at the WIRE-type layer (MeasurementSchemaError) before conditional presence, so a PASS can never
        # be signed with a meaningless empty coordinate that would hash into a valid-looking composite.
        with self.assertRaises(MeasurementSchemaError):
            _signed(trust_policy_digest="")
        with self.assertRaises(MeasurementSchemaError):
            _signed(guard_policy_digest="")

    def test_empty_required_string_is_rejected(self) -> None:
        # a required non-empty field (e.g. a calibration_context field) that is "" is refused too.
        with self.assertRaises(MeasurementSchemaError):
            _signed(oracle_head="")

    def test_orphan_subject_is_SubjectCompositionError_at_sign(self) -> None:
        # a subject claimed while a coordinate is null is incoherent (an unattestable ERROR must not smuggle
        # in a calibrated subject) — refused at SIGN (validate-before-sign).
        with self.assertRaises(SubjectCompositionError):
            _signed(outcome=VerdictType.ERROR, execution_identity_digest=None,
                    subject_identity="orphan-subject")

    def test_forged_subject_is_SubjectMismatchError_at_sign(self) -> None:
        # a subject that is not H(runtime_subject) is caught by the recompute at SIGN, so a validly-signed
        # record can NEVER carry a mismatched composite.
        with self.assertRaises(SubjectMismatchError):
            _signed(subject_identity="forged-subject-that-was-not-derived")

    # ---- tamper (not re-signed) -> signature layer fires (the record's bytes changed) ----

    def test_tamper_any_coordinate_without_resign_fails_signature(self) -> None:
        for field_name, evil in (
            ("resolved_profile_digest", "blake2b:EVIL"),
            ("trust_policy_digest", "trust-EVIL"),
            ("guard_policy_digest", "guard-EVIL"),
            ("execution_identity_digest", "exec-EVIL"),
        ):
            tampered = replace(_signed(), **{field_name: evil})  # signature not recomputed
            with self.assertRaises(AttestationSignatureError):
                verify_measurement(tampered, verifier=KeyVerifier(_PUB))

    # ---- the mandatory CONTEXT-ISOLATION proof (three properties) ----

    def test_context_isolation_three_properties(self) -> None:
        base_unsigned = _unsigned()
        changed_unsigned = replace(base_unsigned, oracle_head="a-DIFFERENT-oracle-head")
        # (a) changing a calibration_context field leaves the SUBJECT identity unchanged (the subject digest
        #     consumes ONLY the four runtime_subject coordinates).
        self.assertEqual(base_unsigned.subject_identity, changed_unsigned.subject_identity)
        # (b) it INVALIDATES the old signature (the envelope covers the context too).
        base_signed = sign_measurement(base_unsigned, signer=SeedSigner(_SEED))
        forged = replace(base_signed, oracle_head="a-DIFFERENT-oracle-head")  # context changed, sig stale
        with self.assertRaises(AttestationSignatureError):
            verify_measurement(forged, verifier=KeyVerifier(_PUB))
        # (c) RE-SIGNING yields a valid attestation with the SAME subject and the changed context.
        resigned = sign_measurement(changed_unsigned, signer=SeedSigner(_SEED))
        verify_measurement(resigned, verifier=KeyVerifier(_PUB))
        self.assertEqual(resigned.subject_identity, base_signed.subject_identity)  # subject unchanged
        self.assertEqual(resigned.oracle_head, "a-DIFFERENT-oracle-head")          # context changed

    def test_inverse_context_isolation_subject_change_leaves_context_bytes(self) -> None:
        # the INVERSE of context-isolation: mutating a runtime_subject coordinate changes the subject but
        # leaves the calibration_context block's serialized bytes UNCHANGED (the separation is bidirectional
        # — subject and context are independent structures).
        import json
        base = _unsigned()
        new_trust = "a-DIFFERENT-trust-digest"
        changed = replace(
            base, trust_policy_digest=new_trust,
            subject_identity=calibrated_subject_identity(
                base.resolved_profile_digest, new_trust, base.guard_policy_digest,
                base.execution_identity_digest),
        )
        self.assertNotEqual(base.subject_identity, changed.subject_identity)  # subject moved
        self.assertEqual(  # context bytes did NOT
            json.dumps(base._calibration_context(), sort_keys=True),
            json.dumps(changed._calibration_context(), sort_keys=True))

    # ---- ERROR / non-restorable ----

    def test_error_with_null_environment_is_valid_but_non_restorable(self) -> None:
        att = _signed(outcome=VerdictType.ERROR, resolved_profile_digest=None, trust_policy_digest=None,
                      guard_policy_digest=None, execution_identity_digest=None, subject_identity=None,
                      harness_errors=("detector-unresolved:UnregisteredDetectorError",))
        verify_measurement(att, verifier=KeyVerifier(_PUB))  # a valid signed record
        self.assertFalse(att.is_clean_pass)                  # but never restorable
        self.assertTrue(attestation_ref(att))                # still content-addressable audit evidence

    def test_all_taxonomy_errors_are_attestation_errors(self) -> None:
        # the layer-tagged subclasses remain AttestationError so existing `except AttestationError` catches.
        for cls in (MeasurementSchemaError, IdentityContractError, AttestationSignatureError,
                    SubjectCompositionError, SubjectMismatchError):
            self.assertTrue(issubclass(cls, AttestationError))


if __name__ == "__main__":
    unittest.main()
