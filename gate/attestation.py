"""gate/attestation.py — 3.5 job-1: the SIGNED MEASUREMENT (the re-calibration runner's only output).

The keystone of *measurement ≠ governance*. The re-calibration runner MEASURES a detector's fitness and
emits one of these — a signed statement "runtime-subject S, under calibration-context C, scored PASS/FAIL/
ERROR over THIS complete coverage, short-circuit OFF, in run R". It carries **no authority to change any
tier**: the signing key is the MEASUREMENT key (not in the tier-write set), and the runner is handed no
``PolicyStore``. A separate governance act (restore controller / human ratify/demote) must CONSUME a
verified attestation to move state.

3.5 S3 — the 4-TUPLE RuntimeSubject (schema ``measurement-attestation:v3``, ``IDENTITY_CONTRACT_VERSION``).
The signed record has two explicit NESTED blocks under ONE issuer signature (board ckpt4 Q1):
  * ``runtime_subject`` = { resolved_profile_digest, trust_policy_digest, guard_policy_digest,
    execution_identity_digest } — WHO/WHAT ran. The ``subject_identity`` composite is
    ``H_v{ICV}(runtime_subject)`` and consumes ONLY these four coordinates (``RUNTIME_SUBJECT_FIELDS``), so
    a calibration-context field can never drift into the identity hash.
  * ``calibration_context`` = { set_id, oracle_head, coverage_digest, tier_generation } — UNDER WHAT it was
    measured. The signature AUTHENTICATES the reported context; it does NOT authorize or vouch for its
    currency (governance re-checks that against live policy/oracle state at restore).
The two blocks are separate STRUCTURES, not separate authorities — one measurement issuer signs both. All
four trust/guard/profile/execution coordinates are measured/derived, never caller-supplied (the P1-3/S3
sign-A-run-B close, now over the full 4-tuple).

``IDENTITY_CONTRACT_VERSION`` is bound TWO ways: an explicit signed field AND the subject digest's
domain PREFIX (``gated.calibrated-subject.v{ICV}``), so a vN subject digest is cryptographically
unverifiable under vM — not merely rejected. The attestation SCHEMA version and the ICV are INDEPENDENT
axes (the wire format may evolve without changing how identity composes, and vice-versa).

Signed with ASYMMETRIC Ed25519: the runner signs with a PRIVATE seed; the restore controller holds ONLY
the PUBLIC key. The signed content is a domain-separated, schema-validated ``canonical_digest`` envelope.
Gate-side; ``core`` never imports this. Deterministic (NFR6): run_id / nonce / issued_at are INPUTS.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from core import VerdictType
from gate import signing
from core.chain import canonical_digest, content_digest

# The attestation WIRE schema — an axis independent of the identity contract. The verifier hard-rejects
# any other value (an old record cannot restore a tier). Nothing is deployed, so no back-compat machinery.
MEASUREMENT_ATTESTATION_SCHEMA = "measurement-attestation:v3"
_ATTESTATION_DOMAIN = "gated.measurement-attestation"

# The IDENTITY CONTRACT version — how the RuntimeSubject coordinates compose into the subject digest. Bound
# as an explicit signed field AND baked into the subject digest's domain prefix (crypto domain separation).
IDENTITY_CONTRACT_VERSION = 1
_SUBJECT_DOMAIN_PREFIX = "gated.calibrated-subject"

# The EXPLICIT allowlist of coordinates that enter the subject identity hash — nothing else may. The
# calibration-context fields are signed by the envelope but MUST NOT feed the subject digest (the
# context-isolation test proves this structurally).
RUNTIME_SUBJECT_FIELDS = (
    "resolved_profile_digest",
    "trust_policy_digest",
    "guard_policy_digest",
    "execution_identity_digest",
)
CALIBRATION_CONTEXT_FIELDS = ("set_id", "oracle_head", "coverage_digest", "tier_generation")


class AttestationError(RuntimeError):
    """Base: a measurement attestation could not be trusted. The consumer fails CLOSED — an unverifiable
    measurement is no measurement, so no state moves. Subclasses are LAYER-TAGGED so a negative test can
    assert exactly which layer rejected (and cannot pass for the wrong reason)."""


class MeasurementSchemaError(AttestationError):
    """Wire layer: wrong schema version, or a field of the wrong primitive type."""


class IdentityContractError(AttestationError):
    """Identity-contract layer: an ``identity_contract_version`` this build does not implement."""


class AttestationSignatureError(AttestationError):
    """Signature layer: the signature is not valid hex, or does not verify under the issuer's public key."""


class SubjectCompositionError(AttestationError):
    """Composition layer: the outcome-required runtime_subject coordinates are absent / partial."""


class SubjectMismatchError(AttestationError):
    """Recompute layer: ``subject_identity`` != ``H_v{ICV}(runtime_subject)`` — tampered or inconsistent."""


def calibrated_subject_identity(
    resolved_profile_digest: str | None,
    trust_policy_digest: str | None,
    guard_policy_digest: str | None,
    execution_identity_digest: str | None,
    *,
    icv: int = IDENTITY_CONTRACT_VERSION,
) -> str:
    """The composite CALIBRATED-SUBJECT identity over the FOUR RuntimeSubject coordinates: WHICH detector
    code, under WHICH observation-trust policy + WHICH backend-guard policy, in WHICH measured environment.
    All four are trusted/measured, never caller-supplied. The ``icv`` is bound into the DOMAIN PREFIX, so a
    change in the identity contract yields a digest that cannot cross-verify under another contract version.
    A change in ANY coordinate yields a new subject identity (the enforcement match then fails closed)."""
    return canonical_digest(f"{_SUBJECT_DOMAIN_PREFIX}.v{icv}", {
        "resolved_profile_digest": resolved_profile_digest,
        "trust_policy_digest": trust_policy_digest,
        "guard_policy_digest": guard_policy_digest,
        "execution_identity_digest": execution_identity_digest,
    })


@dataclass(frozen=True)
class MeasurementAttestation:
    """A signed, self-describing measurement. ``outcome`` is the calibration-level verdict. Everything
    except ``signature`` is signed. The identity lives in the ``runtime_subject`` block (the four
    ``RUNTIME_SUBJECT_FIELDS``); ``set_id``/``oracle_head``/``coverage_digest``/``tier_generation`` are the
    ``calibration_context`` block (signed as REPORTED, not authorized).

    CONDITIONAL VALIDITY: a PASS/FAIL requires ALL FOUR runtime_subject coordinates and the composite
    subject; an ERROR whose environment/policies were unattestable may carry null coordinates (and
    ``subject_identity=None``) — signed evidence of a failed attempt, categorically NON-restorable
    (``is_clean_pass`` False)."""

    outcome: VerdictType
    policy_id: str
    subject_identity: str | None      # MEASURED composite = H_v{ICV}(runtime_subject) (None on ERROR)
    requested_subject_identity: str   # the GOVERNANCE target this run was asked to measure (signed)
    # --- runtime_subject block (the four coordinates the subject digest consumes) ---
    resolved_profile_digest: str | None   # WHICH detector code ran (trusted registry)
    trust_policy_digest: str | None       # WHICH observation-trust policy governed it (S3 B1)
    guard_policy_digest: str | None       # WHICH backend-guard policy governed it (S3 B3)
    execution_identity_digest: str | None  # WHICH measured environment it ran in
    # --- calibration_context block (signed as reported; currency re-checked by governance) ---
    set_id: str
    oracle_head: str                # set_head(set_id) at measurement time (the SEALED head)
    coverage_digest: str            # digest of the exact ground-truth fixtures scored
    tier_generation: str            # policy tier-chain head at measurement (AUDIT provenance)
    # --- issuance metadata ---
    issuer: str                     # the CALIBRATION_GOVERNANCE issuer id (checked vs an allowlist)
    run_id: str
    nonce: str
    issued_at_ms: int               # integer ms IS the wire field (no lossy float round-trip)
    fixture_coverage: tuple[str, ...]
    short_circuit: bool             # MUST be False for a PASS to be a valid restore basis
    fn_failures: tuple[str, ...] = ()
    fp_failures: tuple[str, ...] = ()
    flaky: tuple[str, ...] = ()
    harness_errors: tuple[str, ...] = ()
    identity_contract_version: int = IDENTITY_CONTRACT_VERSION  # signed; exact-matched calibrate<->enforce
    schema: str = MEASUREMENT_ATTESTATION_SCHEMA  # signed; verifier hard-rejects any other value
    signature: str = field(default="")   # Ed25519 signature (hex) over the canonical envelope

    def _runtime_subject(self) -> dict[str, object]:
        return {f: getattr(self, f) for f in RUNTIME_SUBJECT_FIELDS}

    def _calibration_context(self) -> dict[str, object]:
        return {f: getattr(self, f) for f in CALIBRATION_CONTEXT_FIELDS}

    def _envelope(self) -> dict[str, object]:
        """The signed content — a domain-separated ``canonical_digest`` envelope EXCLUDING ``signature``,
        with ``runtime_subject`` and ``calibration_context`` as explicit nested blocks under one signature."""
        return {
            "schema": self.schema,
            "identity_contract_version": self.identity_contract_version,
            "outcome": self.outcome.value, "policy_id": self.policy_id,
            "subject_identity": self.subject_identity,
            "requested_subject_identity": self.requested_subject_identity,
            "runtime_subject": self._runtime_subject(),
            "calibration_context": self._calibration_context(),
            "issuer": self.issuer, "run_id": self.run_id, "nonce": self.nonce,
            "issued_at_ms": self.issued_at_ms,
            "fixture_coverage": sorted(self.fixture_coverage), "short_circuit": self.short_circuit,
            "fn_failures": sorted(self.fn_failures), "fp_failures": sorted(self.fp_failures),
            "flaky": sorted(self.flaky), "harness_errors": sorted(self.harness_errors),
        }

    @property
    def issued_at(self) -> float:
        """Display-only seconds (presentation boundary). The signed/stored field is ``issued_at_ms``."""
        return self.issued_at_ms / 1000.0

    @property
    def is_clean_pass(self) -> bool:
        """A PASS eligible to be a restore basis: v3 schema, matching ICV, outcome PASS, short-circuit OFF,
        non-empty coverage, ALL FOUR runtime_subject coordinates present, and the composite subject present.
        The restore controller ALSO checks value-currency + tier asymmetry; this is the intrinsic shape."""
        return (
            self.schema == MEASUREMENT_ATTESTATION_SCHEMA
            and self.identity_contract_version == IDENTITY_CONTRACT_VERSION
            and self.outcome is VerdictType.PASS
            and self.short_circuit is False
            and len(self.fixture_coverage) > 0
            and all(getattr(self, f) is not None for f in RUNTIME_SUBJECT_FIELDS)
            and self.subject_identity is not None
        )


def _envelope_digest(attestation: MeasurementAttestation) -> str:
    return canonical_digest(_ATTESTATION_DOMAIN, attestation._envelope())


# ---- the deterministic validation pipeline (board ckpt4: type-check discriminators BEFORE comparing) ----

def _check_discriminator_types(att: MeasurementAttestation) -> None:
    """Step 1 — the discriminator PRIMITIVE types, before any comparison (comparing an untyped
    discriminator is not well-defined). ``schema`` is a str; ``identity_contract_version`` is an int (bool
    is an int subclass — reject it)."""
    if type(att.schema) is not str:
        raise MeasurementSchemaError("schema must be a str")
    if type(att.identity_contract_version) is not int:
        raise IdentityContractError("identity_contract_version must be an int (not bool / str)")


def _check_schema_version(att: MeasurementAttestation) -> None:
    if att.schema != MEASUREMENT_ATTESTATION_SCHEMA:
        raise MeasurementSchemaError(
            f"unsupported attestation schema {att.schema!r} — only {MEASUREMENT_ATTESTATION_SCHEMA!r}")


def _check_identity_contract(att: MeasurementAttestation) -> None:
    if att.identity_contract_version != IDENTITY_CONTRACT_VERSION:
        raise IdentityContractError(
            f"unsupported identity_contract_version {att.identity_contract_version!r} — only "
            f"{IDENTITY_CONTRACT_VERSION!r}")


def _req_nonempty_str(att: MeasurementAttestation, name: str) -> None:
    v = getattr(att, name)
    if type(v) is not str or v == "":
        raise MeasurementSchemaError(f"{name} must be a non-empty str")


def _opt_nonempty_str(att: MeasurementAttestation, name: str) -> None:
    """A field that is ``None`` OR a NON-EMPTY str. An empty string is NOT a valid identity coordinate —
    it would otherwise be treated as 'present' by the all-four check and hash into a meaningless composite
    (the empty-string identity-downgrade bypass)."""
    v = getattr(att, name)
    if v is not None and (type(v) is not str or v == ""):
        raise MeasurementSchemaError(f"{name} must be a non-empty str or None")


def _check_wire_types(att: MeasurementAttestation) -> None:
    """The remaining EXACT wire types (after the discriminators are typed + matched) — EVERY signed field,
    not just the runtime coordinates. Identity coordinates must be non-empty when present; the required
    string fields must be non-empty; no coercion is tolerated."""
    if not isinstance(att.outcome, VerdictType):
        raise MeasurementSchemaError("outcome must be a VerdictType")
    if type(att.issued_at_ms) is not int:  # bool is an int subclass — reject it explicitly
        raise MeasurementSchemaError("issued_at_ms must be an int (not bool / str / float)")
    if type(att.short_circuit) is not bool:
        raise MeasurementSchemaError("short_circuit must be a bool")
    for name in ("fixture_coverage", "fn_failures", "fp_failures", "flaky", "harness_errors"):
        seq = getattr(att, name)
        if not isinstance(seq, tuple) or not all(type(x) is str for x in seq):
            raise MeasurementSchemaError(f"{name} must be a tuple of str")
    # the four runtime-subject coordinates + the optional composite: None or a NON-EMPTY str.
    for name in (*RUNTIME_SUBJECT_FIELDS, "subject_identity"):
        _opt_nonempty_str(att, name)
    # the required non-empty string fields (issuance metadata + the whole calibration_context block).
    for name in ("policy_id", "requested_subject_identity", "issuer", "run_id", "nonce",
                 *CALIBRATION_CONTEXT_FIELDS):
        _req_nonempty_str(att, name)


def _check_conditional_validity(att: MeasurementAttestation) -> None:
    """Composition + recompute layers. PASS/FAIL require ALL four runtime_subject coordinates AND a
    composite subject; an ERROR may carry null coordinates (non-restorable evidence). Whenever a subject is
    present, ALL four coordinates must be present and the subject MUST equal ``H_v{ICV}(runtime_subject)``
    using the SIGNED ICV as the domain prefix."""
    # truthiness (not ``is not None``) — an empty-string coordinate is NOT present (defence in depth; the
    # wire-type layer already rejects an empty coordinate, this is the second gate).
    coords_present = all(getattr(att, f) for f in RUNTIME_SUBJECT_FIELDS)
    subj = att.subject_identity
    if att.outcome in (VerdictType.PASS, VerdictType.FAIL):
        if not coords_present or subj is None:
            raise SubjectCompositionError(
                f"a {att.outcome.value} attestation requires all runtime_subject coordinates and a "
                "composite subject_identity (conditional v3 validity)")
    if subj is not None:
        if not coords_present:
            raise SubjectCompositionError(
                "subject_identity present without all runtime_subject coordinates — incoherent "
                "(an unattestable ERROR must not claim a calibrated subject)")
        if subj != calibrated_subject_identity(
            att.resolved_profile_digest, att.trust_policy_digest, att.guard_policy_digest,
            att.execution_identity_digest, icv=att.identity_contract_version,
        ):
            raise SubjectMismatchError(
                "subject_identity != H(runtime_subject) under the signed identity_contract_version — the "
                "measurement-derived composite is tampered or inconsistent")


def sign_measurement(
    unsigned: MeasurementAttestation, *, signer: signing.Signer
) -> MeasurementAttestation:
    """Return a signed copy of ``unsigned`` (Ed25519 over the v3 canonical envelope). VALIDATE-BEFORE-SIGN
    in the deterministic order (minus signature): the runner refuses to sign a record that violates the
    schema / identity-contract / wire types / conditional validity, so an invalid attestation is never
    produced, not merely rejected on read."""
    _check_discriminator_types(unsigned)
    _check_schema_version(unsigned)
    _check_identity_contract(unsigned)
    _check_wire_types(unsigned)
    _check_conditional_validity(unsigned)
    return replace(unsigned, signature=signer.sign(_envelope_digest(unsigned).encode("utf-8")).hex())


def verify_measurement(
    attestation: MeasurementAttestation, *, verifier: signing.Verifier
) -> None:
    """Raise an ``AttestationError`` subclass unless the attestation is a valid v3 record. Deterministic
    validation ORDER (board ckpt4) — each layer's failure is a DISTINCT typed error so a negative cannot
    pass for the wrong reason: (1) discriminator primitive types → (2) schema equality → (3) ICV equality →
    (4) remaining wire types → (5) Ed25519 signature over the canonical envelope → (6) conditional presence
    → (7) composite recompute using the SIGNED ICV. Integrity/authenticity only — value-currency + the
    governance/authorization match are the restore controller's job (a distinct layer)."""
    _check_discriminator_types(attestation)
    _check_schema_version(attestation)
    _check_identity_contract(attestation)
    _check_wire_types(attestation)
    try:
        sig = bytes.fromhex(attestation.signature)
    except (ValueError, TypeError):
        raise AttestationSignatureError("measurement signature is not valid hex") from None
    if not verifier.verify(_envelope_digest(attestation).encode("utf-8"), sig):
        raise AttestationSignatureError("measurement signature invalid — payload tampered or wrong key")
    _check_conditional_validity(attestation)


def attestation_ref(attestation: MeasurementAttestation) -> str:
    """A deterministic, content-derived handle binding a ``calibration_pass`` / RE_ATTESTATION record to
    the EXACT immutable signed measurement (its full v3 envelope + Ed25519 ``signature``). A ref that
    resolves to a real signed PASS cannot be fabricated without a valid signature. Replay of an OLD signed
    attestation is caught separately by the restore CAS (its ``oracle_head`` is no longer current)."""
    return content_digest({"envelope": attestation._envelope(), "signature": attestation.signature})


__all__ = [
    "AttestationError",
    "MeasurementSchemaError",
    "IdentityContractError",
    "AttestationSignatureError",
    "SubjectCompositionError",
    "SubjectMismatchError",
    "MeasurementAttestation",
    "MEASUREMENT_ATTESTATION_SCHEMA",
    "IDENTITY_CONTRACT_VERSION",
    "RUNTIME_SUBJECT_FIELDS",
    "CALIBRATION_CONTEXT_FIELDS",
    "calibrated_subject_identity",
    "sign_measurement",
    "verify_measurement",
    "attestation_ref",
]
