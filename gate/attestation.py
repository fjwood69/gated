"""gate/attestation.py — 3.5 job-1: the SIGNED MEASUREMENT (the re-calibration runner's only output).

The keystone of *measurement ≠ governance*. The re-calibration runner MEASURES a detector's fitness
and emits one of these — a signed statement "subject S, on set S at oracle-head H, tier-generation G,
scored PASS/FAIL/ERROR over THIS complete fixture coverage, short-circuit OFF, in run R". It carries
**no authority to change any tier**: the signing key is the MEASUREMENT key, which is NOT in the
tier-write authorised set, and the runner is handed no ``PolicyStore``. A separate governance act (the
restore controller for an auto-restore, or a human ``ratify_enable`` / demote) must CONSUME a verified
attestation to move state. A FAIL never demotes and a PASS never enables *by itself*.

3.5-close P1-3 — MEASUREMENT-DERIVED IDENTITY (schema ``measurement-attestation:v2``). The identity a
PASS binds is no longer a CALLER-supplied string (the sign-A-run-B hole). It is the **calibrated-subject
identity** = ``H(resolved_profile_digest, execution_identity_digest)``, where BOTH coordinates come from
the SAME calibration operation and neither is caller input:
  * ``resolved_profile_digest`` — the trusted registry's ``ResolvedDetectorProfile`` digest for the
    detector that ACTUALLY ran (which detector code + entrypoint + trusted config), carried out of
    ``calibrate`` so no second resolution can drift.
  * ``execution_identity_digest`` — the parent-measured environment identity (backend/image/isolation/
    observer) the run actually happened in.
Both components are exposed alongside the composite so a consumer can recompute the binding and identify
the measured environment; the verifier RECOMPUTES ``subject_identity`` and rejects a tampered composite.
The 3.4 caller-supplied 4-tuple (``core.identity.bind_identity``) is superseded here — it was itself
caller-derived and is retained only as a non-authoritative legacy helper.

Replay-safety (the amendment): a PASS binds its FULL context — ``subject_identity`` + its two components,
the scoped ``oracle_head``, the ``tier_generation``, ``run_id`` + ``nonce`` + ``issued_at``, the COMPLETE
``fixture_coverage``, and ``short_circuit=False``. A stale PASS cannot be replayed to restore a detector
because the restore controller re-checks these against the CURRENT world and refuses on any drift.

Signed with ASYMMETRIC Ed25519 (merge-ready #2): the runner signs with a PRIVATE seed; the restore
controller holds ONLY the PUBLIC key. The signed content is a domain-separated, schema-validated
``canonical_digest`` envelope (versioned, float-free, NFC-normalised) — cross-language reproducible and
tamper-evident on every field. A deployment binds a KMS/HSM behind the same seam. Gate-side; ``core``
never imports this. Deterministic (NFR6): run_id / nonce / issued_at are INPUTS, not generated here.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

from core import VerdictType
from gate import signing
from core.chain import canonical_digest, content_digest

# The attestation wire schema. This is a NEW evidence schema, not merely new field population — the
# signed bytes carry the version, and the verifier HARD-REJECTS anything else (a v1 record cannot
# restore a tier). Nothing is deployed, so no v1 compatibility machinery exists.
MEASUREMENT_ATTESTATION_SCHEMA = "measurement-attestation:v2"
_ATTESTATION_DOMAIN = "gated.measurement-attestation"

# The calibrated-subject identity binder (P1-3). Domain-separated + versioned so the composite is
# unambiguous and a future scheme change invalidates old records rather than silently reinterpreting them.
_SUBJECT_DOMAIN = "gated.calibrated-subject"
CALIBRATED_SUBJECT_VERSION = 1


class AttestationError(RuntimeError):
    """A measurement attestation could not be trusted — unsupported schema (a v1 record), signature-
    invalid (payload tampered or wrong key), or an incoherent/tampered subject composite. The consumer
    (restore controller / governance) fails CLOSED: an unverifiable measurement is no measurement, so no
    state moves."""


def calibrated_subject_identity(resolved_profile_digest: str, execution_identity_digest: str) -> str:
    """The composite CALIBRATED-SUBJECT identity: WHICH detector code (its resolved-profile digest) ran in
    WHICH measured environment (its parent-measured execution-identity digest). Both coordinates are
    trusted/measured, never caller-supplied — this is the P1-3 close. A change in EITHER yields a new
    subject identity, so a stale calibration cannot bind a drifted detector or a drifted environment (the
    future enforcement match fails closed)."""
    return canonical_digest(_SUBJECT_DOMAIN, {
        "version": CALIBRATED_SUBJECT_VERSION,
        "resolved_profile_digest": resolved_profile_digest,
        "execution_identity_digest": execution_identity_digest,
    })


@dataclass(frozen=True)
class MeasurementAttestation:
    """A signed, self-describing measurement. ``outcome`` is the calibration-level verdict
    (PASS/FAIL/ERROR). Everything except ``signature`` is signed. For a FAIL, the failure breakdown
    (``fn_failures`` etc.) is the legible evidence a human uses for the missed-FN split; it does NOT
    itself resolve anything (no auto-resolve). ``fixture_coverage`` is the sorted tuple of every
    ground-truth fixture id scored — a PASS with incomplete coverage is not a valid restore basis.

    P1-3 (v2): ``subject_identity`` is the measurement-derived calibrated-subject identity (see
    ``calibrated_subject_identity``); ``resolved_profile_digest`` and ``execution_identity_digest`` are its
    two derivation components, exposed so a consumer can recompute + identify the measured environment.
    CONDITIONAL VALIDITY: a PASS/FAIL requires BOTH components (and hence a subject); an ERROR whose
    environment was unattestable may carry ``execution_identity_digest=None`` (and ``subject_identity=None``)
    — it is signed evidence of a failed attempt but is categorically NON-restorable (``is_clean_pass``
    False). A drifted/unregistered resolution likewise yields audit evidence, never a restore basis."""

    outcome: VerdictType
    policy_id: str
    subject_identity: str | None      # P1-3 MEASURED composite = H(profile, execution) (None on ERROR)
    requested_subject_identity: str   # v3: the GOVERNANCE target this run was asked to measure (signed).
    # measurement ≠ governance: the runner MEASURES subject_identity; restore requires measured==requested
    # AND requested==the policy's currently authorized target, so measurement can never SELECT the target.
    resolved_profile_digest: str | None   # component 1 — which detector code ran (trusted registry)
    execution_identity_digest: str | None  # component 2 — which measured environment it ran in
    set_id: str
    oracle_head: str                # set_head(set_id) at measurement time (the SEALED head)
    coverage_digest: str            # digest of the exact ground-truth fixtures scored (co-sealed w/ head)
    tier_generation: str            # policy tier-chain head at measurement (AUDIT provenance only)
    issuer: str                     # the CALIBRATION_GOVERNANCE issuer id (checked vs an allowlist)
    run_id: str
    nonce: str
    issued_at_ms: int               # v3: integer ms IS the wire field (no lossy float round-trip)
    fixture_coverage: tuple[str, ...]
    short_circuit: bool             # MUST be False for a PASS to be a valid restore basis
    fn_failures: tuple[str, ...] = ()
    fp_failures: tuple[str, ...] = ()
    flaky: tuple[str, ...] = ()
    harness_errors: tuple[str, ...] = ()
    schema: str = MEASUREMENT_ATTESTATION_SCHEMA  # signed; verifier hard-rejects any other value
    signature: str = field(default="")   # Ed25519 signature (hex) over the canonical envelope

    def _envelope(self) -> dict[str, object]:
        """The signed content — a domain-separated, schema-validated ``canonical_digest`` envelope,
        EXCLUDING ``signature``. Float-free (``issued_at`` is bound as integer ms) and fully specified so
        the signed bytes are stable and cross-language reproducible (NFR6). Every field except the
        signature is inside it, so the signature covers the whole record."""
        return {
            "schema": self.schema,
            "outcome": self.outcome.value, "policy_id": self.policy_id,
            "subject_identity": self.subject_identity,
            "requested_subject_identity": self.requested_subject_identity,
            "resolved_profile_digest": self.resolved_profile_digest,
            "execution_identity_digest": self.execution_identity_digest,
            "set_id": self.set_id, "oracle_head": self.oracle_head,
            "coverage_digest": self.coverage_digest, "tier_generation": self.tier_generation,
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
        """A PASS eligible to be a restore basis: v2 schema, outcome PASS, short-circuit OFF, non-empty
        complete coverage, AND both derivation components + the composite subject present (conditional
        validity — an ERROR that nulled its environment is categorically non-restorable). The restore
        controller ALSO checks value-currency + tier asymmetry; this is only the intrinsic shape."""
        return (
            self.schema == MEASUREMENT_ATTESTATION_SCHEMA
            and self.outcome is VerdictType.PASS
            and self.short_circuit is False
            and len(self.fixture_coverage) > 0
            and self.resolved_profile_digest is not None
            and self.execution_identity_digest is not None
            and self.subject_identity is not None
        )


def _envelope_digest(attestation: MeasurementAttestation) -> str:
    return canonical_digest(_ATTESTATION_DOMAIN, attestation._envelope())


def _check_wire_schema(att: MeasurementAttestation) -> None:
    """v4 (board P2): validate the COMPLETE wire schema before trusting/signing — not just the identity
    shape. Enforces the exact schema version and exact field TYPES (``bool`` is an ``int`` subclass, so an
    ``issued_at_ms`` of ``True`` must be rejected; collection elements must be ``str``). This closes
    type-coercion laundering (a value that passes a lax check but evaluates differently in app logic)."""
    if att.schema != MEASUREMENT_ATTESTATION_SCHEMA:
        raise AttestationError(
            f"unsupported attestation schema {att.schema!r} — only {MEASUREMENT_ATTESTATION_SCHEMA!r}")
    if not isinstance(att.outcome, VerdictType):
        raise AttestationError("outcome must be a VerdictType")
    if type(att.issued_at_ms) is not int:  # bool is an int subclass — reject it explicitly
        raise AttestationError("issued_at_ms must be an int (not bool / str / float)")
    if type(att.short_circuit) is not bool:
        raise AttestationError("short_circuit must be a bool")
    for field_name in ("fixture_coverage", "fn_failures", "fp_failures", "flaky", "harness_errors"):
        seq = getattr(att, field_name)
        if not isinstance(seq, tuple) or not all(type(x) is str for x in seq):
            raise AttestationError(f"{field_name} must be a tuple of str")


def _check_conditional_validity(att: MeasurementAttestation) -> None:
    """v3 (board P2): enforce the outcome-conditional identity-coordinate rules on the WIRE, not just via
    ``is_clean_pass``. Applied at BOTH sign and verify. Rules:
      * execution-only (execution digest present, profile absent) is IMPOSSIBLE -> rejected;
      * PASS / FAIL require BOTH components AND a composite subject;
      * ERROR may be profile-only (resolution succeeded, environment unattestable) or all-null;
      * whenever a subject is present it MUST equal H(profile, execution) with both components present."""
    rpd, eid, subj = att.resolved_profile_digest, att.execution_identity_digest, att.subject_identity
    if eid is not None and rpd is None:
        raise AttestationError(
            "execution_identity_digest present without resolved_profile_digest — a measured environment "
            "with no resolved detector is incoherent")
    if att.outcome in (VerdictType.PASS, VerdictType.FAIL):
        if rpd is None or eid is None or subj is None:
            raise AttestationError(
                f"a {att.outcome.value} attestation requires both derivation components and a composite "
                "subject_identity (conditional v2 validity)")
    if subj is not None:
        if rpd is None or eid is None:
            raise AttestationError(
                "subject_identity is present without both derivation components — incoherent "
                "(an unattestable ERROR must not claim a calibrated subject)")
        if subj != calibrated_subject_identity(rpd, eid):
            raise AttestationError(
                "subject_identity != H(resolved_profile_digest, execution_identity_digest) — the "
                "measurement-derived composite is tampered or inconsistent")


def sign_measurement(
    unsigned: MeasurementAttestation, *, signer: signing.Signer
) -> MeasurementAttestation:
    """Return a signed copy of ``unsigned`` (Ed25519 signature over the v2 canonical envelope). 3.5-close
    #1.4: takes a ``Signer`` OBJECT, not a raw seed. v3/v4: VALIDATE-BEFORE-SIGN — the runner refuses to
    sign a record that violates the COMPLETE wire schema OR conditional validity, so an invalid attestation
    is never produced, not merely rejected on read."""
    _check_wire_schema(unsigned)
    _check_conditional_validity(unsigned)
    return replace(unsigned, signature=signer.sign(_envelope_digest(unsigned).encode("utf-8")).hex())


def verify_measurement(
    attestation: MeasurementAttestation, *, verifier: signing.Verifier
) -> None:
    """Raise ``AttestationError`` unless the attestation is a valid v2 record: (1) schema is exactly
    ``measurement-attestation:v2`` (a v1 record is HARD-REJECTED); (2) the Ed25519 signature over the
    canonical envelope is valid under ``verifier`` (a public-key-only ``Verifier`` — it cannot forge);
    (3) conditional validity holds — the outcome-appropriate identity coordinates are present and any
    ``subject_identity`` equals ``H(resolved_profile_digest, execution_identity_digest)`` (tamper of either
    component or the composite fails here). Integrity/authenticity only — freshness is the restore CAS."""
    _check_wire_schema(attestation)  # v4: exact schema + field types before trusting the signature
    try:
        sig = bytes.fromhex(attestation.signature)
    except ValueError:
        raise AttestationError("measurement signature is not valid hex") from None
    if not verifier.verify(_envelope_digest(attestation).encode("utf-8"), sig):
        raise AttestationError("measurement signature invalid — payload tampered or wrong key")
    _check_conditional_validity(attestation)


def attestation_ref(attestation: MeasurementAttestation) -> str:
    """A deterministic, content-derived handle binding a ``calibration_pass`` / RE_ATTESTATION record to
    the EXACT immutable signed measurement (its full v2 envelope + Ed25519 ``signature``). Because the
    signature can only be produced by the private-seed holder, a ref that resolves to a real signed PASS
    cannot be fabricated without a valid signature. Replay of an OLD signed attestation is caught
    separately by the restore CAS (its ``oracle_head`` is no longer current)."""
    return content_digest({"envelope": attestation._envelope(), "signature": attestation.signature})


__all__ = [
    "AttestationError",
    "MeasurementAttestation",
    "MEASUREMENT_ATTESTATION_SCHEMA",
    "calibrated_subject_identity",
    "sign_measurement",
    "verify_measurement",
    "attestation_ref",
]
