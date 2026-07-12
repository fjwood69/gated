"""gate/attestation.py — 3.5 job-1: the SIGNED MEASUREMENT (the re-calibration runner's only output).

The keystone of *measurement ≠ governance*. The re-calibration runner MEASURES a detector's fitness
and emits one of these — a signed statement "detector D, on set S at oracle-head H, tier-generation G,
scored PASS/FAIL/ERROR over THIS complete fixture coverage, short-circuit OFF, in run R". It carries
**no authority to change any tier**: the signing key is the MEASUREMENT key, which is NOT in the
tier-write authorised set, and the runner is handed no ``PolicyStore``. A separate governance act (the
restore controller for an auto-restore, or a human ``ratify_enable`` / demote) must CONSUME a verified
attestation to move state. A FAIL never demotes and a PASS never enables *by itself*.

Replay-safety (the amendment): a PASS binds its FULL context — the 4-tuple ``detector_identity``, the
scoped ``oracle_head``, the ``tier_generation`` (tier-chain head at measurement), ``run_id`` + ``nonce``
+ ``issued_at``, the COMPLETE ``fixture_coverage`` (every ground-truth fixture id that was actually
scored — proves no partial/short run passed), and ``short_circuit=False``. A stale PASS cannot be
replayed to restore a detector because the restore controller re-checks every one of these against the
CURRENT world (identity / oracle-head / tier-generation) and refuses on any drift; the nonce + run_id
make each measurement a distinct, non-reusable instance.

Signed with ASYMMETRIC Ed25519 (merge-ready #2): the runner signs with a PRIVATE seed; the restore
controller holds ONLY the PUBLIC key, so a compromised controller cannot forge a PASS attestation — the
measurement≠governance separation is cryptographically real, not a symmetric key the verifier could
re-sign with. A deployment binds a KMS/HSM behind the same seam. Gate-side; ``core`` never imports this.
Deterministic (NFR6): run_id / nonce / issued_at are INPUTS, not generated here, so an attestation is
reproducible from its inputs and unit-testable without a clock or RNG.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Mapping

from core import VerdictType
from gate import signing
from core.chain import content_digest


class AttestationError(RuntimeError):
    """A measurement attestation could not be trusted — signature-invalid (payload tampered or wrong
    key), or malformed. The consumer (restore controller / governance) fails CLOSED: an unverifiable
    measurement is no measurement, so no state moves."""


@dataclass(frozen=True)
class MeasurementAttestation:
    """A signed, self-describing measurement. ``outcome`` is the calibration-level verdict
    (PASS/FAIL/ERROR). Everything except ``mac`` is signed. For a FAIL, the failure breakdown
    (``fn_failures`` etc.) is the legible evidence a human uses for the missed-FN split; it does NOT
    itself resolve anything (no auto-resolve). ``fixture_coverage`` is the sorted tuple of every
    ground-truth fixture id scored — a PASS with incomplete coverage is not a valid restore basis."""

    outcome: VerdictType
    policy_id: str
    detector_identity: str          # the 4-tuple execution identity (core.identity.bind_identity)
    set_id: str
    oracle_head: str                # set_head(set_id) at measurement time (the SEALED head)
    coverage_digest: str            # digest of the exact ground-truth fixtures scored (co-sealed w/ head)
    tier_generation: str            # policy tier-chain head at measurement (AUDIT provenance only —
                                    # integrity-covered by the MAC; the restore GATE is the oracle-head
                                    # + policy-evidence-head CAS, not this field)
    issuer: str                     # the CALIBRATION_GOVERNANCE issuer id (checked vs an allowlist)
    run_id: str
    nonce: str
    issued_at: float
    fixture_coverage: tuple[str, ...]
    short_circuit: bool             # MUST be False for a PASS to be a valid restore basis
    fn_failures: tuple[str, ...] = ()
    fp_failures: tuple[str, ...] = ()
    flaky: tuple[str, ...] = ()
    harness_errors: tuple[str, ...] = ()
    signature: str = field(default="")   # Ed25519 signature (hex) over the canonical payload

    def _payload(self) -> dict[str, object]:
        """Signed content — EXCLUDES ``signature``. Sorted/fully-specified so the bytes are stable and
        cross-language reproducible (NFR6)."""
        return {
            "outcome": self.outcome.value, "policy_id": self.policy_id,
            "detector_identity": self.detector_identity, "set_id": self.set_id,
            "oracle_head": self.oracle_head, "coverage_digest": self.coverage_digest,
            "tier_generation": self.tier_generation, "issuer": self.issuer,
            "run_id": self.run_id, "nonce": self.nonce, "issued_at": self.issued_at,
            "fixture_coverage": sorted(self.fixture_coverage), "short_circuit": self.short_circuit,
            "fn_failures": sorted(self.fn_failures), "fp_failures": sorted(self.fp_failures),
            "flaky": sorted(self.flaky), "harness_errors": sorted(self.harness_errors),
        }

    @property
    def is_clean_pass(self) -> bool:
        """A PASS eligible to be a restore basis: outcome PASS, short-circuit OFF, and non-empty
        complete coverage. (The restore controller ALSO checks value-currency + tier asymmetry; this
        is only the intrinsic shape of the attestation.)"""
        return (
            self.outcome is VerdictType.PASS
            and self.short_circuit is False
            and len(self.fixture_coverage) > 0
        )


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_measurement(unsigned: MeasurementAttestation, *, signing_seed: bytes) -> MeasurementAttestation:
    """Return a signed copy of ``unsigned`` (Ed25519 signature recomputed). ``signing_seed`` is the
    runner's 32-byte PRIVATE measurement seed — held by the measurement side only. The restore
    controller never sees it (it holds the matching public key), so a measurement signature confers no
    power to mutate a tier AND cannot be forged by the verifier (measurement ≠ governance, cryptographic)."""
    return replace(unsigned, signature=signing.sign(_canonical(unsigned._payload()), signing_seed).hex())


def verify_measurement(attestation: MeasurementAttestation, *, verify_key: bytes) -> None:
    """Raise ``AttestationError`` unless the Ed25519 signature is valid under ``verify_key`` (the
    issuer's 32-byte PUBLIC key). Integrity/authenticity only — freshness is the restore controller's
    value-currency CAS (a PASS whose identity / oracle-head still match the world is still true, no
    matter its age; one whose values drifted is refused there). The verifier cannot forge: it has no seed."""
    try:
        sig = bytes.fromhex(attestation.signature)
    except ValueError:
        raise AttestationError("measurement signature is not valid hex") from None
    if not signing.verify(_canonical(attestation._payload()), sig, verify_key):
        raise AttestationError("measurement signature invalid — payload tampered or wrong key")


def attestation_ref(attestation: MeasurementAttestation) -> str:
    """A deterministic, content-derived handle binding a ``calibration_pass`` / RE_ATTESTATION record
    to the EXACT immutable signed measurement (its full payload + Ed25519 ``signature``). Because the
    signature can only be produced by the private-seed holder, a ref that resolves to a real signed PASS
    cannot be fabricated without a valid signature — the restore controller's ref binds an immutable
    signed attestation, not a bare mutable row (board amendment 2). Replay of an OLD signed attestation
    is caught separately by the restore CAS (its ``oracle_head`` is no longer current)."""
    return content_digest({"payload": attestation._payload(), "signature": attestation.signature})


__all__ = [
    "AttestationError",
    "MeasurementAttestation",
    "sign_measurement",
    "verify_measurement",
    "attestation_ref",
]
