"""gate/restore_controller.py — 3.5 job-1: the RESTORE CONTROLLER (governance acting on a signed meter).

The GOVERNANCE half of measurement≠governance, and the ONLY component that turns a signed re-calibration
PASS back into an attestable ENABLED policy. It is deliberately NOT the runner (which cannot write any
tier) and NOT the merge-path gatekeeper (which stays read-only). It holds a capability RESTRICTED to the
RE_ATTESTATION record kind (``ReAttestCapability``) — it can advance a policy's evidence, never perform an
arbitrary tier transition (board amendment 1).

What it enforces before appending a RE_ATTESTATION (the 5-part CAS + gates):
  1. AUTHENTICITY — the measurement is HMAC-valid under the issuer's key AND the issuer is on the
     allowlist (issuer/key-epoch; board amendment 2). An unverifiable measurement moves nothing.
  2. CLEAN PASS — outcome PASS, short_circuit OFF, non-empty coverage (a FAIL/ERROR is a NO-OP on
     governance state — board D4; the policy is already blocking via the oracle-head drift).
  3. IDENTITY STILL TRUSTED — the detector's 4-tuple identity is still in the trusted set (a detector
     revoked while the job queued must not restore).
  4. ORACLE CURRENT — the signed ``oracle_head`` still equals the live ``set_head(set_id)``. If the set
     drifted again, restore is REFUSED; a newer re-cal (enqueued by that append) handles it. Self-
     correcting + fail-closed: a stale re-attest would only leave the policy UNATTESTABLE again.
  5. STATE + POLICY-HEAD CAS — the policy is currently ENABLED (asymmetry: an ADVISORY/DEMOTED policy
     has NO re-attest path and must re-ratify), AND the policy-evidence head is unchanged across the
     append (atomic under the store lock via ``expect_policy_head``) — so a re-attest can never land
     after a concurrent human DEMOTE. On a head-conflict it re-reads and retries; it NEVER forces.

Gate-side. Imports the policy store (governance) + attestation (measurement) + core; does NOT import the
engine or the runner. ``core`` never imports this.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Mapping

from gate.attestation import (
    AttestationError,
    MeasurementAttestation,
    verify_measurement,
)
from gate.attestation_store import MeasurementAttestationStore
from gate.signing import KeyVerifier
from gate.policy_state import PolicyState
from gate.policy_store import PolicyStore, ReAttestConflict, _mint_reattest_grant

# The ONE legitimate mint of the re-attest call-path marker. The structural no-bypass test asserts no
# other gate module calls ``_mint_reattest_grant``, so a verified restore is the sole path in-process
# that advances a policy's enforcement evidence. This is a call-path convention, not an authorization
# boundary (the load-bearing controls are reattest's mandatory chain-checked expectations; see
# gate.policy_store._ReAttestGrant).
_REATTEST_GRANT = _mint_reattest_grant()


class ReAttestCapability:
    """A NARROW capability over a ``PolicyStore`` exposing ONLY what a restore needs: the reads for the
    CAS + persisting the new pass + the RE_ATTESTATION append. It deliberately does NOT expose
    ``transition`` — the restore controller structurally cannot perform an arbitrary tier change, only
    advance evidence under an unchanged ENABLED tier (board amendment 1: capability restricted to this
    record kind)."""

    def __init__(self, store: PolicyStore) -> None:
        self._store = store

    def current_state(self, policy_id: str) -> PolicyState | None:
        return self._store.current_state(policy_id)

    def policy_head(self, policy_id: str) -> str:
        return self._store.policy_head(policy_id)

    def authorized_subject_identity(self, policy_id: str) -> str | None:
        """v3 (board P2): the subject identity the policy is CURRENTLY authorized for (its live
        calibration binding). Restore requires the re-cal's requested subject to equal THIS — so a
        measurement for a different (even globally-trusted) subject can never re-bind the policy."""
        att = self._store.current_attestation(policy_id)
        return None if att is None else att[2]

    def record_calibration_pass(self, ref: str, *, policy_id: str, pinned_set_version: str,
                                detector_identity: str, set_id: str) -> None:
        self._store.record_calibration_pass(
            ref, policy_id=policy_id, pinned_set_version=pinned_set_version,
            detector_identity=detector_identity, set_id=set_id)

    def reattest(self, policy_id: str, *, calibration_result_ref: str, pinned_set_version: str,
                 detector_identity: str, job_id: str, nonce: str, expect_policy_head: str,
                 expect_authorized_subject: str) -> int:
        return self._store.reattest(
            policy_id, grant=_REATTEST_GRANT, calibration_result_ref=calibration_result_ref,
            pinned_set_version=pinned_set_version, detector_identity=detector_identity,
            job_id=job_id, nonce=nonce, expect_policy_head=expect_policy_head,
            expect_authorized_subject=expect_authorized_subject)


class RestoreResult(Enum):
    RESTORED = "restored"                    # a RE_ATTESTATION was appended; the policy is attestable
    REFUSED_NOT_CLEAN_PASS = "not_clean_pass"  # FAIL/ERROR/short-circuit -> no-op on governance state
    REFUSED_UNTRUSTED = "untrusted"          # bad signature / issuer / revoked detector identity
    REFUSED_SUBJECT_MISMATCH = "subject_mismatch"  # measured != requested, or requested != policy's target
    REFUSED_ORACLE_STALE = "oracle_stale"    # signed head != live set_head (a newer re-cal will handle)
    REFUSED_NOT_ENABLED = "not_enabled"      # policy not ENABLED (asymmetry: must re-ratify)
    REFUSED_CAS_EXHAUSTED = "cas_exhausted"  # lost the policy-head CAS too many times


@dataclass(frozen=True)
class RestoreOutcome:
    result: RestoreResult
    reason: str
    seq: int | None = None  # the appended RE_ATTESTATION seq on RESTORED


class RestoreController:
    """Consumes signed measurements and, ONLY for a clean current PASS on an ENABLED policy, appends a
    RE_ATTESTATION advancing the evidence. ``issuer_public_keys`` maps an allowed issuer id -> its
    Ed25519 PUBLIC key (allowlist + per-issuer key epoch in one); the controller holds NO signing seed,
    so it can verify a measurement but never forge one (measurement ≠ governance, cryptographic). ``oracle_head_for`` returns the live ``set_head`` for
    a set (None if the calibration store is unreachable -> cannot verify currency -> refuse).
    ``identity_trusted`` gates on the detector's 4-tuple identity still being trusted."""

    def __init__(
        self,
        capability: ReAttestCapability,
        *,
        issuer_public_keys: Mapping[str, bytes],
        oracle_head_for: Callable[[str], str | None],
        attestation_store: MeasurementAttestationStore,
        identity_trusted: Callable[[str], bool] = lambda _identity: True,
        max_cas_retries: int = 3,
    ) -> None:
        self._cap = capability
        self._issuer_keys = dict(issuer_public_keys)
        self._oracle_head_for = oracle_head_for
        self._attestations = attestation_store
        self._identity_trusted = identity_trusted
        self._max_cas_retries = max_cas_retries

    def attempt_restore(self, att: MeasurementAttestation) -> RestoreOutcome:
        # 1. AUTHENTICITY — issuer allowlist + Ed25519 signature under that issuer's PUBLIC key.
        key = self._issuer_keys.get(att.issuer)
        if key is None:
            return RestoreOutcome(RestoreResult.REFUSED_UNTRUSTED, f"issuer {att.issuer!r} not allowed")
        try:
            verify_measurement(att, verifier=KeyVerifier(key))
        except AttestationError as exc:
            return RestoreOutcome(RestoreResult.REFUSED_UNTRUSTED, f"measurement not verifiable: {exc}")

        # 2. CLEAN PASS — a FAIL/ERROR (or short-circuit / empty coverage) is a NO-OP on governance
        # state (board D4). The policy is already blocking via the oracle-head drift; the human
        # missed-FN split is the only state-moving path for a FAIL.
        if not att.is_clean_pass:
            return RestoreOutcome(
                RestoreResult.REFUSED_NOT_CLEAN_PASS,
                f"outcome {att.outcome.value} (short_circuit={att.short_circuit}, "
                f"coverage={len(att.fixture_coverage)}) is not a clean restore basis — no state change",
            )

        # 3. IDENTITY STILL TRUSTED. P1-3: the identity is the measurement-derived calibrated-SUBJECT
        # identity (H(resolved_profile, measured environment)); is_clean_pass guarantees it is non-None.
        assert att.subject_identity is not None  # narrowed by the is_clean_pass gate above
        if not self._identity_trusted(att.subject_identity):
            return RestoreOutcome(
                RestoreResult.REFUSED_UNTRUSTED,
                f"subject identity {att.subject_identity!r} is no longer trusted",
            )

        # 3b. MEASUREMENT ≠ GOVERNANCE (v3, board P1): the MEASURED subject must equal what governance
        # REQUESTED this run to measure. A clean PASS whose measured subject differs from the request
        # cannot re-attest — measurement never selects the subject, it only confirms the requested one.
        if att.subject_identity != att.requested_subject_identity:
            return RestoreOutcome(
                RestoreResult.REFUSED_SUBJECT_MISMATCH,
                f"measured subject {att.subject_identity!r} != requested "
                f"{att.requested_subject_identity!r} — measurement cannot re-bind a different subject",
            )

        # board blocker #3: persist the signed measurement DURABLY + immutably BEFORE re-attesting, so
        # the RE_ATTESTATION ref binds a stored, signed, re-verifiable attestation (not just a mutable
        # calibration_pass row). Idempotent by ref.
        ref = self._attestations.persist(att)
        # 4 + 5: oracle-currency + state + policy-head CAS, retried on head conflict.
        for _attempt in range(self._max_cas_retries + 1):
            current_head = self._oracle_head_for(att.set_id)
            if current_head is None:
                return RestoreOutcome(
                    RestoreResult.REFUSED_ORACLE_STALE,
                    f"cannot resolve live set_head for {att.set_id!r} — refusing (fail-closed)",
                )
            if current_head != att.oracle_head:
                return RestoreOutcome(
                    RestoreResult.REFUSED_ORACLE_STALE,
                    f"signed oracle_head {att.oracle_head[:12]}.. != live {current_head[:12]}.. — "
                    "the set drifted again; a newer re-calibration will restore",
                )
            if self._cap.current_state(att.policy_id) is not PolicyState.ENABLED:
                return RestoreOutcome(
                    RestoreResult.REFUSED_NOT_ENABLED,
                    f"{att.policy_id} is not ENABLED — a demoted policy must re-ratify, never "
                    "auto-restore (tier asymmetry)",
                )
            # the requested subject MUST equal the policy's CURRENTLY AUTHORIZED target (v3, board P1):
            # a re-cal can only re-attest the SAME subject the policy is already enabled for, never rebind
            # it to a different one — even a globally-trusted measured subject. Measurement ≠ governance.
            authorized = self._cap.authorized_subject_identity(att.policy_id)
            if authorized is None or att.requested_subject_identity != authorized:
                return RestoreOutcome(
                    RestoreResult.REFUSED_SUBJECT_MISMATCH,
                    f"requested subject {att.requested_subject_identity!r} != the policy's authorized "
                    f"target {authorized!r} — restore cannot rebind the policy's subject",
                )
            policy_head = self._cap.policy_head(att.policy_id)
            # persist the pass the re-attest binds to (idempotent; ref binds the immutable signed att).
            # the policy store's generic ``detector_identity`` field carries the calibrated-subject
            # identity value (P1-3) — the identity the future enforcement match compares.
            self._cap.record_calibration_pass(
                ref, policy_id=att.policy_id, pinned_set_version=att.oracle_head,
                detector_identity=att.subject_identity, set_id=att.set_id)
            try:
                seq = self._cap.reattest(
                    att.policy_id, calibration_result_ref=ref, pinned_set_version=att.oracle_head,
                    detector_identity=att.subject_identity, job_id=att.run_id, nonce=att.nonce,
                    expect_policy_head=policy_head,
                    # v4 P1-b: bind the authorized-subject check ATOMICALLY with the head CAS. If governance
                    # moved the authorized target since we read it, reattest raises ReAttestConflict -> the
                    # loop re-reads authorized above and refuses (REFUSED_SUBJECT_MISMATCH) on the retry.
                    expect_authorized_subject=authorized)
            except ReAttestConflict:
                continue  # the policy head moved; re-read and retry the whole CAS
            return RestoreOutcome(RestoreResult.RESTORED, "re-attested to the current oracle head", seq)
        return RestoreOutcome(
            RestoreResult.REFUSED_CAS_EXHAUSTED,
            f"lost the policy-evidence-head CAS {self._max_cas_retries + 1} times — not forcing",
        )


__all__ = [
    "ReAttestCapability",
    "RestoreController",
    "RestoreResult",
    "RestoreOutcome",
]
