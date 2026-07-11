"""gate/snapshot.py — 3.3: the survivable, signed calibration snapshot (identity-bound).

The refinement the design consult added: a naive block-every-merge-when-the-store-blips is itself a
merge-DoS via infra hiccup. The fix is a locally-cached, SIGNED, time-bounded attestation of the
last known-good ENABLED policies, consulted ONLY when the tier store is unreachable.

Addition #1 (board): the snapshot binds each enabled policy to its full ATTESTATION TUPLE, not a
bare state string — detector identity, calibration-result ref, fixture-set version, tier-chain head,
backend, plus issue/expiry. Why it matters: if the store blips AND the detector has since changed,
enforcing a stale "enabled" would enforce an UN-CALIBRATED detector. The consumer compares the
snapshot's detector_identity to the one about to run; a MISMATCH blocks (fail-closed) rather than
stale-enforce. Only ENABLED policies appear — a policy absent from a valid snapshot is not enabled.

Trust-surface (board-pinned):
  * Q1 signing — HMAC-SHA256 with a key held by the GATE-GOVERNANCE side (loaded like the App
    private key; out-of-band by deployment, on the P1 live-confirm list). This is INTEGRITY against
    artifact / runtime-token writes under the trusted-gate threat model — NOT cryptographic
    separation from the gate PROCESS itself (a compromised gate can re-sign; that is out of scope,
    same as every other in-process authority boundary here). Out-of-band-ness is inherited: the
    artifact runs HERMETIC (no gate-host FS reach) and the runtime token is checks:write (no FS
    write) — neither can touch the snapshot or the key.
  * Q2 horizon — ``valid_for_seconds`` (default 300s): max tolerable store-outage before fail-closed.
  * Q3 immediate invalidation — the snapshot is a FALLBACK used only when the store is unreachable;
    on the normal path live state wins, so governance changes are effective at once. On a WEAKENING
    transition the caller MUST invalidate/replace the fallback BEFORE committing (single-instance
    slice; multi-replica revocation deferred, horizon bounds residual staleness).
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Mapping


# Hard upper bound on the freshness horizon (completeness prompt 5: a control must survive
# misconfiguration). Without a cap, an operator setting ``valid_for_seconds`` absurdly high would
# defeat fail-closed-on-outage — a stale snapshot could enforce a revoked calibration for days. The
# cap makes the fail-closed-on-prolonged-outage property misconfiguration-proof. 3600s (1h) matches
# the board's strawman; the board may retune the constant, but the CAP itself is non-negotiable.
MAX_VALID_FOR_SECONDS = 3600.0


class SnapshotError(RuntimeError):
    """The snapshot could not be trusted — missing, HMAC-invalid, past its freshness horizon, or
    minted with an out-of-bounds horizon. The gatekeeper maps this to a blocking decision
    (fail-closed): an un-verifiable cache is no better than an unreachable store."""


@dataclass(frozen=True)
class AttestationRecord:
    """One ENABLED policy's attestation tuple, as of the last known-good state. Identity-bearing:
    the consumer verifies ``detector_identity`` matches the detector about to enforce, AND (close-4)
    that the calibration SET is unchanged — ``oracle_head`` is the ``set_head(set_id)`` at mint, so
    the FALLBACK path detects a fixture-append drift (when the calibration store is still reachable)
    exactly as the live path does. Two freshness dimensions: outage (``valid_until``) + oracle
    (per-set ``oracle_head``)."""

    policy_id: str
    detector_identity: str
    calibration_result_ref: str
    fixture_set_version: str
    tier_chain_head: str
    backend: str
    set_id: str = "default"
    oracle_head: str = ""


@dataclass(frozen=True)
class CalibrationSnapshot:
    """A signed, time-bounded attestation of the currently-ENABLED policies. ``records`` maps
    policy_id -> AttestationRecord (ENABLED only). ``mac`` is HMAC-SHA256 over the canonical
    payload (everything except ``mac``)."""

    records: Mapping[str, AttestationRecord]
    issued_at: float
    valid_until: float
    mac: str

    def _payload(self) -> dict[str, object]:
        # Signed content — EXCLUDES ``mac``. Records rendered as sorted, fully-specified tuples so
        # the signed bytes are stable and cross-language reproducible (NFR6 discipline).
        rendered = {
            pid: {
                "policy_id": r.policy_id, "detector_identity": r.detector_identity,
                "calibration_result_ref": r.calibration_result_ref,
                "fixture_set_version": r.fixture_set_version,
                "tier_chain_head": r.tier_chain_head, "backend": r.backend,
                "set_id": r.set_id, "oracle_head": r.oracle_head,
            }
            for pid, r in sorted(self.records.items())
        }
        return {"records": rendered, "issued_at": self.issued_at, "valid_until": self.valid_until}


def _canonical(payload: Mapping[str, object]) -> str:
    import json

    return json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))


def _sign(payload: Mapping[str, object], key: bytes) -> str:
    """HMAC-SHA256 over the canonical payload bytes."""
    return hmac.new(key, _canonical(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def issue_snapshot(
    records: Mapping[str, AttestationRecord],
    *,
    key: bytes,
    now: float,
    valid_for_seconds: float = 300.0,
) -> CalibrationSnapshot:
    """Mint a signed snapshot of the currently-ENABLED policies. Called on the GOVERNANCE side —
    never by the runtime token. ``key`` is the out-of-band gate-governance secret."""
    if not key:
        raise SnapshotError("refusing to issue an unsigned snapshot — empty signing key")
    if not 0 < valid_for_seconds <= MAX_VALID_FOR_SECONDS:
        raise SnapshotError(
            f"freshness horizon {valid_for_seconds}s out of bounds (0, {MAX_VALID_FOR_SECONDS}] — "
            "a huge horizon would defeat fail-closed-on-outage"
        )
    valid_until = now + valid_for_seconds
    unsigned = CalibrationSnapshot(records=dict(records), issued_at=now, valid_until=valid_until, mac="")
    return CalibrationSnapshot(
        records=dict(records), issued_at=now, valid_until=valid_until,
        mac=_sign(unsigned._payload(), key),
    )


def verify_snapshot(snapshot: CalibrationSnapshot, *, key: bytes, now: float) -> None:
    """Raise ``SnapshotError`` unless the snapshot is HMAC-valid under ``key`` AND within its
    freshness horizon. Constant-time MAC compare. A tampered payload changes the canonical bytes ->
    MAC mismatch; a stale snapshot (now >= valid_until) is refused regardless of MAC validity."""
    if not key:
        raise SnapshotError("no signing key available to verify snapshot")
    if not hmac.compare_digest(_sign(snapshot._payload(), key), snapshot.mac):
        raise SnapshotError("snapshot HMAC mismatch — payload tampered or wrong key")
    if now >= snapshot.valid_until:
        raise SnapshotError(
            f"snapshot past freshness horizon (now={now} >= valid_until={snapshot.valid_until})"
        )


def to_json(snapshot: CalibrationSnapshot) -> str:
    """Serialise a snapshot for on-disk persistence (the refresh job writes this atomically)."""
    import json

    payload = snapshot._payload()
    payload["mac"] = snapshot.mac
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def from_json(data: str) -> CalibrationSnapshot:
    """Load a persisted snapshot. The MAC is re-verified by ``verify_snapshot`` at use — loading
    does not trust it."""
    import json

    obj = json.loads(data)
    records = {
        pid: AttestationRecord(
            policy_id=r["policy_id"], detector_identity=r["detector_identity"],
            calibration_result_ref=r["calibration_result_ref"],
            fixture_set_version=r["fixture_set_version"], tier_chain_head=r["tier_chain_head"],
            backend=r["backend"], set_id=r.get("set_id", "default"),
            oracle_head=r.get("oracle_head", ""),
        )
        for pid, r in obj["records"].items()
    }
    return CalibrationSnapshot(records=records, issued_at=obj["issued_at"],
                              valid_until=obj["valid_until"], mac=obj["mac"])


def attested_record(snapshot: CalibrationSnapshot, policy_id: str) -> AttestationRecord | None:
    """The attestation for a policy from an (already-verified) snapshot, or None if the policy is
    not ENABLED as of it. Caller MUST verify first, then compare ``detector_identity``."""
    return snapshot.records.get(policy_id)


__all__ = [
    "AttestationRecord",
    "CalibrationSnapshot",
    "SnapshotError",
    "issue_snapshot",
    "verify_snapshot",
    "attested_record",
    "to_json",
    "from_json",
]
