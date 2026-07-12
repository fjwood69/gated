"""gate/attestation_store.py — 3.5 job-1 (board blocker #3): durable, append-only signed-measurement log.

Board amendment 2 required the re-attestation to bind an IMMUTABLE, SIGNED attestation — not merely a
mutable ``calibration_pass`` row. The restore controller persists each verified signed measurement here
(keyed by its content-derived ``attestation_ref``) before it re-attests, so the ref a RE_ATTESTATION
record carries provably resolves to a durably-stored, signed, immutable measurement whose Ed25519
signature can be re-checked at audit time. The ``calibration_pass`` row is then just a lookup index; this store is the
source of truth. Append-only, idempotent by ref — a re-persist of the same signed attestation is a no-op.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from core import VerdictType
from gate.attestation import (
    MEASUREMENT_ATTESTATION_SCHEMA,
    AttestationError,
    MeasurementAttestation,
    attestation_ref,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS measurement_attestation (
    ref          TEXT PRIMARY KEY,   -- attestation_ref (content digest of the signed v2 envelope)
    payload_json TEXT NOT NULL,      -- the canonical signed v2 envelope
    signature    TEXT NOT NULL,      -- the Ed25519 signature over that envelope
    persisted_at REAL NOT NULL
);
"""


def _strict_int(v: object) -> int:
    """v4 P2: an int field must be an actual ``int`` — not a ``bool`` (int subclass), string, or float."""
    if type(v) is not int:
        raise AttestationError(f"stored integer field must be an int, got {type(v).__name__}")
    return v


def _reconstruct(payload: dict[str, object], signature: str) -> MeasurementAttestation:
    """Rebuild a v2 ``MeasurementAttestation`` from a stored envelope. HARD-REJECTS a non-v2 schema (an
    earlier record cannot be reconstructed as authoritative). ``issued_at`` is recovered from the signed
    ``issued_at_ms`` (the envelope is float-free); the three P1-3 identity coordinates may be null (an
    unattestable ERROR)."""
    schema = str(payload.get("schema", ""))
    if schema != MEASUREMENT_ATTESTATION_SCHEMA:
        raise AttestationError(
            f"stored attestation has unsupported schema {schema!r} — only "
            f"{MEASUREMENT_ATTESTATION_SCHEMA!r} is reconstructable")

    def _opt(key: str) -> str | None:
        v = payload.get(key)
        if v is None:
            return None
        if not isinstance(v, str):  # v4 P2: strict — no coercion of alternate reprs into a str
            raise AttestationError(f"stored {key!r} must be a string or null, got {type(v).__name__}")
        return v

    return MeasurementAttestation(
        outcome=VerdictType(payload["outcome"]), policy_id=str(payload["policy_id"]),
        subject_identity=_opt("subject_identity"),
        requested_subject_identity=str(payload["requested_subject_identity"]),
        resolved_profile_digest=_opt("resolved_profile_digest"),
        execution_identity_digest=_opt("execution_identity_digest"),
        set_id=str(payload["set_id"]),
        oracle_head=str(payload["oracle_head"]), coverage_digest=str(payload["coverage_digest"]),
        tier_generation=str(payload["tier_generation"]), issuer=str(payload["issuer"]),
        run_id=str(payload["run_id"]), nonce=str(payload["nonce"]),
        issued_at_ms=_strict_int(payload["issued_at_ms"]),
        fixture_coverage=tuple(payload["fixture_coverage"]),  # type: ignore[arg-type]
        short_circuit=bool(payload["short_circuit"]),
        fn_failures=tuple(payload["fn_failures"]),  # type: ignore[arg-type]
        fp_failures=tuple(payload["fp_failures"]),  # type: ignore[arg-type]
        flaky=tuple(payload["flaky"]),  # type: ignore[arg-type]
        harness_errors=tuple(payload["harness_errors"]),  # type: ignore[arg-type]
        schema=schema, signature=signature,
    )


class MeasurementAttestationStore:
    """Durable append-only store of signed measurements. Connection-per-thread; idempotent by ref."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self._path = str(path)
        self._clock = clock
        self._local = threading.local()
        self._lock = threading.Lock()
        conn = self._conn()
        conn.executescript(_SCHEMA)
        conn.commit()

    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def persist(self, attestation: MeasurementAttestation) -> str:
        """Store the signed attestation (idempotent by ref) and return its ref. Immutable — no
        update/delete path. v3 (board P2): the ref BINDS the content — a pre-existing row under the same
        ref whose bytes DIFFER is a collision/tamper and is rejected, never silently ignored."""
        ref = attestation_ref(attestation)
        payload_json = json.dumps(attestation._envelope(), sort_keys=True, separators=(",", ":"))
        with self._lock:
            existing = self._conn().execute(
                "SELECT payload_json, signature FROM measurement_attestation WHERE ref=?", (ref,)
            ).fetchone()
            if existing is not None:
                if existing["payload_json"] != payload_json or existing["signature"] != attestation.signature:
                    raise AttestationError(
                        f"attestation ref {ref} already stored with DIFFERENT bytes — a content/ref "
                        "collision or tamper; refusing to store")
                return ref  # identical bytes -> idempotent no-op
            self._conn().execute(
                "INSERT INTO measurement_attestation (ref, payload_json, signature, persisted_at)"
                " VALUES (?,?,?,?)",
                (ref, payload_json, attestation.signature, self._clock()),
            )
        return ref

    def exists(self, ref: str) -> bool:
        return self._conn().execute(
            "SELECT 1 FROM measurement_attestation WHERE ref=? LIMIT 1", (ref,)
        ).fetchone() is not None

    def get(self, ref: str) -> MeasurementAttestation | None:
        row = self._conn().execute(
            "SELECT payload_json, signature FROM measurement_attestation WHERE ref=?", (ref,)
        ).fetchone()
        if row is None:
            return None
        att = _reconstruct(json.loads(row["payload_json"]), row["signature"])
        # v3 (board P2): bind the lookup key to the content — the reconstructed attestation's ref MUST
        # recompute to the requested ref, else the stored bytes do not match the key (corruption/tamper).
        if attestation_ref(att) != ref:
            raise AttestationError(
                f"stored attestation under ref {ref} recomputes to a DIFFERENT ref — corrupt or tampered")
        # v4 (board P2): the stored bytes MUST BE the canonical serialization — reconstruct then
        # re-serialize canonically and compare to the raw stored JSON. Catches duplicate keys, alternate
        # boolean/number representations, and whitespace that a lax loader would silently accept.
        if json.dumps(att._envelope(), sort_keys=True, separators=(",", ":")) != row["payload_json"]:
            raise AttestationError(
                f"stored attestation under ref {ref} is not in canonical form — corrupt or tampered")
        return att

    def count(self) -> int:
        return int(self._conn().execute(
            "SELECT COUNT(*) AS n FROM measurement_attestation").fetchone()["n"])


__all__ = ["MeasurementAttestationStore"]
