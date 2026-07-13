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
    IDENTITY_CONTRACT_VERSION,
    MEASUREMENT_ATTESTATION_SCHEMA,
    AttestationError,
    MeasurementAttestation,
    MeasurementSchemaError,
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
    """Rebuild a v3 ``MeasurementAttestation`` from a stored envelope. The version GUARD fires FIRST
    (schema, then identity_contract_version) — an old/unknown record is REFUSED before any field is
    interpreted (fail-closed migration boundary; no defaulting of a missing identity coordinate). The four
    ``runtime_subject`` coordinates are read from the nested block and may be null (an unattestable ERROR);
    ``issued_at`` is recovered from the signed ``issued_at_ms`` (the envelope is float-free)."""
    schema = str(payload.get("schema", ""))
    if schema != MEASUREMENT_ATTESTATION_SCHEMA:
        raise AttestationError(
            f"stored attestation has unsupported schema {schema!r} — only "
            f"{MEASUREMENT_ATTESTATION_SCHEMA!r} is reconstructable")
    icv = payload.get("identity_contract_version")
    if type(icv) is not int or icv != IDENTITY_CONTRACT_VERSION:
        raise AttestationError(
            f"stored attestation has unsupported identity_contract_version {icv!r} — only "
            f"{IDENTITY_CONTRACT_VERSION!r} is reconstructable")
    subject = payload.get("runtime_subject")
    context = payload.get("calibration_context")
    if not isinstance(subject, dict) or not isinstance(context, dict):
        raise AttestationError("stored attestation missing its runtime_subject / calibration_context block")

    def _opt(src: dict[str, object], key: str) -> str | None:
        v = src.get(key)
        if v is None:
            return None
        if type(v) is not str:  # strict — no coercion of alternate reprs into a str
            raise AttestationError(f"stored {key!r} must be a string or null, got {type(v).__name__}")
        return v

    def _req(src: dict[str, object], key: str) -> str:
        v = src.get(key)
        if type(v) is not str:  # PRESERVE the exact wire value or REJECT — never str()-coerce
            raise AttestationError(f"stored {key!r} must be a str, got {type(v).__name__}")
        return v

    def _req_tuple(key: str) -> tuple[str, ...]:
        v = payload.get(key)
        if not isinstance(v, list) or not all(type(x) is str for x in v):
            raise AttestationError(f"stored {key!r} must be a list of str")
        return tuple(v)

    sc = payload.get("short_circuit")
    if type(sc) is not bool:
        raise AttestationError(f"stored 'short_circuit' must be a bool, got {type(sc).__name__}")
    try:
        outcome = VerdictType(payload["outcome"])
    except (ValueError, KeyError) as exc:
        raise AttestationError(f"stored 'outcome' is not a valid verdict: {exc}") from None

    return MeasurementAttestation(
        outcome=outcome, policy_id=_req(payload, "policy_id"),
        subject_identity=_opt(payload, "subject_identity"),
        requested_subject_identity=_req(payload, "requested_subject_identity"),
        resolved_profile_digest=_opt(subject, "resolved_profile_digest"),
        trust_policy_digest=_opt(subject, "trust_policy_digest"),
        guard_policy_digest=_opt(subject, "guard_policy_digest"),
        execution_identity_digest=_opt(subject, "execution_identity_digest"),
        set_id=_req(context, "set_id"),
        oracle_head=_req(context, "oracle_head"), coverage_digest=_req(context, "coverage_digest"),
        tier_generation=_req(context, "tier_generation"), issuer=_req(payload, "issuer"),
        run_id=_req(payload, "run_id"), nonce=_req(payload, "nonce"),
        issued_at_ms=_strict_int(payload["issued_at_ms"]),
        fixture_coverage=_req_tuple("fixture_coverage"),
        short_circuit=sc,
        fn_failures=_req_tuple("fn_failures"),
        fp_failures=_req_tuple("fp_failures"),
        flaky=_req_tuple("flaky"),
        harness_errors=_req_tuple("harness_errors"),
        identity_contract_version=icv,
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
        try:
            parsed = json.loads(row["payload_json"])
        except ValueError as exc:  # malformed stored JSON is a schema-layer failure, not an unhandled crash
            raise MeasurementSchemaError(
                f"stored attestation under ref {ref} is not valid JSON: {exc}") from None
        if not isinstance(parsed, dict):
            raise MeasurementSchemaError(f"stored attestation under ref {ref} is not a JSON object")
        att = _reconstruct(parsed, row["signature"])
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
