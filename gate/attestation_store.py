"""gate/attestation_store.py — 3.5 job-1 (board blocker #3): durable, append-only signed-measurement log.

Board amendment 2 required the re-attestation to bind an IMMUTABLE, SIGNED attestation — not merely a
mutable ``calibration_pass`` row. The restore controller persists each verified signed measurement here
(keyed by its content-derived ``attestation_ref``) before it re-attests, so the ref a RE_ATTESTATION
record carries provably resolves to a durably-stored, signed, immutable measurement whose MAC can be
re-checked at audit time. The ``calibration_pass`` row is then just a lookup index; this store is the
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
from gate.attestation import MeasurementAttestation, attestation_ref

_SCHEMA = """
CREATE TABLE IF NOT EXISTS measurement_attestation (
    ref          TEXT PRIMARY KEY,   -- attestation_ref (content digest of the signed payload)
    payload_json TEXT NOT NULL,      -- the canonical signed payload
    mac          TEXT NOT NULL,      -- the HMAC over that payload
    persisted_at REAL NOT NULL
);
"""


def _reconstruct(payload: dict[str, object], mac: str) -> MeasurementAttestation:
    return MeasurementAttestation(
        outcome=VerdictType(payload["outcome"]), policy_id=str(payload["policy_id"]),
        detector_identity=str(payload["detector_identity"]), set_id=str(payload["set_id"]),
        oracle_head=str(payload["oracle_head"]), coverage_digest=str(payload["coverage_digest"]),
        tier_generation=str(payload["tier_generation"]), issuer=str(payload["issuer"]),
        run_id=str(payload["run_id"]), nonce=str(payload["nonce"]),
        issued_at=float(payload["issued_at"]),  # type: ignore[arg-type]
        fixture_coverage=tuple(payload["fixture_coverage"]),  # type: ignore[arg-type]
        short_circuit=bool(payload["short_circuit"]),
        fn_failures=tuple(payload["fn_failures"]),  # type: ignore[arg-type]
        fp_failures=tuple(payload["fp_failures"]),  # type: ignore[arg-type]
        flaky=tuple(payload["flaky"]),  # type: ignore[arg-type]
        harness_errors=tuple(payload["harness_errors"]),  # type: ignore[arg-type]
        mac=mac,
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
        """Store the signed attestation (idempotent by ref) and return its ref. Immutable — there is
        no update/delete path."""
        ref = attestation_ref(attestation)
        with self._lock:
            self._conn().execute(
                "INSERT OR IGNORE INTO measurement_attestation (ref, payload_json, mac, persisted_at)"
                " VALUES (?,?,?,?)",
                (ref, json.dumps(attestation._payload(), sort_keys=True, separators=(",", ":")),
                 attestation.mac, self._clock()),
            )
        return ref

    def exists(self, ref: str) -> bool:
        return self._conn().execute(
            "SELECT 1 FROM measurement_attestation WHERE ref=? LIMIT 1", (ref,)
        ).fetchone() is not None

    def get(self, ref: str) -> MeasurementAttestation | None:
        row = self._conn().execute(
            "SELECT payload_json, mac FROM measurement_attestation WHERE ref=?", (ref,)
        ).fetchone()
        if row is None:
            return None
        return _reconstruct(json.loads(row["payload_json"]), row["mac"])

    def count(self) -> int:
        return int(self._conn().execute(
            "SELECT COUNT(*) AS n FROM measurement_attestation").fetchone()["n"])


__all__ = ["MeasurementAttestationStore"]
