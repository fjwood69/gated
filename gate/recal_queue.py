"""gate/recal_queue.py — 3.5 job-1: the durable, lease-backed re-calibration queue.

The PROACTIVE trigger's async home (board): a fixture append enqueues a re-calibration and the merge
path NEVER waits — the policy is already blocking (transiently UNATTESTABLE via the oracle-head drift),
and a fresh PASS later RESTORES it. Reactive (first-blocked-PR triggers) is banned — it would couple a
victim PR to calibration latency and pressure a fast-tracked false PASS.

Durability + at-least-once (the operational amendment):
  * DURABLE (SQLite) so a crash never loses a trigger.
  * DEDUP by the deterministic ``job_id`` = (policy, set, oracle_head, detector) — the same measurement
    is never run twice; a NEW drift (new head) is a new job.
  * VISIBILITY-TIMEOUT LEASE — ``lease`` claims a job (status=processing, locked_until=now+timeout,
    attempts+=1); a worker that dies mid-run simply lets the lease expire.
  * WATCHDOG — expired leases are re-queued; after ``max_attempts`` a job is DEAD-LETTERED (a hard
    block + a critical-alert surface), never silently dropped.
  * SLA — a job pending/processing past its SLA is surfaced (the caller posts the "re-calibration SLA
    exceeded — manual review required" PR comment) so a wedged queue is never a silent multi-hour block.

Lease tokens + timestamps are INPUTS (injected), so the queue is deterministic + unit-testable without
a clock or RNG. Gate-side; ``core`` never imports this; no engine import (pure orchestration state)."""
from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable


class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    DONE = "done"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True)
class RecalJob:
    """A re-calibration work item — everything the runner + restore controller need, plus lease/retry
    bookkeeping. ``tier_generation`` is what the TRIGGER observed; the restore CAS rechecks currency."""

    job_id: str
    policy_id: str
    set_id: str
    oracle_head: str
    detector_identity: str
    tier_generation: str
    status: JobStatus
    attempts: int
    enqueued_at: float
    lease_token: str | None = None
    locked_until: float | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS recal_queue (
    job_id            TEXT PRIMARY KEY,          -- deterministic dedup key
    policy_id         TEXT NOT NULL,
    set_id            TEXT NOT NULL,
    oracle_head       TEXT NOT NULL,
    detector_identity TEXT NOT NULL,
    tier_generation   TEXT NOT NULL,
    status            TEXT NOT NULL,
    attempts          INTEGER NOT NULL DEFAULT 0,
    lease_token       TEXT,
    locked_until      REAL,
    enqueued_at       REAL NOT NULL,
    updated_at        REAL NOT NULL
);
"""


def _row_to_job(row: sqlite3.Row) -> RecalJob:
    return RecalJob(
        job_id=row["job_id"], policy_id=row["policy_id"], set_id=row["set_id"],
        oracle_head=row["oracle_head"], detector_identity=row["detector_identity"],
        tier_generation=row["tier_generation"], status=JobStatus(row["status"]),
        attempts=int(row["attempts"]), enqueued_at=float(row["enqueued_at"]),
        lease_token=row["lease_token"], locked_until=row["locked_until"],
    )


class RecalQueue:
    """Durable lease queue. Connection-per-thread; state mutations serialised with an IMMEDIATE
    transaction so a lease claim is atomic across workers."""

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

    def enqueue(
        self, *, job_id: str, policy_id: str, set_id: str, oracle_head: str,
        detector_identity: str, tier_generation: str, now: float | None = None,
    ) -> bool:
        """Enqueue a re-calibration (idempotent by ``job_id`` — the same measurement never runs twice;
        a job already present, incl. one dead-lettered, is left as-is). Returns True if a new row was
        inserted, False if it was a duplicate."""
        ts = self._clock() if now is None else now
        with self._lock:
            cur = self._conn().execute(
                "INSERT OR IGNORE INTO recal_queue (job_id, policy_id, set_id, oracle_head,"
                " detector_identity, tier_generation, status, attempts, enqueued_at, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (job_id, policy_id, set_id, oracle_head, detector_identity, tier_generation,
                 JobStatus.PENDING.value, 0, ts, ts),
            )
            return bool(cur.rowcount)

    def lease(self, *, lease_token: str, visibility_timeout: float, now: float | None = None) -> RecalJob | None:
        """Atomically claim one runnable job (PENDING, or PROCESSING whose lease expired) — oldest
        first. Sets it PROCESSING, stamps ``lease_token`` + ``locked_until = now + visibility_timeout``,
        bumps ``attempts``. Returns the leased job, or None if nothing is runnable."""
        ts = self._clock() if now is None else now
        with self._lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT * FROM recal_queue WHERE status=? OR (status=? AND locked_until < ?)"
                    " ORDER BY enqueued_at ASC LIMIT 1",
                    (JobStatus.PENDING.value, JobStatus.PROCESSING.value, ts),
                ).fetchone()
                if row is None:
                    conn.execute("COMMIT")
                    return None
                conn.execute(
                    "UPDATE recal_queue SET status=?, attempts=attempts+1, lease_token=?,"
                    " locked_until=?, updated_at=? WHERE job_id=?",
                    (JobStatus.PROCESSING.value, lease_token, ts + visibility_timeout, ts,
                     row["job_id"]),
                )
                leased = conn.execute("SELECT * FROM recal_queue WHERE job_id=?",
                                      (row["job_id"],)).fetchone()
                conn.execute("COMMIT")
                return _row_to_job(leased)
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def complete(self, job_id: str, *, lease_token: str, now: float | None = None) -> bool:
        """Mark a leased job DONE — only if ``lease_token`` still holds the lease (a stale worker whose
        lease expired and was re-leased cannot complete it). Returns True if it was completed."""
        ts = self._clock() if now is None else now
        with self._lock:
            cur = self._conn().execute(
                "UPDATE recal_queue SET status=?, lease_token=NULL, locked_until=NULL, updated_at=?"
                " WHERE job_id=? AND lease_token=? AND status=?",
                (JobStatus.DONE.value, ts, job_id, lease_token, JobStatus.PROCESSING.value),
            )
            return bool(cur.rowcount)

    def watchdog(self, *, max_attempts: int, now: float | None = None) -> list[RecalJob]:
        """Re-queue expired leases; DEAD-LETTER any that have burned ``max_attempts``. Returns the jobs
        newly moved to DEAD_LETTER (the caller raises a critical alert + hard block for each). A
        dead-lettered job is NEVER auto-retried — it needs human intervention."""
        ts = self._clock() if now is None else now
        with self._lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                expired = conn.execute(
                    "SELECT * FROM recal_queue WHERE status=? AND locked_until < ?",
                    (JobStatus.PROCESSING.value, ts),
                ).fetchall()
                dead: list[RecalJob] = []
                for row in expired:
                    if int(row["attempts"]) >= max_attempts:
                        conn.execute(
                            "UPDATE recal_queue SET status=?, lease_token=NULL, locked_until=NULL,"
                            " updated_at=? WHERE job_id=?",
                            (JobStatus.DEAD_LETTER.value, ts, row["job_id"]),
                        )
                        dead.append(_row_to_job(conn.execute(
                            "SELECT * FROM recal_queue WHERE job_id=?", (row["job_id"],)).fetchone()))
                    else:
                        conn.execute(
                            "UPDATE recal_queue SET status=?, lease_token=NULL, locked_until=NULL,"
                            " updated_at=? WHERE job_id=?",
                            (JobStatus.PENDING.value, ts, row["job_id"]),
                        )
                conn.execute("COMMIT")
                return dead
            except Exception:
                conn.execute("ROLLBACK")
                raise

    def sla_breaches(self, *, sla_seconds: float, now: float | None = None) -> list[RecalJob]:
        """Jobs still unresolved (PENDING/PROCESSING) whose age exceeds the SLA — the caller posts the
        're-calibration SLA exceeded — manual review required' PR comment. Never a silent wedge."""
        ts = self._clock() if now is None else now
        rows = self._conn().execute(
            "SELECT * FROM recal_queue WHERE status IN (?,?) AND enqueued_at + ? < ?"
            " ORDER BY enqueued_at ASC",
            (JobStatus.PENDING.value, JobStatus.PROCESSING.value, sla_seconds, ts),
        ).fetchall()
        return [_row_to_job(r) for r in rows]

    def get(self, job_id: str) -> RecalJob | None:
        row = self._conn().execute("SELECT * FROM recal_queue WHERE job_id=?", (job_id,)).fetchone()
        return _row_to_job(row) if row is not None else None

    def jobs_with_status(self, status: JobStatus) -> list[RecalJob]:
        """All jobs in a given status (oldest first) — the durable operational status of record the
        zombie metric reads."""
        rows = self._conn().execute(
            "SELECT * FROM recal_queue WHERE status=? ORDER BY enqueued_at ASC", (status.value,)
        ).fetchall()
        return [_row_to_job(r) for r in rows]

    def counts(self) -> dict[str, int]:
        rows = self._conn().execute(
            "SELECT status, COUNT(*) AS n FROM recal_queue GROUP BY status").fetchall()
        return {r["status"]: int(r["n"]) for r in rows}


__all__ = ["JobStatus", "RecalJob", "RecalQueue"]
