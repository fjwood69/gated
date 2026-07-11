"""gate/store.py — the durable gating store (2.3): queue + delivery-log + claim state.

ONE SQLite table keyed by ``delivery_id`` (PRIMARY KEY = idempotency + dedup) serves
three roles at once: the durable job QUEUE, the replay DELIVERY-LOG, and the
Claim-Process-Complete claim STATE. This collapses queue + dedup + claim without a
broker (Redis/Celery) — preserving the zero-dependency open core.

Concurrency model (consult-ratified for single-node SQLite):
  * WAL + ``synchronous=NORMAL``;
  * connection-per-thread (never shared across threads);
  * atomic claim under ``BEGIN IMMEDIATE`` so two workers never claim one delivery;
  * atomic finalize ``UPDATE ... WHERE status='processing'`` — the POST-ONCE guard:
    ``rowcount == 0`` means another worker/watchdog already finalized, so the caller
    must NOT post a second terminal Check Run update.

State: ``queued -> processing -> done | error``. ``enqueue`` commits BEFORE the 202,
so a crash between the ack and consumption cannot lose the delivery.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable

from .queue import GatingEvent, SinkFull

_SCHEMA = """
CREATE TABLE IF NOT EXISTS gating (
    delivery_id     TEXT PRIMARY KEY,
    repo_full_name  TEXT NOT NULL,
    head_sha        TEXT NOT NULL,
    installation_id INTEGER NOT NULL,
    action          TEXT NOT NULL,
    status          TEXT NOT NULL,          -- queued | processing | done | error
    check_run_id    TEXT,
    verdict         TEXT,
    reason          TEXT,
    head_repo_full_name TEXT,               -- C2: fork repo (fetch hint); NULL for same-repo
    enqueued_at     REAL NOT NULL,
    claimed_at      REAL,
    updated_at      REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_gating_status ON gating(status, enqueued_at);
-- C3 override-ledger lookup: verdict(s) for a merged SHA. Multiple deliveries can share a
-- SHA (opened+reopened), so this is NOT a key lookup — the index makes the scan efficient
-- and updated_at is the tie-breaker for "effective at merge".
CREATE INDEX IF NOT EXISTS idx_gating_head_sha ON gating(head_sha, updated_at);
"""


def _to_event(row: sqlite3.Row) -> GatingEvent:
    return GatingEvent(
        delivery_id=row["delivery_id"],
        repo_full_name=row["repo_full_name"],
        head_sha=row["head_sha"],
        action=row["action"],
        installation_id=row["installation_id"],
        head_repo_full_name=row["head_repo_full_name"],
    )


class GatingStore:
    """Durable, thread-safe (connection-per-thread) gating store."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self._path = str(path)
        self._clock = clock
        self._local = threading.local()
        # initialise schema + WAL on a bootstrap connection
        conn = self._conn()
        conn.executescript(_SCHEMA)
        # C2 migration: add head_repo_full_name to a pre-existing table (SQLite has no
        # ADD COLUMN IF NOT EXISTS; guard on the column set). Nullable — old rows read NULL.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(gating)")}
        if "head_repo_full_name" not in cols:
            conn.execute("ALTER TABLE gating ADD COLUMN head_repo_full_name TEXT")
        conn.commit()

    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            # timeout=5.0: the Python-level busy handler; busy_timeout is the C-level
            # one — both let a locked writer back off + retry rather than crash a worker
            # with "database is locked" under concurrent claim/finalize/sweep.
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    # ---- producer side (the durable GatingSink backing) ------------------

    def enqueue(self, event: GatingEvent) -> bool:
        """Durable, STATE-AWARE upsert keyed by delivery_id. Returns True if the
        delivery is now queued (freshly inserted OR re-queued from a prior 'error'),
        False if ignored.

        A plain INSERT OR IGNORE would WEDGE a recoverable job: if a delivery errors
        (worker crash / watchdog force) and is later RE-DELIVERED (manual re-deliver, or
        a transient-failure retry), IGNORE drops it and the PR stays errored forever.
        So: a delivery in 'error' is re-queued; one already 'done'/'processing'/'queued'
        is an idempotent no-op (never re-run a live or completed job)."""
        now = self._clock()
        cur = self._conn().execute(
            "INSERT INTO gating "
            "(delivery_id, repo_full_name, head_sha, installation_id, action, status,"
            " head_repo_full_name, enqueued_at, updated_at) VALUES (?,?,?,?,?, 'queued', ?, ?, ?) "
            "ON CONFLICT(delivery_id) DO UPDATE SET "
            "  status='queued', enqueued_at=excluded.enqueued_at,"
            "  updated_at=excluded.updated_at, claimed_at=NULL,"
            "  check_run_id=NULL, verdict=NULL, reason=NULL "
            "WHERE gating.status='error'",
            (
                event.delivery_id,
                event.repo_full_name,
                event.head_sha,
                event.installation_id,
                event.action,
                event.head_repo_full_name,
                now,
                now,
            ),
        )
        return cur.rowcount == 1

    def queued_count(self) -> int:
        row = self._conn().execute(
            "SELECT COUNT(*) AS n FROM gating WHERE status IN ('queued','processing')"
        ).fetchone()
        return int(row["n"])

    # ---- consumer side (Claim-Process-Complete) --------------------------

    def claim_next(self) -> GatingEvent | None:
        """Atomically claim the oldest queued delivery (queued -> processing) under a
        write lock, so concurrent workers never claim the same one. None if empty."""
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            # Board 2.2 #1 — close the upsert race at the source: never claim a delivery
            # whose (repo, head_sha) is ALREADY processing. Two distinct deliveries for
            # one SHA (e.g. opened + reopened) then serialise, and the second re-uses the
            # first's Check Run via the idempotent upsert — no duplicate, independent of
            # worker count (stronger than relying on the concurrency semaphore alone).
            row = conn.execute(
                "SELECT * FROM gating q WHERE q.status='queued' AND NOT EXISTS ("
                "  SELECT 1 FROM gating p WHERE p.status='processing'"
                "    AND p.repo_full_name=q.repo_full_name AND p.head_sha=q.head_sha"
                ") ORDER BY q.enqueued_at LIMIT 1"
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            now = self._clock()
            cur = conn.execute(
                "UPDATE gating SET status='processing', claimed_at=?, updated_at=? "
                "WHERE delivery_id=? AND status='queued'",
                (now, now, row["delivery_id"]),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return _to_event(row) if cur.rowcount == 1 else None

    def finalize(
        self,
        delivery_id: str,
        status: str,
        *,
        check_run_id: str | None = None,
        verdict: str | None = None,
        reason: str | None = None,
    ) -> bool:
        """POST-ONCE guard: move processing -> terminal, but ONLY if still processing.
        Returns True iff this caller won the finalize (and may therefore post the one
        terminal Check Run update); False means another worker/watchdog already did."""
        if status not in ("done", "error"):
            raise ValueError(f"terminal status must be done|error, got {status!r}")
        cur = self._conn().execute(
            "UPDATE gating SET status=?, check_run_id=?, verdict=?, reason=?, updated_at=? "
            "WHERE delivery_id=? AND status='processing'",
            (status, check_run_id, verdict, reason, self._clock(), delivery_id),
        )
        return cur.rowcount == 1

    def sweep_stale(self, older_than_seconds: float) -> list[GatingEvent]:
        """Deliveries stuck in 'processing' past the deadline — the watchdog's input."""
        cutoff = self._clock() - older_than_seconds
        rows = self._conn().execute(
            "SELECT * FROM gating WHERE status='processing' AND claimed_at < ?",
            (cutoff,),
        ).fetchall()
        return [_to_event(r) for r in rows]

    def status_of(self, delivery_id: str) -> str | None:
        row = self._conn().execute(
            "SELECT status FROM gating WHERE delivery_id=?", (delivery_id,)
        ).fetchone()
        return None if row is None else str(row["status"])

    def verdicts_for_sha(self, head_sha: str) -> list[tuple[str, str | None, str | None, float]]:
        """C3 read-only: ALL gating rows for a SHA as ``(status, verdict, reason,
        updated_at)`` — the raw input to the override-ledger classifier. NOT a single-row
        lookup: multiple deliveries (opened+reopened) can share a SHA, and a stale ``done``
        can coexist with a newer ``processing`` — the classifier resolves precedence. This
        read NEVER triggers a check-run; it only inspects recorded state (NFR6)."""
        rows = self._conn().execute(
            "SELECT status, verdict, reason, updated_at FROM gating WHERE head_sha=?",
            (head_sha,),
        ).fetchall()
        return [(r["status"], r["verdict"], r["reason"], float(r["updated_at"])) for r in rows]


class StoreBackedGatingSink:
    """The production ``GatingSink``: a durable enqueue with depth-based backpressure.
    When the backlog hits ``max_depth`` the executor is saturated -> raise ``SinkFull``
    so the 2.1 receiver returns 503 and GitHub re-delivers (backpressure judo)."""

    def __init__(self, store: GatingStore, *, max_depth: int) -> None:
        self._store = store
        self._max_depth = max_depth

    def enqueue(self, event: GatingEvent) -> None:
        if self._store.queued_count() >= self._max_depth:
            raise SinkFull(f"gating backlog at capacity ({self._max_depth})")
        self._store.enqueue(event)  # durable; dup delivery-id is an idempotent no-op
