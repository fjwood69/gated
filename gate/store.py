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
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .queue import GatingEvent, SinkFull


class OutboxInvariantError(RuntimeError):
    """A gating row reached a terminal ``finalize`` WIN with no outbox RESET to bind its conclusion to —
    terminal-without-publication, the v1 defect. finalize RAISES rather than silently skipping the
    publication (which would leave the PR's required check permanently unpublished). A legacy row with no
    reset must be terminalized by the startup migration, never laundered through finalize."""


@dataclass(frozen=True)
class PublicationJob:
    """A claimed publication the Publisher must drive onto the ACTUATOR (the GitHub Check Run). The
    payload is COMPLETE (Increment A complete-binding): identity (repo/head_sha/check_name) + the phase
    (``status``: in_progress reset | completed conclusion) + the rendered conclusion/summary — the
    Publisher needs no live config and no typed JobResult."""

    delivery_id: str
    phase: str               # "reset" | "conclusion" — the durable outbox phase (identifies the row)
    repo_full_name: str
    head_sha: str
    check_name: str
    status: str              # "in_progress" (reset) | "completed" (conclusion)
    conclusion: str | None   # the CheckConclusion for a completed publication; None for a reset
    summary: str | None

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

-- Increment A (publication outbox): decouple DB-terminal from GitHub-publication. The ACTUATOR (the
-- Check Run) is the enforcement surface branch-protection reads; the Publisher drives it from this
-- durable outbox. Each (re)enqueue MINTS a fresh per-identity monotonic GENERATION (MAX(generation)+1
-- over the identity (repo, head_sha, check_name)) — NOT the gating rowid: an error-requeue keeps the
-- SAME rowid (ON CONFLICT UPDATE), so a rowid generation would leave a re-delivered delivery BELOW a
-- newer sibling forever (its reset never max-gen -> never publishes -> the delivery wedges in 'queued').
-- Two DISTINCT DURABLE ROWS per delivery keyed by (delivery_id, phase): a RESET (in_progress, armed at
-- enqueue, published BEFORE the job runs so a prior stale conclusion is cleared and the fail-closed
-- posture is pending-blocks) and a CONCLUSION (completed, armed at finalize). finalize NEVER touches the
-- reset row; repair re-arms the RESET; a generation's CONCLUSION may not publish while its RESET is
-- unpublished (phase ordering = part of the fence).
CREATE TABLE IF NOT EXISTS publication (
    id              INTEGER PRIMARY KEY,
    delivery_id     TEXT NOT NULL,
    generation      INTEGER NOT NULL,   -- per-identity monotonic; minted MAX(gen)+1 at each (re)enqueue
    repo_full_name  TEXT NOT NULL,
    head_sha        TEXT NOT NULL,
    check_name      TEXT NOT NULL,      -- persisted identity (complete-binding; never live config)
    phase           TEXT NOT NULL,      -- reset | conclusion
    status          TEXT NOT NULL,      -- in_progress (reset) | completed (conclusion)
    conclusion      TEXT,               -- the CheckConclusion for a conclusion; NULL for a reset
    summary         TEXT,
    state           TEXT NOT NULL,      -- pending | published | superseded
    attempts        INTEGER NOT NULL DEFAULT 0,
    lease_until     REAL,
    next_at         REAL,
    created_at      REAL NOT NULL,
    UNIQUE(delivery_id, phase)
);
CREATE INDEX IF NOT EXISTS idx_publication_identity
    ON publication(repo_full_name, head_sha, check_name, generation);
CREATE INDEX IF NOT EXISTS idx_publication_pending ON publication(state, next_at);
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

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time,
                 check_name: str = "gate") -> None:
        self._path = str(path)
        self._clock = clock
        # Increment A: the deployed check NAME is persisted into each delivery's publication payload at
        # enqueue (complete-binding — the Publisher never re-derives identity from live config). Defaults
        # for tests that do not exercise publication; live_app passes the configured name.
        self._check_name = check_name
        self._local = threading.local()
        # initialise schema + WAL on a bootstrap connection
        conn = self._conn()
        conn.executescript(_SCHEMA)
        # C2 migration: add head_repo_full_name to a pre-existing table (SQLite has no
        # ADD COLUMN IF NOT EXISTS; guard on the column set). Nullable — old rows read NULL.
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(gating)")}
        if "head_repo_full_name" not in cols:
            conn.execute("ALTER TABLE gating ADD COLUMN head_repo_full_name TEXT")
        # CP2 closure 1: the persisted GATE OUTCOME discriminator (independent of the verdict). Nullable +
        # idempotent — a historical row reads NULL and the classifier treats a done+no-verdict+no-gate row as
        # INDETERMINATE (never clean), so old rows stay classifiable without a backfill.
        if "gate_outcome" not in cols:
            conn.execute("ALTER TABLE gating ADD COLUMN gate_outcome TEXT")
        conn.commit()
        # Increment A dissent (blocker 2): the UPGRADE path is a producer of stranded state. Rows that
        # predate the publication outbox have NO reset row, so a queued legacy row is permanently
        # unclaimable (the reset-gate) and a processing legacy row would drive finalize's raising invariant.
        # Terminalize every legacy NONTERMINAL row (no outbox reset) explicitly, ONCE, at startup.
        self._migrate_legacy_nonterminal(conn)

    def _migrate_legacy_nonterminal(self, conn: sqlite3.Connection) -> None:
        """Terminalize legacy nonterminal gating rows that have NO outbox RESET (pre-Increment-A rows) as
        ``superseded`` with reason ``unmigratable_legacy``. Idempotent (a terminalized row no longer matches).
        A synthesized reset would need the check-name identity coordinate, which legacy rows never persisted;
        re-deriving it from live config would re-import the persisted-name defect the complete-binding fix
        closed — so these rows are HONESTLY abandoned (audit reason) rather than migrated on a guessed
        identity. A fresh Increment-A row is UNAFFECTED: enqueue arms its reset in the SAME atomic txn as the
        gating insert, so a legit nonterminal row ALWAYS has a reset and never matches this sweep."""
        conn.execute(
            "UPDATE gating SET status='superseded', reason='unmigratable_legacy', updated_at=? "
            "WHERE status IN ('queued','processing') AND NOT EXISTS "
            "(SELECT 1 FROM publication p WHERE p.delivery_id=gating.delivery_id AND p.phase='reset')",
            (self._clock(),),
        )
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
        conn = self._conn()
        # Increment A: enqueue + publication arming + supersession are ONE atomic BEGIN IMMEDIATE txn, so
        # the identity fence "a newer generation exists from the instant it is enqueued" is TRUE (not
        # usually-true): a crash cannot leave a new generation that superseded nothing, or a supersession
        # with no successor row.
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "INSERT INTO gating "
                "(delivery_id, repo_full_name, head_sha, installation_id, action, status,"
                " head_repo_full_name, enqueued_at, updated_at) VALUES (?,?,?,?,?, 'queued', ?, ?, ?) "
                "ON CONFLICT(delivery_id) DO UPDATE SET "
                "  status='queued', enqueued_at=excluded.enqueued_at,"
                "  updated_at=excluded.updated_at, claimed_at=NULL,"
                "  check_run_id=NULL, verdict=NULL, reason=NULL "
                "WHERE gating.status='error'",
                (event.delivery_id, event.repo_full_name, event.head_sha, event.installation_id,
                 event.action, event.head_repo_full_name, now, now),
            )
            requeued = cur.rowcount == 1
            if requeued:
                # MINT a fresh per-identity monotonic generation (NOT the gating rowid — a requeue keeps the
                # rowid, which would leave a re-delivered delivery below a newer sibling forever). MAX(gen)+1
                # over the identity means a re-delivery is the NEWEST generation (later event wins), so its
                # reset is max-gen and CAN publish. Computed from the EXISTING publication rows before the
                # reset upsert (which writes =gen, so the supersede `< gen` never hits this delivery's reset).
                gen = int(conn.execute(
                    "SELECT COALESCE(MAX(generation), 0) + 1 AS g FROM publication "
                    "WHERE repo_full_name=? AND head_sha=? AND check_name=?",
                    (event.repo_full_name, event.head_sha, self._check_name)).fetchone()["g"])
                # arm (or re-arm, on an error re-queue) THIS generation's RESET publication — a distinct
                # durable row; the CONCLUSION row (if any prior) is cleared and re-created only at finalize.
                conn.execute(
                    "INSERT INTO publication (delivery_id, generation, repo_full_name, head_sha,"
                    " check_name, phase, status, conclusion, summary, state, attempts, next_at, created_at)"
                    " VALUES (?,?,?,?,?, 'reset', 'in_progress', NULL, NULL, 'pending', 0, ?, ?) "
                    "ON CONFLICT(delivery_id, phase) DO UPDATE SET generation=excluded.generation,"
                    "  state='pending', status='in_progress', conclusion=NULL, summary=NULL, attempts=0,"
                    "  lease_until=NULL, next_at=excluded.next_at",
                    (event.delivery_id, gen, event.repo_full_name, event.head_sha, self._check_name,
                     now, now),
                )
                conn.execute(
                    "DELETE FROM publication WHERE delivery_id=? AND phase='conclusion'",
                    (event.delivery_id,))
                # supersede EVERY older-generation publication (any phase/state) for the identity — no
                # stale conclusion may drive the actuator; this generation's reset re-drives the surface.
                conn.execute(
                    "UPDATE publication SET state='superseded' "
                    "WHERE repo_full_name=? AND head_sha=? AND check_name=? AND generation<? "
                    "AND state IN ('pending','published')",
                    (event.repo_full_name, event.head_sha, self._check_name, gen),
                )
                # Dissent blocker 1 — RETIRE superseded-while-queued deliveries IN THE SAME TXN. A prior
                # delivery for this identity still in 'queued' (whether or not its reset ever published) can
                # NEVER be claimed once this newer generation superseded its reset (the reset-gate requires
                # state='published'), yet it would sit in 'queued' forever and count against capacity. Move it
                # to the 'superseded' TERMINAL with its own audit reason, so queued_count excludes it and a
                # reopen storm is VISIBLE in the record (not inferred from a capacity graph). Same atomic unit
                # as the supersession — a sweeper would leave a window where a concurrent claim_next races the
                # retirement. This delivery (the newest, event.delivery_id) is excluded. External surface: if a
                # retired predecessor's reset already published, THIS generation's reset republishes the same
                # identity at a newer generation (self-corrects by construction); if it never published, no
                # external surface exists to correct.
                conn.execute(
                    "UPDATE gating SET status='superseded', reason='superseded_while_queued', updated_at=? "
                    "WHERE repo_full_name=? AND head_sha=? AND status='queued' AND delivery_id!=?",
                    (now, event.repo_full_name, event.head_sha, event.delivery_id),
                )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return requeued

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
            # Increment A — the RESET GATE: a delivery is claimable ONLY once its RESET publication is
            # PUBLISHED (the actuator shows in_progress), so a prior stale conclusion is cleared BEFORE
            # this job runs and can produce a verdict. If the reset cannot publish (GitHub down), the
            # delivery waits in 'queued' — fail-closed (no premature verdict; the surface is not green).
            row = conn.execute(
                "SELECT * FROM gating q WHERE q.status='queued' "
                "  AND EXISTS (SELECT 1 FROM publication r WHERE r.delivery_id=q.delivery_id "
                "    AND r.phase='reset' AND r.state='published') AND NOT EXISTS ("
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
        gate_outcome: str | None = None,
        publish_conclusion: str | None = None,
        publish_summary: str | None = None,
    ) -> bool:
        """POST-ONCE guard: move processing -> terminal, but ONLY if still processing.
        Returns True iff this caller won the finalize (and may therefore arm the terminal publication);
        False means another worker/watchdog already did.

        ``gate_outcome`` (CP2 closure 1) persists the closed gate-outcome discriminator INDEPENDENTLY of the
        engine ``verdict``, so the override classifier can tell a merge-past-a-blocking-non-run from a clean
        merge without a fabricated verdict.

        Increment A: the winner ARMS the CONCLUSION publication generation (completed + the rendered
        conclusion/summary) in the SAME atomic UPDATE — but publish_state is FENCED: if a NEWER delivery
        (higher rowid) exists for this identity the conclusion is born 'superseded' (never drives a stale
        conclusion onto the actuator); otherwise 'pending' for the Publisher to drive."""
        if status not in ("done", "error"):
            raise ValueError(f"terminal status must be done|error, got {status!r}")
        now = self._clock()
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                "UPDATE gating SET status=?, check_run_id=?, verdict=?, reason=?, gate_outcome=?, "
                "updated_at=? WHERE delivery_id=? AND status='processing'",
                (status, check_run_id, verdict, reason, gate_outcome, now, delivery_id),
            )
            won = cur.rowcount == 1
            if won:
                # arm the delivery's CONCLUSION publication as a DISTINCT durable row (never overwrite the
                # RESET row — phase collapse would leave repair unable to re-drive the surface to pending).
                # COMPLETE-BINDING: derive generation + identity (repo, head_sha, check_name) from THIS
                # delivery's PERSISTED RESET row — NOT self._check_name (live config) — so a restart /
                # config change between RESET and finalize cannot split the two phases across identities
                # (which _RESET_READY, keyed only on delivery_id, would silently accept). Born 'superseded'
                # if a NEWER generation already exists for that same identity; else 'pending'.
                r = conn.execute(
                    "SELECT generation, repo_full_name, head_sha, check_name FROM publication "
                    "WHERE delivery_id=? AND phase='reset'", (delivery_id,)).fetchone()
                if r is None:
                    # Dissent blocker 2 — terminal-without-publication is FORBIDDEN (the v1 defect). A won
                    # finalize with no outbox RESET has nothing to bind the conclusion to; skipping it
                    # silently would leave the PR's required check permanently unpublished. RAISE (the except
                    # ROLLS BACK the terminal UPDATE, so the row stays 'processing' and surfaces LOUDLY). A
                    # legacy row with no reset must be terminalized by the startup migration, never here.
                    raise OutboxInvariantError(
                        f"finalize won for {delivery_id!r} but no outbox RESET exists to bind the conclusion "
                        "to — terminal-without-publication is forbidden (migrate legacy rows at startup)")
                gen, repo, sha, cname = (int(r["generation"]), r["repo_full_name"],
                                         r["head_sha"], r["check_name"])
                newer = conn.execute(
                    "SELECT 1 FROM publication n WHERE n.repo_full_name=? AND n.head_sha=? "
                    "AND n.check_name=? AND n.generation>? LIMIT 1",
                    (repo, sha, cname, gen)).fetchone()
                pub_state = "superseded" if newer is not None else "pending"
                conn.execute(
                    "INSERT INTO publication (delivery_id, generation, repo_full_name, head_sha,"
                    " check_name, phase, status, conclusion, summary, state, attempts, next_at,"
                    " created_at) VALUES (?,?,?,?,?, 'conclusion', 'completed', ?, ?, ?, 0, ?, ?) "
                    "ON CONFLICT(delivery_id, phase) DO UPDATE SET generation=excluded.generation,"
                    "  status='completed', conclusion=excluded.conclusion, summary=excluded.summary,"
                    "  state=excluded.state, attempts=0, lease_until=NULL, next_at=excluded.next_at",
                    (delivery_id, gen, repo, sha, cname,
                     publish_conclusion, publish_summary, pub_state, now, now),
                )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return won

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

    # ---- publication outbox (Increment A) --------------------------------

    # a publication is the CURRENT generation for its identity iff no higher-generation publication
    # exists for the same (repo, head_sha, check_name). Aliased ``p`` in the queries below.
    _IS_MAX_GEN = (
        "NOT EXISTS (SELECT 1 FROM publication n WHERE n.repo_full_name=p.repo_full_name "
        "AND n.head_sha=p.head_sha AND n.check_name=p.check_name AND n.generation > p.generation)"
    )
    # phase ordering (part of the fence): a CONCLUSION may publish ONLY after its OWN generation's RESET
    # is published — else a repair race could land conclusion-then-stale-reset one layer down.
    _RESET_READY = (
        "(p.phase='reset' OR EXISTS (SELECT 1 FROM publication r WHERE r.delivery_id=p.delivery_id "
        "AND r.phase='reset' AND r.state='published'))"
    )

    def _job_from_row(self, row: sqlite3.Row) -> PublicationJob:
        return PublicationJob(
            delivery_id=str(row["delivery_id"]), phase=str(row["phase"]),
            repo_full_name=str(row["repo_full_name"]), head_sha=str(row["head_sha"]),
            check_name=str(row["check_name"]), status=str(row["status"]),
            conclusion=row["conclusion"], summary=row["summary"])

    def claim_publication(self, *, lease_seconds: float = 300.0) -> PublicationJob | None:
        """Atomically claim the oldest DUE, unleased publication that is the CURRENT generation for its
        identity AND phase-ready (a conclusion only after its reset published), leasing it (a crashed
        publisher's lease expires -> reclaimable). RESET before CONCLUSION within a generation. Only the
        MAX generation is claimable, so a stale older payload is never published. None if nothing due."""
        conn = self._conn()
        conn.execute("BEGIN IMMEDIATE")
        try:
            now = self._clock()
            row = conn.execute(
                "SELECT * FROM publication p WHERE p.state='pending' "
                "AND (p.next_at IS NULL OR p.next_at<=?) "
                "AND (p.lease_until IS NULL OR p.lease_until<?) "
                f"AND {self._IS_MAX_GEN} AND {self._RESET_READY} "
                "ORDER BY p.generation, (p.phase='conclusion') LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                conn.execute("COMMIT")
                return None
            conn.execute(
                "UPDATE publication SET lease_until=? WHERE id=? AND state='pending'",
                (now + lease_seconds, row["id"]),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        return self._job_from_row(row)

    def mark_publication_published(self, delivery_id: str, phase: str) -> bool:
        """No-regression CAS: record 'published' ONLY if this publication is STILL the current generation
        for its identity. Returns True iff won. False means a newer generation landed during the publish
        window — the just-written external bytes may be stale, so the caller MUST trigger
        ``repair_publication`` (the ledger is honest, but the ACTUATOR needs re-driving to the true
        head)."""
        cur = self._conn().execute(
            "UPDATE publication AS p SET state='published', lease_until=NULL "
            f"WHERE p.delivery_id=? AND p.phase=? AND p.state='pending' AND {self._IS_MAX_GEN}",
            (delivery_id, phase),
        )
        return cur.rowcount == 1

    def repair_publication(self, repo_full_name: str, head_sha: str, check_name: str) -> None:
        """DURABLE repair (ruling): re-arm the CURRENT-max-generation's publications for the identity as
        'pending' + due-now + unleased, so the Publisher re-drives the actuator to the TRUE head. Both
        phases are re-armed; the phase-ordering fence (``_RESET_READY``) republishes the RESET first
        (returning the surface to pending) THEN the CONCLUSION. A durable DB write drained by the normal
        loop — a crash or a failed immediate retry cannot lose it (a one-shot repair would recreate the
        outage hole). Idempotent: re-arming an already-correct head is one idempotent re-upsert."""
        self._conn().execute(
            "UPDATE publication SET state='pending', next_at=?, lease_until=NULL "
            "WHERE repo_full_name=? AND head_sha=? AND check_name=? AND state IN ('pending','published') "
            "AND generation=(SELECT MAX(generation) FROM publication "
            "  WHERE repo_full_name=? AND head_sha=? AND check_name=?)",
            (self._clock(), repo_full_name, head_sha, check_name,
             repo_full_name, head_sha, check_name),
        )

    def release_publication(self, delivery_id: str, phase: str, *, backoff_seconds: float) -> None:
        """A publish attempt failed (CheckRunError): ++attempts, back off, drop the lease -> retried
        durably on the next sweep (UNBOUNDED — a stuck actuator keeps the check pending/blocking, never a
        false green; the attempts count drives backoff + alerting, never give-up)."""
        self._conn().execute(
            "UPDATE publication SET attempts=attempts+1, next_at=?, lease_until=NULL "
            "WHERE delivery_id=? AND phase=?",
            (self._clock() + backoff_seconds, delivery_id, phase),
        )

    def verdicts_for_sha(
        self, head_sha: str
    ) -> list[tuple[str, str | None, str | None, float, str | None]]:
        """C3 read-only: ALL gating rows for a SHA as ``(status, verdict, reason, updated_at, gate_outcome)``
        — the raw input to the override-ledger classifier. NOT a single-row lookup: multiple deliveries
        (opened+reopened) can share a SHA, and a stale ``done`` can coexist with a newer ``processing`` — the
        classifier resolves precedence. ``gate_outcome`` (CP2 closure 1) lets it classify a blocking non-run
        merged-past without a fabricated verdict. This read NEVER triggers a check-run (NFR6)."""
        rows = self._conn().execute(
            "SELECT status, verdict, reason, updated_at, gate_outcome FROM gating WHERE head_sha=?",
            (head_sha,),
        ).fetchall()
        return [(r["status"], r["verdict"], r["reason"], float(r["updated_at"]), r["gate_outcome"])
                for r in rows]


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
