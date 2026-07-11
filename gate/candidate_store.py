"""gate/candidate_store.py — 3.4: the append-only CANDIDATE log (separate from the fixture store).

The admission gate's low-privilege half. A *candidate* is a PROPOSED fixture — an LLM/red-team
evasion (candidate known-bad) or a C3-triage false-positive (candidate known-good). Proposing is
UNPRIVILEGED and safe-to-be-wrong: a bad candidate is refused at admission, at no cost. The oracle
is only poisoned if a candidate reaches the FIXTURE store without human GOVERNANCE — so the two
must be structurally separate.

The structural discipline (board floor, 3.4):
  * The candidate log and the fixture store (``gate/calibration_store.py``) are SEPARATE append-only
    streams. There is NO shared mutable ``status`` field that a candidate flips from pending->approved
    — a flippable status IS the auto-persist bypass. "Admitted" is not a column here; it is the
    EXISTENCE of a fixture in the calibration store whose provenance references this candidate_id.
  * Proposing is unprivileged (no GovernanceApproval) — the risk is at PERSISTENCE, not proposal.
  * Append-only: no update/delete/status path. A candidate that is never admitted simply stays an
    un-referenced proposal; nothing silently promotes it (no timeout auto-add — there is no code
    path here that writes to the fixture store at all).

Content-addressed: each candidate carries a ``content_hash`` of its payload so admission binds the
EXACT bytes a human reviewed (the confused-deputy-in-signing guard — the human attests the canonical
payload, not a rendered summary).
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable


class CandidateKind(Enum):
    KNOWN_BAD = "known_bad"    # a proposed evasion (red-team / production-miss)
    KNOWN_GOOD = "known_good"  # a proposed clean case (C3-triage false-positive)


class CandidateSource(Enum):
    RED_TEAM = "red_team"              # LLM-proposed evasion (safe-to-be-wrong)
    PRODUCTION_MISS = "production_miss"  # an escape found in production
    C3_TRIAGE = "c3_triage"            # a C3 false-positive override, surfaced read-only
    SEED = "seed"                      # a standing seed class (env-keying / input-keying)


@dataclass(frozen=True)
class Candidate:
    """A proposed fixture. ``merged_tree_hash`` is set ONLY for known-good candidates sourced from a
    real merge (C3-triage) — it is the immutable merged-tree the human approves, never a PR-tree."""

    candidate_id: str
    kind: CandidateKind
    payload: bytes
    source: CandidateSource
    proposed_by: str | None = None
    evasion_class: str | None = None
    c3_override_ref: str | None = None
    merged_tree_hash: str | None = None

    @property
    def content_hash(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_log (
    candidate_id     TEXT PRIMARY KEY,
    kind             TEXT NOT NULL,
    payload          BLOB NOT NULL,
    content_hash     TEXT NOT NULL,
    source           TEXT NOT NULL,
    proposed_by      TEXT,
    evasion_class    TEXT,
    c3_override_ref  TEXT,
    merged_tree_hash TEXT,
    proposed_at      REAL NOT NULL
);
"""


class CandidateStore:
    """Durable, append-only candidate log. UNPRIVILEGED propose; no update/delete/status. Separate
    from the fixture store — the two never share a mutable row."""

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
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return conn

    def propose(self, candidate: Candidate) -> str:
        """Append a proposed fixture. UNPRIVILEGED (no approval) — proposing is safe-to-be-wrong; the
        gate is at admission. Idempotent by candidate_id. Returns the candidate_id. There is NO
        method here that writes a fixture — proposal cannot become persistence in this module."""
        with self._lock:
            self._conn().execute(
                "INSERT OR IGNORE INTO candidate_log "
                "(candidate_id, kind, payload, content_hash, source, proposed_by, evasion_class,"
                " c3_override_ref, merged_tree_hash, proposed_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (candidate.candidate_id, candidate.kind.value, candidate.payload,
                 candidate.content_hash, candidate.source.value, candidate.proposed_by,
                 candidate.evasion_class, candidate.c3_override_ref, candidate.merged_tree_hash,
                 self._clock()),
            )
        return candidate.candidate_id

    def get(self, candidate_id: str) -> Candidate | None:
        row = self._conn().execute(
            "SELECT * FROM candidate_log WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        if row is None:
            return None
        return Candidate(
            candidate_id=row["candidate_id"], kind=CandidateKind(row["kind"]),
            payload=bytes(row["payload"]), source=CandidateSource(row["source"]),
            proposed_by=row["proposed_by"], evasion_class=row["evasion_class"],
            c3_override_ref=row["c3_override_ref"], merged_tree_hash=row["merged_tree_hash"],
        )

    def count(self) -> int:
        return int(self._conn().execute("SELECT COUNT(*) AS n FROM candidate_log").fetchone()["n"])


__all__ = ["CandidateKind", "CandidateSource", "Candidate", "CandidateStore"]
