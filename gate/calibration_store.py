"""gate/calibration_store.py — 3.2: the out-of-band, append-only, tamper-evident CalibrationSet store.

Gate-side — it owns the protected-ref/governance authority; the engine-side calibrator merely
CONSUMES the ``CalibrationSet`` this produces (``engine ⊥ gate`` holds — the engine never imports
this module). REUSES ``core.chain`` (the primitive factored out in step 1), never rebuilds it.

The Oracle invariant's storage half:
  * **1b — the runtime token cannot weaken the fixtures.** Appending a change is PRIVILEGED; there
    is no ``RUNTIME``-authority write path. A check's minimal runtime token can *read* the current
    set (it's the oracle), never mutate it. (The live enforcement is the protected-ref + token
    scope — a deploy-time boundary, flagged for live confirmation; this models it in-process.)
  * **1e — DEPRECATE_KNOWN_BAD needs REAL dual control.** ADD/SUPERSEDE only ever *strengthen* the
    FN corpus (low friction, single ``GOVERNANCE`` enum). ``DEPRECATE_KNOWN_BAD`` is the one op that
    *weakens* it — self-grading could re-enter through the honest-correction door — so it requires a
    ``GovernanceApproval`` with TWO DISTINCT authenticated principals (3.3-consistency: an enum a
    single caller names is not proof of dual control). Adds strengthen; deprecations weaken;
    asymmetric risk, asymmetric authority.
  * **append-only, DELETES FORBIDDEN (FR6.1, §2.4).** There is no UPDATE/DELETE path. A wrong
    known-bad is DEPRECATED (a recorded append with a reason), never removed — it stays in the chain,
    ignored by the current head. A missing fixture is thus always an explicit, cryptographically
    recorded decision, never a silent omission. ``known_good`` corrections are SUPERSESSION appends.
  * **tamper-evident (FR6.1) via the hash chain** — ``verify_chain`` recomputes every record; an
    edit/remove of a prior record breaks it. Content-addressed fixtures give reproducibility (NFR6).

FR3.2: a fixture change re-triggers calibration — this store RECORDS the change (the trigger); the
re-calibration orchestration is 3.5.
"""
from __future__ import annotations

import sqlite3
import threading
import time
from enum import IntEnum
from pathlib import Path
from typing import Callable, Mapping

from core.calibration import CalibrationSet, Fixture, FixtureLabel
from core.chain import GENESIS_HASH, chain_hash, content_digest
from gate.authority import Authority, GovernanceApproval  # re-exported below for API stability


class ChangeOp(IntEnum):
    ADD_KNOWN_BAD = 0
    ADD_KNOWN_GOOD = 1
    SUPERSEDE_KNOWN_GOOD = 2   # replace a known-good (fixture_id=new, supersedes=old, payload=new)
    DEPRECATE_KNOWN_BAD = 3    # exclude a known-bad from the head; it STAYS in the chain


# The authority the STRENGTHENING ops require (single GOVERNANCE — the enum is an acceptable
# in-process MODEL of a deploy-time boundary for a low-risk strengthening op). The one WEAKENING op,
# DEPRECATE_KNOWN_BAD, no longer gates on the enum: it requires a real ``GovernanceApproval`` with
# TWO DISTINCT principals (3.3-consistency ruling — an enum a single caller names is not PROOF of
# dual control). See ``append``.
_REQUIRED: dict[ChangeOp, Authority] = {
    ChangeOp.ADD_KNOWN_BAD: Authority.GOVERNANCE,
    ChangeOp.ADD_KNOWN_GOOD: Authority.GOVERNANCE,
    ChangeOp.SUPERSEDE_KNOWN_GOOD: Authority.GOVERNANCE,
}


class PrivilegedOperationError(PermissionError):
    """A fixture-set change was attempted with insufficient authority (1b / 1e)."""


class ChainIntegrityError(RuntimeError):
    """The calibration chain failed verification — a fixture record was edited/removed/reordered."""


_SCHEMA = """
CREATE TABLE IF NOT EXISTS calibration_chain (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    op             TEXT NOT NULL,
    fixture_id     TEXT NOT NULL,
    label          TEXT,               -- known_good | known_bad (ADD ops)
    payload        BLOB,               -- fixture bytes (ADD / SUPERSEDE)
    evasion_class  TEXT,
    supersedes     TEXT,               -- SUPERSEDE_KNOWN_GOOD: the replaced fixture_id
    reason         TEXT,               -- DEPRECATE / SUPERSEDE justification
    added_by       TEXT,
    added_at       REAL NOT NULL,
    prev_hash      TEXT NOT NULL,
    record_hash    TEXT NOT NULL
);
"""


def _digest_fields(row: Mapping[str, object]) -> str:
    """The canonical content digest of a change record (excludes seq + prev_hash). Uses the shared
    core.chain primitive — same tamper-evidence math as the C3 override ledger."""
    return content_digest(
        {
            "op": row["op"], "fixture_id": row["fixture_id"], "label": row["label"],
            "payload_hash": row["payload_hash"], "evasion_class": row["evasion_class"],
            "supersedes": row["supersedes"], "reason": row["reason"],
            "added_by": row["added_by"], "added_at": row["added_at"],
        }
    )


class CalibrationStore:
    """Durable, append-only, hash-chained CalibrationSet store. Connection-per-thread; appends
    serialised so the chain stays linear (as the C3 ledger). No mutate/delete path exists."""

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

    def append(
        self,
        op: ChangeOp,
        *,
        authority: Authority = Authority.RUNTIME,
        approval: GovernanceApproval | None = None,
        fixture_id: str,
        label: FixtureLabel | None = None,
        payload: bytes | None = None,
        evasion_class: str | None = None,
        supersedes: str | None = None,
        reason: str | None = None,
        added_by: str | None = None,
    ) -> int:
        """Append a fixture-set change, hash-chained. PRIVILEGED. RUNTIME can never append (1b).

        Authority model (3.3-consistency): the STRENGTHENING ops (add / supersede) gate on the
        ``authority`` ENUM (GOVERNANCE) — an acceptable in-process model of the deploy-time boundary.
        The one WEAKENING op, DEPRECATE_KNOWN_BAD (1e), requires a real ``approval`` —
        ``GovernanceApproval`` with TWO DISTINCT authenticated principals — because an enum a single
        caller names is not PROOF of dual control. The approval's principals are recorded in
        ``added_by`` (schema/digest unchanged). Returns the new seq. No update/delete method."""
        if op is ChangeOp.DEPRECATE_KNOWN_BAD:
            if approval is None or not approval.meets(2):
                raise PrivilegedOperationError(
                    "DEPRECATE_KNOWN_BAD requires a GovernanceApproval with two distinct principals "
                    "— the one weakening op is real dual control, not an enum a caller names (1e)"
                )
            added_by = added_by or ",".join(sorted(approval.distinct_principals))
        else:
            required = _REQUIRED[op]
            if authority < required:
                raise PrivilegedOperationError(
                    f"{op.name} requires {required.name}, got {authority.name} — the runtime token "
                    "cannot weaken its own oracle"
                )
        payload_hash = content_digest({"b": payload.hex()}) if payload is not None else None
        with self._lock:
            prev_hash = self._head_hash()
            fields = {
                "op": op.name, "fixture_id": fixture_id,
                "label": label.value if label is not None else None,
                "payload_hash": payload_hash, "evasion_class": evasion_class,
                "supersedes": supersedes, "reason": reason, "added_by": added_by,
                "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            cur = self._conn().execute(
                "INSERT INTO calibration_chain "
                "(op, fixture_id, label, payload, evasion_class, supersedes, reason, added_by,"
                " added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (fields["op"], fixture_id, fields["label"], payload, evasion_class, supersedes,
                 reason, added_by, fields["added_at"], prev_hash, record_hash),
            )
            return int(cur.lastrowid or 0)

    def _head_hash(self) -> str:
        row = self._conn().execute(
            "SELECT record_hash FROM calibration_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return GENESIS_HASH if row is None else str(row["record_hash"])

    def verify_chain(self) -> bool:
        """Recompute the whole chain; False if any record was edited/removed/reordered."""
        prev = GENESIS_HASH
        for row in self._conn().execute("SELECT * FROM calibration_chain ORDER BY seq ASC"):
            payload = row["payload"]
            payload_hash = content_digest({"b": bytes(payload).hex()}) if payload is not None else None
            fields = {
                "op": row["op"], "fixture_id": row["fixture_id"], "label": row["label"],
                "payload_hash": payload_hash, "evasion_class": row["evasion_class"],
                "supersedes": row["supersedes"], "reason": row["reason"],
                "added_by": row["added_by"], "added_at": row["added_at"],
            }
            if row["prev_hash"] != prev or row["record_hash"] != chain_hash(prev, _digest_fields(fields)):
                return False
            prev = str(row["record_hash"])
        return True

    def load_current_set(self) -> CalibrationSet:
        """Replay the chain into the CURRENT active CalibrationSet — applying supersession and
        deprecation. Verifies integrity first (fail-closed: a broken chain raises, never silently
        yields a weakened set). READ-ONLY (no authority needed — reading the oracle is fine; only
        WRITING is gated). This is the sealed value the gate injects into the engine calibrator."""
        if not self.verify_chain():
            raise ChainIntegrityError("calibration chain failed verification — refusing to load")
        good: dict[str, Fixture] = {}
        bad: dict[str, Fixture] = {}
        for row in self._conn().execute("SELECT * FROM calibration_chain ORDER BY seq ASC"):
            op = ChangeOp[row["op"]]
            fid = row["fixture_id"]
            if op is ChangeOp.ADD_KNOWN_BAD:
                bad[fid] = Fixture(fid, FixtureLabel.KNOWN_BAD, bytes(row["payload"]), row["evasion_class"])
            elif op is ChangeOp.ADD_KNOWN_GOOD:
                good[fid] = Fixture(fid, FixtureLabel.KNOWN_GOOD, bytes(row["payload"]), row["evasion_class"])
            elif op is ChangeOp.SUPERSEDE_KNOWN_GOOD:
                good.pop(row["supersedes"], None)  # retire the old (still in the chain)
                good[fid] = Fixture(fid, FixtureLabel.KNOWN_GOOD, bytes(row["payload"]), row["evasion_class"])
            elif op is ChangeOp.DEPRECATE_KNOWN_BAD:
                bad.pop(fid, None)  # excluded from the head; the record STAYS in the chain
        return CalibrationSet(known_good=tuple(good.values()), known_bad=tuple(bad.values()))

    def record_count(self) -> int:
        return int(self._conn().execute("SELECT COUNT(*) AS n FROM calibration_chain").fetchone()["n"])


__all__ = [
    "Authority",
    "ChangeOp",
    "CalibrationStore",
    "PrivilegedOperationError",
    "ChainIntegrityError",
]
