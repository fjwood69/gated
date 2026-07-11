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
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Callable, Mapping

from core.calibration import CalibrationSet, Fixture, FixtureLabel
from core.chain import GENESIS_HASH, chain_hash, content_digest
from gate.authority import Authority, GovernanceApproval  # re-exported below for API stability


@dataclass(frozen=True)
class OutboxEntry:
    """One undrained re-calibration trigger: a set changed, its new head is ``oracle_head_after``.
    The relay fans this out to the ENABLED policies bound to ``set_id`` and enqueues a re-cal each."""

    id: int
    set_id: str
    oracle_head_after: str
    appended_at: float


@dataclass(frozen=True)
class SealedSet:
    """3.5 job-1: a SNAPSHOT-CONSISTENT seal of a calibration set (the fourth-hole fix). The
    ``calibration_set``, the ``oracle_head`` (== ``set_head(set_id)`` at the seal instant), and the
    ``coverage_digest`` are ALL derived from a SINGLE consistent read of the chain, so they provably
    describe the SAME membership instant. Without this, a runner could read the head at T1 and the
    fixtures at T2 and sign a PASS attesting a coverage that never co-existed with that head — a
    cryptographically valid signature over an epistemologically false claim. The runner seals ONCE,
    releases the read transaction, THEN runs the (expensive) calibration against this frozen set."""

    set_id: str
    calibration_set: CalibrationSet
    oracle_head: str
    coverage_digest: str
    fixture_ids: tuple[str, ...]


class ChangeOp(IntEnum):
    ADD_KNOWN_BAD = 0
    ADD_KNOWN_GOOD = 1
    SUPERSEDE_KNOWN_GOOD = 2   # replace a known-good (fixture_id=new, supersedes=old, payload=new)
    DEPRECATE_KNOWN_BAD = 3    # exclude a known-bad from the head; it STAYS in the chain


class AdmissionCapability:
    """Merge-ready #1: an unforgeable-by-convention capability proving a fixture ADD is going through
    the admission gate. ``append`` REFUSES an ADD op without it, so there is no low-level path that
    adds a fixture while skipping the validated, dual-controlled, safe (revoke+outbox) admission — the
    bypass is removed, not merely a safe path added alongside it. Constructed ONLY by
    ``gate.admission.admit()`` (enforced by the structural no-bypass test); any other construction in
    the gate tree fails that test. Tests seed via the same capability (they are trusted)."""

    __slots__ = ()


# Ops that require REAL dual control — a GovernanceApproval with two distinct principals. As of 3.4
# this is every op that admits a fixture to the oracle (both ADDs) plus the weakening DEPRECATE:
# admitting is high-stakes (a known-bad blocks merges; a known-good masks a true positive). This is
# what makes gate/admission.py the only sufficient-authority path in. See ``append``.
_DUAL_APPROVAL_OPS: frozenset[ChangeOp] = frozenset(
    {ChangeOp.ADD_KNOWN_BAD, ChangeOp.ADD_KNOWN_GOOD, ChangeOp.DEPRECATE_KNOWN_BAD}
)

# The enum authority the remaining (non-dual) ops require. SUPERSEDE_KNOWN_GOOD (a correction of an
# existing known-good) keeps the single-GOVERNANCE enum model for now.
_REQUIRED: dict[ChangeOp, Authority] = {
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
    set_id         TEXT NOT NULL DEFAULT 'default',  -- 3.4: the calibration SET this fixture belongs to
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
-- 3.5 job-1: the TRANSACTIONAL OUTBOX (co-located with the fixture store). A re-calibration trigger
-- is INSERTed in the SAME transaction as the fixture append that necessitates it (see append()'s
-- outbox path), so a crash can never leave 'fixture appended but re-cal never enqueued' (which would
-- wedge every bound policy UNATTESTABLE forever). A relay drains it to the lease queue at-least-once;
-- the queue dedups by job_id, so a relay crash after enqueue / before mark is safe.
CREATE TABLE IF NOT EXISTS re_calibration_outbox (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id            TEXT NOT NULL,
    oracle_head_after TEXT NOT NULL,   -- set_head(set_id) computed inside the append transaction
    appended_at       REAL NOT NULL,
    drained           INTEGER NOT NULL DEFAULT 0
);
"""


def _digest_fields(row: Mapping[str, object]) -> str:
    """The canonical content digest of a change record (excludes seq + prev_hash). Uses the shared
    core.chain primitive — same tamper-evidence math as the C3 override ledger."""
    return content_digest(
        {
            "op": row["op"], "fixture_id": row["fixture_id"], "set_id": row["set_id"],
            "label": row["label"], "payload_hash": row["payload_hash"],
            "evasion_class": row["evasion_class"], "supersedes": row["supersedes"],
            "reason": row["reason"], "added_by": row["added_by"], "added_at": row["added_at"],
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
        set_id: str = "default",
        label: FixtureLabel | None = None,
        payload: bytes | None = None,
        evasion_class: str | None = None,
        supersedes: str | None = None,
        reason: str | None = None,
        added_by: str | None = None,
        outbox_set_id: str | None = None,
        admission: AdmissionCapability | None = None,
    ) -> int:
        """Append a fixture-set change, hash-chained. PRIVILEGED. RUNTIME can never append (1b).

        Merge-ready #1: the two ADD ops additionally REQUIRE an ``AdmissionCapability`` — there is no
        low-level path that adds a fixture while skipping the admission gate's validation + safe append.
        Only ``gate.admission.admit()`` holds the capability; a direct ADD without it is refused.

        3.5 job-1 (transactional outbox): when ``outbox_set_id`` is given, the fixture INSERT and a
        ``re_calibration_outbox`` row (carrying the NEW ``set_head`` computed inside the transaction)
        are committed ATOMICALLY — so a crash can never leave the set changed but the re-calibration
        un-enqueued. Board amendment 4: the caller (``commit_fixture_append``) revokes-and-fsyncs the
        fallback FIRST, THEN calls this; a failure before this commit safely OVER-BLOCKS (the fixture
        never lands, the fallback is already revoked, the policy stays fail-closed).

        Authority model (3.4): admitting a fixture to the ORACLE is high-stakes governance, so the
        ADD ops AND the weakening DEPRECATE op all require a real ``approval`` — ``GovernanceApproval``
        with TWO DISTINCT authenticated principals (an enum a single caller names is not proof of
        dual control). This makes the ADMISSION GATE the only sufficient-authority path into the
        fixture store: a known-bad can block merges, a known-good can mask a true positive — both
        earn dual control. SUPERSEDE (a correction of an existing known-good) keeps the ENUM for now.
        Principals are recorded in ``added_by`` (schema/digest unchanged). No update/delete method."""
        if op in (ChangeOp.ADD_KNOWN_BAD, ChangeOp.ADD_KNOWN_GOOD) and not isinstance(
            admission, AdmissionCapability
        ):
            raise PrivilegedOperationError(
                f"{op.name} may only be appended through the admission gate (gate.admission.admit) — "
                "a fixture cannot be added on the low-level path, skipping validation + safe append"
            )
        if op in _DUAL_APPROVAL_OPS:
            if approval is None or not approval.meets(2):
                raise PrivilegedOperationError(
                    f"{op.name} requires a GovernanceApproval with two distinct principals — "
                    "admitting/weakening the oracle is dual-controlled governance, not an enum"
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
            conn = self._conn()
            prev_hash = self._head_hash()
            fields = {
                "op": op.name, "fixture_id": fixture_id, "set_id": set_id,
                "label": label.value if label is not None else None,
                "payload_hash": payload_hash, "evasion_class": evasion_class,
                "supersedes": supersedes, "reason": reason, "added_by": added_by,
                "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            insert_args = (
                fields["op"], fixture_id, set_id, fields["label"], payload, evasion_class,
                supersedes, reason, added_by, fields["added_at"], prev_hash, record_hash,
            )
            insert_sql = (
                "INSERT INTO calibration_chain "
                "(op, fixture_id, set_id, label, payload, evasion_class, supersedes, reason,"
                " added_by, added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            )
            if outbox_set_id is None:
                return int(conn.execute(insert_sql, insert_args).lastrowid or 0)
            # Atomic {fixture append + outbox enqueue}: both rows commit together or not at all.
            conn.execute("BEGIN IMMEDIATE")
            try:
                seq = int(conn.execute(insert_sql, insert_args).lastrowid or 0)
                new_head = self._compute_set_head(outbox_set_id)  # sees the just-inserted row
                conn.execute(
                    "INSERT INTO re_calibration_outbox (set_id, oracle_head_after, appended_at,"
                    " drained) VALUES (?,?,?,0)",
                    (outbox_set_id, new_head, fields["added_at"]),
                )
                conn.execute("COMMIT")
                return seq
            except Exception:
                conn.execute("ROLLBACK")
                raise

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
                "op": row["op"], "fixture_id": row["fixture_id"], "set_id": row["set_id"],
                "label": row["label"], "payload_hash": payload_hash,
                "evasion_class": row["evasion_class"], "supersedes": row["supersedes"],
                "reason": row["reason"], "added_by": row["added_by"], "added_at": row["added_at"],
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

    def set_head(self, set_id: str) -> str:
        """3.4 close-3: the SET-SCOPED oracle head — a digest of the CURRENT membership of ``set_id``
        (its non-deprecated/superseded fixtures). It changes IFF this set's membership changes: an
        append to set X moves set_head(X) and NOTHING else, so a fixture change invalidates only the
        policies calibrated against X — never a global wedge. A policy binds the set_head it was
        calibrated against; enforcement compares that to the current set_head and blocks (UNATTESTABLE)
        on mismatch. Fails CLOSED on a broken chain."""
        if not self.verify_chain():
            raise ChainIntegrityError("calibration chain failed verification — refusing to read")
        return self._compute_set_head(set_id)

    def _compute_set_head(self, set_id: str) -> str:
        """The set-scoped head from the CURRENT chain rows (no verify — callers that need fail-closed
        verify first; the outbox path calls this INSIDE its own append transaction after writing a
        valid record). A digest of the sorted (fixture_id, payload_hash) membership — order-independent,
        changes on any add/supersede/deprecate that alters THIS set."""
        members: dict[str, str] = {}  # fixture_id -> payload_hash, for CURRENT fixtures in set_id
        for row in self._conn().execute("SELECT * FROM calibration_chain ORDER BY seq ASC"):
            if row["set_id"] != set_id and ChangeOp[row["op"]] is not ChangeOp.DEPRECATE_KNOWN_BAD:
                continue
            op = ChangeOp[row["op"]]
            fid = row["fixture_id"]
            payload = row["payload"]
            ph = content_digest({"b": bytes(payload).hex()}) if payload is not None else ""
            if op in (ChangeOp.ADD_KNOWN_BAD, ChangeOp.ADD_KNOWN_GOOD):
                members[fid] = ph
            elif op is ChangeOp.SUPERSEDE_KNOWN_GOOD:
                members.pop(str(row["supersedes"]), None)
                members[fid] = ph
            elif op is ChangeOp.DEPRECATE_KNOWN_BAD:
                members.pop(fid, None)  # a deprecate may target this set regardless of the row's set_id
        return content_digest({"set_id": set_id, "members": sorted(members.items())})

    def seal_set(self, set_id: str) -> SealedSet:
        """3.5 job-1: SNAPSHOT-CONSISTENT seal of ``set_id`` — the fourth-hole fix. Reads the chain
        under a SINGLE consistent snapshot (an explicit deferred transaction; WAL gives a stable
        read-view for its duration) and derives the ``CalibrationSet``, the ``oracle_head``, and the
        ``coverage_digest`` from the SAME pass over the SAME rows, so they cannot describe different
        membership instants. verify_chain runs INSIDE the snapshot (fail-closed on a broken chain).
        The caller RELEASES this (returns) before the expensive calibration run; the restore CAS later
        rechecks that ``oracle_head`` is still current, so a set change mid-run simply forces a re-run.

        ``oracle_head`` is byte-identical to ``set_head(set_id)`` (same membership formula), so a seal
        and the live enforcement path agree on the head. ``coverage_digest`` binds the exact ground-truth
        fixtures scored (sorted id+label+payload-hash)."""
        conn = self._conn()
        conn.execute("BEGIN DEFERRED")
        try:
            if not self.verify_chain():
                raise ChainIntegrityError("calibration chain failed verification — refusing to seal")
            rows = conn.execute("SELECT * FROM calibration_chain ORDER BY seq ASC").fetchall()
        finally:
            conn.execute("COMMIT")
        # Single pass over the frozen snapshot. Mirrors set_head's per-set membership (incl. a
        # DEPRECATE that may target this set regardless of the row's set_id) AND keeps the Fixture.
        members: dict[str, tuple[str, Fixture]] = {}  # fid -> (payload_hash, Fixture)
        for row in rows:
            op = ChangeOp[row["op"]]
            if row["set_id"] != set_id and op is not ChangeOp.DEPRECATE_KNOWN_BAD:
                continue
            fid = str(row["fixture_id"])
            payload = row["payload"]
            ph = content_digest({"b": bytes(payload).hex()}) if payload is not None else ""
            if op is ChangeOp.ADD_KNOWN_BAD:
                members[fid] = (ph, Fixture(fid, FixtureLabel.KNOWN_BAD, bytes(payload), row["evasion_class"]))
            elif op is ChangeOp.ADD_KNOWN_GOOD:
                members[fid] = (ph, Fixture(fid, FixtureLabel.KNOWN_GOOD, bytes(payload), row["evasion_class"]))
            elif op is ChangeOp.SUPERSEDE_KNOWN_GOOD:
                members.pop(str(row["supersedes"]), None)
                members[fid] = (ph, Fixture(fid, FixtureLabel.KNOWN_GOOD, bytes(payload), row["evasion_class"]))
            elif op is ChangeOp.DEPRECATE_KNOWN_BAD:
                members.pop(fid, None)
        oracle_head = content_digest(
            {"set_id": set_id, "members": sorted((fid, ph) for fid, (ph, _f) in members.items())}
        )
        good = tuple(f for _ph, f in members.values() if f.label is FixtureLabel.KNOWN_GOOD)
        bad = tuple(f for _ph, f in members.values() if f.label is FixtureLabel.KNOWN_BAD)
        coverage_digest = content_digest({
            "set_id": set_id,
            "coverage": sorted((fid, f.label.value, ph) for fid, (ph, f) in members.items()),
        })
        return SealedSet(
            set_id=set_id, calibration_set=CalibrationSet(known_good=good, known_bad=bad),
            oracle_head=oracle_head, coverage_digest=coverage_digest,
            fixture_ids=tuple(sorted(members.keys())),
        )

    def undrained_outbox(self) -> tuple[OutboxEntry, ...]:
        """The re-calibration triggers not yet relayed to the queue (oldest first). The relay fans
        each out to the ENABLED policies bound to its set and enqueues a re-cal."""
        rows = self._conn().execute(
            "SELECT id, set_id, oracle_head_after, appended_at FROM re_calibration_outbox "
            "WHERE drained=0 ORDER BY id ASC"
        ).fetchall()
        return tuple(
            OutboxEntry(id=int(r["id"]), set_id=r["set_id"], oracle_head_after=r["oracle_head_after"],
                        appended_at=float(r["appended_at"]))
            for r in rows
        )

    def mark_outbox_drained(self, entry_id: int) -> None:
        """Mark one outbox entry relayed. Called AFTER the enqueue commits (at-least-once): a crash
        between enqueue and this mark re-delivers the entry, and the queue's job_id dedup makes the
        re-delivery a no-op."""
        with self._lock:
            self._conn().execute(
                "UPDATE re_calibration_outbox SET drained=1 WHERE id=?", (entry_id,))

    def head(self) -> str:
        """The chain head (record_hash of the last append) — an opaque epoch that changes on ANY
        fixture append. The snapshot-refresh CAS pairs this with the policy-store tier head; if
        either moves during a mint, the refresh retries (close-4)."""
        return self._head_hash()

    def record_count(self) -> int:
        return int(self._conn().execute("SELECT COUNT(*) AS n FROM calibration_chain").fetchone()["n"])


__all__ = [
    "Authority",
    "ChangeOp",
    "AdmissionCapability",
    "CalibrationStore",
    "SealedSet",
    "OutboxEntry",
    "PrivilegedOperationError",
    "ChainIntegrityError",
]
