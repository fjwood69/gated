"""gate/ledger.py — C3: the Override-Ledger capture (the merge-past-the-gate audit trail).

When a PR closes as MERGED, the gate asks the 2.3 store one question: *what verdict did I
record for that merged head SHA?* — and appends a tamper-evident audit record iff the merge
went past a non-PASS verdict (a HUMAN_OVERRIDE), or the gate cannot cleanly attest the merge
(an UNVERIFIABLE, with a sub-reason that says WHY). A clean PASS-then-merge records nothing
(D-Q1: the ledger is a pure bypass record; positive attestation already lives in the 2.3
verdict store).

TRUTHFUL CAPTURE (the board's headline ruling). The gate records only what its own trusted
context can attest: "I evaluated SHA X, my verdict was non-PASS, the PR merged anyway." It
does NOT claim "a REQUIRED check was bypassed" — knowing whether the check was branch-
protection-required needs the `administration` permission the 2.5 finding deliberately
excluded from the minimal runtime token. Required-vs-advisory is a deploy-time operator
assertion / B enrichment, injected at the layer that has that knowledge — never fabricated
here. ``render_ledger_line`` is phrased to that discipline (see its done-test).

Standing invariants (inherited, non-negotiable):
  * append-only + tamper-evident (FR6.1) — a hash chain (each record hashes the prior
    record's hash + its own content); any edit to a prior record breaks the chain;
  * out-of-band (NFR4) — the ledger is the GATE's store, its own DB, never in the repo
    under test; the merger cannot reach the record of their own override;
  * reads the stored verdict, never re-computes (NFR6) — the capture path makes NO
    check-run call, NO sandbox, NO engine invocation. It is observational: it changes no
    merge decision and cannot introduce a fail-open (it never touches the decision path).

Idempotency (F4, at-least-once webhooks): the record key is the CLOSED webhook's
delivery_id under a UNIQUE constraint — a re-delivery / retry storm cannot double-stamp.
The append is serialised (a lock) so the hash chain stays linear.
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence

from core.chain import GENESIS_HASH, chain_hash, content_digest

from .job_result import GateOutcome
from .queue import OverrideCaptureEvent

_log = logging.getLogger("gated.gate.ledger")


class OverrideKind(Enum):
    HUMAN_OVERRIDE = "HUMAN_OVERRIDE"      # merged past a recorded non-PASS verdict
    UNVERIFIABLE = "OVERRIDE_UNVERIFIABLE"  # the gate cannot cleanly attest this merge


class UnverifiableReason(Enum):
    """WHY the gate can't attest — itself an audit fact (consult's D-Q2 taxonomy)."""

    NEVER_EVALUATED = "NEVER_EVALUATED"          # no verdict row exists for the SHA
    EVALUATION_IN_FLIGHT = "EVALUATION_IN_FLIGHT"  # a check was still running at merge
    INFRA_ERROR = "INFRA_ERROR"                  # the delivery errored (infra), not a verdict
    AMBIGUOUS = "AMBIGUOUS"                       # contradictory terminal outcomes for the SHA
    INDETERMINATE_GATE = "INDETERMINATE_GATE"    # a done row with neither a verdict nor a known gate outcome


class OutcomeKind(Enum):
    NO_OVERRIDE = "NO_OVERRIDE"        # clean PASS-then-merge — record nothing (D-Q1)
    HUMAN_OVERRIDE = "HUMAN_OVERRIDE"
    UNVERIFIABLE = "UNVERIFIABLE"


@dataclass(frozen=True)
class VerdictRow:
    """One 2.3-store row for a SHA, reduced to what the classifier needs. ``status`` is the
    DELIVERY status (queued|processing|done|error); ``verdict`` is the gate's verdict on a
    ``done`` row. The two are DISTINCT (F3): delivery status='error' is retryable infra, NOT
    the gate's ERROR verdict."""

    status: str
    verdict: str | None
    reason: str | None
    updated_at: float
    gate_outcome: str | None = None   # CP2 closure 1: the persisted GateOutcome value (independent of verdict)


@dataclass(frozen=True)
class MergeOutcome:
    """The classifier's verdict on a merge. For HUMAN_OVERRIDE, ``verdict``/``reason`` carry
    the overridden gate verdict; for UNVERIFIABLE, ``sub_reason`` says why."""

    kind: OutcomeKind
    verdict: str | None = None
    reason: str | None = None
    sub_reason: UnverifiableReason | None = None


_KNOWN_VERDICTS = frozenset({"PASS", "FAIL", "ERROR"})


def _row_class(row: VerdictRow) -> str:
    """CP2 closure 1: classify ONE ``done`` row as ``allowing`` / ``blocking`` / ``indeterminate`` by
    validating the COMPLETE (verdict, gate_outcome) PAIR — a contradictory or unknown pair is INDETERMINATE,
    never silently trusted. The ONLY coherent combinations:
      - legacy (gate_outcome=None) + a KNOWN verdict  -> allowing (PASS) / blocking (FAIL|ERROR);
      - RUN_VERDICT + a KNOWN verdict                 -> allowing (PASS) / blocking (FAIL|ERROR);
      - BLOCK_GATE + no verdict                       -> blocking (a blocking non-run merged past);
      - NEUTRAL_GATE + no verdict                     -> allowing.
    Everything else — a PASS paired with block_gate, a verdict paired with a gate, RUN_VERDICT with no
    verdict, or an UNKNOWN verdict string — is INDETERMINATE (an unknown verdict is NOT auto-blocking)."""
    v, g = row.verdict, row.gate_outcome
    if v is None:
        if g == GateOutcome.BLOCK_GATE.value:
            return "blocking"
        if g == GateOutcome.NEUTRAL_GATE.value:
            return "allowing"
        return "indeterminate"                 # None + (None | RUN_VERDICT | unknown gate) — incoherent
    if v not in _KNOWN_VERDICTS:
        return "indeterminate"                 # an unknown verdict string is never trusted as blocking
    if g is None or g == GateOutcome.RUN_VERDICT.value:
        return "allowing" if v == "PASS" else "blocking"
    return "indeterminate"                     # a known verdict paired with BLOCK/NEUTRAL gate — contradictory


def classify_merge(rows: Sequence[VerdictRow]) -> MergeOutcome:
    """PURE: map the 2.3-store rows for a merged SHA to an audit outcome. No I/O.

    Precedence (audit-conservative, CP2 closure 1 — classify the GATE OUTCOME, not just the engine verdict):
      1. any delivery still ``processing`` -> UNVERIFIABLE/EVALUATION_IN_FLIGHT (F2 staleness).
      2. ``done`` rows present, each classed allowing / blocking / indeterminate from verdict + gate outcome:
           - any INDETERMINATE (a done row with neither a verdict nor a known gate outcome, e.g. a historical
             row) -> UNVERIFIABLE/INDETERMINATE_GATE (never a clean success);
           - mixed allowing + blocking     -> UNVERIFIABLE/AMBIGUOUS;
           - blocking-only                 -> HUMAN_OVERRIDE (latest blocking row; a blocking NON-RUN carries
             verdict=None + its stable gate-outcome reason, rendered "gate outcome was ...");
           - allowing-only                 -> NO_OVERRIDE (record nothing, D-Q1).
      3. no ``done`` rows but ``error`` rows -> UNVERIFIABLE/INFRA_ERROR (F3: infra, not verdict).
      4. no rows at all                      -> UNVERIFIABLE/NEVER_EVALUATED.
    """
    if any(r.status == "processing" for r in rows):
        return MergeOutcome(OutcomeKind.UNVERIFIABLE, sub_reason=UnverifiableReason.EVALUATION_IN_FLIGHT)

    done = [r for r in rows if r.status == "done"]
    if done:
        classes = {r: _row_class(r) for r in done}
        if any(c == "indeterminate" for c in classes.values()):
            return MergeOutcome(OutcomeKind.UNVERIFIABLE, sub_reason=UnverifiableReason.INDETERMINATE_GATE)
        allowing = any(c == "allowing" for c in classes.values())
        blocking = [r for r, c in classes.items() if c == "blocking"]
        if allowing and blocking:
            return MergeOutcome(OutcomeKind.UNVERIFIABLE, sub_reason=UnverifiableReason.AMBIGUOUS)
        if blocking:
            # the latest blocking row: a verdict-bearing block carries its verdict/reason; a blocking non-run
            # carries verdict=None + its stable gate-outcome reason (no hash-bound ledger field — reuse fields).
            latest = max(blocking, key=lambda r: r.updated_at)
            return MergeOutcome(OutcomeKind.HUMAN_OVERRIDE, verdict=latest.verdict, reason=latest.reason)
        return MergeOutcome(OutcomeKind.NO_OVERRIDE)

    if any(r.status == "error" for r in rows):
        return MergeOutcome(OutcomeKind.UNVERIFIABLE, sub_reason=UnverifiableReason.INFRA_ERROR)

    return MergeOutcome(OutcomeKind.UNVERIFIABLE, sub_reason=UnverifiableReason.NEVER_EVALUATED)


@dataclass(frozen=True)
class OverrideRecord:
    """A persisted ledger row (append-only). ``record_hash`` chains from ``prev_hash``."""

    seq: int
    delivery_id: str
    kind: OverrideKind
    repo_full_name: str
    pr: int | None
    sha: str
    verdict: str | None          # set for HUMAN_OVERRIDE
    reason: str | None           # the overridden verdict's reason
    sub_reason: str | None       # set for UNVERIFIABLE
    merged_by: str | None
    merged_at: str | None
    policy_version: str | None   # capture-time metadata (labelled; NOT from the stored verdict)
    captured_at: float
    prev_hash: str
    record_hash: str


def _content_digest(
    *,
    delivery_id: str,
    kind: str,
    repo_full_name: str,
    pr: int | None,
    sha: str,
    verdict: str | None,
    reason: str | None,
    sub_reason: str | None,
    merged_by: str | None,
    merged_at: str | None,
    policy_version: str | None,
    captured_at: float,
) -> str:
    """Canonical content hash of a record's semantic fields (excludes seq + prev_hash).
    Delegates to the shared ``core.chain`` primitive — hash-preserving (the field set + the
    canonicalisation are identical to the pre-extraction version; golden-tested)."""
    return content_digest(
        {
            "delivery_id": delivery_id, "kind": kind, "repo_full_name": repo_full_name,
            "pr": pr, "sha": sha, "verdict": verdict, "reason": reason,
            "sub_reason": sub_reason, "merged_by": merged_by, "merged_at": merged_at,
            "policy_version": policy_version, "captured_at": captured_at,
        }
    )


_LEDGER_SCHEMA = """
CREATE TABLE IF NOT EXISTS override_ledger (
    seq            INTEGER PRIMARY KEY AUTOINCREMENT,
    delivery_id    TEXT NOT NULL UNIQUE,   -- idempotency key (the closed webhook delivery)
    kind           TEXT NOT NULL,          -- HUMAN_OVERRIDE | OVERRIDE_UNVERIFIABLE
    repo_full_name TEXT NOT NULL,
    pr             INTEGER,
    sha            TEXT NOT NULL,
    verdict        TEXT,
    reason         TEXT,
    sub_reason     TEXT,
    merged_by      TEXT,
    merged_at      TEXT,
    policy_version TEXT,
    captured_at    REAL NOT NULL,
    prev_hash      TEXT NOT NULL,
    record_hash    TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class AppendResult:
    record: OverrideRecord
    newly_appended: bool  # False => a prior record with this delivery_id already existed


class OverrideLedger:
    """Durable, append-only, hash-chained ledger. Out-of-band (NFR4): its own DB file, the
    gate's trusted store — never the repo under test. Connection-per-thread; appends are
    serialised by a lock so the chain stays linear under the poll loop + reconciliation."""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.time) -> None:
        self._path = str(path)
        self._clock = clock
        self._local = threading.local()
        self._append_lock = threading.Lock()
        conn = self._conn()
        conn.executescript(_LEDGER_SCHEMA)
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
        *,
        delivery_id: str,
        kind: OverrideKind,
        repo_full_name: str,
        pr: int | None,
        sha: str,
        verdict: str | None = None,
        reason: str | None = None,
        sub_reason: str | None = None,
        merged_by: str | None = None,
        merged_at: str | None = None,
        policy_version: str | None = None,
    ) -> AppendResult:
        """Append a record, hash-chained to the current head. IDEMPOTENT on delivery_id:
        a re-delivery returns the EXISTING record with ``newly_appended=False`` and does NOT
        re-chain (so a webhook retry storm cannot double-stamp or fork the chain)."""
        with self._append_lock:
            existing = self._by_delivery(delivery_id)
            if existing is not None:
                return AppendResult(existing, newly_appended=False)

            captured_at = self._clock()
            prev_hash = self.head_hash()
            content = _content_digest(
                delivery_id=delivery_id, kind=kind.value, repo_full_name=repo_full_name,
                pr=pr, sha=sha, verdict=verdict, reason=reason, sub_reason=sub_reason,
                merged_by=merged_by, merged_at=merged_at, policy_version=policy_version,
                captured_at=captured_at,
            )
            record_hash = chain_hash(prev_hash, content)
            cur = self._conn().execute(
                "INSERT INTO override_ledger "
                "(delivery_id, kind, repo_full_name, pr, sha, verdict, reason, sub_reason,"
                " merged_by, merged_at, policy_version, captured_at, prev_hash, record_hash) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(delivery_id) DO NOTHING",
                (delivery_id, kind.value, repo_full_name, pr, sha, verdict, reason,
                 sub_reason, merged_by, merged_at, policy_version, captured_at,
                 prev_hash, record_hash),
            )
            if cur.rowcount == 0:
                # Lost a race to a concurrent writer (belt-and-braces; the lock already
                # serialises us) — return the now-present record, not a second chain link.
                winner = self._by_delivery(delivery_id)
                assert winner is not None
                return AppendResult(winner, newly_appended=False)
            seq = int(cur.lastrowid or 0)
            return AppendResult(
                OverrideRecord(
                    seq=seq, delivery_id=delivery_id, kind=kind, repo_full_name=repo_full_name,
                    pr=pr, sha=sha, verdict=verdict, reason=reason, sub_reason=sub_reason,
                    merged_by=merged_by, merged_at=merged_at, policy_version=policy_version,
                    captured_at=captured_at, prev_hash=prev_hash, record_hash=record_hash,
                ),
                newly_appended=True,
            )

    def head_hash(self) -> str:
        """The record_hash of the latest record, or GENESIS if empty — the chain head an
        out-of-band anchor publishes so truncation (lop the tail + re-chain) is detectable."""
        row = self._conn().execute(
            "SELECT record_hash FROM override_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return GENESIS_HASH if row is None else str(row["record_hash"])

    def head_anchor(self) -> tuple[int, str]:
        """(seq, head_hash) — the checkpoint to publish out-of-band (mori-state) so the
        chain's tail cannot be silently truncated. seq==0 => empty ledger."""
        row = self._conn().execute(
            "SELECT seq, record_hash FROM override_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (0, GENESIS_HASH) if row is None else (int(row["seq"]), str(row["record_hash"]))

    def verify_chain(self) -> bool:
        """Walk the chain oldest->newest, recomputing each hash. Returns False if any record
        was edited, reordered, or its prev-link broken — the tamper-evidence property."""
        prev = GENESIS_HASH
        for row in self._conn().execute("SELECT * FROM override_ledger ORDER BY seq ASC"):
            content = _content_digest(
                delivery_id=row["delivery_id"], kind=row["kind"],
                repo_full_name=row["repo_full_name"], pr=row["pr"], sha=row["sha"],
                verdict=row["verdict"], reason=row["reason"], sub_reason=row["sub_reason"],
                merged_by=row["merged_by"], merged_at=row["merged_at"],
                policy_version=row["policy_version"], captured_at=row["captured_at"],
            )
            if row["prev_hash"] != prev:
                return False
            if row["record_hash"] != chain_hash(prev, content):
                return False
            prev = str(row["record_hash"])
        return True

    def count(self) -> int:
        return int(self._conn().execute("SELECT COUNT(*) AS n FROM override_ledger").fetchone()["n"])

    def _by_delivery(self, delivery_id: str) -> OverrideRecord | None:
        row = self._conn().execute(
            "SELECT * FROM override_ledger WHERE delivery_id=?", (delivery_id,)
        ).fetchone()
        return None if row is None else _row_to_record(row)


def _row_to_record(row: sqlite3.Row) -> OverrideRecord:
    return OverrideRecord(
        seq=int(row["seq"]), delivery_id=row["delivery_id"], kind=OverrideKind(row["kind"]),
        repo_full_name=row["repo_full_name"], pr=row["pr"], sha=row["sha"],
        verdict=row["verdict"], reason=row["reason"], sub_reason=row["sub_reason"],
        merged_by=row["merged_by"], merged_at=row["merged_at"],
        policy_version=row["policy_version"], captured_at=float(row["captured_at"]),
        prev_hash=row["prev_hash"], record_hash=row["record_hash"],
    )


# ---- the capture handler (poll-loop + reconciliation entry point) ------------

# A read-only provider of the 2.3-store verdict rows for a SHA (dependency inversion: the
# ledger does not import the store; the caller injects the lookup).
VerdictLookup = Callable[[str], Sequence[VerdictRow]]


def capture_override(
    event: OverrideCaptureEvent,
    lookup: VerdictLookup,
    ledger: OverrideLedger,
    *,
    policy_version: str | None = None,
) -> OverrideRecord | None:
    """Read the recorded verdict for the merged SHA, classify, and append iff audit-worthy.
    Returns the record appended (or the pre-existing one on a re-delivery), or None for a
    clean PASS-merge (D-Q1: record nothing). NEVER runs the engine — pure store read +
    ledger append. Reads the STORED verdict, never re-computes (NFR6)."""
    outcome = classify_merge(list(lookup(event.head_sha)))
    if outcome.kind is OutcomeKind.NO_OVERRIDE:
        return None

    if outcome.kind is OutcomeKind.HUMAN_OVERRIDE:
        kind, sub_reason = OverrideKind.HUMAN_OVERRIDE, None
    else:
        kind = OverrideKind.UNVERIFIABLE
        sub_reason = outcome.sub_reason.value if outcome.sub_reason is not None else None

    result = ledger.append(
        delivery_id=event.delivery_id, kind=kind, repo_full_name=event.repo_full_name,
        pr=event.pr_number, sha=event.head_sha, verdict=outcome.verdict,
        reason=outcome.reason, sub_reason=sub_reason, merged_by=event.merged_by,
        merged_at=event.merged_at, policy_version=policy_version,
    )
    return result.record


def render_ledger_line(record: OverrideRecord) -> str:
    """The auditor-facing one-line rendering — TRUTHFUL CAPTURE (board headline done-test).

    It states what the gate can attest ("gate verdict was X; PR merged anyway") and must
    NOT imply "a required check was bypassed" — the gate never knew whether the check was
    branch-protection-required (that needs the `administration` scope it deliberately lacks).
    The human-legibility done-test asserts this line never contains 'required'."""
    who = f" by @{record.merged_by}" if record.merged_by else ""
    pr = f"PR #{record.pr}" if record.pr is not None else "a PR"
    if record.kind is OverrideKind.HUMAN_OVERRIDE:
        if record.verdict is None:
            # a blocking NON-RUN gate (no engine verdict) — render the GATE OUTCOME truthfully, NEVER
            # "the gate verdict was None" (there was no verdict; the governance gate itself blocked). The
            # rendering stays "required"-free (the headline no-"required" legibility rule) — the stored
            # reason token ``block_action_required`` is the machine record; the human line says BLOCKING.
            return (
                f"{pr} (head {record.sha[:12]}) merged{who} while the gate outcome was BLOCKING "
                "(a governance gate withheld approval; no engine verdict was produced). "
                "The gate did not approve this merge."
            )
        return (
            f"{pr} (head {record.sha[:12]}) merged{who} while the gate verdict was "
            f"{record.verdict} ({record.reason}). The gate did not approve this merge."
        )
    return (
        f"{pr} (head {record.sha[:12]}) merged{who}, but the gate could not attest it: "
        f"{record.sub_reason}. No gate verdict backs this merge."
    )
