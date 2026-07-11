"""gate/policy_store.py — 3.3: the append-only, tamper-evident TIER-TRANSITION ledger.

The THIRD consumer of ``core.chain`` (after the C3 override ledger and the 3.2 calibration store)
— every governance-significant tier change is a hash-chained record answering the auditor's
question "why did this check stop enforcing on the 14th?" from the RECORD, not from memory.

Each record: (policy_id, prior_state, new_state, calibration_result_ref, pinned_set_version,
detector_identity, principals, purpose, rationale, operation_id, added_at) + the chain fields. The
current tier of a check-type is the ``new_state`` of its latest record (replay). A broken chain
fails CLOSED — ``current_state`` raises rather than return a possibly-tampered tier.

Governance authority — board §2, addition #2 (REAL, not an enum):
  * every transition carries a ``GovernanceApproval`` (distinct authenticated principals + purpose +
    rationale + operation_id). A WEAKENING transition (ENABLED/DEGRADED -> ADVISORY) needs TWO
    DISTINCT principals (``meets(2)``); everything else needs one (``meets(1)``). A RUNTIME caller
    authenticates no governance principal -> ``meets(1)`` is False -> rejected (1b, structurally).
    A caller cannot satisfy dual control by repeating one principal or by naming an enum.
  * PROMOTE to ENABLED (and the 3.5 DEGRADED->ENABLED return) additionally REQUIRE non-null
    calibration_result_ref + pinned_set_version + detector_identity — no un-anchored enablement
    (addition #3). The ratifier identity is the approval's principal(s), recorded in the chain.
  * DEGRADATION (ENABLED -> DEGRADED, reserved 3.5) is NOT weakening (DEGRADED still blocks).
  * There is NO transition edge from a C3 event to any tier — the C3 feedback loop is 3.5 and
    human-gated; this store exposes no C3-driven append (a structural done-test asserts it).

append/current_state are serialised (one lock) so the chain stays linear. No update/delete path —
a superseded tier stays in the chain, excluded from head.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Callable, Mapping

from core.chain import GENESIS_HASH, chain_hash, content_digest
from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState, is_legal_transition, is_weakening


class PrivilegedOperationError(PermissionError):
    """A tier transition was attempted without sufficient governance approval (or missing the
    anchors an enablement requires)."""


class IllegalTransitionError(ValueError):
    """A (src -> dst) tier transition that the state machine does not permit."""


class ChainIntegrityError(RuntimeError):
    """The tier-transition chain failed verification — a record was edited/removed/reordered, or a
    per-policy prior-state continuity / legal-edge invariant was violated."""


def _required_principals(src: PolicyState, dst: PolicyState) -> int:
    """Distinct governance principals a transition demands: 2 for weakening (dual control), else 1."""
    return 2 if is_weakening(src, dst) else 1


_SCHEMA = """
CREATE TABLE IF NOT EXISTS tier_transition_chain (
    seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id              TEXT NOT NULL,
    prior_state            TEXT,               -- NULL only for a policy's first record
    new_state              TEXT NOT NULL,
    calibration_result_ref TEXT,               -- REQUIRED for -> ENABLED (addition #3)
    pinned_set_version     TEXT,               -- REQUIRED for -> ENABLED: the CalibrationSet head
    detector_identity      TEXT,               -- REQUIRED for -> ENABLED: which detector was calibrated
    principals             TEXT NOT NULL,      -- json: sorted distinct governance principal ids
    purpose                TEXT NOT NULL,
    rationale              TEXT NOT NULL,
    operation_id           TEXT NOT NULL,
    added_at               REAL NOT NULL,
    prev_hash              TEXT NOT NULL,
    record_hash            TEXT NOT NULL
);
-- Persisted PASS attestations: the factual record that a calibration RAN and PASSED for a specific
-- (policy, fixture-set version, detector identity). ENABLED is bound MECHANICALLY to a matching row
-- here (gap-1 fix): a fabricated calibration_result_ref cannot enable, because there is no PASS to
-- point at. Written only by the calibration flow (gate-side; the runtime token has no store write).
CREATE TABLE IF NOT EXISTS calibration_pass (
    calibration_result_ref TEXT PRIMARY KEY,
    policy_id              TEXT NOT NULL,
    set_id                 TEXT NOT NULL DEFAULT 'default',  -- 3.4: the SET this policy calibrated against
    pinned_set_version     TEXT NOT NULL,   -- the set_head(set_id) AT calibration time (the oracle head)
    detector_identity      TEXT NOT NULL,
    passed_at              REAL NOT NULL
);
"""


def _digest_fields(row: Mapping[str, object]) -> str:
    """Canonical content digest of a transition record (excludes seq + prev_hash). Same shared
    ``core.chain`` primitive as the C3 ledger + calibration store — one tamper-evidence math."""
    return content_digest(
        {
            "policy_id": row["policy_id"], "prior_state": row["prior_state"],
            "new_state": row["new_state"], "calibration_result_ref": row["calibration_result_ref"],
            "pinned_set_version": row["pinned_set_version"],
            "detector_identity": row["detector_identity"], "principals": row["principals"],
            "purpose": row["purpose"], "rationale": row["rationale"],
            "operation_id": row["operation_id"], "added_at": row["added_at"],
        }
    )


class PolicyStore:
    """Durable, append-only, hash-chained tier-transition store. Connection-per-thread; appends
    serialised so the chain stays linear. No mutate/delete path. The current tier of any policy is
    the head of its replayed sub-chain."""

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

    def transition(
        self,
        policy_id: str,
        new_state: PolicyState,
        *,
        approval: GovernanceApproval,
        calibration_result_ref: str | None = None,
        pinned_set_version: str | None = None,
        detector_identity: str | None = None,
    ) -> int:
        """Append a tier transition, hash-chained. Guarded three ways:
          * the (current -> new_state) edge must be legal (else IllegalTransitionError);
          * ``approval`` must carry enough DISTINCT principals — 2 for weakening, else 1 — plus
            purpose/rationale/operation_id (else PrivilegedOperationError; a RUNTIME caller with no
            principal cannot meet even 1);
          * a transition INTO ENABLED must carry non-null calibration_result_ref + pinned_set_version
            + detector_identity (addition #3 — no un-anchored enablement).
        Returns the new seq. There is deliberately NO update/delete method."""
        with self._lock:
            prior = self._current_state_unlocked(policy_id)
            src = prior if prior is not None else PolicyState.PROPOSED
            if not is_legal_transition(src, new_state):
                raise IllegalTransitionError(f"{src.value} -> {new_state.value} is not permitted")
            required = _required_principals(src, new_state)
            if not approval.meets(required):
                raise PrivilegedOperationError(
                    f"{src.value} -> {new_state.value} requires {required} distinct governance "
                    f"principal(s) + purpose/rationale/operation_id; got "
                    f"{sorted(approval.distinct_principals)}"
                )
            if new_state is PolicyState.ENABLED:
                missing = [
                    n for n, v in (
                        ("calibration_result_ref", calibration_result_ref),
                        ("pinned_set_version", pinned_set_version),
                        ("detector_identity", detector_identity),
                    ) if not v
                ]
                if missing:
                    raise PrivilegedOperationError(
                        f"enablement requires non-null {missing} — no un-anchored ENABLED grant"
                    )
                # gap-1: the anchors must reference a PERSISTED PASS — a non-null but FABRICATED
                # reference cannot enable. Bind mechanically to a recorded, matching calibration_pass.
                if not self._pass_exists_unlocked(
                    str(calibration_result_ref), policy_id, str(pinned_set_version),
                    str(detector_identity),
                ):
                    raise PrivilegedOperationError(
                        f"no recorded passing calibration matches ref={calibration_result_ref!r} for "
                        f"({policy_id}, set={pinned_set_version}, detector={detector_identity}) — "
                        "enablement must bind to a persisted PASS, not an opaque reference"
                    )
            principals_json = json.dumps(sorted(approval.distinct_principals))
            prev_hash = self._head_hash_unlocked()
            fields = {
                "policy_id": policy_id,
                "prior_state": prior.value if prior is not None else None,
                "new_state": new_state.value,
                "calibration_result_ref": calibration_result_ref,
                "pinned_set_version": pinned_set_version,
                "detector_identity": detector_identity,
                "principals": principals_json, "purpose": approval.purpose,
                "rationale": approval.rationale, "operation_id": approval.operation_id,
                "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            cur = self._conn().execute(
                "INSERT INTO tier_transition_chain "
                "(policy_id, prior_state, new_state, calibration_result_ref, pinned_set_version,"
                " detector_identity, principals, purpose, rationale, operation_id, added_at,"
                " prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (policy_id, fields["prior_state"], new_state.value, calibration_result_ref,
                 pinned_set_version, detector_identity, principals_json, approval.purpose,
                 approval.rationale, approval.operation_id, fields["added_at"], prev_hash,
                 record_hash),
            )
            return int(cur.lastrowid or 0)

    def record_calibration_pass(
        self,
        calibration_result_ref: str,
        *,
        policy_id: str,
        pinned_set_version: str,
        detector_identity: str,
        set_id: str = "default",
    ) -> None:
        """Persist the FACTUAL attestation that a calibration ran and PASSED for this
        (policy, SET, set-head/oracle-version, detector identity). Written by the calibration flow
        AFTER a real ``calibrate()`` returned passed=True — never on a FAIL. ``ratify_enable`` ->
        ENABLED is gated on a matching row (gap-1). ``pinned_set_version`` is the ``set_head(set_id)``
        at calibration time — the SCOPED oracle head enforcement later compares against (close-3).
        Idempotent by ref (INSERT OR IGNORE)."""
        with self._lock:
            self._conn().execute(
                "INSERT OR IGNORE INTO calibration_pass "
                "(calibration_result_ref, policy_id, set_id, pinned_set_version, detector_identity,"
                " passed_at) VALUES (?,?,?,?,?,?)",
                (calibration_result_ref, policy_id, set_id, pinned_set_version, detector_identity,
                 self._clock()),
            )

    def current_attestation(self, policy_id: str) -> tuple[str, str, str] | None:
        """The ``(set_id, oracle_head, detector_identity)`` the policy's CURRENT calibration was
        bound to — or None if the policy is not ENABLED (only an ENABLED policy enforces). Fails
        CLOSED on a broken chain. The gatekeeper compares ``oracle_head`` to the live
        ``set_head(set_id)`` (a mismatch means the set's membership changed since calibration ->
        transient UNATTESTABLE; close-3, scoped) AND compares ``detector_identity`` to the 4-tuple
        identity of the detector about to run (a mismatch means the detector's build / host closure /
        image / eval profile drifted since calibration -> the transitive-spoof close, on the LIVE
        path; close-2). Returning the identity is what lets the live path honour the identity.py
        invariant symmetrically with the signed-snapshot fallback."""
        if not self.verify_chain():
            raise ChainIntegrityError("tier-transition chain failed verification — refusing to read")
        row = self._conn().execute(
            "SELECT new_state, calibration_result_ref FROM tier_transition_chain WHERE policy_id=? "
            "ORDER BY seq DESC LIMIT 1", (policy_id,)
        ).fetchone()
        if row is None or row["new_state"] != PolicyState.ENABLED.value:
            return None
        prow = self._conn().execute(
            "SELECT set_id, pinned_set_version, detector_identity FROM calibration_pass "
            "WHERE calibration_result_ref=? AND policy_id=? LIMIT 1",
            (row["calibration_result_ref"], policy_id)
        ).fetchone()
        if prow is None:
            return None
        return (str(prow["set_id"]), str(prow["pinned_set_version"]), str(prow["detector_identity"]))

    def _pass_exists_unlocked(
        self, calibration_result_ref: str, policy_id: str, pinned_set_version: str,
        detector_identity: str,
    ) -> bool:
        row = self._conn().execute(
            "SELECT 1 FROM calibration_pass WHERE calibration_result_ref=? AND policy_id=? "
            "AND pinned_set_version=? AND detector_identity=? LIMIT 1",
            (calibration_result_ref, policy_id, pinned_set_version, detector_identity),
        ).fetchone()
        return row is not None

    def _head_hash_unlocked(self) -> str:
        row = self._conn().execute(
            "SELECT record_hash FROM tier_transition_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return GENESIS_HASH if row is None else str(row["record_hash"])

    def _current_state_unlocked(self, policy_id: str) -> PolicyState | None:
        row = self._conn().execute(
            "SELECT new_state FROM tier_transition_chain WHERE policy_id=? ORDER BY seq DESC LIMIT 1",
            (policy_id,),
        ).fetchone()
        return None if row is None else PolicyState(row["new_state"])

    def verify_chain(self) -> bool:
        """Recompute the whole chain AND replay per-policy prior-state continuity + legal edges.
        False if any record was edited/removed/reordered OR a policy's prior_state does not match
        its previous new_state OR an illegal edge slipped in (belt-and-braces: transition() enforces
        edges at write time; this re-checks against direct-DB tampering)."""
        prev = GENESIS_HASH
        last_state: dict[str, PolicyState] = {}
        for row in self._conn().execute("SELECT * FROM tier_transition_chain ORDER BY seq ASC"):
            fields = {
                "policy_id": row["policy_id"], "prior_state": row["prior_state"],
                "new_state": row["new_state"],
                "calibration_result_ref": row["calibration_result_ref"],
                "pinned_set_version": row["pinned_set_version"],
                "detector_identity": row["detector_identity"], "principals": row["principals"],
                "purpose": row["purpose"], "rationale": row["rationale"],
                "operation_id": row["operation_id"], "added_at": row["added_at"],
            }
            if row["prev_hash"] != prev or row["record_hash"] != chain_hash(prev, _digest_fields(fields)):
                return False
            pid = str(row["policy_id"])
            prior = None if row["prior_state"] is None else PolicyState(row["prior_state"])
            # continuity: a policy's recorded prior_state must equal its last seen new_state
            # (or None only on its first record).
            if prior != last_state.get(pid):
                return False
            src = prior if prior is not None else PolicyState.PROPOSED
            dst = PolicyState(row["new_state"])
            if not is_legal_transition(src, dst):
                return False
            last_state[pid] = dst
            prev = str(row["record_hash"])
        return True

    def current_state(self, policy_id: str) -> PolicyState | None:
        """The current tier of ``policy_id`` (head of its replayed sub-chain), or None if the
        policy has no records. Fails CLOSED: a broken chain raises rather than return a tier that
        may have been tampered — the caller (gatekeeper) maps a raise to a blocking decision."""
        if not self.verify_chain():
            raise ChainIntegrityError("tier-transition chain failed verification — refusing to read")
        return self._current_state_unlocked(policy_id)

    def head_hash(self) -> str:
        """The current chain head — pinned into the signed snapshot (survivable fallback)."""
        return self._head_hash_unlocked()

    def record_count(self) -> int:
        return int(
            self._conn().execute("SELECT COUNT(*) AS n FROM tier_transition_chain").fetchone()["n"]
        )


__all__ = [
    "PolicyStore",
    "PrivilegedOperationError",
    "IllegalTransitionError",
    "ChainIntegrityError",
]
