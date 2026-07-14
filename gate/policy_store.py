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
from gate.attestation import IDENTITY_CONTRACT_VERSION
from gate.authority import GovernanceApproval
from gate.policy_state import PolicyState, is_legal_transition, is_weakening


class PrivilegedOperationError(PermissionError):
    """A tier transition was attempted without sufficient governance approval (or missing the
    anchors an enablement requires)."""


class IllegalTransitionError(ValueError):
    """A (src -> dst) tier transition that the state machine does not permit."""


class ActiveCalibrationIntentExists(RuntimeError):
    """3.5 S3-completion CP4: enter_calibrating was called for a policy that already has an active
    (pending|dispatched) re-calibration intent — an explicit refusal, not a raw DB-unique-constraint
    violation. Re-entry follows the lifecycle: exit CALIBRATING (which supersedes the intent atomically),
    then re-enter."""


class FailedChurnNotCleared(RuntimeError):
    """3.5 S3-completion CP4: enter_calibrating was called for a policy with an un-cleared ``failed_churn``
    intent. ``failed_churn`` is a BLOCKING terminal (the policy never converged) — a human must
    ``clear_failed_churn`` (governance-gated) before the policy can re-enter automatic calibration. The
    partial-unique index does NOT cover terminal rows, so this guard is enforced explicitly."""


class ChainIntegrityError(RuntimeError):
    """The tier-transition chain failed verification — a record was edited/removed/reordered, or a
    per-policy prior-state continuity / legal-edge invariant was violated."""


class ReAttestConflict(RuntimeError):
    """The restore CAS lost: the policy-evidence head moved between the controller's read and the
    atomic re-attest append (a concurrent human transition or another re-attest). The restore
    controller re-reads and retries; it NEVER forces the append (that would re-enforce a policy a
    human may have just demoted)."""


_REATTEST_MINT = object()  # module-private mint sentinel — the grant constructor refuses any other key


class _ReAttestGrant:
    """A CALL-PATH marker that a re-attestation is entering the store THROUGH the RestoreController —
    NOT an authorization control. Its constructor refuses any key but the module-private
    ``_REATTEST_MINT``, so it cannot be minted ACCIDENTALLY elsewhere in the process, and the structural
    no-bypass test asserts the RestoreController is the ONLY caller that mints one. Be honest about what
    that buys: it is a trusted-process CALL-PATH CONVENTION — a co-resident, adversarial in-process caller
    can read the sentinel and mint a grant, so possessing the grant proves call-path, not authority
    (isinstance/capability ≠ authz). The load-bearing teeth are ``reattest``'s MANDATORY
    ``expect_policy_head`` + ``expect_authorized_subject``, checked atomically against the hash chain —
    themselves a concurrency + same-subject CONTINUITY control (replayable, so also not authorization).
    The REAL authorization is an authenticated service/process boundary in front of the store, which is
    deploy-tier (see ARCHITECTURE.md residual: in-process trust)."""

    __slots__ = ()

    def __init__(self, mint: object) -> None:
        if mint is not _REATTEST_MINT:
            raise TypeError("_ReAttestGrant cannot be constructed outside gate.policy_store")


def _mint_reattest_grant() -> _ReAttestGrant:
    """The ONE legitimate mint of a re-attest call-path marker. Module-private; the structural no-bypass
    test asserts ``gate.restore_controller`` is its only caller in the gate tree. Minting one is not an
    authorization — see ``_ReAttestGrant`` for the honest hierarchy (call-path convention → mandatory
    chain-checked expectations → deploy-tier service boundary)."""
    return _ReAttestGrant(_REATTEST_MINT)


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
    set_id                 TEXT,               -- S3 ckpt4-fix2c: REQUIRED for ->ENABLED — the oracle SET the
                                               -- pass is bound to, IN the hash + replay-matched, so a direct
                                               -- edit of the unchained pass.set_id can't repoint enforcement.
    pinned_set_version     TEXT,               -- REQUIRED for -> ENABLED: the CalibrationSet head
    detector_identity      TEXT,               -- REQUIRED for -> ENABLED: which detector was calibrated
    identity_contract_version INTEGER,         -- S3 ckpt4-fix: the ICV the subject was composed under, IN
                                               -- the hash (tamper-evident). REQUIRED for ->ENABLED / re-attest;
                                               -- verify_chain replays each record against ITS OWN recorded ICV
                                               -- (historical integrity); CURRENT enforcement requires it to
                                               -- equal the process ICV (old evidence inadmissible now).
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
    identity_contract_version INTEGER NOT NULL,  -- S3 ckpt4-fix: the ICV the subject identity was composed
                                                 -- under; enable/reattest EXACT-MATCH the current ICV, so a
                                                 -- pass from another identity contract cannot enable.
    passed_at              REAL NOT NULL
);
-- 3.5 S3-completion CP4 (liveness): the RE-CALIBRATION INTENT for a CALIBRATING policy. Created ATOMICALLY
-- with the CALIBRATING tier transition (enter_calibrating, one BEGIN IMMEDIATE), because
-- enabled_policies_for_set is ENABLED-only so the relay would otherwise never re-trigger a CALIBRATING
-- policy (it would get safely-but-stuck). The intent carries model-(b) ROUTING inputs (WHAT to run) — NOT a
-- measured subject: at CALIBRATING entry no subject has been measured yet, so a subject here would be
-- declared-not-measured. detector_id is a resolvable REGISTRY NAME; the expected_*_digest columns are the
-- policy digests the worker VERIFIES its boot-injected trust/guard/profile objects against (reject before
-- calibrating on mismatch). produce_candidate_pass MEASURES the four-tuple itself; the intent is a durable
-- target + expected-policy constraint consumed by the trusted composition root, NOT self-routable.
--
-- SPLIT GENERATIONS (board D1 ruling): a stale-overwrite hazard exists if a single coordinate serves both
-- routing (changes on advance) and fencing. So: ``policy_generation`` = the POLICY tier-chain head captured
-- at CALIBRATING (fences a policy transition); ``target_revision`` = a MONOTONIC advance counter (fences a
-- stale oracle-head advance); ``target_head`` = the oracle head to seal+calibrate at (routing). A distinct
-- oracle-head advance is ONE in-place CAS UPDATE on the (policy_generation, target_revision, target_head)
-- triple, incrementing target_revision + churn_count; completion fences on the same triple. Generation is
-- FENCING only, never evidence identity (the candidate pass ref is content-bound via _result_ref).
CREATE TABLE IF NOT EXISTS refresh_intent (
    seq                    INTEGER PRIMARY KEY AUTOINCREMENT,
    policy_id              TEXT NOT NULL,
    set_id                 TEXT NOT NULL,   -- routing: which oracle SET to recalibrate against
    target_head            TEXT NOT NULL,   -- routing: the set_head (oracle head) to seal + calibrate at
    policy_generation      TEXT NOT NULL,   -- the POLICY tier-chain head captured at CALIBRATING (fences a policy transition)
    target_revision        INTEGER NOT NULL DEFAULT 0,  -- MONOTONIC advance counter (fences a stale oracle-head advance)
    detector_id            TEXT NOT NULL,   -- routing: resolvable detector REGISTRY NAME
    expected_profile_digest TEXT NOT NULL,  -- the detector profile digest the worker verifies its resolved bundle against
    expected_trust_policy_digest TEXT NOT NULL,  -- the observation-trust policy digest the worker verifies boot-injected trust against
    expected_guard_policy_digest TEXT NOT NULL,  -- the backend-guard policy digest the worker verifies boot-injected guard against
    identity_contract_version INTEGER NOT NULL,  -- routing: the ICV the candidate must compose under
    churn_count            INTEGER NOT NULL DEFAULT 0,  -- cumulative per policy; bumped only on a DISTINCT target_head advance
    status                 TEXT NOT NULL    -- pending|dispatched|satisfied|superseded|failed_detector|failed_churn
        CHECK (status IN ('pending','dispatched','satisfied','superseded','failed_detector','failed_churn')),
    created_at             REAL NOT NULL,
    updated_at             REAL NOT NULL
);
-- ONE active intent per policy (board): a fresh pending/dispatched intent cannot coexist with another.
-- Terminal rows (satisfied/superseded/failed_*) are EXCLUDED, so re-entry is allowed once terminalized.
CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_intent_active
    ON refresh_intent (policy_id) WHERE status IN ('pending','dispatched');
"""


def _digest_fields(row: Mapping[str, object]) -> str:
    """Canonical content digest of a transition record (excludes seq + prev_hash). Same shared
    ``core.chain`` primitive as the C3 ledger + calibration store — one tamper-evidence math."""
    return content_digest(
        {
            "policy_id": row["policy_id"], "prior_state": row["prior_state"],
            "new_state": row["new_state"], "calibration_result_ref": row["calibration_result_ref"],
            "set_id": row["set_id"], "pinned_set_version": row["pinned_set_version"],
            "detector_identity": row["detector_identity"],
            "identity_contract_version": row["identity_contract_version"],
            "principals": row["principals"],
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
        set_id: str | None = None,
        pinned_set_version: str | None = None,
        detector_identity: str | None = None,
        identity_contract_version: int | None = None,
    ) -> int:
        """Append a tier transition, hash-chained. Guarded three ways:
          * the (current -> new_state) edge must be legal (else IllegalTransitionError);
          * ``approval`` must carry enough DISTINCT principals — 2 for weakening, else 1 — plus
            purpose/rationale/operation_id (else PrivilegedOperationError; a RUNTIME caller with no
            principal cannot meet even 1);
          * a transition INTO ENABLED must carry non-null calibration_result_ref + pinned_set_version
            + detector_identity (addition #3 — no un-anchored enablement).
        Returns the new seq. There is deliberately NO update/delete method.

        3.5 S3-completion CP4: ``enter_calibrating`` is the SOLE path into ``CALIBRATING`` — a bare
        CALIBRATING transition is REFUSED here, because it would create a policy with no durable
        re-calibration intent (silently un-reachable by the ENABLED-only relay = safe-but-stuck). And a
        transition OUT of CALIBRATING (e.g. → REJECTED) atomically SUPERSEDES the active intent IN THE SAME
        transaction as the tier append (a separate supersede call would reopen a crash gap: transition
        committed, intent still active → stranded, blocking re-entry)."""
        if new_state is PolicyState.CALIBRATING:
            raise IllegalTransitionError(
                "use enter_calibrating() for a CALIBRATING transition — it atomically creates the "
                "re-calibration recovery intent (CP4 liveness); a bare transition would strand the policy")
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
                        ("set_id", set_id),
                        ("pinned_set_version", pinned_set_version),
                        ("detector_identity", detector_identity),
                        ("identity_contract_version", identity_contract_version),
                    ) if not v
                ]
                if missing:
                    raise PrivilegedOperationError(
                        f"enablement requires non-null {missing} — no un-anchored ENABLED grant"
                    )
                # S3 ckpt4-fix: current enablement requires the ICV to equal the process contract — old
                # evidence is inadmissible NOW (a pass composed under a superseded contract cannot enable).
                if identity_contract_version != IDENTITY_CONTRACT_VERSION:
                    raise PrivilegedOperationError(
                        f"enablement identity_contract_version {identity_contract_version} != current "
                        f"{IDENTITY_CONTRACT_VERSION} — a pass from another identity contract cannot enable"
                    )
                # gap-1: the anchors must reference a PERSISTED PASS — a non-null but FABRICATED
                # reference cannot enable. Bind mechanically to a recorded, matching calibration_pass (under
                # the SAME ICV — the pass and the transition record agree on the identity contract).
                if not self._pass_exists_unlocked(
                    str(calibration_result_ref), policy_id, str(set_id), str(pinned_set_version),
                    str(detector_identity), int(identity_contract_version),
                ):
                    raise PrivilegedOperationError(
                        f"no recorded passing calibration matches ref={calibration_result_ref!r} for "
                        f"({policy_id}, set_id={set_id}, set={pinned_set_version}, "
                        f"detector={detector_identity}) — enablement must bind to a persisted PASS"
                    )
            principals_json = json.dumps(sorted(approval.distinct_principals))
            prev_hash = self._head_hash_unlocked()
            fields = {
                "policy_id": policy_id,
                "prior_state": prior.value if prior is not None else None,
                "new_state": new_state.value,
                "calibration_result_ref": calibration_result_ref,
                "set_id": set_id, "pinned_set_version": pinned_set_version,
                "detector_identity": detector_identity,
                "identity_contract_version": identity_contract_version,
                "principals": principals_json, "purpose": approval.purpose,
                "rationale": approval.rationale, "operation_id": approval.operation_id,
                "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            # a transition OUT of CALIBRATING must terminalize the active re-cal intent ATOMICALLY with the
            # tier append (else a crash between them strands a non-terminal intent that blocks re-entry).
            exiting_calibrating = src is PolicyState.CALIBRATING
            conn = self._conn()
            if exiting_calibrating:
                conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "INSERT INTO tier_transition_chain "
                    "(policy_id, prior_state, new_state, calibration_result_ref, set_id, pinned_set_version,"
                    " detector_identity, identity_contract_version, principals, purpose, rationale,"
                    " operation_id, added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (policy_id, fields["prior_state"], new_state.value, calibration_result_ref,
                     set_id, pinned_set_version, detector_identity, identity_contract_version, principals_json,
                     approval.purpose, approval.rationale, approval.operation_id, fields["added_at"],
                     prev_hash, record_hash),
                )
                seq = int(cur.lastrowid or 0)
                if exiting_calibrating:
                    self._supersede_active_intent_unlocked(policy_id)
                    conn.execute("COMMIT")
            except Exception:
                if exiting_calibrating:
                    conn.execute("ROLLBACK")
                raise
            return seq

    def enter_calibrating(
        self,
        policy_id: str,
        *,
        approval: GovernanceApproval,
        set_id: str,
        pinned_set_version: str,
        detector_id: str,
        expected_profile_digest: str,
        expected_trust_policy_digest: str,
        expected_guard_policy_digest: str,
        identity_contract_version: int,
    ) -> int:
        """3.5 S3-completion CP4 (liveness): the SOLE path into ``CALIBRATING`` — it atomically appends the
        CALIBRATING tier transition AND creates the pending re-calibration recovery intent in ONE explicit
        SQLite transaction (``BEGIN IMMEDIATE`` → tier append → derive new policy head → intent insert →
        ``COMMIT``; rollback BOTH on failure). A CALIBRATING policy is invisible to the ENABLED-only relay,
        so without a durable intent it would be silently un-reachable (safely-but-stuck); the atomic pair
        guarantees a CALIBRATING policy ALWAYS has a recovery intent (a crash cannot commit the transition
        without the intent, or vice versa).

        The intent carries model-(b) ROUTING inputs — NOT a measured subject: ``detector_id`` is a resolvable
        registry name; the ``expected_*_digest`` are the policy digests the worker VERIFIES its boot-injected
        profile/trust/guard objects against (reject before calibrating on mismatch). ``policy_generation`` is
        DERIVED from the appended record_hash (the new policy head), never caller-supplied; ``target_revision``
        starts at 0. A live active (pending/dispatched) intent for this policy is refused with
        ``ActiveCalibrationIntentExists`` (an explicit check, not a raw DB-unique violation) — re-entry
        follows the lifecycle: exit CALIBRATING (which supersedes the intent ATOMICALLY inside
        ``transition``), then re-enter. An un-cleared ``failed_churn`` intent refuses with
        ``FailedChurnNotCleared`` (governance ``clear_failed_churn`` required first). Degenerate-value
        guarded: every routing string non-empty, ICV the exact current int contract."""
        for name, val in (("set_id", set_id), ("pinned_set_version", pinned_set_version),
                          ("detector_id", detector_id),
                          ("expected_profile_digest", expected_profile_digest),
                          ("expected_trust_policy_digest", expected_trust_policy_digest),
                          ("expected_guard_policy_digest", expected_guard_policy_digest)):
            if not isinstance(val, str) or val == "":
                raise PrivilegedOperationError(
                    f"enter_calibrating requires a non-empty {name} routing input — an intent with a null "
                    "routing coordinate is unroutable")
        if type(identity_contract_version) is not int or identity_contract_version != IDENTITY_CONTRACT_VERSION:
            raise PrivilegedOperationError(
                f"enter_calibrating requires identity_contract_version == {IDENTITY_CONTRACT_VERSION} "
                "(exact int, not bool/str) — a routing ICV under another contract cannot calibrate")
        with self._lock:
            prior = self._current_state_unlocked(policy_id)
            src = prior if prior is not None else PolicyState.PROPOSED
            if not is_legal_transition(src, PolicyState.CALIBRATING):
                raise IllegalTransitionError(f"{src.value} -> calibrating is not permitted")
            required = _required_principals(src, PolicyState.CALIBRATING)
            if not approval.meets(required):
                raise PrivilegedOperationError(
                    f"{src.value} -> calibrating requires {required} distinct governance principal(s) + "
                    f"purpose/rationale/operation_id; got {sorted(approval.distinct_principals)}")
            if self._active_intent_unlocked(policy_id) is not None:
                raise ActiveCalibrationIntentExists(
                    f"{policy_id} already has an active (pending/dispatched) re-calibration intent — "
                    "exit CALIBRATING (which supersedes it) before re-entering")
            if self._has_failed_churn_unlocked(policy_id):
                raise FailedChurnNotCleared(
                    f"{policy_id} has an un-cleared failed_churn intent — a human must clear_failed_churn "
                    "(governance-gated) before the policy can re-enter automatic calibration")
            # the CALIBRATING tier record — BYTE-IDENTICAL to transition(CALIBRATING, pinned_set_version=..):
            # routing lives on the INTENT, and the tier row's ``detector_identity`` is the MEASURED subject
            # (absent until ENABLED), so it stays None here.
            principals_json = json.dumps(sorted(approval.distinct_principals))
            prev_hash = self._head_hash_unlocked()
            added_at = self._clock()
            fields = {
                "policy_id": policy_id,
                "prior_state": prior.value if prior is not None else None,
                "new_state": PolicyState.CALIBRATING.value,
                "calibration_result_ref": None, "set_id": None, "pinned_set_version": pinned_set_version,
                "detector_identity": None, "identity_contract_version": None,
                "principals": principals_json, "purpose": approval.purpose,
                "rationale": approval.rationale, "operation_id": approval.operation_id, "added_at": added_at,
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                cur = conn.execute(
                    "INSERT INTO tier_transition_chain "
                    "(policy_id, prior_state, new_state, calibration_result_ref, set_id, pinned_set_version,"
                    " detector_identity, identity_contract_version, principals, purpose, rationale,"
                    " operation_id, added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (policy_id, fields["prior_state"], PolicyState.CALIBRATING.value, None, None,
                     pinned_set_version, None, None, principals_json, approval.purpose, approval.rationale,
                     approval.operation_id, added_at, prev_hash, record_hash),
                )
                seq = int(cur.lastrowid or 0)
                # policy_generation = the NEW policy head (the record_hash just appended) — DERIVED, never
                # passed; target_head = the oracle head to seal + calibrate at; target_revision starts at 0.
                conn.execute(
                    "INSERT INTO refresh_intent (policy_id, set_id, target_head, policy_generation,"
                    " target_revision, detector_id, expected_profile_digest, expected_trust_policy_digest,"
                    " expected_guard_policy_digest, identity_contract_version, churn_count, status,"
                    " created_at, updated_at) VALUES (?,?,?,?,0,?,?,?,?,?,0,'pending',?,?)",
                    (policy_id, set_id, pinned_set_version, record_hash, detector_id, expected_profile_digest,
                     expected_trust_policy_digest, expected_guard_policy_digest, identity_contract_version,
                     added_at, added_at),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            return seq

    def _active_intent_unlocked(self, policy_id: str) -> sqlite3.Row | None:
        """The single active (pending|dispatched) refresh_intent row for ``policy_id``, or None. Terminal
        rows (satisfied/superseded/failed_detector/failed_churn) are EXCLUDED, so re-entry is allowed once
        the prior intent is terminalized. The partial unique index guarantees at most one."""
        row: sqlite3.Row | None = self._conn().execute(
            "SELECT * FROM refresh_intent WHERE policy_id=? AND status IN ('pending','dispatched') "
            "ORDER BY seq DESC LIMIT 1", (policy_id,)
        ).fetchone()
        return row

    def active_intent(self, policy_id: str) -> sqlite3.Row | None:
        """The current active (pending|dispatched) re-calibration intent row for ``policy_id``, or None."""
        with self._lock:
            return self._active_intent_unlocked(policy_id)

    def _supersede_active_intent_unlocked(self, policy_id: str) -> int:
        """Terminalize the active intent (if any) to ``superseded``. Returns the number of rows affected
        (0 or 1). Used for LIFECYCLE EXIT / human recovery, NOT ordinary head advancement (which updates the
        row in place). Callers already hold ``self._lock`` (and may be mid-transaction)."""
        cur = self._conn().execute(
            "UPDATE refresh_intent SET status='superseded', updated_at=? "
            "WHERE policy_id=? AND status IN ('pending','dispatched')",
            (self._clock(), policy_id),
        )
        return int(cur.rowcount or 0)

    # NO standalone public supersede: a bare supersede could leave a policy CALIBRATING with NO active
    # intent (safe-but-stuck). Lifecycle exit supersedes ONLY inside the transition transaction
    # (``_supersede_active_intent_unlocked``, called by ``transition`` when leaving CALIBRATING).

    def mark_intent_satisfied(
        self, policy_id: str, *, policy_generation: str, target_revision: int, target_head: str,
    ) -> bool:
        """Completion CAS: terminalize the active intent to ``satisfied`` ONLY if it still matches the
        ``(policy_generation, target_revision, target_head)`` the caller measured under. If the triple
        advanced (a churn advance bumped the revision, or a policy transition moved the generation) the
        UPDATE matches 0 rows and no-ops → the caller classifies it superseded, never a failure. Returns
        True iff the intent was satisfied."""
        return self._cas_terminalize(policy_id, "satisfied", policy_generation, target_revision, target_head)

    def mark_intent_failed_detector(
        self, policy_id: str, *, policy_generation: str, target_revision: int, target_head: str,
    ) -> bool:
        """Terminalize the active intent to ``failed_detector`` under the SAME triple CAS as satisfaction —
        a stale worker cannot terminalize a NEWER target. A DETERMINISTIC calibration failure on the WORKER
        path (Slice C); the policy STAYS CALIBRATING, and ``failed_detector`` does NOT block a new auto-intent
        (a set change can legitimately re-trigger). Returns True iff this exact target was terminalized."""
        return self._cas_terminalize(
            policy_id, "failed_detector", policy_generation, target_revision, target_head)

    def mark_intent_failed_churn(
        self, policy_id: str, *, policy_generation: str, target_revision: int, target_head: str,
    ) -> bool:
        """Terminalize the active intent to ``failed_churn`` under the SAME triple CAS — the cumulative churn
        budget was exhausted (the policy never converged). The policy STAYS CALIBRATING (SKIP_NEUTRAL) + an
        out-of-band alert; NOT unattestable. ``failed_churn`` BLOCKS a new auto-intent (see
        ``has_failed_churn``) until a human ``clear_failed_churn``. (``advance_intent`` also transitions to
        ``failed_churn`` atomically when the bound is exceeded; this is the standalone primitive.)"""
        return self._cas_terminalize(
            policy_id, "failed_churn", policy_generation, target_revision, target_head)

    def _cas_terminalize(
        self, policy_id: str, status: str, policy_generation: str, target_revision: int, target_head: str,
    ) -> bool:
        with self._lock:
            cur = self._conn().execute(
                "UPDATE refresh_intent SET status=?, updated_at=? "
                "WHERE policy_id=? AND status IN ('pending','dispatched') AND policy_generation=? "
                "AND target_revision=? AND target_head=?",
                (status, self._clock(), policy_id, policy_generation, target_revision, target_head),
            )
            return bool(cur.rowcount)

    def advance_intent(
        self, policy_id: str, *, expect_policy_generation: str, expect_target_revision: int,
        expect_target_head: str, new_target_head: str, churn_bound: int,
    ) -> str:
        """Churn-A DISTINCT oracle-head advance: an IN-PLACE CAS on the
        ``(policy_generation, target_revision, target_head)`` triple. ``new_target_head`` MUST be distinct
        from ``expect_target_head`` (a same-head advance does not churn — rejected with ``ValueError``). If
        the fence no longer matches (a stale/delayed advance after the row moved on) → ``"no_op"`` (no
        double-increment, no stale overwrite). Otherwise: if incrementing would exceed ``churn_bound`` the
        intent ATOMICALLY transitions to ``failed_churn`` (the policy never converged) → ``"failed_churn"``;
        else ``target_head`` is set, ``target_revision`` + ``churn_count`` increment → ``"advanced"``. The
        read + conditional write are serialised under the single store lock."""
        if new_target_head == expect_target_head:
            raise ValueError(
                "advance_intent requires a DISTINCT new_target_head — a same-head advance does not churn")
        if type(churn_bound) is not int:
            raise ValueError("churn_bound must be an int")
        with self._lock:
            row = self._conn().execute(
                "SELECT churn_count FROM refresh_intent WHERE policy_id=? AND status IN "
                "('pending','dispatched') AND policy_generation=? AND target_revision=? AND target_head=?",
                (policy_id, expect_policy_generation, expect_target_revision, expect_target_head),
            ).fetchone()
            if row is None:
                return "no_op"  # the fence no longer matches — a newer advance already landed
            now = self._clock()
            if int(row["churn_count"]) + 1 > churn_bound:
                self._conn().execute(
                    "UPDATE refresh_intent SET status='failed_churn', updated_at=? "
                    "WHERE policy_id=? AND status IN ('pending','dispatched') AND policy_generation=? "
                    "AND target_revision=? AND target_head=?",
                    (now, policy_id, expect_policy_generation, expect_target_revision, expect_target_head),
                )
                return "failed_churn"
            self._conn().execute(
                "UPDATE refresh_intent SET target_head=?, target_revision=target_revision+1, "
                "churn_count=churn_count+1, updated_at=? "
                "WHERE policy_id=? AND status IN ('pending','dispatched') AND policy_generation=? "
                "AND target_revision=? AND target_head=?",
                (new_target_head, now, policy_id, expect_policy_generation, expect_target_revision,
                 expect_target_head),
            )
            return "advanced"

    def _has_failed_churn_unlocked(self, policy_id: str) -> bool:
        return self._conn().execute(
            "SELECT 1 FROM refresh_intent WHERE policy_id=? AND status='failed_churn' LIMIT 1",
            (policy_id,),
        ).fetchone() is not None

    def has_failed_churn(self, policy_id: str) -> bool:
        """The EXPLICIT failed-churn guard (the partial-unique index does NOT cover terminal rows): a policy
        with a ``failed_churn`` intent must NOT receive a fresh auto-intent until a human clears it. The
        relay checks this before creating a new CALIBRATING intent; ``enter_calibrating`` enforces it too."""
        with self._lock:
            return self._has_failed_churn_unlocked(policy_id)

    def clear_failed_churn(self, policy_id: str, *, approval: GovernanceApproval) -> int:
        """Human recovery (GOVERNANCE-gated): clear the ``failed_churn`` block (terminalize those rows to
        ``superseded``) so the policy can re-enter automatic calibration. Requires a ``GovernanceApproval``
        (≥1 distinct principal + purpose/rationale/operation_id) — clearing a never-converged block is a
        deliberate human act, not an unrestricted public update. Returns rows cleared."""
        if not approval.meets(1):
            raise PrivilegedOperationError(
                "clear_failed_churn requires a GovernanceApproval (≥1 distinct principal + "
                "purpose/rationale/operation_id) — it is a deliberate human recovery, not a bare update")
        with self._lock:
            cur = self._conn().execute(
                "UPDATE refresh_intent SET status='superseded', updated_at=? "
                "WHERE policy_id=? AND status='failed_churn'",
                (self._clock(), policy_id),
            )
            return int(cur.rowcount or 0)

    def reattest(
        self,
        policy_id: str,
        *,
        grant: _ReAttestGrant,
        calibration_result_ref: str,
        set_id: str,
        pinned_set_version: str,
        detector_identity: str,
        identity_contract_version: int,
        job_id: str,
        nonce: str,
        expect_policy_head: str,
        expect_authorized_context: tuple[str, str, int],
    ) -> int:
        """3.5 job-1: append a RE_ATTESTATION record — an EVIDENCE refresh, NOT a state transition.

        Represented with zero schema/digest change as a ``prior_state == new_state == ENABLED`` record
        (ENABLED->ENABLED is not a legal ``_TRANSITIONS`` edge, so the shape is unambiguous). It advances
        which persisted ``calibration_pass`` justifies the UNCHANGED ENABLED tier — the policy was
        ENABLED, is ENABLED, stays ENABLED; only the evidence backing that disposition moves forward to a
        pass bound to the CURRENT oracle head. Because it is not in ``_TRANSITIONS``/``is_weakening``, the
        closed-enum fail-closed disposition proof is untouched (board D1). This is the ONLY method that
        appends an ENABLED->ENABLED record; ``transition`` still refuses it (a re-attest cannot be smuggled
        through the general governance path). The restore controller is handed a capability restricted to
        THIS method (measurement->governance separation at the capability layer, board amendment 1).

        Carries NO governance principal (principals=[]) — a re-attest is measurement-driven evidence, not a
        governance act; ``job_id``/``nonce`` record the signed measurement's provenance + idempotency.
        gap-1 still holds: the ref must resolve to a persisted matching ``calibration_pass`` (a fabricated
        ref cannot re-attest, exactly as it cannot enable). Requires the policy to currently be ENABLED.

        Capability + expectations (honest hierarchy — see ``_ReAttestGrant``): a ``_ReAttestGrant`` is
        required, which is a trusted-process CALL-PATH convention (accidental-misuse tripwire, NOT authz);
        the load-bearing controls are the MANDATORY ``expect_policy_head`` + ``expect_authorized_context``,
        checked atomically against the chain under this lock — a concurrency + same-CONTEXT CONTINUITY
        guarantee, so a re-attest can never land after a concurrent human DEMOTE or an authorized-context
        change (subject OR set). ``expect_authorized_context`` is the WHOLE ``(set_id, subject, ICV)``
        3-tuple (board refinement): pinning it atomically closes the same-subject/different-set rebind — a
        measurement calibrated against set Y cannot re-attest a policy authorized against set X even when
        the subject matches. Real authorization is an authenticated store boundary (deploy-tier)."""
        if not isinstance(grant, _ReAttestGrant):
            raise PrivilegedOperationError(
                "re-attestation must be called through the RestoreController's grant (a "
                "_ReAttestGrant) — this is a call-path convention that trips accidental low-level use, "
                "not an authorization boundary (that is a deploy-tier store front)"
            )
        with self._lock:
            prior = self._current_state_unlocked(policy_id)
            if prior is not PolicyState.ENABLED:
                raise IllegalTransitionError(
                    f"re-attestation requires the policy to be ENABLED; {policy_id} is "
                    f"{prior.value if prior else 'absent'}"
                )
            # board D2 + v5-P1c: the policy-evidence-head CAS is ATOMIC with the append (both under the
            # lock) and MANDATORY — no None opt-out, not even for direct/test callers — else a re-attest
            # could land AFTER a concurrent human DEMOTE (or another re-attest) that moved this policy's
            # head, re-enforcing a policy a human just moved to ADVISORY. This is the load-bearing tooth
            # (the grant is only a call-path convention).
            if self._policy_head_unlocked(policy_id) != expect_policy_head:
                raise ReAttestConflict(
                    f"policy-evidence head for {policy_id} moved since the restore CAS read it "
                    f"(expected {expect_policy_head[:12]}..) — aborting re-attestation, will retry"
                )
            # v4 P1-b + v5-P1c + S3 restore-continuity: the AUTHORIZED-CONTEXT check is ATOMIC with the head
            # CAS (same lock) and MANDATORY — else a concurrent governance change of the authorized target
            # (subject A->B OR set X->Y) between the restore's read and this append would let a re-attest for
            # the stale context land. The WHOLE (set_id, subject, ICV) 3-tuple is pinned as one unit (board
            # refinement) so no caller can check part of the authorization context; a set rebind is caught
            # here exactly as a subject rebind is.
            if self._current_authorized_context_unlocked(policy_id) != expect_authorized_context:
                raise ReAttestConflict(
                    f"authorized context for {policy_id} moved since the restore CAS read it "
                    f"(expected {expect_authorized_context!r}) — aborting re-attestation, will retry"
                )
            # S3 ckpt4-fix: a re-attest is CURRENT enforcement -> its ICV must equal the process contract
            # (old evidence is inadmissible now), and the persisted PASS must exist under that SAME ICV.
            if identity_contract_version != IDENTITY_CONTRACT_VERSION:
                raise PrivilegedOperationError(
                    f"re-attestation identity_contract_version {identity_contract_version} != current "
                    f"{IDENTITY_CONTRACT_VERSION} — a pass from another identity contract cannot re-attest"
                )
            if not self._pass_exists_unlocked(
                calibration_result_ref, policy_id, set_id, pinned_set_version, detector_identity,
                identity_contract_version,
            ):
                raise PrivilegedOperationError(
                    f"no recorded passing calibration matches ref={calibration_result_ref!r} for "
                    f"({policy_id}, set_id={set_id}, set={pinned_set_version}, "
                    f"detector={detector_identity}) — a re-attestation must bind to a persisted PASS"
                )
            prev_hash = self._head_hash_unlocked()
            fields = {
                "policy_id": policy_id, "prior_state": PolicyState.ENABLED.value,
                "new_state": PolicyState.ENABLED.value,
                "calibration_result_ref": calibration_result_ref,
                "set_id": set_id, "pinned_set_version": pinned_set_version,
                "detector_identity": detector_identity,
                "identity_contract_version": identity_contract_version,
                "principals": "[]", "purpose": "re-attestation", "rationale": job_id,
                "operation_id": nonce, "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            cur = self._conn().execute(
                "INSERT INTO tier_transition_chain "
                "(policy_id, prior_state, new_state, calibration_result_ref, set_id, pinned_set_version,"
                " detector_identity, identity_contract_version, principals, purpose, rationale,"
                " operation_id, added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (policy_id, PolicyState.ENABLED.value, PolicyState.ENABLED.value,
                 calibration_result_ref, set_id, pinned_set_version, detector_identity,
                 identity_contract_version, "[]",
                 "re-attestation", job_id, nonce, fields["added_at"], prev_hash, record_hash),
            )
            return int(cur.lastrowid or 0)

    def enabled_policies_for_set(self, set_id: str) -> list[tuple[str, str]]:
        """3.5 job-1: the ENABLED policies whose CURRENT calibration is bound to ``set_id`` — as
        ``(policy_id, detector_identity)`` pairs. The re-cal relay fans a set's outbox trigger out to
        exactly these. Fails CLOSED on a broken chain (via current_attestation)."""
        out: list[tuple[str, str]] = []
        for row in self._conn().execute(
            "SELECT DISTINCT policy_id FROM tier_transition_chain"
        ).fetchall():
            pid = str(row["policy_id"])
            att = self.current_attestation(pid)  # (set_id, oracle_head, detector_identity) if ENABLED
            if att is not None and att[0] == set_id:
                out.append((pid, att[2]))
        return out

    def policy_head(self, policy_id: str) -> str:
        """3.5 job-1: the POLICY-SPECIFIC evidence head — the record_hash of this policy's latest
        record (enable / transition / re-attest), or GENESIS if it has none. The restore controller's
        CAS pins this (not the global chain head) so a re-attest aborts on a concurrent change to THIS
        policy (e.g. a human DEMOTE) WITHOUT needless retries from unrelated policies' appends (board
        amendment 3)."""
        return self._policy_head_unlocked(policy_id)

    def record_calibration_pass(
        self,
        calibration_result_ref: str,
        *,
        policy_id: str,
        pinned_set_version: str,
        detector_identity: str,
        identity_contract_version: int,
        set_id: str = "default",
    ) -> None:
        """Persist the FACTUAL attestation that a calibration ran and PASSED for this
        (policy, SET, set-head/oracle-version, detector identity, IDENTITY CONTRACT VERSION). Written by
        the calibration flow AFTER a real ``calibrate()`` returned passed=True — never on a FAIL.
        ``ratify_enable`` -> ENABLED is gated on a matching row (gap-1). ``identity_contract_version`` is the
        ICV the subject identity was composed under (S3 ckpt4-fix); the read paths EXACT-MATCH the current
        ICV, so a pass composed under another contract can never enable. Idempotent for an IDENTICAL row;
        a CONFLICTING metadata re-write under the same ref is REJECTED (S3 ckpt4-fix2b — not silently
        retained), so a ref cannot be rebound to a different (policy/set/version/detector/ICV)."""
        with self._lock:
            existing = self._conn().execute(
                "SELECT policy_id, set_id, pinned_set_version, detector_identity, "
                "identity_contract_version FROM calibration_pass WHERE calibration_result_ref=? LIMIT 1",
                (calibration_result_ref,),
            ).fetchone()
            if existing is not None:
                if (str(existing["policy_id"]), str(existing["set_id"]), str(existing["pinned_set_version"]),
                        str(existing["detector_identity"]), existing["identity_contract_version"]) != (
                        policy_id, set_id, pinned_set_version, detector_identity,
                        identity_contract_version):
                    raise PrivilegedOperationError(
                        f"a DIFFERENT calibration_pass already exists for ref {calibration_result_ref!r} — "
                        "refusing to silently retain conflicting metadata (a ref binds one immutable pass)")
                return  # identical row -> idempotent no-op
            self._conn().execute(
                "INSERT INTO calibration_pass "
                "(calibration_result_ref, policy_id, set_id, pinned_set_version, detector_identity,"
                " identity_contract_version, passed_at) VALUES (?,?,?,?,?,?,?)",
                (calibration_result_ref, policy_id, set_id, pinned_set_version, detector_identity,
                 identity_contract_version, self._clock()),
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
            "SELECT new_state, calibration_result_ref, set_id, pinned_set_version, detector_identity,"
            " identity_contract_version FROM tier_transition_chain WHERE policy_id=? "
            "ORDER BY seq DESC LIMIT 1", (policy_id,)
        ).fetchone()
        if row is None or row["new_state"] != PolicyState.ENABLED.value:
            return None
        # S3 ckpt4-fix2b/2c: the HEAD must be under the CURRENT contract (old evidence inadmissible now), and
        # the pass must exact-match the HASH-CHAINED record's OWN coordinates (ref + set_id + pinned_set_version
        # + detector_identity + ICV) — then we return the TRANSITION-bound values, INCLUDING set_id, not the
        # pass-row values. set_id was the LAST attestation coordinate still read off the mutable, unchained
        # calibration_pass row (ckpt4-fix2c): a direct edit of pass.set_id could repoint which set's drift the
        # gatekeeper checks. Now set_id is hash-chained into the record and returned from it, so that edit
        # cannot change the effective current attestation (and fails the pass exact-match below anyway).
        if row["identity_contract_version"] != IDENTITY_CONTRACT_VERSION:
            return None
        if not self._pass_exists_unlocked(
            str(row["calibration_result_ref"]), policy_id, str(row["set_id"]),
            str(row["pinned_set_version"]), str(row["detector_identity"]), IDENTITY_CONTRACT_VERSION,
        ):
            return None
        return (str(row["set_id"]), str(row["pinned_set_version"]), str(row["detector_identity"]))

    def _current_authorized_context_unlocked(self, policy_id: str) -> tuple[str, str, int] | None:
        """S3 restore-continuity: the FULL authorization context the policy's CURRENT ENABLED calibration
        is bound to — ``(set_id, subject, identity_contract_version)`` — read UNDER THE LOCK (no
        verify_chain; the reattest CAS holds the lock and needs only the current binding). None if the
        policy is not ENABLED or has no bound pass under the current contract. This is the SINGLE atomic
        snapshot the restore CAS pins (board refinement): a caller cannot check the subject while missing
        the set (or vice versa) — the whole 3-tuple moves or none of it does. All values are the
        TRANSITION-bound (hash-chained) coordinates, matched against the persisted pass."""
        row = self._conn().execute(
            "SELECT new_state, calibration_result_ref, set_id, pinned_set_version, detector_identity,"
            " identity_contract_version FROM tier_transition_chain WHERE policy_id=? "
            "ORDER BY seq DESC LIMIT 1", (policy_id,)
        ).fetchone()
        if row is None or row["new_state"] != PolicyState.ENABLED.value:
            return None
        # S3 ckpt4-fix2b/2c: head must be the current contract, and the pass must exact-match ALL of the
        # HASH-CHAINED record's coordinates (INCLUDING set_id); the returned context is the TRANSITION-bound
        # (set_id, subject, ICV).
        if row["identity_contract_version"] != IDENTITY_CONTRACT_VERSION:
            return None
        if not self._pass_exists_unlocked(
            str(row["calibration_result_ref"]), policy_id, str(row["set_id"]),
            str(row["pinned_set_version"]), str(row["detector_identity"]), IDENTITY_CONTRACT_VERSION,
        ):
            return None
        return (str(row["set_id"]), str(row["detector_identity"]), int(row["identity_contract_version"]))

    def current_authorized_context(self, policy_id: str) -> tuple[str, str, int] | None:
        """S3 restore-continuity: the locked, chain-verified read of the authorization context
        ``(set_id, subject, identity_contract_version)`` — what the RestoreController reads ONCE to derive
        every CAS input from a single snapshot (no read-then-read TOCTOU between set and subject). Fails
        CLOSED on a broken chain. ``reattest`` re-checks the SAME 3-tuple atomically under the store lock."""
        if not self.verify_chain():
            raise ChainIntegrityError("tier-transition chain failed verification — refusing to read")
        return self._current_authorized_context_unlocked(policy_id)

    def pass_binding(
        self, calibration_result_ref: str, policy_id: str, pinned_set_version: str,
    ) -> tuple[str, str] | None:
        """v4 P1-a + S3 ckpt4-fix2c: recover BOTH measurement-derived coordinates ``ratify_enable`` needs
        from the persisted pass — ``(detector_identity subject, set_id)`` — so the ENABLED transition binds
        the set_id the RUN calibrated against, NOT a caller-supplied one (mirrors the subject: governance
        chooses WHICH pass to ratify, the store supplies the measured coordinates). None if no pass matches
        under the CURRENT identity contract (a fabricated ref, or a pass from another ICV, cannot enable)."""
        row = self._conn().execute(
            "SELECT detector_identity, set_id FROM calibration_pass WHERE calibration_result_ref=? "
            "AND policy_id=? AND pinned_set_version=? AND identity_contract_version=? LIMIT 1",
            (calibration_result_ref, policy_id, pinned_set_version, IDENTITY_CONTRACT_VERSION),
        ).fetchone()
        return None if row is None else (str(row["detector_identity"]), str(row["set_id"]))

    def subject_for_pass(
        self, calibration_result_ref: str, policy_id: str, pinned_set_version: str,
    ) -> str | None:
        """v4 P1-a: the MEASURED subject identity bound to a persisted calibration_pass (the subject
        coordinate of ``pass_binding``), so ``ratify_enable`` enables the identity the RUN produced, not a
        caller-supplied one. None if no such pass exists under the CURRENT identity contract."""
        binding = self.pass_binding(calibration_result_ref, policy_id, pinned_set_version)
        return None if binding is None else binding[0]

    def _pass_exists_unlocked(
        self, calibration_result_ref: str, policy_id: str, set_id: str, pinned_set_version: str,
        detector_identity: str, identity_contract_version: int,
    ) -> bool:
        """Does a persisted PASS match ALL of (ref, policy, set_id, set-version, subject, ICV)? The ICV is a
        PARAMETER (not the process constant) so the CALLER decides which contract to check against: write
        paths (enable/reattest) pass the CURRENT ICV; ``verify_chain`` replay passes each record's OWN
        recorded ICV (historical integrity — a valid old record is not misread as corruption)."""
        row = self._conn().execute(
            "SELECT 1 FROM calibration_pass WHERE calibration_result_ref=? AND policy_id=? AND set_id=? "
            "AND pinned_set_version=? AND detector_identity=? AND identity_contract_version=? LIMIT 1",
            (calibration_result_ref, policy_id, set_id, pinned_set_version, detector_identity,
             identity_contract_version),
        ).fetchone()
        return row is not None

    def _head_hash_unlocked(self) -> str:
        row = self._conn().execute(
            "SELECT record_hash FROM tier_transition_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return GENESIS_HASH if row is None else str(row["record_hash"])

    def _policy_head_unlocked(self, policy_id: str) -> str:
        """The POLICY-SCOPED evidence head (record_hash of this policy's latest record), or GENESIS.
        The re-attest CAS must compare against THIS, not the global chain head — else an unrelated
        policy's append (which moves the global head but not this policy's) would spuriously fail the
        CAS and block restoration (the normal multi-policy case)."""
        row = self._conn().execute(
            "SELECT record_hash FROM tier_transition_chain WHERE policy_id=? ORDER BY seq DESC LIMIT 1",
            (policy_id,),
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
                "set_id": row["set_id"], "pinned_set_version": row["pinned_set_version"],
                "detector_identity": row["detector_identity"],
                "identity_contract_version": row["identity_contract_version"],
                "principals": row["principals"],
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
            if dst is PolicyState.ENABLED:
                # S3 ckpt4-fix2b: EVERY ->ENABLED record — the INITIAL enable (a legal CALIBRATING->ENABLED)
                # AND a re-attest (ENABLED->ENABLED, the deliberate non-edge, state unchanged) — must bind a
                # persisted calibration_pass matching THIS record's OWN coordinates + RECORDED ICV, so the
                # hash-chained record and its unchained pass row stay LINKED. (Before, only re-attest checked
                # the pass, so tampering the pass beneath an INITIAL enable was undetected.) The pass is
                # replayed against the record's OWN recorded ICV — historical integrity — not the process
                # constant; a valid record from a superseded contract stays verifiable (it just cannot
                # enable/re-attest NOW, which the write-path current-ICV guard enforces separately).
                is_reattest = src is PolicyState.ENABLED
                if not is_reattest and not is_legal_transition(src, dst):
                    return False  # an INITIAL enable must still be a legal edge
                rec_icv = row["identity_contract_version"]
                if type(rec_icv) is not int or not self._pass_exists_unlocked(
                    str(row["calibration_result_ref"]), pid, str(row["set_id"]),
                    str(row["pinned_set_version"]), str(row["detector_identity"]), rec_icv,
                ):
                    return False
                last_state[pid] = PolicyState.ENABLED  # initial enable moves to ENABLED; re-attest stays
            elif not is_legal_transition(src, dst):
                return False
            else:
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
    "ActiveCalibrationIntentExists",
    "FailedChurnNotCleared",
    "ChainIntegrityError",
    "ReAttestConflict",
]
# ``_ReAttestGrant`` / ``_mint_reattest_grant`` are deliberately NOT exported — they are a module-private
# call-path convention (see ``_ReAttestGrant``). The RestoreController imports the mint by its private
# name; the structural no-bypass test asserts it is the only caller.
