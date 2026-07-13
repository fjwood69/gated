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
"""


def _digest_fields(row: Mapping[str, object]) -> str:
    """Canonical content digest of a transition record (excludes seq + prev_hash). Same shared
    ``core.chain`` primitive as the C3 ledger + calibration store — one tamper-evidence math."""
    return content_digest(
        {
            "policy_id": row["policy_id"], "prior_state": row["prior_state"],
            "new_state": row["new_state"], "calibration_result_ref": row["calibration_result_ref"],
            "pinned_set_version": row["pinned_set_version"],
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
                    str(calibration_result_ref), policy_id, str(pinned_set_version),
                    str(detector_identity), int(identity_contract_version),
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
                "identity_contract_version": identity_contract_version,
                "principals": principals_json, "purpose": approval.purpose,
                "rationale": approval.rationale, "operation_id": approval.operation_id,
                "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            cur = self._conn().execute(
                "INSERT INTO tier_transition_chain "
                "(policy_id, prior_state, new_state, calibration_result_ref, pinned_set_version,"
                " detector_identity, identity_contract_version, principals, purpose, rationale,"
                " operation_id, added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (policy_id, fields["prior_state"], new_state.value, calibration_result_ref,
                 pinned_set_version, detector_identity, identity_contract_version, principals_json,
                 approval.purpose, approval.rationale, approval.operation_id, fields["added_at"], prev_hash,
                 record_hash),
            )
            return int(cur.lastrowid or 0)

    def reattest(
        self,
        policy_id: str,
        *,
        grant: _ReAttestGrant,
        calibration_result_ref: str,
        pinned_set_version: str,
        detector_identity: str,
        identity_contract_version: int,
        job_id: str,
        nonce: str,
        expect_policy_head: str,
        expect_authorized_subject: str,
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
        the load-bearing controls are the MANDATORY ``expect_policy_head`` + ``expect_authorized_subject``,
        checked atomically against the chain under this lock — a concurrency + same-subject CONTINUITY
        guarantee, so a re-attest can never land after a concurrent human DEMOTE or an authorized-target
        change. Real authorization is an authenticated store boundary (deploy-tier)."""
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
            # v4 P1-b + v5-P1c: the AUTHORIZED-SUBJECT check is ATOMIC with the head CAS (same lock) and
            # MANDATORY — else a concurrent governance change of the authorized target (A->B) between the
            # restore's read and this append would let a re-attest for the stale subject land. Verify the
            # policy's CURRENT authorized subject still equals what the restore controller verified against.
            if self._current_authorized_subject_unlocked(policy_id) != expect_authorized_subject:
                raise ReAttestConflict(
                    f"authorized subject for {policy_id} moved since the restore CAS read it "
                    f"(expected {expect_authorized_subject!r}) — aborting re-attestation, will retry"
                )
            # S3 ckpt4-fix: a re-attest is CURRENT enforcement -> its ICV must equal the process contract
            # (old evidence is inadmissible now), and the persisted PASS must exist under that SAME ICV.
            if identity_contract_version != IDENTITY_CONTRACT_VERSION:
                raise PrivilegedOperationError(
                    f"re-attestation identity_contract_version {identity_contract_version} != current "
                    f"{IDENTITY_CONTRACT_VERSION} — a pass from another identity contract cannot re-attest"
                )
            if not self._pass_exists_unlocked(
                calibration_result_ref, policy_id, pinned_set_version, detector_identity,
                identity_contract_version,
            ):
                raise PrivilegedOperationError(
                    f"no recorded passing calibration matches ref={calibration_result_ref!r} for "
                    f"({policy_id}, set={pinned_set_version}, detector={detector_identity}) — "
                    "a re-attestation must bind to a persisted PASS, not an opaque reference"
                )
            prev_hash = self._head_hash_unlocked()
            fields = {
                "policy_id": policy_id, "prior_state": PolicyState.ENABLED.value,
                "new_state": PolicyState.ENABLED.value,
                "calibration_result_ref": calibration_result_ref,
                "pinned_set_version": pinned_set_version, "detector_identity": detector_identity,
                "identity_contract_version": identity_contract_version,
                "principals": "[]", "purpose": "re-attestation", "rationale": job_id,
                "operation_id": nonce, "added_at": self._clock(),
            }
            record_hash = chain_hash(prev_hash, _digest_fields(fields))
            cur = self._conn().execute(
                "INSERT INTO tier_transition_chain "
                "(policy_id, prior_state, new_state, calibration_result_ref, pinned_set_version,"
                " detector_identity, identity_contract_version, principals, purpose, rationale,"
                " operation_id, added_at, prev_hash, record_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (policy_id, PolicyState.ENABLED.value, PolicyState.ENABLED.value,
                 calibration_result_ref, pinned_set_version, detector_identity,
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
        ICV, so a pass composed under another contract can never enable. Idempotent by ref
        (INSERT OR IGNORE)."""
        with self._lock:
            self._conn().execute(
                "INSERT OR IGNORE INTO calibration_pass "
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
            "SELECT new_state, calibration_result_ref FROM tier_transition_chain WHERE policy_id=? "
            "ORDER BY seq DESC LIMIT 1", (policy_id,)
        ).fetchone()
        if row is None or row["new_state"] != PolicyState.ENABLED.value:
            return None
        prow = self._conn().execute(
            "SELECT set_id, pinned_set_version, detector_identity FROM calibration_pass "
            "WHERE calibration_result_ref=? AND policy_id=? AND identity_contract_version=? LIMIT 1",
            (row["calibration_result_ref"], policy_id, IDENTITY_CONTRACT_VERSION)
        ).fetchone()
        if prow is None:
            return None
        return (str(prow["set_id"]), str(prow["pinned_set_version"]), str(prow["detector_identity"]))

    def _current_authorized_subject_unlocked(self, policy_id: str) -> str | None:
        """v4 P1-b: the subject identity the policy's CURRENT ENABLED calibration is bound to, read UNDER
        THE LOCK (no verify_chain — the reattest CAS holds the lock and only needs the current binding).
        None if the policy is not ENABLED or has no bound pass. Mirrors ``current_attestation``'s identity
        column, used for the atomic authorized-subject check inside ``reattest``."""
        row = self._conn().execute(
            "SELECT new_state, calibration_result_ref FROM tier_transition_chain WHERE policy_id=? "
            "ORDER BY seq DESC LIMIT 1", (policy_id,)
        ).fetchone()
        if row is None or row["new_state"] != PolicyState.ENABLED.value:
            return None
        prow = self._conn().execute(
            "SELECT detector_identity FROM calibration_pass "
            "WHERE calibration_result_ref=? AND policy_id=? AND identity_contract_version=? LIMIT 1",
            (row["calibration_result_ref"], policy_id, IDENTITY_CONTRACT_VERSION)
        ).fetchone()
        return None if prow is None else str(prow["detector_identity"])

    def subject_for_pass(
        self, calibration_result_ref: str, policy_id: str, pinned_set_version: str,
    ) -> str | None:
        """v4 P1-a: recover the MEASURED subject identity bound to a persisted calibration_pass, so
        ``ratify_enable`` enables the identity the RUN produced, not a caller-supplied one. None if no such
        pass exists under the CURRENT identity contract (a fabricated ref, or a pass composed under another
        ICV, cannot enable — S3 ckpt4-fix)."""
        row = self._conn().execute(
            "SELECT detector_identity FROM calibration_pass WHERE calibration_result_ref=? AND policy_id=? "
            "AND pinned_set_version=? AND identity_contract_version=? LIMIT 1",
            (calibration_result_ref, policy_id, pinned_set_version, IDENTITY_CONTRACT_VERSION),
        ).fetchone()
        return None if row is None else str(row["detector_identity"])

    def _pass_exists_unlocked(
        self, calibration_result_ref: str, policy_id: str, pinned_set_version: str,
        detector_identity: str, identity_contract_version: int,
    ) -> bool:
        """Does a persisted PASS match ALL of (ref, policy, set-version, subject, ICV)? The ICV is a
        PARAMETER (not the process constant) so the CALLER decides which contract to check against: write
        paths (enable/reattest) pass the CURRENT ICV; ``verify_chain`` replay passes each record's OWN
        recorded ICV (historical integrity — a valid old record is not misread as corruption)."""
        row = self._conn().execute(
            "SELECT 1 FROM calibration_pass WHERE calibration_result_ref=? AND policy_id=? "
            "AND pinned_set_version=? AND detector_identity=? AND identity_contract_version=? LIMIT 1",
            (calibration_result_ref, policy_id, pinned_set_version, detector_identity,
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
                "pinned_set_version": row["pinned_set_version"],
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
            if src is PolicyState.ENABLED and dst is PolicyState.ENABLED:
                # 3.5 job-1: a RE_ATTESTATION record (evidence refresh, not a transition). NOT gated on
                # is_legal_transition (ENABLED->ENABLED is deliberately not a legal edge). Replay guard
                # (board): the referenced calibration_pass must still match the record's own
                # pinned_set_version + detector_identity, so a replayed/forged re-attest pointing at a
                # stale or mismatched pass is rejected. State is unchanged.
                # S3 ckpt4-fix: replay the pass-existence against THIS record's OWN recorded ICV (historical
                # integrity) — NOT the process constant. A valid record from a superseded identity contract
                # must remain verifiable history (it just cannot enable/re-attest NOW, which the write-path
                # current-ICV guard enforces separately).
                rec_icv = row["identity_contract_version"]
                if type(rec_icv) is not int or not self._pass_exists_unlocked(
                    str(row["calibration_result_ref"]), pid, str(row["pinned_set_version"]),
                    str(row["detector_identity"]), rec_icv,
                ):
                    return False
                # last_state[pid] stays ENABLED (no state change).
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
    "ChainIntegrityError",
    "ReAttestConflict",
]
# ``_ReAttestGrant`` / ``_mint_reattest_grant`` are deliberately NOT exported — they are a module-private
# call-path convention (see ``_ReAttestGrant``). The RestoreController imports the mint by its private
# name; the structural no-bypass test asserts it is the only caller.
