"""gate/c3_router.py — 3.5 job-2: the C3 -> calibration ROUTER + provenance NOTARY.

A C3 override (a human merged past a non-PASS gate verdict) is a SIGNAL that a detector may need
attention — most often "the gate false-positived; this merged code is actually clean", i.e. a candidate
known-good. This router carries that signal from the override ledger into the calibration-governance
REVIEW QUEUE (the candidate log) and NOTARISES its provenance. It is deliberately powerless:

  * TYPE isolation — it emits a ``Candidate`` (source=C3_TRIAGE, a proposal), never a fixture. The
    fixture loader / calibration runner consume the fixture store, never the candidate log; only the
    3.4 admission gate converts a candidate to a fixture, and only under TWO human approvals.
  * ACL isolation — it holds ONLY a ``CandidateStore`` (the review queue). It imports no calibration /
    policy / tier / ledger-write store and has no reference to one, so it structurally cannot write a
    fixture, move a tier, or append to any tamper-chain. Routing a C3 event to a mutator is not a
    permission it can be denied — it is a capability it does not possess.
  * PROVENANCE-ONLY signature — the machine ``C3ProvenanceStamp`` (HMAC under a ROUTER key) proves a
    candidate originated from a specific override record. It is EVIDENCE OF ORIGIN, not authority: the
    admission gate ignores it entirely and still demands two DISTINCT HUMAN ``GovernanceApproval``
    principals + the canonical merged-tree hash. A payload pre-stamped by the router plus one human
    signature is still a bypass and is still refused — the stamp never counts toward the two.

Gate-side; imports only the candidate store + the ledger's record type; no engine, no core.chain write.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Mapping

from gate.candidate_store import Candidate, CandidateKind, CandidateSource, CandidateStore
from gate.ledger import OverrideKind, OverrideRecord


class C3RoutingError(ValueError):
    """The override record cannot be routed as a calibration candidate (e.g. it is not a
    HUMAN_OVERRIDE — an UNVERIFIABLE 'could not attest' is not a false-positive signal)."""


@dataclass(frozen=True)
class C3ProvenanceStamp:
    """A machine notary stamp: this candidate provably originated from override ``c3_override_ref``
    whose ledger record hashed to ``override_record_hash``. PROVENANCE ONLY — signed under the router
    key, it authorises NOTHING; the admission gate never reads it as an approval."""

    candidate_id: str
    c3_override_ref: str
    override_record_hash: str
    routed_at: float
    signature: str

    def _payload(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id, "c3_override_ref": self.c3_override_ref,
            "override_record_hash": self.override_record_hash, "routed_at": self.routed_at,
        }


def _sign(payload: Mapping[str, object], key: bytes) -> str:
    canonical = json.dumps(dict(payload), sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


class C3Router:
    """Routes override records into the candidate review queue and notarises their provenance. Holds
    ONLY the candidate store (ACL isolation) + a machine router key (provenance signing)."""

    def __init__(self, candidate_store: CandidateStore, *, router_key: bytes) -> None:
        if not router_key:
            raise ValueError("C3Router requires a non-empty router key for provenance signing")
        self._candidates = candidate_store
        self._router_key = router_key

    def route(
        self,
        override: OverrideRecord,
        *,
        payload: bytes,
        merged_tree_hash: str,
        routed_at: float,
        proposed_by: str | None = None,
    ) -> tuple[str, C3ProvenanceStamp]:
        """Surface a HUMAN_OVERRIDE as a READ-ONLY known-good CANDIDATE and stamp its provenance.
        ``payload`` + ``merged_tree_hash`` are the merged code + its system-computed merged-tree hash
        (the human confirms the latter at admission; the router only carries it). Returns
        ``(candidate_id, stamp)``. Proposing is UNPRIVILEGED (safe-to-be-wrong); the gate is at
        admission, where two humans decide. The router cannot admit."""
        if override.kind is not OverrideKind.HUMAN_OVERRIDE:
            raise C3RoutingError(
                f"only HUMAN_OVERRIDE records route as candidates; got {override.kind.value} "
                "(an UNVERIFIABLE merge is not a false-positive signal)"
            )
        candidate = Candidate(
            candidate_id=f"c3-{override.delivery_id}",
            kind=CandidateKind.KNOWN_GOOD,
            payload=payload,
            source=CandidateSource.C3_TRIAGE,
            proposed_by=proposed_by,
            c3_override_ref=override.delivery_id,
            merged_tree_hash=merged_tree_hash,
        )
        candidate_id = self._candidates.propose(candidate)
        stamp = C3ProvenanceStamp(
            candidate_id=candidate_id, c3_override_ref=override.delivery_id,
            override_record_hash=override.record_hash, routed_at=routed_at, signature="",
        )
        from dataclasses import replace

        return candidate_id, replace(stamp, signature=_sign(stamp._payload(), self._router_key))


def verify_provenance(stamp: C3ProvenanceStamp, *, router_key: bytes) -> bool:
    """True iff the stamp's HMAC is valid under ``router_key`` (constant-time). Confirms the candidate
    came from the router — NOT that it may be admitted. Provenance, never authority."""
    return hmac.compare_digest(_sign(stamp._payload(), router_key), stamp.signature)


__all__ = [
    "C3RoutingError",
    "C3ProvenanceStamp",
    "C3Router",
    "verify_provenance",
]
