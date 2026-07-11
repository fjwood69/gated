"""gate/authority.py — the governance authority ladder, shared by every gate-side store.

Factored out of ``gate/calibration_store.py`` (3.2) so the calibration store AND the 3.3
tier-transition store enforce the SAME asymmetric rule without duplicating it: strengthening
is low-friction (single GOVERNANCE), WEAKENING needs a second authority (GOVERNANCE_DUAL). The
runtime token sits at the bottom — RUNTIME can read an oracle, never mutate it (1b).

Gate-side ONLY. ``core`` never imports this (it stays a pure hashing primitive — see the board's
§4: dual-authority is a GATE concept and must not leak into ``core.chain``, or ``engine`` — which
imports ``core.chain`` — would transitively depend on governance, breaking engine⊥gate). The
tamper-evidence math lives in ``core.chain``; the AUTHORITY to append lives here.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class Authority(IntEnum):
    """Write authority, ordered. RUNTIME cannot append (1b). GOVERNANCE strengthens/corrects.
    GOVERNANCE_DUAL (a second, distinct authority) is required for any WEAKENING op — the one
    channel through which self-grading could re-enter, so it earns more scrutiny (1e).

    NOTE (board-flagged, 3.2-consistency pending): the calibration store (3.2 §1e) still gates on
    this ENUM. 3.3's tier transitions use ``GovernanceApproval`` instead — an enum value is not
    PROOF of dual control (any caller can type ``GOVERNANCE_DUAL``). Whether 3.2 should be upgraded
    to approvals, or the enum ratified as the in-process model of a deploy-time boundary, is a board
    question — deliberately not resolved here.
    """

    RUNTIME = 0          # the check's minimal token — READ-ONLY, cannot mutate any oracle
    GOVERNANCE = 1       # can ADD / SUPERSEDE / PROMOTE (strengthening or enable-path)
    GOVERNANCE_DUAL = 2  # can DEPRECATE / DEMOTE (weakening — needs a second authority)


@dataclass(frozen=True)
class GovernanceApproval:
    """A REAL governance authorisation for a tier transition — not an enum a caller merely names.

    Dual control is proven by TWO DISTINCT authenticated principals, not by a label. A weakening
    transition requires ``meets(2)`` — two distinct principal ids — so a caller cannot satisfy it
    by repeating one principal, and a RUNTIME caller (which authenticates no governance principal)
    cannot satisfy even ``meets(1)``. Purpose / rationale / operation_id are mandatory so every
    governance act is legible and (via operation_id) idempotency-addressable.

    In-process model, live-confirmed at deploy (same fake-then-live discipline as 1b): here the
    principals are authenticated ids the gate has verified; the deployment binds them to real
    credentials. The object makes the two-principal requirement STRUCTURAL, closing the enum hole.
    """

    principals: tuple[str, ...]
    purpose: str
    rationale: str
    operation_id: str

    @property
    def distinct_principals(self) -> frozenset[str]:
        """Distinct, non-empty principal ids — repeats and blanks do not count toward dual."""
        return frozenset(p for p in self.principals if p)

    def meets(self, required_principals: int) -> bool:
        """True iff enough DISTINCT principals AND all mandatory fields present."""
        return (
            len(self.distinct_principals) >= required_principals
            and bool(self.purpose)
            and bool(self.rationale)
            and bool(self.operation_id)
        )


__all__ = ["Authority", "GovernanceApproval"]
