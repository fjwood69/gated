"""gate/policy_state.py — 3.3: the tier-gatekeeper's closed-enum state machine + fail-closed
disposition mapping.

3.3 is the first increment where a check's CALIBRATION STATE binds its enforcement tier. A policy
moves through a lifecycle; the gate must decide, per PR, whether that policy RUNS-AND-BLOCKS,
is SKIPPED (non-blocking), or BLOCKS-WITHOUT-RUNNING (it was enforcing but can no longer attest
its calibration). That decision is a pure mapping from state -> disposition, and it MUST be
fail-closed-typed: no state may map to "silently enforce" or "silently fall open".

Scope (board-ratified): 3.3 = the ENABLE-PATH transition only (PENDING -> CALIBRATING ->
ENABLED / REJECTED) plus DEGRADED and human-gated DEMOTED. Re-calibration triggers and the C3
feedback loop are 3.5. RETIRED is enumerated for closed-enum completeness; its transition logic
is not built here.

Gate-side. Consumes ``core`` (via the store) but is itself pure policy logic — no engine import
at module load beyond the shared ``core`` verdict types used for the disposition mapping.
"""
from __future__ import annotations

from enum import Enum

from gate.checkrun import CheckConclusion


class PolicyState(Enum):
    """The lifecycle of one check-type's policy. A CLOSED enum — every state has an explicit
    disposition (see ``DISPOSITION``); there is no default/fall-through, so a new state cannot
    be added without also deciding whether it enforces (fail-closed by construction).

    VOCABULARY (do not conflate with PBGF-CS): these are POLICY LIFECYCLE states — §4.2 blocking
    AUTHORITY, i.e. whether this policy may run and block at the boundary. They are NOT PBGF-CS
    §4.1 property TIERS (ENFORCEABLE / VERIFIABLE-AT-PROMOTION / ADVISABLE), which classify a
    PROPERTY by what a check can withstand and are produced by a recorded red-team procedure.
    This repository emits no §4.1 tier records at all. In particular ``ADVISORY`` below is a
    demotion state of a policy, NOT the §4.1 ``ADVISABLE`` tier — the names are adjacent and mean
    different things."""

    PROPOSED = "proposed"                      # authored, awaiting human governance approval
    PENDING_CALIBRATION = "pending_calibration"  # approved, queued for the batch calibrator
    CALIBRATING = "calibrating"                # the 3.2 calibrator is running the fixtures
    ENABLED = "enabled"                        # calibration passed -> holds authority (runs + blocks)
    DEGRADED = "degraded"                      # was ENABLED, lost attestation -> blocks, no run
    ADVISORY = "advisory"                      # human-gated demote -> runs-not / non-blocking
    REJECTED = "rejected"                      # calibration failed (FN/FP) -> never enforces
    RETIRED = "retired"                        # explicitly disabled (enum-completeness; 3.x)


class Disposition(Enum):
    """What the dispatcher DOES for a policy in a given state, before it touches the engine."""

    RUN_ENFORCING = "run_enforcing"        # run the engine; the real Verdict maps + can block
    SKIP_NEUTRAL = "skip_neutral"          # do NOT run; post a non-blocking neutral check
    BLOCK_ACTION_REQUIRED = "block_action_required"  # do NOT run; post a BLOCKING action_required


# The load-bearing fail-closed mapping. ENABLED is the ONLY state that runs the engine. DEGRADED
# BLOCKS (it was enforcing and can no longer attest calibration — an un-attestable enforcing check
# must not silently fall open to neutral, and must not enforce a stale verdict; it blocks-and-flags,
# the ERROR->action_required lesson from 2.4 applied to the tier layer). Everything not-yet-enabled
# or explicitly-not-enforcing SKIPS non-blocking (it never earned the right to block a merge).
DISPOSITION: dict[PolicyState, Disposition] = {
    PolicyState.PROPOSED: Disposition.SKIP_NEUTRAL,
    PolicyState.PENDING_CALIBRATION: Disposition.SKIP_NEUTRAL,
    PolicyState.CALIBRATING: Disposition.SKIP_NEUTRAL,
    PolicyState.ENABLED: Disposition.RUN_ENFORCING,
    PolicyState.DEGRADED: Disposition.BLOCK_ACTION_REQUIRED,
    PolicyState.ADVISORY: Disposition.SKIP_NEUTRAL,
    PolicyState.REJECTED: Disposition.SKIP_NEUTRAL,
    PolicyState.RETIRED: Disposition.SKIP_NEUTRAL,
}

# Non-run dispositions -> the GitHub conclusion the dispatcher posts WITHOUT running the engine.
# SKIP_NEUTRAL -> neutral (passing, non-blocking). BLOCK_ACTION_REQUIRED -> action_required
# (a BLOCKING conclusion per BLOCKING_CONCLUSIONS — the fail-closed guarantee for DEGRADED).
_NONRUN_CONCLUSION: dict[Disposition, CheckConclusion] = {
    Disposition.SKIP_NEUTRAL: CheckConclusion.NEUTRAL,
    Disposition.BLOCK_ACTION_REQUIRED: CheckConclusion.ACTION_REQUIRED,
}


def disposition_for(state: PolicyState) -> Disposition:
    """Fail-closed: a state with no mapping is a programming error, not a silent enforce/skip.
    The closed enum + this KeyError-on-miss means an un-triaged new state can never quietly
    map to RUN_ENFORCING or to a non-blocking skip."""
    return DISPOSITION[state]


def nonrun_conclusion_for(disposition: Disposition) -> CheckConclusion:
    """The Check Run conclusion for a disposition that does NOT run the engine. RUN_ENFORCING has
    no static conclusion (it comes from the real Verdict) and raises if asked — guards against a
    caller trying to short-circuit an enforcing check to a canned conclusion."""
    if disposition is Disposition.RUN_ENFORCING:
        raise ValueError("RUN_ENFORCING has no static conclusion — run the engine")
    return _NONRUN_CONCLUSION[disposition]


# ---------------------------------------------------------------------------------------------
# Legal transitions. Every edge is explicit; the STRENGTHENING vs WEAKENING classification drives
# which governance authority the tier-transition store demands (weakening -> GOVERNANCE_DUAL).
# ---------------------------------------------------------------------------------------------

# Allowed (from -> to) edges for the 3.3 enable path + degradation + human-gated demotion.
_TRANSITIONS: dict[PolicyState, frozenset[PolicyState]] = {
    PolicyState.PROPOSED: frozenset({PolicyState.PENDING_CALIBRATION, PolicyState.RETIRED}),
    PolicyState.PENDING_CALIBRATION: frozenset({PolicyState.CALIBRATING, PolicyState.RETIRED}),
    PolicyState.CALIBRATING: frozenset({PolicyState.ENABLED, PolicyState.REJECTED}),
    PolicyState.ENABLED: frozenset(
        {PolicyState.DEGRADED, PolicyState.ADVISORY, PolicyState.RETIRED}
    ),
    PolicyState.DEGRADED: frozenset(
        {PolicyState.ENABLED, PolicyState.ADVISORY, PolicyState.RETIRED}
    ),
    PolicyState.ADVISORY: frozenset(
        {PolicyState.PENDING_CALIBRATION, PolicyState.RETIRED}
    ),
    PolicyState.REJECTED: frozenset({PolicyState.PENDING_CALIBRATION, PolicyState.RETIRED}),
    PolicyState.RETIRED: frozenset(),  # terminal
}

# Transitions that WEAKEN the gate's catching power (require GOVERNANCE_DUAL). Demoting an
# enforcing check to ADVISORY (stops blocking) is the archetypal weakening move; it must never
# be automatic (no C3-event edge exists to ADVISORY — that path is 3.5, human-gated).
_WEAKENING: frozenset[tuple[PolicyState, PolicyState]] = frozenset(
    {
        (PolicyState.ENABLED, PolicyState.ADVISORY),
        (PolicyState.DEGRADED, PolicyState.ADVISORY),
    }
)


def is_legal_transition(src: PolicyState, dst: PolicyState) -> bool:
    return dst in _TRANSITIONS.get(src, frozenset())


def is_weakening(src: PolicyState, dst: PolicyState) -> bool:
    """True if the transition reduces enforcement (needs GOVERNANCE_DUAL). ENABLED->DEGRADED is
    NOT weakening — DEGRADED still BLOCKS (it's fail-closed); only dropping to a non-blocking
    ADVISORY genuinely weakens the gate."""
    return (src, dst) in _WEAKENING


__all__ = [
    "PolicyState",
    "Disposition",
    "DISPOSITION",
    "disposition_for",
    "nonrun_conclusion_for",
    "is_legal_transition",
    "is_weakening",
]
