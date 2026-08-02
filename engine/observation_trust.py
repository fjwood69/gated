"""engine/observation_trust.py — B1: whether the ENGINE trusts an ``ExecutionResult`` enough to hand it to
the detector. TWO SEPARATE responsibilities (board 2026-07-13):

  1. ``ExecutionResult`` SCHEMA validation — a NON-CONFIGURABLE engine invariant: a ``completed`` run MUST
     carry an integer ``exit_code``; ``timeout``/``error`` MAY carry ``exit_code=None``; ``outcome`` must be
     one of the three known values. A malformed result is UNTRUSTED regardless of any policy.
  2. The observation TRUST POLICY — the CONFIGURABLE decision over a schema-valid result: which outcomes are
     trusted. The reference policy trusts only ``completed``. A NON-ZERO ``completed`` exit code is a TRUSTED
     observation (the detector decides what it means); an ABSENT ``egress_attempts`` stays detector-semantic
     telemetry — a ``completed`` run carrying an ``EgressAbsence`` is passed THROUGH to the detector as
     trusted, and ``RetryCheck`` is what refuses it.

⚠ THE EXPOSURE THAT LINE DESCRIBES, STATED AS SCOPE RATHER THAN AS SAFETY. This layer does NOT refuse an
absence; it forwards one. The reason nothing is currently laundered is that the ONLY detector that exists
maps both ``EgressAbsence`` members to ``Verdict(ERROR)`` (``engine/retry.py``'s ``_ABSENCE_REASON``). So the
verified claim is "no coercion BY THE ONLY DETECTOR THAT EXISTS" — not "no coercion anywhere". A SECOND
detector inherits the exposure: a low-egress predicate written as ``case NOT_OBSERVED: pass`` would turn a
refusal into a clean result, and this layer would not stop it, because forwarding is what this layer does.

Written at this length deliberately. "No coercion anywhere" is the shorter sentence and it is FALSE — and
the substitution of the strong claim for the scoped one is the same move as dropping an ``[ASSUMED]`` label
when retelling a finding. The scope is the claim.

*(This paragraph was corrected 2026-08-02: it previously said ``egress_attempts=None`` and named a
``TELEMETRY_MISSING`` reason. Both predate the typed-absence work — absence is now an ``EgressAbsence``
member and the reasons are ``TELEMETRY_NOT_OBSERVED`` / ``TELEMETRY_UNREADABLE``. A doc sentence naming a
spelling that no longer exists is the same staleness class as a comment citing a deleted field.)*

An untrusted observation is mapped by ``run_check`` to ``Verdict(ERROR)`` MECHANICALLY — the detector's
``assert_invariant`` is NEVER consulted for an untrusted result, so an always-PASS detector cannot launder a
timeout / error / malformed run into a PASS. The engine consumes a plain ``TrustPolicy`` object and never
learns the gate's registry / identity machinery (engine ⊥ gate).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core import ExecutionResult

_VALID_OUTCOMES = ("completed", "timeout", "error")


@dataclass(frozen=True)
class TrustDecision:
    """The engine's trust verdict on an ``ExecutionResult``, before the detector is consulted. ``code`` is a
    stable, layer-tagged reason: ``OK`` (trusted), ``MALFORMED`` (failed the schema invariant),
    ``OUTCOME_UNTRUSTED`` (schema-valid but the policy does not trust the outcome)."""

    trusted: bool
    code: str


def execution_result_schema_ok(result: ExecutionResult) -> bool:
    """Responsibility 1 — the NON-CONFIGURABLE ``ExecutionResult`` schema invariant. A ``completed`` run MUST
    carry an integer ``exit_code`` (a completed run that exited with no code is incoherent); ``timeout`` /
    ``error`` MAY carry ``exit_code=None``; the outcome must be a known value. ``bool`` is an ``int``
    subclass, so an ``exit_code`` of ``True`` is rejected. Independent of any trust policy."""
    if result.outcome not in _VALID_OUTCOMES:
        return False
    if result.outcome == "completed":
        return type(result.exit_code) is int  # completed REQUIRES a real integer exit code (not None / bool)
    return True  # timeout / error may carry exit_code=None (or any int)


class TrustPolicy(Protocol):
    """The engine's view of an observation trust policy — a plain object. ``policy_digest`` identifies the
    APPLIED policy (the caller binds it into the signed identity as measured provenance); ``evaluate``
    returns the trust decision for a result."""

    @property
    def policy_digest(self) -> str: ...

    def evaluate(self, result: ExecutionResult) -> TrustDecision: ...


def evaluate_outcome_allowlist(
    result: ExecutionResult, trusted_outcomes: tuple[str, ...],
) -> TrustDecision:
    """The evaluator named by ``impl_id = gated.engine.observation-trust.outcome-allowlist:v1``. Schema FIRST
    (malformed → untrusted, code ``MALFORMED``); then the CONFIGURABLE allowlist (a schema-valid outcome in
    ``trusted_outcomes`` → trusted; otherwise ``OUTCOME_UNTRUSTED``). A non-zero ``completed`` exit code is
    still ``completed`` → trusted."""
    if not execution_result_schema_ok(result):
        return TrustDecision(trusted=False, code="MALFORMED")
    if result.outcome in trusted_outcomes:
        return TrustDecision(trusted=True, code="OK")
    return TrustDecision(trusted=False, code="OUTCOME_UNTRUSTED")


__all__ = [
    "TrustDecision",
    "TrustPolicy",
    "execution_result_schema_ok",
    "evaluate_outcome_allowlist",
]
