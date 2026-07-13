"""gate/trust_policy.py — B1 identity: the CLOSED registry of observation trust policies + the resolved,
identity-bearing policy whose digest binds into the ``RuntimeSubject``.

The policy is RESOLVED from the closed registry (never a caller-supplied object/string) and APPLIED
(``engine.observation_trust``) before the detector runs; the digest carried into the signed identity is the
digest of the policy that ACTUALLY governed the observation — measured PROVENANCE, not a caller string. S3
binds + verifies the policy's IDENTITY and its calibrate↔enforce CONTINUITY; S5b enriches the mechanics
(rc-125 image reclassification, 126/127/timeout adversarial handling, richer JobOutcome evidence) reading
THIS SAME identity-bound config — the single source, so there is no sign-config-A-run-config-B drift.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from core import ExecutionResult
from core.chain import canonical_digest
from engine.observation_trust import TrustDecision, evaluate_outcome_allowlist

_TRUST_POLICY_DOMAIN = "gated.observation-trust-policy"
# The one impl the reference registry approves: a schema-first, outcome-allowlist evaluator.
_OUTCOME_ALLOWLIST_IMPL = "gated.engine.observation-trust.outcome-allowlist:v1"


class UnknownTrustPolicyError(RuntimeError):
    """A ``trust_policy_id`` was requested that is not in the closed registry — refused (no arbitrary
    policy can govern an observation; only an audited, identity-bearing one)."""


@dataclass(frozen=True)
class ObservationTrustPolicy:
    """A resolved, identity-bearing observation trust policy. ``policy_digest`` is the canonical digest of
    its FULL spec (name + version + impl_id + config) — changing ANY of them changes the digest. ``evaluate``
    dispatches on ``impl_id`` to the trusted engine evaluator over the config-declared trusted outcomes."""

    name: str
    version: int
    impl_id: str
    config: Mapping[str, Any]

    @property
    def trust_policy_id(self) -> str:
        return f"trust-policy:{self.name}"

    @property
    def policy_digest(self) -> str:
        return canonical_digest(_TRUST_POLICY_DOMAIN, {
            "name": self.name, "version": self.version, "impl_id": self.impl_id,
            "config": dict(self.config),
        })

    def evaluate(self, result: ExecutionResult) -> TrustDecision:
        if self.impl_id == _OUTCOME_ALLOWLIST_IMPL:
            trusted = tuple(self.config.get("trusted_outcomes", ()))
            return evaluate_outcome_allowlist(result, trusted)
        raise UnknownTrustPolicyError(  # an unrecognised impl cannot silently trust anything
            f"trust policy impl {self.impl_id!r} has no approved evaluator")


# The one reference policy: trust ONLY a schema-valid ``completed`` outcome.
_COMPLETED_ONLY = ObservationTrustPolicy(
    name="completed-only", version=1, impl_id=_OUTCOME_ALLOWLIST_IMPL,
    config=MappingProxyType({"trusted_outcomes": ("completed",)}),
)

# The CLOSED trust-policy registry — keyed by ``trust_policy_id``. Distinct from the backend + guard
# registries; adding a policy here is a reviewed, security-relevant change.
_APPROVED_TRUST_POLICIES: dict[str, ObservationTrustPolicy] = {
    _COMPLETED_ONLY.trust_policy_id: _COMPLETED_ONLY,
}


def approved_trust_policies() -> tuple[str, ...]:
    return tuple(sorted(_APPROVED_TRUST_POLICIES))


def resolve_trust_policy(trust_policy_id: str) -> ObservationTrustPolicy:
    """Resolve a ``trust_policy_id`` to its audited, identity-bearing policy from the CLOSED registry. An
    unknown id is refused (no arbitrary policy). The returned object is what is APPLIED to observations and
    whose ``policy_digest`` is carried as measured provenance — the caller never supplies the digest."""
    policy = _APPROVED_TRUST_POLICIES.get(trust_policy_id)
    if policy is None:
        raise UnknownTrustPolicyError(
            f"trust policy {trust_policy_id!r} is not approved {list(approved_trust_policies())}")
    return policy


__all__ = [
    "ObservationTrustPolicy",
    "UnknownTrustPolicyError",
    "approved_trust_policies",
    "resolve_trust_policy",
]
