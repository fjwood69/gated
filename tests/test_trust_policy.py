"""tests/test_trust_policy.py — B1 identity + evaluation (S3 checkpoint 1). Run:
python3 -m unittest discover -s tests

Covers the two separated responsibilities and the identity: (1) the non-configurable ExecutionResult schema
invariant, (2) the configurable outcome-allowlist trust decision, and the resolved policy's digest/registry.
The run_check WIRING negatives (always-PASS not called on untrusted; digest carried from the APPLIED policy
through CalibrationResult; policy-A-applied-while-digest-B-supplied impossible) live with checkpoint 2.
"""
from __future__ import annotations

import unittest

from core import ExecutionResult, IsolationLevel
from engine.observation_trust import (
    evaluate_outcome_allowlist,
    execution_result_schema_ok,
)
from gate.trust_policy import (
    ObservationTrustPolicy,
    UnknownTrustPolicyError,
    approved_trust_policies,
    resolve_trust_policy,
)

_HERMETIC = IsolationLevel.HERMETIC


def _result(outcome, exit_code, *, egress=None):  # type: ignore[no-untyped-def]
    return ExecutionResult(
        outcome=outcome, exit_code=exit_code, isolation_level=_HERMETIC,
        artifact_hash="sha256:test", egress_attempts=egress,
    )


_REF_ID = "trust-policy:completed-only"


class ExecutionResultSchemaTests(unittest.TestCase):
    """Responsibility 1 — the non-configurable engine invariant (independent of any policy)."""

    def test_completed_requires_integer_exit_code(self) -> None:
        self.assertTrue(execution_result_schema_ok(_result("completed", 0)))
        self.assertTrue(execution_result_schema_ok(_result("completed", 137)))  # non-zero completed is valid
        self.assertFalse(execution_result_schema_ok(_result("completed", None)))  # completed w/o a code

    def test_completed_exit_code_bool_rejected(self) -> None:
        # bool is an int subclass — an exit_code of True must not satisfy the integer invariant.
        self.assertFalse(execution_result_schema_ok(_result("completed", True)))  # type: ignore[arg-type]

    def test_timeout_and_error_permit_none_exit_code(self) -> None:
        self.assertTrue(execution_result_schema_ok(_result("timeout", None)))
        self.assertTrue(execution_result_schema_ok(_result("error", None)))

    def test_unknown_outcome_rejected(self) -> None:
        self.assertFalse(execution_result_schema_ok(_result("weird", 0)))  # type: ignore[arg-type]


class OutcomeAllowlistTests(unittest.TestCase):
    """Responsibility 2 — the configurable decision over a schema-valid result (reference: only completed)."""

    def _eval(self, result: ExecutionResult):  # type: ignore[no-untyped-def]
        return evaluate_outcome_allowlist(result, ("completed",))

    def test_completed_zero_and_nonzero_are_trusted(self) -> None:
        self.assertTrue(self._eval(_result("completed", 0)).trusted)
        d = self._eval(_result("completed", 3))
        self.assertTrue(d.trusted)
        self.assertEqual(d.code, "OK")  # non-zero completed is a TRUSTED observation (detector decides)

    def test_egress_none_on_completed_is_trusted(self) -> None:
        # egress_attempts=None is detector-semantic telemetry, NOT a trust concern — a completed run with
        # no egress telemetry is still a trusted observation the detector sees (it may return TELEMETRY_MISSING).
        self.assertTrue(self._eval(_result("completed", 0, egress=None)).trusted)

    def test_timeout_and_error_are_untrusted(self) -> None:
        for outcome in ("timeout", "error"):
            d = self._eval(_result(outcome, None))
            self.assertFalse(d.trusted)
            self.assertEqual(d.code, "OUTCOME_UNTRUSTED")

    def test_malformed_is_untrusted_independent_of_policy(self) -> None:
        # a completed result with no integer exit_code fails the schema invariant -> MALFORMED, regardless of
        # the allowlist (even an allowlist that trusts everything cannot trust a malformed result).
        d = evaluate_outcome_allowlist(_result("completed", None), ("completed", "timeout", "error"))
        self.assertFalse(d.trusted)
        self.assertEqual(d.code, "MALFORMED")


class TrustPolicyIdentityTests(unittest.TestCase):
    def test_reference_policy_resolves_and_evaluates(self) -> None:
        policy = resolve_trust_policy(_REF_ID)
        self.assertEqual(policy.name, "completed-only")
        self.assertEqual(policy.version, 1)
        self.assertTrue(policy.evaluate(_result("completed", 0)).trusted)
        self.assertFalse(policy.evaluate(_result("timeout", None)).trusted)
        self.assertIn(_REF_ID, approved_trust_policies())

    def test_unknown_policy_id_refused(self) -> None:
        with self.assertRaises(UnknownTrustPolicyError):
            resolve_trust_policy("trust-policy:anything-goes")

    def test_policy_digest_is_stable_and_spec_sensitive(self) -> None:
        base = resolve_trust_policy(_REF_ID)
        d0 = base.policy_digest
        self.assertEqual(d0, resolve_trust_policy(_REF_ID).policy_digest)  # stable
        # changing ANY spec coordinate changes the digest (name / version / impl_id / config)
        variants = [
            ObservationTrustPolicy(name="completed-only-X", version=1, impl_id=base.impl_id, config=base.config),
            ObservationTrustPolicy(name="completed-only", version=2, impl_id=base.impl_id, config=base.config),
            ObservationTrustPolicy(name="completed-only", version=1, impl_id="other:v1", config=base.config),
            ObservationTrustPolicy(name="completed-only", version=1, impl_id=base.impl_id,
                                   config={"trusted_outcomes": ("completed", "timeout")}),
        ]
        for v in variants:
            self.assertNotEqual(v.policy_digest, d0, f"digest did not change for {v.name}/{v.version}/{v.impl_id}")

    def test_unapproved_impl_cannot_silently_trust(self) -> None:
        # a policy carrying an impl_id with no approved evaluator must REFUSE, never default to trusting.
        rogue = ObservationTrustPolicy(name="x", version=1, impl_id="unapproved:v9",
                                       config={"trusted_outcomes": ("completed",)})
        with self.assertRaises(UnknownTrustPolicyError):
            rogue.evaluate(_result("completed", 0))


if __name__ == "__main__":
    unittest.main()
