"""Increment 2.5 (code half) — fail-closed startup verifications + rate-limit budget.

Run from the gated/ root:  python3 -m unittest discover -s tests

These are the two most-elevated 2.5 findings, unit-testable now against fakes: the
check-name-match footgun (the invisible gate-disabler) and the rate-limit load-shed.
"""
from __future__ import annotations

import unittest

from gate.preflight import ConfigurationError, verify_check_required
from gate.ratelimit import RateLimitBudget

_NAME = "gated/retry"


class CheckNameMatchTests(unittest.TestCase):
    def test_name_present_in_legacy_contexts_ok(self) -> None:
        prot = {"required_status_checks": {"contexts": [_NAME, "other/ci"]}}
        verify_check_required(prot, _NAME)  # no raise

    def test_name_present_in_new_checks_ok(self) -> None:
        prot = {"required_status_checks": {"checks": [{"context": _NAME, "app_id": 42}]}}
        verify_check_required(prot, _NAME)  # no raise

    def test_name_mismatch_is_fail_open_refused(self) -> None:
        # branch protection requires a DIFFERENT name -> the App's check is advisory ->
        # merges proceed on non-PASS -> fail-OPEN. Must refuse to start.
        prot = {"required_status_checks": {"contexts": ["gated/retry-check"]}}
        with self.assertRaises(ConfigurationError):
            verify_check_required(prot, _NAME)

    def test_no_required_checks_refused(self) -> None:
        with self.assertRaises(ConfigurationError):
            verify_check_required({"required_status_checks": {"contexts": []}}, _NAME)

    def test_no_branch_protection_refused(self) -> None:
        with self.assertRaises(ConfigurationError):
            verify_check_required({}, _NAME)


class RateLimitBudgetTests(unittest.TestCase):
    def test_unknown_budget_accepts(self) -> None:
        self.assertTrue(RateLimitBudget().accepting())  # not hit GitHub yet

    def test_sheds_below_floor(self) -> None:
        b = RateLimitBudget(floor=100)
        b.observe(50)
        self.assertFalse(b.accepting())  # 503 new webhooks, finish in-flight

    def test_accepts_above_floor(self) -> None:
        b = RateLimitBudget(floor=100)
        b.observe(4000)
        self.assertTrue(b.accepting())


if __name__ == "__main__":
    unittest.main()
