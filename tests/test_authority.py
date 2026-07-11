"""3.5 — the measurement/governance domain separation on GovernanceApproval. Run:
python3 -m unittest discover -s tests

Load-bearing: a governance act carries an AuthorityDomain, and ``meets`` checks it. The two domains
are DISJOINT — a CALIBRATION_GOVERNANCE approval cannot satisfy a governance (tier-write) op and a
GOVERNANCE approval cannot satisfy a calibration-governance op — so 'the meter cannot move the tier'
is structural. The default domain is GOVERNANCE, so every 3.2-3.4 call site (``meets(n)``) is
unchanged against the governance-default approvals it already constructs.
"""
from __future__ import annotations

import unittest

from gate.authority import AuthorityDomain, GovernanceApproval


def _appr(*principals: str, domain: AuthorityDomain = AuthorityDomain.GOVERNANCE) -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose="p", rationale="r",
                              operation_id="o", domain=domain)


class DomainSeparationTests(unittest.TestCase):
    def test_default_domain_is_governance(self) -> None:
        self.assertIs(_appr("a").domain, AuthorityDomain.GOVERNANCE)

    def test_governance_approval_satisfies_governance_op(self) -> None:
        self.assertTrue(_appr("a", "b").meets(2))  # default domain=GOVERNANCE on both sides

    def test_calibration_approval_cannot_satisfy_governance_op(self) -> None:
        # the meter cannot move the tier: a CALIBRATION_GOVERNANCE approval fails a governance op
        # even with enough distinct principals.
        cal = _appr("a", "b", domain=AuthorityDomain.CALIBRATION_GOVERNANCE)
        self.assertFalse(cal.meets(2))
        self.assertFalse(cal.meets(1))

    def test_governance_approval_cannot_satisfy_calibration_op(self) -> None:
        # symmetric: a tier admin cannot ghost-write the acceptance report that grades a detector.
        gov = _appr("a", "b")
        self.assertFalse(gov.meets(2, domain=AuthorityDomain.CALIBRATION_GOVERNANCE))

    def test_calibration_approval_satisfies_calibration_op(self) -> None:
        cal = _appr("a", "b", domain=AuthorityDomain.CALIBRATION_GOVERNANCE)
        self.assertTrue(cal.meets(2, domain=AuthorityDomain.CALIBRATION_GOVERNANCE))

    def test_domain_match_still_requires_principals_and_fields(self) -> None:
        # domain is necessary, not sufficient — principal count + mandatory fields still apply.
        self.assertFalse(_appr("a").meets(2))  # right domain, too few principals
        self.assertFalse(_appr("a", "a").meets(2))  # repeats don't count
        blank = GovernanceApproval(principals=("a", "b"), purpose="", rationale="r", operation_id="o")
        self.assertFalse(blank.meets(2))  # missing purpose


if __name__ == "__main__":
    unittest.main()
