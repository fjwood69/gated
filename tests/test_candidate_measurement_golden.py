"""3.5 S3-completion CP4 Slice B — the CANONICAL GOLDEN for the shared measurement spine.

Under a FROZEN oracle (fixed fixtures + the deterministic NoOp execution identity + a fixed signer/nonce),
this pins the EXACT measurement the shared ``produce_candidate_measurement`` spine yields, and proves BOTH
consumers derive their authority-bearing outputs from it byte-for-byte:

  * ``produce_candidate_measurement`` → sealed ``oracle_head`` + ``coverage_digest``, the four measured
    RuntimeSubject coordinates, the composite ``subject_identity``, and the derived ``calibration_result_ref``.
  * ``run_calibration`` (enable path) PERSISTS a pass under the SAME measured head + SAME ref + SAME subject.
  * ``run_recalibration`` (signed measurement runner) SIGNS an attestation over the SAME subject.

The single cross-consumer invariant — spine subject == run_calibration persisted subject == recal signed
subject — is the "measurement is shared, cannot diverge" property in one assertion. ``passed_at`` /
issuance wall-clock are deliberately EXCLUDED (not asserted). The golden constants depend on
``tests/_golden_detector`` (its module bytes content-address into the resolved-profile digest); a
deliberate change there re-pins them.
"""
from __future__ import annotations

import unittest

from core import IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import Fixture, FixtureLabel
from gate.attestation import verify_measurement
from gate.calibration_identity import calibration_result_ref
from gate.candidate_measurement import prepare_candidate, produce_candidate_measurement
from gate.gatekeeper import run_calibration
from gate.policy_state import PolicyState
from gate.recalibration import run_recalibration
from gate.signing import KeyVerifier, SeedSigner, public_key
from gate.trust_policy import resolve_trust_policy
from sandbox.noop import NoOpSandbox
from tests._backend_optout import test_guard_policy
from tests._golden_detector import GoldenScriptedDetector, golden_resolver
from tests.test_gatekeeper import _appr, _cal_store, _store

_REF_TP = resolve_trust_policy("trust-policy:completed-only")
_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_SEED = bytes(range(32))
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)
_KB = (Fixture("b1", FixtureLabel.KNOWN_BAD, b"y"),)
_KG = (Fixture("g1", FixtureLabel.KNOWN_GOOD, b"z"),)

# --- golden constants (frozen oracle; clean two-sided pass: catches b1, passes g1) --------------------
_ORACLE_HEAD = "251149b0bd0040acc78afbdb6832bcd3570e137e8958b8cfc1601d012fe90ba3"
_COVERAGE = "d93c6d4cfe0c521521d34c7d243cb87613bb427b29dda62d322d955d38d86ab2"
_RPD = "546f51213c6f78107b92656c4922c45cdda4de460b38593b368b5ff678ac6ac9"
_TPD = "6bec6cb6bf7ae0e785715fa9eb192d0f2480ebc108ec3eb08616cb434be88de7"
_GPD = "test-guard-digest:v1"
_EID = "03f8a1881718b16a47343881be9e4e7fc6eb8c4347b14057a07b2c42283a6555"
_SUBJECT = "318cd243c9caad602c507e7ca03e6334c8aec66b609cbb49cd8e45983ffa2695"
_REF = "fe49c1fcf8d7af2e8e568d6f0532f2fc5055c209281ce408f28d29211b78631b"
_RECAL_RUN_ID = "56bfc5daba300f4c674c586b471f816ac85f35408d2eb8ede1865b2148bec854"
_RECAL_SIG = (
    "440034e4a1acc98743c8d06cba2c2701958eb3dbcf124b8301eed8015356cdc8"
    "1bdca793c1f9b2ffd76249d17ea7ff34a6f4a98ddd38d595cf3c0765996da70a"
)


class _H(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _fac():  # type: ignore[no-untyped-def]
    return lambda: _H()


def _det() -> GoldenScriptedDetector:
    return GoldenScriptedDetector([_FAIL] * 3 + [_PASS] * 3)


class CandidateMeasurementGoldenTests(unittest.TestCase):
    def test_spine_measurement_is_canonical(self) -> None:
        cal = _cal_store(known_bad=_KB, known_good=_KG)
        sealed = cal.seal_set("default")
        m = produce_candidate_measurement(
            prepare_candidate(sealed, resolve=golden_resolver(_det()), detector_id="d",
                              trust_policy=_REF_TP, backend_guard=test_guard_policy),
            make_sandbox=_fac(), budget=_BUDGET, backend_guard=test_guard_policy,
            trust_policy=_REF_TP, trials=3,
        )
        self.assertEqual(m.oracle_head, _ORACLE_HEAD)
        self.assertEqual(m.coverage_digest, _COVERAGE)
        self.assertEqual(m.resolved_profile_digest, _RPD)
        self.assertEqual(m.trust_policy_digest, _TPD)
        self.assertEqual(m.guard_policy_digest, _GPD)
        self.assertEqual(m.execution_identity_digest, _EID)
        self.assertEqual(m.subject_identity, _SUBJECT)
        self.assertEqual(m.fixture_ids, ("b1", "g1"))
        ref = calibration_result_ref(
            "p1", m.oracle_head, m.subject_identity, passed=True,  # type: ignore[arg-type]
            n_bad=len(m.result.outcomes), fixture_ids=[o.fixture_id for o in m.result.outcomes],
        )
        self.assertEqual(ref, _REF)

    def test_run_calibration_persists_the_same_measured_pass(self) -> None:
        cal = _cal_store(known_bad=_KB, known_good=_KG)
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="p1-1"))
        out = run_calibration("p1", store=s, calibration_store=cal, make_sandbox=_fac(), detector_id="d",
                              resolve=golden_resolver(_det()), budget=_BUDGET,
                              approval=_appr("gov1", op="p1-cal"), trials=3,
                              backend_guard=test_guard_policy, trust_policy=_REF_TP)
        self.assertTrue(out.passed)
        self.assertEqual(out.calibration_result_ref, _REF)              # SAME ref the spine derives
        self.assertEqual(cal.set_head("default"), _ORACLE_HEAD)         # SAME measured head
        binding = s.pass_binding(_REF, "p1", _ORACLE_HEAD)
        self.assertIsNotNone(binding)
        assert binding is not None
        subject, set_id = binding
        self.assertEqual(subject, _SUBJECT)                            # governance cannot rewrite it
        self.assertEqual(set_id, "default")

    def test_run_recalibration_signs_the_same_subject(self) -> None:
        cal = _cal_store(known_bad=_KB, known_good=_KG)
        att = run_recalibration(
            policy_id="p1", set_id="default", calibration_store=cal, make_sandbox=_fac(),
            detector_id="d", resolve=golden_resolver(_det()), requested_subject_identity="req-1",
            tier_generation="tier-h", budget=_BUDGET, issuer="cal-gov-1", nonce="n1", now=100.0,
            signer=SeedSigner(_SEED), trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP,
        )
        verify_measurement(att, verifier=KeyVerifier(public_key(_SEED)))
        self.assertIs(att.outcome, VerdictType.PASS)
        self.assertEqual(att.subject_identity, _SUBJECT)               # SAME measured subject as the spine
        self.assertEqual(att.run_id, _RECAL_RUN_ID)
        self.assertEqual(att.signature, _RECAL_SIG)                    # byte-stable signed envelope

    def test_the_two_consumers_cannot_diverge(self) -> None:
        # the load-bearing invariant in one assertion: the enable path's PERSISTED subject and the signed
        # runner's SIGNED subject are the SAME measured identity — because both flow through one spine.
        cal_a = _cal_store(known_bad=_KB, known_good=_KG)
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="p1-1"))
        run_calibration("p1", store=s, calibration_store=cal_a, make_sandbox=_fac(), detector_id="d",
                        resolve=golden_resolver(_det()), budget=_BUDGET, approval=_appr("gov1", op="p1-cal"),
                        trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP)
        persisted = s.pass_binding(_REF, "p1", cal_a.set_head("default"))
        assert persisted is not None

        cal_b = _cal_store(known_bad=_KB, known_good=_KG)
        att = run_recalibration(
            policy_id="p1", set_id="default", calibration_store=cal_b, make_sandbox=_fac(),
            detector_id="d", resolve=golden_resolver(_det()), requested_subject_identity="req-1",
            tier_generation="tier-h", budget=_BUDGET, issuer="cal-gov-1", nonce="n1", now=100.0,
            signer=SeedSigner(_SEED), trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP,
        )
        self.assertEqual(persisted[0], att.subject_identity)


if __name__ == "__main__":
    unittest.main()
