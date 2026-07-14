"""tests/test_run_admission.py — 3.5 S3-completion: the LIVE-PATH run-result admission typestate + currency.
Run: python3 -m unittest discover -s tests

The admission core (``gate/run_admission.py``, distinct from the 3.4 fixture gate). Properties pinned:
  * STRUCTURAL: the MEASURED subject is recomputed SOLELY from the authoritative engine return and must
    equal the DISPATCHED target (the runner-bypass catch) — measured-vs-plan, never plan-vs-plan, and
    ordered BEFORE the live subject check so a runner deviation is caught regardless of live state;
  * LIVE currency (CP1): admission's OWN reads (current_attestation + set_head, fail-closed) prove the set
    has not drifted (SET_HEAD_STALE / AUTHORIZED_SET_MOVED) and the subject is still authorized
    (AUTHORIZED_SUBJECT_MOVED);
  * every refusal is a DISTINCT typed RunAdmissionRefusal that still BLOCKS (Verdict(ERROR, RUN_UNADMITTED));
  * PROOF-GATED construction: AdmittedRunResult requires a result-bound live-admission proof minted only by
    admit_run_result, so a direct construction cannot bypass the live checks.
"""
from __future__ import annotations

import dataclasses
import unittest

from core import Reason, Verdict, VerdictType
from engine.runner import EngineRunResult, ExecutionIdentity, TrialReport
from gate.attestation import IDENTITY_CONTRACT_VERSION, calibrated_subject_identity
from gate.run_admission import (
    _LiveAdmissionProof,
    _mint_live_admission_proof,
    AdmittedRunResult,
    AuthorizedRunPlan,
    BlockingRefusal,
    RunAdmissionError,
    RunAdmissionRefusal,
    UnadmittedRunResult,
    admit_run_result,
)

_PASS = Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)

_RPD, _TPD, _GPD = "profile-digest", "trust-digest", "guard-digest"
_EXEC = ExecutionIdentity(backend="ObservedOCISandbox", image_ref="sha256:abc",
                          isolation_level="hermetic", observer_config_hash="obs")
_EID = _EXEC.digest()
_SUBJECT = calibrated_subject_identity(_RPD, _TPD, _GPD, _EID)         # what a legitimate run measures
_SUBJECT2 = calibrated_subject_identity(_RPD, _TPD, "guard-2", _EID)   # a DIFFERENT measured subject
_SET = "set-1"
_HEAD = "oracle-head-abc"


def _report(*, rpd: str | None = _RPD, tpd: str | None = _TPD, gpd: str | None = _GPD,
            execution_identity: ExecutionIdentity | None = _EXEC,
            aggregate: Verdict = _PASS) -> TrialReport:
    return TrialReport(
        trials=(aggregate,), trials_configured=1, short_circuited=False, aggregate=aggregate,
        execution_identity=execution_identity, trust_policy_digest=tpd,
        resolved_profile_digest=rpd, guard_policy_digest=gpd, detector_id="retry",
    )


def _plan(*, target: str = _SUBJECT, authorized: str = _SUBJECT, set_id: str = _SET,
          icv: int = IDENTITY_CONTRACT_VERSION) -> AuthorizedRunPlan:
    return AuthorizedRunPlan(policy_id="p1", target_subject=target,
                             authorized_context=(set_id, authorized, icv))


class _FakeGovernance:
    """A fake AdmissionGovernanceView. Defaults to the CURRENT, matching attestation; each dimension can be
    moved or made to raise to exercise a specific live refusal."""

    def __init__(self, *, set_id: str = _SET, bound_head: str = _HEAD, subject: str = _SUBJECT,
                 attestation_none: bool = False, live_head: str | None = _HEAD,
                 raise_attn: bool = False, raise_head: bool = False) -> None:
        self._attn = None if attestation_none else (set_id, bound_head, subject)
        self._live_head = live_head
        self._raise_attn = raise_attn
        self._raise_head = raise_head

    def current_attestation(self, policy_id: str) -> tuple[str, str, str] | None:
        if self._raise_attn:
            raise RuntimeError("tier-transition chain failed verification")
        return self._attn

    def oracle_head_for(self, set_id: str) -> str | None:
        if self._raise_head:
            raise RuntimeError("calibration store unreachable")
        return self._live_head


def _admit(plan: AuthorizedRunPlan, report: TrialReport,
           gov: _FakeGovernance) -> AdmittedRunResult | BlockingRefusal:
    return admit_run_result(UnadmittedRunResult(plan=plan, result=EngineRunResult(trial_report=report)),
                            governance=gov)


def _proof(*, policy_id: str = "p1", set_id: str = _SET, head: str = _HEAD,
           subject: str = _SUBJECT) -> _LiveAdmissionProof:
    return _mint_live_admission_proof(policy_id=policy_id, set_id=set_id, oracle_head=head, subject=subject)


class HappyPathTests(unittest.TestCase):
    def test_current_run_is_admitted_with_scoped_metadata(self) -> None:
        res = _admit(_plan(), _report(), _FakeGovernance())
        self.assertIsInstance(res, AdmittedRunResult)
        assert isinstance(res, AdmittedRunResult)
        self.assertEqual(res.measured_subject, _SUBJECT)
        self.assertEqual(res.admitted_set_id, _SET)       # scoped metadata (Fred: not an unscoped head)
        self.assertEqual(res.bound_oracle_head, _HEAD)
        self.assertIs(res.verdict, _PASS)                 # single source: the report's aggregate

    def test_admitted_verdict_is_a_derived_property(self) -> None:
        rep = _report(aggregate=_FAIL)
        res = _admit(_plan(), rep, _FakeGovernance())
        assert isinstance(res, AdmittedRunResult)
        self.assertIs(res.verdict, rep.aggregate)
        self.assertIs(res.verdict, _FAIL)

    def test_recompute_matches_the_calibration_path_composite(self) -> None:
        expected = calibrated_subject_identity(_RPD, _TPD, _GPD, _EID, icv=IDENTITY_CONTRACT_VERSION)
        res = _admit(_plan(target=expected, authorized=expected), _report(),
                     _FakeGovernance(subject=expected))
        assert isinstance(res, AdmittedRunResult)
        self.assertEqual(res.measured_subject, expected)


class StructuralRefusalTests(unittest.TestCase):
    def test_icv_exact_int_typing_rejects_bool_str_and_bad_value(self) -> None:
        bad_icvs: tuple[object, ...] = (True, False, "1", IDENTITY_CONTRACT_VERSION + 1, 0)
        for bad in bad_icvs:
            with self.subTest(icv=repr(bad)):
                plan = AuthorizedRunPlan(policy_id="p1", target_subject=_SUBJECT,
                                         authorized_context=(_SET, _SUBJECT, bad))  # type: ignore[arg-type]
                res = _admit(plan, _report(), _FakeGovernance())
                assert isinstance(res, BlockingRefusal)
                self.assertIs(res.reason, RunAdmissionRefusal.ICV_UNSUPPORTED)

    def test_mint_incoherent_plan_refused(self) -> None:
        res = _admit(_plan(target=_SUBJECT, authorized="other"), _report(), _FakeGovernance())
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.UNAUTHORIZED_SUBJECT)

    def test_incomplete_coordinates_refused(self) -> None:
        for kwargs in ({"rpd": None}, {"tpd": None}, {"gpd": None}, {"execution_identity": None},
                       {"rpd": ""}):
            with self.subTest(missing=next(iter(kwargs))):
                res = _admit(_plan(), _report(**kwargs), _FakeGovernance())  # type: ignore[arg-type]
                assert isinstance(res, BlockingRefusal)
                self.assertIs(res.reason, RunAdmissionRefusal.INCOMPLETE_COORDINATES)

    def test_subject_drift_is_the_runner_bypass_catch(self) -> None:
        # the report recomputes to _SUBJECT2 (a DIFFERENT guard) but the plan dispatched _SUBJECT.
        res = _admit(_plan(target=_SUBJECT, authorized=_SUBJECT), _report(gpd="guard-2"), _FakeGovernance())
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SUBJECT_DRIFT)

    def test_structural_precedes_live_reads(self) -> None:
        # a structural failure wins even when the live governance would also refuse (attestation None).
        res = _admit(_plan(icv=IDENTITY_CONTRACT_VERSION + 1), _report(),
                     _FakeGovernance(attestation_none=True))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.ICV_UNSUPPORTED)


class RunnerBypassOrderingTests(unittest.TestCase):
    def test_run_matching_live_but_not_the_plan_is_subject_drift_not_authorized_moved(self) -> None:
        # THE bypass the board flagged: live subject = S2, plan dispatched S1, the runner measured S2 (the
        # live subject) instead of S1. This must be SUBJECT_DRIFT (the runner did not execute the plan) —
        # NOT AUTHORIZED_SUBJECT_MOVED — because the structural measured-vs-plan check runs FIRST and the
        # execution was unauthorized regardless of whether it happens to match live state.
        res = _admit(_plan(target=_SUBJECT, authorized=_SUBJECT), _report(gpd="guard-2"),
                     _FakeGovernance(subject=_SUBJECT2))  # live subject == the measured S2
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SUBJECT_DRIFT)


class LiveCurrencyRefusalTests(unittest.TestCase):
    def test_attestation_none_fail_closed(self) -> None:
        res = _admit(_plan(), _report(), _FakeGovernance(attestation_none=True))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE)

    def test_attestation_raises_fail_closed(self) -> None:
        res = _admit(_plan(), _report(), _FakeGovernance(raise_attn=True))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.LIVE_ATTESTATION_UNAVAILABLE)

    def test_oracle_head_none_fail_closed(self) -> None:
        res = _admit(_plan(), _report(), _FakeGovernance(live_head=None))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.ORACLE_UNAVAILABLE)

    def test_oracle_head_raises_fail_closed(self) -> None:
        res = _admit(_plan(), _report(), _FakeGovernance(raise_head=True))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.ORACLE_UNAVAILABLE)

    def test_authorized_set_moved(self) -> None:
        # the live attestation is bound to a DIFFERENT set than the plan authorized (a rebind).
        res = _admit(_plan(set_id=_SET), _report(), _FakeGovernance(set_id="set-2", subject=_SUBJECT))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.AUTHORIZED_SET_MOVED)

    def test_set_head_stale(self) -> None:
        # the bound head differs from the live set_head — the set drifted while the policy stayed ENABLED.
        res = _admit(_plan(), _report(), _FakeGovernance(bound_head="old-head", live_head="new-head"))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SET_HEAD_STALE)

    def test_authorized_subject_moved(self) -> None:
        # structural passes (measured == target) but governance moved the authorized subject.
        res = _admit(_plan(target=_SUBJECT, authorized=_SUBJECT), _report(),
                     _FakeGovernance(subject="a-newly-authorized-subject"))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.AUTHORIZED_SUBJECT_MOVED)

    def test_set_continuity_checked_before_head(self) -> None:
        # a moved set is reported as AUTHORIZED_SET_MOVED even if the head also differs (ordering).
        res = _admit(_plan(set_id=_SET), _report(),
                     _FakeGovernance(set_id="set-2", bound_head="x", live_head="y"))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.AUTHORIZED_SET_MOVED)

    def test_moved_set_with_unavailable_oracle_is_set_moved_not_oracle(self) -> None:
        # forensic ordering (dissent): set-continuity is checked BEFORE the oracle query, so a moved set
        # PLUS an unavailable oracle is the actionable AUTHORIZED_SET_MOVED, not ORACLE_UNAVAILABLE.
        res = _admit(_plan(set_id=_SET), _report(), _FakeGovernance(set_id="set-2", live_head=None))
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.AUTHORIZED_SET_MOVED)


class EveryRefusalBlocksTests(unittest.TestCase):
    def test_every_refusal_carries_a_blocking_error_verdict(self) -> None:
        for res in (
            _admit(_plan(icv=99), _report(), _FakeGovernance()),
            _admit(_plan(target=_SUBJECT, authorized="x"), _report(), _FakeGovernance()),
            _admit(_plan(), _report(execution_identity=None), _FakeGovernance()),
            _admit(_plan(), _report(gpd="guard-2"), _FakeGovernance()),
            _admit(_plan(), _report(), _FakeGovernance(attestation_none=True)),
            _admit(_plan(), _report(), _FakeGovernance(live_head=None)),
            _admit(_plan(set_id=_SET), _report(), _FakeGovernance(set_id="set-2")),
            _admit(_plan(), _report(), _FakeGovernance(bound_head="a", live_head="b")),
            _admit(_plan(), _report(), _FakeGovernance(subject="other")),
        ):
            assert isinstance(res, BlockingRefusal)
            self.assertIs(res.verdict.status, VerdictType.ERROR)
            self.assertIs(res.verdict.reason, Reason.RUN_UNADMITTED)


class ProofGatedConstructionTests(unittest.TestCase):
    """Construction is gated by a RESULT-BOUND proof (not a reusable grant): the metadata is DERIVED from
    the proof (no caller-supplied fields to forge), the proof cannot be constructed outside the module, and
    the constructor verifies proof↔run coherence + re-runs the pure structural validator. A direct
    construction can bypass NEITHER the live checks NOR the report recompute NOR reuse a foreign proof."""

    def test_proof_cannot_be_constructed_without_the_mint_sentinel(self) -> None:
        # a caller cannot fabricate a proof — the constructor refuses any key but the module-private mint.
        with self.assertRaises(RunAdmissionError):
            _LiveAdmissionProof(policy_id="p1", set_id=_SET, oracle_head=_HEAD, subject=_SUBJECT)

    def test_admitted_metadata_is_derived_from_the_proof(self) -> None:
        # the scoped metadata comes off the proof, not caller-supplied fields.
        adm = AdmittedRunResult(plan=_plan(), report=_report(), _proof=_proof())
        self.assertEqual(adm.admitted_set_id, _SET)
        self.assertEqual(adm.bound_oracle_head, _HEAD)
        self.assertEqual(adm.measured_subject, _SUBJECT)

    def test_report_drift_with_valid_proof_still_raises(self) -> None:
        # a genuine proof but a report recomputing to a different subject fails the structural re-run.
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=_plan(target=_SUBJECT), report=_report(gpd="guard-2"),
                              _proof=_proof(subject=_SUBJECT))

    def test_proof_subject_not_report_recomputed_raises(self) -> None:
        # a proof minted for _SUBJECT2 cannot admit a run that measured _SUBJECT (proof/run mismatch).
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=_plan(target=_SUBJECT), report=_report(), _proof=_proof(subject=_SUBJECT2))

    def test_proof_from_a_different_policy_raises(self) -> None:
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=_plan(target=_SUBJECT), report=_report(),
                              _proof=_proof(policy_id="another-policy"))

    def test_bad_icv_with_valid_proof_raises(self) -> None:
        plan = AuthorizedRunPlan(policy_id="p1", target_subject=_SUBJECT,
                                 authorized_context=(_SET, _SUBJECT, IDENTITY_CONTRACT_VERSION + 1))
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=plan, report=_report(), _proof=_proof())


class TypestateTests(unittest.TestCase):
    def test_admitted_and_refusal_are_frozen(self) -> None:
        adm = _admit(_plan(), _report(), _FakeGovernance())
        assert isinstance(adm, AdmittedRunResult)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            adm.report = _report()  # a real field (measured_subject etc. are derived properties)  # type: ignore[misc]
        ref = _admit(_plan(), _report(), _FakeGovernance(attestation_none=True))
        assert isinstance(ref, BlockingRefusal)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ref.detail = "x"  # type: ignore[misc]

    def test_plan_derives_set_subject_icv_from_the_single_context_tuple(self) -> None:
        plan = _plan(authorized="subj", set_id="set-7", icv=IDENTITY_CONTRACT_VERSION)
        self.assertEqual(plan.authorized_set, "set-7")
        self.assertEqual(plan.authorized_subject, "subj")
        self.assertEqual(plan.identity_contract_version, IDENTITY_CONTRACT_VERSION)

    def test_measured_coordinates_read_solely_from_the_report(self) -> None:
        un = UnadmittedRunResult(plan=_plan(),
                                 result=EngineRunResult(trial_report=_report(rpd="RP", tpd="TP", gpd="GP")))
        self.assertEqual(un.measured_coordinates(), ("RP", "TP", "GP", _EID))


if __name__ == "__main__":
    unittest.main()
