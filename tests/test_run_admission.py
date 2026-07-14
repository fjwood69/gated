"""tests/test_run_admission.py — 3.5 S3-completion: the LIVE-PATH run-result admission typestate.
Run: python3 -m unittest discover -s tests

The isolated admission core (``gate/run_admission.py``, distinct from the 3.4 fixture gate). Properties
pinned:
  * the MEASURED subject is recomputed SOLELY from the authoritative engine return (``result.trial_report``)
    and compared vs the plan's dispatched target + governance-authorized subject — measured-vs-authorized,
    never plan-vs-plan;
  * the recompute is the SAME composite ``calibrated_subject_identity`` the calibration path signs, so a
    legitimately-authorized run admits (no spurious drift);
  * every refusal is a DISTINCT typed ``RunAdmissionRefusal`` (fail-closed, layered order) that still BLOCKS
    (``Verdict(ERROR, RUN_UNADMITTED)`` → action_required), never a silent drop to neutral;
  * ``AdmittedRunResult`` is the sole admit type; its verdict is the report's single-source aggregate and its
    constructor refuses an incoherent admission (defence in depth).
"""
from __future__ import annotations

import dataclasses
import unittest

from core import Reason, Verdict, VerdictType
from core.chain import content_digest
from engine.runner import EngineRunResult, ExecutionIdentity, TrialReport
from gate.attestation import IDENTITY_CONTRACT_VERSION, calibrated_subject_identity
from gate.run_admission import (
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

_RPD = "profile-digest"
_TPD = "trust-digest"
_GPD = "guard-digest"
_EXEC = ExecutionIdentity(backend="ObservedOCISandbox", image_ref="sha256:abc",
                          isolation_level="hermetic", observer_config_hash="obs")
_EID = _EXEC.digest()
# the subject a legitimate run measures — the SAME composite the calibration path signs.
_SUBJECT = calibrated_subject_identity(_RPD, _TPD, _GPD, _EID)
_SET = "set-1"


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


def _unadmitted(plan: AuthorizedRunPlan, report: TrialReport) -> UnadmittedRunResult:
    return UnadmittedRunResult(plan=plan, result=EngineRunResult(trial_report=report))


class HappyPathTests(unittest.TestCase):
    def test_legitimate_run_is_admitted_with_the_measured_subject(self) -> None:
        res = admit_run_result(_unadmitted(_plan(), _report()))
        self.assertIsInstance(res, AdmittedRunResult)
        assert isinstance(res, AdmittedRunResult)
        self.assertEqual(res.measured_subject, _SUBJECT)  # recomputed from the report's coords
        self.assertIs(res.verdict, _PASS)                 # single source: the report's aggregate

    def test_admitted_verdict_is_a_derived_property_of_the_report_aggregate(self) -> None:
        # single source: verdict is a DERIVED property (no stored copy) — it IS report.aggregate, so it
        # cannot diverge from the report the admission inspected (same discipline as EngineRunResult.verdict).
        rep = _report(aggregate=_FAIL)
        adm = AdmittedRunResult(plan=_plan(), report=rep, measured_subject=_SUBJECT)
        self.assertIs(adm.verdict, rep.aggregate)
        self.assertIs(adm.verdict, _FAIL)

    def test_a_real_fail_run_admits_and_carries_the_fail_verdict(self) -> None:
        # admission attests IDENTITY, not the verdict value: a FAIL with a matching identity is ADMITTED
        # (and blocks downstream via its FAIL verdict), distinct from a refusal.
        res = admit_run_result(_unadmitted(_plan(), _report(aggregate=_FAIL)))
        self.assertIsInstance(res, AdmittedRunResult)
        assert isinstance(res, AdmittedRunResult)
        self.assertIs(res.verdict, _FAIL)


class MeasuredNotPlanTests(unittest.TestCase):
    def test_measured_subject_comes_from_the_report_not_the_plan(self) -> None:
        # the operand-source proof: hold the plan's target fixed but change a REPORT coordinate -> the
        # recomputed measured subject changes -> drift. The subject is measured off the return, never the plan.
        res = admit_run_result(_unadmitted(_plan(), _report(gpd="a-DIFFERENT-guard")))
        self.assertIsInstance(res, BlockingRefusal)
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SUBJECT_DRIFT)

    def test_recompute_matches_the_calibration_path_composite(self) -> None:
        # the admitted measured subject equals the composite the calibration path signs for the SAME coords
        # (recalibration.py) — so a legitimately-calibrated identity is not spuriously rejected at admission.
        expected = calibrated_subject_identity(_RPD, _TPD, _GPD, _EID, icv=IDENTITY_CONTRACT_VERSION)
        res = admit_run_result(_unadmitted(_plan(target=expected, authorized=expected), _report()))
        self.assertIsInstance(res, AdmittedRunResult)
        assert isinstance(res, AdmittedRunResult)
        self.assertEqual(res.measured_subject, expected)

    def test_execution_coordinate_is_the_identity_digest(self) -> None:
        # the fourth coordinate is the digest of the parent-measured execution identity (not a raw field).
        rpd, tpd, gpd, eid = _unadmitted(_plan(), _report()).measured_coordinates()
        self.assertEqual((rpd, tpd, gpd), (_RPD, _TPD, _GPD))
        self.assertEqual(eid, content_digest({
            "backend": "ObservedOCISandbox", "image_ref": "sha256:abc",
            "isolation_level": "hermetic", "observer_config_hash": "obs"}))


class RefusalTests(unittest.TestCase):
    def test_icv_mismatch_refused_first(self) -> None:
        # a plan authorizing an unimplemented identity contract is refused BEFORE anything else — even with
        # otherwise-incomplete coordinates (layer ordering: ICV is the first gate).
        res = admit_run_result(_unadmitted(
            _plan(icv=IDENTITY_CONTRACT_VERSION + 1),
            _report(execution_identity=None)))  # also incomplete, but ICV must win
        self.assertIsInstance(res, BlockingRefusal)
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.ICV_UNSUPPORTED)

    def test_unauthorized_subject_refused(self) -> None:
        # the plan's dispatch target != the governance-authorized subject -> the run was dispatched against a
        # subject the policy does not authorize (compare vs authorized context).
        res = admit_run_result(_unadmitted(
            _plan(target=_SUBJECT, authorized="some-OTHER-authorized-subject"), _report()))
        self.assertIsInstance(res, BlockingRefusal)
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.UNAUTHORIZED_SUBJECT)

    def test_incomplete_coordinates_refused_on_each_missing_coordinate(self) -> None:
        for kwargs in ({"rpd": None}, {"tpd": None}, {"gpd": None}, {"execution_identity": None}):
            with self.subTest(missing=next(iter(kwargs))):
                res = admit_run_result(_unadmitted(_plan(), _report(**kwargs)))  # type: ignore[arg-type]
                self.assertIsInstance(res, BlockingRefusal)
                assert isinstance(res, BlockingRefusal)
                self.assertIs(res.reason, RunAdmissionRefusal.INCOMPLETE_COORDINATES)

    def test_empty_string_coordinate_is_not_present(self) -> None:
        # an empty-string coordinate does NOT count as present (the empty-string identity-downgrade guard,
        # matching the attestation module) -> refused as incomplete, not hashed into a meaningless composite.
        res = admit_run_result(_unadmitted(_plan(), _report(rpd="")))
        self.assertIsInstance(res, BlockingRefusal)
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.INCOMPLETE_COORDINATES)

    def test_subject_drift_refused(self) -> None:
        res = admit_run_result(_unadmitted(_plan(target="not-the-measured-subject",
                                                 authorized="not-the-measured-subject"), _report()))
        self.assertIsInstance(res, BlockingRefusal)
        assert isinstance(res, BlockingRefusal)
        self.assertIs(res.reason, RunAdmissionRefusal.SUBJECT_DRIFT)

    def test_every_refusal_blocks_the_merge_fail_closed(self) -> None:
        # a refusal is never a silent drop: it carries a blocking ERROR verdict (-> action_required).
        for res in (
            admit_run_result(_unadmitted(_plan(icv=99), _report())),
            admit_run_result(_unadmitted(_plan(authorized="x"), _report())),
            admit_run_result(_unadmitted(_plan(), _report(execution_identity=None))),
            admit_run_result(_unadmitted(_plan(target="x", authorized="x"), _report())),
        ):
            assert isinstance(res, BlockingRefusal)
            self.assertIs(res.verdict.status, VerdictType.ERROR)
            self.assertIs(res.verdict.reason, Reason.RUN_UNADMITTED)


class TypestateTests(unittest.TestCase):
    def test_all_types_are_frozen(self) -> None:
        plan = _plan()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            plan.policy_id = "other"  # type: ignore[misc]
        un = _unadmitted(plan, _report())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            un.plan = plan  # type: ignore[misc]
        adm = admit_run_result(un)
        assert isinstance(adm, AdmittedRunResult)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            adm.measured_subject = "x"  # type: ignore[misc]
        ref = admit_run_result(_unadmitted(_plan(target="x", authorized="x"), _report()))
        assert isinstance(ref, BlockingRefusal)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            ref.detail = "x"  # type: ignore[misc]

    def test_plan_derives_set_subject_icv_from_the_single_context_tuple(self) -> None:
        plan = _plan(authorized="subj", set_id="set-7", icv=IDENTITY_CONTRACT_VERSION)
        self.assertEqual(plan.authorized_set, "set-7")
        self.assertEqual(plan.authorized_subject, "subj")
        self.assertEqual(plan.identity_contract_version, IDENTITY_CONTRACT_VERSION)

    def test_admitted_ctor_refuses_incoherent_subject_defence_in_depth(self) -> None:
        # constructing an AdmittedRunResult whose measured_subject != the plan's target raises, so a
        # hand-assembled admitted result for the wrong identity fails closed rather than publishing.
        with self.assertRaises(RunAdmissionError):
            AdmittedRunResult(plan=_plan(target=_SUBJECT), report=_report(),
                              measured_subject="a-different-subject")


if __name__ == "__main__":
    unittest.main()
