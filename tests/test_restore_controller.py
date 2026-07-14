"""3.5 job-1 step-3 — the RESTORE CONTROLLER + the full re-calibration loop. Run:
python3 -m unittest discover -s tests

The crux of Job 1: a signed clean PASS on an ENABLED-but-drifted policy re-attests it (evidence
advances, tier unchanged) and live enforcement RESUMES; a FAIL is a no-op on governance state (the
policy stays blocking); a stale/untrusted/demoted case is refused. The end-to-end test walks the whole
loop: enable -> fixture append (live UNATTESTABLE) -> runner PASS -> controller RESTORED -> live
RUN_ENFORCING again.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Command, Fixtures, IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import FixtureLabel
from gate.signing import KeyVerifier, SeedSigner, public_key
from gate.attestation_store import MeasurementAttestationStore
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore, ChangeOp
from gate.calibration_store import AdmissionCapability
from gate.detector_registry import DetectorRegistry, profile_of
from gate.gatekeeper import resolve_disposition
from gate.policy_state import Disposition, PolicyState
from gate.policy_store import PolicyStore
from gate.recalibration import run_recalibration
from gate.restore_controller import (
    ReAttestCapability,
    RestoreController,
    RestoreResult,
)
from sandbox.noop import NoOpSandbox
from gate.trust_policy import resolve_trust_policy
from tests._backend_optout import test_guard_policy
_REF_TP = resolve_trust_policy("trust-policy:completed-only")

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_SEED = bytes(range(32))
_PUB = public_key(_SEED)
_ISSUER = "cal-gov-1"
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


_ADMIT_CAP = AdmissionCapability()


class _HermeticNoOp(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _factory():  # type: ignore[no-untyped-def]
    return lambda: _HermeticNoOp()


class _ScriptedDetector:
    def __init__(self, verdicts: list[Verdict]) -> None:
        self.fixtures = Fixtures()
        self._verdicts = verdicts
        self._i = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        v = self._verdicts[self._i]
        self._i += 1
        return v


class _OtherEntrypoint(_ScriptedDetector):
    """Same module, DIFFERENT entrypoint -> a DIFFERENT resolved profile -> a DIFFERENT measured subject
    (v3 governance-target negatives)."""

    def entrypoint(self) -> Command:
        return Command(argv=("false",))


def _appr(*p: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="admit", rationale="r", operation_id=op)


def _cal_store() -> CalibrationStore:
    c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-rc-cal-")) / "c.db")
    c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
             set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad1")
    c.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="2"), fixture_id="g1",
             set_id="X", label=FixtureLabel.KNOWN_GOOD, payload=b"good1")
    return c


def _policy_store_enabled(head: str) -> PolicyStore:
    s = PolicyStore(Path(tempfile.mkdtemp(prefix="mv-rc-pol-")) / "t.db")
    s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="a"))
    s.enter_calibrating("p1", approval=_appr("g1", op="b"), set_id="X", pinned_set_version=head,
                        detector_id=_DET, expected_profile_digest="pd", expected_trust_policy_digest="tp",
                        expected_guard_policy_digest="gp", identity_contract_version=1)
    s.record_calibration_pass("cal-0", policy_id="p1", pinned_set_version=head,
                              detector_identity=_DET, set_id="X", identity_contract_version=1)
    s.transition("p1", PolicyState.ENABLED, approval=_appr("g1", op="c"),
                 calibration_result_ref="cal-0", set_id="X", pinned_set_version=head,
                 detector_identity=_DET, identity_contract_version=1)
    return s


def _att_store() -> MeasurementAttestationStore:
    return MeasurementAttestationStore(Path(tempfile.mkdtemp(prefix="mv-rc-att-")) / "a.db")


def _controller(s: PolicyStore, c: CalibrationStore, *, trusted: bool = True,
                att_store: MeasurementAttestationStore | None = None) -> RestoreController:
    return RestoreController(
        ReAttestCapability(s), issuer_public_keys={_ISSUER: _PUB},
        oracle_head_for=c.set_head, attestation_store=att_store or _att_store(),
        identity_trusted=lambda _i: trusted)


def _run(c: CalibrationStore, verdicts: list[Verdict], *, tier_gen: str = "tg", nonce: str = "n1",  # type: ignore[no-untyped-def]
         requested: str | None = None, detector: "_ScriptedDetector | None" = None, set_id: str = "X"):
    # detectors arrive by NAME through a trusted registry via the ATOMIC bundle (P1-3 v3); the SIGNED
    # subject is measurement-derived. ``requested`` defaults to the policy's authorized subject (_DET).
    # ``set_id`` selects WHICH set to calibrate against — the SAME detector against a different set yields
    # the SAME measurement-derived subject (profile/env unchanged) but a different signed set_id.
    det = detector if detector is not None else _ScriptedDetector(verdicts)
    reg = DetectorRegistry()
    reg.register("d", lambda: det, accepted_profile_digest=profile_of("d", det).digest())
    return run_recalibration(
        policy_id="p1", set_id=set_id, calibration_store=c, make_sandbox=_factory(),
        detector_id="d", resolve=reg.resolve_bundle,
        requested_subject_identity=(requested if requested is not None else _DET), tier_generation=tier_gen,
        budget=_BUDGET, issuer=_ISSUER, nonce=nonce, now=100.0, signer=SeedSigner(_SEED), trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP)


# The deterministic MEASUREMENT-DERIVED subject identity for this module's detector + NoOp environment
# (P1-3): resolved-profile digest (module bytes + entrypoint + config) ⊕ parent-measured execution
# identity. The whole restore loop binds and enforces THIS — not a caller string. Computed from one clean
# pass; constant across runs because both components are deterministic here.
def _canonical_subject() -> str:
    att = _run(_cal_store(), [_FAIL] * 3 + [_PASS] * 3, requested="bootstrap")
    assert att.subject_identity is not None
    return att.subject_identity


_DET = _canonical_subject()


class RestoreControllerTests(unittest.TestCase):
    def test_full_loop_enable_drift_recal_restore_reenforce(self) -> None:
        c = _cal_store()
        h0 = c.set_head("X")
        s = _policy_store_enabled(h0)
        # enabled + head current -> enforcing.
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.RUN_ENFORCING)
        # a security engineer appends a new known-bad -> set_head moves -> live UNATTESTABLE (blocking).
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.BLOCK_ACTION_REQUIRED)
        # async re-cal: detector now catches BOTH known-bad (b1,b2) and passes g1 -> clean PASS @ new head.
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3, tier_gen=s.policy_head("p1"))
        self.assertIs(att.outcome, VerdictType.PASS)
        # the restore controller re-attests.
        outcome = _controller(s, c).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.RESTORED)
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)   # tier NEVER changed
        # live enforcement RESUMES — the evidence now matches the current head.
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.RUN_ENFORCING)

    def test_fail_is_noop_on_governance_state(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        head_before = s.policy_head("p1")
        # re-cal MISSES the new known-bad -> FAIL.
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3 + [_PASS] * 3)  # catches b1, MISSES b2, passes g1
        self.assertIs(att.outcome, VerdictType.FAIL)
        outcome = _controller(s, c).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.REFUSED_NOT_CLEAN_PASS)
        self.assertEqual(s.policy_head("p1"), head_before)  # NO record appended — meter didn't move tier
        # still blocking (transiently UNATTESTABLE).
        self.assertIs(resolve_disposition("p1", expected_detector_identity=_DET, store=s,
                                          snapshot=None, snapshot_key=b"k", now=1.0,
                                          oracle_head_for=c.set_head).disposition,
                      Disposition.BLOCK_ACTION_REQUIRED)

    def test_bad_issuer_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)
        ctrl = RestoreController(ReAttestCapability(s), issuer_public_keys={"other": _PUB},
                                 oracle_head_for=c.set_head, attestation_store=_att_store())
        self.assertIs(ctrl.attempt_restore(att).result, RestoreResult.REFUSED_UNTRUSTED)

    def test_wrong_key_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)
        ctrl = RestoreController(ReAttestCapability(s), issuer_public_keys={_ISSUER: public_key(bytes(range(1, 33)))},
                                 oracle_head_for=c.set_head, attestation_store=_att_store())
        self.assertIs(ctrl.attempt_restore(att).result, RestoreResult.REFUSED_UNTRUSTED)

    def test_stale_oracle_head_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)  # PASS bound to the CURRENT head
        # the set drifts AGAIN after the measurement, before restore.
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift2"), fixture_id="b9",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad9")
        self.assertIs(_controller(s, c).attempt_restore(att).result, RestoreResult.REFUSED_ORACLE_STALE)

    def test_revoked_identity_refused(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)
        self.assertIs(_controller(s, c, trusted=False).attempt_restore(att).result,
                      RestoreResult.REFUSED_UNTRUSTED)

    def test_restore_persists_the_signed_attestation(self) -> None:
        # board blocker #3: the re-attest ref must bind a DURABLE, immutable, signed attestation.
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3, tier_gen=s.policy_head("p1"))
        store = _att_store()
        outcome = _controller(s, c, att_store=store).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.RESTORED)
        from gate.attestation import attestation_ref, verify_measurement
        ref = attestation_ref(att)
        self.assertTrue(store.exists(ref))                       # durably persisted
        stored = store.get(ref)
        assert stored is not None
        verify_measurement(stored, verifier=KeyVerifier(_PUB))    # the stored copy is the signed one
        self.assertEqual(stored.oracle_head, att.oracle_head)

    def test_restore_succeeds_when_other_policies_exist(self) -> None:
        # regression (board blocker #4): the policy-head CAS must compare against THIS policy's head,
        # not the GLOBAL chain head — else a second enabled policy (whose enable is the global head)
        # spuriously fails the CAS and blocks restoration. This is the normal multi-policy case.
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        # a SECOND enabled policy -> its enable record is now the global chain head, not p1's.
        s.transition("p2", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="p2a"))
        s.enter_calibrating("p2", approval=_appr("g1", op="p2b"), set_id="X",
                            pinned_set_version=c.set_head("X"), detector_id=_DET,
                            expected_profile_digest="pd", expected_trust_policy_digest="tp",
                            expected_guard_policy_digest="gp", identity_contract_version=1)
        s.record_calibration_pass("cal-p2", policy_id="p2", pinned_set_version=c.set_head("X"),
                                  detector_identity=_DET, set_id="X", identity_contract_version=1)
        s.transition("p2", PolicyState.ENABLED, approval=_appr("g1", op="p2c"),
                     calibration_result_ref="cal-p2", set_id="X", pinned_set_version=c.set_head("X"),
                     detector_identity=_DET, identity_contract_version=1)
        self.assertNotEqual(s.policy_head("p1"), s.head_hash())  # p1's head != global head
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3, tier_gen=s.policy_head("p1"))
        outcome = _controller(s, c).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.RESTORED)  # p1 restores despite p2 existing

    def test_demoted_policy_cannot_auto_restore(self) -> None:
        # asymmetry: a human-demoted (ADVISORY) policy has no re-attest path — must re-ratify.
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3)  # a valid clean PASS
        s.transition("p1", PolicyState.ADVISORY, approval=_appr("g1", "g2", op="demote"))  # human demote
        self.assertIs(_controller(s, c).attempt_restore(att).result, RestoreResult.REFUSED_NOT_ENABLED)


class V3GovernanceTargetTests(unittest.TestCase):
    """v3 (board P1): measurement ≠ governance — a re-cal can only re-attest the policy's CURRENTLY
    authorized subject. A clean PASS whose measured subject differs (or whose request targets a subject
    the policy is not authorized for) must NOT re-bind the policy."""

    def test_measurement_cannot_rebind_policy_to_a_different_subject(self) -> None:
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))  # authorized for subject A (== _DET)
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"),
                 fixture_id="b2", set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        other = _OtherEntrypoint([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3)  # catches b1,b2; passes g1
        # attack 1: request claims the authorized subject A, but the run MEASURED subject B.
        att = _run(c, [], detector=other, requested=_DET)
        self.assertIs(att.outcome, VerdictType.PASS)
        self.assertNotEqual(att.subject_identity, _DET)              # measured B != authorized A
        self.assertIs(_controller(s, c).attempt_restore(att).result,
                      RestoreResult.REFUSED_SUBJECT_MISMATCH)         # measured != requested
        # attack 2: request matches the measured B, but B is not the policy's authorized target A.
        subject_b = att.subject_identity
        assert subject_b is not None
        att2 = _run(c, [], detector=_OtherEntrypoint([_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3),
                    requested=subject_b, nonce="n2")
        self.assertEqual(att2.subject_identity, subject_b)
        self.assertIs(_controller(s, c).attempt_restore(att2).result,
                      RestoreResult.REFUSED_SUBJECT_MISMATCH)         # requested != policy's authorized target

    def test_reattest_refuses_when_authorized_context_moved(self) -> None:
        # v4 P1-b + S3 restore-continuity: the authorized-CONTEXT check is ATOMIC with the head CAS (under
        # the store lock). If the policy's authorized (set, subject, ICV) no longer equals what the restore
        # verified, reattest raises ReAttestConflict — closing the read-context-then-CAS-on-head-only race.
        # Guard = the expect_authorized_context check inside reattest; remove it and this re-attests a stale
        # context. A moved SUBJECT is caught here exactly as a moved SET is (both are in the 3-tuple).
        from gate.policy_store import ReAttestConflict
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))  # authorized context == ("X", _DET, 1), ref "cal-0"
        cap = ReAttestCapability(s)
        with self.assertRaises(ReAttestConflict):
            cap.reattest(
                "p1", calibration_result_ref="cal-0", set_id="X", pinned_set_version=c.set_head("X"),
                detector_identity=_DET, identity_contract_version=1, job_id="j", nonce="n",
                expect_policy_head=s.policy_head("p1"),
                expect_authorized_context=("X", "a-DIFFERENT-subject", 1))  # != current -> conflict

    def test_store_get_rejects_a_tampered_row(self) -> None:
        # v3 (board P2): the store binds the lookup key to content — a row whose bytes were tampered
        # recomputes to a different ref, so get() refuses it.
        from gate.attestation import AttestationError
        store = _att_store()
        ref = store.persist(_run(_cal_store(), [_FAIL] * 3 + [_PASS] * 3))
        store._conn().execute(  # type: ignore[attr-defined]
            "UPDATE measurement_attestation SET signature=? WHERE ref=?", ("00" * 64, ref))
        with self.assertRaises(AttestationError):
            store.get(ref)

    def test_store_persist_rejects_conflicting_bytes_for_a_ref(self) -> None:
        from gate.attestation import AttestationError
        store = _att_store()
        att = _run(_cal_store(), [_FAIL] * 3 + [_PASS] * 3)
        ref = store.persist(att)
        store._conn().execute(  # type: ignore[attr-defined]
            "UPDATE measurement_attestation SET signature=? WHERE ref=?", ("00" * 64, ref))
        with self.assertRaises(AttestationError):
            store.persist(att)  # same computed ref, but the stored bytes now differ -> reject


class RestoreControllerStructuralTests(unittest.TestCase):
    def test_controller_does_not_import_engine_or_runner(self) -> None:
        src = (Path(__file__).resolve().parent.parent / "gate" / "restore_controller.py").read_text()
        imports = [ln for ln in src.splitlines() if ln.startswith(("import ", "from "))]
        joined = "\n".join(imports)
        self.assertNotIn("engine", joined)
        self.assertNotIn("recalibration", joined)  # governance half must not import the runner

    def test_capability_exposes_no_arbitrary_transition(self) -> None:
        # board amendment 1: the restore capability is restricted to the RE_ATTESTATION record kind.
        self.assertFalse(hasattr(ReAttestCapability, "transition"))


class RestoreContinuityNegativesTests(unittest.TestCase):
    """S3 restore-continuity acceptance harness (board-required negatives). Each proves a distinct
    continuity coordinate: a valid, clean, AUTHENTIC measurement is still REFUSED when it targets the
    wrong set or a superseded generation, or is replayed; and set_id / tier_generation are signed
    (tampering either breaks authenticity). Remove the corresponding guard and each of these flips to
    RESTORED — that is the guard's teeth."""

    def _cal_with_set_Y(self) -> CalibrationStore:
        c = _cal_store()  # set X: b1(bad) + g1(good)
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="y1"),
                 fixture_id="yb", set_id="Y", label=FixtureLabel.KNOWN_BAD, payload=b"ybad")
        c.append(ChangeOp.ADD_KNOWN_GOOD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="y2"),
                 fixture_id="yg", set_id="Y", label=FixtureLabel.KNOWN_GOOD, payload=b"ygood")
        return c

    def test_neg1_same_subject_different_set_refused(self) -> None:
        # FINDING 1: a clean, same-SUBJECT measurement calibrated against set Y cannot restore a policy
        # authorized against set X — the oracle check only proves Y is itself current, not that Y is
        # THIS policy's set. The set is now an atomic CAS coordinate.
        c = self._cal_with_set_Y()
        s = _policy_store_enabled(c.set_head("X"))            # p1 authorized for set X, subject _DET
        att = _run(c, [_FAIL] * 3 + [_PASS] * 3, set_id="Y",  # SAME detector -> SAME subject, set_id="Y"
                   tier_gen=s.policy_head("p1"))
        self.assertIs(att.outcome, VerdictType.PASS)
        self.assertEqual(att.set_id, "Y")
        self.assertEqual(att.subject_identity, _DET)          # subject matches the authorized one...
        outcome = _controller(s, c).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.REFUSED_SET_MISMATCH)  # ...but the SET does not

    def test_neg2_stale_generation_refused(self) -> None:
        # FINDING 2: a clean measurement whose signed tier_generation != the policy's current head (as
        # after a human DEMOTE->re-ratify moved the head between trigger and restore) is refused.
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"),
                 fixture_id="b2", set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3,
                   tier_gen="a-stale-generation-that-is-not-the-current-head")
        self.assertIs(att.outcome, VerdictType.PASS)
        self.assertIs(_controller(s, c).attempt_restore(att).result,
                      RestoreResult.REFUSED_STALE_GENERATION)

    def test_neg3_set_move_in_context_cas_rejected(self) -> None:
        # the SET coordinate is part of the CAS: reattest REJECTS an expect_authorized_context whose SET
        # differs from the store's CURRENT one (mirrors the subject-move test — both live in the 3-tuple).
        # SCOPE (honest): this proves MISMATCH-REJECTION (a stale expectation is refused), NOT an actual
        # concurrent interleaving. The ATOMICITY that makes the read->recheck->append race-free is
        # established by CODE INSPECTION — all three run under one ``with self._lock:`` in reattest() — not
        # by this test. A true two-thread interleaving test is deliberately omitted (it would test
        # threading.Lock, not the design) — see the atomicity argument in reattest()'s docstring.
        from gate.policy_store import ReAttestConflict
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        cap = ReAttestCapability(s)
        with self.assertRaises(ReAttestConflict):
            cap.reattest("p1", calibration_result_ref="cal-0", set_id="X", pinned_set_version=c.set_head("X"),
                         detector_identity=_DET, identity_contract_version=1, job_id="j", nonce="n",
                         expect_policy_head=s.policy_head("p1"),
                         expect_authorized_context=("Y-DIFFERENT-SET", _DET, 1))  # wrong SET -> conflict

    def test_neg5_duplicate_measurement_after_success_refused(self) -> None:
        # FINDING 2 bonus (single-use / replay resistance): a measurement that RESTORED once cannot be
        # replayed — the successful re-attest moved the head, so the SAME signed measurement now fails the
        # tier_generation check. Per the relay invariant, this refusal means "already done", not "failed".
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"),
                 fixture_id="b2", set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3, tier_gen=s.policy_head("p1"))
        ctrl = _controller(s, c)
        self.assertIs(ctrl.attempt_restore(att).result, RestoreResult.RESTORED)      # first succeeds
        self.assertIs(ctrl.attempt_restore(att).result,                              # replay refused
                      RestoreResult.REFUSED_STALE_GENERATION)

    def test_neg6_signed_set_id_and_tier_generation_are_tamper_evident(self) -> None:
        # FINDINGS 1+2: set_id and tier_generation are in the SIGNED calibration_context. Tampering either
        # breaks the HMAC -> unverifiable -> refused at AUTHENTICITY (step 1), never reaching the continuity
        # checks. replace() keeps the ORIGINAL signature over the ORIGINAL bytes, so the recompute mismatches.
        from dataclasses import replace
        c = _cal_store()
        s = _policy_store_enabled(c.set_head("X"))
        c.append(ChangeOp.ADD_KNOWN_BAD, admission=_ADMIT_CAP, approval=_appr("g1", "g2", op="drift"),
                 fixture_id="b2", set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2")
        att = _run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3, tier_gen=s.policy_head("p1"))
        for tampered in (replace(att, set_id="EVIL"), replace(att, tier_generation="EVIL")):
            self.assertIs(_controller(s, c).attempt_restore(tampered).result,
                          RestoreResult.REFUSED_UNTRUSTED)


if __name__ == "__main__":
    unittest.main()
