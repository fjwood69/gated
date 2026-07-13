"""3.3 — the tier-gatekeeper: resolution + enable path. The non-negotiable done-tests. Run:
python3 -m unittest discover -s tests

Done-tests:
  #1 a formerly-ENABLED policy that can't be attested BLOCKS (action_required) — never silent
     neutral, never stale-enforce; a fresh identity-MATCHING snapshot survives a store blip; an
     identity-MISMATCH snapshot blocks (addition #1).
  #2 refuse-enable NAMES the breaking fixture (legible).
  #3 per-policy calibration isolation — one policy's calibration failure doesn't touch another.
  #4 (survivability) folded into #1.
  #5 structural: no C3-event -> tier-write path (gatekeeper + store never import gate.ledger).
Plus: tampered chain blocks; the full shadow-first human-gated enable path enables.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from core import (
    Command,
    Fixtures,
    IsolationLevel,
    Reason,
    ResourceBudget,
    Verdict,
    VerdictType,
)
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from core.identity import DetectorManifest, identity_for
from engine.calibration import ResolvedDetector
from gate.authority import GovernanceApproval
from gate.calibration_store import AdmissionCapability, CalibrationStore, ChangeOp
from gate.detector_registry import profile_of
from gate.gatekeeper import ratify_enable, resolve_disposition, run_calibration
from gate.policy_state import Disposition, PolicyState
from gate.policy_store import PolicyStore
from gate.snapshot import AttestationRecord, issue_snapshot
from sandbox.noop import NoOpSandbox
from gate.trust_policy import resolve_trust_policy
from tests._backend_optout import test_guard_policy
_REF_TP = resolve_trust_policy("trust-policy:completed-only")


def _bundle(det):  # type: ignore[no-untyped-def]
    # P1-3 v3/v4: run_calibration takes a BundleResolver (assertion + profile digest + frozen command).
    return lambda _id: ResolvedDetector(
        assertion=det, profile_digest=profile_of(_id, det).digest(), command=det.entrypoint())

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_KEY = b"gate-governance-key"
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


_ADMIT_CAP = AdmissionCapability()


class _HermeticNoOp(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _hermetic_factory():  # type: ignore[no-untyped-def]
    def make() -> _HermeticNoOp:
        return _HermeticNoOp()
    return make


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


def _appr(*principals: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=principals, purpose="test", rationale="because", operation_id=op)


def _store() -> PolicyStore:
    d = Path(tempfile.mkdtemp(prefix="mv-gk-"))
    return PolicyStore(d / "tier.db")


def _enable(store: PolicyStore, pid: str, *, detector: str = "det-1", set_id: str = "default",
            head: str = "fx-head") -> None:
    ref = f"cal-{pid}"  # unique per policy so current_attestation resolves the right pass
    store.transition(pid, PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op=f"{pid}-1"))
    store.transition(pid, PolicyState.CALIBRATING, approval=_appr("gov1", op=f"{pid}-2"),
                     pinned_set_version=head)
    store.record_calibration_pass(ref, policy_id=pid, pinned_set_version=head,
                                  detector_identity=detector, set_id=set_id, identity_contract_version=1)
    store.transition(pid, PolicyState.ENABLED, approval=_appr("gov1", op=f"{pid}-3"),
                     calibration_result_ref=ref, pinned_set_version=head,
                     detector_identity=detector)


class _UnreachableStore(PolicyStore):
    """Models an availability failure — reads raise OperationalError (the gatekeeper falls to the
    snapshot)."""

    def current_state(self, policy_id: str) -> PolicyState | None:  # type: ignore[override]
        raise sqlite3.OperationalError("database is locked")


def _snap(pid: str, detector: str, *, set_id: str = "default", oracle_head: str = "fx-head"):  # type: ignore[no-untyped-def]
    rec = AttestationRecord(
        policy_id=pid, detector_identity=detector, calibration_result_ref="cal-1",
        fixture_set_version="fx-head", tier_chain_head="tier-head", backend="podman",
        set_id=set_id, oracle_head=oracle_head,
    )
    return issue_snapshot({pid: rec}, key=_KEY, now=1000.0, valid_for_seconds=300)


def _resolve(store, pid, *, detector="det-1", snapshot=None, now=1100.0,  # type: ignore[no-untyped-def]
             oracle_head_for=None):
    if oracle_head_for is None:
        oracle_head_for = lambda s: "fx-head"  # noqa: E731 — default: bound head matches -> enforce
    return resolve_disposition(
        pid, expected_detector_identity=detector, store=store, snapshot=snapshot,
        snapshot_key=_KEY, now=now, oracle_head_for=oracle_head_for,
    )


class Done1_UnattestableBlocksTests(unittest.TestCase):
    def test_live_enabled_runs_enforcing(self) -> None:
        s = _store()
        _enable(s, "p1")
        self.assertIs(_resolve(s, "p1").disposition, Disposition.RUN_ENFORCING)

    def test_store_unreachable_no_snapshot_blocks(self) -> None:
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u-")) / "t.db")
        d = _resolve(u, "p1", snapshot=None)
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")

    def test_store_unreachable_fresh_matching_snapshot_survives(self) -> None:
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u2-")) / "t.db")
        d = _resolve(u, "p1", detector="det-1", snapshot=_snap("p1", "det-1"), now=1100.0)
        self.assertIs(d.disposition, Disposition.RUN_ENFORCING)  # blip survived
        self.assertEqual(d.source, "snapshot")

    def test_store_unreachable_stale_snapshot_blocks(self) -> None:
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u3-")) / "t.db")
        d = _resolve(u, "p1", snapshot=_snap("p1", "det-1"), now=1000.0 + 300.0)  # stale
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)

    def test_store_unreachable_oracle_drift_on_fallback_blocks(self) -> None:
        # close-4: tier store down (fallback), but the calibration store is reachable and reports a
        # DRIFTED head for the policy's set -> UNATTESTABLE, mirroring the live path (completes close 3).
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u6-")) / "t.db")
        d = _resolve(u, "p1", detector="det-1", snapshot=_snap("p1", "det-1", oracle_head="h1"),
                     now=1100.0, oracle_head_for=lambda _s: "h2")  # set grew since mint
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")

    def test_store_unreachable_calibration_also_down_trusts_fresh_snapshot(self) -> None:
        # both stores down -> cannot check the head -> trust the fresh (horizon-bounded) snapshot.
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u7-")) / "t.db")
        d = _resolve(u, "p1", detector="det-1", snapshot=_snap("p1", "det-1", oracle_head="h1"),
                     now=1100.0, oracle_head_for=lambda _s: None)
        self.assertIs(d.disposition, Disposition.RUN_ENFORCING)

    def test_store_unreachable_policy_absent_blocks(self) -> None:
        # gap-2: absence from a valid snapshot is indistinguishable from an incomplete mint ->
        # fail CLOSED (action_required), NOT skip-neutral. Snapshot lists p1; we ask about pX.
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u5-")) / "t.db")
        d = _resolve(u, "pX", detector="det-1", snapshot=_snap("p1", "det-1"), now=1100.0)
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")

    def test_store_unreachable_identity_mismatch_blocks(self) -> None:
        # addition #1: the snapshot attests det-1 but det-EVIL is about to run -> refuse to enforce
        # an un-calibrated detector.
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-u4-")) / "t.db")
        d = _resolve(u, "p1", detector="det-EVIL", snapshot=_snap("p1", "det-1"), now=1100.0)
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")

    def test_tampered_chain_blocks(self) -> None:
        s = _store()
        _enable(s, "p1")
        s._conn().execute("UPDATE tier_transition_chain SET new_state=? WHERE seq=1",
                          (PolicyState.ENABLED.value,))
        self.assertIs(_resolve(s, "p1").disposition, Disposition.BLOCK_ACTION_REQUIRED)


class Done2_LegibleRefuseTests(unittest.TestCase):
    def test_refuse_enable_names_the_breaking_fixture(self) -> None:
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="p1-1"))
        b1 = Fixture("b1", FixtureLabel.KNOWN_BAD, b"x")
        b2 = Fixture("b2", FixtureLabel.KNOWN_BAD, b"y")
        g1 = Fixture("g1", FixtureLabel.KNOWN_GOOD, b"z")
        cset = CalibrationSet(known_good=(g1,), known_bad=(b1, b2))
        # detector catches b1 [FAIL]*3, MISSES b2 [PASS]*3, passes g1 [PASS]*3.
        det = _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3 + [_PASS] * 3)
        outcome = run_calibration(
            "p1", store=s, make_sandbox=_hermetic_factory(), detector_id="d", resolve=_bundle(det),
            calibration_set=cset, budget=_BUDGET, calibration_chain_head="fx-head",
            approval=_appr("gov1", op="p1-cal"), trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP
        )
        self.assertFalse(outcome.passed)
        self.assertIsNone(outcome.calibration_result_ref)  # no PASS -> no ref -> cannot enable
        self.assertIn("b2", outcome.breaking_fixtures)
        self.assertIn("b2", outcome.report)
        self.assertIs(s.current_state("p1"), PolicyState.REJECTED)


class Done3_PerPolicyIsolationTests(unittest.TestCase):
    def test_one_policy_calibration_failure_does_not_touch_another(self) -> None:
        s = _store()
        _enable(s, "pB")  # pB independently ENABLED
        # pA calibration fails -> REJECTED.
        s.transition("pA", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="pA-1"))
        cset = CalibrationSet(
            known_good=(Fixture("g", FixtureLabel.KNOWN_GOOD, b"z"),),
            known_bad=(Fixture("bad", FixtureLabel.KNOWN_BAD, b"y"),),
        )
        det = _ScriptedDetector([_PASS] * 3 + [_PASS] * 3)  # MISSES the known-bad
        run_calibration("pA", store=s, make_sandbox=_hermetic_factory(), detector_id="d",
                        resolve=_bundle(det), calibration_set=cset, budget=_BUDGET,
                        calibration_chain_head="fx",
                        approval=_appr("gov1", op="pA-cal"), trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP)
        self.assertIs(s.current_state("pA"), PolicyState.REJECTED)
        self.assertIs(_resolve(s, "pA").disposition, Disposition.SKIP_NEUTRAL)
        # pB untouched by pA's failure.
        self.assertIs(s.current_state("pB"), PolicyState.ENABLED)
        self.assertIs(_resolve(s, "pB").disposition, Disposition.RUN_ENFORCING)


class EnablePathTests(unittest.TestCase):
    def test_shadow_first_then_human_ratify_enables(self) -> None:
        s = _store()
        s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("gov1", op="p1-1"))
        cset = CalibrationSet(
            known_good=(Fixture("g1", FixtureLabel.KNOWN_GOOD, b"z"),),
            known_bad=(Fixture("b1", FixtureLabel.KNOWN_BAD, b"y"),),
        )
        det = _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3)  # catches b1, passes g1
        outcome = run_calibration("p1", store=s, make_sandbox=_hermetic_factory(), detector_id="d",
                                  resolve=_bundle(det), calibration_set=cset, budget=_BUDGET,
                                  calibration_chain_head="fx",
                                  approval=_appr("gov1", op="p1-cal"), trials=3, backend_guard=test_guard_policy, trust_policy=_REF_TP)
        self.assertTrue(outcome.passed)
        self.assertIsNotNone(outcome.calibration_result_ref)  # PASS -> a ref to bind ENABLED to
        self.assertIs(s.current_state("p1"), PolicyState.CALIBRATING)  # NOT auto-enabled
        # human ratify with the ref the PASS produced (mechanically bound — gap-1).
        ratify_enable("p1", store=s, approval=_appr("gov1", op="p1-ratify"),
                      calibration_result_ref=outcome.calibration_result_ref, pinned_set_version="fx")
        self.assertIs(s.current_state("p1"), PolicyState.ENABLED)


class Close3ScopedOracleTests(unittest.TestCase):
    """close-3: fixture append to a SET invalidates ONLY the policies calibrated against THAT set.
    The board's required regression: append to shared set X -> every policy bound to X blocks
    (live path); unrelated set Y remains enforcing; unknown set membership fails closed."""

    def _cal(self) -> CalibrationStore:
        d = Path(tempfile.mkdtemp(prefix="mv-gk-cal-"))
        return CalibrationStore(d / "cal.db")

    def _add(self, cal: CalibrationStore, fid: str, set_id: str, bad: bool = True) -> None:
        appr = GovernanceApproval(principals=("g1", "g2"), purpose="admit", rationale="r",
                                  operation_id=f"op-{fid}")
        op = ChangeOp.ADD_KNOWN_BAD if bad else ChangeOp.ADD_KNOWN_GOOD
        label = FixtureLabel.KNOWN_BAD if bad else FixtureLabel.KNOWN_GOOD
        cal.append(op, admission=_ADMIT_CAP, approval=appr, fixture_id=fid, set_id=set_id, label=label,
                   payload=fid.encode())

    def test_append_to_set_X_blocks_bound_policies_set_Y_unaffected(self) -> None:
        cal = self._cal()
        self._add(cal, "bx1", "X")
        self._add(cal, "gy1", "Y", bad=False)
        hX1, hY = cal.set_head("X"), cal.set_head("Y")
        s = _store()
        _enable(s, "P", set_id="X", head=hX1)
        _enable(s, "Q", set_id="Y", head=hY)
        ohf = cal.set_head  # oracle_head_for = the REAL scoped head
        self.assertIs(_resolve(s, "P", oracle_head_for=ohf).disposition, Disposition.RUN_ENFORCING)
        self.assertIs(_resolve(s, "Q", oracle_head_for=ohf).disposition, Disposition.RUN_ENFORCING)
        # append to set X -> set_head(X) moves; set_head(Y) unchanged.
        self._add(cal, "bx2", "X")
        self.assertNotEqual(cal.set_head("X"), hX1)
        self.assertEqual(cal.set_head("Y"), hY)
        pd = _resolve(s, "P", oracle_head_for=ohf)
        self.assertIs(pd.disposition, Disposition.BLOCK_ACTION_REQUIRED)  # X grew -> P unattestable
        self.assertEqual(pd.source, "unattestable")
        self.assertIs(_resolve(s, "Q", oracle_head_for=ohf).disposition,
                      Disposition.RUN_ENFORCING)  # Y untouched -> Q still enforces (scoped)

    def test_unknown_set_membership_fails_closed(self) -> None:
        s = _store()
        _enable(s, "P", set_id="Z", head="hz")
        d = _resolve(s, "P", oracle_head_for=lambda _sid: None)  # set can't be resolved
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")


class TransitiveSpoofIntegrationTests(unittest.TestCase):
    """close-2 integration (UAT Phase 1): the 4-tuple execution identity, threaded end-to-end through
    the gate, refuses a detector whose TRANSITIVE (host-side) dependency drifted — on BOTH the live
    path and the signed-snapshot fallback. Uses the real ``core.identity.bind_identity`` (not string
    placeholders): the only coordinate that moves is ``host_closure_digest`` (the detector's own build
    artifact, the sandbox image, and the eval profile are byte-identical), which is exactly the
    transitive-dependency spoof the 2-tuple missed and the 4-tuple closes.

    Regression guard: before the live-path identity fix, the live assertions here returned
    RUN_ENFORCING — the identity invariant held only during a store outage and fell open on the
    primary path."""

    def _identity(self, *, host_closure: str) -> str:
        # same detector build + same artifact image + same eval profile; ONLY the host closure moves.
        m = DetectorManifest(check_type="egress", entrypoint=("python3", "main.py"),
                             impl_digest="detector-build-v1", eval_profile={"trials": 3, "budget": 1.0})
        return identity_for(m, host_closure_digest=host_closure, artifact_image_digest="img-sha-v1")

    def test_live_path_refuses_host_closure_drift(self) -> None:
        id_v1 = self._identity(host_closure="closure-v1")
        id_v2 = self._identity(host_closure="closure-v2")  # a host-side helper changed
        self.assertNotEqual(id_v1, id_v2)  # the drift produced a new identity
        s = _store()
        _enable(s, "p1", detector=id_v1)  # calibrated + ENABLED for the v1 closure
        # the detector about to run is bound to the v1 closure -> enforce.
        self.assertIs(_resolve(s, "p1", detector=id_v1).disposition, Disposition.RUN_ENFORCING)
        # the detector about to run has the DRIFTED (v2) closure -> refuse (un-calibrated), on the
        # LIVE path with the store fully reachable.
        d = _resolve(s, "p1", detector=id_v2)
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")

    def test_snapshot_path_refuses_host_closure_drift(self) -> None:
        id_v1 = self._identity(host_closure="closure-v1")
        id_v2 = self._identity(host_closure="closure-v2")
        u = _UnreachableStore(Path(tempfile.mkdtemp(prefix="mv-gk-spoof-")) / "t.db")
        snap = _snap("p1", id_v1)  # the survivable snapshot attests the v1 identity
        self.assertIs(_resolve(u, "p1", detector=id_v1, snapshot=snap).disposition,
                      Disposition.RUN_ENFORCING)  # store blip, matching identity -> survives
        d = _resolve(u, "p1", detector=id_v2, snapshot=snap)  # drifted closure during the outage
        self.assertIs(d.disposition, Disposition.BLOCK_ACTION_REQUIRED)
        self.assertEqual(d.source, "unattestable")


class Done5_NoC3PathTests(unittest.TestCase):
    def test_gatekeeper_and_store_never_import_c3_ledger(self) -> None:
        root = Path(__file__).resolve().parent.parent / "gate"
        for mod in ("gatekeeper.py", "policy_store.py"):
            src = (root / mod).read_text()
            self.assertNotIn("from gate.ledger", src, f"{mod} must not import the C3 ledger")
            self.assertNotIn("import gate.ledger", src)
            self.assertNotIn("from .ledger", src)


if __name__ == "__main__":
    unittest.main()
