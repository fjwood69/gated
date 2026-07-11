"""3.5 job-1 steps 5-6 — the transactional outbox, the relay, the zombie metric, and the full
proactive-trigger loop end to end. Run: python3 -m unittest discover -s tests

Board amendment 4: revoke-and-fsync the fallback FIRST, then {append fixture + outbox} in ONE db
transaction; a failure before that commit OVER-BLOCKS. At-least-once relay (mark drained after
enqueue; job_id dedups a re-delivery). Board D4/zombie: an ENABLED-but-unattestable policy with an
unresolved re-cal is a visible zombie (age-metric), never a silent stuck block, never auto-degraded.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Command, Fixtures, IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import FixtureLabel
from gate.attestation_store import MeasurementAttestationStore
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore, ChangeOp
from gate.gatekeeper import resolve_disposition
from gate.policy_state import Disposition, PolicyState
from gate.policy_store import PolicyStore
from gate.recal_metrics import zombies, zombies_over_threshold
from gate.recal_queue import JobStatus, RecalQueue
from gate.recal_relay import relay_outbox
from gate.recalibration import run_recalibration
from gate.restore_controller import ReAttestCapability, RestoreController, RestoreResult
from gate.snapshot_refresh import commit_fixture_append
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_MEAS_KEY = b"measurement-key"
_ISSUER = "cal-gov-1"
_DET = "det-1"
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _HermeticNoOp(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


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


def _appr(*p: str, op: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="admit", rationale="r", operation_id=op)


def _cal() -> CalibrationStore:
    c = CalibrationStore(Path(tempfile.mkdtemp(prefix="mv-orch-cal-")) / "c.db")
    c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="1"), fixture_id="b1",
             set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad1")
    c.append(ChangeOp.ADD_KNOWN_GOOD, approval=_appr("g1", "g2", op="2"), fixture_id="g1",
             set_id="X", label=FixtureLabel.KNOWN_GOOD, payload=b"good1")
    return c


def _pol(head: str) -> PolicyStore:
    s = PolicyStore(Path(tempfile.mkdtemp(prefix="mv-orch-pol-")) / "t.db")
    s.transition("p1", PolicyState.PENDING_CALIBRATION, approval=_appr("g1", op="a"))
    s.transition("p1", PolicyState.CALIBRATING, approval=_appr("g1", op="b"), pinned_set_version=head)
    s.record_calibration_pass("cal-0", policy_id="p1", pinned_set_version=head,
                              detector_identity=_DET, set_id="X")
    s.transition("p1", PolicyState.ENABLED, approval=_appr("g1", op="c"),
                 calibration_result_ref="cal-0", pinned_set_version=head, detector_identity=_DET)
    return s


class OutboxAtomicityTests(unittest.TestCase):
    def test_append_with_outbox_is_atomic_and_records_new_head(self) -> None:
        c = _cal()
        n_before = c.record_count()
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2", outbox_set_id="X")
        self.assertEqual(c.record_count(), n_before + 1)  # fixture landed
        outbox = c.undrained_outbox()
        self.assertEqual(len(outbox), 1)
        self.assertEqual(outbox[0].set_id, "X")
        self.assertEqual(outbox[0].oracle_head_after, c.set_head("X"))  # head co-committed, current

    def test_commit_fixture_append_revokes_before_appending(self) -> None:
        # board amendment 4 ordering: invalidate (revoke+fsync) runs BEFORE the append.
        c = _cal()
        order: list[str] = []

        def invalidate() -> None:
            order.append("revoke")

        def append() -> int:
            order.append("append")
            return c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d"),
                            fixture_id="b2", set_id="X", label=FixtureLabel.KNOWN_BAD,
                            payload=b"bad2", outbox_set_id="X")
        commit_fixture_append(invalidate=invalidate, append=append)
        self.assertEqual(order, ["revoke", "append"])

    def test_failure_before_commit_over_blocks(self) -> None:
        # if the append fails AFTER the fallback was revoked, the fixture never lands (over-block):
        # neither the fixture nor the outbox row is present, and the fallback is already revoked.
        c = _cal()
        n_before = c.record_count()
        revoked = {"done": False}

        def invalidate() -> None:
            revoked["done"] = True

        def append() -> int:
            raise RuntimeError("crash after revoke, before append commit")

        with self.assertRaises(RuntimeError):
            commit_fixture_append(invalidate=invalidate, append=append)
        self.assertTrue(revoked["done"])              # fallback WAS revoked -> fail-closed
        self.assertEqual(c.record_count(), n_before)  # fixture did NOT land
        self.assertEqual(c.undrained_outbox(), ())    # no orphan trigger


class RelayTests(unittest.TestCase):
    def test_relay_fans_out_and_is_idempotent(self) -> None:
        c = _cal()
        s = _pol(c.set_head("X"))
        q = RecalQueue(Path(tempfile.mkdtemp(prefix="mv-orch-q-")) / "q.db")
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2", outbox_set_id="X")
        self.assertEqual(relay_outbox(calibration_store=c, policy_store=s, queue=q, now=10.0), 1)
        self.assertEqual(c.undrained_outbox(), ())          # drained
        # a second relay (e.g. a crash re-delivered the entry) is a safe no-op: already drained,
        # and even a duplicate enqueue would dedup by job_id.
        self.assertEqual(relay_outbox(calibration_store=c, policy_store=s, queue=q, now=11.0), 0)
        self.assertEqual(q.counts().get(JobStatus.PENDING.value), 1)

    def test_two_appends_collapse_to_one_job_at_current_head(self) -> None:
        c = _cal()
        s = _pol(c.set_head("X"))
        q = RecalQueue(Path(tempfile.mkdtemp(prefix="mv-orch-q2-")) / "q.db")
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d1"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2", outbox_set_id="X")
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d2"), fixture_id="b3",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad3", outbox_set_id="X")
        # two outbox entries, but both target the CURRENT head -> one job (dedup).
        relay_outbox(calibration_store=c, policy_store=s, queue=q, now=10.0)
        self.assertEqual(q.counts().get(JobStatus.PENDING.value), 1)


class FullLoopTests(unittest.TestCase):
    def _run(self, c: CalibrationStore, verdicts: list[Verdict]):  # type: ignore[no-untyped-def]
        return run_recalibration(
            policy_id="p1", set_id="X", calibration_store=c,
            make_sandbox=lambda: _HermeticNoOp(), detector=_ScriptedDetector(verdicts),
            detector_identity=_DET, tier_generation="tg", budget=_BUDGET, issuer=_ISSUER,
            nonce="n1", now=100.0, measurement_key=_MEAS_KEY, trials=3)

    def test_proactive_trigger_to_restore_end_to_end(self) -> None:
        c = _cal()
        s = _pol(c.set_head("X"))
        q = RecalQueue(Path(tempfile.mkdtemp(prefix="mv-orch-e2e-")) / "q.db")
        ohf = c.set_head

        def enforcing() -> Disposition:
            return resolve_disposition("p1", expected_detector_identity=_DET, store=s, snapshot=None,
                                       snapshot_key=b"k", now=1.0, oracle_head_for=ohf).disposition

        self.assertIs(enforcing(), Disposition.RUN_ENFORCING)
        # a fixture append via the transactional path: fallback revoked, fixture+outbox atomic.
        commit_fixture_append(
            invalidate=lambda: None,
            append=lambda: c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d"),
                                    fixture_id="b2", set_id="X", label=FixtureLabel.KNOWN_BAD,
                                    payload=b"bad2", outbox_set_id="X"))
        self.assertIs(enforcing(), Disposition.BLOCK_ACTION_REQUIRED)  # transiently UNATTESTABLE

        # relay -> queue -> lease -> run -> restore.
        relay_outbox(calibration_store=c, policy_store=s, queue=q, now=10.0)
        job = q.lease(lease_token="w1", visibility_timeout=60.0, now=20.0)
        assert job is not None
        att = self._run(c, [_FAIL] * 3 + [_FAIL] * 3 + [_PASS] * 3)  # catches b1+b2, passes g1
        att_store = MeasurementAttestationStore(Path(tempfile.mkdtemp(prefix="mv-orch-att-")) / "a.db")
        outcome = RestoreController(
            ReAttestCapability(s), issuer_keys={_ISSUER: _MEAS_KEY}, oracle_head_for=ohf,
            attestation_store=att_store,
        ).attempt_restore(att)
        self.assertIs(outcome.result, RestoreResult.RESTORED)
        self.assertTrue(q.complete(job.job_id, lease_token="w1", now=30.0))
        self.assertIs(enforcing(), Disposition.RUN_ENFORCING)  # merges flow again


class ZombieMetricTests(unittest.TestCase):
    def _setup_drifted(self):  # type: ignore[no-untyped-def]
        c = _cal()
        s = _pol(c.set_head("X"))
        q = RecalQueue(Path(tempfile.mkdtemp(prefix="mv-orch-z-")) / "q.db")
        c.append(ChangeOp.ADD_KNOWN_BAD, approval=_appr("g1", "g2", op="d"), fixture_id="b2",
                 set_id="X", label=FixtureLabel.KNOWN_BAD, payload=b"bad2", outbox_set_id="X")
        relay_outbox(calibration_store=c, policy_store=s, queue=q, now=0.0)
        return c, s, q

    def test_unresolved_recal_is_a_visible_zombie(self) -> None:
        c, s, q = self._setup_drifted()
        zs = zombies(queue=q, policy_store=s, oracle_head_for=c.set_head, now=100.0)
        self.assertEqual(len(zs), 1)
        self.assertEqual(zs[0].policy_id, "p1")
        self.assertEqual(zs[0].age_seconds, 100.0)         # blocked for 100s
        self.assertFalse(zs[0].dead_lettered)
        self.assertEqual(len(zombies_over_threshold(zs, threshold_seconds=60.0)), 1)   # alerts
        self.assertEqual(len(zombies_over_threshold(zs, threshold_seconds=200.0)), 0)  # under

    def test_dead_lettered_zombie_alerts_regardless_of_age(self) -> None:
        c, s, q = self._setup_drifted()
        # burn the lease attempts to dead-letter the job.
        q.lease(lease_token="w1", visibility_timeout=1.0, now=0.0)
        q.watchdog(max_attempts=1, now=100.0)  # attempts(1) >= 1 -> dead-letter
        zs = zombies(queue=q, policy_store=s, oracle_head_for=c.set_head, now=101.0)
        self.assertEqual(len(zs), 1)
        self.assertTrue(zs[0].dead_lettered)
        self.assertEqual(len(zombies_over_threshold(zs, threshold_seconds=1e9)), 1)  # always alerts

    def test_restored_policy_is_not_a_zombie(self) -> None:
        c, s, q = self._setup_drifted()
        # re-attest p1 back to the current head, and mark the job done.
        s.record_calibration_pass("cal-1", policy_id="p1", pinned_set_version=c.set_head("X"),
                                  detector_identity=_DET, set_id="X")
        s.reattest("p1", calibration_result_ref="cal-1", pinned_set_version=c.set_head("X"),
                   detector_identity=_DET, job_id="j", nonce="n")
        job = q.lease(lease_token="w1", visibility_timeout=60.0, now=0.0)
        assert job is not None
        q.complete(job.job_id, lease_token="w1", now=1.0)
        self.assertEqual(zombies(queue=q, policy_store=s, oracle_head_for=c.set_head, now=100.0), [])


if __name__ == "__main__":
    unittest.main()
