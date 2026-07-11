"""3.5 job-1 step-4 — the durable lease-backed re-calibration queue. Run:
python3 -m unittest discover -s tests

Load-bearing: dedup by deterministic job_id; visibility-timeout leases; watchdog re-queues expired
leases and DEAD-LETTERS after max_attempts (never silently drops); SLA surfaces a wedged queue. Clocks
+ lease tokens are injected, so the queue is deterministic.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from gate.recal_queue import JobStatus, RecalQueue


def _q() -> RecalQueue:
    return RecalQueue(Path(tempfile.mkdtemp(prefix="mv-q-")) / "q.db")


def _enq(q: RecalQueue, job_id: str = "j1", *, now: float = 0.0) -> bool:
    return q.enqueue(job_id=job_id, policy_id="p1", set_id="X", oracle_head="h1",
                     detector_identity="det-1", tier_generation="tg", now=now)


class QueueTests(unittest.TestCase):
    def test_enqueue_dedups_by_job_id(self) -> None:
        q = _q()
        self.assertTrue(_enq(q, "j1"))
        self.assertFalse(_enq(q, "j1"))  # same measurement -> not re-enqueued
        self.assertTrue(_enq(q, "j2"))

    def test_lease_claims_pending_and_bumps_attempts(self) -> None:
        q = _q()
        _enq(q)
        job = q.lease(lease_token="w1", visibility_timeout=30.0, now=100.0)
        assert job is not None
        self.assertIs(job.status, JobStatus.PROCESSING)
        self.assertEqual(job.attempts, 1)
        self.assertEqual(job.locked_until, 130.0)
        self.assertIsNone(q.lease(lease_token="w2", visibility_timeout=30.0, now=105.0))  # nothing left

    def test_complete_requires_matching_lease_token(self) -> None:
        q = _q()
        _enq(q)
        q.lease(lease_token="w1", visibility_timeout=30.0, now=100.0)
        self.assertFalse(q.complete("j1", lease_token="STALE", now=110.0))  # not the lease holder
        self.assertTrue(q.complete("j1", lease_token="w1", now=110.0))
        self.assertIs(q.get("j1").status, JobStatus.DONE)

    def test_expired_lease_is_releasable(self) -> None:
        q = _q()
        _enq(q)
        q.lease(lease_token="w1", visibility_timeout=30.0, now=100.0)
        self.assertIsNone(q.lease(lease_token="w2", visibility_timeout=30.0, now=120.0))  # still locked
        job = q.lease(lease_token="w2", visibility_timeout=30.0, now=131.0)  # lease expired -> reclaim
        assert job is not None
        self.assertEqual(job.attempts, 2)

    def test_watchdog_requeues_then_dead_letters(self) -> None:
        q = _q()
        _enq(q)
        # burn 2 attempts (max_attempts=2): lease + expire, lease + expire.
        q.lease(lease_token="w1", visibility_timeout=10.0, now=100.0)
        self.assertEqual(q.watchdog(max_attempts=2, now=200.0), [])  # attempt 1 expired -> requeue
        q.lease(lease_token="w2", visibility_timeout=10.0, now=300.0)  # attempt 2
        dead = q.watchdog(max_attempts=2, now=400.0)  # attempts(2) >= max -> dead-letter
        self.assertEqual([d.job_id for d in dead], ["j1"])
        self.assertIs(q.get("j1").status, JobStatus.DEAD_LETTER)
        # a dead-lettered job is never auto-retried.
        self.assertIsNone(q.lease(lease_token="w3", visibility_timeout=10.0, now=500.0))

    def test_sla_breaches(self) -> None:
        q = _q()
        _enq(q, "j1", now=0.0)
        _enq(q, "j2", now=1000.0)
        breached = q.sla_breaches(sla_seconds=900.0, now=1000.0)  # j1 is 1000s old, j2 is 0s old
        self.assertEqual([b.job_id for b in breached], ["j1"])


if __name__ == "__main__":
    unittest.main()
