"""tests/test_slice_c_queue.py — 3.5 S3-completion CP4 Slice C queue remediation: token-CAS renew that
refuses an expired lease, kind-filtered leasing, and the idempotent in-place migration of a pre-Slice-C
queue database.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from gate.recal_queue import JobStatus, RecalQueue


def _q() -> RecalQueue:
    return RecalQueue(Path(tempfile.mkdtemp(prefix="mv-cq-")) / "q.db")


def _enq(q: RecalQueue, jid: str, *, kind: str = "outbox", now: float = 100.0) -> None:
    q.enqueue(job_id=jid, policy_id="p", set_id="s", oracle_head="h", detector_identity="d",
              tier_generation="g", now=now, kind=kind, intent_seq=1 if kind == "intent" else None,
              policy_generation="g" if kind == "intent" else None,
              target_revision=0 if kind == "intent" else None)


class RenewTests(unittest.TestCase):
    def test_renew_extends_a_held_lease(self) -> None:
        q = _q()
        _enq(q, "j1")
        q.lease(lease_token="T", visibility_timeout=10.0, now=100.0)  # locked_until=110
        self.assertTrue(q.renew("j1", lease_token="T", visibility_timeout=10.0, now=105.0))  # -> 115
        self.assertEqual(q.get("j1").locked_until, 115.0)  # type: ignore[union-attr]

    def test_renew_refuses_an_already_expired_lease(self) -> None:
        q = _q()
        _enq(q, "j1")
        q.lease(lease_token="T", visibility_timeout=10.0, now=100.0)  # locked_until=110
        # now=120 is past locked_until=110 -> the lease lapsed (watchdog could have re-leased it) -> refuse.
        self.assertFalse(q.renew("j1", lease_token="T", visibility_timeout=10.0, now=120.0))

    def test_renew_refuses_a_wrong_token(self) -> None:
        q = _q()
        _enq(q, "j1")
        q.lease(lease_token="T", visibility_timeout=10.0, now=100.0)
        self.assertFalse(q.renew("j1", lease_token="OTHER", visibility_timeout=10.0, now=105.0))


class KindFilteredLeaseTests(unittest.TestCase):
    def test_intent_worker_never_leases_an_outbox_job(self) -> None:
        q = _q()
        _enq(q, "outbox-1", kind="outbox", now=100.0)
        _enq(q, "intent-1", kind="intent", now=101.0)
        leased = q.lease(lease_token="T", visibility_timeout=10.0, now=200.0, kind="intent")
        assert leased is not None
        self.assertEqual(leased.job_id, "intent-1")
        self.assertEqual(leased.kind, "intent")
        # the outbox job is untouched; a second intent-lease finds nothing.
        self.assertIsNone(q.lease(lease_token="T2", visibility_timeout=10.0, now=200.0, kind="intent"))
        self.assertIs(q.get("outbox-1").status, JobStatus.PENDING)  # type: ignore[union-attr]

    def test_outbox_lease_excludes_intent_jobs(self) -> None:
        q = _q()
        _enq(q, "intent-1", kind="intent", now=100.0)
        self.assertIsNone(q.lease(lease_token="T", visibility_timeout=10.0, now=200.0, kind="outbox"))


class QueueMigrationTests(unittest.TestCase):
    def test_pre_slice_c_queue_migrates_and_backfills_kind_outbox(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mv-qmig-")) / "q.db"
        conn = sqlite3.connect(str(d))
        conn.execute(
            "CREATE TABLE recal_queue (job_id TEXT PRIMARY KEY, policy_id TEXT NOT NULL, set_id TEXT NOT "
            "NULL, oracle_head TEXT NOT NULL, detector_identity TEXT NOT NULL, tier_generation TEXT NOT "
            "NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, lease_token TEXT, "
            "locked_until REAL, enqueued_at REAL NOT NULL, updated_at REAL NOT NULL)")
        conn.execute(
            "INSERT INTO recal_queue (job_id, policy_id, set_id, oracle_head, detector_identity, "
            "tier_generation, status, attempts, enqueued_at, updated_at) "
            "VALUES ('legacy','p','s','h','d','g','pending',0,0,0)")
        conn.commit()
        conn.close()
        q = RecalQueue(d)  # opening runs the migration
        cols = {r["name"] for r in q._conn().execute("PRAGMA table_info(recal_queue)").fetchall()}
        for c in ("kind", "intent_seq", "policy_generation", "target_revision"):
            self.assertIn(c, cols)
        job = q.get("legacy")
        assert job is not None
        self.assertEqual(job.kind, "outbox")  # existing rows backfilled -> excluded from the intent worker
        # and the migrated legacy job is invisible to a kind='intent' lease.
        self.assertIsNone(q.lease(lease_token="T", visibility_timeout=10.0, now=200.0, kind="intent"))


if __name__ == "__main__":
    unittest.main()
