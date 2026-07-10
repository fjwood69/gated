"""Increment 2.3 (chunk 2) — durable store + async executor + watchdog.

Run from the gated/ root:  python3 -m unittest discover -s tests

Proves: durable dedup, atomic Claim-Process-Complete, same-SHA serialisation (board
2.2 #1), the POST-ONCE finalize guard (worker vs watchdog never both post), the
watchdog fail-closed force-ERROR, backpressure, and lifecycle observability.
"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from core import VerdictType
from gate.executor import Executor, LifecycleEvent, Transition, Watchdog
from gate.queue import GatingEvent, SinkFull
from gate.store import GatingStore, StoreBackedGatingSink


class _Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


def _event(delivery_id: str, *, sha: str = "a" * 40, repo: str = "acme/widgets") -> GatingEvent:
    return GatingEvent(
        delivery_id=delivery_id,
        repo_full_name=repo,
        head_sha=sha,
        action="opened",
        installation_id=9001,
    )


def _store() -> tuple[GatingStore, _Clock, Path]:
    d = Path(tempfile.mkdtemp(prefix="mv-store-"))
    clk = _Clock()
    return GatingStore(d / "gating.db", clock=clk), clk, d


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store, self.clk, _ = _store()

    def test_enqueue_dedup(self) -> None:
        self.assertTrue(self.store.enqueue(_event("d1")))
        self.assertFalse(self.store.enqueue(_event("d1")))  # re-delivery -> idempotent
        self.assertEqual(self.store.queued_count(), 1)

    def test_claim_moves_to_processing_then_empty(self) -> None:
        self.store.enqueue(_event("d1", sha="a" * 40))
        self.store.enqueue(_event("d2", sha="b" * 40))
        first = self.store.claim_next()
        second = self.store.claim_next()
        third = self.store.claim_next()
        self.assertEqual({first.delivery_id, second.delivery_id}, {"d1", "d2"})  # type: ignore[union-attr]
        self.assertIsNone(third)
        self.assertEqual(self.store.status_of("d1"), "processing")

    def test_same_sha_serialised(self) -> None:
        # two distinct deliveries for ONE (repo, sha) must not process concurrently
        self.store.enqueue(_event("d1", sha="c" * 40))
        self.store.enqueue(_event("d2", sha="c" * 40))
        first = self.store.claim_next()
        blocked = self.store.claim_next()  # same SHA already processing -> not claimable
        self.assertIsNotNone(first)
        self.assertIsNone(blocked)
        self.store.finalize(first.delivery_id, "done")  # type: ignore[union-attr]
        second = self.store.claim_next()  # now the sibling is claimable
        self.assertIsNotNone(second)

    def test_errored_delivery_requeued_on_redelivery(self) -> None:
        # the retry-trap fix: an errored delivery re-delivered (manual re-deliver /
        # transient retry) must be RE-QUEUED, not dropped by INSERT OR IGNORE.
        self.store.enqueue(_event("d1"))
        self.store.claim_next()
        self.store.finalize("d1", "error", reason="watchdog_timeout")
        self.assertEqual(self.store.status_of("d1"), "error")
        self.assertTrue(self.store.enqueue(_event("d1")))  # re-delivery re-queues it
        self.assertEqual(self.store.status_of("d1"), "queued")

    def test_done_or_processing_delivery_not_requeued(self) -> None:
        self.store.enqueue(_event("d1"))
        self.store.claim_next()  # -> processing
        self.assertFalse(self.store.enqueue(_event("d1")))  # live job, ignore
        self.store.finalize("d1", "done")
        self.assertFalse(self.store.enqueue(_event("d1")))  # completed job, ignore
        self.assertEqual(self.store.status_of("d1"), "done")

    def test_same_sha_claimable_after_prior_errored(self) -> None:
        # a NEW delivery for a SHA whose prior delivery ERRORED (not processing) must be
        # claimable — the same-SHA guard blocks only on 'processing', never on error/done.
        self.store.enqueue(_event("d1", sha="f" * 40))
        self.store.claim_next()
        self.store.finalize("d1", "error", reason="watchdog_timeout")
        self.store.enqueue(_event("d2", sha="f" * 40))  # e.g. a reopened event
        self.assertIsNotNone(self.store.claim_next())  # not wedged by the errored sibling

    def test_finalize_post_once(self) -> None:
        self.store.enqueue(_event("d1"))
        self.store.claim_next()
        self.assertTrue(self.store.finalize("d1", "done"))
        self.assertFalse(self.store.finalize("d1", "error"))  # already terminal
        self.assertEqual(self.store.status_of("d1"), "done")

    def test_sweep_stale(self) -> None:
        self.store.enqueue(_event("d1"))
        self.store.claim_next()
        self.assertEqual(self.store.sweep_stale(900), [])  # not yet stale
        self.clk.t += 1000
        stale = self.store.sweep_stale(900)
        self.assertEqual([e.delivery_id for e in stale], ["d1"])

    def test_concurrent_claims_no_double(self) -> None:
        for i in range(6):
            self.store.enqueue(_event(f"d{i}", sha=f"{i:040d}"))
        claimed: list[str] = []
        lock = threading.Lock()

        def worker() -> None:
            while True:
                e = self.store.claim_next()
                if e is None:
                    return
                with lock:
                    claimed.append(e.delivery_id)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(claimed), [f"d{i}" for i in range(6)])  # each claimed once
        self.assertEqual(len(claimed), len(set(claimed)))


class _RecordingUpdater:
    def __init__(self) -> None:
        self.calls: list[tuple[str, VerdictType]] = []

    def __call__(self, event: GatingEvent, verdict) -> None:  # type: ignore[no-untyped-def]
        self.calls.append((event.delivery_id, verdict.status))


class _RecordingLifecycle:
    def __init__(self) -> None:
        self.events: list[LifecycleEvent] = []

    def record(self, event: LifecycleEvent) -> None:
        self.events.append(event)


class ExecutorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store, self.clk, _ = _store()
        self.updater = _RecordingUpdater()
        self.life = _RecordingLifecycle()

    def _transitions(self, delivery_id: str) -> list[Transition]:
        return [e.transition for e in self.life.events if e.delivery_id == delivery_id]

    def test_happy_path_posts_verdict(self) -> None:
        ex = Executor(self.store, lambda e: _pass(), self.updater, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        self.store.claim_next()
        ex.process_claimed(_event("d1"))
        self.assertEqual(self.updater.calls, [("d1", VerdictType.PASS)])
        self.assertEqual(self.store.status_of("d1"), "done")
        self.assertIn(Transition.COMPLETED, self._transitions("d1"))

    def test_job_crash_becomes_error(self) -> None:
        def boom(_: GatingEvent):  # type: ignore[no-untyped-def]
            raise RuntimeError("engine died")

        ex = Executor(self.store, boom, self.updater, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        self.store.claim_next()
        ex.process_claimed(_event("d1"))
        self.assertEqual(self.updater.calls, [("d1", VerdictType.ERROR)])
        self.assertEqual(self.store.status_of("d1"), "error")
        self.assertIn(Transition.ERRORED, self._transitions("d1"))

    def test_post_once_worker_loses_to_watchdog(self) -> None:
        ex = Executor(self.store, lambda e: _pass(), self.updater, lifecycle=self.life)
        wd = Watchdog(self.store, self.updater, timeout_seconds=900, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        self.store.claim_next()
        self.clk.t += 1000
        self.assertEqual(wd.sweep_once(), 1)          # watchdog force-ERRORs it first
        ex.process_claimed(_event("d1"))              # wedged worker un-wedges, too late
        # exactly ONE terminal post (the watchdog's ERROR); the worker was skipped
        self.assertEqual(self.updater.calls, [("d1", VerdictType.ERROR)])
        self.assertIn(Transition.POST_SKIPPED, self._transitions("d1"))

    def test_shutdown_stops_claiming(self) -> None:
        ex = Executor(self.store, lambda e: _pass(), self.updater, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        ex.request_shutdown()
        self.assertEqual(ex.drain(), 0)  # graceful shutdown: claim nothing new
        self.assertEqual(self.store.status_of("d1"), "queued")  # left for after restart

    def test_drain_processes_all_distinct(self) -> None:
        ex = Executor(self.store, lambda e: _pass(), self.updater, max_workers=2, lifecycle=self.life)
        for i in range(5):
            self.store.enqueue(_event(f"d{i}", sha=f"{i:040d}"))
        self.assertEqual(ex.drain(), 5)
        self.assertEqual(len(self.updater.calls), 5)


class BackpressureTests(unittest.TestCase):
    def test_sink_full_at_capacity(self) -> None:
        store, _, _ = _store()
        sink = StoreBackedGatingSink(store, max_depth=2)
        sink.enqueue(_event("d1", sha="1" * 40))
        sink.enqueue(_event("d2", sha="2" * 40))
        with self.assertRaises(SinkFull):
            sink.enqueue(_event("d3", sha="3" * 40))


def _pass():  # type: ignore[no-untyped-def]
    from core import Reason, Verdict

    return Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS)


if __name__ == "__main__":
    unittest.main()
