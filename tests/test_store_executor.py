"""Increment 2.3 (chunk 2) + Increment A — durable store + async executor + watchdog + publication outbox.

Run from the gated/ root:  python3 -m unittest discover -s tests

Proves: durable dedup, atomic Claim-Process-Complete, same-SHA supersession (the generation fence), the
POST-ONCE finalize guard (worker vs watchdog never both arm), the watchdog fail-closed force-ERROR,
backpressure, lifecycle observability, AND (Increment A) the two-phase publication outbox: the RESET gates
execution (fail-closed), the CONCLUSION is armed at finalize + drained by the Publisher onto the actuator,
a delayed OLD publish can never overwrite a NEWER conclusion (the ABA generation fence + durable repair), a
dropped publish is retried not lost, a re-derived identity binds to the persisted RESET (complete-binding),
and an error-requeue mints a fresh generation (never a wedged, unpublishable queued row).
"""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from core import Reason, Verdict, VerdictType
from gate.checkrun import (
    CheckConclusion,
    CheckOutput,
    CheckRunError,
    CheckStatus,
    GitHubCheckClient,
)
from gate.executor import Executor, LifecycleEvent, Publisher, Transition, Watchdog
from gate.job_result import JobResult, NonRunDecision
from gate.policy_state import Disposition
from gate.queue import GatingEvent, SinkFull
from gate.run_admission import AdmittedRunResult
from gate.store import GatingStore, OutboxInvariantError, StoreBackedGatingSink
from tests.test_run_admission import _FakeGovernance, _admit, _plan, _report


class _Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


def _event(
    delivery_id: str, *, sha: str = "a" * 40, repo: str = "acme/widgets",
    head_repo: str | None = None,
) -> GatingEvent:
    return GatingEvent(
        delivery_id=delivery_id,
        repo_full_name=repo,
        head_sha=sha,
        action="opened",
        installation_id=9001,
        head_repo_full_name=head_repo,
    )


def _store(*, check_name: str = "gate") -> tuple[GatingStore, _Clock, Path]:
    d = Path(tempfile.mkdtemp(prefix="mv-store-"))
    clk = _Clock()
    return GatingStore(d / "gating.db", clock=clk, check_name=check_name), clk, d


def _flush_resets(store: GatingStore) -> None:
    """Mark every pending RESET published (simulating a successful Publisher actuator drive), so the
    ``claim_next`` reset-gate admits the delivery. MUST run before any finalize (asserts only resets pending)."""
    while True:
        job = store.claim_publication()
        if job is None:
            break
        assert job.phase == "reset", "call _flush_resets before any finalize"
        store.mark_publication_published(job.delivery_id, "reset")


class _FakeCheckClient:
    """In-memory ``GitHubCheckClient``: models find-then-PATCH-or-POST idempotency, records the CURRENT
    actuator surface (status + conclusion) per (repo, sha, name), and logs every COMPLETED conclusion posted
    (so a test can assert exactly-one-terminal-post / detect a stale overwrite). ``fail`` makes every call
    raise ``CheckRunError`` (a GitHub outage) — fail-closed retry surface."""

    def __init__(self) -> None:
        self._runs: dict[tuple[str, str, str], dict[str, object]] = {}
        self.completed_log: list[tuple[str, CheckConclusion | None]] = []
        self._next = 0
        self.fail = False

    @staticmethod
    def _key(repo: str, sha: str, name: str) -> tuple[str, str, str]:
        return (repo, sha, name)

    def find_check_run(self, *, repo_full_name: str, head_sha: str, name: str) -> str | None:
        if self.fail:
            raise CheckRunError("find failed (outage)")
        r = self._runs.get(self._key(repo_full_name, head_sha, name))
        return None if r is None else str(r["id"])

    def create_check_run(
        self, *, repo_full_name: str, head_sha: str, name: str, status: CheckStatus,
        external_id: str, conclusion: CheckConclusion | None = None, output: CheckOutput | None = None,
    ) -> str:
        if self.fail:
            raise CheckRunError("create failed (outage)")
        self._next += 1
        cid = f"cr-{self._next}"
        self._runs[self._key(repo_full_name, head_sha, name)] = {
            "id": cid, "status": status, "conclusion": conclusion, "sha": head_sha}
        if status is CheckStatus.COMPLETED:
            self.completed_log.append((head_sha, conclusion))
        return cid

    def update_check_run(
        self, *, repo_full_name: str, check_run_id: str, status: CheckStatus,
        conclusion: CheckConclusion | None = None, output: CheckOutput | None = None,
    ) -> None:
        if self.fail:
            raise CheckRunError("update failed (outage)")
        for r in self._runs.values():
            if r["id"] == check_run_id:
                r["status"] = status
                r["conclusion"] = conclusion if status is CheckStatus.COMPLETED else None
                if status is CheckStatus.COMPLETED:
                    self.completed_log.append((str(r["sha"]), conclusion))
                return
        raise CheckRunError(f"no such check run {check_run_id}")

    def surface(self, repo: str, sha: str, name: str = "gate") -> tuple[CheckStatus, CheckConclusion | None] | None:
        r = self._runs.get(self._key(repo, sha, name))
        return None if r is None else (r["status"], r["conclusion"])  # type: ignore[return-value]


# a mypy sanity check that the fake satisfies the protocol
_PROTOCOL_CHECK: GitHubCheckClient = _FakeCheckClient()


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store, self.clk, _ = _store()

    def test_enqueue_dedup(self) -> None:
        self.assertTrue(self.store.enqueue(_event("d1")))
        self.assertFalse(self.store.enqueue(_event("d1")))  # re-delivery -> idempotent
        self.assertEqual(self.store.queued_count(), 1)

    def test_fork_repo_survives_durable_round_trip(self) -> None:
        # C2: the executor CLAIMS the event from the store, so a fork-fetch hint lost in the
        # round-trip would silently revert the contingency to a base fetch. The base repo
        # (check + ledger key) must be untouched.
        self.store.enqueue(_event("dfork", sha="f" * 40, head_repo="forkuser/widgets"))
        _flush_resets(self.store)
        claimed = self.store.claim_next()
        assert claimed is not None
        self.assertEqual(claimed.head_repo_full_name, "forkuser/widgets")
        self.assertEqual(claimed.repo_full_name, "acme/widgets")

    def test_same_repo_event_has_null_head_repo(self) -> None:
        self.store.enqueue(_event("dsame"))
        _flush_resets(self.store)
        claimed = self.store.claim_next()
        assert claimed is not None
        self.assertIsNone(claimed.head_repo_full_name)

    def test_claim_moves_to_processing_then_empty(self) -> None:
        self.store.enqueue(_event("d1", sha="a" * 40))
        self.store.enqueue(_event("d2", sha="b" * 40))
        _flush_resets(self.store)
        first = self.store.claim_next()
        second = self.store.claim_next()
        third = self.store.claim_next()
        self.assertEqual({first.delivery_id, second.delivery_id}, {"d1", "d2"})  # type: ignore[union-attr]
        self.assertIsNone(third)
        self.assertEqual(self.store.status_of("d1"), "processing")

    def test_same_sha_serialised_and_newer_supersedes(self) -> None:
        # two DISTINCT deliveries for ONE (repo, sha) must not process concurrently (board 2.2 #1). Under the
        # Increment A generation fence they are two GENERATIONS of one publication identity: the NEWER (the
        # reopen) supersedes the older's publication (the exact multi-delivery false-green the fence closes).
        self.store.enqueue(_event("d1", sha="c" * 40))
        _flush_resets(self.store)
        first = self.store.claim_next()          # d1 claimed + processing
        assert first is not None and first.delivery_id == "d1"
        # a reopened event d2 for the SAME sha arrives WHILE d1 processes -> supersedes d1's publication rows
        self.store.enqueue(_event("d2", sha="c" * 40))
        _flush_resets(self.store)                # publishes d2's reset (max gen); d1's rows now superseded
        self.assertIsNone(self.store.claim_next())  # same sha still processing -> d2 not yet claimable
        self.store.finalize("d1", "done", verdict="pass", reason="UNANIMOUS_PASS")  # d1 conclusion born superseded
        second = self.store.claim_next()         # d1 done -> the newer sibling d2 is claimable
        assert second is not None
        self.assertEqual(second.delivery_id, "d2")

    def test_errored_delivery_requeued_on_redelivery(self) -> None:
        # the retry-trap fix: an errored delivery re-delivered (manual re-deliver /
        # transient retry) must be RE-QUEUED, not dropped by INSERT OR IGNORE.
        self.store.enqueue(_event("d1"))
        _flush_resets(self.store)
        self.store.claim_next()
        self.store.finalize("d1", "error", reason="watchdog_timeout")
        self.assertEqual(self.store.status_of("d1"), "error")
        self.assertTrue(self.store.enqueue(_event("d1")))  # re-delivery re-queues it
        self.assertEqual(self.store.status_of("d1"), "queued")

    def test_done_or_processing_delivery_not_requeued(self) -> None:
        self.store.enqueue(_event("d1"))
        _flush_resets(self.store)
        self.store.claim_next()  # -> processing
        self.assertFalse(self.store.enqueue(_event("d1")))  # live job, ignore
        self.store.finalize("d1", "done")
        self.assertFalse(self.store.enqueue(_event("d1")))  # completed job, ignore
        self.assertEqual(self.store.status_of("d1"), "done")

    def test_finalize_persists_gate_outcome_round_trips_through_verdicts_for_sha(self) -> None:
        # CP2 closure 1: the gate-outcome discriminator persists INDEPENDENTLY of the verdict + is exposed to
        # the classifier. A blocking non-run carries gate_outcome='block_gate' with NO verdict.
        sha = "e" * 40
        self.store.enqueue(_event("d1", sha=sha))
        _flush_resets(self.store)
        self.store.claim_next()
        self.store.finalize("d1", "done", gate_outcome="block_gate", reason="block_action_required")
        rows = self.store.verdicts_for_sha(sha)
        self.assertEqual(len(rows), 1)
        status, verdict, reason, _updated, gate_outcome = rows[0]
        self.assertEqual(status, "done")
        self.assertIsNone(verdict)                       # no fabricated verdict
        self.assertEqual(gate_outcome, "block_gate")
        self.assertEqual(reason, "block_action_required")

    def test_verdicts_for_sha_gate_outcome_defaults_none(self) -> None:
        sha = "1" * 40
        self.store.enqueue(_event("d2", sha=sha))
        _flush_resets(self.store)
        self.store.claim_next()
        self.store.finalize("d2", "done", verdict="pass", reason="UNANIMOUS_PASS")  # no gate_outcome
        self.assertIsNone(self.store.verdicts_for_sha(sha)[0][4])

    def test_same_sha_claimable_after_prior_errored(self) -> None:
        # a NEW delivery for a SHA whose prior delivery ERRORED (not processing) must be
        # claimable — the same-SHA guard blocks only on 'processing', never on error/done.
        self.store.enqueue(_event("d1", sha="f" * 40))
        _flush_resets(self.store)
        self.store.claim_next()
        self.store.finalize("d1", "error", reason="watchdog_timeout")
        self.store.enqueue(_event("d2", sha="f" * 40))  # e.g. a reopened event
        _flush_resets(self.store)
        self.assertIsNotNone(self.store.claim_next())  # not wedged by the errored sibling

    def test_finalize_post_once(self) -> None:
        self.store.enqueue(_event("d1"))
        _flush_resets(self.store)
        self.store.claim_next()
        self.assertTrue(self.store.finalize("d1", "done"))
        self.assertFalse(self.store.finalize("d1", "error"))  # already terminal
        self.assertEqual(self.store.status_of("d1"), "done")

    def test_sweep_stale(self) -> None:
        self.store.enqueue(_event("d1"))
        _flush_resets(self.store)
        self.store.claim_next()
        self.assertEqual(self.store.sweep_stale(900), [])  # not yet stale
        self.clk.t += 1000
        stale = self.store.sweep_stale(900)
        self.assertEqual([e.delivery_id for e in stale], ["d1"])

    def test_concurrent_claims_no_double(self) -> None:
        for i in range(6):
            self.store.enqueue(_event(f"d{i}", sha=f"{i:040d}"))
        _flush_resets(self.store)
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


class _RecordingLifecycle:
    def __init__(self) -> None:
        self.events: list[LifecycleEvent] = []

    def record(self, event: LifecycleEvent) -> None:
        self.events.append(event)


def _summ(_result: JobResult) -> str:  # a trivial JobSummarizer for executor/watchdog construction
    return "summary"


def _admitted_pass() -> AdmittedRunResult:
    res = _admit(_plan(), _report(), _FakeGovernance())
    assert isinstance(res, AdmittedRunResult)
    return res


class ExecutorTests(unittest.TestCase):
    """Increment A: the executor + watchdog RENDER + arm a durable publication at finalize (never post inline);
    the ``Publisher`` drains the outbox onto the actuator. Each test drives the FULL path (reset -> claim ->
    run -> conclusion) through a real ``Publisher`` + fake actuator client, asserting BOTH the persisted gating
    row AND the conclusion the merge UI would see."""

    def setUp(self) -> None:
        self.store, self.clk, _ = _store()
        self.client = _FakeCheckClient()
        self.publisher = Publisher(self.store, self.client)
        self.life = _RecordingLifecycle()

    def _transitions(self, delivery_id: str) -> list[Transition]:
        return [e.transition for e in self.life.events if e.delivery_id == delivery_id]

    def _row(self, sha: str):  # type: ignore[no-untyped-def]
        rows = self.store.verdicts_for_sha(sha)
        assert len(rows) == 1
        return rows[0]  # (status, verdict, reason, updated_at, gate_outcome)

    def _run(self, delivery_id: str, runner, *, sha: str = "a" * 40):  # type: ignore[no-untyped-def]
        ex = Executor(self.store, runner, _summ, lifecycle=self.life)
        self.store.enqueue(_event(delivery_id, sha=sha))
        self.publisher.drain_once()                  # publish RESET (actuator -> in_progress) -> claimable
        assert self.store.claim_next() is not None
        ex.process_claimed(_event(delivery_id, sha=sha))
        self.publisher.drain_once()                  # publish CONCLUSION onto the actuator

    def test_admitted_run_posts_verdict_and_run_gate_outcome(self) -> None:
        self._run("d1", lambda e: _admitted_pass())
        status, verdict, _reason, _u, gate_outcome = self._row("a" * 40)
        self.assertEqual((status, verdict, gate_outcome), ("done", "pass", "run_verdict"))
        self.assertEqual(self.client.surface("acme/widgets", "a" * 40),
                         (CheckStatus.COMPLETED, CheckConclusion.SUCCESS))
        self.assertIn(Transition.COMPLETED, self._transitions("d1"))

    def test_non_run_block_persists_gate_outcome_no_verdict(self) -> None:
        self._run("d1", lambda e: NonRunDecision(Disposition.BLOCK_ACTION_REQUIRED, "degraded"))
        status, verdict, _reason, _u, gate_outcome = self._row("a" * 40)
        self.assertEqual((status, verdict, gate_outcome), ("done", None, "block_gate"))
        self.assertEqual(self.client.surface("acme/widgets", "a" * 40),
                         (CheckStatus.COMPLETED, CheckConclusion.ACTION_REQUIRED))  # blocking

    def test_worker_exception_is_worker_fault(self) -> None:
        def boom(_: GatingEvent) -> JobResult:
            raise RuntimeError("engine died")

        self._run("d1", boom)
        status, verdict, reason, _u, gate_outcome = self._row("a" * 40)
        self.assertEqual((status, verdict, gate_outcome, reason), ("error", None, None, "worker_fault"))
        self.assertEqual(self.client.surface("acme/widgets", "a" * 40),
                         (CheckStatus.COMPLETED, CheckConclusion.ACTION_REQUIRED))  # fail-closed block
        self.assertIn(Transition.ERRORED, self._transitions("d1"))

    def test_non_jobresult_return_is_unaccounted_result_not_worker_fault(self) -> None:
        # board C2: a runner that RETURNS a non-JobResult (a bare Verdict) is UNACCOUNTED_RESULT, DISTINCT
        # from a worker exception (WORKER_FAULT). account() rejects it OUTSIDE the runner try.
        self._run("d1", lambda e: Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))  # noqa: E501 -- NOT a JobResult (runtime-rejected)
        _status, _v, reason, _u, _g = self._row("a" * 40)
        self.assertEqual(reason, "unaccounted_result")
        self.assertEqual(self.client.surface("acme/widgets", "a" * 40),
                         (CheckStatus.COMPLETED, CheckConclusion.ACTION_REQUIRED))

    def test_watchdog_force_is_infrastructure_failure(self) -> None:
        wd = Watchdog(self.store, _summ, timeout_seconds=900, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        self.publisher.drain_once()          # reset published
        self.store.claim_next()
        self.clk.t += 1000
        self.assertEqual(wd.sweep_once(), 1)
        self.publisher.drain_once()          # conclusion published
        status, verdict, reason, _u, gate_outcome = self._row("a" * 40)
        self.assertEqual((status, verdict, gate_outcome, reason), ("error", None, None, "watchdog_timeout"))
        self.assertEqual(self.client.surface("acme/widgets", "a" * 40),
                         (CheckStatus.COMPLETED, CheckConclusion.ACTION_REQUIRED))
        self.assertIn(Transition.WATCHDOG_FORCED, self._transitions("d1"))

    def test_post_once_worker_loses_to_watchdog(self) -> None:
        ex = Executor(self.store, lambda e: _admitted_pass(), _summ, lifecycle=self.life)
        wd = Watchdog(self.store, _summ, timeout_seconds=900, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        self.publisher.drain_once()
        self.store.claim_next()
        self.clk.t += 1000
        self.assertEqual(wd.sweep_once(), 1)          # watchdog force-errors it first (arms conclusion)
        ex.process_claimed(_event("d1"))              # wedged worker un-wedges, too late -> POST_SKIPPED
        self.publisher.drain_once()
        # exactly ONE conclusion reaches the actuator (the watchdog's ACTION_REQUIRED); the worker was skipped
        self.assertEqual(self.client.surface("acme/widgets", "a" * 40),
                         (CheckStatus.COMPLETED, CheckConclusion.ACTION_REQUIRED))
        self.assertEqual([c for (_s, c) in self.client.completed_log], [CheckConclusion.ACTION_REQUIRED])
        self.assertIn(Transition.POST_SKIPPED, self._transitions("d1"))

    def test_shutdown_stops_claiming(self) -> None:
        ex = Executor(self.store, lambda e: _admitted_pass(), _summ, lifecycle=self.life)
        self.store.enqueue(_event("d1"))
        ex.request_shutdown()
        self.assertEqual(ex.drain(), 0)  # graceful shutdown: claim nothing new
        self.assertEqual(self.store.status_of("d1"), "queued")  # left for after restart

    def test_drain_processes_all_distinct(self) -> None:
        ex = Executor(self.store, lambda e: _admitted_pass(), _summ, max_workers=2, lifecycle=self.life)
        for i in range(5):
            self.store.enqueue(_event(f"d{i}", sha=f"{i:040d}"))
        self.publisher.drain_once()          # publish all resets -> all claimable
        self.assertEqual(ex.drain(), 5)
        self.assertEqual(self.publisher.drain_once(), 5)  # 5 conclusions drained onto the actuator


class ClassifierEndToEndTests(unittest.TestCase):
    """dissent P1b/P1c: the REAL executor -> store -> override classifier WIRE path, proven with the actual
    persisted values (VerdictType.value == 'pass'), NOT fictional uppercase literals. The executor persists
    'pass'; the classifier must read that as ALLOWING (a clean merge -> NO_OVERRIDE), and a coexisting infra
    'error' row must surface as INFRA_ERROR (the C5 "infra cannot disappear" masking fix, for real data)."""

    def _persisted_rows(self):  # type: ignore[no-untyped-def]
        from gate.ledger import VerdictRow
        store, _clk, _ = _store()
        ex = Executor(store, lambda e: _admitted_pass(), _summ)
        store.enqueue(_event("d1"))
        _flush_resets(store)
        store.claim_next()
        ex.process_claimed(_event("d1"))
        return [VerdictRow(status=s, verdict=v, reason=r, updated_at=u, gate_outcome=g)
                for (s, v, r, u, g) in store.verdicts_for_sha("a" * 40)]

    def test_executor_persisted_pass_classifies_as_no_override(self) -> None:
        from gate.ledger import OutcomeKind, classify_merge
        rows = self._persisted_rows()
        self.assertEqual(rows[0].verdict, "pass")                          # the persisted WIRE value
        self.assertIs(classify_merge(rows).kind, OutcomeKind.NO_OVERRIDE)  # allowing -> no spurious override

    def test_executor_persisted_pass_plus_infra_error_is_infra_error(self) -> None:
        from gate.ledger import OutcomeKind, UnverifiableReason, VerdictRow, classify_merge
        rows = self._persisted_rows()
        rows.append(VerdictRow(status="error", verdict=None, reason="watchdog_timeout", updated_at=99.0))
        out = classify_merge(rows)
        self.assertIs(out.kind, OutcomeKind.UNVERIFIABLE)
        self.assertIs(out.sub_reason, UnverifiableReason.INFRA_ERROR)      # C5 masking fix, real wire values


class PublicationOutboxTests(unittest.TestCase):
    """Increment A (HIGH liveness): the two-phase publication outbox. The SEAL is the adversarial delayed
    old-after-new interleaving (a stale OLD publish must never overwrite a NEWER conclusion) + durable repair,
    plus the fail-closed reset gate, the Finding-1 dropped-publish regression, complete-binding across a
    config change, and a fresh generation on error-requeue (never a wedged unpublishable queued row)."""

    _REPO = "acme/widgets"

    def setUp(self) -> None:
        self.store, self.clk, _ = _store()          # check_name="gate"
        self.client = _FakeCheckClient()
        self.publisher = Publisher(self.store, self.client)

    def _finalize_done(self, delivery_id: str, conclusion_verdict: str) -> None:
        # a done row whose publication conclusion is success|failure (verdict pass|fail)
        v = "pass" if conclusion_verdict == "success" else "fail"
        self.store.finalize(delivery_id, "done", verdict=v, reason="UNANIMOUS_PASS",
                            gate_outcome="run_verdict",
                            publish_conclusion=conclusion_verdict, publish_summary="s")

    # ---- fail-closed reset gate -----------------------------------------

    def test_reset_gate_blocks_claim_until_published(self) -> None:
        self.store.enqueue(_event("d1", sha="c" * 40))
        self.assertIsNone(self.store.claim_next())        # reset not yet published -> NOT claimable (fail-closed)
        self.assertEqual(self.publisher.drain_once(), 1)  # publisher drives + marks the reset
        self.assertEqual(self.client.surface(self._REPO, "c" * 40), (CheckStatus.IN_PROGRESS, None))
        claimed = self.store.claim_next()
        assert claimed is not None and claimed.delivery_id == "d1"

    def test_github_outage_leaves_delivery_queued_fail_closed(self) -> None:
        self.client.fail = True
        self.store.enqueue(_event("d1", sha="c" * 40))
        self.assertEqual(self.publisher.drain_once(), 0)  # reset cannot publish (outage)
        self.assertIsNone(self.store.claim_next())        # delivery waits in 'queued' -> fail-closed
        self.assertEqual(self.store.status_of("d1"), "queued")

    # ---- THE SEAL: delayed old publish cannot overwrite a newer conclusion

    def test_delayed_old_publish_cannot_overwrite_newer_conclusion(self) -> None:
        sha = "c" * 40
        # generation 1 (d1) runs to a SUCCESS conclusion, pending publish
        self.store.enqueue(_event("d1", sha=sha))
        self.publisher.drain_once()                       # reset1 published
        self.store.claim_next()
        self._finalize_done("d1", "success")
        # an OLD publisher CLAIMS d1's success conclusion (in-flight), then a NEWER delivery lands
        old_job = self.store.claim_publication()
        assert old_job is not None and old_job.phase == "conclusion" and old_job.delivery_id == "d1"
        self.store.enqueue(_event("d2", sha=sha))         # gen2 supersedes gen1's pending conclusion + reset
        # the in-flight OLD publisher writes the stale SUCCESS onto the actuator, THEN tries to mark published
        self.publisher._drive(old_job)                    # stale write lands last
        self.assertEqual(self.client.surface(self._REPO, sha), (CheckStatus.COMPLETED, CheckConclusion.SUCCESS))
        won = self.store.mark_publication_published("d1", "conclusion")
        self.assertFalse(won)                             # no-regression CAS refuses (gen1 is no longer max)
        self.store.repair_publication(self._REPO, sha, "gate")  # durable repair re-drives the true head (gen2)
        # gen2 now runs to a FAILURE and the Publisher drains: reset2 (clears the stale success) THEN failure
        self.publisher.drain_once()                       # publishes reset2 -> surface in_progress
        self.store.claim_next()
        self._finalize_done("d2", "failure")
        self.publisher.drain_once()                       # publishes the gen2 FAILURE conclusion
        # FINAL surface is the newer FAILURE (blocking), NEVER the stale older SUCCESS
        self.assertEqual(self.store.status_of("d2"), "done")
        self.assertEqual(self.client.surface(self._REPO, sha), (CheckStatus.COMPLETED, CheckConclusion.FAILURE))

    # ---- Finding-1 regression: a dropped publish is retried, not lost ----

    def test_dropped_publish_is_retried_not_lost(self) -> None:
        sha = "c" * 40
        self.store.enqueue(_event("d1", sha=sha))
        self.publisher.drain_once()                       # reset published
        self.store.claim_next()
        self._finalize_done("d1", "success")
        self.client.fail = True                           # GitHub goes down mid-publish window
        self.assertEqual(self.publisher.drain_once(), 0)  # conclusion publish fails -> released, attempts++
        # the conclusion is NOT lost: it stays pending (a stuck check keeps the merge blocked, never a false green)
        self.clk.t += 3600                                # let the backoff elapse
        self.client.fail = False                          # GitHub recovers
        self.assertEqual(self.publisher.drain_once(), 1)  # retried durably -> published
        self.assertEqual(self.client.surface(self._REPO, sha), (CheckStatus.COMPLETED, CheckConclusion.SUCCESS))

    def test_permanently_failing_publish_never_shows_a_conclusion(self) -> None:
        sha = "c" * 40
        self.store.enqueue(_event("d1", sha=sha))
        self.publisher.drain_once()                       # reset published (in_progress = blocking)
        self.store.claim_next()
        self._finalize_done("d1", "success")
        self.client.fail = True                           # permanent outage
        for _ in range(3):
            self.clk.t += 3600
            self.assertEqual(self.publisher.drain_once(), 0)  # never publishes a conclusion
        # the surface stays in_progress (blocking) — never a false green, never a COMPLETED success
        self.assertEqual(self.client.surface(self._REPO, sha), (CheckStatus.IN_PROGRESS, None))

    # ---- crash-atomicity: enqueue + supersession are ONE txn ------------

    def test_enqueue_and_supersession_are_atomic(self) -> None:
        sha = "c" * 40
        self.store.enqueue(_event("d1", sha=sha))
        self.publisher.drain_once()                       # reset1 published
        self.store.enqueue(_event("d2", sha=sha))         # ONE BEGIN IMMEDIATE: arm reset2 + supersede reset1
        # both effects are present together — never a newer generation that superseded nothing, nor a
        # supersession with no successor (the crash window the single txn closes).
        pending = self.store.claim_publication()          # only the MAX-gen reset is claimable
        assert pending is not None and pending.delivery_id == "d2" and pending.phase == "reset"
        # d1's reset was superseded (not claimable): draining again yields nothing else pending
        self.store.mark_publication_published("d2", "reset")
        self.assertIsNone(self.store.claim_publication())

    # ---- complete-binding: restart with a changed check name -------------

    def test_restart_with_changed_config_binds_conclusion_to_persisted_reset_identity(self) -> None:
        # Fred's addendum test A: a restart with a CHANGED check name between RESET and finalize must NOT split
        # the two phases across identities — finalize binds the conclusion to the delivery's PERSISTED reset
        # identity (check_name "gate"), never live config ("RENAMED").
        d = Path(tempfile.mkdtemp(prefix="mv-rebind-"))
        db = d / "g.db"
        store1 = GatingStore(db, clock=self.clk, check_name="gate")
        store1.enqueue(_event("d1", sha="c" * 40))
        _flush_resets(store1)                              # reset armed + published under "gate"
        # RESTART with a different deployed name
        store2 = GatingStore(db, clock=self.clk, check_name="RENAMED")
        claimed = store2.claim_next()                     # the reset-gate is delivery-keyed -> still admits d1
        assert claimed is not None
        store2.finalize("d1", "done", verdict="pass", reason="UNANIMOUS_PASS", gate_outcome="run_verdict",
                        publish_conclusion="success", publish_summary="s")
        job = store2.claim_publication()                  # the conclusion must be publishable + bound to "gate"
        assert job is not None and job.phase == "conclusion"
        self.assertEqual(job.check_name, "gate")          # NOT "RENAMED" (complete-binding)

    # ---- fresh generation on error-requeue (Fred's addendum test B) ------

    def test_error_requeue_when_newer_same_identity_exists_is_publishable(self) -> None:
        # Fred's addendum test B: retaining the gating rowid as the generation would leave a re-delivered
        # delivery BELOW a newer sibling forever (reset never max-gen -> never publishes -> a wedged,
        # unpublishable 'queued' row). Minting a fresh per-identity generation on requeue makes the
        # re-delivery the NEWEST generation, so its reset is claimable + publishable.
        sha = "c" * 40
        self.store.enqueue(_event("d1", sha=sha))
        self.publisher.drain_once()
        self.store.claim_next()
        self.store.finalize("d1", "error", reason="watchdog_timeout")  # d1 errored
        self.store.enqueue(_event("d2", sha=sha))         # a NEWER same-identity delivery (gen2) supersedes d1
        self.publisher.drain_once()                       # publishes reset2
        # d1 is RE-DELIVERED (requeue). A rowid generation would keep d1 < gen2 -> wedged. A fresh generation
        # makes d1 the newest -> its reset is the max generation -> claimable + publishable.
        self.assertTrue(self.store.enqueue(_event("d1", sha=sha)))  # error -> requeued
        job = self.store.claim_publication()
        assert job is not None and job.phase == "reset" and job.delivery_id == "d1"  # NOT wedged
        self.assertTrue(self.store.mark_publication_published("d1", "reset"))
        self.assertIsNotNone(self.store.claim_next())     # d1 (re-delivered) can now run


class PublicationLivenessTests(unittest.TestCase):
    """Whole-arc dissent remediation — the STRANDED-STATE class (correctness held, liveness lost). Blocker 1:
    a superseded-while-queued delivery must be RETIRED (never left counting against capacity). Blocker 2: the
    upgrade path must not strand legacy nonterminal rows, and finalize must RAISE (never silently terminalize)
    without an outbox record. Bound: Publisher.drain_once cannot starve the executor under sustained ingress."""

    _REPO = "acme/widgets"

    def setUp(self) -> None:
        self.store, self.clk, self.dir = _store()
        self.client = _FakeCheckClient()
        self.publisher = Publisher(self.store, self.client)

    def _reason(self, store: GatingStore, delivery_id: str) -> str | None:
        row = store._conn().execute(
            "SELECT reason FROM gating WHERE delivery_id=?", (delivery_id,)).fetchone()
        return None if row is None else row["reason"]

    # ---- Blocker 1: reopen storm leaves no unclaimable residue -----------

    def test_reopen_storm_returns_to_steady_state_no_unclaimable_residue(self) -> None:
        sha = "c" * 40
        # leg A — the FIRST delivery's reset is PUBLISHED, then superseded by the storm.
        self.store.enqueue(_event("d0", sha=sha))
        self.publisher.drain_once()                       # d0 reset PUBLISHED
        self.assertEqual(self.client.surface(self._REPO, sha), (CheckStatus.IN_PROGRESS, None))
        # leg B — every subsequent delivery's reset is NEVER published before the next supersedes it.
        for i in range(1, 25):
            self.store.enqueue(_event(f"d{i}", sha=sha))
        # steady state: exactly ONE claimable-queued delivery (the newest); all priors RETIRED.
        self.assertEqual(self.store.queued_count(), 1)
        self.assertEqual(self.store.status_of("d0"), "superseded")   # leg A retired
        self.assertEqual(self.store.status_of("d1"), "superseded")   # leg B retired
        self.assertEqual(self.store.status_of("d24"), "queued")      # the newest survives
        # audit visibility: the retirement reason is recorded (a storm is visible in the record).
        self.assertEqual(self._reason(self.store, "d0"), "superseded_while_queued")
        self.assertEqual(self._reason(self.store, "d1"), "superseded_while_queued")
        # the newest still runs to completion end-to-end (no residue blocks it).
        self.publisher.drain_once()                       # publish d24 reset
        ev = self.store.claim_next()
        assert ev is not None and ev.delivery_id == "d24"

    def test_retired_superseded_row_is_non_participating_in_the_classifier(self) -> None:
        from gate.ledger import OutcomeKind, VerdictRow, classify_merge
        sha = "c" * 40
        self.store.enqueue(_event("d0", sha=sha))
        self.publisher.drain_once()
        self.store.enqueue(_event("d1", sha=sha))         # retires d0 as superseded-while-queued
        # a retired 'superseded' row coexisting with a clean done verdict must NOT change the outcome.
        rows = [VerdictRow(status=s, verdict=v, reason=r, updated_at=u, gate_outcome=g)
                for (s, v, r, u, g) in self.store.verdicts_for_sha(sha)]
        rows.append(VerdictRow(status="done", verdict="pass", reason="UNANIMOUS_PASS", updated_at=99.0,
                               gate_outcome="run_verdict"))
        self.assertTrue(any(r.status == "superseded" for r in rows))   # it IS in the audit trail
        self.assertIs(classify_merge(rows).kind, OutcomeKind.NO_OVERRIDE)  # but does not skew the verdict

    # ---- Blocker 2: upgrade migration + finalize invariant ---------------

    def test_upgrade_migration_terminalizes_all_legacy_nonterminal_shapes(self) -> None:
        # a fixture DB seeded (via raw SQL, bypassing enqueue) with the three legacy shapes that predate the
        # publication outbox — NONE has a reset row. A fresh GatingStore's startup migration must terminalize
        # every one (never leave a permanently-unclaimable queued row, nor a processing row that would drive
        # finalize's raising invariant).
        db = self.dir / "legacy.db"
        seed = GatingStore(db, clock=self.clk)             # create schema
        raw = sqlite3.connect(str(db))
        raw.executescript(
            "INSERT INTO gating (delivery_id, repo_full_name, head_sha, installation_id, action, status,"
            " enqueued_at, updated_at) VALUES"
            " ('leg-queued-payload','acme/w','a','1','opened','queued',1,1),"
            " ('leg-queued-bare','acme/w','b','1','opened','queued',1,1),"
            " ('leg-processing','acme/w','c','1','opened','processing',1,1);")
        raw.commit()
        raw.close()
        del seed
        migrated = GatingStore(db, clock=self.clk)         # __init__ runs the migration
        self.assertEqual(migrated.queued_count(), 0)       # no stranded nonterminal residue
        for did in ("leg-queued-payload", "leg-queued-bare", "leg-processing"):
            self.assertEqual(migrated.status_of(did), "superseded")
            self.assertEqual(self._reason(migrated, did), "unmigratable_legacy")
        # a fresh Increment-A delivery on the SAME upgraded DB is unaffected (arms its own reset).
        migrated.enqueue(_event("fresh", sha="f" * 40))
        self.assertEqual(migrated.status_of("fresh"), "queued")

    def test_finalize_without_outbox_reset_raises_never_silently_terminalizes(self) -> None:
        # terminal-without-publication is the v1 defect: a won finalize with no RESET must RAISE, and the
        # raise must ROLL BACK the terminal UPDATE (the row stays 'processing', surfacing loudly).
        db = self.dir / "noreset.db"
        store = GatingStore(db, clock=self.clk)            # migration runs on the empty DB -> no-op
        raw = sqlite3.connect(str(db))                     # seed a processing row with NO reset AFTER migration
        raw.execute(
            "INSERT INTO gating (delivery_id, repo_full_name, head_sha, installation_id, action, status,"
            " enqueued_at, updated_at) VALUES ('p','acme/w','a','1','opened','processing',1,1)")
        raw.commit()
        raw.close()
        with self.assertRaises(OutboxInvariantError):
            store.finalize("p", "done", verdict="pass", reason="R", gate_outcome="run_verdict",
                           publish_conclusion="success", publish_summary="s")
        self.assertEqual(store.status_of("p"), "processing")  # rolled back — surfaces loudly, not laundered

    # ---- Bound: sustained ingress cannot starve the executor -------------

    def test_drain_once_bounded_by_max_items(self) -> None:
        pub = Publisher(self.store, self.client, max_items=3)
        for i in range(10):
            self.store.enqueue(_event(f"d{i}", sha=f"{i:040d}"))   # 10 distinct identities, all claimable
        self.assertEqual(pub.drain_once(), 3)                       # BOUNDED — did not drain all 10
        self.assertEqual(pub.drain_once(), 3)                       # remaining work drains on later calls
        self.assertGreater(self.store.queued_count(), 0)            # executor still has claimable work between

    def test_drain_once_bounded_by_wall_clock(self) -> None:
        ticks = [0.0, 0.0, 9.0, 9.0, 9.0]                           # start=0; after 1 item the clock passes 5s
        pub = Publisher(self.store, self.client, max_seconds=5.0,
                        clock=lambda: ticks.pop(0) if ticks else 9.0)
        for i in range(10):
            self.store.enqueue(_event(f"d{i}", sha=f"{i:040d}"))
        published = pub.drain_once()
        self.assertLessEqual(published, 1)                          # wall-clock budget stopped it early
        self.assertGreater(self.store.queued_count(), 5)           # the loop did NOT monopolise the tick


class IdentityStructuralClosureTests(unittest.TestCase):
    """Dissent #5 — the partial-identity / unbound-reader defect, caught a fifth time (re-imported by the
    remediation for the third). The STRUCTURAL closure: identity is derived through the single ``_reset_identity``
    accessor; ``self._check_name`` (the partial coordinate) is read in exactly ONE place — enqueue's fresh mint.
    A rename must not let a new delivery compute a wrong-identity generation nor retire another identity's row."""

    def _store_file(self) -> Path:
        return Path(__file__).resolve().parent.parent / "gate" / "store.py"

    def test_check_name_read_only_in_enqueue_mint_fallback(self) -> None:
        # STRUCTURAL guard: make the partial form unrepresentable. Every ``self._check_name`` Attribute-LOAD in
        # store.py must live inside ``enqueue`` (the sole sanctioned config read); the assignment in __init__ is
        # a Store ctx and is not flagged. A future retirement/generation query written by the next agent
        # physically cannot scope by the partial coordinate — it would trip this test in CI.
        import ast
        tree = ast.parse(self._store_file().read_text())
        offenders: list[tuple[str, int]] = []

        class V(ast.NodeVisitor):
            def __init__(self) -> None:
                self.fn: list[str] = []

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                self.fn.append(node.name)
                self.generic_visit(node)
                self.fn.pop()

            visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

            def visit_Attribute(self, node: ast.Attribute) -> None:
                if node.attr == "_check_name" and isinstance(node.ctx, ast.Load):
                    where = self.fn[-1] if self.fn else "<module>"
                    if where != "enqueue":
                        offenders.append((where, node.lineno))
                self.generic_visit(node)

        V().visit(tree)
        self.assertEqual(offenders, [], f"self._check_name read outside enqueue's mint: {offenders}")


class RenameIdentityTests(unittest.TestCase):
    """The two dissent-mandated rename scenarios — twins of the reopen-storm and complete-binding tests, one
    actuator-identity level up. A deployed check-name RENAME is modelled by reopening the SAME DB with a
    different ``check_name``."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="mv-rename-"))
        self.db = self.dir / "g.db"
        self.clk = _Clock()

    def _open(self, check_name: str) -> GatingStore:
        return GatingStore(self.db, clock=self.clk, check_name=check_name)

    def test_rename_then_new_same_sha_does_not_retire_old_identity(self) -> None:
        sha = "c" * 40
        old = self._open("old-name")
        old.enqueue(_event("d-old", sha=sha))
        _flush_resets(old)                                  # d-old reset PUBLISHED under "old-name"
        # RENAME: reopen the same DB with a new deployed check name; a fresh same-SHA delivery arrives.
        new = self._open("new-name")
        new.enqueue(_event("d-new", sha=sha))
        # d-old belongs to a DIFFERENT actuator identity — it must NOT be retired (both checks deserve a life).
        self.assertEqual(new.status_of("d-old"), "queued")
        self.assertEqual(new.status_of("d-new"), "queued")
        # each reset kept its own persisted identity (write-once).
        self.assertEqual(new._reset_identity(new._conn(), "d-old"), (  # type: ignore[comparison-overlap]
            "acme/widgets", sha, "old-name", 1))
        self.assertEqual(new._reset_identity(new._conn(), "d-new")[2], "new-name")  # type: ignore[index]
        # NOT stranded: d-old's reset is already published, so it is claimable + runs (config-agnostic).
        ev = new.claim_next()
        assert ev is not None and ev.delivery_id == "d-old"

    def test_rename_then_error_requeue_derives_identity_from_persisted_reset(self) -> None:
        sha = "c" * 40
        old = self._open("old-name")
        old.enqueue(_event("d1", sha=sha))
        _flush_resets(old)
        old.claim_next()
        old.finalize("d1", "error", reason="watchdog_timeout")   # d1 errored under "old-name", gen 1
        old.enqueue(_event("d2", sha=sha))                        # a NEWER "old-name" sibling, gen 2
        _flush_resets(old)
        # RENAME, then ERROR-REQUEUE d1 under the new config. A live-config generation would compute MAX over
        # "new-name" (=0)+1 = gen 1 < d2's gen 2 -> unpublishable wedge. Deriving from the persisted reset uses
        # "old-name" (MAX=2)+1 = gen 3 -> the NEWEST for its identity -> publishable.
        new = self._open("new-name")
        self.assertTrue(new.enqueue(_event("d1", sha=sha)))       # error -> requeued
        ident = new._reset_identity(new._conn(), "d1")
        assert ident is not None
        self.assertEqual(ident[2], "old-name")                    # identity PRESERVED across the rename
        self.assertEqual(ident[3], 3)                             # fresh gen minted over the OLD identity
        # publishable: claim_publication hands out d1's reset (max gen for "old-name"), NOT wedged.
        job = new.claim_publication()
        assert job is not None and job.delivery_id == "d1"
        self.assertEqual(job.check_name, "old-name")


class BackpressureTests(unittest.TestCase):
    def test_sink_full_at_capacity(self) -> None:
        store, _, _ = _store()
        sink = StoreBackedGatingSink(store, max_depth=2)
        sink.enqueue(_event("d1", sha="1" * 40))
        sink.enqueue(_event("d2", sha="2" * 40))
        with self.assertRaises(SinkFull):
            sink.enqueue(_event("d3", sha="3" * 40))


if __name__ == "__main__":
    unittest.main()
