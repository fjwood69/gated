"""gate/executor.py — the async executor + watchdog (2.3).

Consumes the durable ``GatingStore`` with a BOUNDED thread pool (the concurrency
semaphore — protects the single-node runner from OOM; backpressure is propagated to
the 2.1 receiver by the store-backed sink returning 503). Each job:

    claim (store) -> run the check (injected job_runner) -> finalize POST-ONCE -> post
    the one terminal Check Run update (injected updater).

Crash -> ERROR, never a hung check, via two layers:
  * in-worker ``try/except`` — a job that raises becomes an ERROR verdict;
  * the ``Watchdog`` — sweeps deliveries stuck in ``processing`` past a deadline and
    force-completes them as ERROR.

Both go through ``store.finalize(... WHERE status='processing')`` — the POST-ONCE
guard — so a wedged worker that later un-wedges and the watchdog can never both post a
terminal update: whoever wins the atomic finalize posts; the loser is skipped.

Lifecycle observability (continuing the 2.1 boundary audit trail through the middle):
every transition is emitted to a ``LifecycleSink`` so the audit trail is continuous
from webhook-received to verdict-posted.

Threads (not processes): the heavy work is the podman subprocess + network I/O, so the
GIL is released; a process pool would add complexity for no gain. Stdlib only — no
external message broker (open-core purity).
"""
from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Protocol

from .checkrun import (
    CheckConclusion,
    CheckOutput,
    CheckRunError,
    CheckStatus,
    GitHubCheckClient,
    upsert_check_run,
)
from .job_result import InfraFailureReason, InfrastructureFailure, JobResult, account
from .queue import GatingEvent
from .store import GatingStore, PublicationJob

_log = logging.getLogger("gated.gate.lifecycle")

# CP2 S5: the job runner returns a TYPED ``JobResult`` (never a bare Verdict). ``account`` maps it to the
# HONEST persistence + publication fields. A DB-terminal 'done' row is an admitted run / admission refusal /
# governance non-run; a DB-terminal 'error' row is an infrastructure fault (``InfrastructureFailure``) — a
# worker exception, an unaccounted return, or a watchdog force. The conclusion is ``account(result).conclusion``.
JobRunner = Callable[[GatingEvent], JobResult]     # fetch+extract+build+run engine+admit (injected)
# Increment A: the executor + watchdog no longer POST to GitHub inline (that unwrapped call on a terminal row
# was the Finding-1 liveness defect). They RENDER the summary via a ``JobSummarizer`` and persist a durable
# publication at finalize; the ``Publisher`` drains the outbox onto the actuator.
JobSummarizer = Callable[[JobResult], str]         # render the Check Run summary string (closes over the name)
CheckUpdater = Callable[[GatingEvent, JobResult], None]  # legacy inline updater (retained for make_check_updater/tests)


class Transition(Enum):
    CLAIMED = "claimed"
    COMPLETED = "completed"        # a 'done' row (admitted run / admission refusal / non-run), posted
    ERRORED = "errored"           # an 'error' row (infra fault: worker exception / unaccounted / watchdog), posted
    WATCHDOG_FORCED = "watchdog_forced"  # stuck job force-completed to a blocking infra error
    POST_SKIPPED = "post_skipped"  # lost the finalize race -> did NOT arm a publication (post-once)
    # Increment A (Publisher — the sole actuator writer):
    PUBLISHED = "published"          # a publication (reset|conclusion) was driven onto the actuator + CAS-marked
    PUBLISH_DEFERRED = "publish_deferred"  # CheckRunError -> re-armed for durable retry (fail-closed, unbounded)
    PUBLISH_REPAIRED = "publish_repaired"  # a newer generation landed mid-publish -> durable repair re-drove


@dataclass(frozen=True)
class LifecycleEvent:
    delivery_id: str
    transition: Transition
    detail: str


class LifecycleSink(Protocol):
    def record(self, event: LifecycleEvent) -> None: ...


class LoggingLifecycleSink:
    def record(self, event: LifecycleEvent) -> None:
        _log.info(
            "gate.lifecycle delivery=%s transition=%s detail=%s",
            event.delivery_id,
            event.transition.value,
            event.detail,
        )


class NullLifecycleSink:
    def record(self, event: LifecycleEvent) -> None:
        return


class Executor:
    """Bounded-concurrency consumer of the gating store."""

    def __init__(
        self,
        store: GatingStore,
        job_runner: JobRunner,
        summarize: JobSummarizer,
        *,
        max_workers: int = 1,
        lifecycle: LifecycleSink | None = None,
    ) -> None:
        self._store = store
        self._job_runner = job_runner
        self._summarize = summarize
        self._max_workers = max_workers
        self._lifecycle = lifecycle if lifecycle is not None else LoggingLifecycleSink()
        self._shutting_down = False

    def request_shutdown(self) -> None:
        """Signal graceful shutdown (SIGTERM): stop CLAIMING new jobs. In-flight jobs in
        the current ``drain()`` batch finish; the live server also flips the receiver to
        503 and waits (with a hard timeout) before exit, force-ERRORing any straggler so
        no Check Run is orphaned in ``in_progress``."""
        self._shutting_down = True

    def process_claimed(self, event: GatingEvent) -> None:
        """Run one ALREADY-CLAIMED (status=processing) delivery to a terminal, POST-ONCE
        Check Run update. Safe to call from any worker thread.

        Two DISTINCT infra faults, NOT collapsed (board C2): a worker that RAISES is a ``WORKER_FAULT``;
        a worker that RETURNS a non-``JobResult`` (so ``account`` rejects it) is an ``UNACCOUNTED_RESULT``.
        ``account`` sits OUTSIDE the job-runner ``try`` so a bad-return is classified distinctly from a
        raise, and BOTH fail closed (a blocking ``error`` row) rather than crashing the poll loop."""
        self._emit(event, Transition.CLAIMED, event.head_sha)
        result: JobResult
        try:
            result = self._job_runner(event)
        except Exception as exc:  # a worker exception -> WORKER_FAULT (blocking error), never a hang
            result = InfrastructureFailure(InfraFailureReason.WORKER_FAULT, detail=repr(exc))
            _log.warning("gate job raised for %s: %r", event.delivery_id, exc)
        try:
            outcome = account(result)
        except TypeError as exc:  # a non-JobResult RETURN (not a raise) — distinct from WORKER_FAULT
            _log.error("gate job returned a non-JobResult for %s: %r", event.delivery_id, exc)
            result = InfrastructureFailure(InfraFailureReason.UNACCOUNTED_RESULT, detail=repr(exc))
            outcome = account(result)

        # Increment A: RENDER the summary in-process BEFORE finalize, and persist the CONCLUSION publication
        # payload ATOMICALLY in the finalize CAS (the winner arms a distinct durable outbox row bound to the
        # delivery's persisted RESET identity; a newer generation makes it born 'superseded'). We do NOT post
        # to GitHub here — the Publisher drains the outbox onto the actuator. A raise can no longer drop the
        # publication permanently on a terminal row (the Finding-1 defect).
        publish_summary = self._summarize(result)
        won = self._store.finalize(
            event.delivery_id,
            outcome.status,
            verdict=(outcome.verdict.status.value if outcome.verdict is not None else None),
            reason=outcome.reason,
            gate_outcome=(outcome.gate_outcome.value if outcome.gate_outcome is not None else None),
            publish_conclusion=outcome.conclusion.value,
            publish_summary=publish_summary,
        )
        if not won:
            # the watchdog (or another worker) already finalized + armed the publication -> do NOT double-arm
            self._emit(event, Transition.POST_SKIPPED, "lost finalize race")
            return
        # record the DECIDED conclusion as an audit FACT: the outcome's stable reason token + the conclusion
        # armed for publication. A 'done' row COMPLETED (ran/refused/non-run); an 'error' row ERRORED (infra).
        transition = Transition.COMPLETED if outcome.status == "done" else Transition.ERRORED
        self._emit(event, transition, f"{outcome.reason} -> {outcome.conclusion.value}")

    def drain(self) -> int:
        """Claim + process every currently-claimable delivery across the bounded pool.
        Returns the number processed. (A server calls this on a poll loop.)"""
        if self._shutting_down:
            return 0  # graceful shutdown: claim nothing new (in-flight already draining)
        events: list[GatingEvent] = []
        while True:
            event = self._store.claim_next()
            if event is None:
                break
            events.append(event)
        if not events:
            return 0
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            list(pool.map(self.process_claimed, events))
        return len(events)

    def _emit(self, event: GatingEvent, transition: Transition, detail: str) -> None:
        self._lifecycle.record(LifecycleEvent(event.delivery_id, transition, detail))


class Watchdog:
    """Fail-closed sweeper for deliveries stuck in ``processing`` (a crashed/wedged
    worker). Force-completes them as ERROR — POST-ONCE via the same finalize guard."""

    def __init__(
        self,
        store: GatingStore,
        summarize: JobSummarizer,
        *,
        timeout_seconds: float,
        lifecycle: LifecycleSink | None = None,
    ) -> None:
        self._store = store
        self._summarize = summarize
        self._timeout = timeout_seconds
        self._lifecycle = lifecycle if lifecycle is not None else LoggingLifecycleSink()

    def sweep_once(self) -> int:
        """Force every stale processing delivery we win the finalize for to a blocking infra ERROR.
        Returns the number forced. A wedged worker force-completed by the watchdog is an
        ``InfrastructureFailure(WATCHDOG_TIMEOUT)`` — a blocking 'error' row (verdict None, no gate outcome).
        Increment A: the winner ARMS the CONCLUSION publication in the finalize CAS (rendered here) rather
        than posting inline; the Publisher drains it (POST-ONCE preserved — only the finalize winner arms)."""
        forced = 0
        for event in self._store.sweep_stale(self._timeout):
            result: JobResult = InfrastructureFailure(
                InfraFailureReason.WATCHDOG_TIMEOUT, detail="stale processing past the watchdog deadline")
            outcome = account(result)
            won = self._store.finalize(
                event.delivery_id,
                outcome.status,
                verdict=None,
                reason=outcome.reason,
                gate_outcome=None,
                publish_conclusion=outcome.conclusion.value,
                publish_summary=self._summarize(result),
            )
            if not won:
                # the worker completed between the sweep and the finalize -> skip (it armed the publication)
                self._lifecycle.record(
                    LifecycleEvent(event.delivery_id, Transition.POST_SKIPPED, "worker won")
                )
                continue
            self._lifecycle.record(
                LifecycleEvent(event.delivery_id, Transition.WATCHDOG_FORCED, "stale timeout")
            )
            forced += 1
        return forced


class Publisher:
    """Increment A: the SOLE writer of the ACTUATOR — the GitHub Check Run branch protection reads. It drains
    the durable publication outbox the executor/watchdog arm at finalize (and the RESET the store arms at
    enqueue). The executor never posts inline any more (an unwrapped inline post on a terminal row was the
    Finding-1 liveness defect: a raise dropped the publication permanently, blocking the PR with no recovery).

    Each ``drain_once`` claims the oldest DUE, current-max-generation, phase-ready publication (leasing it so a
    crashed publisher's work is reclaimable), drives it idempotently onto the actuator, and marks it published
    under a NO-REGRESSION CAS:
      * ``CheckRunError`` -> ``release_publication`` (++attempts, back off) -> retried durably on a later
        drain. UNBOUNDED: a stuck actuator keeps the check pending/blocking, never a false green.
      * a LOST mark-published CAS -> a NEWER generation landed during the publish window, so the bytes we just
        wrote may be stale (last-writer-wins on the actuator) -> ``repair_publication`` DURABLY re-drives the
        current max generation (re-assert the true head — the ABA barrier's re-assert half, not just release).
    RESET publishes before its generation's CONCLUSION (the phase-ordering fence lives in ``claim_publication``),
    so a stale conclusion can never land after a reset re-armed the surface to pending."""

    def __init__(
        self,
        store: GatingStore,
        client: GitHubCheckClient,
        *,
        lease_seconds: float = 300.0,
        backoff_seconds: float = 30.0,
        lifecycle: LifecycleSink | None = None,
    ) -> None:
        self._store = store
        self._client = client
        self._lease = lease_seconds
        self._backoff = backoff_seconds
        self._lifecycle = lifecycle if lifecycle is not None else LoggingLifecycleSink()

    def drain_once(self) -> int:
        """Drive every currently-claimable publication onto the actuator. Returns the number newly published.
        Bounded: each iteration either publishes (progress) or re-arms the finite current-max-generation set,
        which then drains — never an unbounded spin."""
        published = 0
        while True:
            job = self._store.claim_publication(lease_seconds=self._lease)
            if job is None:
                break
            try:
                self._drive(job)
            except CheckRunError as exc:
                # fail-closed durable retry: the surface stays pending/blocking (never a false green); the
                # attempts count drives backoff + alerting, never give-up.
                self._store.release_publication(
                    job.delivery_id, job.phase, backoff_seconds=self._backoff)
                self._lifecycle.record(LifecycleEvent(
                    job.delivery_id, Transition.PUBLISH_DEFERRED, f"{job.phase}: {exc!r}"))
                continue
            won = self._store.mark_publication_published(job.delivery_id, job.phase)
            if won:
                published += 1
                self._lifecycle.record(LifecycleEvent(
                    job.delivery_id, Transition.PUBLISHED, f"{job.phase} -> {job.status}"))
            else:
                # superseded mid-publish: our external bytes may have landed last + stale. DURABLY re-drive the
                # current max generation to re-assert the true head (the last-writer-wins ABA barrier).
                self._store.repair_publication(job.repo_full_name, job.head_sha, job.check_name)
                self._lifecycle.record(LifecycleEvent(
                    job.delivery_id, Transition.PUBLISH_REPAIRED,
                    f"{job.phase}: superseded mid-publish, repaired to max generation"))
        return published

    def _drive(self, job: PublicationJob) -> None:
        """Drive ONE publication phase onto the actuator idempotently (find-then-PATCH-or-POST by SHA+name).
        RESET flips the surface to ``in_progress`` (clearing any prior stale conclusion -> non-passing ->
        BLOCKS) BEFORE the delivery is allowed to run (the ``claim_next`` reset-gate). CONCLUSION posts the
        already-decided, fail-closed conclusion + rendered summary."""
        if job.phase == "reset":
            upsert_check_run(
                self._client, repo_full_name=job.repo_full_name, head_sha=job.head_sha,
                name=job.check_name, status=CheckStatus.IN_PROGRESS)
            return
        conclusion = (CheckConclusion(job.conclusion) if job.conclusion is not None
                      else CheckConclusion.ACTION_REQUIRED)  # defensive: account() always yields a conclusion
        upsert_check_run(
            self._client, repo_full_name=job.repo_full_name, head_sha=job.head_sha,
            name=job.check_name, status=CheckStatus.COMPLETED, conclusion=conclusion,
            output=CheckOutput(title=job.check_name, summary=job.summary or ""))
