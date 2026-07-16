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

from .job_result import InfraFailureReason, InfrastructureFailure, JobResult, account
from .queue import GatingEvent
from .store import GatingStore

_log = logging.getLogger("gated.gate.lifecycle")

# CP2 S5: the job runner returns a TYPED ``JobResult`` (never a bare Verdict). ``account`` maps it to the
# HONEST persistence + publication fields; the updater publishes from the typed result. A DB-terminal 'done'
# row is an admitted run / admission refusal / governance non-run; a DB-terminal 'error' row is an
# infrastructure fault (``InfrastructureFailure``) — a worker exception, an unaccounted return, or a
# watchdog force. Both post one completed Check Run (the conclusion is ``account(result).conclusion``).
JobRunner = Callable[[GatingEvent], JobResult]     # fetch+extract+build+run engine+admit (injected)
CheckUpdater = Callable[[GatingEvent, JobResult], None]  # post the terminal Check Run from the typed result


class Transition(Enum):
    CLAIMED = "claimed"
    COMPLETED = "completed"        # a 'done' row (admitted run / admission refusal / non-run), posted
    ERRORED = "errored"           # an 'error' row (infra fault: worker exception / unaccounted / watchdog), posted
    WATCHDOG_FORCED = "watchdog_forced"  # stuck job force-completed to a blocking infra error
    POST_SKIPPED = "post_skipped"  # lost the finalize race -> did NOT post (post-once)


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
        updater: CheckUpdater,
        *,
        max_workers: int = 1,
        lifecycle: LifecycleSink | None = None,
    ) -> None:
        self._store = store
        self._job_runner = job_runner
        self._updater = updater
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

        won = self._store.finalize(
            event.delivery_id,
            outcome.status,
            verdict=(outcome.verdict.status.value if outcome.verdict is not None else None),
            reason=outcome.reason,
            gate_outcome=(outcome.gate_outcome.value if outcome.gate_outcome is not None else None),
        )
        if not won:
            # the watchdog (or another worker) already finalized -> do NOT double-post
            self._emit(event, Transition.POST_SKIPPED, "lost finalize race")
            return
        self._updater(event, result)
        # record the ACTUAL posted conclusion as an audit FACT: the outcome's stable reason token + the
        # conclusion GitHub was told. A 'done' row COMPLETED (ran/refused/non-run); an 'error' row ERRORED (infra).
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
        updater: CheckUpdater,
        *,
        timeout_seconds: float,
        lifecycle: LifecycleSink | None = None,
    ) -> None:
        self._store = store
        self._updater = updater
        self._timeout = timeout_seconds
        self._lifecycle = lifecycle if lifecycle is not None else LoggingLifecycleSink()

    def sweep_once(self) -> int:
        """Force every stale processing delivery we win the finalize for to a blocking infra ERROR.
        Returns the number forced. A wedged worker force-completed by the watchdog is an
        ``InfrastructureFailure(WATCHDOG_TIMEOUT)`` — a blocking 'error' row (verdict None, no gate
        outcome), published via the same typed updater as every other outcome (POST-ONCE)."""
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
            )
            if not won:
                # the worker completed between the sweep and the finalize -> skip
                self._lifecycle.record(
                    LifecycleEvent(event.delivery_id, Transition.POST_SKIPPED, "worker won")
                )
                continue
            self._updater(event, result)
            self._lifecycle.record(
                LifecycleEvent(event.delivery_id, Transition.WATCHDOG_FORCED, "stale timeout")
            )
            forced += 1
        return forced
