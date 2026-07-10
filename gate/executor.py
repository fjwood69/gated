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

from core import Reason, Verdict, VerdictType

from .checkrun import verdict_to_conclusion
from .queue import GatingEvent
from .store import GatingStore

_log = logging.getLogger("gated.gate.lifecycle")

# Engine/telemetry fault (job raised, or watchdog forced) -> a blocking ERROR verdict.
ERROR_VERDICT = Verdict(VerdictType.ERROR, Reason.OBSERVATION_INCOMPLETE)

# The check that RAN (any verdict) is DB-terminal 'done'; an infra fault / watchdog
# force is DB-terminal 'error'. Both post a completed Check Run (the conclusion
# difference is the verdict->conclusion mapping in checkrun.py).
JobRunner = Callable[[GatingEvent], Verdict]     # fetch+extract+build+run engine (injected)
CheckUpdater = Callable[[GatingEvent, Verdict], None]  # post the terminal Check Run (injected)


class Transition(Enum):
    CLAIMED = "claimed"
    COMPLETED = "completed"        # ran to a verdict, posted
    ERRORED = "errored"           # job raised -> ERROR verdict, posted
    WATCHDOG_FORCED = "watchdog_forced"  # stuck job force-ERRORed
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
        Check Run update. Safe to call from any worker thread."""
        self._emit(event, Transition.CLAIMED, event.head_sha)
        try:
            verdict = self._job_runner(event)
            terminal, transition = "done", Transition.COMPLETED
        except Exception as exc:  # infra/engine fault -> ERROR, never a hang
            verdict = ERROR_VERDICT
            terminal, transition = "error", Transition.ERRORED
            _log.warning("gate job raised for %s: %r", event.delivery_id, exc)

        won = self._store.finalize(
            event.delivery_id,
            terminal,
            verdict=verdict.status.value,
            reason=verdict.reason.value,
        )
        if not won:
            # the watchdog (or another worker) already finalized -> do NOT double-post
            self._emit(event, Transition.POST_SKIPPED, "lost finalize race")
            return
        self._updater(event, verdict)
        # record the ACTUAL posted conclusion as an audit FACT (not merely derivable):
        # verdict.reason + the conclusion GitHub was told, for the compliance trail.
        conclusion = verdict_to_conclusion(verdict.status)
        self._emit(event, transition, f"{verdict.reason.value} -> {conclusion.value}")

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
        """Force-ERROR every stale processing delivery we win the finalize for. Returns
        the number forced."""
        forced = 0
        for event in self._store.sweep_stale(self._timeout):
            won = self._store.finalize(
                event.delivery_id,
                "error",
                verdict=VerdictType.ERROR.value,
                reason="watchdog_timeout",
            )
            if not won:
                # the worker completed between the sweep and the finalize -> skip
                self._lifecycle.record(
                    LifecycleEvent(event.delivery_id, Transition.POST_SKIPPED, "worker won")
                )
                continue
            self._updater(event, ERROR_VERDICT)
            self._lifecycle.record(
                LifecycleEvent(event.delivery_id, Transition.WATCHDOG_FORCED, "stale timeout")
            )
            forced += 1
        return forced
