"""gate/queue.py — the gating-event sink SEAM.

2.1 is a PURE receiver: on an authenticated + authorized gating event it ENQUEUES a
``GatingEvent`` and returns 202 immediately — decoupling the webhook ack from any
GitHub API latency (GitHub's ~10s delivery-timeout budget; a synchronous write there
risks timeout -> re-delivery -> duplicate). The consumer — the async executor that
creates the Check Run and runs the engine — is 2.2/2.3.

A bounded sink lets the executor apply BACKPRESSURE (the concurrency gap): when the
single-host runner is saturated, ``enqueue`` raises ``SinkFull`` -> the receiver
returns 503 and GitHub re-delivers, rather than the runner OOMing on a burst of
``synchronize`` events across several PRs.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


class SinkFull(RuntimeError):
    """The gating queue is at capacity (backpressure). Receiver -> 503, GitHub retries."""


@dataclass(frozen=True)
class GatingEvent:
    """A PR head that needs gating — the unit handed to the executor. Bound to the
    exact head SHA the eventual verdict must match at merge.

    ``repo_full_name`` is ALWAYS the BASE repo — the Check Run posts there (that is where
    branch protection blocks) and the override ledger keys on it. ``head_repo_full_name``
    is the FORK's repo for a cross-repo PR (else None / == base); it is ONLY a fetch hint
    for the C2 fork-fetch contingency, and must never displace the base for check/ledger."""

    delivery_id: str
    repo_full_name: str
    head_sha: str
    action: str
    installation_id: int
    head_repo_full_name: str | None = None


class GatingSink(Protocol):
    def enqueue(self, event: GatingEvent) -> None:
        """Accept an event for async processing, or raise ``SinkFull`` under
        backpressure (never block the webhook handler)."""


class InMemoryGatingSink:
    """Reference sink: an unbounded process-local list (2.1 has no consumer yet).
    2.3 replaces this with a bounded queue feeding the async executor."""

    def __init__(self) -> None:
        self.events: list[GatingEvent] = []

    def enqueue(self, event: GatingEvent) -> None:
        self.events.append(event)


# ---- C3: override-capture seam (the merge-past-the-gate audit path) ----------
#
# A DISTINCT event class from GatingEvent. Gating events run the engine; an override
# capture NEVER runs the engine — it reads the recorded verdict for a merged SHA and
# appends an audit record. The receiver hands one off on `pull_request` closed+merged;
# the poll loop drains it to the ledger (idempotent by the closed webhook's delivery_id).


@dataclass(frozen=True)
class OverrideCaptureEvent:
    """A PR that closed as MERGED — the unit handed to the override-ledger capture.
    Carries only what the webhook payload attests (no branch-protection knowledge): the
    idempotency key (this closed delivery), the merged head SHA, and the merge actor/time
    for the audit record."""

    delivery_id: str          # the CLOSED webhook's delivery-id — the ledger idempotency key
    repo_full_name: str
    head_sha: str
    pr_number: int | None
    merged_by: str | None
    merged_at: str | None


class OverrideSink(Protocol):
    def enqueue(self, event: OverrideCaptureEvent) -> None:
        """Accept a merged-PR capture, or raise ``SinkFull`` under backpressure (the
        receiver then 503s and GitHub re-delivers — the closed event is idempotent at
        the ledger, so a re-delivery cannot double-record)."""


class InMemoryOverrideSink:
    """Bounded process-local capture queue. Loss on crash is tolerated by design — the
    ledger's delivery_id UNIQUE constraint makes re-delivery safe, and reconciliation
    backfills a dropped event. ``drain`` hands the batch to the capture handler."""

    def __init__(self, *, max_depth: int = 256) -> None:
        self._events: list[OverrideCaptureEvent] = []
        self._max_depth = max_depth

    def enqueue(self, event: OverrideCaptureEvent) -> None:
        if len(self._events) >= self._max_depth:
            raise SinkFull(f"override capture backlog at capacity ({self._max_depth})")
        self._events.append(event)

    def drain(self) -> list[OverrideCaptureEvent]:
        batch, self._events = self._events, []
        return batch
