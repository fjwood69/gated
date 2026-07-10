"""gate/dedup.py — the delivery-id replay SEAM.

GitHub stamps every delivery with a unique ``X-GitHub-Delivery`` UUID and
LEGITIMATELY re-delivers on failure. So the correct shape is IDEMPOTENCY, not
rejection (board ruling): a re-delivered id must be safely re-processable —
same id -> same outcome, no double-effect (no second queued Check Run) — rather
than treated as an attack.

For 2.1 this is replay-AWARENESS: an in-memory log detects a repeat within the
process. The PERSISTENT backend (survives restart; the real anti-replay + the
"never drop a synchronize" guarantee) lands in 2.2 behind this same Protocol.
"""
from __future__ import annotations

from typing import Protocol


class DeliveryLog(Protocol):
    """Tracks which delivery-ids have already been fully handled."""

    def seen(self, delivery_id: str) -> bool: ...

    def record(self, delivery_id: str) -> None:
        """Mark a delivery-id as fully handled. Called only AFTER the handling
        side-effect (the synchronous queued Check Run) has succeeded, so a crash
        mid-handling leaves the id UN-recorded and GitHub's re-delivery re-runs it
        — fail-closed against a dropped synchronize leaving a PR stuck pending."""


class InMemoryDeliveryLog:
    """Reference backend: a process-local set. Lost on restart — replaced by a
    persistent (SQLite) backend in 2.2."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def seen(self, delivery_id: str) -> bool:
        return delivery_id in self._seen

    def record(self, delivery_id: str) -> None:
        self._seen.add(delivery_id)
