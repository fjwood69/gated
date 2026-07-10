"""gate/audit.py — rejection observability at the trust boundary.

A security boundary that rejects SILENTLY is blind exactly where it matters: an
attacker probing the endpoint (forged signatures, wrong-installation, replay) leaves
no trace. Every reject/error decision emits a structured ``RejectionEvent`` here — the
SOURCE of the audit trail. Full tamper-evident audit-export is an enterprise (B)
feature; the HOOK belongs at the boundary now, cheaply, so the trail has an origin.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Protocol

_log = logging.getLogger("gated.gate.audit")


@dataclass(frozen=True)
class RejectionEvent:
    reason: str
    status_code: int
    delivery_id: str | None
    source: str | None  # transport-supplied (e.g. client address); None from pure core


class AuditSink(Protocol):
    def record_rejection(self, event: RejectionEvent) -> None: ...


class LoggingAuditSink:
    """Reference sink: one structured WARNING per rejection. Deployment swaps this for
    a tamper-evident ledger backend implementing the same Protocol."""

    def record_rejection(self, event: RejectionEvent) -> None:
        _log.warning(
            "gate.reject reason=%s status=%d delivery=%s source=%s",
            event.reason,
            event.status_code,
            event.delivery_id,
            event.source,
        )


class NullAuditSink:
    """Drops rejection events — for tests that don't assert on the audit trail."""

    def record_rejection(self, event: RejectionEvent) -> None:
        return
