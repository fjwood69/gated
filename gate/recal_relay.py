"""gate/recal_relay.py — 3.5 job-1: the outbox -> queue RELAY (at-least-once fan-out).

Bridges the transactional outbox (co-located in the fixture store, written atomically with each fixture
append) to the durable lease queue. For every undrained trigger it fans the set change out to the
ENABLED policies bound to that set and enqueues one re-calibration each; the deterministic ``job_id``
dedups, so multiple appends to a set before a relay collapse to ONE job per policy at the CURRENT head.

At-least-once: the entry is marked drained AFTER the enqueue commits, so a crash between enqueue and
mark simply re-delivers — and the queue's ``job_id`` dedup makes the re-delivery a no-op. This is the
tail of the transactional-outbox guarantee: the atomic append guarantees the trigger is never LOST; the
relay guarantees it is eventually DELIVERED.

Pure gate-side orchestration — reads the fixture store + policy store, writes the queue. No engine
import; ``core`` never imports this.
"""
from __future__ import annotations

from typing import Callable

from gate.calibration_store import CalibrationStore
from gate.policy_store import PolicyStore
from gate.recal_queue import RecalQueue
from gate.recalibration import deterministic_job_id


def relay_outbox(
    *,
    calibration_store: CalibrationStore,
    policy_store: PolicyStore,
    queue: RecalQueue,
    now: float,
    clock: Callable[[], float] | None = None,
) -> int:
    """Drain the fixture-store outbox into the re-cal queue. Returns the number of NEW jobs enqueued.

    Targets the CURRENT ``set_head`` (not the entry's append-time head), so all pending triggers for a
    set collapse to the current head — a policy is re-calibrated against reality, once, not once per
    intermediate append. ``tier_generation`` records the tier head at relay time (provenance; the
    restore CAS gates on the policy-evidence head, not this)."""
    enqueued = 0
    tier_generation = policy_store.head_hash()
    for entry in calibration_store.undrained_outbox():
        current_head = calibration_store.set_head(entry.set_id)
        for policy_id, detector_identity in policy_store.enabled_policies_for_set(entry.set_id):
            # the policy's stored identity IS the calibrated-subject identity (P1-3) — passed as the
            # dedup/routing key, never as signed authority.
            job_id = deterministic_job_id(
                policy_id=policy_id, set_id=entry.set_id, oracle_head=current_head,
                subject_identity=detector_identity,
            )
            if queue.enqueue(
                job_id=job_id, policy_id=policy_id, set_id=entry.set_id, oracle_head=current_head,
                detector_identity=detector_identity, tier_generation=tier_generation, now=now,
            ):
                enqueued += 1
        # AFTER the enqueue(s): mark drained. A crash here re-delivers; job_id dedup makes it safe.
        calibration_store.mark_outbox_drained(entry.id)
    return enqueued


__all__ = ["relay_outbox"]
