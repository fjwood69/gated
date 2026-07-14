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
from gate.recal_queue import RecalQueue, intent_candidate_job_id
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
    intermediate append. ``tier_generation`` is the POLICY-SCOPED head (``policy_head(policy_id)``),
    captured PER-POLICY (S3 restore-continuity): the restore CAS requires the signed generation to still
    equal this policy's head, refusing a measurement triggered under a generation a human DEMOTE->re-ratify
    later superseded. It is deliberately NOT the global ``head_hash()`` — a global head would spuriously
    fail restore whenever an UNRELATED policy transitioned between trigger and restore."""
    enqueued = 0
    for entry in calibration_store.undrained_outbox():
        current_head = calibration_store.set_head(entry.set_id)
        for policy_id, detector_identity in policy_store.enabled_policies_for_set(entry.set_id):
            # the policy's stored identity IS the calibrated-subject identity (P1-3) — passed as the
            # dedup/routing key, never as signed authority.
            tier_generation = policy_store.policy_head(policy_id)  # POLICY-scoped generation (per-policy)
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


DEFAULT_SET_CHURN_BOUND = 32
"""3.5 CP4 Slice C (board): the distinct-head advance budget before ``failed_churn`` — the ORACLE-MOVEMENT
budget only (the calibration-failure budget is ``RecalQueue.max_attempts``, ~3-5). Sized generously (a
churning set is expected) and configurable; a future refinement is to make it time-windowed/decaying so a
slow, indefinite append stream cannot eventually false-trigger a static bound."""


def relay_intents(
    *,
    policy_store: PolicyStore,
    calibration_store: CalibrationStore,
    queue: RecalQueue,
    now: float,
    churn_bound: int = DEFAULT_SET_CHURN_BOUND,
) -> int:
    """3.5 CP4 Slice C: the durable RECONCILER that connects a CALIBRATING policy's ``refresh_intent`` to the
    queue — the intent-side counterpart to ``relay_outbox`` (which is ENABLED-only, so a CALIBRATING policy is
    invisible to it). For every RECONCILABLE intent (pending / dispatched / failed_detector; ``failed_churn``
    is excluded — human recovery), compare its ``target_head`` to the CURRENT ``set_head``:

      * head UNCHANGED → enqueue a fenced ``'intent'`` candidate job (idempotent by the intent job-id).
      * head DRIFTED (distinct) → advance the fence to the current head FIRST — ``advance_intent`` for an
        active intent, ``reactivate_failed_detector`` for a failed_detector one (a distinct new head is the
        ONLY way a deterministic detector failure retries) — then enqueue at the NEW head. A raced advance
        (``no_op``) or an exhausted churn budget (``failed_churn``) enqueues nothing.

    Returns the number of NEW jobs enqueued. Idempotent + fenced: a re-run enqueues nothing for an unchanged
    intent (job-id dedup), and every head advance is a triple-CAS (no double-increment, no stale overwrite).
    The worker PREFLIGHTS the job's ``(policy_generation, target_revision, target_head)`` against the intent's
    CURRENT fence before doing work, so a job enqueued at a head the intent has since advanced past is stale."""
    enqueued = 0
    for intent in policy_store.intents_to_reconcile():
        policy_id = str(intent["policy_id"])
        set_id = str(intent["set_id"])
        seq = int(intent["seq"])
        status = str(intent["status"])
        pg, tr, th = str(intent["policy_generation"]), int(intent["target_revision"]), str(intent["target_head"])
        current_head = calibration_store.set_head(set_id)
        if current_head == th:
            # NO drift. Enqueue a candidate ONLY for an active intent with no candidate produced yet; a
            # ``failed_detector`` (deterministic failure at THIS head) and a ``satisfied`` (candidate awaiting
            # human ratify) do NOT re-enqueue at the same head — they wait for a DISTINCT new head.
            if status in ("pending", "dispatched"):
                if queue.enqueue(
                    job_id=intent_candidate_job_id(intent_seq=seq, policy_generation=pg, target_revision=tr,
                                                   target_head=th),
                    policy_id=policy_id, set_id=set_id, oracle_head=th,
                    detector_identity=str(intent["detector_id"]), tier_generation=pg, now=now,
                    kind="intent", intent_seq=seq, policy_generation=pg, target_revision=tr,
                ):
                    enqueued += 1
            continue
        # DISTINCT-head drift: advance/reactivate the fence to the current head FIRST (by status), then
        # enqueue at the new head. ``satisfied`` (stale candidate) and ``failed_detector`` (retry on a new
        # head) reactivate; an active intent advances in place.
        if status == "failed_detector":
            advanced = policy_store.reactivate_failed_detector(
                policy_id, expect_policy_generation=pg, expect_target_revision=tr, expect_target_head=th,
                new_target_head=current_head, churn_bound=churn_bound) == "reactivated"
        elif status == "satisfied":
            advanced = policy_store.reactivate_satisfied(
                policy_id, expect_policy_generation=pg, expect_target_revision=tr, expect_target_head=th,
                new_target_head=current_head, churn_bound=churn_bound) == "reactivated"
        else:  # pending / dispatched
            advanced = policy_store.advance_intent(
                policy_id, expect_policy_generation=pg, expect_target_revision=tr, expect_target_head=th,
                new_target_head=current_head, churn_bound=churn_bound) == "advanced"
        if not advanced:
            continue  # no_op (raced / not CALIBRATING) or failed_churn — nothing to enqueue
        fresh = policy_store.active_intent(policy_id)
        if fresh is None:
            continue  # superseded between the advance and the re-read — fail-closed, skip
        pg, tr, th = str(fresh["policy_generation"]), int(fresh["target_revision"]), str(fresh["target_head"])
        if queue.enqueue(
            job_id=intent_candidate_job_id(intent_seq=seq, policy_generation=pg, target_revision=tr,
                                           target_head=th),
            policy_id=policy_id, set_id=set_id, oracle_head=th,
            detector_identity=str(intent["detector_id"]), tier_generation=pg, now=now,
            kind="intent", intent_seq=seq, policy_generation=pg, target_revision=tr,
        ):
            enqueued += 1
    return enqueued


__all__ = ["relay_outbox", "relay_intents"]
