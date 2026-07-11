"""gate/recal_metrics.py — 3.5 job-1: the ZOMBIE metric (operational telemetry, never governance).

The board ratified the "zombie" posture: an ENABLED-but-transiently-UNATTESTABLE policy stays ENABLED
(a human governance decision) and stays BLOCKING (fail-closed) until a clean PASS re-attests it — a FAIL
never auto-degrades the tier (that would be measurement moving governance). The one hazard is a SILENT
stuck zombie: an ENABLED policy blocked forever because its re-calibration wedged. So the zombie MUST be
observable. This module is that observability — a PURE READ over the durable queue + live attestation
state. It computes, never mutates: it emits the `state=ENABLED ∧ unattestable_age>threshold` signal the
board made a hard requirement, and touches no tier.

A policy is a zombie iff it is currently ENABLED, its bound oracle head no longer equals the live
``set_head`` (so the gatekeeper is blocking it), and a re-calibration job for it is still unresolved
(PENDING/PROCESSING = in-flight; DEAD_LETTER = permanently stuck, the worst kind). The age is measured
from the job's ``enqueued_at`` — how long the merge has been blocked awaiting a fresh PASS.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from gate.policy_state import PolicyState
from gate.policy_store import PolicyStore
from gate.recal_queue import JobStatus, RecalQueue


@dataclass(frozen=True)
class Zombie:
    """An ENABLED-but-unattestable policy with an unresolved re-calibration. ``dead_lettered`` marks
    the permanently-stuck kind (re-cal burned its retries — needs human intervention)."""

    policy_id: str
    set_id: str
    age_seconds: float
    job_status: JobStatus
    dead_lettered: bool


def zombies(
    *,
    queue: RecalQueue,
    policy_store: PolicyStore,
    oracle_head_for: Callable[[str], str | None],
    now: float,
) -> list[Zombie]:
    """The current zombies: ENABLED policies the gatekeeper is blocking (bound head != live head) with
    an unresolved re-cal job. Pure read — computes from the durable queue + live attestation, mutates
    nothing. A job in DONE is excluded (its policy was restored); a PENDING/PROCESSING/DEAD_LETTER job
    whose policy is still ENABLED and still drifted is a zombie."""
    out: list[Zombie] = []
    for status in (JobStatus.PENDING, JobStatus.PROCESSING, JobStatus.DEAD_LETTER):
        for job in queue.jobs_with_status(status):
            if policy_store.current_state(job.policy_id) is not PolicyState.ENABLED:
                continue
            attestation = policy_store.current_attestation(job.policy_id)
            if attestation is None:
                continue
            bound_set_id, bound_head, _identity = attestation
            live_head = oracle_head_for(bound_set_id)
            if live_head is not None and live_head == bound_head:
                continue  # attestable again (a restore landed) — not a zombie
            out.append(Zombie(
                policy_id=job.policy_id, set_id=job.set_id, age_seconds=max(0.0, now - job.enqueued_at),
                job_status=status, dead_lettered=status is JobStatus.DEAD_LETTER,
            ))
    return out


def zombies_over_threshold(zs: list[Zombie], *, threshold_seconds: float) -> list[Zombie]:
    """The zombies breaching the age threshold — the `state=ENABLED ∧ unattestable_age>threshold`
    alert set the board required (plus every DEAD_LETTER, which is a zombie regardless of age)."""
    return [z for z in zs if z.dead_lettered or z.age_seconds > threshold_seconds]


__all__ = ["Zombie", "zombies", "zombies_over_threshold"]
