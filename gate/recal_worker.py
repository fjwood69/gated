"""gate/recal_worker.py — 3.5 S3-completion CP4 Slice C: the async re-calibration WORKER.

The consumer end of the CALIBRATING-liveness loop: it leases an ``'intent'`` job from the durable queue,
measures a candidate through the shared spine, and RESOLVES the intent — the async analogue of the
synchronous ``run_calibration`` enable path (it PERSISTS a pass + satisfies the intent; it does NOT sign a
measurement — that is the separate ``run_recalibration`` runner, and it does NOT enable — that is the human
``ratify_enable`` gate). It is NOT governance: a worker NEVER moves a policy to ``REJECTED``.

The ordering is the correctness spine (board + deep consult, 7-item checklist):

  lease(kind='intent') → re-read the intent by seq under the lock + preflight the FULL fence → seal + the
  three-way oracle check (sealed == job == intent for set_id / oracle_head, and job.policy_id ==
  intent.policy_id) BEFORE running → prepare (resolve once) + verify boot digests == intent.expected
  BEFORE calibrating → produce → recheck the LIVE head before satisfaction → renew (a failed renewal ABORTS
  with ZERO PolicyStore mutations) → the intent triple-CAS is the completion authority (post-renew races
  resolve through it) → complete the queue lease last.

Taxonomy (ratified): PASS → satisfy_intent_with_pass + complete. Clean deterministic FAIL →
``failed_detector`` + complete (the policy stays CALIBRATING; never worker-REJECTED). ERROR / unattested /
boot-digest mismatch / set-head drift (the intent is still ACTIVE at this fence) → RELEASE the lease for a
prompt re-lease with backoff (``attempts`` → dead-letter after ``max_attempts`` is the calibration-failure
budget) — NEVER complete, because completing (DONE) a job whose intent is still active would let the
deterministic job-id dedup STRAND the policy if the set head returns. Only a job that is genuinely OBSOLETE
— the intent ADVANCED past this fence, or is TERMINAL (satisfied/superseded/failed), or a matching SATISFIED
job — is completed (DONE) with NO work and NO mutation.
"""
from __future__ import annotations

import sqlite3
from enum import Enum
from typing import Callable

from core import ResourceBudget, Sandbox, VerdictType
from engine.calibration import DEFAULT_CALIBRATION_TRIALS, BackendGuard, BundleResolver
from engine.observation_trust import TrustPolicy
from gate.calibration_identity import calibration_result_ref
from gate.calibration_store import CalibrationStore
from gate.candidate_measurement import (
    PreparedCandidate,
    WitnessInconsistencyError,
    classify_measurement,
    prepare_candidate,
    produce_candidate_measurement,
)
from gate.detector_registry import DetectorResolutionError
from gate.policy_store import IntentSatisfyOutcome, PolicyStore
from gate.recal_queue import RecalQueue


class WorkerOutcome(Enum):
    """The disposition of one ``run_one`` — for observability + tests. Only ``SATISFIED`` and
    ``FAILED_DETECTOR`` mutate PolicyStore; ``RETRY`` / ``ABORTED_LEASE_LOST`` mutate NOTHING (fail-closed)."""

    IDLE = "idle"                              # nothing runnable to lease
    SATISFIED = "satisfied"                    # PASS -> satisfy_with_pass -> complete
    ALREADY_DONE = "already_done"              # a matching satisfied job -> complete, no measurement
    FAILED_DETECTOR = "failed_detector"        # clean deterministic FAIL -> failed_detector -> complete
    RETRY = "retry"                            # ERROR / boot mismatch / drift -> release (backoff), no complete
    STALE = "stale"                            # intent advanced-past / terminal -> complete (obsolete), no mutation
    ABORTED_LEASE_LOST = "aborted_lease_lost"  # renewal failed -> ZERO PolicyStore mutations


def _boot_digests_match(prepared: PreparedCandidate, intent: sqlite3.Row) -> bool:
    """Reject-before-calibrate (model-(b) worker check + thread-1 intent-expected bite): the boot-injected
    detector/trust/guard identities the run WILL use (captured once by prepare) must equal the digests the
    intent was ROUTED for. Positive-shape: each witness must be a NON-EMPTY str AND equal its expected — a
    None/empty witness (e.g. a digestless guard) is a mismatch, never a silent pass."""
    for witness, expected in (
        (prepared.profile_witness, intent["expected_profile_digest"]),
        (prepared.trust_witness, intent["expected_trust_policy_digest"]),
        (prepared.guard_witness, intent["expected_guard_policy_digest"]),
    ):
        if not (isinstance(witness, str) and witness) or witness != str(expected):
            return False
    return True


def run_one(
    *,
    queue: RecalQueue,
    policy_store: PolicyStore,
    calibration_store: CalibrationStore,
    resolve: BundleResolver,
    make_sandbox: Callable[[], Sandbox],
    trust_policy: TrustPolicy,
    backend_guard: BackendGuard,
    budget: ResourceBudget,
    lease_token: str,
    visibility_timeout: float,
    clock: Callable[[], float],
    retry_delay: float = 0.0,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
) -> WorkerOutcome:
    """Lease and process at most ONE intent candidate. Returns the disposition. Idempotent + fenced end to
    end: a crash at any point leaves the durable state recoverable (the queue redelivers; the intent CAS
    dedups), and no path records a pass for the wrong head or moves a policy to REJECTED.

    ``clock`` is read AT the lease AND re-read AFTER the (potentially long) measurement — renewal, completion
    and release use the FRESH time, not the lease-start time, so a renewal genuinely detects a lease that
    expired during calibration (a frozen timestamp would revive an expired lease and defeat the guarantee)."""
    if not (isinstance(lease_token, str) and lease_token):  # positive-shape: a lease token is an identity
        raise ValueError("lease_token must be a non-empty string")

    now = clock()  # lease timestamp — also used by the EARLY (pre-measurement) complete/release paths
    job = queue.lease(lease_token=lease_token, visibility_timeout=visibility_timeout, now=now, kind="intent")
    if job is None:
        return WorkerOutcome.IDLE

    def _complete_no_work(outcome: WorkerOutcome) -> WorkerOutcome:
        # complete (DONE) ONLY when the job is genuinely obsolete — the intent has ADVANCED past this fence
        # or is TERMINAL. Completing a job whose intent is still ACTIVE at this fence would let the
        # deterministic job-id dedup STRAND the policy if the set head ever returns to this head.
        queue.complete(job.job_id, lease_token=lease_token, now=now)
        return outcome

    def _retry() -> WorkerOutcome:
        # a RETRYABLE condition where the intent is STILL active at this fence (boot mismatch, unattested
        # ERROR, or a set-head drift the relay will resolve): RELEASE for a prompt re-lease with backoff
        # (bounded by the queue's max_attempts -> dead-letter), NEVER complete. If the lease already lapsed
        # (release token-CAS misses), another worker owns it — still RETRY, no harm.
        queue.release(job.job_id, lease_token=lease_token, now=now, delay=retry_delay)
        return WorkerOutcome.RETRY

    # PREFLIGHT: re-read the intent by its seq (NOT active_intent — that excludes satisfied) and compare the
    # job's enqueue-time fence to the intent's CURRENT fence. A cached job head is never the sole fence.
    intent = policy_store.intent_by_seq(job.intent_seq) if job.intent_seq is not None else None
    if intent is None:
        return _complete_no_work(WorkerOutcome.STALE)  # the intent vanished — nothing to do
    status = str(intent["status"])
    fence_matches = (
        job.policy_id == str(intent["policy_id"])
        and job.set_id == str(intent["set_id"])
        and job.policy_generation == (str(intent["policy_generation"]) if job.policy_generation is not None else None)
        and job.target_revision == int(intent["target_revision"])
        and job.oracle_head == str(intent["target_head"])
    )
    if status == "satisfied" and fence_matches:
        # #1 crash-redelivery at the door: a matching satisfied job is done — complete WITHOUT re-measuring.
        return _complete_no_work(WorkerOutcome.ALREADY_DONE)
    if status not in ("pending", "dispatched") or not fence_matches:
        # superseded / failed_* / advanced-past / satisfied-at-another-fence -> stale; complete, no work.
        return _complete_no_work(WorkerOutcome.STALE)

    # the intent's CURRENT fence == the job's (verified) — use it for the completion CAS.
    policy_id, set_id, detector_id = job.policy_id, str(intent["set_id"]), str(intent["detector_id"])
    pg, tr, th = str(intent["policy_generation"]), int(intent["target_revision"]), str(intent["target_head"])
    icv = int(intent["identity_contract_version"])

    # SEAL + three-way oracle check BEFORE running: the sealed head, the job head, and the intent target
    # head must all agree (and the sealed/job/intent set + the job/intent policy). A drift here means the set
    # moved since enqueue — the relay will re-enqueue at the new head; this job is stale.
    # the intent is STILL active at this fence here; a set-head mismatch means the set DRIFTED, not that the
    # job is obsolete (the relay will advance the intent). RELAY ORDERING INVARIANT (documented, enforced by
    # relay_intents): the relay advances ``intent.target_head`` no later than the set head moves, so a drift
    # here is transient — RETRY (release), never complete, else a set head that returns would strand the job.
    sealed = calibration_store.seal_set(set_id)
    if not (sealed.set_id == set_id == job.set_id and sealed.oracle_head == th == job.oracle_head):
        return _retry()

    # PREPARE (resolve once + capture witnesses), then VERIFY boot digests == intent.expected BEFORE
    # calibrating. A resolution failure or a boot mismatch is a retryable operational condition — RELEASE
    # (leave the intent dispatched), so the queue re-leases (bounded by max_attempts -> dead-letter).
    try:
        prepared = prepare_candidate(sealed, resolve=resolve, detector_id=detector_id,
                                     trust_policy=trust_policy, backend_guard=backend_guard)
    except DetectorResolutionError:
        return _retry()
    if not _boot_digests_match(prepared, intent):
        return _retry()
    try:
        measurement = produce_candidate_measurement(
            prepared, make_sandbox=make_sandbox, budget=budget, backend_guard=backend_guard,
            trust_policy=trust_policy, trials=trials)
    except WitnessInconsistencyError:
        return _retry()  # a mid-run boot-object mutation — retry operationally

    # REFRESH the clock: calibration may have taken real time, so renewal / completion / release from here on
    # use the CURRENT time, not the lease-start time — a renewal must genuinely detect a lease that expired
    # during the run. (The nested _retry / _complete_no_work read this ``now`` by closure, so they pick it up.)
    now = clock()

    # RECHECK the LIVE head before satisfaction: if the set drifted DURING calibration, the sealed head is
    # stale — don't record a pass we already know is superseded; the intent is still active, so RETRY (the
    # relay re-enqueues at the new head). This external read is an OPTIMISATION, not the authority — the
    # satisfy triple-CAS on the intent is what actually fences a wrong-head pass.
    if calibration_store.set_head(set_id) != sealed.oracle_head:
        return _retry()

    # CLASSIFY via the SHARED authority-free classifier (identical to the signed runner). A harness ERROR can
    # leave the four coordinates measurable (a non-null subject), so ``subject is None`` alone would WRONGLY
    # terminalize it as failed_detector — classify_measurement checks harness_errors/inadequate/inconsistent
    # explicitly. ERROR -> RETRY (never a deterministic failure); PASS -> satisfy; FAIL -> failed_detector.
    kind = classify_measurement(measurement)
    if kind is VerdictType.ERROR:
        return _retry()

    # RENEW before ANY durable mutation (PASS satisfy OR clean-FAIL failed_detector). A failed renewal means
    # exclusivity was lost (the lease lapsed and may have been re-leased) — ABORT with ZERO PolicyStore
    # mutations; a re-leased worker redoes it, and the intent CAS makes that safe.
    if not queue.renew(job.job_id, lease_token=lease_token, visibility_timeout=visibility_timeout, now=now):
        return WorkerOutcome.ABORTED_LEASE_LOST

    if kind is VerdictType.PASS:
        subject = measurement.subject_identity
        assert subject is not None  # classify_measurement PASS guarantees the four coordinates + subject
        ref = calibration_result_ref(
            policy_id, sealed.oracle_head, subject, passed=True,
            n_bad=len(measurement.result.outcomes),
            fixture_ids=[o.fixture_id for o in measurement.result.outcomes])
        outcome = policy_store.satisfy_intent_with_pass(
            policy_id, policy_generation=pg, target_revision=tr, target_head=th,
            calibration_result_ref=ref, pinned_set_version=sealed.oracle_head, detector_identity=subject,
            identity_contract_version=icv, set_id=set_id)
        if outcome is IntentSatisfyOutcome.STALE:
            # a concurrent advance moved the fence between renew and the CAS — the CAS is the authority, no
            # wrong pass was recorded; complete the (now-stale) job, no work.
            return _complete_no_work(WorkerOutcome.STALE)
        return _complete_no_work(WorkerOutcome.SATISFIED)  # SATISFIED or idempotent ALREADY_SATISFIED

    # VerdictType.FAIL — an ATTESTED deterministic miss / false-positive / flake -> failed_detector (policy
    # stays CALIBRATING; NEVER worker-REJECTED). The CAS fences the fence: a miss means the intent advanced.
    if policy_store.mark_intent_failed_detector(policy_id, policy_generation=pg, target_revision=tr,
                                                target_head=th):
        return _complete_no_work(WorkerOutcome.FAILED_DETECTOR)
    return _complete_no_work(WorkerOutcome.STALE)


__all__ = ["WorkerOutcome", "run_one"]
