"""gate/admission.py — 3.4: the fixture ADMISSION GATE. The true floor of the calibration oracle.

An oracle is only as trustworthy as the discipline of what enters it. If an unvalidated LLM
proposal or an auto-persisted C3 override can reach the fixture store, the calibration chain becomes
a formally-correct proof of a false thing. This module is the one, human-gated, dual-controlled path
by which a CANDIDATE (from the low-privilege candidate log) becomes a FIXTURE (in the calibration
store). Closed by CONSTRUCTION, verified by structural-absence tests:

  * PROPOSE and PERSIST are separate ops in separate stores. ``admit`` is the ONLY promotion path,
    and it requires a ``GovernanceApproval`` with TWO DISTINCT principals — an LLM role, or any
    single principal, cannot satisfy it. There is NO batch method and NO timeout auto-promotion.
  * Pre-persistence VALIDATION: a candidate is dry-run before it can be admitted. A fixture that
    does not execute cleanly (crashes / times out / ERRORs the observer) is REFUSED — a malformed
    known-good would otherwise wedge a whole policy's calibration, and a malformed known-bad is a
    fail-closed DoS on the pipeline. This checks EXECUTABILITY only. It deliberately does NOT judge
    the label by the detector's verdict: a known-bad that the current detector PASSES is normally
    the DISCOVERED EVASION we are capturing (the detector is the thing being calibrated — it cannot
    define ground truth for the fixtures that calibrate it). Ground truth is the human's dual
    attestation, not the detector's behaviour.
  * C3 -> known_good is CANDIDATE-ONLY: ``emit_c3_triage_candidate`` writes to the candidate log
    only; it has no reference to the calibration store, so a C3 event structurally cannot become a
    fixture write. A human ``admit``s it, binding the exact system-computed MERGED-TREE hash (never
    a PR-tree, which can carry a malicious subset the merge did not take).

The dry-run is INJECTED (a ``Validator``) rather than hardwired to the engine — the gate owns the
governance decision; the engine owns execution (gate MAY import engine, but the seam keeps the
admission LOGIC testable without a real sandbox, mirroring the calibrator's ``make_sandbox`` factory).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from core import VerdictType
from core.calibration import FixtureLabel
from gate.authority import GovernanceApproval
from gate.calibration_store import CalibrationStore, ChangeOp
from gate.candidate_store import Candidate, CandidateKind, CandidateSource, CandidateStore
from gate.snapshot_refresh import commit_fixture_append

# The distinct-principal count admitting a fixture requires. Admitting is high-stakes (a known-bad
# can block merges; a known-good can mask a true positive) — dual control, not a low-friction add.
_REQUIRED_PRINCIPALS = 2


class AdmissionError(PermissionError):
    """A candidate could not be admitted — insufficient approval, does not execute cleanly, an
    unacknowledged mislabel, or (known_good) a missing/invalid merged-tree hash."""


@dataclass(frozen=True)
class AdmissionCheck:
    """The result of dry-running a candidate before persistence."""

    executes_cleanly: bool                 # produced a deterministic PASS/FAIL, not ERROR/crash
    baseline_verdict: VerdictType | None    # the baseline detector's verdict (None if unclean)
    detail: str = ""


# validator(payload) -> AdmissionCheck: dry-run the candidate in a hermetic sandbox against a
# baseline detector. The production validator wires engine.run_check; tests inject a fake.
Validator = Callable[[bytes], AdmissionCheck]

_CHANGE_OP = {
    CandidateKind.KNOWN_BAD: ChangeOp.ADD_KNOWN_BAD,
    CandidateKind.KNOWN_GOOD: ChangeOp.ADD_KNOWN_GOOD,
}
_LABEL = {
    CandidateKind.KNOWN_BAD: FixtureLabel.KNOWN_BAD,
    CandidateKind.KNOWN_GOOD: FixtureLabel.KNOWN_GOOD,
}


def _is_canonical_tree_hash(h: str | None) -> bool:
    """A system-computed merged-tree hash is a 64-hex digest. This rejects blanks and obviously
    non-canonical values; the LIVE guarantee (it is the MERGE tree, not the PR tree) is the trusted
    system's to compute — the human confirms it, never types it."""
    if h is None:
        return False
    return len(h) == 64 and all(c in "0123456789abcdef" for c in h.lower())


# revoke_fallback(set_id) -> None: SYNCHRONOUSLY revoke the fallback snapshot's attestations for the
# set BEFORE the fixture lands (close-4). Production wires ``invalidate_fallback_for_set(path, set_id,
# key)``; it is a no-op when no snapshot exists yet. REQUIRED — the safe append is not optional.
FallbackRevoker = Callable[[str], None]


def admit(
    candidate: Candidate,
    *,
    approval: GovernanceApproval,
    validator: Validator,
    calibration_store: CalibrationStore,
    revoke_fallback: FallbackRevoker,
    set_id: str = "default",
) -> int:
    """Promote a candidate to a FIXTURE — the one, dual-controlled, validated, SAFE path. Raises
    ``AdmissionError`` unless: the approval carries two distinct principals; the candidate executes
    cleanly (deterministic PASS/FAIL, not ERROR/crash); a known-good carries a canonical
    system-computed merged-tree hash. On success, lands the fixture via the MANDATORY safe append and
    returns the fixture seq.

    Board blocker #5 (safe append is mandatory, not optional): admission is the normal path a fixture
    enters the oracle, so it MUST carry the close-4 orchestration — the fixture append is committed
    through ``commit_fixture_append``: the fallback snapshot for ``set_id`` is durably REVOKED first,
    then the fixture lands ATOMICALLY with its re-calibration outbox trigger (``outbox_set_id``). Without
    this, admitting a known-bad would move the oracle head while (a) a stale fallback snapshot could
    still enforce the pre-append head during an outage, and (b) no re-calibration is ever enqueued, so
    every bound policy is wedged UNATTESTABLE forever. ``revoke_fallback`` is REQUIRED so the caller
    cannot silently skip the revocation.

    The dry-run checks EXECUTABILITY only — it does NOT gate on the detector's verdict-vs-label,
    because a known-bad that the current detector PASSES is normally the discovered evasion, and the
    detector cannot define ground truth for its own calibration fixtures. There is deliberately no
    batch/auto-promote path: one candidate, one dual approval, one dry-run."""
    if not approval.meets(_REQUIRED_PRINCIPALS):
        raise AdmissionError(
            f"admission requires {_REQUIRED_PRINCIPALS} distinct governance principals + "
            "purpose/rationale/operation_id — proposal is unprivileged, PERSISTENCE is dual-gated"
        )

    check = validator(candidate.payload)
    if not check.executes_cleanly or check.baseline_verdict is VerdictType.ERROR:
        raise AdmissionError(
            f"fixture rejected: does not execute cleanly in the sandbox ({check.detail or 'ERROR'})"
        )

    if candidate.kind is CandidateKind.KNOWN_GOOD and not _is_canonical_tree_hash(
        candidate.merged_tree_hash
    ):
        raise AdmissionError(
            "known-good admission requires a canonical system-computed merged-tree hash "
            "(64-hex) — reject PR-tree hashes; the human confirms the computed hash, never types it"
        )

    provenance = (
        f"admitted from candidate {candidate.candidate_id} (source={candidate.source.value}"
        + (f", merged_tree={candidate.merged_tree_hash}" if candidate.merged_tree_hash else "")
        + (f", c3_override={candidate.c3_override_ref}" if candidate.c3_override_ref else "")
        + ")"
    )

    def _append() -> int:
        return calibration_store.append(
            _CHANGE_OP[candidate.kind],
            approval=approval,
            fixture_id=candidate.candidate_id,
            label=_LABEL[candidate.kind],
            payload=candidate.payload,
            evasion_class=candidate.evasion_class,
            reason=provenance,
            set_id=set_id,
            outbox_set_id=set_id,  # atomic re-calibration trigger for the policies bound to this set
        )

    # revoke-and-fsync the fallback FIRST, then the atomic {append + outbox} — board amendment 4.
    return commit_fixture_append(invalidate=lambda: revoke_fallback(set_id), append=_append)


def emit_c3_triage_candidate(
    candidate_store: CandidateStore,
    *,
    c3_override_ref: str,
    payload: bytes,
    merged_tree_hash: str,
    proposed_by: str | None = None,
) -> str:
    """Surface a C3 false-positive override as a READ-ONLY known-good CANDIDATE. Writes ONLY to the
    candidate log — this function has no calibration-store reference, so a C3 event structurally
    cannot become a fixture write (a human must ``admit`` it). Returns the candidate_id."""
    candidate = Candidate(
        candidate_id=f"c3-{c3_override_ref}",
        kind=CandidateKind.KNOWN_GOOD,
        payload=payload,
        source=CandidateSource.C3_TRIAGE,
        proposed_by=proposed_by,
        c3_override_ref=c3_override_ref,
        merged_tree_hash=merged_tree_hash,
    )
    return candidate_store.propose(candidate)


__all__ = [
    "AdmissionError",
    "AdmissionCheck",
    "Validator",
    "admit",
    "emit_c3_triage_candidate",
]
