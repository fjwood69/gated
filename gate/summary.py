"""gate/summary.py — the human-readable Check Run summary (2.4), OUT-OF-BAND ONLY.

The text a developer reads in the GitHub UI is rendered STRICTLY from the typed
``Verdict`` (whose ``Reason`` is derived from the engine's out-of-band ``ExecutionResult``
— egress count, exit code — never from anything the artifact wrote). This carries the
"verdict depends only on out-of-band observation" invariant all the way into the
human-facing text: an adversarial artifact that prints "VERIFICATION SUCCESSFUL" to
stdout gets ZERO voice in its own trial, because this function is not even given the
container logs — only the ``Verdict``.
"""
from __future__ import annotations

from core import Reason, Verdict, VerdictType

from .checkrun import CheckOutput

_VERB = {
    VerdictType.PASS: "PASSED",
    VerdictType.FAIL: "FAILED",
    VerdictType.ERROR: "ERRORED",
}

# Each phrase describes the OUT-OF-BAND observation the verdict rests on.
_REASON_PHRASE = {
    Reason.EGRESS_GE_2: "2 or more egress attempts observed — retried after a transient failure",
    Reason.EGRESS_ONE: "1 egress attempt observed, expected 2 or more — gave up after one try",
    Reason.EGRESS_ZERO: "0 egress attempts observed, expected 2 or more — never attempted",
    Reason.UNANIMOUS_PASS: "all trials passed",
    Reason.NON_DETERMINISTIC: "flaky — trials disagreed (some passed, some failed)",
    Reason.TELEMETRY_MISSING: "boundary telemetry missing — the check could not be observed",
    Reason.SANDBOX_START_FAILED: "the sandbox could not start the artifact — nothing ran, and nothing was measured",
    Reason.TELEMETRY_NOT_OBSERVED: "this backend has no boundary observer — nothing was measured",
    Reason.TELEMETRY_UNREADABLE: "the boundary observer ran, but its count could not be read",
    Reason.OBSERVATION_INCOMPLETE: "observation incomplete — a trial could not be observed",
    Reason.ARTIFACT_INTEGRITY_MISMATCH: "the mounted tree did NOT match its verified hash",
    Reason.IMAGE_UNRESOLVED: "the sandbox image digest could not be resolved before run",
    Reason.DETECTOR_UNRESOLVED: "the enforced detector is unregistered or drifted from the accepted one",
    Reason.RUN_UNADMITTED: "the run could not be admitted under the authorized identity — measured "
                           "subject drift, an absent coordinate, or a stale authorization",
}


def _provenance_line(detector_id: str | None, image_digest: str | None) -> str:
    """3.5-close #1.5: a non-repudiation line recording WHICH detector + WHICH image produced this
    verdict, on the EXISTING merge-blocking Check Run path (not a new heavy signed local receipt). This
    binds {detector, image} to the verdict at the platform boundary; it is IDENTITY provenance, not
    runtime-behaviour assurance (the unattested-TCB ceiling still applies — see ARCHITECTURE.md)."""
    if not detector_id and not image_digest:
        return ""
    return f" [detector={detector_id or '?'} image={image_digest or '?'}]"


def render_check_summary(
    verdict: Verdict, check_name: str, *,
    detector_id: str | None = None, image_digest: str | None = None,
) -> CheckOutput:
    """Compose the Check Run title + summary from the typed ``Verdict`` alone (plus, for non-repudiation,
    the ATTESTED ``detector_id`` + ``image_digest`` — 3.5-close #1.5 — which are engine-measured identity,
    never artifact output). Never accepts (and so can never render) artifact-written output — the
    anti-spoofing guarantee is structural, not a discipline to remember."""
    verb = _VERB[verdict.status]
    phrase = _REASON_PHRASE.get(verdict.reason, verdict.reason.value)
    prov = _provenance_line(detector_id, image_digest)
    if verdict.reason is Reason.ARTIFACT_INTEGRITY_MISMATCH:
        # A hash mismatch blocks like any ERROR, but it is a distinct SECURITY event
        # (the exact TOCTOU tamper the SHA-bind exists to catch) — the audit must SCREAM,
        # not read as a routine "re-run the flaky check" glitch.
        return CheckOutput(
            title=f"{check_name}: SECURITY — ARTIFACT INTEGRITY MISMATCH",
            summary=(
                f"{check_name} BLOCKED — {phrase} (possible payload tampering / TOCTOU). "
                "This is a security event, not an infrastructure flake: the tree that was "
                "hashed is not the tree that was mounted. Merge blocked; security review "
                f"required before any re-run.{prov}"
            ),
        )
    title = f"{check_name}: {verb}"
    if verdict.status is VerdictType.ERROR:
        summary = (
            f"{check_name} {verb} — {phrase}. Verification could not complete; "
            f"a human must review (the merge is blocked, not passed).{prov}"
        )
    else:
        summary = f"{check_name} {verb} — {phrase}.{prov}"
    return CheckOutput(title=title, summary=summary)
