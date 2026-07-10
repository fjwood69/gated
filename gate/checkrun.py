"""gate/checkrun.py — the SHA-bound Check Run lifecycle (Increment 2.2).

Posts a Check Run bound to the exact PR head SHA and drives it
``queued -> in_progress -> completed``. 2.2 does NOT *enforce* SHA-binding — GitHub
does (required status checks are keyed by head SHA; branch protection required-by-name
is 2.5). 2.2's obligation is to bind HONESTLY: always create/update the check for the
exact ``head_sha`` from the triggering event, and never leak a duplicate.

Idempotent create (the CRITICAL fix): a crash after ``POST /check-runs`` but before
persisting the id would, on GitHub's re-delivery, create a SECOND check run of the
same name on the same SHA. GitHub's Check Runs API is NOT queryable by ``external_id``
(write-only metadata), so the find is by (commit SHA, check name):

    GET /repos/{repo}/commits/{head_sha}/check-runs?check_name=<name>
      -> found  : PATCH that run
      -> absent : POST a new run (carrying external_id = "<head_sha>:<name>" for
                  audit/correlation only)

``reopened`` fires on the SAME head SHA; the find-then-PATCH path re-uses the existing
run rather than colliding — so the same mechanism covers crash-retry AND reopened.

The lifecycle logic is pure and transport-agnostic: it drives a ``GitHubCheckClient``
Protocol, tested against a fake. The real HTTPS + App-JWT client is a separate adapter.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from core import VerdictType


class CheckStatus(Enum):
    QUEUED = "queued"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


class CheckConclusion(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    ACTION_REQUIRED = "action_required"
    NEUTRAL = "neutral"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    STALE = "stale"
    SKIPPED = "skipped"


# Conclusions that BLOCK a required-by-name merge. Verified against GitHub Docs
# (docs.github.com "About status checks"): the ONLY passing conclusions are
# `success`, `skipped`, `neutral`; every other conclusion is non-passing and blocks a
# required check. So `action_required` DOES block (a board pass once claimed it was
# fail-open — primary source refutes that). A fail-closed verdict must never map to
# `neutral`/`skipped`.
BLOCKING_CONCLUSIONS = frozenset(
    {
        CheckConclusion.FAILURE,
        CheckConclusion.ACTION_REQUIRED,
        CheckConclusion.CANCELLED,
        CheckConclusion.TIMED_OUT,
        CheckConclusion.STALE,
    }
)

# Verdict -> GitHub conclusion. ERROR -> action_required (NOT failure): our ERROR means
# the engine/telemetry broke, not that the code is bad — a human/admin must act, and it
# blocks (fail-closed, H3 escalate-to-human). FAIL -> failure: the code is bad, the
# developer fixes it. PASS -> success.
_VERDICT_CONCLUSION = {
    VerdictType.PASS: CheckConclusion.SUCCESS,
    VerdictType.FAIL: CheckConclusion.FAILURE,
    VerdictType.ERROR: CheckConclusion.ACTION_REQUIRED,
}


def verdict_to_conclusion(verdict: VerdictType) -> CheckConclusion:
    conclusion = _VERDICT_CONCLUSION[verdict]
    # Standing guarantee: a non-PASS verdict must map to a BLOCKING conclusion
    # (fail-closed). Pinned here so a future edit can't silently open the gate.
    if verdict is not VerdictType.PASS:
        assert conclusion in BLOCKING_CONCLUSIONS  # noqa: S101 - invariant guard
    return conclusion


def external_id_for(head_sha: str, name: str) -> str:
    """Deterministic correlation id carried on the check run (audit/trace only — NOT a
    query key; GitHub cannot search by external_id)."""
    return f"{head_sha}:{name}"


@dataclass(frozen=True)
class CheckOutput:
    title: str
    summary: str


class CheckRunError(RuntimeError):
    """A Check Run API call failed — the caller treats it as fail-closed (do not record
    success; let the delivery be retried)."""


class GitHubCheckClient(Protocol):
    """The GitHub Checks API surface the lifecycle needs. The real implementation
    authenticates as the App installation (checks:write only); a fake backs the tests."""

    def find_check_run(self, *, repo_full_name: str, head_sha: str, name: str) -> str | None:
        """GET commits/{sha}/check-runs?check_name — the existing run id, or None.
        Raises CheckRunError on API failure (do NOT treat an error as 'absent' — that
        would defeat idempotency and create a duplicate)."""

    def create_check_run(
        self,
        *,
        repo_full_name: str,
        head_sha: str,
        name: str,
        status: CheckStatus,
        external_id: str,
        conclusion: CheckConclusion | None = None,
        output: CheckOutput | None = None,
    ) -> str: ...

    def update_check_run(
        self,
        *,
        repo_full_name: str,
        check_run_id: str,
        status: CheckStatus,
        conclusion: CheckConclusion | None = None,
        output: CheckOutput | None = None,
    ) -> None: ...


def upsert_check_run(
    client: GitHubCheckClient,
    *,
    repo_full_name: str,
    head_sha: str,
    name: str,
    status: CheckStatus,
    conclusion: CheckConclusion | None = None,
    output: CheckOutput | None = None,
) -> str:
    """Find-then-PATCH-or-POST — the idempotent create. Existing run for (sha, name) is
    re-used (covers crash-retry AND reopened); otherwise a fresh run is created bound to
    ``head_sha``. Returns the check_run_id."""
    existing = client.find_check_run(repo_full_name=repo_full_name, head_sha=head_sha, name=name)
    if existing is not None:
        client.update_check_run(
            repo_full_name=repo_full_name,
            check_run_id=existing,
            status=status,
            conclusion=conclusion,
            output=output,
        )
        return existing
    return client.create_check_run(
        repo_full_name=repo_full_name,
        head_sha=head_sha,
        name=name,
        status=status,
        external_id=external_id_for(head_sha, name),
        conclusion=conclusion,
        output=output,
    )


class CheckRunLifecycle:
    """Drives one PR head through queued -> in_progress -> completed, idempotently."""

    def __init__(self, client: GitHubCheckClient, *, name: str) -> None:
        self._client = client
        self._name = name

    def open_queued(self, *, repo_full_name: str, head_sha: str) -> str:
        """Announce jurisdiction: a pending check bound to head_sha (idempotent)."""
        return upsert_check_run(
            self._client,
            repo_full_name=repo_full_name,
            head_sha=head_sha,
            name=self._name,
            status=CheckStatus.QUEUED,
        )

    def mark_in_progress(self, *, repo_full_name: str, check_run_id: str) -> None:
        self._client.update_check_run(
            repo_full_name=repo_full_name,
            check_run_id=check_run_id,
            status=CheckStatus.IN_PROGRESS,
        )

    def complete(
        self,
        *,
        repo_full_name: str,
        check_run_id: str,
        verdict: VerdictType,
        summary: str,
    ) -> None:
        """Terminal transition: completed + the mapped (fail-closed) conclusion."""
        conclusion = verdict_to_conclusion(verdict)
        self._client.update_check_run(
            repo_full_name=repo_full_name,
            check_run_id=check_run_id,
            status=CheckStatus.COMPLETED,
            conclusion=conclusion,
            output=CheckOutput(title=self._name, summary=summary),
        )
