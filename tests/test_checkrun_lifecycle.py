"""Increment 2.2 — SHA-bound Check Run lifecycle + idempotent create.

Run from the gated/ root:  python3 -m unittest discover -s tests

Lifecycle correctness (NOT merge-gating — that's 2.5) proved against a fake GitHub
client that models the real (commit SHA, check name) find semantics:

  open PR             -> queued check appears bound to the head SHA
  in_progress -> completed with the mapped, fail-closed conclusion
  crash-retry (open twice on same SHA) -> re-uses the run, does NOT create a duplicate
  reopened (existing failing run on same SHA) -> re-used, not duplicated
  new commit (new SHA) -> a FRESH check on the new SHA (old one untouched)
  verdict mapping     -> PASS/FAIL/ERROR -> success/failure/action_required (all blocking
                         except success)
"""
from __future__ import annotations

import unittest

from core import VerdictType
from gate.checkrun import (
    BLOCKING_CONCLUSIONS,
    CheckConclusion,
    CheckRunLifecycle,
    CheckStatus,
    external_id_for,
    upsert_check_run,
    verdict_to_conclusion,
)

_NAME = "gated promotion gate"


class _FakeGitHub:
    """Models GitHub's Checks API keyed by (repo, sha, name) — one run per triple, as
    the find-by-commit-and-name query sees it. Records every op for assertions."""

    def __init__(self) -> None:
        self._runs: dict[tuple[str, str, str], str] = {}  # (repo, sha, name) -> id
        self.creates: list[tuple[str, str, str]] = []  # (repo, sha, external_id)
        self.updates: list[tuple[str, CheckStatus, CheckConclusion | None]] = []
        self._next = 0

    def find_check_run(self, *, repo_full_name: str, head_sha: str, name: str) -> str | None:
        return self._runs.get((repo_full_name, head_sha, name))

    def create_check_run(
        self, *, repo_full_name, head_sha, name, status, external_id, conclusion=None, output=None
    ) -> str:
        self._next += 1
        run_id = f"cr-{self._next}"
        self._runs[(repo_full_name, head_sha, name)] = run_id
        self.creates.append((repo_full_name, head_sha, external_id))
        return run_id

    def update_check_run(
        self, *, repo_full_name, check_run_id, status, conclusion=None, output=None
    ) -> None:
        self.updates.append((check_run_id, status, conclusion))

    # test helper: pre-seed an existing run (e.g. a prior failing run before reopened)
    def seed(self, *, repo_full_name: str, head_sha: str, name: str) -> str:
        self._next += 1
        run_id = f"seed-{self._next}"
        self._runs[(repo_full_name, head_sha, name)] = run_id
        return run_id


class MappingTests(unittest.TestCase):
    def test_verdict_conclusion_mapping(self) -> None:
        self.assertIs(verdict_to_conclusion(VerdictType.PASS), CheckConclusion.SUCCESS)
        self.assertIs(verdict_to_conclusion(VerdictType.FAIL), CheckConclusion.FAILURE)
        self.assertIs(verdict_to_conclusion(VerdictType.ERROR), CheckConclusion.ACTION_REQUIRED)

    def test_non_pass_always_blocks(self) -> None:
        # fail-closed: FAIL and ERROR must both map to blocking conclusions
        self.assertIn(verdict_to_conclusion(VerdictType.FAIL), BLOCKING_CONCLUSIONS)
        self.assertIn(verdict_to_conclusion(VerdictType.ERROR), BLOCKING_CONCLUSIONS)
        self.assertNotIn(verdict_to_conclusion(VerdictType.PASS), BLOCKING_CONCLUSIONS)

    def test_error_is_action_required_not_failure(self) -> None:
        # infra fault != bad code — the locus of responsibility differs
        self.assertIs(verdict_to_conclusion(VerdictType.ERROR), CheckConclusion.ACTION_REQUIRED)

    def test_external_id_scheme(self) -> None:
        self.assertEqual(external_id_for("abc123", _NAME), f"abc123:{_NAME}")


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gh = _FakeGitHub()
        self.lc = CheckRunLifecycle(self.gh, name=_NAME)
        self.repo = "acme/widgets"

    def test_open_queued_creates_bound_to_head_sha(self) -> None:
        cid = self.lc.open_queued(repo_full_name=self.repo, head_sha="a" * 40)
        self.assertEqual(len(self.gh.creates), 1)
        repo, sha, ext = self.gh.creates[0]
        self.assertEqual(sha, "a" * 40)
        self.assertEqual(ext, external_id_for("a" * 40, _NAME))  # correlation id carried
        self.assertTrue(cid)

    def test_full_lifecycle_pass(self) -> None:
        sha = "b" * 40
        cid = self.lc.open_queued(repo_full_name=self.repo, head_sha=sha)
        self.lc.mark_in_progress(repo_full_name=self.repo, check_run_id=cid)
        self.lc.complete(repo_full_name=self.repo, check_run_id=cid, verdict=VerdictType.PASS, summary="ok")
        statuses = [u[1] for u in self.gh.updates]
        self.assertEqual(statuses, [CheckStatus.IN_PROGRESS, CheckStatus.COMPLETED])
        self.assertIs(self.gh.updates[-1][2], CheckConclusion.SUCCESS)

    def test_complete_fail_maps_failure(self) -> None:
        sha = "c" * 40
        cid = self.lc.open_queued(repo_full_name=self.repo, head_sha=sha)
        self.lc.complete(repo_full_name=self.repo, check_run_id=cid, verdict=VerdictType.FAIL, summary="1 egress")
        self.assertIs(self.gh.updates[-1][2], CheckConclusion.FAILURE)

    def test_crash_retry_does_not_duplicate(self) -> None:
        # open twice on the same SHA (as a GitHub re-delivery would) -> find-then-PATCH,
        # exactly ONE create, second call re-uses the run.
        sha = "d" * 40
        first = self.lc.open_queued(repo_full_name=self.repo, head_sha=sha)
        second = self.lc.open_queued(repo_full_name=self.repo, head_sha=sha)
        self.assertEqual(first, second)
        self.assertEqual(len(self.gh.creates), 1)  # NOT duplicated

    def test_reopened_reuses_existing_run(self) -> None:
        # a prior (failing) run exists on this SHA; reopened must re-use it, not collide.
        sha = "e" * 40
        seeded = self.gh.seed(repo_full_name=self.repo, head_sha=sha, name=_NAME)
        cid = upsert_check_run(
            self.gh, repo_full_name=self.repo, head_sha=sha, name=_NAME, status=CheckStatus.QUEUED
        )
        self.assertEqual(cid, seeded)
        self.assertEqual(len(self.gh.creates), 0)  # re-used the seeded run
        self.assertEqual(len(self.gh.updates), 1)  # PATCHed it

    def test_new_sha_is_a_fresh_check(self) -> None:
        # a new commit (new SHA) gets its own check; the old one is untouched.
        old = self.lc.open_queued(repo_full_name=self.repo, head_sha="1" * 40)
        new = self.lc.open_queued(repo_full_name=self.repo, head_sha="2" * 40)
        self.assertNotEqual(old, new)
        self.assertEqual(len(self.gh.creates), 2)
        self.assertEqual({c[1] for c in self.gh.creates}, {"1" * 40, "2" * 40})


if __name__ == "__main__":
    unittest.main()
