#!/usr/bin/env python3
"""The process gate, tested offline: every rule in ``scripts/dissent_gate.py``'s pure ``evaluate``.

⚠ THE LIVE BEHAVIOUR IS NOT TESTED HERE, AND THAT IS STATED RATHER THAN IMPLIED. Whether GitHub attaches a
``pull_request_target`` check to the PR head, whether an ``edited`` re-run resolves a required check,
what happens when a PR adds a same-named job, where an admin bypass is logged, and whether a hosted
runner can read the board — those are measured on a scratch repository before the gate is made
required (M1-M5), not asserted by this file. A green run here says the RULES are right, not that the
PLATFORM behaves as the rules assume.
"""
from __future__ import annotations

import json
import re
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

import dissent_gate as G  # noqa: E402

HEAD = "a" * 40
OLD = "b" * 40
OTHER = "c" * 40
KEY = "gated-p10b-dissent-head"
PRIOR_KEY = "gated-p10b-dissent-prior"


def _dissent(head: str, prior: str | None = None, **extra: object) -> dict:
    """The board Worker's envelope around the canonical dissent object."""
    value: dict = {"kind": "dissent", "head": head, **extra}
    if prior is not None:
        value["prior"] = prior
    return {"key": "k", "updated_at": "2026-09-26T00:00:00Z", "value": {"value": value}}


class _Board:
    """A fake board that records every key it is asked for."""

    def __init__(self, entries: dict | None = None, fail: bool = False):
        self.entries = entries or {}
        self.fail = fail
        self.asked: list[str] = []

    def __call__(self, key: str) -> object:
        self.asked.append(key)
        if self.fail:
            raise G.InstrumentError("board returned HTTP 503")
        return self.entries.get(key, G.ABSENT)


def _run(body: str | None, *, head: str = HEAD, same_repo: bool = True, paths: list[str] | None = None,
         ancestor: bool | Exception = True, board: _Board | None = None,
         files_fail: bool = False) -> G.Verdict:
    board = board if board is not None else _Board({KEY: _dissent(HEAD)})

    def changed() -> list[str]:
        if files_fail:
            raise G.InstrumentError("PR files returned HTTP 502")
        return paths if paths is not None else ["scripts/x.py"]

    def is_anc(old: str, new: str) -> bool:
        if isinstance(ancestor, Exception):
            raise ancestor
        return ancestor

    return G.evaluate(body, head, same_repo=same_repo, changed_paths=changed,
                      is_ancestor=is_anc, fetch_entry=board)


def _ref(head: str = HEAD, board: str = KEY, prior: str | None = None) -> str:
    return f"Dissent-Ref: board={board} head={head}" + (f" prior={prior}" if prior else "")


class TheCorrelatedPositive(unittest.TestCase):
    def test_a_matching_reference_to_a_dissent_on_THIS_head_PASSES(self):
        """⚠ WITHOUT THIS, a gate that rejected everything would pass every red test below."""
        v = _run(f"Some description.\n\n{_ref()}\n")
        self.assertTrue(v.passed, G.render(v))
        self.assertIn("PASS", G.render(v))

    def test_an_incremental_reference_with_a_valid_prior_chain_PASSES(self):
        board = _Board({KEY: _dissent(HEAD, prior=f"{PRIOR_KEY}@{OLD}"), PRIOR_KEY: _dissent(OLD)})
        v = _run(_ref(prior=f"{PRIOR_KEY}@{OLD}"), board=board)
        self.assertTrue(v.passed, G.render(v))
        self.assertEqual(board.asked, [KEY, PRIOR_KEY])


class G1_HeadEquality(unittest.TestCase):
    def test_ONE_MORE_COMMIT_after_the_dissent_is_RED_naming_BOTH_shas(self):
        """#49 exactly: the dissent was on an earlier commit, then more commits landed."""
        v = _run(_ref(head=OLD), board=_Board({KEY: _dissent(OLD)}))
        self.assertIn(G.HEAD_MISMATCH, v.codes)
        msg = dict(v.failures)[G.HEAD_MISMATCH]
        self.assertIn(OLD, msg)
        self.assertIn(HEAD, msg)

    def test_a_NEAR_MISS_sha_sharing_a_long_prefix_is_still_a_mismatch(self):
        """Red-proof survivor D1: the test above used SHAs differing in the FIRST character, so a
        prefix comparison passed it too. Equality has to be pinned where a prefix would agree."""
        # Near misses at BOTH ends (ways-of-working §5.5): only the last character differs, and only the first.
        for near in (HEAD[:39] + "b", "b" + HEAD[1:]):
            with self.subTest(near=near[:3] + "…" + near[-3:]):
                self.assertEqual(sum(x != y for x, y in zip(near, HEAD)), 1, "stimulus control: one char")
                v = _run(_ref(head=near), board=_Board({KEY: _dissent(near)}))
                self.assertIn(G.HEAD_MISMATCH, v.codes)


class G2_EveryFailureIsRedAndDistinct(unittest.TestCase):
    def test_MISSING(self):
        self.assertEqual(_run("no reference here").codes, [G.MISSING])
        self.assertEqual(_run(None).codes, [G.MISSING])

    def test_MALFORMED_cases_each_say_WHICH_rule(self):
        cases = {
            "short sha": (f"Dissent-Ref: board={KEY} head={'a' * 12}", "does not match"),
            "uppercase sha": (f"Dissent-Ref: board={KEY} head={'A' * 40}", "does not match"),
            "url for a key": (f"Dissent-Ref: board=https://example.test/state/{KEY} head={HEAD}", "is a URL"),
            "two lines": (_ref() + "\n" + _ref(), "exactly one is allowed"),
            "bad key characters": (f"Dissent-Ref: board=Bad_Key head={HEAD}", "does not match"),
        }
        seen = set()
        for label, (body, fragment) in cases.items():
            with self.subTest(case=label):
                v = _run(body)
                self.assertEqual(v.codes, [G.MALFORMED])
                self.assertIn(fragment, dict(v.failures)[G.MALFORMED])
                seen.add(fragment)
        self.assertEqual(len(seen), 3, "three distinct MALFORMED rules, each with its own message")

    def test_a_reference_INDENTED_or_INSIDE_A_FENCE_is_not_a_reference(self):
        """A body documenting the format must not count as carrying it."""
        self.assertEqual(_run("  " + _ref()).codes, [G.MISSING])
        self.assertEqual(_run("```\n" + _ref() + "\n```\n").codes, [G.MISSING])
        v = _run("```\n" + _ref(head=OTHER) + "\n```\n" + _ref())
        self.assertTrue(v.passed, "a fenced example alongside the real line must not make it ambiguous")

    def test_an_INSTRUMENT_failure_is_NEVER_a_pass(self):
        """Every probe: board, ancestry, file list. An unanswered question is not a 'no'."""
        cases = {
            "board unreachable": dict(board=_Board(fail=True)),
            "ancestry unreachable": dict(ancestor=G.InstrumentError("compare returned HTTP 502")),
            "file list unreachable": dict(files_fail=True),
        }
        for label, kw in cases.items():
            with self.subTest(case=label):
                body = _ref(prior=f"{PRIOR_KEY}@{OLD}") if "ancestry" in label else _ref()
                v = _run(body, **kw)
                self.assertFalse(v.passed)
                self.assertIn(G.INSTRUMENT, v.codes)

    def test_EVERY_code_is_reported_not_just_the_first(self):
        v = _run(_ref(head=OLD), paths=[".github/workflows/ci.yml"], board=_Board())
        self.assertEqual(set(v.codes), {G.WORKFLOW_TOUCHED, G.HEAD_MISMATCH, G.BOARD_ENTRY_MISSING})

    def test_the_code_set_is_DISTINCT(self):
        self.assertEqual(len(set(G.ALL_CODES)), len(G.ALL_CODES))


class G5_TheBoardEntryIsATypedDissent(unittest.TestCase):
    """Ruled T, 2026-09-26. The entry must BE a dissent on this head — not merely mention it."""

    def test_an_absent_entry_is_BOARD_ENTRY_MISSING(self):
        self.assertEqual(_run(_ref(), board=_Board()).codes, [G.BOARD_ENTRY_MISSING])

    def test_a_PROSE_entry_NAMING_THE_HEAD_is_NOT_a_dissent(self):
        """⚠ THE FINDING THIS RULING EXISTS FOR. The ordinary workflow writes 'built, awaiting dissent @
        <sha>' before any dissent. A substring check would pass #49 without anyone stating anything false.
        The prose below CONTAINS the head SHA — and must still red, because prose is never searched."""
        prose = {"key": "k", "updated_at": "t", "value": {"value": f"built, awaiting dissent @ {HEAD}"}}
        self.assertIn(HEAD, json.dumps(prose), "stimulus control: the prose must contain the head")
        v = _run(_ref(), board=_Board({KEY: prose}))
        self.assertEqual(v.codes, [G.BOARD_NOT_A_DISSENT])
        self.assertIn("untyped", dict(v.failures)[G.BOARD_NOT_A_DISSENT])

    def test_the_wrong_KIND_is_not_a_dissent(self):
        entry = _dissent(HEAD)
        entry["value"]["value"]["kind"] = "build"
        self.assertEqual(_run(_ref(), board=_Board({KEY: entry})).codes, [G.BOARD_NOT_A_DISSENT])

    def test_head_is_compared_by_EQUALITY_never_substring(self):
        for near in (HEAD + "0", HEAD[:39], "x" + HEAD, HEAD[:39] + "b", "b" + HEAD[1:]):
            with self.subTest(head=near):
                self.assertEqual(_run(_ref(), board=_Board({KEY: _dissent(near)})).codes,
                                 [G.BOARD_NOT_A_DISSENT])

    def test_a_JSON_STRING_that_parses_to_a_dissent_is_accepted(self):
        """Tolerated on read; never produced by a writer (ways-of-working §3)."""
        entry = {"key": "k", "updated_at": "t", "value": {"value": json.dumps({"kind": "dissent", "head": HEAD})}}
        self.assertTrue(_run(_ref(), board=_Board({KEY: entry})).passed)

    def test_a_response_WITHOUT_THE_ENVELOPE_is_not_a_dissent(self):
        self.assertEqual(_run(_ref(), board=_Board({KEY: {"kind": "dissent", "head": HEAD}})).codes,
                         [G.BOARD_NOT_A_DISSENT])


class G6_MovedHead(unittest.TestCase):
    def test_a_prior_that_is_NOT_AN_ANCESTOR_is_red(self):
        board = _Board({KEY: _dissent(HEAD, prior=f"{PRIOR_KEY}@{OLD}"), PRIOR_KEY: _dissent(OLD)})
        v = _run(_ref(prior=f"{PRIOR_KEY}@{OLD}"), ancestor=False, board=board)
        self.assertEqual(v.codes, [G.PRIOR_NOT_ANCESTOR])

    def test_the_PRIOR_entry_must_itself_be_a_dissent_on_the_prior_head(self):
        board = _Board({KEY: _dissent(HEAD, prior=f"{PRIOR_KEY}@{OLD}"), PRIOR_KEY: _dissent(OTHER)})
        v = _run(_ref(prior=f"{PRIOR_KEY}@{OLD}"), board=board)
        self.assertEqual(v.codes, [G.BOARD_NOT_A_DISSENT])
        self.assertIn("the prior entry", dict(v.failures)[G.BOARD_NOT_A_DISSENT])

    def test_the_cited_entry_must_cite_the_SAME_prior_as_the_PR(self):
        board = _Board({KEY: _dissent(HEAD, prior=f"{PRIOR_KEY}@{OTHER}"), PRIOR_KEY: _dissent(OLD)})
        v = _run(_ref(prior=f"{PRIOR_KEY}@{OLD}"), board=board)
        self.assertEqual(v.codes, [G.BOARD_NOT_A_DISSENT])
        self.assertIn("cites prior", dict(v.failures)[G.BOARD_NOT_A_DISSENT])


class Forks(unittest.TestCase):
    def test_a_FORK_PR_is_red_and_the_board_is_NEVER_ASKED(self):
        """The secret reaches pull_request_target runs for forks, and two distinct board codes would make
        the gate an oracle for which keys exist. So a fork never reaches the board at all."""
        board = _Board({KEY: _dissent(HEAD)})
        v = _run(_ref(), same_repo=False, board=board)
        self.assertEqual(v.codes, [G.FORK_UNVERIFIED])
        self.assertEqual(board.asked, [], "the board must not be queried for a fork PR")


class WorkflowTouched(unittest.TestCase):
    def test_a_PR_touching_github_is_red_and_WAIVABLE_only_when_that_is_the_sole_failure(self):
        v = _run(_ref(), paths=[".github/workflows/ci.yml", "README.md"])
        self.assertEqual(v.codes, [G.WORKFLOW_TOUCHED])
        self.assertTrue(v.admin_waivable)
        self.assertIn("ADMIN-WAIVABLE: yes", G.render(v))

    def test_an_override_NEVER_waives_a_bad_Dissent_Ref(self):
        """Board item 10. An admin ruling on a workflow change is not permission to skip the dissent."""
        for body in ("no reference", _ref(head=OLD)):
            with self.subTest(body=body[:20]):
                v = _run(body, paths=[".github/workflows/x.yml"], board=_Board({KEY: _dissent(OLD)}))
                self.assertIn(G.WORKFLOW_TOUCHED, v.codes)
                self.assertFalse(v.admin_waivable)
                self.assertIn("ADMIN-WAIVABLE: no", G.render(v))


class NothingAttackerControlledIsEchoed(unittest.TestCase):
    def test_the_output_never_contains_the_BODY_the_BOARD_URL_or_ENTRY_CONTENT(self):
        """A runner reads lines beginning '::' as workflow commands, and the body is public input."""
        hostile = "::set-env name=X::pwned\nhttps://secret.example/token/state/k\n" + _ref(head=OLD)
        entry = _dissent(OLD, summary="::add-mask::leak SECRET-CONTENT")
        v = _run(hostile, paths=[".github/x\n::warning::injected"], board=_Board({KEY: entry}))
        out = G.render(v)
        self.assertFalse(any(line.startswith("::") for line in out.splitlines()),
                         f"an output line begins with '::':\n{out}")
        for leak in ("pwned", "secret.example", "SECRET-CONTENT"):
            self.assertNotIn(leak, out)

    def test_a_MALFORMED_line_is_named_by_NUMBER_never_echoed(self):
        """Red-proof survivor D10: the test above carries a WELL-FORMED reference, so the MALFORMED path
        never ran. A malformed line is exactly where echoing 'the offending line' would print input."""
        v = _run("intro\nDissent-Ref: board=x ::set-env name=X::pwned\n")
        self.assertEqual(v.codes, [G.MALFORMED], "stimulus control: the hostile line must be MALFORMED")
        out = G.render(v)
        self.assertIn("line 2", out)
        self.assertNotIn("pwned", out)
        self.assertNotIn("set-env", out)


class TheWorkflowFileKeepsItsInvariants(unittest.TestCase):
    """Static pins on .github/workflows/dissent-gate.yml — each invariant a future edit could break."""

    @classmethod
    def setUpClass(cls):
        cls.text = (_ROOT / ".github" / "workflows" / "dissent-gate.yml").read_text(encoding="utf-8")
        cls.code = "\n".join(ln for ln in cls.text.splitlines() if not ln.lstrip().startswith("#"))

    def test_it_runs_on_pull_request_target_and_never_checks_out_the_head(self):
        self.assertIn("pull_request_target:", self.code)
        self.assertNotRegex(self.code, r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head")
        self.assertIn("persist-credentials: false", self.code)

    def test_no_attacker_controlled_field_is_interpolated_into_a_run_line(self):
        for line in self.code.splitlines():
            if re.match(r"\s*(?:- )?run:", line):
                self.assertNotIn("${{", line, f"a run line interpolates an expression: {line.strip()}")

    def test_permissions_are_read_only_and_there_is_no_cache(self):
        self.assertRegex(self.code, r"permissions:\s*\n\s+contents: read\s*\n\s+pull-requests: read")
        self.assertNotIn("write", self.code)
        self.assertNotIn("cache", self.code)

    def test_the_job_name_is_the_check_name_the_ruleset_will_require(self):
        self.assertIn("name: Dissent gate", self.code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
