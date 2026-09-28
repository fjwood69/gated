#!/usr/bin/env python3
"""The process gate, tested offline: every rule in ``scripts/judge/dissent_gate.py``'s pure ``evaluate``, the
derivation of the files it executes, ``main`` through an injected HTTP getter, and the one workflow parser.

⚠ THE LIVE BEHAVIOUR IS NOT TESTED HERE, AND THAT IS STATED RATHER THAN IMPLIED. Whether GitHub attaches a
``pull_request_target`` check to the PR head, whether an ``edited`` re-run resolves a required check,
what happens when a PR adds a same-named job, where an admin bypass is logged, and whether a hosted
runner can read the board — those are measured on a scratch repository and on the real one (M1-M5), not
asserted by this file. A green run here says the RULES are right, not that the PLATFORM behaves as the
rules assume.

⚠ NO TEST WRITES INTO THE WORKTREE (#61). Derivation cases build scratch trees in a temporary directory;
the real tree is only ever read.
"""
from __future__ import annotations

import ast
import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts" / "judge"))

import dissent_gate as G  # noqa: E402
import workflow_steps as W  # noqa: E402

HEAD = "a" * 40
OLD = "b" * 40
OTHER = "c" * 40
KEY = "gated-p10b-dissent-head"
PRIOR_KEY = "gated-p10b-dissent-prior"
GATE_YML = ".github/workflows/dissent-gate.yml"
GATE_PY = "scripts/judge/dissent_gate.py"
PARSER_PY = "scripts/judge/workflow_steps.py"
JUDGE = G.Judge(files=frozenset({GATE_YML, GATE_PY, PARSER_PY}), dirs=frozenset({"scripts/judge"}))
_SRC = (_ROOT / GATE_PY).read_text(encoding="utf-8")
_TREE = ast.parse(_SRC)


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
         judge: G.Judge | Exception = JUDGE, ancestor: bool | Exception = True,
         board: _Board | None = None, files_fail: bool = False, body_fail: bool = False) -> G.Verdict:
    board = board if board is not None else _Board({KEY: _dissent(HEAD)})

    def fetch_body() -> str | None:
        if body_fail:
            raise G.InstrumentError("the PR returned HTTP 502")
        return body

    def derived() -> G.Judge:
        if isinstance(judge, Exception):
            raise judge
        return judge

    def changed() -> list[str]:
        if files_fail:
            raise G.InstrumentError("PR files returned HTTP 502")
        return paths if paths is not None else ["scripts/x.py"]

    def is_anc(old: str, new: str) -> bool:
        if isinstance(ancestor, Exception):
            raise ancestor
        return ancestor

    return G.evaluate(head, same_repo=same_repo, fetch_body=fetch_body, judge=derived,
                      changed_paths=changed, is_ancestor=is_anc, fetch_entry=board)


def _stray_names() -> list[str]:
    """Names a stray file in a judge directory could have: every standard module name this interpreter knows (3.10+;
    on 3.9, the modules the gate imports), the start-up hooks, a dotfile, case variants, other suffixes."""
    stdlib = set(getattr(sys, "stdlib_module_names", ())) or {
        m for m, mod in sys.modules.items() if not str(getattr(mod, "__file__", "") or "").startswith(str(_ROOT))}
    names = {f"{m}.py" for m in stdlib if m.isidentifier()}
    names |= {"sitecustomize.py", "usercustomize.py", ".hidden.py", "JSON.py", "Functools.py", "x.pth", "x.pyc",
              "x.so", "x.txt", "unrelated_tool.py"}
    return sorted(names)


_FRESH: list[tempfile.TemporaryDirectory] = []


def _fresh() -> Path:
    """The tracked tree, copied to a temporary directory — what a FRESH CHECKOUT holds, which is what the gate derives from.
    ⚠ Not the worktree: running this suite without -B writes scripts/judge/__pycache__, which the derivation (rightly)
    refuses, and a developer's untracked files are not in a checkout either."""
    if not _FRESH:
        tracked = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True, cwd=_ROOT).stdout
        _FRESH.append(tempfile.TemporaryDirectory())
        dest = Path(_FRESH[0].name)
        for rel in filter(None, tracked.decode().split("\0")):
            src = _ROOT / rel
            if src.is_file() and not src.is_symlink():
                (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                (dest / rel).write_bytes(src.read_bytes())
    return Path(_FRESH[0].name)


def tearDownModule() -> None:
    for d in _FRESH:
        d.cleanup()


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

    def test_the_MALFORMED_message_states_the_ONE_grammar(self):
        """Consult P3: the message restated the regex's grammar in prose — a second statement of one rule.
        It is now built from ``_REF_GRAMMAR``, and that grammar accepts what ``_REF`` accepts."""
        v = _run(f"Dissent-Ref: board={KEY} head=zz")
        self.assertIn(G._REF_GRAMMAR, dict(v.failures)[G.MALFORMED])
        example = G._REF_GRAMMAR.replace("<key>", KEY).replace("<40-hex sha>", HEAD)
        self.assertTrue(G._REF.match(example.replace(" [prior=", " prior=").replace("]", "")))

    def test_a_reference_INDENTED_or_INSIDE_A_FENCE_is_not_a_reference(self):
        """A body documenting the format must not count as carrying it."""
        self.assertEqual(_run("  " + _ref()).codes, [G.MISSING])
        self.assertEqual(_run("```\n" + _ref() + "\n```\n").codes, [G.MISSING])
        v = _run("```\n" + _ref(head=OTHER) + "\n```\n" + _ref())
        self.assertTrue(v.passed, "a fenced example alongside the real line must not make it ambiguous")

    def test_an_INSTRUMENT_failure_is_NEVER_a_pass(self):
        """Every probe: board, ancestry, file list, judge set, PR body. An unanswered question is not a 'no'."""
        cases = {
            "board unreachable": dict(board=_Board(fail=True)),
            "ancestry unreachable": dict(ancestor=G.InstrumentError("compare returned HTTP 502")),
            "file list unreachable": dict(files_fail=True),
            "judge underivable": dict(judge=G.InstrumentError("2 jobs are named 'Dissent gate'")),
            "body unreadable": dict(body_fail=True),
        }
        for label, kw in cases.items():
            with self.subTest(case=label):
                body = _ref(prior=f"{PRIOR_KEY}@{OLD}") if "ancestry" in label else _ref()
                v = _run(body, **kw)
                self.assertFalse(v.passed)
                self.assertIn(G.INSTRUMENT, v.codes)
                self.assertFalse(v.admin_waivable)

    def test_an_unreadable_body_still_reports_WORKFLOW_TOUCHED_and_is_NOT_waivable(self):
        """Consult Part B (D2 composition): the judge check runs first, so a transient API failure on a PR
        touching the judge shows BOTH — and INSTRUMENT makes it non-waivable until a clean re-run."""
        v = _run(_ref(), paths=[GATE_PY], body_fail=True)
        self.assertEqual(v.codes, [G.WORKFLOW_TOUCHED, G.INSTRUMENT])
        self.assertFalse(v.admin_waivable)

    def test_EVERY_code_is_reported_not_just_the_first(self):
        v = _run(_ref(head=OLD), paths=[GATE_PY], board=_Board())
        self.assertEqual(set(v.codes), {G.WORKFLOW_TOUCHED, G.HEAD_MISMATCH, G.BOARD_ENTRY_MISSING})

    def test_the_code_set_is_DISTINCT(self):
        """⚠ VACUOUS BY CONSTRUCTION since D5 — ALL_CODES is a set over module names, so it cannot hold a
        duplicate. Kept, and stated; the safety lives in the three pins in ``D5_TheCodesAreDerived``."""
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
        self.assertIn("cites a prior other than the PR's reference", dict(v.failures)[G.BOARD_NOT_A_DISSENT])


class Forks(unittest.TestCase):
    def test_a_FORK_PR_is_red_and_the_board_is_NEVER_ASKED(self):
        """The secret reaches pull_request_target runs for forks, and two distinct board codes would make
        the gate an oracle for which keys exist. So a fork never reaches the board at all."""
        board = _Board({KEY: _dissent(HEAD)})
        v = _run(_ref(), same_repo=False, board=board)
        self.assertEqual(v.codes, [G.FORK_UNVERIFIED])
        self.assertEqual(board.asked, [], "the board must not be queried for a fork PR")


class WorkflowTouched(unittest.TestCase):
    def test_a_PR_touching_the_judge_is_red_and_WAIVABLE_only_when_that_is_the_sole_failure(self):
        v = _run(_ref(), paths=[GATE_YML, "README.md"])
        self.assertEqual(v.codes, [G.WORKFLOW_TOUCHED])
        self.assertTrue(v.admin_waivable)
        self.assertIn("ADMIN-WAIVABLE: yes (WORKFLOW_TOUCHED only)", G.render(v))

    def test_an_override_NEVER_waives_a_bad_Dissent_Ref(self):
        """Board item 10. An admin ruling on a change to the judge is not permission to skip the dissent."""
        for body in ("no reference", _ref(head=OLD)):
            with self.subTest(body=body[:20]):
                v = _run(body, paths=[GATE_PY], board=_Board({KEY: _dissent(OLD)}))
                self.assertIn(G.WORKFLOW_TOUCHED, v.codes)
                self.assertFalse(v.admin_waivable)
                self.assertIn("ADMIN-WAIVABLE: no", G.render(v))

    def test_a_NEW_file_under_the_judge_directory_IS_touched(self):
        """Board ruling 2026-09-28: the directory, not the file list. A file added there can run inside the gate, before
        its code, if the standard library imports its name — so adding one is a change to the judge. Generated names."""
        for new in [f"scripts/judge/{n}" for n in _stray_names()] + ["scripts/judge/sub/x.py",
                                                                     "scripts/judge/__pycache__/x.pyc"]:
            with self.subTest(path=new):
                self.assertNotIn(new, JUDGE.files, "stimulus control: not an existing judge file")
                self.assertTrue(JUDGE.covers(new))
        self.assertEqual(_run(_ref(), paths=["scripts/judge/functools.py"]).codes, [G.WORKFLOW_TOUCHED])

    def test_membership_is_by_EXACT_path_or_directory(self):
        """Near misses at both ends of a judge path and of the judge directory."""
        for near in ("scripts/judge.py", "scripts/judgement/x.py", "xscripts/judge/x.py", "scripts/Judge/x.py",
                     "scripts/dissent_gate.py", "scripts/judge_x/dissent_gate.py", "judge/dissent_gate.py",
                     ".github/workflows/dissent-gate.yaml", ".github/workflows/ci.yml", ".github/CODEOWNERS"):
            with self.subTest(path=near):
                self.assertTrue(_run(_ref(), paths=[near]).passed)


class D1_TheJudgeSetOnTheRealTree(unittest.TestCase):
    """The spec's acceptance, against the derivation itself — not an injected set."""

    def _judged(self, paths: list[str]) -> G.Verdict:
        return _run(_ref(), paths=paths, judge=G.derive_judge(_fresh()))

    def test_the_CORRELATED_POSITIVE_the_derived_judge_is_exactly_the_judge(self):
        """Derived on the PR's own tracked tree: a PR adding a second context-named job, or anything the derivation
        refuses, reds here — unless the same PR edits this test, which only the board's reading of the diff catches."""
        self.assertEqual(G.derive_judge(_fresh()), JUDGE)

    def test_the_judge_directory_TRACKS_nothing_but_the_judge_files(self):
        """Board ruling: the CI layer of the directory rule, on the tracked listing."""
        out = subprocess.run(["git", "ls-files", "scripts/judge"], capture_output=True, text=True, check=True,
                             cwd=_ROOT).stdout.split()
        self.assertEqual(sorted(out), sorted(JUDGE.files - {GATE_YML}))

    def test_a_ci_yml_only_PR_is_NOT_touched(self):
        self.assertTrue(self._judged([".github/workflows/ci.yml"]).passed)

    def test_each_judge_file_alone_IS_touched(self):
        for path in sorted(JUDGE.files):
            with self.subTest(path=path):
                v = self._judged([path])
                self.assertEqual(v.codes, [G.WORKFLOW_TOUCHED])
                self.assertIn(repr(path), dict(v.failures)[G.WORKFLOW_TOUCHED])


# ── Scratch trees: the derivation's mechanism ──────────────────────────────────────────────────────────
_BASE_WORKFLOW = """\
name: Dissent gate
on:
  pull_request_target:
    branches: [main]
jobs:
  gate:
    name: Dissent gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with:
          persist-credentials: false
      - name: Evaluate
        env:
          PR_NUMBER: ${{ github.event.pull_request.number }}
        run: python -E -s -S -B scripts/g.py
"""
_BASE = {".github/workflows/gate.yml": _BASE_WORKFLOW, "scripts/g.py": "import json\n"}


def _edit(files: dict[str, str], path: str, old: str, new: str) -> dict[str, str]:
    """One edit to the base tree — the anchor must occur exactly once (the stimulus is armed)."""
    assert files[path].count(old) == 1, f"anchor {old!r} occurs {files[path].count(old)} times in {path}"
    return {**files, path: files[path].replace(old, new)}


@contextlib.contextmanager
def _scratch(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        yield root


def _derive(files: dict[str, str]) -> G.Judge | str:
    """The derived judge, or the refusal's message."""
    with _scratch(files) as root:
        try:
            return G.derive_judge(root)
        except G.InstrumentError as exc:
            return str(exc)


def _judge(*files: str) -> G.Judge:
    return G.Judge(frozenset({".github/workflows/gate.yml", *files}), frozenset({"scripts"}))


class D1_TheDerivation(unittest.TestCase):
    def test_the_scratch_CONTROL_derives_the_workflow_its_script_and_its_directory(self):
        """⚠ Every refusal below is ONE edit from this tree — without it, a derivation that refused
        everything would pass them all."""
        self.assertEqual(_derive(_BASE), _judge("scripts/g.py"))

    def test_a_LOCAL_IMPORT_extends_the_judge_TRANSITIVELY(self):
        files = _edit(_BASE, "scripts/g.py", "import json\n", "import json\nimport helper\n")
        files.update({"scripts/helper.py": "from helper2 import thing\n", "scripts/helper2.py": "import re\n"})
        self.assertEqual(_derive(files), _judge("scripts/g.py", "scripts/helper.py", "scripts/helper2.py"))

    def test_a_local_file_SHADOWING_a_standard_module_the_judge_imports_joins_it(self):
        files = {**_BASE, "scripts/json.py": ""}
        self.assertEqual(_derive(files), _judge("scripts/g.py", "scripts/json.py"))

    def test_F1_a_STDLIB_SHADOW_that_NO_JUDGE_FILE_IMPORTS_is_refused(self):
        """Finding 1, measured 2026-09-28: a scripts/functools.py imported by no judge file ran inside the gate, because
        the standard library imports functools after sys.path[0] is set. An import closure cannot see it; the
        directory rule does. ⚠ GENERATED, NOT LISTED (consult Q3): every standard module name this interpreter knows,
        the start-up hook names, a dotfile and case variants — a hand-picked handful would let a one-name exemption in
        the rule pass green."""
        imported = {f"{m}.py" for m in G._imports(ast.parse(_BASE["scripts/g.py"]), "g")}   # those JOIN the judge instead
        self.assertEqual(imported, {"json.py"}, "stimulus control: the one name excluded, and why")
        with _scratch(_BASE) as root:
            self.assertIsInstance(G.derive_judge(root), G.Judge, "stimulus control: the base tree derives")
            for name in sorted(set(_stray_names()) - imported):
                with self.subTest(stray=name):
                    path = root / "scripts" / name
                    path.write_text("", encoding="utf-8")
                    try:
                        with self.assertRaises(G.InstrumentError):
                            G.derive_judge(root)
                    finally:
                        path.unlink()

    def test_every_REFUSAL_is_INSTRUMENT_never_a_judge(self):
        wf = ".github/workflows/gate.yml"
        run = "        run: python -E -s -S -B scripts/g.py\n"
        cases = {
            "no job named with the context": _edit(_BASE, wf, "    name: Dissent gate\n", "    name: Gate\n"),
            "two jobs named with it": {**_BASE, ".github/workflows/other.yml":
                                       "jobs:\n  x:\n    name: Dissent gate\n    steps:\n      - run: python a.py\n"},
            "another workflow does not parse": {**_BASE, ".github/workflows/other.yml": "jobs:\n  x: {}\n"},
            "a block-scalar run": _edit(_BASE, wf, run, "        run: |\n          python -E -s -S -B scripts/g.py\n"),
            "no flags": _edit(_BASE, wf, run, "        run: python scripts/g.py\n"),
            "-I instead": _edit(_BASE, wf, run, "        run: python -I scripts/g.py\n"),
            "flags reordered": _edit(_BASE, wf, run, "        run: python -B -E -s -S scripts/g.py\n"),
            "-S omitted (the previous form)": _edit(_BASE, wf, run, "        run: python -E -s -B scripts/g.py\n"),
            "-S reordered": _edit(_BASE, wf, run, "        run: python -E -S -s -B scripts/g.py\n"),
            "-s omitted": _edit(_BASE, wf, run, "        run: python -E -S -B scripts/g.py\n"),
            "python -m": _edit(_BASE, wf, run, "        run: python -E -s -S -B -m g\n"),
            "python -c": _edit(_BASE, wf, run, "        run: python -E -s -S -B -c 'import os'\n"),
            "an operator": _edit(_BASE, wf, run, "        run: python -E -s -S -B scripts/g.py && python evil.py\n"),
            "a redirect": _edit(_BASE, wf, run, "        run: python -E -s -S -B scripts/g.py > out\n"),
            "an env prefix": _edit(_BASE, wf, run, "        run: X=1 python -E -s -S -B scripts/g.py\n"),
            "an extra option": _edit(_BASE, wf, run, "        run: python -E -s -S -B -W error scripts/g.py\n"),
            "a versioned interpreter": _edit(_BASE, wf, run, "        run: python3.13 -E -s -S -B scripts/g.py\n"),
            "python3 instead of python": _edit(_BASE, wf, run, "        run: python3 -E -s -S -B scripts/g.py\n"),
            "a script that is not a file": _edit(_BASE, wf, run, "        run: python -E -s -S -B scripts/nope.py\n"),
            "a parent-directory path": _edit(_BASE, wf, run, "        run: python -E -s -S -B scripts/../scripts/g.py\n"),
            "a script at the repository root": {**_edit(_BASE, wf, run, "        run: python -E -s -S -B g.py\n"),
                                                "g.py": "import json\n"},
            "a local action": _edit(_BASE, wf, "      - uses: actions/checkout@v5\n", "      - uses: ./local\n"),
            "shell:": _edit(_BASE, wf, run, run + "        shell: python\n"),
            "working-directory:": _edit(_BASE, wf, run, run + "        working-directory: scripts\n"),
            "if: on a step": _edit(_BASE, wf, run, run + "        if: false\n"),
            "a job container": _edit(_BASE, wf, "    runs-on: ubuntu-latest\n",
                                     "    runs-on: ubuntu-latest\n    container: python:3\n"),
            "workflow defaults:": _edit(_BASE, wf, "jobs:\n", "defaults:\n  run:\n    shell: bash\njobs:\n"),
            "PYTHONPATH on the step": _edit(_BASE, wf, "          PR_NUMBER:", "          PYTHONPATH: x\n          PR_NUMBER:"),
            "PATH on the job": _edit(_BASE, wf, "    runs-on: ubuntu-latest\n",
                                     "    runs-on: ubuntu-latest\n    env:\n      PATH: /tmp\n"),
            "BASH_ENV on the workflow": _edit(_BASE, wf, "jobs:\n", "env:\n  BASH_ENV: x.sh\njobs:\n"),
            "no run step at all": _edit(_BASE, wf, run, "        uses: actions/setup-python@v6\n"),
            "a relative import": {**_BASE, "scripts/g.py": "from . import x\n"},
            "a relative import of a module that exists": {**_BASE, "scripts/g.py": "from .helper import x\n",
                                                          "scripts/helper.py": ""},
            "a sys.path edit": {**_BASE, "scripts/g.py": "import sys\nsys.path.insert(0, 'x')\n"},
            "importlib": {**_BASE, "scripts/g.py": "import importlib\n"},
            "subprocess": {**_BASE, "scripts/g.py": "import subprocess\n"},
            "runpy": {**_BASE, "scripts/g.py": "import runpy\n"},
            "os.system": {**_BASE, "scripts/g.py": "import os\nos.system('x')\n"},
            "from os import system": {**_BASE, "scripts/g.py": "from os import system\n"},
            "os under another name": {**_BASE, "scripts/g.py": "import os as o\n"},
            "exec": {**_BASE, "scripts/g.py": "exec('x')\n"},
            "__import__": {**_BASE, "scripts/g.py": "__import__('x')\n"},
            "a dunder escape": {**_BASE, "scripts/g.py": "().__class__\n"},
            "a subscript of globals()": {**_BASE, "scripts/g.py": "globals()['json']\n"},
            "a non-standard import": {**_BASE, "scripts/g.py": "import requests\n"},
            "a local package": {**_BASE, "scripts/g.py": "import pkg\n", "scripts/pkg/__init__.py": ""},
            "a namespace directory": {**_BASE, "scripts/g.py": "import pkg.mod\n", "scripts/pkg/mod.py": ""},
            "beneath a module file": {**_BASE, "scripts/g.py": "import helper.sub\n", "scripts/helper.py": ""},
            "unparseable Python": {**_BASE, "scripts/g.py": "def (:\n"},
            "a refusal in a TRANSITIVE import": {**_BASE, "scripts/g.py": "import helper\n",
                                                 "scripts/helper.py": "import subprocess\n"},
            # the directory rule: nothing in the judge directory but source files the judge imports
            "a stray .py nobody imports": {**_BASE, "scripts/tool.py": ""},
            "a __pycache__": {**_BASE, "scripts/__pycache__/g.cpython-313.pyc": ""},
            "a .pyc beside": {**_BASE, "scripts/helper.pyc": ""},
            "an extension module": {**_BASE, "scripts/helper.cpython-313-x86_64-linux-gnu.so": ""},
            "a subdirectory": {**_BASE, "scripts/data/readme.txt": ""},
            "a non-Python file": {**_BASE, "scripts/notes.txt": ""},
        }
        for label, files in cases.items():
            with self.subTest(case=label):
                self.assertIsInstance(_derive(files), str, f"{label}: derived a judge instead of refusing")

    def test_a_script_at_the_REPOSITORY_ROOT_is_refused_for_that_reason(self):
        """Its directory would be the whole checkout. Another rule also refuses it (the root holds more than the
        closure), so the message is pinned — otherwise this refusal could be deleted with every test green."""
        files = {**_edit(_BASE, ".github/workflows/gate.yml", "        run: python -E -s -S -B scripts/g.py\n",
                         "        run: python -E -s -S -B g.py\n"), "g.py": "import json\n"}
        self.assertIn("repository root", _derive(files))

    def test_a_SYMLINKED_script_is_refused(self):
        with _scratch({**_BASE, "real/real.py": ""}) as root:
            (root / "scripts" / "g.py").unlink()
            (root / "scripts" / "g.py").symlink_to(root / "real" / "real.py")
            with self.assertRaises(G.InstrumentError):
                G.derive_judge(root)

    def test_a_SYMLINK_entry_in_the_judge_directory_is_refused(self):
        with _scratch({**_BASE, "elsewhere/x.py": ""}) as root:
            self.assertIsInstance(G.derive_judge(root), G.Judge, "stimulus control: the tree derives before the link")
            (root / "scripts" / "json.py").symlink_to(root / "elsewhere" / "x.py")
            with self.assertRaises(G.InstrumentError):
                G.derive_judge(root)

    def test_the_message_names_no_input_text(self):
        """A refusal names a rule and repo paths — base-side, but still never the step's text."""
        msg = _derive(_edit(_BASE, ".github/workflows/gate.yml", "        run: python -E -s -S -B scripts/g.py\n",
                            "        run: python -E -s -S -B scripts/g.py ::warning::x\n"))
        self.assertIsInstance(msg, str)
        self.assertNotIn("::warning", msg)


# ── main(), through an injected HTTP getter ────────────────────────────────────────────────────────────
_ENV = {"GITHUB_REPOSITORY": "fjwood69/gated", "GITHUB_TOKEN": "TOKEN-VALUE", "PR_NUMBER": "7",
        "HEAD_SHA": HEAD, "HEAD_REPO": "fjwood69/gated", "BASE_REPO": "fjwood69/gated",
        "BOARD_BASE": "https://board.test/SECRET-PATH"}
_PR = "https://api.github.com/repos/fjwood69/gated/pulls/7"


class _Api:
    """A fake GitHub API and board. ``pages`` is the PR-files listing, one list per page, linked by
    ``Link: rel="next"`` unless ``link=False``."""

    def __init__(self, *, body: object = None, pr_status: int = 200, pr_raw: bytes | None = None,
                 pages: list[list[dict]] | None = None, files_raw: bytes | None = None, link: bool = True,
                 next_url: str | None = None, board: dict | None = None):
        self.body = f"text\n\n{_ref()}\n" if body is None else body
        self.pr_status, self.pr_raw = pr_status, pr_raw
        self.pages = pages if pages is not None else [[{"filename": "README.md"}]]
        self.files_raw, self.link, self.next_url = files_raw, link, next_url
        self.board = board if board is not None else {KEY: _dissent(HEAD)}
        self.urls: list[str] = []

    def __call__(self, url: str, headers: dict[str, str]) -> tuple[int, bytes, dict[str, str]]:
        self.urls.append(url)
        if url.startswith(_ENV["BOARD_BASE"]):
            key = url.rsplit("/", 1)[1]
            return (200, json.dumps(self.board[key]).encode(), {}) if key in self.board else (404, b"", {})
        if url == _PR:
            raw = self.pr_raw if self.pr_raw is not None else json.dumps({"body": self.body}).encode()
            return self.pr_status, raw, {}
        if url.startswith(_PR + "/files"):
            page = int(urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("page", ["1"])[0])
            if self.files_raw is not None:
                return 200, self.files_raw, {}
            link = ""
            if self.next_url is not None:
                link = f'<{self.next_url}>; rel="next"'
            elif self.link and page < len(self.pages):
                link = f'<{_PR}/files?per_page=100&page={page + 1}>; rel="next"'
            return 200, json.dumps(self.pages[page - 1]).encode(), {"Link": link}
        raise AssertionError(f"unexpected request {url}")


def _main(api: _Api, env: dict[str, str] | None = None) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = G.main(_ENV if env is None else env, get=api, root=_fresh())
    return code, out.getvalue()


class D2_ThroughMain(unittest.TestCase):
    def test_the_CONTROL_passes_through_main_and_prints_no_secret(self):
        code, out = _main(_Api())
        self.assertEqual(code, 0, out)
        self.assertTrue(out.startswith("DISSENT GATE: PASS"), out)
        for leak in ("SECRET-PATH", "board.test", "TOKEN-VALUE", "text"):
            self.assertNotIn(leak, out)

    def test_the_body_judged_is_the_API_body_NEVER_the_environment(self):
        """D2: an env PR_BODY carrying a valid reference must be ignored when the API body has none."""
        env = {**_ENV, "PR_BODY": _ref()}
        code, out = _main(_Api(body="no reference in the API body"), env)
        self.assertEqual(code, 1)
        self.assertIn("MISSING", out)

    def test_a_null_body_is_MISSING(self):
        code, out = _main(_Api(pr_raw=b'{"body": null}'))
        self.assertIn("FAIL — MISSING —", out)

    def test_a_body_FETCH_FAILURE_is_INSTRUMENT_and_NOT_also_MISSING(self):
        cases = {"HTTP 500": _Api(pr_status=500), "not JSON": _Api(pr_raw=b"<html>"),
                 "no body field": _Api(pr_raw=b'{"title": "x"}'), "a non-string body": _Api(pr_raw=b'{"body": 5}'),
                 "not an object": _Api(pr_raw=b"[]")}
        for label, api in cases.items():
            with self.subTest(case=label):
                code, out = _main(api)
                self.assertEqual(code, 1)
                self.assertIn("FAIL — INSTRUMENT — ADMIN-WAIVABLE: no", out)
                self.assertNotIn("MISSING", out)

    def test_a_missing_or_empty_ENV_NAME_is_INSTRUMENT_naming_it_before_any_request(self):
        """Y5: every name the script reads is required and checked first — never a traceback, never a
        default (HEAD_REPO/BASE_REPO once defaulted to a silent FORK_UNVERIFIED)."""
        for name in G.REQUIRED_ENV:
            for env in ({k: v for k, v in _ENV.items() if k != name}, {**_ENV, name: ""}):
                with self.subTest(name=name, empty=name in env):
                    api = _Api()
                    code, out = _main(api, env)
                    self.assertEqual(code, 1)
                    self.assertIn("INSTRUMENT", out)
                    self.assertIn(name, out)
                    self.assertEqual(api.urls, [], "nothing may run before the environment is checked")

    def test_a_FORK_never_reaches_the_board_through_main(self):
        api = _Api()
        code, out = _main(api, {**_ENV, "HEAD_REPO": "someone/gated"})
        self.assertIn("FORK_UNVERIFIED", out)
        self.assertFalse([u for u in api.urls if u.startswith(_ENV["BOARD_BASE"])])


class D1_ChangedFiles(unittest.TestCase):
    def test_a_judge_file_on_PAGE_TWO_is_found_by_following_Link(self):
        """Amendment 4: never assume a page size. Pages of ONE entry — the old short-page rule would stop
        after the first."""
        pages = [[{"filename": "README.md"}], [{"filename": GATE_PY}]]
        code, out = _main(_Api(pages=pages))
        self.assertIn("FAIL — WORKFLOW_TOUCHED — ADMIN-WAIVABLE: yes", out)
        code, out = _main(_Api(pages=pages, link=False))
        self.assertEqual(code, 0, "stimulus control: without the Link, page two is never read")

    def test_a_RENAME_of_a_judge_file_is_a_change_to_it(self):
        renamed = [[{"filename": "scripts/renamed.py", "previous_filename": GATE_PY, "status": "renamed"}]]
        code, out = _main(_Api(pages=renamed))
        self.assertIn("WORKFLOW_TOUCHED", out)
        code, out = _main(_Api(pages=[[{"filename": "scripts/renamed.py", "status": "added"}]]))
        self.assertEqual(code, 0, "stimulus control: the previous_filename is what catches it")

    def test_a_malformed_listing_is_INSTRUMENT(self):
        cases = {"not JSON": _Api(files_raw=b"<html>"), "not a list": _Api(files_raw=b"{}"),
                 "no filename": _Api(pages=[[{"name": "x"}]]),
                 "a non-string previous_filename": _Api(pages=[[{"filename": "x", "previous_filename": 1}]]),
                 "3000 entries": _Api(pages=[[{"filename": f"f{i}"} for i in range(3000)]])}
        for label, api in cases.items():
            with self.subTest(case=label):
                code, out = _main(api)
                self.assertIn("INSTRUMENT", out)
                self.assertEqual(code, 1)

    def test_a_Link_OFF_the_API_host_is_NEVER_followed_with_the_token(self):
        api = _Api(next_url="https://elsewhere.test/steal")
        code, out = _main(api)
        self.assertIn("INSTRUMENT", out)
        self.assertNotIn("https://elsewhere.test/steal", api.urls)


class D3_ThePassLineNamesWhatItVerified(unittest.TestCase):
    """#62."""

    def test_PASS_names_the_key_and_the_head(self):
        out = G.render(_run(_ref()))
        self.assertEqual(out, f"DISSENT GATE: PASS — board={KEY} head={HEAD} — a dissent-typed board entry "
                              f"names this exact head.")

    def test_PASS_names_the_prior_on_an_incremental_dissent(self):
        board = _Board({KEY: _dissent(HEAD, prior=f"{PRIOR_KEY}@{OLD}"), PRIOR_KEY: _dissent(OLD)})
        out = G.render(_run(_ref(prior=f"{PRIOR_KEY}@{OLD}"), board=board))
        self.assertIn(f"board={KEY} head={HEAD} prior={PRIOR_KEY}@{OLD} —", out)

    def test_a_verdict_with_no_failures_and_NO_REFERENCE_is_not_a_pass(self):
        self.assertFalse(G.Verdict().passed)


class NothingAttackerControlledIsEchoed(unittest.TestCase):
    def test_the_output_never_contains_the_BODY_the_BOARD_URL_or_ENTRY_CONTENT(self):
        """A runner reads lines beginning '::' as workflow commands, and the body is public input. The
        hostile path is a JUDGE path, so the WORKFLOW_TOUCHED message — the one that names paths — runs."""
        hostile_path = ".github/x\n::warning::injected"
        hostile = "::set-env name=X::pwned\nhttps://secret.example/token/state/k\n" + _ref(head=OLD)
        entry = _dissent(OLD, summary="::add-mask::leak SECRET-CONTENT")
        v = _run(hostile, paths=[hostile_path], judge=G.Judge(frozenset({hostile_path}), frozenset()), board=_Board({KEY: entry}))
        self.assertIn(G.WORKFLOW_TOUCHED, v.codes, "stimulus control: the path-naming message must run")
        out = G.render(v)
        self.assertFalse(any(line.startswith("::") for line in out.splitlines()),
                         f"an output line begins with '::':\n{out}")
        for leak in ("pwned", "secret.example", "SECRET-CONTENT"):
            self.assertNotIn(leak, out)

    def test_an_entrys_PRIOR_is_never_echoed(self):
        """Consult Q4 P2-1: the prior-mismatch message printed the ENTRY's `prior` — entry content — making the
        docstring's "never an entry's content" false. It prints the PR's prior only."""
        hostile = "::warning::ENTRY-CONTENT"
        board = _Board({KEY: _dissent(HEAD, prior=hostile), PRIOR_KEY: _dissent(OLD)})
        v = _run(_ref(prior=f"{PRIOR_KEY}@{OLD}"), board=board)
        self.assertEqual(v.codes, [G.BOARD_NOT_A_DISSENT], "stimulus control: the prior-mismatch path ran")
        out = G.render(v)
        self.assertNotIn("ENTRY-CONTENT", out)
        self.assertIn(f"{PRIOR_KEY}@{OLD}", out, "the PR's own prior is still named")

    def test_a_MALFORMED_line_is_named_by_NUMBER_never_echoed(self):
        """Red-proof survivor D10: the test above carries a WELL-FORMED reference, so the MALFORMED path
        never ran. A malformed line is exactly where echoing 'the offending line' would print input."""
        v = _run("intro\nDissent-Ref: board=x ::set-env name=X::pwned\n")
        self.assertEqual(v.codes, [G.MALFORMED], "stimulus control: the hostile line must be MALFORMED")
        out = G.render(v)
        self.assertIn("line 2", out)
        self.assertNotIn("pwned", out)
        self.assertNotIn("set-env", out)


# ── Static pins on the gate's own source ───────────────────────────────────────────────────────────────
def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    found = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(found) == 1, f"{name}: {len(found)} definitions"
    return found[0]


def _enclosing(node: ast.AST, parents: dict) -> list[str]:
    names = []
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            names.append(node.name)
    return names


class D5_TheCodesAreDerived(unittest.TestCase):
    """ALL_CODES is every module-level string whose value is its name. Three pins make that safe."""

    def test_the_derived_set_is_the_nine_codes(self):
        self.assertEqual(G.ALL_CODES, {G.MISSING, G.MALFORMED, G.HEAD_MISMATCH, G.PRIOR_NOT_ANCESTOR,
                                       G.INSTRUMENT, G.BOARD_ENTRY_MISSING, G.BOARD_NOT_A_DISSENT,
                                       G.FORK_UNVERIFIED, G.WORKFLOW_TOUCHED})

    def test_USE_every_code_is_loaded_somewhere(self):
        """A code defined and never used is inert."""
        loads = [n.id for n in ast.walk(_TREE) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)]
        for code in G.ALL_CODES:
            with self.subTest(code=code):
                self.assertIn(code, loads)

    def test_WRITE_Verdict_fail_is_the_ONLY_writer_to_failures(self):
        """A second writer would bypass every code pin. Outside ``fail``, ``.failures`` is only read: as
        the iterable of a loop or comprehension, or under ``not``."""
        parents = _parents(_TREE)
        mutators = {"append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse", "__setitem__",
                    "__iadd__"}
        for node in ast.walk(_TREE):
            if not (isinstance(node, ast.Attribute) and node.attr == "failures"):
                continue
            parent = parents[node]
            where = _enclosing(node, parents)
            write = (not isinstance(node.ctx, ast.Load)
                     or (isinstance(parent, ast.Attribute) and parent.attr in mutators))
            if write:
                self.assertEqual(where[:2], ["fail", "Verdict"], f"a write to .failures in {where}")
            else:
                self.assertTrue(isinstance(parent, (ast.comprehension, ast.For)) and parent.iter is node
                                or isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not),
                                f"an unrecognised use of .failures in {where}")
        for call in ast.walk(_TREE):
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "Verdict":
                self.assertEqual((call.args, call.keywords), ([], []), "a Verdict constructed with failures")

    def test_FAIL_records_exactly_what_it_is_given(self):
        """Consult Q3 P2-2: the three pins constrain CALLS to fail; nothing pinned what fail does. Its body is exactly one
        append of the (code, message) pair it was given."""
        fail = _function(_TREE, "fail")
        body = [n for n in fail.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant))]
        self.assertEqual(len(body), 1)
        self.assertEqual(ast.unparse(body[0]) if hasattr(ast, "unparse") else "",
                         "self.failures.append((code, message))" if hasattr(ast, "unparse") else "")
        self.assertEqual([a.arg for a in fail.args.args], ["self", "code", "message"])

    def test_ARG_every_fail_code_is_a_code_constant_or_the_one_named_alias(self):
        """The alias is the loop variable over ``parse_ref``'s errors — whose codes are themselves pinned."""
        ev = _function(_TREE, "evaluate")
        [bind] = [a for a in ast.walk(ev) if isinstance(a, ast.Assign) and isinstance(a.value, ast.Call)
                  and getattr(a.value.func, "id", None) == "parse_ref"]
        errs = bind.targets[0].elts[1].id
        [loop] = [f for f in ast.walk(ev) if isinstance(f, ast.For) and getattr(f.iter, "id", None) == errs]
        alias = loop.target.elts[0].id
        in_loop = {id(n) for n in ast.walk(loop)}
        calls = [c for c in ast.walk(_TREE) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
                 and c.func.attr == "fail"]
        self.assertGreater(len(calls), 10, "stimulus control: the calls were found")
        for c in calls:
            arg = c.args[0]
            self.assertIsInstance(arg, ast.Name)
            # Consult Q3 P2-1: the alias is accepted ONLY inside the loop that binds it — elsewhere `code = "X";
            # v.fail(code, …)` would pass a comparison of names alone.
            self.assertTrue(arg.id in G.ALL_CODES or (arg.id == alias and id(c) in in_loop),
                            f"fail({arg.id}, …) at line {c.lineno}")
        returns = [r for r in ast.walk(_function(_TREE, "parse_ref")) if isinstance(r, ast.Return)]
        for r in returns:
            errors = r.value.elts[1]
            self.assertIsInstance(errors, ast.List, f"parse_ref line {r.lineno} returns computed errors")
            for pair in errors.elts:
                self.assertIsInstance(pair.elts[0], ast.Name, f"parse_ref line {r.lineno}: a code that is not a constant")
                self.assertIn(pair.elts[0].id, G.ALL_CODES, f"parse_ref line {r.lineno}")


class Y5_TheEnvContract(unittest.TestCase):
    """Pinned both ways: what the script reads IS ``REQUIRED_ENV``, and the workflow supplies exactly that
    minus what the runner provides. ⚠ NAMES, NOT VALUES: ``HEAD_SHA: ${{ …base.sha }}`` would pass — the
    same boundary as ``display_only_flags``'."""

    def test_os_environ_is_touched_ONCE_as_the_argument_to_read_env(self):
        parents = _parents(_TREE)
        touches = [n for n in ast.walk(_TREE) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                   and n.value.id == "os"]
        self.assertEqual([t.attr for t in touches], ["environ"])
        node = touches[0]
        while not isinstance(node, ast.Call):
            node = parents[node]
        self.assertEqual(node.func.id, "read_env")
        self.assertNotIn("getenv", _SRC)

    def test_the_script_READS_exactly_REQUIRED_ENV(self):
        main = _function(_TREE, "main")
        [bind] = [a for a in ast.walk(main) if isinstance(a, ast.Assign) and isinstance(a.value, ast.Call)
                  and getattr(a.value.func, "id", None) == "read_env"]
        cfg = bind.targets[0].elts[0].id
        parents = _parents(main)
        reads = set()
        for n in ast.walk(main):
            if isinstance(n, ast.Name) and n.id == cfg and isinstance(n.ctx, ast.Load):
                sub = parents[n]
                self.assertTrue(isinstance(sub, ast.Subscript) and isinstance(sub.slice, ast.Constant),
                                f"{cfg} used other than as {cfg}['NAME'] at line {n.lineno}")
                reads.add(sub.slice.value)
        self.assertEqual(reads, set(G.REQUIRED_ENV))
        read_env = _function(_TREE, "read_env")
        loops = [f for f in ast.walk(read_env) if isinstance(f, ast.comprehension)]
        self.assertTrue(loops and all(getattr(c.iter, "id", None) == "REQUIRED_ENV" for c in loops))
        # Consult Q3 P2-4: every read of the environment inside read_env is inside one of those comprehensions.
        inside = {id(n) for comp in ast.walk(read_env) if isinstance(comp, (ast.ListComp, ast.DictComp))
                  for n in ast.walk(comp)}
        param = read_env.args.args[0].arg
        uses = [n for n in ast.walk(read_env) if isinstance(n, ast.Name) and n.id == param]
        self.assertTrue(uses)
        self.assertTrue(all(id(n) in inside for n in uses), f"{param} read outside a comprehension over REQUIRED_ENV")

    def test_the_workflow_supplies_each_name_from_THE_RIGHT_EXPRESSION(self):
        """Consult Q3 P2-3: the pin below compares NAMES. `head.repo` → `base.repo` in HEAD_REPO would keep every name
        and make every fork PR look same-repo — the board queried with the secret for anyone who opens one. So the
        expressions are pinned too: this table is the contract between the event and the script."""
        wf = W.parse_workflow(_ROOT / GATE_YML)
        [job] = [j for j in wf.jobs.values() if j.keys.get("name") == G.CONTEXT]
        supplied = {k: v for env in [wf.env, job.env] + [s.env for s in job.steps] for k, v in env.items()}
        self.assertEqual(supplied, {
            "PR_NUMBER": "${{ github.event.pull_request.number }}",
            "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
            "HEAD_REPO": "${{ github.event.pull_request.head.repo.full_name }}",
            "BASE_REPO": "${{ github.event.pull_request.base.repo.full_name }}",
            "GITHUB_TOKEN": "${{ github.token }}",
            "BOARD_BASE": "${{ secrets.BOARD_BASE }}",
        })

    def test_the_workflow_SUPPLIES_exactly_REQUIRED_ENV_minus_the_runners(self):
        wf = W.parse_workflow(_ROOT / GATE_YML)
        [job] = [j for j in wf.jobs.values() if j.keys.get("name") == G.CONTEXT]
        supplied = [n for env in [wf.env, job.env] + [s.env for s in job.steps] for n in env]
        self.assertEqual(sorted(supplied), sorted(set(G.REQUIRED_ENV) - set(G.RUNNER_PROVIDED)))
        self.assertTrue(set(G.RUNNER_PROVIDED) <= set(G.REQUIRED_ENV))


class EveryJudgeFile(unittest.TestCase):
    """Consult Q3 P1-2: the Y5 and one-parse pins read dissent_gate.py only, and the derivation allows `os.environ`
    in any judge file — so workflow_steps.py, imported before main's env check runs, could read and print BOARD_BASE with
    every pin green. Pinned across the WHOLE judge: every judge .py but the gate imports only what its docstring says,
    and nothing but the gate names the environment."""

    def test_the_parser_imports_only_re_pathlib_and_dataclasses(self):
        for rel in sorted(JUDGE.files - {GATE_YML, GATE_PY}):
            with self.subTest(file=rel):
                tree = ast.parse((_ROOT / rel).read_text(encoding="utf-8"))
                mods = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
                mods |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
                self.assertEqual(mods - {"__future__"}, {"re", "pathlib", "dataclasses"})
                names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
                        {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
                self.assertFalse(names & {"os", "sys", "environ", "getenv", "print", "open"}, rel)


class TheOneParse(unittest.TestCase):
    """Board carry-over from PR-1: a STRUCTURAL pin, not a literal count. The gate obtains workflow steps
    only through ``workflow_steps.parse_workflow``, and no function in it reads a workflow's lines itself."""

    def test_the_gate_imports_the_parser_and_nothing_else_local(self):
        local = [n for n in ast.walk(_TREE) if isinstance(n, ast.ImportFrom) and n.module == "workflow_steps"]
        self.assertEqual([sorted(a.name for a in n.names) for n in local], [["WorkflowParseError", "parse_workflow"]])
        self.assertFalse([n for n in ast.walk(_TREE) if isinstance(n, ast.Import)
                          and any(a.name == "workflow_steps" for a in n.names)])

    def test_no_function_in_the_gate_reads_lines_but_the_two_that_must(self):
        parents = _parents(_TREE)
        readers: dict[str, set[str]] = {}
        for n in ast.walk(_TREE):
            if isinstance(n, ast.Call):
                name = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "")
                if name in ("splitlines", "readlines", "read_text", "read_bytes", "open", "parse_workflow", "urlopen",
                            "read"):
                    readers.setdefault(name, set()).add(_enclosing(n, parents)[0])
        self.assertEqual(readers, {"splitlines": {"parse_ref"}, "read_text": {"_python_source"},
                                   "parse_workflow": {"derive_judge"}, "urlopen": {"_get"}, "read": {"_get"}})


class EveryWorkflowParses(unittest.TestCase):
    """Board amendment 3 — the argument that makes the gate's fail-closed scan safe: an unparseable
    workflow reds the PR that introduces it, so it never reaches base but through an admin bypass."""

    def test_every_TRACKED_workflow_parses(self):
        out = subprocess.run(["git", "ls-files", ".github/workflows"], capture_output=True, text=True,
                             check=True, cwd=_ROOT).stdout.split()
        workflows = [p for p in out if p.endswith((".yml", ".yaml"))]
        self.assertIn(GATE_YML, workflows, "stimulus control: the listing found the gate")
        for rel in workflows:
            with self.subTest(workflow=rel):
                W.parse_workflow(_ROOT / rel)


_MINIMAL = """\
name: W
jobs:
  a:
    name: Job A
    runs-on: ubuntu-latest
    steps:
      - name: step
        run: python x.py
      - uses: actions/checkout@v5
"""


def _parse(text: str) -> W.Workflow | str:
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "w.yml"
        path.write_text(text, encoding="utf-8")
        try:
            return W.parse_workflow(path)
        except W.WorkflowParseError as exc:
            return str(exc)


class TheParser(unittest.TestCase):
    def test_the_CONTROL_parses(self):
        wf = _parse(_MINIMAL)
        self.assertIsInstance(wf, W.Workflow)
        self.assertEqual(wf.jobs["a"].keys["name"], "Job A")
        self.assertEqual([s.keys for s in wf.jobs["a"].steps],
                         [{"name": "step", "run": "python x.py"}, {"uses": "actions/checkout@v5"}])

    def test_only_the_JOB_LEVEL_name_is_a_job_name(self):
        """Consult A1 P1: the workflow-level ``name:``, a step's ``- name:`` and a line in a block body
        share the key — only the job member counts."""
        # A body is always deeper than its key, so the only body that can hold a line at the job-member indent
        # is a top-level key's — the `note: |` after `jobs:` below.
        text = ("name: Dissent gate\njobs:\n  a:\n    runs-on: x\n    steps:\n      - name: Dissent gate\n"
                "        run: |\n          name: Dissent gate\nnote: |\n    name: Dissent gate\n")
        wf = _parse(text)
        self.assertIsInstance(wf, W.Workflow, wf)
        self.assertNotIn("name", wf.jobs["a"].keys)
        self.assertIsInstance(_parse(text.replace("    runs-on: x\n", "    runs-on: x\n    name: Dissent gate\n")),
                              W.Workflow, "stimulus control: a job member IS read")
        self.assertEqual(_parse(text.replace("    runs-on: x\n", "    runs-on: x\n    name: Dissent gate\n"))
                         .jobs["a"].keys["name"], "Dissent gate")

    def test_every_REFUSAL(self):
        step = "        run: python x.py\n"
        cases = {
            "a continued plain run": _MINIMAL.replace(step, step + "          --more\n"),
            "a continued job name": _MINIMAL.replace("    name: Job A\n", "    name: Dissent\n      gate\n"),
            # Red-proof survivor M13: under jobs, the structural rules refuse a continuation too; at the top level
            # the plain-scalar rule is the only one that does.
            "a continued top-level value": _MINIMAL.replace("name: W\n", "name: W\n  continued\n"),
            "a tab": _MINIMAL.replace("    runs-on", "\t  runs-on"),
            "a duplicate job": _MINIMAL + "  a:\n    runs-on: x\n",
            "a duplicate job member": _MINIMAL.replace("    runs-on", "    name: Other\n    runs-on"),
            "a duplicate step key": _MINIMAL.replace(step, step + "        run: python y.py\n"),
            "a duplicate top-level key": _MINIMAL + "name: again\n",
            "an anchor": _MINIMAL.replace("    runs-on: ubuntu-latest", "    runs-on: &r ubuntu-latest"),
            "an alias": _MINIMAL.replace("    runs-on: ubuntu-latest", "    runs-on: *r"),
            "a merge key": _MINIMAL.replace("    runs-on:", "    <<: *base\n    runs-on:"),
            "a flow job": "jobs:\n  a: {name: x}\n",
            "a flow step": _MINIMAL.replace("      - uses: actions/checkout@v5", "      - {uses: x}"),
            "compact steps at indent 4": "jobs:\n  a:\n    steps:\n    - run: x\n",
            "a document marker": "---\n" + _MINIMAL,
            "a flow env": _MINIMAL.replace("    runs-on", "    env: {A: b}\n    runs-on"),
            "an unknown block header": _MINIMAL.replace(step, "        run: |x\n"),
            "a run with no value": _MINIMAL.replace(step, "        run:\n"),
            "an odd indent under jobs": _MINIMAL.replace("    runs-on", "   runs-on"),
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(text, _MINIMAL, "stimulus control: the edit applied")
                self.assertIsInstance(_parse(text), str, f"{label}: parsed instead of refusing")

    def test_a_character_PYTHON_BREAKS_LINES_ON_and_YAML_DOES_NOT_is_refused(self):
        """Measured before the fix: `runs-on: x<U+2028>  other:` made this parser see a phantom job `other` that took the
        gate job's later steps — `shell: python` included — while YAML sees one value. Every such character, and the
        other controls YAML forbids, is refused; CRLF, where both sides agree, still parses the same."""
        hidden = "    runs-on: ubuntu-latest{}  other:\n"
        for ch in "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029\x00\x7f\ufeff":
            with self.subTest(char=hex(ord(ch))):
                text = _MINIMAL.replace("    runs-on: ubuntu-latest\n", hidden.format(ch))
                self.assertIn(ch, text, "stimulus control: the character is in the file")
                self.assertIsInstance(_parse(text), str)
        self.assertIsInstance(_parse(_MINIMAL.replace("    runs-on: ubuntu-latest\n", hidden.format(" "))),
                              W.Workflow, "control: the same line with a space parses")
        crlf = _parse(_MINIMAL.replace("\n", "\r\n"))
        self.assertIsInstance(crlf, W.Workflow)
        self.assertEqual(crlf, _parse(_MINIMAL))

    def test_a_job_NAME_whose_YAML_value_could_differ_from_its_text_is_refused(self):
        """Consult P2-3: a quoted, folded, tagged, flow or commented job name reads as not-the-context here while GitHub
        can resolve it to exactly the context — a context-named job invisible to the scan. Refused; the plain name and a
        `#` with no space before it (not a YAML comment) are the controls."""
        line = "    name: Job A\n"
        for label, form in {"single-quoted": "'Dissent gate'", "double-quoted": '"Dissent gate"',
                            "folded": ">-\n      Dissent gate", "literal": "|\n      Dissent gate",
                            "tagged": "!!str Dissent gate", "flow": "[Dissent gate]",
                            "trailing comment": "Dissent gate # the gate", "empty": ""}.items():
            with self.subTest(form=label):
                text = _MINIMAL.replace(line, f"    name: {form}\n" if form else "    name:\n")
                self.assertIsInstance(_parse(text), str, f"{label}: parsed instead of refusing")
        for ok in ("Dissent gate", "C# build", "Unit tests (py ${{ matrix.python-version }})"):
            with self.subTest(control=ok):
                self.assertEqual(_parse(_MINIMAL.replace(line, f"    name: {ok}\n")).jobs["a"].keys["name"], ok)

    def test_a_refusal_names_the_line_never_its_text(self):
        msg = _parse(_MINIMAL.replace("    runs-on: ubuntu-latest", "    runs-on: *SECRETISH"))
        self.assertIn("line 5", msg)
        self.assertNotIn("SECRETISH", msg)


class TheRunLineStartsCleanly(unittest.TestCase):
    """Board, 2026-09-28: the new run line is NOT executed live on the PR that introduces it — the old gate judges that PR
    from base — so a flag that broke interpreter start-up on a hosted runner would surface only as INSTRUMENT on the first
    PR after merge, non-waivable, wedging the repository. So the EXACT line is run here, in ordinary CI, on every
    interpreter in the matrix: taken from the workflow through the parser (never restated), with an empty environment."""

    def test_the_workflow_run_line_starts_and_refuses_on_an_empty_environment(self):
        wf = W.parse_workflow(_ROOT / GATE_YML)
        [job] = [j for j in wf.jobs.values() if j.keys.get("name") == G.CONTEXT]
        [line] = [s.keys["run"] for s in job.steps if "run" in s.keys]
        argv = line.split()
        self.assertEqual(argv[0], "python", f"stimulus control: the run line is {line!r}")
        self.assertIn("-S", argv, "stimulus control: the line under test carries the ruled flags")
        proc = subprocess.run([sys.executable] + argv[1:], cwd=_fresh(), env={}, capture_output=True, text=True,
                              timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertTrue(proc.stdout.startswith("DISSENT GATE: FAIL — INSTRUMENT — ADMIN-WAIVABLE: no"), proc.stdout)
        self.assertIn("the run's environment lacks", proc.stdout)
        self.assertNotIn("Traceback", proc.stdout + proc.stderr)
        self.assertEqual(proc.stderr, "")
        self.assertFalse((_fresh() / "scripts" / "judge" / "__pycache__").exists(), "-B: no bytecode was written")


class TheWorkflowFileKeepsItsInvariants(unittest.TestCase):
    """Static pins on .github/workflows/dissent-gate.yml — each invariant a future edit could break."""

    @classmethod
    def setUpClass(cls):
        cls.text = (_ROOT / GATE_YML).read_text(encoding="utf-8")
        cls.code = "\n".join(ln for ln in cls.text.splitlines() if not ln.lstrip().startswith("#"))

    def test_it_runs_on_pull_request_target_and_never_checks_out_the_head(self):
        self.assertIn("pull_request_target:", self.code)
        self.assertNotRegex(self.code, r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head")
        self.assertIn("persist-credentials: false", self.code)

    def test_no_attacker_controlled_field_is_interpolated_into_a_run_line(self):
        for line in self.code.splitlines():
            if re.match(r"\s*(?:- )?run:", line):
                self.assertNotIn("${{", line, f"a run line interpolates an expression: {line.strip()}")

    def test_the_PR_body_never_passes_through_env(self):
        """D2: the runner echoes the step's env into the public log."""
        self.assertNotIn("PR_BODY", self.text)
        self.assertNotIn("pull_request.body", self.code)

    def test_permissions_are_read_only_and_there_is_no_cache(self):
        self.assertRegex(self.code, r"permissions:\s*\n\s+contents: read\s*\n\s+pull-requests: read")
        self.assertNotIn("write", self.code)
        self.assertNotIn("cache", self.code)

    def test_the_JOB_LEVEL_name_is_the_context_the_ruleset_requires(self):
        """Consult A1 P1: the old pin, ``assertIn("name: Dissent gate", code)``, was satisfied by the
        WORKFLOW name on line 1 even with the job's name deleted. The literal comes from the script."""
        wf = W.parse_workflow(_ROOT / GATE_YML)
        self.assertEqual([k for k, j in wf.jobs.items() if j.keys.get("name") == G.CONTEXT], ["dissent-gate"])

    def test_the_header_says_the_log_is_public_and_where_the_safety_comes_from(self):
        """D4."""
        self.assertIn("THIS JOB'S LOG IS PUBLIC", self.text)
        self.assertIn("The safety comes from WHAT\n# IS PRINTED", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
