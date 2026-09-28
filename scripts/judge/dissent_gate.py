#!/usr/bin/env python3
"""The process gate: nothing merges into ``main`` unless a dissent-typed board entry, under the key the
PR cites, names the exact head being merged.

WHAT THIS CANNOT DO, STATED FIRST. Local commit ordering cannot be enforced in a repository the builder
controls: a hook is local, advisory, and bypassable by the party it constrains. What CAN be enforced is
PROMOTION — what becomes authoritative. This gate governs that and nothing else.

THE HONEST LIMIT. The reference and the board entry are both written by the builder. The gate converts
FORGETTING into HAVING TO STATE SOMETHING FALSE. It closes omission; it does not close deception. It
verifies that a dissent-typed entry exists naming this head; it does not verify that the entry's content
is a real dissent.

WHY THE ENTRY IS TYPED. The ordinary workflow already writes board entries that name a head before any
dissent ("built, awaiting dissent @ <sha>"). A gate that searched an entry for the SHA would pass #49's
commit-before-dissent without anyone stating anything false. So the entry must be an object with
``kind == "dissent"`` and ``head`` EQUAL to the PR head; prose is untyped and is never searched. The
schema is in the private ways-of-working document; writers post one canonical shape (the object).

THE JUDGE, DERIVED. The check runs from the base branch, so a PR cannot change the code that judges it —
but it can change that code for every LATER PR. So a PR that changes the judge is ``WORKFLOW_TOUCHED``:
red, and waivable only by an admin ruling, which leaves every change to the judge as a logged bypass.
The judge is DERIVED from base on every run, never listed: the one job, across the tracked workflows,
whose job-level ``name:`` is ``CONTEXT``; the directory its script runs from (``scripts/judge/``); and
every path under that directory. It is bounded by a DIRECTORY, not an import closure: the interpreter
searches the script's directory first, and the standard library's own internal imports never appear in
the judge's source, so anything placed there can run inside the gate (see ``derive_judge``). Anything
the derivation cannot bound is refused (``INSTRUMENT``), never resolved to an empty or partial judge: an
empty one would send every change to the judge down the ordinary path, the dangerous direction.
Everything else, ``ci.yml`` included, takes the ordinary dissent.

THE DESIGN PRESSURE. Every module this script imports from its directory is part of the judge, and every
edit to it is a waiver event. That is correct, and it is the reason to keep the gate stdlib-only. The
one deliberate exception is ``workflow_steps.py``, the repository's one workflow parser: the gate must
read its own workflow, and a second parser here would be a second copy of one grammar.

TWO BOUNDARIES, STATED. (1) A PR that adds a second ``pull_request_target`` workflow is not a judge file,
so it takes the ordinary dissent; once merged, that workflow receives the repository's secrets,
``BOARD_BASE`` included, and the review is the only thing in front of it. (2) THE WEDGE: a job given the
context name in ANY workflow merges through the ordinary path — and from that base the derivation finds
two, so every later PR is ``INSTRUMENT``, which is not waivable; recovery is an admin bypass of a
non-waivable verdict. The ordinary test suite derives the judge on each PR's own tree (the correlated
positive in ``tests/test_dissent_gate.py``), so the PR that would wedge reds a required check — unless
the same PR edits that test, because the PR's tests run from its head: what catches that is the board
reading the diff, not a mechanism. The dissent checklist asks "does this PR add or rename a job to the
required context name?". A job-level ``name:`` that is quoted, a block scalar or carries a comment is
refused by the parser, so a context-named job cannot hide from the scan that way. An expression-named job (a matrix value evaluating to the context) evades the textual
scan; a matrix on the gate's own job would change its context to ``Dissent gate (…)``.

THE SHAPE OF THIS FILE. ``evaluate`` is a pure function over the head and five injected probes (the PR
body, the judge, the changed files, ancestry, the board), so every rule is tested offline. ``main``
is the only I/O. THE HEAD COMES FROM THE EVENT AND THE BODY FROM THE API, DELIBERATELY: the head is the
commit the check attaches to and the one the ruleset evaluates, so it must be the event's; the body is
fetched so that it never passes through the step's ``env:``, which the runner echoes into a public log.
Do not "fix" the asymmetry by fetching the head too. THIS SCRIPT prints nothing it was handed — not the
PR body, not the board URL, not an entry's content; what it prints is built from its own codes, the
verified key and head (both already public in the PR body), and ``repr()`` of file paths.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from workflow_steps import WorkflowParseError, parse_workflow

_ROOT = Path(__file__).resolve().parents[2]   # scripts/judge/dissent_gate.py -> the checkout root
CONTEXT = "Dissent gate"               # the required status check — the job-level name that identifies this check
WORKFLOWS_DIR = Path(".github") / "workflows"

# ⚠ THE ENV CONTRACT. Every name this script reads, all REQUIRED, checked first in ``main`` — a missing or
# empty one is INSTRUMENT naming it, never a traceback and never a default. The runner provides
# ``GITHUB_REPOSITORY``; the step's ``env:`` supplies the rest. Pinned both ways by the tests: the names
# read equal this tuple, and the workflow supplies exactly this tuple minus the runner's.
REQUIRED_ENV = ("GITHUB_REPOSITORY", "GITHUB_TOKEN", "PR_NUMBER", "HEAD_SHA", "HEAD_REPO", "BASE_REPO", "BOARD_BASE")
RUNNER_PROVIDED = ("GITHUB_REPOSITORY",)

_KEY = r"[a-z0-9][a-z0-9-]{2,127}"
_SHA = r"[0-9a-f]{40}"
_REF = re.compile(rf"^Dissent-Ref: board=({_KEY}) head=({_SHA})(?: prior=({_KEY})@({_SHA}))?\s*$")
_PREFIX = "Dissent-Ref:"
_REF_GRAMMAR = "Dissent-Ref: board=<key> head=<40-hex sha> [prior=<key>@<40-hex sha>]"

MISSING = "MISSING"
MALFORMED = "MALFORMED"
HEAD_MISMATCH = "HEAD_MISMATCH"
PRIOR_NOT_ANCESTOR = "PRIOR_NOT_ANCESTOR"
INSTRUMENT = "INSTRUMENT"
BOARD_ENTRY_MISSING = "BOARD_ENTRY_MISSING"
BOARD_NOT_A_DISSENT = "BOARD_NOT_A_DISSENT"
FORK_UNVERIFIED = "FORK_UNVERIFIED"
WORKFLOW_TOUCHED = "WORKFLOW_TOUCHED"
# ALL_CODES is derived at the END of this module: every module-level string whose value equals its name.

ABSENT = object()   # what a board fetch returns for a key that does not exist (a 404)

# ── What the derivation follows, and nothing else. A key, command, import or name outside these is REFUSED. ──
# Each set is the model's vocabulary, not a roster of the repo: widening one is an edit to the judge, i.e. a waiver.
_JOB_KEYS = frozenset({"name", "runs-on", "steps", "permissions", "timeout-minutes", "env"})
_STEP_KEYS = frozenset({"name", "id", "uses", "with", "run", "env"})
# The ONE run shape: `python`, exactly `-E -s -S -B` in that order, one script. Each flag closes one door, and each is kept
# even where another covers it, so that an edit removing one flag cannot silently remove another's cover:
#   -E  ignores PYTHON* variables — a floating action can write them to GITHUB_ENV for this step;
#   -s  drops the user site — redundant under -S (the user site is added by `site`), kept so it stands alone;
#   -S  skips `site` entirely — no sitecustomize or .pth file from the interpreter's SYSTEM site-packages runs before the
#       gate (a floating action could drop one there, the same threat as GITHUB_ENV); the gate imports nothing third-party;
#   -B  writes no bytecode, so the judge directory is required to hold source only.
# Not -I: it removes the script's directory from sys.path, and putting it back leaves a slot for any module name the
# standard library tries and does not provide on this platform. The start-up test in tests/test_dissent_gate.py runs this
# exact line, taken from the workflow, on every interpreter in the CI matrix.
_RUN = re.compile(r"^python -E -s -S -B ([A-Za-z0-9_][A-Za-z0-9_./-]*\.py)$")
_EXTERNAL_ACTION = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[A-Za-z0-9_.-]+$")
_STDLIB = frozenset({"__future__", "ast", "dataclasses", "json", "os", "pathlib", "re", "sys", "typing",
                     "urllib.error", "urllib.parse", "urllib.request"})
_MODULE_ATTRS = {"os": frozenset({"environ"}), "sys": frozenset({"exit"})}
# `globals` is not refused as a name — ALL_CODES is derived from it — but a SUBSCRIPT of `globals()` is: that is the
# string-keyed path to anything (`globals()["os"].system`), which no Name or Attribute check would see.
_DYNAMIC_NAMES = frozenset({"exec", "eval", "compile", "__import__", "getattr", "setattr", "delattr", "locals",
                            "vars", "breakpoint", "__builtins__"})
_DYNAMIC_ATTRS = frozenset({"__builtins__", "__dict__", "__globals__", "__code__", "__class__", "__mro__", "__bases__",
                            "__base__", "__subclasses__"})


class InstrumentError(Exception):
    """A probe could not answer. Never a pass: an unanswered question is not a 'no'."""


@dataclass(frozen=True)
class Ref:
    board: str
    head: str
    prior_key: str | None = None
    prior_head: str | None = None


@dataclass
class Verdict:
    failures: list[tuple[str, str]] = field(default_factory=list)
    ref: Ref | None = None             # the reference that was verified — what a PASS line names

    def fail(self, code: str, message: str) -> None:
        self.failures.append((code, message))

    @property
    def passed(self) -> bool:
        return not self.failures and self.ref is not None

    @property
    def codes(self) -> list[str]:
        return [c for c, _ in self.failures]

    @property
    def admin_waivable(self) -> bool:
        """True ONLY when WORKFLOW_TOUCHED is the sole failure. An admin override of a change to the judge
        is never permission to merge with a missing, malformed or mismatched Dissent-Ref (board, item
        10) — so the verdict says which case it is, and the ruling is made on the whole of it."""
        return self.codes == [WORKFLOW_TOUCHED]


def parse_ref(body: str | None) -> tuple[Ref | None, list[tuple[str, str]]]:
    """The one ``Dissent-Ref:`` line: at column 0, outside any code fence, exactly once.

    ⚠ MESSAGES NAME A LINE NUMBER AND A RULE, NEVER THE LINE'S TEXT. The body is attacker-controlled
    in a public repository, and a runner interprets output lines beginning ``::`` as workflow commands.
    Printing nothing from the body closes that path outright rather than escaping it.
    """
    found: list[tuple[int, str]] = []
    in_fence = False
    for n, line in enumerate((body or "").splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue
        if not in_fence and line.startswith(_PREFIX):
            found.append((n, line))
    if not found:
        return None, [(MISSING, "no Dissent-Ref line at column 0 outside a code fence")]
    if len(found) > 1:
        lines = ", ".join(str(n) for n, _ in found)
        return None, [(MALFORMED, f"{len(found)} Dissent-Ref lines (lines {lines}) — exactly one is allowed")]
    n, line = found[0]
    if "://" in line:
        return None, [(MALFORMED, f"line {n}: the board reference is a URL — it must be a key, and the "
                                  f"board's address must never appear in a public PR")]
    m = _REF.match(line)
    if not m:
        return None, [(MALFORMED, f"line {n}: does not match '{_REF_GRAMMAR}' (full lowercase SHAs; keys a-z 0-9 -)")]
    return Ref(m.group(1), m.group(2), m.group(3), m.group(4)), []


def as_dissent(envelope: object) -> dict | str:
    """Unwrap the board Worker's envelope and return the dissent object — or a reason it is not one.

    The Worker returns ``{"key", "updated_at", "value": <posted body>}`` and writers post
    ``{"value": <dissent object>}``, so the entry is ``envelope["value"]["value"]``. That value may be an
    object or a JSON string that parses to one; anything else is UNTYPED and is never searched.
    """
    try:
        value = envelope["value"]["value"]            # type: ignore[index]
    except (TypeError, KeyError):
        return "the board response does not have the envelope shape {value: {value: ...}}"
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return "the entry is prose, not a dissent object — untyped, and never searched"
    if not isinstance(value, dict):
        return "the entry is not an object — untyped"
    if value.get("kind") != "dissent":
        return "the entry's kind is not 'dissent'"
    return value


# ── The judge ─────────────────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Judge:
    """What this check executes: ``files`` (the workflow and every file in the judge directories) and ``dirs`` (each
    directory a judged script runs from — its ``sys.path[0]``). A PR changing any path in ``files`` OR any path under a
    directory in ``dirs`` — a NEW file there included — touches the judge."""
    files: frozenset[str]
    dirs: frozenset[str]

    def covers(self, path: str) -> bool:
        return path in self.files or any(path == d or path.startswith(d + "/") for d in self.dirs)


def derive_judge(root: Path) -> Judge:
    """The judge, derived from ``root`` (the base checkout). Raises ``InstrumentError`` rather than return one it cannot
    stand behind.

    ⚠ THE JUDGE IS BOUNDED BY A DIRECTORY, NOT BY AN IMPORT CLOSURE (board, 2026-09-28). `python <dir>/<script>.py` puts
    ``<dir>`` FIRST on sys.path, ahead of the standard library, and the standard library's OWN internal imports — about 80
    names on 3.13 (functools, enum, collections, typing ...) — never appear in the judge's source. Measured: a
    ``scripts/functools.py`` imported by no judge file executed inside the gate, at interpreter start-up, before a line of
    it ran — holding ``BOARD_BASE`` and the token. So the judge is everything the interpreter can load from that directory,
    and the rule is: the directory holds NOTHING but source files the closure reaches. Any other entry — a ``.py`` nobody
    imports, a package or any subdirectory, a ``__pycache__``, a ``.pyc``, an extension module, a symlink — is refused. The
    predicate (``Judge.covers``) covers every path under the directory, so ADDING a file there is itself a change to the
    judge: the only protection a PR cannot edit is this base-side check, because the PR's own tests run from its head and
    a shadow runs before the gate's code does.

    Refused as well: a workflow the parser cannot read (every workflow must parse — a CI test keeps them so); zero or two
    jobs named ``CONTEXT``; and, IN THE CONTEXT JOB AND ITS WORKFLOW ONLY (other workflows' jobs are not the judge, and are
    read for nothing but their names): a workflow ``defaults:``; a job or step key the model does not follow (``shell:``,
    ``working-directory:``, ``if:``, ``container:`` ...); an ``env:`` name, at any level, that is not in ``REQUIRED_ENV``;
    a ``run:`` that is not exactly ``python -E -s -S -B <script>.py``; a local action; a script at the repository root; and,
    in any judged Python file, a relative or dotted local import, an import outside the standard modules named in
    ``_STDLIB`` that does not resolve in the judge directory, ``os``/``sys`` attributes other than those in
    ``_MODULE_ATTRS``, the dynamic names and attributes in ``_DYNAMIC_*``, and a subscript of ``globals()``. A judge with no repository file beyond the
    workflow is refused too: a judge that executes nothing is not a judge.

    ⚠ "TRACKED" MEANS "PRESENT IN THE CHECKOUT". This runs on a fresh base checkout, which holds tracked files only, and the
    gate runs with -B, so it writes no ``__pycache__`` of its own; it spawns no process, so it does not ask git. A COMMITTED
    ``.pyc`` (PEP 552 unchecked-hash bytecode runs without its source being read) is refused twice: here, as an entry in
    the judge directory, and by the required ``Repo hygiene`` check, which refuses any tracked ``__pycache__/`` or ``*.pyc``.

    ⚠ A STATIC SCAN BOUNDS THE PLAIN FORMS. Obfuscated execution inside a judge file is outside what it can see — and a judge
    file changes only through a waiver, which is the review this derivation exists to force.
    """
    wdir = root / WORKFLOWS_DIR
    try:
        workflows = sorted(p for p in wdir.iterdir() if p.suffix in (".yml", ".yaml"))
    except OSError as exc:
        raise InstrumentError(f"cannot list {WORKFLOWS_DIR.as_posix()}: {type(exc).__name__}") from None
    found = []
    for path in workflows:
        rel = _checked(root, path.relative_to(root).as_posix())
        try:
            wf = parse_workflow(path)
        except (WorkflowParseError, OSError, UnicodeDecodeError) as exc:
            raise InstrumentError(f"{rel!r} does not parse ({exc}) — every workflow must") from None
        found += [(rel, wf, job) for job in wf.jobs.values() if job.keys.get("name") == CONTEXT]
    if len(found) != 1:
        raise InstrumentError(f"{len(found)} jobs are named {CONTEXT!r} across the workflows — exactly one "
                              f"defines this check")
    rel, wf, job = found[0]
    if "defaults" in wf.keys:
        raise InstrumentError(f"{rel!r} sets `defaults:` — it can change how every run step executes")
    extra = sorted(set(job.keys) - _JOB_KEYS)
    if extra:
        raise InstrumentError(f"the {CONTEXT!r} job uses {extra} — keys this derivation does not follow")
    scripts = []
    for i, step in enumerate(job.steps, start=1):
        extra = sorted(set(step.keys) - _STEP_KEYS)
        if extra:
            raise InstrumentError(f"step {i} of the {CONTEXT!r} job uses {extra} — keys this derivation does "
                                  f"not follow")
        if ("run" in step.keys) == ("uses" in step.keys):
            raise InstrumentError(f"step {i} of the {CONTEXT!r} job must have exactly one of run: / uses:")
        if "uses" in step.keys:
            if not _EXTERNAL_ACTION.match(step.keys["uses"]):
                raise InstrumentError(f"step {i} of the {CONTEXT!r} job uses a local or unrecognised action")
            continue
        m = _RUN.match(step.keys["run"])
        if not m or ".." in m.group(1).split("/"):
            raise InstrumentError(f"step {i} of the {CONTEXT!r} job runs something other than "
                                  f"`python -E -s -S -B <script>.py` — refused, not modelled")
        if "/" not in m.group(1):
            raise InstrumentError(f"step {i} of the {CONTEXT!r} job runs a script at the repository root — the "
                                  f"whole checkout would be its judge directory")
        scripts.append(_checked(root, m.group(1)))
    for scope, env in [("the workflow", wf.env), ("the job", job.env)] + [(f"step {i}", s.env) for i, s in
                                                                         enumerate(job.steps, start=1)]:
        stray = sorted(set(env) - set(REQUIRED_ENV))
        if stray:
            raise InstrumentError(f"{scope} sets {stray} for the {CONTEXT!r} job — not names this script reads")
    if not scripts:
        raise InstrumentError(f"the {CONTEXT!r} job executes no repository file")
    files, dirs = {rel}, set()
    for script in scripts:
        closure = _python_closure(root, script)
        directory = script.rsplit("/", 1)[0]
        _only_the_closure(root, directory, closure)
        files |= closure
        dirs.add(directory)
    return Judge(frozenset(files), frozenset(dirs))


def _checked(root: Path, rel: str) -> str:
    """``rel`` if it names a regular file inside ``root`` reached through no symlink; else INSTRUMENT."""
    path = root / rel
    if not path.is_file() or path.resolve() != root.resolve() / rel:
        raise InstrumentError(f"{rel!r} is not a regular file in the checkout, or a symlink is on its path")
    return rel


def _only_the_closure(root: Path, directory: str, closure: set[str]) -> None:
    """The judge directory holds exactly the closure's files: every entry a regular file the closure reaches. Anything else in the directory the interpreter searches first could be loaded in place of a module."""
    try:
        entries = sorted((root / directory).iterdir())
    except OSError as exc:
        raise InstrumentError(f"cannot list the judge directory {directory!r}: {type(exc).__name__}") from None
    for entry in entries:
        rel = entry.relative_to(root).as_posix()
        # A symlink needs no term of its own: one the closure imports is refused by ``_checked`` on the import path, and
        # one it does not is not in the closure.
        if not entry.is_file() or rel not in closure:
            raise InstrumentError(f"the judge directory {directory!r} holds {rel!r}, which is not a source file the "
                                  f"judge imports — it could be loaded in place of a module; refused")


def _python_closure(root: Path, script: str) -> set[str]:
    """``script`` and every judge-directory module it imports, transitively — resolved, as Python does for a script,
    against the SCRIPT'S directory (``sys.path[0]``) for every module in the closure."""
    base = (root / script).parent
    seen: set[str] = set()
    todo = [script]
    while todo:
        rel = todo.pop()
        if rel in seen:
            continue
        seen.add(rel)
        tree = _python_source(root / _checked(root, rel), rel)
        for dotted in _imports(tree, rel):
            for path in _resolve(base, dotted, rel):
                todo.append(path.relative_to(root).as_posix())
    return seen


def _python_source(path: Path, rel: str) -> ast.Module:
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=rel)
    except (SyntaxError, ValueError, OSError) as exc:
        raise InstrumentError(f"{rel!r} does not parse as Python ({type(exc).__name__})") from None


def _imports(tree: ast.Module, rel: str) -> list[str]:
    """Every module ``tree`` imports; refuses what the import graph cannot bound."""
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _MODULE_ATTRS and alias.asname:
                    raise InstrumentError(f"{rel!r} imports {alias.name!r} under another name")
                out.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                raise InstrumentError(f"{rel!r} has a relative import — refused, not modelled")
            names = {a.name for a in node.names}
            allowed = _MODULE_ATTRS.get(node.module)
            if allowed is not None and not names <= allowed:
                raise InstrumentError(f"{rel!r} imports {sorted(names - allowed)} from {node.module!r}")
            out.append(node.module)
        elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call) \
                and isinstance(node.value.func, ast.Name) and node.value.func.id == "globals":
            raise InstrumentError(f"{rel!r} subscripts globals() — execution the import graph cannot bound")
        elif isinstance(node, ast.Name) and node.id in _DYNAMIC_NAMES:
            raise InstrumentError(f"{rel!r} uses {node.id!r} — execution the import graph cannot bound")
        elif isinstance(node, ast.Attribute):
            if node.attr in _DYNAMIC_ATTRS:
                raise InstrumentError(f"{rel!r} uses {node.attr!r} — execution the import graph cannot bound")
            if isinstance(node.value, ast.Name) and node.value.id in _MODULE_ATTRS \
                    and node.attr not in _MODULE_ATTRS[node.value.id]:
                raise InstrumentError(f"{rel!r} uses {node.value.id}.{node.attr} — not an attribute this "
                                      f"derivation allows")
    return out


def _resolve(base: Path, dotted: str, rel: str) -> list[Path]:
    """The judge-directory file an import executes, or ``[]`` for an allowed standard module. A local module is a plain
    ``<name>.py`` in the judge directory — packages are refused (the directory holds no subdirectory at all)."""
    top, _, rest = dotted.partition(".")
    module = base / f"{top}.py"
    if module.is_file():
        if rest:
            raise InstrumentError(f"{rel!r} imports {dotted!r}, beneath the local module {top!r}")
        return [module]
    if (base / top).exists():
        raise InstrumentError(f"{rel!r} imports {dotted!r}, and {top!r} in the judge directory is not a module file")
    if dotted not in _STDLIB:
        raise InstrumentError(f"{rel!r} imports {dotted!r} — neither a judge-directory module nor a standard module "
                              f"this derivation allows")
    return []


# ── The rules ─────────────────────────────────────────────────────────────────────────────────────────
def evaluate(head_sha: str, *, same_repo: bool,
             fetch_body: Callable[[], str | None],
             judge: Callable[[], Judge],
             changed_paths: Callable[[], list[str]],
             is_ancestor: Callable[[str, str], bool],
             fetch_entry: Callable[[str], object]) -> Verdict:
    """Every rule, every code — evaluated in full, never first-failure-only."""
    v = Verdict()

    derived: Judge | None = None
    paths: list[str] | None = None
    try:
        derived = judge()
    except InstrumentError as exc:
        v.fail(INSTRUMENT, f"could not derive the judge: {exc}")
    try:
        paths = changed_paths()
    except InstrumentError as exc:
        v.fail(INSTRUMENT, f"could not list the PR's changed files: {exc}")
    touched = sorted(p for p in set(paths) if derived.covers(p)) if derived is not None and paths is not None else []
    if touched:
        # ⚠ repr(), NOT THE RAW NAME: a path is attacker-controlled in a fork PR, and git allows a newline
        # in a filename — a raw name could start an output line with '::' and become a workflow command.
        v.fail(WORKFLOW_TOUCHED, f"the PR changes {len(touched)} path(s) of the judge — what this check executes from base "
                                 f"({', '.join(repr(p) for p in touched[:5])}{' …' if len(touched) > 5 else ''}) "
                                 f"— a PR cannot vouch for the gate that judges it; admin ruling")

    try:
        body = fetch_body()
    except InstrumentError as exc:
        # Not also MISSING: a body that could not be read is not a body without a reference.
        v.fail(INSTRUMENT, f"could not read the PR body: {exc}")
        return v
    ref, errs = parse_ref(body)
    for code, msg in errs:
        v.fail(code, msg)
    if ref is None:
        return v
    v.ref = ref

    if ref.head != head_sha:
        v.fail(HEAD_MISMATCH, f"the reference names {ref.head} but the PR head is {head_sha} — the dissent "
                              f"covers an earlier head; re-dissent on this one")

    if ref.prior_head is not None:
        try:
            if not is_ancestor(ref.prior_head, head_sha):
                v.fail(PRIOR_NOT_ANCESTOR, f"prior {ref.prior_head} is not an ancestor of head {head_sha} "
                                           f"(rebase or force-push) — an incremental dissent cannot cover "
                                           f"this; full re-dissent")
        except InstrumentError as exc:
            v.fail(INSTRUMENT, f"could not establish ancestry of the prior: {exc}")

    if not same_repo:
        v.fail(FORK_UNVERIFIED, "the PR comes from a fork; the board is never queried for a fork PR "
                                "(it would expose the board to anyone who can open one) — admin ruling")
        return v

    _check_entry(v, ref.board, expect_head=ref.head,
                 expect_prior=None if ref.prior_key is None else f"{ref.prior_key}@{ref.prior_head}",
                 fetch_entry=fetch_entry, role="the cited entry")
    if ref.prior_key is not None and ref.prior_head is not None:
        _check_entry(v, ref.prior_key, expect_head=ref.prior_head, expect_prior=ABSENT,
                     fetch_entry=fetch_entry, role="the prior entry")
    return v


def _check_entry(v: Verdict, key: str, *, expect_head: str, expect_prior: object,
                 fetch_entry: Callable[[str], object], role: str) -> None:
    try:
        envelope = fetch_entry(key)
    except InstrumentError as exc:
        v.fail(INSTRUMENT, f"could not read {role} {key!r} from the board: {exc}")
        return
    if envelope is ABSENT:
        v.fail(BOARD_ENTRY_MISSING, f"{role} {key!r} does not exist on the board")
        return
    entry = as_dissent(envelope)
    if isinstance(entry, str):
        v.fail(BOARD_NOT_A_DISSENT, f"{role} {key!r}: {entry}")
        return
    if entry.get("head") != expect_head:
        v.fail(BOARD_NOT_A_DISSENT, f"{role} {key!r} is a dissent on a different head (compared by "
                                    f"equality) — expected {expect_head}")
    if expect_prior is not ABSENT and entry.get("prior") != expect_prior:
        # The entry's own `prior` is NOT printed — an entry's content is never echoed; the PR's prior (public, and
        # matched against the reference grammar) is.
        v.fail(BOARD_NOT_A_DISSENT, f"{role} {key!r} cites a prior other than the PR's reference, which cites "
                                    f"{expect_prior!r}")


def render(v: Verdict) -> str:
    """The job's output. Built only from codes and messages this module wrote, and the verified reference
    — whose key and SHAs matched a grammar of ``[a-z0-9-]`` and hex — never from input text."""
    if v.passed and v.ref is not None:
        r = v.ref
        prior = f" prior={r.prior_key}@{r.prior_head}" if r.prior_key is not None else ""
        return f"DISSENT GATE: PASS — board={r.board} head={r.head}{prior} — a dissent-typed board entry names this exact head."
    lines = [f"DISSENT GATE: FAIL — {', '.join(v.codes)} — ADMIN-WAIVABLE: "
             f"{'yes (WORKFLOW_TOUCHED only)' if v.admin_waivable else 'no'}"]
    lines += [f"  {code}: {msg}" for code, msg in v.failures]
    return "\n".join(lines)


# ── I/O: the only part that touches the network. Nothing here echoes what it reads. ──────────────────
Getter = Callable[[str, "dict[str, str]"], "tuple[int, bytes, dict[str, str]]"]
_NEXT = re.compile(r'<([^>]+)>\s*;\s*rel="next"')
_API = "https://api.github.com/"
_MAX_FILES = 3000       # GitHub's cap on the PR-files endpoint: a list this long may be truncated


def _get(url: str, headers: dict[str, str]) -> tuple[int, bytes, dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": "gated-dissent-gate/1", **headers})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read(), {"Link": r.headers.get("Link") or ""}
    except urllib.error.HTTPError as exc:
        return exc.code, b"", {}
    except (urllib.error.URLError, OSError) as exc:
        raise InstrumentError(type(exc).__name__) from None


def _json(raw: bytes, what: str) -> object:
    try:
        return json.loads(raw)
    except ValueError:
        raise InstrumentError(f"{what} returned a body that is not JSON") from None


def read_env(environ: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    """The run's configuration: every name in ``REQUIRED_ENV``, and the ones missing or empty."""
    missing = [name for name in REQUIRED_ENV if not environ.get(name)]
    return {name: environ[name] for name in REQUIRED_ENV if name not in missing}, missing


def main(environ: Mapping[str, str] | None = None, *, get: Getter = _get, root: Path = _ROOT) -> int:
    cfg, missing = read_env(os.environ if environ is None else environ)
    if missing:
        v = Verdict()
        v.fail(INSTRUMENT, f"the run's environment lacks {', '.join(missing)} — every name this script "
                           f"reads is required, and checked before anything else runs")
        print(render(v))
        return 1
    gh = {"Authorization": f"Bearer {cfg['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json"}
    api = f"{_API}repos/{cfg['GITHUB_REPOSITORY']}"
    pr = cfg["PR_NUMBER"]

    def fetch_body() -> str | None:
        status, raw, _ = get(f"{api}/pulls/{pr}", gh)
        if status != 200:
            raise InstrumentError(f"the PR returned HTTP {status}")
        data = _json(raw, "the PR")
        if not isinstance(data, dict) or "body" not in data \
                or not (data["body"] is None or isinstance(data["body"], str)):
            raise InstrumentError("the PR response has no body field of the expected type")
        return data["body"]

    def changed_paths() -> list[str]:
        """Every changed path — and a rename's or copy's ``previous_filename``, so renaming a judge file
        away is still a change to it. Follows ``Link: rel="next"`` to the end, never assuming a page size."""
        out: list[str] = []
        files = 0
        url: str | None = f"{api}/pulls/{pr}/files?per_page=100"
        while url is not None:
            if not url.startswith(_API):
                raise InstrumentError("a pagination link leaves the API host — not followed with the token")
            status, raw, headers = get(url, gh)
            if status != 200:
                raise InstrumentError(f"PR files returned HTTP {status}")
            batch = _json(raw, "PR files")
            if not isinstance(batch, list):
                raise InstrumentError("PR files returned something other than a list")
            for f in batch:
                if not isinstance(f, dict) or not isinstance(f.get("filename"), str) \
                        or not isinstance(f.get("previous_filename", ""), str):
                    raise InstrumentError("a PR file entry has no filename of the expected type")
                out.append(f["filename"])
                if "previous_filename" in f:
                    out.append(f["previous_filename"])
            files += len(batch)
            if files >= _MAX_FILES:
                raise InstrumentError(f"PR files reached {_MAX_FILES} — the list may be truncated, so it is "
                                      f"not an answer")
            nxt = _NEXT.search(headers.get("Link", ""))
            url = nxt.group(1) if nxt else None
        return out

    def is_ancestor(old: str, new: str) -> bool:
        status, raw, _ = get(f"{api}/compare/{old}...{new}", gh)
        if status != 200:
            raise InstrumentError(f"compare returned HTTP {status}")
        data = _json(raw, "compare")
        if not isinstance(data, dict):
            raise InstrumentError("compare returned something other than an object")
        return data.get("status") in ("ahead", "identical")

    def fetch_entry(key: str) -> object:
        status, raw, _ = get(f"{cfg['BOARD_BASE'].rstrip('/')}/state/{urllib.parse.quote(key)}", {})
        if status == 404:
            return ABSENT
        if status != 200:
            raise InstrumentError(f"board returned HTTP {status}")   # the status, never the body or URL
        return _json(raw, "board")

    verdict = evaluate(cfg["HEAD_SHA"], same_repo=cfg["HEAD_REPO"] == cfg["BASE_REPO"],
                       fetch_body=fetch_body, judge=lambda: derive_judge(root),
                       changed_paths=changed_paths, is_ancestor=is_ancestor, fetch_entry=fetch_entry)
    print(render(verdict))
    return 0 if verdict.passed else 1


# ⚠ DERIVED, AND LAST, so a code defined anywhere above is in it: a module-level string whose value is its
# own name. A typo'd value ("HEAD_MISMTACH") drops the constant out, and the tests' use/arg pins then red.
ALL_CODES = frozenset(v for k, v in list(globals().items()) if isinstance(v, str) and k == v)


if __name__ == "__main__":
    sys.exit(main())
