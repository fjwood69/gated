#!/usr/bin/env python3
"""THE ONE PARSER OF THIS REPOSITORY'S WORKFLOW FILES — ``parse_workflow(path)``, and ``parse_jobs(path)``, its projection.

Two callers share it, so there is one grammar rather than two copies of it: ``gate_coverage`` (the README <-> CI claims, which
read ``ci.yml``'s steps through ``parse_jobs``) and ``dissent_gate`` (which reads EVERY workflow through ``parse_workflow`` to
find the one job named with its required context, and derives from that job's steps the files the check executes). The path
is a REQUIRED argument: which workflow to read is the caller's policy.

``parse_jobs`` maps each job, in file order, to its steps as ``(kind, text)``: ``run`` (a single-line command — the text is the
command), ``block`` (a ``run:`` whose value is a block scalar — the text is the header, e.g. ``|``), or ``uses`` (an action
reference). ``parse_workflow`` keeps what that projection drops: the top-level keys and ``env:``, and each job's and each
step's own keys and ``env:``.

⚠ A FIXED GRAMMAR, AND WHAT DOES NOT FIT IT IS REFUSED, NEVER GUESSED. No PyYAML — the repo is stdlib-only across a 3.9-3.13
matrix. This reads THIS repository's workflow shape, not YAML in general: top-level keys at column 0; job keys at 2 under a
top-level ``jobs:``; job members at 4; steps as ``- `` items at 6 with their members at 8; ``env:`` keys two deeper than their
``env:``. A line at one of those levels that does not fit raises ``WorkflowParseError`` — so do a duplicate key, a plain
scalar continued onto a second line (a two-line job ``name:`` would otherwise be read as its first line), a flow-style job or
step, a tab in indentation, a document marker, a control or line-separator character that Python and YAML
split differently, a job-level `name:` whose YAML value could differ from its text (quoted, block, tagged,
flow or commented), and YAML anchors, aliases and merge keys (each can put a key into a mapping
that no line of it shows). Content deeper than a modelled level — ``with:``, ``strategy:``, ``on:`` — is opaque and skipped.

WHY REFUSING IS SAFE HERE: the dissent gate parses every workflow on the base branch, so a refusal there stops every later
PR. A CI test (``tests/test_dissent_gate.py``) asserts that every tracked workflow parses, so an unparseable workflow reds
the PR that introduces it and reaches the base branch only through an admin bypass. A TOLERANT parser would be worse: it
could skip the very line that names a second job with the gate's context.

⚠ BLOCK BODIES ARE CONSUMED, NOT SCANNED. A line inside a ``run: |`` body that happens to begin ``run:`` is shell text, not a
step — and the same holds for a block scalar under any key.

⚠ STDLIB ONLY: ``re``, ``pathlib`` and ``dataclasses``. The dissent gate imports this module, so it IS in the gate's judge set:
every edit to it is a waiver event, and anything it imports is judged too. A ``subprocess`` or a local import here would drag
more into the judge.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

# A block scalar header: `|` or `>`, optionally with a chomping indicator and/or an indentation digit,
# in either order (`|-`, `>+`, `|2`, `>2-`, `|-2`).
_BLOCK_SCALAR = re.compile(r"^[|>](?:[+-]?\d?|\d[+-]?)$")
# `key: value`, `key:` or `- key: value`. A colon must be followed by a space or the end of the line, as in YAML.
_KEY_LINE = re.compile(r"^( *)(- +)?([A-Za-z_][\w.-]*):(?: +(.*?))?\s*$")
# An anchor (`&a`) or alias (`*a`) where YAML reads a node: after `key: `, after `- `, or inside a flow collection.
_ANCHOR_OR_ALIAS = re.compile(r"(?:^-\s+|:\s+|[\[{,]\s*)[&*][A-Za-z0-9_]")
_MERGE_KEY = re.compile(r"(?:^|[\s{,])<<\s*:")
# ⚠ Characters Python's str.splitlines() breaks a line on and a YAML 1.2 parser does not (\v \f \x1c-\x1e \x85 U+2028
# U+2029), and the other controls YAML forbids. One of them inside a value makes this parser see a line GitHub does not — a
# phantom `  other:` job that takes the gate job's later steps with it (measured). Refused anywhere in the file, so the
# line breaks left are \n, \r and \r\n: the ones both sides agree on.
_NOT_A_YAML_CHARACTER = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufeff]")

# A job-level `name:` is read as its literal text, so any form whose YAML value differs from that text is refused:
# quoted ('Dissent gate'), a block scalar (>- folding to it), a tag (!!str), flow, or a trailing comment. Otherwise a job
# GitHub names with the gate's context could be invisible to the scan for it (consult P2-3).
_NAME_INDICATORS = "'\"|>!{[@`%"
_TRAILING_COMMENT = re.compile(r"\s#")

JOB_INDENT, MEMBER_INDENT, STEP_INDENT, STEP_MEMBER_INDENT = 2, 4, 6, 8


class WorkflowParseError(ValueError):
    """The file is outside the grammar this module reads. The message names a line number and a rule, never the line."""


@dataclass
class Step:
    keys: dict[str, str] = field(default_factory=dict)     # the step's own keys -> inline value ("" when nested)
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class Job:
    keys: dict[str, str] = field(default_factory=dict)     # the job's own keys -> inline value ("" when nested)
    env: dict[str, str] = field(default_factory=dict)
    steps: list[Step] = field(default_factory=list)


@dataclass
class Workflow:
    keys: dict[str, str] = field(default_factory=dict)     # top-level keys -> inline value ("" when nested)
    env: dict[str, str] = field(default_factory=dict)
    jobs: dict[str, Job] = field(default_factory=dict)


def _entry(key: str, value: str) -> tuple[str, str]:
    if key == "uses":
        return "uses", value
    return ("block" if _BLOCK_SCALAR.match(value) else "run"), value


def parse_jobs(path: Path) -> dict[str, list[tuple[str, str]]]:
    """Every job in the workflow at ``path``, in file order, mapped to its ``(kind, text)`` steps — a projection of
    ``parse_workflow``, not a second parse."""
    return {name: [_entry(k, v) for step in job.steps for k, v in step.keys.items() if k in ("run", "uses")]
            for name, job in parse_workflow(path).jobs.items()}


def parse_workflow(path: Path) -> Workflow:
    """The workflow at ``path``, or ``WorkflowParseError`` naming the line and the rule it breaks."""
    wf = Workflow()
    in_jobs = False
    top_section: str | None = None      # a top-level key whose value is nested (``env``, ``on``, ...)
    job: Job | None = None
    job_section: str | None = None     # a job member whose value is nested (``steps``, ``env``, ``strategy``, ...)
    step: Step | None = None
    step_section: str | None = None    # a step member whose value is nested (``env``, ``with``)
    block: int | None = None           # consuming a block scalar's body: lines indented deeper than this column
    plain: int | None = None           # after a plain value at a modelled level: a deeper line would continue it

    def refuse(n: int, rule: str) -> WorkflowParseError:
        return WorkflowParseError(f"{path.name} line {n}: {rule}")

    def put(n: int, mapping: dict[str, str], key: str, value: str) -> None:
        if key in mapping:
            raise refuse(n, f"duplicate key {key!r} — YAML would keep one of them silently")
        mapping[key] = value

    text = path.read_text(encoding="utf-8")
    bad = _NOT_A_YAML_CHARACTER.search(text)
    if bad:
        raise refuse(text.count("\n", 0, bad.start()) + 1, "a control or line-separator character — Python and YAML would "
                                                          "disagree about where lines break")
    for n, line in enumerate(text.splitlines(), start=1):
        if block is not None:
            if not line.strip() or len(line) - len(line.lstrip()) > block:
                continue
            block = None
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        lead = line[:len(line) - len(line.lstrip())]
        if lead.strip(" "):
            raise refuse(n, "indentation that is not spaces")
        ind = len(lead)
        if plain is not None:
            if ind > plain:
                raise refuse(n, "a plain scalar continued onto another line — its value would be misread")
            plain = None
        if ind == 0 and (s.startswith("---") or s.startswith("...") or s.startswith("%")):
            raise refuse(n, "a document marker or directive — one document per file")
        if _ANCHOR_OR_ALIAS.search(s) or _MERGE_KEY.search(s):
            raise refuse(n, "a YAML anchor, alias or merge key — it can add keys no line shows")
        m = _KEY_LINE.match(line)
        key = m.group(3) if m else ""
        value = (m.group(4) or "") if m else ""
        if value.startswith("#"):
            value = ""
        col = (len(m.group(1)) + len(m.group(2) or "")) if m else ind   # the key's column

        def consume_or_watch() -> None:
            nonlocal block, plain
            if value.startswith(("|", ">")):
                if not _BLOCK_SCALAR.match(value):
                    raise refuse(n, "a block scalar header this parser does not read")
                block = col
            elif value:
                plain = col

        if ind == 0:
            if not m or m.group(2):
                raise refuse(n, "a top-level line that is not a `key:`")
            put(n, wf.keys, key, value)
            job = step = None
            job_section = step_section = None
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
                continue
            if key == "jobs":
                raise refuse(n, "`jobs:` must open a block")
            in_jobs = False
            top_section = None if value else key
            consume_or_watch()
            continue

        if not in_jobs:
            if top_section == "env":
                if ind != 2 or not m or m.group(2) or not value:
                    raise refuse(n, "a top-level `env:` entry that is not `NAME: value` at indent 2")
                put(n, wf.env, key, value)
                consume_or_watch()
            elif m and value.startswith(("|", ">")):
                consume_or_watch()            # opaque, but its body is still not scanned
            continue

        if ind == JOB_INDENT:
            if not m or m.group(2) or value or not re.match(r"^[A-Za-z_][\w-]*$", key):
                raise refuse(n, "a job that is not `<id>:` opening a block at indent 2")
            if key in wf.jobs:
                raise refuse(n, f"duplicate job id {key!r}")
            job = wf.jobs[key] = Job()
            job_section = step_section = None
            step = None
            continue
        if job is None or ind < MEMBER_INDENT:
            raise refuse(n, "content under `jobs:` that is neither a job at indent 2 nor inside one")
        if ind == MEMBER_INDENT:
            if not m or m.group(2):
                raise refuse(n, "a job member that is not `key:` at indent 4")
            put(n, job.keys, key, value)
            if key == "name" and (not value or value[0] in _NAME_INDICATORS or _TRAILING_COMMENT.search(value)):
                raise refuse(n, "a job name: that is empty, quoted, a block scalar, tagged, flow-style or carries a "
                                "comment — the name GitHub resolves could differ from the text read here")
            step = None
            step_section = None
            if key in ("steps", "env") and value:
                raise refuse(n, f"`{key}:` must open a block — a flow or expression form is not read")
            job_section = None if value else key
            consume_or_watch()
            continue
        if job_section is None:
            raise refuse(n, "content under a job member that has an inline value")
        if job_section == "env":
            if ind != MEMBER_INDENT + 2 or not m or m.group(2) or not value:
                raise refuse(n, "a job `env:` entry that is not `NAME: value` at indent 6")
            put(n, job.env, key, value)
            consume_or_watch()
            continue
        if job_section != "steps":
            if m and value.startswith(("|", ">")):
                consume_or_watch()            # opaque (``strategy:``, ``permissions:``), body not scanned
            continue

        if ind == STEP_INDENT:
            if not m or not m.group(2) or len(m.group(2)) != 2:
                raise refuse(n, "a step that is not `- key:` at indent 6")
            step = Step()
            job.steps.append(step)
        elif ind == STEP_MEMBER_INDENT:
            if step is None or not m or m.group(2):
                raise refuse(n, "a step member that is not `key:` at indent 8")
        elif ind > STEP_MEMBER_INDENT and step is not None:
            if step_section == "env":
                if ind != STEP_MEMBER_INDENT + 2 or not m or m.group(2) or not value:
                    raise refuse(n, "a step `env:` entry that is not `NAME: value` at indent 10")
                put(n, step.env, key, value)
                consume_or_watch()
            elif step_section is None:
                raise refuse(n, "content under a step member that has an inline value")
            elif m and value.startswith(("|", ">")):
                consume_or_watch()            # opaque (``with:``), body not scanned
            continue
        else:
            raise refuse(n, "a line under `steps:` at an indent this parser does not read")
        assert step is not None and m is not None
        put(n, step.keys, key, value)
        if key == "env" and value:
            raise refuse(n, "a step `env:` must open a block — a flow or expression form is not read")
        if key in ("run", "uses") and not value:
            raise refuse(n, f"`{key}:` with no inline value")
        step_section = None if value else key
        consume_or_watch()
    return wf
