#!/usr/bin/env python3
"""THE ONE PARSER OF A WORKFLOW'S JOBS BLOCK — ``parse_jobs(path)``.

Extracted from ``gate_coverage._ci_jobs`` (P10d PR-1), unchanged, so that ``gate_coverage`` (the README <-> CI claims) and,
from P10d PR-2, ``dissent_gate`` (which must read its own workflow) share ONE parser rather than two copies of one grammar.
The path is a REQUIRED argument: which workflow to read is the caller's policy (``gate_coverage`` reads ``ci.yml``).

Each job, in file order, maps to its steps as ``(kind, text)``: ``run`` (a single-line command — the text is the command),
``block`` (a ``run:`` whose value is a block scalar — the text is the header, e.g. ``|``), or ``uses`` (an action reference).

⚠ BLOCK BODIES ARE CONSUMED, NOT SCANNED. A line inside a ``run: |`` body that happens to begin ``run:`` is shell text, not
a step.

⚠ NO PyYAML — the repo is stdlib-only across a 3.9-3.13 matrix. This reads THIS repository's workflow shape (two-space job
keys under a top-level ``jobs:``), not YAML in general, and says so.

⚠ STDLIB ONLY, AND ONLY ``re`` AND ``pathlib``. From P10d PR-2 this module is imported by the dissent gate, so it joins the
gate's judge set: every edit to it becomes a waiver event, and anything it imports is judged too. A ``subprocess`` or a
local import here would drag more into the judge.
"""
from __future__ import annotations

import re
from pathlib import Path

# A block scalar header: `|` or `>`, optionally with a chomping indicator and/or an indentation digit,
# in either order (`|-`, `>+`, `|2`, `>2-`, `|-2`).
_BLOCK_SCALAR = re.compile(r"^[|>](?:[+-]?\d?|\d[+-]?)$")


def parse_jobs(path: Path) -> dict[str, list[tuple[str, str]]]:
    """Every job in the workflow at ``path``, in file order, mapped to its ``(kind, text)`` steps."""
    text = path.read_text(encoding="utf-8")
    jobs: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None
    in_jobs = False
    body_indent: int | None = None     # set while consuming a block scalar's body
    for line in text.splitlines():
        if body_indent is not None:
            if not line.strip() or (len(line) - len(line.lstrip())) > body_indent:
                continue
            body_indent = None
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if not in_jobs:
            continue
        if line.strip() and not line.startswith(" "):
            break
        m = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
        if m:
            current = m.group(1)
            jobs[current] = []
            continue
        if current is None:
            continue
        r = re.match(r"^(\s*(?:- )?)run:\s*(\S.*)$", line)
        if r:
            value = r.group(2).strip()
            if _BLOCK_SCALAR.match(value):
                jobs[current].append(("block", value))
                body_indent = len(r.group(1))
            else:
                jobs[current].append(("run", value))
            continue
        u = re.match(r"^\s*(?:- )?uses:\s*(\S.*)$", line)
        if u:
            jobs[current].append(("uses", u.group(1).strip()))
    return jobs
