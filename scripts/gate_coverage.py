#!/usr/bin/env python3
"""THE ONE READER FOR ``scripts/gate_coverage.json`` — the roster every gate derives from.

⚠ ONE READER, MANY CONSUMERS, AND THAT IS THE WHOLE POINT. Two enumerations of one conceptual
set is the shape this tree has met repeatedly and never survived: two argv construction sites,
``_SEALED_NETWORK_FLAGS`` hashed but applied by literal, ``_PREFIX`` selecting while names were
built from literals, ``_MARKDOWN`` at two files, ``check-voice.py`` CI-invoked and absent from
the README's development snippet — and the one this file exists for, ``mypy``'s package argv
against ``check-overclaim.py``'s ``_PACKAGES``, WHICH HAD ALREADY DRIFTED (``demo`` in the first,
absent from the second).

**Reconciling two lists is not the fix.** Reconciled lists agree today; derived lists cannot
disagree. So no consumer restates the set — each calls in here.

⚠ AND THE ROSTER ITSELF NEEDS A PARTITION CHECK, WHICH IS THE SAME DEFECT ONE LEVEL UP. A derived
roster still requires a human to add a new package to it, and nothing fails if they do not — the
enumeration is authoritative about members it happens to name and silent about the rest. So
``partition_errors`` asserts every top-level Python-bearing directory is EITHER covered OR
excluded WITH A REASON AND AN EXPIRY, turning a silent omission into a forced adjudication.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
ROSTER_PATH = _ROOT / "scripts" / "gate_coverage.json"


def load() -> dict:
    """The roster, read once, in one place.

    ⚠ A MISSING OR MALFORMED ROSTER RAISES RATHER THAN DEFAULTING. A reader that fell back to an
    empty set would let every consumer pass vacuously — the gate would cover nothing and report
    success, which is the clean-and-wrong this whole file exists to prevent. ``check-overclaim.py``
    already refuses to pass on an empty vocabulary for the same reason.
    """
    with ROSTER_PATH.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not data.get("packages"):
        raise ValueError(f"{ROSTER_PATH}: no packages declared — refusing to derive vacuously")
    return data


def packages() -> tuple[str, ...]:
    """The packages the enumerating gates cover."""
    return tuple(load()["packages"])


def markdown() -> tuple[str, ...]:
    """The markdown docs the overclaim gate scans.

    ⚠ DERIVING THIS IS NOT WIDENING IT. The membership is unchanged — the same two files the
    hand-maintained ``_MARKDOWN`` named. Widening the set to every planning document is a cost
    decision boarded separately; sourcing the SAME members from the roster is the opposite act,
    and leaving it hand-maintained would keep a second literal list inside the very file this
    increment exists to de-duplicate.
    """
    return tuple(load()["markdown"])


def _tracked_python_dirs() -> set[str]:
    """Top-level directories holding tracked ``.py`` files.

    ⚠ FROM ``git ls-files``, NOT FROM A FILESYSTEM WALK, AND THE INSTRUMENT IS DELIBERATE. It is
    the same one ``check-sterility.py`` and ``check-voice.py`` already use, and it asserts on what
    is TRACKED rather than on what happens to be lying in the working tree — so a stray untracked
    scratch package cannot red the build, and a genuinely committed one cannot hide behind
    ``.gitignore``.
    """
    out = subprocess.run(["git", "ls-files", "*.py"], capture_output=True, text=True,
                         check=True, cwd=_ROOT).stdout
    dirs = set()
    for line in out.splitlines():
        if "/" in line:
            dirs.add(line.split("/", 1)[0])
    return dirs


def partition_errors() -> list[str]:
    """Every tracked Python-bearing directory is covered, or excluded with a reason AND an expiry.

    ⚠ THE EXPIRY IS NOT DECORATION. An exclusion carrying only a justification is a PERMANENT
    GRANT, and a table of permanent grants is where claims go to stop being checked — it only ever
    accumulates, and nobody revisits a reason. ``remove_when`` states the condition under which the
    entry should cease to exist, which makes a STALE exclusion mechanically findable instead of
    invisible. That is the tombstone's discipline applied to an exclusion table.

    ⚠ AN EMPTY REASON OR AN EMPTY EXPIRY IS A FAILURE, NOT AN OMISSION. Accepting a blank would let
    the required field be satisfied by its own absence — a control discharged by typing the key.
    """
    data = load()
    covered = set(data["packages"])
    excluded = data.get("packages_excluded", {})
    errs: list[str] = []

    for name, entry in sorted(excluded.items()):
        if name in covered:
            errs.append(f"{name!r} is BOTH covered and excluded — the partition is not a partition")
        if not isinstance(entry, dict):
            errs.append(f"exclusion {name!r} is not an object carrying reason + remove_when")
            continue
        if not str(entry.get("reason", "")).strip():
            errs.append(f"exclusion {name!r} has no reason — an unexplained exclusion is a silent one")
        if not str(entry.get("remove_when", "")).strip():
            errs.append(
                f"exclusion {name!r} has no `remove_when` — an exclusion without an expiry "
                f"condition is a PERMANENT GRANT, and a table of those cannot be audited for "
                f"staleness. State what would make this entry unnecessary.")

    for d in sorted(_tracked_python_dirs()):
        if d not in covered and d not in excluded:
            errs.append(
                f"{d}/ holds tracked Python and is NEITHER covered NOR excluded in "
                f"{ROSTER_PATH.name}. Add it to `packages`, or to `packages_excluded` with a "
                f"reason and a `remove_when`. A package in neither list is covered by nothing "
                f"while the roster still reads as authoritative.")

    for name in sorted(covered):
        if name not in _tracked_python_dirs():
            errs.append(f"{name!r} is in `packages` but holds no tracked Python — stale roster entry")

    return errs
