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
import re
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


def top_level_dirs() -> set[str]:
    """EVERY tracked top-level directory — the source of truth for the README's layout list.

    ⚠ WIDER THAN ``_tracked_python_dirs``, AND THE WIDENING IS THE FIX. The layout check first
    walked python-bearing directories only, while the design claimed its source of truth was THE
    GIT TREE. So `docs/` could be added to the README's layout list and NOTHING PINNED IT —
    deleting the line redded nothing. The stated source was wider than the actual source, which is
    this increment's own defect committed one level in. Found in dissent on PR #49.

    Directories that legitimately do not belong in a reader-facing layout list are excluded AS
    DATA, with a reason and an expiry, exactly like the package roster.
    """
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                         check=True, cwd=_ROOT).stdout
    return {line.split("/", 1)[0] for line in out.splitlines() if "/" in line}


def layout_errors(listed: set[str]) -> list[str]:
    """Every tracked top-level directory is listed in the README, or excluded with a reason + expiry.

    ⚠ A PUBLIC HELPER, BECAUSE THE TEST USED TO REACH ACROSS THE MODULE BOUNDARY INTO A PRIVATE ONE.
    A checker calling `_private` is coupled to an implementation detail it does not own.
    """
    data = load()
    excluded = data.get("layout_excluded", {})
    errs: list[str] = []
    for name, entry in sorted(excluded.items()):
        for field in ("reason", "remove_when"):
            if not str(entry.get(field, "")).strip():
                errs.append(f"layout_excluded {name!r} has no {field}")
        if name not in top_level_dirs():
            errs.append(
                f"layout_excluded names {name!r}, which is NOT a tracked top-level directory — "
                f"a stale exclusion for something that no longer exists, inert and invisible")
    for d in sorted(top_level_dirs()):
        if d not in listed and d not in excluded:
            errs.append(
                f"{d}/ is a tracked top-level directory, is NOT in the README layout list, and is "
                f"NOT excluded with a reason. A list is a claim about its contents.")
    # ⚠ THE OTHER DIRECTION, ADDED IN RE-DISSENT. The first repair caught TRACKED-BUT-NOT-LISTED
    # and accepted LISTED-BUT-NOT-TRACKED — a README naming a directory that does not exist redded
    # nothing. The two are not the same defect: an omission makes the list INCOMPLETE, while a
    # phantom entry makes it FALSE, and a false claim is the worse of the two.
    # ⚠ AND THE ONE-WAY CHECK WAS BUILT IN THE SAME INCREMENT THAT RULED BIDIRECTIONALITY "THE
    # WHOLE POINT" for the README-versus-CI pin. The rule was stated on one axiom and not carried
    # to the next — which is this increment's subject arriving through its own door.
    for d in sorted(listed):
        if d not in top_level_dirs():
            errs.append(
                f"the README layout list names {d}/, which is NOT a tracked top-level directory. "
                f"An omission leaves the list incomplete; a phantom entry makes it FALSE.")
    return errs


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


def ci_job_names(ci_path: Path | None = None) -> list[str]:
    """The job KEYS declared in the workflow, read from the workflow itself.

    ⚠ NO PyYAML — the repo is stdlib-only across a 3.9-3.13 matrix. Job keys are the two-space
    entries under a top-level ``jobs:``, which is a shape this file already relies on for the run
    lines. The narrowness is deliberate and stated: it reads THIS workflow, not YAML in general.
    """
    text = (ci_path or (_ROOT / ".github" / "workflows" / "ci.yml")).read_text(encoding="utf-8")
    out, in_jobs = [], False
    for line in text.splitlines():
        if re.match(r"^jobs:\s*$", line):
            in_jobs = True
            continue
        if in_jobs:
            if line.strip() and not line.startswith(" "):
                break
            m = re.match(r"^  ([A-Za-z][\w-]*):\s*$", line)
            if m:
                out.append(m.group(1))
    return out


def ci_jobs_with_commands(ci_path: Path | None = None) -> dict[str, list[str]]:
    """Each job mapped to its SINGLE-LINE ``run:`` commands — the ones a README could mirror.

    ⚠ A BLOCK SCALAR (``run: |``) IS DELIBERATELY NOT A MIRRORABLE COMMAND. The hygiene job is two
    multi-line shell assertions embedded in the workflow; there is no command a reader could type,
    which is precisely why it needs an exemption rather than a README line. Distinguishing the two
    shapes here is what makes "has no local twin" a MEASURED property rather than an assertion.
    """
    text = (ci_path or (_ROOT / ".github" / "workflows" / "ci.yml")).read_text(encoding="utf-8")
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    in_jobs = False
    for line in text.splitlines():
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
        r = re.match(r"^\s*(?:- )?run:\s*(\S.*)$", line)
        if r and current and not r.group(1).startswith("|"):
            jobs[current].append(r.group(1).strip())
    return jobs


def ci_exemption_errors() -> list[str]:
    """Every CI job is checked or exempted, and every exemption names a job that EXISTS.

    ⚠ THIS IS THE ROSTER CONSTRUCTOR APPLIED TO THE EXEMPTION TABLE, AND WITHOUT IT THE FIX FOR
    PR #49's D1 WOULD HAVE BEEN THE SAME DEFECT ONE FIELD OVER. Keying exemptions on CI job names
    makes the table a CLAIM ABOUT ci.yml's JOB SET — a second enumeration. An exemption for a job
    that has been renamed or deleted is then inert for exactly the reason the original filename-
    keyed entry was inert: an unconsulted entry never fails, so it lapses silently and its mere
    presence still reads as evidence the boundary was considered.

    So the table is partitioned in BOTH directions: no job may be silently unchecked, and no
    exemption may name a job that does not exist. That is what makes the day-one claim honest —
    hygiene is exempt from a check that WOULD otherwise fire, and if the job is renamed the
    exemption REDS rather than quietly lapsing.
    """
    data = load()
    exempt = data.get("ci_claim_exemptions", {})
    jobs = set(ci_job_names())
    errs: list[str] = []
    if not jobs:
        return ["no CI jobs parsed from ci.yml — refusing to check the exemption table vacuously"]
    for name, entry in sorted(exempt.items()):
        if name not in jobs:
            errs.append(
                f"ci_claim_exemptions names job {name!r}, which does not exist in ci.yml "
                f"(jobs: {sorted(jobs)}). A stale exemption is inert and invisible — it never "
                f"fails, so it lapses silently while still reading as a considered decision.")
        for field in ("reason", "remove_when"):
            if not str(entry.get(field, "")).strip():
                errs.append(f"ci_claim_exemptions {name!r} has no {field}")
    return errs


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
