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


_CI_PATH = _ROOT / ".github" / "workflows" / "ci.yml"
_PARTITIONED_WORKFLOWS = ("ci.yml",)     # the workflow files `_ci_jobs` reads; everything else is exempted
README_PATH = _ROOT / "README.md"

# A block scalar header: `|` or `>`, optionally with a chomping indicator and/or an indentation digit,
# in either order (`|-`, `>+`, `|2`, `>2-`, `|-2`).
_BLOCK_SCALAR = re.compile(r"^[|>](?:[+-]?\d?|\d[+-]?)$")


def _ci_jobs(ci_path: Path | None = None) -> dict[str, list[tuple[str, str]]]:
    """THE ONLY READER OF ``ci.yml``'s JOBS BLOCK. Every job, in file order, mapped to its steps.

    Each step is ``(kind, text)`` where kind is ``run`` (a single-line command — the text is the
    command), ``block`` (a ``run:`` whose value is a block scalar — the text is the header, e.g.
    ``|``), or ``uses`` (an action reference).

    ⚠ ONE PARSE, AND THE SENTENCE THAT SAYS SO IS TRUE BECAUSE OF THIS FUNCTION. Before P10a,
    ``ci_job_names`` and ``ci_jobs_with_commands`` each walked the jobs block with the SAME TWO REGEX
    LITERALS — a second enumeration inside the module whose docstring says two enumerations of one
    set is the shape this tree has never survived. The design said "the one parse" about that code
    and was wrong; the consult found it. Both accessors are now projections of this.

    ⚠ BLOCK BODIES ARE CONSUMED, NOT SCANNED. A line inside a ``run: |`` body that happens to begin
    ``run:`` is shell text, not a step. The previous reader matched every line and would have read it
    as a command.

    ⚠ NO PyYAML — the repo is stdlib-only across a 3.9-3.13 matrix. This reads THIS workflow's shape
    (two-space job keys under a top-level ``jobs:``), not YAML in general, and says so.
    """
    text = (ci_path or _CI_PATH).read_text(encoding="utf-8")
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


def ci_job_names(ci_path: Path | None = None) -> list[str]:
    """The job KEYS declared in the workflow — a projection of ``_ci_jobs``, not a second parse."""
    return list(_ci_jobs(ci_path))


def ci_jobs_with_commands(ci_path: Path | None = None) -> dict[str, list[str]]:
    """Each job mapped to its SINGLE-LINE ``run:`` commands — a projection of ``_ci_jobs``."""
    return {job: [t for kind, t in steps if kind == "run"]
            for job, steps in _ci_jobs(ci_path).items()}


def runnable_commands(cmds: list[str]) -> list[str]:
    """The commands in a job a README could mirror — defined ONCE, here.

    ⚠ THIS PREDICATE USED TO LIVE IN THE TEST while the function that named the property lived
    here, so the two halves of one rule sat on opposite sides of the module boundary. That is the
    dual-site shape by another route: the day someone widens one, the other does not follow.

    ⚠ AN ALLOWLIST, AND SINCE P10a ITS OUTSIDE IS NO LONGER SILENT. A command it does not admit is
    classified by ``classify_ci_command``, and anything neither setup nor runnable is RED as
    unclassified — before P10a, ``pytest -W error tests`` in a job that also ran ``ruff`` was dropped
    by every check. ``python3`` does not match ``^python\\b`` and lands in unclassified: deliberately.
    """
    return [c for c in cmds
            if re.match(r"^(python|mypy|ruff)\b", c) and "pip install" not in c]


# Any shell operator that can join an install to something else. `$(` and backticks included: a
# substitution runs a command too.
_SHELL_OPERATOR = re.compile(r"&&|\|\||;|\||`|\$\(")
_SETUP = re.compile(r"^(?:python3? -m )?pip3? install\b")


def classify_ci_command(cmd: str) -> str:
    """``setup``, ``runnable`` or ``unclassified`` — a PARTITION of every single-line CI command.

    ⚠ SETUP IS ANCHORED AND OPERATOR-FREE. The design first said "contains ``pip install`` ⇒ setup",
    and both consult samples found the hole: ``pip install x && pytest -W error tests`` contains it,
    would have been ignored as setup, and #46's defect would have re-entered through the classifier
    written to close it. An install step is the WHOLE command, with no operator joining it to
    anything that executes.
    """
    if _SETUP.match(cmd) and not _SHELL_OPERATOR.search(cmd):
        return "setup"
    if runnable_commands([cmd]):
        return "runnable"
    return "unclassified"


_BEGIN = "<!-- ci-claims:begin -->"
_END = "<!-- ci-claims:end -->"


def readme_claims(text: str) -> tuple[list[str], list[str]]:
    """The README's CI claims: every non-blank line of a ```` ```bash ```` fence between the markers.

    Returns ``(claims, errors)``. ⚠ EVERY STRUCTURAL FAILURE IS RED WITH ITS OWN MESSAGE, and an empty
    or missing region is never read as "nothing to check" — an empty result is not a value:

    * no begin marker; no end marker; more than one of either; end before begin;
    * a marker inside a fence anywhere in the file (which also covers a fence straddling a marker);
    * an unterminated fence;
    * a fence in the region that is indented, or whose info string is not exactly ``bash``;
    * a ``#`` comment line inside a claims fence; a duplicate claim;
    * a region holding zero claims.

    Markers and fences are recognised line by line in the RAW text. Prose inside the region is not a
    claim — the boundary ruled on 2026-08-08: commands and flags are mechanical, statements about
    CI's character are not.
    """
    errs: list[str] = []
    claims: list[str] = []
    begins = ends = 0
    state = "before"            # before -> inside -> after
    fence_open: int | None = None
    fence_state = ""
    claims_fence = False
    for n, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped in (_BEGIN, _END):
            if fence_open is not None:
                errs.append(f"README line {n}: a ci-claims marker sits INSIDE the fence opened at line "
                            f"{fence_open} — the region cannot be delimited from inside a code block")
                continue
            if line != stripped:
                errs.append(f"README line {n}: a ci-claims marker must start at column 0")
            if stripped == _BEGIN:
                begins += 1
                if state == "after":
                    errs.append(f"README line {n}: a second ci-claims:begin after the region closed")
                state = "inside"
            else:
                ends += 1
                if state != "inside":
                    errs.append(f"README line {n}: ci-claims:end with no open region (end before begin, "
                                f"or a second end)")
                state = "after"
            continue
        if stripped.startswith("```") or stripped.startswith("~~~"):
            if fence_open is None:
                fence_open, fence_state = n, state
                claims_fence = False
                if state == "inside":
                    if line != stripped:
                        errs.append(f"README line {n}: an INDENTED fence in the ci-claims region — "
                                    f"claims fences must start at column 0")
                    elif stripped != "```bash":
                        errs.append(f"README line {n}: fence {stripped!r} in the ci-claims region — only "
                                    f"```bash fences hold claims, and nothing else may sit there silently")
                    else:
                        claims_fence = True
            else:
                fence_open = None
                claims_fence = False
            continue
        if claims_fence and fence_state == "inside" and stripped:
            if stripped.startswith("#"):
                errs.append(f"README line {n}: a comment line inside the ci-claims fence — every "
                            f"line there is a claim, so a comment would be a phantom command")
                continue
            if stripped in claims:
                errs.append(f"README line {n}: duplicate claim {stripped!r}")
                continue
            claims.append(stripped)
    if fence_open is not None:
        errs.append(f"README line {fence_open}: a fence is opened and never closed")
    if begins == 0:
        errs.append("README has NO ci-claims:begin marker — found nothing to check, which is a "
                    "failure, not a pass")
    if ends == 0:
        errs.append("README has NO ci-claims:end marker — the region is not delimited")
    if begins > 1:
        errs.append(f"README has {begins} ci-claims:begin markers — exactly one region is allowed")
    if ends > 1:
        errs.append(f"README has {ends} ci-claims:end markers — exactly one region is allowed")
    if begins and not claims:
        errs.append("the README ci-claims region holds ZERO claims — found nothing, which is a "
                    "failure, not 'everything matched'")
    return claims, errs


def _normalise(cmd: str, display_only: set[str]) -> str:
    """Whitespace collapsed, display-only flags dropped — applied IDENTICALLY to both sides.

    ⚠ EQUALITY IS DELIBERATELY STRICT. Quoting (``"."`` vs ``.``), argument order, ``--f=v`` vs
    ``--f v``, backslash continuations and env-prefixes all RED. They are intended reds, stated here so
    they are not later "fixed" by loosening the comparison until it compares nothing.
    """
    return " ".join(t for t in cmd.split() if t not in display_only)


def workflow_files(root: Path | None = None) -> list[str]:
    """Every TRACKED file under ``.github/workflows/``, by name — from ``git ls-files``, not a glob.

    ⚠ THE ENUMERATION IS THE FIX (board, 2026-09-26). The claims check read ``ci.yml`` and nothing else,
    while the README said every command CI runs is claimed. A second workflow file — the process gate's,
    the day it lands — would have been CI the checker never saw. Scoping the sentence to ``ci.yml`` would
    have made it true and left the hole; enumerating the directory closes it.
    """
    out = subprocess.run(["git", "ls-files", "--", ".github/workflows/"], capture_output=True, text=True,
                         check=True, cwd=root or _ROOT).stdout
    return sorted(line.rsplit("/", 1)[-1] for line in out.splitlines() if line.strip())


def workflow_errors(files: list[str] | None = None) -> list[str]:
    """Every workflow file is PARTITIONED (its steps checked, today only ``ci.yml``) or EXEMPTED by name.

    Both directions red: an unlisted workflow file, and an exemption naming a file that no longer
    exists. A file both partitioned and exempted is red too — the partition is not a partition.
    """
    names = workflow_files() if files is None else files
    exempt = load().get("workflows_excluded", {})
    errs: list[str] = []
    if not names:
        return ["no workflow files found under .github/workflows/ — refusing to report CI as checked"]
    for name in names:
        if name in _PARTITIONED_WORKFLOWS and name in exempt:
            errs.append(f"workflow {name!r} is BOTH checked and exempted — the partition is not a partition")
        elif name not in _PARTITIONED_WORKFLOWS and name not in exempt:
            errs.append(f"workflow {name!r} is neither checked against the README nor exempted in "
                        f"workflows_excluded — CI the claims check never sees is an unrecorded decision")
    for name in sorted(exempt):
        if name not in names:
            errs.append(f"workflows_excluded names {name!r}, which is not a tracked workflow file — stale")
    return errs


def readme_ci_claim_errors(readme_text: str | None = None,
                           ci_path: Path | None = None,
                           workflows: list[str] | None = None) -> list[str]:
    """THE README'S CI CLAIMS AND WHAT CI RUNS, CHECKED IN BOTH DIRECTIONS — and nothing more.

    README → CI: every claim in the region is a command CI runs, or carries a ``side: "readme"``
    exemption. CI → README: every runnable CI command is a claim in the region. Around those two:
    every CI step is classified (setup / runnable / block / unclassified — unclassified is RED), a job
    with a block or with no run step needs a ``side: "ci"`` exemption, and every exemption and
    display-only flag is checked for staleness mechanically, not by reading its ``remove_when``.

    ⚠ ONE FUNCTION FOR BOTH DIRECTIONS, AND ITS NAME CLAIMS NO MORE THAN THAT. Before P10a,
    ``ci_exemption_errors`` covered part of the CI side, a test covered the rest by searching the
    WHOLE README for a token, and the README → CI direction did not exist (#50). The token search
    was weaker than it read: deleting the ``mypy`` line left everything green, because "mypy" also
    appears in prose.

    Every file in ``.github/workflows/`` is either partitioned here (today only ``ci.yml``) or exempted
    by name in ``workflows_excluded``; an unlisted workflow file is RED (``workflow_errors``).

    ⚠ WHAT THIS DOES NOT CHECK, STATED: the inside of a block scalar (a ``side: "ci"`` exemption is
    blanket trust over what that block runs); ``uses:`` steps (recorded, not partitioned — a later
    increment); the steps of an EXEMPTED workflow file (the exemption is the decision not to); and the
    Python-floor sentence (a separate substring pin in the test).

    ⚠ AND ``display_only_flags`` IS A TRUST BOUNDARY THIS DOES NOT CLOSE. A flag listed there is deleted
    from both sides before comparison, so listing a BEHAVIOURAL flag (one that changes what runs or what
    fails, not only what is printed) HIDES a one-sided disagreement: the README could carry it and CI
    not, and this function would report nothing. The staleness predicate does not catch that — it catches
    only an entry present on NEITHER side. A test pins the hole as existing, so closing it reds that test.
    """
    data = load()
    exempt = data.get("ci_claim_exemptions", {})
    display_only = set(data.get("display_only_flags", {}))
    jobs = _ci_jobs(ci_path)
    if not jobs:
        return ["no CI jobs parsed from ci.yml — refusing to check the README claims vacuously"]
    text = readme_text if readme_text is not None else README_PATH.read_text(encoding="utf-8")
    claims, errs = readme_claims(text)
    errs += workflow_errors(workflows)

    def norm(cmd: str) -> str:
        return _normalise(cmd, display_only)

    claimed = {norm(c): c for c in claims}
    ci_runnable: dict[str, str] = {}
    needs_ci_exemption: set[str] = set()
    for job, steps in jobs.items():
        runs = [t for kind, t in steps if kind == "run"]
        if any(kind == "block" for kind, _ in steps) or not runs:
            needs_ci_exemption.add(job)
            if not (job in exempt and exempt[job].get("side") == "ci"):
                what = ("a block-scalar step" if any(k == "block" for k, _ in steps)
                        else "no run step at all")
                errs.append(f"CI job {job!r} has {what} and no side=ci exemption — what it runs "
                            f"cannot be mirrored, so saying nothing about it is an unrecorded decision")
        for cmd in runs:
            kind = classify_ci_command(cmd)
            if kind == "runnable":
                ci_runnable[norm(cmd)] = job
            elif kind == "unclassified":
                errs.append(f"CI job {job!r} runs {cmd!r}, which is neither an install step, a runnable "
                            f"gate/test command, nor an exempted block — classify it")

    for name, entry in sorted(exempt.items()):
        if not isinstance(entry, dict):
            errs.append(f"ci_claim_exemptions {name!r} is not an object")
            continue
        side = entry.get("side")
        if side == "ci":
            if name not in jobs:
                errs.append(f"ci_claim_exemptions names job {name!r}, which does not exist in ci.yml "
                            f"(jobs: {sorted(jobs)}) — a stale exemption is inert and invisible")
            elif name not in needs_ci_exemption:
                errs.append(f"ci_claim_exemptions {name!r} (side=ci) is STALE: the job has no block step "
                            f"and does run a command, so there is nothing left for it to exempt")
        elif side == "readme":
            key = norm(name)
            if key not in claimed:
                errs.append(f"ci_claim_exemptions {name!r} (side=readme) is STALE: that claim is no "
                            f"longer in the README region")
            elif key in ci_runnable:
                errs.append(f"ci_claim_exemptions {name!r} (side=readme) is STALE: CI now runs it, "
                            f"so it needs no exemption")
        elif side is None:
            errs.append(f"ci_claim_exemptions {name!r} has no `side` — there is no default, because a "
                        f"default is a silent assumption about which namespace the key lives in")
        else:
            errs.append(f"ci_claim_exemptions {name!r} has side={side!r}; only 'ci' and 'readme' "
                        f"exist, and an entry no predicate reads is inert")

    readme_exempt = {norm(n) for n, e in exempt.items() if isinstance(e, dict) and e.get("side") == "readme"}
    for key, raw in sorted(claimed.items()):
        if key not in ci_runnable and key not in readme_exempt:
            errs.append(f"README claims {raw!r}; CI never runs it — a claim about CI that CI does not "
                        f"honour is false, not incomplete")
    for key, job in sorted(ci_runnable.items()):
        if key not in claimed:
            errs.append(f"CI runs {key!r} (job {job!r}); the README ci-claims region omits it — an "
                        f"incomplete list is still a claim about its contents")

    tokens = {t for c in claims for t in c.split()}
    tokens |= {t for steps in jobs.values() for kind, c in steps if kind == "run" for t in c.split()}
    for flag in sorted(display_only):
        if flag not in tokens:
            errs.append(f"display_only_flags {flag!r} is STALE: it appears in neither the README "
                        f"claims nor any CI command, so it hides nothing and exempts nothing")
    return errs


def exemption_tables() -> tuple[dict[str, dict], list[str]]:
    """Every exemption table in the roster, DERIVED — and every top-level key accounted for.

    Returns ``(tables, errors)``. A top-level key is either listed in ``_non_exemption_keys`` or it
    is an exemption table; an exemption table is an object whose every entry is an object carrying a
    non-blank ``reason`` and ``remove_when``.

    ⚠ DERIVED BY DECLARATION, NOT BY SHAPE ALONE, AND THE DIFFERENCE IS THE FIX. Deriving "a table is
    an object whose entries carry `reason`" meant a table with an entry MISSING `reason` was simply
    not a table — excluded instead of failed: the validator dropping the malformed input it exists
    to validate (board, 2026-09-26). So membership is declared, and both directions red: an
    undeclared key that is not a well-formed table, and a declared key that no longer exists.
    """
    data = load()
    declared = data.get("_non_exemption_keys", [])
    errs: list[str] = []
    if "_non_exemption_keys" not in declared:
        errs.append("_non_exemption_keys does not list itself — the partition would leave it unaccounted")
    for key in declared:
        if key not in data:
            errs.append(f"_non_exemption_keys lists {key!r}, which is not a top-level key — stale")
    tables: dict[str, dict] = {}
    for key, value in data.items():
        if key in declared:
            continue
        if not isinstance(value, dict) or not value:
            errs.append(f"top-level key {key!r} is not declared a non-exemption key and is not a "
                        f"non-empty exemption table")
            continue
        tables[key] = value
        for name, entry in value.items():
            if not isinstance(entry, dict):
                errs.append(f"{key}.{name} is not an object carrying reason + remove_when")
                continue
            for field in ("reason", "remove_when"):
                if not str(entry.get(field, "")).strip():
                    errs.append(f"{key}.{name} has no {field}")
    return tables, errs


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
