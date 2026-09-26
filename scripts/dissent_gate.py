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

THE SHAPE OF THIS FILE. ``evaluate`` is a pure function over the PR body, the head, and three injected
probes (ancestry, board fetch, changed files), so every rule is tested offline. ``main`` is the only
I/O, and it prints nothing it was handed: not the PR body, not the board URL, not an entry's content.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

_KEY = r"[a-z0-9][a-z0-9-]{2,127}"
_SHA = r"[0-9a-f]{40}"
_REF = re.compile(rf"^Dissent-Ref: board=({_KEY}) head=({_SHA})(?: prior=({_KEY})@({_SHA}))?\s*$")
_PREFIX = "Dissent-Ref:"

MISSING = "MISSING"
MALFORMED = "MALFORMED"
HEAD_MISMATCH = "HEAD_MISMATCH"
PRIOR_NOT_ANCESTOR = "PRIOR_NOT_ANCESTOR"
INSTRUMENT = "INSTRUMENT"
BOARD_ENTRY_MISSING = "BOARD_ENTRY_MISSING"
BOARD_NOT_A_DISSENT = "BOARD_NOT_A_DISSENT"
FORK_UNVERIFIED = "FORK_UNVERIFIED"
WORKFLOW_TOUCHED = "WORKFLOW_TOUCHED"

ALL_CODES = (MISSING, MALFORMED, HEAD_MISMATCH, PRIOR_NOT_ANCESTOR, INSTRUMENT, BOARD_ENTRY_MISSING,
             BOARD_NOT_A_DISSENT, FORK_UNVERIFIED, WORKFLOW_TOUCHED)

ABSENT = object()   # what a board fetch returns for a key that does not exist (a 404)


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

    def fail(self, code: str, message: str) -> None:
        self.failures.append((code, message))

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def codes(self) -> list[str]:
        return [c for c, _ in self.failures]

    @property
    def admin_waivable(self) -> bool:
        """True ONLY when WORKFLOW_TOUCHED is the sole failure. An admin override of a workflow change
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
        return None, [(MALFORMED, f"line {n}: does not match 'Dissent-Ref: board=<key> head=<40-hex sha> "
                                  f"[prior=<key>@<40-hex sha>]' (full lowercase SHAs; keys a-z 0-9 -)")]
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


def evaluate(body: str | None, head_sha: str, *, same_repo: bool,
             changed_paths: Callable[[], list[str]],
             is_ancestor: Callable[[str, str], bool],
             fetch_entry: Callable[[str], object]) -> Verdict:
    """Every rule, every code — evaluated in full, never first-failure-only."""
    v = Verdict()

    try:
        touched = sorted(p for p in changed_paths() if p.startswith(".github/"))
    except InstrumentError as exc:
        v.fail(INSTRUMENT, f"could not list the PR's changed files: {exc}")
        touched = []
    if touched:
        # ⚠ repr(), NOT THE RAW NAME: a path is attacker-controlled in a fork PR, and git allows a newline
        # in a filename — a raw name could start an output line with '::' and become a workflow command.
        v.fail(WORKFLOW_TOUCHED, f"the PR changes {len(touched)} file(s) under .github/ "
                                 f"({', '.join(repr(p) for p in touched[:5])}{' …' if len(touched) > 5 else ''}) — a PR "
                                 f"that edits CI cannot vouch for the gate that judges it; admin ruling")

    ref, errs = parse_ref(body)
    for code, msg in errs:
        v.fail(code, msg)
    if ref is None:
        return v

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
        v.fail(BOARD_NOT_A_DISSENT, f"{role} {key!r} cites prior {entry.get('prior')!r}, but the PR's "
                                    f"reference cites {expect_prior!r}")


def render(v: Verdict) -> str:
    """The job's output. Built only from codes and messages this module wrote — never from input text."""
    if v.passed:
        return "DISSENT GATE: PASS — a dissent-typed board entry names this exact head."
    lines = [f"DISSENT GATE: FAIL — {', '.join(v.codes)} — ADMIN-WAIVABLE: "
             f"{'yes (WORKFLOW_TOUCHED only)' if v.admin_waivable else 'no'}"]
    lines += [f"  {code}: {msg}" for code, msg in v.failures]
    return "\n".join(lines)


# ── I/O: the only part that touches the network. Nothing here echoes what it reads. ──────────────────
def _get(url: str, headers: dict[str, str]) -> tuple[int, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "gated-dissent-gate/1", **headers})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""
    except (urllib.error.URLError, OSError) as exc:
        raise InstrumentError(type(exc).__name__) from None


def main() -> int:
    env = os.environ
    repo, token = env["GITHUB_REPOSITORY"], env.get("GITHUB_TOKEN", "")
    gh = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{repo}"
    pr = env["PR_NUMBER"]

    def changed_paths() -> list[str]:
        out: list[str] = []
        for page in range(1, 31):                    # 3000 files: GitHub's own cap on this endpoint
            status, raw = _get(f"{api}/pulls/{pr}/files?per_page=100&page={page}", gh)
            if status != 200:
                raise InstrumentError(f"PR files returned HTTP {status}")
            batch = json.loads(raw)
            out += [f["filename"] for f in batch]
            if len(batch) < 100:
                return out
        raise InstrumentError("PR files exceeded 3000 — the list is incomplete, so it is not an answer")

    def is_ancestor(old: str, new: str) -> bool:
        status, raw = _get(f"{api}/compare/{old}...{new}", gh)
        if status != 200:
            raise InstrumentError(f"compare returned HTTP {status}")
        return json.loads(raw).get("status") in ("ahead", "identical")

    def fetch_entry(key: str) -> object:
        base = env.get("BOARD_BASE", "")
        if not base:
            raise InstrumentError("the board is not configured for this run")
        status, raw = _get(f"{base.rstrip('/')}/state/{urllib.parse.quote(key)}", {})
        if status == 404:
            return ABSENT
        if status != 200:
            raise InstrumentError(f"board returned HTTP {status}")   # the status, never the body or URL
        try:
            return json.loads(raw)
        except ValueError:
            raise InstrumentError("board returned a body that is not JSON") from None

    verdict = evaluate(env.get("PR_BODY"), env["HEAD_SHA"],
                       same_repo=env.get("HEAD_REPO", "") == env.get("BASE_REPO", "-"),
                       changed_paths=changed_paths, is_ancestor=is_ancestor, fetch_entry=fetch_entry)
    print(render(verdict))
    return 0 if verdict.passed else 1


if __name__ == "__main__":
    sys.exit(main())
