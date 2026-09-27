#!/usr/bin/env python3
"""3.5-close #1.7 — the scoped overclaim lint (an EDITORIAL guard, NOT proof every claim is true).

Makes "no unsuppressed overclaim survives" a TESTED property so the claim-narrowing this increment did
stays total and enforced (a future commit reintroducing overclaim language fails CI).

Design (board-ratified scoped form, not the full claims-as-data registry):
  * scans PYTHON STRING LITERALS (docstrings + string constants) via the ``ast`` module — so COMMENTS
    are EXEMPT, which dodges the false-positive-on-explanatory-comments problem a naive grep has. NOTE
    (CP2 S7): a COMMENT that asserts a security PROPERTY is held to the SAME honesty standard as a
    docstring — the linter cannot scan comments without a high false-positive rate, so comments are a
    MANUAL-review surface, not exempt-from-the-standard;
  * plus designated Markdown docs (line scan);
  * against a NARROW banned vocabulary of unambiguous overclaim PHRASES (absolute-safety /
    execution-assurance / guarantee / un-bypassable / fully-bound) — NOT common single words like
    "verified"/"only"/"pinned", which are legitimate almost everywhere (banning them would need a huge
    suppressions file = the theatre this avoids);
  * a hit FAILS unless it is in the REVIEWED suppressions file with a justification. A growing
    suppressions file is a SMELL (the vocabulary is wrong or the claim is), not the norm.

Vocabulary: ``scripts/claims_vocabulary.txt`` — a GUARD list, every entry in normal form (lowercase, straight
apostrophes), refused if empty. Suppressions: the ``overclaim_suppressions`` table in ``scripts/gate_coverage.json``,
keyed ``"<relpath> :: <phrase>"`` with ``reason`` + ``remove_when`` (they were a tab-separated ``.txt`` file until
P10c, #52, where a malformed line was printed and skipped while the gate said OK). Stdlib-only (no PyYAML) so it
runs on the whole 3.9-3.13 CI matrix. Files outside the roster (tests, ``scripts/``, scratch) are not scanned —
by construction of the roster, not by an exemption list.

WHAT A GREEN RUN DOES NOT SAY (P10c, stated so it is not read into the result):
  * a ``.py`` COMMENT is never scanned (only string literals), so a suppression for a comment-only phrase is
    STALE — correctly: it suppresses nothing;
  * every run is a FULL scan (there are no arguments), which is what makes "never consulted" mean "stale";
  * a roster file that is missing, cannot be read or decoded as UTF-8, or a ``.py`` that does not parse, is NOT
    SCANNED and reds — never OK, and never a traceback. The roster's ``.py`` files are discovered through
    ``git ls-files`` (tracked files only), as the other two linters discover theirs — not by a filesystem walk,
    which scanned untracked files and silently missed a tracked file deleted from the worktree;
  * the suppression grain is per file per phrase, not per occurrence;
  * a phrase WRAPPED across a line break in markdown is not detected (matching is ``phrase in text``).
    Pre-dates P10c; tracked as #56. Collapsing whitespace is safe for markdown but not across the joined
    ``.py`` literals, where it would weld separate strings into false matches;
  * no vocabulary entry may contain another: nesting makes a suppression for the longer phrase unable to
    silence the shorter one's hit, so it is refused.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

# ⚠ DERIVED FROM ``scripts/gate_coverage.json``, NEVER RESTATED HERE. These were two hand-maintained
# literals, and the packages one HAD ALREADY DRIFTED from the argv in ci.yml — `demo` was
# type-checked by mypy and invisible to this gate, so overclaim language in the one package the
# README tells every new reader to RUN was never scanned. Reconciling the two lists would have
# fixed the values and left the class open; deriving them makes disagreement unrepresentable.
#
# ⚠ THE MARKDOWN SET IS DERIVED, NOT WIDENED. Same two files as before. Widening to every planning
# document is a boarded cost decision; sourcing the same members is the opposite act, and leaving
# this one literal would keep a second hand-maintained list inside the file whose de-duplication is
# the whole increment.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_coverage import (OVERCLAIM_SUPPRESSIONS, fold, guard_list_errors,  # noqa: E402
                           nested_entry_errors, suppression_key_errors, suppression_pairs,
                           tracked_files, unconsumed)
from gate_coverage import markdown as _roster_markdown  # noqa: E402
from gate_coverage import packages as _roster_packages  # noqa: E402
_VOCAB_FILE = _ROOT / "scripts" / "claims_vocabulary.txt"


def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _string_literals(source: str) -> list[str]:
    """All str constants in the source (docstrings + literals), via AST — comments are not nodes, so
    they are exempt by construction.

    ⚠ RAISES ``SyntaxError`` RATHER THAN RETURNING ``[]``. The empty-list fallback reported an unparseable file
    as scanned-and-clean; the caller now records it as NOT SCANNED (P10c)."""
    tree = ast.parse(source)
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _read(path: Path) -> str | None:
    """A tracked file's text as strict UTF-8, or ``None`` if it cannot be read OR decoded — the one read path, so
    every failure becomes NOT SCANNED rather than a traceback outside the taxonomy."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def scan_overclaim(py_sources: dict[str, str | None], md_texts: dict[str, str | None], banned: list[str],
                   pairs: dict[tuple[str, str], str]) -> tuple[list[str], set[str], set[str]]:
    """The whole scan, pure: ``(violations, consumed suppression keys, NOT-SCANNED relpaths)``.

    ``py_sources`` and ``md_texts`` map a relpath to its text, or ``None`` if it could not be read or decoded. Every
    suppression consulted is recorded — consultation happens exactly when a phrase occurs in the SCANNED text,
    so an unconsulted suppression is one that suppressed nothing.
    """
    violations: list[str] = []
    consumed: set[str] = set()
    not_scanned: set[str] = set()

    def check(rel: str, text: str, where: str) -> None:
        for phrase in banned:
            if phrase in text:
                key = pairs.get((rel, phrase))
                if key is None:
                    violations.append(f"{rel}: overclaim phrase {phrase!r} in {where}")
                else:
                    consumed.add(key)

    for rel, source in sorted(py_sources.items()):
        if source is None:
            not_scanned.add(rel)
            violations.append(f"{rel}: tracked but could not be read or decoded — NOT SCANNED")
            continue
        try:
            blob = fold("\n".join(_string_literals(source)))
        except SyntaxError:
            not_scanned.add(rel)
            violations.append(f"{rel}: does not parse — NOT SCANNED (it must not be reported as clean)")
            continue
        check(rel, blob, "a string literal")
    for rel, text in sorted(md_texts.items()):
        if text is None:
            not_scanned.add(rel)
            violations.append(f"{rel}: listed in the markdown roster but could not be read or decoded — NOT SCANNED")
            continue
        check(rel, fold(text), "the doc")
    return violations, consumed, not_scanned


def main() -> int:
    banned = _load_lines(_VOCAB_FILE)
    guard = guard_list_errors("claims_vocabulary.txt", banned) + nested_entry_errors("claims_vocabulary.txt", banned)
    if guard:
        print("check-overclaim: the vocabulary is unusable — refusing to pass:")
        for e in guard:
            print(f"  - {e}")
        return 1

    tracked = tracked_files()
    py_sources = {rel: _read(_ROOT / rel) for rel in sorted(tracked)
                  if rel.endswith(".py") and any(rel.startswith(pkg + "/") for pkg in _roster_packages())}
    md_texts = {md: _read(_ROOT / md) for md in _roster_markdown()}
    pairs = suppression_pairs(OVERCLAIM_SUPPRESSIONS)
    violations, consumed, not_scanned = scan_overclaim(py_sources, md_texts, banned, pairs)
    violations += suppression_key_errors(OVERCLAIM_SUPPRESSIONS)
    violations += unconsumed(OVERCLAIM_SUPPRESSIONS, consumed, not_scanned,
                             scanned=set(py_sources) | set(md_texts))

    if violations:
        print("OVERCLAIM LINT FAILED — narrow the claim, or add a reviewed suppression (reason + remove_when) "
              "to overclaim_suppressions in scripts/gate_coverage.json:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("Overclaim lint OK — no unsuppressed overclaim language in shipped code strings + key docs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
