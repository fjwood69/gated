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

Vocabulary: ``scripts/claims_vocabulary.txt``. Suppressions: ``scripts/overclaim_suppressions.txt``
(``<relpath>\\t<phrase>\\t<justification>`` per line). Stdlib-only (no PyYAML) so it runs on the whole
3.9-3.13 CI matrix. Tests, this script, the vocab/suppression files, and scratch (RESUME-*) are exempt.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_PACKAGES = ("core", "sandbox", "engine", "observe", "gate", "cli")
_MARKDOWN = ("README.md", "ARCHITECTURE.md")
_VOCAB_FILE = _ROOT / "scripts" / "claims_vocabulary.txt"
_SUPPRESS_FILE = _ROOT / "scripts" / "overclaim_suppressions.txt"


def _load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def _load_suppressions(path: Path) -> set[tuple[str, str]]:
    allowed = set()
    for line in _load_lines(path):
        parts = line.split("\t")
        if len(parts) < 3 or not parts[2].strip():
            print(f"SUPPRESSION MALFORMED (need <relpath>\\t<phrase>\\t<justification>): {line}")
            continue
        allowed.add((parts[0].strip(), parts[1].strip().lower()))
    return allowed


def _string_literals(source: str) -> list[str]:
    """All str constants in the source (docstrings + literals), via AST — comments are not nodes, so
    they are exempt by construction."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def main() -> int:
    banned = [p.lower() for p in _load_lines(_VOCAB_FILE)]
    if not banned:
        print("check-overclaim: no vocabulary loaded — refusing to pass vacuously")
        return 1
    suppressions = _load_suppressions(_SUPPRESS_FILE)
    violations: list[str] = []

    for pkg in _PACKAGES:
        for py in sorted((_ROOT / pkg).rglob("*.py")):
            rel = py.relative_to(_ROOT).as_posix()
            blob = "\n".join(_string_literals(py.read_text(encoding="utf-8"))).lower()
            for phrase in banned:
                if phrase in blob and (rel, phrase) not in suppressions:
                    violations.append(f"{rel}: overclaim phrase {phrase!r} in a string literal")

    for md in _MARKDOWN:
        path = _ROOT / md
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8").lower()
        for phrase in banned:
            if phrase in text and (md, phrase) not in suppressions:
                violations.append(f"{md}: overclaim phrase {phrase!r} in the doc")

    if violations:
        print("OVERCLAIM LINT FAILED — narrow the claim, or add a reviewed suppression with a justification:")
        for v in violations:
            print(f"  - {v}")
        return 1
    print("Overclaim lint OK — no unsuppressed overclaim language in shipped code strings + key docs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
