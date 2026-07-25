#!/usr/bin/env python3
"""The published-voice guard — first person SINGULAR, never plural.

This is a solo project with advisory review. A corporate "we" in published prose implies an
organisation that does not exist, and quietly launders individual accountability into a collective
one: "we chose the licence" is unfalsifiable in a way "I chose the licence" is not. The framework's
whole posture is that a named human is accountable for every ratification, so the prose says who.

Scope (deliberately narrow, same discipline as ``check-overclaim.py``):
  * PUBLISHED MARKDOWN only — the docs a reader actually meets. Shipped code comments and
    docstrings are ENGINEERING prose, where a collaborative "we" is idiomatic and harmless; they
    are a manual-review surface, not part of this gate. That boundary is stated rather than
    implied, so nobody later reads a green build as "no first-person-plural anywhere".
  * a NARROW banned set: the plural subject/object/possessive pronouns, matched as whole words,
    case-insensitively. Not "us" inside "thus", not "our" inside "yours".
  * a hit FAILS unless it is in the REVIEWED suppressions file with a justification. A growing
    suppressions file is a SMELL, not the norm.

Quoted material is the one structural exception: a Markdown blockquote (a line starting ``>``) may
legitimately quote someone else's plural voice, so those lines are skipped.

Suppressions: ``scripts/voice_suppressions.txt`` (``<relpath>\\t<pronoun>\\t<justification>``).
Stdlib-only, so it runs anywhere the rest of CI does.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SUPPRESSIONS = _ROOT / "scripts" / "voice_suppressions.txt"

# First-person PLURAL only. "I"/"my"/"me" are the intended voice and are never flagged.
_PRONOUNS = ("we", "us", "our", "ours", "ourselves", "we're", "we've", "we'll", "we'd", "let's")
_PATTERN = re.compile(r"\b(" + "|".join(p.replace("'", "['’]") for p in _PRONOUNS) + r")\b",
                      re.IGNORECASE)

# This file necessarily contains the pronouns it bans.
_ALLOW = {"scripts/check-voice.py", "scripts/voice_suppressions.txt"}


def _tracked_markdown() -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True,
                         check=True, cwd=_ROOT).stdout
    return [f for f in out.splitlines() if f and f not in _ALLOW]


def _suppressions() -> set[tuple[str, str]]:
    if not _SUPPRESSIONS.is_file():
        return set()
    pairs: set[tuple[str, str]] = set()
    for line in _SUPPRESSIONS.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) >= 2:
            pairs.add((parts[0].strip(), parts[1].strip().lower()))
    return pairs


def main() -> int:
    suppressed = _suppressions()
    violations: list[tuple[str, int, str, str]] = []
    for rel in _tracked_markdown():
        path = _ROOT / rel
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            if line.lstrip().startswith(">"):
                continue  # a blockquote may quote someone else's voice
            for m in _PATTERN.finditer(line):
                word = m.group(0).lower().replace("’", "'")
                if (rel, word) in suppressed:
                    continue
                violations.append((rel, i, word, line.strip()[:96]))

    if violations:
        print("VOICE GATE FAILED — first-person PLURAL in published prose "
              "(this project speaks as 'I', not 'we'):\n")
        for rel, i, word, text in violations:
            print(f"  {rel}:{i}  [{word}]  {text}")
        print(f"\n{len(violations)} violation(s). Rewrite in the first person singular or "
              "impersonally; if a use is deliberate (a quotation, a genuine joint statement), add "
              "it to scripts/voice_suppressions.txt with a justification.")
        return 1

    print("Voice gate OK — no unsuppressed first-person-plural in published prose.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
