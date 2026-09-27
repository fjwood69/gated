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
  * a hit FAILS unless it is in the REVIEWED ``voice_suppressions`` table with a reason and a
    ``remove_when``. A growing table is a SMELL, not the norm.

Quoted material is the one structural exception: a Markdown blockquote (a line starting ``>``) may
legitimately quote someone else's plural voice, so those lines are skipped.

Suppressions: the ``voice_suppressions`` table in ``scripts/gate_coverage.json``, keyed
``"<relpath> :: <pronoun>"``; ABSENT while it has no entries (absence is declared to mean "none"). Until P10c
(#52) they were a ``.txt`` file whose loader silently dropped a malformed line and never required the
justification this docstring promised. Stdlib-only, so it runs anywhere the rest of CI does.

WHAT A GREEN RUN DOES NOT SAY (P10c):
  * a blockquoted line is never consulted, so a suppression whose pronoun appears only in blockquotes is
    STALE — correctly: it suppresses nothing, and the fix is to delete it, not to scan blockquotes;
  * every run is a FULL scan (there are no arguments), which is what makes "never consulted" mean "stale";
  * a tracked markdown file that cannot be read is NOT SCANNED and reds — never OK;
  * files are read with ``errors="ignore"``: undecodable bytes are dropped from the scanned text. Accepted as
    lossy, and stated rather than implied.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gate_coverage import (VOICE_SUPPRESSIONS, fold, guard_list_errors,  # noqa: E402
                           suppression_key_errors, suppression_pairs, unconsumed)

# First-person PLURAL only. "I"/"my"/"me" are the intended voice and are never flagged.
_PRONOUNS = ("we", "us", "our", "ours", "ourselves", "we're", "we've", "we'll", "we'd", "let's")
# ⚠ LONGEST ALTERNATIVE FIRST (P10c). The alternation used to try `we` before `we're`, and `\b` matches at an
# apostrophe, so `we're`/`we've`/`we'll`/`we'd` could NEVER match as themselves — four inert entries in a live
# guard list, invisible to the normal-form check because each was perfectly normal. `shadowed_pronouns()` now
# checks every entry is matched as itself.
_PATTERN = re.compile(r"\b(" + "|".join(p.replace("'", "['’]") for p in sorted(_PRONOUNS, key=len, reverse=True))
                      + r")\b", re.IGNORECASE)


def shadowed_pronouns() -> list[str]:
    """Every pronoun, scanned on its own, must be matched AS ITSELF — else an earlier alternative shadows it and
    it can never be consulted: an inert entry in a live list (board amendment 4, the case normal form misses)."""
    out = []
    for p in _PRONOUNS:
        m = _PATTERN.search(p)
        if m is None or fold(m.group(0)) != p:
            out.append(f"_PRONOUNS entry {p!r} is SHADOWED — scanned alone it matches as "
                       f"{fold(m.group(0)) if m else None!r}, so it can never match as itself")
    return out

def _tracked_markdown() -> list[str]:
    out = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True,
                         check=True, cwd=_ROOT).stdout
    return [f for f in out.splitlines() if f]


def scan_voice(md_texts: dict[str, str | None], pairs: dict[tuple[str, str], str]
               ) -> tuple[list[tuple[str, int, str, str]], set[str], set[str]]:
    """The whole scan, pure: ``(violations, consumed suppression keys, NOT-SCANNED relpaths)``.

    ``md_texts`` maps a tracked markdown relpath to its text, or ``None`` if it could not be read.
    """
    violations: list[tuple[str, int, str, str]] = []
    consumed: set[str] = set()
    not_scanned: set[str] = set()
    for rel, text in sorted(md_texts.items()):
        if text is None:
            not_scanned.add(rel)
            violations.append((rel, 0, "NOT SCANNED", "tracked markdown that could not be read"))
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith(">"):
                continue  # a blockquote may quote someone else's voice
            for m in _PATTERN.finditer(line):
                word = fold(m.group(0))
                key = pairs.get((rel, word))
                if key is not None:
                    consumed.add(key)
                    continue
                violations.append((rel, i, word, line.strip()[:96]))
    return violations, consumed, not_scanned


def main() -> int:
    guard = guard_list_errors("_PRONOUNS", _PRONOUNS) + shadowed_pronouns()
    if guard:
        print("check-voice: the pronoun list is unusable — refusing to pass:")
        for e in guard:
            print(f"  - {e}")
        return 1
    md_texts: dict[str, str | None] = {}
    for rel in _tracked_markdown():
        try:
            md_texts[rel] = (_ROOT / rel).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            md_texts[rel] = None
    pairs = suppression_pairs(VOICE_SUPPRESSIONS)
    violations, consumed, not_scanned = scan_voice(md_texts, pairs)
    table_errors = suppression_key_errors(VOICE_SUPPRESSIONS) + unconsumed(VOICE_SUPPRESSIONS, consumed,
                                                                              not_scanned, scanned=set(md_texts))
    # ⚠ ACCUMULATE, NEVER EARLY-RETURN: a table error must not hide a violation, nor the reverse.
    if table_errors:
        print("VOICE GATE FAILED — the suppressions table:")
        for e in table_errors:
            print(f"  - {e}")
    if violations:
        print("VOICE GATE FAILED — first-person PLURAL in published prose "
              "(this project speaks as 'I', not 'we'):\n")
        for rel, i, word, text in violations:
            print(f"  {rel}:{i}  [{word}]  {text}")
        print(f"\n{len(violations)} violation(s). Rewrite in the first person singular or "
              "impersonally; if a use is deliberate (a quotation, a genuine joint statement), add "
              "it to voice_suppressions in scripts/gate_coverage.json with a reason and remove_when.")
    if table_errors or violations:
        return 1

    print("Voice gate OK — no unsuppressed first-person-plural in published prose.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
