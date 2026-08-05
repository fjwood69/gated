#!/usr/bin/env python3
"""sweep — find every surface still asserting a withdrawn claim.

Built to DESIGN-supersession-sweep.md v3 (ratified 2026-08-04). Ruling IDs (R1, R2, R4a, …) in the
comments below refer to that document; the design carries the reasoning, this file carries the
mechanism, and neither is complete without the other.

THE ONE-LINE REASON THIS EXISTS: on 2026-08-03 a withdrawn claim was swept FROM MEMORY, three carriers
were named, and it lived on five. The two missed were the design document under active edit and a
follow-on carrying a second withdrawal nested inside the first.

⚠ THIS TOOL NEVER ADJUDICATES (R5). It reports observables and ranks them. A classifier may reorder;
it may never remove. The reason is asymmetry: ranking errors are recoverable by reading, filtering
errors are invisible.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

# ── exit codes, STRATIFIED (R4a) ──────────────────────────────────────────────────────────────────
# Process debt must NEVER share a code with a live finding. An exit that is always red trains the
# reader to route around it — this tool's own thesis arriving through the door built to prevent it.
EXIT_CLEAN = 0
EXIT_INSTRUMENT = 1   # control failed · surface missing · count dropped · unmanifested file
EXIT_TOMBSTONE = 2    # a correction was re-worded — STILL PRINTS EVERY HIT (R8)
EXIT_HITS = 3         # live hits, read them
EXIT_DEBT = 4         # a record is open (zero tombstones)

CONFIG_PATH = Path(__file__).resolve().parent / "sweep.config.json"
# ⚠ NOT COMMITTED. gated is PUBLIC and the real config names a private board endpoint and
# a private planning-doc root. `sweep.config.example.json` ships the SHAPE; the operator
# supplies the values. See also NAMESPACE below.
# R13 — the namespace is TOOL-OWNED BY NAME. Humans put notes in a sibling SEARCHED surface, never
# here. Brittleness is solved by naming, not by softening the rule.
NAMESPACE = Path(__file__).resolve().parent / "sweep-registry"
# ⚠ THE REGISTRY IS NEVER COMMITTED TO THIS REPO, AND THAT IS A DESIGN CONSTRAINT RATHER
# THAN A PREFERENCE. Run reports persist the FULL MATCHED SPAN of every hit (R5), and the
# corpus swept is PRIVATE — planning documents and a private board thick with hostnames,
# usernames and absolute paths. MEASURED: check-sterility.py over one day of artefacts
# returned 113 violations, 68 of them hostnames, with ZERO in this file. Sanitising the
# artefacts would fix nothing: the next run regenerates them. So the ARTEFACT STORE LIVES
# OUTSIDE THIS REPOSITORY, and .gitignore enforces it.


# ── matching (R2) ─────────────────────────────────────────────────────────────────────────────────
def normalise(text: str) -> str:
    """NFKC, and the K is load-bearing — but NOT for the reason first given.

    THE RULING SURVIVED ITS RED-PROOF; ITS ORIGINAL JUSTIFICATION DID NOT, AND THIS DOCSTRING CARRIED
    THE DEAD REASON AFTER THE DESIGN AND THE TESTS WERE BOTH CORRECTED. That is recorded here rather
    than quietly fixed, because it is precisely the defect this tool exists to catch: a correct ruling,
    a wrong reason, and the reason corrected only on the surfaces the author happened to be looking at.
    THE CODE IS THE SURFACE THE NEXT READER ACTUALLY REACHES.

    THE DEAD REASON: "NFC leaves NBSP as NBSP, so an NBSP-joined occurrence evades both the whitespace
    rule and literal matching." MEASURED FALSE in Python: re.match(r"[\\s]", "\\u00a0") is True for a
    str pattern (only re.ASCII disables it), so such an occurrence matches under NFC too. Reversing
    NFKC->NFC left the test GREEN, which is how the false reason was found at all.

    THE REAL REASON: COMPATIBILITY CHARACTERS INSIDE WORDS, which no whitespace rule can reach — the
    fi-ligature and fullwidth letter forms. Both defeat literal matching outright, both are realistic
    in typography-rich prose, and NFKC folds both to ASCII.

    ⚠ AND THE THIRD EXAMPLE THIS DOCSTRING USED TO GIVE — THE NON-BREAKING HYPHEN — IS DEAD. It read
    "the fi-ligature, fullwidth letter forms, and the non-breaking hyphen". MEASURED: NFKC maps
    U+2011 NON-BREAKING HYPHEN to U+2010 HYPHEN, **not** to U+002D HYPHEN-MINUS, so an ASCII-hyphen
    pattern STILL MISSES after normalisation. NFKC does not rescue that case and never did.

    ⚠ THE POINT IS NOT THE CHARACTER. This docstring exists to record that a ruling survived its
    red-proof while its stated justification did not — and the CORRECTED justification then shipped
    with a fresh false example of its own, undetected until an outside reviewer read it. A correction
    is not self-certifying. The hyphen axis is crossed by ``expand``, deliberately and by
    enumeration, precisely because normalisation does not cross it.

    Widening equivalence in a tool that never removes hits can only ADD them, so this stays fail-safe.
    """
    return unicodedata.normalize("NFKC", text)


def compile_pattern(text: str, *, case_insensitive: bool = True) -> re.Pattern[str]:
    """A pattern that survives hard-wrapping, re-flowing and indentation changes.

    ⚠ SLURP, NEVER LINE-ORIENTED. The v1 design document hard-wrapped its OWN key phrase across a line
    break, so a line-oriented matcher would have missed the very sentence the document was about. Every
    whitespace run in the pattern becomes ``\\s+`` so the match does not care where the lines fall.

    Literal by default: the text is escaped before compilation, so a claim containing regex
    metacharacters cannot silently become a wildcard.
    """
    tokens = [re.escape(t) for t in re.split(r"\s+", normalise(text).strip()) if t]
    if not tokens:
        raise ValueError("empty pattern")
    flags = re.UNICODE | re.DOTALL
    if case_insensitive:
        flags |= re.IGNORECASE
    # re.UNICODE is explicit rather than assumed: \s is ASCII-only by default in several engines,
    # and this corpus is typography-rich.
    return re.compile(r"\s+".join(tokens), flags)


@dataclass
class Hit:
    surface: str
    location: str          # path:line-line, or board key
    span: str              # the FULL matched span (R5: a single context line reads as a false positive)
    pattern_label: str
    marker_offset: int | None = None   # observable, NOT a verdict (R5)
    in_namespace: bool = False
    in_tombstoned_block: bool = False   # R7 — inside a REGISTERED, HASH-MATCHING block
    in_unregistered_block: bool = False  # delimiter-shaped, NOT registered — a signal, not a control

    def disposition(self) -> str:
        """An OBSERVABLE, never a verdict.

        ``marker-4-lines-before`` states what was seen. ``QUOTED`` would state what it means — and the
        heuristic that decided that misclassified twice in one evening, in both directions.
        """
        if self.in_tombstoned_block:
            # R7 — a REGISTERED, HASH-MATCHING quote block. Safe to exclude precisely because the
            # exclusion is keyed on (location, record-id, block_sha) rather than on the shape of a
            # delimiter, which anyone can type.
            return "in-tombstoned-block"
        if self.in_unregistered_block:
            # ⚠ NOT A CONTROL — A SIGNAL. Text wrapped in withdrawal delimiters with no matching
            # registration is EITHER a correction someone forgot to harvest OR an attempted
            # suppression. Both are worth seeing, and neither may suppress the exit code.
            return "delimiter-block-UNREGISTERED"
        if self.in_namespace:
            return "control-namespace"
        if self.marker_offset is None:
            return "no-marker-within-window"
        return f"marker-{abs(self.marker_offset)}-lines-{'before' if self.marker_offset < 0 else 'after'}"


    def counts_as_live(self) -> bool:
        """R7/R9 — what may drive EXIT_HITS.

        ⚠ THIS IS THE ONLY PLACE ANYTHING IS EXCLUDED FROM ADJUDICATION, AND BOTH EXCLUSIONS ARE
        MACHINE-VERIFIABLE RATHER THAN INTERPRETIVE: a hash-pinned quote block (R7) and a manifested
        file in the tool-owned namespace (R13). Neither is a judgement about prose. Every excluded hit
        is STILL PRINTED (R5) — sorted last, never removed.

        Without this, exit 3 becomes permanent the moment the first real correction lands, and the
        tool's primary signal degrades to noise on first contact with its own output: the
        load-generation problem the design named, shipping.
        """
        return not (self.in_tombstoned_block or self.in_namespace)
        # NB: in_unregistered_block is deliberately ABSENT from this expression.


def block_spans(text: str) -> list[tuple[int, int, str, str]]:
    """Every delimiter-shaped span: (start, end, record_id, sha_of_body).

    ⚠ SHAPE ONLY. Whether a span may be EXCLUDED is decided by ``registered_spans`` below, which
    consults the registry. This function knows nothing about registration and must not be used to
    exclude anything.
    """
    return [(m.start(), m.end(), m.group("id"), block_sha(m.group("body").strip()))
            for m in _BLOCK_RE.finditer(normalise(text))]


def registered_spans(text: str, location: str, records: dict, selected: list[str]
                     ) -> tuple[list[tuple[int, int]], list[tuple[int, int]]]:
    """Split delimiter spans into (REGISTERED, UNREGISTERED).

    ⚠⚠ THE EXCLUSION IS KEYED ON REGISTRATION, NOT ON SHAPE, AND THIS WAS A REAL DEFECT FOUND IN
    DISSENT. The first implementation excluded any delimiter-shaped span, which meant WRAPPING LIVE
    TEXT IN ``<!-- withdrawn: -->`` SUPPRESSED IT FROM THE EXIT CODE — a self-service exclusion,
    available to anyone who types the delimiter, inside the tool built to stop claims disappearing
    without record. Searched-but-unreadable, reinvented as searched-but-EXCLUDABLE.

    ⚠ NOTE THE POLARITY: the code was MORE PERMISSIVE than its docstring. Every other instance in this
    project has run the other way — prose naming a hazard the code did not have. A docstring naming a
    CONTROL the code does not apply is worse, because the reader believes a gate exists.

    A span is registered iff some SELECTED record has a tombstone at THIS location whose recorded
    block hash matches the hash of THIS span's body. Shape alone earns nothing.
    """
    reg, unreg = [], []
    for start, end, rid, sha in block_spans(text):
        ok = False
        if rid in selected and rid in records:
            for t in records[rid].tombstones:
                if t.get("location") == location and t.get("block_sha256") == sha:
                    ok = True
                    break
        (reg if ok else unreg).append((start, end))
    return reg, unreg


# Correction markers are SIGNALS FOR RANKING ONLY. They never suppress a hit.
_MARKERS = re.compile(
    r"⚠|CORRECTED|WITHDRAWN|SUPERSED|It read|used to (?:read|say|end)|REWRITTEN|RETIRED",
    re.IGNORECASE)


def find_hits(text: str, pattern: re.Pattern[str], *, label: str, surface: str,
              location_of, window: int = 20, in_namespace: bool = False,
              registered: list[tuple[int, int]] | None = None,
              unregistered: list[tuple[int, int]] | None = None) -> list[Hit]:
    norm = normalise(text)
    # Default: NOTHING is registered. A caller that does not supply the registry gets no exclusions,
    # which is the fail-safe direction for a tool whose exclusions are the dangerous part.
    registered = registered or []
    unregistered = unregistered or []
    lines = norm.splitlines()
    # Offsets let a slurp match be reported with real line numbers.
    starts, pos = [], 0
    for ln in lines:
        starts.append(pos)
        pos += len(ln) + 1

    def line_of(off: int) -> int:
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= off:
                lo = mid
            else:
                hi = mid - 1
        return lo

    out: list[Hit] = []
    for m in pattern.finditer(norm):
        a, b = line_of(m.start()), line_of(m.end())
        marker_off = None
        for d in range(-window, window + 1):
            i = a + d
            if 0 <= i < len(lines) and _MARKERS.search(lines[i]):
                if marker_off is None or abs(d) < abs(marker_off):
                    marker_off = d
        # R7 — REGISTERED blocks are controls; delimiter-shaped-but-unregistered ones are SIGNALS.
        in_reg = any(bs <= m.start() and m.end() <= be for bs, be in registered)
        in_unreg = (not in_reg) and any(bs <= m.start() and m.end() <= be for bs, be in unregistered)
        out.append(Hit(surface=surface, location=location_of(a, b),
                       span="\n".join(lines[a:b + 1]).strip(),
                       pattern_label=label, marker_offset=marker_off,
                       in_namespace=in_namespace, in_tombstoned_block=in_reg,
                       in_unregistered_block=in_unreg))
    return out


# ── surfaces (R9, R10, R11) ───────────────────────────────────────────────────────────────────────
@dataclass
class SurfaceResult:
    name: str
    mechanism: str
    identity: str
    item_count: int
    items: list[tuple[str, str]] = field(default_factory=list)   # (location-key, text)
    error: str | None = None


def _git_head(path: Path) -> str:
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip() if r.returncode == 0 else "UNKNOWN"
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"


def enumerate_filesystem(name: str, root: Path, globs: list[str], git: bool) -> SurfaceResult:
    if not root.exists():
        # R10/§6: a configured path that does not exist is an INSTRUMENT FAILURE, not an empty result.
        return SurfaceResult(name, "filesystem", "MISSING", 0, error=f"configured path absent: {root}")
    items: list[tuple[str, str]] = []
    for g in globs:
        for p in sorted(root.glob(g)):
            if not p.is_file():
                continue
            try:
                items.append((str(p), p.read_text(encoding="utf-8", errors="replace")))
            except OSError as exc:
                return SurfaceResult(name, "filesystem", "READ-FAILED", 0,
                                     error=f"{p}: {type(exc).__name__}")
    identity = f"HEAD {_git_head(root)}" if git else f"{len(items)} files"
    return SurfaceResult(name, "filesystem", identity, len(items), items)


def enumerate_board(name: str, base_url: str, timeout: int = 30) -> SurfaceResult:
    """The board store. ⚠ SNAPSHOT THE KEY LIST ONCE — enumerate-then-fetch can otherwise miss keys
    added mid-run, and a key added between listing and fetching is invisible to both."""
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    def _get(url: str):
        # ⚠ THE DEFAULT urllib USER-AGENT IS 403'd BY THE EDGE IN FRONT OF THIS STORE. Discovered on
        # the FIRST real run: the tool failed CLOSED with an instrument failure rather than
        # enumerating zero keys and reporting clean, which is R5/R10 behaving correctly on first
        # contact with the world. A silent empty enumeration here is exactly the clean-and-wrong the
        # zero-items rule exists to catch.
        req = urllib.request.Request(url, headers={"User-Agent": "sweep/1.0 (+local tool)"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode())

    try:
        payload = _get(base_url)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
        return SurfaceResult(name, "http", "FETCH-FAILED", 0, error=f"{type(exc).__name__}: {exc}")
    keys = payload if isinstance(payload, list) else payload.get("keys", payload)
    if isinstance(keys, dict):
        keys = list(keys)
    keys = [k if isinstance(k, str) else k.get("key", "") for k in keys]
    keys = [k for k in keys if k]
    items: list[tuple[str, str]] = []
    for k in keys:
        try:
            v = _get(f"{base_url}/{k}")
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            return SurfaceResult(name, "http", "FETCH-FAILED", 0,
                                 error=f"key {k}: {type(exc).__name__}: {exc}")
        val = v.get("value", v)
        if isinstance(val, dict):
            val = val.get("value", json.dumps(val))
        items.append((f"board/{k}", val if isinstance(val, str) else json.dumps(val)))
    return SurfaceResult(name, "http", f"{len(keys)} keys @{stamp}", len(keys), items)


# ── R3: carrier units, extraction, expansion ──────────────────────────────────────────────────────
# ⚠ THE THREE MECHANISMS ARE DISTINCT AND NONE RETIRES ANOTHER:
#   TOLERANCE  — the matcher folds an axis. Crosses it UNCONDITIONALLY, for every term, for ever.
#   EXTRACTION — read a reached carrier, take its vocabulary. Crosses an axis OPPORTUNISTICALLY:
#                only where some ALREADY-REACHED carrier happens to use the other form.
#   EXPANSION  — generate the other spellings of a term already held. Crosses an ENUMERABLE axis
#                unconditionally for that term, with no second carrier required.
# The measured incident needed extraction for its 5/5 and expansion for its tripwire; a design
# review found that extraction ALONE could not mint `false pass`, which is the string the whole
# fixpoint argument rests on.

# Headings bound the carrier unit. ⚠ THE BLOCKQUOTE PREFIX IS LOAD-BEARING, NOT COSMETIC: this
# project's own design documents put every ruling under `> ### R7 — …`, so a heading regex that does
# not tolerate `>` would treat a 400-line design as ONE unit and harvest its entire vocabulary.
_HEADING = re.compile(r"^[ \t]*(?:>[ \t]*)*#{1,6}[ \t]+\S", re.MULTILINE)

# ⚠ AND A HEADING MARK INSIDE A FENCED BLOCK IS NOT A HEADING. `_HEADING` matches any line whose
# first non-whitespace (modulo `>` prefixes) is 1-6 `#` plus a space — WHICH INCLUDES A SHELL OR
# PYTHON COMMENT INSIDE A FENCE, markdown-in-markdown samples, and quoted code via the blockquote
# tolerance. MEASURED on the 2026-08-05 corpus: 245 such marks across 33 of 492 locations (6.7%).
#
# ⚠ WHY IT BECAME LOAD-BEARING ONLY NOW. Under the deleted fixpoint loop a mis-split barely
# mattered — the flood crossed every boundary anyway. Under claim-span seeding THE UNIT *IS* THE
# CANDIDATE SET, so a `# comment` inside a fence ABOVE the claim CUTS THE UNIT SHORT, extraction
# loses the claim's trailing vocabulary, and `variants` SILENTLY NARROWS. Worse: EDITING A CODE
# SAMPLE would then change harvest output — and the founding failure was a design document UNDER
# ACTIVE EDIT, so that instability class is the live one.
#
# ⚠ THE ABLATION CANNOT BE CITED AGAINST THIS. Both of its arms shared `_HEADING`, so it measured
# GRANULARITY (block vs unit), never PARSE CORRECTNESS.
_FENCE = re.compile(r"^[ \t]*(?:`{3,}|~{3,})", re.MULTILINE)


def _fenced_spans(text: str) -> list[tuple[int, int]]:
    """Fence-delimited regions, as (start, end) offsets.

    ⚠ AN UNCLOSED FENCE EXTENDS TO END OF TEXT, AND THE DIRECTION IS DELIBERATE. Suppressing splits
    after an unterminated fence yields FEWER, LARGER units — more vocabulary harvested, which is
    noise the tool already tolerates and prints. Ignoring it instead would let splits happen INSIDE
    what is probably a fence, which TRUNCATES a unit silently. Truncation is the dangerous direction
    under claim-span seeding, so the fail-safe is to over-include.
    """
    marks = [m.start() for m in _FENCE.finditer(text)]
    spans = [(marks[i], marks[i + 1]) for i in range(0, len(marks) - 1, 2)]
    if len(marks) % 2:                      # unterminated fence
        spans.append((marks[-1], len(text)))
    return spans

# Extraction classes. ⚠ ALL CASE-INSENSITIVE BY CONSTRUCTION, BECAUSE THE MATCHER IS. A
# lowercase-only compound class was MEASURED to see nothing at all in a carrier that spells its terms
# in capitals — and that was one of only three carriers the seed reached.
_C_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:[._][A-Za-z0-9_]+)+\b")        # snake · dotted
_C_CAMEL = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-z0-9]+)+\b")                    # CamelCase
_C_HYPHEN = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-‐‑][A-Za-z0-9]+)+\b")  # hyphen family
_C_QUOTED = re.compile(r"`([^`\n]{3,60})`")                                        # backticked span
# ⚠ CLASS (d) — FREE-FORM PROSE N-GRAMS — IS DELIBERATELY ABSENT. It is the only class that needs a
# judgement about which n-grams matter; the other three are decidable by SHAPE. An unbounded prose
# class plus a cutoff is R12's silent adjudication wearing a feature's clothes. It is deferred on a
# MEASURED reason, not a preference: expansion mints the space form without it (see EXPANSION).

_HYPHENS = ("-", "‐", "‑")
# Eligibility for orthographic expansion: word-shaped parts only (see ``expand``).
_ORTHO_PART = re.compile(r"^\w+$", re.UNICODE)

# ⚠ THE PROMOTION RULE, AND THE MEASUREMENT THAT SET IT. ITS JUSTIFICATION LIVES HERE, AT THE VALUE.
#
# A candidate is promoted into the LOOP only if it appears in at least this many ALREADY-REACHED
# carrier units. Everything else is still extracted, still scored on both legs, still written to the
# manifest-registered candidate file, and still stored on the record — so the rule NARROWS WHAT IS
# SEARCHED, never what is seen or kept. That is the difference R12 actually cares about: a cutoff is
# banned for being SILENT, and this one is deterministic, printed every run, and reversible.
#
# ⚠ THE FIRST IMPLEMENTATION HAD NO CUTOFF AT ALL, AND THAT WAS WRONG FOR A REASON I DID NOT EXPECT.
# It is not that promoting everything is SLOW — round-1 scoring measured ~18s. It is that promoting
# all 1745 round-1 candidates puts GENERIC identifiers into the net, which then reach essentially
# every unit in the corpus, so the next extraction harvests THE WHOLE CORPUS VOCABULARY. The loop
# still terminates — at the TRIVIAL fixpoint, where the net reaches everything and discriminates
# nothing. MEASURED: the uncapped run did not finish in 600s.
#
# WHY 2, MEASURED ON THE 2026-08-04 INCIDENT, seed "no egress", 2861 carrier units:
#   1745 candidates total · DF>=2 promotes 133 (7.6%) · DF==1 is a 494-long tail · DF==0 is 1118
#   pure expansions, which match nothing TODAY and are exactly the tripwires.
#   All four pre-registered terms survive: zero-gate 11 · false-pass 10 · false pass 7 · false-passes 4.
# ⚠ THIS IS A DEFENSIBLE FLOOR, NOT A CALIBRATION. It was chosen as the weakest rule that both
# bounds the net and retains every term the experiment named; it has been measured on ONE incident
# and one corpus, and it is not known to transfer.
PROMOTE_MIN_CARRIER_DF = 2


def canonical(term: str) -> str:
    """The MATCHER'S OWN equivalence class, decidable WITHOUT searching.

    ⚠ NOT "the set of spans it matches". Two DIFFERENT zero-hit tripwires both match the EMPTY SET
    and would be merged by a span-set test — destroying precisely the future-guarding forms expansion
    exists to create. The equivalence is a property of the pattern, so it is computed from the
    pattern: NFKC + case-fold + whitespace-run collapse, mirroring compile_pattern's flags.
    """
    return re.sub(r"\s+", " ", normalise(term).casefold()).strip()


def carrier_units(location: str, text: str) -> list[tuple[str, str]]:
    """Split a surface item into the STRUCTURAL units a candidate can be attributed to.

    ⚠ DERIVED FROM THE DOCUMENT, NOT FROM A WINDOW SIZE. A ±N-line window is an unmeasured constant
    whose value nothing justifies, and — worse for this corpus — it RE-DERIVES DIFFERENTLY AFTER
    EVERY REFLOW, so harvest would be non-deterministic on documents under active edit. R2 already
    immunised MATCHING against rewrap; the carrier unit must not reintroduce the sensitivity.

    A board value has no headings and is returned whole, which is its structure.
    """
    fenced = _fenced_spans(text)
    marks = [m.start() for m in _HEADING.finditer(text)
             if not any(a <= m.start() < b for a, b in fenced)]
    if not marks:
        return [(location, text)]
    bounds = ([0] if marks[0] > 0 else []) + marks + [len(text)]
    out = []
    for i in range(len(bounds) - 1):
        body = text[bounds[i]:bounds[i + 1]]
        if body.strip():
            out.append((f"{location}#{i}", body))
    return out


def extract_candidates(text: str) -> set[str]:
    """Classes (a) identifier (b) hyphen-family compound (c) backticked span. NOT free prose."""
    t = normalise(text)
    out: set[str] = set()
    for rx in (_C_IDENT, _C_CAMEL, _C_HYPHEN):
        out.update(m.group(0) for m in rx.finditer(t))
    out.update(m.group(1).strip() for m in _C_QUOTED.finditer(t) if m.group(1).strip())
    return {c for c in out if len(canonical(c)) >= 3}


def expand(term: str) -> set[str]:
    """Every ORTHOGRAPHIC spelling of a held term, across the axes that are ENUMERABLE.

    ⚠ THIS IS THE MECHANISM EXTRACTION CANNOT REPLACE. `false pass` and `false-pass` are DISJOINT in
    the measured corpus — neither literal reaches more than 3 of 5 carriers — and extraction can only
    mint the second from a carrier that already spells it that way. Expansion needs no such carrier.

    ⚠ AND THE HYPHEN AXIS IS WIDER THAN ASCII. MEASURED: NFKC maps U+2011 NON-BREAKING HYPHEN to
    U+2010 HYPHEN, **not** to U+002D HYPHEN-MINUS — so normalisation does NOT make an ASCII-hyphen
    pattern match a typographic one, and the whole hyphen family must be generated explicitly.

    Zero-hit expansions are KEPT. A form matching nothing today is a TRIPWIRE for the carrier written
    tomorrow, and this tool's entire subject is the surface nobody has written yet.

    ⚠ AND IT IS BIDIRECTIONAL, WHICH IT WAS NOT. The first implementation split on the HYPHEN FAMILY
    ONLY, so a SPACE-FORM term had nothing to split and returned the EMPTY SET — while the docstring
    above claimed "every orthographic spelling". ``expand("no egress")`` yielded NOTHING, and
    ``"no egress"`` IS THE SEED. The axis was enumerated in one direction and described in two.
    FIFTH described-vs-built divergence in this tool, and the first found by an outside reviewer
    rather than by execution.

    ⚠ SCOPE IS THE ORTHOGRAPHIC AXIS ONLY: space <-> hyphen-family <-> concatenation, in both
    directions. NO case folding (the matcher already folds it), NO pluralisation, NO stemming. Those
    are DIFFERENT AXES and each needs its own justification; the defect ruled here was ONE-WAYNESS,
    not narrowness, and widening beyond the ruling is how a fix becomes a redesign.
    """
    parts = [p for p in re.split(r"[-‐‑\s]+", normalise(term).strip()) if p]
    if len(parts) < 2:
        return set()
    # ⚠ ELIGIBILITY FOR THE ORTHOGRAPHIC AXIS — A DOMAIN PRECONDITION, NOT A NEW EXPANSION CLASS.
    # This does NOT amend the scope pinned above: it adds no axis, folds no case, pluralises and
    # stems nothing. It answers a different question — WHICH INPUTS ARE ELIGIBLE for the axis that
    # was already ruled — so the orthographic transform only runs where the parts are orthographic
    # parts. Widening was forbidden because it turns a fix into a redesign; THIS NARROWS
    # APPLICATION OF THE SAME TRANSFORM, which is the opposite failure mode.
    #
    # ⚠ AND IT CLOSES A PATH THAT ALREADY FIRES, NOT A FUTURE ONE. ``_C_QUOTED`` extracts backticked
    # spans, so ``count == 0 => no egress`` is a live candidate TODAY, and expansion turned it into
    # ``count-==-0-=>-no-egress``. That string is already sitting in a persisted 2026-08-04 run
    # transcript. Joining operators with hyphens produces a pattern that can match nothing and
    # occupies the variant set as noise.
    #
    # THE CRITERION IS STRUCTURAL AND STAYS THAT WAY: every part must be word-shaped, i.e. drawn
    # from the same alphabet the hyphen/space family joins. It is NEVER a semantic judgement about
    # whether something "is a claim" — that would be adjudication, which R5 forbids.
    if not all(_ORTHO_PART.match(part) for part in parts):
        return set()
    return ({" ".join(parts), "".join(parts)} | {h.join(parts) for h in _HYPHENS}) - {term}


# ── registry (R3, R4, R13) ────────────────────────────────────────────────────────────────────────
@dataclass
class Record:
    id: str
    seed: str
    variants: list[str]
    anchors: list[str]
    nets_run: list[str]
    tombstones: list[dict]          # {location, block_sha256}
    surfaces_at_withdrawal: list[str]
    expected_counts: dict[str, int]
    parent: str | None
    created: str
    # ── R3 state. ⚠ DEFAULTED SO AN OLDER RECORD STILL LOADS: ``Record(**d)`` would otherwise raise
    # on every pre-R3 record in the registry, and a tool that cannot read its own history has no
    # history. New fields are added ONLY with defaults, for the same reason.
    rounds: list[dict] = field(default_factory=list)      # [{round, carriers, promoted, unpromoted}]
    candidates: dict = field(default_factory=dict)        # canonical -> provenance + both DF legs
    at_fixpoint: bool = False

    @property
    def is_open(self) -> bool:
        """OPEN = zero registered tombstones = the harvest→correct→register loop was never closed.

        R4: ordering cannot be enforced (harvest and correction happen in one session and the person
        who benefits from skipping holds the clock). CLOSURE can be, because the tool holds the state.
        """
        return not self.tombstones


def load_records(ns: Path) -> dict[str, Record]:
    out: dict[str, Record] = {}
    rd = ns / "records"
    if not rd.exists():
        return out
    known = {f.name for f in fields(Record)}
    for p in sorted(rd.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        # ⚠ UNKNOWN KEYS ARE DROPPED, NOT FATAL. R3 added fields to the record; without this an
        # OLDER checkout of the tool crashes on the whole registry the moment a NEWER one writes to
        # it — and a tool that cannot read its own history has no history. Pairs with the defaults
        # on the new fields, which cover the opposite direction.
        out[d["id"]] = Record(**{k: v for k, v in d.items() if k in known})
    return out


def ancestor_closure(rec_ids: Iterable[str], records: dict[str, Record]) -> list[str]:
    """R1 — a caller-selected subset expands to its TRANSITIVE ANCESTORS.

    ⚠ WHY: record B withdraws A's fix. Harvesting B finds B's strings. Any reassertion of A inside B's
    own correction is A-VARIANT TEXT, which sweeping B alone never searches — exit 0, registry-backed,
    in the precise scenario this tool exists for. Caller-selected B must never green-wash A.
    """
    seen: list[str] = []
    stack = list(rec_ids)
    while stack:
        rid = stack.pop()
        if rid in seen or rid not in records:
            continue
        seen.append(rid)
        parent = records[rid].parent
        if parent:
            stack.append(parent)
    return seen


def manifest_check(ns: Path) -> list[str]:
    """R13 — every file the tool writes is manifested; anything else in the namespace is an
    INSTRUMENT FAILURE naming the stray file.

    ⚠ The alternative — excluding a PATH — invents a SEARCHED-BUT-UNREADABLE surface: a human note
    parked here containing a live carrier would be found, counted and suppressed permanently, with the
    run header remaining literally true.
    """
    mf = ns / "manifest.json"
    if not ns.exists():
        return []
    known = set(json.loads(mf.read_text(encoding="utf-8"))) if mf.exists() else set()
    known.add("manifest.json")
    stray = []
    for p in sorted(ns.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(ns))
            if rel not in known:
                stray.append(rel)
    return stray


def manifest_add(ns: Path, rel: str) -> None:
    mf = ns / "manifest.json"
    known = set(json.loads(mf.read_text(encoding="utf-8"))) if mf.exists() else set()
    known.add(rel)
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps(sorted(known), indent=2), encoding="utf-8")


# ── quote blocks + tombstones (R7, R8) ────────────────────────────────────────────────────────────
BLOCK_OPEN = "<!-- withdrawn:"
BLOCK_CLOSE = "<!-- /withdrawn -->"
_BLOCK_RE = re.compile(re.escape(BLOCK_OPEN) + r"(?P<id>[^\s>]+)\s*-->(?P<body>.*?)"
                       + re.escape(BLOCK_CLOSE), re.DOTALL)


def extract_blocks(text: str) -> dict[str, str]:
    """R7 — corrections quote withdrawn text ONLY inside a machine-delimited block.

    Tombstones then assert the BLOCK, never the prose, so a correction can be re-worded freely without
    breaking a control. v2 tombstoned prose and created a coupling where every rewrite broke a run —
    and if updating the control is harder than ignoring the failure, ignoring wins.
    """
    return {m.group("id"): m.group("body").strip() for m in _BLOCK_RE.finditer(text)}


def block_sha(body: str) -> str:
    return hashlib.sha256(normalise(body).encode("utf-8")).hexdigest()


# ── the run ───────────────────────────────────────────────────────────────────────────────────────
def _previous_hits(ns: Path) -> tuple[set[str], str | None]:
    """The previous run's live-hit keys, for the R14 undisposed diff."""
    rd = ns / "reports"
    if not rd.exists():
        return set(), None
    reports = sorted(rd.glob("*.txt"))
    if not reports:
        return set(), None
    last = reports[-1]
    keys, stamp = set(), None
    body = last.read_text(encoding="utf-8", errors="replace")
    for line in body.splitlines():
        if line.startswith("RUN "):
            stamp = line.split()[1]
        if line.count("\t") >= 2:
            disp, loc, _ = line.split("\t", 2)
            if disp not in ("in-tombstoned-block", "control-namespace"):
                keys.add(loc)
    return keys, stamp


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(f"no config at {CONFIG_PATH} — run `sweep init` first")
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def gather_surfaces(cfg: dict) -> list[SurfaceResult]:
    out = []
    for s in cfg["surfaces"]:
        if s["mechanism"] == "filesystem":
            out.append(enumerate_filesystem(s["name"], Path(s["root"]).expanduser(),
                                            s.get("globs", ["**/*.md"]), s.get("git", False)))
        elif s["mechanism"] == "http-board":
            out.append(enumerate_board(s["name"], s["url"]))
    return out


def run_controls(surfaces: list[SurfaceResult], cfg: dict) -> list[tuple[str, bool, str]]:
    """R9 — ONE CONTROL PER ENUMERATION MECHANISM, each travelling the REAL path.

    ⚠ v2 specified a single fixture file for five heterogeneous surfaces, which violated its own
    correlation law: an HTTP fetch/decode path shares no failure modes with a filesystem read. The
    concrete clean-and-wrong was a board fetch truncating while the filesystem fixture passed green.

    The control string must be present in BOTH a line-wrapped and a LIGATURE/FULLWIDTH form (R2) —
    NOT NBSP, which certifies nothing here because the whitespace class already matches it. A control
    aimed at the wrong character blesses the gap while looking rigorous, and the first version of this
    control did exactly that.
    """
    token = cfg["control_token"]
    pat = compile_pattern(token)
    results = []
    for s in surfaces:
        if s.error:
            results.append((f"{s.name}[{s.mechanism}]", False, s.error))
            continue
        found = any(pat.search(normalise(text)) for _, text in s.items)
        results.append((f"{s.name}[{s.mechanism}]", found,
                        "" if found else "control token not found on this surface"))
    return results


def instrument_gate(surfaces: list[SurfaceResult], cfg: dict, records: dict[str, Record],
                    selected: list[str], ns: Path
                    ) -> tuple[list[str], list[tuple[str, bool, str]]]:
    """THE WHOLE INSTRUMENT GATE, IN ONE PLACE, FOR EVERY COMMAND THAT TOUCHES A SURFACE.

    ⚠ THIS EXISTS BECAUSE ``harvest`` USED TO RUN A STRICTLY WEAKER GATE THAN ``sweep`` — it checked
    ``s.error`` and nothing else. Not zero-items, not the controls, not the count pins, not the
    manifest. So a harvest against a mis-globbed root or a half-truncated board fetch WROTE THE RECORD
    ANYWAY and pinned ``expected_counts`` FROM THE BROKEN ENUMERATION — authoritative state built on a
    reading ``sweep`` would have refused to certify, with the registry then vouching for every later
    clean run. **That is this tool's own founding failure, one level down, inside the command whose
    docstring claims to make the registry honest.**

    ⚠ AND IT IS SHARED, NOT COPIED. Two implementations that must agree is the dual-site shape this
    project has now met repeatedly: the copy is correct on the day it is written and silently diverges
    on the day only one side is edited. One function, both callers, or the divergence returns under a
    different name.

    ``selected`` is the set of records whose count pins are in force. ⚠ FOR A HARVEST THAT IS **EVERY
    REGISTERED RECORD**, not the record being written: a new harvest must never be able to certify a
    corpus that has dropped below a floor an existing record already established.
    """
    controls = run_controls(surfaces, cfg)
    errors: list[str] = []
    for s in surfaces:
        if s.error:
            errors.append(f"{s.name}: {s.error}")
        elif s.item_count == 0:
            # R10 — zero items is an INSTRUMENT FAILURE, not a clean result.
            errors.append(f"{s.name}: enumerated ZERO items")
        else:
            # R10 — and zero is not the only broken enumeration: a board returning 200 of 289 keys is
            # nonzero and would otherwise pass. Counts are pinned; any DROP fails. Never auto-updated
            # on a green run — that is a drift ratchet.
            # R10 — the pin is the STRICTEST of the config floor and every selected record's own
            # harvested count. Records could otherwise write a pin that nothing enforced (inert
            # state, the same half-built shape R14 had). Taking the max means registering a record
            # can only ever TIGHTEN the floor, never loosen one already in force.
            pins = [cfg.get("expected_counts", {}).get(s.name)]
            pins += [records[r].expected_counts.get(s.name) for r in selected if r in records]
            pins = [p for p in pins if isinstance(p, int)]
            exp = max(pins) if pins else None
            if exp is not None and s.item_count < exp:
                src = "config" if cfg.get("expected_counts", {}).get(s.name) == exp else "record pin"
                errors.append(
                    f"{s.name}: {s.item_count} items, expected >= {exp} ({src}) — COUNT DROPPED")
    for name, ok, why in controls:
        if not ok:
            errors.append(f"control {name}: {why}")
    for f in manifest_check(ns):
        errors.append(f"UNMANIFESTED FILE in control namespace: {f}")
    return errors, controls


def sweep(args) -> int:
    cfg = load_config()
    ns = NAMESPACE
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    records = load_records(ns)

    # R1 — DEFAULT IS EVERY REGISTERED RECORD, closed ones included. A record with tombstones is
    # "closed", but its withdrawn text is still live in the world: closed means the correction was made
    # once, not that the text is gone. A-variants inside B's correction prose are exactly the miss.
    if args.records:
        selected = ancestor_closure(args.records, records)
        swept_label = f"{','.join(args.records)} + ancestors: {','.join(selected)}"
    else:
        selected = list(records)
        swept_label = f"all registered ({len(selected)})"

    surfaces = gather_surfaces(cfg)
    instrument_errors, controls = instrument_gate(surfaces, cfg, records, selected, ns)
    stray = manifest_check(ns)

    # tombstones (R8) — checked, reported, and NEVER allowed to suppress the hit list
    tomb_ok, tomb_lost = 0, []
    by_path = {loc: text for s in surfaces if not s.error for loc, text in s.items}
    for rid in selected:
        for t in records[rid].tombstones:
            body = extract_blocks(by_path.get(t["location"], "")).get(rid)
            if body is not None and block_sha(body) == t["block_sha256"]:
                tomb_ok += 1
            else:
                tomb_lost.append((rid, t["location"],
                                  "block absent" if body is None else "block CHANGED"))

    # hits
    hits: list[Hit] = []
    per_pattern: dict[str, int] = {}
    ns_str = str(ns)
    for rid in selected:
        rec = records[rid]
        pats = [(f"{rid}:v{i}", v) for i, v in enumerate(rec.variants)] + \
               [(f"{rid}:anchor:{a}", a) for a in rec.anchors]
        for label, text in pats:
            try:
                pat = compile_pattern(text)
            except ValueError:
                continue
            per_pattern.setdefault(label, 0)
            for s in surfaces:
                if s.error:
                    continue
                for loc, body in s.items:
                    reg, unreg = registered_spans(body, loc, records, selected)
                    found = find_hits(body, pat, label=label, surface=s.name,
                                      registered=reg, unregistered=unreg,
                                      location_of=lambda a, b, L=loc: (
                                          f"{L}:{a + 1}" if a == b else f"{L}:{a + 1}-{b + 1}"),
                                      in_namespace=loc.startswith(ns_str))
                    hits.extend(found)
                    per_pattern[label] += len(found)

    open_records = [r for r in selected if records[r].is_open]

    # ── report ────────────────────────────────────────────────────────────────────────────────────
    L = []
    L.append(f"RUN {started}   swept: {swept_label}")
    L.append(f"MATCHING literal · whitespace→\\s+ · NFKC · unicode \\s · "
             f"{'case-insensitive' if True else 'case-sensitive'} · slurp")
    L.append("SURFACES  " + "  ".join(
        f"{s.name}[{s.identity if not s.error else 'ERROR'}]" for s in surfaces))
    L.append("CONTROLS  " + " · ".join(f"{n} {'OK' if ok else 'FAIL'}" for n, ok, _ in controls))
    L.append(f"TOMBSTONES {tomb_ok} matching, {len(tomb_lost)} lost")
    L.append(f"NAMESPACE {ns} — {len(stray)} unmanifested")
    # R11 — surface drift printed: records store the surfaces present at withdrawal; nothing else
    # reconciles that with the run's list, which is the stale-record direction.
    for rid in selected:
        drift = set(records[rid].surfaces_at_withdrawal) - {s.name for s in surfaces}
        if drift:
            L.append(f"⚠ SURFACE DRIFT {rid}: recorded but not swept now: {sorted(drift)}")
    if open_records:
        L.append(f"OPEN RECORDS  {', '.join(open_records)}   <-- process debt (exit {EXIT_DEBT})")
    L.append("")

    if instrument_errors:
        # exit 1 withholds the HIT LIST, never the DIAGNOSIS — the message names the failing check.
        L.append("⚠ INSTRUMENT FAILURE — the hit list is withheld because it cannot be trusted:")
        L.extend(f"    {e}" for e in instrument_errors)
        print("\n".join(L))
        return EXIT_INSTRUMENT

    if tomb_lost:
        L.append("⚠ TOMBSTONE LOST (a correction was re-worded) — HITS STILL PRINTED BELOW:")
        L.extend(f"    {rid} @ {loc}: {why}" for rid, loc, why in tomb_lost)
        L.append("")

    # R5 — unknown-disposition FIRST. Leading with a suspected-live class primes confirmation over
    # reading; leading with what has NOT been dispositioned primes reading.
    live_hits = [h for h in hits if h.counts_as_live()]
    order = {"no-marker-within-window": 0, "control-namespace": 3, "in-tombstoned-block": 3}
    hits.sort(key=lambda h: (order.get(h.disposition(), 1), h.surface, h.location))

    shown = hits[:args.show]
    for h in shown:
        first = h.span.splitlines()[0] if h.span else ""
        L.append(f"  {h.disposition():28} {h.location:52} | {first[:100]}")
        if len(h.span.splitlines()) > 1:
            L.append(f"  {'':28} {'':52} |   …span continues to end of match…")

    L.append("")
    # R6 — THE BUDGET NEVER DESTROYS INFORMATION. v2 refused to list above N and destroyed the count
    # AND the unlisted hits, moving skimming to a step that leaves no trace — with adverse selection,
    # since the broad recall nets are what blow the budget, so narrowing amputates recall first.
    L.append(f"TOTAL {len(live_hits)} live / {len(hits)} matched "
             f"({len(hits) - len(live_hits)} excluded: tombstoned blocks + control namespace) "
             f"/ {len({h.surface for h in hits})} surfaces"
             + (f" (showing {len(shown)}; full list spilled)" if len(hits) > len(shown) else ""))
    L.append("per-pattern: " + "  ".join(f"{k} [{v}]" for k, v in sorted(per_pattern.items())))
    L.append("READ THEM — this tool does not adjudicate.")
    L.append("This run does not prove the claim is absent. It proves these patterns were not")
    L.append("found on these surfaces at this timestamp.")

    # R14 — the DIFF is the half that makes persistence mean anything. Writing reports without
    # comparing them relocates the original failure from remembering-WHERE to remembering-TO-READ,
    # which is the failure R14 is named for.
    prev_keys, prev_stamp = _previous_hits(ns)
    now_keys = {f"{h.location}|{h.pattern_label}" for h in live_hits}
    new_since = sorted(now_keys - prev_keys)
    if prev_stamp:
        L.append("")
        L.append(f"SINCE {prev_stamp}: {len(new_since)} NEW live hit(s), "
                 f"{len(now_keys & prev_keys)} still undisposed from the previous run")
        for k in new_since[:args.show]:
            L.append(f"  NEW  {k}")
    else:
        L.append("")
        L.append("SINCE: no previous run recorded — this is the baseline.")

    report = "\n".join(L)
    print(report)

    # R14 — persist the run, so the NEXT run can diff undisposed hits. Without this the tool merely
    # relocates the original failure from remembering-WHERE to remembering-TO-READ.
    rep_dir = ns / "reports"
    rep_dir.mkdir(parents=True, exist_ok=True)
    rel = f"reports/{started.replace(':', '').replace('-', '')}.txt"
    (ns / rel).write_text(report + "\n\nFULL HIT LIST:\n" +
                          "\n".join(f"{h.disposition()}\t{h.location}|{h.pattern_label}\t"
                                    f"{h.span}" for h in hits),
                          encoding="utf-8")
    manifest_add(ns, rel)

    if tomb_lost:
        return EXIT_TOMBSTONE
    if live_hits:
        return EXIT_HITS
    if open_records:
        return EXIT_DEBT
    return EXIT_CLEAN


def harvest(args) -> int:
    """R3/R4 — HARVEST THE STRINGS THAT ACTUALLY OCCUR, then register the record.

    ⚠ THIS IS THE COMMAND THAT MAKES THE REGISTRY HONEST. Memory is used for exactly one thing — the
    SEED — because seeding one search string is what memory is good enough for. Everything downstream
    (which variants exist, on which surfaces, how many) is ENUMERATED BY THE TOOL. v1 enumerated from
    memory and missed two of five carriers; v2 would have persisted that miss as authoritative state.

    The record is written OPEN (zero tombstones), so every subsequent run prints it and exits with the
    process-debt code until the corrections are made and registered. **CLOSURE is enforced, not
    ORDERING** — the ordering cannot be policed because the person who benefits from skipping holds
    the clock; the tool holds the state instead.
    """
    cfg = load_config()
    surfaces = gather_surfaces(cfg)
    # ⚠ THE FULL GATE, THE SAME ONE ``sweep`` RUNS. This used to be ``if s.error`` and nothing else,
    # so a harvest could certify — and PIN — an enumeration sweep would have refused. The pins in
    # force are EVERY registered record's, not the one being written: see instrument_gate.
    records = load_records(NAMESPACE)
    errs, _ = instrument_gate(surfaces, cfg, records, list(records), NAMESPACE)
    if errs:
        print("⚠ INSTRUMENT FAILURE — refusing to harvest against surfaces that cannot be trusted.")
        print("  NOTHING WAS WRITTEN. A record written now would pin these counts as authoritative.")
        for e in errs:
            print("   ", e)
        return EXIT_INSTRUMENT

    # ── THE UNIT INDEX. Built ONCE, from a single snapshot, and the fixpoint is defined on it.
    # ⚠ THE TOOL'S OWN NAMESPACE IS EXCLUDED FROM EXTRACTION. Run reports contain every live hit's
    # full span, so harvesting them would bootstrap round 2's vocabulary TAUTOLOGICALLY out of round
    # 1's output, and the control fixture would enter the candidate set as if it were evidence.
    ns_str = str(NAMESPACE)
    units: list[tuple[str, str, str]] = []          # (unit_id, surface_name, text)
    for surf in surfaces:
        for loc, body in surf.items:
            if loc.startswith(ns_str):
                continue
            for uid, utext in carrier_units(loc, normalise(body)):
                units.append((uid, surf.name, utext))

    # ── THE FIXPOINT LOOP (R3). Add-only over a fixed snapshot ⇒ the reached set is monotone and
    # bounded by the corpus, so it terminates in at most |units| rounds and CANNOT oscillate.
    # ⚠ THERE IS NO --anchor FLAG, AND ITS ABSENCE IS THE RULING. The design states that ANCHORS ARE
    # AN OUTPUT OF HARVEST, NEVER AN INPUT, and the CLI used to invite them in anyway — laundering a
    # remembered guess into the registry wearing an output's clothing. MEASURED on the 2026-08-04
    # incident: hand-chosen subject anchors reached 1 of 5 carriers, STRICTLY WORSE than the literal
    # seed's 3 of 5, and recovered NOTHING the seed had missed. The bias is systematic — whoever
    # picks anchors has just finished writing the correction, so they reach for the MECHANISM's
    # vocabulary while the carriers are still speaking the CLAIM's.
    held: dict[str, str] = {canonical(args.seed): args.seed}
    reached: dict[str, str] = {}
    occurrences: dict[str, int] = {}
    rounds: list[dict] = []
    candidates: dict[str, dict] = {}
    rnd = 0
    while True:
        rnd += 1
        compiled = []
        for c, term in held.items():
            try:
                compiled.append((c, term, compile_pattern(term)))
            except ValueError:
                continue
        new_units = {}
        for uid, sname, utext in units:
            for c, term, pat in compiled:
                hits = pat.findall(utext)
                if hits:
                    occurrences[c] = occurrences.get(c, 0) + len(hits)
                    if uid not in reached:
                        new_units[uid] = utext
        # ⚠ THE STOP RULE IS EVALUATED AFTER THE ROUND HAS SEARCHED THE TERMS THE PREVIOUS ROUND
        # PROMOTED. Stopping when a round PROMOTES nothing would truncate one round early and drop
        # exactly the opportunistic axis-crossing terms the loop exists for.
        if not new_units:
            rounds.append({"round": rnd, "new_carriers": 0, "promoted": 0, "held": len(held)})
            break
        reached.update(new_units)

        # EXTRACT from every reached carrier, then EXPAND every candidate and every held term.
        found: set[str] = set()
        for utext in reached.values():
            found |= extract_candidates(utext)
        expansions: set[str] = set()
        for t in list(found) + list(held.values()):
            expansions |= expand(t)

        promoted = 0
        for term, origin in [(t, "extraction") for t in sorted(found)] + \
                            [(t, "expansion") for t in sorted(expansions)]:
            c = canonical(term)
            if not c:
                continue
            # carrier-DF and corpus-DF are recorded as TWO LEGS, never fused into one score. A single
            # scalar hides WHICH leg moved a candidate, and R5's whole posture is observables over
            # verdicts. Nothing is excluded on either leg — they RANK.
            if c not in candidates:
                try:
                    cpat = compile_pattern(term)
                except ValueError:
                    continue
                # ⚠ ONLY THE CHEAP LEG IS COMPUTED IN THE LOOP. carrier_df scans the REACHED set
                # (tens to hundreds of units) and is what the promotion rule consults. corpus_df
                # scans the WHOLE corpus and is a printed RANKING leg only — computing it per
                # candidate per round measured ~10ms x thousands of candidates and did not finish
                # in 600s. It is computed once, at the end, for the candidates actually recorded.
                candidates[c] = {"term": term, "origin": origin, "round": rnd,
                                 "carrier_df": sum(1 for u in reached.values() if cpat.search(u)),
                                 "corpus_df": None}
            if c not in held and candidates[c]["carrier_df"] >= PROMOTE_MIN_CARRIER_DF:
                held[c] = term
                promoted += 1
        rounds.append({"round": rnd, "new_carriers": len(new_units), "promoted": promoted,
                       "held": len(held)})

    # The second leg, once, at the end. R5: BOTH legs are reported, never fused into one score —
    # a single scalar hides WHICH leg moved a candidate.
    for c, d in candidates.items():
        try:
            cpat = compile_pattern(d["term"])
        except ValueError:
            d["corpus_df"] = -1
            continue
        d["corpus_df"] = sum(1 for _, _, u in units if cpat.search(u))

    where = {sname for uid, sname, _ in units if uid in reached}
    rec = Record(
        id=args.id, seed=args.seed,
        variants=sorted({v for v in held.values()}) or [args.seed],
        anchors=[],   # OUTPUT-only; see the fixpoint loop above
        nets_run=["literal-seed", "carrier-extraction", "orthographic-expansion"],
        tombstones=[],                      # OPEN by construction — see R4
        surfaces_at_withdrawal=sorted(where),
        expected_counts={s.name: s.item_count for s in surfaces},
        parent=args.parent, created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        rounds=rounds, candidates=candidates, at_fixpoint=True)
    variants = {v: occurrences.get(canonical(v), 0) for v in rec.variants}

    rd = NAMESPACE / "records"
    rd.mkdir(parents=True, exist_ok=True)
    rel = f"records/{rec.id}.json"
    # ⚠ NEVER OVERWRITE AN EXISTING RECORD. `harvest` wrote unconditionally, and a re-harvest under
    # an id already in use RESET `tombstones` TO [] — silently destroying the hash-pinned exclusions
    # a CLOSED record licenses. The loss is INVISIBLE by construction: the tombstones that would
    # raise `tomb_lost` on the next sweep are the very thing deleted, so the run afterwards is clean
    # and the formerly-excluded blocks simply return as live hits with no explanation.
    # ⚠ THIS WAS A LIVE NEAR-MISS, NOT A HYPOTHETICAL: on 2026-08-04 I re-harvested an existing id
    # to register an experiment's anchors. That record happened to be OPEN, so nothing was lost.
    # Inside the tool built to stop claims disappearing without record.
    if (NAMESPACE / rel).exists():
        print(f"⚠ INSTRUMENT FAILURE — record {rec.id!r} ALREADY EXISTS. NOTHING WAS WRITTEN.")
        print(f"    {NAMESPACE / rel}")
        print("  Overwriting would reset its tombstones to [], destroying every hash-pinned")
        print("  exclusion it licenses — and the next sweep could not report the loss, because the")
        print("  tombstones that would flag it are what the overwrite deletes.")
        print("  Choose a new id, or delete the record deliberately if that is what you mean.")
        return EXIT_INSTRUMENT
    (NAMESPACE / rel).write_text(json.dumps(rec.__dict__, indent=2), encoding="utf-8")
    manifest_add(NAMESPACE, rel)

    # R6 — the full ranked candidate list is SPILLED TO A MANIFESTED FILE, never destroyed. The
    # display budget bounds what is SHOWN; it never bounds what is searched or what is recorded.
    ranked = sorted(candidates.values(),
                    key=lambda d: (-d["carrier_df"], d["corpus_df"], d["term"]))
    crel = f"candidates/{rec.id}.tsv"
    (NAMESPACE / "candidates").mkdir(parents=True, exist_ok=True)
    (NAMESPACE / crel).write_text(
        "carrier_df\tcorpus_df\tround\torigin\tterm\n" +
        "\n".join(f"{d['carrier_df']}\t{d['corpus_df']}\t{d['round']}\t{d['origin']}\t{d['term']}"
                  for d in ranked) + "\n", encoding="utf-8")
    manifest_add(NAMESPACE, crel)

    print(f"HARVESTED {rec.id}")
    print(f"  seed            : {rec.seed!r}")
    print(f"  carrier units   : {len(reached)} reached, of {len(units)} in the corpus")
    print(f"  rounds          : {len(rounds)}  "
          + " · ".join(f"r{r['round']}:+{r['new_carriers']}c/+{r['promoted']}p" for r in rounds))
    print("  FIXPOINT        : reached — the final round searched every promoted term and found no")
    print( "                    new carrier. Add-only over one snapshot, so this cannot oscillate.")
    unprom = [d for d in candidates.values() if canonical(d["term"]) not in held]
    print(f"  candidates      : {len(candidates)} scored  ·  {len(candidates)-len(unprom)} PROMOTED "
          f"(carrier_df >= {PROMOTE_MIN_CARRIER_DF})  ·  {len(unprom)} NOT PROMOTED")
    print( "  ⚠ NOT-PROMOTED IS NOT DISCARDED: every candidate above is scored on BOTH legs, written")
    print(f"    to {crel}, and stored on the record. The rule narrows WHAT IS SEARCHED, never what is")
    print( "    kept — and it is printed here every run, which is the whole of R12's requirement.")
    print(f"  patterns held   : {len(rec.variants)}  (occurrences: {sum(variants.values())})")
    print(f"  full ranked list: {crel}   [carrier_df, corpus_df — TWO LEGS, never fused]")
    for d in ranked[:12]:
        print(f"      c{d['carrier_df']:<3} n{d['corpus_df']:<4} r{d['round']} {d['origin'][:9]:<9} "
              f"{d['term'][:64]}")
    if len(ranked) > 12:
        print(f"      … {len(ranked) - 12} more in {crel} — NOT truncated, SPILLED")
    print(f"  surfaces        : {', '.join(rec.surfaces_at_withdrawal) or 'NONE — seed matched nothing'}")
    print(f"  nets run        : {', '.join(rec.nets_run)}")
    print(f"  expected counts : pinned for {len(rec.expected_counts)} surfaces")
    print()
    print("⚠ RECORD IS OPEN (zero tombstones). Every sweep will print it and exit with the")
    print(f"  process-debt code ({EXIT_DEBT}) until corrections are written and registered.")
    print("  Quote the withdrawn text in each correction inside a block:")
    print(f"      {BLOCK_OPEN}{rec.id} -->")
    print("      <the withdrawn text, verbatim>")
    print(f"      {BLOCK_CLOSE}")
    return EXIT_DEBT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sw = sub.add_parser("sweep", help="sweep records (default: ALL registered)")
    sw.add_argument("records", nargs="*", help="record ids; omit for all (R1)")
    sw.add_argument("--show", type=int, default=40)
    sw.set_defaults(fn=sweep)
    hv = sub.add_parser("harvest", help="harvest actual variants and register a record (R3/R4)")
    hv.add_argument("id")
    hv.add_argument("seed")
    hv.add_argument("--parent", default=None, help="supersession parent record id (R1)")
    hv.set_defaults(fn=harvest)
    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
