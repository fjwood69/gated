#!/usr/bin/env python3
"""sweep — find every surface still asserting a withdrawn claim.

Built to DESIGN-supersession-sweep.md — v3 (ratified 2026-08-04) THROUGH v4/R15, R16 and R17, all
ratified 2026-08-06 and built here. Ruling IDs (R1, R2, R4a, …) refer to that document; the design
carries the reasoning, this file carries the mechanism, and neither is complete without the other.

⚠ THIS LINE SAID "v3" FOR A DAY AFTER v4 WAS BUILT, AND A VERSION CLAIM IS RULED RATHER THAN TIDIED.
An outside reviewer, given only this file, framed the mismatch as a binary — stale header, or a
rationale citing an unratified design — and it was neither: the DESIGN's own title was the stale
surface, and this header was right until v4 landed. Two surfaces, one status, and the false one hid
behind the true one. The tool's entire subject, on line 4 of the tool.

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
EXIT_SEED = 5         # the SEED the caller supplied cannot be searched with (R16)
EXIT_BIND = 6         # `retombstone` found nothing to bind (R4/R7)
EXIT_CONFIG = 7       # no config file — the CALLER'S ENVIRONMENT is unbuilt (2026-08-08)
# ⚠ SEVEN, AND THE SEVENTH WAS THE ONE AN OPERATOR HITS **FIRST**. Until 2026-08-08 the no-config
# refusal was `sys.exit(<str>)`, which exits **1** — so it landed on EXIT_INSTRUMENT by COINCIDENCE
# rather than by construction, and the whole enumeration above was an unpartitioned roster: six
# causes each carrying a rationale, and the commonest cause of all declared NOWHERE.
# ⚠ THE COLLISION WAS NOT COSMETIC. By R16's own reasoning, config-absent is a CALLER-ENVIRONMENT
# failure, not a failure of the corpus or the channel — so exit 1 sent the reader to check globs,
# roots and the board endpoint when the thing actually wrong was that they had never made a config.
# Different cause, different remediation, different code: the law this file already states, applied
# to the door every first-time operator walks through. Found by consult 1a37f46e.
# ⚠ SIX, DELIBERATELY NOT TWO. `EXIT_TOMBSTONE` (2) means "a registered control BROKE"; this means
# "there was nothing to register in the first place". Opposite ends of the same loop — one is a
# correction that drifted, the other is a correction that was never written — and an operator shown
# code 2 goes looking for a re-worded block that does not exist. Same stratification law as R16's
# exit 5: different CAUSE, different remediation, so different code.
# ⚠ R16 — WHY THE BROKEN SEED GETS ITS OWN STRATUM RATHER THAN REUSING EXIT_INSTRUMENT.
# Every other code above names a failure of the CORPUS or the CHANNEL: a surface vanished, a fetch
# truncated, a control did not travel, a file appeared unmanifested. A seed that will not compile is
# none of those — it is a CALLER-INPUT failure, and the whole point of stratifying exits is that
# DIFFERENT CAUSES GET DIFFERENT REMEDIATIONS. An operator who sees "instrument failure" goes and
# checks the corpus, the board endpoint and the glob roots; the thing actually wrong is the string
# they typed. Folding this into code 1 would send every future reader to the wrong place, which is
# the same defect R4a exists to prevent one level in.

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

# ── R15 — THE CORPUS FIXPOINT LOOP IS GONE. ITS OBITUARY LIVES HERE, IN THE CODE (R15h).
#
# ⚠ THE JUSTIFICATION FOR A DELETION MUST LIVE WHERE THE NEXT READER LOOKS. Before this, the flood
# measurements existed only in a consult and on a board — which is precisely the failure this tool
# was built to close, performed by the tool's own history.
#
# WHAT THE LOOP DID: seed the net, search the corpus, extract vocabulary from every unit that
# matched, promote what recurred, search again. It terminated. It terminated at the TRIVIAL FIXPOINT
# — the net reaching everything and discriminating nothing.
#
#   MEASURED, 2026-08-04 incident, seed "no egress":  uncapped 98% of the corpus at round 4
#   MEASURED, same corpus, commonness-capped:         85% and STILL CLIMBING at round 7
#   MEASURED, 2026-08-06, a corpus NOT chosen for the test and a carrier nobody planted:
#       2,727 of 2,752 units = 99.1%, 8,848 terms held, ~32 minutes, FROM A SEED OCCURRING 5 TIMES
#
# ⚠ AND THE OBVIOUS READING OF THAT LAST RUN IS WRONG, WHICH IS WHY IT IS WRITTEN DOWN. It promoted
# `and` (carrier-DF 2003), `for`, `str`, `int`, `---`. That looks like a broken expander, and it is
# NOT: every one has origin=extraction, and the orthographic class gate on `expand` does not touch a
# single one. THE PATH IS `_C_QUOTED` PLUS A LENGTH FLOOR OF 3 — any backticked span of 3-60 chars
# becomes a candidate, and technical prose is full of them. MEASURED on that corpus, the commonest
# short backticked spans are inline separators: ` | ` x94, ` / ` x76, ` + ` x61, ` and ` x34. So
# ` and ` mints `and`. ONE OCCURRENCE IS ENOUGH — the term is minted once and its carrier-DF is then
# computed over the whole reached set, which for an ordinary English word is thousands.
# THAT IS STRUCTURAL TO SHAPE-BASED EXTRACTION OVER PROSE-CONTAINING-CODE, not a defect in one class.
#
# FOUR RESCUES DIED BY MEASUREMENT, NOT BY OPINION, and they are named so none is re-proposed:
#   1. NO CUTOFF AT ALL          — did not finish in 600s; promoting everything harvests the corpus.
#   2. CORPUS-RARITY             — refuted; the flood is not made of rare terms.
#   3. CARRIER-UNIT SIZE         — bounded units flood within ONE percentage point.
#   4. A COMMONNESS CAP          — fitted to retain the known-good, and STILL 85% and climbing.
# ⚠ RAISING THE LENGTH FLOOR FROM 3 TO 4 WOULD DROP `and`/`for`/`str`/`int` AND IS THE SAME MISTAKE
# A FIFTH TIME. The tune is not the answer; the POPULATION is.
#
# > Same corpus. Same extractor. Same expander. THE ONLY THING THAT CHANGED WAS THE POPULATION READ.
# The loop extracted from documents that HAPPENED TO CONTAIN THE SEED. Claim-span seeding extracts
# from THE PLACES THE CLAIM WAS ACTUALLY MADE. Three refuted mechanisms were all statistics over the
# wrong population, and NO REPARAMETRISATION REPAIRS A POPULATION.
#
# ⚠ AND WHAT THE REPLACEMENT BUYS IS NOT BETTER FILTERING. It is a candidate set bounded by ONE SPAN
# rather than by the corpus's supply of short quoted tokens. The claim-span set never contained `and`
# BECAUSE `and` IS NOT IN THE CLAIM'S BLOCK — not because any rule rejected it. No rule fires. The
# population is different. Describing it as filtering would invite the reparametrisation above.
#
# THERE IS NO PROMOTION RULE ANY MORE, SO R12'S SILENT-CUTOFF HAZARD DOES NOT ARISE: there is no
# cutoff left to be silent about.
BOUNDARY_RULE = "carrier_units/heading-bounded/fence-aware@2026-08-06"
# ⚠ VERSIONED BECAUSE A RECORD MUST BE DIAGNOSABLE LATER. If a re-run disagrees with a stored record,
# the question is CORPUS CHANGED versus RULE CHANGED, and without this pin the two are
# distinguishable only by memory — which is the thing this tool exists not to rely on.


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
            # ⚠ `#unit-<n>`, NOT `#<n>`. A board key may legitimately END in `#<digits>`, and a
            # key with no headings is returned UNSUFFIXED — so `board/incident#42` and a unit of
            # `board/incident` were indistinguishable, and `_unit_location` reduced the former to
            # the latter, MERGING TWO DISTINCT LOCATIONS and understating the very figure it exists
            # to report. An unambiguous separator makes the collision unrepresentable.
            out.append((f"{location}#unit-{i}", body))
    return out


def _unit_location(unit_id: str) -> str:
    """The LOCATION a unit belongs to — `docs/a.md#3` -> `docs/a.md`.

    ⚠ REACH MUST BE REPORTABLE AT BOTH GRANULARITIES, AND UNTIL NOW IT WAS NOT. Every reach figure
    this project produced was a UNIT count, because nothing recorded which units were reached and the
    location figure could not be recovered afterwards. **A HUMAN OPENS LOCATIONS** — `11% of units`
    and `41% of locations` were the same run, and only the second is a reading list.

    ⚠ ONLY A ``#unit-<digits>`` SUFFIX IS STRIPPED, AND THE FIRST VERSION OF THIS WAS WRONG. It
    stripped any trailing `#<digits>` — but a board key may legitimately END in `#<digits>`, and a
    location with no headings is returned by ``carrier_units`` UNSUFFIXED. So `board/incident#42`
    was reduced to `board/incident` and MERGED WITH A DISTINCT LOCATION, understating the location
    count. A blind `rsplit("#")` is worse still. The separator now makes the collision
    unrepresentable rather than merely unlikely.
    """
    head, sep, tail = unit_id.rpartition("#unit-")
    return head if sep and tail.isdigit() else unit_id


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


def seed_census(seed: str, units: list[tuple[str, str, str]]) -> dict:
    """EVERY SEARCHED UNIT THE SEED OCCURS IN — the ADJUDICATION'S INPUT, recorded BEFORE anything
    narrows it.

    ⚠ "SEARCHED" IS NOT A HEDGE, IT IS THE SCOPE. The unit index this is handed EXCLUDES the tool's
    own namespace (see ``harvest``), and until this line was written that exclusion was documented
    only against EXTRACTION — so a docstring saying "every unit" described a population the caller
    does not supply. Doc-vs-code drift inside the tool whose entire subject is doc-vs-code drift.

    ⚠ THIS EXISTS BECAUSE THE DESIGN RECORDS THE OUTCOME OF AN ADJUDICATION AND NEVER THE
    ADJUDICATION. Claim-span seeding asks which carrier holds the claim, and that answer is a
    JUDGEMENT. MEASURED on the 2026-08-04 incident: ``no egress`` is ordinary vocabulary in a project
    about network isolation, and SEVEN OF THE EIGHT locations using the phrase were HOMONYMS — they
    meant ``--network=none``, not the withdrawn compound ``count == 0 ⇒ no egress``. A record that
    stores the chosen carrier and nothing else has replaced an ENUMERATION with an UNRECORDED
    JUDGEMENT — which is this tool's founding failure (a sweep that searches what its author
    remembers) one level down, inside the command whose docstring claims to make the registry honest.

    ⚠ IT COUNTS, IT NEVER CHOOSES (R5). No threshold, no ranking, no filter: every unit holding the
    seed is listed. WHICH of them were actually used is recorded SEPARATELY, by the caller, from the
    loop's own behaviour — so the census and the run can DISAGREE VISIBLY. Fusing the two would be the
    adjudication wearing the instrument's clothes, and a census that also decided could never
    contradict the decision.

    ⚠ AND IT IS COMPUTED ON THE SAME UNIT INDEX THE RUN USES, from the same snapshot. A census built
    by a second enumeration would be measuring a different population from the one seeded, and any
    disagreement would then be attributable to the instrument rather than to the judgement — which is
    exactly the confound that made the first ARM-1 grid unreadable.

    An uncompilable seed yields ``error`` set and an empty population. It is reported rather than
    raised, because the caller decides what an instrument condition costs; this function only counts.
    """
    out: dict = {"seed": seed, "unit_total": len(units), "units_holding": [],
                 "surfaces": [], "occurrences_total": 0, "error": None}
    try:
        pat = compile_pattern(seed)
    except ValueError as exc:
        out["error"] = f"seed does not compile to a pattern: {exc}"
        return out
    for uid, sname, utext in units:
        n = len(pat.findall(normalise(utext)))
        if n:
            out["units_holding"].append({"unit": uid, "surface": sname, "occurrences": n})
    out["surfaces"] = sorted({h["surface"] for h in out["units_holding"]})
    out["occurrences_total"] = sum(h["occurrences"] for h in out["units_holding"])
    return out


def census_adjudication(census: dict, seeded: Iterable[str], *,
                        carriers_named: Iterable[str] = (), basis: str) -> dict:
    """What was DONE with the census — kept separate from the census itself, and PURE so it can be
    tested on inputs that DISAGREE.

    ⚠ THE SEPARATION IS THE POINT. ``seeded`` is measured by the caller from the run's own behaviour,
    never copied from the census, so the two can contradict each other and the record will say so.
    Inlining this as a set difference over a variable derived from the census would make the
    contradiction UNREPRESENTABLE — the record would agree with itself by construction, which is the
    property a self-check must not have.

    ⚠ AND IT IS A FUNCTION SO THE DISAGREEMENT PATH CAN BE EXERCISED AT ALL. In the current build the
    census and round 1 search the same seed over the same units, so they agree BY CONSTRUCTION and no
    end-to-end test can distinguish a measurement from a copy. Extracting the reconciliation is what
    makes the difference testable today rather than a claim waiting for ``--carrier`` to arrive.
    """
    held_units = {h["unit"] for h in census["units_holding"]}
    seeded = list(seeded)
    return {"carriers_named": list(carriers_named),
            "seeded": sorted(seeded),
            "adjudicated_out": sorted(held_units - set(seeded)),
            "basis": basis}


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
    # ⚠ R15g — THESE THREE ARE DEAD STATE AND THEY STAY. `rounds`, `candidates` and `at_fixpoint`
    # belonged to the fixpoint loop, which R15 deleted. Removing the FIELDS would make every record
    # written before 2026-08-06 fail to load, and a tool that cannot read its own history has none.
    # They are never written by the current code; they are read, preserved, and printed as history.
    rounds: list[dict] = field(default_factory=list)      # [{round, carriers, promoted, unpromoted}]
    candidates: dict = field(default_factory=dict)        # canonical -> provenance + both DF legs
    at_fixpoint: bool = False
    # ⚠ THE SEED CENSUS AND THE ADJUDICATION OVER IT — the population the seeding decision was made
    # FROM, not merely the decision's outcome. Defaulted like every other added field so an older
    # record still loads; a record written before this field existed carries {} and says so, which is
    # honest, rather than an empty census implying a measured zero.
    seed_census: dict = field(default_factory=dict)
    # ── R15/R15g. ALL DEFAULTED, for the same reason as every field above it.
    # `carriers`      — the location(s) the operator NAMED as holding the claim. An adjudication.
    # `boundary_rule` — which unit-boundary rule produced those spans, so a later disagreement is
    #                   diagnosable as CORPUS CHANGED versus RULE CHANGED.
    # `seeding_units` — WHICH units seeded, and what each contributed (R15f: the migrated audit
    #                   target — the candidates TSV recorded a FILTERING decision that no longer
    #                   exists, but WHICH TEXT SEEDED THE VOCABULARY is still a decision).
    # `reach`         — R15c's one corpus pass, at BOTH granularities. ⚠ THE REACHED SET ITSELF IS
    #                   PERSISTED, not just its size: every reach figure this project produced before
    #                   today was unit-only, because nothing recorded WHICH units were reached, and
    #                   a human opens LOCATIONS.
    # ── R18 SHAPE ONLY. RULED 2026-08-06: ADOPT THE FIELDS, BUILD NO COMMAND YET.
    # ⚠ NOTHING EXCLUDES A RETIRED RECORD FROM ANYTHING. These fields are carried, printed, and
    # otherwise INERT — a retired record is still swept, still counted, still pinned, still checked.
    # That is deliberate: the design review found THREE SEMANTIC ERRORS BY OMISSION in the retire
    # draft, and the one that matters here is that `selected` feeds SIX consumers (count pins,
    # tombstone-loss checks, variant sweeping, process debt, drift printing, and R7 exclusion
    # licensing). "Leaves the default sweep set, and nothing else" is UNIMPLEMENTABLE AS STATED, and
    # the obvious implementation — filter `selected` once, early — silently changes all six and
    # VOIDS THE DRAFT'S OWN DEBT SAFEGUARD while the header still claims it holds.
    #
    # ⚠ SO THE SAFEGUARD SHIPS BEFORE THE LEVER, WHICH IS THE ORDER THAT MATTERS. `sweep` prints
    # every retired record with its reason from today; the act that would exclude one does not exist
    # yet. An exclusion whose visibility arrives later is the R7 self-service-exclusion defect
    # waiting to happen, and R7 was found in dissent inside the tool built to stop claims
    # disappearing without record.
    #
    # THE MANUAL PROCEDURE, until a second hand-edit justifies a command: set these two fields by
    # hand on the record JSON. `load_records` tolerates it (defaulted, unknown keys dropped), every
    # sweep prints it, and NOTHING is silently un-hunted — because nothing is un-hunted at all.
    retired_at: str = ""
    retired_reason: str = ""
    carriers: list[str] = field(default_factory=list)
    boundary_rule: str = ""
    seeding_units: dict = field(default_factory=dict)     # unit_id -> {surface, extracted[]}
    reach: dict = field(default_factory=dict)             # units/locations reached + totals

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
        # ⚠ D3 — A MALFORMED RECORD REFUSES THE **WHOLE REGISTRY**, AND THAT IS THE RULING RATHER
        # THAN A CONVENIENCE. This used to be a bare `json.loads` / `Record(**d)`, so a malformed
        # file raised straight out of `load_records` — which every command calls BEFORE
        # `instrument_gate` — producing an unstratified traceback where R4a requires a named code.
        #
        # ⚠ AND SKIPPING THE BAD FILE WOULD BE WORSE THAN CRASHING. The selected set becomes
        # UNKNOWABLE, not merely smaller: the tool cannot say which records it failed to load, so
        # every downstream count, pin and closure is computed over a population nobody can name.
        # That is the sixth doorway — searched less than the caller believes — reached through the
        # loader instead of through the CLI.
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(d, dict) or "id" not in d:
                raise ValueError("record is not an object carrying an 'id'")
        except (OSError, ValueError, TypeError) as exc:
            raise RegistryUnreadable(
                f"REGISTRY UNREADABLE: {p} — {type(exc).__name__}: {exc}. The selected set is "
                f"UNKNOWABLE, not merely smaller, so nothing was swept.") from exc
        # ⚠ UNKNOWN KEYS ARE DROPPED, NOT FATAL. R3 added fields to the record; without this an
        # OLDER checkout of the tool crashes on the whole registry the moment a NEWER one writes to
        # it — and a tool that cannot read its own history has no history. Pairs with the defaults
        # on the new fields, which cover the opposite direction.
        out[d["id"]] = Record(**{k: v for k, v in d.items() if k in known})
    return out


def load_records_or_refuse(ns: Path) -> tuple[dict[str, Record] | None, int]:
    """D3 — THE ONE ENTRY EVERY COMMAND USES. Returns (records, 0) or (None, EXIT_INSTRUMENT).

    ⚠ ONE SHARED ENTRY, **NOT THREE CATCHES**, AND THE DISTINCTION IS THE RULING (2026-08-07).
    Three separate try/excepts that must agree is the dual-site shape this tree has met FIVE times —
    two argv sites, a hashed-but-literal flag set, a selected-vs-created prefix, `mypy`'s package
    list against `_PACKAGES` with `demo` missing from one of them. **None of those survived contact.**
    A reviewer who reads "move the catch into each command" and does so reintroduces the defect;
    this docstring exists so that reading is unavailable.

    ⚠ AND IT EXISTS BECAUSE D3's GUARANTEE WAS CLI-ONLY. `main` caught `RegistryUnreadable` and the
    commands did not, so `S.sweep(...)` called directly RAISED — the very traceback D3 was written to
    remove. MEASURED 2026-08-07. **The suite itself is a programmatic caller**: nearly every fixture
    drives the commands directly, so the tests exercised the path WITHOUT the guarantee while one
    test covered the path with it. `main` keeps a backstop; the guarantee now holds without it.
    """
    try:
        return load_records(ns), EXIT_CLEAN
    except RegistryUnreadable as exc:
        print(f"⚠ INSTRUMENT FAILURE — {exc}")
        print("  This is NOT an empty registry, which is clean. The registry EXISTS and cannot be")
        print("  read, so the selected set is UNKNOWABLE and no run may report on it.")
        return None, EXIT_INSTRUMENT


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


class RegistryUnreadable(Exception):
    """D3/D4 — the registry cannot be read, so the selected set is UNKNOWABLE.

    ⚠ A TYPED CONDITION RATHER THAN A BARE RAISE, so every command can turn it into the SAME
    stratified exit code instead of each inventing its own handling — the dual-site shape this file
    has met repeatedly. Carries the file and the exception class in its message, because "the
    registry is broken" sends the operator to look at everything.
    """


def _read_manifest(ns: Path) -> tuple[set[str], str | None]:
    """The manifest, read ONCE, in ONE place. Returns (entries, error).

    ⚠ THIS EXISTS BECAUSE `manifest_check` PARSED IT WITH NO GUARD AND CRASHED. An unreadable
    `manifest.json` raised `JSONDecodeError` straight out of `instrument_gate` — an unstratified
    traceback where R4a requires a stratified refusal naming the failing check. Found by a test
    written for R-A, not by review, and not by any of the four earlier passes over this file.

    ⚠ ONE READER, TWO CALLERS, FOR THE REASON THIS FILE ALREADY GIVES ABOUT `instrument_gate`: two
    implementations that must agree is the dual-site shape that is correct the day it is written and
    silently diverges the day only one side is edited.
    """
    mf = ns / "manifest.json"
    if not mf.exists():
        return set(), None
    try:
        return set(json.loads(mf.read_text(encoding="utf-8"))), None
    except (OSError, ValueError, TypeError) as exc:
        return set(), f"manifest.json is present but unreadable: {type(exc).__name__}: {exc}"


def manifest_check(ns: Path) -> list[str]:
    """R13 — every file the tool writes is manifested; anything else in the namespace is an
    INSTRUMENT FAILURE naming the stray file.

    ⚠ The alternative — excluding a PATH — invents a SEARCHED-BUT-UNREADABLE surface: a human note
    parked here containing a live carrier would be found, counted and suppressed permanently, with the
    run header remaining literally true.
    """
    if not ns.exists():
        return []
    known, err = _read_manifest(ns)
    if err is not None:
        # ⚠ AN UNREADABLE MANIFEST YIELDS NO STRAY CLAIMS, AND THAT IS THE FAIL-SAFE DIRECTION.
        # Treating it as an EMPTY manifest would make every file in the namespace a stray and bury
        # the real diagnosis under a list of the tool's own artefacts. `registry_integrity` reports
        # the parse failure precisely; this function declines to guess.
        return []
    known = set(known)
    known.add("manifest.json")
    stray = []
    for p in sorted(ns.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(ns))
            if rel not in known:
                stray.append(rel)
    return stray


def manifest_add(ns: Path, rel: str) -> None:
    """⚠ D4 — REFUSES THE WRITE ON AN UNREADABLE MANIFEST. It does NOT archive-and-continue.

    This carried an unguarded ``json.loads`` behind the comment that "recovering would rewrite the
    manifest with only the new entry and destroy the record of everything else". THAT REASONING WAS
    SOUND AND JUSTIFIED A DIFFERENT BEHAVIOUR THAN THE ONE SHIPPED: it argues against silent
    recovery, not for an unstratified traceback. Conceded in consult, ruled 2026-08-07.

    ⚠ AND ARCHIVING TO ``manifest.json.broken`` WAS ALSO REFUSED. It mutates the namespace during a
    command that is already failing, so the operator's next look is at a tree the tool rearranged
    while in a state it could not read. Repair is a deliberate act, never a side effect of a write.
    """
    mf = ns / "manifest.json"
    known, err = _read_manifest(ns)
    if err is not None:
        raise RegistryUnreadable(
            f"REGISTRY UNREADABLE: {err}. NOTHING WAS WRITTEN and the manifest was NOT modified — "
            f"repair it by hand; the tool will not rewrite a file it cannot read.")
    known = set(known)
    known.add(rel)
    mf.parent.mkdir(parents=True, exist_ok=True)
    mf.write_text(json.dumps(sorted(known), indent=2), encoding="utf-8")


def registry_integrity(ns: Path, records: dict[str, Record]) -> list[str]:
    """R-A — AN EMPTY REGISTRY IS CLEAN; A **BROKEN** ONE IS NOT.

    ⚠ THE DISCRIMINATOR IS EVIDENCE OF PRIOR TOOL AUTHORSHIP, NOT WHETHER A DIRECTORY EXISTS, AND
    THAT DISTINCTION IS THE WHOLE RULING. `records/` missing and `records/` empty are the SAME
    reading — "all registered" found none, and no named claim was falsified. Failing on bare absence
    would red every run before the first harvest, because **harvest is what creates the directory**.

    What is NOT clean is the registry contradicting ITSELF: `manifest.json` names a record file that
    does not load. Both artefacts were written by this tool, so their disagreement is an observable
    about the instrument rather than about the corpus — R10's posture applied to a CORRUPTED
    registry rather than to a fresh one.

    ⚠ THE SECOND HALF OF THE DRAFTED RULE IS DELIBERATELY NOT BUILT, AND THIS COMMENT IS WHY.
    It read: "other manifested artefacts exist while `records/` is gone". MEASURED 2026-08-07 by
    execution, not by reading: a sweep on a VIRGIN namespace exits `EXIT_CLEAN`, never creates
    `records/`, and writes `manifest.json` holding `reports/<stamp>.txt`. That is precisely the state
    the clause describes — so it would have RED-FLAGGED THE PRE-FIRST-HARVEST CASE THIS RULING EXISTS
    TO KEEP CLEAN, inverting it. A guard that fires on the state its own ruling protects is worse
    than no guard, because it trains the operator to route around the code that means something.

    An absent or unreadable manifest earns nothing: with no prior authorship recorded there is
    nothing for the registry to contradict.
    """
    manifested, err = _read_manifest(ns)
    if err is not None:
        # The manifest is itself a tool-written artefact. Unreadable is not empty.
        return [err]
    errs = []
    for rel in sorted(manifested):
        if rel.startswith("records/") and rel.endswith(".json"):
            rid = Path(rel).stem
            if rid not in records:
                errs.append(
                    f"REGISTRY CORRUPTED: manifest.json names {rel} but record {rid!r} did not load")
    # ⚠ D1/D2 — A DANGLING PARENT EDGE IS THE FIFTH DOORWAY, AND THE WORST-SHAPED OF THE SIX.
    # `--parent` is validated at HARVEST, but a parent registered and DELETED afterwards leaves an
    # edge pointing at nothing, and `ancestor_closure` skips ids it does not know — silently.
    #
    # MEASURED 2026-08-07: a record C whose parent B had been deleted swept **EXIT 0 CLEAN**, said
    # nothing, and printed the header `swept: C + ancestors: C`. It does not merely under-search —
    # **IT PRINTS A CLAIM THAT IT DID NOT.** Every other doorway is silent; this one asserts.
    #
    # ⚠ HERE, NOT IN `ancestor_closure`, AND THAT PLACEMENT IS THE RULING (D2). THE DEFAULT SWEEP
    # NEVER CALLS CLOSURE — it takes `list(records)` — so a check at the drop site would miss the
    # common path entirely and be tested green through the rare one. The condition is evaluated for
    # EVERY LOADED RECORD, independent of `selected`, because the corruption is a property of the
    # registry rather than of the caller's selection.
    for rid in sorted(records):
        parent = records[rid].parent
        if parent and parent not in records:
            errs.append(
                f"REGISTRY CORRUPTED: record {rid!r} names parent {parent!r}, which is NOT "
                f"REGISTERED. ancestor_closure would drop it silently while the run header still "
                f"claimed ancestors were swept. Restore the parent record, or clear the link.")
    return errs


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


class ConfigMissing(Exception):
    """No config file. A typed condition so every command returns the SAME stratified code.

    ⚠ IT REPLACES A `sys.exit(<str>)`, WHICH IS WHY THIS IS A CLASS AND NOT A TIDIER STRING. That
    call exited **1** and therefore agreed with EXIT_INSTRUMENT by accident; nothing in the code
    said so, and nothing would have noticed if the stdlib's default had differed. A named exception
    turned into a named code by ONE handler is the same argument `RegistryUnreadable` already makes.
    """


def load_config() -> dict:
    """⚠ THE REFUSAL NAMES A TRACKED FILE AND **ZERO SUBCOMMANDS**, AND THAT IS THE RULING.

    It used to tell the operator to run an "init" subcommand. **THERE HAS NEVER BEEN ONE** — the
    parser carries exactly `sweep`, `harvest` and `retombstone` — so the one part of a refusal an
    operator actually acts on could not be performed. A refusal whose remediation does not exist is
    strictly worse than one with no remediation at all: it sends the reader somewhere before they
    conclude the tool is wrong.

    ⚠ AND THE PHANTOM IS NAMED IN PROSE HERE RATHER THAN IN THE PINNED FORM, WHICH IS A REAL COST OF
    THE GUARD AND IS RECORDED RATHER THAN WORKED AROUND. The check scopes to BACKTICKED
    ``sweep <word>`` spans, so it cannot distinguish a refusal offering a phantom command from a
    docstring explaining that the phantom was removed. Writing the dead name in backticks here would
    red the build. That is the correct trade — the alternative is prose-wide tokenisation, which
    false-positives on the parser's own help text ("sweep records (default: ALL registered)") — but
    it means this file describes the removed command WITHOUT quoting it, deliberately.

    ⚠ AND NAMING `harvest` INSTEAD WOULD HAVE BEEN A PLAUSIBLE CLAIM REPLACING A FALSE ONE, WHICH IS
    NOT A FIX. `load_config()` is the FIRST STATEMENT of all three command bodies, so every
    subcommand hits this identical refusal — `harvest` is refuted, not merely unverified. The
    drafted repair reasoned about `sweep-registry/` (which harvest does create); the failing
    precondition is the CONFIG, a different artefact.

    So the remediation is a MANUAL ACT OF AUTHORSHIP NO SUBCOMMAND COULD PERFORM: the real config
    names a private board endpoint and private planning roots that the tool cannot invent, and a
    hypothetical `init` could only ever scaffold the template — which is what
    `sweep.config.example.json` already is. The message therefore names a **tracked file**, and a
    path claim is checkable in a way a command claim was not.
    """
    if not CONFIG_PATH.exists():
        raise ConfigMissing(
            f"no config at {CONFIG_PATH} — copy {CONFIG_PATH.parent.name}/"
            f"sweep.config.example.json and edit in your values. The config is deliberately "
            f"uncommitted: it names a private board endpoint and a private planning-doc root "
            f"(README §Development).")
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
    # R-A — and the registry must not contradict ITSELF. Placed in the SHARED gate rather than in
    # `sweep` alone, for the reason this function exists: `harvest` once ran a strictly weaker gate
    # and pinned counts from an enumeration `sweep` would have refused. A harvest or a re-bind
    # against a corrupted registry has the same defect one door along.
    errors.extend(registry_integrity(ns, records))
    return errors, controls


def sweep(args) -> int:
    cfg = load_config()
    ns = NAMESPACE
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    records, _rc = load_records_or_refuse(ns)
    if records is None:
        return _rc

    # R1 — DEFAULT IS EVERY REGISTERED RECORD, closed ones included. A record with tombstones is
    # "closed", but its withdrawn text is still live in the world: closed means the correction was made
    # once, not that the text is gone. A-variants inside B's correction prose are exactly the miss.
    if args.records:
        # ⚠ AN UNKNOWN RECORD ID IS AN INSTRUMENT FAILURE, NOT A CLEAN SWEEP. RULED 2026-08-06.
        # `ancestor_closure` skips ids it does not know (`rid not in records: continue`), so
        # `sweep TYPO-ID` used to yield an EMPTY selected set, search nothing, find nothing, and
        # EXIT 0 CLEAN — with the header printing the id it never swept. A typo and a genuinely
        # clean sweep were INDISTINGUISHABLE, and the wrong one is the reassuring one.
        # Same posture as `retombstone`'s unknown-record refusal: the caller named something that
        # does not exist, so the remediation is to check what they typed, not to trust the zero.
        unknown = [r for r in args.records if r not in records]
        if unknown:
            print("⚠ INSTRUMENT FAILURE — unknown record id(s). NOTHING WAS SWEPT.")
            for r in unknown:
                print(f"    {r}")
            print(f"  known: {', '.join(sorted(records)) or 'none'}")
            print("  A sweep that searched nothing must never report clean — a typo would then be")
            print("  indistinguishable from a corpus with no live carriers.")
            return EXIT_INSTRUMENT
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
    # ── R-B — A RECORD THAT CANNOT BE SEARCHED MUST NEVER REPORT AS SEARCHED.
    # ⚠ THIS IS THE THIRD SITE OF ONE RULE, NOT A THIRD RULE. An unknown record id (C1), an
    # uncompilable seed at harvest (R16) and a selected record whose patterns ALL fail to compile
    # are the same shape: SELECTED, NEVER SEARCHED, REPORTS CLEAN — a dead tripwire registered as a
    # live one. Only the door differs. The design states the rule once; these are its doorways.
    #
    # ⚠ REACHABLE ONLY BY HAND-EDIT — WHICH IS EXACTLY WHY IT IS IN SCOPE. `harvest` refuses an
    # uncompilable seed (R16) and never mints an empty variant, so the tool cannot produce this
    # state. R18's ruled procedure for retirement is EDITING THE RECORD JSON BY HAND, so C2 opens
    # the very door this closes. The two are one increment.
    unsearchable: list[tuple[str, list[str]]] = []
    for rid in selected:
        rec = records[rid]
        pats = [(f"{rid}:v{i}", v) for i, v in enumerate(rec.variants)] + \
               [(f"{rid}:anchor:{a}", a) for a in rec.anchors]
        compiled_here, failed_here = 0, []
        for label, text in pats:
            try:
                pat = compile_pattern(text)
            except ValueError:
                # Counted and NAMED, never silently skipped. The ruling requires the ids.
                failed_here.append(label)
                continue
            compiled_here += 1
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
        if compiled_here == 0:
            # ⚠ ZERO COMPILED PATTERNS FOR A SELECTED RECORD. Not "found nothing" — NEVER LOOKED.
            # A record with no patterns at all is the same condition as one whose patterns all
            # failed: either way this id contributed no search, and reporting the run as clean
            # would certify a corpus against a net that was never cast.
            unsearchable.append((rid, failed_here))
    # ⚠ APPENDED TO ``instrument_errors`` RATHER THAN GIVEN ITS OWN RETURN, DELIBERATELY. That list
    # is checked below, BEFORE the report is written and BEFORE the exit cascade, and it withholds
    # the hit list with the diagnosis printed. A parallel refusal path here would be a second
    # implementation of a decision this file already makes in one place — the dual-site shape that
    # has bitten this project repeatedly.
    for rid, failed in unsearchable:
        rec_u = records[rid]
        total = len(rec_u.variants) + len(rec_u.anchors)
        if total == 0:
            instrument_errors.append(
                f"UNSEARCHABLE RECORD {rid}: it carries NO variants and NO anchors, so selecting "
                f"it searched nothing. A record that cannot be searched must never report as "
                f"searched.")
        else:
            instrument_errors.append(
                f"UNSEARCHABLE RECORD {rid}: all {total} pattern(s) failed to compile — "
                f"{', '.join(failed)}. A record that cannot be searched must never report as "
                f"searched.")

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
    # ── R18 — THE ALWAYS-PRINT LINE. ⚠ IT IS A WARNING, NOT A DISCHARGED SAFEGUARD (R-C, ruled
    # 2026-08-07). RETIREMENT EXCLUDES NOTHING TODAY: a retired record is still swept, still
    # contributes count pins, still has its tombstones checked, still licenses R7 exclusions, still
    # fires process debt.
    #
    # ⚠ THE SENTENCE THIS BLOCK USED TO CARRY WAS THE DEFECT, NOT THE LINE ITSELF. It presented the
    # print as a safeguard shipped ahead of its lever — which reads as a hazard DISCHARGED. Nothing
    # can enter an excluded state, so nothing has been guarded against; what the line does is warn
    # the next reader NOT TO ASSUME exclusion exists. Keeping the constant is right — unlike
    # `span_sha256` it is auditable by reading — but claiming it demonstrates a control fired is the
    # `normalise()` docstring failure again: THE MECHANISM WAS RIGHT AND THE SENTENCE ABOUT IT WAS
    # NOT.
    #
    # ⚠ WHEN `retire` LANDS, DERIVE THIS LINE FROM BEHAVIOUR — excluded versus still-in-`selected`.
    # A constant string cannot disagree with the code; a derived one can, and on the day the lever
    # changes what is swept, this text goes false with nothing announcing it.
    #
    # ⚠ AND THE DRIFT LINE FOR A RETIRED RECORD BELONGS HERE, NOT DROPPED (ruled): the information
    # survives, scoped, rather than polluting the live section or vanishing.
    retired = [rid for rid in selected if records[rid].retired_at]
    for rid in retired:
        rec_r = records[rid]
        L.append(f"RETIRED {rid} @ {rec_r.retired_at} — ⚠ STILL SWEPT: "
                 f"{rec_r.retired_reason or '(no reason given)'}")
        L.append(f"        {len(rec_r.variants)} variants, ALL STILL SEARCHED. Retirement fields "
                 f"are CARRIED AND PRINTED; EXCLUSION IS NOT BUILT.")
        L.append( "        ⚠ THIS LINE IS A WARNING AGAINST ASSUMING EXCLUSION. It is NOT proof "
                  "that a safeguard fired — nothing can enter an excluded state yet.")
    # ⚠ THE ZERO-SEED OBSERVABLE WAS REMOVED 2026-08-06, AND ITS ABSENCE IS THE RULING.
    # It printed "seed matched nothing at harvest — tripwire, or typo?" for a record whose census
    # measured zero. With ``--carrier`` REQUIRED and a zero inside a named carrier REFUSED, a new
    # record CANNOT carry a zero census — so the line became unreachable. Leaving it would be dead
    # code wearing a control's clothes, which is the defect class this project has shipped three
    # times (R7 described-unimplemented, R14 persisted-never-diffed, harvest-not-discovering-variants).
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
    records, _rc = load_records_or_refuse(NAMESPACE)
    if records is None:
        return _rc
    errs, _ = instrument_gate(surfaces, cfg, records, list(records), NAMESPACE)
    if errs:
        print("⚠ INSTRUMENT FAILURE — refusing to harvest against surfaces that cannot be trusted.")
        print("  NOTHING WAS WRITTEN. A record written now would pin these counts as authoritative.")
        for e in errs:
            print("   ", e)
        return EXIT_INSTRUMENT

    # ── ⚠ AN UNKNOWN `--parent` IS A REFUSAL. THE SAME DEFECT AS C1, ONE EDGE IN.
    # `--parent` is the ONLY input to `ancestor_closure`, and that function skips ids it does not
    # know (`rid not in records: continue`). So a typo'd parent was accepted, written to the record,
    # and then SILENTLY DROPPED at every later sweep: `sweep B` searched B alone and exited CLEAN
    # while B's own correction prose reasserted A. That is verbatim the green-washing
    # `ancestor_closure`'s docstring forbids — "caller-selected B must never green-wash A" — and the
    # NESTED withdrawal is half the founding failure.
    #
    # ⚠ IT REFUSES AT HARVEST, NOT AT SWEEP, BECAUSE HARVEST IS WHERE THE CLAIM IS MADE. The operator
    # asserts a parent once, when writing the record; every sweep afterwards merely reads it. Failing
    # at read time would red a registry the operator can no longer easily correct, and would fire
    # long after the person who typed it has gone.
    if args.parent is not None and args.parent not in records:
        print(f"⚠ INSTRUMENT FAILURE — unknown --parent {args.parent!r}. NOTHING WAS WRITTEN.")
        print(f"    known: {', '.join(sorted(records)) or 'none'}")
        print("  `--parent` is the only input to ancestor_closure, which SKIPS ids it does not")
        print("  know — so this record would have carried a dangling edge, and every later sweep")
        print("  of a child would have exited CLEAN without ever searching the parent's variants.")
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

    # ── THE SEED CENSUS (P1-1). Computed on the unit index above, BEFORE the loop reaches anything,
    # so it records the population the seeding decision was made FROM rather than the decision's
    # outcome. See ``seed_census`` for why the design's ``--carrier`` needs this to exist.
    #
    # ⚠ DEFERRED TEST GAP, RECORDED RATHER THAN CLAIMED CLOSED. Moving this call BELOW the fixpoint
    # loop SURVIVES THE WHOLE SUITE — ``units`` is not mutated by the loop, so every output is
    # byte-identical. The ordering is therefore load-bearing in INTENT and inert in BEHAVIOUR today.
    # It stops being inert the day ``--carrier`` narrows the seeded population, because then the
    # census must describe what existed BEFORE the narrowing. NO TEST PINS THIS YET; the test that
    # can arrives with the flag. Found by dissent, not by the red-proof, and written here rather
    # than left to memory — a surviving mutant is a test gap or a bad mutant, and this one is a gap
    # whose CONSEQUENCE IS DEFERRED, NOT ABSENT.
    census = seed_census(args.seed, units)

    # ── R16 — AN UNSEARCHABLE SEED IS A REFUSAL. RULED 2026-08-06.
    # ⚠ THE RECORD IT WOULD HAVE WRITTEN IS A FALSE INSTRUMENT, WHICH IS WORSE THAN AN EMPTY ONE.
    # `variants` falls back to ``[args.seed]``, and every later sweep compiles the variants inside a
    # ``try/except ValueError: continue`` — so the pattern NEVER RUNS, no observable says so, and the
    # record SWEEPS CLEAN FOR EVER. A dead tripwire registered as a live one, in the tool whose whole
    # subject is claims that stop being checked without anyone noticing.
    #
    # ⚠ TWO ZERO-SHAPED HARVEST ACTS, BOTH REFUSALS. AMENDED 2026-08-06 WHEN --carrier BECAME
    # REQUIRED — the middle case was RETIRED rather than rescued:
    #   (1) UNSEARCHABLE SEED                    → REFUSE here, exit 5. The pattern CAN NEVER FIRE.
    #   (2) ZERO INSIDE A NAMED --carrier (R15d) → REFUSE. A location was ASSERTED and is empty.
    #
    # ⚠ THE RETIRED CASE WAS "corpus-wide zero on a BARE harvest is PERMITTED, as a tripwire". It
    # died with the bare harvest, and it was NOT replaced by a flag. A flag invented to rescue
    # yesterday's table is the same act as the fallback invented to rescue a mechanism.
    # TRIPWIRE INTENT ALREADY LIVES IN ``expand``'s ZERO-HIT FORMS, which guard the carrier written
    # tomorrow; and a typo against a named carrier is correctly caught by (2). If "register a guard
    # at a location that does not yet hold the seed" is ever genuinely needed, IT IS A NEW CONSULT.
    if census["error"]:
        print("⚠ SEED FAILURE — the seed cannot be compiled into a pattern. NOTHING WAS WRITTEN.")
        print(f"    {census['error']}")
        print("  A record written now would carry this seed as its only variant, and every sweep")
        print("  compiles variants inside `except ValueError: continue` — so the pattern would")
        print("  NEVER RUN and the record would report CLEAN for ever, with no observable saying")
        print("  the search did not happen. A dead tripwire registered as a live one.")
        print(f"  This is exit {EXIT_SEED}, NOT the instrument code: the corpus is fine, the seed is not.")
        return EXIT_SEED

    # ── R15 — CLAIM-SPAN SEEDING. THE CANDIDATE SET COMES FROM THE CLAIM, NOT FROM THE CORPUS.
    # The fixpoint loop that stood here is DELETED; its obituary and the four dead rescues are at
    # ``BOUNDARY_RULE`` above, in the code, because a deletion whose justification lives only in a
    # consult is this tool's own failure mode wearing a commit message.

    # ⚠ R15b — ``--carrier`` MUST NOT NAME THE TOOL'S OWN NAMESPACE. A stored run report carries the
    # claim's FULL MATCHED SPAN, so seeding from one bootstraps the vocabulary tautologically out of
    # the tool's own output — and under claim-span seeding it does so CLEANLY, producing a plausible
    # 5/5. The failure is silent and self-certifying, which is exactly why it is a refusal and not a
    # warning. The old guard lived inside the unit index the deletion removed.
    named = list(args.carrier or [])
    # ⚠ RULED 2026-08-06 — ``--carrier`` IS REQUIRED, AND THE REFUSAL LIVES HERE RATHER THAN IN
    # argparse. A bare harvest USED to seed from every unit holding the seed; that was inferred from
    # a ruling about a different question, and it RESTORED THE FLOOD IN ONE PASS — every
    # seed-holding unit contributes its backticked spans, so `variants` explodes exactly as it did
    # under the deleted loop. Cost sealed it: ~1,000 seed-holding units x ~50 terms x ~5 expansions
    # is ~250,000 variants over the whole corpus. It also inverted the flag's meaning, turning
    # ``--carrier`` into a NARROWER of an existing population rather than THE ACT THAT CREATES ONE.
    #
    # ⚠ AND IT IS NOT `required=True` ON THE ARGUMENT. argparse exits **2** on a missing required
    # flag, and 2 is EXIT_TOMBSTONE — a forgotten flag would be indistinguishable from "a correction
    # was re-worded", which is precisely the collision R4a's stratification exists to prevent.
    if not named:
        print("⚠ INSTRUMENT FAILURE — --carrier is REQUIRED. NOTHING WAS WRITTEN.")
        print("  The seeding population IS the claim span; without a carrier there is no span, and")
        print("  seeding from every unit holding the seed restores the flood this build deletes.")
        return EXIT_INSTRUMENT
    in_ns = [c for c in named if c.startswith(ns_str)]
    if in_ns:
        print("⚠ INSTRUMENT FAILURE — a --carrier names the tool's OWN namespace. NOTHING WRITTEN.")
        for c in in_ns:
            print(f"    {c}")
        print("  Run reports store every hit's full matched span, so seeding from one would derive")
        print("  the vocabulary from this tool's own output and produce a CLEAN-LOOKING result.")
        return EXIT_INSTRUMENT

    # Step 2 — locate each named carrier among the enumerated surfaces.
    # ⚠ ABSENT IS AN INSTRUMENT FAILURE, NEVER AN EMPTY RESULT (R10's posture, applied to the input).
    by_loc: dict[str, tuple[str, str]] = {}
    for surf in surfaces:
        if surf.error:
            continue
        for loc, body in surf.items:
            by_loc[loc] = (surf.name, body)
    missing = [c for c in named if c not in by_loc]
    if missing:
        print("⚠ INSTRUMENT FAILURE — --carrier not found on any enumerated surface. NOTHING WRITTEN.")
        for c in missing:
            print(f"    {c}")
        print("  A carrier that cannot be located is not an empty carrier; the enumeration and the")
        print("  operator disagree, and a record written now would pin that disagreement.")
        return EXIT_INSTRUMENT

    # Step 3 — EVERY occurrence of the seed, and the WHOLE ``carrier_units`` unit containing each.
    # ⚠ EVERY OCCURRENCE, NEVER "THE CLAIM SENTENCE". MEASURED: one occurrence gives 4/5 and loses
    # the carrier three prior passes had already missed; all occurrences give 5/5, recovering it via
    # vocabulary from a span TWENTY LINES AWAY from the first occurrence. Reporting the first run
    # alone would have boarded a failure caused by which paragraph happened to be picked.
    #
    seed_pat = compile_pattern(args.seed)
    scope = [(uid, sname, utext) for uid, sname, utext in units
             if _unit_location(uid) in named]
    seeding = [(uid, sname, utext) for uid, sname, utext in scope if seed_pat.search(utext)]

    # ⚠ R15d — ZERO OCCURRENCES IN A NAMED CARRIER IS A REFUSAL, NOT AN EMPTY RESULT.
    # A carrier that exists but no longer holds the seed — renamed claim, rewritten under active
    # edit — yields an empty union and would otherwise be written as AUTHORITATIVE STATE.
    # ⚠ THIS IS NOT THE SAME ACT AS A CORPUS-WIDE ZERO ON A BARE HARVEST, WHICH IS PERMITTED (R16).
    # There the pattern DOES NOT FIRE YET and is a tripwire; here THE CALLER ASSERTED A LOCATION and
    # the assertion is refuted. Identical in the number, opposite in what they mean.
    if not seeding:
        print("⚠ INSTRUMENT FAILURE — the named carrier(s) contain ZERO occurrences of the seed.")
        print("  NOTHING WAS WRITTEN. You asserted a location; the location does not hold the claim.")
        for c in named:
            print(f"    {c}")
        print("  ⚠ THIS IS NOT A TRIPWIRE. Tripwire intent lives in `expand`'s zero-hit forms, which")
        print("  guard a term that may be written tomorrow. A carrier you NAMED and that does not")
        print("  hold the claim is a refuted assertion, and a typo is correctly caught here too.")
        return EXIT_INSTRUMENT

    # Step 4 — extract + expand over the UNION OF THOSE UNITS ONLY. No corpus. No rounds.
    extracted: set[str] = set()
    seeding_units: dict[str, dict] = {}
    for uid, sname, utext in seeding:
        terms = extract_candidates(utext)
        # R15f — the candidates TSV recorded a FILTERING decision and the filtering is gone, so that
        # audit target genuinely ceases to exist. But a decision REMAINS — WHICH TEXT SEEDED THE
        # VOCABULARY — and a span sha256 is a commitment, not something a reviewer can read. So the
        # per-unit contribution is recorded by UNIT IDENTITY, on the record and in a manifested spill.
        seeding_units[uid] = {"surface": sname, "extracted": sorted(terms)}
        extracted |= terms
    expansions: set[str] = set()
    for t in list(extracted) + [args.seed]:
        expansions |= expand(t)

    # ⚠ R15a — THE SEED IS IN ``variants`` BY CONSTRUCTION, AND THIS WAS CONFIRMED BY EXECUTION.
    # ``extract_candidates`` excludes free prose BY DESIGN and ``expand`` excludes its own input BY
    # CONSTRUCTION, so for a PROSE seed neither produces it. MEASURED on the real claim block: 15
    # terms extracted and the seed was not among them — a record whose sweep never matches the exact
    # withdrawn sentence. The old code guaranteed this twice, and BOTH guarantees lived inside the
    # loop this change deletes.
    variants_list = sorted({v for v in ({args.seed} | extracted | expansions) if v.strip()})

    # ⚠ ``span_sha256`` IS STRUCK, NOT DEFERRED. It hashed the seeding text and NOTHING EVER
    # RECOMPUTED OR COMPARED IT — by the same standard that killed R15e, an unverified hash is
    # ceremony. What it claimed to protect is already carried by ``seeding_units`` and the spill:
    # WHICH units seeded and WHAT each contributed, auditable by opening the unit, which a hash
    # never was. If a consumer ever exists, it arrives WITH the consumer.

    # ── R15c — STEP 4½: ONE CORPUS PASS. NO ITERATION, NO PROMOTION, NO THRESHOLD.
    # ⚠ WITHOUT IT ``surfaces_at_withdrawal`` BECOMES MEMORY-AUTHORED AGAIN. Today it is COMPUTED
    # from the reached set and the deletion removes the only thing computing it — the original
    # disease persisting inside the registry, wearing a tool's clothing.
    occurrences: dict[str, int] = {}
    reached_units: set[str] = set()
    for v in variants_list:
        try:
            vp = compile_pattern(v)
        except ValueError:
            continue
        n = 0
        for uid, _sname, utext in units:
            hits = vp.findall(utext)
            if hits:
                n += len(hits)
                reached_units.add(uid)
        occurrences[canonical(v)] = n

    # ⚠ BOTH GRANULARITIES, AND THE REACHED SET ITSELF IS PERSISTED — NOT MERELY ITS SIZE.
    # Every reach figure this project has produced was UNIT-only, because nothing recorded WHICH
    # units were reached, so the location figure could not be computed after the fact at all. A
    # human opens LOCATIONS. Persisting the set is what makes a run scoreable at the granularity
    # the cost is actually paid in.
    all_locations = {_unit_location(uid) for uid, _, _ in units}
    reached_locations = {_unit_location(uid) for uid in reached_units}
    reach = {
        "units_reached": len(reached_units), "units_total": len(units),
        "locations_reached": len(reached_locations), "locations_total": len(all_locations),
        "reached_units": sorted(reached_units), "reached_locations": sorted(reached_locations),
    }

    # ── THE ADJUDICATION OVER THE CENSUS (R5) — and with ``--carrier`` it finally records a REAL
    # narrowing rather than an empty one. ``seeded`` is measured from what actually seeded above.
    census["adjudication"] = census_adjudication(
        census, [uid for uid, _, _ in seeding], carriers_named=named,
        basis="carrier(s) named: the seeding population is the claim span inside them")

    where = {sname for uid, sname, _ in units if uid in reached_units}

    rec = Record(
        id=args.id, seed=args.seed,
        # ⚠ R15g — SORTED. The union is set-derived, and set iteration order would make record files
        # nondeterministic across runs of identical input, so diffing two records would report
        # changes nobody made.
        variants=variants_list,
        anchors=[],   # OUTPUT-only, never an input — see the --anchor ruling in main()
        nets_run=["claim-span-seed", "carrier-extraction", "orthographic-expansion"],
        tombstones=[],                      # OPEN by construction — see R4
        surfaces_at_withdrawal=sorted(where),
        expected_counts={s.name: s.item_count for s in surfaces},
        parent=args.parent, created=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        seed_census=census, carriers=named,
        boundary_rule=BOUNDARY_RULE, seeding_units=seeding_units, reach=reach)
    # ⚠ `rounds` / `candidates` / `at_fixpoint` ARE DELIBERATELY NOT WRITTEN. They were the fixpoint
    # loop's state; the loop is gone. The FIELDS survive (defaulted) only so that records written
    # before this change still load — a tool that cannot read its own history has none.
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

    # ── R15f — THE CANDIDATES TSV IS GONE; THE DECISION IT RECORDED HAS MIGRATED.
    # ⚠ THAT FILE RECORDED A *FILTERING* DECISION — which candidates the promotion rule admitted —
    # and the deletion removes the filtering, so nothing is dropped and that audit target genuinely
    # CEASES TO EXIST. But a decision REMAINS: **WHICH TEXT SEEDED THE VOCABULARY**. A span sha256 is
    # a COMMITMENT, not something a reviewer can read, so the replacement carries UNIT IDENTITIES and
    # each unit's contribution — auditable by opening the unit, which is the point.
    crel = f"seeding/{rec.id}.tsv"
    (NAMESPACE / "seeding").mkdir(parents=True, exist_ok=True)
    (NAMESPACE / crel).write_text(
        "surface\tunit\tterms_extracted\tterms\n" +
        "\n".join(f"{d['surface']}\t{uid}\t{len(d['extracted'])}\t{' | '.join(d['extracted'])}"
                  for uid, d in sorted(seeding_units.items())) + "\n", encoding="utf-8")
    manifest_add(NAMESPACE, crel)

    # R6/R13 — and the REACHED SET spills too, at both granularities. Persisting the SET rather than
    # its size is what makes a run scoreable in locations later; every figure before today was
    # unit-only because nothing recorded which units were reached.
    rrel = f"reach/{rec.id}.tsv"
    (NAMESPACE / "reach").mkdir(parents=True, exist_ok=True)
    (NAMESPACE / rrel).write_text(
        "kind\tidentity\n" +
        "\n".join(f"unit\t{u}" for u in reach["reached_units"]) + "\n" +
        "\n".join(f"location\t{loc}" for loc in reach["reached_locations"]) + "\n",
        encoding="utf-8")
    manifest_add(NAMESPACE, rrel)

    # R6/R12/R13 — the census SPILLS IN FULL to a manifested file. The printed view is bounded; what
    # is recorded is not. A census that printed a top-N and kept nothing else would reproduce the
    # silent cutoff it exists to expose.
    seeded_set = set(census["adjudication"]["seeded"])
    out_set = set(census["adjudication"]["adjudicated_out"])
    # ⚠ ``adj_named``, NOT A REBIND OF ``named``. This USED to shadow the local `named` AFTER it had
    # already been consumed at record construction (``carriers=named``), so one fact had TWO SOURCES:
    # `Record.carriers` from the local, and everything below from the census's copy. Inert while
    # ``census_adjudication`` returns ``list(carriers_named)`` of that same list — but that function
    # exists SPECIFICALLY so it can be handed inputs that DISAGREE (see its docstring), so the two
    # are equal by today's construction and not by any rule. The defect was never the value; it was
    # that a divergence would have been silent.
    adj_named = census["adjudication"]["carriers_named"]
    # ⚠ ORDERED BY LOCATION, NOT BY FREQUENCY, AND THE FILE ALREADY RULED THIS ABOUT ITSELF. ``sweep``
    # sorts unknown-disposition FIRST because "leading with a suspected-live class primes confirmation
    # over reading" — and an occurrence-ranked census primes by FREQUENCY, which on the founding
    # incident points the wrong way: `no egress` was ordinary project vocabulary and 7 of its 8
    # locations were HOMONYMS, so frequency plausibly ANTI-correlates with carrier-hood. The
    # SINGLE-OCCURRENCE unit is where a forgotten carrier lives BY DEFINITION, and ranking sank it
    # into the unprinted tail. Occurrence-ascending would be the opposite unjustified ranking; the
    # answer is to present the POPULATION and let the occurrence column speak.
    census_rows = sorted(census["units_holding"], key=lambda h: (h["surface"], h["unit"]))
    srel = f"census/{rec.id}.tsv"
    (NAMESPACE / "census").mkdir(parents=True, exist_ok=True)
    (NAMESPACE / srel).write_text(
        "occurrences\tseeded\tadjudicated_out\tsurface\tunit\n" +
        "\n".join(f"{h['occurrences']}\t{h['unit'] in seeded_set}\t{h['unit'] in out_set}\t"
                  f"{h['surface']}\t{h['unit']}" for h in census_rows) + "\n",
        encoding="utf-8")
    manifest_add(NAMESPACE, srel)

    print(f"HARVESTED {rec.id}")
    print(f"  seed            : {rec.seed!r}")
    # ── THE SEED CENSUS, PRINTED. The design records which carrier was chosen; this records what
    # there was to choose FROM, which is the half a later reader cannot reconstruct.
    if census["error"]:
        print(f"  ⚠ SEED CENSUS   : NOT COMPUTED — {census['error']}")
        print( "    The record below was built without one. Nothing downstream should be read as")
        print( "    evidence about where the seed occurs.")
    else:
        print(f"  seed census     : {census['occurrences_total']} occurrences in "
              f"{len(census['units_holding'])} of {census['unit_total']} carrier units, "
              f"on {len(census['surfaces'])} surface(s): {', '.join(census['surfaces']) or 'NONE'}")
        print(f"    seeded {len(seeded_set)}  ·  adjudicated out {len(out_set)}  ·  "
              f"carriers named: {', '.join(adj_named)}")
        print(f"    {census['adjudication']['basis']}")
        # ⚠ WHICH OF THE TWO THIS IS, IS DECIDED BY THE CODE AND NOT BY WHOEVER EDITS IT NEXT.
        # A non-empty ``adjudicated_out`` means one of two OPPOSITE things, and the earlier version
        # of this block asserted in PROSE that it could only ever mean the first: "this build
        # adjudicates nothing, so the two must agree". That sentence goes FALSE the day ``--carrier``
        # lands, and nothing would have failed to say so. Keying on ``carriers_named`` makes the
        # distinction structural, which is this project's standing preference — mechanism over
        # intent, because prose describing a behaviour the code has outgrown is the dangerous
        # direction and this tool exists to find exactly that.
        if out_set and not adj_named:
            print( "    ⚠ INSTRUMENT DISAGREEMENT — the census found the seed in units round 1 did")
            print( "      not reach, and NO CARRIER WAS NAMED, so nothing narrowed the population.")
            print( "      The two instruments disagree; this is NOT a recorded adjudication:")
            for uid in sorted(out_set)[:8]:
                print(f"        {uid}")
        elif out_set:
            print(f"    {len(out_set)} unit(s) held the seed and were ADJUDICATED OUT by the named")
            print( "      carrier(s) above. This is the narrowing, RECORDED rather than silent:")
            for uid in sorted(out_set)[:8]:
                print(f"        {uid}")
        for h in census_rows[:8]:
            print(f"      x{h['occurrences']:<3} {h['surface'][:10]:<10} {h['unit'][:78]}")
        if len(census_rows) > 8:
            print(f"      … {len(census_rows) - 8} more in {srel} — NOT truncated, SPILLED")
        print( "    ⚠ THESE ARE OCCURRENCES, NOT CARRIERS OF THE CLAIM. Whether a unit ASSERTS the")
        print( "      withdrawn claim or merely uses the same words is a JUDGEMENT this tool does not")
        print( "      make (R5). MEASURED on the founding incident: 7 of 8 were homonyms.")
    # ── R15 — WHAT SEEDED, AND WHAT IT REACHED. Both, because they are different questions.
    print(f"  carriers named  : {', '.join(adj_named)}")
    print(f"  seeding units   : {len(seeding_units)}")
    print(f"  boundary rule   : {BOUNDARY_RULE}")
    for uid, d in sorted(seeding_units.items())[:8]:
        print(f"      {len(d['extracted']):>3} terms  {d['surface'][:10]:<10} {uid[:74]}")
    if len(seeding_units) > 8:
        print(f"      … {len(seeding_units) - 8} more in {crel} — NOT truncated, SPILLED")
    print(f"  variants        : {len(rec.variants)}  (occurrences: {sum(variants.values())})")
    print( "    = seed ∪ extracted ∪ orthographic expansions, over the seeding units ONLY.")
    print( "    ⚠ NO ROUNDS, NO PROMOTION, NO THRESHOLD — so there is no cutoff left to be silent")
    print( "      about (R12). The candidate set is bounded by the CLAIM SPAN, not by the corpus.")
    # ⚠ REACH AT BOTH GRANULARITIES, ALWAYS. `11% of units` and `41% of locations` were the SAME
    # run, and only the second is a reading list a human pays for.
    print(f"  reach           : {reach['units_reached']}/{reach['units_total']} units "
          f"({100 * reach['units_reached'] / max(1, reach['units_total']):.1f}%)  ·  "
          f"{reach['locations_reached']}/{reach['locations_total']} LOCATIONS "
          f"({100 * reach['locations_reached'] / max(1, reach['locations_total']):.1f}%)")
    print(f"    the reached SET is persisted to {rrel}, not merely its size — so this run stays")
    print( "    scoreable in locations later. A human opens locations.")
    print( "    ⚠ ONE CORPUS PASS (R15c), no iteration and no promotion. This pins")
    print( "      surfaces_at_withdrawal by MEASUREMENT; without it the record is memory-authored.")
    print(f"  surfaces        : {', '.join(rec.surfaces_at_withdrawal)}")
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


def retombstone(args) -> int:
    """R4/R7.5 — BIND A RECORD'S CORRECTION BLOCKS. THE STEP THAT CLOSES THE LOOP.

    ⚠ THIS WAS SPECIFIED AND NEVER SHIPPED, AND ITS ABSENCE BROKE THE TOOL'S OWN PROCESS. `harvest`
    writes records OPEN; `sweep` CHECKS tombstones; **nothing created one.** So the loop the whole
    design is built around — harvest → correct → register — COULD NOT BE COMPLETED WITH THE TOOL.
    Two records sat open, exiting 4 for ever, beside a correct hash-verified withdrawn block with
    nowhere to go.

    That lands exactly on R4a's own warning: *"an exit that is always red trains the reader to route
    around it"*. A permanently-open record is process debt the tool MANUFACTURES and then reports.
    Fourth instance of built-enough-to-describe after R7, R14 and harvest-not-discovering-variants —
    and, again, found by EXECUTION rather than by review.

    ⚠ "HASH-VERIFIED" MEANS **COMPUTED, NEVER SUPPLIED**. The stored `block_sha256` is derived from
    the bytes of the block actually found on the surface, so a caller cannot assert a hash that does
    not match its text. There is deliberately NO `--expect <sha>` flag: an assertion the caller
    writes by hand is one more thing to get wrong, and R7 already keys the control on the block.

    ⚠ AND RE-BINDING IS AN OVERWRITE, WHICH IS THE ONE PLACE THAT IS CORRECT. `harvest` REFUSES to
    overwrite a record precisely because it would silently reset tombstones; here, replacing a
    tombstone with a freshly computed one IS the point — R7.5 exists because *"if updating the
    control is harder than ignoring the failure, ignoring wins"*. Scope is still bounded: with
    `--location`, tombstones OUTSIDE the named locations are PRESERVED, so a narrow re-bind cannot
    quietly drop a control it was not asked about.
    """
    cfg = load_config()
    surfaces = gather_surfaces(cfg)
    records, _rc = load_records_or_refuse(NAMESPACE)
    if records is None:
        return _rc
    if args.record not in records:
        print(f"⚠ INSTRUMENT FAILURE — no registered record {args.record!r}. NOTHING WAS WRITTEN.")
        print(f"    known: {', '.join(sorted(records)) or 'none'}")
        return EXIT_INSTRUMENT
    errs, _ = instrument_gate(surfaces, cfg, records, list(records), NAMESPACE)
    if errs:
        # The blocks live ON the surfaces, so binding against an enumeration `sweep` would refuse to
        # certify would pin a control to a reading the tool does not trust.
        print("⚠ INSTRUMENT FAILURE — refusing to bind against surfaces that cannot be trusted.")
        for e in errs:
            print("   ", e)
        return EXIT_INSTRUMENT

    wanted = list(args.location or [])
    found: list[tuple[str, str]] = []          # (location, block_sha256)
    for s in surfaces:
        if s.error:
            continue
        for loc, body in s.items:
            if wanted and loc not in wanted:
                continue
            block = extract_blocks(body).get(args.record)
            if block is not None:
                found.append((loc, block_sha(block)))

    if not found:
        # ⚠ TWO DIFFERENT REFUSALS, AND THE MESSAGE MUST SAY WHICH. "You named a location and there
        # is no block there" is a refuted assertion; "there is no block anywhere" is a correction
        # that was never written. Same exit, different remediation, so the text carries the split.
        print(f"⚠ NOTHING TO BIND for record {args.record!r}. NOTHING WAS WRITTEN.")
        if wanted:
            print(f"    no {BLOCK_OPEN}{args.record} --> block at: {', '.join(wanted)}")
            print("  You named a location and the block is not there — a refuted assertion, not an")
            print("  empty result. Check the location, or omit --location to bind wherever it is.")
        else:
            print(f"    no {BLOCK_OPEN}{args.record} --> block on ANY enumerated surface")
            print("  The correction has not been written yet. Quote the withdrawn text inside a")
            print(f"  {BLOCK_OPEN}{args.record} --> … {BLOCK_CLOSE} block, then bind it.")
        print(f"  This is exit {EXIT_BIND}, NOT {EXIT_TOMBSTONE}: nothing BROKE — nothing EXISTS.")
        return EXIT_BIND

    rec = records[args.record]
    # PRESERVE tombstones outside the scope that was asked about; replace those inside it.
    touched = {loc for loc, _ in found} | set(wanted)
    kept = [t for t in rec.tombstones if t.get("location") not in touched]
    rec.tombstones = kept + [{"location": loc, "block_sha256": sha} for loc, sha in sorted(found)]

    rel = f"records/{rec.id}.json"
    (NAMESPACE / "records").mkdir(parents=True, exist_ok=True)
    (NAMESPACE / rel).write_text(json.dumps(rec.__dict__, indent=2), encoding="utf-8")
    manifest_add(NAMESPACE, rel)

    print(f"BOUND {rec.id}")
    for loc, sha in sorted(found):
        print(f"  {sha[:16]}…  {loc}")
    if kept:
        print(f"  {len(kept)} tombstone(s) OUTSIDE the named scope were PRESERVED, not dropped.")
    print(f"  record is now {'CLOSED' if not rec.is_open else 'OPEN'} "
          f"({len(rec.tombstones)} tombstone(s))")
    print("  ⚠ CLOSED DOES NOT MEAN GONE (R1). The withdrawn text is still live in the world, and")
    print("    every sweep still searches this record's variants — closed means the correction was")
    print("    made once, not that the claim stopped existing.")
    return EXIT_CLEAN


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sw = sub.add_parser("sweep", help="sweep records (default: ALL registered)")
    sw.add_argument("records", nargs="*", help="record ids; omit for all (R1)")
    sw.add_argument("--show", type=int, default=40)
    sw.set_defaults(fn=sweep)
    hv = sub.add_parser("harvest", help="harvest actual variants and register a record (R3/R4/R15)")
    hv.add_argument("id")
    hv.add_argument("seed")
    # ⚠ REPEATABLE, AND THAT IS A RULING RATHER THAN A CONVENIENCE. A claim can be made in more than
    # one place before anyone notices it is wrong — the founding incident had FIVE carriers — so a
    # single-valued flag would force the operator to pick one and silently discard the rest of the
    # span they had already found. `action="append"` keeps the adjudication explicit and RECORDED:
    # every named carrier lands in `Record.carriers` and in the census adjudication.
    hv.add_argument("--carrier", action="append", default=[], metavar="LOCATION",
                    help="location holding the claim; REPEATABLE and REQUIRED. The seeding "
                         "population IS the claim span inside these carriers (R15)")
    # ⚠ RETAINED DELIBERATELY, AND ITS ABSENCE WOULD BE SILENT. `--parent` is the ONLY input to
    # `ancestor_closure`, so dropping it by omission would leave R1's nested-withdrawal case with
    # nothing to close over — and the NESTED withdrawal is half of the founding failure. A flag that
    # goes missing takes a whole ruling dark without anything failing.
    hv.add_argument("--parent", default=None, help="supersession parent record id (R1)")
    hv.set_defaults(fn=harvest)
    # R7.5 — "re-binds in ONE command. If updating the control is harder than ignoring the failure,
    # ignoring wins." The friction IS the design constraint, so the shape stays one positional.
    rt = sub.add_parser("retombstone",
                        help="bind a record's correction blocks — closes the loop (R4/R7)")
    rt.add_argument("record")
    rt.add_argument("--location", action="append", default=[], metavar="LOCATION",
                    help="restrict to these locations; REPEATABLE. Omit to bind wherever the "
                         "block is. Tombstones outside the named scope are PRESERVED")
    rt.set_defaults(fn=retombstone)
    a = ap.parse_args(argv)
    # ⚠ D3/D4 — ONE HANDLER FOR EVERY COMMAND. `sweep`, `harvest` and `retombstone` all call
    # `load_records` BEFORE `instrument_gate`, so a broken registry cannot be caught by the gate.
    # Handling it here, once, is the same argument `instrument_gate` itself carries: three copies
    # are correct on the day they are written and diverge on the day one is edited.
    try:
        return int(a.fn(a))
    except RegistryUnreadable as exc:
        print(f"⚠ INSTRUMENT FAILURE — {exc}")
        print("  This is NOT an empty registry, which is clean. The registry EXISTS and cannot be")
        print("  read, so the selected set is UNKNOWABLE and no run may report on it.")
        return EXIT_INSTRUMENT
    except ConfigMissing as exc:
        # ⚠ ONE HANDLER, LIKE THE ONE ABOVE, AND FOR THE SAME REASON — all three commands call
        # `load_config` as their first statement, so three catches that must agree is the dual-site
        # shape this file has met repeatedly.
        print(f"⚠ NO CONFIG — {exc}")
        print("  This is exit 7, NOT the instrument code: the corpus and the channel are fine —")
        print("  the tool has never been configured on this machine. Different cause, different")
        print("  remediation, so different code (R4a).")
        return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
