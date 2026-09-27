#!/usr/bin/env python3
"""Content-sterility gate for the public `gated` repo.

Fails (exit 1) if internal / homelab-specific markers leak into TRACKED content.
Adopted from the mori project's gate, and since extended here (P10c, #52) — a leak
fails the build instead of shipping. Run locally:  python scripts/check-sterility.py

Allowed exceptions (deliberate references) live in ALLOW, in this script.

WHAT P10c ADDED, AND WHAT A GREEN RUN STILL DOES NOT SAY:
  * an ALLOW entry must be a tracked file that contains at least one marker, else it is
    STALE and reds. The grain is PER FILE: once a file is allowed for one legitimate
    marker, further markers added to it stay green. That is a stated limit, not a check.
  * ALLOW stays here, not in scripts/gate_coverage.json with the other exemption tables:
    .github/workflows/ci.yml describes this as "a maintained MARKERS + ALLOW script", and
    P10c could not touch .github/. The move is issue #55.
  * a tracked path that cannot be read is NOT SCANNED and reds — never reported clean.
  * MARKERS must be non-empty (an empty list would pass vacuously) and every pattern must
    compile. They are matched case-insensitively, so case is not a normal-form question here.
  * files are read with errors="ignore": undecodable bytes are dropped from the scanned
    text. Accepted as lossy, and stated rather than implied.
  * every run is a FULL scan of `git ls-files`; there are no arguments.
"""

from __future__ import annotations

import re
import subprocess
import sys

# (pattern, human-readable reason). Case-insensitive. High-signal / low-false-positive:
# specific homelab hostnames, paths, the known prod IP, LAN range, and internal id forms.
MARKERS: list[tuple[str, str]] = [
    (r"/home/nucadmin", "absolute homelab path"),
    (r"\bnuc15pro\b", "homelab hostname"),
    (r"\buk-smr-", "homelab hostname"),
    (r"\bca-ws-raspi", "homelab hostname"),
    (r"\buk-ga-raspi", "homelab hostname"),
    (r"\bux3405\b", "homelab hostname"),
    (r"\btwiggy\b", "homelab hostname"),
    (r"\braspi[0-9]", "homelab hostname"),
    (r"\b10\.1\.2\.[0-9]{1,3}\b", "homelab LAN IP"),
    (r"\b100\.90\.219\.111\b", "prod GCE IP"),
    (r"consult-[0-9a-f]{10,}", "internal consult id"),
    (r"dotfiles/", "dotfiles path"),
    (r"sk-ant-", "Anthropic credential shape"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub token shape"),
    (r"xoxb-", "Slack token shape"),
    # open-core purity: gated must not name the private stack it was extracted from.
    (r"\bmori-verse\b", "pre-extraction project name (de-baptise to 'gated')"),
    (r"\bmoriverse\b", "pre-extraction project name (de-baptise to 'gated')"),
    (r"MORIVERSE_", "pre-extraction env prefix (de-baptise to 'GATED_')"),
    (r"\bbifrost\b", "private-stack component"),
    # homelab hosts / users the high-signal set above misses (bare forms). NOTE: 'mori' is NOT blocked —
    # it is the project's genesis name and appears deliberately (moriapp.dev, the reference image, etc.).
    (r"\bNUC\b", "homelab host shorthand (genericise to 'a self-hosted runner' / 'a machine with podman')"),
    (r"\bnucadmin\b", "homelab username"),
    (r"\bpiadmin\b", "homelab username"),
    (r"\bjadmin\b", "homelab username"),
]

# Files where an internal reference is intentional and reviewed.
ALLOW = {
    "scripts/check-sterility.py",  # this file necessarily contains the patterns
}


def _tracked_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if f]


def scan_sterility(files: dict[str, str | None], markers: list[tuple[str, str]], allow: set[str]
                   ) -> tuple[list[tuple[str, int, str, str]], list[str]]:
    """The whole scan, pure: ``(violations, table errors)``.

    ``files`` maps a tracked path to its text, or ``None`` if it could not be read. Allowed files are
    still scanned, to COUNT their marker hits: an allowed file with no hit is a stale entry.
    """
    table_errors: list[str] = []
    if not markers:
        table_errors.append("MARKERS is EMPTY — the gate would pass vacuously, guarding nothing")
    pats = []
    for p, why in markers:
        try:
            pats.append((re.compile(p, re.IGNORECASE), why))
        except re.error as exc:
            table_errors.append(f"MARKERS pattern {p!r} does not compile ({exc}) — it guards nothing")
    violations: list[tuple[str, int, str, str]] = []
    allowed_hits = {a: 0 for a in allow}
    for f, text in sorted(files.items()):
        if text is None:
            violations.append((f, 0, "NOT SCANNED", "tracked path that could not be read"))
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pat, why in pats:
                if pat.search(line):
                    if f in allow:
                        allowed_hits[f] += 1
                    else:
                        violations.append((f, i, why, line.strip()[:100]))
    for a in sorted(allow):
        if a not in files:
            table_errors.append(f"ALLOW names {a!r}, which is not a tracked file — STALE")
        elif files[a] is not None and allowed_hits[a] == 0:
            table_errors.append(f"ALLOW names {a!r}, which contains no marker — STALE: it exempts nothing")
    return violations, table_errors


def main() -> int:
    files: dict[str, str | None] = {}
    for f in _tracked_files():
        try:
            with open(f, encoding="utf-8", errors="ignore") as fh:
                files[f] = fh.read()
        except OSError:  # includes IsADirectoryError
            files[f] = None
    violations, table_errors = scan_sterility(files, MARKERS, ALLOW)

    # Accumulate, never early-return: a table error must not hide a violation, nor the reverse.
    if table_errors:
        print("STERILITY GATE FAILED — its own tables:")
        for e in table_errors:
            print(f"  - {e}")
    if violations:
        print("STERILITY GATE FAILED — internal/homelab markers in tracked content:\n")
        for f, i, why, txt in violations:
            print(f"  {f}:{i}  [{why}]  {txt}")
        print(
            f"\n{len(violations)} violation(s). Sanitise before committing; "
            "if a reference is intentional, add the file to ALLOW."
        )
    if table_errors or violations:
        return 1

    print("Sterility gate OK — no internal/homelab markers in tracked content.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
