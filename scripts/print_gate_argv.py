#!/usr/bin/env python3
"""Print the package argv for the enumerating gates, so ``ci.yml`` DERIVES it rather than restates it.

⚠ THIS EXISTS BECAUSE THE WORKFLOW CANNOT HOLD A PYTHON CONSTANT. ``ci.yml`` is YAML consumed by
GitHub Actions and ``check-overclaim.py`` is Python; they cannot share a module-level tuple. But
they do not need to — GitHub Actions never parses the roster, the SHELL does:

    - run: mypy --strict $(python scripts/print_gate_argv.py)

⚠ AND THE POINT IS NOT BREVITY, IT IS THAT THE LITERAL ARGV IS GONE. A workflow line reading
``mypy --strict core sandbox engine observe gate cli demo`` is a second enumeration of the roster,
correct on the day it is written and silently divergent the day only the other side is edited.
That is exactly how ``demo`` came to be type-checked while the overclaim gate never saw it.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_coverage import packages, partition_errors  # noqa: E402


def main() -> int:
    # ⚠ THE PARTITION IS CHECKED HERE TOO, NOT ONLY IN THE SUITE — because this is the path CI
    # actually takes. A roster that fails its own partition must never silently produce an argv:
    # mypy would then run over a set nobody had adjudicated, and pass, and the green build would
    # certify coverage the roster does not have.
    errs = partition_errors()
    if errs:
        print("gate roster FAILED its partition check — refusing to emit an argv:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(" ".join(packages()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
