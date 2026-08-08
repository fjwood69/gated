#!/usr/bin/env python3
"""ONE CLAIMS HARNESS FOR FIVE AXIOMS — a stated thing must not disagree with the actual thing.

⚠ ONE HARNESS PARAMETERISED BY SOURCE AND MODE, **NOT FIVE BESPOKE SCRIPTS**, AND THAT IS THE
RULING (R1, 2026-08-08). The five defects below have five different SOURCES OF TRUTH but ONE
constructor shape:

    derive the enumeration from its source, or pin it bidirectionally — and add a partition
    check with exclusions-as-data, so the source itself cannot silently miss a member.

    axiom        enumeration                        source of truth
    packages     which packages a gate covers       scripts/gate_coverage.json
    subcommands  that a subcommand exists           the argparse parser
    CI           what CI runs                       .github/workflows/ci.yml
    layout       what the repository contains       the git tree
    exit codes   which causes are stratified        the declared EXIT_* set

Writing five separate "compare two lists and fail" implementations would be the dual-site disease
this whole increment exists to kill, REBUILT ONE LEVEL UP. So the comparison lives in one place and
the axioms differ only in what they feed it.

⚠ WHAT THIS SUITE CANNOT DO, STATED RATHER THAN DISCOVERED LATER. The mechanism pins below are
SYNTACTIC. They catch a consumer that has stopped READING the roster; they do not catch one that
reads it and then ignores the result. A consumer carrying its own copy with IDENTICAL values is an
EQUIVALENT MUTANT that no value comparison can see — which is why the mechanism layer exists at
all, and why its limit is written here instead of being left for the next reader to find.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

import gate_coverage  # noqa: E402

_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_README = _ROOT / "README.md"


def _tracked(pattern: str = "") -> list[str]:
    argv = ["git", "ls-files"] + ([pattern] if pattern else [])
    return [f for f in subprocess.run(argv, capture_output=True, text=True, check=True,
                                      cwd=_ROOT).stdout.splitlines() if f]


# ══════════════════════════════════════════════════════════════════════════════════════════════
# AXIOM 1 — packages. Source of truth: scripts/gate_coverage.json
# ══════════════════════════════════════════════════════════════════════════════════════════════
class PackageRosterIsDerived(unittest.TestCase):
    """#47 — mypy's argv and check-overclaim's set were two enumerations of one conceptual set."""

    def test_the_roster_PARTITIONS_every_tracked_python_directory(self):
        """⚠ THE ROSTER ITSELF IS THE SAME DEFECT ONE LEVEL UP, WHICH IS WHY THIS EXISTS. A derived
        roster still needs a human to add a new package, and nothing fails if they do not — it is
        authoritative about members it happens to name and silent about the rest. The partition
        turns a silent omission into a forced adjudication."""
        self.assertEqual(gate_coverage.partition_errors(), [])

    def test_every_exclusion_states_WHAT_WOULD_MAKE_IT_UNNECESSARY(self):
        """⚠ `remove_when` IS WHAT SEPARATES EXCLUSIONS-AS-DATA FROM EXCLUSIONS-AS-DRAIN. An entry
        carrying only a justification is a PERMANENT GRANT: the table only accumulates, and nobody
        revisits a reason. An expiry condition makes a STALE exclusion mechanically findable. It is
        the tombstone's discipline — a suppression that carries its own expiry, not a standing one."""
        data = gate_coverage.load()
        tables = {"packages_excluded": data.get("packages_excluded", {}),
                  "layout_excluded": data.get("layout_excluded", {}),
                  "ci_claim_exemptions": data.get("ci_claim_exemptions", {})}
        for table, entries in tables.items():
            self.assertTrue(entries, f"{table} is empty — this test would pass vacuously")
            for name, entry in entries.items():
                with self.subTest(table=table, entry=name):
                    self.assertTrue(str(entry.get("reason", "")).strip(),
                                    f"{table}.{name} has no reason")
                    self.assertTrue(str(entry.get("remove_when", "")).strip(),
                                    f"{table}.{name} has no remove_when — a permanent grant")

    def test_ci_DERIVES_the_argv_and_carries_NO_literal_package_list(self):
        """⚠ MECHANISM PIN, NOT A VALUE PIN — LAYER 2. A consumer that copies the roster with
        IDENTICAL values is invisible to every value comparison (an equivalent mutant today, a
        divergence next week). What is detectable is that the consumer STOPPED READING: the run
        line must contain the substitution and nothing shaped like a literal package argv."""
        # ⚠ `run:` LINES ONLY — a comment mentioning the command is not an invocation. The first
        # version of this matched any line containing "mypy --strict" and caught the two comment
        # lines explaining the derivation, so it failed on correct work. A guard that reds on the
        # thing it is documenting gets loosened by whoever is blocked.
        line = [ln for ln in _CI.read_text(encoding="utf-8").splitlines()
                if re.match(r"\s*(?:- )?run:.*mypy --strict", ln)]
        self.assertEqual(len(line), 1, "expected exactly one mypy invocation in ci.yml")
        self.assertIn("print_gate_argv.py", line[0],
                      "ci.yml must DERIVE the package argv, never restate it")
        for pkg in gate_coverage.packages():
            self.assertNotIn(f" {pkg}", line[0],
                             f"ci.yml names {pkg!r} literally — that is a second enumeration")

    def test_overclaim_takes_its_sets_FROM_THE_LOADER_not_a_module_level_tuple(self):
        """⚠ THE SAME MECHANISM PIN, AT AST LEVEL. A re-introduced `_PACKAGES = (...)` literal would
        agree with the roster on the day it was written and diverge silently afterwards — which is
        precisely what happened before this increment: `demo` was type-checked by mypy and never
        scanned by this gate."""
        src = (_ROOT / "scripts" / "check-overclaim.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        known = set(gate_coverage.packages()) | set(gate_coverage.markdown())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Tuple, ast.List)):
                vals = {e.value for e in node.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                if len(vals) >= 2 and vals <= known:
                    self.fail(f"check-overclaim.py carries a literal roster copy: {sorted(vals)}")
        self.assertIn("from gate_coverage import", src)

    def test_the_ROSTER_ITSELF_reds_when_an_entry_is_removed(self):
        """The armed mutant: delete a package from the single file. LAYER 1 — value disagreement.

        ⚠ AND THE STIMULUS IS PROVEN, NOT ASSUMED: the unmutated roster must partition cleanly
        first, or this test would pass on a roster that was already broken."""
        self.assertEqual(gate_coverage.partition_errors(), [], "stimulus control: roster starts clean")
        data = gate_coverage.load()
        dropped = dict(data)
        dropped["packages"] = [p for p in data["packages"] if p != "demo"]
        orig = gate_coverage.load
        try:
            gate_coverage.load = lambda: dropped     # type: ignore[assignment]
            errs = gate_coverage.partition_errors()
        finally:
            gate_coverage.load = orig                # type: ignore[assignment]
        self.assertTrue(any("demo/" in e for e in errs),
                        "dropping `demo` from the roster must red — it is neither covered nor excluded")


# ══════════════════════════════════════════════════════════════════════════════════════════════
# AXIOM 2 — subcommands. Source of truth: the argparse parser
# ══════════════════════════════════════════════════════════════════════════════════════════════
_BACKTICKED_SWEEP = re.compile(r"`sweep\s+([a-z][a-z0-9_-]*)`")


class SubcommandClaimsAreDerivedFromTheParser(unittest.TestCase):
    """#45 — a refusal named `sweep init`, which has never existed.

    ⚠ SCOPED TO BACKTICKED SPANS, AND THAT IS RECORDED RATHER THAN CLAIMED AWAY. Naive tokenisation
    false-positives immediately: the parser's own help reads "sweep records (default: ALL
    registered)" and `records` is not a subcommand. The defect lived inside backticks, so the check
    lives there too — this is NOT full-prose coverage and must not be read as it.
    """

    def test_no_operator_facing_string_names_an_UNREGISTERED_subcommand(self):
        import sweep as S
        known = S.registered_subcommands()
        self.assertTrue(known, "no subcommands discovered — the check would pass vacuously")
        src = (_ROOT / "scripts" / "sweep.py").read_text(encoding="utf-8")
        named = set(_BACKTICKED_SWEEP.findall(src))
        self.assertEqual(named - known, set(),
                         f"operator-facing text names subcommand(s) the parser does not define; "
                         f"registered: {sorted(known)}")

    def test_the_check_REDS_on_a_phantom_and_STAYS_GREEN_on_a_real_one(self):
        """⚠ THE CORRELATED POSITIVE COMES FROM A FIXTURE, BECAUSE THE FIX REMOVED ITS CARRIER. After
        the repair the production message names ZERO subcommands, so "a message naming a real
        subcommand stays green" has no production string left to stand on. The property under test
        is the CHECK's behaviour, so a synthetic pair is the honest instrument — without it this
        would silently pin "messages contain no subcommand names", which is not the property."""
        import sweep as S
        known = S.registered_subcommands()
        self.assertEqual(set(_BACKTICKED_SWEEP.findall("run `sweep harvest` first")) - known, set())
        self.assertEqual(set(_BACKTICKED_SWEEP.findall("run `sweep init` first")) - known, {"init"})

    def test_subcommands_come_from_the_PARSER_OBJECT_not_the_SOURCE_TEXT(self):
        """⚠ THE CONTROL THAT DISTINGUISHES D2's FIX FROM D2's DEFECT, AND IT WAS MEASURED ONCE IN A
        BOARD ENTRY AND NEVER COMMITTED. Reverting the derivation to the old regex over
        ``sub.add_parser("...")`` literals would leave every other test in this file GREEN, because
        production registers with lowercase string literals that the regex happens to match. So the
        mechanism closing D2 could regress in silence.

        A stimulus that proves a mechanism works is not a control until it is IN THE SUITE — the
        disarmed-bomb rule applied to a control rather than to a test.

        The discriminator: register a subcommand whose name arrives via a VARIABLE. A regex over
        source literals cannot see it; a read of the parser's own ``choices`` must. Asserting BOTH
        halves is what makes this a discriminator rather than a restatement — it pins that the two
        mechanisms genuinely disagree, and that ours is the one telling the truth.

        ⚠ AND THE HARNESS HAS NO WRAPPER ROUND IT, WHICH IS THE OTHER HALF OF THE FIX. The first
        attempt pinned production and left a `_registered()` helper in this file free to go back to
        a regex — a red-proof mutant reverted exactly that and SURVIVED, because nothing here called
        the pinned function through it. A wrapper is a second site, and a second site is the defect
        this whole increment is about. So the wrapper is deleted rather than checked: every caller
        asks `sweep.registered_subcommands()` directly, and there is no intermediate left to drift.

        ⚠ RESIDUAL, MEASURED AND NOT CLOSED. Deleting the wrapper removes the second site that
        EXISTS; it does not make second sites UNREPRESENTABLE. Measured 2026-08-08: reintroducing a
        `_registered()` helper that reads the source with a VERIFIED-WORKING regex, and repointing
        the two callers at it, leaves this whole file GREEN. So a future contributor can reopen D2
        by hand and nothing here will say so.
        ⚠ AND THE FIRST ATTEMPT TO MEASURE THAT PRODUCED A FALSE KILL: an escaping error made the
        mutant's regex match nothing, the tests redded, and it read as "the wrapper is forbidden".
        It was a BAD MUTANT — killed for a reason unrelated to its target. The real answer only
        appeared after asserting the mutant's own regex found the three subcommands first. A mutant
        must be proven ARMED before its death means anything.
        Closing this properly needs a pin on THIS FILE's own mechanism, which is a step deeper than
        the increment was scoped for. Stated here rather than left for the next reader to find.
        """
        import sweep as S
        real = S.build_parser

        def patched():
            ap = real()
            for act in ap._actions:
                if isinstance(act, S.argparse._SubParsersAction):
                    name = "audit"      # via a variable — invisible to a literal-matching regex
                    act.add_parser(name, help="probe")
            return ap

        try:
            S.build_parser = patched                 # type: ignore[assignment]
            seen = S.registered_subcommands()
        finally:
            S.build_parser = real                    # type: ignore[assignment]

        self.assertIn("audit", seen,
                      "registered_subcommands must read the parser OBJECT — a variable-named "
                      "registration is exactly what a source-text regex cannot see")
        src = (_ROOT / "scripts" / "sweep.py").read_text(encoding="utf-8")
        by_regex = set(re.findall(r'sub\.add_parser\(\s*"([a-z]+)"', src))
        self.assertNotIn("audit", by_regex,
                         "stimulus control: if the regex COULD see it, this test proves nothing")

    def test_the_no_config_refusal_points_at_a_TRACKED_FILE(self):
        """The remediation is a manual act of authorship: a path claim, which is checkable."""
        import sweep as S
        msg = ""
        real = S.CONFIG_PATH
        try:
            S.CONFIG_PATH = _ROOT / "scripts" / "definitely-absent.json"
            try:
                S.load_config()
            except S.ConfigMissing as exc:
                msg = str(exc)
        finally:
            S.CONFIG_PATH = real
        self.assertIn("sweep.config.example.json", msg)
        self.assertEqual(set(_BACKTICKED_SWEEP.findall(msg)), set(),
                         "the refusal must name NO subcommand — none can perform this remediation")
        self.assertIn("scripts/sweep.config.example.json", _tracked(),
                      "the file the refusal names must actually be tracked")


# ══════════════════════════════════════════════════════════════════════════════════════════════
# AXIOM 3 — exit codes. Source of truth: the declared EXIT_* set
# ══════════════════════════════════════════════════════════════════════════════════════════════
class ExitCodesArePartitioned(unittest.TestCase):
    """The seventh carrier — the exit-code set was itself an enumeration with no partition check."""

    def test_every_declared_code_is_DISTINCT(self):
        """⚠ DERIVED FROM THE MODULE, NOT A HAND-LISTED SET. The previous distinctness tests named
        codes one at a time, so each new code had to be REMEMBERED into them — and `EXIT_BIND` was
        pinned against exactly one of six. A registry-level test cannot be forgotten."""
        import sweep as S
        codes = {n: v for n, v in vars(S).items() if n.startswith("EXIT_")}
        self.assertGreaterEqual(len(codes), 8)
        self.assertEqual(len(set(codes.values())), len(codes),
                         f"exit codes collide: {sorted(codes.items(), key=lambda kv: kv[1])}")

    def test_no_refusal_site_exits_with_a_BARE_STRING_OR_INT(self):
        """⚠ THE PARTITION CHECK FOR THIS MICRO-ROSTER. `sys.exit(<str>)` exits 1, so the no-config
        refusal agreed with EXIT_INSTRUMENT by COINCIDENCE — the collision the R4a stratification
        exists to prevent, reached through a stdlib default rather than through a decision."""
        src = (_ROOT / "scripts" / "sweep.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        bad = []
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "exit" and node.args):
                arg = node.args[0]
                if isinstance(arg, ast.Constant) or isinstance(arg, ast.JoinedStr):
                    bad.append(getattr(node, "lineno", "?"))
                elif isinstance(arg, ast.Name) and not arg.id.startswith("EXIT_"):
                    if arg.id not in ("rc", "code"):
                        bad.append(getattr(node, "lineno", "?"))
        self.assertEqual(bad, [], f"sys.exit with a non-EXIT_* argument at line(s) {bad}")

    def test_config_absent_is_its_OWN_code_not_the_instrument_code(self):
        import sweep as S
        self.assertNotEqual(S.EXIT_CONFIG, S.EXIT_INSTRUMENT,
                            "config-absent is a CALLER-ENVIRONMENT failure; EXIT_INSTRUMENT sends "
                            "the reader to check globs and the board when the config was never made")


# ══════════════════════════════════════════════════════════════════════════════════════════════
# AXIOM 4 — CI. Source of truth: .github/workflows/ci.yml   (BIDIRECTIONAL)
# ══════════════════════════════════════════════════════════════════════════════════════════════
class ReadmeCiClaimsArePinnedBOTHWays(unittest.TestCase):
    """#46 — README documented `-W error`; CI never ran it.

    ⚠ BIDIRECTIONALITY IS THE WHOLE POINT. A one-way check (everything the README claims is in CI)
    would have PASSED on the development snippet's `check-voice.py` omission, because omitting a
    gate is not a false claim — it is an incomplete one. A list is a claim about its contents.

    ⚠ THE BOUNDARY, STATED SO IT STAYS STABLE: this pins command names, their flags, and the Python
    floor. Prose about CI's character is out of scope and stays a human matter. Anything that
    mentions CI and is neither must be hedged prose or a reviewed exemption CARRYING ITS OWN
    `remove_when` — otherwise the exemption table becomes where claims go to stop being checked.
    """

    @staticmethod
    def _ci_commands() -> set[str]:
        out = set()
        for ln in _CI.read_text(encoding="utf-8").splitlines():
            m = re.match(r"\s*(?:- )?run:\s*(.+)$", ln)
            if m and not m.group(1).startswith("|"):
                out.add(m.group(1).strip())
        return out

    @staticmethod
    def _readme_commands() -> set[str]:
        text = _README.read_text(encoding="utf-8")
        out = set()
        for block in re.findall(r"```bash\n(.*?)```", text, re.DOTALL):
            for ln in block.splitlines():
                if ln.strip():
                    out.add(ln.strip())
        return out

    def test_EVERY_CI_JOB_is_checked_or_exempted_and_no_exemption_is_STALE(self):
        """⚠ THE EXEMPTION TABLE IS ITSELF PARTITIONED, WHICH IS THE CORRECTION AND NOT A DETAIL.

        The first version keyed exemptions on gate-script FILENAMES and compared them against
        `scripts/*.py` run lines — so the key `hygiene` could never match anything, the entry was
        INERT, and the claim that the hygiene job "would have redded on day one" was FALSE AS
        BUILT: the check never inspected that job at all. A clearance predicate with no caller,
        committed while closing the family that names it.

        Keying on JOB NAMES fixes that and introduces the same defect one field over — the table
        becomes a claim about ci.yml's job set. So it partitions BOTH ways: no job silently
        unchecked, and no exemption naming a job that does not exist.
        """
        self.assertEqual(gate_coverage.ci_exemption_errors(), [])

    def test_every_job_with_a_RUNNABLE_command_has_it_mentioned_in_the_readme(self):
        """⚠ JOB-LEVEL, NOT SCRIPT-LEVEL. A job whose commands cannot be mirrored locally must be
        EXEMPTED; a job whose commands can be must have them in the README. That makes "has no
        local twin" a measured property of the workflow rather than an assertion about it."""
        readme = _README.read_text(encoding="utf-8")
        exempt = set(gate_coverage.load().get("ci_claim_exemptions", {}))
        jobs = gate_coverage.ci_jobs_with_commands()
        self.assertTrue(jobs, "no jobs parsed — this check would pass vacuously")
        for job, cmds in sorted(jobs.items()):
            runnable = gate_coverage.runnable_commands(cmds)
            with self.subTest(job=job):
                if not runnable:
                    self.assertIn(job, exempt,
                                  f"job {job!r} has no locally runnable command and is not "
                                  f"exempted — it can never be mirrored, so silence about it is "
                                  f"an unrecorded decision")
                    continue
                for cmd in runnable:
                    tok = re.search(r"(scripts/[a-z-]+\.py|mypy|ruff|unittest)", cmd)
                    self.assertTrue(tok and tok.group(1) in readme,
                                    f"CI job {job!r} runs {cmd!r} and the README never mentions "
                                    f"it — an incomplete list is still a claim about contents")

    def test_the_readme_unittest_flags_MATCH_ci(self):
        """The actual defect, at FLAG granularity: `-W error` in one surface only."""
        ci = [c for c in self._ci_commands() if "unittest discover" in c]
        rd = [c for c in self._readme_commands() if "unittest discover" in c]
        self.assertTrue(ci and rd)
        # ⚠ `-v` IS EXCLUDED FROM BOTH SIDES, AND ONLY `-v`. It is a VERBOSITY flag: it changes what
        # the runner prints, never what is executed or asserted, so CI wanting per-test output while
        # the README shows the plain command is not a disagreement about behaviour. `-W error` is
        # the opposite kind — it changes whether a warning fails the run — which is why the actual
        # defect this test exists for still reds. Excluding the set symmetrically matters: an
        # asymmetric exclusion would have hidden the defect on whichever side it was applied to.
        display_only = {"-v"}
        self.assertEqual(set(re.findall(r"-\w+", ci[0])) - display_only,
                         set(re.findall(r"-\w+", rd[0])) - display_only,
                         f"README and CI disagree on unittest flags: {rd[0]!r} vs {ci[0]!r}")

    def test_the_python_floor_matches_the_matrix(self):
        """A between-case the drafted boundary missed: mechanical floor, unbounded 'or later'."""
        matrix = re.findall(r'"(3\.\d+)"', _CI.read_text(encoding="utf-8"))
        self.assertTrue(matrix)
        floor = min(matrix, key=lambda v: [int(x) for x in v.split(".")])
        self.assertIn(f"Python {floor} or later", _README.read_text(encoding="utf-8"))

    def test_the_hygiene_exemption_is_RECORDED_with_its_expiry(self):
        """⚠ EXEMPTION #1, AND IT WOULD HAVE REDDED ON DAY ONE. The hygiene job is shell embedded in
        YAML with no locally invocable twin, so the README cannot mirror it. That is not a false
        claim — it is an unclassifiable one, and the honest form is data, not silence."""
        ex = gate_coverage.load()["ci_claim_exemptions"]["hygiene"]
        self.assertTrue(ex["reason"].strip() and ex["remove_when"].strip())


# ══════════════════════════════════════════════════════════════════════════════════════════════
# AXIOM 5 — layout. Source of truth: the git tree
# ══════════════════════════════════════════════════════════════════════════════════════════════
class LayoutListIsAClaimAboutTheTree(unittest.TestCase):
    """The eighth carrier — the layout section omitted `demo/`, the one package the README says to run.

    ⚠ WIDENED TO EVERY TRACKED TOP-LEVEL DIRECTORY, VIA A PUBLIC HELPER. The first version walked
    python-bearing directories only, while the design claimed the source of truth was THE GIT TREE
    — so `docs/` could be added to the list and NOTHING PINNED IT. The stated source was wider than
    the actual source: this increment's own defect, one level in, found in dissent on PR #49. It
    also reached across a module boundary into a private helper.
    """

    def test_every_tracked_top_level_directory_APPEARS_or_is_EXCLUDED(self):
        text = _README.read_text(encoding="utf-8")
        section = text.split("## Repository layout", 1)[1].split("\n## ", 1)[0]
        listed = set(re.findall(r"^- `([a-z_.]+)/`", section, re.MULTILINE))
        self.assertEqual(gate_coverage.layout_errors(listed), [])

    def test_the_layout_check_is_BIDIRECTIONAL(self):
        """⚠ ADDED IN RE-DISSENT. The first repair caught tracked-but-not-listed and accepted
        listed-but-not-tracked, so a README naming a directory that does not exist redded nothing.
        An omission leaves a list INCOMPLETE; a phantom entry makes it FALSE. And the one-way check
        was written in the same increment that ruled bidirectionality "the whole point" for the
        README-versus-CI pin — the rule stated on one axiom and not carried to the next."""
        real = gate_coverage.top_level_dirs() - set(gate_coverage.load().get("layout_excluded", {}))
        self.assertEqual(gate_coverage.layout_errors(real), [], "stimulus control: starts clean")
        self.assertTrue(any("ghost" in e for e in gate_coverage.layout_errors(real | {"ghost"})),
                        "a phantom layout entry must red")
        victim = sorted(real)[0]
        self.assertTrue(any(victim in e for e in gate_coverage.layout_errors(real - {victim})),
                        "an omitted directory must red")


if __name__ == "__main__":
    unittest.main(verbosity=2)
