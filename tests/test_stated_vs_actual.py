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
import json
import re
import subprocess
import sys
import tempfile
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
        # ⚠ DERIVED, NOT HAND-LISTED. This dict used to name three tables, so a fourth
        # (display_only_flags) would have been silently skipped — the per-surface shape in the test
        # that polices it. `exemption_tables()` derives the set and reds anything it cannot classify.
        tables, errs = gate_coverage.exemption_tables()
        self.assertEqual(errs, [])
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
class _Roster:
    """Patch the roster for one test, restoring it however the test exits."""

    def __init__(self, mutate):
        self.mutate = mutate

    def __enter__(self):
        self.orig = gate_coverage.load
        data = json.loads(json.dumps(self.orig()))
        self.mutate(data)
        gate_coverage.load = lambda: data                     # type: ignore[assignment]
        return data

    def __exit__(self, *exc):
        gate_coverage.load = self.orig                        # type: ignore[assignment]
        return False


class ReadmeCiClaimsArePinnedBOTHWays(unittest.TestCase):
    """#46 and #50 — README documented `-W error`; CI never ran it. Nothing stopped it coming back.

    ⚠ ONE FUNCTION, BOTH DIRECTIONS: ``gate_coverage.readme_ci_claim_errors``. README → CI (every
    claim in the delimited region is a command CI runs) and CI → README (every runnable CI command is
    claimed there). The class name claims both directions because the function implements both —
    the F2 rule from #49, where a function's name claimed a direction its body did not implement.

    ⚠ WHAT THE OLD VERSION OF THIS CLASS ACTUALLY CHECKED, MEASURED 2026-09-26. The CI → README
    "direction" searched the WHOLE README for a token: deleting the `mypy` line from the gates block
    left everything green, because "mypy" also appears in prose. The README → CI direction did not
    exist. And a CI command outside the runnable allowlist — `pytest -W error tests` — was dropped by
    every check. Each of those is now a test below, and each mutant is PROVEN ARMED before its red
    is counted: a mutant that dies for an unrelated reason manufactures evidence of safety.

    ⚠ THE BOUNDARY, STATED SO IT STAYS STABLE: command names and flags, inside the marked region.
    Prose about CI's character is out of scope and stays a human matter.
    """

    @staticmethod
    def _readme() -> str:
        return _README.read_text(encoding="utf-8")

    def _errs(self, readme: str | None = None, ci: str | None = None) -> list[str]:
        if ci is None:
            return gate_coverage.readme_ci_claim_errors(readme_text=readme)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ci.yml"
            p.write_text(ci, encoding="utf-8")
            return gate_coverage.readme_ci_claim_errors(readme_text=readme, ci_path=p)

    def _assert_reds(self, errs: list[str], fragment: str) -> None:
        self.assertTrue(any(fragment in e for e in errs),
                        f"expected a red containing {fragment!r}; got {errs}")

    # ── the correlated positive ───────────────────────────────────────────────────────────────
    def test_the_real_tree_is_CLEAN_in_both_directions(self):
        """⚠ THE CORRELATED POSITIVE: without it, a check that rejected everything would pass every
        red test below. Six real claims, six real commands, zero errors."""
        claims, errs = gate_coverage.readme_claims(self._readme())
        self.assertEqual(errs, [])
        self.assertEqual(len(claims), 6, f"expected the six real claims, got {claims}")
        self.assertEqual(gate_coverage.readme_ci_claim_errors(), [])

    # ── README → CI (#50) ─────────────────────────────────────────────────────────────────────
    def test_a_PHANTOM_claim_reds(self):
        """#50 itself: a README claiming a gate CI never runs. VALUE mutant."""
        text = self._readme().replace("python scripts/check-voice.py\n",
                                      "python scripts/check-voice.py\npython scripts/check-phantom.py\n", 1)
        self.assertIn("python scripts/check-phantom.py", gate_coverage.readme_claims(text)[0],
                      "stimulus control: the phantom must be parsed as a claim, or this proves nothing")
        self._assert_reds(self._errs(text), "CI never runs it")

    def test_the_46_defect_reds(self):
        """The original defect, kept as a committed control: `-W error` on the README side only."""
        text = self._readme().replace("python -m unittest discover -s tests\n",
                                      "python -m unittest discover -s tests -W error\n", 1)
        self.assertIn("-W error", text, "stimulus control")
        errs = self._errs(text)
        self._assert_reds(errs, "CI never runs it")
        self._assert_reds(errs, "omits it")

    # ── CI → README ───────────────────────────────────────────────────────────────────────────
    def test_an_OMITTED_claim_reds_EVEN_THOUGH_THE_TOKEN_SURVIVES_IN_PROSE(self):
        """Mutant A — the one the old whole-README token search could not see."""
        line = "mypy --strict $(python scripts/print_gate_argv.py)\n"
        text = self._readme()
        self.assertIn(line, text)
        text = text.replace(line, "", 1)
        self.assertIn("mypy", text, "stimulus control: the TOKEN must survive in prose, or this "
                                    "does not reproduce the blind spot")
        self._assert_reds(self._errs(text), "omits it")

    def test_a_command_OUTSIDE_the_region_is_not_a_claim(self):
        """MECHANISM mutant (i): the check must read the REGION, never the whole README. The mypy line
        is moved out of the region into its own bash fence after the end marker."""
        line = "mypy --strict $(python scripts/print_gate_argv.py)\n"
        text = self._readme().replace(line, "", 1)
        text = text.replace("<!-- ci-claims:end -->\n",
                            "<!-- ci-claims:end -->\n\n```bash\n" + line + "```\n", 1)
        self.assertIn("```bash\n" + line, text, "stimulus control")
        self._assert_reds(self._errs(text), "omits it")

    # ── the region's structure (R3) ───────────────────────────────────────────────────────────
    def test_every_STRUCTURAL_failure_reds_with_its_OWN_message(self):
        """An empty or missing region is a failure, never a pass — and each malformation says which."""
        base = self._readme()
        b, e = "<!-- ci-claims:begin -->\n", "<!-- ci-claims:end -->\n"
        region = base[base.index(b):base.index(e) + len(e)]
        cases = {
            "no begin": (base.replace(b, "", 1), "NO ci-claims:begin"),
            "no end": (base.replace(e, "", 1), "NO ci-claims:end"),
            "two regions": (base + "\n" + region, "exactly one region"),
            "end before begin": (base.replace(b, "@@B@@", 1).replace(e, b, 1).replace("@@B@@", e, 1),
                                 "no open region"),
            "empty region": (base.replace(region, b + "Nothing here.\n" + e, 1), "ZERO claims"),
            "marker inside a fence": (base.replace("```bash\npython -m unittest",
                                                   "```bash\n<!-- ci-claims:end -->\npython -m unittest", 1),
                                      "INSIDE the fence"),
            "unterminated fence": (base + "\n```bash\nleft open\n", "never closed"),
            "non-bash fence": (base.replace("```bash\npython -m unittest", "```sh\npython -m unittest", 1),
                               "only ```bash"),
            "indented fence": (base.replace("```bash\npython -m unittest", "  ```bash\npython -m unittest", 1),
                               "INDENTED"),
            "comment in a claims fence": (base.replace("ruff check .\n", "ruff check .\n# lint\n", 1),
                                          "comment line"),
            "duplicate claim": (base.replace("ruff check .\n", "ruff check .\nruff check .\n", 1),
                                "duplicate claim"),
        }
        messages = set()
        for label, (text, fragment) in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(text, base, "stimulus control: the mutation must change the text")
                errs = self._errs(text)
                self._assert_reds(errs, fragment)
                messages.add(fragment)
        self.assertEqual(len(messages), len(cases), "each structural failure has its own message")

    # ── every workflow file, not just ci.yml (board, 2026-09-26) ──────────────────────────────
    def test_an_UNLISTED_workflow_file_reds(self):
        """A second workflow is CI the claims check never sees. It must be partitioned or exempted."""
        # ⚠ AGAINST THE REAL ENUMERATION PLUS A NAME NO WORKFLOW HAS. The first version used
        # dissent-gate.yml as its unlisted example and ci.yml-alone as its control — both true at
        # P10a, both false the moment P10b exempted that file. A test coupled to the tree's state
        # rather than to the rule breaks on correct work.
        real = gate_coverage.workflow_files()
        self.assertEqual(gate_coverage.workflow_errors(real), [], "control: the real tree is clean")
        self._assert_reds(gate_coverage.workflow_errors(real + ["unlisted-probe.yml"]),
                          "neither checked against the README nor exempted")
        self._assert_reds(gate_coverage.readme_ci_claim_errors(workflows=["ci.yml", "extra.yaml"]),
                          "'extra.yaml'")

    def test_an_EXEMPTED_workflow_file_is_green_and_a_STALE_one_reds(self):
        entry = {"reason": "r", "remove_when": "w"}
        with _Roster(lambda d: d.update({"workflows_excluded": {"extra.yml": entry}})):
            self.assertEqual(gate_coverage.workflow_errors(["ci.yml", "extra.yml"]), [],
                             "correlated positive: an exempted workflow file is not red")
            self._assert_reds(gate_coverage.workflow_errors(["ci.yml"]), "not a tracked workflow file")
        with _Roster(lambda d: d.update({"workflows_excluded": {"ci.yml": entry}})):
            self._assert_reds(gate_coverage.workflow_errors(["ci.yml"]), "BOTH checked and exempted")

    def test_the_ENUMERATION_reads_the_tracked_directory_not_a_list(self):
        """MECHANISM: the check is only as good as the enumeration. A throwaway repository holding a
        second workflow, with a .yaml extension, must be seen — a hard-coded list or a *.yml glob
        would miss it."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            wf = root / ".github" / "workflows"
            wf.mkdir(parents=True)
            (wf / "ci.yml").write_text("name: CI\n", encoding="utf-8")
            (wf / "other.yaml").write_text("name: Other\n", encoding="utf-8")
            (wf / "untracked.yml").write_text("name: U\n", encoding="utf-8")
            for argv in (["git", "init", "-q"], ["git", "add", ".github/workflows/ci.yml",
                                                 ".github/workflows/other.yaml"]):
                subprocess.run(argv, cwd=root, check=True, capture_output=True)
            self.assertEqual(gate_coverage.workflow_files(root), ["ci.yml", "other.yaml"])
        self.assertEqual(gate_coverage.workflow_files(), ["ci.yml", "dissent-gate.yml"],
                         "the real tree: ci.yml, and the process gate's workflow (exempted by name)")

    # ── the CI side, partitioned (mutant E, split into its two stimuli) ───────────────────────
    _LINT_ANCHOR = "      - run: ruff check .\n"

    def _ci(self) -> str:
        return _CI.read_text(encoding="utf-8")

    def test_an_UNCLASSIFIED_ci_command_reds(self):
        """E1 — `pytest -W error tests` in a job that also runs ruff. Before P10a: dropped silently."""
        ci = self._ci().replace(self._LINT_ANCHOR, self._LINT_ANCHOR + "      - run: pytest -W error tests\n", 1)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ci.yml"
            p.write_text(ci, encoding="utf-8")
            self.assertIn(("run", "pytest -W error tests"), gate_coverage._ci_jobs(p)["lint"],
                          "stimulus control: the step must be parsed into the lint job")
        self._assert_reds(self._errs(ci=ci), "classify it")

    def test_a_BLOCK_in_an_UNEXEMPTED_job_reds(self):
        """E2 — a block scalar added to a job that has no side=ci exemption."""
        ci = self._ci().replace(self._LINT_ANCHOR,
                                self._LINT_ANCHOR + "      - run: |\n          bash scripts/unlisted.sh\n", 1)
        self.assertIn("unlisted.sh", ci, "stimulus control")
        self._assert_reds(self._errs(ci=ci), "block-scalar step")

    def test_a_block_BODY_is_consumed_not_scanned(self):
        """A line inside a `run: |` body that begins `run:` is shell text, not a step. The reader
        before P10a matched every line and would have taken it for a command."""
        ci = self._ci().replace("          set -uo pipefail\n          missing=\"\"\n",
                                "          set -uo pipefail\n          run: pytest -W error tests\n"
                                "          missing=\"\"\n", 1)
        self.assertIn("          run: pytest -W error tests\n", ci, "stimulus control")
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ci.yml"
            p.write_text(ci, encoding="utf-8")
            hygiene = gate_coverage._ci_jobs(p)["hygiene"]
        self.assertEqual([k for k, _ in hygiene], ["uses", "block", "block"],
                         f"the body line was read as a step: {hygiene}")

    def test_a_COMPOUND_install_is_NOT_setup(self):
        """Mutant (v) — the consult's P1. `contains pip install` would have classified this as setup."""
        self.assertEqual(gate_coverage.classify_ci_command('pip install "ruff==0.15.15"'), "setup")
        self.assertEqual(gate_coverage.classify_ci_command("python -m pip install x"), "setup")
        for cmd in ("pip install x && pytest -W error tests", "pip install x; pytest",
                    "pip install $(cat reqs)", "python3 -m unittest"):
            with self.subTest(cmd=cmd):
                self.assertEqual(gate_coverage.classify_ci_command(cmd), "unclassified")
        ci = self._ci().replace(self._LINT_ANCHOR, self._LINT_ANCHOR
                                + "      - run: pip install pytest && pytest -W error tests\n", 1)
        self.assertIn("&& pytest -W error", ci, "stimulus control")
        self._assert_reds(self._errs(ci=ci), "classify it")

    def test_a_job_with_NO_run_step_reds_unless_exempted(self):
        """The zero-command direction the old function had, carried over rather than lost in the fold."""
        ci = self._ci() + "\n  empty:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v5\n"
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ci.yml"
            p.write_text(ci, encoding="utf-8")
            self.assertIn("empty", gate_coverage._ci_jobs(p), "stimulus control: the job must parse")
        self._assert_reds(self._errs(ci=ci), "no run step at all")

    def test_a_MIXED_job_has_a_SATISFYING_assignment(self):
        """Mutant (vi) — the consult's P1 against v1 of the design, where a job with a runnable command
        AND a block could never be green: the block demanded the exemption and the staleness rule
        redded it. Now the exemption covers the blocks and the command must still be claimed."""
        cmd = "python scripts/check-hygiene.py"
        ci = self._ci().replace("      - name: No generated or local-only artefact is TRACKED\n",
                                f"      - run: {cmd}\n      - name: No generated or local-only artefact is TRACKED\n", 1)
        self.assertIn(cmd, ci, "stimulus control")
        claimed = self._readme().replace("python scripts/check-voice.py\n",
                                         f"python scripts/check-voice.py\n{cmd}\n", 1)
        self.assertEqual(self._errs(readme=claimed, ci=ci), [], "mixed job, command claimed → GREEN")
        self._assert_reds(self._errs(ci=ci), "omits it")

    # ── exemptions: one table, a required side, mechanical staleness ──────────────────────────
    def test_exemption_staleness_is_MECHANICAL_per_side(self):
        """Every case is a COMPOSITION mutant: the two directions disagree about one item."""
        entry = {"reason": "r", "remove_when": "w"}
        cases = {
            "readme exemption for a command CI runs":
                (lambda d: d["ci_claim_exemptions"].update({"ruff check .": {**entry, "side": "readme"}}),
                 "CI now runs it"),
            "readme exemption for a claim not in the region":
                (lambda d: d["ci_claim_exemptions"].update({"python gone.py": {**entry, "side": "readme"}}),
                 "no longer in the README region"),
            "ci exemption on a job with nothing to exempt":
                (lambda d: d["ci_claim_exemptions"].update({"lint": {**entry, "side": "ci"}}),
                 "nothing left for it to exempt"),
            "ci exemption naming no job":
                (lambda d: d["ci_claim_exemptions"].update({"ghost": {**entry, "side": "ci"}}),
                 "does not exist in ci.yml"),
            "no side": (lambda d: d["ci_claim_exemptions"]["hygiene"].pop("side"), "has no `side`"),
            "unknown side": (lambda d: d["ci_claim_exemptions"]["hygiene"].update({"side": "both"}),
                             "only 'ci' and 'readme'"),
            "hygiene exemption removed": (lambda d: d["ci_claim_exemptions"].pop("hygiene"),
                                          "block-scalar step"),
        }
        for label, (mutate, fragment) in cases.items():
            with self.subTest(case=label), _Roster(mutate):
                self._assert_reds(gate_coverage.readme_ci_claim_errors(), fragment)

    def test_a_LEGITIMATE_readme_exemption_stays_green(self):
        """The correlated positive for side=readme — otherwise the side could only ever red."""
        text = self._readme().replace("python scripts/check-voice.py\n",
                                      "python scripts/check-voice.py\npython scripts/local-only.py\n", 1)
        exempt = {"python scripts/local-only.py": {"side": "readme", "reason": "r", "remove_when": "w"}}
        self._assert_reds(self._errs(text), "CI never runs it")
        with _Roster(lambda d: d["ci_claim_exemptions"].update(exempt)):
            self.assertEqual(gate_coverage.readme_ci_claim_errors(readme_text=text), [])

    def test_the_hygiene_exemption_is_RECORDED_with_its_side_and_expiry(self):
        ex = gate_coverage.load()["ci_claim_exemptions"]["hygiene"]
        self.assertEqual(ex["side"], "ci")
        self.assertTrue(ex["reason"].strip() and ex["remove_when"].strip())

    # ── display-only flags ────────────────────────────────────────────────────────────────────
    def test_a_display_only_flag_on_NEITHER_side_is_stale(self):
        with _Roster(lambda d: d["display_only_flags"].update({"-q": {"reason": "r", "remove_when": "w"}})):
            self._assert_reds(gate_coverage.readme_ci_claim_errors(), "'-q' is STALE")

    def test_the_display_only_TRUST_BOUNDARY_is_real_and_stated(self):
        """⚠ A PINNED RESIDUAL, NOT A PASSING SAFEGUARD. Listing a BEHAVIOURAL flag as display-only
        hides it on both sides: `-f` (failfast) on the README side alone goes green once `-f` is in the
        table. This test asserts the hole EXISTS, so closing it later reds here and forces the note in
        gate_coverage.json to be updated rather than silently falsified."""
        text = self._readme().replace("python -m unittest discover -s tests\n",
                                      "python -m unittest discover -s tests -f\n", 1)
        self._assert_reds(self._errs(text), "CI never runs it")
        with _Roster(lambda d: d["display_only_flags"].update({"-f": {"reason": "r", "remove_when": "w"}})):
            self.assertEqual(gate_coverage.readme_ci_claim_errors(readme_text=text), [],
                             "if this now reds, the trust boundary was closed — update _display_only_note")
        self.assertIn("TRUST BOUNDARY", " ".join(gate_coverage.load()["_display_only_note"]))

    # ── mechanism pins ────────────────────────────────────────────────────────────────────────
    def test_ONE_parse_of_the_jobs_block(self):
        """Mutant (vii): a second reader of ci.yml's jobs block reintroduced. The literal that opens
        the jobs block appears once in the module, the accessors call the one reader, and this file
        no longer parses `run:` lines itself."""
        # ⚠ MOVED IN P10d PR-1, AND IT PINS ALL THREE FILES. The parse now lives in workflow_steps.py; retargeting the pin
        # there alone would leave gate_coverage.py unpinned at zero, free to regrow a second parse with the pin green.
        counts = {f: (_ROOT / "scripts" / f).read_text(encoding="utf-8").count('re.match(r"^jobs:')
                  for f in ("judge/workflow_steps.py", "gate_coverage.py", "judge/dissent_gate.py")}
        self.assertEqual(counts, {"judge/workflow_steps.py": 1, "gate_coverage.py": 0, "judge/dissent_gate.py": 0},
                         f"the jobs-block parse must exist exactly once, in workflow_steps.py: {counts}")
        src = (_ROOT / "scripts" / "gate_coverage.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        calls = {fn.name: {n.func.id for n in ast.walk(fn)
                           if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
                 for fn in tree.body if isinstance(fn, ast.FunctionDef)}
        for name in ("ci_job_names", "ci_jobs_with_commands", "readme_ci_claim_errors"):
            self.assertIn("_ci_jobs", calls[name], f"{name} must read through _ci_jobs")
        # ⚠ BY AST, NOT BY SUBSTRING: the first version searched this file's text for the old helper
        # names and found them — in its own assertion. A pin that reds on the line documenting it is
        # the #49 comment-line trap again.
        own = ast.parse(Path(__file__).read_text(encoding="utf-8"))
        defined = {n.name for n in ast.walk(own) if isinstance(n, ast.FunctionDef)}
        self.assertFalse(defined & {"_ci_commands", "_readme_commands"},
                         "this file parses ci.yml or the README itself again")

    def test_the_python_floor_matches_the_matrix(self):
        """A between-case the drafted boundary missed: mechanical floor, unbounded 'or later'.

        ⚠ RESIDUAL, STATED: this is a whole-README substring pin, the shape P10a removed from the
        commands axis — a contradictory floor stated elsewhere in the README reds nothing. And it is
        a second read of ci.yml (the matrix, not the jobs block). Named, not widened into P10a."""
        matrix = re.findall(r'"(3\.\d+)"', _CI.read_text(encoding="utf-8"))
        self.assertTrue(matrix)
        floor = min(matrix, key=lambda v: [int(x) for x in v.split(".")])
        self.assertIn(f"Python {floor} or later", _README.read_text(encoding="utf-8"))


class ExemptionTablesAreDerivedAndPartitioned(unittest.TestCase):
    """Every top-level roster key is an exemption table or declared not to be — and both directions red."""

    def test_the_real_roster_is_clean_and_finds_ALL_SIX_tables(self):
        tables, errs = gate_coverage.exemption_tables()
        self.assertEqual(errs, [])
        self.assertEqual(set(tables), {"packages_excluded", "layout_excluded",
                                       "ci_claim_exemptions", "display_only_flags",
                                       "workflows_excluded", "overclaim_suppressions"},
                         "control: the derivation must find every table, or its checks are vacuous")

    def test_a_MALFORMED_table_is_RED_not_excluded(self):
        """⚠ THE BOARD'S FINDING: deriving by 'entries carry reason' dropped the malformed table it
        exists to validate. A table whose entry lacks `reason` must still be a table, and red."""
        with _Roster(lambda d: d["display_only_flags"]["-v"].pop("reason")):
            tables, errs = gate_coverage.exemption_tables()
        self.assertIn("display_only_flags", tables)
        self.assertTrue(any("display_only_flags.-v has no reason" in e for e in errs), errs)

    def test_an_UNDECLARED_non_table_key_reds(self):
        with _Roster(lambda d: d.update({"stray": ["a", "b"]})):
            _, errs = gate_coverage.exemption_tables()
        self.assertTrue(any("'stray'" in e for e in errs), errs)

    def test_a_DECLARED_key_that_no_longer_exists_reds(self):
        # (P10c: the stimulus was `gates`, which P10c deleted — a test coupled to a key's existence is a carrier.)
        with _Roster(lambda d: d.pop("_workflows_note")):
            _, errs = gate_coverage.exemption_tables()
        self.assertTrue(any("lists '_workflows_note'" in e for e in errs), errs)


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
