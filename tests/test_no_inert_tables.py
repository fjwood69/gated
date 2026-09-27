#!/usr/bin/env python3
"""P10c (#52): NO INERT TABLES — a table that exists, looks like a control, and is not one.

Four were named by the P10 census (C packages_excluded, D the markdown roster, B the gates table, S the overclaim
suppressions); the P10c census and its consult found more of the same class (V voice suppressions, V1 the voice
gate's _ALLOW, T sterility's ALLOW, X5/X9 files reported as scanned that were not, X10 a declaration that
unvalidates a table), and the board added the rest (guard-list entries that can never match, a table with no
consumer). Every mutant below is PROVEN ARMED before its red is counted.

⚠ STALENESS IS CONSULTATION, NOT OCCURRENCE. The two composition tests that pin it — a phrase only in a ``.py``
COMMENT, a pronoun only on a BLOCKQUOTED line — assert that such a suppression reds as stale. That red is correct:
the entry suppresses nothing. Do not "fix" it by making the scans read comments or blockquotes.
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "scripts"))

import gate_coverage as GC  # noqa: E402


def _linter(name: str):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), _ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)          # type: ignore[union-attr]
    return mod


OVERCLAIM = _linter("check-overclaim")
VOICE = _linter("check-voice")
STERILITY = _linter("check-sterility")


class _Roster:
    """Patch the roster for one test, restoring it however the test exits."""

    def __init__(self, mutate):
        self.mutate = mutate

    def __enter__(self):
        self.orig = GC.load
        data = json.loads(json.dumps(self.orig()))
        self.mutate(data)
        GC.load = lambda: data                                   # type: ignore[assignment]
        return data

    def __exit__(self, *exc):
        GC.load = self.orig                                      # type: ignore[assignment]
        return False


def _reds(test: unittest.TestCase, errs: list, fragment: str) -> None:
    test.assertTrue(any(fragment in str(e) for e in errs), f"expected a red containing {fragment!r}; got {errs}")


ENTRY = {"reason": "r", "remove_when": "w"}


class TheRealTreeIsClean(unittest.TestCase):
    """The correlated positives: without them, a check that rejected everything would pass every red below."""

    def test_every_gate_and_every_table_check_is_green_on_the_real_tree(self):
        self.assertEqual(GC.partition_errors(), [])
        self.assertEqual(GC.markdown_errors(), [])
        tables, errs = GC.exemption_tables()
        self.assertEqual(errs, [])
        self.assertIn("overclaim_suppressions", tables)
        for t in (GC.OVERCLAIM_SUPPRESSIONS, GC.VOICE_SUPPRESSIONS):
            self.assertEqual(GC.suppression_key_errors(t), [], t.name)
        for script in ("check-overclaim.py", "check-voice.py", "check-sterility.py"):
            with self.subTest(script=script):
                p = subprocess.run([sys.executable, "-B", f"scripts/{script}"], cwd=_ROOT, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_the_two_live_overclaim_suppressions_are_CONSULTED(self):
        """Measured before the migration: both phrases still occur in their scanned text. If either stops, the
        entry reds as stale — this test pins that it is consulted TODAY, so a later red is a real change."""
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            rc = OVERCLAIM.main()
        self.assertEqual(rc, 0, stdout.getvalue())
        self.assertEqual(len(GC.suppression_pairs(GC.OVERCLAIM_SUPPRESSIONS)), 2)


class C_PackagesExcluded(unittest.TestCase):
    def test_an_exclusion_for_a_directory_that_is_not_there_is_STALE(self):
        with _Roster(lambda d: d["packages_excluded"].update({"ghost": ENTRY})):
            self.assertFalse((_ROOT / "ghost").exists(), "stimulus control")
            _reds(self, GC.partition_errors(), "'ghost' is STALE")


class D_MarkdownRoster(unittest.TestCase):
    def test_a_listed_file_that_is_missing_is_NOT_SCANNED_and_the_gate_exits_nonzero(self):
        with _Roster(lambda d: d["markdown"].append("GHOST.md")):
            self.assertFalse((_ROOT / "GHOST.md").exists(), "stimulus control")
            _reds(self, GC.markdown_errors(), "NOT SCANNED")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = OVERCLAIM.main()
        self.assertEqual(rc, 1)
        self.assertIn("GHOST.md: listed in the markdown roster but could not be read or decoded — NOT SCANNED", stdout.getvalue())
        self.assertNotIn("Overclaim lint OK", stdout.getvalue())

    def test_the_roster_is_a_POSITIVE_list_not_an_exemption(self):
        self.assertIn("markdown", GC.load()["_non_exemption_keys"])
        self.assertNotIn("markdown", GC.exemption_tables()[0])


class B_GatesTableIsGone(unittest.TestCase):
    def test_no_gates_table_and_no_reference_to_its_fields_anywhere_tracked(self):
        self.assertNotIn("gates", GC.load())
        self.assertNotIn("gates", GC.load()["_non_exemption_keys"])
        field = "invoked" + "_as"          # built, so this file does not match its own search
        hits = subprocess.run(["git", "grep", "-l", field], cwd=_ROOT, capture_output=True, text=True).stdout.split()
        self.assertEqual(hits, [], f"{field} is still cited in {hits}")


class SuppressionKeys(unittest.TestCase):
    """S1 / V2 / V4: malformed is RED, never printed and skipped — through three named shared checks."""

    TRACKED = {"gate/acceptance.py", "ARCHITECTURE.md", "README.md"}

    def _key_errs(self, key: str) -> list[str]:
        with _Roster(lambda d: d.update({"voice_suppressions": {key: ENTRY}})):
            return GC.suppression_key_errors(GC.VOICE_SUPPRESSIONS, tracked=self.TRACKED)

    def test_each_malformation_reds_with_its_own_message(self):
        cases = {
            "no separator": ("README.md we", "exactly one separator"),
            "two separators": ("README.md :: we :: us", "exactly one separator"),
            "capital": ("README.md :: We", "not in normal form"),
            "curly apostrophe": ("README.md :: we’re", "not in normal form"),
            "untracked file": ("GHOST.md :: we", "not a tracked file"),
            "backslash path": ("docs\\README.md :: we", "not a clean posix path"),
        }
        for label, (key, fragment) in cases.items():
            with self.subTest(case=label):
                _reds(self, self._key_errs(key), fragment)

    def test_a_well_formed_key_is_clean(self):
        self.assertEqual(self._key_errs("README.md :: we're"), [])

    def test_missing_reason_or_remove_when_is_RED_through_exemption_tables(self):
        for field in ("reason", "remove_when"):
            with self.subTest(field=field), _Roster(
                    lambda d: d["overclaim_suppressions"]["gate/acceptance.py :: proven safe"].pop(field)):
                _reds(self, GC.exemption_tables()[1], f"has no {field}")

    def test_a_malformed_key_is_ALSO_never_consumed(self):
        """Defence in depth: unconsumed() iterates RAW keys, so a key the grammar check would miss still reds."""
        with _Roster(lambda d: d.update({"voice_suppressions": {"README.md we": ENTRY}})):
            self.assertEqual(GC.suppression_pairs(GC.VOICE_SUPPRESSIONS), {})
            _reds(self, GC.unconsumed(GC.VOICE_SUPPRESSIONS, set(), set()), "STALE")


class S_OverclaimStaleness(unittest.TestCase):
    PAIRS = {("pkg/a.py", "proven safe"): "pkg/a.py :: proven safe"}

    def test_a_consulted_suppression_is_consumed_and_the_hit_is_suppressed(self):
        v, consumed, ns = OVERCLAIM.scan_overclaim({"pkg/a.py": '"""never proven safe."""'}, {}, ["proven safe"], self.PAIRS)
        self.assertEqual((v, consumed, ns), ([], {"pkg/a.py :: proven safe"}, set()))

    def test_a_phrase_gone_from_its_file_leaves_the_suppression_unconsumed(self):
        v, consumed, ns = OVERCLAIM.scan_overclaim({"pkg/a.py": '"""rephrased."""'}, {}, ["proven safe"], self.PAIRS)
        self.assertEqual(consumed, set())

    def test_a_phrase_ONLY_IN_A_COMMENT_is_never_consulted_so_its_suppression_is_STALE(self):
        """COMPOSITION (board amendment 1): the phrase is IN the file and never scanned. The red is correct."""
        src = '# this is proven safe, says a comment\nX = 1\n'
        self.assertIn("proven safe", src, "stimulus control: the phrase is in the file")
        v, consumed, ns = OVERCLAIM.scan_overclaim({"pkg/a.py": src}, {}, ["proven safe"], self.PAIRS)
        self.assertEqual((v, consumed), ([], set()))
        with _Roster(lambda d: d.update({"overclaim_suppressions": {"pkg/a.py :: proven safe": ENTRY}})):
            _reds(self, GC.unconsumed(GC.OVERCLAIM_SUPPRESSIONS, consumed, ns), "STALE: never consulted")

    def test_an_unparseable_py_is_NOT_SCANNED_and_its_suppression_says_so(self):
        """X9 + amendment 2: a file that was not scanned does not make its suppressions stale."""
        v, consumed, ns = OVERCLAIM.scan_overclaim({"pkg/a.py": "def broken(:\n"}, {}, ["proven safe"], self.PAIRS)
        _reds(self, v, "does not parse — NOT SCANNED")
        self.assertEqual(ns, {"pkg/a.py"})
        with _Roster(lambda d: d.update({"overclaim_suppressions": {"pkg/a.py :: proven safe": ENTRY}})):
            errs = GC.unconsumed(GC.OVERCLAIM_SUPPRESSIONS, consumed, ns)
        _reds(self, errs, "its file was NOT SCANNED — restore the file")
        self.assertFalse(any("STALE" in e for e in errs), "a NOT SCANNED file must not read as stale")

    def test_an_UNDECODABLE_or_missing_file_reads_as_None_never_a_traceback(self):
        """Board item 2: strict UTF-8 raised UnicodeDecodeError outside the taxonomy the docstring promises."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.md"
            bad.write_bytes(b"proven \xff\xfe safe")
            good = Path(d) / "good.md"
            good.write_text("fine", encoding="utf-8")
            self.assertIsNone(OVERCLAIM._read(bad))
            self.assertIsNone(OVERCLAIM._read(Path(d) / "absent.md"))
            self.assertEqual(OVERCLAIM._read(good), "fine")
        v, _, ns = OVERCLAIM.scan_overclaim({"pkg/a.py": None}, {}, ["proven safe"], {})
        _reds(self, v, "could not be read or decoded — NOT SCANNED")
        self.assertEqual(ns, {"pkg/a.py"})

    def test_roster_py_files_are_the_TRACKED_ones_in_both_directions(self):
        """Board item 2: a filesystem walk scanned untracked files and silently missed a tracked file deleted from the
        worktree. Both directions, through main()."""
        probe = _ROOT / "core" / "_p10c_untracked_probe.py"
        orig = OVERCLAIM.tracked_files
        try:
            probe.write_text('X = "this is proven safe"\n', encoding="utf-8")        # untracked, banned phrase
            OVERCLAIM.tracked_files = lambda: orig() | {"core/_p10c_deleted_probe.py"}   # tracked, absent
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = OVERCLAIM.main()
        finally:
            OVERCLAIM.tracked_files = orig
            probe.unlink(missing_ok=True)
        out = stdout.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("core/_p10c_deleted_probe.py: tracked but could not be read or decoded — NOT SCANNED", out)
        self.assertNotIn("_p10c_untracked_probe", out, "an untracked file must not be scanned")

    def test_a_suppression_for_a_file_OUTSIDE_the_scan_set_says_so(self):
        """Board item 3: the third cause. The first two messages would send the reader to the wrong fix."""
        with _Roster(lambda d: d.update({"overclaim_suppressions": {"scripts/sweep.py :: proven safe": ENTRY}})):
            errs = GC.unconsumed(GC.OVERCLAIM_SUPPRESSIONS, set(), set(), scanned={"gate/acceptance.py"})
        _reds(self, errs, "OUTSIDE this gate's scan set")
        self.assertFalse(any("STALE" in e for e in errs))

    def test_NESTED_vocabulary_entries_are_refused(self):
        """Board item 5: with nesting, a suppression for the longer phrase cannot silence the shorter hit. The real
        vocabulary has none; the check keeps it so."""
        _reds(self, GC.nested_entry_errors("v", ["proven", "proven safe"]), "'proven' is contained in 'proven safe'")
        vocab = [ln.strip() for ln in (_ROOT / "scripts" / "claims_vocabulary.txt").read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(GC.nested_entry_errors("claims_vocabulary.txt", vocab), [])

    def test_the_overclaim_gate_REFUSES_a_nested_vocabulary(self):
        orig = OVERCLAIM._load_lines
        try:
            OVERCLAIM._load_lines = lambda path: ["proven", "proven safe"]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = OVERCLAIM.main()
        finally:
            OVERCLAIM._load_lines = orig
        self.assertEqual(rc, 1)
        self.assertIn("contained in", stdout.getvalue())

    def test_key_matching_is_EQUALITY_with_near_misses_at_both_ends(self):
        """ways-of-working §5.5: one near miss in the last character, one in the first — phrase and path."""
        for rel, phrase in (("pkg/a.py", "proven safd"), ("pkg/a.py", "sroven safe"),
                            ("pkg/a.pz", "proven safe"), ("qkg/a.py", "proven safe")):
            with self.subTest(key=f"{rel} :: {phrase}"):
                pairs = {(rel, phrase): f"{rel} :: {phrase}"}
                v, consumed, _ = OVERCLAIM.scan_overclaim({"pkg/a.py": '"x proven safe"'}, {}, ["proven safe"], pairs)
                self.assertEqual(consumed, set())
                self.assertEqual(len(v), 1, "the near-miss key must not suppress the real hit")


class V_Voice(unittest.TestCase):
    PAIRS = {("doc.md", "we"): "doc.md :: we"}

    def test_a_consulted_pronoun_is_consumed(self):
        v, consumed, ns = VOICE.scan_voice({"doc.md": "Here we stand."}, self.PAIRS)
        self.assertEqual((v, consumed), ([], {"doc.md :: we"}))

    def test_a_pronoun_ONLY_ON_A_BLOCKQUOTE_is_never_consulted_so_its_suppression_is_STALE(self):
        """COMPOSITION (board amendment 1): in the file, never consulted — the red is correct."""
        text = "> we said this, quoted\n\nplain prose\n"
        self.assertIn("we", text, "stimulus control")
        v, consumed, ns = VOICE.scan_voice({"doc.md": text}, self.PAIRS)
        self.assertEqual((v, consumed), ([], set()))
        with _Roster(lambda d: d.update({"voice_suppressions": {"doc.md :: we": ENTRY}})):
            _reds(self, GC.unconsumed(GC.VOICE_SUPPRESSIONS, consumed, ns), "STALE: never consulted")

    def test_an_unreadable_tracked_markdown_is_NOT_SCANNED(self):
        """X5: it used to be skipped with `continue`, and the gate said OK."""
        v, consumed, ns = VOICE.scan_voice({"doc.md": None}, {})
        _reds(self, v, "NOT SCANNED")
        self.assertEqual(ns, {"doc.md"})

    def test_the_voice_MAIN_turns_an_unreadable_file_into_NOT_SCANNED(self):
        """Red-proof survivor R10: the pure scan was tested with None, but main() — the only place a read failure
        BECOMES None — was not; restoring the old `continue` there went unseen."""
        orig = VOICE._tracked_markdown
        try:
            VOICE._tracked_markdown = lambda: ["GHOST-unreadable.md"]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = VOICE.main()
        finally:
            VOICE._tracked_markdown = orig
        self.assertFalse((_ROOT / "GHOST-unreadable.md").exists(), "stimulus control")
        self.assertEqual(rc, 1)
        self.assertIn("NOT SCANNED", stdout.getvalue())

    def test_voice_consults_in_NORMAL_FORM(self):
        """Red-proof survivor R22: a capitalised or curly-apostrophe pronoun in the TEXT must still consult the
        normal-form key — otherwise a legal key never matches (board amendment 4, at the consult site)."""
        for text in ("We stand here.", "We’re here."):
            with self.subTest(text=text):
                key = "doc.md :: " + ("we" if "’" not in text else "we're")
                pair = {tuple(key.split(" :: ")): key}
                v, consumed, _ = VOICE.scan_voice({"doc.md": text}, pair)
                self.assertEqual((v, consumed), ([], {key}))

    def test_the_inert_ALLOW_is_gone(self):
        """V1: it filtered `*.md` output by a .py and a .txt name — neither could ever match."""
        tree = ast.parse((_ROOT / "scripts" / "check-voice.py").read_text(encoding="utf-8"))
        names = {t.id for n in ast.walk(tree) if isinstance(n, ast.Assign) for t in n.targets if isinstance(t, ast.Name)}
        self.assertNotIn("_ALLOW", names)

    def test_the_voice_table_is_ABSENT_and_absence_is_DECLARED_to_mean_none(self):
        self.assertNotIn("voice_suppressions", GC.load())
        self.assertTrue(GC.VOICE_SUPPRESSIONS.absent_means_none)


class GuardLists(unittest.TestCase):
    """Board amendment 4 + 5: an entry the matcher can never match is inert in a live list; an empty list passes
    vacuously."""

    def test_empty_guard_lists_are_RED(self):
        _reds(self, GC.guard_list_errors("_PRONOUNS", ()), "EMPTY")
        _reds(self, GC.guard_list_errors("claims_vocabulary.txt", []), "EMPTY")

    def test_a_non_normal_entry_is_RED_as_inert(self):
        for entry in ("Proven safe", "we’re", " padded "):
            with self.subTest(entry=entry):
                _reds(self, GC.guard_list_errors("x", ["ok", entry]), "can never match")

    def test_the_REAL_guard_lists_are_clean(self):
        vocab = [ln.strip() for ln in (_ROOT / "scripts" / "claims_vocabulary.txt").read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.lstrip().startswith("#")]
        self.assertEqual(GC.guard_list_errors("claims_vocabulary.txt", vocab), [])
        self.assertEqual(GC.guard_list_errors("_PRONOUNS", VOICE._PRONOUNS), [])

    def test_every_pronoun_matches_AS_ITSELF(self):
        """FOUND BY THIS INCREMENT'S OWN TEST: with `we` tried before `we're`, the four contractions could never
        match as themselves — inert entries in a live list that the normal-form check cannot see. The control
        rebuilds the OLD alternation order and proves the check sees exactly those four."""
        self.assertEqual(VOICE.shadowed_pronouns(), [])
        old = re.compile(r"\b(" + "|".join(p.replace("'", "['’]") for p in VOICE._PRONOUNS) + r")\b", re.IGNORECASE)
        orig = VOICE._PATTERN
        try:
            VOICE._PATTERN = old
            shadowed = VOICE.shadowed_pronouns()
        finally:
            VOICE._PATTERN = orig
        names = {ast.literal_eval(re.search(r"entry (\".*?\"|'.*?') is SHADOWED", e).group(1)) for e in shadowed}
        self.assertEqual(names, {"we're", "we've", "we'll", "we'd"}, shadowed)

    def test_a_SHADOWING_pattern_makes_the_voice_gate_REFUSE(self):
        """Red-proof survivor R24: shadowed_pronouns() was tested, the gate's USE of it was not."""
        old = re.compile(r"\b(" + "|".join(p.replace("'", "['’]") for p in VOICE._PRONOUNS) + r")\b", re.IGNORECASE)
        orig = VOICE._PATTERN
        try:
            VOICE._PATTERN = old
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = VOICE.main()
        finally:
            VOICE._PATTERN = orig
        self.assertEqual(rc, 1)
        self.assertIn("SHADOWED", stdout.getvalue())

    def test_an_empty_pronoun_list_makes_the_voice_gate_REFUSE(self):
        orig = VOICE._PRONOUNS
        try:
            VOICE._PRONOUNS = ()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = VOICE.main()
        finally:
            VOICE._PRONOUNS = orig
        self.assertEqual(rc, 1)
        self.assertIn("refusing to pass", stdout.getvalue())


class T_Sterility(unittest.TestCase):
    def test_the_real_ALLOW_entry_HITS_today(self):
        """Correlated positive (board amendment 8): if marker matching changes, this fails — rather than the entry
        turning up as an unexplained stale."""
        text = (_ROOT / "scripts" / "check-sterility.py").read_text(encoding="utf-8")
        v, errs = STERILITY.scan_sterility({"scripts/check-sterility.py": text}, STERILITY.MARKERS, STERILITY.ALLOW)
        self.assertEqual((v, errs), ([], []))

    def test_a_ghost_ALLOW_entry_is_STALE(self):
        v, errs = STERILITY.scan_sterility({"a.txt": "clean"}, STERILITY.MARKERS, {"ghost/none.py"})
        _reds(self, errs, "not a tracked file — STALE")

    def test_an_ALLOW_entry_with_no_marker_is_STALE(self):
        v, errs = STERILITY.scan_sterility({"a.txt": "clean text"}, STERILITY.MARKERS, {"a.txt"})
        _reds(self, errs, "contains no marker — STALE")

    def test_an_unreadable_tracked_path_is_NOT_SCANNED(self):
        v, errs = STERILITY.scan_sterility({"a.txt": None}, STERILITY.MARKERS, set())
        _reds(self, v, "NOT SCANNED")

    def test_the_sterility_MAIN_turns_an_unreadable_path_into_NOT_SCANNED(self):
        """Red-proof survivor R11: as for voice — main() is where a read failure becomes None."""
        orig = STERILITY._tracked_files
        try:
            STERILITY._tracked_files = lambda: ["GHOST-unreadable.txt", "scripts/check-sterility.py"]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = STERILITY.main()
        finally:
            STERILITY._tracked_files = orig
        self.assertEqual(rc, 1)
        self.assertIn("NOT SCANNED", stdout.getvalue())

    def test_empty_or_broken_MARKERS_are_RED(self):
        _reds(self, STERILITY.scan_sterility({}, [], set())[1], "EMPTY")
        _reds(self, STERILITY.scan_sterility({}, [("(unclosed", "x")], set())[1], "does not compile")


class TablesHaveConsumers(unittest.TestCase):
    """Board amendments 6 + 7."""

    def test_a_MISSPELT_table_has_no_consumer_and_reds(self):
        with _Roster(lambda d: d.update({"voice_suppression": {"README.md :: we": ENTRY}})):
            _reds(self, GC.exemption_tables()[1], "'voice_suppression' has NO CONSUMER")

    def test_a_constant_whose_table_is_ABSENT_reds_unless_declared_none(self):
        with _Roster(lambda d: d.pop("overclaim_suppressions")):
            _reds(self, GC.exemption_tables()[1], "'overclaim_suppressions' has no table")
        self.assertFalse(any("voice_suppressions" in e for e in GC.exemption_tables()[1]))

    def test_a_TABLE_SHAPED_key_declared_out_of_the_validator_reds_even_without_reason(self):
        def mutate(d):
            d["packages_excluded"]["scripts"].pop("reason")
            d["_non_exemption_keys"].append("packages_excluded")
        with _Roster(mutate):
            _reds(self, GC.exemption_tables()[1], "'packages_excluded' is declared a non-exemption key but is TABLE-SHAPED")

    def test_the_constants_are_DERIVED_not_listed(self):
        self.assertEqual(set(GC.table_constants()),
                         {v.name for v in vars(GC).values() if isinstance(v, GC.Table)})

    def test_no_production_script_names_an_exemption_table_by_string_literal(self):
        """MECHANISM: every consumer goes through a Table constant. A literal lookup would be a second site."""
        names = set(GC.table_constants())
        for script in ("gate_coverage.py", "check-overclaim.py", "check-voice.py", "check-sterility.py", "print_gate_argv.py"):
            tree = ast.parse((_ROOT / "scripts" / script).read_text(encoding="utf-8"))
            in_table_call = {id(a) for n in ast.walk(tree) if isinstance(n, ast.Call)
                             and isinstance(n.func, ast.Name) and n.func.id == "Table" for a in n.args}
            stray = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and n.value in names
                     and id(n) not in in_table_call]
            with self.subTest(script=script):
                self.assertEqual(stray, [], f"{script} names a table by literal: {stray}")


    def test_every_Table_constant_is_READ_by_a_consumer(self):
        """Board item 1: a named constant is not a consumer. A table + a matching constant with no consumer would pass
        every check above — an inert table with a name. Every constant must be READ (an ast.Name load) somewhere other
        than its own definition; an import alone does not count."""
        loads: dict[str, int] = {n: 0 for n in (c for c in vars(GC) if isinstance(getattr(GC, c), GC.Table))}
        for script in ("gate_coverage.py", "check-overclaim.py", "check-voice.py", "check-sterility.py", "print_gate_argv.py"):
            tree = ast.parse((_ROOT / "scripts" / script).read_text(encoding="utf-8"))
            for n in ast.walk(tree):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id in loads:
                    loads[n.id] += 1
        self.assertTrue(loads, "control: the constants must be found")
        self.assertEqual([c for c, k in loads.items() if k == 0], [], f"constants nothing reads: {loads}")


class FullScansOnly(unittest.TestCase):
    def test_no_linter_reads_argv(self):
        """Board amendment 3: "never consulted" means stale only on a full scan. No linter takes arguments; a
        future subset option must refuse staleness on partial runs, and this test is where it meets that."""
        for script in ("check-overclaim.py", "check-voice.py", "check-sterility.py"):
            src = (_ROOT / "scripts" / script).read_text(encoding="utf-8")
            with self.subTest(script=script):
                self.assertIsNone(re.search(r"sys\.argv|argparse", src))


if __name__ == "__main__":
    unittest.main(verbosity=2)
