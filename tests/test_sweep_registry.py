#!/usr/bin/env python3
"""The registry as state — closure, the tool-owned namespace, quote blocks, overwrite refusal, R-A integrity, and the parent edge.

⚠ SPLIT FROM test_sweep.py 2026-08-07 at 122,382 bytes — 95.6%% of the 125KB per-file attachment
cap. The payload rule is whole-or-nothing, so crossing it would have ENDED consults on this file
rather than degrading them. Split BY CONCERN: an arbitrary cut leaves a reviewer with half a suite
and no way to know what is absent, which is worse than the ceiling.

Every test here is written to FAIL IF ITS RULING IS REVERSED.
"""
# ⚠ PLAIN IMPORT, NOT RELATIVE. CI runs `unittest discover -s tests`, which imports these
# modules as TOP-LEVEL names and puts tests/ on sys.path — so a relative import raises
# "attempted relative import with no known parent package". MEASURED, not assumed: the
# relative form was written first and every module failed to import, which the split guard
# caught as 7 loader errors rather than as a quietly smaller run.
from _sweep_harness import S, json, unittest, Path, _SweepHarness


class AncestorClosure(unittest.TestCase):
    """R1 — the failure v2 would have shipped."""

    def _records(self):
        def mk(i, p):
            return S.Record(id=i, seed="", variants=[], anchors=[], nets_run=[],
                            tombstones=[], surfaces_at_withdrawal=[], expected_counts={},
                            parent=p, created="")
        return {"A": mk("A", None), "B": mk("B", "A"), "C": mk("C", "B")}

    def test_selecting_a_child_sweeps_its_ancestors(self):
        """Sweeping B alone would never search A's patterns, so a reassertion of A inside B's own
        correction returns exit 0, registry-backed, in the precise scenario the tool exists for."""
        self.assertEqual(set(S.ancestor_closure(["B"], self._records())), {"B", "A"})

    def test_closure_is_transitive(self):
        self.assertEqual(set(S.ancestor_closure(["C"], self._records())), {"C", "B", "A"})

    def test_closed_records_are_not_excluded_by_default(self):
        """⚠ CLOSED DOES NOT MEAN GONE. A record with tombstones is closed, but its withdrawn text is
        still live in the world — an open-records-only default would skip exactly the carrier this
        tool exists for."""
        recs = self._records()
        recs["A"].tombstones = [{"location": "x", "block_sha256": "y"}]
        self.assertFalse(recs["A"].is_open)
        self.assertIn("A", S.ancestor_closure(["B"], recs),
                      "a CLOSED ancestor must still be swept")


class Namespace(unittest.TestCase):
    """R13 — the exclusion must be incapable of hiding."""

    def test_unmanifested_file_is_detected(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ns = Path(d)
            (ns / "manifest.json").write_text(json.dumps(["known.txt"]))
            (ns / "known.txt").write_text("fine")
            (ns / "someone-dropped-a-note.md").write_text("a live carrier hiding here")
            stray = S.manifest_check(ns)
            self.assertEqual(stray, ["someone-dropped-a-note.md"],
                             "a human note in the tool-owned tree must be named, not excluded")


class QuoteBlocks(unittest.TestCase):
    """R7 — tombstone the BLOCK, never the prose."""

    def test_prose_rewrite_does_not_break_the_tombstone(self):
        v1 = ("⚠ CORRECTED. It read:\n" + S.BLOCK_OPEN + "REC-1 -->\nthe withdrawn claim\n"
              + S.BLOCK_CLOSE + "\nand the reason it was wrong.")
        v2 = ("⚠ CORRECTED, and here is a completely rewritten explanation.\n"
              + S.BLOCK_OPEN + "REC-1 -->\nthe withdrawn claim\n" + S.BLOCK_CLOSE
              + "\nwith different prose entirely.")
        self.assertEqual(S.block_sha(S.extract_blocks(v1)["REC-1"]),
                         S.block_sha(S.extract_blocks(v2)["REC-1"]),
                         "re-wording a correction must NOT break its control")

    def test_editing_the_block_is_reportable(self):
        a = S.BLOCK_OPEN + "R -->\noriginal text\n" + S.BLOCK_CLOSE
        b = S.BLOCK_OPEN + "R -->\ntampered text\n" + S.BLOCK_CLOSE
        self.assertNotEqual(S.block_sha(S.extract_blocks(a)["R"]),
                            S.block_sha(S.extract_blocks(b)["R"]))

    def test_block_survives_reflow(self):
        a = S.BLOCK_OPEN + "R -->\nsome withdrawn text here\n" + S.BLOCK_CLOSE
        b = S.BLOCK_OPEN + "R -->\nsome withdrawn\ntext here\n" + S.BLOCK_CLOSE
        self.assertNotEqual(S.block_sha(S.extract_blocks(a)["R"]),
                            S.block_sha(S.extract_blocks(b)["R"]),
                            "hashing is byte-exact; reflow inside a block IS a change and is reported")


class RecordOverwrite(unittest.TestCase):
    """⚠ `harvest` OVERWROTE AN EXISTING RECORD ID, RESETTING ITS TOMBSTONES TO [].

    The loss is INVISIBLE BY CONSTRUCTION: the tombstones that would raise `tomb_lost` on the next
    sweep are exactly what the overwrite deletes, so the following run is CLEAN and the
    formerly-excluded blocks simply return as live hits with no explanation. A live near-miss on
    2026-08-04 — an existing id was re-harvested to register an experiment's anchors; it happened to
    be OPEN, so nothing was lost. Inside the tool built to stop claims disappearing without record.
    """

    def _run(self, ns, rid):
        from types import SimpleNamespace
        from unittest import mock
        cfg = {"control_token": "ZZ-SWEEP-CONTROL-TOKEN", "surfaces": [], "expected_counts": {}}
        surf = [S.SurfaceResult("docs", "filesystem", "3 files", 3,
                                [(f"docs/f{i}.md", "a claim body ZZ-SWEEP-CONTROL-TOKEN")
                                 for i in range(3)])]
        args = SimpleNamespace(id=rid, seed="a claim", parent=None, carrier=["docs/f0.md"])
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=surf), \
             mock.patch.object(S, "NAMESPACE", ns):
            return S.harvest(args)

    def test_existing_record_is_NOT_overwritten(self):
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        closed = {"id": "R", "seed": "a claim", "variants": ["a claim"], "anchors": [],
                  "nets_run": [], "tombstones": [{"location": "docs/f0.md", "block_sha256": "abc"}],
                  "surfaces_at_withdrawal": [], "expected_counts": {}, "parent": None, "created": ""}
        (ns / "records" / "R.json").write_text(json.dumps(closed), encoding="utf-8")
        # ⚠ THE NAMESPACE MUST BE MANIFEST-CLEAN OR THIS TEST PASSES FOR THE WRONG REASON. Without a
        # manifest listing records/R.json, instrument_gate fails on an UNMANIFESTED STRAY and returns
        # EXIT_INSTRUMENT before the overwrite guard is ever reached — the assertion then holds while
        # the guard could be deleted entirely. Caught by a mutant that SURVIVED.
        (ns / "manifest.json").write_text(json.dumps(["records/R.json"]), encoding="utf-8")
        self.assertEqual(S.manifest_check(ns), [], "the gate must not short-circuit this test")
        rc = self._run(ns, "R")
        self.assertEqual(rc, S.EXIT_INSTRUMENT, "re-harvesting an existing id must REFUSE")
        after = json.loads((ns / "records" / "R.json").read_text(encoding="utf-8"))
        self.assertEqual(after["tombstones"], closed["tombstones"],
                         "⚠ THE TOMBSTONES MUST SURVIVE — they are the exclusions the record licenses")

    def test_a_fresh_id_still_writes(self):
        """Correlated positive control: prove the refusal above is the guard, not harvest broken."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        rc = self._run(ns, "FRESH")
        self.assertEqual(rc, S.EXIT_DEBT)
        self.assertTrue((ns / "records" / "FRESH.json").exists())


class RegistryIntegrity(_SweepHarness):
    """R-A — ⚠ AN EMPTY REGISTRY IS CLEAN; A **BROKEN** ONE IS NOT.

    The discriminator is EVIDENCE OF PRIOR TOOL AUTHORSHIP, not whether a directory exists. That
    distinction is the ruling: `records/` missing and `records/` empty are the same reading — "all
    registered" found none, and no named claim was falsified.
    """

    def test_a_manifest_naming_a_record_that_does_not_load_is_INSTRUMENT(self):
        """⚠ TWO TOOL-WRITTEN ARTEFACTS CONTRADICTING EACH OTHER. The manifest is the tool's own
        record of what it wrote; a record it names and cannot load is the registry disagreeing with
        itself, which is an observable about the INSTRUMENT rather than about the corpus."""
        ns = self._ns(records=[], manifest=["records/GONE.json"])
        rc, out = self._sweep(ns)
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("REGISTRY CORRUPTED", out)
        self.assertIn("GONE", out, "the ruling requires naming what is missing")

    def test_an_ABSENT_records_dir_is_CLEAN(self):
        """⚠ HARVEST IS WHAT CREATES THE DIRECTORY, so failing on bare absence would red every run
        before the first harvest — the exact case the ruling protects."""
        rc, _ = self._sweep(self._ns(make_records_dir=False))
        self.assertEqual(rc, S.EXIT_CLEAN)

    def test_an_EMPTY_records_dir_is_CLEAN(self):
        """The correlated half: present-but-empty reads identically to absent. ABSENT-vs-EMPTY was
        the wrong axis; INTACT-vs-CORRUPTED is the right one."""
        rc, _ = self._sweep(self._ns(records=[]))
        self.assertEqual(rc, S.EXIT_CLEAN)

    def test_a_VIRGIN_namespace_that_has_ONLY_EVER_BEEN_SWEPT_stays_CLEAN(self):
        """⚠ THE REGRESSION PIN FOR A CLAUSE DELIBERATELY NOT BUILT. The drafted rule also said
        "other manifested artefacts exist while records/ is gone". MEASURED by execution: a sweep on
        a virgin namespace exits CLEAN, never creates records/, and writes manifest.json holding
        reports/<stamp>.txt — precisely that state. Building the clause would have RED-FLAGGED THE
        PRE-FIRST-HARVEST CASE THE RULING EXISTS TO KEEP CLEAN. This test fails the day someone
        re-derives it from the draft."""
        ns = self._ns(make_records_dir=False)
        rc1, _ = self._sweep(ns)
        self.assertEqual(rc1, S.EXIT_CLEAN, "first sweep on a virgin namespace")
        self.assertTrue((ns / "manifest.json").exists(), "which manifests a report")
        self.assertFalse((ns / "records").exists(), "and still has no records/")
        rc2, out = self._sweep(ns)
        self.assertEqual(rc2, S.EXIT_CLEAN,
                         f"a SECOND sweep must still be clean, not corrupted: {out}")

    def test_an_UNREADABLE_manifest_is_INSTRUMENT(self):
        """The manifest is itself a tool-written artefact. Unreadable is not empty."""
        ns = self._ns(records=[])
        (ns / "manifest.json").write_text("{not json", encoding="utf-8")
        rc, out = self._sweep(ns)
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("unreadable", out)

    def test_a_manifest_naming_only_NON_record_artefacts_earns_nothing(self):
        """Correlated negative: reports and spills are not records, and their presence is not
        evidence of a missing record. Without this the corruption check could fire on any
        manifested file and the tests above would pass on a gate that rejects everything."""
        ns = self._ns(records=[], manifest=["reports/20260101T000000+0000.txt", "census/X.tsv"])
        rc, _ = self._sweep(ns)
        self.assertEqual(rc, S.EXIT_CLEAN)

    def test_a_NON_record_JSON_artefact_earns_nothing_either(self):
        """⚠ FOUND BY CONSULT 2026-08-07, AND THE CONTROL ABOVE COULD NOT SEE IT. Every artefact it
        names ends `.txt` or `.tsv`, so deleting `rel.startswith("records/")` and keeping only the
        `.json` suffix check SURVIVED THE WHOLE SUITE — no fixture had a non-record `.json`, and the
        registry writes several (`reach/`, spills). The prefix is what makes the check about RECORDS
        rather than about file extensions."""
        ns = self._ns(records=[], manifest=["reach/NEW.json", "census/X.json"])
        rc, out = self._sweep(ns)
        self.assertEqual(rc, S.EXIT_CLEAN,
                         f"a .json OUTSIDE records/ is not a record and must earn nothing: {out}")


class MalformedRegistry(_SweepHarness):
    """R19 DOORWAY 6 — ⚠ `load_records` RAN BEFORE ANY GATE AND CRASHED.

    Every command calls it before `instrument_gate`, so a malformed record produced an unstratified
    traceback where R4a requires a named code. **Skipping the bad file would be worse than
    crashing**: the selected set becomes UNKNOWABLE, not merely smaller, and every downstream count,
    pin and closure would then be computed over a population nobody can name.
    """

    def _ns_bad(self, body="{not json"):
        ns = self._ns(records=[])
        (ns / "records" / "BAD.json").write_text(body, encoding="utf-8")
        (ns / "manifest.json").write_text(json.dumps(["records/BAD.json"]), encoding="utf-8")
        return ns

    def test_a_malformed_record_raises_the_TYPED_condition(self):
        with self.assertRaises(S.RegistryUnreadable) as cm:
            S.load_records(self._ns_bad())
        self.assertIn("BAD.json", str(cm.exception), "the failing FILE must be named")
        self.assertIn("UNKNOWABLE", str(cm.exception))

    def test_a_record_that_is_not_an_object_is_also_refused(self):
        """JSON that parses but is not a record. `Record(**d)` would raise TypeError far from here."""
        with self.assertRaises(S.RegistryUnreadable):
            S.load_records(self._ns_bad('["a", "list"]'))

    def test_a_record_with_NO_id_is_refused(self):
        with self.assertRaises(S.RegistryUnreadable):
            S.load_records(self._ns_bad('{"seed": "s"}'))

    def test_main_turns_it_into_ONE_stratified_exit(self):
        """⚠ BEHAVIOUR AND WIRING ARE TWO CLAIMS. A typed exception nothing catches is a traceback
        with extra steps, and the handler lives in `main` so all three commands share it."""
        import contextlib
        import io
        from unittest import mock
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value={"control_token": self.TOKEN,
                                                               "surfaces": [],
                                                               "expected_counts": {}}), \
             mock.patch.object(S, "gather_surfaces", return_value=[]), \
             mock.patch.object(S, "NAMESPACE", self._ns_bad()), \
             contextlib.redirect_stdout(out):
            rc = S.main(["sweep"])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("INSTRUMENT FAILURE", out.getvalue())
        self.assertIn("NOT an empty registry", out.getvalue(),
                      "the message must separate UNREADABLE from EMPTY, which is clean")

    def test_a_WELL_FORMED_registry_still_loads(self):
        """Correlated positive: prove the refusals are the guard, not the loader broken."""
        ns = self._ns(records=[self._rec()], manifest=["records/R.json"])
        self.assertIn("R", S.load_records(ns))


class ManifestAddRefuses(_SweepHarness):
    """D4 — ⚠ `manifest_add` REFUSES THE WRITE; IT DOES NOT ARCHIVE-AND-CONTINUE.

    The old comment argued that recovering "would rewrite the manifest with only the new entry and
    destroy the record of everything else". **That reasoning was sound and justified a different
    behaviour than the one shipped** — it argues against silent recovery, not for a traceback.
    Archiving to `.broken` was refused too: it mutates the namespace during a command that is
    already failing.
    """

    def test_it_raises_rather_than_crashing_or_rewriting(self):
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "manifest.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(S.RegistryUnreadable):
            S.manifest_add(ns, "records/NEW.json")

    def test_the_BROKEN_MANIFEST_IS_LEFT_EXACTLY_AS_IT_WAS(self):
        """⚠ THE PROPERTY THAT MATTERS. Not the exception — that the file is untouched, and that no
        `.broken` sibling appeared. The operator's next look must be at the tree they left."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "manifest.json").write_text("{not json", encoding="utf-8")
        before = (ns / "manifest.json").read_bytes()
        with self.assertRaises(S.RegistryUnreadable):
            S.manifest_add(ns, "records/NEW.json")
        self.assertEqual((ns / "manifest.json").read_bytes(), before, "must NOT be rewritten")
        self.assertEqual(sorted(p.name for p in ns.iterdir()), ["manifest.json"],
                         "and must NOT archive to a .broken sibling mid-command")

    def test_a_READABLE_manifest_still_gains_the_entry(self):
        """Correlated positive: the refusal must be the guard, not manifest_add broken."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        S.manifest_add(ns, "records/NEW.json")
        self.assertIn("records/NEW.json",
                      json.loads((ns / "manifest.json").read_text(encoding="utf-8")))


class DanglingParent(_SweepHarness):
    """R19 DOORWAY 5 — ⚠ A PARENT REGISTERED AND THEN **DELETED**.

    MEASURED 2026-08-07 before the fix: record C whose parent B had been deleted swept **EXIT 0
    CLEAN**, said nothing, and printed the header ``swept: C + ancestors: C``. Every other doorway
    is silent; **this one prints a claim it did not honour.** `--parent` validation fires at harvest
    and cannot reach a deletion that happens afterwards.
    """

    def _ns_dangling(self, parent="B-DELETED"):
        return self._ns(records=[self._rec(id="C", parent=parent)], manifest=["records/C.json"])

    def test_the_DEFAULT_sweep_REFUSES_a_dangling_parent(self):
        """⚠ THE BUILD REQUIREMENT, NOT A PREFERENCE (D2). The check lives in `registry_integrity`
        rather than in `ancestor_closure` because **THE DEFAULT SWEEP NEVER CALLS CLOSURE** — it
        takes `list(records)`. A guard tested only through a closure-invoking path would prove
        nothing about the common case and would FAKE GREEN."""
        rc, out = self._sweep(self._ns_dangling())
        self.assertEqual(rc, S.EXIT_INSTRUMENT, out)
        self.assertIn("B-DELETED", out, "the ruling requires naming the unreachable parent")
        self.assertIn("Restore the parent record", out, "and naming the remediation")

    def test_the_default_path_DOES_NOT_INVOKE_ancestor_closure(self):
        """⚠ THE CONTROL THAT MAKES THE TEST ABOVE MEAN ANYTHING. If closure were invoked on the
        default path, the previous test would pass even with the check misplaced, and the whole
        reason for D2's placement would evaporate. This asserts the premise directly."""
        from unittest import mock
        with mock.patch.object(S, "ancestor_closure",
                               side_effect=AssertionError("closure WAS invoked")) as spy:
            rc, _ = self._sweep(self._ns_dangling())
        self.assertEqual(spy.call_count, 0,
                         "the default sweep must not call ancestor_closure — D2 rests on this")
        self.assertEqual(rc, S.EXIT_INSTRUMENT, "and it must still refuse without it")

    def test_it_ALSO_refuses_when_the_record_is_NAMED(self):
        """The rare path must not be a hole either — same corruption, same refusal."""
        rc, out = self._sweep(self._ns_dangling(), ids=["C"])
        self.assertEqual(rc, S.EXIT_INSTRUMENT, out)

    def test_an_INTACT_parent_chain_is_untouched(self):
        """⚠ THE CORRELATED NEGATIVE. Without it both tests above pass on a check that refuses any
        record carrying a parent at all, which would red every supersession the tool exists for."""
        ns = self._ns(records=[self._rec(id="B"), self._rec(id="C", parent="B")],
                      manifest=["records/B.json", "records/C.json"])
        rc, out = self._sweep(ns)
        self.assertNotEqual(rc, S.EXIT_INSTRUMENT, out)

    def test_a_record_with_NO_parent_is_untouched(self):
        rc, out = self._sweep(self._ns(records=[self._rec()], manifest=["records/R.json"]))
        self.assertNotEqual(rc, S.EXIT_INSTRUMENT, out)


class ParentIsValidated(unittest.TestCase):
    """⚠ THE SIBLING OF C1, FOUND BY THE DISSENT AND VERIFIED AT SOURCE.

    `--parent` appeared exactly twice — the argparse definition and the assignment into `Record` —
    with NOTHING between them. `ancestor_closure` skips ids it does not know, so a typo'd parent was
    accepted, written, and silently dropped at every later sweep: `sweep B` searched B alone and
    exited CLEAN while B's own correction prose reasserted A. Verbatim the green-washing
    `ancestor_closure`'s docstring forbids, and the NESTED withdrawal is half the founding failure.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _harvest(self, parent, with_parent_record=False):
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        ns = Path(tempfile.mkdtemp())
        if with_parent_record:
            (ns / "records").mkdir()
            (ns / "records" / "ANCESTOR.json").write_text(json.dumps({
                "id": "ANCESTOR", "seed": "s", "variants": ["s"], "anchors": [], "nets_run": [],
                "tombstones": [{"location": "docs/a.md", "block_sha256": "x"}],
                "surfaces_at_withdrawal": [], "expected_counts": {}, "parent": None,
                "created": ""}), encoding="utf-8")
            (ns / "manifest.json").write_text(json.dumps(["records/ANCESTOR.json"]),
                                              encoding="utf-8")
        cfg = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", "1 files", 1,
                               [("docs/a.md", f"no egress\n{self.TOKEN}\n")])
        args = SimpleNamespace(id="NEW", seed="no egress", parent=parent, carrier=["docs/a.md"])
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.harvest(args)
        rec = None
        if (ns / "records" / "NEW.json").exists():
            rec = json.loads((ns / "records" / "NEW.json").read_text(encoding="utf-8"))
        return rc, out.getvalue(), rec

    def test_an_UNKNOWN_parent_REFUSES_and_WRITES_NOTHING(self):
        rc, out, rec = self._harvest("A-TYPO")
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIsNone(rec, "a record carrying a dangling parent edge must not be written")
        self.assertIn("unknown --parent", out)
        self.assertIn("A-TYPO", out)

    def test_a_KNOWN_parent_still_harvests(self):
        """Correlated positive: prove the refusal is the check and not --parent broken outright."""
        rc, out, rec = self._harvest("ANCESTOR", with_parent_record=True)
        self.assertEqual(rc, S.EXIT_DEBT, out)
        self.assertEqual(rec["parent"], "ANCESTOR")

    def test_NO_parent_is_still_permitted(self):
        """Second correlated negative: a root record has no parent, and refusing None would make
        the ordinary case impossible."""
        rc, _, rec = self._harvest(None)
        self.assertEqual(rc, S.EXIT_DEBT)
        self.assertIsNone(rec["parent"])
