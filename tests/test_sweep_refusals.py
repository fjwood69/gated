#!/usr/bin/env python3
"""Refusals and the exit strata — R4a, R19's doorways, and the retombstone bind.

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
from _sweep_harness import S, json, unittest, _SweepHarness, Path


class ExitStratification(unittest.TestCase):
    """R4a — process debt must never share a code with a live finding."""

    def test_all_five_codes_are_distinct(self):
        codes = [S.EXIT_CLEAN, S.EXIT_INSTRUMENT, S.EXIT_TOMBSTONE, S.EXIT_HITS, S.EXIT_DEBT]
        self.assertEqual(len(set(codes)), 5,
                         "a shared code is how process debt drowns out a real finding")

    def test_debt_is_not_the_instrument_code(self):
        self.assertNotEqual(S.EXIT_DEBT, S.EXIT_INSTRUMENT)
        self.assertNotEqual(S.EXIT_DEBT, S.EXIT_HITS)

    def test_open_record_is_zero_tombstones(self):
        r = S.Record(id="x", seed="", variants=[], anchors=[], nets_run=[], tombstones=[],
                     surfaces_at_withdrawal=[], expected_counts={}, parent=None, created="")
        self.assertTrue(r.is_open)
        r.tombstones = [{"location": "a", "block_sha256": "b"}]
        self.assertFalse(r.is_open)


class UnknownRecordId(unittest.TestCase):
    """⚠ `sweep TYPO-ID` USED TO EXIT 0 CLEAN. Found by a design review of an unrelated feature.

    `ancestor_closure` skips ids it does not know, so an unknown id yielded an EMPTY selected set:
    nothing searched, nothing found, **exit 0**, and the header printing the id it never swept. A
    typo and a genuinely clean corpus were indistinguishable — and **the wrong one is the reassuring
    one**, which is this tool's entire subject.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _sweep(self, ids, with_record=True):
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        ns = Path(tempfile.mkdtemp())
        if with_record:
            (ns / "records").mkdir()
            (ns / "records" / "REAL.json").write_text(json.dumps({
                "id": "REAL", "seed": "x", "variants": ["x"], "anchors": [], "nets_run": [],
                "tombstones": [{"location": "docs/a.md", "block_sha256": "s"}],
                "surfaces_at_withdrawal": [], "expected_counts": {}, "parent": None,
                "created": ""}), encoding="utf-8")
            (ns / "manifest.json").write_text(json.dumps(["records/REAL.json"]), encoding="utf-8")
        cfg = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", "1 files", 1, [("docs/a.md", self.TOKEN)])
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.sweep(SimpleNamespace(records=ids, show=10))
        return rc, out.getvalue()

    def test_an_unknown_id_REFUSES_instead_of_reporting_clean(self):
        rc, out = self._sweep(["TYPO-ID"])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("unknown record id", out)
        self.assertNotEqual(rc, S.EXIT_CLEAN, "a sweep that searched nothing must never read clean")

    def test_a_KNOWN_id_still_sweeps(self):
        """Correlated control: prove the refusal is the unknown-id check and not a broken path."""
        rc, out = self._sweep(["REAL"])
        self.assertNotEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("REAL", out)

    def test_one_unknown_among_known_ids_STILL_refuses(self):
        """⚠ A partial match is the dangerous case: the run would sweep the real ids, find nothing,
        and the caller would believe the typo'd one was covered too."""
        rc, out = self._sweep(["REAL", "TYPO-ID"])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("TYPO-ID", out)


class UnsearchableRecord(_SweepHarness):
    """R-B — ⚠ A RECORD THAT CANNOT BE SEARCHED MUST NEVER REPORT AS SEARCHED.

    Third site of ONE rule, not a third rule: an unknown record id (C1), an uncompilable seed at
    harvest (R16), and a selected record whose patterns all fail to compile are the same shape —
    SELECTED, NEVER SEARCHED, REPORTS CLEAN. Only the door differs.

    ⚠ REACHABLE ONLY BY HAND-EDIT, WHICH IS WHY IT IS IN SCOPE: R18's ruled retirement procedure is
    editing the record JSON by hand, so C2 opens the very door this closes.
    """

    def test_a_record_whose_variants_ALL_fail_to_compile_REFUSES(self):
        ns = self._ns(records=[self._rec(variants=["   ", ""])], manifest=["records/R.json"])
        rc, out = self._sweep(ns)
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("UNSEARCHABLE RECORD R", out)

    def test_the_refusal_NAMES_THE_FAILING_VARIANT_IDS(self):
        """⚠ RULED: print the failing ids. 'Something did not compile' sends the operator to read
        1,600 lines; 'R:v0, R:v1' sends them to the record."""
        ns = self._ns(records=[self._rec(variants=["   ", ""])], manifest=["records/R.json"])
        _, out = self._sweep(ns)
        self.assertIn("R:v0", out)
        self.assertIn("R:v1", out)

    def test_a_record_with_NO_variants_at_all_also_REFUSES(self):
        """Same condition by a different route: nothing to compile and nothing compiled. Either way
        this id contributed no search, and a clean exit would certify a corpus against a net that
        was never cast."""
        ns = self._ns(records=[self._rec(variants=[])], manifest=["records/R.json"])
        rc, out = self._sweep(ns)
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("NO variants and NO anchors", out)

    def test_ONE_compilable_variant_among_broken_ones_is_ENOUGH(self):
        """⚠ THE CORRELATED NEGATIVE, AND IT IS LOAD-BEARING. Without it these tests pass on a
        version that refuses whenever ANY variant fails — which would red every record carrying a
        zero-hit tripwire, and tripwires are the mechanism `expand` exists to create."""
        ns = self._ns(records=[self._rec(variants=["   ", "a seed"])], manifest=["records/R.json"])
        rc, out = self._sweep(ns)
        self.assertNotEqual(rc, S.EXIT_INSTRUMENT, out)

    def test_a_HEALTHY_record_still_sweeps(self):
        """Second correlated positive: prove the refusals are the guard and not sweep broken."""
        ns = self._ns(records=[self._rec()], manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", f"{self.TOKEN}\na seed lives here\n")])
        self.assertEqual(rc, S.EXIT_HITS, out)


class Retombstone(unittest.TestCase):
    """R4/R7.5 — ⚠ THE COMMAND THAT CLOSES THE LOOP, SPECIFIED AND NEVER SHIPPED UNTIL NOW.

    `harvest` wrote records OPEN; `sweep` CHECKED tombstones; **NOTHING CREATED ONE.** So the loop
    the whole design is built around — harvest → correct → register — could not be completed with
    the tool. Two records sat open, exiting 4 for ever, beside a correct hash-verified withdrawn
    block with nowhere to go.

    That is R4a's own warning arriving through the door built to prevent it: *"an exit that is
    always red trains the reader to route around it"* — process debt the tool MANUFACTURES and then
    reports. Fourth built-enough-to-describe defect, and again found by EXECUTION, not review.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _ns_with_record(self, tombstones=None):
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        (ns / "records" / "REC.json").write_text(json.dumps({
            "id": "REC", "seed": "the withdrawn claim", "variants": ["the withdrawn claim"],
            "anchors": [], "nets_run": [], "tombstones": tombstones or [],
            "surfaces_at_withdrawal": [], "expected_counts": {}, "parent": None,
            "created": ""}), encoding="utf-8")
        (ns / "manifest.json").write_text(json.dumps(["records/REC.json"]), encoding="utf-8")
        return ns

    def _doc(self, rid="REC", body="the withdrawn claim"):
        return (f"⚠ CORRECTED. It read:\n{S.BLOCK_OPEN}{rid} -->\n{body}\n{S.BLOCK_CLOSE}\n"
                f"and here is why it was wrong.\n{self.TOKEN}\n")

    def _run(self, ns, items, record="REC", location=None):
        import contextlib
        import io
        from types import SimpleNamespace
        from unittest import mock
        cfg = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", f"{len(items)} files", len(items), items)
        args = SimpleNamespace(record=record, location=list(location or []))
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.retombstone(args)
        rec = json.loads((ns / "records" / "REC.json").read_text(encoding="utf-8"))
        return rc, out.getvalue(), rec

    # ── the loop actually closes ─────────────────────────────────────────────────────────────────
    def test_binding_CLOSES_an_open_record(self):
        """⚠ THE PROPERTY THE WHOLE COMMAND EXISTS FOR. Before this, a record could only ever go
        from OPEN to OPEN, and exit 4 was permanent by construction."""
        ns = self._ns_with_record()
        self.assertTrue(S.load_records(ns)["REC"].is_open)
        rc, out, rec = self._run(ns, [("docs/a.md", self._doc())])
        self.assertEqual(rc, S.EXIT_CLEAN)
        self.assertEqual(len(rec["tombstones"]), 1)
        self.assertEqual(rec["tombstones"][0]["location"], "docs/a.md")
        self.assertFalse(S.load_records(ns)["REC"].is_open, "the record must now be CLOSED")

    def test_the_stored_hash_is_COMPUTED_from_the_block_and_MATCHES_a_sweep(self):
        """⚠ "HASH-VERIFIED" MEANS COMPUTED, NEVER SUPPLIED. The bound hash must be the one a later
        sweep recomputes from the same bytes, or the control is decorative."""
        ns = self._ns_with_record()
        doc = self._doc()
        _, _, rec = self._run(ns, [("docs/a.md", doc)])
        self.assertEqual(rec["tombstones"][0]["block_sha256"],
                         S.block_sha(S.extract_blocks(doc)["REC"]))

    def test_the_bound_block_is_then_EXCLUDED_from_the_live_count(self):
        """End-to-end: binding must actually license the R7 exclusion, or the loop closes on paper
        while every sweep still reports the quoted text as a live hit."""
        ns = self._ns_with_record()
        doc = self._doc()
        self._run(ns, [("docs/a.md", doc)])
        recs = S.load_records(ns)
        reg, unreg = S.registered_spans(doc, "docs/a.md", recs, ["REC"])
        hits = S.find_hits(doc, S.compile_pattern("the withdrawn claim"), label="p", surface="s",
                           location_of=lambda a, b: "docs/a.md", registered=reg, unregistered=unreg)
        self.assertTrue(hits, "the quoted text must still be FOUND")
        self.assertFalse(any(h.counts_as_live() for h in hits),
                         "and a BOUND block must not count as a live finding (R7)")

    def test_it_binds_EVERY_location_carrying_the_block(self):
        """R7.5 — "re-binds in ONE command". A correction quoted in three places must not need three
        invocations; friction is what makes ignoring the failure win."""
        ns = self._ns_with_record()
        rc, _, rec = self._run(ns, [("docs/a.md", self._doc()), ("docs/b.md", self._doc()),
                                    ("docs/c.md", "unrelated\n" + self.TOKEN)])
        self.assertEqual(rc, S.EXIT_CLEAN)
        self.assertEqual(sorted(t["location"] for t in rec["tombstones"]),
                         ["docs/a.md", "docs/b.md"])

    # ── refusals, and the stratification ─────────────────────────────────────────────────────────
    def test_NOTHING_TO_BIND_is_exit_6_and_NOT_the_tombstone_code(self):
        """⚠ SIX, NOT TWO. `EXIT_TOMBSTONE` means a registered control BROKE; this means there was
        nothing to register. An operator shown code 2 goes looking for a re-worded block that does
        not exist — different cause, different remediation, different code."""
        ns = self._ns_with_record()
        rc, out, rec = self._run(ns, [("docs/a.md", "no block here\n" + self.TOKEN)])
        self.assertEqual(rc, S.EXIT_BIND)
        self.assertNotEqual(S.EXIT_BIND, S.EXIT_TOMBSTONE)
        self.assertEqual(rec["tombstones"], [], "a failed bind must write nothing")
        self.assertIn("has not been written yet", out)

    def test_a_NAMED_location_without_the_block_is_a_REFUTED_ASSERTION(self):
        """The other half of the same exit, and the message must distinguish them: you named a
        location and the block is not there, which is not the same as no correction existing."""
        ns = self._ns_with_record()
        rc, out, _ = self._run(ns, [("docs/a.md", self._doc()), ("docs/b.md", self.TOKEN)],
                               location=["docs/b.md"])
        self.assertEqual(rc, S.EXIT_BIND)
        self.assertIn("refuted assertion", out)

    def test_an_unknown_record_is_refused(self):
        ns = self._ns_with_record()
        rc, out, _ = self._run(ns, [("docs/a.md", self._doc())], record="NOPE")
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("no registered record", out)

    def test_it_refuses_to_bind_against_an_UNTRUSTED_enumeration(self):
        """⚠ The blocks live ON the surfaces. Binding against a reading `sweep` would refuse to
        certify pins a control to an enumeration the tool does not trust."""
        import contextlib
        import io
        from types import SimpleNamespace
        from unittest import mock
        ns = self._ns_with_record()
        cfg = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        empty = S.SurfaceResult("docs", "filesystem", "0 files", 0, [])
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[empty]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(io.StringIO()):
            rc = S.retombstone(SimpleNamespace(record="REC", location=[]))
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertEqual(json.loads((ns / "records" / "REC.json").read_text())["tombstones"], [])

    # ── re-binding is an overwrite, and the scope of that overwrite is bounded ───────────────────
    def test_REBINDING_replaces_a_stale_hash(self):
        """R7.5's actual subject: a correction was re-worded, the control broke, and re-binding must
        fix it in one command — otherwise ignoring the failure wins."""
        ns = self._ns_with_record([{"location": "docs/a.md", "block_sha256": "STALE"}])
        _, _, rec = self._run(ns, [("docs/a.md", self._doc())])
        self.assertEqual(len(rec["tombstones"]), 1)
        self.assertNotEqual(rec["tombstones"][0]["block_sha256"], "STALE")

    def test_a_NARROW_rebind_PRESERVES_tombstones_outside_its_scope(self):
        """⚠ THE GUARD ON THE ONE PLACE AN OVERWRITE IS CORRECT. `harvest` refuses to overwrite a
        record because it would silently reset tombstones; here the overwrite is the point, so the
        SCOPE is what must be bounded. A re-bind of one location must not drop a control at
        another — that would be the record-overwrite defect wearing this command's clothes."""
        ns = self._ns_with_record([{"location": "docs/elsewhere.md", "block_sha256": "KEEPME"}])
        _, out, rec = self._run(ns, [("docs/a.md", self._doc())], location=["docs/a.md"])
        locs = {t["location"]: t["block_sha256"] for t in rec["tombstones"]}
        self.assertEqual(locs.get("docs/elsewhere.md"), "KEEPME",
                         "a tombstone outside the named scope must SURVIVE")
        self.assertIn("docs/a.md", locs)
        self.assertIn("PRESERVED", out)

    def test_the_CLI_exposes_it(self):
        """Behaviour and wiring are two claims — the SharedInstrumentGate lesson."""
        import contextlib
        import io
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            S.main(["retombstone", "REC", "--nonsense"])
        self.assertIn("unrecognized arguments: --nonsense", err.getvalue())
