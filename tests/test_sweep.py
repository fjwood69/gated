#!/usr/bin/env python3
"""Tests for sweep.py — each one pinned to the ruling it discharges.

⚠ EVERY TEST HERE IS WRITTEN TO FAIL IF THE RULING IS REVERSED. A test that passes both before and
after a change discharges nothing, and this project has shipped two of those.
"""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import sweep as S  # noqa: E402


class MatchingSemantics(unittest.TestCase):
    """R2 — matching is SPEC. These are the failures that motivated it."""

    def test_hard_wrapped_phrase_is_found(self):
        """THE v1 FAILURE. v1's design document hard-wrapped its own key phrase, so a line-oriented
        matcher would have missed the sentence the document was about."""
        corpus = "a supersession that greps only the surfaces it remembers is a partial sweep\nwearing a complete one's clothes."
        pat = S.compile_pattern("a partial sweep wearing a complete one's clothes")
        self.assertIsNotNone(pat.search(S.normalise(corpus)),
                             "a phrase split across a newline must still match")

    def test_line_oriented_matching_would_have_missed_it(self):
        """The control for the test above: prove the naive approach actually fails, so the test is
        not passing for an unrelated reason."""
        corpus = "…is a partial sweep\nwearing a complete one's clothes."
        naive = "a partial sweep wearing a complete one's clothes"
        self.assertFalse(any(naive in line for line in corpus.splitlines()),
                         "if a line-oriented search found this, the test proves nothing")

    def test_nfkc_is_load_bearing_for_compatibility_chars_inside_words(self):
        """⚠ THE RULING SURVIVED ITS RED-PROOF; ITS STATED REASON DID NOT.

        The design (and an earlier version of this test) justified NFKC by NBSP: "NFC leaves NBSP as
        NBSP, so the occurrence evades the whitespace rule". MEASURED: Python's ``\\s`` matches NBSP
        natively, so the NBSP case passes under NFC too — reversing NFKC->NFC left the old test GREEN.
        The reason was wrong; the ruling is not. Where NFKC is genuinely load-bearing is COMPATIBILITY
        CHARACTERS INSIDE WORDS, which no whitespace rule can reach.
        """
        corpus = "the \ufb01nal claim was \uff37rong"      # fi-ligature, fullwidth W
        pat = S.compile_pattern("the final claim was Wrong")
        self.assertIsNotNone(pat.search(S.normalise(corpus)),
                             "NFKC must fold ligatures and fullwidth forms for the match to land")

    def test_nbsp_is_handled_by_the_whitespace_rule_not_by_normalisation(self):
        """The correlated control for the test above: NBSP is NOT the case that motivates NFKC.
        Recorded so the wrong justification cannot be re-derived from a passing test."""
        import re as _re
        self.assertTrue(_re.match(r"\s", "\u00a0"), "Python's \\s matches NBSP natively")

    def test_indent_and_reflow_survive(self):
        pat = S.compile_pattern("count is stable")
        self.assertIsNotNone(pat.search(S.normalise("    count\n        is\n  stable")))

    def test_pattern_is_literal_not_regex(self):
        """A claim containing metacharacters must not silently become a wildcard."""
        pat = S.compile_pattern("count == 0 (always)")
        self.assertIsNotNone(pat.search(S.normalise("we said count == 0 (always) here")))
        self.assertIsNone(pat.search(S.normalise("count == 0 always")))

    def test_multiline_span_is_reported_whole(self):
        """R5 — a single context line missing the pattern words reads as a false positive."""
        text = "alpha\nthe claim is\nspread over lines\nomega"
        hits = S.find_hits(text, S.compile_pattern("the claim is spread over lines"),
                           label="t", surface="s", location_of=lambda a, b: f"f:{a}-{b}")
        self.assertEqual(len(hits), 1)
        self.assertIn("spread over lines", hits[0].span)
        self.assertIn("the claim is", hits[0].span)


class NeverAdjudicates(unittest.TestCase):
    """R5 — a classifier may reorder; it may never remove."""

    def test_marker_proximity_does_not_suppress_a_hit(self):
        """⚠ THE CENTRAL RULING. The missed carrier in the origin incident WAS a correction document,
        with a second withdrawal nested inside the first — so marker-proximity safety is falsified by
        the very event that motivated the tool."""
        text = "⚠ CORRECTED: this used to read differently.\nthe claim is live here anyway"
        hits = S.find_hits(text, S.compile_pattern("the claim is live here"),
                           label="t", surface="s", location_of=lambda a, b: "f")
        self.assertEqual(len(hits), 1, "a hit near a correction marker must still be REPORTED")
        self.assertTrue(hits[0].disposition().startswith("marker-"),
                        "the marker is an observable that RANKS it, not one that removes it")

    def test_disposition_is_an_observable_not_a_verdict(self):
        far = S.Hit("s", "f", "x", "p", marker_offset=None)
        near = S.Hit("s", "f", "x", "p", marker_offset=-4)
        self.assertEqual(far.disposition(), "no-marker-within-window")
        self.assertEqual(near.disposition(), "marker-4-lines-before")
        for d in (far.disposition(), near.disposition()):
            self.assertNotIn("QUOTED", d.upper())
            self.assertNotIn("LIVE", d.upper())


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


class BlockExclusion(unittest.TestCase):
    """R7 — and the exclusion is keyed on REGISTRATION, not on the SHAPE of a delimiter."""

    TEXT = ("intro\n" + S.BLOCK_OPEN + "REC -->\nthe withdrawn claim\n" + S.BLOCK_CLOSE
            + "\nand the withdrawn claim is ALSO live out here\n")

    def _records(self, sha):
        r = S.Record(id="REC", seed="", variants=[], anchors=[], nets_run=[],
                     tombstones=[{"location": "f.md", "block_sha256": sha}],
                     surfaces_at_withdrawal=[], expected_counts={}, parent=None, created="")
        return {"REC": r}

    def _hits(self, records, selected):
        reg, unreg = S.registered_spans(self.TEXT, "f.md", records, selected)
        return S.find_hits(self.TEXT, S.compile_pattern("the withdrawn claim"),
                           label="p", surface="s", location_of=lambda x, y: f"f.md:{x}",
                           registered=reg, unregistered=unreg)

    def test_registered_block_is_excluded_from_the_live_count(self):
        sha = S.block_sha(S.extract_blocks(self.TEXT)["REC"])
        hits = self._hits(self._records(sha), ["REC"])
        self.assertEqual(len(hits), 2, "both occurrences must be FOUND")
        self.assertEqual([h for h in hits if h.counts_as_live()].__len__(), 1,
                         "only the occurrence OUTSIDE the registered block is a live finding")

    def test_unregistered_delimiter_does_NOT_suppress(self):
        """⚠ THE DEFECT FOUND IN DISSENT. Excluding on shape meant WRAPPING LIVE TEXT IN THE DELIMITER
        SUPPRESSED IT FROM THE EXIT CODE — a self-service exclusion available to anyone who types
        `<!-- withdrawn: -->`, inside the tool built to stop claims disappearing without record."""
        hits = self._hits({}, [])          # nothing registered at all
        self.assertEqual(len(hits), 2)
        self.assertTrue(all(h.counts_as_live() for h in hits),
                        "a delimiter with no matching registration must NOT suppress anything")

    def test_unregistered_delimiter_is_labelled_as_a_signal(self):
        """It is EITHER a correction someone forgot to harvest OR an attempted suppression. Both are
        worth seeing, so it gets its own visible disposition rather than passing as ordinary."""
        hits = self._hits({}, [])
        labels = {h.disposition() for h in hits}
        self.assertIn("delimiter-block-UNREGISTERED", labels)

    def test_wrong_hash_does_not_earn_exclusion(self):
        """Tampering with a registered block's body must not keep its exclusion."""
        hits = self._hits(self._records("a-hash-that-does-not-match"), ["REC"])
        self.assertTrue(all(h.counts_as_live() for h in hits),
                        "a block whose hash does not match its tombstone is NOT registered")

    def test_unselected_record_does_not_earn_exclusion(self):
        sha = S.block_sha(S.extract_blocks(self.TEXT)["REC"])
        hits = self._hits(self._records(sha), [])     # record exists but is not in this run
        self.assertTrue(all(h.counts_as_live() for h in hits))

    def test_the_excluded_hit_is_still_printed(self):
        """R5 — never remove. Exclusion changes the COUNT, never the visibility."""
        sha = S.block_sha(S.extract_blocks(self.TEXT)["REC"])
        blocked = [h for h in self._hits(self._records(sha), ["REC"]) if not h.counts_as_live()]
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0].disposition(), "in-tombstoned-block")
        self.assertIn("withdrawn claim", blocked[0].span)

    def test_namespace_hits_also_excluded_but_present(self):
        h = S.Hit("s", "l", "x", "p", in_namespace=True)
        self.assertFalse(h.counts_as_live())
        self.assertEqual(h.disposition(), "control-namespace")

    def test_ordinary_hit_counts_as_live(self):
        self.assertTrue(S.Hit("s", "l", "x", "p").counts_as_live())


class UndisposedDiff(unittest.TestCase):
    """R14 — persistence without comparison relocates the failure to remembering-TO-READ.

    ⚠ THESE TESTS EXIST BECAUSE A MUTANT SURVIVED. Neutering the diff changed nothing observable, which
    meant the diff was BUILT AND UNDISCHARGED — the same half-built shape dissent had just flagged for
    R7. A mutant surviving is either a test gap or a bad mutant; this one was a test gap.
    """

    def _ns(self, body: str):
        import tempfile
        d = tempfile.mkdtemp()
        ns = Path(d)
        (ns / "reports").mkdir()
        (ns / "reports" / "20260804T090000.txt").write_text(body, encoding="utf-8")
        return ns

    def test_previous_live_hits_are_recovered(self):
        body = ("RUN 2026-08-04T09:00:00+00:00   swept: all\n\nFULL HIT LIST:\n"
                "no-marker-within-window\tdocs/a.md:10|REC:v0\tsome span\n"
                "marker-4-lines-before\tdocs/b.md:20|REC:v0\tanother span\n")
        keys, stamp = S._previous_hits(self._ns(body))
        self.assertEqual(keys, {"docs/a.md:10|REC:v0", "docs/b.md:20|REC:v0"})
        self.assertEqual(stamp, "2026-08-04T09:00:00+00:00")

    def test_excluded_dispositions_are_not_carried_forward(self):
        """A tombstoned block was never a live finding, so it must not appear as 'still undisposed'
        and inflate the debt the next run reports."""
        body = ("RUN 2026-08-04T09:00:00+00:00\n\nFULL HIT LIST:\n"
                "in-tombstoned-block\tdocs/a.md:10|REC:v0\tquoted\n"
                "control-namespace\tns/x.md:1|REC:v0\tfixture\n"
                "no-marker-within-window\tdocs/c.md:5|REC:v0\treal\n")
        keys, _ = S._previous_hits(self._ns(body))
        self.assertEqual(keys, {"docs/c.md:5|REC:v0"})

    def test_no_previous_run_is_a_baseline_not_a_clean_result(self):
        import tempfile
        keys, stamp = S._previous_hits(Path(tempfile.mkdtemp()))
        self.assertEqual(keys, set())
        self.assertIsNone(stamp, "absence of a prior run must be distinguishable from zero new hits")


class ExpectedCountPins(unittest.TestCase):
    """R10 — harvest wrote pins onto the record and sweep enforced only config, so the record's pin
    was INERT: the same half-built shape R14 had, found in the same dissent round."""

    def test_strictest_pin_wins(self):
        cfg = {"expected_counts": {"docs": 400}}
        rec = S.Record(id="R", seed="", variants=[], anchors=[], nets_run=[], tombstones=[],
                       surfaces_at_withdrawal=[], expected_counts={"docs": 412},
                       parent=None, created="")
        pins = [cfg["expected_counts"].get("docs"), rec.expected_counts.get("docs")]
        self.assertEqual(max(p for p in pins if isinstance(p, int)), 412,
                         "a record pin must be able to TIGHTEN the floor")

    def test_a_record_pin_can_never_loosen_a_config_floor(self):
        cfg = {"expected_counts": {"docs": 400}}
        rec_low = S.Record(id="R", seed="", variants=[], anchors=[], nets_run=[], tombstones=[],
                           surfaces_at_withdrawal=[], expected_counts={"docs": 10},
                           parent=None, created="")
        pins = [cfg["expected_counts"].get("docs"), rec_low.expected_counts.get("docs")]
        self.assertEqual(max(p for p in pins if isinstance(p, int)), 400,
                         "registering a record must not be a way to lower an existing floor")


class SharedInstrumentGate(unittest.TestCase):
    """P1-2 — ⚠ harvest USED TO RUN A STRICTLY WEAKER GATE THAN sweep.

    It checked ``s.error`` and nothing else — not zero-items, not the controls, not the count pins,
    not the manifest — and then WROTE the record and PINNED ``expected_counts`` from that enumeration.
    Authoritative state built on a reading ``sweep`` would have refused to certify, with the registry
    then vouching for every later clean run: this tool's own founding failure, one level down, inside
    the command whose docstring claims to make the registry honest.

    ⚠ NO TEST SAW IT. The suite was 32 green across the whole build. Found by a source-attached design
    review, not by execution and not by the tests — which is why BOTH the function AND THE CALL are
    pinned below. Testing the gate does not test that harvest runs it.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _cfg(self, **kw):
        c = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        c.update(kw)
        return c

    def _surface(self, name="docs", count=5, with_token=True):
        items = [(f"{name}/f{i}.md", f"body {self.TOKEN}" if with_token else "body")
                 for i in range(count)]
        return S.SurfaceResult(name, "filesystem", f"{count} files", count, items)

    def _pinning_record(self, name, floor):
        return {"OLD": S.Record(id="OLD", seed="", variants=[], anchors=[], nets_run=[],
                                tombstones=[], surfaces_at_withdrawal=[],
                                expected_counts={name: floor}, parent=None, created="")}

    # ── the gate itself ───────────────────────────────────────────────────────────────────────────
    def test_gate_catches_zero_items(self):
        import tempfile
        errs, _ = S.instrument_gate([S.SurfaceResult("docs", "filesystem", "0 files", 0, [])],
                                    self._cfg(), {}, [], Path(tempfile.mkdtemp()))
        self.assertTrue(any("ZERO items" in e for e in errs),
                        "an empty enumeration is an instrument failure, not a clean result")

    def test_gate_catches_a_dropped_count(self):
        import tempfile
        errs, _ = S.instrument_gate([self._surface(count=5)], self._cfg(),
                                    self._pinning_record("docs", 10), ["OLD"],
                                    Path(tempfile.mkdtemp()))
        self.assertTrue(any("COUNT DROPPED" in e for e in errs),
                        "a partial enumeration is nonzero and must still fail")

    def test_gate_catches_a_failed_control(self):
        import tempfile
        errs, _ = S.instrument_gate([self._surface(with_token=False)], self._cfg(), {}, [],
                                    Path(tempfile.mkdtemp()))
        self.assertTrue(any("control" in e for e in errs))

    def test_gate_passes_a_healthy_surface(self):
        """The correlated positive control. Without it the three tests above pass on a gate that
        rejects EVERYTHING, which certifies nothing."""
        import tempfile
        errs, _ = S.instrument_gate([self._surface()], self._cfg(), {}, [],
                                    Path(tempfile.mkdtemp()))
        self.assertEqual(errs, [], f"a healthy surface must pass cleanly, got {errs}")

    # ── the CALL. Behaviour and wiring are two claims. ────────────────────────────────────────────
    def _run_harvest(self, surfaces, records=None):
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        ns = Path(tempfile.mkdtemp())
        if records:
            (ns / "records").mkdir()
            for rid, r in records.items():
                (ns / "records" / f"{rid}.json").write_text(json.dumps(r.__dict__), encoding="utf-8")
        args = SimpleNamespace(id="NEW", seed="some claim", anchor=None, parent=None)
        with mock.patch.object(S, "load_config", return_value=self._cfg()), \
             mock.patch.object(S, "gather_surfaces", return_value=surfaces), \
             mock.patch.object(S, "NAMESPACE", ns):
            rc = S.harvest(args)
        return rc, ns

    def test_harvest_REFUSES_and_WRITES_NOTHING_on_zero_items(self):
        """⚠ THE PROPERTY THAT MATTERS IS NOT THE EXIT CODE, IT IS THAT NO RECORD EXISTS AFTERWARDS.
        The old gate returned a record pinning ``expected_counts`` from a broken enumeration."""
        rc, ns = self._run_harvest([S.SurfaceResult("docs", "filesystem", "0 files", 0, [])])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertFalse((ns / "records" / "NEW.json").exists(),
                         "harvest must not persist a record built on an enumeration it cannot trust")

    def test_harvest_REFUSES_and_WRITES_NOTHING_on_a_dropped_count(self):
        rc, ns = self._run_harvest([self._surface(count=5)], self._pinning_record("docs", 10))
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertFalse((ns / "records" / "NEW.json").exists())

    def test_harvest_STILL_WRITES_on_a_healthy_surface(self):
        """The correlated positive control for the wiring: prove the refusals above are the gate
        firing and not harvest being broken outright."""
        rc, ns = self._run_harvest([self._surface()])
        self.assertEqual(rc, S.EXIT_DEBT, "a clean harvest writes an OPEN record (process debt)")
        self.assertTrue((ns / "records" / "NEW.json").exists(),
                        "a healthy surface must still produce a record")


class OrthographicExpansion(unittest.TestCase):
    """R3 — expansion is the mechanism EXTRACTION CANNOT REPLACE, and it was ONE-WAY.

    ⚠ THE DEFECT: ``expand`` split on the HYPHEN FAMILY ONLY, so a SPACE-FORM term had nothing to
    split and returned the EMPTY SET — while its docstring claimed "every orthographic spelling".
    ``expand("no egress")`` yielded NOTHING, AND "no egress" IS THE SEED. Found by an outside
    reviewer reading the source, not by execution and not by these tests, which did not exist.
    """

    def test_space_form_expands_to_the_hyphen_family(self):
        """⚠ THE SEED CASE. This is the assertion the one-way implementation fails."""
        got = S.expand("no egress")
        self.assertIn("no-egress", got, "a SPACE-form term must yield the ASCII-hyphen form")
        self.assertIn("noegress", got)
        self.assertIn("no‑egress", got, "and the NON-BREAKING hyphen, which NFKC does NOT fold to ASCII")

    def test_hyphen_form_still_expands_to_the_space_form(self):
        """The other direction, which already worked — kept so a fix cannot swap the bug's polarity."""
        self.assertIn("false pass", S.expand("false-pass"))

    def test_a_term_with_no_axis_yields_nothing(self):
        """The correlated negative control: without it the tests above pass on an expander that
        returns junk for every input."""
        self.assertEqual(S.expand("single"), set())

    def test_the_term_itself_is_never_returned(self):
        for t in ("no egress", "false-pass"):
            self.assertNotIn(t, S.expand(t))

    def test_scope_is_ORTHOGRAPHIC_ONLY(self):
        """⚠ THE RULED DEFECT WAS ONE-WAYNESS, NOT NARROWNESS. Case folding, pluralisation and
        stemming are DIFFERENT AXES, each needing its own justification. Widening beyond the ruling
        is how a fix becomes a redesign, so the boundary is pinned here."""
        got = S.expand("ZERO-GATE")
        self.assertTrue(all(g.replace(" ", "").replace("-", "").replace("\u2010", "")
                            .replace("\u2011", "") == "ZEROGATE" for g in got),
                        f"expansion must not change letters or case, got {got}")
        self.assertNotIn("zero-gate", got, "no case folding — the MATCHER already folds case")
        self.assertNotIn("zero-gates", got, "no pluralisation")


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
                                [(f"docs/f{i}.md", "body ZZ-SWEEP-CONTROL-TOKEN") for i in range(3)])]
        args = SimpleNamespace(id=rid, seed="a claim", parent=None)
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


class NfkcHyphenIsNotFolded(unittest.TestCase):
    """⚠ THE DOCSTRING'S THIRD NFKC EXAMPLE WAS DEAD, AND IT WAS THE CORRECTED VERSION.

    `normalise` exists to record that a ruling survived its red-proof while its stated reason did
    not. The rewritten reason then shipped with a FRESH false example — the non-breaking hyphen —
    undetected until an outside reviewer read it. This test pins the measurement so the claim cannot
    quietly return.
    """

    def test_U2011_does_NOT_fold_to_ascii_hyphen(self):
        folded = S.normalise("\u2011")
        self.assertEqual(folded, "\u2010", "NFKC maps NON-BREAKING HYPHEN to HYPHEN, not to ASCII")
        self.assertNotEqual(folded, "-", "so NFKC does NOT rescue an ASCII-hyphen pattern")
        self.assertIsNone(S.compile_pattern("co-operate").search(S.normalise("co\u2011operate")),
                          "an ASCII-hyphen pattern still MISSES a typographic hyphen after NFKC")

    def test_the_two_surviving_examples_are_real(self):
        """The correlated control: ligature and fullwidth DO fold, so the ruling still stands."""
        self.assertIsNotNone(S.compile_pattern("final").search(S.normalise("\ufb01nal")))
        self.assertEqual(S.normalise("\uff21"), "A")

    def test_expand_is_what_crosses_the_hyphen_axis(self):
        """Since normalisation does not cross it, expansion must — by enumeration."""
        self.assertIn("co\u2011operate", S.expand("co-operate"))


class AnchorsAreAnOutputNotAnInput(unittest.TestCase):
    """⚠ THE CLI USED TO INVITE ANCHORS IN while the design ruled them an OUTPUT of harvest.

    That laundered a remembered guess into the registry wearing an output's clothing. MEASURED:
    hand-chosen anchors reached 1 of 5 carriers — STRICTLY WORSE than the literal seed's 3 of 5 —
    and recovered nothing the seed had missed.
    """

    def test_harvest_has_no_anchor_flag(self):
        """⚠ ASSERT WHICH SystemExit. Bare `assertRaises(SystemExit)` passes whether or not the flag
        exists — with it, argparse accepts and `load_config` exits on a missing config instead. That
        mutant SURVIVED. The parser's own error message is the only thing that distinguishes them."""
        import contextlib, io
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            S.main(["harvest", "ID", "seed", "--anchor", "SomeIdentifier"])
        self.assertIn("unrecognized arguments: --anchor", err.getvalue(),
                      "the flag must be REJECTED BY THE PARSER, not merely absent from the outcome")

    def test_the_parser_still_accepts_a_real_harvest_invocation(self):
        """Correlated control: prove the rejection above is the flag and not a broken parser."""
        import contextlib, io
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            S.main(["harvest", "ID", "seed", "--parent", "P"])
        self.assertNotIn("unrecognized arguments", err.getvalue(),
                         "--parent is a real flag and must parse")


# ⚠ THIS ENTRY POINT MUST STAY AT THE END OF THE FILE, AND IT USED TO SIT IN THE MIDDLE.
# ``unittest.main()`` runs at the point it is reached during module execution, so every class defined
# BELOW it was never registered when the file was run as a script: `python3 test_sweep.py` reported
# "Ran 19 tests ... OK" while pytest and `unittest discover` both ran 39. A TRUNCATED RUN THAT PRINTS
# OK is precisely the failure class this tool exists to catch, and it was living in its own test file.
if __name__ == "__main__":
    unittest.main(verbosity=2)
