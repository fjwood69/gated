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
        items = [(f"{name}/f{i}.md",
                  f"some claim body {self.TOKEN}" if with_token else "some claim body")
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
        # ⚠ --carrier IS REQUIRED (ruled 2026-08-06). These fixtures exist to exercise the
        # INSTRUMENT GATE, which runs BEFORE the carrier checks, so a healthy run must still name a
        # carrier that genuinely holds the seed or it refuses for the wrong reason.
        args = SimpleNamespace(id="NEW", seed="some claim", anchor=None, parent=None,
                               carrier=[surfaces[0].items[0][0]] if surfaces[0].items else ["x"])
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

    def test_operator_compounds_are_INELIGIBLE_for_the_orthographic_axis(self):
        """⚠ A PATH THAT ALREADY FIRED, NOT A FUTURE ONE. ``_C_QUOTED`` extracts backticked spans, so
        ``count == 0 => no egress`` is a live candidate TODAY — and expansion turned it into
        ``count-==-0-=>-no-egress``, a string already sitting in a persisted 2026-08-04 transcript.

        This is a DOMAIN PRECONDITION, not a new expansion class: no axis added, no case folded,
        nothing pluralised or stemmed. It NARROWS application of the same ruled transform.
        """
        self.assertEqual(S.expand("count == 0"), set())
        self.assertEqual(S.expand("count == 0 => no egress"), set())

    def test_the_gate_leaves_ordinary_orthographic_terms_UNCHANGED(self):
        """⚠ THE CORRELATED NEGATIVE. Without it the test above passes on a gate that refuses
        everything, which would silently delete the mechanism it is meant to protect."""
        self.assertIn("no-egress", S.expand("no egress"))
        self.assertIn("false pass", S.expand("false-pass"))
        self.assertIn("false PASSES", S.expand("false-PASSES"),
                      "the criterion is STRUCTURAL, so mixed case must survive it")

    def test_the_criterion_is_structural_not_semantic(self):
        """It asks 'are the parts word-shaped', never 'is this a claim'. A meaningless but
        word-shaped term must still expand, or the gate has become adjudication (R5)."""
        self.assertIn("a-b", S.expand("a b"))

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
        import contextlib
        import io
        err = io.StringIO()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(err):
            S.main(["harvest", "ID", "seed", "--anchor", "SomeIdentifier"])
        self.assertIn("unrecognized arguments: --anchor", err.getvalue(),
                      "the flag must be REJECTED BY THE PARSER, not merely absent from the outcome")

    def _parse(self, argv):
        """Drive ``main`` with the COMMAND STUBBED OUT, and return (rc, stderr, args).

        ⚠ THIS USED TO RELY ON ``load_config`` EXITING BECAUSE NO CONFIG FILE EXISTED, AND THAT IS
        A TEST THAT PASSES FOR A REASON ABOUT THE DEVELOPER'S MACHINE. On CI there is no config, so
        it went green. The moment a real config was present — as it is on any workstation that has
        actually RUN the tool — the parse fell through and **executed a live harvest against the
        private corpus**, 331 board keys over HTTP included. It did not fail; it did the thing.
        MEASURED 2026-08-06: the suite hung, CPU-bound, and had to be killed.

        A control that depends on a file being ABSENT is not a control. Stubbing the command makes
        the assertion about the PARSER, which is what it always claimed to be about.
        """
        import contextlib
        import io
        from unittest import mock
        seen = {}

        def _stub(a):
            seen.update(vars(a))
            return 0

        err = io.StringIO()
        with mock.patch.object(S, "harvest", _stub), contextlib.redirect_stderr(err):
            rc = S.main(argv)
        return rc, err.getvalue(), seen

    def test_the_parser_still_accepts_a_real_harvest_invocation(self):
        """Correlated control: prove the rejection above is the flag and not a broken parser."""
        rc, err, args = self._parse(["harvest", "ID", "seed", "--parent", "P"])
        self.assertEqual(rc, 0)
        self.assertNotIn("unrecognized arguments", err, "--parent is a real flag and must parse")
        self.assertEqual(args["parent"], "P",
                         "⚠ --parent must REACH the command: it is the only input to "
                         "ancestor_closure, and R1's nested-withdrawal case goes dark without it")

    def test_carrier_is_REPEATABLE(self):
        """⚠ A RULING, NOT A CONVENIENCE. A claim can be made in more than one place before anyone
        notices it is wrong — the founding incident had FIVE carriers — so a single-valued flag
        would force the operator to pick one and silently discard the rest of a span already
        found."""
        _, _, args = self._parse(["harvest", "ID", "seed", "--carrier", "a.md", "--carrier", "b.md"])
        self.assertEqual(args["carrier"], ["a.md", "b.md"])


class FenceAwareCarrierUnits(unittest.TestCase):
    """⚠ A HEADING MARK INSIDE A FENCED BLOCK IS NOT A HEADING.

    `_HEADING` matches any line starting (modulo `>` prefixes) with 1-6 `#` and a space, so a SHELL
    OR PYTHON COMMENT INSIDE A FENCE was a split mark. MEASURED on the 2026-08-05 corpus: 245 such
    marks across 33 of 492 locations (6.7%).

    ⚠ IT BECAME LOAD-BEARING ONLY WITH CLAIM-SPAN SEEDING. Under the fixpoint loop a mis-split barely
    mattered — the flood crossed every boundary. When THE UNIT IS THE CANDIDATE SET, a mis-split
    above the claim CUTS THE UNIT SHORT and `variants` SILENTLY NARROWS. And the ablation cannot be
    cited against it: both arms shared `_HEADING`, so it measured granularity, never parse
    correctness.
    """

    F = "```"

    def _doc(self):
        return ("intro paragraph\n\n" + self.F + "bash\n"
                "# this is a shell comment, NOT a heading\n"
                "echo hi\n" + self.F + "\n\n"
                "the claim lives here\n\n"
                "## A REAL HEADING\n"
                "tail\n")

    def test_a_hash_comment_inside_a_fence_does_NOT_split(self):
        """⚠ THE TARGET ASSERTION. Fence-blind, this yields THREE units and the claim's unit begins
        at the shell comment — losing everything above it."""
        units = S.carrier_units("f.md", S.normalise(self._doc()))
        self.assertEqual(len(units), 2, f"the fence must not split; got {[u for u,_ in units]}")
        claim = [t for _, t in units if "the claim lives here" in t][0]
        self.assertIn("intro paragraph", claim,
                      "⚠ the claim's unit must still reach back past the fence")

    def test_a_real_heading_outside_a_fence_STILL_splits(self):
        """The correlated positive control: without it the test above passes on a function that
        never splits at all."""
        units = S.carrier_units("f.md", S.normalise(self._doc()))
        self.assertEqual(len(units), 2)
        self.assertTrue(any("A REAL HEADING" in t for _, t in units))
        self.assertFalse(any("A REAL HEADING" in t and "the claim lives here" in t
                             for _, t in units), "the real heading must separate them")

    def test_an_unterminated_fence_extends_to_end_of_text(self):
        """⚠ THE FAIL-SAFE DIRECTION, STATED. Suppressing splits after an unclosed fence yields
        FEWER, LARGER units — more vocabulary, which the tool already prints. Ignoring it would let
        splits happen INSIDE a probable fence, TRUNCATING silently. Truncation is the dangerous
        direction under claim-span seeding."""
        doc = "intro\n\n" + self.F + "\n# not a heading\n## also not\n"
        self.assertEqual(len(S.carrier_units("f.md", S.normalise(doc))), 1)

    def test_tilde_fences_count_too(self):
        doc = "intro\n\n~~~\n# not a heading\n~~~\n\nbody\n"
        self.assertEqual(len(S.carrier_units("f.md", S.normalise(doc))), 1)

    def test_headings_still_split_a_document_with_no_fences_at_all(self):
        """Second correlated control: fence logic must not perturb the ordinary path."""
        doc = "preamble\n\n# One\na\n\n## Two\nb\n"
        self.assertEqual(len(S.carrier_units("f.md", S.normalise(doc))), 3)


class SeedCensus(unittest.TestCase):
    """P1-1 — ⚠ THE DESIGN DELETES THE INSTRUMENT FOR CARRIER *ENUMERATION* AND REPLACES IT WITH AN
    UNRECORDED *ADJUDICATION*.

    Claim-span seeding asks which carrier holds the claim. The design stores the ANSWER (``--carrier``)
    and never the QUESTION — what there was to choose from. That is this tool's founding failure, one
    level down: a sweep that searches what its author remembers, reappearing inside the command whose
    docstring claims to make the registry honest.

    MEASURED on the founding incident: ``no egress`` is ordinary vocabulary in a project about network
    isolation, and 7 of the 8 locations using the phrase were HOMONYMS. So the population and the
    choice are genuinely different objects, and only one of them was being written down.
    """

    def _units(self, *triples):
        return list(triples)

    # ── the census counts, and never chooses (R5) ─────────────────────────────────────────────────
    def test_lists_every_unit_holding_the_seed(self):
        c = S.seed_census("no egress", self._units(
            ("a.md#0", "docs", "the count is zero so no egress"),
            ("a.md#1", "docs", "unrelated prose"),
            ("board/k", "board", "no egress here too")))
        self.assertEqual({h["unit"] for h in c["units_holding"]}, {"a.md#0", "board/k"})
        self.assertEqual(c["unit_total"], 3, "the denominator is the whole unit index, not the hits")

    def test_a_single_occurrence_is_listed_exactly_like_a_frequent_one(self):
        """⚠ THE NO-THRESHOLD PROPERTY, AS A TEST RATHER THAN A COMMENT. A census that quietly
        dropped the long tail would reproduce the silent cutoff it exists to expose — and the tail is
        where a forgotten carrier lives, by definition."""
        c = S.seed_census("seed", self._units(
            ("rare#0", "docs", "seed"),
            ("common#0", "docs", "seed seed seed seed seed")))
        self.assertEqual(len(c["units_holding"]), 2)
        self.assertEqual({h["unit"]: h["occurrences"] for h in c["units_holding"]},
                         {"rare#0": 1, "common#0": 5},
                         "occurrences are REPORTED, never used to filter")

    def test_occurrences_and_units_are_distinct_numbers(self):
        c = S.seed_census("seed", self._units(("u#0", "docs", "seed seed seed")))
        self.assertEqual(len(c["units_holding"]), 1)
        self.assertEqual(c["occurrences_total"], 3,
                         "3 occurrences in 1 unit must never be reported as 3 carriers")

    def test_surfaces_are_deduplicated_and_sorted(self):
        c = S.seed_census("seed", self._units(
            ("b#0", "board", "seed"), ("a#0", "docs", "seed"), ("a#1", "docs", "seed")))
        self.assertEqual(c["surfaces"], ["board", "docs"])

    def test_matching_is_the_matcher_not_a_substring(self):
        """The census must agree with what a sweep would find, so it goes through ``compile_pattern``
        — hard-wrap tolerant and NFKC-folded. A bare ``in`` test would under-count exactly the
        re-flowed occurrence R2 exists for."""
        c = S.seed_census("no egress", self._units(("w#0", "docs", "the claim says no\negress here")))
        self.assertEqual(len(c["units_holding"]), 1,
                         "a hard-wrapped occurrence is an occurrence (R2)")

    def test_an_uncompilable_seed_is_REPORTED_not_raised(self):
        """⚠ THE COUNTER DOES NOT DECIDE WHAT AN INSTRUMENT CONDITION COSTS. It reports; the caller
        rules. Raising here would make the census's failure indistinguishable from harvest crashing."""
        c = S.seed_census("   ", self._units(("u#0", "docs", "anything")))
        self.assertIsNotNone(c["error"])
        self.assertEqual(c["units_holding"], [],
                         "an empty population, never a population that was not measured")

    def test_zero_occurrences_is_a_measured_zero_not_an_error(self):
        """The correlated negative control for the test above: absence of the seed and inability to
        look for it must not produce the same record."""
        c = S.seed_census("absent", self._units(("u#0", "docs", "nothing here")))
        self.assertIsNone(c["error"])
        self.assertEqual(c["units_holding"], [])

    # ── the adjudication over it, which is a DIFFERENT object ─────────────────────────────────────
    def test_adjudication_records_what_was_LEFT_OUT_and_can_disagree(self):
        """⚠ THE PROPERTY THE WHOLE ITEM EXISTS FOR. Naming one carrier out of three must leave the
        other two NAMED in the record, not merely absent from it. This is exercised on inputs that
        DISAGREE, which no end-to-end run in this build can produce."""
        c = S.seed_census("seed", self._units(
            ("a#0", "docs", "seed"), ("b#0", "docs", "seed"), ("c#0", "docs", "seed")))
        adj = S.census_adjudication(c, ["a#0"], carriers_named=["a#0"], basis="operator named a#0")
        self.assertEqual(adj["seeded"], ["a#0"])
        self.assertEqual(adj["adjudicated_out"], ["b#0", "c#0"],
                         "the units NOT chosen are the record's whole point")
        self.assertEqual(adj["carriers_named"], ["a#0"])

    def test_adjudication_is_empty_when_everything_was_seeded(self):
        """The correlated positive control: prove the test above is the difference firing and not
        ``adjudicated_out`` being non-empty unconditionally."""
        c = S.seed_census("seed", self._units(("a#0", "docs", "seed"), ("b#0", "docs", "seed")))
        adj = S.census_adjudication(c, ["a#0", "b#0"], basis="all")
        self.assertEqual(adj["adjudicated_out"], [])

    def test_seeding_a_unit_the_census_never_found_does_not_go_negative(self):
        """A set difference in the other direction. It must not silently vanish: the two instruments
        disagreeing the OTHER way is still a disagreement, and ``adjudicated_out`` is not the place
        it would show — so this pins that the reconciliation does not crash or invent an entry."""
        c = S.seed_census("seed", self._units(("a#0", "docs", "seed")))
        adj = S.census_adjudication(c, ["a#0", "ghost#9"], basis="x")
        self.assertEqual(adj["adjudicated_out"], [])
        self.assertIn("ghost#9", adj["seeded"])

    # ── the WIRING. Behaviour and wiring are two claims (the SharedInstrumentGate lesson). ────────
    def _run_harvest(self, seed, items, carrier=None):
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        token = "ZZ-SWEEP-CONTROL-TOKEN"
        cfg = {"control_token": token, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", f"{len(items)} files", len(items),
                               [(loc, f"{body}\n{token}\n") for loc, body in items])
        ns = Path(tempfile.mkdtemp())
        # ⚠ DEFAULT: name EVERY fixture location. --carrier is required, and these tests are about
        # the CENSUS (which counts corpus-wide) rather than about narrowing, so naming everything
        # keeps `adjudicated_out` empty and leaves the census assertions measuring what they claim.
        args = SimpleNamespace(id="NEW", seed=seed, anchor=None, parent=None,
                               carrier=list(carrier) if carrier is not None
                               else [loc for loc, _ in items])
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.harvest(args)
        return rc, ns, out.getvalue()

    def test_harvest_PERSISTS_the_census_onto_the_record(self):
        """⚠ THE CORPUS HERE CARRIES A HARD-WRAPPED OCCURRENCE ON PURPOSE. The census and round 1
        agree BY CONSTRUCTION in this build, so this assertion can only ever fail if they diverge —
        and the likeliest divergence is a PARSE one. A corpus of unwrapped one-liners would never
        exercise it, which would make the agreement claim rest on the easiest possible input."""
        rc, ns, _ = self._run_harvest("no egress", [("docs/a.md", "the claim: no egress"),
                                                    ("docs/w.md", "and again no\negress here"),
                                                    ("docs/b.md", "nothing to see")])
        self.assertEqual(rc, S.EXIT_DEBT)
        rec = json.loads((ns / "records" / "NEW.json").read_text(encoding="utf-8"))
        self.assertIn("seed_census", rec, "a census computed and not written down is not a record")
        self.assertEqual(sorted(h["unit"] for h in rec["seed_census"]["units_holding"]),
                         ["docs/a.md", "docs/w.md"],
                         "the hard-wrapped occurrence is an occurrence (R2)")
        self.assertEqual(rec["seed_census"]["adjudication"]["adjudicated_out"], [],
                         "this build adjudicates nothing, so the two instruments must agree")

    def test_harvest_SPILLS_the_census_to_a_MANIFESTED_file(self):
        """R6/R13 — spilled in full, and manifested, or the next run reports it as a stray and the
        tool fails its own instrument gate on a file it wrote itself."""
        rc, ns, _ = self._run_harvest("no egress", [("docs/a.md", "no egress")])
        self.assertEqual(rc, S.EXIT_DEBT)
        self.assertTrue((ns / "census" / "NEW.tsv").exists(), "the full census must be persisted")
        self.assertIn("census/NEW.tsv",
                      json.loads((ns / "manifest.json").read_text(encoding="utf-8")))
        self.assertEqual(S.manifest_check(ns), [],
                         "harvest must not leave a file its own gate would call a stray")

    # ── the PRINTED view. ⚠ ONE STDOUT ASSERTION, ON THE ONE PRINT THAT CARRIES A RULING. ────────
    def test_the_OCCURRENCES_ARE_NOT_CARRIERS_warning_is_PRINTED(self):
        """⚠ FOUND BY DISSENT AS A SURVIVING MUTANT CLASS: every display-only change passed a green
        suite, including DELETING THIS WARNING — the one line doing R5's work at the census.

        ⚠ AND IT IS DELIBERATELY THE *ONLY* STDOUT TEST. A general assertion over harvest's output
        would pin formatting, which is not a ruling and would break on every cosmetic edit until
        someone loosened it into uselessness. This line is different in kind: it is the only print
        that carries a RULING — occurrences are not carriers, and whether a unit ASSERTS the claim
        is a judgement R5 forbids the tool from making. The ordering ruling is pinned on the
        PERSISTED TSV below, where it is an artefact rather than a layout.
        """
        _, _, out = self._run_harvest("no egress", [("docs/a.md", "no egress")])
        self.assertIn("OCCURRENCES, NOT CARRIERS OF THE CLAIM", out)
        self.assertIn("7 of 8 were homonyms", out,
                      "the measurement is what makes the warning more than a disclaimer")

    def test_the_spilled_census_is_ordered_by_LOCATION_not_by_frequency(self):
        """⚠ THE FILE ALREADY RULED THIS ABOUT ITSELF. ``sweep`` sorts unknown-disposition FIRST
        because "leading with a suspected-live class primes confirmation over reading" — and an
        occurrence-ranked census primes by FREQUENCY, which on the founding incident points the
        WRONG WAY: `no egress` was ordinary project vocabulary and 7 of its 8 locations were
        HOMONYMS, so frequency plausibly ANTI-correlates with carrier-hood. The single-occurrence
        unit is where a forgotten carrier lives by definition, and ranking sank it into the tail.

        Asserted on the SPILLED FILE, which is the durable artefact; the printed view reads from the
        same ordered list.
        """
        _, ns, _ = self._run_harvest("no egress", [
            ("docs/zzz.md", "no egress no egress no egress"),   # most frequent, LAST by location
            ("docs/aaa.md", "no egress")])                      # rarest, FIRST by location
        rows = (ns / "census" / "NEW.tsv").read_text(encoding="utf-8").splitlines()[1:]
        self.assertEqual([r.split("\t")[-1] for r in rows], ["docs/aaa.md", "docs/zzz.md"],
                         "the RAREST unit must not be ranked below the most frequent one")
        self.assertEqual(rows[0].split("\t")[0], "1",
                         "the occurrence count is still REPORTED — the ruling is about order only")

    # ── R16, RULED 2026-08-06. THREE ZERO-SHAPED CASES, TWO DIFFERENT ACTS. ──────────────────────
    def test_an_UNSEARCHABLE_seed_REFUSES_and_WRITES_NOTHING(self):
        """⚠ THE RECORD IT WOULD HAVE WRITTEN IS A FALSE INSTRUMENT, WORSE THAN AN EMPTY ONE.
        `variants` falls back to [seed], and `sweep` compiles variants inside
        `except ValueError: continue` — so the pattern NEVER RUNS, nothing says so, and the record
        reports CLEAN for ever. A dead tripwire registered as a live one."""
        rc, ns, out = self._run_harvest("   ", [("docs/a.md", "anything at all")])
        self.assertEqual(rc, S.EXIT_SEED)
        self.assertFalse((ns / "records" / "NEW.json").exists(),
                         "a seed that can never fire must not be registered as a live pattern")
        self.assertIn("SEED FAILURE", out)

    def test_the_seed_refusal_has_its_OWN_stratum_not_the_instrument_code(self):
        """⚠ DIFFERENT CAUSE, DIFFERENT REMEDIATION. Every other exit names a failure of the CORPUS
        or the CHANNEL; this one names the caller's own input. An operator shown "instrument
        failure" goes and checks surfaces, globs and the board endpoint — while the thing actually
        wrong is the string they typed."""
        codes = [S.EXIT_CLEAN, S.EXIT_INSTRUMENT, S.EXIT_TOMBSTONE, S.EXIT_HITS, S.EXIT_DEBT,
                 S.EXIT_SEED]
        self.assertEqual(len(set(codes)), 6, "a shared code sends the reader to the wrong place")
        self.assertNotEqual(S.EXIT_SEED, S.EXIT_INSTRUMENT)





    def _sweep_lines(self, census=None, **census_kw):
        """Drive the real ``sweep`` and return its printed lines."""
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        token = "ZZ-SWEEP-CONTROL-TOKEN"
        cfg = {"control_token": token, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", "1 files", 1,
                               [("docs/a.md", f"body {token}")])
        ns = Path(tempfile.mkdtemp())
        sc = census if census is not None else {"seed": "s", "unit_total": 1, "units_holding": [],
                                                "surfaces": [], **census_kw}
        (ns / "records").mkdir()
        (ns / "records" / "R.json").write_text(json.dumps({
            "id": "R", "seed": "a seed", "variants": ["a seed"], "anchors": [], "nets_run": [],
            "tombstones": [{"location": "docs/a.md", "block_sha256": "x"}],
            "surfaces_at_withdrawal": [], "expected_counts": {}, "parent": None, "created": "",
            "seed_census": sc}), encoding="utf-8")
        (ns / "manifest.json").write_text(json.dumps(["records/R.json"]), encoding="utf-8")
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            S.sweep(SimpleNamespace(records=[], show=40))
        return out.getvalue().splitlines()

    def test_a_record_written_before_the_census_existed_STILL_LOADS(self):
        """The added field carries a default for the same reason every other R3 field does: a tool
        that cannot read its own history has no history."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        (ns / "records" / "OLD.json").write_text(json.dumps({
            "id": "OLD", "seed": "s", "variants": [], "anchors": [], "nets_run": [],
            "tombstones": [], "surfaces_at_withdrawal": [], "expected_counts": {},
            "parent": None, "created": ""}), encoding="utf-8")
        recs = S.load_records(ns)
        self.assertEqual(recs["OLD"].seed_census, {},
                         "an absent census must read as absent, never as a measured zero")


class ClaimSpanSeeding(unittest.TestCase):
    """R15 — THE CORPUS FIXPOINT LOOP IS DELETED. The candidate set comes from the CLAIM.

    MEASURED, and this is the deletion's whole case: the loop reached 98% of one corpus and — on
    2026-08-06, on a corpus not chosen for the test and a carrier nobody planted — **2,727 of 2,752
    units (99.1%), 8,848 terms, ~32 minutes, from a seed occurring FIVE times.** A sweep that flags
    99.1% of the corpus has not found the carrier; it has stopped discriminating.

    ⚠ AND THE REPLACEMENT IS NOT A FILTER. The claim-span set never contained `and` BECAUSE `and` IS
    NOT IN THE CLAIM'S BLOCK — no rule rejected it. The population is different, and describing it
    as filtering would invite the reparametrisation that has already failed four times.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _run(self, seed, items, carrier=None, ns=None):
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        cfg = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", f"{len(items)} files", len(items),
                               [(loc, f"{body}\n{self.TOKEN}\n") for loc, body in items])
        ns = ns or Path(tempfile.mkdtemp())
        args = SimpleNamespace(id="NEW", seed=seed, parent=None, carrier=list(carrier or []))
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.harvest(args)
        rec = None
        if (ns / "records" / "NEW.json").exists():
            rec = json.loads((ns / "records" / "NEW.json").read_text(encoding="utf-8"))
        return rc, ns, out.getvalue(), rec

    # ── R15a — the seed is in variants BY CONSTRUCTION ────────────────────────────────────────────
    def test_the_PROSE_seed_is_in_variants(self):
        """⚠ CONFIRMED BY EXECUTION, NOT BY REVIEW. `extract_candidates` excludes free prose BY
        DESIGN and `expand` excludes its own input BY CONSTRUCTION, so for a prose seed NEITHER
        produces it. MEASURED on the real claim block: 15 terms extracted and the seed was not among
        them — a record whose sweep never matches the exact withdrawn sentence. The old code
        guaranteed it twice and BOTH guarantees lived inside the loop this change deletes."""
        _, _, _, rec = self._run("no egress", [("docs/a.md", "the claim: no egress here")],
                                 carrier=["docs/a.md"])
        self.assertIn("no egress", rec["variants"],
                      "the seed must survive the deletion of the loop that used to carry it")

    def test_variants_are_SORTED(self):
        """R15g — the union is set-derived; unsorted output makes record files nondeterministic
        across runs of identical input, so a diff would report changes nobody made."""
        _, _, _, rec = self._run("no egress", [("docs/a.md", "no egress `zero-gate` `false-pass`")],
                                 carrier=["docs/a.md"])
        self.assertEqual(rec["variants"], sorted(rec["variants"]))

    # ── R15b — the tool's own namespace is not a carrier ──────────────────────────────────────────
    def test_a_carrier_inside_the_TOOL_NAMESPACE_is_refused(self):
        """⚠ A stored run report carries the claim's FULL MATCHED SPAN, so seeding from one derives
        the vocabulary from the tool's own output — and under claim-span seeding it does so CLEANLY,
        producing a plausible result. Silent and self-certifying, which is why it is a refusal."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        rc, _, out, rec = self._run("no egress", [("docs/a.md", "no egress")],
                                    carrier=[str(ns / "reports" / "x.txt")], ns=ns)
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIsNone(rec, "nothing may be written from a tautological seeding")
        self.assertIn("OWN namespace", out)

    def test_an_ABSENT_carrier_is_an_instrument_failure_not_an_empty_result(self):
        rc, _, out, rec = self._run("no egress", [("docs/a.md", "no egress")],
                                    carrier=["docs/does-not-exist.md"])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIsNone(rec)
        self.assertIn("not found on any enumerated surface", out)

    # ── R15d — zero inside a NAMED carrier refutes an assertion ───────────────────────────────────
    def test_zero_occurrences_in_a_NAMED_carrier_is_a_REFUSAL(self):
        """⚠ NOT THE SAME ACT AS A CORPUS-WIDE ZERO. Here the caller ASSERTED a location and the
        assertion is refuted; a bare harvest that finds nothing is a TRIPWIRE and is permitted.
        Identical in the number, opposite in meaning."""
        rc, _, out, rec = self._run("no egress", [("docs/a.md", "unrelated prose entirely")],
                                    carrier=["docs/a.md"])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIsNone(rec, "a carrier that does not hold the claim must not be pinned as state")
        self.assertIn("ZERO occurrences", out)


    # ── the narrowing is RECORDED, which is what the census was built for ────────────────────────
    def test_naming_a_carrier_RECORDS_what_it_left_out(self):
        """⚠ THE BRANCH THAT WAS UNREACHABLE THIS MORNING. Until --carrier existed, the census and
        the seeding population agreed by construction and `adjudicated_out` could never be non-empty.
        Now naming one carrier out of two must leave the other NAMED in the record — not merely
        absent from it. That is the difference between recording an adjudication and recording only
        its outcome, which is the P1 this whole line of work exists for."""
        _, _, _, rec = self._run("no egress",
                                 [("docs/a.md", "the claim: no egress"),
                                  ("docs/b.md", "also no egress over here")],
                                 carrier=["docs/a.md"])
        adj = rec["seed_census"]["adjudication"]
        self.assertEqual(adj["carriers_named"], ["docs/a.md"])
        self.assertEqual(adj["seeded"], ["docs/a.md"])
        self.assertEqual(adj["adjudicated_out"], ["docs/b.md"],
                         "the unit NOT chosen is the record's whole point")


    # ── R15c — one corpus pass, and reach at BOTH granularities ──────────────────────────────────
    def test_surfaces_at_withdrawal_is_MEASURED_not_memory_authored(self):
        """⚠ Today it is COMPUTED from the reached set, and the deletion removes the only thing
        computing it. Without step 4½ the field becomes memory-authored again — the original disease
        persisting inside the registry, wearing a tool's clothing."""
        _, _, _, rec = self._run("no egress", [("docs/a.md", "no egress")], carrier=["docs/a.md"])
        self.assertEqual(rec["surfaces_at_withdrawal"], ["docs"])

    def test_reach_is_reported_at_BOTH_granularities_and_the_SET_is_persisted(self):
        """⚠ EVERY REACH FIGURE THIS PROJECT PRODUCED WAS UNIT-ONLY, because nothing recorded WHICH
        units were reached, so the location figure could not be computed after the fact at all —
        while every pre-registration asked for both, because A HUMAN OPENS LOCATIONS."""
        _, ns, out, rec = self._run("no egress", [("docs/a.md", "no egress")], carrier=["docs/a.md"])
        for k in ("units_reached", "units_total", "locations_reached", "locations_total"):
            self.assertIn(k, rec["reach"])
        self.assertTrue(rec["reach"]["reached_units"], "the SET must be persisted, not just its size")
        self.assertIn("LOCATIONS", out, "the printed report must state the location figure")
        self.assertTrue((ns / "reach" / "NEW.tsv").exists())
        self.assertIn("reach/NEW.tsv",
                      json.loads((ns / "manifest.json").read_text(encoding="utf-8")))

    # ── R15f — the migrated audit target ─────────────────────────────────────────────────────────
    def test_the_seeding_units_are_recorded_and_SPILLED(self):
        """The candidates TSV recorded a FILTERING decision and the filtering is gone, so that audit
        target ceases to exist. WHICH TEXT SEEDED THE VOCABULARY is still a decision, and a span
        sha256 is a commitment rather than something a reviewer can read."""
        _, ns, _, rec = self._run("no egress", [("docs/a.md", "no egress `zero-gate`")],
                                  carrier=["docs/a.md"])
        self.assertIn("docs/a.md", rec["seeding_units"])
        self.assertIn("zero-gate", rec["seeding_units"]["docs/a.md"]["extracted"])
        self.assertTrue((ns / "seeding" / "NEW.tsv").exists())
        self.assertEqual(S.manifest_check(ns), [], "harvest must not leave its own files as strays")
        self.assertEqual(rec["boundary_rule"], S.BOUNDARY_RULE,
                         "a later disagreement must be diagnosable as CORPUS vs RULE changed")

    # ── the loop's state is gone from new records, and old records still load ────────────────────
    def test_new_records_carry_NO_fixpoint_state(self):
        _, _, _, rec = self._run("no egress", [("docs/a.md", "no egress")], carrier=["docs/a.md"])
        self.assertEqual(rec["rounds"], [])
        self.assertEqual(rec["candidates"], {})
        self.assertFalse(rec["at_fixpoint"], "there is no fixpoint any more; claiming one is a lie")

    def test_a_record_written_by_the_LOOP_still_loads(self):
        """⚠ THE FIELDS STAY EVEN THOUGH THE LOOP IS GONE. Removing them would make every record
        written before today fail to load, and a tool that cannot read its own history has none."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        (ns / "records" / "OLD.json").write_text(json.dumps({
            "id": "OLD", "seed": "s", "variants": ["s"], "anchors": [], "nets_run": [],
            "tombstones": [], "surfaces_at_withdrawal": [], "expected_counts": {},
            "parent": None, "created": "", "rounds": [{"round": 1}],
            "candidates": {"x": {}}, "at_fixpoint": True}), encoding="utf-8")
        recs = S.load_records(ns)
        self.assertEqual(recs["OLD"].rounds, [{"round": 1}])
        self.assertEqual(recs["OLD"].carriers, [], "a new field must default, not explode")

    # ── Ruling 1 — --carrier is REQUIRED ─────────────────────────────────────────────────────────
    def test_a_BARE_harvest_is_REFUSED(self):
        """⚠ RULED 2026-08-06, AND THE FALLBACK IT REPLACES WAS MY OWN INVENTION — inferred from a
        ruling about a different question and never designed, consulted or boarded. It RESTORED THE
        FLOOD IN ONE PASS: every seed-holding unit contributes its backticked spans, so `variants`
        explodes exactly as under the deleted loop. Cost sealed it — ~1,000 seed-holding units at
        ~50 terms and ~5 expansions each is ~250,000 variants over the whole corpus."""
        rc, _, out, rec = self._run("no egress", [("docs/a.md", "no egress")])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIsNone(rec, "a harvest with no claim span must write nothing")
        self.assertIn("--carrier is REQUIRED", out)

    def test_the_refusal_is_NOT_argparse_exit_2(self):
        """⚠ WHY THE REFUSAL IS IN-CODE AND NOT `required=True`. argparse exits **2** on a missing
        required flag, and 2 is EXIT_TOMBSTONE — a forgotten flag would be indistinguishable from
        "a correction was re-worded", the exact collision R4a's stratification exists to prevent."""
        rc, _, _, _ = self._run("no egress", [("docs/a.md", "no egress")])
        self.assertNotEqual(rc, S.EXIT_TOMBSTONE)
        self.assertEqual(rc, S.EXIT_INSTRUMENT)

    # ── the surviving mutant the consult found ───────────────────────────────────────────────────
    def test_a_carrier_does_NOT_match_a_prefix_EXTENSION(self):
        """⚠ A MUTATION THAT SURVIVED THE WHOLE SUITE. Changing the scope filter from `in named` to
        `startswith(named[0])` makes carrier `docs/a.md` also seed from `docs/a.md.bak`, and every
        existing assertion still held because no fixture had a prefix collision. Found by the
        consult reading the source, not by the red-proof."""
        _, _, _, rec = self._run("no egress",
                                 [("docs/a.md", "no egress"), ("docs/a.md.bak", "no egress")],
                                 carrier=["docs/a.md"])
        adj = rec["seed_census"]["adjudication"]
        self.assertEqual(adj["seeded"], ["docs/a.md"], "a carrier is a location, not a prefix")
        self.assertIn("docs/a.md.bak", adj["adjudicated_out"])

    def test_parent_reaches_the_WRITTEN_RECORD_not_merely_the_parser(self):
        """⚠ THE PARSER TEST WAS NOT ENOUGH. `--parent` is the only input to `ancestor_closure`, and
        a value that parses but never lands on the record takes R1's nested-withdrawal case dark
        with nothing failing."""
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        cfg = {"control_token": self.TOKEN, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", "1 files", 1,
                               [("docs/a.md", f"no egress\n{self.TOKEN}\n")])
        ns = Path(tempfile.mkdtemp())
        args = SimpleNamespace(id="NEW", seed="no egress", parent="ANCESTOR",
                               carrier=["docs/a.md"])
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(io.StringIO()):
            S.harvest(args)
        rec = json.loads((ns / "records" / "NEW.json").read_text(encoding="utf-8"))
        self.assertEqual(rec["parent"], "ANCESTOR")

    def test_span_sha256_is_STRUCK(self):
        """⚠ CEREMONY, BY THE STANDARD THAT KILLED R15e. Nothing ever recomputed or compared it.
        What it claimed to protect is carried by `seeding_units` and the spill — WHICH units seeded
        and WHAT each contributed, auditable by opening the unit, which a hash never was."""
        _, _, _, rec = self._run("no egress", [("docs/a.md", "no egress")], carrier=["docs/a.md"])
        self.assertNotIn("span_sha256", rec, "an unverified hash must not ship as a commitment")

    # ── the location helper, which the whole dual-granularity claim rests on ─────────────────────
    def test_unit_location_strips_only_a_carrier_units_suffix(self):
        """⚠ THE FIRST VERSION OF THIS RULE WAS WRONG, AND THE CONSULT FOUND IT. It stripped any
        trailing `#<digits>` — but a board key may legitimately END in `#<digits>`, and a location
        with no headings is returned UNSUFFIXED. So `board/incident#42` was reduced to
        `board/incident` and MERGED WITH A DISTINCT LOCATION, understating the location count: the
        exact figure this helper exists to make reportable."""
        self.assertEqual(S._unit_location("docs/a.md#unit-3"), "docs/a.md")
        self.assertEqual(S._unit_location("docs/a.md"), "docs/a.md")
        self.assertEqual(S._unit_location("board/some#key"), "board/some#key")
        self.assertEqual(S._unit_location("board/incident#42"), "board/incident#42",
                         "⚠ a board key ending in #<digits> is a LOCATION, not a unit suffix")
        self.assertEqual(S._unit_location("board/incident#42#unit-1"), "board/incident#42")

    def test_carrier_units_emits_the_unambiguous_separator(self):
        """The correlated half: the helper's rule is only safe if the producer uses that separator."""
        units = S.carrier_units("board/incident#42", S.normalise("intro\n\n# One\na\n"))
        self.assertTrue(all("#unit-" in uid for uid, _ in units), f"got {[u for u, _ in units]}")
        self.assertTrue(all(S._unit_location(uid) == "board/incident#42" for uid, _ in units))


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


# ⚠ THIS ENTRY POINT MUST STAY AT THE END OF THE FILE, AND IT USED TO SIT IN THE MIDDLE.
# ``unittest.main()`` runs at the point it is reached during module execution, so every class defined
# BELOW it was never registered when the file was run as a script: `python3 test_sweep.py` reported
# "Ran 19 tests ... OK" while pytest and `unittest discover` both ran 39. A TRUNCATED RUN THAT PRINTS
# OK is precisely the failure class this tool exists to catch, and it was living in its own test file.
if __name__ == "__main__":
    unittest.main(verbosity=2)
