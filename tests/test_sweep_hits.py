#!/usr/bin/env python3
"""Hit disposition — R5 never-adjudicates, R7 registration-keyed exclusion, R14 the undisposed diff.

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
from _sweep_harness import S, unittest, Path


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
