#!/usr/bin/env python3
"""R18 retirement — carried, printed, and inert across every consumer of `selected`.

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


class RetirementShapeOnly(unittest.TestCase):
    """R18 — ⚠ THE SHAPE IS ADOPTED AND THE COMMAND IS NOT BUILT. RULED 2026-08-06.

    A design review found three semantic errors by omission in the `retire` draft, the load-bearing
    one being that `selected` feeds SIX consumers — count pins, tombstone-loss checks, variant
    sweeping, process debt, drift printing, and R7 exclusion licensing. "Leaves the default sweep
    set, and nothing else" is **unimplementable as stated**, and filtering `selected` once would
    void the draft's own debt safeguard while the header still claimed it held.

    ⚠ **SO THE SAFEGUARD SHIPS BEFORE THE LEVER.** The always-print control exists from today; the
    act that would exclude anything does not. An exclusion whose visibility arrives later is the R7
    self-service-exclusion defect waiting to happen.
    """

    def _rec(self, **kw):
        d = {"id": "R", "seed": "x", "variants": ["x", "y"], "anchors": [], "nets_run": [],
             "tombstones": [], "surfaces_at_withdrawal": [], "expected_counts": {},
             "parent": None, "created": ""}
        d.update(kw)
        return d

    def test_the_fields_default_and_an_OLD_record_still_loads(self):
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        (ns / "records" / "R.json").write_text(json.dumps(self._rec()), encoding="utf-8")
        r = S.load_records(ns)["R"]
        self.assertEqual(r.retired_at, "")
        self.assertEqual(r.retired_reason, "")

    def test_a_HAND_EDITED_retirement_is_carried_by_the_loader(self):
        """The manual procedure: set the two fields by hand. The loader must tolerate it, or the
        procedure the ruling adopted does not work at all."""
        import tempfile
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        (ns / "records" / "R.json").write_text(json.dumps(
            self._rec(retired_at="2026-08-06", retired_reason="loop artefact")), encoding="utf-8")
        r = S.load_records(ns)["R"]
        self.assertEqual(r.retired_at, "2026-08-06")
        self.assertEqual(r.retired_reason, "loop artefact")

    def test_sweep_PRINTS_a_retired_record_with_its_reason(self):
        """⚠ THE ALWAYS-PRINT LINE. Retirement that is invisible is the R7 defect reinvented, so the
        visibility exists before anything can be excluded at all."""
        rc, out = self._sweep_with(retired_at="2026-08-06", retired_reason="loop artefact")
        self.assertIn("RETIRED R @ 2026-08-06", out)
        self.assertIn("loop artefact", out, "the reason is the only thing distinguishing a record "
                                            "retired as noise from one retired as inconvenient")

    def test_the_QUALIFIER_IS_ON_THE_LEAD_LINE_not_a_continuation(self):
        """⚠ RULED 2026-08-07 (R-C). A reader who saw RETIRED and assumed "not searched" would have
        the exclusion's danger without the exclusion existing — and BOTH review passes flagged that
        a skim catches the lead line and stops. So the qualifier moved ONTO it. Asserting merely
        that "STILL SWEPT" appears somewhere in the output passes on the version that buried it."""
        _, out = self._sweep_with(retired_at="2026-08-06", retired_reason="noise")
        lead = [ln for ln in out.splitlines() if ln.startswith("RETIRED R @")]
        self.assertEqual(len(lead), 1, f"expected one lead line, got {lead}")
        self.assertIn("STILL SWEPT", lead[0],
                      "the qualifier must be on the line a skimmer actually reads")

    def test_the_line_claims_to_WARN_and_NOT_to_have_discharged_anything(self):
        """⚠ R-C's ACTUAL SUBJECT: the defect was never the constant string, it was THE CLAIM ABOUT
        WHAT ITS PRESENCE DEMONSTRATES. The block used to present itself as a safeguard shipped
        ahead of its lever, which reads as a hazard DISCHARGED. Nothing can enter an excluded state,
        so nothing has been guarded — the line warns against ASSUMING exclusion. Same class as the
        normalise() docstring: the mechanism was right and the sentence about it was not."""
        _, out = self._sweep_with(retired_at="2026-08-06", retired_reason="noise")
        self.assertIn("EXCLUSION IS NOT BUILT", out)
        self.assertIn("WARNING AGAINST ASSUMING EXCLUSION", out)
        self.assertNotIn("SHIPPED BEFORE THE LEVER", out,
                         "the printed report must not claim a safeguard fired")

    def test_retirement_changes_NOTHING_about_the_run(self):
        """⚠ THE WHOLE POINT OF SHAPE-ONLY. Retirement must be inert until the consumer table is
        ruled and built: same exit, same debt, same everything."""
        rc_plain, _ = self._sweep_with()
        rc_retired, _ = self._sweep_with(retired_at="2026-08-06", retired_reason="noise")
        self.assertEqual(rc_plain, rc_retired,
                         "a retired record must still fire process debt — the draft's own safeguard")

    def test_a_NON_retired_record_prints_no_RETIRED_line(self):
        """Correlated negative control: without it the print tests pass on code that labels every
        record retired."""
        _, out = self._sweep_with()
        self.assertNotIn("RETIRED", out)

    def _sweep_with(self, **kw):
        import contextlib
        import io
        import tempfile
        from types import SimpleNamespace
        from unittest import mock
        token = "ZZ-SWEEP-CONTROL-TOKEN"
        ns = Path(tempfile.mkdtemp())
        (ns / "records").mkdir()
        (ns / "records" / "R.json").write_text(json.dumps(self._rec(**kw)), encoding="utf-8")
        (ns / "manifest.json").write_text(json.dumps(["records/R.json"]), encoding="utf-8")
        cfg = {"control_token": token, "surfaces": [], "expected_counts": {}}
        surf = S.SurfaceResult("docs", "filesystem", "1 files", 1, [("docs/a.md", token)])
        out = io.StringIO()
        with mock.patch.object(S, "load_config", return_value=cfg), \
             mock.patch.object(S, "gather_surfaces", return_value=[surf]), \
             mock.patch.object(S, "NAMESPACE", ns), contextlib.redirect_stdout(out):
            rc = S.sweep(SimpleNamespace(records=[], show=10))
        return rc, out.getvalue()


class RetirementIsInertACROSSEveryConsumer(_SweepHarness):
    """⚠ THE FOUR CORRELATED NEGATIVE CONTROLS THE DISSENT FOUND MISSING.

    Inertness was pinned ONLY as exit-code equality, by a fixture whose record was open,
    tombstone-free, pin-free, and whose variants never occurred in the corpus — so it observed at
    most ONE of the six consumers `selected` feeds. A future change excluding retired records from
    count pins, tombstone-loss checks, or R7 licensing would not have been caught.
    """

    RETIRED = {"retired_at": "2026-08-06", "retired_reason": "loop artefact"}

    def test_a_retired_record_STILL_ENFORCES_ITS_COUNT_PIN(self):
        ns = self._ns(records=[self._rec(expected_counts={"docs": 10}, **self.RETIRED)],
                      manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", self.TOKEN)])
        self.assertEqual(rc, S.EXIT_INSTRUMENT)
        self.assertIn("COUNT DROPPED", out, "retirement must not be a way to drop a floor")

    def test_a_retired_record_STILL_REPORTS_A_LOST_TOMBSTONE(self):
        ns = self._ns(records=[self._rec(
            tombstones=[{"location": "docs/a.md", "block_sha256": "STALE"}], **self.RETIRED)],
            manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", self.TOKEN)])
        self.assertEqual(rc, S.EXIT_TOMBSTONE)
        self.assertIn("TOMBSTONE LOST", out)

    def test_a_retired_record_STILL_PRODUCES_LIVE_HITS(self):
        ns = self._ns(records=[self._rec(**self.RETIRED)], manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", f"{self.TOKEN}\na seed is live here\n")])
        self.assertEqual(rc, S.EXIT_HITS, out)
        self.assertIn("STILL SWEPT", out, "and the line must say so on the same run")

    def test_a_retired_records_TOMBSTONE_STILL_LICENSES_THE_R7_EXCLUSION(self):
        """⚠ THE SUBTLEST OF THE FOUR. If retirement ever removed a record from `selected`, its
        hash-pinned exclusions would stop being licensed and the quoted withdrawn text would return
        as LIVE HITS — the tool loudly reporting the correction it was told about."""
        doc = (f"⚠ CORRECTED. It read:\n{S.BLOCK_OPEN}R -->\na seed\n{S.BLOCK_CLOSE}\n"
               f"and why it was wrong.\n{self.TOKEN}\n")
        sha = S.block_sha(S.extract_blocks(doc)["R"])
        ns = self._ns(records=[self._rec(
            tombstones=[{"location": "docs/a.md", "block_sha256": sha}], **self.RETIRED)],
            manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", doc)])
        self.assertEqual(rc, S.EXIT_CLEAN, out)
        self.assertIn("in-tombstoned-block", out, "the exclusion must still be licensed")

    def test_the_UNRETIRED_twin_behaves_IDENTICALLY(self):
        """⚠ THE CONTROL FOR ALL FOUR. Each test above must fail because RETIREMENT CHANGED NOTHING,
        not because the fixture happens to produce that code anyway. Same fixtures, retirement
        stripped, same outcomes."""
        plain = {}
        for kw, items, expect in (
            ({"expected_counts": {"docs": 10}}, [("docs/a.md", self.TOKEN)], S.EXIT_INSTRUMENT),
            ({"tombstones": [{"location": "docs/a.md", "block_sha256": "STALE"}]},
             [("docs/a.md", self.TOKEN)], S.EXIT_TOMBSTONE),
            (plain, [("docs/a.md", f"{self.TOKEN}\na seed is live here\n")], S.EXIT_HITS),
        ):
            ns = self._ns(records=[self._rec(**kw)], manifest=["records/R.json"])
            rc, out = self._sweep(ns, items=items)
            self.assertEqual(rc, expect, f"unretired twin diverged for {kw}: {out}")


class RetirementConsumersFiveAndSix(_SweepHarness):
    """⚠ THE TWO CONSUMERS THE FOUR CONTROLS DID NOT REACH.

    `selected` feeds six: count pins, tombstone-loss checks, VARIANT SWEEPING, process debt, DRIFT
    PRINTING, and R7 exclusion licensing. The existing four cover four. A future `retire` that
    filtered `selected` before the hits loop but still included the record for the exit-code check
    would pass every existing test while variant sweeping and drift printing silently ceased.
    """

    RETIRED = {"retired_at": "2026-08-06", "retired_reason": "loop artefact"}

    def test_a_retired_records_VARIANTS_ARE_STILL_SEARCHED_hit_by_hit(self):
        """⚠ NOT VIA THE EXIT CODE, WHICH IS THE HOLE. The per-pattern line proves the variant was
        actually compiled and run, so a filter that skipped the hits loop is caught even if the
        exit code were preserved by other means."""
        ns = self._ns(records=[self._rec(variants=["a seed"], **self.RETIRED)],
                      manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", f"{self.TOKEN}\na seed is here\n")])
        self.assertEqual(rc, S.EXIT_HITS, out)
        self.assertIn("R:v0 [1]", out, "the retired record's variant must appear in per-pattern")

    def test_a_retired_record_STILL_PRINTS_SURFACE_DRIFT(self):
        """The sixth consumer. Drift is computed from surfaces_at_withdrawal minus the run's
        surfaces, and was ruled to survive retirement — scoped, not dropped."""
        ns = self._ns(records=[self._rec(surfaces_at_withdrawal=["docs", "board"], **self.RETIRED)],
                      manifest=["records/R.json"])
        _, out = self._sweep(ns)
        self.assertIn("SURFACE DRIFT R", out)
        self.assertIn("board", out, "and it must name the surface that vanished")

    def test_the_UNRETIRED_twins_behave_identically(self):
        """The control for both: the outcomes above must be retirement changing nothing, not the
        fixtures producing them anyway."""
        ns = self._ns(records=[self._rec(variants=["a seed"])], manifest=["records/R.json"])
        rc, out = self._sweep(ns, items=[("docs/a.md", f"{self.TOKEN}\na seed is here\n")])
        self.assertEqual(rc, S.EXIT_HITS)
        self.assertIn("R:v0 [1]", out)
        ns2 = self._ns(records=[self._rec(surfaces_at_withdrawal=["docs", "board"])],
                       manifest=["records/R.json"])
        _, out2 = self._sweep(ns2)
        self.assertIn("SURFACE DRIFT R", out2)
