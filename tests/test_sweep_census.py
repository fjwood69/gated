#!/usr/bin/env python3
"""The seed census, claim-span seeding, and anchors as an OUTPUT of harvest.

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
from _sweep_harness import S, json, unittest, Path


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
        ruling about a different question and never designed, consulted or boarded.

        The mechanism is the argument: every seed-holding unit would contribute its backticked
        spans, so `variants` grows with the corpus rather than with the claim — the shape the
        deleted loop had.

        ⚠ AND THE NUMBER THAT USED TO BE HERE IS WITHDRAWN. It read "it RESTORED THE FLOOD IN ONE
        PASS ... ~1,000 seed-holding units at ~50 terms and ~5 expansions each is ~250,000 variants
        over the whole corpus", phrased as though sealed by measurement. IT WAS AN ARITHMETIC
        ESTIMATE FROM THREE ROUNDED GUESSES, AND NOTHING EVER RAN IT. This test asserts only that
        the bare harvest is REFUSED; it measures no variant count at all.

        That is the stated-reason-stronger-than-mechanism defect — live in the file that condemns
        it, three classes away from the NBSP test written to record the same failure. Found by
        consult 2026-08-07. **The refusal stands on the mechanism; it never needed the number.**
        """
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
        # ⚠ THE ANCESTOR MUST NOW EXIST. Before 2026-08-07 this fixture named a parent that was
        # never registered and harvest accepted it — which is precisely the dangling edge
        # `ParentIsValidated` closes. The test passed while demonstrating the defect.
        (ns / "records").mkdir()
        (ns / "records" / "ANCESTOR.json").write_text(json.dumps({
            "id": "ANCESTOR", "seed": "s", "variants": ["s"], "anchors": [], "nets_run": [],
            "tombstones": [{"location": "docs/a.md", "block_sha256": "x"}],
            "surfaces_at_withdrawal": [], "expected_counts": {}, "parent": None,
            "created": ""}), encoding="utf-8")
        (ns / "manifest.json").write_text(json.dumps(["records/ANCESTOR.json"]), encoding="utf-8")
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
