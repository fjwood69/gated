#!/usr/bin/env python3
"""The shared instrument gate and the count pins it enforces.

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


class ExpectedCountPins(unittest.TestCase):
    """R10 — harvest wrote pins onto the record and sweep enforced only config, so the record's pin
    was INERT: the same half-built shape R14 had, found in the same dissent round.

    ⚠⚠ AND THESE TESTS WERE THEMSELVES THE DEFECT UNTIL 2026-08-07. They computed ``max()`` IN THE
    TEST BODY and asserted on the result, touching no production code but the ``Record``
    constructor. **Deleting every line of pin-merging logic from sweep.py left them green** — so the
    fix for an inert record pin was pinned by an inert test, and no mutation of the module could
    ever have implicated them. Third instance of the shape this file's own header condemns, found by
    a dissent that read the suite rather than ran it.

    They now drive ``instrument_gate``.
    """

    TOKEN = "ZZ-SWEEP-CONTROL-TOKEN"

    def _gate(self, count, cfg_floor=None, record_pin=None):
        import tempfile
        cfg = {"control_token": self.TOKEN, "surfaces": [],
               "expected_counts": {"docs": cfg_floor} if cfg_floor is not None else {}}
        items = [(f"docs/f{i}.md", f"body {self.TOKEN}") for i in range(count)]
        surf = S.SurfaceResult("docs", "filesystem", f"{count} files", count, items)
        records, selected = {}, []
        if record_pin is not None:
            records = {"OLD": S.Record(id="OLD", seed="", variants=[], anchors=[], nets_run=[],
                                       tombstones=[], surfaces_at_withdrawal=[],
                                       expected_counts={"docs": record_pin}, parent=None,
                                       created="")}
            selected = ["OLD"]
        errs, _ = S.instrument_gate([surf], cfg, records, selected, Path(tempfile.mkdtemp()))
        return errs

    def test_a_record_pin_TIGHTENS_a_config_floor(self):
        """cfg says >=400, the record says >=412, the corpus has 405. The strictest pin is the
        record's, so this must FAIL — and it can only fail if production merged them."""
        errs = self._gate(count=405, cfg_floor=400, record_pin=412)
        self.assertTrue(any("COUNT DROPPED" in e for e in errs),
                        f"a record pin must be able to TIGHTEN the floor, got {errs}")
        self.assertTrue(any("record pin" in e for e in errs),
                        "and the message must name WHICH pin bound, or the operator cannot act")

    def test_a_record_pin_can_never_LOOSEN_a_config_floor(self):
        """cfg says >=400, the record says >=10, the corpus has 350. Registering a record must not
        be a route to lowering a floor already in force."""
        errs = self._gate(count=350, cfg_floor=400, record_pin=10)
        self.assertTrue(any("COUNT DROPPED" in e for e in errs), f"got {errs}")
        self.assertTrue(any("config" in e for e in errs), "the CONFIG floor is the one that bound")

    def test_the_CONFIG_floor_is_enforced_with_NO_record_present(self):
        """⚠ THE COVERAGE HOLE THE DISSENT NAMED. Every other pin test drives a RECORD pin with an
        empty cfg, so a mutant reading only record pins and ignoring config pins was killed by
        nothing at all."""
        errs = self._gate(count=350, cfg_floor=400)
        self.assertTrue(any("COUNT DROPPED" in e for e in errs), f"got {errs}")

    def test_a_corpus_AT_the_floor_PASSES(self):
        """⚠ THE CORRELATED POSITIVE. Without it every test above passes on a gate that rejects
        every enumeration, which certifies nothing. The comparison is `<`, not `<=`."""
        self.assertEqual(self._gate(count=400, cfg_floor=400, record_pin=400), [])

    def test_NO_pins_anywhere_PASSES(self):
        """Second correlated negative: an unpinned surface must not be red merely for being
        unpinned, or the first run of any new surface is a failure."""
        self.assertEqual(self._gate(count=3), [])


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
