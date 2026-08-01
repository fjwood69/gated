"""THE SEAM, tested — not either end of it.

⚠ WHY THIS FILE EXISTS. The anti-circularity design was entirely unwired and INVISIBLE, because each
module's tests passed locally: ``pin.py`` declared the authority, ``receipt.py`` never imported it,
and every binding lived in code that had not been written. Fixing the wiring without fixing the
DISCHARGE would leave the same blind spot pointed at a new seam.

So every receipt below is INDIVIDUALLY VALID — it satisfies ``Receipt`` completely, its verdict
follows from its own operands, and nothing about it is malformed. Each is refused only by the seam:
by ``CompletedRun`` checking it against the pin. If these tests pass without having been seen red,
the wiring is asserted by construction and the construction is untested — which is the shape the
whole increment exists to refuse.
"""
from __future__ import annotations

import pathlib
import unittest

from demo import pin
from demo.receipt import (
    CompletedRun,
    CorpusIdentity,
    ExpectationKey,
    Instrument,
    InstrumentInvalid,
    MemberPath,
    PinBinding,
    PinInconsistent,
    Receipt,
    RunHeader,
    SubjectPin,
    verify_measured_against_pin,
)

NONCE = "0123456789abcdef0123456789abcdef"
INSTRUMENT = Instrument("gate0000", "sha256:image", "podman", "4.9.3", "sealed", "witness-503")

SWALLOW = MemberPath("fixtures/retry-swallow-v2/main.py")
GOOD = MemberPath("fixtures/retry-good-v2/main.py")


def _binding(**over: object) -> PinBinding:
    """The pin's OWN data, not a reconstruction of it.

    ⚠ NOT a comprehension over ``EXPECTED_EGRESS``. The previous version built the member paths with
    ``f"fixtures/{m}/main.py"`` — the SAME derive-by-string defect as the one in ``drifted()``,
    committed one level up in the test that was supposed to catch it."""
    kw: dict[str, object] = dict(
        corpus_digest=pin.CORPUS_SHA256,
        subject_rows=frozenset(
            SubjectPin(MemberPath(m), ExpectationKey(k), pin.EXPECTED_EGRESS[k])
            for m, k in pin.SUBJECT_ROWS),
        expected_cardinality=pin.SUBJECT_CARDINALITY,
        control_member=MemberPath(pin.CONTROL_NAME),
        control_floor=pin.CONTROL_EXPECTED_EGRESS,
        positive_member=MemberPath(pin.POSITIVE_NAME),
        positive_expected=pin.POSITIVE_EXPECTED_EGRESS,
        policy_expectation=pin.ADMIT_AT_OR_ABOVE,
        expectation_provenance=pin.EXPECTATION_PROVENANCE,
    )
    kw.update(over)
    return PinBinding(**kw)  # type: ignore[arg-type]


BINDING = _binding()


def _spec(member: str, measured: int, *, kind: str = "subject", key: str | None = None,
          digest: str = "", expectation: int | None = None, nonce: str = NONCE,
          counter_ok: bool = True, events: int | None = None,
          force_no_key: bool = False) -> dict[str, object]:
    """A row's content, before it is chained. ``key`` is looked up in the PINNED pairs rather than
    derived from the path, so no test silently reintroduces the string transform.

    ⚠ ``force_no_key`` exists because the default LOOKUP swallowed an explicit ``key=None``: the test
    for a missing key was handed the correct one and passed for the wrong reason. A helper whose
    default silently repairs the condition under test is an instrument fault, not a passing test."""
    if key is None and kind == "subject" and not force_no_key:
        key = next((k for m, k in pin.SUBJECT_ROWS if m == member), None)
    exp = pin.ADMIT_AT_OR_ABOVE if expectation is None else expectation
    n_events = measured if events is None else events
    return dict(
        run_nonce=nonce, row=member, kind=kind,
        corpus=CorpusIdentity("demo-corpus-v1", digest or pin.CORPUS_SHA256, MemberPath(member),
                              "sha256:member",
                              expectation_key=None if key is None else ExpectationKey(key)),
        instrument=INSTRUMENT, measured=measured,
        boundary_events=tuple(f"attempt-{i}" for i in range(n_events)),
        expectation=exp,
        verdict=("ADMIT" if measured >= exp else "BLOCK") if kind == "subject" else "CONTROL",
        expectation_provenance=pin.EXPECTATION_PROVENANCE,
        counter_readable_at_end=counter_ok)


def _chain(header: RunHeader, specs: list[dict[str, object]]) -> list[Receipt]:
    """Seal rows IN ORDER, each committing to the previous sealed object. Row 1 commits to the
    header — which is why the header exists: without it row 1 is unanchored and a uniformly stale
    run is internally consistent."""
    out: list[Receipt] = []
    prior = header.digest()
    for s in specs:
        r = Receipt(prior_digest=prior, **s)  # type: ignore[arg-type]
        out.append(r)
        prior = r.digest()
    return out


def _complete_specs() -> list[dict[str, object]]:
    """A set that SHOULD construct — including the positive control, without which every refusal
    below is indistinguishable from a constructor that refuses everything."""
    specs = [_spec(m, pin.EXPECTED_EGRESS[k]) for m, k in sorted(pin.SUBJECT_ROWS)]
    specs.append(_spec(pin.CONTROL_NAME, pin.CONTROL_EXPECTED_EGRESS, kind="control"))
    specs.append(_spec(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS, kind="positive"))
    return specs


def _header(binding: PinBinding | None = None, nonce: str = NONCE) -> RunHeader:
    return RunHeader(nonce, INSTRUMENT, (binding or BINDING).digest())


def _run(specs: list[dict[str, object]] | None = None, binding: PinBinding | None = None,
         header: RunHeader | None = None) -> CompletedRun:
    b = binding or BINDING
    h = header or _header(b)
    return CompletedRun(h, _chain(h, specs if specs is not None else _complete_specs()), b)


def _replacing(member: str, replacement: dict[str, object]) -> list[dict[str, object]]:
    """A complete set with ONE row swapped, addressed BY MEMBER. Positional ``[0] =`` was silently
    wrong once row order became the pin's order: it swapped a DIFFERENT row, creating a duplicate and
    a missing member, so the test still raised — passing for the wrong reason."""
    out = [s for s in _complete_specs() if s["row"] != member]
    assert len(out) == len(_complete_specs()) - 1, f"{member!r} was not in the complete set"
    out.append(replacement)
    return out


class TheCompleteSetConstructs(unittest.TestCase):
    def test_the_positive_control(self) -> None:
        run = _run()
        self.assertEqual(len(run.subjects), pin.SUBJECT_CARDINALITY)
        self.assertEqual(run.drifted(), [], "a clean set reported drift")


class ThePinMustBeWellFormed(unittest.TestCase):
    """Q3's real home. Every downstream check is a control over MALFORMED pins; a control whose
    precondition nothing enforces is the claim-not-a-control shape."""

    def test_an_EMPTY_pin_is_refused(self) -> None:
        """P1-1. With zero pinned rows every set check passes trivially — set() == set() — and the
        drift report returns [] over ZERO comparisons: 'everything agrees', measured on nothing."""
        with self.assertRaises(PinInconsistent) as caught:
            _binding(subject_rows=frozenset(), expected_cardinality=0)
        self.assertIn("ZERO subject rows", str(caught.exception))

    def test_a_pin_whose_CARDINALITY_disagrees_with_its_rows_is_refused(self) -> None:
        with self.assertRaises(PinInconsistent):
            _binding(expected_cardinality=4)

    def test_ONE_member_as_BOTH_controls_is_refused(self) -> None:
        """It demands that a single artifact read both 0 and 1. Unsatisfiable, and previously
        constructed without complaint."""
        with self.assertRaises(PinInconsistent) as caught:
            _binding(control_member=MemberPath("same"), positive_member=MemberPath("same"))
        self.assertIn("Unsatisfiable", str(caught.exception))

    def test_a_control_that_is_ALSO_a_subject_is_refused(self) -> None:
        with self.assertRaises(PinInconsistent):
            _binding(control_member=SWALLOW)

    def test_a_NON_POSITIVE_positive_control_is_refused(self) -> None:
        """A second zero control brackets one direction twice — the exact half-floor this control
        exists to close."""
        with self.assertRaises(PinInconsistent) as caught:
            _binding(positive_expected=0)
        self.assertIn("half-floor", str(caught.exception))

    def test_a_pin_that_is_not_a_BIJECTION_is_refused(self) -> None:
        rows = {SubjectPin(SWALLOW, ExpectationKey("k1"), 1),
                SubjectPin(SWALLOW, ExpectationKey("k2"), 2)}
        with self.assertRaises(PinInconsistent):
            _binding(subject_rows=frozenset(rows), expected_cardinality=2)


class ThePinAndTheCorpusAreCrossChecked(unittest.TestCase):
    """``PinInconsistent`` was ornamental for a full increment — defined, documented, and raised
    NOWHERE, while ``pin.py``'s docstring already claimed this cross-check existed."""

    def test_agreement_passes(self) -> None:
        verify_measured_against_pin(dict(pin.EXPECTED_EGRESS), BINDING)

    def test_a_DISAGREEING_frozen_count_is_PinInconsistent_not_drift(self) -> None:
        m = dict(pin.EXPECTED_EGRESS)
        m["retry-good-v2"] = 99
        with self.assertRaises(PinInconsistent) as caught:
            verify_measured_against_pin(m, BINDING)
        self.assertIn("disagree on frozen counts", str(caught.exception))

    def test_a_key_the_CORPUS_records_but_the_pin_does_not_demand_is_refused(self) -> None:
        """The one-directional version let the corpus carry frozen claims never compared."""
        m = dict(pin.EXPECTED_EGRESS)
        m["a-claim-nothing-measures"] = 7
        with self.assertRaises(PinInconsistent) as caught:
            verify_measured_against_pin(m, BINDING)
        self.assertIn("recorded-but-unpinned", str(caught.exception))

    def test_a_key_the_PIN_demands_but_the_corpus_omits_is_refused(self) -> None:
        m = dict(pin.EXPECTED_EGRESS)
        del m["retry-good-v2"]
        with self.assertRaises(PinInconsistent) as caught:
            verify_measured_against_pin(m, BINDING)
        self.assertIn("pinned-but-unrecorded", str(caught.exception))


class TheSealChainAnchorsTheRun(unittest.TestCase):
    """LINKAGE, NOT ATTESTATION. This makes tampering WITHIN a run detectable; it says nothing about
    who sealed it or when."""

    def test_a_REMOVED_row_breaks_the_chain(self) -> None:
        h = _header()
        rows = _chain(h, _complete_specs())
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(h, rows[:2] + rows[3:], BINDING)
        self.assertIn("seal chain is broken", str(caught.exception))

    def test_a_REORDERED_row_breaks_the_chain(self) -> None:
        h = _header()
        rows = _chain(h, _complete_specs())
        swapped = [rows[1], rows[0]] + list(rows[2:])
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(h, swapped, BINDING)
        self.assertIn("seal chain is broken", str(caught.exception))

    def test_an_UNANCHORED_first_row_is_refused(self) -> None:
        """Row 1 must commit to the header. This is the case a chain starting at row 1 cannot see."""
        h = _header()
        rows = _chain(h, _complete_specs())
        orphan = Receipt(**{**_complete_specs()[0], "prior_digest": "0" * 64})  # type: ignore[arg-type]
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(h, [orphan] + list(rows[1:]), BINDING)
        self.assertIn("seal chain is broken", str(caught.exception))

    def test_a_header_committing_to_ANOTHER_binding_is_refused(self) -> None:
        """The authority may not change after the run starts."""
        other = _binding(policy_expectation=3)
        h = RunHeader(NONCE, INSTRUMENT, other.digest())
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(h, _chain(h, _complete_specs()), BINDING)
        self.assertIn("authority changed", str(caught.exception))

    def test_receipts_from_ANOTHER_run_are_refused(self) -> None:
        h = _header()
        specs = _complete_specs()
        specs[0] = _spec(SWALLOW, 1, nonce="f" * 32)
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(h, _chain(h, specs), BINDING)
        self.assertIn("do not all belong", str(caught.exception))


class TheProbesAreNamedForWhatTheyMeasure(unittest.TestCase):
    """⚠ NEITHER OF THESE IS THE WITNESS, and the field names now say so. A single
    ``witness_verified: bool`` was drafted and REJECTED before any seal: its root was the harness, so
    a sceptic could not recheck it, and it collapsed seal posture, counter liveness, and the
    witness's actual behaviour into one word."""

    def test_there_is_NO_unfalsifiable_seal_field(self) -> None:
        """A ``seal_verified_at_start`` field was drafted and REMOVED: the runner could only ever
        set it to the literal True, because ``prepare()`` RAISES on a leak. An unfalsifiable field
        carries zero bits while reading as an affirmative claim."""
        import dataclasses
        self.assertNotIn("seal_verified_at_start", {f.name for f in dataclasses.fields(Receipt)})

    def test_an_UNREADABLE_COUNTER_at_row_end_is_INSTRUMENT_INVALID(self) -> None:
        """``egress_attempts is None`` means the number attributed to the row is not a measurement."""
        specs = _replacing(GOOD, _spec(GOOD, 3, counter_ok=False))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("UNREADABLE counter", str(caught.exception))

    def test_the_KNOWN_GAP_is_recorded_rather_than_faked(self) -> None:
        """THE FAILURE NEITHER PROBE SEES: a witness that serves a success mid-row. The escape probe
        still passes (posture unchanged), the counter is still readable, and the row measures 1
        instead of 3 — fresh receipts, consistent digests, valid chain, false interpretation.

        The field that would close it is per-event response codes. It is ABSENT because the boundary
        observer records only a count; deriving codes from the configured mode would be computation
        presented as measurement. This test exists so the gap cannot be quietly closed by a field
        that asserts rather than measures."""
        import dataclasses
        fields = {f.name for f in dataclasses.fields(Receipt)}
        self.assertNotIn("witness_verified", fields,
                         "a single boolean collapses three different things and its root is the "
                         "harness — a sceptic cannot recheck it")
        self.assertNotIn("seal_verified_at_start", fields, "unfalsifiable on every prod path")
        self.assertIn("counter_readable_at_end", fields)
        src = (pathlib.Path(__file__).resolve().parent.parent / "demo" / "receipt.py").read_text()
        self.assertIn("witness_codes", src,
                      "the known gap must stay NAMED in the contract; deleting the note would make "
                      "the absence look like a decision nobody had to make")


class TheFloorIsTwoSided(unittest.TestCase):
    """Checking only ``measured != 0`` detects OVER-reporting."""

    def test_a_DEAD_counter_is_refused_rather_than_reported_as_drift(self) -> None:
        """A counter capturing nothing reads 0 everywhere. Under the one-sided check it constructed,
        and every subject then surfaced as DRIFT — a displayed RESULT — while the instrument was
        dead."""
        specs = [_spec(m, 0) for m, _ in sorted(pin.SUBJECT_ROWS)]
        specs.append(_spec(pin.CONTROL_NAME, 0, kind="control"))       # floor still passes
        specs.append(_spec(pin.POSITIVE_NAME, 0, kind="positive"))     # <-- caught here
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("POSITIVE CONTROL", str(caught.exception))

    def test_an_UNDER_reporting_counter_is_refused(self) -> None:
        """M_true - 1 passes a zero floor and looks like plausible drift on every row."""
        specs = _replacing(pin.POSITIVE_NAME,
                           _spec(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS - 1,
                                 kind="positive"))
        with self.assertRaises(InstrumentInvalid):
            _run(specs)

    def test_an_OVER_reporting_counter_is_still_refused(self) -> None:
        specs = _replacing(pin.CONTROL_NAME, _spec(pin.CONTROL_NAME, 1, kind="control"))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("FLOOR", str(caught.exception))

    def test_a_MISSING_positive_control_is_refused(self) -> None:
        specs = [s for s in _complete_specs() if s["kind"] != "positive"]
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("one-sided", str(caught.exception))


class ValidReceiptsTheSEAMMustRefuse(unittest.TestCase):
    """Each of these is a perfectly well-formed receipt. Only the pin binding rejects it."""

    def test_a_PARTIAL_table_is_refused_by_exact_cardinality(self) -> None:
        """``>= 1`` would accept this. A table missing four of five rows renders and means nothing."""
        specs = [s for s in _complete_specs()
                 if s["kind"] != "subject" or s["row"] == SWALLOW]
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("exactly", str(caught.exception))

    def test_DUPLICATED_members_are_refused(self) -> None:
        specs = [_spec(SWALLOW, 1) for _ in pin.SUBJECT_ROWS]
        specs.append(_spec(pin.CONTROL_NAME, 0, kind="control"))
        specs.append(_spec(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS, kind="positive"))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("more than once", str(caught.exception))

    def test_a_FOREIGN_corpus_digest_is_refused(self) -> None:
        """A receipt from a superseded release is individually valid and renders fine without this."""
        specs = _replacing(SWALLOW, _spec(SWALLOW, 1, digest="0" * 64))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("does not pin", str(caught.exception))

    def test_an_EXPECTATION_FROM_THE_WRONG_SOURCE_is_refused(self) -> None:
        """Three plausible sources existed and yield DIFFERENT verdicts, while self_consistent()
        passes for all of them. Here the expectation is the row's own measured count — the circular
        case the pin exists to prevent."""
        specs = _replacing(SWALLOW, _spec(SWALLOW, 1, expectation=1))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("pinned policy", str(caught.exception))

    def test_an_IMPOSTOR_control_is_refused(self) -> None:
        specs = [s for s in _complete_specs() if s["kind"] != "control"]
        specs.append(_spec(GOOD, 0, kind="control"))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("not the pinned", str(caught.exception))

    def test_a_MISSING_subject_is_refused(self) -> None:
        specs = [s for s in _complete_specs() if s["row"] != GOOD]
        with self.assertRaises(InstrumentInvalid):
            _run(specs)

    def test_EVENTS_THAT_DO_NOT_TOTAL_THE_COUNT_are_refused(self) -> None:
        """Otherwise the events are decorative and the number is an integer to be believed."""
        specs = _replacing(GOOD, _spec(GOOD, 3, events=1))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("re-counted", str(caught.exception))


class TheKeyIsCARRIEDNotDERIVED(unittest.TestCase):
    """The key was computed at the point of use by ``member.split("/")[1]`` with a fall back to the
    whole string — two places deriving one name by different means, silently shape-dependent."""

    def test_a_row_naming_a_pinned_member_under_ANOTHER_ROWS_KEY_is_refused(self) -> None:
        """The case a member-only set cannot see AT ALL. Every member present exactly once, every
        key present exactly once — but one row is paired to the wrong one."""
        specs = [s for s in _complete_specs() if s["row"] not in (SWALLOW, GOOD)]
        specs += [_spec(SWALLOW, 1, key="retry-good-v2"),
                  _spec(GOOD, 3, key="retry-swallow-v2")]
        subs = [s for s in specs if s["kind"] == "subject"]
        self.assertEqual(len({s["row"] for s in subs}), len(subs), "premise: members unique")
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("EXACT SET of PAIRS", str(caught.exception))

    def test_a_subject_carrying_NO_key_is_refused(self) -> None:
        """Absence must not read as 'derive it for me'."""
        specs = _replacing(SWALLOW, _spec(SWALLOW, 1, force_no_key=True))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("inconsistent with their kind", str(caught.exception))

    def test_a_WHITESPACE_key_is_refused(self) -> None:
        """``bool("   ")`` is True, so a truthiness check admitted it and it reached a lookup."""
        specs = _replacing(SWALLOW, _spec(SWALLOW, 1, key="   "))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("inconsistent with their kind", str(caught.exception))

    def test_a_CONTROL_carrying_a_subject_key_is_refused(self) -> None:
        specs = [s for s in _complete_specs() if s["kind"] != "control"]
        specs.append(_spec(pin.CONTROL_NAME, 0, kind="control", key="retry-good-v2"))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("inconsistent with their kind", str(caught.exception))

    def test_a_DIFFERENTLY_SHAPED_member_is_compared_not_mis_keyed(self) -> None:
        """THE DISCHARGE FOR REMOVING THE TRANSFORM, and it needs an ADVERSARIAL BINDING — which is
        the whole reason ``PinBinding`` is a parameter rather than an import.

        ``member.split("/")[1]`` is CORRECT for every member the current tag carries, so restoring it
        breaks nothing in the pinned set: the transform cannot be shown red against today's data.
        That is exactly the condition under which a latent derivation bug survives review, so the red
        case uses a member of a DIFFERENT SHAPE — nested one level deeper. Under the transform it
        keys on ``pkg``; under the carried key it keys on what it says."""
        deep = MemberPath("fixtures/pkg/nested/main.py")
        adversarial = _binding(
            subject_rows=frozenset({SubjectPin(deep, ExpectationKey("deep-fixture-v1"), 2)}),
            expected_cardinality=1)
        specs = [_spec(deep, 2, key="deep-fixture-v1"),
                 _spec(pin.CONTROL_NAME, pin.CONTROL_EXPECTED_EGRESS, kind="control"),
                 _spec(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS, kind="positive")]
        self.assertEqual(_run(specs, adversarial).drifted(), [])

        specs[0] = _spec(deep, 5, key="deep-fixture-v1")
        self.assertEqual(_run(specs, adversarial).drifted(), [(deep, 2, 5)])

    def test_the_pin_declares_pairs_that_AGREE_with_its_two_independent_sets(self) -> None:
        """SUBJECT_ROWS and SUBJECT_CARDINALITY are written out literally rather than generated, so
        they CAN disagree with the sets they relate. Generating either would agree by construction
        and test nothing."""
        members = {m for m, _ in pin.SUBJECT_ROWS}
        keys = {k for _, k in pin.SUBJECT_ROWS}
        self.assertEqual(keys, set(pin.EXPECTED_EGRESS))
        self.assertTrue(members <= pin.EXPECTED_MEMBERS,
                        f"members the corpus does not carry: {sorted(members - pin.EXPECTED_MEMBERS)}")
        self.assertEqual(len(pin.SUBJECT_ROWS), len(members), "a member is paired to two keys")
        self.assertEqual(pin.SUBJECT_CARDINALITY, len(pin.SUBJECT_ROWS),
                         "the pinned cardinality no longer matches the pinned rows")


class DriftIsTheResult(unittest.TestCase):
    def test_real_drift_is_REPORTED_not_raised(self) -> None:
        """If this raised, the detector could only ever say 'all clear'."""
        specs = _replacing(SWALLOW, _spec(SWALLOW, 2))
        drift = _run(specs).drifted()
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0][1:], (1, 2))

    def test_drifted_takes_NO_second_input(self) -> None:
        """The expectations were a bare dict parameter — a second, unauthenticated input to the one
        computation the tool exists to perform, while the design claimed ``CompletedRun`` was the
        table's only input. A tampered dict could fabricate or erase drift undetectably."""
        import inspect
        params = list(inspect.signature(CompletedRun.drifted).parameters)
        self.assertEqual(params, ["self"],
                         "drifted() accepts an argument again — the authority must come from the "
                         "binding the run header committed to, not from a caller")


class TheGateOutputIsImmutable(unittest.TestCase):
    def test_the_caller_cannot_inject_rows_after_construction(self) -> None:
        """``self.receipts = receipts`` aliased the caller's list, so a post-construction append put
        unvalidated rows into the very collection the table renders."""
        h = _header()
        rows = _chain(h, _complete_specs())
        run = CompletedRun(h, rows, BINDING)
        rows.append(rows[0])
        self.assertEqual(len(run.receipts), len(_complete_specs()))

    def test_a_sealed_receipts_events_cannot_be_extended(self) -> None:
        """``frozen=True`` blocks rebinding, not ``.append()`` — the events were a list, so a sealed
        receipt's bytes changed after issuance and its digest with them."""
        r = _run().subjects[0]
        self.assertIsInstance(r.boundary_events, tuple)
        with self.assertRaises(AttributeError):
            r.boundary_events.append("injected")  # type: ignore[attr-defined]


class ThePromotionTripwire(unittest.TestCase):
    def test_the_interim_controls_must_not_outlive_the_corpus_release(self) -> None:
        """Interim trust roots become permanent unless something goes red."""
        self.assertEqual(
            pin.CORPUS_RELEASE, "demo-corpus-v1",
            "CORPUS_RELEASE has advanced. Per the promotion path in pin.py, the interim CONTROL and "
            "POSITIVE blocks must now be corpus members and their consumer-side definitions DELETED "
            "— they must not survive as a second source of truth for members the corpus carries.")


if __name__ == "__main__":
    unittest.main()


class ControlsAreNotAdmittedOrBlocked(unittest.TestCase):
    """RULING. The subject predicate applied to a zero control seals a HEALTHY control as BLOCK."""

    def test_a_healthy_zero_control_is_not_sealed_BLOCK(self) -> None:
        run = _run()
        self.assertEqual(run.control.verdict, "CONTROL")
        self.assertEqual(run.positive.verdict, "CONTROL")
        self.assertTrue(run.control.self_consistent())

    def test_a_control_sealed_with_a_SUBJECT_verdict_is_refused(self) -> None:
        bad = dict(_spec(pin.CONTROL_NAME, 0, kind="control"))
        bad["verdict"] = "BLOCK"
        specs = [s for s in _complete_specs() if s["kind"] != "control"] + [bad]
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("does not follow", str(caught.exception))


class EventsAreObservedNeverSynthesised(unittest.TestCase):
    """RULING. Labels derived from the count are computation where a sceptic reads data."""

    def test_an_EMPTY_event_tuple_marks_the_count_UNCORROBORATED(self) -> None:
        r = _receipt_with_no_events()
        self.assertTrue(r.uncorroborated())
        self.assertIn("UNCORROBORATED", r.to_json())

    def test_DISCLOSED_events_must_still_total_the_count(self) -> None:
        specs = _replacing(GOOD, _spec(GOOD, 3, events=1))
        with self.assertRaises(InstrumentInvalid) as caught:
            _run(specs)
        self.assertIn("re-counted", str(caught.exception))


def _receipt_with_no_events() -> Receipt:
    h = _header()
    spec = dict(_spec(SWALLOW, 1, events=0))
    spec["measured"] = 1
    return Receipt(prior_digest=h.digest(), **spec)  # type: ignore[arg-type]
