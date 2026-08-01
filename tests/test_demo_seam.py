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

import unittest

from demo import pin
from demo.receipt import (
    CompletedRun,
    CorpusIdentity,
    Instrument,
    InstrumentInvalid,
    PinBinding,
    Receipt,
)

NONCE = "0123456789abcdef0123456789abcdef"
INSTRUMENT = Instrument("gate0000", "sha256:image", "podman", "4.9.3", "sealed", "witness-503")

BINDING = PinBinding(
    corpus_digest=pin.CORPUS_SHA256,
    subject_members=frozenset(f"fixtures/{m}/main.py" for m in pin.EXPECTED_EGRESS),
    control_member=pin.CONTROL_NAME,
    control_floor=pin.CONTROL_EXPECTED_EGRESS,
    positive_member=pin.POSITIVE_NAME,
    positive_expected=pin.POSITIVE_EXPECTED_EGRESS,
    policy_expectation=pin.ADMIT_AT_OR_ABOVE,
)


def _receipt(member: str, measured: int, *, kind: str = "subject", nonce: str = NONCE,
             digest: str = "", expectation: int | None = None) -> Receipt:
    """An INDIVIDUALLY VALID receipt. Its verdict is computed, never asserted."""
    exp = pin.ADMIT_AT_OR_ABOVE if expectation is None else expectation
    return Receipt(
        run_nonce=nonce,
        row=member,
        kind=kind,  # type: ignore[arg-type]
        corpus=CorpusIdentity("demo-corpus-v1", digest or pin.CORPUS_SHA256, member, "sha256:member"),
        instrument=INSTRUMENT,
        measured=measured,
        boundary_events=[f"attempt-{i}" for i in range(measured)],
        expectation=exp,
        verdict="ADMIT" if measured >= exp else "BLOCK",
    )


def _complete() -> list[Receipt]:
    """A set that SHOULD construct — the positive control, without which every refusal below is
    indistinguishable from a constructor that refuses everything."""
    rows = [_receipt(f"fixtures/{m}/main.py", c) for m, c in pin.EXPECTED_EGRESS.items()]
    rows.append(_receipt(pin.CONTROL_NAME, pin.CONTROL_EXPECTED_EGRESS, kind="control"))
    rows.append(_receipt(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS, kind="positive"))
    return rows


class TheCompleteSetConstructs(unittest.TestCase):
    def test_the_positive_control(self) -> None:
        run = CompletedRun(_complete(), BINDING)
        self.assertEqual(len(run.subjects), len(pin.EXPECTED_EGRESS))
        self.assertEqual(run.drifted(pin.EXPECTED_EGRESS), [], "a clean set reported drift")


class TheFloorIsTwoSided(unittest.TestCase):
    """THE FINDING THE DISSENT LANDED ON. Checking only ``measured != 0`` detects OVER-reporting."""

    def test_a_DEAD_counter_is_refused_rather_than_reported_as_drift(self) -> None:
        """A counter capturing nothing reads 0 everywhere. Under the one-sided check it constructed,
        and every subject then surfaced as DRIFT — a displayed RESULT — while the instrument was
        dead. This is the exact scenario, and it must now be INSTRUMENT-INVALID."""
        dead = [_receipt(f"fixtures/{m}/main.py", 0) for m in pin.EXPECTED_EGRESS]
        dead.append(_receipt(pin.CONTROL_NAME, 0, kind="control"))          # floor still passes
        dead.append(_receipt(pin.POSITIVE_NAME, 0, kind="positive"))        # <-- caught here
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(dead, BINDING)
        self.assertIn("POSITIVE CONTROL", str(caught.exception))

    def test_an_UNDER_reporting_counter_is_refused(self) -> None:
        """M_true - 1 passes a zero floor and looks like plausible drift on every row."""
        rows = _complete()
        rows[-1] = _receipt(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS - 1, kind="positive")
        with self.assertRaises(InstrumentInvalid):
            CompletedRun(rows, BINDING)

    def test_an_OVER_reporting_counter_is_still_refused(self) -> None:
        """The direction the one-sided check already caught — it must not regress."""
        rows = _complete()
        rows[-2] = _receipt(pin.CONTROL_NAME, 1, kind="control")
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("FLOOR", str(caught.exception))

    def test_a_MISSING_positive_control_is_refused(self) -> None:
        """Without it the floor is one-sided again, which is how this started."""
        rows = [r for r in _complete() if r.kind != "positive"]
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("one-sided", str(caught.exception))


class ValidReceiptsTheSEAMMustRefuse(unittest.TestCase):
    """Each of these is a perfectly well-formed receipt. Only the pin binding rejects it."""

    def test_DUPLICATED_members_are_refused(self) -> None:
        """A count-based check accepted five copies of one row as a complete table."""
        one = "fixtures/retry-swallow-v2/main.py"
        rows = [_receipt(one, 1) for _ in pin.EXPECTED_EGRESS]
        rows.append(_receipt(pin.CONTROL_NAME, 0, kind="control"))
        rows.append(_receipt(pin.POSITIVE_NAME, pin.POSITIVE_EXPECTED_EGRESS, kind="positive"))
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("more than once", str(caught.exception))

    def test_a_FOREIGN_corpus_digest_is_refused(self) -> None:
        """A receipt from a superseded release is individually valid and renders fine without this."""
        rows = _complete()
        rows[0] = _receipt("fixtures/retry-swallow-v2/main.py", 1, digest="0" * 64)
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("does not pin", str(caught.exception))

    def test_an_EXPECTATION_FROM_THE_WRONG_SOURCE_is_refused(self) -> None:
        """Three plausible sources existed and yield DIFFERENT verdicts, while self_consistent()
        passes for all of them. Here the expectation is the row's own measured count — the circular
        case the pin exists to prevent — and the receipt is entirely self-consistent."""
        rows = _complete()
        rows[0] = _receipt("fixtures/retry-swallow-v2/main.py", 1, expectation=1)
        self.assertTrue(rows[0].self_consistent(), "the premise: the receipt is individually valid")
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("pinned policy", str(caught.exception))

    def test_an_IMPOSTOR_control_is_refused(self) -> None:
        """Any receipt with kind=='control' and measured==0 satisfied the floor before."""
        rows = [r for r in _complete() if r.kind != "control"]
        rows.append(_receipt("fixtures/retry-good-v2/main.py", 0, kind="control"))
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("not the pinned", str(caught.exception))

    def test_a_MISSING_subject_is_refused(self) -> None:
        rows = [r for r in _complete() if r.corpus.member != "fixtures/retry-good-v2/main.py"]
        with self.assertRaises(InstrumentInvalid) as caught:
            CompletedRun(rows, BINDING)
        self.assertIn("missing", str(caught.exception))

    def test_MIXED_nonces_are_refused(self) -> None:
        rows = _complete()
        rows[0] = _receipt("fixtures/retry-swallow-v2/main.py", 1, nonce="f" * 32)
        with self.assertRaises(InstrumentInvalid):
            CompletedRun(rows, BINDING)


class DriftNeverReportsOverZeroComparisons(unittest.TestCase):
    def test_an_unkeyable_row_RAISES_rather_than_being_skipped(self) -> None:
        """The soft skip yielded an empty drift list over ZERO performed comparisons, which reads
        exactly like 'everything agrees'. An empty result is not a value."""
        run = CompletedRun(_complete(), BINDING)
        with self.assertRaises(InstrumentInvalid) as caught:
            run.drifted({"retry-swallow-v2": 1})          # the other four have no expectation
        self.assertIn("never performed", str(caught.exception))

    def test_real_drift_is_REPORTED_not_raised(self) -> None:
        """Drift is the RESULT. If this raised, the detector could only ever say 'all clear'."""
        rows = _complete()
        rows[0] = _receipt("fixtures/retry-swallow-v2/main.py", 2)
        run = CompletedRun(rows, BINDING)
        drift = run.drifted(pin.EXPECTED_EGRESS)
        self.assertEqual(len(drift), 1)
        self.assertEqual(drift[0][1:], (1, 2))


class TheReceiptIsImmutableOnceIssued(unittest.TestCase):
    def test_a_receipt_cannot_be_edited_after_it_is_sealed(self) -> None:
        """It was the only non-frozen dataclass of the four, so evidence was mutable after issuance
        and a digest recomputed after an edit would be self-consistent."""
        import dataclasses

        r = _receipt("fixtures/retry-good-v2/main.py", 3)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            r.measured = 99  # type: ignore[misc]


class ThePromotionTripwire(unittest.TestCase):
    def test_the_interim_controls_must_not_outlive_the_corpus_release(self) -> None:
        """Interim trust roots become permanent unless something goes red. The controls are pinned
        consumer-side ONLY until they become corpus members; when the release advances, the block
        must be deleted rather than left as a second source of truth."""
        self.assertEqual(
            pin.CORPUS_RELEASE, "demo-corpus-v1",
            "CORPUS_RELEASE has advanced. Per the promotion path in pin.py, the interim CONTROL and "
            "POSITIVE blocks must now be corpus members and their consumer-side definitions DELETED "
            "— they must not survive as a second source of truth for members the corpus carries.")


if __name__ == "__main__":
    unittest.main()
