#!/usr/bin/env python3
"""⚠ THE GUARD ON THE SPLIT ITSELF. Derived, never declared.

``tests/test_sweep.py`` reached 122,382 bytes — 95.6% of the 125KB per-file attachment cap — and was
split by concern before it crossed. The danger of any split is that a class stops being discovered
and NOTHING SAYS SO: a broken import, a mid-file ``unittest.main()``, or a module nobody added to
discovery all produce a smaller run that still prints OK.

⚠ THE ASSERTION IS THE **UNION** AGAINST A **PRE-SPLIT CENSUS CAPTURED BY DISCOVERY**, not a
per-file expected count. A per-file number is one edit away from being updated to match a drop —
whoever removes a class also updates the constant, and the guard ratifies the loss. A union against
a total captured BEFORE the cut cannot drift from what is actually there, and it cannot be
reconstructed afterwards, which is why it was captured first.

IT EARNED ITS KEEP BEFORE THE CUT WAS MADE, TWICE:
  * ``grep "^class "`` said 29 and discovery said 28 — ``_SweepHarness`` subclasses ``TestCase`` and
    carries no ``test_`` methods, so it is a class in the file and not a class in the run. A
    DECLARED 29 would have been wrong from birth.
  * the assignment pre-flight found ``ParentIsValidated`` unassigned to any module — a class written
    hours earlier that the split WOULD HAVE SILENTLY DROPPED.
"""
import json
import unittest
from pathlib import Path

_CENSUS = Path(__file__).resolve().parent / "PRE-SPLIT-CENSUS.json"


def _discovered():
    """Every test the sweep suite actually runs, by real discovery over the split modules."""
    suite = unittest.defaultTestLoader.discover(
        str(Path(__file__).resolve().parent), pattern="test_sweep_*.py",
        top_level_dir=str(Path(__file__).resolve().parent.parent))

    def walk(s):
        for t in s:
            if isinstance(t, unittest.TestSuite):
                yield from walk(t)
            else:
                yield t
    return list(walk(suite))


class SplitIntegrity(unittest.TestCase):

    def setUp(self):
        self.census = json.loads(_CENSUS.read_text(encoding="utf-8"))
        self.found = _discovered()

    def test_NO_CLASS_WAS_LOST_IN_THE_SPLIT(self):
        """⚠ THE ONE THAT MATTERS. Names, not counts — a count alone would pass if one class were
        dropped and another added.

        ⚠ SUBSET, NOT EQUALITY, AND THE CHANGE IS ITSELF A FINDING. The first version asserted
        EQUALITY and went red the moment a legitimate new test class arrived — equality was true only
        at the INSTANT of the cut, so the guard was pinning "the suite never changes" rather than
        "the split lost nothing". A guard that reds on correct work gets loosened by whoever is
        blocked by it, and R4a already names where that ends: an exit that is always red trains the
        reader to route around it. The property is CONTAINMENT.
        """
        before = set(self.census["classes"])
        after = {type(t).__name__ for t in self.found} - {"SplitIntegrity"}
        self.assertEqual(before - after, set(),
                         f"CLASSES LOST IN THE SPLIT: {sorted(before - after)}")

    def test_NO_TEST_WAS_LOST_IN_THE_SPLIT(self):
        """A class can survive while its methods do not — e.g. a body truncated at a bad boundary.

        ⚠ A FLOOR, NOT AN EQUALITY, for the reason above — but a floor is WEAKER, and the weakness is
        stated rather than hidden: dropping one test while adding two would pass here. The class-name
        subset above is what carries the real guarantee; this catches wholesale truncation only.
        """
        n = len([t for t in self.found if type(t).__name__ != "SplitIntegrity"])
        self.assertGreaterEqual(n, self.census["test_count"],
                                f"TESTS LOST: {self.census['test_count']} before, {n} now")

    def test_the_HARNESS_IS_NOT_COLLECTED_AS_TESTS(self):
        """⚠ THE CORRELATED CONTROL. If ``_sweep_harness`` were discoverable, it would inflate the
        union and mask a genuine loss elsewhere — the guard would pass while the suite shrank."""
        self.assertNotIn("_SweepHarness", {type(t).__name__ for t in self.found})
        self.assertFalse((Path(__file__).resolve().parent / "test_sweep_harness.py").exists(),
                         "the harness must not be named so that discovery collects it")

    def test_the_census_is_a_REAL_capture_not_a_placeholder(self):
        """Without this, a census of zeroes would make every assertion above vacuous."""
        self.assertGreater(self.census["test_count"], 100)
        self.assertGreater(self.census["class_count"], 20)
        self.assertEqual(len(self.census["classes"]), self.census["class_count"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
