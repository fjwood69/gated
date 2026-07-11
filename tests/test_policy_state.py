"""3.3 — the closed-enum state machine + fail-closed disposition mapping. Run:
python3 -m unittest discover -s tests

Load-bearing: EVERY PolicyState has an explicit disposition (no fall-through -> a new state can't
silently enforce or silently skip); DEGRADED maps to a BLOCKING conclusion (fail-closed);
not-yet-enabled/refused states skip NON-blocking; the genesis law + legal edges hold; weakening is
correctly classified (ENABLED->ADVISORY weakens; ENABLED->DEGRADED does NOT — DEGRADED still blocks).
"""
from __future__ import annotations

import unittest

from gate.checkrun import BLOCKING_CONCLUSIONS, CheckConclusion
from gate.policy_state import (
    DISPOSITION,
    Disposition,
    PolicyState,
    disposition_for,
    is_legal_transition,
    is_weakening,
    nonrun_conclusion_for,
)


class DispositionMappingTests(unittest.TestCase):
    def test_every_state_has_a_disposition(self) -> None:
        # closed enum: no state may be un-triaged (which would default to enforce/skip somewhere).
        for state in PolicyState:
            self.assertIn(state, DISPOSITION, f"{state} has no disposition")

    def test_only_enabled_runs_the_engine(self) -> None:
        enforcing = [s for s in PolicyState if disposition_for(s) is Disposition.RUN_ENFORCING]
        self.assertEqual(enforcing, [PolicyState.ENABLED])

    def test_degraded_blocks_not_skips(self) -> None:
        self.assertIs(disposition_for(PolicyState.DEGRADED), Disposition.BLOCK_ACTION_REQUIRED)

    def test_not_yet_enabled_states_skip_neutral(self) -> None:
        for state in (PolicyState.PROPOSED, PolicyState.PENDING_CALIBRATION,
                      PolicyState.CALIBRATING, PolicyState.ADVISORY, PolicyState.REJECTED,
                      PolicyState.RETIRED):
            self.assertIs(disposition_for(state), Disposition.SKIP_NEUTRAL)

    def test_nonrun_conclusions_are_fail_closed_typed(self) -> None:
        # DEGRADED's conclusion must BLOCK; a skip must NOT block. This is the fail-open guard.
        self.assertIn(
            nonrun_conclusion_for(Disposition.BLOCK_ACTION_REQUIRED), BLOCKING_CONCLUSIONS
        )
        self.assertNotIn(nonrun_conclusion_for(Disposition.SKIP_NEUTRAL), BLOCKING_CONCLUSIONS)
        self.assertIs(nonrun_conclusion_for(Disposition.SKIP_NEUTRAL), CheckConclusion.NEUTRAL)

    def test_run_enforcing_has_no_static_conclusion(self) -> None:
        with self.assertRaises(ValueError):
            nonrun_conclusion_for(Disposition.RUN_ENFORCING)


class TransitionTests(unittest.TestCase):
    def test_genesis_law_cannot_jump_to_enabled(self) -> None:
        # a brand-new policy is implicitly PROPOSED; PROPOSED->ENABLED is not a legal edge.
        self.assertFalse(is_legal_transition(PolicyState.PROPOSED, PolicyState.ENABLED))
        self.assertTrue(is_legal_transition(PolicyState.PROPOSED, PolicyState.PENDING_CALIBRATION))

    def test_enable_path_edges(self) -> None:
        self.assertTrue(is_legal_transition(PolicyState.CALIBRATING, PolicyState.ENABLED))
        self.assertTrue(is_legal_transition(PolicyState.CALIBRATING, PolicyState.REJECTED))
        self.assertFalse(is_legal_transition(PolicyState.ENABLED, PolicyState.CALIBRATING))

    def test_weakening_classification(self) -> None:
        self.assertTrue(is_weakening(PolicyState.ENABLED, PolicyState.ADVISORY))
        self.assertTrue(is_weakening(PolicyState.DEGRADED, PolicyState.ADVISORY))
        # ENABLED->DEGRADED is NOT weakening: DEGRADED still blocks (fail-closed), so it needs no
        # dual authority.
        self.assertFalse(is_weakening(PolicyState.ENABLED, PolicyState.DEGRADED))


if __name__ == "__main__":
    unittest.main()
