"""3.5-close #1.7 — the overclaim lint is a REAL tested property, not vacuous theatre. Run:
python3 -m unittest discover -s tests

Proves the guard (a) loads a non-empty vocabulary, (b) actually DETECTS a banned phrase in a string
literal, (c) ignores it in a COMMENT (AST-scoped, dodging false-positives), and (d) the live tree passes.
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check-overclaim.py"
_spec = importlib.util.spec_from_file_location("check_overclaim", _SCRIPT)
assert _spec and _spec.loader
_lint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lint)


class OverclaimLintTests(unittest.TestCase):
    def test_vocabulary_is_non_empty(self) -> None:
        self.assertTrue(_lint._load_lines(_lint._VOCAB_FILE), "banned vocabulary must be loaded")

    def test_detects_banned_phrase_in_a_string_literal(self) -> None:
        src = 'X = "this mechanism is absolutely safe and cannot be bypassed"\n'
        blob = "\n".join(_lint._string_literals(src)).lower()
        self.assertIn("absolutely safe", blob)
        self.assertIn("cannot be bypassed", blob)

    def test_ignores_banned_phrase_in_a_comment(self) -> None:
        # a COMMENT is not an AST node -> exempt (the false-positive the naive grep would hit).
        src = "# this is absolutely safe as a comment\nX = 1\n"
        blob = "\n".join(_lint._string_literals(src)).lower()
        self.assertNotIn("absolutely safe", blob)

    def test_live_tree_passes_the_lint(self) -> None:
        self.assertEqual(_lint.main(), 0)  # the shipped tree carries no unsuppressed overclaim

    # ---- CP2 S7: the narrow proof/plan-context patterns (forward-guard against reintroduction) ----
    def _banned(self):  # type: ignore[no-untyped-def]
        return [p.lower() for p in _lint._load_lines(_lint._VOCAB_FILE)]

    def test_s7_proof_plan_phrases_are_banned(self) -> None:
        banned = self._banned()
        for phrase in ("unconstructible", "provably unforgeable", "unforgeable capability",
                       "unforgeable-by-convention", "sealed token", "sealed-token"):
            self.assertIn(phrase, banned, f"{phrase!r} must be in the banned vocabulary")

    def test_s7_detects_a_reintroduced_proof_overclaim(self) -> None:
        # a future commit that re-asserts the proof/typestate as an unforgeable boundary is CAUGHT.
        for overclaim in ('This mints an unforgeable capability; the plan is unconstructible.',
                          'The plan is a sealed token proving admission.',
                          'a sealed-token capability'):
            src = f'def f():\n    """{overclaim}"""\n'
            blob = "\n".join(_lint._string_literals(src)).lower()
            banned = self._banned()
            self.assertTrue(any(p in blob for p in banned),
                            f"an assertive proof overclaim must be detected: {overclaim!r}")

    def test_s7_allows_the_negated_disclaimer_and_real_crypto(self) -> None:
        # the HONEST forms must NOT trip: the negated proof disclaimer, and real asymmetric-crypto language.
        src = ('def g():\n'
               '    """The proof is a call-path convention, NOT an unforgeable boundary; a Verifier holding\n'
               '    only the public key cannot forge a receipt."""\n')
        blob = "\n".join(_lint._string_literals(src)).lower()
        banned = self._banned()
        hit = [p for p in banned if p in blob]
        self.assertEqual(hit, [], f"legitimate negated / real-crypto prose must pass, but matched {hit}")


if __name__ == "__main__":
    unittest.main()
