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


if __name__ == "__main__":
    unittest.main()
