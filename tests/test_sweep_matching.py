#!/usr/bin/env python3
"""Matching semantics — R2 normalisation, the hyphen axis, orthographic expansion, fence-aware carrier units.

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
from _sweep_harness import S, unittest


class MatchingSemantics(unittest.TestCase):
    """R2 — matching is SPEC. These are the failures that motivated it."""

    def test_hard_wrapped_phrase_is_found(self):
        """THE v1 FAILURE. v1's design document hard-wrapped its own key phrase, so a line-oriented
        matcher would have missed the sentence the document was about."""
        corpus = "a supersession that greps only the surfaces it remembers is a partial sweep\nwearing a complete one's clothes."
        pat = S.compile_pattern("a partial sweep wearing a complete one's clothes")
        self.assertIsNotNone(pat.search(S.normalise(corpus)),
                             "a phrase split across a newline must still match")

    def test_line_oriented_matching_would_have_missed_it(self):
        """The control for the test above: prove the naive approach actually fails, so the test is
        not passing for an unrelated reason."""
        corpus = "…is a partial sweep\nwearing a complete one's clothes."
        naive = "a partial sweep wearing a complete one's clothes"
        self.assertFalse(any(naive in line for line in corpus.splitlines()),
                         "if a line-oriented search found this, the test proves nothing")

    def test_nfkc_is_load_bearing_for_compatibility_chars_inside_words(self):
        """⚠ THE RULING SURVIVED ITS RED-PROOF; ITS STATED REASON DID NOT.

        The design (and an earlier version of this test) justified NFKC by NBSP: "NFC leaves NBSP as
        NBSP, so the occurrence evades the whitespace rule". MEASURED: Python's ``\\s`` matches NBSP
        natively, so the NBSP case passes under NFC too — reversing NFKC->NFC left the old test GREEN.
        The reason was wrong; the ruling is not. Where NFKC is genuinely load-bearing is COMPATIBILITY
        CHARACTERS INSIDE WORDS, which no whitespace rule can reach.
        """
        corpus = "the \ufb01nal claim was \uff37rong"      # fi-ligature, fullwidth W
        pat = S.compile_pattern("the final claim was Wrong")
        self.assertIsNotNone(pat.search(S.normalise(corpus)),
                             "NFKC must fold ligatures and fullwidth forms for the match to land")

    def test_nbsp_is_handled_by_the_whitespace_rule_not_by_normalisation(self):
        """The correlated control for the test above: NBSP is NOT the case that motivates NFKC.
        Recorded so the wrong justification cannot be re-derived from a passing test.

        \u26a0 THIS TEST USED TO ASSERT ``re.match(r"\\s", "\\u00a0")`` AND NOTHING ELSE \u2014 a fact about
        the REGEX ENGINE, not about this tool. It proved Python's ``\\s`` matches NBSP; it did NOT
        prove that ``compile_pattern`` relies on that rather than on NFKC, which is the claim its
        name makes. Its stated reason was stronger than its mechanism, and it would have stayed
        green if the matcher had stopped using ``\\s+`` altogether. It now drives the tool, and
        pins the discriminating case: the match must survive under NFC, where NFKC cannot be doing
        the work.
        """
        import re as _re
        import unicodedata as _ud
        # \u00a0 IS WRITTEN AS AN ESCAPE, NEVER AS A LITERAL CHARACTER. A literal NBSP is
        # indistinguishable from a space when read, and an edit that silently substitutes one
        # turns every assertion below VACUOUS while leaving them GREEN. That happened to this
        # very test on 2026-08-07, and was caught only by COUNTING THE CODEPOINTS in the file --
        # a fix that reproduced the defect it was fixing.
        NBSP = "\u00a0"
        self.assertEqual(ord(NBSP), 0xA0, "the fixture must be a REAL NBSP, not a space")
        self.assertTrue(_re.match(r"\s", NBSP), "Python's \\s matches NBSP natively")
        # THE TOOL, not the engine: an NBSP-joined occurrence must match.
        joined = f"no{NBSP}egress"
        self.assertIsNotNone(S.compile_pattern("no egress").search(S.normalise(joined)),
                             "compile_pattern must match across a non-breaking space")
        # THE DISCRIMINATOR: under NFC the NBSP SURVIVES, so a match there is the whitespace
        # rule doing the work rather than the folding.
        nfc = _ud.normalize("NFC", joined)
        self.assertIn(NBSP, nfc, "NFC must leave the NBSP in place, or this proves nothing")
        self.assertIsNotNone(S.compile_pattern("no egress").search(nfc),
                             "so the \\s+ rule -- not NFKC -- is what crosses the NBSP axis")

    def test_matching_is_CASE_INSENSITIVE(self):
        """⚠ FOUND BY CONSULT 2026-08-07 AS A SURVIVING MUTATION. Every fixture in this file matched
        in the SAME CASE, so deleting `re.IGNORECASE` from `compile_pattern` passed the whole suite —
        while the extraction classes are documented as case-insensitive BY CONSTRUCTION BECAUSE THE
        MATCHER IS, and a lowercase-only class was measured to see nothing in a carrier spelling its
        terms in capitals. The ruling had no pin at all."""
        pat = S.compile_pattern("No Egress")
        self.assertIsNotNone(pat.search(S.normalise("the claim says NO EGRESS here")))
        self.assertIsNotNone(S.compile_pattern("ZERO-GATE").search(S.normalise("zero-gate")))

    def test_indent_and_reflow_survive(self):
        pat = S.compile_pattern("count is stable")
        self.assertIsNotNone(pat.search(S.normalise("    count\n        is\n  stable")))

    def test_pattern_is_literal_not_regex(self):
        """A claim containing metacharacters must not silently become a wildcard."""
        pat = S.compile_pattern("count == 0 (always)")
        self.assertIsNotNone(pat.search(S.normalise("we said count == 0 (always) here")))
        self.assertIsNone(pat.search(S.normalise("count == 0 always")))

    def test_multiline_span_is_reported_whole(self):
        """R5 — a single context line missing the pattern words reads as a false positive."""
        text = "alpha\nthe claim is\nspread over lines\nomega"
        hits = S.find_hits(text, S.compile_pattern("the claim is spread over lines"),
                           label="t", surface="s", location_of=lambda a, b: f"f:{a}-{b}")
        self.assertEqual(len(hits), 1)
        self.assertIn("spread over lines", hits[0].span)
        self.assertIn("the claim is", hits[0].span)


class NfkcHyphenIsNotFolded(unittest.TestCase):
    """⚠ THE DOCSTRING'S THIRD NFKC EXAMPLE WAS DEAD, AND IT WAS THE CORRECTED VERSION.

    `normalise` exists to record that a ruling survived its red-proof while its stated reason did
    not. The rewritten reason then shipped with a FRESH false example — the non-breaking hyphen —
    undetected until an outside reviewer read it. This test pins the measurement so the claim cannot
    quietly return.
    """

    def test_U2011_does_NOT_fold_to_ascii_hyphen(self):
        folded = S.normalise("\u2011")
        self.assertEqual(folded, "\u2010", "NFKC maps NON-BREAKING HYPHEN to HYPHEN, not to ASCII")
        self.assertNotEqual(folded, "-", "so NFKC does NOT rescue an ASCII-hyphen pattern")
        self.assertIsNone(S.compile_pattern("co-operate").search(S.normalise("co\u2011operate")),
                          "an ASCII-hyphen pattern still MISSES a typographic hyphen after NFKC")

    def test_the_two_surviving_examples_are_real(self):
        """The correlated control: ligature and fullwidth DO fold, so the ruling still stands."""
        self.assertIsNotNone(S.compile_pattern("final").search(S.normalise("\ufb01nal")))
        self.assertEqual(S.normalise("\uff21"), "A")

    def test_expand_is_what_crosses_the_hyphen_axis(self):
        """Since normalisation does not cross it, expansion must — by enumeration."""
        self.assertIn("co\u2011operate", S.expand("co-operate"))


class OrthographicExpansion(unittest.TestCase):
    """R3 — expansion is the mechanism EXTRACTION CANNOT REPLACE, and it was ONE-WAY.

    ⚠ THE DEFECT: ``expand`` split on the HYPHEN FAMILY ONLY, so a SPACE-FORM term had nothing to
    split and returned the EMPTY SET — while its docstring claimed "every orthographic spelling".
    ``expand("no egress")`` yielded NOTHING, AND "no egress" IS THE SEED. Found by an outside
    reviewer reading the source, not by execution and not by these tests, which did not exist.
    """

    def test_space_form_expands_to_the_hyphen_family(self):
        """⚠ THE SEED CASE. This is the assertion the one-way implementation fails."""
        got = S.expand("no egress")
        self.assertIn("no-egress", got, "a SPACE-form term must yield the ASCII-hyphen form")
        self.assertIn("noegress", got)
        self.assertIn("no‑egress", got, "and the NON-BREAKING hyphen, which NFKC does NOT fold to ASCII")

    def test_hyphen_form_still_expands_to_the_space_form(self):
        """The other direction, which already worked — kept so a fix cannot swap the bug's polarity."""
        self.assertIn("false pass", S.expand("false-pass"))

    def test_a_term_with_no_axis_yields_nothing(self):
        """The correlated negative control: without it the tests above pass on an expander that
        returns junk for every input."""
        self.assertEqual(S.expand("single"), set())

    def test_the_term_itself_is_never_returned(self):
        for t in ("no egress", "false-pass"):
            self.assertNotIn(t, S.expand(t))

    def test_operator_compounds_are_INELIGIBLE_for_the_orthographic_axis(self):
        """⚠ A PATH THAT ALREADY FIRED, NOT A FUTURE ONE. ``_C_QUOTED`` extracts backticked spans, so
        ``count == 0 => no egress`` is a live candidate TODAY — and expansion turned it into
        ``count-==-0-=>-no-egress``, a string already sitting in a persisted 2026-08-04 transcript.

        This is a DOMAIN PRECONDITION, not a new expansion class: no axis added, no case folded,
        nothing pluralised or stemmed. It NARROWS application of the same ruled transform.
        """
        self.assertEqual(S.expand("count == 0"), set())
        self.assertEqual(S.expand("count == 0 => no egress"), set())

    def test_the_gate_leaves_ordinary_orthographic_terms_UNCHANGED(self):
        """⚠ THE CORRELATED NEGATIVE. Without it the test above passes on a gate that refuses
        everything, which would silently delete the mechanism it is meant to protect."""
        self.assertIn("no-egress", S.expand("no egress"))
        self.assertIn("false pass", S.expand("false-pass"))
        self.assertIn("false PASSES", S.expand("false-PASSES"),
                      "the criterion is STRUCTURAL, so mixed case must survive it")

    def test_the_criterion_is_structural_not_semantic(self):
        """It asks 'are the parts word-shaped', never 'is this a claim'. A meaningless but
        word-shaped term must still expand, or the gate has become adjudication (R5)."""
        self.assertIn("a-b", S.expand("a b"))

    def test_scope_is_ORTHOGRAPHIC_ONLY(self):
        """⚠ THE RULED DEFECT WAS ONE-WAYNESS, NOT NARROWNESS. Case folding, pluralisation and
        stemming are DIFFERENT AXES, each needing its own justification. Widening beyond the ruling
        is how a fix becomes a redesign, so the boundary is pinned here."""
        got = S.expand("ZERO-GATE")
        self.assertTrue(all(g.replace(" ", "").replace("-", "").replace("\u2010", "")
                            .replace("\u2011", "") == "ZEROGATE" for g in got),
                        f"expansion must not change letters or case, got {got}")
        self.assertNotIn("zero-gate", got, "no case folding — the MATCHER already folds case")
        self.assertNotIn("zero-gates", got, "no pluralisation")


class FenceAwareCarrierUnits(unittest.TestCase):
    """⚠ A HEADING MARK INSIDE A FENCED BLOCK IS NOT A HEADING.

    `_HEADING` matches any line starting (modulo `>` prefixes) with 1-6 `#` and a space, so a SHELL
    OR PYTHON COMMENT INSIDE A FENCE was a split mark. MEASURED on the 2026-08-05 corpus: 245 such
    marks across 33 of 492 locations (6.7%).

    ⚠ IT BECAME LOAD-BEARING ONLY WITH CLAIM-SPAN SEEDING. Under the fixpoint loop a mis-split barely
    mattered — the flood crossed every boundary. When THE UNIT IS THE CANDIDATE SET, a mis-split
    above the claim CUTS THE UNIT SHORT and `variants` SILENTLY NARROWS. And the ablation cannot be
    cited against it: both arms shared `_HEADING`, so it measured granularity, never parse
    correctness.
    """

    F = "```"

    def _doc(self):
        return ("intro paragraph\n\n" + self.F + "bash\n"
                "# this is a shell comment, NOT a heading\n"
                "echo hi\n" + self.F + "\n\n"
                "the claim lives here\n\n"
                "## A REAL HEADING\n"
                "tail\n")

    def test_a_hash_comment_inside_a_fence_does_NOT_split(self):
        """⚠ THE TARGET ASSERTION. Fence-blind, this yields THREE units and the claim's unit begins
        at the shell comment — losing everything above it."""
        units = S.carrier_units("f.md", S.normalise(self._doc()))
        self.assertEqual(len(units), 2, f"the fence must not split; got {[u for u,_ in units]}")
        claim = [t for _, t in units if "the claim lives here" in t][0]
        self.assertIn("intro paragraph", claim,
                      "⚠ the claim's unit must still reach back past the fence")

    def test_a_real_heading_outside_a_fence_STILL_splits(self):
        """The correlated positive control: without it the test above passes on a function that
        never splits at all."""
        units = S.carrier_units("f.md", S.normalise(self._doc()))
        self.assertEqual(len(units), 2)
        self.assertTrue(any("A REAL HEADING" in t for _, t in units))
        self.assertFalse(any("A REAL HEADING" in t and "the claim lives here" in t
                             for _, t in units), "the real heading must separate them")

    def test_an_unterminated_fence_extends_to_end_of_text(self):
        """⚠ THE FAIL-SAFE DIRECTION, STATED. Suppressing splits after an unclosed fence yields
        FEWER, LARGER units — more vocabulary, which the tool already prints. Ignoring it would let
        splits happen INSIDE a probable fence, TRUNCATING silently. Truncation is the dangerous
        direction under claim-span seeding."""
        doc = "intro\n\n" + self.F + "\n# not a heading\n## also not\n"
        self.assertEqual(len(S.carrier_units("f.md", S.normalise(doc))), 1)

    def test_tilde_fences_count_too(self):
        doc = "intro\n\n~~~\n# not a heading\n~~~\n\nbody\n"
        self.assertEqual(len(S.carrier_units("f.md", S.normalise(doc))), 1)

    def test_headings_still_split_a_document_with_no_fences_at_all(self):
        """Second correlated control: fence logic must not perturb the ordinary path."""
        doc = "preamble\n\n# One\na\n\n## Two\nb\n"
        self.assertEqual(len(S.carrier_units("f.md", S.normalise(doc))), 3)
