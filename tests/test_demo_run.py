"""The runner's checkable parts — above all, the diff correspondence that a sceptic can recompute.

⚠ A PROOF NEVER SEEN TO REJECT IS A CLAIM. The proof is the COMPARISON in ``render_and_prove``:
reconstructed text set equal to the derived bytes. ``apply_unified`` supplies the recomputable half —
base + displayed diff -> derived, rerunnable offline by a reader who trusts nothing about the process
that produced it — but it decides nothing on its own. That distinction is worth exactly as much as
the evidence that the refusals FIRE, so most of this file is doctored diffs that must be refused.

⚠ AND THIS DOCSTRING WAS ITSELF STALE — the fourth prose-scan of the session. It described
``apply_unified`` as "the only actual proof" for a full commit after that claim was corrected in
``run.py``, and the guard below could not see it, because the guard only scans ``run.__file__``. The
test against stale prose carried stale prose, invisible to itself. Any test that reads a source file
must PARSE it, and no test file may make claims about source it does not scan.
"""
from __future__ import annotations

import difflib
import unittest
from pathlib import Path

from demo import pin, run
from demo.fetch import CorpusIntegrityError
from demo.receipt import InstrumentInvalid

BASE = """import socket


def main():
    for attempt in range(3):
        try:
            socket.create_connection(("h", 80), timeout=1)
            return
        except OSError:
            continue
"""

DERIVED = """import socket


def main():
    for attempt in range(3):
        try:
            socket.create_connection(("h", 80), timeout=1)
            return
        except OSError:
            raise
"""


def _diff(a: str, b: str) -> list[str]:
    return list(difflib.unified_diff(a.splitlines(keepends=True), b.splitlines(keepends=True),
                                     fromfile="a", tofile="b", n=3))


class ThePureFunctionReproducesTheDerivedBytes(unittest.TestCase):
    def test_a_real_transformation_round_trips(self) -> None:
        out = run.apply_unified(BASE.splitlines(keepends=True), _diff(BASE, DERIVED))
        self.assertEqual("".join(out), DERIVED)

    def test_an_IDENTICAL_pair_round_trips(self) -> None:
        """difflib emits no hunks; the base must survive unchanged rather than come back empty."""
        out = run.apply_unified(BASE.splitlines(keepends=True), _diff(BASE, BASE))
        self.assertEqual("".join(out), BASE)

    def test_a_MULTI_HUNK_transformation_round_trips(self) -> None:
        far = BASE.replace("import socket", "import socket  # header").replace("continue", "raise")
        out = run.apply_unified(BASE.splitlines(keepends=True), _diff(BASE, far))
        self.assertEqual("".join(out), far)


class ThePureFunctionMustBeSeenToREJECT(unittest.TestCase):
    """Each doctored diff is well-FORMED — it parses, its hunk headers are valid, and a lenient
    applier would happily produce something. Only strictness refuses them."""

    def test_a_diff_REMOVING_a_line_the_base_does_not_have_is_refused(self) -> None:
        doctored = [ln.replace("-            continue", "-            THIS WAS NEVER HERE")
                    for ln in _diff(BASE, DERIVED)]
        with self.assertRaises(InstrumentInvalid) as caught:
            run.apply_unified(BASE.splitlines(keepends=True), doctored)
        self.assertIn("does not describe these bytes", str(caught.exception))

    def test_a_diff_whose_CONTEXT_does_not_match_the_base_is_refused(self) -> None:
        """The subtle one. Context lines are the part a lenient applier skips over, and they are
        exactly what ties the hunk to THESE bytes rather than to plausible-looking bytes."""
        doctored = [ln.replace("         except OSError:", "         except ValueError:")
                    for ln in _diff(BASE, DERIVED)]
        with self.assertRaises(InstrumentInvalid) as caught:
            run.apply_unified(BASE.splitlines(keepends=True), doctored)
        self.assertIn("context does not match", str(caught.exception))

    def test_OUT_OF_ORDER_hunks_are_refused(self) -> None:
        """Hand-built, because a doubled real diff is caught EARLIER by the removal guard (its second
        ``--- a`` header parses as a removal). Asserting the wrong message there would have recorded
        this guard as proven while it was never reached — a test passing for another guard's reason.

        Here the second hunk starts before the first one ended, which is the case a rewind would
        silently accept by re-emitting base lines already consumed."""
        base = BASE.splitlines(keepends=True)
        doctored = [
            "@@ -5,1 +5,1 @@\n",
            "-    for attempt in range(3):\n",
            "+    for attempt in range(9):\n",
            "@@ -2,1 +2,1 @@\n",              # <-- rewinds behind the previous hunk
            "-\n",
            "+# added\n",
        ]
        with self.assertRaises(InstrumentInvalid) as caught:
            run.apply_unified(base, doctored)
        self.assertIn("ordered and non-overlapping", str(caught.exception))

    def test_render_and_prove_refuses_a_diff_that_does_not_reproduce_the_derived_bytes(self) -> None:
        """The integration of the two: if difflib and the applier ever disagree, the demo must refuse
        rather than display a transformation it did not perform."""
        original = difflib.unified_diff

        def lying_diff(*a: object, **k: object) -> list[str]:
            return list(original(BASE.splitlines(keepends=True),
                                 BASE.splitlines(keepends=True), n=3))  # a diff for the WRONG pair

        difflib.unified_diff = lying_diff  # type: ignore[assignment]
        try:
            with self.assertRaises(InstrumentInvalid) as caught:
                run.render_and_prove(BASE.encode(), DERIVED.encode(), "a", "b")
            self.assertIn("does not reproduce the derived bytes", str(caught.exception))
        finally:
            difflib.unified_diff = original  # type: ignore[assignment]

    def test_render_and_prove_ACCEPTS_the_honest_pair(self) -> None:
        """Without this, every refusal above is indistinguishable from a function that refuses
        everything."""
        out = run.render_and_prove(BASE.encode(), DERIVED.encode(), "a", "b")
        self.assertIn("-            continue", out)
        self.assertIn("+            raise", out)


class CorrespondenceIsDataNotComputation(unittest.TestCase):
    def test_DERIVED_FROM_is_a_literal_table_not_a_substring_rule(self) -> None:
        """Inferring "is this row derived?" from the substring ``mutated`` would be the same
        derive-by-string defect the pin fix removed, one module over."""
        src = (run.__file__ and open(run.__file__).read()) or ""
        self.assertNotIn('"mutated" in', src)
        self.assertNotIn("startswith(\"fixtures/retry-swallow-v2-mutated", src)
        for derived, base in run.DERIVED_FROM.items():
            self.assertIn(derived, {m for m, _ in pin.SUBJECT_ROWS},
                          "a derived row that is not a pinned subject")
            self.assertIn(base, {m for m, _ in pin.SUBJECT_ROWS},
                          "a base that is not a pinned subject")

    def test_the_MEASURED_json_key_is_read_LITERALLY(self) -> None:
        """REGRESSION. The first draft did ``measured_json.get("egress", measured_json)`` — and the
        real file's key is ``egress_counts``, so the fallback would have handed the pin cross-check
        every metadata key in the file ("format_version", "note", "witness_condition") as though they
        were expectation keys. Written from memory of the schema instead of from the file."""
        src = open(run.__file__).read()
        self.assertIn('raw["egress_counts"]', src)
        self.assertNotIn('.get("egress"', src)


class TheTwoArtifactsAreDifferentThings(unittest.TestCase):
    def test_the_run_report_carries_NO_verdict_column(self) -> None:
        """It is not a degraded verdict table. Showing verdicts for the rows that happened to be
        measured would reintroduce the partial table through the door marked 'diagnostics'."""
        src = open(run.__file__).read()
        body = src.split("def run_report(")[1].split("def verdict_table(")[0]
        self.assertNotIn("r.verdict", body)
        self.assertIn("no verdicts", body)

    def test_the_verdict_table_takes_a_CompletedRun_and_never_a_directory(self) -> None:
        import inspect
        sig = inspect.signature(run.verdict_table)
        self.assertEqual(sig.parameters["run"].annotation, "CompletedRun")
        src = open(run.__file__).read()
        table = src.split("def verdict_table(")[1]
        for forbidden in ("glob(", "iterdir(", "listdir("):
            self.assertNotIn(forbidden, table,
                             "the table must not be assembled by reading a directory")

    def test_every_exit_code_is_DISTINCT(self) -> None:
        """Automation must never route a real finding into an infrastructure-failure handler."""
        from demo import receipt
        codes = [receipt.EXIT_AGREE, receipt.EXIT_DRIFT, receipt.EXIT_INSTRUMENT,
                 receipt.EXIT_PINS, run.EXIT_CORPUS_UNAVAILABLE, run.EXIT_CORPUS_INTEGRITY]
        self.assertEqual(len(codes), len(set(codes)), f"exit codes collide: {codes}")

    def test_DRIFT_does_not_share_a_code_with_any_refusal(self) -> None:
        """Drift is the RESULT. If it shared a code with a refusal, a caller could not tell a finding
        from a broken instrument — which is the whole point of the taxonomy."""
        from demo import receipt
        self.assertNotIn(receipt.EXIT_DRIFT,
                         {receipt.EXIT_INSTRUMENT, receipt.EXIT_PINS,
                          run.EXIT_CORPUS_UNAVAILABLE, run.EXIT_CORPUS_INTEGRITY})


if __name__ == "__main__":
    unittest.main()


class TheParserRefusesWhatItUsedToWaveThrough(unittest.TestCase):
    """The four original rejections were ALL byte-divergence cases. None of these was covered by
    them — a rejection set that covers one failure mode is not evidence about the others."""

    def test_an_EMPTY_BASE_is_no_longer_spuriously_refused(self) -> None:
        """difflib emits ``@@ -0,0 +1 @@``; subtracting 1 gave -1 and tripped the ordering guard.
        Latent while every base is non-empty — exactly how it would have survived to the day one
        was not."""
        d = list(difflib.unified_diff([], ["x\n"]))
        self.assertEqual("".join(run.apply_unified([], d)), "x\n")

    def test_a_MALFORMED_hunk_header_raises_InstrumentInvalid_not_IndexError(self) -> None:
        """This function is billed as the artifact an offline sceptic runs, so non-difflib input is
        precisely what it will meet. Raw IndexError/ValueError escaped the taxonomy."""
        for bad in ("@@\n", "@@ garbage @@\n", "@@ +1,2 @@\n"):
            with self.assertRaises(InstrumentInvalid, msg=bad):
                run.apply_unified(["a\n"], [bad])

    def test_a_line_the_proof_would_IGNORE_is_refused(self) -> None:
        """A doctored diff could carry payload lines that RENDER in the displayed artifact — read by
        a human as part of the transformation — while the proof stepped straight over them."""
        base = ["a\n", "b\n"]
        d = list(difflib.unified_diff(base, ["a\n", "c\n"]))
        with self.assertRaises(InstrumentInvalid) as caught:
            run.apply_unified(base, d + ["!PAYLOAD SHOWN BUT NEVER CHECKED\n"])
        self.assertIn("unrecognised prefix", str(caught.exception))

    def test_a_NO_NEWLINE_marker_is_refused_rather_than_skipped(self) -> None:
        """difflib never emits it, but a hand-written diff will, and silently skipping it lets the
        displayed artifact differ from what was proven."""
        base = ["a\n"]
        d = list(difflib.unified_diff(base, ["b\n"])) + ["\\ No newline at end of file\n"]
        with self.assertRaises(InstrumentInvalid) as caught:
            run.apply_unified(base, d)
        self.assertIn("no-newline marker", str(caught.exception))


class TheLeakDetectorsDetectionEntersTheTaxonomy(unittest.TestCase):
    def test_NetworkIsolationError_is_NOT_an_InstrumentInvalid_subclass(self) -> None:
        """THE PREMISE, asserted rather than assumed — this is why the wrap is needed at all. If this
        ever becomes a subclass, the wrap is redundant and this test says so."""
        from sandbox.observed import NetworkIsolationError
        self.assertFalse(issubclass(NetworkIsolationError, InstrumentInvalid))

    def test_measure_row_WRAPS_prepare_so_a_leak_is_a_refusal_not_a_traceback(self) -> None:
        src = open(run.__file__).read()
        body = src.split("def measure_row(")[1].split("def run_report(")[0]
        self.assertIn("except NetworkIsolationError", body)
        self.assertIn("raise InstrumentInvalid", body)


class NothingIsSealedThatWasNotMeasured(unittest.TestCase):
    def test_an_UNREADABLE_counter_raises_instead_of_sealing_zero(self) -> None:
        """``egress_attempts or 0`` turned a proxy outage into measured=0 on a permanent receipt.
        Downstream refused it, but the lying bytes were already on disk."""
        # ⚠ AST AGAIN — the grep version matched MY OWN COMMENT describing the removed code.
        # Second prose-scan in one batch; the rule is to inspect what the code does, not what the
        # file says about itself.
        import ast
        tree = ast.parse(open(run.__file__).read())
        fn = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "measure_row")
        or_defaults = [n for n in ast.walk(fn) if isinstance(n, ast.BoolOp)
                       and isinstance(n.op, ast.Or)
                       and any(isinstance(v, ast.Attribute) and v.attr == "egress_attempts"
                               for v in n.values)]
        self.assertEqual(or_defaults, [],
                         "`egress_attempts or 0` seals an outage as a measurement of zero")
        guards = [n for n in ast.walk(fn) if isinstance(n, ast.Compare)
                  and isinstance(n.left, ast.Attribute) and n.left.attr == "egress_attempts"
                  and any(isinstance(o, ast.Is) for o in n.ops)]
        self.assertTrue(guards, "an unreadable counter must raise before anything is sealed")

    def test_events_are_NEVER_synthesised_from_the_count(self) -> None:
        src = open(run.__file__).read()
        self.assertNotIn("boundary-attempt-", src,
                         "labels derived from the count are computation where a sceptic reads data")

    def test_the_header_REFUSES_an_instrument_that_cannot_name_itself(self) -> None:
        """Resolving the digest before the header means the header can now FAIL — so it needs its own
        refusal, before any row runs. ``pending`` never could."""
        # ⚠ AST, NOT GREP. The first version scanned the source text and hit MY OWN COMMENT
        # explaining that "pending" used to be sealed — a test failing on prose that documents the
        # fix. Same defect as the earlier one that grepped for "insecure" and matched a docstring
        # saying no such flag exists. Establish direction first: inspect what the code DOES.
        # BEHAVIOURAL. The first version only scanned source, so disabling the guard left it green —
        # the red-proof harness reported NOT RED and the guard turned out to be untested.
        for bad in ("", "unknown", "pending"):
            with self.assertRaises(InstrumentInvalid, msg=f"digest {bad!r} was accepted"):
                run.require_nameable("abc123", "podman 4.9.3", bad)
            with self.assertRaises(InstrumentInvalid, msg=f"commit {bad!r} was accepted"):
                run.require_nameable(bad, "podman 4.9.3", "sha256:aa")
            with self.assertRaises(InstrumentInvalid, msg=f"version {bad!r} was accepted"):
                run.require_nameable("abc123", bad, "sha256:aa")
        # ...and it must ACCEPT a fully resolved instrument, or it is a function that refuses all.
        run.require_nameable("abc123", "podman 4.9.3", "sha256:aa")

        import ast
        literals = [kw.value.value
                    for node in ast.walk(ast.parse(open(run.__file__).read()))
                    if isinstance(node, ast.Call) for kw in node.keywords
                    if kw.arg == "image_digest" and isinstance(kw.value, ast.Constant)]
        self.assertNotIn("pending", literals, "the header must not seal a placeholder digest")


class AMalformedCorpusIsINTEGRITYNotATraceback(unittest.TestCase):
    """P3-3. `json.loads`, `["egress_counts"]` and `int(v)` raised OUTSIDE the four refusal classes,
    so a corpus that matched its pinned digest perfectly and then carried unusable contents produced
    a raw traceback and exit 1. A digest pins BYTES, NOT SEMANTICS."""

    def _write(self, text: str) -> Path:
        import tempfile
        p = Path(tempfile.mkdtemp()) / "MEASURED.json"
        p.write_text(text)
        return p

    def test_unparseable_json_is_CORPUS_INTEGRITY(self) -> None:
        with self.assertRaises(CorpusIntegrityError):
            run.read_recorded_counts(self._write("{not json"))

    def test_a_MISSING_egress_counts_key_is_CORPUS_INTEGRITY(self) -> None:
        with self.assertRaises(CorpusIntegrityError) as c:
            run.read_recorded_counts(self._write('{"format_version": 1}'))
        self.assertIn("BYTES, NOT SEMANTICS", str(c.exception))

    def test_an_EMPTY_counts_object_is_refused(self) -> None:
        """It would cross-check against nothing and pass — an empty result is not a value."""
        with self.assertRaises(CorpusIntegrityError) as c:
            run.read_recorded_counts(self._write('{"egress_counts": {}}'))
        self.assertIn("empty result is not a value", str(c.exception))

    def test_a_NON_INTEGER_count_is_refused_rather_than_coerced(self) -> None:
        for bad in ('"3"', "3.5", "null", "true"):
            with self.assertRaises(CorpusIntegrityError, msg=bad):
                run.read_recorded_counts(self._write('{"egress_counts": {"a": %s}}' % bad))

    def test_a_WELL_FORMED_record_is_accepted(self) -> None:
        """Without this every refusal above is indistinguishable from a function that refuses all."""
        got = run.read_recorded_counts(self._write('{"egress_counts": {"a": 3, "b": 0}}'))
        self.assertEqual(got, {"a": 3, "b": 0})

    def test_the_parse_is_INSIDE_the_taxonomy(self) -> None:
        """CorpusIntegrityError is one of main()'s four caught classes, so this maps to exit 6."""
        src = open(run.__file__).read()
        self.assertIn("except CorpusIntegrityError", src)
        self.assertIn("read_recorded_counts(corpus", src)


class TheDocstringsDoNotOverclaim(unittest.TestCase):
    def test_apply_unified_does_NOT_call_itself_the_proof(self) -> None:
        """The demo's whole subject is what constitutes proof. A reader following the code to find
        the proof would land on the parser and stop."""
        doc = run.apply_unified.__doc__ or ""
        self.assertNotIn("ONLY THING HERE THAT PROVES", doc)
        # The SECTION BANNER above it carried the same overclaim — a docstring-only check would
        # have passed while the file still told a reader the applier was the proof.
        self.assertNotIn("the only actual proof", open(run.__file__).read())
        self.assertIn("NOT THE PROOF", doc)
        self.assertIn("render_and_prove", doc)

    def test_receipt_does_not_narrate_a_field_it_does_not_have(self) -> None:
        import dataclasses
        from demo.receipt import Receipt
        src = open(__import__("demo.receipt", fromlist=["x"]).__file__).read()
        fields = {f.name for f in dataclasses.fields(Receipt)}
        self.assertNotIn("seal_verified_at_start", fields)
        # It may be NAMED in the paragraph explaining its absence, but must not be described as a
        # field the receipt carries.
        self.assertNotIn("seal_verified_at_start — the escape probe", src)


class OneCanonicalResolver(unittest.TestCase):
    """The first live run died on TWO derivations of one identity: this module's own
    `_resolve_image_digest` returned bare hex from `{{.Id}}` while the sandbox used
    `resolve_image_id` returning `sha256:`-prefixed. Same image, format disagreement, and the
    comparison declared "the image changed mid-run"."""

    def test_the_second_resolver_is_DELETED_not_aliased(self) -> None:
        """An alias is one refactor away from acquiring its own normalisation and becoming a second
        derivation wearing one name."""
        self.assertFalse(hasattr(run, "_resolve_image_digest"))

    def test_the_header_uses_the_ENGINES_resolver(self) -> None:
        import ast
        tree = ast.parse(open(run.__file__).read())
        called = {n.func.id for n in ast.walk(tree)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        self.assertIn("resolve_image_id", called)

    def test_the_two_paths_now_AGREE_on_the_same_image(self) -> None:
        """THE FALSE POSITIVE, closed. This is the exact pair that failed the first live run."""
        run.require_same_image("row", "sha256:abc", "sha256:abc")   # must not raise

    def test_a_REAL_mid_run_image_change_is_STILL_refused(self) -> None:
        """⚠ THE GUARD MUST NOT BE LOST WHILE THE FALSE POSITIVE IS FIXED. Both sides now call one
        function, so in production this compares two calls to `resolve_image_id` and always agrees —
        the fix removed the guard's ability to fire on its own. It earned its place by catching a
        real defect on first contact with a runtime; it does not get demoted in the commit that
        fixes it."""
        with self.assertRaises(InstrumentInvalid) as c:
            run.require_same_image("row", "sha256:aaa", "sha256:bbb")
        self.assertIn("changed mid-run", str(c.exception))

    def test_NO_normalisation_papers_over_a_format_disagreement(self) -> None:
        """Stripping/adding `sha256:` would treat a FORMAT disagreement as equality and leave the two
        derivations in place — the next divergence reopens silently, or hides a real change."""
        with self.assertRaises(InstrumentInvalid):
            run.require_same_image("row", "abc", "sha256:abc")

    def test_the_report_does_not_claim_sealed_rows_when_there_are_none(self) -> None:
        """Observed on the first live run: the note said "the rows above are sealed" with
        `sealed rows 0` four lines above it."""
        from demo.receipt import Instrument, RunHeader
        h = RunHeader("n" * 32, Instrument("g", "sha256:i", "podman", "podman v1", "sealed", "w"),
                      "d" * 64)
        out = run.run_report(h, [], [], "the rows above are sealed but carry NO verdicts")
        self.assertNotIn("rows above are sealed", out)
        self.assertIn("before ANY row was sealed", out)

    def test_the_runtime_name_is_not_doubled(self) -> None:
        """Rendered as "podman podman version 4.9.3" — `--version` already names the runtime."""
        from demo.receipt import Instrument
        r = Instrument("g", "sha256:i", "podman", "podman version 4.9.3", "sealed", "w").render()
        self.assertNotIn("podman podman", r)


class TheNoVCSRefusalTellsYouWhatToDo(unittest.TestCase):
    """Three real stranger paths reach this refusal and need DIFFERENT fixes. A single generic hint
    would be wrong for two of them, so the hint is DERIVED from git's own stderr — the same contract
    preflight keeps: a remediation wherever one is mechanically derivable."""

    CASES = [
        ("fatal: not a git repository (or any of the parent directories): .git",
         "no `.git` here at all", "zip / vendored copy"),
        ("fatal: not a git repository: /nonexistent/path",
         "git WORKTREE", "worktree whose gitdir is absent"),
        ("fatal: ambiguous argument 'HEAD': unknown revision or path not in the working tree.",
         "NO COMMITS", "checkout with no history"),
        ("fatal: detected dubious ownership in repository at '/x'",
         "owned by another user", "foreign-owned checkout"),
    ]

    def test_each_failure_mode_gets_its_OWN_remediation(self) -> None:
        seen = set()
        for stderr, expected, label in self.CASES:
            hint = run.vcs_hint(stderr)
            self.assertIn(expected, hint, f"wrong hint for {label}")
            seen.add(hint)
        self.assertEqual(len(seen), len(self.CASES),
                         "two failure modes produced the SAME hint — then it is generic, and generic "
                         "is wrong for at least one of them")

    def test_an_EMPTY_stderr_does_not_invent_a_diagnosis(self) -> None:
        """Silence where nothing is derivable, rather than a guess presented as a finding."""
        self.assertIn("no diagnostic", run.vcs_hint(""))

    def test_the_REFUSAL_still_refuses(self) -> None:
        """The guard is right and does not soften: an unidentified instrument must not seal."""
        with self.assertRaises(InstrumentInvalid) as c:
            run.require_nameable("unknown", "podman 4.9.3", "sha256:aa",
                                 "fatal: not a git repository (or any of the parent directories): .git")
        msg = str(c.exception)
        self.assertIn("cannot name itself", msg)
        self.assertIn("hint", msg)
        self.assertIn("git clone", msg)

    def test_a_RESOLVED_instrument_still_passes(self) -> None:
        run.require_nameable("abc123", "podman 4.9.3", "sha256:aa", "")

    def test_git_commit_returns_its_own_diagnostic(self) -> None:
        """The stderr is carried, not swallowed — that is what makes the hint derivable."""
        commit, diag = run._git_commit()
        self.assertIsInstance(commit, str)
        self.assertIsInstance(diag, str)

    def test_git_stderr_is_CARRIED_from_the_probe_to_the_hint(self) -> None:
        """THE SEAM. Reverting `_git_commit` to swallow stderr left every other test green, because
        they all hand the stderr to `require_nameable` directly. This drives the real probe against a
        real non-repository and requires the derived hint to come out the other end."""
        import tempfile
        commit, diag = run._git_commit(Path(tempfile.mkdtemp()))
        self.assertEqual(commit, "unknown")
        self.assertTrue(diag, "git's diagnostic was swallowed — the hint cannot be derived from it")
        self.assertIn("no `.git` here at all", run.vcs_hint(diag))
