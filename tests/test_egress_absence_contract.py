"""P3 step 1 item (i) — absence of an egress count is TYPED, and the capability variant is DERIVED.

WHAT WAS WRONG. ``egress_attempts: int | None`` spelled two different absences the same way:

  * NO OBSERVER EXISTS — the normal terminal state of three of four backends, which never set the field
    and let it default;
  * AN OBSERVER RAN AND ITS COUNT COULD NOT BE READ — only ``ObservedOCISandbox`` can produce this.

The field's own docstring documented the first and was therefore FALSE about the second from the day the
second became possible. The original ratified instruction was to REFUSE ``completed`` + ``None``; that
was withdrawn as incoherent, because it would have made three backends' legitimate terminal state
unrepresentable. The PURPOSE survived: no consumer may inherit a false PASS by coalescing absence into
zero.

HOW THE DEFECT SURVIVED, which is the argument for this change stated as an observation rather than a
design claim: THE OUTERMOST LAYER HAD THE DISCIPLINE AND THE TYPE DID NOT. ``demo/run.py`` already
refused an unreadable counter rather than sealing zero, and ``tests/test_demo_run.py`` already banned
``egress_attempts or 0`` by AST. So the demo's refusal protected THE DEMO. Every intermediate consumer
was free to coerce, and nothing protected the next detector.

THE THREE PINS BELOW, in order of how long they outlive this increment:

  1. CLASS-DERIVATION, BOTH DIRECTIONS. A class declaring ``observes_egress = False`` derives its
     absence; one declaring ``True`` cannot obtain ``NOT_OBSERVED`` through the accessor.
     ⚠ AN EARLIER VERSION OF THIS LINE SAID THIS MADE A FIFTH BACKEND "UNASKABLE-WRONG". IT DID NOT, and
     the overclaim is kept here rather than quietly deleted. The member is public and the field accepts
     it, so a backend can write the literal and never touch the accessor — the tree's own suite does. The
     accessor buys HARD-TO-GET-WRONG-BY-ACCIDENT. What buys the strong claim is the pair below: the
     runner's choke-point check (which also reaches Protocol backends that never inherit BaseSandbox) and
     the AST ban on constructing a result with the literal.
  1b. THE MISSING MUTANT. The first red-proof matrix looked complete because every mutant that could be
     written went red; the one that could NOT be written was direct-literal construction. A
     complete-looking matrix is evidence about the mutants you thought of.
  2. NO DEFAULT — a backend cannot state an absence by ACCIDENT, i.e. by omission.
  3. EXHAUSTIVE DIAGNOSIS — every ``EgressAbsence`` member maps to its own ``Reason``, so a future
     variant cannot silently fall back to a generic one. One verdict class, two diagnoses: "never ran"
     and "ran and produced nothing" have different fixes, and collapsing them would replace one spelling
     of absence with two that print identically.
"""
from __future__ import annotations

import dataclasses
import unittest
from pathlib import Path

from core import (
    EgressAbsence,
    IsolationLevel,
    EgressCapabilityContradiction,
    EgressCapabilityUndeclared,
    ExecutionResult,
)
from engine.runner import _require_consistent_egress_capability
from core.assertion import Reason, Verdict, VerdictType
from core.sandbox import SandboxStartError
from engine.retry import _ABSENCE_REASON
from sandbox.base import BaseSandbox
from sandbox.noop import NoOpSandbox
from sandbox.observed import ObservedOCISandbox
from sandbox.oci import OCISandbox
from sandbox.subprocess import SubprocessSandbox

_BACKENDS = (NoOpSandbox, SubprocessSandbox, OCISandbox, ObservedOCISandbox)


class CapabilityIsDerivedFromTheClass(unittest.TestCase):
    """THE PIN THAT OUTLIVES THIS INCREMENT. Passing the variant at construction leaves the type
    ACCEPTING AN ANSWER, and an answer can be wrong. Deriving it asks the question where the answer is a
    fact about the code."""

    def test_every_backend_declares_the_capability(self) -> None:
        """Not inherited by accident: a backend that never thought about it gets ``False`` from
        ``BaseSandbox``, which is the safe direction, but the declaration must EXIST and be a bool."""
        for cls in _BACKENDS:
            self.assertIsInstance(
                getattr(cls, "observes_egress", None), bool,
                f"{cls.__name__} does not declare observes_egress — the absence variant cannot be "
                "derived, so NOT_OBSERVED would have to be passed in and could be passed WRONGLY",
            )

    def test_a_non_observing_backend_derives_not_observed(self) -> None:
        for cls in (NoOpSandbox, SubprocessSandbox, OCISandbox):
            self.assertFalse(cls.observes_egress, f"{cls.__name__} unexpectedly claims an observer")
            got = BaseSandbox.egress_when_unobserved.fget(cls.__new__(cls))  # type: ignore[attr-defined]
            self.assertIs(
                got, EgressAbsence.NOT_OBSERVED,
                f"{cls.__name__} must derive NOT_OBSERVED from its class declaration",
            )

    def test_an_observing_backend_CANNOT_OBTAIN_not_observed(self) -> None:
        """THE OTHER DIRECTION, and the one a fifth backend gets wrong. An observer that failed is
        OBSERVER_UNREADABLE (the run completed; its product is uncertifiable) or a whole-run refusal (the
        observer never came up) — never NOT_OBSERVED, which would be a third absence squatting on the
        most innocent spelling. It RAISES rather than returning — but ONLY for callers that go through
        this accessor. The literal remains reachable directly; that hole is closed at the runner."""
        self.assertTrue(ObservedOCISandbox.observes_egress)
        with self.assertRaises(TypeError):
            BaseSandbox.egress_when_unobserved.fget(  # type: ignore[attr-defined]
                ObservedOCISandbox.__new__(ObservedOCISandbox))


class TheBackendListIsDiscovered(unittest.TestCase):
    """A hand-maintained tuple covers a FIFTH backend only when a human remembers to edit it."""

    def test_the_pinned_list_matches_every_BaseSandbox_subclass(self) -> None:
        def descendants(cls: type) -> set[type]:
            out: set[type] = set()
            for sub in cls.__subclasses__():
                out.add(sub)
                out |= descendants(sub)
            return out
        live = {c for c in descendants(BaseSandbox) if not c.__name__.startswith("_")}
        self.assertEqual(
            live, set(_BACKENDS),
            "the pinned backend list has drifted from the live BaseSandbox subclasses — a backend not in "
            "the tuple is a backend none of the pins below inspect. NOTE the residual limit: Sandbox is a "
            "PROTOCOL, so a conforming backend need not inherit BaseSandbox and would be invisible here "
            "too. That gap is closed at the runner choke point, not by this test",
        )


class TheLiteralIsRestrictedInProductionCode(unittest.TestCase):
    """THE MISSING MUTANT, made writable.

    The red-proof matrix for this increment looked complete because every mutant that could be written
    went red. The one that could NOT be written was direct-literal construction — ``NOT_OBSERVED`` is a
    public member, so a backend can bypass the derivation entirely, and no test existed that such a
    mutant would have failed. A complete-looking matrix is only evidence about the mutants you thought
    of; the missing one is where the hole is.

    This is that test. Production code may name the literal only where the derivation lives. Test code is
    exempt: fakes legitimately declare their own absence, and the runner check brackets them at runtime
    anyway.
    """

    def test_no_production_site_CONSTRUCTS_a_result_with_the_literal(self) -> None:
        """THE POSITIVE SHAPE, after a first attempt that was too broad.

        Banning every MENTION of the member was wrong and this test caught it immediately: it flagged
        ``engine/retry.py`` using it as a MAP KEY and ``engine/runner.py`` using it in an ``is``
        comparison inside the consistency guard. Both READ the variant; neither ASSERTS it. Widening an
        allow-list to admit them would have been exemption by adjacency — a grant justified for one thing
        and consumed by another.

        The defect is narrower and nameable: A BACKEND STATING THE CAPABILITY BY HAND, i.e. the literal
        passed as the egress value of a constructed result. That is the only shape that bypasses the
        derivation, and it is the mutant the earlier red-proof matrix could not express.
        """
        import ast
        root = Path(__file__).resolve().parent.parent
        allowed = {"sandbox/base.py"}
        offenders = []

        def is_the_literal(node: ast.expr) -> bool:
            return (isinstance(node, ast.Attribute) and node.attr == "NOT_OBSERVED"
                    and isinstance(node.value, ast.Name) and node.value.id == "EgressAbsence")

        for pkg in ("core", "sandbox", "engine", "gate", "cli", "observe", "demo"):
            for path in sorted((root / pkg).rglob("*.py")):
                rel = path.relative_to(root).as_posix()
                if rel in allowed:
                    continue
                for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                    if not isinstance(node, ast.Call):
                        continue
                    callee = (node.func.attr if isinstance(node.func, ast.Attribute)
                              else getattr(node.func, "id", ""))
                    if callee not in ("ExecutionResult", "_result"):
                        continue
                    if any(is_the_literal(a) for a in node.args) or any(
                            is_the_literal(k.value) for k in node.keywords):
                        offenders.append(f"{rel}:{node.lineno}")
        self.assertEqual(
            offenders, [],
            "a production site CONSTRUCTS a result with EgressAbsence.NOT_OBSERVED written by hand: "
            f"{offenders}. The variant is a CAPABILITY FACT ABOUT THE CLASS and must be DERIVED from "
            "``observes_egress`` — writing it at a construction site is exactly how a backend states it, "
            "and therefore how a backend states it WRONGLY",
        )


class TheChokePointBracketsBothDirections(unittest.TestCase):
    """The runner check is what makes the strong claim TRUE, so it needs its own red witness.

    It was added and initially SHIPPED UNTESTED — deleting it left every other test green, which by this
    tree's own standard makes it a claim rather than a control. Found by writing the mutant: the harness
    that checks a guard is also what proves the guard is load-bearing.

    Both directions, because a control that brackets one certifies nothing about the other. Plus a
    positive control, so the test cannot pass by never engaging.
    """

    @staticmethod
    def _result(egress: object) -> ExecutionResult:
        return ExecutionResult(
            outcome="completed", exit_code=0, isolation_level=NoOpSandbox.isolation_level,
            artifact_hash="sha256:x", egress_attempts=egress,  # type: ignore[arg-type]
        )

    def test_an_observing_backend_reporting_NOT_OBSERVED_is_refused(self) -> None:
        """The capability lie: the innocent-looking variant from a backend whose observer may simply
        have failed. This is the shape the accessor cannot prevent, because the literal is public."""
        with self.assertRaises(EgressCapabilityContradiction) as caught:
            _require_consistent_egress_capability(
                ObservedOCISandbox.__new__(ObservedOCISandbox),
                self._result(EgressAbsence.NOT_OBSERVED))
        # NOT a SandboxStartError: that type means NO RUN OCCURRED, and here a run completed. Asserting
        # the negative too, because a subclass would satisfy assertRaises above while re-opening the
        # silent reclassification into a per-trial ERROR verdict that run_check's handler performs.
        self.assertNotIsInstance(caught.exception, SandboxStartError)

    def test_a_non_observing_backend_reporting_a_COUNT_is_refused(self) -> None:
        """The other direction: a measurement nothing took."""
        with self.assertRaises(EgressCapabilityContradiction) as caught:
            _require_consistent_egress_capability(NoOpSandbox(), self._result(3))
        self.assertNotIsInstance(caught.exception, SandboxStartError)

    def test_the_exception_CARRIES_the_evidence_through_stringification(self) -> None:
        """Propagation alone DISCARDS the completed trials: no TrialReport is built on the raise path.
        That is acceptable for a harness fault only if the exception is the evidence vessel — and
        verified against the live path, gate/executor.py converts a worker exception into
        InfrastructureFailure(WORKER_FAULT, detail=repr(exc)), which STRINGIFIES it. Evidence held only
        on an attribute would be discarded exactly where it is needed."""
        done = (Verdict(VerdictType.PASS, Reason.EGRESS_GE_2),
                Verdict(VerdictType.FAIL, Reason.EGRESS_ONE))
        with self.assertRaises(EgressCapabilityContradiction) as caught:
            _require_consistent_egress_capability(NoOpSandbox(), self._result(3), done)
        exc = caught.exception
        self.assertEqual(exc.completed_trials, done, "the verdicts must be on the exception")
        rendered = repr(exc)
        for token in ("NoOpSandbox", "EGRESS_GE_2", "EGRESS_ONE"):
            self.assertIn(token, rendered,
                          f"{token!r} is lost when the exception is stringified by its actual handler")

    def test_an_UNDECLARED_capability_is_NON_CONFORMANCE_not_contradiction(self) -> None:
        """A DISTINCT type, because they are different faults with different fixes: a contradiction means
        the backend answered wrongly; non-conformance means it never answered. Reading with a default
        would have coalesced undeclared into declared-False and let a backend with a live observer pass by
        inheriting a claim it never made."""
        class _Undeclared:  # satisfies nothing; deliberately does NOT declare observes_egress
            pass
        with self.assertRaises(EgressCapabilityUndeclared):
            _require_consistent_egress_capability(
                _Undeclared(), self._result(EgressAbsence.NOT_OBSERVED))  # type: ignore[arg-type]

    def test_a_NON_BOOL_declaration_is_also_non_conformance(self) -> None:
        """A truthy non-bool would pass a bool() coercion and silently answer the question."""
        class _Truthy:
            observes_egress = "yes"  # type: ignore[assignment]
        with self.assertRaises(EgressCapabilityUndeclared):
            _require_consistent_egress_capability(
                _Truthy(), self._result(EgressAbsence.NOT_OBSERVED))  # type: ignore[arg-type]

    def test_the_runner_ACTUALLY_CALLS_it(self) -> None:
        """WIRING, not behaviour — and they are two different claims.

        The three tests around this one invoke the check DIRECTLY, so they stay green even if the runner
        never calls it. Deleting the call site was mutated and NOTHING WENT RED: the classic
        testing-the-thing-next-to-the-thing, which this tree has now hit four times. A guard that is
        correct and unwired is a guard that does not run.

        Parsed, not grepped: this asserts the call node exists inside ``run_check``, which is the
        function that owns the result-and-backend pair.
        """
        import ast
        import inspect as _inspect

        from engine import runner as _runner
        tree = ast.parse(_inspect.getsource(_runner.run_check))
        called = {
            (n.func.id if isinstance(n.func, ast.Name) else getattr(n.func, "attr", ""))
            for n in ast.walk(tree) if isinstance(n, ast.Call)
        }
        self.assertIn(
            "_require_consistent_egress_capability", called,
            "run_check does not call the egress-capability consistency check — the guard exists but is "
            "not wired, so a backend's capability claim is unbracketed at the only site that sees both "
            "the result and the backend class",
        )

    def test_consistent_pairs_pass(self) -> None:
        """POSITIVE CONTROL. Without it the two refusals above could both be satisfied by a check that
        rejects everything."""
        _require_consistent_egress_capability(
            NoOpSandbox(), self._result(EgressAbsence.NOT_OBSERVED))
        _require_consistent_egress_capability(
            ObservedOCISandbox.__new__(ObservedOCISandbox), self._result(2))
        _require_consistent_egress_capability(
            ObservedOCISandbox.__new__(ObservedOCISandbox),
            self._result(EgressAbsence.OBSERVER_UNREADABLE))


class FromRunDerivesWhatItCan(unittest.TestCase):
    """A CONVENIENCE with a stated ceiling, not a security control.

    It does NOT make the lie unconstructible — ExecutionResult is a public frozen dataclass and the raw
    constructor stays open — and it does NOT verify declaration truth, because it derives FROM the
    declaration. What it removes is the PARAMETER through which a non-observing backend could state a
    count, and the ACCEPTED VALUE by which an observing one could claim it has no observer.
    """

    class _NoObs:
        isolation_level = IsolationLevel.WEAK
        observes_egress = False

    class _Obs:
        isolation_level = IsolationLevel.HERMETIC
        observes_egress = True

    def _mk(self, sandbox: object, **kw: object) -> ExecutionResult:
        return ExecutionResult.from_run(
            sandbox, outcome="completed", exit_code=0, artifact_hash="sha256:x", **kw)  # type: ignore[arg-type,misc]

    def test_a_non_observing_backend_gets_its_absence_DERIVED(self) -> None:
        self.assertIs(self._mk(self._NoObs()).egress_attempts, EgressAbsence.NOT_OBSERVED)

    def test_a_non_observing_backend_CANNOT_supply_a_count(self) -> None:
        with self.assertRaises(EgressCapabilityContradiction):
            self._mk(self._NoObs(), measured=3)

    def test_an_observing_backend_CANNOT_claim_NOT_OBSERVED(self) -> None:
        """The variant is not an accepted answer for a backend that HAS an observer."""
        with self.assertRaises(EgressCapabilityContradiction):
            self._mk(self._Obs(), measured=EgressAbsence.NOT_OBSERVED)

    def test_an_observing_backend_MUST_answer(self) -> None:
        """Omitting the measurement is not the same as having no observer."""
        with self.assertRaises(EgressCapabilityContradiction):
            self._mk(self._Obs())

    def test_an_observing_backend_may_report_a_count_or_UNREADABLE(self) -> None:
        """POSITIVE CONTROL — without it the four refusals above are satisfied by a factory that
        rejects everything."""
        self.assertEqual(self._mk(self._Obs(), measured=2).egress_attempts, 2)
        self.assertIs(self._mk(self._Obs(), measured=EgressAbsence.OBSERVER_UNREADABLE).egress_attempts,
                      EgressAbsence.OBSERVER_UNREADABLE)

    def test_isolation_level_is_derived_from_the_backend(self) -> None:
        """Derive everything derivable, so the passed-value surface shrinks to what is irreducibly
        per-run."""
        self.assertIs(self._mk(self._Obs(), measured=1).isolation_level, IsolationLevel.HERMETIC)
        self.assertIs(self._mk(self._NoObs()).isolation_level, IsolationLevel.WEAK)


class TheGuardPostureMustBeSpelled(unittest.TestCase):
    def test_backend_guard_is_a_required_keyword(self) -> None:
        """A default made THE UNGUARDED PATH THE DEFAULT — a caller got it by doing nothing, so the
        secure composition was available rather than enforced. Required-with-explicit-None makes skipping
        the guard a spelled, greppable act. No behaviour change: both production callers already passed
        it; the sixteen that did not were tests."""
        import inspect as _inspect

        from engine.runner import run_check
        param = _inspect.signature(run_check).parameters["backend_guard"]
        self.assertIs(
            param.default, _inspect.Parameter.empty,
            "backend_guard has a default again — a caller can now omit the guard by doing nothing, and "
            "the unguarded path is once more reachable without anyone writing it down",
        )
        self.assertIs(param.kind, _inspect.Parameter.KEYWORD_ONLY)


class TheReportedCountIsNotComputed(unittest.TestCase):
    """``_egress`` REPORTS the observer's count. It does not adjust it.

    ``ObservedHandle`` carried a ``baseline`` field documented as "proxy count after the escape probe
    (subtracted from the final)". It was assigned the literal ``0`` on every path, so the subtraction was
    identically the identity function — the comment described the PRE-RESTART design, superseded when
    ``prepare()`` began restarting the proxy after the probe so the artifact faces a fresh observer at
    zero. The field outlived the design that justified it.

    SUBTRACTION WOULD BE WRONG EVEN IF THE FIELD WERE LIVE, which is why the fix was deletion rather than
    repair: a one-shot contamination is contamination, and subtracting it LAUNDERS it into a clean
    number; an ONGOING source contributes at T1..Tn, so a baseline measured at T0 under-corrects by
    exactly the post-start events. Contamination is eliminated or discriminated AT THE OBSERVER, never
    corrected arithmetically afterwards.

    A DELETION WITH NO GUARD CAN BE SILENTLY UNDONE, and this one is easy to reintroduce because a
    correction term reads as prudence. Parsed, not scanned.
    """

    def test_ObservedHandle_carries_no_baseline_field(self) -> None:
        import dataclasses

        from sandbox.observed import ObservedHandle
        names = {f.name for f in dataclasses.fields(ObservedHandle)}
        self.assertNotIn(
            "baseline", names,
            "ObservedHandle has a baseline field again — a correction term on the verdict input, which "
            "launders a one-shot contamination and under-corrects an ongoing one",
        )

    def test_the_egress_read_performs_no_arithmetic(self) -> None:
        import ast

        src = (Path(__file__).resolve().parent.parent / "sandbox" / "observed.py").read_text()
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "_egress")
        # ARITHMETIC operators only. A first version flagged every BinOp and immediately tripped on the
        # return annotation ``int | EgressAbsence``, whose ``|`` parses as BitOr — the guard accusing the
        # type of doing arithmetic. Naming the operators is the positive shape; "any BinOp" was a
        # convenient over-approximation that happened to be wrong on the very function it guards.
        _ARITH = (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow)
        ops = [type(n.op).__name__ for n in ast.walk(fn)
               if isinstance(n, ast.BinOp) and isinstance(n.op, _ARITH)]
        self.assertEqual(
            ops, [],
            f"_egress performs arithmetic on the observer's count ({ops}). The reported number is the "
            "number the observer produced; anything else is a correction, and a correction is a claim "
            "about contamination that the reader cannot check",
        )


class AbsenceCannotBeStatedByAccident(unittest.TestCase):
    def test_the_field_has_no_default(self) -> None:
        """A default is spelled absence AT THE CONSTRUCTION SITE: it lets a backend omit the field and
        thereby assert 'no measurement' without ever deciding to."""
        field = {f.name: f for f in dataclasses.fields(ExecutionResult)}["egress_attempts"]
        self.assertIs(
            field.default, dataclasses.MISSING,
            "egress_attempts has a default again — a backend can now state an absence by OMISSION",
        )
        self.assertIs(field.default_factory, dataclasses.MISSING)

    def test_constructing_without_it_raises(self) -> None:
        with self.assertRaises(TypeError):
            ExecutionResult(  # type: ignore[call-arg]
                outcome="completed", exit_code=0,
                isolation_level=NoOpSandbox.isolation_level, artifact_hash="sha256:x",
            )


class EveryAbsenceHasItsOwnDiagnosis(unittest.TestCase):
    def test_the_map_is_exhaustive_over_the_enum(self) -> None:
        """Exhaustive BY TEST, so a future variant cannot silently fall back to a generic reason. The
        verdict class is shared; the diagnosis is not."""
        self.assertEqual(
            set(_ABSENCE_REASON), set(EgressAbsence),
            "an EgressAbsence variant has no Reason of its own — it would print as some other absence",
        )

    def test_the_two_diagnoses_are_distinct(self) -> None:
        self.assertEqual(
            len(set(_ABSENCE_REASON.values())), len(_ABSENCE_REASON),
            "two absences share a Reason — that is one spelling of absence replaced by two that print "
            "identically, which is the defect this increment exists to close",
        )

    def test_no_reason_string_claims_a_single_producer(self) -> None:
        """``TELEMETRY_MISSING`` used to read 'observer failed'. It was already false for a backend with
        no observer AND for the MALFORMED engine decision that also raises it. A reason's text is what an
        operator reads, so it must not name a mechanism it cannot vouch for."""
        for reason in (Reason.TELEMETRY_MISSING, Reason.TELEMETRY_NOT_OBSERVED,
                       Reason.TELEMETRY_UNREADABLE):
            self.assertNotIn(
                "observer failed", reason.value,
                f"{reason.name} claims 'observer failed', which is not true of all its producers",
            )


if __name__ == "__main__":
    unittest.main()
