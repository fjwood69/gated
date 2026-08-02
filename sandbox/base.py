"""BaseSandbox — shared RAII for isolation backends (NOT in the core contract layer).

Ruling D: ``session()`` was duplicated identically across backends; divergent
cleanup is a subtle-bug risk. This provides it once — prepare -> yield -> teardown
in a ``finally`` (every exit path, incl. exceptions; relies on teardown being
idempotent) — so backends implement only the primitives. Lives in ``sandbox/`` to
keep ``core`` a pure Protocol.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Iterator

from core import (
    ArtifactSpec,
    Command,
    EgressAbsence,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    SandboxHandle,
)


class BaseSandbox(ABC):
    """Mixin base: RAII ``session()`` in terms of the backend's primitives."""

    isolation_level: IsolationLevel

    observes_egress: bool = False
    """Does this backend class HAVE a boundary observer? Defaults to False because most backends do not,
    and an observing backend must say so DELIBERATELY — a default of True would let a backend inherit a
    capability claim it cannot honour."""

    @property
    def egress_when_unobserved(self) -> EgressAbsence:
        """The absence variant for a backend that has NO observer — DERIVED from the class, never passed.

        This is the whole mechanism behind ``NOT_OBSERVED`` being a static capability fact. Handing the
        variant in at the construction site leaves the type ACCEPTING AN ANSWER, and an answer can be
        wrong: a backend could pass ``NOT_OBSERVED`` while holding a live observer and nothing would
        object. Reading it from here means the claim is derived from ``observes_egress``, which is a fact
        about the code rather than a decision at a call site.

        RAISES for an observing backend rather than returning the variant. An observer that failed is
        ``OBSERVER_UNREADABLE`` (the run completed; its product is uncertifiable) or a whole-run refusal
        (the observer never came up) — never ``NOT_OBSERVED``, which would be a third absence squatting
        on the most innocent spelling.

        ⚠ SCOPE OF THAT GUARANTEE, stated exactly, because an earlier version of this docstring OVERCLAIMED
        it and was FALSE. It said the wrong variant was "unobtainable through the only channel that
        produces it". This is not the only channel: ``EgressAbsence.NOT_OBSERVED`` is a public importable
        member, ``ExecutionResult`` accepts it, and a backend can write the literal without ever touching
        this property — the tree's own test suite does exactly that. Worse, ``Sandbox`` is a Protocol, so
        a conforming backend need not inherit ``BaseSandbox`` and would inherit none of this.

        What this property actually buys: for a backend that DOES inherit here and DOES route through it,
        a correct-by-construction absence. HARD TO GET WRONG BY ACCIDENT — not unaskable-wrong. The claim
        is made true elsewhere, by ``engine.runner._require_consistent_egress_capability``, which sees the
        result AND the backend class at one choke point and brackets both directions for any backend;
        and by an AST guard restricting the literal to this module in production code.
        """
        if self.observes_egress:
            raise TypeError(
                f"{type(self).__name__} declares observes_egress=True, so it must never report "
                "NOT_OBSERVED. An observer that ran and could not be read is OBSERVER_UNREADABLE; an "
                "observer that never came up is a whole-run refusal, not a completed run with no "
                "observation"
            )
        return EgressAbsence.NOT_OBSERVED

    @abstractmethod
    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle: ...

    @abstractmethod
    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult: ...

    @abstractmethod
    def teardown(self, handle: SandboxHandle) -> None: ...

    @contextmanager
    def session(
        self, artifact: ArtifactSpec, fixtures: Fixtures
    ) -> Iterator[SandboxHandle]:
        handle = self.prepare(artifact, fixtures)
        try:
            yield handle
        finally:
            self.teardown(handle)  # every exit path, incl. exceptions; idempotent
