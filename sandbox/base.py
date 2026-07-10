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
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    SandboxHandle,
)


class BaseSandbox(ABC):
    """Mixin base: RAII ``session()`` in terms of the backend's primitives."""

    isolation_level: IsolationLevel

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
