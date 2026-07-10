"""NoOpSandbox — the null backend (no isolation, no execution, no verification).

For conformance/tests only: satisfies ``core.Sandbox`` without doing anything. It
stages nothing, so there is nothing to hash — it does NOT verify the artifact hash,
it echoes the claimed one. Never a real gate backend. (Moved from core/ to sandbox/
under Ruling D — it is an implementation, so it belongs with the backends.)
"""
from __future__ import annotations

from dataclasses import dataclass

from core import (
    ArtifactSpec,
    Command,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    Sandbox,
    SandboxHandle,
)
from sandbox.base import BaseSandbox


@dataclass(frozen=True)
class NoOpHandle:
    """Minimal SandboxHandle — the two read-only members the contract requires."""

    id: str
    artifact_hash: str


class NoOpSandbox(BaseSandbox):
    """Satisfies ``Sandbox`` without isolating, executing, or verifying anything."""

    isolation_level: IsolationLevel = IsolationLevel.WEAK

    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        # Null backend: stages nothing, so it cannot verify — echoes the claim.
        return NoOpHandle(id="noop", artifact_hash=artifact.tree_hash)

    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        return ExecutionResult(
            outcome="completed",
            exit_code=0,
            isolation_level=self.isolation_level,
            artifact_hash=handle.artifact_hash,
            raw_return_code=0,
        )

    def teardown(self, handle: SandboxHandle) -> None:
        return None


_conforms: Sandbox = NoOpSandbox()  # type-check proof (session inherited from base)
