"""gated enforcement core (LLM-free) — CONTRACTS only.

Interfaces + value types every layer depends on: the Sandbox Protocol, the value
types it passes, and the canonical artifact-tree hash (the shared definition of
``ArtifactSpec.tree_hash``). No execution, no grading (NFR4). Backends live in
``sandbox/``; orchestration in ``engine/``.
"""
from __future__ import annotations

from .artifact_hash import ArtifactHashMismatchError, tree_hash
from .assertion import Reason, RuntimeAssertion, Verdict, VerdictType
from .sandbox import (
    ArtifactSpec,
    BoundaryFault,
    BoundaryFaultMode,
    Command,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    Sandbox,
    SandboxHandle,
    SandboxLeakError,
)

__all__ = [
    "IsolationLevel",
    "ResourceBudget",
    "Command",
    "ArtifactSpec",
    "Fixtures",
    "BoundaryFault",
    "BoundaryFaultMode",
    "SandboxHandle",
    "ExecutionResult",
    "Sandbox",
    "SandboxLeakError",
    "tree_hash",
    "ArtifactHashMismatchError",
    "RuntimeAssertion",
    "Verdict",
    "VerdictType",
    "Reason",
]
