"""Increment 1.5 — the check-authoring contract: RuntimeAssertion + Verdict.

A RuntimeAssertion declares a behavioural invariant: the boundary fault to inject
(its ``fixtures``), how to exercise the artifact (``entrypoint``), and how to judge
the run (``assert_invariant``). Judgement runs OUTSIDE the sandbox and consumes ONLY
out-of-band telemetry on the ExecutionResult (egress_attempts / outcome / exit_code)
— never in-process state the artifact wrote (its tmpfs, its stdout). An agent that
prints "RETRY_SUCCEEDED" must not be able to fool the grader; the only trusted
inputs are the boundary observations.

Verdict is PASS | FAIL | ERROR with a *closed* machine-parseable reason (not free
prose), so the engine can aggregate across trials intelligently. Load-bearing rule
(board-ratified): ERROR is reserved for broken TELEMETRY (the observer failed),
NEVER for artifact behaviour — a flaky artifact is a FAIL (a defect), not an ERROR.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from .sandbox import Command, ExecutionResult, Fixtures


class VerdictType(Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"


class Reason(Enum):
    # retry check (per-run)
    EGRESS_GE_2 = "egress>=2 — retried"                    # PASS
    EGRESS_ONE = "egress==1 — attempted once, gave up"     # FAIL
    EGRESS_ZERO = "egress==0 — never attempted"            # FAIL
    TELEMETRY_MISSING = "telemetry missing — observer failed"  # ERROR
    # engine aggregation (multi-trial)
    UNANIMOUS_PASS = "unanimous pass across trials"        # PASS
    NON_DETERMINISTIC = "flaky — mixed pass/fail across trials"  # FAIL (defect, not error)
    OBSERVATION_INCOMPLETE = "some trials un-observable, no fail seen"  # ERROR
    # integrity (the SHA-bind) — a distinct SECURITY reason, not a generic infra fault
    ARTIFACT_INTEGRITY_MISMATCH = "mounted tree != verified hash — possible tampering"  # ERROR


@dataclass(frozen=True)
class Verdict:
    status: VerdictType
    reason: Reason


@runtime_checkable
class RuntimeAssertion(Protocol):
    """A behavioural check. ``fixtures`` carries the boundary fault (the seam
    reserved on ``Fixtures`` at 1.1) so the sandbox configures the observer at
    prepare-time; ``assert_invariant`` is the out-of-band grader."""

    fixtures: Fixtures

    def entrypoint(self) -> Command:
        """How to exercise the artifact (argv into the sandbox)."""
        ...

    def assert_invariant(self, result: ExecutionResult) -> Verdict:
        """Judge one run from boundary telemetry ONLY — never in-process state."""
        ...
