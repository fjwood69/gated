"""engine/retry.py — the retry-resilience RuntimeAssertion (idempotency-scoped).

The first concrete check. Invariant: a call the POLICY has marked idempotent must
retry after a transient failure. Fault = fail-once at the boundary; the boundary
observer counts egress attempts; the verdict is read from that count ALONE (never
in-process state). Idempotency-scoped (Gap-1): the check ENFORCES retry on a
marked-safe call — it does not decide idempotency (that is the policy layer's job,
a later increment). Here the entrypoint exercises one designated call.
"""
from __future__ import annotations

from core import (
    BoundaryFault,
    BoundaryFaultMode,
    Command,
    ExecutionResult,
    Fixtures,
    Reason,
    Verdict,
    VerdictType,
)


class RetryCheck:
    """Boundary-observed retry check. PASS iff >=2 egress attempts were seen."""

    def __init__(self, argv: tuple[str, ...]) -> None:
        self._argv = argv
        self.fixtures = Fixtures(boundary_fault=BoundaryFault(BoundaryFaultMode.FAIL_ONCE))

    def entrypoint(self) -> Command:
        return Command(argv=self._argv)

    def assert_invariant(self, result: ExecutionResult) -> Verdict:
        # Out-of-band boundary telemetry ONLY — never in-process state.
        n = result.egress_attempts
        if n is None:
            return Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING)  # observer failed
        if n >= 2:
            return Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)          # retried
        if n == 1:
            return Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)          # gave up after 1
        return Verdict(VerdictType.FAIL, Reason.EGRESS_ZERO)             # never attempted
