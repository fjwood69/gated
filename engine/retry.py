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
    EgressAbsence,
    BoundaryFault,
    BoundaryFaultMode,
    Command,
    ExecutionResult,
    Fixtures,
    Reason,
    Verdict,
    VerdictType,
)


# The absence -> diagnosis map. Exhaustive over EgressAbsence by construction: the contract test
# asserts every member has an entry, so a future variant cannot silently fall back to a generic reason.
_ABSENCE_REASON = {
    EgressAbsence.NOT_OBSERVED: Reason.TELEMETRY_NOT_OBSERVED,
    EgressAbsence.OBSERVER_UNREADABLE: Reason.TELEMETRY_UNREADABLE,
}


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
        if isinstance(n, EgressAbsence):
            # ONE VERDICT CLASS, TWO DIAGNOSES. Both absences are ERROR — there is no measurement, and no
            # measurement is not a measurement of zero. But the VARIANT SURVIVES TO THE REASON rather than
            # being collapsed here: an operator refused with this verdict needs to know whether the
            # observer never existed or ran and produced nothing, because those have different fixes.
            # Collapsing them would have replaced one spelling of absence with two that print identically.
            #
            # The previous branch tested ``n is None`` and commented "observer failed" — true only because
            # this detector happens to run on the observing backend. Safe by THIS detector's
            # implementation, never by construction, which is exactly what a second detector inherits.
            return Verdict(VerdictType.ERROR, _ABSENCE_REASON[n])
        if n >= 2:
            return Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)          # retried
        if n == 1:
            return Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)          # gave up after 1
        return Verdict(VerdictType.FAIL, Reason.EGRESS_ZERO)             # never attempted
