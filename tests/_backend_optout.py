"""tests/_backend_optout.py — the TEST-ONLY backend-guard opt-out. EXCLUDED from the shipped wheel (the
pyproject allowlist ships only the six production packages), so it can never re-enter a production
execution path — the clean-wheel test asserts it is unavailable after a real install.

The guard is MANDATORY on ``calibrate`` and the gate entry points (no ``None`` default). Tests that
exercise NON-security backends (``NoOpSandbox`` / ``SubprocessSandbox``) inject THIS explicitly, so the
"no real guarding" choice is an EXPLICIT, test-scoped, artifact-absent decision — not a silent logic path.
Any PRODUCTION no-op guard would reintroduce the fail-open the mandatory guard closes; the AST/packaging
tests assert this opt-out is the ONLY no-op guard in the tree and that it is absent from the wheel."""
from __future__ import annotations

from core import Sandbox


def allow_any_backend(sandbox: Sandbox) -> None:
    """A no-op guard: verifies nothing, accepts any backend. TEST-ONLY. Using it in production would
    reintroduce the audited-backend fail-open — which is exactly why it lives here (excluded from the
    wheel) and why the packaging/AST tests forbid any other no-op guard in production code."""
    return None


class _TestGuardPolicy:
    """A TEST-ONLY guard policy that accepts any backend but bears a stable ``policy_digest`` — so tests
    exercising the S3 4-tuple RuntimeSubject (which requires a guard-policy digest for a clean PASS/FAIL)
    can run against a NoOp sandbox without a real audited backend. Excluded from the wheel."""

    policy_id = "test-guard:v1"

    @property
    def policy_digest(self) -> str:
        return "test-guard-digest:v1"

    def __call__(self, sandbox: Sandbox) -> None:
        return None


# a shared instance for tests that need a guard-with-digest (the 4-tuple PASS/FAIL path).
test_guard_policy = _TestGuardPolicy()
