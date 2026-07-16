"""3.5-close #1.6 — the trusted-backend construction guard + its adversarial harness. Run:
python3 -m unittest discover -s tests

The guard confines security-relevant calibration to AUDITED backends (whose isolation is verified in
code), refusing a backend that merely DECLARES HERMETIC. The token's constructor requires the module's
internal mint sentinel, so a caller routes through the intended path (a trusted-code convention, not an
unforgeable boundary); the guard verifies the RETURNED object bears the exact token (board amendment:
a factory that returns a different object is still refused).
"""
from __future__ import annotations

import unittest

from core import (
    Command,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
)
from unittest import mock

from gate.backends import (
    UntrustedBackendError,
    approved_backends,
    approved_runtimes,
    guarded_backend,
    trusted_backend_guard,
    trusted_sandbox_factory,
)
from sandbox.noop import NoOpSandbox
from sandbox.oci import OCISandbox


class _HermeticNoOp(NoOpSandbox):
    """An UNAUDITED backend that merely DECLARES HERMETIC — exactly what the guard must refuse."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


class TrustedBackendGuardTests(unittest.TestCase):
    def test_unaudited_hermetic_declaring_backend_is_refused(self) -> None:
        # the fail-open the guard closes: a backend that DECLARES HERMETIC but is not audited.
        with self.assertRaises(UntrustedBackendError):
            trusted_backend_guard(_HermeticNoOp())

    def test_ticketless_object_cannot_forge_the_token(self) -> None:
        # a caller outside the intended path holds no exact token; stamping an arbitrary object is not
        # identity-equal to the real ticket -> refused.
        sb = _HermeticNoOp()
        object.__setattr__(sb, "_gated_trusted_backend_ticket", object())  # a forged "token"
        with self.assertRaises(UntrustedBackendError):
            trusted_backend_guard(sb)

    def test_unknown_backend_kind_is_refused(self) -> None:
        with self.assertRaises(UntrustedBackendError):
            trusted_sandbox_factory("not-a-real-backend", "scratch")

    def test_approved_backends_are_the_audited_set(self) -> None:
        self.assertEqual(approved_backends(), ("observed", "oci"))  # sorted

    def test_trusted_factory_stamps_a_backend_the_guard_accepts(self) -> None:
        # a backend built through the trusted factory bears the token -> the guard accepts it. The explicit
        # ``runtime="podman"`` PINS the runtime (S3-completion closed-runtime contract) so construction does
        # NOT run a container probe.
        sb = trusted_sandbox_factory("oci", "scratch", runtime="podman")()
        trusted_backend_guard(sb)  # does not raise
        self.assertIsInstance(sb, OCISandbox)

    # ---- adversarial harness (factory forgery): a factory that returns a DIFFERENT, unticketed object ----
    def test_factory_forgery_returning_untrusted_object_is_refused(self) -> None:
        # model a hostile factory that (were it able to) hands back an unaudited object: the guard checks
        # the RETURNED object, which bears no valid token -> refused. Also proves the SubprocessSandbox
        # (WEAK) path cannot masquerade as audited.
        from sandbox.subprocess import SubprocessSandbox

        def forged_factory():  # type: ignore[no-untyped-def]
            return SubprocessSandbox()  # not audited, no token

        with self.assertRaises(UntrustedBackendError):
            trusted_backend_guard(forged_factory())


class ClosedRuntimeContractTests(unittest.TestCase):
    """S3-completion: the trusted factory may PIN an audited runtime (closed set) so the live path preserves
    explicit ``podman`` without a detection probe. An arbitrary runtime string/path is refused BEFORE any
    sandbox is constructed (no exec-injection surface)."""

    def test_approved_runtimes_is_a_closed_set(self) -> None:
        self.assertEqual(approved_runtimes(), ("docker", "nerdctl", "podman"))  # sorted, closed

    def test_explicit_runtime_is_pinned_and_propagated(self) -> None:
        sb = trusted_sandbox_factory("oci", "scratch", runtime="podman")()
        self.assertEqual(sb.runtime, "podman")  # the pinned runtime propagates to the sandbox
        trusted_backend_guard(sb)  # still token-stamped -> guard accepts

    def test_explicit_runtime_bypasses_the_detection_probe(self) -> None:
        # a pinned runtime must NOT trigger the per-sandbox container detection probe.
        with mock.patch.object(OCISandbox, "_detect_runtime") as detect:
            sb = trusted_sandbox_factory("oci", "scratch", runtime="podman")()
        detect.assert_not_called()
        self.assertEqual(sb.runtime, "podman")

    def test_unknown_runtime_refused_before_construction(self) -> None:
        # an unapproved runtime is refused by the factory BEFORE it builds (or stamps) any sandbox.
        with mock.patch.object(OCISandbox, "__init__", side_effect=AssertionError("must not construct")):
            with self.assertRaises(UntrustedBackendError):
                trusted_sandbox_factory("oci", "scratch", runtime="/bin/evil")

    def test_guarded_backend_threads_the_pinned_runtime(self) -> None:
        make, guard = guarded_backend("observed", "scratch", runtime="podman")
        sb = make()
        self.assertEqual(sb.runtime, "podman")
        guard(sb)  # the paired reference guard accepts the token-stamped, runtime-pinned sandbox

    def test_guard_policy_digest_is_a_stable_content_address(self) -> None:
        # the digest the runner reads OFF the guard object is derived from the guard's IDENTITY (policy_id),
        # NOT a re-hash of mutable runtime state — so two DISTINCT instances of the same guard policy produce
        # the SAME digest, and admission (which compares digests) never fails spuriously across instances.
        from gate.backends import _TrustedBackendGuardPolicy
        g1, g2 = _TrustedBackendGuardPolicy(), _TrustedBackendGuardPolicy()
        self.assertIsNot(g1, g2)                              # distinct instances...
        self.assertEqual(g1.policy_digest, g2.policy_digest)  # ...same stable content-address
        self.assertTrue(g1.policy_digest)


class _AlwaysPass:
    fixtures = Fixtures()

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> object:
        from core import Reason, Verdict, VerdictType
        return Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class GuardedCalibrationTests(unittest.TestCase):
    """calibrate() with a backend_guard refuses an unaudited factory before running fixtures."""

    def test_calibrate_with_guard_refuses_unaudited_factory(self) -> None:

        from core.calibration import CalibrationSet, Fixture, FixtureLabel
        from engine.calibration import calibrate
        from gate.detector_registry import DetectorRegistry, profile_of

        det = _AlwaysPass()
        reg = DetectorRegistry()
        reg.register("d", lambda: det, accepted_profile_digest=profile_of("d", det).digest())
        cset = CalibrationSet(
            known_good=(Fixture("g", FixtureLabel.KNOWN_GOOD, b"x"),),
            known_bad=(Fixture("b", FixtureLabel.KNOWN_BAD, b"y"),),
        )
        # an unaudited factory (declares HERMETIC) + the real guard -> refused before any fixture runs.
        with self.assertRaises(UntrustedBackendError):
            calibrate(lambda: _HermeticNoOp(), "d", reg.resolve, cset,
                      ResourceBudget(wall_clock_seconds=1.0), trials=2,
                      backend_guard=trusted_backend_guard)


if __name__ == "__main__":
    unittest.main()
