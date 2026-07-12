"""3.5-close #1.6 — the trusted-backend construction guard + its adversarial harness. Run:
python3 -m unittest discover -s tests

The guard confines security-relevant calibration to AUDITED backends (whose isolation is verified in
code), refusing a backend that merely DECLARES HERMETIC. The token's constructor is module-private, so a
caller cannot mint one; the guard verifies the RETURNED object bears the exact token (board amendment:
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
from gate.backends import (
    UntrustedBackendError,
    approved_backends,
    trusted_backend_guard,
    trusted_sandbox_factory,
)
from sandbox.noop import NoOpSandbox


class _HermeticNoOp(NoOpSandbox):
    """An UNAUDITED backend that merely DECLARES HERMETIC — exactly what the guard must refuse."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


class TrustedBackendGuardTests(unittest.TestCase):
    def test_unaudited_hermetic_declaring_backend_is_refused(self) -> None:
        # the fail-open the guard closes: a backend that DECLARES HERMETIC but is not audited.
        with self.assertRaises(UntrustedBackendError):
            trusted_backend_guard(_HermeticNoOp())

    def test_ticketless_object_cannot_forge_the_token(self) -> None:
        # a caller cannot mint the token; stamping an arbitrary object is not identity-equal -> refused.
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
        # a backend built through the trusted factory bears the token -> the guard accepts it.
        # (constructing OCISandbox does NOT run a container — runtime detection is passed explicitly.)
        from sandbox.oci import OCISandbox

        # the factory's build() would auto-detect a runtime; inject one to avoid a container probe.
        import gate.backends as _b
        orig = _b._APPROVED["oci"]
        _b._APPROVED["oci"] = lambda image: OCISandbox(image=image, runtime="podman")
        try:
            sb = trusted_sandbox_factory("oci", "scratch")()
        finally:
            _b._APPROVED["oci"] = orig
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
        from gate.detector_registry import DetectorRegistry, content_address

        det = _AlwaysPass()
        reg = DetectorRegistry()
        reg.register("d", lambda: det, content_hash=content_address(det))
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
