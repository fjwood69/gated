"""#4 (Option B) — the TRUSTED, content-addressed detector registry + the entry-point contract. Run:
python3 -m unittest discover -s tests

The registry is the ONLY way a detector_id becomes runnable code. It refuses unregistered ids, refuses a
built detector whose content_id does not match its (optionally signed) registration, and returns a single
cached instance per id. The structural test proves the four entry points take a detector by NAME + an
injected resolver — never a detector object — so a caller cannot smuggle in holdout-gaming detector code.
"""
from __future__ import annotations

import inspect
import unittest

from core import Command, Fixtures, Reason, Verdict, VerdictType
from gate.detector_registry import (
    DetectorIntegrityError,
    DetectorRegistry,
    RegistrationError,
    UnregisteredDetectorError,
    registration_binding,
)
from gate.signing import public_key, sign

_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _Detector:
    """A minimal RegistrableDetector: a RuntimeAssertion that declares a trusted content_id."""

    def __init__(self, content_id: str = "detector-v1") -> None:
        self.fixtures = Fixtures()
        self.content_id = content_id

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        return _PASS


class RegistryTests(unittest.TestCase):
    def test_unregistered_id_is_refused(self) -> None:
        reg = DetectorRegistry()
        with self.assertRaises(UnregisteredDetectorError):
            reg.resolve("nobody-registered-this")

    def test_resolve_returns_the_registered_detector(self) -> None:
        reg = DetectorRegistry()
        det = _Detector()
        reg.register("d", lambda: det, content_hash=det.content_id)
        self.assertIs(reg.resolve("d"), det)

    def test_content_integrity_mismatch_is_refused(self) -> None:
        # the factory builds a detector whose content_id != the registered hash -> code does not match
        # its registration -> refused (a swapped factory cannot silently return different code).
        reg = DetectorRegistry()
        reg.register("d", lambda: _Detector("ACTUALLY-DIFFERENT"), content_hash="registered-hash")
        with self.assertRaises(DetectorIntegrityError):
            reg.resolve("d")

    def test_resolve_caches_one_instance_per_id(self) -> None:
        # a stateless detector graded across visible + holdout lanes must be the SAME instance.
        reg = DetectorRegistry()
        builds = {"n": 0}

        def build() -> _Detector:
            builds["n"] += 1
            return _Detector()

        reg.register("d", build, content_hash="detector-v1")
        first = reg.resolve("d")
        second = reg.resolve("d")
        self.assertIs(first, second)
        self.assertEqual(builds["n"], 1)  # built once, cached

    def test_registration_is_write_once(self) -> None:
        reg = DetectorRegistry()
        det = _Detector()
        reg.register("d", lambda: det, content_hash=det.content_id)
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, content_hash=det.content_id)  # no silent rebind

    def test_empty_content_hash_is_refused(self) -> None:
        reg = DetectorRegistry()
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: _Detector(), content_hash="")


class SignedRegistryTests(unittest.TestCase):
    _SEED = bytes(range(64, 96))
    _PUB = public_key(_SEED)

    def test_signed_registry_requires_a_valid_registrar_signature(self) -> None:
        reg = DetectorRegistry(verify_key=self._PUB)
        det = _Detector()
        # no signature -> refused.
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, content_hash=det.content_id)
        # a signature over the WRONG binding -> refused.
        wrong = sign(registration_binding("other-id", det.content_id), self._SEED)
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, content_hash=det.content_id, signature=wrong)
        # a valid signature over (id, content_hash) -> accepted, and resolves.
        good = sign(registration_binding("d", det.content_id), self._SEED)
        reg.register("d", lambda: det, content_hash=det.content_id, signature=good)
        self.assertIs(reg.resolve("d"), det)

    def test_signature_by_the_wrong_key_is_refused(self) -> None:
        reg = DetectorRegistry(verify_key=self._PUB)
        det = _Detector()
        forged = sign(registration_binding("d", det.content_id), bytes(range(96, 128)))  # other seed
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, content_hash=det.content_id, signature=forged)


class EntryPointContractTests(unittest.TestCase):
    """Structural: the four entry points accept a detector by NAME + an injected resolver — NEVER a
    detector object. No RuntimeAssertion-typed parameter may survive on them."""

    def _params(self, fn):  # type: ignore[no-untyped-def]
        return inspect.signature(fn).parameters

    def test_entry_points_take_a_detector_id_and_no_detector_object(self) -> None:
        from engine.calibration import calibrate
        from gate.acceptance import run_acceptance_anchor
        from gate.gatekeeper import run_calibration
        from gate.recalibration import run_recalibration

        cases = {
            calibrate: ["detector_id"],
            run_recalibration: ["detector_id"],
            run_calibration: ["detector_id"],
            run_acceptance_anchor: ["honest_detector_id", "fn_deficient_detector_id",
                                    "fp_happy_detector_id"],
        }
        for fn, id_params in cases.items():
            params = self._params(fn)
            for p in id_params:
                self.assertIn(p, params, f"{fn.__name__} must take {p}")
            self.assertIn("resolve", params, f"{fn.__name__} must take an injected resolver")
            # with `from __future__ import annotations`, annotations are strings — assert none is a
            # RuntimeAssertion (no entry point accepts a detector OBJECT any more).
            for name, param in params.items():
                self.assertNotIn(
                    "RuntimeAssertion", str(param.annotation),
                    f"{fn.__name__}.{name} must not accept a detector object")

    def test_engine_does_not_import_the_gate(self) -> None:
        # the resolver type is engine-side (a plain Callable); the engine must not import the gate.
        from pathlib import Path
        src = (Path(__file__).resolve().parent.parent / "engine" / "calibration.py").read_text()
        self.assertNotIn("from gate", src)
        self.assertNotIn("import gate", src)


if __name__ == "__main__":
    unittest.main()
