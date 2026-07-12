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
    profile_of,
    DetectorIntegrityError,
    DetectorRegistry,
    RegistrationError,
    content_address,
    registration_binding,
    UnregisteredDetectorError,
)
from gate.signing import public_key, sign

_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _Detector:
    """A minimal RegistrableDetector (a RuntimeAssertion). Its content-address is COMPUTED from this
    module's bytes by the registry (§1.2) — the ``content_id`` attribute below is DELIBERATELY ignored
    by the registry (proving self-declaration is not trusted)."""

    def __init__(self, content_id: str = "self-declared-IGNORED") -> None:
        self.fixtures = Fixtures()
        self.content_id = content_id  # a lie the registry does not read

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        return _PASS


# the accepted content-address of a _Detector = a hash of THIS test module's bytes (§1.2 computes it
# from the module file, not the self-declared content_id). Constant across _Detector instances here.
_ADDR = profile_of("d", _Detector()).digest()


class RegistryTests(unittest.TestCase):
    def test_unregistered_id_is_refused(self) -> None:
        reg = DetectorRegistry()
        with self.assertRaises(UnregisteredDetectorError):
            reg.resolve("nobody-registered-this")

    def test_resolve_returns_the_registered_detector(self) -> None:
        reg = DetectorRegistry()
        det = _Detector()
        reg.register("d", lambda: det, accepted_profile_digest=_ADDR)
        self.assertIs(reg.resolve("d"), det)

    def test_content_address_is_computed_from_module_bytes_not_self_declared(self) -> None:
        # §1.2: the address is a hash of THIS module's bytes, NOT the self-declared content_id.
        import hashlib
        from pathlib import Path
        expected = "blake2b:" + hashlib.blake2b(Path(__file__).read_bytes()).hexdigest()
        self.assertEqual(content_address(_Detector("a-lie")), expected)
        self.assertEqual(content_address(_Detector("another-lie")), expected)  # content_id ignored

    def test_drift_from_accepted_address_is_refused(self) -> None:
        # the deployed detector's computed address != the accepted (registered) one -> DRIFT -> refused
        # (a self-declared content_id cannot rescue it; the registry recomputes from the bytes).
        reg = DetectorRegistry()
        reg.register("d", lambda: _Detector("declares-the-accepted-hash"), accepted_profile_digest="accepted-addr")
        with self.assertRaises(DetectorIntegrityError):
            reg.resolve("d")

    def test_bundle_profile_is_cached_not_re_read_from_disk(self) -> None:
        # v3 (board P1, atomicity): the (assertion, profile) pair is computed ONCE and cached; a later
        # module-file swap on disk (modelled by patching content_address AFTER first resolve) must NOT
        # change the resolved profile digest — the runnable object and its hashed bytes can never diverge
        # across calls. Guard = caching the pair; remove it and resolve would re-read (patched) and drift.
        reg = DetectorRegistry()
        det = _Detector()
        reg.register("d", lambda: det, accepted_profile_digest=_ADDR)
        first = reg.resolve_bundle("d").profile_digest
        import gate.detector_registry as dr
        orig = dr.content_address
        dr.content_address = lambda _det: "blake2b:SWAPPED-ON-DISK-AFTER-RESOLVE"  # type: ignore[assignment]
        try:
            second = reg.resolve_bundle("d").profile_digest
            via_profile = reg.resolve_profile("d").digest()
        finally:
            dr.content_address = orig
        self.assertEqual(first, second)       # cached, not re-read from (swapped) disk
        self.assertEqual(first, via_profile)  # resolve/resolve_profile/resolve_bundle share ONE computation

    def test_behavioral_config_is_frozen_at_registration(self) -> None:
        # v4 P1-c: the registry deep-freezes a snapshot of behavioral_config at registration and caches the
        # VALIDATED digest string; mutating the caller's original config dict afterwards must NOT change the
        # resolved digest. Guard = deep-copy-at-register + cached digest string; remove it and d2 drifts.
        reg = DetectorRegistry()
        det = _Detector()
        cfg = {"k": "v"}
        accepted = profile_of("d", det, {"k": "v"}).digest()
        reg.register("d", lambda: det, accepted_profile_digest=accepted, behavioral_config=cfg)
        d1 = reg.resolve_bundle("d").profile_digest
        cfg["k"] = "MUTATED-AFTER-REGISTRATION"  # mutate the caller's original mapping
        d2 = reg.resolve_bundle("d").profile_digest
        self.assertEqual(d1, d2)  # frozen snapshot -> post-registration mutation has no effect

    def test_command_is_captured_once_and_frozen(self) -> None:
        # v4 P1-c: the entrypoint command is captured ONCE at resolution and returned frozen on every
        # resolve — security-relevant paths execute THIS, never a fresh entrypoint() a stateful detector
        # could answer differently. Guard = capture-once + cache; remove it and the two commands differ.
        reg = DetectorRegistry()
        det = _Detector()
        reg.register("d", lambda: det, accepted_profile_digest=_ADDR)
        cmd1 = reg.resolve_bundle("d").command
        cmd2 = reg.resolve_bundle("d").command
        self.assertEqual(cmd1.argv, ("true",))
        self.assertIs(cmd1, cmd2)  # same frozen command object, captured once at first resolve

    def test_resolve_caches_one_instance_per_id(self) -> None:
        # a stateless detector graded across visible + holdout lanes must be the SAME instance.
        reg = DetectorRegistry()
        builds = {"n": 0}

        def build() -> _Detector:
            builds["n"] += 1
            return _Detector()

        reg.register("d", build, accepted_profile_digest=_ADDR)
        first = reg.resolve("d")
        second = reg.resolve("d")
        self.assertIs(first, second)
        self.assertEqual(builds["n"], 1)  # built once, cached

    def test_registration_is_write_once(self) -> None:
        reg = DetectorRegistry()
        det = _Detector()
        reg.register("d", lambda: det, accepted_profile_digest=_ADDR)
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, accepted_profile_digest=_ADDR)  # no silent rebind

    def test_empty_content_hash_is_refused(self) -> None:
        reg = DetectorRegistry()
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: _Detector(), accepted_profile_digest="")


class SignedRegistryTests(unittest.TestCase):
    _SEED = bytes(range(64, 96))
    _PUB = public_key(_SEED)

    def test_signed_registry_requires_a_valid_registrar_signature(self) -> None:
        reg = DetectorRegistry(verify_key=self._PUB)
        det = _Detector()
        # no signature -> refused.
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, accepted_profile_digest=_ADDR)
        # a signature over the WRONG binding -> refused.
        wrong = sign(registration_binding("other-id", _ADDR), self._SEED)
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, accepted_profile_digest=_ADDR, signature=wrong)
        # a valid signature over (id, content_hash) -> accepted, and resolves.
        good = sign(registration_binding("d", _ADDR), self._SEED)
        reg.register("d", lambda: det, accepted_profile_digest=_ADDR, signature=good)
        self.assertIs(reg.resolve("d"), det)

    def test_signature_by_the_wrong_key_is_refused(self) -> None:
        reg = DetectorRegistry(verify_key=self._PUB)
        det = _Detector()
        forged = sign(registration_binding("d", _ADDR), bytes(range(96, 128)))  # other seed
        with self.assertRaises(RegistrationError):
            reg.register("d", lambda: det, accepted_profile_digest=_ADDR, signature=forged)


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
