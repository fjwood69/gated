"""gate/detector_registry.py — #4 (Option B): the TRUSTED, content-addressed detector registry.

WHY THIS EXISTS (the fundamental limit it works around). Blindness against an AUTHOR-CONTROLLED
detector is impossible in-process: a detector the author supplies can encode holdout membership in
the cross-fixture PASS/FAIL pattern (~1 bit per fixture — the *verdict side-channel*), so no amount
of encryption of the holdout stops an adversarial detector from leaking which fixtures are the blind
ones. The only sound answer in-process is to change the trust model: the honest reference baseline
the acceptance anchor grades against must come from a TRUSTED source, NEVER arbitrary caller code.

WHAT IT ENFORCES. Entry points (``calibrate``, ``run_acceptance_anchor``, ``run_recalibration``,
``run_calibration``) accept a ``detector_id`` (a name) plus an INJECTED resolver — never a detector
object, lambda, or path. The ONLY way a name becomes runnable code is a registry like this one, which:
  * REFUSES an unregistered id (a caller cannot smuggle in code by naming something unknown);
  * is CONTENT-ADDRESSED — a registration binds ``detector_id -> content_hash``, and ``resolve``
    rebuilds the detector and refuses it unless its self-declared ``content_id`` matches (so a swapped
    factory reference cannot silently return different code);
  * is optionally SIGNED — with a ``verify_key`` set, only registrations bearing a valid registrar
    signature over the ``(detector_id, content_hash)`` binding are accepted (a tamper-evident,
    authenticated registry).

ADVERSARY / TRUSTED PROCESS. Untrusted: the policy author + the calibration caller (they may want a
detector that games the holdout). Trusted (the TCB): the detector maintainer who registers a
content-addressed, signed detector, and the gate host that holds this registry. This registry moves
"which detector judges" out of the untrusted caller's hands.

LAYERING. The gate holds the registry; the engine takes only a ``Callable[[str], RuntimeAssertion]``
(``DetectorResolver``, defined engine-side) — dependency inversion, so engine⊥gate is preserved.
NOT a sandbox: a resolved detector still runs in the hermetic sandbox. The registry governs WHICH
detector runs, not HOW — the two controls compose.

REFERENCE IMPL — NOT SECURITY-COMPLETE. In-memory, content-addressed by a self-declared ``content_id``,
Ed25519-signed binding via ``gate.signing``. A deployment backs this with an external, content-addressed,
signed artifact store (e.g. signed OCI images) and runs each detector in its own container with
aggregate-only output (so even the side-channel's ~1 bit/fixture is denied a path back to the author).
The STRUCTURE proven here — named + trusted-only + verified-on-resolve + no caller code — is the seam a
deployment hardens; the in-process mechanism alone is not a security boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from core import Command, Fixtures, RuntimeAssertion, Verdict
from gate import signing


class DetectorResolutionError(RuntimeError):
    """A ``detector_id`` could not be resolved to trusted, content-verified detector code."""


class UnregisteredDetectorError(DetectorResolutionError):
    """The id names no registered detector — refused (a caller cannot summon unknown code by name)."""


class DetectorIntegrityError(DetectorResolutionError):
    """The rebuilt detector's content address does not match its signed registration — refused
    (a swapped factory reference cannot silently return different code)."""


class RegistrationError(RuntimeError):
    """A registration was rejected — a duplicate id, or (signed registry) a missing/invalid signature."""


class RegistrableDetector(Protocol):
    """A ``RuntimeAssertion`` that ALSO declares its trusted content address (``content_id``). Only a
    detector built by the trusted process — which stamps a ``content_id`` over the exact impl it shipped
    — is registrable; a caller's ad-hoc object has no honest ``content_id`` to match a registration."""

    fixtures: Fixtures
    content_id: str

    def entrypoint(self) -> Command: ...
    def assert_invariant(self, result: object) -> Verdict: ...


def registration_binding(detector_id: str, content_hash: str) -> bytes:
    """The exact bytes a registrar signs to authenticate a ``detector_id -> content_hash`` binding.
    Versioned + newline-delimited so neither field can be smuggled into the other."""
    return f"detector-registration:v1\n{detector_id}\n{content_hash}".encode("utf-8")


@dataclass(frozen=True)
class _Entry:
    content_hash: str
    build: Callable[[], RegistrableDetector]


class DetectorRegistry:
    """A trusted, content-addressed (optionally signed) map ``detector_id -> detector code``. ``resolve``
    is the injected ``DetectorResolver`` the entry points call. Detectors are assumed STATELESS (a real
    detector judges each ``ExecutionResult`` independently); ``resolve`` returns a single cached instance
    per id, so the acceptance anchor grades the SAME build across its visible and holdout lanes."""

    def __init__(self, *, verify_key: bytes | None = None) -> None:
        self._entries: dict[str, _Entry] = {}
        self._cache: dict[str, RuntimeAssertion] = {}
        self._verify_key = verify_key  # set => signed registry (registrations must be signed)

    def register(
        self,
        detector_id: str,
        build: Callable[[], RegistrableDetector],
        *,
        content_hash: str,
        signature: bytes | None = None,
    ) -> None:
        """Register a trusted detector under ``detector_id``, bound to ``content_hash`` (its declared
        ``content_id``). On a SIGNED registry (``verify_key`` set) a valid registrar ``signature`` over
        the binding is REQUIRED. Ids are write-once — re-registration is refused (no silent rebind)."""
        if detector_id in self._entries:
            raise RegistrationError(f"detector id {detector_id!r} is already registered (write-once)")
        if not content_hash:
            raise RegistrationError("refusing to register a detector with an empty content hash")
        if self._verify_key is not None:
            if signature is None or not signing.verify(
                registration_binding(detector_id, content_hash), signature, self._verify_key
            ):
                raise RegistrationError(
                    f"signed registry: registration of {detector_id!r} needs a valid registrar "
                    "signature over its (id, content_hash) binding"
                )
        self._entries[detector_id] = _Entry(content_hash=content_hash, build=build)

    def resolve(self, detector_id: str) -> RuntimeAssertion:
        """Return the trusted detector for ``detector_id``. Refuses an unregistered id, and refuses a
        built detector whose ``content_id`` does not match the registration (content-address integrity).
        This bound method IS the ``DetectorResolver`` injected into the entry points."""
        cached = self._cache.get(detector_id)
        if cached is not None:
            return cached
        entry = self._entries.get(detector_id)
        if entry is None:
            raise UnregisteredDetectorError(
                f"no detector registered under id {detector_id!r} — the entry point refuses to run "
                "unregistered code (only trusted, content-addressed detectors may judge)"
            )
        detector = entry.build()
        actual = getattr(detector, "content_id", None)
        if actual != entry.content_hash:
            raise DetectorIntegrityError(
                f"detector {detector_id!r} built with content_id {actual!r} != registered "
                f"{entry.content_hash!r} — the code does not match its signed registration"
            )
        self._cache[detector_id] = detector
        return detector


# The resolver contract the entry points accept (a plain Callable so the ENGINE need not import the
# gate). ``DetectorRegistry.resolve`` is the production implementation; a test/first-party caller may
# inject any trusted Callable of this shape.
DetectorResolver = Callable[[str], RuntimeAssertion]


__all__ = [
    "DetectorRegistry",
    "RegistrableDetector",
    "DetectorResolver",
    "DetectorResolutionError",
    "UnregisteredDetectorError",
    "DetectorIntegrityError",
    "RegistrationError",
    "registration_binding",
]
