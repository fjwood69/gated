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
  * is CONTENT-ADDRESSED — a registration binds ``detector_id -> accepted_profile_digest``; at FIRST
    resolution the registry COMPUTES the detector's profile (module-byte content-address + the entrypoint
    command captured once + the trusted behavioral_config) and refuses it unless the computed digest
    matches the accepted one (so a swapped factory reference cannot silently return different code). The
    detector's own attributes are NOT trusted — the address is a hash of the module bytes, not a
    self-declared field;
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

REFERENCE IMPL — NOT SECURITY-COMPLETE. In-memory, content-addressed by a hash of the detector's MODULE
BYTES (not a self-declared attribute), Ed25519-signed binding via ``gate.signing``. Resolution PINS one
process-lifetime bundle: the profile digest + the entrypoint command are captured and validated ONCE at
first resolve and cached (the registry does NOT continuously detect source drift — the first-resolve read
of the source file vs the already-imported module is a NAMED trusted-process-model residual; see
ARCHITECTURE.md). A deployment backs this with an external, content-addressed, signed artifact store (e.g.
signed OCI images), an immutable verified execution process, and runs each detector in its own container
with aggregate-only output. The STRUCTURE proven here — named + trusted-only + validated-at-resolve +
frozen-command execution + no caller code — is the seam a deployment hardens; the in-process mechanism
alone is not a security boundary.
"""
from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from core import Command, Fixtures, RuntimeAssertion, Verdict
from core.chain import canonical_digest
from engine.calibration import ResolvedDetector
from gate import signing

_PROFILE_DOMAIN = "gated.resolved-detector-profile"


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
    """A registrable detector is just a ``RuntimeAssertion``. Its content-address is COMPUTED from its
    module bytes at registration/resolution (``content_address``), NOT self-declared (3.5-close #1.2) —
    a caller's ad-hoc object is still refused because its computed address won't match a registration."""

    fixtures: Fixtures

    def entrypoint(self) -> Command: ...
    def assert_invariant(self, result: object) -> Verdict: ...


def content_address(detector: object) -> str:
    """The deterministic content-address of a detector = a hash of the EXACT bytes of the module file
    that defines it (the packaged/installed artifact) — NOT a self-declared attribute, NOT an AST, and
    NOT EOL-normalized (normalization would hide real byte differences; board amendment 2).

    3.5-close #1.2 — an ANTI-DRIFT / config-integrity coordinate: it detects the deployed detector
    drifting from the accepted bytes (bad rollout, partial revert, cache corruption, registry
    mis-selection). It is NOT anti-smuggling against a malicious deployer — whoever can edit the module
    can recompute and re-sign the address. It becomes AUTHORITY only under separation of duties
    (source-signer != image-builder), a deploy-tier property; in the in-process reference it is hygiene
    (see ARCHITECTURE.md). A deployment's real content-address is the detector's immutable CONTAINER
    IMAGE digest."""
    try:
        src_file = inspect.getfile(type(detector))
    except TypeError as exc:  # builtins / C-extensions / dynamically-defined types have no source file
        raise DetectorIntegrityError(
            f"cannot content-address {type(detector).__name__} — no source file to hash"
        ) from exc
    return "blake2b:" + hashlib.blake2b(Path(src_file).read_bytes()).hexdigest()


@dataclass(frozen=True)
class ResolvedDetectorProfile:
    """3.5-close P1-3: the RESOLVER-ATTESTABLE identity of a resolved detector — the coordinates the
    registry can vouch for. ``behavioral_config`` comes from TRUSTED REGISTRY METADATA (registered by the
    governing party), NOT detector self-declaration (a self-attested config would be the same circularity
    as the accepted-hash). ``None`` behavioral_config (a config-less detector) is DISTINCT from ``{}``.
    Does NOT include the evaluation profile (trials/budget/seeds) — those are caller CALIBRATION INPUTS,
    not detector identity, and live in the acceptance envelope's ``calibration_inputs`` (putting them here
    would be resolver authority creep). ``module_bytes_hash`` + ``entrypoint_argv`` are the minimal
    binding that closes sign-A-run-B (two entrypoints in one module have DIFFERENT profiles)."""

    detector_id: str
    module_bytes_hash: str
    entrypoint_argv: tuple[str, ...]
    behavioral_config: Mapping[str, Any] | None

    def digest(self) -> str:
        return canonical_digest(_PROFILE_DOMAIN, {
            "detector_id": self.detector_id,
            "module_bytes_hash": self.module_bytes_hash,
            "entrypoint_argv": list(self.entrypoint_argv),
            "behavioral_config": dict(self.behavioral_config) if self.behavioral_config is not None else None,
        })


def profile_of(
    detector_id: str, detector: RuntimeAssertion, behavioral_config: Mapping[str, Any] | None = None,
    *, command: Command | None = None,
) -> ResolvedDetectorProfile:
    """Compute the ``ResolvedDetectorProfile`` for a resolved detector: its module-byte content-address,
    its entrypoint argv, and the TRUSTED behavioral_config the registry holds (not the detector's own
    claim). v4 P1-c: if a ``command`` is supplied (captured ONCE at resolution), its argv is used — so the
    profile's ``entrypoint_argv`` binds the SAME command that will execute, not a second ``entrypoint()``
    call that a stateful detector could answer differently."""
    cmd = command if command is not None else detector.entrypoint()
    return ResolvedDetectorProfile(
        detector_id=detector_id,
        module_bytes_hash=content_address(detector),
        entrypoint_argv=tuple(cmd.argv),
        behavioral_config=behavioral_config,
    )


def registration_binding(detector_id: str, content_hash: str) -> bytes:
    """The exact bytes a registrar signs to authenticate a ``detector_id -> content_hash`` binding.
    Versioned + newline-delimited so neither field can be smuggled into the other."""
    return f"detector-registration:v1\n{detector_id}\n{content_hash}".encode("utf-8")


@dataclass(frozen=True)
class _Entry:
    accepted_profile_digest: str
    behavioral_config: Mapping[str, Any] | None
    build: Callable[[], RuntimeAssertion]


@dataclass(frozen=True)
class _Resolved:
    """The immutable cached result of ONE resolution (v4 P1-c): the runnable assertion, its verified
    profile, the VALIDATED digest STRING (cached — never recomputed from the live object), and the FROZEN
    command captured at resolution."""

    assertion: RuntimeAssertion
    profile: ResolvedDetectorProfile
    profile_digest: str
    command: Command


class DetectorRegistry:
    """A trusted, profile-addressed (optionally signed) map ``detector_id -> detector code``. ``resolve``
    is the injected ``DetectorResolver`` the entry points call. Detectors are assumed STATELESS (a real
    detector judges each ``ExecutionResult`` independently); ``resolve`` returns a single cached instance
    per id, so the acceptance anchor grades the SAME build across its visible and holdout lanes.

    3.5-close P1-1/P1-3/v4: an entry is bound to an ACCEPTED PROFILE DIGEST (module bytes + entrypoint
    command + trusted behavioral_config), NOT just a module-byte hash — so a same-module different-entrypoint
    swap is refused. The profile digest + the entrypoint command are validated + captured ONCE at first
    resolve and the VALIDATED DIGEST STRING is cached (never recomputed from a live, potentially-mutated
    object); the trusted behavioral_config is deep-frozen at registration. Resolution therefore PINS one
    process-lifetime bundle. NOTE (issue-10, honest scope): the first-resolve read of the source file vs the
    already-imported module, and the fact that the loaded host-side object could be monkeypatched in
    process, are the trusted-process-model residuals — hygiene, not runtime assurance; strong closure is an
    immutable verified execution process (ARCHITECTURE.md)."""

    def __init__(self, *, verify_key: bytes | None = None) -> None:
        self._entries: dict[str, _Entry] = {}
        # P1-3 v3/v4: cache the immutable resolved record, computed by ONE resolution. The validated digest
        # STRING + the frozen command are pinned for the process lifetime — the runnable object, the hashed
        # bytes, and the executed command can never diverge across calls.
        self._cache: dict[str, _Resolved] = {}
        self._verify_key = verify_key  # set => signed registry (registrations must be signed)

    def register(
        self,
        detector_id: str,
        build: Callable[[], RuntimeAssertion],
        *,
        accepted_profile_digest: str,
        behavioral_config: Mapping[str, Any] | None = None,
        signature: bytes | None = None,
    ) -> None:
        """Register a trusted detector under ``detector_id``, bound to ``accepted_profile_digest`` — the
        ACCEPTED ``ResolvedDetectorProfile.digest()`` (module bytes + entrypoint + trusted
        behavioral_config), pinned at acceptance time. ``resolve`` recomputes the profile digest and
        refuses on drift. ``behavioral_config`` is the TRUSTED registry metadata (not detector
        self-declaration). On a SIGNED registry a valid registrar ``signature`` over the (id, digest)
        binding is REQUIRED. Ids are write-once — no silent rebind."""
        if detector_id in self._entries:
            raise RegistrationError(f"detector id {detector_id!r} is already registered (write-once)")
        if not accepted_profile_digest:
            raise RegistrationError("refusing to register a detector with an empty accepted profile digest")
        if self._verify_key is not None:
            if signature is None or not signing.verify(
                registration_binding(detector_id, accepted_profile_digest), signature, self._verify_key
            ):
                raise RegistrationError(
                    f"signed registry: registration of {detector_id!r} needs a valid registrar "
                    "signature over its (id, accepted_profile_digest) binding"
                )
        # v4 P1-c: DEEP-FREEZE the trusted behavioral_config at registration (a read-only snapshot copy),
        # so it can never be mutated after resolution to change the computed digest.
        frozen_config: Mapping[str, Any] | None = (
            MappingProxyType(dict(behavioral_config)) if behavioral_config is not None else None
        )
        self._entries[detector_id] = _Entry(
            accepted_profile_digest=accepted_profile_digest, behavioral_config=frozen_config, build=build,
        )

    def _resolved(self, detector_id: str) -> _Resolved:
        """Resolve ``detector_id`` to its immutable resolved record ONCE and cache it. The command +
        profile are captured a single time at first resolution (one ``content_address`` read, one
        ``entrypoint()`` call) and validated against the accepted digest; the VALIDATED DIGEST STRING is
        cached (never recomputed from a live object). Every later resolve returns the SAME cached record —
        it pins ONE process-lifetime resolved bundle (it does NOT continuously detect source drift; that is
        a named trusted-process-model residual, see the module docstring). A drift from the accepted
        profile at first resolution is refused (never cached)."""
        cached = self._cache.get(detector_id)
        if cached is not None:
            return cached
        entry = self._entries.get(detector_id)
        if entry is None:
            raise UnregisteredDetectorError(
                f"no detector registered under id {detector_id!r} — the entry point refuses to run "
                "unregistered code (only trusted, profile-addressed detectors may judge)"
            )
        detector = entry.build()
        command = detector.entrypoint()  # captured ONCE — the executed command binds to the profile below
        profile = profile_of(detector_id, detector, entry.behavioral_config, command=command)
        digest = profile.digest()  # the ONE content read; validated then cached as a STRING
        if digest != entry.accepted_profile_digest:
            raise DetectorIntegrityError(
                f"detector {detector_id!r} resolved to profile digest {digest} != accepted "
                f"{entry.accepted_profile_digest} — the deployed detector DRIFTED (module bytes / "
                "entrypoint / config changed from what was accepted), refused"
            )
        record = _Resolved(assertion=detector, profile=profile, profile_digest=digest, command=command)
        self._cache[detector_id] = record
        return record

    def resolve_bundle(self, detector_id: str) -> ResolvedDetector:
        """The ATOMIC resolver (P1-3 v3/v4): return the runnable assertion, its VALIDATED profile digest
        (a cached string, never recomputed from a mutable object), AND the FROZEN command captured at
        resolution — all from ONE resolution. Security-relevant paths execute ``command``, never a fresh
        ``entrypoint()``. This is the ``BundleResolver`` the calibration entry points inject."""
        r = self._resolved(detector_id)
        return ResolvedDetector(assertion=r.assertion, profile_digest=r.profile_digest, command=r.command)

    def resolve_profile(self, detector_id: str) -> ResolvedDetectorProfile:
        """Return the verified ``ResolvedDetectorProfile`` for ``detector_id`` (from the cached single
        resolution — not re-read)."""
        return self._resolved(detector_id).profile

    def resolve(self, detector_id: str) -> RuntimeAssertion:
        """Return the trusted detector for ``detector_id`` — refusing an unregistered id or a profile
        drift. This bound method IS the ``DetectorResolver`` injected into the enforcement path (which
        needs only the runnable object)."""
        return self._resolved(detector_id).assertion


# The resolver contract the entry points accept (a plain Callable so the ENGINE need not import the
# gate). ``DetectorRegistry.resolve`` is the production implementation; a test/first-party caller may
# inject any trusted Callable of this shape.
DetectorResolver = Callable[[str], RuntimeAssertion]


__all__ = [
    "DetectorRegistry",
    "RegistrableDetector",
    "ResolvedDetectorProfile",
    "profile_of",
    "DetectorResolver",
    "DetectorResolutionError",
    "UnregisteredDetectorError",
    "DetectorIntegrityError",
    "RegistrationError",
    "content_address",
    "registration_binding",
]
