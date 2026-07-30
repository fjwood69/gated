"""gate/backends.py — 3.5-close #1.6: the TRUSTED-BACKEND construction guard.

WHY. calibrate() runs adversarial known-bad fixtures and requires HERMETIC isolation, but the generic
``Sandbox`` API only lets a factory DECLARE ``IsolationLevel.HERMETIC`` — it does not PROVE no-egress /
observer isolation. An unaudited backend could declare HERMETIC without being it (a fail-open). This
module confines security-relevant calibration to the AUDITED backends (``OCISandbox``,
``ObservedOCISandbox``).

WHAT "AUDITED" MEANS HERE, AND IT IS NOT THE SAME FOR BOTH. An earlier version of this paragraph said
their isolation is "verified in code (``--network=none`` / sealed network + external proxy + escape
probe)", collapsing two very different postures into one sentence. That is true of one backend and false
of the other, which matters because this is the module that decides what may be trusted for
security-relevant calibration:

  * ``ObservedOCISandbox`` — isolation is VERIFIED AT RUNTIME. It creates a sealed network, stands up an
    out-of-process proxy, and runs an escape probe that must find every residual channel closed before
    the artifact runs at all; a reachable channel raises ``NetworkIsolationError``. Its observer config
    is additionally bound into the attested execution identity via ``observer_config_hash``.
  * ``OCISandbox`` — isolation is APPLIED, NOT VERIFIED. ``--network=none`` is placed in the run argv by
    ``_network_args()`` and nothing checks it took effect: there is no escape probe in ``sandbox/oci.py``
    and no post-hoc network check of any kind. It also carries NO ``observer_config_hash``, so its
    isolation posture contributes nothing to the attested execution identity — ``engine/runner.py``'s
    ``getattr(sandbox, "observer_config_hash", "")`` reads the empty string for it.

Presence of a flag in an argv is APPLICATION, not verification. So ``OCISandbox``'s membership in
``_APPROVED`` rests on the weaker of the two claims, and it should be read that way: the hermetic
posture is only as good as that literal being correct, with no second layer to catch it if it is not.
Making the value attestable at all requires it to come from one shared builder rather than a literal
(deferred: the builder increment, then envelope attestation); a RUNTIME check for this backend is a
separate open question and does not exist today.

HOW — a construction guard under the trusted-gate model, NOT authorization. Audited backends are built
through ``trusted_sandbox_factory`` and stamped with a capability token whose constructor requires the
module's internal mint sentinel; ``trusted_backend_guard`` verifies the RETURNED sandbox object bears that
exact token by IDENTITY (not a forgeable type name). The sentinel is a TRUSTED-CODE convention — same-address
code CAN read the module-private objects, so this routes construction through the INTENDED API; it is NOT an
unforgeable boundary against untrusted in-process code. And because the guard checks the object that was
actually RETURNED, a factory that accepts the token but returns a different object is still refused (board
amendment).

ADVERSARY / TRUSTED PROCESS. A within-runtime construction guard: it REJECTS an unstamped / unaudited
sandbox object (the guard checks the RETURNED object bears the exact ticket), routing construction through
the intended public path (``guarded_backend``) under trusted code. It is NOT authority against a malicious
deployer who can import this module and read the sentinel — that requires a BUILD-TIME SIGNED MANIFEST of
trusted-backend module hashes
verified by the host / TEE (deploy-tier, the same tier as SoD / KMS; see ARCHITECTURE.md). In the
in-process reference this is hygiene against operational error + caller smuggling, not authorization
against a compromised gate.
"""
from __future__ import annotations

from typing import Callable, Protocol

from core import Sandbox
from core.chain import canonical_digest
from sandbox.oci import OCISandbox
from sandbox.observed import ObservedOCISandbox


class UntrustedBackendError(RuntimeError):
    """A sandbox presented to security-relevant calibration is not an audited backend (it bears no
    valid trusted-backend token). Fail-closed: a generic HERMETIC declaration is not proof of it."""


_MINT = object()  # module-private mint sentinel — the token constructor refuses any other key


class _TrustedBackendTicket:
    """A capability token whose constructor requires the module's internal mint sentinel (``_MINT``).
    Possessing the exact instance IS the capability; it is not exported. A TRUSTED-CODE convention —
    same-address code can read ``_MINT``, so this routes construction through the intended path, it is NOT
    an unforgeable boundary."""

    __slots__ = ()

    def __init__(self, mint: object) -> None:
        if mint is not _MINT:
            raise TypeError(
                "_TrustedBackendTicket requires the module's internal mint sentinel; use the intended path "
                "(gate.backends.trusted_sandbox_factory)")


_TICKET = _TrustedBackendTicket(_MINT)
_TICKET_ATTR = "_gated_trusted_backend_ticket"

# the CLOSED set of audited backends. NOT the generic ``Sandbox`` interface. The two members are NOT
# equally evidenced and the module header says so at length: ObservedOCISandbox VERIFIES its isolation at
# runtime (sealed net + external proxy + escape probe, fail-closed); OCISandbox APPLIES --network=none by
# argv construction, with no runtime check and no attestation of that posture. Adding a backend here is a
# reviewed, security-relevant change — and reviewing it means asking which of those two bars it clears.
_APPROVED: dict[str, Callable[[str, str | None], Sandbox]] = {
    "oci": lambda image, runtime: OCISandbox(image=image, runtime=runtime),
    "observed": lambda image, runtime: ObservedOCISandbox(image=image, runtime=runtime),
}

# S3-completion: the CLOSED set of audited RUNTIMES a trusted factory may PIN (mirrors the sandbox
# backends' own audited ``_RUNTIMES``). ``runtime=None`` means DETECT (the sandbox probes for a working
# runtime); an EXPLICIT runtime must be one of THESE — never an arbitrary executable string or path, which
# would be an exec-injection surface into the container runtime. Adding one is a reviewed change.
_APPROVED_RUNTIMES: frozenset[str] = frozenset({"podman", "nerdctl", "docker"})


def approved_backends() -> tuple[str, ...]:
    return tuple(sorted(_APPROVED))


def approved_runtimes() -> tuple[str, ...]:
    return tuple(sorted(_APPROVED_RUNTIMES))


def trusted_sandbox_factory(kind: str, image: str, *, runtime: str | None = None) -> Callable[[], Sandbox]:
    """A ``make_sandbox`` factory that builds an AUDITED backend and stamps it with the trusted-backend
    token. ``kind`` must name an approved backend; an unknown kind is refused (no arbitrary factory).
    ``runtime`` optionally PINS an audited runtime (bypassing per-sandbox detection, preserving explicit
    behaviour); it must be in the CLOSED ``_APPROVED_RUNTIMES`` set (never an arbitrary string/path) or it
    is refused BEFORE any sandbox is constructed. ``None`` = detect."""
    if kind not in _APPROVED:
        raise UntrustedBackendError(
            f"backend {kind!r} is not an audited backend {list(approved_backends())}"
        )
    if runtime is not None and runtime not in _APPROVED_RUNTIMES:
        raise UntrustedBackendError(
            f"runtime {runtime!r} is not an approved runtime {list(approved_runtimes())} — refused BEFORE "
            "construction (an arbitrary runtime string/path would be an exec-injection surface)"
        )
    build = _APPROVED[kind]

    def make() -> Sandbox:
        sb = build(image, runtime)
        object.__setattr__(sb, _TICKET_ATTR, _TICKET)  # stamp the audited instance
        return sb

    return make


def trusted_backend_guard(sandbox: Sandbox) -> None:
    """Raise ``UntrustedBackendError`` unless ``sandbox`` bears the exact trusted-backend token. Verifies
    the RETURNED object (board amendment): a factory that accepts the token but returns a DIFFERENT object
    is refused, because that returned object carries no valid token."""
    if getattr(sandbox, _TICKET_ATTR, None) is not _TICKET:
        raise UntrustedBackendError(
            f"{type(sandbox).__name__} is not an audited backend — security-relevant calibration refuses "
            "a backend that merely DECLARES HERMETIC (the generic API cannot prove no-egress / observer "
            "isolation). Build it via gate.backends.trusted_sandbox_factory."
        )


_GUARD_POLICY_DOMAIN = "gated.backend-guard-policy"


class BackendGuardPolicy(Protocol):
    """Gate-side CONTRACT (B3): a NAMED, versioned guard policy. ``policy_id`` identifies it (name +
    version); CALLING it applies the guard to a sandbox and RAISES on rejection — it never returns a bool
    (an ignored return value would be a fail-open). It is structurally a ``BackendGuard``
    (``Callable[[Sandbox], None]``), so the engine consumes ``__call__`` as a plain callable and never
    learns this gate type (engine ⊥ gate). ``policy_digest`` is measured PROVENANCE — the calibration layer
    reads it OFF the applied object (never separately supplied), so S3 binds the digest of the guard that
    actually ran: there is NO independent digest ARGUMENT — the digest is read from the invoked guard
    object, so a policy-A-applied-while-digest-B-supplied split has no argument through which to enter."""

    policy_id: str

    @property
    def policy_digest(self) -> str: ...

    def __call__(self, sandbox: Sandbox) -> None: ...


class _TrustedBackendGuardPolicy:
    """The one approved guard policy in the reference: it applies ``trusted_backend_guard`` (the audited-
    backend token check). ``policy_id`` names + versions it; ``policy_digest`` is its canonical identity
    digest, read off THIS object when it is the guard actually applied."""

    __slots__ = ()
    policy_id = "trusted-backend:v1"

    @property
    def policy_digest(self) -> str:
        return canonical_digest(_GUARD_POLICY_DOMAIN, {"policy_id": self.policy_id})

    def __call__(self, sandbox: Sandbox) -> None:
        trusted_backend_guard(sandbox)


# The CLOSED guard-policy registry — DISTINCT from the ``_APPROVED`` BACKEND registry (a backend is a
# sandbox CONSTRUCTOR; a guard policy is a check applied to the constructed object). Not conflated: adding
# either is a reviewed, security-relevant change to its own registry.
_APPROVED_GUARD_POLICIES: dict[str, BackendGuardPolicy] = {
    "trusted-backend": _TrustedBackendGuardPolicy(),
}


def approved_guard_policies() -> tuple[str, ...]:
    return tuple(sorted(_APPROVED_GUARD_POLICIES))


def guarded_backend(
    backend_kind: str, image: str, *, guard_policy: str = "trusted-backend", runtime: str | None = None,
) -> tuple[Callable[[], Sandbox], BackendGuardPolicy]:
    """Production composition root (B3 / D3): select an approved BACKEND kind AND an approved GUARD POLICY
    from the two DISTINCT closed registries, returning the guarded factory + the guard the entry points
    now REQUIRE (no ``None`` default). An unknown backend kind, guard policy, or ``runtime`` is refused —
    no arbitrary factory, no arbitrary guard, no arbitrary runtime. ``runtime`` PINS an audited runtime
    (bypassing detection); ``None`` = detect."""
    if guard_policy not in _APPROVED_GUARD_POLICIES:
        raise UntrustedBackendError(
            f"guard policy {guard_policy!r} is not an approved guard policy "
            f"{list(approved_guard_policies())}"
        )
    make = trusted_sandbox_factory(backend_kind, image, runtime=runtime)  # refuses bad kind OR runtime
    return make, _APPROVED_GUARD_POLICIES[guard_policy]


__all__ = [
    "UntrustedBackendError",
    "trusted_sandbox_factory",
    "trusted_backend_guard",
    "approved_backends",
    "approved_runtimes",
    "BackendGuardPolicy",
    "approved_guard_policies",
    "guarded_backend",
]
