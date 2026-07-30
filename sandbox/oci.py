"""Increment 1.3 — OCISandbox (HERMETIC isolation).

Runs the artifact in an ephemeral OCI container (podman-first; docker optional,
never required), with the verified tree mounted read-only, ``--network=none``, a
sterile env, and a writable scratch tmpfs — the real Promotion Gate isolation.

Board-ratified design (every point mechanically verified against podman 4.9.3):

  * Catch 1 — capability, not presence: detection actually runs
    ``<rt> run --rm --network=none <image> true`` and fails closed if it can't;
    a runtime on ``$PATH`` that can't run hermetically is not "available".
  * Catch 2 — teardown that CONFIRMS: ``rm -f`` then VERIFY with ``ps``; on a
    survivor, escalate, then raise SandboxLeakError. A container that outlives
    teardown is a hermeticity breach, not a warning.
  * Catch 3 — read-only that's VERIFIED: the mount is ``readonly`` + private
    propagation; the write-probe test proves the artifact can't rewrite itself
    post-verification (which would void the SHA-bind).
  * SHA-bind: hash the IMMUTABLE snapshot copy and mount THAT ``:ro`` (never the
    live staging dir) — closes the hash→mount TOCTOU.
  * NFR4: ``--network=none`` (no route to the grader/host), no host env inherited
    (sterile env built from scratch), no host mounts but the ro artifact. The
    writable ``/work`` tmpfs is scratch/AUDIT-ONLY — per ARCHITECTURE.md the
    verdict depends only on out-of-band observation, never on what the artifact
    wrote there.

Boundary egress *counting* is Increment 1.4 (observe/). The container's network
config is isolated to ``_network_args()`` so 1.4 can swap ``--network=none`` for a
veth pair + host-side tap without touching prepare/run/teardown.

Container contract: the verified tree is at ``/artifact`` (read-only); the cwd is a
writable tmpfs ``/work``. Entrypoints reference the code via ``/artifact/…`` and may
scratch to ``/work``.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    Command,
    Existence,
    ExecutionResult,
    Fixtures,
    ImageResolutionError,
    IsolationLevel,
    ResourceBudget,
    Sandbox,
    SandboxHandle,
    SandboxLeakError,
    tree_hash,
)
from sandbox.base import BaseSandbox
from sandbox.subprocess import _rmtree_resilient  # shared resilient rmtree

_Outcome = Literal["completed", "timeout", "error"]
_RUNTIMES = ("podman", "nerdctl", "docker")  # docker last — optional, never preferred
ARTIFACT_MOUNT = "/artifact"  # verified tree, read-only
WORK_DIR = "/work"            # writable tmpfs — scratch/audit only, NEVER graded

# The name prefix every gated-created runtime resource carries. LOAD-BEARING, and shared: the
# observed sandbox's ``reap_orphans`` selects orphans with ``--filter name=<this>``, so a container
# whose name does not derive from it is one the reaper cannot see. It lived as a bare literal in both
# modules, which meant the reaper's coverage of THIS module's containers rode on two independently
# maintained strings happening to agree. Defined once here and imported by ``sandbox/observed.py``.
RESOURCE_PREFIX = "moriverify-"


class OCIRuntimeUnavailable(Exception):
    """No OCI runtime can actually run a hermetic (rootless, --network=none)
    container for the requested image. HERMETIC is unavailable — the engine must
    fail closed (no silent WEAK fallback outside explicit dev mode).

    Defined HERE, above the resolution helpers, so ``RuntimePathUnresolved`` can subclass it."""


class RuntimePathUnresolved(OCIRuntimeUnavailable):
    """The runtime NAME could not be resolved to an ABSOLUTE binary path, so no argv may be built
    around it — raised at the exec boundary, never at construction or import.

    A SUBCLASS of ``OCIRuntimeUnavailable`` deliberately: the consequence is identical (HERMETIC is
    unavailable, fail closed) and every existing handler — including ``available()``, which reports
    the backend as unusable rather than propagating — already treats that correctly. A fresh
    top-level exception type would have slipped past all of them.
    """


# ---------------------------------------------------------------------------------------------------
# P2a — ONE runtime resolution and ONE client-env policy, shared by every sandbox backend.
#
# Two DISTINCT things, deliberately not conflated (they were, before P2a):
#
#   * the runtime NAME  — an audited identity from a closed set (``gate/backends.py``'s
#     ``_APPROVED_RUNTIMES``). It is what ``sandbox.runtime`` reports and what the trusted factory
#     validates. It must stay a bare name: an arbitrary string or path there is an exec-injection
#     surface, which is precisely what that closed set exists to refuse.
#   * the runtime PATH  — the resolved absolute binary, used as ``argv[0]`` at every invocation.
#
# Why the split matters. ``Popen(cmd, env=...)`` with a slash-less ``cmd[0]`` resolves the binary via
# the PATH *in the passed env dict*, so a trojaned ``podman`` on an early PATH entry would execute AS
# THE GATE during verdict runs. Naming the binary absolutely closes that regardless of env. Keeping the
# NAME separate means the closed-set contract is untouched.
_CLIENT_PATH_FALLBACK = "/usr/bin:/bin"

# The client env allowlist. NOT full ``os.environ`` (the runtime client should not inherit the host's
# world) and NOT ``{"PATH": ...}`` alone.
#
# MEASURED on the reference host (podman 4.9.3, crun 1.14.1, conmon 2.1.10, rootless uid 1000,
# Ubuntu 24.04.4, kernel 6.17.0-35, home-dir ``storage.conf``) on 2026-07-29, n=1: a bare
# ``{"PATH": ...}`` IS sufficient — the capability probe exits 0, the configured graphroot resolves,
# and locally-built images are readable, because podman falls back to ``getpwuid`` when HOME is unset.
# An ABSENT ``HOME`` degrades correctly; a WRONG one fails loudly.
#
# The scope of that measurement is load-bearing and is stated with it deliberately: cited bare, it
# reads as justifying this allowlist by the very measurement that showed it unnecessary. What it
# establishes is a fact about ONE host. The allowlist exists for hosts where the ``getpwuid`` fallback
# is not authoritative and for the untested runtimes (``nerdctl``, ``docker``) — i.e. PORTABILITY
# INSURANCE, NOT "what makes rootless podman work", which the measurement contradicts.
# Each name is passed through ONLY if present in the parent environment.
_CLIENT_ENV_PASSTHROUGH = (
    "HOME",                       # rootless config/storage discovery when getpwuid is not authoritative
    "XDG_RUNTIME_DIR",            # rootless runroot / socket location
    "XDG_CONFIG_HOME",            # non-default config root
    "CONTAINERS_CONF",            # explicit containers.conf
    "CONTAINERS_STORAGE_CONF",    # explicit storage.conf
    "CONTAINERS_REGISTRIES_CONF", # explicit registries.conf
    "DOCKER_HOST",                # docker/nerdctl daemon endpoint
    "DOCKER_CONFIG",              # docker client config dir
)


def client_path() -> str:
    """The ``PATH`` a runtime client will be given — and the SAME value resolution searches.

    Resolution and execution MUST agree. Resolving a bare name against the *host's* ``PATH`` while
    executing with a *different* ``PATH`` in the env dict is how an argv[0] that looks resolved ends up
    naming a binary the client would never have found — or a different one. Keeping both through this
    one function makes that divergence unrepresentable rather than merely unlikely.
    """
    return os.environ.get("PATH", _CLIENT_PATH_FALLBACK)


def runtime_client_env() -> dict[str, str]:
    """The environment for a HOST-SIDE runtime invocation — every one of them, uniformly.

    This is the CLIENT's env (podman/docker itself), NOT the container's: no ``--env`` appears in any
    argv, so the container's environment comes from the image config and is already covered by the
    attested image digest. The artifact cannot reach this dict.

    Before P2a there were three postures in one package — one site hardcoded ``{"PATH": "/usr/bin:/bin"}``,
    one inherited the host ``PATH``, and eighteen passed no ``env=`` at all and inherited the entire host
    environment, including the capability probe that decides whether the gate can run. Nobody chose that;
    it drifted.

    ``PATH`` IS STILL PASSED, and the reason changed under P2a — so the rationale is restated here rather
    than left to rot into a false claim. With the absolute-path pin, this ``PATH`` no longer selects the
    runtime BINARY: argv[0] is absolute, so the client is found without it. It is retained because the
    runtime spawns HELPER CHILDREN of its own (``crun``/``runc``, ``conmon``, ``newuidmap``, the OCI
    hooks), and those are resolved by name against exactly this value. Stripping it would break the
    container lifecycle while closing nothing that the pin has not already closed.
    """
    env = {"PATH": client_path()}
    for var in _CLIENT_ENV_PASSTHROUGH:
        value = os.environ.get(var)
        if value is not None:
            env[var] = value
    return env


def resolve_runtime_path(runtime: str) -> str:
    """An ABSOLUTE path for ``runtime``, or ``runtime`` UNCHANGED when no absolute path can be produced.

    The postcondition is "absolute, or the input verbatim" — NOT "the absolute path". That distinction
    is the whole point of this function and an earlier docstring got it wrong, which is worth recording
    because the wrong version was strictly more dangerous than no docstring: it stamped a value as
    resolved without establishing it.

    ``shutil.which()`` DOES return a relative path — verified on CPython 3.12.3/Linux,
    ``which('zzruntime', path='reldir') -> 'reldir/zzruntime'`` — whenever the matching ``PATH`` entry is
    itself relative. A relative argv[0] is resolved by ``Popen`` at spawn time against the CWD, which is
    precisely the trojan geometry the pin exists to close, so a non-absolute result is treated as NO
    RESULT here and rejected outright at the exec boundary (``require_resolved_runtime``).

    Searched against ``client_path()`` — the PATH the invocation will actually carry — not the ambient
    default. (A second mechanism was proposed for this finding and is REFUTED on this platform, recorded
    so it is not re-added: ``os.defpath`` is ``/bin:/usr/bin``, with no leading empty entry, so an unset
    ``PATH`` does not fall back to a CWD-searching default. The finding stands on the relative-entry
    route alone.)

    BEST-EFFORT BY DESIGN — it does not raise, for two reasons that both still hold:

      * ``detect_runtime`` must SKIP an unresolvable candidate and try the next one. A resolver that
        raised on the first miss would make "podman is absent" fatal on a host where docker would have
        worked. That is why the detection path narrows this through ``_resolved_or_none`` instead.
      * CONSTRUCTING IS NOT EXECUTING. A sandbox may be built and never run — ``gate/backends.py``
        constructs with a pinned runtime under test — and refusal is a decision about ONE INVOCATION.
        It belongs at the exec boundary (``require_resolved_runtime``).

    An earlier version of this paragraph justified best-effort by a THIRD reason that is no longer true:
    that ``observed.py`` instantiated a sandbox at MODULE IMPORT for the protocol conformance check, so
    raising here would break importing the package. That instantiation was moved behind ``_conforms()``
    in the same change that added the exec boundary, so the import constraint is GONE. Recorded rather
    than quietly deleted, because a docstring citing a constraint the tree no longer has is the same
    defect class as the "absolute path" claim two paragraphs up — a property credited, not held.

    Already-absolute input is returned as-is, so a caller that pinned a path keeps it.

    TOCTOU, stated rather than implied: resolution happens once at construction, so a binary replaced
    between construction and invocation is not detected. That is strictly better than resolving by name
    at every call — which is what this replaces — but it is not a guarantee that the bytes are unchanged.
    Binding the runtime's identity into the attested execution identity is a separate, deferred question.
    """
    if os.path.isabs(runtime):
        return runtime
    found = shutil.which(runtime, path=client_path())
    if found is None or not os.path.isabs(found):
        return runtime  # UNRESOLVED — a relative hit is not a resolution
    return found


def require_resolved_runtime(runtime: str, path: str) -> str:
    """THE EXEC BOUNDARY: refuse to build a runtime argv around a non-absolute ``argv[0]``.

    Fail-closed, and placed here rather than in ``__init__`` for two reasons that both bit the first
    attempt. CONSTRUCTING IS NOT EXECUTING — an ``__init__`` raise fires for a sandbox that is never run
    and breaks the ungated ``test_backends`` construction. And a guard in ``__init__`` cannot BIND
    ``_runtime_path``, which is writable and IS written by tests on ``__new__`` instances; only a check
    on the value actually being used can.

    RESIDUAL, stated plainly: failure therefore surfaces at the FIRST INVOCATION, not at startup. On a
    host where the runtime cannot be resolved, the refusal arrives when the gate first tries to exec.
    That is the correct trade for refusing per-invocation rather than per-construction, but it is not
    startup validation. (An earlier version of this paragraph also cited the module-import conformance
    check; that instantiation now sits behind ``_conforms()``, so it is no longer a reason for anything.)
    """
    if not os.path.isabs(path):
        raise RuntimePathUnresolved(
            f"runtime {runtime!r} did not resolve to an absolute binary path on the client PATH "
            f"(got {path!r}); refusing to exec an argv[0] that PATH would resolve at spawn time — "
            "HERMETIC unavailable, fail closed"
        )
    return path


def exec_runtime_path(runtime: str) -> str:
    """Resolve ``runtime`` and REFUSE a non-absolute result — one expression, for module-level callers.

    Resolution and enforcement are deliberately fused: there is no way to obtain the resolved value
    without passing the check, so no shape exists in which an unresolved path reaches an argv.
    """
    return require_resolved_runtime(runtime, resolve_runtime_path(runtime))


def _resolved_or_none(runtime: str) -> str | None:
    """``resolve_runtime_path`` narrowed to "an absolute path, or nothing" — for DETECTION, which must
    SKIP an unresolvable candidate and try the next rather than raise on the first.

    The ``None`` branch cannot reach an argv, and that is enforced by a compiler rather than by review:
    ``mypy --strict`` refuses ``str | None`` as a member of the ``list[str]`` ``subprocess`` requires, so
    omitting the guard is a type error, not a latent bug.
    """
    path = resolve_runtime_path(runtime)
    return path if os.path.isabs(path) else None


class _ResolvedRuntimeMixin:
    """The exec boundary for the OCI-family backends — ONE implementation, mixed into both.

    Deliberately not duplicated per class and not pushed down into ``BaseSandbox``: the NAME/PATH split
    is specific to the backends that exec a container runtime, and ``NoOpSandbox`` /
    ``SubprocessSandbox`` have no runtime to resolve.
    """

    _runtime: str
    _runtime_path: str

    def _exec_runtime(self) -> str:
        """``argv[0]`` for every runtime invocation — the resolved path, REFUSED if not absolute.

        The pin and its enforcement are one expression on purpose: a method cannot build a runtime argv
        without passing the check. Reading ``self._runtime_path`` directly into an argv is therefore a
        defect the static sweep flags, not a style preference. One ``isabs`` per invocation.
        """
        return require_resolved_runtime(self._runtime, self._runtime_path)


def detect_runtime(image: str) -> str:
    """The ONE runtime-detection implementation, shared by every OCI-family backend.

    Returns the audited NAME (not the path) so the closed-set contract in ``gate/backends.py`` and
    ``sandbox.runtime`` are unaffected. Detection is by CAPABILITY, not presence: a runtime on ``$PATH``
    that cannot actually run a hermetic container is not "available".

    Was duplicated verbatim in ``oci.py`` and ``observed.py`` — the function that decides WHICH BINARY
    THE GATE EXECUTES, maintained in two places. ``ObservedOCISandbox`` does not subclass ``OCISandbox``
    (both derive from ``BaseSandbox``), which is why it was copied rather than inherited.
    """
    for rt in _RUNTIMES:
        path = _resolved_or_none(rt)
        if path is None:
            continue  # not resolvable to an absolute binary on the client PATH — try the next
        try:
            probe = subprocess.run(
                capability_probe_argv(path, image),
                capture_output=True,
                timeout=90,
                env=runtime_client_env(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:  # it can actually run hermetically
            return rt
    raise OCIRuntimeUnavailable(
        f"no OCI runtime can run '{image}' hermetically "
        "(rootless, --network=none); HERMETIC unavailable — fail closed"
    )


def probe_existence(argv: list[str], name: str, *, timeout: float = 30.0) -> Existence:
    """Probe whether the runtime resource ``name`` is listed by ``argv`` — the SHARED, fail-CLOSED existence
    check for OCI + observed teardown/reap. EXISTS/ABSENT are returned ONLY on a query that actually ran
    (return code 0); ANY inability to tell — an ``OSError``, a timeout / ``SubprocessError``, OR a NON-ZERO
    return code (an empty stdout from a *failed* ``ps`` is not proof of absence) — is ``UNKNOWN``. Ephemerality
    is security-critical, so a caller must treat ``UNKNOWN`` after teardown as a leak, never as 'gone'."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           env=runtime_client_env())
    except (OSError, subprocess.SubprocessError):
        return Existence.UNKNOWN
    if r.returncode != 0:
        return Existence.UNKNOWN
    return Existence.EXISTS if name in r.stdout.split() else Existence.ABSENT


def resolve_image_id(runtime: str, image: str) -> str:
    """Resolve ``image`` (a possibly-mutable tag) to its IMMUTABLE local content id
    (``<rt> inspect --format {{.Id}}`` -> ``sha256:...``) so the caller can execute the DIGEST,
    not the tag (3.5-close #1.1 — closes the tag-remap TOCTOU). The FULL digest is returned (never
    a short prefix — a short prefix reopens id ambiguity). Raises ``ImageResolutionError`` if the
    image is absent or the runtime can't report an id, and ``RuntimePathUnresolved`` (an
    ``OCIRuntimeUnavailable``) if ``runtime`` yields no absolute binary — an unresolvable runtime is a
    fail-closed refusal to exec, not an image-resolution outcome, so it is NOT folded into the latter."""
    try:
        out = subprocess.run(
            [exec_runtime_path(runtime), "image", "inspect", "--format", "{{.Id}}", image],
            capture_output=True, text=True, timeout=30, env=runtime_client_env(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ImageResolutionError(f"could not inspect image {image!r}: {exc}") from exc
    digest = out.stdout.strip()
    if out.returncode != 0 or not digest:
        raise ImageResolutionError(
            f"image {image!r} has no resolvable local id (absent or GC'd before run): "
            f"{out.stderr.strip() or 'no id'}"
        )
    return digest if digest.startswith("sha256:") else f"sha256:{digest}"


@dataclass(frozen=True)
class OCIHandle:
    id: str
    artifact_hash: str
    snapshot: Path   # host-side immutable snapshot (mounted read-only)
    container: str   # unique container name (teardown / reaper target)
    image_id: str    # 3.5-close #1.1: the IMMUTABLE digest resolved at prepare(); run() executes THIS


def _selinux_enforcing() -> bool:
    return os.path.exists("/sys/fs/selinux/enforce")


# ---------------------------------------------------------------------------------------------------
# P2b — POSTURE PRIMITIVES and ARGV BUILDERS.
#
# Every CONSTRUCT invocation (one that creates or configures a runtime resource whose posture flags bear
# on isolation) builds its argv HERE rather than inline. Classification is by WHO CONSUMES THE EFFECT OR
# THE STDOUT — the ratified replacement for a posture/lifecycle split that was refuted by two live
# counter-examples in this package: ``exec cat`` is "lifecycle" yet its stdout IS the verdict input, and
# ``inspect`` is "lifecycle" yet its stdout AUTHORS ``--add-host``.
#
# WHY CENTRALISE. Before P2b, three posture values were restated across argv-bearing sites:
# ``--network=none`` appeared as a live literal in TWO places (the capability probe and
# ``_network_args``), the mount spec carrying the read-only guarantee was hand-built in two modules, and
# ``--rm --init --name`` / ``--tmpfs`` / ``--workdir`` were restated at both artifact-run sites. That is
# P1's defect class exactly: a value that matters, applied by hand, with nothing binding application to
# intent.
#
# AND IT IS THE PRECONDITION FOR ATTESTING ANY OF IT. ``OCISandbox`` carries no ``observer_config_hash``
# and has no runtime network check, so its hermetic posture currently rests on a literal being correct
# with no second layer to catch it if it is not. Attestation (a later increment) binds BUILDER SOURCE
# BYTES — so until a value comes out of one shared builder there is nothing for it to attest. This
# increment does not attest anything and does not claim to.
# ---------------------------------------------------------------------------------------------------


def hermetic_network_segment() -> list[str]:
    """The no-network posture, stated ONCE for both the capability probe and the artifact run.

    Returned as a SEGMENT (a list spliced into an argv) rather than signalled by a mode flag, so a
    caller selects a posture by passing data instead of by passing a boolean the builder branches on.
    A branch inside the builder would put the choice back where the census cannot see it.
    """
    return ["--network=none"]


def artifact_mount_spec(snapshot: Path, target: str = ARTIFACT_MOUNT) -> str:
    """The read-only bind of the verified tree — the mount that closes the hash->mount TOCTOU.

    Was hand-built identically in ``oci.py`` and ``observed.py``. Verified char-identical to both before
    centralising: same field order, same ``readonly,bind-propagation=rprivate``, same conditional
    ``,relabel=private`` under SELinux (``:Z``-equivalent, and it does NOT break readonly).
    """
    spec = f"type=bind,source={snapshot},target={target},readonly,bind-propagation=rprivate"
    if _selinux_enforcing():
        spec += ",relabel=private"
    return spec


def capability_probe_argv(runtime: str, image: str) -> list[str]:
    """Detection by CAPABILITY, not presence: can this runtime actually run a hermetic container?

    Its ``--network=none`` now comes from the same segment the artifact run uses, so the probe cannot
    certify a posture the real run does not apply — which is precisely what two independent literals
    permitted.
    """
    return [runtime, "run", "--rm", *hermetic_network_segment(), image, "true"]


def artifact_run_argv(
    runtime: str,
    *,
    container: str,
    network: list[str],
    snapshot: Path,
    image_id: str,
    entrypoint: list[str],
) -> list[str]:
    """The artifact-execution argv — ONE builder serving BOTH backends.

    The two run sites differed only in their network segment, so passing that as DATA collapses them.
    That collapse is the whole argument for segments-over-mode-flags, and it is why this increment has
    five builders rather than six.

    ``--init``: a real init as PID 1 so the artifact runs as its child — a namespace's PID 1 cannot be
    signal-killed from within (crashes would otherwise be mis-reported as clean exits) and zombies get
    reaped. ``image_id`` is the IMMUTABLE digest resolved at prepare(), never the mutable tag.
    """
    return [
        runtime, "run", "--rm", "--init", "--name", container,
        *network,
        "--mount", artifact_mount_spec(snapshot),
        "--tmpfs", WORK_DIR,
        "--workdir", WORK_DIR,
        image_id, *entrypoint,
    ]


def _make_snapshot_readable(root: Path) -> None:
    """Add world read (+ dir traverse) so a rootless container's non-root user can
    read the ro-mounted tree. The artifact code is not secret; tree_hash excludes
    permissions, so the hash is unaffected. No-op-ish on Windows (podman-machine VM
    handles mount perms VM-side)."""
    for p in (root, *root.rglob("*")):
        try:
            add = stat.S_IROTH | stat.S_IRGRP
            if p.is_dir():
                add |= stat.S_IXOTH | stat.S_IXGRP
            os.chmod(p, p.stat().st_mode | add)
        except OSError:
            pass


class OCISandbox(_ResolvedRuntimeMixin, BaseSandbox):
    """HERMETIC isolation via an ephemeral OCI container."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC

    def __init__(self, image: str, runtime: str | None = None) -> None:
        self.image = image
        # NAME (audited identity, closed set) and PATH (what actually execs) are separate — see the
        # module header. ``runtime`` reports the name; every argv[0] uses ``_runtime_path``.
        self._runtime = runtime if runtime is not None else self._detect_runtime(image)
        self._runtime_path = resolve_runtime_path(self._runtime)

    @property
    def runtime(self) -> str:
        return self._runtime

    # -- Catch 1: detect by CAPABILITY, not presence ----------------------
    @staticmethod
    def _detect_runtime(image: str) -> str:
        """Thin delegation to the shared ``detect_runtime`` — ONE implementation for both backends.

        Kept as a staticmethod on the class because it is a patch point in the closed-runtime tests
        (``mock.patch.object(OCISandbox, "_detect_runtime")`` asserts a pinned runtime does NOT probe).
        """
        return detect_runtime(image)

    @staticmethod
    def available(image: str) -> bool:
        """True iff some runtime can run `image` hermetically (for skip-guards)."""
        try:
            OCISandbox._detect_runtime(image)
            return True
        except OCIRuntimeUnavailable:
            return False

    # -- 1.4-swappable network isolation ----------------------------------
    @staticmethod
    def _network_args() -> list[str]:
        # 1.3: hard no-network. 1.4 replaces this with a veth pair + host-side tap
        # for egress counting — without touching prepare/run/teardown.
        # P2b: delegates rather than restating. This was the SECOND live statement of the no-network
        # posture (the capability probe held the other), so the two could drift with nothing failing.
        return hermetic_network_segment()

    # -- prepare: snapshot -> hash -> verify (TOCTOU-closed) --------------
    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        # 3.5-close #1.1: resolve the IMMUTABLE image digest at the TOP of prepare(), ONCE, before
        # anything runs — run() then executes THIS digest, not the mutable tag (closes tag-remap).
        image_id = resolve_image_id(self._exec_runtime(), self.image)
        snapshot = Path(tempfile.mkdtemp(prefix=f"{RESOURCE_PREFIX}oci-"))
        try:
            if artifact.path.is_dir():
                shutil.copytree(artifact.path, snapshot, dirs_exist_ok=True)
            else:
                shutil.copy2(artifact.path, snapshot / artifact.path.name)
            _make_snapshot_readable(snapshot)  # rootless non-root container must read it
            staged = tree_hash(snapshot)  # hash the immutable snapshot, not the live dir
            if staged != artifact.tree_hash:
                raise ArtifactHashMismatchError(
                    f"staged tree {staged} != claimed {artifact.tree_hash}"
                )
        except BaseException:
            shutil.rmtree(snapshot, ignore_errors=True)
            raise
        return OCIHandle(
            id=uuid.uuid4().hex,
            artifact_hash=artifact.tree_hash,
            snapshot=snapshot,
            container=f"{RESOURCE_PREFIX}{uuid.uuid4().hex[:16]}",
            image_id=image_id,
        )

    # -- run: hermetic container, our wall-clock timeout ------------------
    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        h = self._require_own(handle)
        # P2b: argv comes from the shared builder. 3.5-close #1.1 still holds — the digest executed is
        # the IMMUTABLE h.image_id resolved in prepare(), the same value recorded in the result.
        cmd = artifact_run_argv(
            self._exec_runtime(),
            container=h.container,
            network=self._network_args(),
            snapshot=h.snapshot,
            image_id=h.image_id,
            entrypoint=list(entrypoint.argv),
        )
        # One client-env policy for every runtime invocation (P2a) — see ``runtime_client_env``.
        # This is the CLIENT's env, never the container's: no ``--env`` appears in this argv.
        sterile = runtime_client_env()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=sterile,
            )
        except OSError:
            return self._result("error", exit_code=None, raw=None, handle=h)

        try:
            proc.communicate(timeout=budget.wall_clock_seconds)
        except subprocess.TimeoutExpired:
            self._force_remove(h.container)  # kill the container first
            proc.kill()
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            return self._result("timeout", exit_code=None, raw=None, handle=h)

        rc = proc.returncode
        # podman propagates the container's exit code. 125-127 = podman/exec
        # failure; >=128 = killed by signal (crash). Neither is a clean completion.
        if rc is None or rc in (125, 126, 127) or rc >= 128:
            return self._result("error", exit_code=None, raw=rc, handle=h)
        return self._result("completed", exit_code=rc, raw=rc, handle=h)

    # -- Catch 2: teardown that CONFIRMS destruction ----------------------
    def teardown(self, handle: SandboxHandle) -> None:
        if not isinstance(handle, OCIHandle):
            return
        try:
            self._force_remove(handle.container)
            # PROVE destruction: teardown succeeds ONLY on a probed ABSENT. EXISTS is a survivor; UNKNOWN
            # (the probe could not tell — timeout / error / non-zero) is ALSO a leak, because we cannot
            # CONFIRM the container is gone (SandboxLeakError's contract). One escalation, then fail closed.
            if self._container_state(handle.container) is not Existence.ABSENT:
                self._force_remove(handle.container)  # reaper escalation
                state = self._container_state(handle.container)
                if state is not Existence.ABSENT:
                    raise SandboxLeakError(
                        f"container {handle.container} could not be CONFIRMED destroyed (probe={state.value}) "
                        "— ephemerality (a security property) is violated"
                    )
        finally:
            _rmtree_resilient(handle.snapshot)

    # -- internals --------------------------------------------------------
    def _force_remove(self, name: str) -> None:
        # best-effort removal — the AUTHORITY that destruction happened is the tri-state probe below, not this
        # return code (a non-zero rm still forces a re-probe, which fails closed on EXISTS/UNKNOWN).
        try:
            subprocess.run([self._exec_runtime(), "rm", "-f", name], capture_output=True, timeout=30,
                           env=runtime_client_env())
        except (OSError, subprocess.SubprocessError):
            pass

    def _container_state(self, name: str) -> Existence:
        return probe_existence(
            [self._exec_runtime(), "ps", "-a", "--filter", f"name=^{name}$", "--format", "{{.Names}}"],
            name)

    def _result(
        self,
        outcome: _Outcome,
        *,
        exit_code: int | None,
        raw: int | None,
        handle: OCIHandle,
    ) -> ExecutionResult:
        return ExecutionResult(
            outcome=outcome,
            exit_code=exit_code,
            isolation_level=self.isolation_level,
            artifact_hash=handle.artifact_hash,
            raw_return_code=raw,
            # single source of truth: the SAME digest that was interpolated into the run argv.
            image_digest=handle.image_id,
        )

    @staticmethod
    def _require_own(handle: SandboxHandle) -> OCIHandle:
        if not isinstance(handle, OCIHandle):
            raise TypeError(
                f"OCISandbox received a foreign handle: {type(handle).__name__}"
            )
        return handle


# Type-check proof: OCISandbox IS a core.Sandbox (session() inherited from base).
def _conforms() -> Sandbox:
    return OCISandbox(image="scratch", runtime="podman")  # no detection at import
