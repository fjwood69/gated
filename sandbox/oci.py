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
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Literal, NamedTuple

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    Command,
    Existence,
    ExecutionResult,
    Fixtures,
    ImageResolutionError,
    IsolationLevel,
    ReplayedSandboxLeak,
    ReplayedTeardownIncomplete,
    ReplayedTeardownUnverifiable,
    ResourceBudget,
    Sandbox,
    SandboxHandle,
    SandboxLeakError,
    TeardownCleanupError,
    TeardownError,
    TeardownIncompleteError,
    TeardownUnverifiableError,
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

# Disable engine-run healthchecks on EVERY container gated creates. This is a VERDICT control, not
# hygiene, and it is defined once here for the same reason ``RESOURCE_PREFIX`` is: three builders across
# two modules apply it, and three independently maintained literals would be three chances to drift.
#
# WHY IT IS LOAD-BEARING. A HEALTHCHECK makes the ENGINE open periodic connections. The proxy counts
# CONNECTIONS at accept, so engine traffic lands in the verdict input as if the artifact had made it —
# and worse, ``fail_once`` is a GLOBAL counter, so a single stray connection consumes attempt 1 and
# silently upgrades the artifact's first retry from 503 to 200. That changes what the artifact DOES,
# changes the number, and nothing notices. The artifact container is the dangerous surface: it holds
# ``--add-host health-proxy`` on the sealed network, so its healthcheck can reach the proxy directly.
#
# MEASURED 2026-08-02: the configured image (``python:3.11-alpine``) has ``Config.Healthcheck = null``,
# so this is not firing today. THAT IS THE FINDING, NOT THE REASSURANCE — the safety rested entirely on
# the configured image happening to lack one, and NOTHING CHECKED IT. Accidental protection, not
# structural. An image swap is an ordinary act and would have made it live silently.
#
# ATTESTED AS A VALUE, deliberately. It is a member of ``_OBSERVER_CONFIG_HASH`` (see sandbox/observed.py)
# because it is a value whose change alters what the instrument reports on a run that STILL SUCCEEDS —
# Clause M. Builder-SOURCE hashing would also have covered it, but that mechanism IS NOT BUILT (see the
# attestation note further down this module: "this increment does not attest anything and does not claim
# to"), so relying on it here would ship a Clause-M control with ZERO IDENTITY MOVEMENT — the fossil
# class that the vestigial ``baseline`` field already proves can happen.
NO_HEALTHCHECK_FLAGS = ("--no-healthcheck",)


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


class VerdictKind(Enum):
    """What a completed teardown established. FOUR states, because the first version had three and used
    one of them for two different things.

    ``CLEAN`` and ``LEAK`` are answers about the SUBJECT. ``UNVERIFIED`` is a report about the
    INSTRUMENT — the sweep ran and the probe could not answer. ``INCOMPLETE`` is a report about the
    COMPUTATION: no reading was taken at all, because the sweep raised somewhere unanticipated. Absence
    of a measurement and a measurement of absence are different facts, one level up from where this
    increment started."""

    CLEAN = "clean"
    LEAK = "leak"
    UNVERIFIED = "unverified"
    INCOMPLETE = "incomplete"


# The verdict → exception mapping, in ONE place and split by whether the verdict is being raised LIVE or
# REPLAYED. ``INCOMPLETE`` deliberately has no live entry: the first teardown never raises it, because the
# exception that crashed the sweep is the certain fact and must stay primary. It exists only so the
# REPEAT cannot read a crash as a clean result.
_LIVE_VERDICT_EXC: dict[VerdictKind, type[TeardownError]] = {
    VerdictKind.LEAK: SandboxLeakError,
    VerdictKind.UNVERIFIED: TeardownUnverifiableError,
    # INCOMPLETE IS MAPPED NOW. It used to be deliberately absent, on the reasoning that a crash is
    # always propagating and must stay primary. True when one IS propagating — and ``_crashed_verdict``
    # explicitly anticipates the case where none is. In that case the old code returned None and the
    # fall-through surfaced as nothing. ``live()`` gates on ``crash_in_flight``, not on the map.
    VerdictKind.INCOMPLETE: TeardownIncompleteError,
}
_REPLAY_VERDICT_EXC: dict[VerdictKind, type[TeardownError]] = {
    VerdictKind.LEAK: ReplayedSandboxLeak,
    VerdictKind.UNVERIFIED: ReplayedTeardownUnverifiable,
    VerdictKind.INCOMPLETE: ReplayedTeardownIncomplete,
}


@dataclass
class TeardownVerdict:
    """A teardown outcome recorded AS DATA — never as a live exception object held for re-raising.

    Holding the exception was four defects wearing one coat: replays accumulate tracebacks on a shared
    object; ``__notes__`` written by whoever caught it last leak into the next raise; the stored message
    was composed SEPARATELY from the live one and understated it (the leak replay dropped the unproven
    list entirely, so the same event read differently on the second call); and one mutable object is
    shared by every caller that ever catches it.

    ``when`` is CONSUMED, not merely recorded: it is rendered into the replayed message. A field written
    by one side and read by nobody is the seed of the next credited-property defect — this increment has
    found five of those, and a timestamp that no output can show is the same shape.
    """

    kind: VerdictKind
    detail: str
    when: float
    # WHAT THIS VERDICT IS ABOUT — REQUIRED, no default, and that is the fix rather than a nicety. The
    # store is keyed by handle id alone, and a replay matching only on the key would certify THIS handle
    # from a measurement of ANOTHER, silently, on the clean path. My first attempt added the field with
    # a ``""`` default and guarded with ``if prior.subject and …`` — which makes a subject-less verdict
    # REPRESENTABLE and then declines to check it: a fail-closed control with a representable skip
    # state is fail-open by construction. I had written "positive shape, not truthiness" in this very
    # increment. Required-by-contract removes the skip state instead of testing for it.
    subject: str
    notes: list[str] = field(default_factory=list)
    # Was a crash genuinely propagating when this INCOMPLETE was minted? Only then may ``live()`` stay
    # silent — because only then is there a primary exception to defer to. ``_crashed_verdict``
    # explicitly anticipates the other case ("no exception was in flight"), and in THAT case silence
    # would mean a fall-through bug surfaces as nothing at all.
    crash_in_flight: bool = False

    def live(self) -> TeardownError | None:
        """The exception to raise on the FIRST teardown, or ``None`` when the verdict is clean.

        ``CLEAN`` and ``INCOMPLETE`` are the ONLY silent kinds, and they are named rather than
        defaulted. A kind missing from the map used to fall out as ``None`` — silence — so ADDING a
        verdict kind and forgetting the map entry would have created a third quiet path in the one
        place quiet paths are the subject. Now that is a loud failure at the moment of the omission.
        """
        if self.kind is VerdictKind.CLEAN:
            return None
        if self.kind is VerdictKind.INCOMPLETE and self.crash_in_flight:
            # ONLY here. The crash is the certain fact and stays primary; the verdict is recorded, not
            # raised. A CRASHLESS incomplete has no primary to defer to, so silence there would let a
            # fall-through bug surface as nothing — fail-closed must be LOUD.
            return None
        exc_type = _LIVE_VERDICT_EXC.get(self.kind)
        if exc_type is None:
            raise AssertionError(
                f"no LIVE exception is mapped for verdict kind {self.kind!r} — a new kind was added "
                "without deciding how it surfaces, and returning None here would make it silent")
        return exc_type(self._with_notes())

    def replay(self) -> TeardownError | None:
        """The exception to raise on a REPEAT teardown, reconstructed fresh and STAMPED as a replay.

        A stored verdict is a claim about a past moment. Presenting it as a current observation is the
        same confusion this increment exists to close, so the moment of measurement is in the message.
        """
        if self.kind is VerdictKind.CLEAN:
            return None
        exc_type = _REPLAY_VERDICT_EXC.get(self.kind)
        if exc_type is None:
            raise AssertionError(
                f"no REPLAY exception is mapped for verdict kind {self.kind!r} — an unmapped kind "
                "would replay as SILENCE, which is the defect this type exists to prevent")
        stamp = datetime.fromtimestamp(self.when, tz=timezone.utc).isoformat(timespec="seconds")
        return exc_type(
            f"{self._with_notes()} [REPLAYED verdict — MEASURED AT {stamp}, not re-probed now]"
        )

    def _with_notes(self) -> str:
        """The detail plus any cleanup notes — ONE composition site, used by both surfaces.

        Notes used to be rendered by ``replay()`` alone, so a note recorded during cleanup reached an
        operator only if someone happened to tear down twice. On a CLEAN verdict it reached nobody at
        all, because both surfaces return ``None`` before formatting: a field written by one side and
        read by no one, which is this increment's own defect class inside its own failure machinery.
        """
        if not self.notes:
            return self.detail
        return f"{self.detail} [also: {'; '.join(self.notes)}]"

    def cleanup_failed(self) -> bool:
        """Did post-verdict cleanup record a problem? The CLEAN path's only way to be heard."""
        return bool(self.notes)


class _ResolvedRuntimeMixin:
    """The exec boundary for the OCI-family backends — ONE implementation, mixed into both.

    Deliberately not duplicated per class and not pushed down into ``BaseSandbox``: the NAME/PATH split
    is specific to the backends that exec a container runtime, and ``NoOpSandbox`` /
    ``SubprocessSandbox`` have no runtime to resolve.
    """

    _runtime: str
    _runtime_path: str
    # The container-kind witness for this session. Class-level default "" on purpose: an instance built
    # via __new__ (as argv-shape tests do) has NO witness. The sentinel is None rather than "" so that
    # NEVER-PROVISIONED and SPENT cannot share a representation, and so an accidental empty witness
    # RAISES (WitnessNotProvisioned) rather than silently degrading to UNKNOWN.
    _witness: str | None = None

    def _verdict_store(self) -> dict[str, TeardownVerdict]:
        """Per-instance tombstones, created lazily. Values are DATA — see ``TeardownVerdict``.

        NOT a class-level ``= {}``: that is one dict SHARED BY EVERY INSTANCE, so a verdict recorded by
        one sandbox would be replayed by another. ``__init__`` would shadow it for normally-constructed
        objects and hide the bug, leaving it live only for ``__new__``-built ones — which is exactly the
        construction path this increment already learned to distrust.
        """
        store: dict[str, TeardownVerdict] | None = self.__dict__.get("_verdicts")
        if store is None:
            store = {}
            self.__dict__["_verdicts"] = store
        return store

    def _replay_verdict(self, handle_id: str, subject: str) -> TeardownVerdict | None:
        """The recorded verdict for this handle, or ``None`` if it has not been torn down.

        REFUSES on a subject mismatch rather than replaying. A stored verdict answers a question about
        a NAMED resource; matching on the key alone would let a handle inherit a clean certificate
        earned by a different one. Fail-closed: the mismatch itself is unverifiable, not clean.
        """
        prior = self._verdict_store().get(handle_id)
        if prior is not None and prior.subject != subject:
            raise TeardownUnverifiableError(
                f"a verdict is recorded under handle id {handle_id!r} for subject {prior.subject!r}, "
                f"but this teardown is for {subject!r}. Replaying it would certify one resource from a "
                "measurement of another — refusing; re-probe with a fresh handle")
        return prior

    def _crashed_verdict(self, subject: str) -> TeardownVerdict:
        """The verdict for a sweep that RAISED before it reached one.

        The whole point of a distinct kind. The alternative — which shipped — was to leave the result
        lists at their empty initial values and let the ``finally`` block read those empties as
        "nothing present, nothing unproven", i.e. CLEAN. A crashed computation then held a permanent
        clean certificate, and the next teardown returned silently.

        ⚠ THE CAUSE IS CAPTURED, and the first version of this method did not capture it. It took only
        a subject name, so the ``TeardownIncompleteError`` a repeat call raises could not name what went
        wrong — at exactly the boundary where the crash is the ONLY fact anyone has. Building the
        diagnostic plumbing for ``UNKNOWN`` while composing a message that excluded its own cause by
        construction is the same defect, one method along. ``sys.exc_info()`` is read rather than passed
        in, so no caller can forget to supply it.

        ⚠ AND THE WORDING WAS AN OVERCLAIM. It said "nothing was measured". That is not knowable here:
        the sweep destroys everything BEFORE it probes, so a crash may follow partial destruction and
        partial measurement. What is true is that no verdict was REACHED — which is a statement about
        the computation, and the only one this method is entitled to make.
        """
        exc = sys.exc_info()[1]
        cause = (f"{type(exc).__name__}: {exc}" if exc is not None
                 else "NO EXCEPTION WAS IN FLIGHT — the verdict was never assigned, which is a "
                      "fall-through bug in teardown itself and has no primary error to defer to")
        return TeardownVerdict(
            VerdictKind.INCOMPLETE,
            f"teardown of {subject} CRASHED MID-SWEEP and NEVER REACHED A VERDICT — destruction may "
            f"have partially run and some resources may have been probed, but no verdict was reached, "
            f"so nothing is claimed either way. Cause: {cause}. The witness and the snapshot are "
            "RETAINED deliberately: they are what a re-probe needs",
            time.time(),
            subject,
            crash_in_flight=exc is not None,
        )

    def _finalise(self, verdict: TeardownVerdict | None, handle_id: str, subject: str,
                  snapshot: Path) -> TeardownVerdict:
        """Record the verdict and run post-verdict cleanup. Returns the verdict actually stored.

        Runs from the ``finally`` of both teardowns, so it must not raise: the sweep's own exception (if
        any) is the certain fact. Every cleanup failure lands as a note on the verdict, and the caller
        decides how to surface it once the unwinding is over.
        """
        if verdict is None:
            verdict = self._crashed_verdict(subject)
        # TOMBSTONE FIRST, CLEAN UP SECOND. Recording last meant that anything raising during cleanup
        # LOST the verdict entirely, and the next teardown re-probed with a spent witness. The store
        # holds the same object the cleanup below annotates, so notes still reach it.
        self._verdict_store()[handle_id] = verdict
        if verdict.kind is VerdictKind.CLEAN:
            self._release_witness(verdict)
        self._dispose_snapshot(snapshot, verdict)
        return verdict

    def _drop_witness(self) -> None:
        """Destroy this session's witness. Implemented by each backend (each owns its own removal).

        Declared here because ``_release_witness`` below calls it: without the declaration the mixin
        would be reaching for an attribute it does not define, which ``mypy --strict`` correctly refuses
        — and which would fail at runtime for any future mixee that forgot to provide one.
        """
        raise NotImplementedError

    def _surface(self, verdict: TeardownVerdict) -> None:
        """Raise whatever a FINALISED verdict has to say — the one place teardown becomes loud.

        Called AFTER the ``finally`` block, so ``verdict.notes`` are complete and reach the exception.
        Two things can need surfacing and they are different claims:

          * the verdict itself (LEAK / UNVERIFIED / a crashless INCOMPLETE) — about the measurement;
          * a cleanup failure on an otherwise CLEAN verdict — about what happened AFTER it.

        The second used to reach nobody: notes were rendered only by ``replay()``, and ``replay()``
        returns early for CLEAN. So a failed witness release on a clean teardown was written into a
        field with no consumer — this module's own defect class, inside its own failure machinery. The
        verdict is NOT reclassified: the measurement was clean and stays clean in the tombstone, so a
        repeat replays clean and silent. This fires once, on the call that actually did the cleanup.
        """
        live = verdict.live()
        if live is not None:
            raise live
        if verdict.cleanup_failed():
            raise TeardownCleanupError(
                f"{verdict.detail} — the verdict is CLEAN and stands, but POST-VERDICT CLEANUP FAILED: "
                f"{'; '.join(verdict.notes)}")

    def _release_witness(self, verdict: TeardownVerdict) -> None:
        """Drop the session witness on a clean verdict — and NEVER let that failing lose the verdict.

        The asymmetry this closes was in my own code: ``_dispose_snapshot`` right below was guarded and
        this call was BARE, three lines apart. A raise here (an unresolvable runtime, a client error)
        after the tombstone is stored leaves a verdict that says CLEAN, a witness still alive, and
        nothing recording that the release failed. That surviving canary is not merely a leaked
        resource: it is the precondition for the namesake-collision state on the next session that
        draws the same rid — now certified clean.
        """
        try:
            self._drop_witness()
        except Exception as exc:  # noqa: BLE001 — a cleanup failure must never lose the verdict
            verdict.notes.append(f"witness release FAILED: {type(exc).__name__} — canary may survive")

    def _dispose_snapshot(self, snapshot: Path, verdict: TeardownVerdict) -> None:
        """Delete the session snapshot — but ONLY on a verdict that was actually reached.

        RULED, and the ruling is the reason this is a method rather than a bare call. On a PROVEN leak
        (``EXISTS`` survivors) deleting the snapshot is intended HYGIENE: the snapshot is ephemeral
        scratch and the leak claim is about runtime resources, not about the staged tree. On any
        non-clean, unverifiable or crashed path it is EVIDENCE DESTRUCTION — that is precisely the state
        in which someone must re-probe, and destroying the tree removes what they would re-probe with.

        And the removal cannot be allowed to REPLACE the finding. This runs inside ``finally``, so a
        raise here supplants the in-flight verdict with a filesystem error: the leak alarm disappears and
        an ``OSError`` arrives in its place. The failure is therefore attached to the verdict as a note
        and the verdict wins. ``BaseException`` is deliberately NOT caught — ``KeyboardInterrupt`` must
        still propagate as itself.
        """
        if verdict.kind not in (VerdictKind.CLEAN, VerdictKind.LEAK):
            verdict.notes.append(
                f"snapshot {snapshot} RETAINED for re-probe (verdict: {verdict.kind.value})")
            return
        try:
            _rmtree_resilient(snapshot)
        except Exception as exc:  # noqa: BLE001 — a cleanup failure must never mask the verdict
            verdict.notes.append(f"snapshot cleanup failed: {type(exc).__name__}")

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


class ResourceKind(Enum):
    """The kind of runtime resource a probe asks about. A probe is ALWAYS about one kind, and the kind
    selects both the listing argv and the witness — so it may not be inferred from the name."""

    CONTAINER = "container"
    NETWORK = "network"


class ProbeCause(Enum):
    """WHY a probe returned ``UNKNOWN``. A CLOSED SET, and closed is the point.

    There are exactly three ways to arrive at UNKNOWN and they demand different responses: the listing
    never ran (check the client), it ran and failed (check the runtime), or it ran and answered without
    the witness in it (something destroyed the canary — the only one that points at another actor).
    Collapsing them into one silent value is the confusion this module exists to end, applied to its own
    output; and reporting them as FREE TEXT would drift, because a string nobody can enumerate cannot be
    exhaustively tested. An enum can: a test asserts all three are reachable and distinct.
    """

    LISTING_DID_NOT_RUN = "listing-did-not-run"
    LISTING_EXITED_NONZERO = "listing-exited-nonzero"
    WITNESS_NOT_IN_LISTING = "witness-not-in-listing"


class ProbeReading(NamedTuple):
    """A probe's answer AND why, together — so a mute reading is unrepresentable.

    ⚠ THIS REPLACED AN OPTIONAL OUT-PARAMETER, and the reason is worth keeping. The first version
    threaded an optional ``reasons`` list that callers could pass or omit, which made diagnosability a
    PER-CALL-SITE CHOICE: the same UNKNOWN was diagnosable at one site and mute at another, and the
    guarantee that every site passed it lived in prose rather than in the type. Rule 2 — a site that
    threads it says nothing about the site that does not. Returning the cause makes omission impossible.

    ``cause`` is ``None`` if and only if ``state`` is EXISTS or ABSENT: an answer about the subject needs
    no excuse. ``detail`` carries a bounded fact (a return code, an exception type name) and NEVER the
    listing content — the listing is unfiltered and holds names this process does not own.
    """

    state: Existence
    cause: ProbeCause | None = None
    detail: str = ""

    def describe(self) -> str:
        """One human-readable line naming the cause, for a verdict message. Empty when there is none."""
        if self.cause is None:
            return ""
        return f"{self.cause.value}{f' ({self.detail})' if self.detail else ''}"


# The UNFILTERED listing argv per kind. There is exactly ONE construction site per kind and callers cannot
# reach it — see ``probe_existence``'s docstring for why the seam had to move.
#
# NB the ``--format`` field differs BY KIND: containers report ``{{.Names}}``, networks ``{{.Name}}``. A
# future "harmonising" edit that unified them would silently empty one kind's listing — which under the
# old code read as ABSENT. The per-kind witness is what catches that, and it is why the witness is not
# optional.
_LISTING: dict[ResourceKind, tuple[str, ...]] = {
    ResourceKind.CONTAINER: ("ps", "-a", "--format", "{{.Names}}"),
    ResourceKind.NETWORK: ("network", "ls", "--format", "{{.Name}}"),
}

# ⚠ THE AMBIENT NETWORK PER RUNTIME — MEASURED, NOT ASSUMED, AND THIS IS THE LINE THAT MATTERS.
#
# An earlier draft carried a single constant with a comment asserting it was "present on every supported
# runtime". That was a claim in a comment with no evidence behind it, in a control — the exact defect
# this increment exists to close, one layer along. Each entry below was MEASURED on the reference host on
# 2026-07-31 by listing networks under that runtime:
#
#     podman 4.9.3 (rootless)  -> "podman"
#     docker 29.6.2 (daemon reachable, rc 0) -> "bridge"
#
# ``nerdctl`` is DELIBERATELY ABSENT: it is not installed here, so its ambient network name could only be
# guessed. A guessed entry in a witness map is the same defect as the constant it replaced. An
# unsupported runtime therefore fails CLOSED at the lookup below — and it fails at the LOOKUP, before any
# subprocess runs, so the error says "this runtime is not in the supported set" rather than "witness not
# found". Those are different failures and must not share a message: the second is indistinguishable from
# a broken channel, which is precisely the confusion this increment eliminates. ABSENCE OF SUPPORT AND
# ABSENCE OF EVIDENCE MUST NOT LOOK ALIKE. Widen this map by MEASURING, never by inferring.
#
# ⚠ QUIET-DOWNGRADE HAZARD, stated HERE because this is the line someone edits when a runtime reports a
# false failure. The witness works because the ambient network is AMBIENT and NOT REMOVABLE. Do not
# "fix" a failing runtime by CREATING a network with this name — that converts a non-removable ambient
# witness into an ordinary user object that can be deleted, silently downgrading the guarantee to nothing
# while every test stays green. Measure the real name and add it here instead.
_AMBIENT_NETWORK: dict[str, str] = {
    "podman": "podman",
    "docker": "bridge",
}


class WitnessProvisioningError(Exception):
    """The container-kind witness could not be created, or was created and could not be SEEN.

    A distinct type because a failure HERE is a failure of the instrument, before any measurement is
    attempted — it must never be reported as, or be indistinguishable from, a fact about the subject.
    The earlier version of this function swallowed creation failures and returned the name anyway, so a
    session could carry a witness IN NAME ONLY: non-empty, so no emptiness guard caught it, and absent
    from every listing, so every probe returned UNKNOWN and every resource was reported a survivor. That
    manufactured a leak alarm no measurement supported."""


class WitnessCreateFailed(WitnessProvisioningError):
    """``create`` did not succeed — it raised, or exited non-zero with no namesake in the listing.

    ⚠ THE GUARD THAT RAISES THIS IS LOAD-BEARING, AND I CONCLUDED OTHERWISE. My reasoning was that
    "create failed yet the canary is visible" could not be constructed, which would make the return-code
    check mere defence-in-depth behind bootstrap-verify. It is constructible, and THE DESIGN CONSTRUCTS
    IT — see ``WitnessNameCollision``. The two guards are a PAIR and prove different things:

        return code  ->  EXCLUSIVITY: THIS session created the container now bearing this name
        bootstrap    ->  LIVENESS:    the listing channel can actually see it

    Neither implies the other. Dropping the first admits an adopted namesake; dropping the second admits
    a witness that exists but cannot be read. They are separate TYPES rather than one message so a test
    can assert WHICH guard refused — asserting on prose would pin the wording, not the control."""


class WitnessNameCollision(WitnessCreateFailed):
    """``create`` exited non-zero AND a container by that name IS listed — a stale namesake exists.

    THE STATE THE DISCHARGE NEVER CONSTRUCTED. Canary names are deterministic (``canary-{rid}``), leaked
    canaries are ANTICIPATED (the reaper is unwired, so namesakes persist across sessions), and a
    repeated rid therefore makes ``create`` fail on a name conflict WHILE the stale canary is listed.
    Accept that and the guarantor adopts a witness it did not create, whose lifetime belongs to a dead
    session and which some other actor may destroy mid-probe. The same shape arrives via a client-side
    create timeout that completes daemon-side and is then retried, and via a multi-phase runtime wrapper.

    Refusal is decided by the RETURN CODE alone; the listing is read only to name the failure correctly.
    Reading it does not and cannot authorise adoption — an unrecognised namesake is refused either way."""


class WitnessNotVisible(WitnessProvisioningError):
    """The witness was created and the listing channel cannot see it — bootstrap-verify's refusal.

    Creating it is not the same as being able to READ it. This is the calibration PROOF the first version
    of the increment never had: it added the calibration CHECK at probe time and left the instrument
    unverified until teardown, which is the worst possible moment to discover it was never on."""


class WitnessNotProvisioned(Exception):
    """A probe was asked for a verdict with no witness. A PRECONDITION failure, not an outcome.

    Absence of CALIBRATION must not look like absence of EVIDENCE — the same distinction the board drew
    for an unmeasured runtime, applied one level in. An uncalibrated instrument is not a quiet channel;
    asking it a question is a category error, and the tri-state is an evidence-level type that cannot
    express one. So this RAISES rather than returning UNKNOWN, and it raises BEFORE any subprocess."""


class UnsupportedRuntimeWitness(OCIRuntimeUnavailable):
    """No MEASURED ambient-network witness exists for this runtime, so a network probe cannot be trusted.

    A subclass of ``OCIRuntimeUnavailable`` so existing fail-closed handlers already cover it.
    """


def ambient_network_witness(runtime_name: str) -> str:
    """The measured ambient network for ``runtime_name``, or refuse.

    Raises BEFORE any subprocess call, so an unsupported runtime never reaches a listing and can never be
    mistaken for a quiet channel."""
    try:
        return _AMBIENT_NETWORK[runtime_name]
    except KeyError:
        raise UnsupportedRuntimeWitness(
            f"runtime {runtime_name!r} has no MEASURED ambient-network witness "
            f"(measured: {sorted(_AMBIENT_NETWORK)}); a network probe cannot be trusted without one, so "
            "this is a refusal to probe — NOT a failed probe. Measure the runtime's ambient network and "
            "add it to _AMBIENT_NETWORK; do not create a network to satisfy the existing entries."
        ) from None


def listing_argv(runtime: str, kind: ResourceKind) -> list[str]:
    """The UNFILTERED listing for ``kind``. Unfiltered deliberately — see ``probe_existence``."""
    return [runtime, *_LISTING[kind]]


def canary_container_argv(runtime: str, name: str, image_id: str) -> list[str]:
    """CREATE (never start) the container-kind witness.

    CREATED-NOT-RUNNING is load-bearing, not incidental. Every container listing this module makes uses
    ``ps -a``, and a created-but-never-started container is listed ONLY under ``-a`` — measured on the
    reference host (``ps`` → 0 matches, ``ps -a`` → 1). So this witness BINDS THE ``-a`` FLAG: drop it and
    the witness vanishes, which is UNKNOWN rather than a silently truncated listing. A RUNNING witness
    (reusing the proxy, say) would still be listed without ``-a`` and would certify strictly less.

    A CONSTRUCT site under the posture census: it creates a container the validity of every subsequent
    destruction verdict depends on, so its argv is built here rather than by a caller.
    """
    return [runtime, "create", "--name", name, image_id, "true"]


def probe_existence(
    runtime: str,
    kind: ResourceKind,
    name: str,
    *,
    witness: str | None,
    timeout: float = 30.0,
) -> ProbeReading:
    """Is ``name`` present, on a channel PROVEN LIVE IN THIS RUN? The shared fail-CLOSED existence check.

    ABSENT requires a POSITIVE OBSERVATION, not silence. The old contract said EXISTS/ABSENT are returned
    "only on a query that actually RAN (return code 0)" — but "it ran" is the instrument's report about
    its own operation, not an answer about the subject. A syntactically valid, semantically WRONG query
    runs fine, returns rc 0 and empty stdout, and used to yield ABSENT: a surviving container reported as
    destroyed, by the function whose own docstring calls itself the destruction authority.

    THE SEAM HAD TO MOVE. This used to take a fully-built ``argv``, which made a positive control
    impossible: a function handed a finished list cannot construct the control query that would prove
    that list's shape works. It now takes ``(kind, name)`` and owns construction. A caller-supplied
    control was considered and REJECTED — an independently built control SHARES NO FAILURE MODES with the
    real query, so its success certifies nothing. The control's entire value is CORRELATED FAILURE: a
    broken real query must break the control too.

    ONE SAMPLE, TWO READINGS. The listing is UNFILTERED, so the witness and the subject are read from the
    SAME output of the SAME call. There is no adjacency window in which the channel could change between
    a control and a query, it is one subprocess call rather than two, and the filter disappears as a
    failure mode entirely — along with the unescaped regex metacharacters the old ``name=^{n}$`` form
    interpolated. What the witness still covers is every OTHER way the channel can go quiet: a wrong
    binary, a mangled storage root in the client env, a dropped ``-a``, a harmonised ``--format``, output
    truncation. Those survive the filter's deletion, which is why deleting the filter does not remove the
    need for a control.

    WITNESS ABSENT ⇒ UNKNOWN, NEVER ABSENT. If the channel cannot show us a thing we know exists, its
    silence about ``name`` carries no information.

    ⚠ DO NOT LOG OR EMBED THE LISTING. Unfiltered means it contains the names of containers this process
    does not own. It must not reach a log record, an exception message, or a signed receipt — a precedent
    in this tree baked ``str(exc)`` into a published observation, and that was found by review rather
    than by anything failing. Sealed by test.

    AN UNKNOWN THAT CANNOT SAY WHY IS THE DEFECT ONE LEVEL UP, so the return is a ``ProbeReading``:
    the state AND, when it is UNKNOWN, which of the three arrivals produced it. Found by a red test I
    could not diagnose from its own message. The cause is a CLOSED ENUM, and it is RETURNED rather than
    accumulated into a caller-supplied list, so a call site cannot opt out of diagnosability — see
    ``ProbeReading``.
    """
    def _unknown(cause: ProbeCause, detail: str = "") -> ProbeReading:
        return ProbeReading(Existence.UNKNOWN, cause, detail)

    # POSITIVE SHAPE, not a truthiness test. ``not witness`` accepts anything falsy-adjacent that is not
    # a usable witness name and — worse — accepts any non-empty NON-STRING (a Mock, a list, a sentinel
    # object) as calibrated, after which ``witness not in listed`` compares that object against a list of
    # strings and reports UNKNOWN forever. What is required is a NON-EMPTY STRING; that is what is
    # checked. The evasion set for "not falsy" is unbounded; the admitted set for "is a non-empty str"
    # is exactly the valid one.
    if not isinstance(witness, str) or not witness:
        raise WitnessNotProvisioned(
            f"a {kind.value} probe for {name!r} was asked for a verdict with NO WITNESS. This is a "
            "refusal to measure, NOT a measurement — an uncalibrated instrument cannot distinguish "
            "'absent' from 'I cannot see', and returning UNKNOWN here would let a lifecycle bug "
            "masquerade as a quiet channel"
        )
    try:
        r = subprocess.run(listing_argv(runtime, kind), capture_output=True, text=True,
                           timeout=timeout, env=runtime_client_env())
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        # UnicodeDecodeError is NOT a SubprocessError. ``text=True`` decodes the child's output, so
        # undecodable bytes raise it straight out of this function — which has a TRI-STATE contract and
        # must not throw. Measured reachable, and MORE reachable under unfiltered listing, because the
        # output now contains names this process did not choose.
        return _unknown(ProbeCause.LISTING_DID_NOT_RUN, type(exc).__name__)
    if r.returncode != 0:
        return _unknown(ProbeCause.LISTING_EXITED_NONZERO, f"rc={r.returncode}")
    listed = r.stdout.split()
    if witness not in listed:
        # The channel is not proven live — its silence proves nothing. Distinct from the two above: the
        # listing RAN and ANSWERED, and what it answered did not include a resource we know exists. This
        # is the only one of the three that points at ANOTHER ACTOR rather than at our own client.
        return _unknown(ProbeCause.WITNESS_NOT_IN_LISTING, f"witness={witness!r}")
    return ProbeReading(Existence.EXISTS if name in listed else Existence.ABSENT)


def ensure_container_witness(runtime: str, image_id: str, rid: str) -> str:
    """Create the container-kind witness for this session and return its name.

    Named ``{RESOURCE_PREFIX}canary-{rid}`` — kind-segmented like every other resource here, and it stays
    UNDER the shared prefix ON PURPOSE so a leaked canary is reapable. Excluding it from the reaper would
    make it a leak by design, which is the thing this control exists to prevent.

    ⚠ PRECONDITION HANDED FORWARD, decided rather than discovered: the reaper selects by PREFIX, not by
    instance, so a *wired* reaper could destroy another instance's LIVE canary mid-probe. That is the
    pre-existing prefix-not-instance hazard with a new participant, and it is not live today because the
    reaper is a test/ops utility that nothing invokes at startup. The wiring increment MUST handle
    live-canary exclusion (by instance or by age); the ``canary-`` segment exists so it has something to
    key on. The window is short — created and destroyed inside one session — which bounds it, not closes it.

    ⚠ ``rid`` PROVENANCE. It is the caller's per-session random id, and it is RANDOM ON PURPOSE — never
    derived from the artifact or its hash. An artifact-derived rid would make two runs of the same
    artifact collide BY CONSTRUCTION, converting the namesake hazard below from a rare accident into the
    normal case. Callers pass the SAME rid they name the session's other resources with, so a leaked
    canary is correlatable by name to the session that leaked it: reaping is not diagnosis.

    TWO GUARDS, PROVING DIFFERENT THINGS — exclusivity (return code) and liveness (bootstrap-verify).
    See ``WitnessCreateFailed``; I previously reasoned the first was redundant and it is not.
    """
    name = f"{RESOURCE_PREFIX}canary-{rid}"
    try:
        r = subprocess.run(canary_container_argv(runtime, name, image_id),
                           capture_output=True, text=True, timeout=30, env=runtime_client_env())
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        raise WitnessCreateFailed(
            f"could not create the container witness {name!r}: {type(exc).__name__}"
        ) from exc
    if r.returncode != 0:
        # REFUSAL IS ALREADY DECIDED — by the return code, above and alone. The listing below is read
        # ONLY to say WHICH failure this is, and it cannot authorise adoption: both branches raise. A
        # namesake found here belongs to another session's lifetime, so "it is visible" is the more
        # dangerous outcome, not the recovering one.
        namesake = probe_existence(runtime, ResourceKind.CONTAINER, name, witness=name).state
        if namesake is Existence.EXISTS:
            raise WitnessNameCollision(
                f"creating the container witness {name!r} exited {r.returncode} AND a container of that "
                "name IS listed — a STALE NAMESAKE from another session. Refusing to adopt a witness "
                "this session did not create: its lifetime is not ours, and an actor outside this "
                "session may destroy it mid-probe, turning every verdict derived from it into UNKNOWN "
                "at a moment we do not control"
            )
        raise WitnessCreateFailed(
            f"creating the container witness {name!r} exited {r.returncode} and NO NAMESAKE WAS "
            f"OBSERVED (probe={namesake.value}) — refusing to proceed with a witness that exists in "
            "NAME ONLY. Note the probe above is itself UNCALIBRATED by construction: no canary exists "
            "at this moment, so it can prove a namesake PRESENT but never prove one ABSENT. This "
            "subtype therefore means 'no collision seen', not 'no collision'"
        )
    # BOOTSTRAP-VERIFY: creating it is not the same as being able to SEE it. Prove the instrument on the
    # very channel it will be used to read, BEFORE anything trusts a verdict derived from it. This is the
    # calibration PROOF the first version of this increment never had: it added the calibration CHECK at
    # probe time and left the instrument itself unverified until teardown — the worst possible moment to
    # discover it was never on.
    if probe_existence(runtime, ResourceKind.CONTAINER, name, witness=name).state is not Existence.EXISTS:
        raise WitnessNotVisible(
            f"the container witness {name!r} was created but does not appear in the listing — the probe "
            "channel cannot see a resource that demonstrably exists, so no verdict derived from it "
            "could be trusted"
        )
    return name


def probe_container(runtime: str, name: str, *, witness: str | None) -> ProbeReading:
    """Container-kind probe. A WRAPPER, and the kind being in the FUNCTION NAME is the point.

    Passing ``(kind, name)`` created a new way to lie that the old seam did not have: probe a CONTAINER
    name under ``ResourceKind.NETWORK`` and the network witness passes, the network listing has no such
    name, and the verdict is ABSENT — while the container lives. Fail-open, one token long. Naming the
    kind removes the token that could be wrong.
    """
    return probe_existence(runtime, ResourceKind.CONTAINER, name, witness=witness)


def probe_network(runtime: str, name: str, *, runtime_name: str) -> ProbeReading:
    """Network-kind probe. Its witness is the runtime's MEASURED ambient network — always present, not
    removable, and costing no resource to create. ``runtime_name`` is the audited NAME (podman/docker),
    not the resolved path, because the witness is a property of the runtime rather than of the binary."""
    return probe_existence(runtime, ResourceKind.NETWORK, name,
                           witness=ambient_network_witness(runtime_name))


def resolve_image_id(runtime: str, image: str) -> str:
    """Resolve ``image`` (a possibly-mutable tag) to its IMMUTABLE local content id
    (``<rt> inspect --format {{.Id}}`` -> ``sha256:...``) so the caller can execute the DIGEST,
    not the tag (3.5-close #1.1 — closes the tag-remap TOCTOU). The FULL digest is returned (never
    a short prefix — a short prefix reopens id ambiguity). Raises ``ImageResolutionError`` if the
    image is absent or the runtime can't report an id, and ``RuntimePathUnresolved`` (an
    ``OCIRuntimeUnavailable``) if ``runtime`` yields no absolute binary — an unresolvable runtime is a
    fail-closed refusal to exec, not an image-resolution outcome, so it is NOT folded into the latter.

    ⚠ LOCAL-ONLY, AND THAT IS A CONTRACT RATHER THAN AN ACCIDENT. This runs ``image inspect`` and nothing
    else: an image that is absent locally raises, it is NEVER pulled. Verified at source, and locked here
    because the orphan reaper now resolves an image through this path — an ops tool that silently
    acquired a registry dependency AT INCIDENT TIME would be a posture change, not a convenience.
    ADDING PULL BEHAVIOUR HERE IS A POSTURE CHANGE REQUIRING ITS OWN DISSENT, not a quiet helper
    improvement. A verified property becomes a constraint, or it decays into a description of one moment."""
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
        runtime, "run", "--rm", "--init", *NO_HEALTHCHECK_FLAGS, "--name", container,
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
        # ONE session rid, shared by the witness and the sandbox container. RANDOM, never artifact-derived
        # (an artifact-derived rid would make repeat runs of the same artifact collide BY CONSTRUCTION —
        # see ``ensure_container_witness`` on rid provenance), and SHARED so that a leaked canary is
        # correlatable by name to the session that leaked it. Two independent uuid4s reaped identically
        # and diagnosed not at all.
        rid = uuid.uuid4().hex[:16]
        # The container-kind witness: created-never-started, so it binds ``ps -a``. Destroyed in teardown.
        self._witness = ensure_container_witness(self._exec_runtime(), image_id, rid)
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
            container=f"{RESOURCE_PREFIX}{rid}",
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
            # A FOREIGN HANDLE IS A PROGRAMMING ERROR, NOT A NO-OP. The silent ``return`` handed out
            # unearned success: the caller believes its resources were torn down and verified, and the
            # one function authorised to make that claim never looked at anything.
            raise TypeError(
                f"{type(self).__name__}.teardown was given a {type(handle).__name__}, which it cannot "
                "tear down. Returning silently would report success for work never attempted"
            )
        prior = self._replay_verdict(handle.id, handle.container)
        if prior is not None:
            # REPLAY, not a fresh assertion — see ObservedOCISandbox.teardown for why a stored verdict is
            # returned as a past measurement rather than re-probed. Reconstructed from data, stamped.
            replayed = prior.replay()
            if replayed is not None:
                raise replayed
            return
        verdict: TeardownVerdict | None = None
        try:
            self._force_remove(handle.container)
            # PROVE destruction: teardown succeeds ONLY on a probed ABSENT. But EXISTS and UNKNOWN are NOT
            # the same event and no longer share an exception. EXISTS is an answer about the SUBJECT (the
            # container was observed to persist); UNKNOWN is a report about the INSTRUMENT (nothing could
            # be observed). Both block; only one is a leak.
            if not isinstance(self._witness, str) or not self._witness:
                # Uncalibrated. The destroy above still ran; nothing is claimed about what remains. The
                # predicate is the probe's own — see ``probe_existence`` on positive shape.
                verdict = TeardownVerdict(
                    VerdictKind.UNVERIFIED,
                    f"container {handle.container} could not be VERIFIED destroyed: no witness was "
                    "provisioned, so the probe was never calibrated. Destruction was attempted",
                    time.time(),
                    handle.container,
                )
            else:
                # Only the SECOND reading is kept: the first UNKNOWN is expected on the escalation path
                # (that is why there is an escalation), so reporting it would make every escalated
                # teardown carry a stale cause for a state it then recovered from.
                reading = self._container_state(handle.container)
                if reading.state is not Existence.ABSENT:
                    self._force_remove(handle.container)  # reaper escalation
                    reading = self._container_state(handle.container)
                verdict = self._verdict_for(handle.container, reading)
        finally:
            # THE VERDICT IS BUILT AND FINALISED BEFORE IT IS RAISED. The raise used to sit inside the
            # ``try``, so cleanup notes were appended AFTER the exception was constructed and could never
            # appear in it. Finalisation happens here — where it still runs if the sweep crashed — and
            # the raise happens below, once the notes are complete.
            verdict = self._finalise(verdict, handle.id, handle.container, handle.snapshot)
        # Reached ONLY when the sweep did not raise. A crash propagates from the ``finally`` above with
        # its own exception intact and never arrives here.
        self._surface(verdict)

    def _verdict_for(self, container: str, reading: ProbeReading) -> TeardownVerdict:
        """The verdict for a probe that ANSWERED — one composition site for the live and replayed text.

        Composing the two separately is how the replayed message came to say less than the live one.
        """
        state = reading.state
        if state is Existence.EXISTS:
            return TeardownVerdict(
                VerdictKind.LEAK,
                f"container {container} was OBSERVED TO PERSIST after teardown — ephemerality "
                "(a security property) is violated",
                time.time(),
                container,
            )
        if state is not Existence.ABSENT:
            why = f" — cause: {reading.describe()}" if reading.cause is not None else ""
            return TeardownVerdict(
                VerdictKind.UNVERIFIED,
                f"container {container} could not be VERIFIED destroyed (probe={state.value}) — "
                "destruction was attempted; this is a report about the instrument, NOT a claim that "
                f"the container survived{why}",
                time.time(),
                container,
            )
        return TeardownVerdict(VerdictKind.CLEAN, f"container {container} verified ABSENT",
                               time.time(), container)

    def _drop_witness(self) -> None:
        """Destroy this session's container witness. Best-effort: a surviving witness is itself
        prefix-named, so the reaper can clear it — leaving it would be a leak by design."""
        if self._witness is not None:
            self._force_remove(self._witness)
            self._witness = None

    # -- internals --------------------------------------------------------
    def _force_remove(self, name: str) -> None:
        # best-effort removal — the AUTHORITY that destruction happened is the tri-state probe below, not this
        # return code (a non-zero rm still forces a re-probe, which fails closed on EXISTS/UNKNOWN).
        try:
            subprocess.run([self._exec_runtime(), "rm", "-f", name], capture_output=True, timeout=30,
                           env=runtime_client_env())
        except (OSError, subprocess.SubprocessError):
            pass

    def _container_state(self, name: str) -> ProbeReading:
        return probe_container(self._exec_runtime(), name, witness=self._witness)

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
            egress_attempts=self.egress_when_unobserved,
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
