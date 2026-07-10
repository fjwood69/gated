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
    ExecutionResult,
    Fixtures,
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


class OCIRuntimeUnavailable(Exception):
    """No OCI runtime can actually run a hermetic (rootless, --network=none)
    container for the requested image. HERMETIC is unavailable — the engine must
    fail closed (no silent WEAK fallback outside explicit dev mode)."""


@dataclass(frozen=True)
class OCIHandle:
    id: str
    artifact_hash: str
    snapshot: Path   # host-side immutable snapshot (mounted read-only)
    container: str   # unique container name (teardown / reaper target)


def _selinux_enforcing() -> bool:
    return os.path.exists("/sys/fs/selinux/enforce")


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


class OCISandbox(BaseSandbox):
    """HERMETIC isolation via an ephemeral OCI container."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC

    def __init__(self, image: str, runtime: str | None = None) -> None:
        self.image = image
        self._runtime = runtime if runtime is not None else self._detect_runtime(image)

    @property
    def runtime(self) -> str:
        return self._runtime

    # -- Catch 1: detect by CAPABILITY, not presence ----------------------
    @staticmethod
    def _detect_runtime(image: str) -> str:
        for rt in _RUNTIMES:
            if shutil.which(rt) is None:
                continue
            try:
                probe = subprocess.run(
                    [rt, "run", "--rm", "--network=none", image, "true"],
                    capture_output=True,
                    timeout=90,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if probe.returncode == 0:  # it can actually run hermetically
                return rt
        raise OCIRuntimeUnavailable(
            f"no OCI runtime can run '{image}' hermetically "
            "(rootless, --network=none); HERMETIC unavailable — fail closed"
        )

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
        return ["--network=none"]

    # -- prepare: snapshot -> hash -> verify (TOCTOU-closed) --------------
    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        snapshot = Path(tempfile.mkdtemp(prefix="moriverify-oci-"))
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
            container=f"moriverify-{uuid.uuid4().hex[:16]}",
        )

    # -- run: hermetic container, our wall-clock timeout ------------------
    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        h = self._require_own(handle)
        mount = (
            f"type=bind,source={h.snapshot},target={ARTIFACT_MOUNT},"
            "readonly,bind-propagation=rprivate"
        )
        if _selinux_enforcing():
            mount += ",relabel=private"  # :Z-equivalent, doesn't break readonly
        cmd = [
            # --init: a real init as PID 1 so the artifact runs as its child — a
            # namespace's PID 1 can't be signal-killed from within (crashes would
            # otherwise be mis-reported as clean exits), and zombies get reaped.
            self._runtime, "run", "--rm", "--init", "--name", h.container,
            *self._network_args(),
            "--mount", mount,          # verified artifact, read-only, private
            "--tmpfs", WORK_DIR,       # writable scratch (audit-only)
            "--workdir", WORK_DIR,
            self.image, *entrypoint.argv,
        ]
        # Sterile env: Popen(env=...) with a minimal dict — the container never
        # inherits the host runner's environment. podman itself needs a PATH.
        sterile = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
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
            if self._container_exists(handle.container):
                self._force_remove(handle.container)  # reaper escalation
                if self._container_exists(handle.container):
                    raise SandboxLeakError(
                        f"container {handle.container} survived teardown — "
                        "ephemerality (a security property) is violated"
                    )
        finally:
            _rmtree_resilient(handle.snapshot)

    # -- internals --------------------------------------------------------
    def _force_remove(self, name: str) -> None:
        try:
            subprocess.run(
                [self._runtime, "rm", "-f", name],
                capture_output=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            pass

    def _container_exists(self, name: str) -> bool:
        try:
            out = subprocess.run(
                [self._runtime, "ps", "-a", "--filter", f"name=^{name}$",
                 "--format", "{{.Names}}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return False  # can't tell -> don't false-alarm a leak
        return name in out.stdout.split()

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
