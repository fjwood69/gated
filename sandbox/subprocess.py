"""Increment 1.2 — SubprocessSandbox (WEAK isolation).

The WEAK-tier backend: runs the artifact in a **child process** (never in-process)
inside an ephemeral temp dir, with a wall-clock timeout. A crash or hang in the
child cannot take down the harness.

WEAK provides **process-level isolation only — ZERO network, filesystem, or resource
containment** (board Ruling B: the earlier best-effort ``os.unshare`` was thread-
unsafe via preexec_fn and off without privilege anyway — dangerous where it worked,
a no-op where it didn't, so it was removed). WEAK is for executing local, cooperative
demos; a real Promotion Gate requires HERMETIC (1.3, OCI ``--network=none`` + host-
side flow counting). The engine rejects a WEAK pass as merge-insufficient; the
backend just reports its isolation level honestly on every result.

SHA-bind (board Ruling A): ``prepare()`` verifies the staged tree — it computes the
canonical ``core.tree_hash`` and asserts it equals ``ArtifactSpec.tree_hash``,
raising ``ArtifactHashMismatchError`` and returning no handle on mismatch. So if a
handle exists, the bytes that run are the bytes the caller claimed (no echo-only
forgery).

Relationship to the demo: promotion-boundary-demo runs its check in-process (its
zero-dependency point); this is the same thesis moved to a child process behind
``core.Sandbox`` — but the demo's runner is check-specific, so this general
executor is new code, not a copy.

Note: this file is ``sandbox/subprocess.py``; ``import subprocess`` below resolves to
the stdlib module (absolute imports), not this file.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
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
    tree_hash,
)
from sandbox.base import BaseSandbox

_Outcome = Literal["completed", "timeout", "error"]


@dataclass(frozen=True)
class SubprocessHandle:
    """A WEAK-backend handle. ``workdir`` is the ephemeral temp dir the (verified)
    artifact was staged into (backend-private; teardown removes it). ``id`` +
    ``artifact_hash`` satisfy the SandboxHandle contract."""

    id: str
    artifact_hash: str
    workdir: Path


def _rmtree_resilient(path: Path) -> None:
    """Remove a tree, retrying briefly. On Windows a just-killed process's file
    handle can linger a moment and block deletion (PermissionError); on POSIX the
    first attempt succeeds. Falls back to best-effort after the retries so teardown
    never raises (RAII relies on that)."""
    for attempt in range(10):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return  # already gone -> idempotent
        except OSError:
            if attempt == 9:
                shutil.rmtree(path, ignore_errors=True)
                return
            time.sleep(0.1)


class SubprocessSandbox(BaseSandbox):
    """WEAK isolation: run the artifact in a child process inside a temp dir."""

    isolation_level: IsolationLevel = IsolationLevel.WEAK

    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        workdir = Path(tempfile.mkdtemp(prefix="moriverify-weak-"))
        try:
            if artifact.path.is_dir():
                shutil.copytree(artifact.path, workdir, dirs_exist_ok=True)
            else:
                shutil.copy2(artifact.path, workdir / artifact.path.name)
            # SHA-bind: VERIFY the staged bytes against the claim. Refuse a handle
            # on mismatch — execution must never start on unverified bytes.
            staged = tree_hash(workdir)
            if staged != artifact.tree_hash:
                raise ArtifactHashMismatchError(
                    f"staged tree {staged} != claimed {artifact.tree_hash}"
                )
        except BaseException:
            shutil.rmtree(workdir, ignore_errors=True)  # no leak on a rejected prepare
            raise
        # Fixtures is empty in the current contract; the fault model places fixture
        # files into `workdir` here when it lands (at the boundary — NFR4).
        return SubprocessHandle(
            id=uuid.uuid4().hex,
            artifact_hash=artifact.tree_hash,
            workdir=workdir,
        )

    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        sub = self._require_own(handle)
        posix = os.name == "posix"
        try:
            proc = subprocess.Popen(
                list(entrypoint.argv),
                cwd=str(sub.workdir),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=posix,  # own process group -> killable as a tree
            )
        except OSError:
            # The sandbox could not even start the process (e.g. entrypoint missing).
            return self._result("error", exit_code=None, raw=None, handle=sub)

        try:
            proc.communicate(timeout=budget.wall_clock_seconds)
        except subprocess.TimeoutExpired:
            self._terminate(proc)
            try:
                proc.communicate(timeout=5.0)  # reap after kill
            except subprocess.TimeoutExpired:
                pass
            return self._result("timeout", exit_code=None, raw=None, handle=sub)

        rc = proc.returncode
        if posix and rc is not None and rc < 0:
            # Killed by a signal it did not request -> a crash (POSIX: rc = -signum).
            return self._result("error", exit_code=None, raw=rc, handle=sub)
        return self._result("completed", exit_code=rc, raw=rc, handle=sub)

    def teardown(self, handle: SandboxHandle) -> None:
        # Lenient + idempotent (RAII exception path relies on both): a foreign or
        # already-removed handle is a no-op, never a raise.
        if isinstance(handle, SubprocessHandle):
            _rmtree_resilient(handle.workdir)

    # -- internals ------------------------------------------------------------
    def _result(
        self,
        outcome: _Outcome,
        *,
        exit_code: int | None,
        raw: int | None,
        handle: SubprocessHandle,
    ) -> ExecutionResult:
        # Facts only, provenance echoed from self + the handle. No verdict (NFR4).
        return ExecutionResult(
            outcome=outcome,
            exit_code=exit_code,
            isolation_level=self.isolation_level,
            artifact_hash=handle.artifact_hash,
            egress_attempts=self.egress_when_unobserved,
            raw_return_code=raw,
        )

    @staticmethod
    def _require_own(handle: SandboxHandle) -> SubprocessHandle:
        # Opaque-handle discipline: this backend only accepts its own handle type.
        if not isinstance(handle, SubprocessHandle):
            raise TypeError(
                f"SubprocessSandbox received a foreign handle: {type(handle).__name__}"
            )
        return handle

    @staticmethod
    def _terminate(proc: subprocess.Popen[bytes]) -> None:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)  # kill the process tree
            else:
                # Windows has no killpg; taskkill /T kills the whole tree
                # (grandchildren included) — closes the orphan gap proc.kill() leaves.
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    capture_output=True,
                )
        except (ProcessLookupError, OSError):
            pass


# Type-check proof: SubprocessSandbox IS a core.Sandbox (mypy --strict verifies;
# session() is inherited from BaseSandbox).
_conforms: Sandbox = SubprocessSandbox()
