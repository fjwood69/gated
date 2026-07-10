"""Increment 1.2 done-when + board-check tests for SubprocessSandbox.

Run from the gated/ root:  python3 -m unittest discover -s tests

Verified on Linux here; the code is cross-platform (stdlib subprocess), but the
timeout/teardown guarantees on macOS/Windows are UNTESTED in this environment and
need a run on those OSes (board Ruling E — Windows tree-kill needs a Job Object,
and rmtree can fail on locked files).
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    Command,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    Sandbox,
    tree_hash,
)
from sandbox.noop import NoOpSandbox
from sandbox.subprocess import SubprocessSandbox

BUDGET_FAST = ResourceBudget(wall_clock_seconds=1.0)
_RUN_MAIN = Command(argv=(sys.executable, "main.py"))


def _artifact(script: str) -> ArtifactSpec:
    """Build a one-file artifact tree and bind its REAL canonical hash (so prepare
    verifies successfully)."""
    d = Path(tempfile.mkdtemp(prefix="mvtest-art-"))
    (d / "main.py").write_text(script, encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


def _pid_alive(pid: int) -> bool:
    """Cross-platform liveness check for an arbitrary PID."""
    if os.name == "posix":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    out = subprocess.run(
        ["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True
    )
    return str(pid) in out.stdout


def _kill_pid(pid: int) -> None:
    """Best-effort kill (test cleanup, so an orphan can't survive a failure)."""
    try:
        if os.name == "posix":
            os.kill(pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
    except OSError:
        pass


class SubprocessSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = SubprocessSandbox()

    # -- done-when: trivial / non-zero / timeout / crash --------------------
    def test_trivial_completes_zero(self) -> None:
        with self.sb.session(_artifact("raise SystemExit(0)\n"), Fixtures()) as h:
            r = self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.exit_code, 0)

    def test_nonzero_exit_is_completed_not_error(self) -> None:
        with self.sb.session(_artifact("raise SystemExit(3)\n"), Fixtures()) as h:
            r = self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.exit_code, 3)
        self.assertEqual(r.raw_return_code, 3)

    def test_hang_times_out_at_budget_not_forever(self) -> None:
        t0 = time.monotonic()
        with self.sb.session(_artifact("import time\ntime.sleep(30)\n"), Fixtures()) as h:
            r = self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
        self.assertEqual(r.outcome, "timeout")
        self.assertLess(time.monotonic() - t0, 15.0, "timeout must fire, not hang")

    @unittest.skipUnless(os.name == "posix", "signal-crash detection is POSIX")
    def test_crash_is_error_parent_survives_raw_negative(self) -> None:
        parent = os.getpid()
        spec = _artifact("import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n")
        with self.sb.session(spec, Fixtures()) as h:
            r = self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
        self.assertEqual(r.outcome, "error")
        self.assertIsNotNone(r.raw_return_code)
        assert r.raw_return_code is not None
        self.assertLess(r.raw_return_code, 0, "POSIX signal death -> negative raw code")
        self.assertEqual(os.getpid(), parent, "parent must survive a child crash")

    # -- board Ruling A: SHA-bind VERIFIES (not echo) ----------------------
    def test_hash_mismatch_refuses_handle(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mvtest-art-"))
        (d / "main.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
        bad = ArtifactSpec(path=d, tree_hash="sha256:not-the-real-hash")
        with self.assertRaises(ArtifactHashMismatchError):
            self.sb.prepare(bad, Fixtures())

    def test_hash_match_binds_and_echoes(self) -> None:
        spec = _artifact("raise SystemExit(0)\n")
        h = self.sb.prepare(spec, Fixtures())  # verifies; raises if it didn't match
        try:
            r = self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
            self.assertEqual(h.artifact_hash, spec.tree_hash)  # type: ignore[attr-defined]
            self.assertEqual(r.artifact_hash, spec.tree_hash)
        finally:
            self.sb.teardown(h)

    # -- board checks: child process / isolation surfaced ------------------
    def test_runs_in_child_process(self) -> None:
        spec = _artifact("import os\nopen('pid.txt','w').write(str(os.getpid()))\n")
        h = self.sb.prepare(spec, Fixtures())
        try:
            self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
            child_pid = int((Path(h.workdir) / "pid.txt").read_text())  # type: ignore[attr-defined]
            self.assertNotEqual(child_pid, os.getpid(), "must run in a child process")
        finally:
            self.sb.teardown(h)

    def test_isolation_level_weak_and_surfaced(self) -> None:
        self.assertIs(self.sb.isolation_level, IsolationLevel.WEAK)
        with self.sb.session(_artifact("raise SystemExit(0)\n"), Fixtures()) as h:
            r = self.sb.run(h, _RUN_MAIN, BUDGET_FAST)
        self.assertIs(r.isolation_level, IsolationLevel.WEAK)

    # -- board check: teardown always runs + idempotent --------------------
    def test_teardown_removes_workdir_and_is_idempotent(self) -> None:
        h = self.sb.prepare(_artifact("raise SystemExit(0)\n"), Fixtures())
        workdir = Path(h.workdir)  # type: ignore[attr-defined]
        self.assertTrue(workdir.exists())
        self.sb.teardown(h)
        self.assertFalse(workdir.exists(), "teardown removes the ephemeral workdir")
        self.sb.teardown(h)  # idempotent: must not raise

    def test_session_tears_down_on_exception(self) -> None:
        captured: dict[str, Path] = {}
        with self.assertRaises(RuntimeError):
            with self.sb.session(_artifact("import time\ntime.sleep(30)\n"), Fixtures()) as h:
                captured["workdir"] = Path(h.workdir)  # type: ignore[attr-defined]
                raise RuntimeError("boom")
        self.assertFalse(captured["workdir"].exists(), "teardown runs on exception path")

    # -- opaque-handle discipline: foreign handle rejected -----------------
    def test_foreign_handle_rejected(self) -> None:
        foreign = NoOpSandbox().prepare(_artifact("pass\n"), Fixtures())  # NoOp echoes
        with self.assertRaises(TypeError):
            self.sb.run(foreign, _RUN_MAIN, BUDGET_FAST)

    # -- Ruling E parity: process-TREE kill (grandchild dies with the child) --
    def test_timeout_kills_grandchild_process_tree(self) -> None:
        # child spawns a long-lived grandchild, records its pid, then hangs.
        script = (
            "import subprocess, sys, time\n"
            "gc = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
            "open('gc_pid.txt', 'w').write(str(gc.pid))\n"
            "time.sleep(60)\n"
        )
        h = self.sb.prepare(_artifact(script), Fixtures())
        gc_pid: int | None = None
        try:
            r = self.sb.run(h, _RUN_MAIN, ResourceBudget(wall_clock_seconds=2.0))
            self.assertEqual(r.outcome, "timeout")
            gc_pid = int((Path(h.workdir) / "gc_pid.txt").read_text())  # type: ignore[attr-defined]
            time.sleep(0.8)  # let the tree-kill propagate
            self.assertFalse(
                _pid_alive(gc_pid),
                "grandchild must die with the child (process-tree kill parity)",
            )
        finally:
            if gc_pid is not None:
                _kill_pid(gc_pid)
            self.sb.teardown(h)

    # -- Ruling E parity: teardown succeeds even if the child held a file open --
    def test_teardown_after_child_holds_workdir_file_open(self) -> None:
        script = (
            "import time\n"
            "f = open('held.dat', 'w'); f.write('x'); f.flush()\n"
            "time.sleep(60)\n"
        )
        with self.sb.session(_artifact(script), Fixtures()) as h:
            workdir = Path(h.workdir)  # type: ignore[attr-defined]
            r = self.sb.run(h, _RUN_MAIN, ResourceBudget(wall_clock_seconds=2.0))
            self.assertEqual(r.outcome, "timeout")
        # teardown ran on session exit; the workdir must be gone even though the
        # killed child had a file open (Windows: a lingering handle can block rmtree).
        self.assertFalse(
            workdir.exists(), "teardown must remove the workdir even after a locked file"
        )

    # -- both backends still core.Sandbox ---------------------------------
    def test_both_conform_to_protocol(self) -> None:
        self.assertIsInstance(self.sb, Sandbox)
        self.assertIsInstance(NoOpSandbox(), Sandbox)


if __name__ == "__main__":
    unittest.main()
