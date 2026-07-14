"""Increment 1.3 OCISandbox (HERMETIC) tests — real podman required.

Skipped entirely when no OCI runtime can run the base image hermetically (e.g. CI
without podman). On the NUC: run from gated/ with `python3 -m unittest discover -s tests`.

Base image must contain a Python interpreter (the artifacts run `python3 /artifact/main.py`).
"""
from __future__ import annotations

import subprocess
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
from sandbox.oci import OCIHandle, OCISandbox
from core import Existence as _Existence

IMAGE = "localhost/mori:local"  # local, has python3 (3.13) — the test base image
_HAVE_OCI = OCISandbox.available(IMAGE)

# entrypoint: code is read-only at /artifact; cwd is the writable /work tmpfs.
_RUN = Command(argv=("python3", "/artifact/main.py"))


def _artifact(script: str) -> ArtifactSpec:
    d = Path(tempfile.mkdtemp(prefix="mvtest-oci-"))
    (d / "main.py").write_text(script, encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


def _exists_(sb, name):  # test helper: True iff the tri-state probe says EXISTS (healthy runtime)
    return sb._container_state(name) is _Existence.EXISTS


@unittest.skipUnless(_HAVE_OCI, f"no OCI runtime can run {IMAGE} hermetically")
class OCISandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = OCISandbox(image=IMAGE)

    # -- parity with 1.2: trivial / non-zero / hang / crash ---------------
    def test_trivial_completes_zero(self) -> None:
        with self.sb.session(_artifact("raise SystemExit(0)\n"), Fixtures()) as h:
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.exit_code, 0)
        self.assertIs(r.isolation_level, IsolationLevel.HERMETIC)

    def test_nonzero_exit_is_completed(self) -> None:
        with self.sb.session(_artifact("raise SystemExit(3)\n"), Fixtures()) as h:
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.exit_code, 3)

    def test_hang_times_out_and_container_is_killed(self) -> None:
        h = self.sb.prepare(_artifact("import time\ntime.sleep(120)\n"), Fixtures())
        try:
            t0 = time.monotonic()
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=4.0))
            self.assertEqual(r.outcome, "timeout")
            self.assertLess(time.monotonic() - t0, 30.0, "timeout must fire")
            self.assertFalse(
                _exists_(self.sb, h.container),  # type: ignore[attr-defined]
                "timed-out container must be killed, not orphaned",
            )
        finally:
            self.sb.teardown(h)

    def test_crash_is_error(self) -> None:
        # SIGKILL inside the container -> podman propagates 137 (128+9).
        script = "import os, signal\nos.kill(os.getpid(), signal.SIGKILL)\n"
        with self.sb.session(_artifact(script), Fixtures()) as h:
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
        self.assertEqual(r.outcome, "error")
        self.assertIsNotNone(r.raw_return_code)
        assert r.raw_return_code is not None
        self.assertGreaterEqual(r.raw_return_code, 128)

    # -- board check (d)/NFR4: --network=none actually enforced -----------
    def test_network_none_blocks_egress(self) -> None:
        script = (
            "import socket, sys\n"
            "try:\n"
            "    socket.create_connection(('1.1.1.1', 53), 2); sys.exit(1)\n"
            "except OSError:\n"
            "    sys.exit(0)\n"
        )
        with self.sb.session(_artifact(script), Fixtures()) as h:
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.exit_code, 0, "egress must be unreachable under --network=none")

    # -- Catch 3: the read-only mount is ENFORCED, not just requested -----
    def test_ro_mount_write_probe(self) -> None:
        script = (
            "import sys\n"
            "try:\n"
            "    open('/artifact/evil', 'w'); sys.exit(1)\n"
            "except OSError:\n"
            "    sys.exit(0)\n"
        )
        with self.sb.session(_artifact(script), Fixtures()) as h:
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
        self.assertEqual(r.exit_code, 0, "artifact must NOT be able to write its ro mount")

    # -- writable scratch works (so real artifacts can run) ---------------
    def test_work_tmpfs_is_writable(self) -> None:
        script = "open('scratch.txt', 'w').write('ok')\n"  # cwd is /work (tmpfs)
        with self.sb.session(_artifact(script), Fixtures()) as h:
            r = self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.exit_code, 0)

    # -- Catch 2: teardown DESTROYS a live container + verifies (reaper) --
    def test_teardown_destroys_live_container(self) -> None:
        h = self.sb.prepare(_artifact("pass\n"), Fixtures())
        assert isinstance(h, OCIHandle)
        # simulate a container that outlived a crashed run wrapper:
        subprocess.run(
            [self.sb.runtime, "run", "-d", "--network=none", "--name", h.container,
             IMAGE, "sleep", "120"],
            capture_output=True, timeout=60,
        )
        self.assertTrue(_exists_(self.sb, h.container))  # type: ignore[attr-defined]
        self.sb.teardown(h)  # must rm -f + verify gone (no SandboxLeakError)
        self.assertFalse(
            _exists_(self.sb, h.container),  # type: ignore[attr-defined]
            "teardown must destroy a live container",
        )

    def test_container_gone_after_normal_run(self) -> None:
        h = self.sb.prepare(_artifact("raise SystemExit(0)\n"), Fixtures())
        assert isinstance(h, OCIHandle)
        try:
            self.sb.run(h, _RUN, ResourceBudget(wall_clock_seconds=30.0))
            self.assertFalse(
                _exists_(self.sb, h.container),  # type: ignore[attr-defined]
                "--rm must leave no container after a normal run",
            )
        finally:
            self.sb.teardown(h)

    # -- SHA-bind verify + snapshot removed on teardown -------------------
    def test_hash_mismatch_refuses_handle(self) -> None:
        d = Path(tempfile.mkdtemp(prefix="mvtest-oci-"))
        (d / "main.py").write_text("pass\n", encoding="utf-8")
        bad = ArtifactSpec(path=d, tree_hash="sha256:not-real")
        with self.assertRaises(ArtifactHashMismatchError):
            self.sb.prepare(bad, Fixtures())

    def test_teardown_removes_snapshot(self) -> None:
        h = self.sb.prepare(_artifact("pass\n"), Fixtures())
        assert isinstance(h, OCIHandle)
        snap = h.snapshot
        self.assertTrue(snap.exists())
        self.sb.teardown(h)
        self.assertFalse(snap.exists(), "teardown removes the host-side snapshot")

    # -- opaque-handle discipline + conformance ---------------------------
    def test_foreign_handle_rejected(self) -> None:
        foreign = NoOpSandbox().prepare(_artifact("pass\n"), Fixtures())
        with self.assertRaises(TypeError):
            self.sb.run(foreign, _RUN, ResourceBudget(wall_clock_seconds=5.0))

    def test_conforms_to_protocol(self) -> None:
        self.assertIsInstance(self.sb, Sandbox)


class OCIDetectionTests(unittest.TestCase):
    """Detection is capability-based (runs without a real runtime present)."""

    def test_unavailable_image_fails_closed(self) -> None:
        # a bogus runtime name -> not on PATH -> no runtime -> unavailable (fail closed)
        from sandbox.oci import OCIRuntimeUnavailable

        self.assertFalse(OCISandbox.available("definitely/not/a/real/image:x0x0x0"))
        with self.assertRaises((OCIRuntimeUnavailable, Exception)):
            OCISandbox(image="definitely/not/a/real/image:x0x0x0")


if __name__ == "__main__":
    unittest.main()
