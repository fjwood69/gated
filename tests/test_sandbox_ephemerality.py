"""tests/test_sandbox_ephemerality.py — the fail-CLOSED existence/teardown contract (board P1).

Ephemerality is a security property and the threat model is a MALICIOUS artifact, so a teardown that
CANNOT confirm destruction (the runtime timed out / errored / returned non-zero) MUST raise
``SandboxLeakError`` — never fail open by reading "can't tell" as "gone". These run with FAKE, unreachable
runtimes (no podman): ``/nonexistent-…`` triggers ``OSError``, ``false`` a non-zero exit, ``sleep`` a timeout.
"""
from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import sandbox.observed as observed_mod
from core import ArtifactSpec, Existence, Fixtures, SandboxLeakError, tree_hash
from sandbox.observed import ObservedHandle, ObservedOCISandbox, reap_orphans
from sandbox.oci import OCIHandle, OCISandbox, probe_existence

_MISSING = "/nonexistent-runtime-zzzqfx"  # an argv[0] that cannot exec -> OSError


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _artifact_dir(body: str = "pass\n") -> ArtifactSpec:
    d = Path(tempfile.mkdtemp(prefix="mv-eph-art-"))
    (d / "main.py").write_text(body, encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


def _wait_count(countfile: Path, want: int, within: float) -> int | None:
    """Poll the proxy's OWN countfile until it reads ``want`` (or ``within`` seconds elapse)."""
    deadline = time.monotonic() + within
    last: int | None = None
    while time.monotonic() < deadline:
        try:
            last = int(countfile.read_text().strip())
        except (OSError, ValueError):
            last = None
        if last == want:
            return last
        time.sleep(0.02)
    return last


def _oci_handle(container: str = "mv-eph-ctr") -> OCIHandle:
    snap = Path(tempfile.mkdtemp(prefix="mv-eph-"))
    return OCIHandle(id="i", artifact_hash="h", snapshot=snap, container=container, image_id="img")


def _obs_handle() -> ObservedHandle:
    snap = Path(tempfile.mkdtemp(prefix="mv-eph-o-"))
    return ObservedHandle(id="i", artifact_hash="h", snapshot=snap, container="mv-eph-c",
                          network="mv-eph-n", proxy="mv-eph-p", proxy_ip="10.0.0.2", baseline=0,
                          image_id="img")


class ProbeExistenceTests(unittest.TestCase):
    def test_exists_on_zero_exit_with_name(self) -> None:
        self.assertIs(probe_existence(["echo", "myname"], "myname"), Existence.EXISTS)

    def test_absent_on_zero_exit_without_name(self) -> None:
        self.assertIs(probe_existence(["echo", "other"], "myname"), Existence.ABSENT)

    def test_unknown_on_oserror(self) -> None:
        self.assertIs(probe_existence([_MISSING, "ps"], "x"), Existence.UNKNOWN)

    def test_unknown_on_nonzero_exit(self) -> None:
        # a FAILED `ps` with empty stdout is NOT proof of absence — non-zero return code -> UNKNOWN.
        self.assertIs(probe_existence(["false"], "x"), Existence.UNKNOWN)

    def test_unknown_on_timeout(self) -> None:
        self.assertIs(probe_existence(["sleep", "5"], "x", timeout=0.05), Existence.UNKNOWN)


class OCITeardownFailClosedTests(unittest.TestCase):
    def test_teardown_raises_when_runtime_unreachable(self) -> None:
        sb = OCISandbox(image="x", runtime=_MISSING)  # probe -> OSError -> UNKNOWN -> cannot confirm destroyed
        with self.assertRaises(SandboxLeakError):
            sb.teardown(_oci_handle())

    def test_teardown_raises_on_nonzero_probe(self) -> None:
        sb = OCISandbox(image="x", runtime="false")  # probe -> returncode 1 -> UNKNOWN
        with self.assertRaises(SandboxLeakError):
            sb.teardown(_oci_handle())


class ObservedTeardownFailClosedTests(unittest.TestCase):
    def test_teardown_raises_when_runtime_unreachable(self) -> None:
        sb = ObservedOCISandbox(image="x", runtime=_MISSING)
        with self.assertRaises(SandboxLeakError):
            sb.teardown(_obs_handle())


class PartialPrepareFailClosedTests(unittest.TestCase):
    """Board P1 remaining hole: a partial-setup failure runs cleanup, and if that cleanup cannot PROVE
    the infra gone the survivor list MUST surface a ``SandboxLeakError`` (fail-closed) — not be discarded
    behind the original setup error. Uses a fake runtime (``false``): ``_create_network`` exits non-zero
    (check=True -> CalledProcessError) after the snapshot is staged, then the real cleanup probes the
    proxy+network as UNKNOWN and reports them as survivors."""

    def test_partial_prepare_surfaces_survivors_chained(self) -> None:
        sb = ObservedOCISandbox(image="x", runtime="false")  # network create -> non-zero -> setup fails
        art = _artifact_dir()
        orig = observed_mod.resolve_image_id
        observed_mod.resolve_image_id = lambda rt, img: "img-digest"  # skip the real image resolve
        try:
            with self.assertRaises(SandboxLeakError) as cm:
                sb.prepare(art, Fixtures())
            self.assertIsNotNone(cm.exception.__cause__, "original setup error must be preserved as cause")
        finally:
            observed_mod.resolve_image_id = orig


class ProxyCountAtAcceptTests(unittest.TestCase):
    """P2 focused negative: the count is taken at ``accept()``, so a SILENT client (connects, sends
    nothing) is counted well before the 5s handler peek-timeout, and an accepted-but-semaphore-blocked
    client is still counted. Scope note: this covers ACCEPTED connections; connections still in the
    kernel backlog (beyond ``listen()``) are not counted until accepted — the acknowledged boundary."""

    def _serve(self, mode: str = "fail_always") -> tuple[int, Path]:
        from observe.proxy import serve
        port = _free_port()
        countfile = Path(tempfile.mkdtemp(prefix="mv-eph-cnt-")) / "count"
        threading.Thread(target=serve, args=(port, str(countfile), mode), daemon=True).start()
        self.assertEqual(_wait_count(countfile, 0, within=2.0), 0, "proxy did not initialise its countfile")
        return port, countfile

    def test_silent_client_counted_before_peek_timeout(self) -> None:
        port, countfile = self._serve()
        conn = socket.create_connection(("127.0.0.1", port), 3)  # send NOTHING (slowloris)
        try:
            # count must reach 1 far inside the handler's 5s recv timeout — i.e. it was taken at accept.
            self.assertEqual(_wait_count(countfile, 1, within=2.0), 1)
        finally:
            conn.close()

    def test_accept_counts_under_semaphore_saturation(self) -> None:
        from observe.proxy import _MAX_INFLIGHT
        port, countfile = self._serve()
        # _MAX_INFLIGHT silent clients occupy every handler; the next accept still increments the count
        # BEFORE it blocks on the semaphore -> the count reaches _MAX_INFLIGHT+1 despite full saturation.
        conns = [socket.create_connection(("127.0.0.1", port), 3) for _ in range(_MAX_INFLIGHT + 1)]
        try:
            self.assertEqual(_wait_count(countfile, _MAX_INFLIGHT + 1, within=3.0), _MAX_INFLIGHT + 1)
        finally:
            for c in conns:
                c.close()


class ReaperFailClosedTests(unittest.TestCase):
    def test_reap_raises_when_listing_unreachable(self) -> None:
        with self.assertRaises(SandboxLeakError):
            reap_orphans(_MISSING)

    def test_reap_raises_on_nonzero_listing(self) -> None:
        with self.assertRaises(SandboxLeakError):
            reap_orphans("false")


if __name__ == "__main__":
    unittest.main()
