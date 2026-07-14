"""tests/test_sandbox_ephemerality.py — the fail-CLOSED existence/teardown contract (board P1).

Ephemerality is a security property and the threat model is a MALICIOUS artifact, so a teardown that
CANNOT confirm destruction (the runtime timed out / errored / returned non-zero) MUST raise
``SandboxLeakError`` — never fail open by reading "can't tell" as "gone". These run with FAKE, unreachable
runtimes (no podman): ``/nonexistent-…`` triggers ``OSError``, ``false`` a non-zero exit, ``sleep`` a timeout.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Existence, SandboxLeakError
from sandbox.observed import ObservedHandle, ObservedOCISandbox, reap_orphans
from sandbox.oci import OCIHandle, OCISandbox, probe_existence

_MISSING = "/nonexistent-runtime-zzzqfx"  # an argv[0] that cannot exec -> OSError


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


class ReaperFailClosedTests(unittest.TestCase):
    def test_reap_raises_when_listing_unreachable(self) -> None:
        with self.assertRaises(SandboxLeakError):
            reap_orphans(_MISSING)

    def test_reap_raises_on_nonzero_listing(self) -> None:
        with self.assertRaises(SandboxLeakError):
            reap_orphans("false")


if __name__ == "__main__":
    unittest.main()
