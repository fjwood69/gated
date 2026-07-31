"""Increment 1.4 ObservedOCISandbox tests — real podman required.

Skipped when no OCI runtime can run the base image hermetically. On a machine with an OCI runtime:
run from gated/ with `python3 -m unittest tests.test_observed_sandbox`.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import (
    ArtifactSpec, Command, Fixtures, IsolationLevel, ResourceBudget, Sandbox, tree_hash,
)
from sandbox.noop import NoOpSandbox
import subprocess
import uuid

from sandbox.oci import ensure_container_witness, probe_container, probe_network
from sandbox.observed import ObservedHandle, ObservedOCISandbox, reap_orphans
from core import Existence as _Existence

IMAGE = "localhost/mori:local"
_HAVE = ObservedOCISandbox.available(IMAGE)
_RUN = Command(argv=("python3", "/artifact/main.py"))
_BUDGET = ResourceBudget(wall_clock_seconds=60.0)

# an artifact that makes N real connection attempts to the proxy, then exits.
_ATTEMPT_N = """
import socket, sys
n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
for _ in range({N}):
    try:
        s = socket.create_connection(("health-proxy", 8080), 3)
        s.sendall(b"GET /health HTTP/1.0\\r\\n\\r\\n"); s.recv(64); s.close()
    except OSError:
        pass
"""


def _artifact(script: str) -> ArtifactSpec:
    d = Path(tempfile.mkdtemp(prefix="mvtest-obs-"))
    (d / "main.py").write_text(script, encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


def _exists_(sb, name):
    """True iff the probe says EXISTS, ON A CHANNEL PROVEN LIVE FOR THIS CALL.

    The old version claimed "True iff the tri-state probe says EXISTS (healthy runtime)" and probed
    whatever witness the instance happened to hold. On an instance that has not run ``prepare()`` there
    is none, so it reported False for a container that demonstrably existed — the helper was itself an
    artifact credited with a property it did not have, inside a suite that checks for exactly that.

    It now PROVISIONS ITS OWN WITNESS for the duration of the call. Note what that costs: this helper is
    no longer free, and it can raise ``WitnessProvisioningError`` if the runtime cannot create or list a
    canary. That is the honest failure — it means the assertion below it could not have been trusted.
    """
    rt = sb._exec_runtime()
    witness = ensure_container_witness(rt, IMAGE, uuid.uuid4().hex[:16])
    try:
        return probe_container(rt, name, witness=witness).state is _Existence.EXISTS
    finally:
        subprocess.run([rt, "rm", "-f", witness], capture_output=True, timeout=30)


def _net_exists_(sb, name):
    """Network kind. Its witness is the runtime's MEASURED ambient network, which always exists and costs
    nothing to provision — so unlike the container helper above, this one needs no canary."""
    return probe_network(sb._exec_runtime(), name, runtime_name=sb.runtime).state is _Existence.EXISTS


@unittest.skipUnless(_HAVE, f"no OCI runtime can run {IMAGE} hermetically")
class ObservedSandboxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sb = ObservedOCISandbox(image=IMAGE)

    def test_counts_exactly_n_attempts_from_outside(self) -> None:
        with self.sb.session(_artifact(_ATTEMPT_N.format(N=3)), Fixtures()) as h:
            r = self.sb.run(h, _RUN, _BUDGET)
        self.assertEqual(r.outcome, "completed")
        self.assertEqual(r.egress_attempts, 3, "boundary observer must count 3 real attempts")
        self.assertIs(r.isolation_level, IsolationLevel.HERMETIC)

    def test_lying_artifact_counted_as_its_real_attempts(self) -> None:
        # 1 real attempt, then loudly claims it retried — count is the truth, not the claim.
        script = (
            'import socket\n'
            'try:\n'
            '    socket.create_connection(("health-proxy", 8080), 3).close()\n'
            'except OSError:\n'
            '    pass\n'
            'print("I retried 5 times, honest!")\n'
        )
        with self.sb.session(_artifact(script), Fixtures()) as h:
            r = self.sb.run(h, _RUN, _BUDGET)
        self.assertEqual(r.egress_attempts, 1, "count reflects real requests, not self-report")

    def test_external_egress_blocked_and_uncounted(self) -> None:
        # tries a real external host (blocked by the sealed net) + one proxy hit.
        script = (
            'import socket\n'
            'try:\n'
            '    socket.create_connection(("1.1.1.1", 53), 2).close()\n'
            'except OSError:\n'
            '    pass\n'
            'try:\n'
            '    socket.create_connection(("health-proxy", 8080), 3).close()\n'
            'except OSError:\n'
            '    pass\n'
        )
        with self.sb.session(_artifact(script), Fixtures()) as h:
            r = self.sb.run(h, _RUN, _BUDGET)
        self.assertEqual(r.egress_attempts, 1, "external egress is blocked -> only the proxy hit counts")

    def test_teardown_leaves_no_zombie_resources(self) -> None:
        h = self.sb.prepare(_artifact(_ATTEMPT_N.format(N=1)), Fixtures())
        assert isinstance(h, ObservedHandle)
        self.sb.run(h, _RUN, _BUDGET)
        snap = h.snapshot
        self.sb.teardown(h)
        self.assertFalse(_exists_(self.sb, h.proxy), "proxy must be gone")  # type: ignore[attr-defined]
        self.assertFalse(_exists_(self.sb, h.container), "sandbox must be gone")  # type: ignore[attr-defined]
        self.assertFalse(_net_exists_(self.sb, h.network), "network must be gone")  # type: ignore[attr-defined]
        self.assertFalse(snap.exists(), "snapshot must be gone")

    def test_teardown_converges_after_partial_failure(self) -> None:
        # Fab's elevated done-test: teardown must reach all-gone from a PARTIAL
        # failure (here the proxy dies before teardown) — not just the happy path.
        h = self.sb.prepare(_artifact(_ATTEMPT_N.format(N=1)), Fixtures())
        assert isinstance(h, ObservedHandle)
        subprocess.run([self.sb.runtime, "rm", "-f", h.proxy], capture_output=True, timeout=30)
        self.sb.teardown(h)  # must converge, no SandboxLeakError
        self.assertFalse(_net_exists_(self.sb, h.network))  # type: ignore[attr-defined]
        self.assertFalse(_exists_(self.sb, h.container))  # type: ignore[attr-defined]
        self.assertFalse(h.snapshot.exists())

    def test_reaper_cleans_orphans(self) -> None:
        rt = self.sb.runtime
        net, ctr = "moriverify-net-orphantest", "moriverify-proxy-orphantest"
        subprocess.run([rt, "network", "create", "--internal", "--disable-dns", net],
                       capture_output=True, timeout=30)
        subprocess.run([rt, "run", "-d", "--network", net, "--name", ctr, IMAGE, "sleep", "120"],
                       capture_output=True, timeout=60)
        self.assertTrue(_exists_(self.sb, ctr))  # type: ignore[attr-defined]
        reap_orphans(rt, canary_image=IMAGE)
        self.assertFalse(_exists_(self.sb, ctr), "reaper removes orphan container")  # type: ignore[attr-defined]
        self.assertFalse(_net_exists_(self.sb, net), "reaper removes orphan network")  # type: ignore[attr-defined]

    def test_foreign_handle_rejected(self) -> None:
        foreign = NoOpSandbox().prepare(_artifact("pass\n"), Fixtures())
        with self.assertRaises(TypeError):
            self.sb.run(foreign, _RUN, _BUDGET)

    def test_conforms(self) -> None:
        self.assertIsInstance(self.sb, Sandbox)


if __name__ == "__main__":
    unittest.main()
