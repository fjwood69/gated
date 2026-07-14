"""Increment 1.5 — the retry check + multi-trial engine.

Two layers:
  * aggregation unit tests (no podman) — the Gap-4 unanimity/flaky logic.
  * demo regression (real podman) — A/B/C through the REAL engine (ObservedOCISandbox
    + boundary observer) must reproduce the demo's A=PASS, B=FAIL, C=FAIL, with B
    caught BECAUSE the boundary saw 1 attempt (never by inspecting B's structure).
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import ArtifactSpec, Reason, ResourceBudget, Verdict, VerdictType, tree_hash
from engine.retry import RetryCheck
from engine.runner import aggregate, run_check
from sandbox.observed import ObservedOCISandbox

IMAGE = "localhost/mori:local"
_HAVE = ObservedOCISandbox.available(IMAGE)
_ENTRY = ("python3", "/artifact/main.py")
_BUDGET = ResourceBudget(wall_clock_seconds=30.0)

# Real-network A/B/C: connect to the boundary proxy (health-proxy) with the same
# behaviour as the demo's three artifacts, but over a real socket the boundary counts.
_A = (  # a real retry loop -> 2 attempts under fail-once (1st 503, retry, 2nd 200)
    "import socket\n"
    "def _get():\n"
    "    s = socket.create_connection(('health-proxy', 8080), 3)\n"
    "    s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
    "    r = s.recv(64); s.close()\n"
    "    if b'503' in r: raise OSError('transient')\n"
    "    return r\n"
    "for _ in range(3):\n"
    "    try:\n"
    "        _get(); break\n"
    "    except OSError:\n"
    "        continue\n"
)
_B = (  # swallowing helper: catches the failure, returns truthy -> loop stops at 1 attempt
    "import socket\n"
    "def _safe_get():\n"
    "    try:\n"
    "        s = socket.create_connection(('health-proxy', 8080), 3)\n"
    "        s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
    "        r = s.recv(64); s.close()\n"
    "        if b'503' in r: raise OSError('transient')\n"
    "        return r\n"
    "    except OSError:\n"
    "        return b'unavailable'\n"
    "for _ in range(3):\n"
    "    r = _safe_get()\n"
    "    if r: break\n"
)
_C = (  # one attempt, no retry
    "import socket\n"
    "s = socket.create_connection(('health-proxy', 8080), 3)\n"
    "s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n'); s.recv(64); s.close()\n"
)


def _artifact(script: str) -> ArtifactSpec:
    d = Path(tempfile.mkdtemp(prefix="mvtest-eng-"))
    (d / "main.py").write_text(script, encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


_P = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)
_F = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_E = Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING)


class AggregationTests(unittest.TestCase):
    """Gap-4 unanimity — GLM correction: flaky is FAIL (a defect), ERROR is telemetry-only."""

    def test_all_pass(self) -> None:
        self.assertIs(aggregate([_P, _P, _P]).status, VerdictType.PASS)

    def test_all_fail_propagates_reason(self) -> None:
        v = aggregate([_F, _F])
        self.assertIs(v.status, VerdictType.FAIL)
        self.assertIs(v.reason, Reason.EGRESS_ONE)

    def test_mixed_pass_fail_is_flaky_FAIL_not_error(self) -> None:
        v = aggregate([_P, _F, _P])
        self.assertIs(v.status, VerdictType.FAIL, "flaky is a defect -> FAIL")
        self.assertIs(v.reason, Reason.NON_DETERMINISTIC)

    def test_error_without_fail_is_ERROR(self) -> None:
        self.assertIs(aggregate([_P, _E]).status, VerdictType.ERROR)

    def test_fail_beats_error_fail_closed(self) -> None:
        self.assertIs(aggregate([_F, _E]).status, VerdictType.FAIL, "observed non-compliance blocks")


@unittest.skipUnless(_HAVE, f"no OCI runtime can run {IMAGE} hermetically")
class DemoRegressionTests(unittest.TestCase):
    """The thesis proof: same verdicts as the demo, via the hermetic boundary mechanism."""

    @staticmethod
    def _mk() -> ObservedOCISandbox:
        return ObservedOCISandbox(image=IMAGE, runtime="podman")

    def _run(self, script: str) -> Verdict:
        return run_check(self._mk, RetryCheck(_ENTRY), _artifact(script), _BUDGET, trials=2).verdict

    def test_A_retry_PASS(self) -> None:
        self.assertIs(self._run(_A).status, VerdictType.PASS)

    def test_B_swallowing_helper_FAIL_caught_by_boundary(self) -> None:
        # B looks like a retry (loop + try/except) but the BOUNDARY sees 1 attempt.
        # The engine judges only egress_attempts — it never inspects B's structure.
        self.assertIs(self._run(_B).status, VerdictType.FAIL)

    def test_C_no_retry_FAIL(self) -> None:
        self.assertIs(self._run(_C).status, VerdictType.FAIL)


if __name__ == "__main__":
    unittest.main()
