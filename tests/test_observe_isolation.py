"""3.5 job-3 — observe-mode isolation by structural absence. Run:
python3 -m unittest discover -s tests

The killer done-test (board): an AST gate over the ENFORCE path (engine/runner.py + the gate
dispatcher) proving NO ``if mode == 'observe'`` branch exists — observe is not a mode of enforce, it
does not exist there. Plus: an observe result is a distinct type that the enforce boundary
RUNTIME-REJECTS (a cast cannot launder it), and observe/enforce share no isolation-critical resource.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path
from typing import cast

from core import Reason, Verdict, VerdictType
from gate.observe_isolation import (
    IsolationConfig,
    ObserveIsolationError,
    ObserveResult,
    ObserveResultLeakError,
    assert_observe_enforce_isolated,
    require_enforce_verdict,
)

_ROOT = Path(__file__).resolve().parent.parent

# Names / string constants that would betray an observe-vs-enforce runtime branch in the enforce path.
_OBSERVE_NAMES = {"observe", "is_observe", "observe_mode", "observing", "shadow", "shadow_mode"}
_OBSERVE_CONSTS = {"observe", "shadow"}

# The ENFORCE path: the engine that computes a Verdict + the gate dispatcher that acts on tier state.
_ENFORCE_PATH = ("engine/runner.py", "gate/gatekeeper.py", "gate/pipeline.py")


def _observe_branch_hits(source: str) -> list[str]:
    """Every ``if``/``elif`` whose test references an observe-ish name/attribute or compares to an
    observe-ish string constant — i.e. a mode flag deciding observe-vs-enforce."""
    hits: list[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        for sub in ast.walk(node.test):
            if isinstance(sub, ast.Name) and sub.id in _OBSERVE_NAMES:
                hits.append(f"if references name {sub.id!r} (line {node.lineno})")
            elif isinstance(sub, ast.Attribute) and sub.attr in _OBSERVE_NAMES:
                hits.append(f"if references attr {sub.attr!r} (line {node.lineno})")
            elif isinstance(sub, ast.Constant) and isinstance(sub.value, str) \
                    and sub.value in _OBSERVE_CONSTS:
                hits.append(f"if compares to constant {sub.value!r} (line {node.lineno})")
    return hits


class NoSuchFlagASTGateTests(unittest.TestCase):
    def test_enforce_path_has_no_observe_mode_flag(self) -> None:
        offenders: list[str] = []
        for rel in _ENFORCE_PATH:
            src = (_ROOT / rel).read_text(encoding="utf-8")
            offenders += [f"{rel}: {h}" for h in _observe_branch_hits(src)]
        self.assertEqual(offenders, [], "the enforce path must contain NO observe/enforce mode "
                         "branch — observe is structurally absent, not a runtime flag:\n"
                         + "\n".join(offenders))

    def test_the_gate_detects_a_planted_flag(self) -> None:
        # the AST gate must actually bite — a planted mode branch is caught.
        planted = "def dispatch(mode):\n    if mode == 'observe':\n        return 1\n    return 0\n"
        self.assertTrue(_observe_branch_hits(planted))


class RuntimeRejectionTests(unittest.TestCase):
    def test_real_verdict_passes(self) -> None:
        v = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)
        self.assertIs(require_enforce_verdict(v), v)

    def test_observe_result_is_rejected_at_the_boundary(self) -> None:
        obs = ObserveResult(check_name="gated/observe/retry", observed_flows=1)
        with self.assertRaises(ObserveResultLeakError):
            require_enforce_verdict(obs)

    def test_cast_does_not_launder_an_observe_result(self) -> None:
        # typing alone is insufficient (board): a cast fools the checker but not the runtime tag check.
        obs = ObserveResult(check_name="gated/observe/retry", observed_flows=1)
        laundered = cast(Verdict, obs)  # a lie to the type checker; a no-op at runtime
        with self.assertRaises(ObserveResultLeakError):
            require_enforce_verdict(laundered)

    def test_observe_result_is_not_a_verdict(self) -> None:
        obs = ObserveResult(check_name="c", observed_flows=0)
        self.assertNotIsInstance(obs, Verdict)
        self.assertFalse(hasattr(obs, "status"))  # no VerdictType -> cannot map to a conclusion


class InfraIsolationTests(unittest.TestCase):
    def _cfg(self, lane: str, **over: str) -> IsolationConfig:
        base = dict(podman_socket=f"/run/{lane}.sock", check_name=f"gated/{lane}/retry",
                    worker_pool=f"{lane}-pool", service_account=f"{lane}-sa",
                    rate_limit_bucket=f"{lane}-bucket")
        base.update(over)
        return IsolationConfig(lane=lane, **base)  # type: ignore[arg-type]

    def test_fully_isolated_passes(self) -> None:
        assert_observe_enforce_isolated(self._cfg("observe"), self._cfg("enforce"))

    def test_shared_podman_socket_fails_closed(self) -> None:
        with self.assertRaises(ObserveIsolationError):
            assert_observe_enforce_isolated(
                self._cfg("observe", podman_socket="/run/shared.sock"),
                self._cfg("enforce", podman_socket="/run/shared.sock"))

    def test_shared_rate_limit_bucket_fails_closed(self) -> None:
        # starvation vector: a shared quota lets observe exhaust enforce's budget.
        with self.assertRaises(ObserveIsolationError):
            assert_observe_enforce_isolated(
                self._cfg("observe", rate_limit_bucket="global"),
                self._cfg("enforce", rate_limit_bucket="global"))

    def test_shared_check_name_fails_closed(self) -> None:
        with self.assertRaises(ObserveIsolationError):
            assert_observe_enforce_isolated(
                self._cfg("observe", check_name="gated/retry"),
                self._cfg("enforce", check_name="gated/retry"))


if __name__ == "__main__":
    unittest.main()
