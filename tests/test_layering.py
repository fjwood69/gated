"""The open-core dependency boundary, enforced as a zero-dep test (the import-linter rule the
board mandated, without adding a tooling dependency — the core stays stdlib-only).

Invariants (belt-and-braces with the gitnexus call-graph check):
  * ``core`` imports NEITHER ``engine`` NOR ``gate`` — it is the shared base.
  * ``engine`` does NOT import ``gate`` — the extractability invariant (engine ships without the
    gate). This is the property graph-verified for the calibrator and re-checked here statically.
The gate MAY import engine + core (it is the top layer).
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _py_files(pkg: str) -> list[Path]:
    return [p for p in (_ROOT / pkg).rglob("*.py") if "__pycache__" not in p.parts]


def _imports_forbidden(path: Path, forbidden: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        for pkg in forbidden:
            if re.match(rf"\s*(from|import)\s+{pkg}(\.|\s|$)", line):
                hits.append(f"{path.relative_to(_ROOT)}: {line.strip()}")
    return hits


class LayeringTests(unittest.TestCase):
    def test_core_imports_neither_engine_nor_gate(self) -> None:
        hits = [h for p in _py_files("core") for h in _imports_forbidden(p, ("engine", "gate"))]
        self.assertEqual(hits, [], "core must not import engine/gate:\n" + "\n".join(hits))

    def test_engine_does_not_import_gate(self) -> None:
        # The extractability invariant: engine ships without the gate. calibration.py reuses the
        # tamper-chain via core.chain, NOT via gate.ledger — this proves that statically.
        hits = [h for p in _py_files("engine") for h in _imports_forbidden(p, ("gate",))]
        self.assertEqual(hits, [], "engine must not import gate:\n" + "\n".join(hits))

    def test_sandbox_observe_do_not_import_gate(self) -> None:
        # The isolation layers are engine-adjacent open-core too — no gate reach.
        hits = [
            h for pkg in ("sandbox", "observe")
            for p in _py_files(pkg) for h in _imports_forbidden(p, ("gate",))
        ]
        self.assertEqual(hits, [], "sandbox/observe must not import gate:\n" + "\n".join(hits))

    def test_tier_store_and_state_layers_are_engine_free(self) -> None:
        # 3.3: the tier store / state / snapshot / authority layers hold governance + tamper state
        # and must NOT reach into the engine — only the gatekeeper ORCHESTRATOR bridges gate->engine
        # (allowed; engine⊥gate is one-directional). This mirrors 3.2's calibration STORE being
        # engine-free while the calibrate CALL lives engine-side.
        engine_free = ("policy_state.py", "policy_store.py", "snapshot.py", "authority.py",
                       "calibration_store.py")
        gate_dir = _ROOT / "gate"
        hits = [
            f"{name}: {line}"
            for name in engine_free
            for line in (gate_dir / name).read_text(encoding="utf-8").splitlines()
            if re.match(r"\s*(from|import)\s+engine(\.|\s|$)", line)
        ]
        self.assertEqual(hits, [], "tier store/state layers must not import engine:\n" + "\n".join(hits))


if __name__ == "__main__":
    unittest.main()
