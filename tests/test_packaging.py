"""tests/test_packaging.py — B3 / S2 packaging + guard-boundary enforcement. Run:
python3 -m unittest discover -s tests

Reference-tier controls proving (1) the SHIPPED ARTIFACT excludes tests/scripts/the opt-out, and (2) the
trusted-backend guard is STRUCTURALLY mandatory. Board-ratified amendments, each written against a named
confound:

  * The AUTHORITATIVE packaging check is the CLEAN-WHEEL test (``CleanWheelTests``): build the REAL wheel,
    inspect its emitted contents, install into a clean environment OUTSIDE the repo with a sanitised
    PYTHONPATH, import every production package, prove the test opt-out is absent, and re-verify the
    observer-proxy hash golden. A manifest/config test alone proves only that setuptools was CONFIGURED,
    not what it EMITTED (confound #4).
  * The AST layering scan is UNIVERSAL — all six production packages, not just ``gate`` — and also bans
    DYNAMIC ``tests.*`` imports (confound: a cross-package or importlib bypass of a gate-only scan).
  * The mandatory-guard tripwire asserts ``backend_guard`` is a REQUIRED parameter by SIGNATURE (no
    default at all), NOT by scanning for the literal ``None`` — which ``default_bypass = None`` or a
    ``**kwargs`` indirection would slip past (confound #3).
  * A no-op guard may exist ONLY in ``tests/_backend_optout.py`` (confound #6).
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from engine.calibration import calibrate
from gate.acceptance import run_acceptance_anchor
from gate.gatekeeper import run_calibration
from gate.recalibration import run_recalibration

_ROOT = Path(__file__).resolve().parent.parent
_PROD_PKGS = ("core", "sandbox", "engine", "observe", "gate", "cli")
# The proxy-bytes golden (shared with the execution-identity golden): re-verified after a REAL install to
# prove observe/proxy.py shipped and its bytes are unchanged (confound #7).
#
# ⚠ "shared with" IS ASPIRATIONAL — this is a RESTATED LITERAL, not a shared value, and P3 step 0 had to
# edit both copies by hand to keep them agreeing. A literal is CORRECT here (importing the golden from the
# source tree would compare the installed package against the dev tree instead of against a pinned
# expectation); TWO literals are not. The fix is one shared test constant, and it is deliberately NOT done
# in this increment: it is the test-side instance of exactly the defect P3 step 3 already carries — "the
# receipt must carry the module's CURRENT hash rather than a restated copy" — and this tree has already
# named the law: "the two must be one value rather than two that agree today".
#
# RE-PINNED — P3 step 0, 2026-08-02: write_count publishes by atomic rename; see the execution-identity
# golden for the measurement.
_GOLDEN_OBSERVER_CONFIG_HASH = "c9d22c3fa5389986d941333d1b717f4a0a5b45271c3e801f1dfc8113159cf4eb"


def _iter_prod_py() -> "list[Path]":
    return [p for pkg in _PROD_PKGS for p in (_ROOT / pkg).rglob("*.py")]


class UniversalLayeringTests(unittest.TestCase):
    """No PRODUCTION package may import ``tests.*`` — statically or dynamically. A gate-only scan is a
    confound: ``engine`` importing the opt-out passes a gate-only check yet reintroduces it into a
    production run when launched from the repo root."""

    def test_no_production_package_statically_imports_tests(self) -> None:
        offenders: list[str] = []
        for p in _iter_prod_py():
            tree = ast.parse(p.read_text(), filename=str(p))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    offenders += [f"{p}: import {a.name}" for a in node.names
                                  if a.name == "tests" or a.name.startswith("tests.")]
                elif isinstance(node, ast.ImportFrom):
                    mod = node.module or ""
                    if mod == "tests" or mod.startswith("tests."):
                        offenders.append(f"{p}: from {mod}")
        self.assertEqual(offenders, [], f"production code imports tests.*: {offenders}")

    def test_no_production_package_dynamically_imports_tests(self) -> None:
        # confound: importlib.import_module("tests...") / __import__("tests...") bypasses the static scan.
        offenders: list[str] = []
        for p in _iter_prod_py():
            for node in ast.walk(ast.parse(p.read_text(), filename=str(p))):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""
                if name not in ("import_module", "__import__"):
                    continue
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and \
                        (a0.value == "tests" or a0.value.startswith("tests.")):
                    offenders.append(f"{p}: {name}({a0.value!r})")
        self.assertEqual(offenders, [], f"production code dynamically imports tests.*: {offenders}")


class MandatoryGuardSignatureTests(unittest.TestCase):
    """The guard is REQUIRED by SIGNATURE on every entry point — value-agnostic. Checking for a literal
    ``None`` default is bypassable via ``default_bypass = None`` or ``**kwargs`` indirection (confound #3);
    asserting the parameter has NO default at all cannot be bypassed that way."""

    def test_backend_guard_is_a_required_keyword_only_param(self) -> None:
        for fn in (calibrate, run_calibration, run_recalibration, run_acceptance_anchor):
            p = inspect.signature(fn).parameters.get("backend_guard")
            self.assertIsNotNone(p, f"{fn.__name__} lost its backend_guard parameter")
            assert p is not None  # for the type-checker
            self.assertIs(
                p.default, inspect.Parameter.empty,
                f"{fn.__name__}.backend_guard has a default ({p.default!r}) — the guard MUST be required; "
                "ANY default (even a non-None indirection) reopens the audited-backend fail-open",
            )
            self.assertIs(p.kind, inspect.Parameter.KEYWORD_ONLY, f"{fn.__name__}.backend_guard")


class NoOpGuardScanTests(unittest.TestCase):
    """A no-op guard (takes a sandbox, does nothing) is the fail-open the mandatory guard closes. The ONLY
    one permitted is ``tests/_backend_optout.py`` (test-only, excluded from the wheel). Scan production for
    any trivially-no-op function that takes a sandbox-shaped parameter (confound #6). ``...`` Protocol/ABC
    stubs are NOT no-ops (they are unimplemented) and are excluded."""

    @staticmethod
    def _is_noop_body(body: list[ast.stmt]) -> bool:
        stmts = body
        if stmts and isinstance(stmts[0], ast.Expr) and isinstance(stmts[0].value, ast.Constant) \
                and isinstance(stmts[0].value.value, str):
            stmts = stmts[1:]  # drop a docstring
        if len(stmts) != 1:
            return False
        s = stmts[0]
        if isinstance(s, ast.Pass):
            return True
        if isinstance(s, ast.Return) and (s.value is None
                                          or (isinstance(s.value, ast.Constant) and s.value.value is None)):
            return True
        # a lone ``...`` is a Protocol/ABC stub — NOT a no-op implementation.
        return False

    @staticmethod
    def _takes_sandbox(fn: ast.FunctionDef) -> bool:
        for arg in fn.args.args + fn.args.kwonlyargs:
            ann = getattr(arg.annotation, "id", None) or getattr(arg.annotation, "attr", None)
            if arg.arg in ("sandbox", "sb") or ann == "Sandbox":
                return True
        return False

    def test_no_production_noop_guard(self) -> None:
        offenders: list[str] = []
        for p in _iter_prod_py():
            for node in ast.walk(ast.parse(p.read_text(), filename=str(p))):
                if isinstance(node, ast.FunctionDef) and self._takes_sandbox(node) \
                        and self._is_noop_body(node.body):
                    offenders.append(f"{p}:{node.lineno} {node.name}")
        self.assertEqual(
            offenders, [],
            f"production code defines a no-op sandbox guard (fail-open); the only permitted one is "
            f"tests/_backend_optout.py: {offenders}",
        )


class PackagingConfigTests(unittest.TestCase):
    """A configuration check (weaker than the wheel test — it proves setuptools was CONFIGURED to exclude
    tests, not what the wheel EMITTED). Kept as a fast complement; the authoritative proof is
    ``CleanWheelTests``."""

    def test_pyproject_excludes_tests_and_allowlists_prod(self) -> None:
        txt = (_ROOT / "pyproject.toml").read_text()
        self.assertIn('exclude = ["tests*", "scripts*"]', txt)
        for pkg in _PROD_PKGS:
            self.assertIn(f'"{pkg}*"', txt, f"{pkg} missing from the packaging allowlist")


def _build_available() -> bool:
    return importlib.util.find_spec("build") is not None


@unittest.skipUnless(_build_available(), "wheel build tooling ('build') unavailable — clean-wheel test skipped")
class CleanWheelTests(unittest.TestCase):
    """The AUTHORITATIVE packaging check: build the REAL wheel and verify its EMITTED contents + a clean
    install. Neither the AST scan (inspects source) nor the config test (inspects setuptools config)
    inspects the artifact; only this does."""

    tmp: Path
    wheel: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="mv-wheel-"))
        # --no-isolation: build in the current env (setuptools/wheel already present) -> no network.
        proc = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", str(cls.tmp)],
            cwd=str(_ROOT), capture_output=True, text=True,
        )
        if proc.returncode != 0:
            raise unittest.SkipTest(f"wheel build failed:\n{proc.stdout}\n{proc.stderr}")
        wheels = list(cls.tmp.glob("*.whl"))
        assert len(wheels) == 1, f"expected one wheel, got {wheels}"
        cls.wheel = wheels[0]
        # clean the in-repo build side-effects so the tree stays clean (gitignored anyway).
        for d in ("build", "gated.egg-info"):
            path = _ROOT / d
            if path.exists():
                subprocess.run(["rm", "-rf", str(path)], check=False)

    def _wheel_names(self) -> list[str]:
        with zipfile.ZipFile(self.wheel) as z:
            return z.namelist()

    def test_wheel_emits_no_tests_scripts_or_optout(self) -> None:
        bad = [n for n in self._wheel_names()
               if n.startswith(("tests/", "scripts/")) or "_backend_optout" in n]
        self.assertEqual(bad, [], f"the built wheel LEAKED test/script/opt-out files: {bad}")

    def test_wheel_ships_the_observer_proxy_source(self) -> None:
        # confound #7: observe/proxy.py is required at runtime by ObservedOCISandbox AND its bytes are part
        # of the execution identity — it MUST ship, or the reference breaks / the identity silently drifts.
        self.assertIn("observe/proxy.py", self._wheel_names())

    def test_install_clean_env_optout_absent_and_proxy_hash_golden(self) -> None:
        venv_dir = self.tmp / "venv"
        # --system-site-packages: runtime deps (pynacl/pyjwt) come from the system -> --no-deps install is
        # offline/hermetic. The repo source is NOT on this venv's path.
        subprocess.run([sys.executable, "-m", "venv", "--system-site-packages", str(venv_dir)], check=True)
        py = venv_dir / "bin" / "python"
        inst = subprocess.run(
            [str(py), "-m", "pip", "install", "--no-deps", "--force-reinstall", str(self.wheel)],
            capture_output=True, text=True,
        )
        self.assertEqual(inst.returncode, 0, f"install failed:\n{inst.stdout}\n{inst.stderr}")

        outside = self.tmp / "run"
        outside.mkdir(exist_ok=True)
        probe = r"""
import importlib
for pkg in ["core", "sandbox", "engine", "observe", "gate", "cli"]:
    importlib.import_module(pkg)
try:
    importlib.import_module("tests._backend_optout")
    print("OPTOUT_PRESENT_FAIL")
except ModuleNotFoundError:
    print("OPTOUT_ABSENT")
from sandbox.observed import _OBSERVER_CONFIG_HASH
print("OBSERVER_HASH=" + _OBSERVER_CONFIG_HASH)
from sandbox.oci import OCISandbox
from sandbox.observed import ObservedOCISandbox
from sandbox.noop import NoOpSandbox
ok = (OCISandbox.__name__ == "OCISandbox" and ObservedOCISandbox.__name__ == "ObservedOCISandbox"
      and NoOpSandbox.__name__ == "NoOpSandbox")
print("BACKEND_NAMES_OK" if ok else "BACKEND_NAMES_FAIL")
"""
        # confound #1: run OUTSIDE the repo with a sanitised environment (no PYTHONPATH) so a successful
        # import proves the INSTALLED wheel, not the source tree on cwd/sys.path.
        env = {"PATH": os.environ.get("PATH", "")}
        r = subprocess.run([str(py), "-c", probe], cwd=str(outside), env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, f"clean-env probe failed:\n{r.stdout}\n{r.stderr}")
        self.assertIn("OPTOUT_ABSENT", r.stdout, "the test opt-out was importable from the installed wheel")
        self.assertIn(f"OBSERVER_HASH={_GOLDEN_OBSERVER_CONFIG_HASH}", r.stdout,
                      "observer-proxy hash from the installed wheel != source golden (proxy bytes drifted "
                      "or the proxy source did not ship)")
        self.assertIn("BACKEND_NAMES_OK", r.stdout, "backend class names from the installed wheel != golden")


if __name__ == "__main__":
    unittest.main()
