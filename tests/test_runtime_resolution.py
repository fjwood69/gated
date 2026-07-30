"""P2a — one runtime resolution, one client-env policy, across every invocation site.

Two properties, both asserted STATICALLY over the whole `sandbox` package rather than by driving each
call site, because a behavioural test can only reach the sites a test host can actually run:

  1. every runtime invocation uses the RESOLVED ABSOLUTE PATH as ``argv[0]``, never the bare audited
     name — a slash-less ``argv[0]`` is resolved by ``Popen`` via the PATH *in the passed env dict*, so
     a trojaned binary on an early PATH entry would execute as the gate during a verdict run;
  2. every runtime invocation passes ``env=`` — before P2a, 18 of 20 passed none and inherited the whole
     host environment, including the capability probe that decides whether the gate can run at all.

Why static. The P1 binding tests were verified NOT to catch a bare-name regression: they compare the
create argv against ``network_create_argv(runtime, ...)`` with whatever the caller passed, so reverting
``_runtime_path`` to ``_runtime`` leaves them green. That was checked by reintroducing the defect. A
property about *every* site needs a check that sees every site.

``ast`` only — no ``tokenize``, no f-string token counts. A prior test in this tree depended on PEP 701
tokenisation and would have failed on CPython 3.9/3.10/3.11, three of the five versions in the matrix.
"""
from __future__ import annotations

import ast
import os
import pathlib
import unittest
from unittest import mock

from sandbox.oci import (
    OCISandbox,
    _CLIENT_ENV_PASSTHROUGH,
    detect_runtime,
    resolve_runtime_path,
    runtime_client_env,
)
from sandbox.observed import ObservedOCISandbox

_PKG = pathlib.Path(__file__).resolve().parent.parent / "sandbox"

# Modules that invoke a CONTAINER RUNTIME. ``sandbox/subprocess.py`` is deliberately excluded: the WEAK
# backend execs the ARTIFACT directly as a host process, so it is not a runtime invocation and P2a's
# argv[0]/client-env policy does not apply to it. Recorded rather than silently skipped, because the
# exclusion is a claim: that backend currently passes no ``env=`` at all, so it runs the artifact with
# the FULL host environment. WEAK is documented as insufficient for a real merge gate, so that is a
# separate question — but it is a question, not a non-issue.
_RUNTIME_MODULES = ("oci.py", "observed.py")

# ``probe_existence`` receives a fully-built argv from its callers and executes it verbatim; the callers
# are the sites that must pin. Keyed by qualified location so a stale entry is visible.
_ARGV_FROM_CALLER = {"sandbox/oci.py::probe_existence"}


def _runtime_invocations() -> list[tuple[str, ast.Call]]:
    """Every ``subprocess.run`` / ``subprocess.Popen`` call in the sandbox package, with its location."""
    found: list[tuple[str, ast.Call]] = []
    for path in sorted(_PKG.glob("*.py")):
        if path.name not in _RUNTIME_MODULES:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        funcs: list[tuple[str, ast.AST]] = [
            (n.name, n) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        for name, node in funcs:
            for call in ast.walk(node):
                if not isinstance(call, ast.Call):
                    continue
                f = call.func
                if (isinstance(f, ast.Attribute) and f.attr in ("run", "Popen")
                        and isinstance(f.value, ast.Name) and f.value.id == "subprocess"):
                    found.append((f"sandbox/{path.name}::{name}", call))
    return found


class Argv0IsAlwaysResolved(unittest.TestCase):
    def test_no_invocation_uses_the_bare_runtime_name(self) -> None:
        """``argv[0]`` must never be ``self._runtime`` — that is the audited NAME, not a binary."""
        offenders = []
        for where, call in _runtime_invocations():
            if not call.args:
                continue
            first = call.args[0]
            if not isinstance(first, ast.List) or not first.elts:
                continue
            head = first.elts[0]
            if isinstance(head, ast.Attribute) and head.attr == "_runtime":
                offenders.append(where)
        self.assertEqual(
            offenders, [],
            "these sites use the bare runtime NAME as argv[0] instead of the resolved path "
            f"(_runtime_path): {offenders}",
        )

    def test_every_invocation_passes_an_env(self) -> None:
        """One client-env policy means no site may inherit the host environment by omission."""
        offenders = [
            where for where, call in _runtime_invocations()
            if where not in _ARGV_FROM_CALLER
            and not any(k.arg == "env" for k in call.keywords)
        ]
        self.assertEqual(
            offenders, [],
            f"these runtime invocations pass no env= and inherit the host environment: {offenders}",
        )

    def test_the_sweep_can_actually_find_sites(self) -> None:
        """Guard the guard: a sweep that finds nothing would pass both assertions above vacuously."""
        sites = _runtime_invocations()
        self.assertGreaterEqual(
            len(sites), 12,
            "the AST sweep found implausibly few runtime invocations — it is probably not matching, "
            "which would make the two assertions above pass while checking nothing",
        )


class RuntimeNameVersusPath(unittest.TestCase):
    """The audited NAME and the executed PATH are separate, and the closed-set contract needs the name."""

    def test_runtime_property_reports_the_name_not_the_path(self) -> None:
        # gate/backends.py validates against a CLOSED SET of names and test_backends asserts
        # sb.runtime == "podman"; resolving into that attribute would break an exec-injection control.
        for cls in (OCISandbox, ObservedOCISandbox):
            sbx = cls.__new__(cls)
            sbx._runtime = "podman"
            sbx._runtime_path = "/usr/bin/podman"
            self.assertEqual(sbx.runtime, "podman", f"{cls.__name__}.runtime must report the NAME")

    def test_absolute_input_is_returned_unchanged(self) -> None:
        self.assertEqual(resolve_runtime_path("/opt/bin/podman"), "/opt/bin/podman")

    def test_unresolvable_name_does_not_raise(self) -> None:
        """Import-time safety: ``observed.py`` builds a sandbox at module import for the protocol check,
        so raising here would make importing the package fail on a host without that runtime."""
        got = resolve_runtime_path("zz-definitely-not-on-path")
        self.assertEqual(got, "zz-definitely-not-on-path")


class OneDetectImplementation(unittest.TestCase):
    def test_both_backends_delegate_to_the_shared_detector(self) -> None:
        """It chooses WHICH BINARY THE GATE EXECUTES; two copies could drift into two runtimes.

        Patched PER MODULE, not once on ``sandbox.oci``: ``observed.py`` does
        ``from sandbox.oci import detect_runtime``, which binds the name into its own namespace, so
        patching the definition site would not affect it. (My first version of this test made exactly
        that mistake and failed against correct code.)
        """
        for cls, module in ((OCISandbox, "sandbox.oci"), (ObservedOCISandbox, "sandbox.observed")):
            with mock.patch(f"{module}.detect_runtime", return_value="podman") as shared:
                self.assertEqual(cls._detect_runtime("img"), "podman")
            shared.assert_called_once_with("img")

    def test_shared_detector_is_the_same_object_from_both_modules(self) -> None:
        import sandbox.observed as obs
        self.assertIs(obs.detect_runtime, detect_runtime)


class ClientEnvIsAnAllowlist(unittest.TestCase):
    def test_host_environment_is_not_inherited(self) -> None:
        with mock.patch.dict(os.environ, {"ZZ_SENTINEL_SHOULD_NOT_LEAK": "1"}):
            env = runtime_client_env()
        self.assertNotIn("ZZ_SENTINEL_SHOULD_NOT_LEAK", env)

    def test_path_is_always_present(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertIn("PATH", runtime_client_env())

    def test_allowlisted_names_pass_through_when_present(self) -> None:
        with mock.patch.dict(os.environ, {"HOME": "/home/zz"}):
            self.assertEqual(runtime_client_env().get("HOME"), "/home/zz")

    def test_allowlisted_names_are_absent_when_unset(self) -> None:
        """An ABSENT variable must be absent, not empty-string: measured on the reference host, an
        absent HOME degrades correctly via getpwuid while a WRONG one fails loudly."""
        with mock.patch.dict(os.environ, {}, clear=True):
            env = runtime_client_env()
        for name in _CLIENT_ENV_PASSTHROUGH:
            self.assertNotIn(name, env, f"{name} was fabricated rather than passed through")


if __name__ == "__main__":
    unittest.main()
