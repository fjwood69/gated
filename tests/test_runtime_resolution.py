"""P2a — one runtime resolution, one client-env policy, across every invocation site.

Two properties, both asserted STATICALLY over the ``sandbox`` package rather than by driving each call
site, because a behavioural test can only reach the sites a test host can actually run:

  1. every runtime invocation uses the RESOLVED ABSOLUTE PATH as ``argv[0]``, never the bare audited
     name — a slash-less ``argv[0]`` is resolved by ``Popen`` via the PATH *in the passed env dict*, so
     a trojaned binary on an early PATH entry would execute as the gate during a verdict run;
  2. every runtime invocation passes the ONE client-env policy — before P2a, 18 of 20 passed no ``env=``
     at all and inherited the whole host environment, including the capability probe that decides
     whether the gate can run.

Why static. The P1 binding tests were verified NOT to catch a bare-name regression: they compare the
create argv against ``network_create_argv(runtime, ...)`` with whatever the caller passed, so reverting
``_runtime_path`` to ``_runtime`` leaves them green. That was checked by reintroducing the defect. A
property about *every* site needs a check that sees every site.

``ast`` only — no ``tokenize``, no f-string token counts. A prior test in this tree depended on PEP 701
tokenisation and would have failed on CPython 3.9/3.10/3.11, three of the five versions in the matrix.

THE SWEEP'S POLARITY, which is the whole design and was WRONG in the first version of this file.

The first version enumerated ONE KNOWN-BAD shape (``head.attr == "_runtime"``) and skipped everything it
did not recognise — including, fatally, ``cmd = [...]`` followed by ``Popen(cmd)``, which is the shape of
BOTH artifact-executing ``run()`` sites. Reverting both of those to the bare name left the entire suite
green: the assertion could not fail at the sites that execute as the gate during a verdict. It was a
claim, not a control.

Enumerating known-bad shapes cannot work here, because the evasion set is unbounded — ``f"{self._runtime}"``
(``JoinedStr``), ``self._runtime_path or self._runtime`` (``BoolOp``), ``base + [...]`` (``BinOp``),
``cmd.insert(0, …)`` after a compliant assign, two-branch reassignment, ``shlex.split(...)``, a helper
returning the argv. So the polarity is inverted, per the board's ruling:

    When the sweep cannot PROVE that ``argv[0]`` is the resolved path, it FLAGS. It never SKIPS.

``_pinned_argv0`` below is that proof obligation, and everything it does not recognise is an offender —
including shapes that are perfectly correct but unproven. A new-but-fine construction makes this test go
red and the fix is to teach it the provenance, not to loosen it.

ONE TIGHTENING of the ruling as written, flagged rather than folded in silently. The ruling admitted "a
``Name`` bound by every ``Assign`` in scope to a ``resolve_runtime_path(...)`` call". That function is
exactly the one whose contract permits a NON-absolute return — it is the finding this remediation
exists to close — so admitting it as pinned provenance would re-open the hole the same day it was
closed. Pinned provenance here is therefore restricted to resolvers that either REFUSE a non-absolute
result (``_exec_runtime`` / ``exec_runtime_path``) or make it unrepresentable at the argv
(``_resolved_or_none``, whose ``None`` branch ``mypy --strict`` refuses to put in a ``list[str]``).
"""
from __future__ import annotations

import ast
import os
import pathlib
import shutil
import unittest
from unittest import mock

from sandbox.oci import (
    OCISandbox,
    RuntimePathUnresolved,
    _CLIENT_ENV_PASSTHROUGH,
    _resolved_or_none,
    client_path,
    detect_runtime,
    exec_runtime_path,
    require_resolved_runtime,
    resolve_runtime_path,
    runtime_client_env,
)
from sandbox.observed import ObservedOCISandbox

_PKG = pathlib.Path(__file__).resolve().parent.parent / "sandbox"

# --------------------------------------------------------------------------------------------------
# DISCOVERY — package-wide MINUS recorded exclusions.
#
# INVERTED from the first version, which was an inclusion list (``("oci.py", "observed.py")``) while the
# module docstring claimed the sweep covered "the whole sandbox package". A third runtime-invoking module
# would have been silently unswept — the sweep would have reported a clean tree it had never looked at.
# Now a new module is swept by default and an exclusion must be WRITTEN DOWN WITH A REASON, which is the
# only form in which the coverage boundary is reviewable.
# --------------------------------------------------------------------------------------------------
_EXCLUDED_MODULES = {
    "__init__.py": "re-exports only — contains no call of any kind",
    "base.py": "abstract RAII session() over the backend primitives; execs nothing",
    "noop.py": "in-process stub backend; execs nothing",
    "subprocess.py": (
        "the WEAK backend execs the ARTIFACT directly as a host process, so it is not a container-runtime "
        "invocation and P2a's argv[0]/client-env policy does not apply to it. Recorded rather than "
        "silently skipped, because the exclusion is a CLAIM: that backend passes no env= at all, so it "
        "runs the artifact with the FULL host environment. WEAK is documented as insufficient for a real "
        "merge gate, so that is a separate question — but it is a question, not a non-issue."
    ),
}

# --------------------------------------------------------------------------------------------------
# PINNED PROVENANCE — the positive shapes, and nothing else.
# --------------------------------------------------------------------------------------------------
# Resolvers that REFUSE a non-absolute result. Their return value may be argv[0] directly.
_ENFORCING_RESOLVERS = ("_exec_runtime", "exec_runtime_path")
# Resolvers that cannot RETURN a non-absolute string — they return ``None`` instead. Valid provenance for
# a Name because the ``None`` branch cannot reach a ``list[str]`` under ``mypy --strict``: the guard is
# compiler-enforced, not review-enforced.
_PROVING_RESOLVERS = ("_resolved_or_none",)

# Functions that RETURN an argv. ``{name: index of the parameter that becomes argv[0]}``.
_ARGV_BUILDERS = {
    "network_create_argv": 0,
    # P2b posture builders. Registering them here is what lets the argv[0] assertion see through a
    # builder call: each takes the resolved runtime as parameter 0 and returns the argv verbatim.
    "capability_probe_argv": 0,
    "artifact_run_argv": 0,
    "proxy_run_argv": 0,
    "escape_probe_argv": 0,
}
# Functions that RECEIVE a built argv and exec it. ``{name: index of the argv parameter}``.
_ARGV_CONSUMERS = {"probe_existence": 0, "_names": 0, "_rm": 0}

# Methods that would rewrite a list after a compliant assignment.
_MUTATORS = ("insert", "append", "extend", "__setitem__")

# Never permitted on a runtime invocation. ``executable=`` OVERRIDES ``argv[0]`` — VERIFIED:
# ``Popen(['/bin/false'], executable='/bin/true')`` returns 0. So a pinned argv[0] proves nothing about
# which binary ran if this keyword is present, and the pin would be decorative. ``shell=`` hands the
# whole command to ``/bin/sh`` and re-opens PATH resolution wholesale.
_FORBIDDEN_KWARGS = ("executable", "shell")

# --------------------------------------------------------------------------------------------------
# EXEMPTIONS — scoped to ONE named assertion each, with a mandatory reason.
#
# The first version had a single set, ``_ARGV_FROM_CALLER``, justified for ARGV OWNERSHIP and then
# consumed ONLY by the ENV assertion: granted where it had never been justified (and unnecessary there,
# since that site does pass ``env=``), and justified where it was never consumed. An exemption is scoped
# to the assertion it was argued for; anything else is an exemption by adjacency.
# --------------------------------------------------------------------------------------------------
_ASSERTIONS = ("argv0_is_pinned", "env_is_the_policy", "no_forbidden_kwargs")

_ARGV_FROM_CALLER = (
    "receives a fully-built argv from its callers and execs it verbatim, so argv[0] is not this "
    "function's to own. The compensating control is test_registered_argv_sinks_receive_a_pinned_head, "
    "which sweeps every CALL SITE of this function for a pinned head — the exemption moves the "
    "obligation, it does not discharge it."
)

# {swept site qualname: (CLASS, the ONE assertion it applies to, why)}
_EXEMPTIONS: dict[str, tuple[str, str, str]] = {
    "sandbox/oci.py::probe_existence": ("ARGV_FROM_CALLER", "argv0_is_pinned", _ARGV_FROM_CALLER),
    "sandbox/observed.py::reap_orphans._names": ("ARGV_FROM_CALLER", "argv0_is_pinned", _ARGV_FROM_CALLER),
    "sandbox/observed.py::reap_orphans._rm": ("ARGV_FROM_CALLER", "argv0_is_pinned", _ARGV_FROM_CALLER),
}


def _exempt(where: str, assertion: str) -> bool:
    """True only if ``where`` is exempt from THIS assertion. Each assertion consults its own keys."""
    entry = _EXEMPTIONS.get(where)
    return entry is not None and entry[1] == assertion


def _callee(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


class _Scope:
    """One function body, with the bindings and mutations visible in it.

    Scoped rather than flat because the first version walked ``ast.walk`` over each top-level function
    AND over the nested functions inside it, so ``reap_orphans``'s ``_names``/``_rm`` were each found
    TWICE — once labelled ``reap_orphans``, once themselves. That made exemption keys ambiguous and
    inflated the site count the vacuity guard checks against.
    """

    def __init__(self, module: str, qualname: str) -> None:
        self.where = f"sandbox/{module}::{qualname}" if qualname else f"sandbox/{module}"
        self.assigns: dict[str, list[ast.expr]] = {}
        self.mutated: set[str] = set()
        self.execs: list[ast.Call] = []
        self.sinks: list[ast.Call] = []
        self.builders: list[ast.Call] = []

    # -- proof obligations ---------------------------------------------------------------------
    def pinned_argv0(self, node: ast.expr) -> bool:
        """``node`` becomes ``argv[0]``. Provable, or an offender — there is no third answer."""
        if isinstance(node, ast.Call):
            return _callee(node.func) in _ENFORCING_RESOLVERS
        if isinstance(node, ast.Name):
            if node.id in self.mutated:
                return False
            bindings = self.assigns.get(node.id)
            return bool(bindings) and all(
                isinstance(b, ast.Call)
                and _callee(b.func) in _ENFORCING_RESOLVERS + _PROVING_RESOLVERS
                for b in bindings
            )
        return False

    def pinned_argv(self, node: ast.expr) -> bool:
        """``node`` is the whole argv."""
        if isinstance(node, ast.List):
            return bool(node.elts) and self.pinned_argv0(node.elts[0])
        if isinstance(node, ast.Call):
            pos = _ARGV_BUILDERS.get(_callee(node.func))
            return pos is not None and len(node.args) > pos and self.pinned_argv0(node.args[pos])
        if isinstance(node, ast.Name):
            if node.id in self.mutated:
                return False
            bindings = self.assigns.get(node.id)
            return bool(bindings) and all(self.pinned_argv(b) for b in bindings)
        return False


def _exec_aliases(tree: ast.Module) -> tuple[set[str], set[str]]:
    """Every local spelling of ``subprocess.run`` / ``subprocess.Popen`` in this module.

    The first version matched ``f.value.id == "subprocess"`` — one spelling. ``import subprocess as sp``
    or ``from subprocess import run`` was invisible, so a site could opt out of the sweep with an import.
    NB ``from sandbox.subprocess import …`` must NOT match: the package shadows the stdlib name.
    """
    modules, bare = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "subprocess":
                    modules.add(a.asname or a.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess" and not node.level:
                for a in node.names:
                    if a.name in ("run", "Popen"):
                        bare.add(a.asname or a.name)
    return modules, bare


def _scopes_of(module: str, source: str) -> list[_Scope]:
    """Every function scope in one module, each holding only the calls DIRECTLY inside it."""
    tree = ast.parse(source)
    modules, bare = _exec_aliases(tree)
    scopes: list[_Scope] = []

    def is_exec(call: ast.Call) -> bool:
        f = call.func
        if isinstance(f, ast.Attribute) and f.attr in ("run", "Popen"):
            return isinstance(f.value, ast.Name) and f.value.id in modules
        return isinstance(f, ast.Name) and f.id in bare

    def walk(node: ast.AST, qual: str, scope: _Scope | None) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{qual}.{child.name}" if qual else child.name
                inner = _Scope(module, name)
                scopes.append(inner)
                walk(child, name, inner)
                continue
            if isinstance(child, ast.ClassDef):
                walk(child, f"{qual}.{child.name}" if qual else child.name, scope)
                continue
            if scope is not None:
                if isinstance(child, ast.Assign):
                    for t in child.targets:
                        if isinstance(t, ast.Name):
                            scope.assigns.setdefault(t.id, []).append(child.value)
                        elif isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name):
                            scope.mutated.add(t.value.id)  # cmd[0] = …
                elif isinstance(child, ast.AugAssign) and isinstance(child.target, ast.Name):
                    scope.mutated.add(child.target.id)
                elif isinstance(child, ast.Call):
                    f = child.func
                    if isinstance(f, ast.Attribute) and f.attr in _MUTATORS and isinstance(f.value, ast.Name):
                        scope.mutated.add(f.value.id)
                    if is_exec(child):
                        scope.execs.append(child)
                    callee = _callee(f)
                    if callee in _ARGV_CONSUMERS:
                        scope.sinks.append(child)
                    if callee in _ARGV_BUILDERS:
                        scope.builders.append(child)
            walk(child, qual, scope)

    walk(tree, "", None)
    return scopes


def _swept_modules() -> list[str]:
    return sorted(p.name for p in _PKG.glob("*.py") if p.name not in _EXCLUDED_MODULES)


def _all_scopes() -> list[_Scope]:
    out: list[_Scope] = []
    for name in _swept_modules():
        out.extend(_scopes_of(name, (_PKG / name).read_text(encoding="utf-8")))
    return out


def _env_is_policy(scope: _Scope, call: ast.Call) -> bool:
    """``env=`` must BE the one policy, not merely be present.

    Presence is not policy: the first version accepted ``any(k.arg == "env")``, under which ``env=None``
    (inherit nothing — breaks the runtime) and ``env=os.environ`` (inherit everything — the exact defect
    P2a closed) both passed.
    """
    for kw in call.keywords:
        if kw.arg != "env":
            continue
        v = kw.value
        if isinstance(v, ast.Call):
            return _callee(v.func) == "runtime_client_env"
        if isinstance(v, ast.Name):
            bindings = scope.assigns.get(v.id)
            return bool(bindings) and all(
                isinstance(b, ast.Call) and _callee(b.func) == "runtime_client_env" for b in bindings
            )
        return False
    return False


def _argv_of(call: ast.Call) -> ast.expr | None:
    """The argv expression, positional OR keyword.

    ``if not call.args: continue`` in the first version skipped ``Popen(args=…)`` entirely — a keyword
    spelling of the very thing being asserted about.
    """
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg == "args":
            return kw.value
    return None


class Argv0IsAlwaysResolved(unittest.TestCase):
    def test_no_invocation_uses_an_unproven_argv0(self) -> None:
        """Every runtime invocation's ``argv[0]`` must be PROVABLY the resolved absolute path."""
        offenders = []
        for scope in _all_scopes():
            if _exempt(scope.where, "argv0_is_pinned"):
                continue
            for call in scope.execs:
                argv = _argv_of(call)
                if argv is None or not scope.pinned_argv(argv):
                    shape = type(argv).__name__ if argv is not None else "no-argv-argument"
                    offenders.append(f"{scope.where} (line {call.lineno}, argv shape: {shape})")
        self.assertEqual(
            offenders, [],
            "these runtime invocations do not PROVABLY use the resolved absolute path as argv[0]. "
            "If the construction is in fact correct, teach _Scope.pinned_argv0 its provenance — do not "
            f"weaken the check: {offenders}",
        )

    def test_registered_argv_sinks_receive_a_pinned_head(self) -> None:
        """The obligation the ARGV_FROM_CALLER exemption moves, discharged at the call sites.

        A literal passed to a plain function was invisible to the first version under either polarity:
        it swept only ``subprocess.*`` calls, so ``probe_existence([self._runtime, …])`` and the
        reaper's ``_names``/``_rm`` calls were never examined at all.
        """
        offenders = []
        for scope in _all_scopes():
            for call in scope.sinks:
                pos = _ARGV_CONSUMERS[_callee(call.func)]
                if len(call.args) <= pos or not scope.pinned_argv(call.args[pos]):
                    offenders.append(f"{scope.where} -> {_callee(call.func)}() (line {call.lineno})")
            for call in scope.builders:
                pos = _ARGV_BUILDERS[_callee(call.func)]
                if len(call.args) <= pos or not scope.pinned_argv0(call.args[pos]):
                    offenders.append(f"{scope.where} -> {_callee(call.func)}() (line {call.lineno})")
        self.assertEqual(offenders, [], f"argv sinks/builders handed an unproven argv[0]: {offenders}")

    def test_every_invocation_passes_the_client_env_policy(self) -> None:
        offenders = [
            f"{scope.where} (line {call.lineno})"
            for scope in _all_scopes()
            if not _exempt(scope.where, "env_is_the_policy")
            for call in scope.execs
            if not _env_is_policy(scope, call)
        ]
        self.assertEqual(
            offenders, [],
            f"these runtime invocations do not pass env=runtime_client_env(): {offenders}",
        )

    def test_no_invocation_can_override_argv0(self) -> None:
        """``executable=`` beats ``argv[0]``; ``shell=`` re-opens PATH resolution wholesale."""
        offenders = [
            f"{scope.where} (line {call.lineno}, {kw.arg}=)"
            for scope in _all_scopes()
            if not _exempt(scope.where, "no_forbidden_kwargs")
            for call in scope.execs
            for kw in call.keywords
            if kw.arg in _FORBIDDEN_KWARGS
        ]
        self.assertEqual(
            offenders, [],
            "executable= overrides argv[0] and shell= bypasses it, so either makes the pin "
            f"decorative: {offenders}",
        )


class TheSweepIsNotVacuous(unittest.TestCase):
    """Guard the guard. Every assertion above passes trivially on a sweep that finds nothing."""

    def test_the_sweep_finds_the_invocations(self) -> None:
        execs = sum(len(s.execs) for s in _all_scopes())
        self.assertGreaterEqual(
            execs, 12,
            "the AST sweep found implausibly few runtime invocations — it is probably not matching, "
            "which would make every assertion above pass while checking nothing",
        )

    def test_the_sweep_finds_the_sink_and_builder_call_sites(self) -> None:
        scopes = _all_scopes()
        self.assertGreaterEqual(sum(len(s.sinks) for s in scopes), 6, "argv-consumer call sites unswept")
        self.assertGreaterEqual(sum(len(s.builders) for s in scopes), 1, "argv-builder call sites unswept")

    def test_both_artifact_run_sites_are_swept(self) -> None:
        """NAMED, because these two are the ones the first version could not see.

        They build ``cmd = [...]`` and pass the NAME to ``Popen``, so a sweep that inspected only inline
        list literals skipped exactly the sites that exec as the gate during a verdict. Reverting both to
        the bare name left the whole suite green. A test seen to fail at one site is only a claim about
        every other site — so these two are asserted by name rather than by count.
        """
        swept = {s.where for s in _all_scopes() if s.execs}
        for site in ("sandbox/oci.py::OCISandbox.run", "sandbox/observed.py::ObservedOCISandbox.run"):
            self.assertIn(site, swept, f"{site} is not swept — it is the verdict-executing invocation")

    def test_every_registered_sink_and_builder_is_actually_called(self) -> None:
        """A registry entry naming a function nobody calls is an INERT rule that reads as a live one.

        Renaming ``_names`` would silently empty its entry. The exemption-staleness test catches that
        case indirectly — the exemption key would go stale — but only because those two happen to be
        exempt. A consumer or builder with no exemption has no such backstop, so assert the registry
        against the tree directly.

        NB registration is by BARE NAME, not qualified name: an unrelated same-named function elsewhere
        in the package would be swept too. That is the safe direction (a spurious red, never a silent
        pass), but it is a real property of this registry and not an accident.
        """
        called: set[str] = set()
        for scope in _all_scopes():
            called.update(_callee(c.func) for c in scope.sinks)
            called.update(_callee(c.func) for c in scope.builders)
        for name in tuple(_ARGV_CONSUMERS) + tuple(_ARGV_BUILDERS):
            self.assertIn(
                name, called,
                f"registered argv sink/builder {name!r} is never called in the swept tree — the "
                "registry entry is stale and enforcing nothing",
            )

    def test_every_swept_module_is_accounted_for(self) -> None:
        """A module is swept or its exclusion is written down. There is no third state."""
        on_disk = {p.name for p in _PKG.glob("*.py")}
        self.assertEqual(
            on_disk - set(_EXCLUDED_MODULES) - set(_swept_modules()), set(),
            "a module is neither swept nor excluded",
        )
        self.assertEqual(
            set(_EXCLUDED_MODULES) - on_disk, set(),
            "an exclusion names a module that no longer exists — stale coverage boundary",
        )
        for name, reason in _EXCLUDED_MODULES.items():
            self.assertTrue(reason.strip(), f"exclusion of {name} carries no reason")


class ExemptionsAreScopedAndFresh(unittest.TestCase):
    """§2.4. The comment on the first version promised stale keys would be visible; nothing delivered it,
    so a typo'd key was silently inert — an exemption that exempts nothing, reading as a live one."""

    def test_every_exemption_key_names_a_real_swept_site(self) -> None:
        swept = {s.where for s in _all_scopes()}
        self.assertEqual(
            set(_EXEMPTIONS) - swept, set(),
            "these exemption keys match no swept site — a typo'd key is invisible without this test",
        )

    def test_every_exemption_names_one_real_assertion_and_a_reason(self) -> None:
        for where, (cls, assertion, reason) in _EXEMPTIONS.items():
            self.assertIn(assertion, _ASSERTIONS, f"{where} exempts an unknown assertion {assertion!r}")
            self.assertTrue(cls.strip(), f"{where} has no exemption CLASS")
            self.assertTrue(reason.strip(), f"{where} has no reason")

    def test_an_exemption_does_not_leak_to_other_assertions(self) -> None:
        for where, (_cls, assertion, _reason) in _EXEMPTIONS.items():
            for other in _ASSERTIONS:
                if other != assertion:
                    self.assertFalse(
                        _exempt(where, other),
                        f"{where}'s exemption for {assertion!r} also grants {other!r}",
                    )

    def test_argv_exempt_sites_still_pass_the_env_assertion(self) -> None:
        """The exemption is for argv OWNERSHIP only — those sites do pass ``env=``, and must keep doing so."""
        by_where = {s.where: s for s in _all_scopes()}
        for where, (_cls, assertion, _reason) in _EXEMPTIONS.items():
            if assertion != "argv0_is_pinned":
                continue
            scope = by_where[where]
            for call in scope.execs:
                self.assertTrue(
                    _env_is_policy(scope, call),
                    f"{where} is exempt from the argv assertion but must still pass the env policy",
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
        """Import-time safety: raising in the resolver would make importing the package fail on a host
        without that runtime. Refusal belongs at the exec boundary, one invocation at a time."""
        self.assertEqual(resolve_runtime_path("zz-definitely-not-on-path"), "zz-definitely-not-on-path")


class AResolvedPathIsAlwaysAbsolute(unittest.TestCase):
    """§2.1 — the pin could be FALSE while labelled TRUE, and nothing asserted otherwise.

    ``resolve_runtime_path``'s docstring said "the absolute path"; ``shutil.which()`` returns a RELATIVE
    path whenever the matching PATH entry is relative. So ``_runtime_path`` — the single value the whole
    argv[0] control exists to pin — could be CWD-relative, carrying a stamp that said it was not. The
    old test asserted absolute INPUT was preserved and never asserted the OUTPUT was absolute at all.
    """

    def test_a_relative_which_hit_is_not_a_resolution(self) -> None:
        with mock.patch.object(shutil, "which", return_value="reldir/zzruntime"):
            got = resolve_runtime_path("zzruntime")
        self.assertFalse(os.path.isabs("reldir/zzruntime"), "premise: the stubbed hit is relative")
        self.assertEqual(got, "zzruntime", "a relative which() hit must be treated as UNRESOLVED")

    def test_resolution_searches_the_path_the_invocation_will_carry(self) -> None:
        """Resolving against the host PATH while EXECUTING with a different PATH in the env dict is how
        argv[0] ends up naming a binary the client would never have found.

        (A second mechanism was proposed for the finding above and is REFUTED on this platform: an unset
        PATH does not fall back to a CWD-searching default, because ``os.defpath`` is ``/bin:/usr/bin``
        with no empty entry. Asserted here as the MECHANISM — an explicit ``path=`` — rather than as a
        fact about ``os.defpath``, so the guarantee does not rest on the premise that was wrong.)
        """
        with mock.patch.object(shutil, "which", return_value="/usr/bin/zzruntime") as which:
            resolve_runtime_path("zzruntime")
        self.assertEqual(which.call_args.kwargs.get("path"), client_path())
        self.assertEqual(runtime_client_env()["PATH"], client_path(), "one PATH, both purposes")

    def test_the_exec_boundary_refuses_a_relative_path(self) -> None:
        with self.assertRaises(RuntimePathUnresolved):
            require_resolved_runtime("zzruntime", "reldir/zzruntime")

    def test_the_exec_boundary_accepts_a_valid_absolute_path(self) -> None:
        """The KNOWN-GOOD side, named — the other half of a two-sided control.

        ``require_resolved_runtime`` is the single point of correctness for every runtime invocation
        (12 execution flows converge on it — corroborated independently by the call graph), which is the
        concentration the fused-boundary design deliberately accepts. The cost of that concentration is
        that "refuses the bad" and "refuses EVERYTHING" are indistinguishable from the refusal
        assertions alone: a guard that raised unconditionally would satisfy every one of them.

        The acceptance assertions did already exist, but only as second assertions inside tests whose
        NAMES say "refuses". An unnamed property is one a later edit can weaken without any test's
        title objecting, so it is lifted out here and discharged in its own right: verified RED by
        making the raise unconditional.

        All three shapes, because each is a distinct entry point: the bare guard, the fused
        module-level resolver, and the fused method on both backends.
        """
        self.assertEqual(require_resolved_runtime("podman", "/usr/bin/podman"), "/usr/bin/podman")
        self.assertEqual(exec_runtime_path("/opt/bin/podman"), "/opt/bin/podman")
        for cls in (OCISandbox, ObservedOCISandbox):
            sbx = cls.__new__(cls)
            sbx._runtime, sbx._runtime_path = "podman", "/usr/bin/podman"
            self.assertEqual(
                sbx._exec_runtime(), "/usr/bin/podman",
                f"{cls.__name__} refused a VALID absolute argv[0] — the guard rejects everything",
            )

    def test_exec_runtime_path_refuses_an_unresolvable_name(self) -> None:
        with self.assertRaises(RuntimePathUnresolved):
            exec_runtime_path("zz-definitely-not-on-path")

    def test_a_sandbox_refuses_to_build_an_argv_around_a_bare_name(self) -> None:
        """The enforcement point. ``_runtime_path`` is writable and IS written by tests, so the check has
        to be on the value at use — not on what ``__init__`` happened to compute."""
        for cls in (OCISandbox, ObservedOCISandbox):
            sbx = cls.__new__(cls)
            sbx._runtime, sbx._runtime_path = "podman", "podman"
            with self.assertRaises(RuntimePathUnresolved, msg=f"{cls.__name__} accepted a bare argv[0]"):
                sbx._exec_runtime()
            sbx._runtime_path = "/usr/bin/podman"
            self.assertEqual(sbx._exec_runtime(), "/usr/bin/podman")

    def test_refusal_is_an_oci_runtime_unavailable_so_available_reports_false(self) -> None:
        """Fail CLOSED through the EXISTING handlers rather than past them."""
        with mock.patch("sandbox.oci.detect_runtime", side_effect=RuntimePathUnresolved("no path")):
            self.assertFalse(OCISandbox.available("img"))

    def test_detection_skips_a_candidate_that_resolves_relatively(self) -> None:
        """``detect_runtime`` must SKIP an unresolvable candidate and try the next, not raise on the
        first — so its resolver narrows to 'absolute or None' rather than refusing."""
        self.assertIsNone(_resolved_or_none("zz-definitely-not-on-path"))
        with mock.patch.object(shutil, "which", return_value="reldir/podman"):
            self.assertIsNone(_resolved_or_none("podman"))
        with mock.patch("sandbox.oci._resolved_or_none", return_value=None):
            with self.assertRaises(Exception) as caught:
                detect_runtime("img")
        self.assertIn("fail closed", str(caught.exception))


class OneDetectImplementation(unittest.TestCase):
    def test_both_backends_delegate_to_the_shared_detector(self) -> None:
        """It chooses WHICH BINARY THE GATE EXECUTES; two copies could drift into two runtimes.

        Patched PER MODULE, not once on ``sandbox.oci``: ``observed.py`` does
        ``from sandbox.oci import detect_runtime``, which binds the name into its own namespace, so
        patching the definition site would not affect it. (My first version of this test made exactly
        that mistake and failed against correct code — a red test is disagreement between test and code,
        not proof of a defect.)
        """
        for cls, module in ((OCISandbox, "sandbox.oci"), (ObservedOCISandbox, "sandbox.observed")):
            with mock.patch(f"{module}.detect_runtime", return_value="podman") as shared:
                self.assertEqual(cls._detect_runtime("img"), "podman")
            shared.assert_called_once_with("img")

    def test_shared_detector_is_the_same_object_from_both_modules(self) -> None:
        import sandbox.observed as obs
        self.assertIs(obs.detect_runtime, detect_runtime)

    def test_the_exec_boundary_is_one_implementation(self) -> None:
        self.assertIs(OCISandbox._exec_runtime, ObservedOCISandbox._exec_runtime)


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
