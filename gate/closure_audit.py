"""gate/closure_audit.py — 3.4 close-2: the execution-closure audit tooling.

The 4-tuple identity (``core.identity``) is only SOUND if the digests it binds are TOTAL closures —
i.e. the host engine and the sandbox each execute nothing outside their content-addressed set. Two
audits enforce that:

  * AUTHORING-TIME dynamic-import gate (``assert_static_imports``): a detector that uses
    ``importlib`` / ``__import__`` / ``eval`` / ``exec`` can load code at RUNTIME that no static
    digest captures — a hole straight through the closure. This is a HARD gate at authoring time
    (refuse to package), not a warning at calibration time. Pure AST static analysis.

  * BUILD-TIME strace closure audit (``audit_strace``): the parser half — given ``strace`` output
    from running a detector inside the (pinned, --network=none) image, assert NO file is opened
    outside the image root + an explicit mount ALLOWLIST, and NO network syscall is made. Run the
    HOST-engine closure and the SANDBOX closure SEPARATELY (they are two distinct execution
    environments — the detector runs host-side, the artifact sandbox-side). The live strace run is a
    deploy/CI job (needs the real image + podman); this module is the reusable, unit-tested parser +
    allowlist check, so the audit LOGIC is proven here and only the run is deferred.
"""
from __future__ import annotations

import ast
import re
from typing import Sequence

# Calls that resolve code at runtime, defeating a static build digest.
_FORBIDDEN_CALLS = frozenset({"eval", "exec", "__import__", "compile"})
# Modules whose whole purpose is dynamic import.
_FORBIDDEN_IMPORT_ROOTS = frozenset({"importlib"})

# strace line shapes we care about (openat/open + the network syscalls).
_OPEN_RE = re.compile(r'\bopen(?:at)?\([^,]*,?\s*"([^"]+)"')
_NET_SYSCALLS = ("connect(", "sendto(", "sendmsg(", "socket(")


class DynamicImportError(ValueError):
    """A detector uses dynamic import / exec — its static build digest is not a total closure, so
    the 4-tuple identity binding would be spoofable. Refused at authoring time."""


class ClosureAuditError(RuntimeError):
    """The strace closure audit found an open outside the image/allowlist, or a network syscall."""


def assert_static_imports(source: str, *, name: str = "<detector>") -> None:
    """Raise ``DynamicImportError`` if ``source`` uses ``importlib`` / ``__import__`` / ``eval`` /
    ``exec`` / ``compile`` — the runtime-resolution escapes a static closure. A HARD authoring gate."""
    tree = ast.parse(source)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in _FORBIDDEN_IMPORT_ROOTS:
                    violations.append(f"import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in _FORBIDDEN_IMPORT_ROOTS:
                violations.append(f"from {node.module} import ...")
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in _FORBIDDEN_CALLS:
                violations.append(f"call to {node.func.id}()")
    if violations:
        raise DynamicImportError(
            f"{name}: dynamic import/exec breaks static execution closure — {violations}. "
            "Refactor to static imports before packaging (the 4-tuple identity requires a total closure)."
        )


def _within(path: str, image_root: str, allowed_prefixes: Sequence[str]) -> bool:
    return path.startswith(image_root) or any(path.startswith(p) for p in allowed_prefixes)


def audit_strace(
    strace_lines: Sequence[str],
    *,
    image_root: str = "/",
    allowed_prefixes: Sequence[str] = (),
) -> list[str]:
    """Parse ``strace`` output; return the list of closure violations (empty = clean). A violation
    is an ``openat`` to a path outside ``image_root`` + the ``allowed_prefixes`` mount allowlist, or
    any network syscall (the image must run ``--network=none``). The live run is deploy-side; this is
    the proven parser."""
    violations: list[str] = []
    for line in strace_lines:
        m = _OPEN_RE.search(line)
        if m:
            path = m.group(1)
            if not _within(path, image_root, allowed_prefixes):
                violations.append(f"open outside closure: {path}")
        if any(sc in line for sc in _NET_SYSCALLS):
            violations.append(f"network syscall (image must be --network=none): {line.strip()[:70]}")
    return violations


def assert_closure(
    strace_lines: Sequence[str],
    *,
    image_root: str = "/",
    allowed_prefixes: Sequence[str] = (),
) -> None:
    """Raise ``ClosureAuditError`` if ``audit_strace`` finds any violation. The gating form."""
    violations = audit_strace(strace_lines, image_root=image_root, allowed_prefixes=allowed_prefixes)
    if violations:
        raise ClosureAuditError(
            f"execution closure NOT total — {len(violations)} violation(s): {violations[:5]}"
        )


__all__ = [
    "DynamicImportError",
    "ClosureAuditError",
    "assert_static_imports",
    "audit_strace",
    "assert_closure",
]
