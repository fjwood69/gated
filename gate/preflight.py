"""gate/preflight.py — fail-closed STARTUP verifications (2.5).

A gate is only a gate if the platform is actually configured to require it. The most
dangerous deployment footgun in this whole architecture is INVISIBLE: if branch
protection requires a check name that does not EXACTLY match the name the App posts,
GitHub requires a check that never reports (blocks everything) — or, worse, the App's
check is merely advisory and merges proceed on non-PASS (FAIL-OPEN). Everything looks
healthy — checks post, PRs exist — but the check isn't actually required.

So the App VERIFIES, at startup, that the exact check name it posts is in the
protected branch's required-status-check contexts, and REFUSES TO START if not. A gate
that isn't verified-wired is theatre at the platform level.
"""
from __future__ import annotations

from typing import Any, Mapping


class ConfigurationError(RuntimeError):
    """The deployment is misconfigured such that the gate would not actually enforce.
    Fail closed: the App must refuse to start."""


def _required_check_names(protection: Mapping[str, Any]) -> set[str]:
    """Extract every required-status-check name from a GitHub branch-protection object
    (GET /repos/{o}/{r}/branches/{b}/protection). Handles both the legacy ``contexts``
    list and the newer ``checks`` list of ``{context, app_id}``."""
    rsc = protection.get("required_status_checks")
    if not isinstance(rsc, Mapping):
        return set()
    names: set[str] = set()
    contexts = rsc.get("contexts")
    if isinstance(contexts, list):
        names.update(str(c) for c in contexts)
    checks = rsc.get("checks")
    if isinstance(checks, list):
        for entry in checks:
            if isinstance(entry, Mapping) and "context" in entry:
                names.add(str(entry["context"]))
    return names


def verify_check_required(protection: Mapping[str, Any], check_name: str) -> None:
    """Assert the App's ``check_name`` is a REQUIRED status check on the protected
    branch. Raises ``ConfigurationError`` (fail-closed startup) if branch protection is
    absent, has no required checks, or requires a different name — any of which would
    silently make the gate advisory.

    Verified against the live API at startup (the App reads its own repo's protection),
    so a name typo / namespace drift can't ship a gate that does nothing."""
    required = _required_check_names(protection)
    if not required:
        raise ConfigurationError(
            "branch protection has NO required status checks — the gate would not "
            "enforce anything (fail-closed refuse-to-start)"
        )
    if check_name not in required:
        raise ConfigurationError(
            f"the App posts check {check_name!r} but branch protection requires "
            f"{sorted(required)!r} — the posted check is NOT required, so merges would "
            "proceed on non-PASS (fail-OPEN). Fix the name match before starting."
        )
