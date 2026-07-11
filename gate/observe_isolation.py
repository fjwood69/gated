"""gate/observe_isolation.py — 3.5 job-3: observe-mode isolation by STRUCTURAL ABSENCE.

"Observe mode" runs a detector in shadow (non-blocking) to watch a not-yet-enabled check in production.
The trap it must not fall into: a ``if mode == "observe"`` branch inside the enforce path. A shared code
path with a mode flag means one bug (or one cast) flips an observe result into an enforce verdict, or a
fork-bombing observe artifact crashes the enforce daemon. So observe is NOT a mode of the enforce path —
it does not exist there at all. This module makes that structural:

  * DISTINCT TYPE — an observe run yields an ``ObserveResult``, a different type from the enforce
    ``core.Verdict``. It is never blocking and carries no ``VerdictType``.
  * RUNTIME REJECTION (not typing — board careful-voice) — ``require_enforce_verdict`` tag-checks the
    ACTUAL object. A ``cast(Verdict, observe_result)`` defeats the type checker but not this: the
    runtime object is still an ``ObserveResult``, so it is REJECTED. Typing alone is insufficient; this
    is the teeth.
  * INFRA ISOLATION (fail-closed startup assertion) — ``assert_observe_enforce_isolated`` refuses to
    boot if observe and enforce share a podman socket, a check name, a worker pool, a service account,
    or a rate-limit bucket. A fork-bomb in observe cannot crash enforce (separate socket); a slow
    observe cannot starve enforce (separate quota); deleting observe cannot affect enforce (separate
    infra). The absence of a shared flag is proven by the AST done-test over the enforce path.

Gate-side; imports only ``core`` (the enforce Verdict type it guards). No engine, no other gate store.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

from core import Verdict


class ObserveResultLeakError(TypeError):
    """An ``ObserveResult`` (or anything that is not a genuine enforce ``Verdict``) was about to be
    used as an enforce verdict. Runtime-rejected — a cast cannot launder an observation into a
    merge-blocking decision."""


class ObserveIsolationError(RuntimeError):
    """Observe and enforce share an isolation-critical resource (socket / check name / worker pool /
    service account / rate-limit bucket). Fail-closed at startup: the App refuses to boot."""


@dataclass(frozen=True)
class ObserveResult:
    """The outcome of a SHADOW (observe-mode) run. Deliberately NOT a ``core.Verdict``: it has no
    ``VerdictType``, cannot map to a Check Run conclusion, and is never blocking. It writes to the
    observe store and drives no merge decision."""

    check_name: str
    observed_flows: int
    note: str = ""
    detail: Mapping[str, object] = field(default_factory=dict)

    # A structural tag: an explicit, checkable marker that this is an observation, not a verdict.
    is_observation: bool = True


def require_enforce_verdict(obj: object) -> Verdict:
    """Return ``obj`` iff it is a genuine enforce ``Verdict`` — else raise ``ObserveResultLeakError``.
    The RUNTIME rejection the board mandated over mere typing: this inspects the actual object, so an
    ``ObserveResult`` handed in via ``cast(Verdict, ...)`` is still caught (its runtime type is
    ``ObserveResult``, not ``Verdict``). Call this at the enforce path's verdict boundary — the point
    where a value becomes a merge-blocking conclusion."""
    if isinstance(obj, ObserveResult) or not isinstance(obj, Verdict):
        raise ObserveResultLeakError(
            f"expected an enforce Verdict at the merge-blocking boundary, got {type(obj).__name__} — "
            "an observation cannot become a verdict (runtime-rejected; a cast does not launder it)"
        )
    return obj


@dataclass(frozen=True)
class IsolationConfig:
    """The isolation-critical resources of one lane (observe or enforce). Two lanes must share NONE of
    these — that is what makes 'delete observe → enforce unaffected' and 'fork-bomb observe → enforce
    survives' structural rather than hopeful."""

    lane: str                 # "observe" | "enforce" (distinct check-name namespace, too)
    podman_socket: str        # separate sockets: a fork-bomb in one cannot crash the other's daemon
    check_name: str           # distinct Check Run names: observe never posts an enforce check
    worker_pool: str          # separate worker pools: observe scheduling cannot starve enforce
    service_account: str      # separate creds: observe cannot act with enforce's authority
    rate_limit_bucket: str    # NO shared bucket: observe cannot exhaust enforce's budget (starvation)


def assert_observe_enforce_isolated(observe: IsolationConfig, enforce: IsolationConfig) -> None:
    """Fail-closed startup assertion: raise ``ObserveIsolationError`` if observe and enforce share ANY
    isolation-critical resource. Wire this into the App's boot alongside the other fail-closed
    startup checks — an observe lane that shares enforce's socket / check / pool / creds / quota is a
    latent path for observe to affect enforce, and must prevent boot, not warn."""
    shared: list[str] = []
    for name, o, e in (
        ("podman_socket", observe.podman_socket, enforce.podman_socket),
        ("check_name", observe.check_name, enforce.check_name),
        ("worker_pool", observe.worker_pool, enforce.worker_pool),
        ("service_account", observe.service_account, enforce.service_account),
        ("rate_limit_bucket", observe.rate_limit_bucket, enforce.rate_limit_bucket),
    ):
        if o == e:
            shared.append(f"{name}={o!r}")
    if observe.lane == enforce.lane:
        shared.append(f"lane={observe.lane!r}")
    if shared:
        raise ObserveIsolationError(
            "observe and enforce must not share isolation-critical resources — shared: "
            + ", ".join(shared)
            + ". A fork-bomb, a slow run, or a deletion in observe would otherwise reach enforce."
        )


__all__ = [
    "ObserveResultLeakError",
    "ObserveIsolationError",
    "ObserveResult",
    "require_enforce_verdict",
    "IsolationConfig",
    "assert_observe_enforce_isolated",
]
