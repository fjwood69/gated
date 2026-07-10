"""gate/ratelimit.py — a per-source token bucket (transport-layer DoS bound).

The consult recommended rate-limiting the endpoint; this is that. HMAC is cheap, but
an unauthenticated flood still costs signature work + memory per request; a per-source
bucket caps it. It is DEFENCE-IN-DEPTH, not an auth control (GitHub has many source
IPs) — the cryptographic boundary remains the security wall. Lives in the transport
(it needs the client address), behind a Protocol so it is swappable.
"""
from __future__ import annotations

from typing import Callable, Protocol


class RateLimiter(Protocol):
    def allow(self, key: str) -> bool: ...


class TokenBucketRateLimiter:
    """Per-key token bucket: ``capacity`` tokens, refilled ``refill_per_sec``. Each
    request consumes one; an empty bucket denies (the transport maps that to 429).
    ``clock`` is injected (monotonic in production, a fake in tests) so the hot path
    carries no hidden wall-clock dependency."""

    def __init__(
        self, *, capacity: float, refill_per_sec: float, clock: Callable[[], float]
    ) -> None:
        self._capacity = capacity
        self._refill = refill_per_sec
        self._clock = clock
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_ts)

    def allow(self, key: str) -> bool:
        now = self._clock()
        tokens, last = self._state.get(key, (self._capacity, now))
        tokens = min(self._capacity, tokens + (now - last) * self._refill)
        if tokens < 1.0:
            self._state[key] = (tokens, now)
            return False
        self._state[key] = (tokens - 1.0, now)
        return True


class NullRateLimiter:
    """Allows everything — for tests / contexts where an upstream proxy rate-limits."""

    def allow(self, key: str) -> bool:
        return True


class RateLimitBudget:
    """Tracks GitHub's App rate limit from ``X-RateLimit-Remaining`` and sheds load
    BEFORE the quota is exhausted. A single team's PR burst (~5 API calls/PR: token,
    tarball, find, create, N×patch) can drain the 5000/hr installation budget and wedge
    ALL pending checks; when the remaining budget drops below ``floor`` the receiver
    stops accepting NEW webhooks (503 -> GitHub re-delivers later) and prioritises
    finishing in-flight jobs. Updated from each GitHub response's header."""

    def __init__(self, *, floor: int = 100) -> None:
        self._floor = floor
        self._remaining: int | None = None  # unknown until the first response

    def observe(self, remaining: int) -> None:
        """Record ``X-RateLimit-Remaining`` from a GitHub response."""
        self._remaining = remaining

    def accepting(self) -> bool:
        """True if there is budget to start new work. Unknown budget = accept (we
        haven't hit GitHub yet); known-and-low = shed."""
        return self._remaining is None or self._remaining > self._floor

    @property
    def remaining(self) -> int | None:
        return self._remaining
