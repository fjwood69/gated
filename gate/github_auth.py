"""gate/github_auth.py — GitHub App installation-token provider (Increment 2.2).

Runs ONLY on the single gate service — the one place with the App private key.
Developers never touch this; they just open PRs. It mints short-lived, least-privilege
(`checks:write`) installation tokens to post Check Runs.

Built against SEAMS so the substantive logic — App-JWT claim bounds, the per-installation
token cache with a refresh margin, and permission scoping — is tested with fakes NOW.
The two LIVE-ONLY adapters are deferred to the App wire-up (Fork-2 ruling: PyJWT,
isolated to this module; the dependency is added only when those land):

  * ``JwtSigner``   — real impl signs the claims RS256 with PyJWT.
  * ``TokenFetcher`` — real impl POSTs /app/installations/{id}/access_tokens over HTTPS.

Consult-ratified constants: iat back-dated for clock skew; exp <= GitHub's 10-min max;
the App JWT is used ONLY to mint the installation token; tokens cached ~50 min with a
5-min refresh margin, never logged or persisted.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

_APP_JWT_EXP_SECONDS = 9 * 60      # <= GitHub's 10-minute ceiling
_APP_JWT_IAT_BACKDATE = 60         # clock-skew guard: iat a minute in the past
_TOKEN_REFRESH_MARGIN = 5 * 60     # re-mint 5 min before expiry (never serve near-stale)


class KeyMissingError(RuntimeError):
    """The App private key is unavailable. Fail closed — never sign with an absent key."""


class KeySource(Protocol):
    """The App private key (PEM). Behind a seam: env / secret-manager, in-memory only,
    never committed or baked into an image."""

    def private_key_pem(self) -> bytes: ...


class EnvKeySource:
    """Reference backend: read the PEM from an env var. Deployment swaps this for a
    secret-manager backend implementing the same Protocol."""

    def __init__(self, var: str = "GATED_APP_PRIVATE_KEY") -> None:
        self._var = var

    def private_key_pem(self) -> bytes:
        value = os.environ.get(self._var)
        if not value:
            raise KeyMissingError(f"App private key env var {self._var!r} is unset or empty")
        return value.encode("utf-8")


class FileKeySource:
    """Read the PEM from a file path — the deployment shape (a secret-manager mounts the
    key to a path). In-memory only after read; never logged."""

    def __init__(self, path: str) -> None:
        self._path = path

    def private_key_pem(self) -> bytes:
        if not os.path.exists(self._path):
            raise KeyMissingError(f"App private key not found at {self._path!r}")
        with open(self._path, "rb") as f:
            data = f.read()
        if not data:
            raise KeyMissingError(f"App private key at {self._path!r} is empty")
        return data


@dataclass(frozen=True)
class AppJwtClaims:
    """The GitHub App authentication JWT payload (RFC 7519 subset GitHub requires)."""

    iss: str  # the App id (as a string)
    iat: int  # issued-at, back-dated for clock skew
    exp: int  # expiry, <= iat + 10 min


class JwtSigner(Protocol):
    """Signs App-JWT claims with RS256. Real impl = PyJWT (deferred to live wiring)."""

    def sign_rs256(self, claims: AppJwtClaims, private_key_pem: bytes) -> str: ...


@dataclass(frozen=True)
class InstallationToken:
    token: str
    expires_at: int  # epoch seconds


class TokenFetcher(Protocol):
    """Exchanges an App JWT for an installation token scoped to ``permissions``. Real
    impl = HTTPS POST /app/installations/{id}/access_tokens (deferred to live wiring)."""

    def fetch(
        self, *, app_jwt: str, installation_id: int, permissions: Mapping[str, str]
    ) -> InstallationToken: ...


def build_app_jwt_claims(app_id: int, now: int) -> AppJwtClaims:
    """iat back-dated (clock skew), exp within GitHub's 10-min ceiling."""
    return AppJwtClaims(
        iss=str(app_id),
        iat=now - _APP_JWT_IAT_BACKDATE,
        exp=now + _APP_JWT_EXP_SECONDS,
    )


class InstallationTokenProvider:
    """Mints + caches least-privilege installation tokens, per installation.

    ``clock`` is injected (monotonic/epoch in production, a fake in tests) so the cache
    logic carries no hidden wall-clock dependency. Tokens are held in memory only and
    never logged.
    """

    def __init__(
        self,
        *,
        app_id: int,
        key_source: KeySource,
        signer: JwtSigner,
        fetcher: TokenFetcher,
        clock: Callable[[], float],
        permissions: Mapping[str, str] | None = None,
    ) -> None:
        self._app_id = app_id
        self._key_source = key_source
        self._signer = signer
        self._fetcher = fetcher
        self._clock = clock
        # Least privilege: only what posting a Check Run needs.
        self._permissions: dict[str, str] = dict(permissions or {"checks": "write"})
        self._cache: dict[int, InstallationToken] = {}

    def get_valid_token(self, installation_id: int) -> str:
        """Explicit alias for ``token_for`` — call this at JOB-START / POST-time, never
        cache a token from enqueue: a job may sit queued past the token's life under
        backpressure. Freshness (refresh-margin) is re-checked on every call."""
        return self.token_for(installation_id)

    def token_for(self, installation_id: int) -> str:
        now = int(self._clock())
        cached = self._cache.get(installation_id)
        if cached is not None and cached.expires_at - now > _TOKEN_REFRESH_MARGIN:
            return cached.token
        # Mint fresh: App JWT (used ONLY to exchange) -> installation token.
        claims = build_app_jwt_claims(self._app_id, now)
        app_jwt = self._signer.sign_rs256(claims, self._key_source.private_key_pem())
        token = self._fetcher.fetch(
            app_jwt=app_jwt,
            installation_id=installation_id,
            permissions=self._permissions,
        )
        self._cache[installation_id] = token
        return token.token
