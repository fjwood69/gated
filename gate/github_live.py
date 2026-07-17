"""gate/github_live.py — the REAL GitHub adapters (2.5 live wire-up).

Built against real GitHub responses (not mocks — the fakes' model has been wrong
before). Implements the seams the against-fakes increments defined:
``JwtSigner`` (PyJWT RS256), ``TokenFetcher`` (installation-token exchange), and
``GitHubCheckClient`` (find/create/update Check Runs) — plus a streaming, byte-capped
tarball download and the startup branch-protection fetch.

PyJWT is isolated to this module + ``github_auth`` (Fork-2 ruling), and imported LAZILY inside
``RealJwtSigner.sign_rs256`` so importing this module (and ``gate.live_app`` through it) needs no
third-party dep beyond PyNaCl — the CI unit-test contract. The rest of the
gate stays stdlib. Every outbound call has a hard timeout + bounded backoff on 5xx /
secondary-rate-limit, and threads the ``X-RateLimit-Remaining`` header into an optional
``RateLimitBudget`` so the receiver can shed load before the quota wedges.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

from .checkrun import CheckConclusion, CheckOutput, CheckRunError, CheckStatus
from .github_auth import AppJwtClaims, InstallationToken, InstallationTokenProvider
from .preflight import verify_check_required
from .ratelimit import RateLimitBudget

_API = "https://api.github.com"
_UA = "promotion-gate"
_TIMEOUT = 10.0            # per socket op (connect + each read)
_MAX_RETRIES = 3
_DL_CAP = 100 * 1024 * 1024  # 100 MiB streamed tarball ceiling


class RealJwtSigner:
    """Sign App-JWT claims RS256 with PyJWT (proven accepted by real GitHub)."""

    def sign_rs256(self, claims: AppJwtClaims, private_key_pem: bytes) -> str:
        # Deferred import: PyJWT is loaded only when a JWT is actually signed, so importing this module
        # (and gate.live_app through it) stays stdlib+PyNaCl-only — the CI unit-test contract. A unit test
        # importing _ProductionAdmissionGovernanceView from live_app must not require PyJWT.
        import jwt  # type: ignore[import-not-found]

        return str(
            jwt.encode(
                {"iat": claims.iat, "exp": claims.exp, "iss": claims.iss},
                private_key_pem,
                algorithm="RS256",
            )
        )


def _http(
    method: str,
    url: str,
    *,
    token: str,
    bearer: bool = False,
    body: Mapping[str, Any] | None = None,
    budget: RateLimitBudget | None = None,
) -> tuple[int, Any, Mapping[str, str]]:
    """One GitHub API call with hard timeout + bounded backoff on 5xx/429. ``bearer``
    picks the App-JWT auth scheme; otherwise the installation token."""
    scheme = "Bearer" if bearer else "token"
    data = json.dumps(body).encode() if body is not None else None
    last_exc: Exception | None = None
    for attempt in range(_MAX_RETRIES):
        req = urllib.request.Request(url, method=method, data=data)
        req.add_header("Authorization", f"{scheme} {token}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", _UA)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                raw = resp.read()
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                if budget is not None and "x-ratelimit-remaining" in hdrs:
                    budget.observe(int(hdrs["x-ratelimit-remaining"]))
                parsed = json.loads(raw) if raw else None
                return resp.status, parsed, hdrs
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < _MAX_RETRIES - 1:
                retry_after = e.headers.get("Retry-After")
                time.sleep(float(retry_after) if retry_after else 2 ** attempt)
                last_exc = e
                continue
            detail = e.read()[:300].decode(errors="replace")
            raise CheckRunError(f"{method} {url} -> {e.code}: {detail}") from e
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < _MAX_RETRIES - 1:
                time.sleep(2 ** attempt)
                last_exc = e
                continue
            raise CheckRunError(f"{method} {url} network error: {e!r}") from e
    raise CheckRunError(f"{method} {url} exhausted retries: {last_exc!r}")


class RealTokenFetcher:
    """Exchange an App JWT for a scoped installation token (proven live)."""

    def __init__(self, budget: RateLimitBudget | None = None) -> None:
        self._budget = budget

    def fetch(
        self, *, app_jwt: str, installation_id: int, permissions: Mapping[str, str]
    ) -> InstallationToken:
        status, data, _ = _http(
            "POST",
            f"{_API}/app/installations/{installation_id}/access_tokens",
            token=app_jwt,
            bearer=True,
            body={"permissions": dict(permissions)},
            budget=self._budget,
        )
        if not isinstance(data, dict) or "token" not in data:
            raise CheckRunError(f"token exchange gave no token (status {status})")
        expires = data.get("expires_at", "")
        # "2026-07-08T19:03:50Z" -> epoch
        exp = int(time.mktime(time.strptime(expires, "%Y-%m-%dT%H:%M:%SZ"))) if expires else 0
        return InstallationToken(token=data["token"], expires_at=exp)


class RealGitHubCheckClient:
    """find/create/update Check Runs via the installation token. Idempotent create:
    GitHub is NOT queryable by external_id, so find by (commit SHA, check name)."""

    def __init__(
        self,
        token_provider: InstallationTokenProvider,
        installation_id: int,
        *,
        budget: RateLimitBudget | None = None,
    ) -> None:
        self._tp = token_provider
        self._iid = installation_id
        self._budget = budget

    def _token(self) -> str:
        # freshness re-checked on every call (never a token cached from enqueue)
        return self._tp.get_valid_token(self._iid)

    def find_check_run(self, *, repo_full_name: str, head_sha: str, name: str) -> str | None:
        from urllib.parse import quote
        url = f"{_API}/repos/{repo_full_name}/commits/{head_sha}/check-runs?check_name={quote(name)}"
        _, data, _ = _http("GET", url, token=self._token(), budget=self._budget)
        if isinstance(data, dict):
            runs = data.get("check_runs") or []
            if runs:
                return str(runs[0]["id"])
        return None

    def create_check_run(
        self,
        *,
        repo_full_name: str,
        head_sha: str,
        name: str,
        status: CheckStatus,
        external_id: str,
        conclusion: CheckConclusion | None = None,
        output: CheckOutput | None = None,
    ) -> str:
        body: dict[str, Any] = {"name": name, "head_sha": head_sha,
                                "status": status.value, "external_id": external_id}
        _apply_conclusion(body, conclusion, output)
        _, data, _ = _http("POST", f"{_API}/repos/{repo_full_name}/check-runs",
                            token=self._token(), body=body, budget=self._budget)
        return str(data["id"])

    def update_check_run(
        self,
        *,
        repo_full_name: str,
        check_run_id: str,
        status: CheckStatus,
        conclusion: CheckConclusion | None = None,
        output: CheckOutput | None = None,
    ) -> None:
        body: dict[str, Any] = {"status": status.value}
        _apply_conclusion(body, conclusion, output)
        _http("PATCH", f"{_API}/repos/{repo_full_name}/check-runs/{check_run_id}",
              token=self._token(), body=body, budget=self._budget)


def _apply_conclusion(
    body: dict[str, Any], conclusion: CheckConclusion | None, output: CheckOutput | None
) -> None:
    if conclusion is not None:
        body["conclusion"] = conclusion.value
    if output is not None:
        body["output"] = {"title": output.title, "summary": output.summary}


def fetch_branch_protection(repo_full_name: str, branch: str, token: str) -> dict[str, Any]:
    _, data, _ = _http("GET", f"{_API}/repos/{repo_full_name}/branches/{branch}/protection",
                        token=token)
    return data if isinstance(data, dict) else {}


def assert_gate_is_required(
    *,
    token_provider: InstallationTokenProvider,
    installation_id: int,
    repo_full_name: str,
    branch: str,
    check_name: str,
) -> None:
    """Fail-closed startup check: fetch the branch protection LIVE and assert our check
    is required-by-name (the invisible-fail-open footgun)."""
    token = token_provider.get_valid_token(installation_id)
    protection = fetch_branch_protection(repo_full_name, branch, token)
    verify_check_required(protection, check_name)


def download_tarball(repo_full_name: str, ref: str, dest_tar: str, token: str) -> None:
    """Stream the PR-head tarball to ``dest_tar`` with a running byte-cap — abort before
    a multi-GB blob exhausts RAM/disk (the board OOM vector). GitHub redirects to
    codeload; urllib follows it, carrying the auth header."""
    url = f"{_API}/repos/{repo_full_name}/tarball/{ref}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"token {token}")
    req.add_header("User-Agent", _UA)
    total = 0
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp, open(dest_tar, "wb") as out:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _DL_CAP:
                raise CheckRunError(f"tarball exceeds {_DL_CAP} bytes — aborted mid-stream")
            out.write(chunk)


__all__ = [
    "RealJwtSigner",
    "RealTokenFetcher",
    "RealGitHubCheckClient",
    "fetch_branch_protection",
    "assert_gate_is_required",
    "download_tarball",
]
