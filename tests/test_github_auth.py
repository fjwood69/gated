"""Increment 2.2 — GitHub App installation-token provider (against fakes).

Run from the gated/ root:  python3 -m unittest discover -s tests

The LIVE adapters (RS256 signing via PyJWT, HTTPS token exchange) are deferred to the
App wire-up. This proves the substantive logic against fakes: App-JWT claim bounds,
the per-installation cache with a refresh margin, and checks:write scoping.
"""
from __future__ import annotations

import unittest

from gate.github_auth import (
    AppJwtClaims,
    EnvKeySource,
    InstallationToken,
    InstallationTokenProvider,
    KeyMissingError,
    build_app_jwt_claims,
)

_APP_ID = 424242


class _FakeKey:
    def private_key_pem(self) -> bytes:
        return b"-----BEGIN FAKE KEY-----"


class _FakeSigner:
    def __init__(self) -> None:
        self.signed: list[AppJwtClaims] = []

    def sign_rs256(self, claims: AppJwtClaims, private_key_pem: bytes) -> str:
        self.signed.append(claims)
        return f"jwt-for-{claims.iss}"


class _FakeFetcher:
    def __init__(self, *, ttl: int = 3600) -> None:
        self.calls: list[tuple[str, int, dict[str, str]]] = []
        self._ttl = ttl
        self._n = 0

    def fetch(self, *, app_jwt: str, installation_id: int, permissions):  # type: ignore[no-untyped-def]
        self._n += 1
        self.calls.append((app_jwt, installation_id, dict(permissions)))
        # expires_at relative to a caller-controlled clock is set by the test via _now
        return InstallationToken(token=f"tok-{installation_id}-{self._n}", expires_at=_now[0] + self._ttl)


# a mutable clock the tests advance
_now = [1_000_000]


def _clock() -> float:
    return _now[0]


class ClaimBoundsTests(unittest.TestCase):
    def test_iat_backdated_and_exp_within_ceiling(self) -> None:
        claims = build_app_jwt_claims(_APP_ID, now=1_000_000)
        self.assertEqual(claims.iss, str(_APP_ID))
        self.assertEqual(claims.iat, 1_000_000 - 60)      # clock-skew backdate
        self.assertLessEqual(claims.exp - claims.iat, 600)  # <= GitHub's 10-min ceiling
        self.assertGreater(claims.exp, 1_000_000)


class TokenProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        _now[0] = 1_000_000
        self.signer = _FakeSigner()
        self.fetcher = _FakeFetcher(ttl=3600)
        self.provider = InstallationTokenProvider(
            app_id=_APP_ID,
            key_source=_FakeKey(),
            signer=self.signer,
            fetcher=self.fetcher,
            clock=_clock,
        )

    def test_mints_then_caches(self) -> None:
        t1 = self.provider.token_for(9001)
        t2 = self.provider.token_for(9001)
        self.assertEqual(t1, t2)
        self.assertEqual(len(self.fetcher.calls), 1)  # cached, not re-fetched

    def test_scopes_to_checks_write(self) -> None:
        self.provider.token_for(9001)
        _, _, perms = self.fetcher.calls[0]
        self.assertEqual(perms, {"checks": "write"})  # least privilege

    def test_refresh_margin_remints_before_expiry(self) -> None:
        self.provider.token_for(9001)                 # expires at now+3600
        _now[0] += 3600 - 4 * 60                       # within the 5-min refresh margin
        self.provider.token_for(9001)
        self.assertEqual(len(self.fetcher.calls), 2)  # re-minted, not served near-stale

    def test_expired_token_reminted(self) -> None:
        self.provider.token_for(9001)
        _now[0] += 3601
        self.provider.token_for(9001)
        self.assertEqual(len(self.fetcher.calls), 2)

    def test_per_installation_isolation(self) -> None:
        a = self.provider.token_for(9001)
        b = self.provider.token_for(9002)
        self.assertNotEqual(a, b)
        self.assertEqual({c[1] for c in self.fetcher.calls}, {9001, 9002})

    def test_app_jwt_used_for_exchange(self) -> None:
        self.provider.token_for(9001)
        # the fetcher receives the signed App JWT (used only to mint the install token)
        self.assertEqual(self.fetcher.calls[0][0], f"jwt-for-{_APP_ID}")


class EnvKeySourceTests(unittest.TestCase):
    def test_absent_key_fails_closed(self) -> None:
        src = EnvKeySource(var="GATED_APP_PRIVATE_KEY_ABSENT_FOR_TEST")
        with self.assertRaises(KeyMissingError):
            src.private_key_pem()


if __name__ == "__main__":
    unittest.main()
