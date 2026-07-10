"""gate/secret.py — the webhook-secret access SEAM (board tightening).

The webhook secret is the out-of-band trust root: it is what proves a delivery
genuinely came from GitHub (HMAC key). It must NEVER live in the repo or the image.

The receiver reads it through this seam rather than touching ``os.environ`` inline,
so the deployment build swaps the source (Vault / sealed secret / cloud secret
manager) WITHOUT changing the receiver — the same pluggable-backend discipline as
the sandbox layer.

    reference build  -> ``EnvSecretSource``   (env var; podman-on-NUC)
    deployment       -> a secret-manager backend (deferred; not this tree's concern)
"""
from __future__ import annotations

import os
from typing import Protocol


class SecretMissingError(RuntimeError):
    """The webhook secret is not available. Fail closed — never verify against an
    empty/absent secret (that would accept everything)."""


class SecretSource(Protocol):
    """Where the webhook secret comes from. Backends may cache internally; the
    receiver calls ``webhook_secret()`` per request so rotation can take effect."""

    def webhook_secret(self) -> bytes: ...


class EnvSecretSource:
    """Reference backend: read the secret from an environment variable.

    Deployment replaces this with a secret-manager backend implementing the same
    ``SecretSource`` Protocol — the receiver is unaffected.
    """

    def __init__(self, var: str = "GATED_WEBHOOK_SECRET") -> None:
        self._var = var

    def webhook_secret(self) -> bytes:
        value = os.environ.get(self._var)
        if not value:  # unset OR empty -> fail closed
            raise SecretMissingError(
                f"webhook secret env var {self._var!r} is unset or empty"
            )
        return value.encode("utf-8")


class StaticSecretSource:
    """In-memory backend — for tests and single-shot reference runs where the
    secret is already in hand. Not for production (holds the secret in process
    memory with no rotation)."""

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise SecretMissingError("StaticSecretSource given an empty secret")
        self._secret = secret

    def webhook_secret(self) -> bytes:
        return self._secret
