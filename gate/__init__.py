"""gated gate — bind the engine's verdict at the GitHub merge boundary.

The harness-agnostic Promotion Gate. Step 2 ships the GitHub App adapter; the gate
logic (webhook trust boundary, Check Run semantics) is built independent of the
harness so an Action adapter can be a later thin front-end on the same core.

Apache-core pure — no proprietary runtime dependencies (see ARCHITECTURE.md). The
grader/policy lives here, OUT-OF-BAND from the repo (NFR4).

Increment 2.1 = the webhook receiver: authenticate (HMAC), authorize (app-id +
installation), classify, and ENQUEUE a gating event (202) — no GitHub write, no
blocking. Check Run creation + the async executor are 2.2/2.3.
"""
from __future__ import annotations

from .artifact import (
    ExtractLimits,
    SafeExtractError,
    build_artifact_spec,
    extraction_workspace,
    safe_extract_tarball,
)
from .audit import AuditSink, LoggingAuditSink, NullAuditSink, RejectionEvent
from .checkrun import (
    BLOCKING_CONCLUSIONS,
    CheckConclusion,
    CheckOutput,
    CheckRunError,
    CheckRunLifecycle,
    CheckStatus,
    GitHubCheckClient,
    external_id_for,
    upsert_check_run,
    verdict_to_conclusion,
)
from .dedup import DeliveryLog, InMemoryDeliveryLog
from .detector_registry import (
    DetectorIntegrityError,
    DetectorRegistry,
    DetectorResolutionError,
    DetectorResolver,
    RegistrableDetector,
    RegistrationError,
    UnregisteredDetectorError,
    registration_binding,
)
from .executor import (
    ERROR_VERDICT,
    Executor,
    LifecycleEvent,
    LifecycleSink,
    LoggingLifecycleSink,
    NullLifecycleSink,
    Transition,
    Watchdog,
)
from .github_auth import (
    AppJwtClaims,
    EnvKeySource,
    InstallationToken,
    InstallationTokenProvider,
    JwtSigner,
    KeyMissingError,
    KeySource,
    TokenFetcher,
    build_app_jwt_claims,
)
from .pipeline import (
    ArtifactSource,
    assert_budget_fits_watchdog,
    extract_to_spec,
    make_check_updater,
    make_job_runner,
    run_engine_check,
)
from .preflight import ConfigurationError, verify_check_required
from .queue import GatingEvent, GatingSink, InMemoryGatingSink, SinkFull
from .summary import render_check_summary
from .ratelimit import NullRateLimiter, RateLimitBudget, RateLimiter, TokenBucketRateLimiter
from .store import GatingStore, StoreBackedGatingSink
from .secret import (
    EnvSecretSource,
    SecretMissingError,
    SecretSource,
    StaticSecretSource,
)
from .webhook import (
    GATING_ACTIONS,
    Headers,
    Reason,
    ReceiverOutcome,
    ReceiverResult,
    WebhookReceiver,
)

__all__ = [
    "WebhookReceiver",
    "ReceiverResult",
    "ReceiverOutcome",
    "Reason",
    "Headers",
    "GATING_ACTIONS",
    "SecretSource",
    "EnvSecretSource",
    "StaticSecretSource",
    "SecretMissingError",
    "DeliveryLog",
    "InMemoryDeliveryLog",
    "GatingSink",
    "GatingEvent",
    "InMemoryGatingSink",
    "SinkFull",
    "RateLimiter",
    "TokenBucketRateLimiter",
    "NullRateLimiter",
    "AuditSink",
    "LoggingAuditSink",
    "NullAuditSink",
    "RejectionEvent",
    "CheckStatus",
    "CheckConclusion",
    "BLOCKING_CONCLUSIONS",
    "CheckOutput",
    "CheckRunError",
    "GitHubCheckClient",
    "CheckRunLifecycle",
    "verdict_to_conclusion",
    "external_id_for",
    "upsert_check_run",
    "KeySource",
    "EnvKeySource",
    "KeyMissingError",
    "AppJwtClaims",
    "JwtSigner",
    "InstallationToken",
    "TokenFetcher",
    "InstallationTokenProvider",
    "build_app_jwt_claims",
    "safe_extract_tarball",
    "build_artifact_spec",
    "extraction_workspace",
    "ExtractLimits",
    "SafeExtractError",
    "GatingStore",
    "StoreBackedGatingSink",
    "Executor",
    "Watchdog",
    "Transition",
    "LifecycleEvent",
    "LifecycleSink",
    "LoggingLifecycleSink",
    "NullLifecycleSink",
    "ERROR_VERDICT",
    "run_engine_check",
    "make_job_runner",
    "make_check_updater",
    "extract_to_spec",
    "assert_budget_fits_watchdog",
    "ArtifactSource",
    "render_check_summary",
    "verify_check_required",
    "ConfigurationError",
    "RateLimitBudget",
    "DetectorRegistry",
    "RegistrableDetector",
    "DetectorResolver",
    "DetectorResolutionError",
    "UnregisteredDetectorError",
    "DetectorIntegrityError",
    "RegistrationError",
    "registration_binding",
]
