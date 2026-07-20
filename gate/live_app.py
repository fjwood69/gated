"""gate/live_app.py — the assembled LIVE gate (2.5 wire-up).

Ties the real GitHub adapters (``github_live``) into the durable executor + hermetic
engine and runs two loops: the HTTP receiver (catches webhooks) and a background
executor+watchdog poll loop (claims queued deliveries, runs the check, posts the
verdict). Config from the environment; the App private key from a file path.

This is the deployment shape, kept thin: everything it assembles was built and
model-verified in the against-fakes increments + the live adapter checks.
"""
from __future__ import annotations

import logging
import os
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable

from core import ArtifactSpec
from engine.runner import TrialReport

from .artifact import ArtifactFetchError
from .calibration_store import CalibrationStore
from .checkrun import CheckRunError
from .dedup import InMemoryDeliveryLog
from .executor import Executor, Publisher, Watchdog
from .gatekeeper import GateDecision, resolve_disposition
from .github_auth import FileKeySource, InstallationTokenProvider
from .github_live import RealGitHubCheckClient, RealJwtSigner, RealTokenFetcher, download_tarball
from http.server import ThreadingHTTPServer

from .http_server import _handler_factory  # reuse the transport handler
from .ledger import OverrideLedger, VerdictRow, capture_override, render_ledger_line
from .pipeline import (
    DEFAULT_ENGINE_BUDGET,
    assert_budget_fits_watchdog,
    assert_detector_registered,
    default_detector_registry,
    extract_to_spec,
    make_gated_job_runner,
    make_job_summarizer,
)
from .policy_store import PolicyStore
from .preflight import ConfigurationError
from .queue import GatingEvent, InMemoryOverrideSink
from .ratelimit import RateLimitBudget, TokenBucketRateLimiter
from .secret import EnvSecretSource
from .store import GatingStore, StoreBackedGatingSink
from .webhook import WebhookReceiver

_log = logging.getLogger("gated.gate.live")

CHECK_NAME = os.environ.get("GATED_CHECK_NAME", "promotion-gate/retry")
IMAGE = os.environ.get("GATED_IMAGE", "localhost/mori:local")
DETECTOR_ID = os.environ.get("GATED_DETECTOR_ID", "retry")  # 3.5-close #1.3: the accepted detector id
# 3.5-close P1-3: the ACCEPTED profile digest is the output of an INDEPENDENT acceptance ceremony and
# MUST be supplied externally. Production must NOT self-compute it (a hash of the current bytes vs the
# current bytes is circular and enforces nothing). ``required_accepted_profile_digest`` fails boot closed
# when it is unset — see below.
ACCEPTED_PROFILE_DIGEST = os.environ.get("GATED_ACCEPTED_PROFILE_DIGEST")
KEY_PATH = os.environ.get("GATED_APP_KEY_PATH", "app-private-key.pem")
TRIALS = int(os.environ.get("GATED_TRIALS", "2"))
WATCHDOG_TIMEOUT = float(os.environ.get("GATED_WATCHDOG_SECONDS", "900"))
# C1 short-circuit is the ENGINE'S PHYSICS — togglable via deploy config, NOT a code
# change. Step-3 Calibration runs full distributions on live PRs (SHORT_CIRCUIT=0) to
# gather baselines; a hardcoded default would force a commit to flip it (the "Calibration
# Trap"). Default ON (fast dev feedback); set GATED_SHORT_CIRCUIT=0 for distribution.
SHORT_CIRCUIT = os.environ.get("GATED_SHORT_CIRCUIT", "1") not in ("0", "false", "no", "")
# C3 override ledger: capture-time metadata (labelled — NOT "from the stored verdict"; the
# 2.3 store doesn't persist policy_version, board-ruled logged-forward-hard-dep). The ledger
# is out-of-band (NFR4): its own DB file, never the repo under test.
POLICY_VERSION = os.environ.get("GATED_POLICY_VERSION")  # nullable
LEDGER_DB = os.environ.get("GATED_LEDGER_DB")            # default: alongside the gate db
# C2 fork-fetch contingency. Default OFF: fetch the fork's code from the BASE repo by SHA
# (GET /repos/{base}/tarball/{fork_head_sha}) — the base commit-store mirrors the fork head
# via refs/pull/N/head, and by-SHA is TOCTOU-proof (a fork force-push can't change what we
# run). Flip ON only if that 404s live: then fetch from the FORK repo by the same SHA (still
# SHA-bound; works for PUBLIC forks with the base token; a private fork needs an App install
# on the fork). repo_full_name stays BASE regardless — only the fetch source changes.
FORK_FETCH = os.environ.get("GATED_FORK_FETCH", "0") not in ("0", "false", "no", "")


def _acquire_head_tarball(
    provider: InstallationTokenProvider, event: GatingEvent, ws: Path, *, fork_fetch: bool,
) -> None:
    """Increment B / F3: the ACQUISITION stage (token exchange + tarball fetch/write) in isolation, so a
    GitHub-adapter ``CheckRunError`` (404 / oversized / HTTP / network) or an ``OSError`` on the local tar
    WRITE is normalised to a typed ``ArtifactFetchError`` -> ``ARTIFACT_FETCH_FAILED`` — never a
    misclassified ``WORKER_FAULT``. Deliberately NARROW + POSITIONAL: only these acquisition calls are
    guarded; extraction is the CALLER's separate ``extract_to_spec`` (its own ``SafeExtractError`` path),
    and any unrelated filesystem fault stays a worker fault. PRIMARY: base repo by SHA (TOCTOU-proof; the
    base store mirrors the fork head). CONTINGENCY (GATED_FORK_FETCH=1): same SHA from the fork repo —
    only if base-by-SHA 404s live; the SHA (what we attest) is identical either way."""
    try:
        token = provider.get_valid_token(event.installation_id)
        fetch_repo = event.repo_full_name
        if fork_fetch and event.head_repo_full_name:
            fetch_repo = event.head_repo_full_name
        download_tarball(fetch_repo, event.head_sha, str(ws / "head.tar"), token)
    except (CheckRunError, OSError) as exc:
        raise ArtifactFetchError(
            f"artifact acquisition failed for {event.head_sha}: {exc!r}") from exc
# CP2 S5: the SINGLE policy this deployed check enforces (D1: one policy per deployed check; a per-event
# policy resolver is a named-next increment). Fail boot closed if unset (see required_policy_id).
POLICY_ID = os.environ.get("GATED_POLICY_ID")
# The governance stores live on their OWN DB files, SEPARATE from the queue DB: the tier decision reads the
# PolicyStore; the post-run admission-currency check reads the PolicyStore + CalibrationStore. Defaults sit
# alongside the queue DB.
POLICY_DB = os.environ.get("GATED_POLICY_DB")            # default: alongside the gate db
CALIBRATION_DB = os.environ.get("GATED_CALIBRATION_DB")  # default: alongside the gate db


class _LoggingTrialReportSink:
    """Gate-side sink for the engine's C1 ``TrialReport`` — emits the trial audit as a
    PARSEABLE key=value line (run / configured / short-circuited + per-trial reasons), so
    a verdict from N-1 trials is explained AND the short-circuited-vs-full-distribution
    ratio is queryable from the logs. Satisfies the engine-side ``TrialReportSink``.

    SCOPE (board flag #3): this is DIAGNOSTIC telemetry, NOT the durable compliance audit
    trail. A log line rotates away; it must not be quietly relied on as the audit record.
    The durable, queryable trial-audit is C3's Override Ledger — this seeds the shape, not
    the storage."""

    def record(self, report: TrialReport) -> None:
        _log.info(
            "gate.trial-report run=%d/%d short_circuited=%s reasons=%s -> %s",
            report.trials_run,
            report.trials_configured,
            report.short_circuited,
            [v.reason.value for v in report.trials],
            report.aggregate.status.value,
        )


def required_accepted_profile_digest() -> str:
    """3.5-close P1-3: production REQUIRES an externally-supplied accepted profile digest — the output of
    an INDEPENDENT acceptance ceremony — so the live gate enforces the EXACT detector profile that was
    accepted. Refuse to self-compute it in production (current-bytes-vs-a-hash-of-current-bytes is
    circular and enforces nothing). Fail boot CLOSED when ``GATED_ACCEPTED_PROFILE_DIGEST`` is unset."""
    digest = (ACCEPTED_PROFILE_DIGEST or "").strip()
    if not digest:
        raise ConfigurationError(
            "production gate requires GATED_ACCEPTED_PROFILE_DIGEST (the output of an independent "
            "acceptance ceremony); refusing to self-compute the accepted detector identity in production")
    return digest


def required_policy_id() -> str:
    """CP2 S5 D1: the deployed check enforces exactly ONE policy; ``resolve_disposition`` + the dispatch-time
    invariant recheck both need its id. Fail boot CLOSED when ``GATED_POLICY_ID`` is unset/blank (a missing
    policy id would leave the tier decision without a subject)."""
    pid = (POLICY_ID or "").strip()
    if not pid:
        raise ConfigurationError(
            "production gate requires GATED_POLICY_ID (the single policy this deployed check enforces)")
    return pid


def require_distinct_db_paths(queue_db: Path, policy_db: Path, calibration_db: Path) -> None:
    """CP2 S5 (dissent P2): the queue / policy / calibration stores MUST live on DISTINCT DB files — a shared
    file would let one store's writes corrupt another's schema/rows. Comments + defaults do NOT prevent an
    env-configured collision (``GATED_POLICY_DB`` == ``GATED_CALIBRATION_DB``, say); assert the RESOLVED
    paths are distinct at boot and fail CLOSED."""
    resolved = {"queue": queue_db.resolve(), "policy": policy_db.resolve(),
                "calibration": calibration_db.resolve()}
    if len(set(resolved.values())) != len(resolved):
        raise ConfigurationError(
            "the queue / policy / calibration DB paths must be DISTINCT (a shared file lets one store "
            f"corrupt another): {dict((k, str(v)) for k, v in resolved.items())}")


class _ProductionAdmissionGovernanceView:
    """The production ``AdmissionGovernanceView`` (CP2 S5, board D2): admission's OWN post-run governance
    read. ``current_attestation`` is backed by ``PolicyStore.current_attestation_snapshot`` — which already
    gates ICV == the current identity contract AND the hash-chained pass exact-match IN-STORE inside ONE
    atomic snapshot — repackaged to the ``(set_id, oracle_head, subject, generation)`` 4-tuple admission needs
    (the ICV gate stays a store invariant, not re-implemented here; the ``generation`` is the snapshot's own
    monotonic head record_hash, so it is captured ATOMICALLY with the binding — the ABA-bracket baseline).
    ``oracle_head_for`` is ``CalibrationStore.set_head``; ``current_generation`` is ``PolicyStore.policy_head``
    (the post-oracle re-read that closes the ``set_head`` ABA). All reads may RAISE (a broken chain /
    unreachable store); ``admit_run_result`` catches and fails closed. Read-only — admission never mutates
    governance state."""

    def __init__(self, policy_store: PolicyStore, calibration_store: CalibrationStore) -> None:
        self._policy_store = policy_store
        self._calibration_store = calibration_store

    def current_attestation(self, policy_id: str) -> tuple[str, str, str, str] | None:
        snap = self._policy_store.current_attestation_snapshot(policy_id)
        if snap is None:
            return None
        set_id, oracle_head, subject, _icv, generation = snap  # drop ICV (store-gated); carry generation
        return (set_id, oracle_head, subject, generation)

    def oracle_head_for(self, set_id: str) -> str | None:
        return self._calibration_store.set_head(set_id)

    def current_generation(self, policy_id: str) -> str | None:
        return self._policy_store.policy_head(policy_id)


def build(
    db_path: Path,
) -> tuple[WebhookReceiver, Executor, Watchdog, Publisher, InstallationTokenProvider, Callable[[], int]]:
    accepted_profile_digest = required_accepted_profile_digest()  # P1-3: fail boot if unset (no self-compute)
    policy_id = required_policy_id()  # CP2 S5 D1: fail boot if GATED_POLICY_ID unset
    # S7 (dissent): WIRE the enforced startup invariant — the engine applies the budget PER TRIAL, so the
    # aggregate (trials x per-trial x margin) MUST fit the watchdog window, else a slow multi-trial run races
    # the watchdog's force-ERROR. Previously only tests called this, so the docstring's "the App MUST call
    # this at startup" was a gap; the live path now enforces it and fails boot CLOSED on violation.
    assert_budget_fits_watchdog(
        trials=TRIALS, per_trial_wall_clock=DEFAULT_ENGINE_BUDGET.wall_clock_seconds,
        watchdog_timeout=WATCHDOG_TIMEOUT)
    app_id = int(os.environ["GATED_APP_ID"])
    installs = frozenset(
        int(x) for x in os.environ.get("GATED_INSTALLATION_IDS", "").split(",") if x
    )
    budget = RateLimitBudget(floor=100)

    provider = InstallationTokenProvider(
        app_id=app_id,
        key_source=FileKeySource(KEY_PATH),
        signer=RealJwtSigner(),
        fetcher=RealTokenFetcher(budget),
        clock=time.time,
    )
    # CP2 S5: SEPARATE governance stores (NOT the queue DB) — the tier decision reads the PolicyStore; the
    # post-run admission-currency read reads the PolicyStore + CalibrationStore. Own DB files.
    queue_db = db_path
    policy_db = Path(POLICY_DB) if POLICY_DB else db_path.with_name("gated-policy.db")
    calibration_db = Path(CALIBRATION_DB) if CALIBRATION_DB else db_path.with_name("gated-calibration.db")
    require_distinct_db_paths(queue_db, policy_db, calibration_db)  # dissent P2: fail boot on a collision
    # Increment A: persist the deployed check NAME into each publication payload at enqueue (complete-binding —
    # the Publisher never re-derives identity from live config; a restart with a changed name cannot split a
    # delivery's reset + conclusion across identities).
    store = GatingStore(queue_db, check_name=CHECK_NAME)
    policy_store = PolicyStore(policy_db)
    calibration_store = CalibrationStore(calibration_db)
    governance = _ProductionAdmissionGovernanceView(policy_store, calibration_store)
    # C3: the override ledger lives out-of-band — a SEPARATE DB file, the gate's trusted
    # store, never the repo under test (NFR4). The in-memory capture sink is drained by the
    # poll loop; loss on crash is safe (ledger idempotency + reconciliation).
    ledger_path = Path(LEDGER_DB) if LEDGER_DB else db_path.with_name("gated-override-ledger.db")
    ledger = OverrideLedger(ledger_path)
    override_sink = InMemoryOverrideSink(max_depth=256)
    receiver = WebhookReceiver(
        secret_source=EnvSecretSource(),
        app_id=app_id,
        authorized_installations=installs,
        gating_sink=StoreBackedGatingSink(store, max_depth=64),
        delivery_log=InMemoryDeliveryLog(),  # fast pre-enqueue dedup; the store's
        # ON CONFLICT enqueue is the DURABLE dedup backstop (survives restart)
        audit_sink=None,
        override_sink=override_sink,
    )

    def artifact_source(event: GatingEvent, ws: Path) -> ArtifactSpec:
        # Increment B / F3: acquisition (token exchange + tarball fetch/write) is confined to
        # ``_acquire_head_tarball`` — a CheckRunError / acquisition OSError there is normalised to a typed
        # ArtifactFetchError -> ARTIFACT_FETCH_FAILED, never a misclassified WORKER_FAULT. ``extract_to_spec``
        # is a SEPARATE step OUTSIDE that guard, so an EXTRACTION failure keeps its own SafeExtractError path
        # and an unrelated fs OSError stays a worker fault (positional confinement, per the ruling).
        _acquire_head_tarball(provider, event, ws, fork_fetch=FORK_FETCH)
        return extract_to_spec(ws / "head.tar", ws)

    # C4: the engine's trial report is DIAGNOSTIC logging only. The authoritative Check Run summary is
    # rendered from the TYPED JobResult (an AdmittedRunResult carries its OWN report); no capture sink feeds
    # the summary — a stale capture must never contaminate a refusal / non-run / infra summary.
    report_sink = _LoggingTrialReportSink()

    # 3.5-close #1.3: the enforced detector is resolved by NAME through the trusted registry (enforced ==
    # accepted). Boot assertion — fail HERE if the accepted detector does not resolve, not per-PR.
    detector_registry = default_detector_registry(
        detector_id=DETECTOR_ID, entrypoint=("python3", "/artifact/main.py"),
        accepted_profile_digest=accepted_profile_digest)  # P1-3: enforce the externally-accepted profile
    # boot assertion: resolve revalidates the resolved profile against the accepted digest — a mismatch
    # (wrong ceremony output, or a drifted live detector) fails boot here, not per-PR.
    assert_detector_registered(detector_registry.resolve, DETECTOR_ID)

    def resolve_decision(event: GatingEvent) -> GateDecision:
        # CP2 S5: the tier decision for THIS deployment's single policy. snapshot=None (D3): a store outage
        # with no signed snapshot -> UNATTESTABLE block (fail-closed; the signed-snapshot fallback is a
        # named-next increment). Oracle currency is the live CalibrationStore set head.
        return resolve_disposition(
            policy_id, store=policy_store, snapshot=None, snapshot_key=b"",
            now=time.time(), oracle_head_for=calibration_store.set_head)

    # CP2 S5: the FULL tier-decision + engine + run-admission job runner (de-vestigialised path). A non-run
    # disposition publishes a typed NonRunDecision and never runs the engine; an enforce runs the engine
    # under the minted plan and ADMITS the result (post-run currency) before publishing the measured verdict.
    job_runner = make_gated_job_runner(
        resolve_decision, artifact_source, policy_id=policy_id, governance=governance,
        image=IMAGE, resolve=detector_registry.resolve_bundle, detector_id=DETECTOR_ID,
        trials=TRIALS, first_fail=SHORT_CIRCUIT, report_sink=report_sink)

    client = RealGitHubCheckClient(provider, next(iter(installs)), budget=budget)
    # Increment A: the executor + watchdog RENDER the summary and arm a durable publication at finalize; the
    # Publisher is the SOLE writer of the actuator (draining the outbox). No inline GitHub call on a terminal
    # row (the Finding-1 liveness defect is removed at the root).
    summarize = make_job_summarizer(CHECK_NAME)
    executor = Executor(store, job_runner, summarize, max_workers=1)
    watchdog = Watchdog(store, summarize, timeout_seconds=WATCHDOG_TIMEOUT)
    publisher = Publisher(store, client)

    def verdict_lookup(sha: str) -> list[VerdictRow]:
        return [
            VerdictRow(status=s, verdict=v, reason=r, updated_at=u, gate_outcome=g)
            for (s, v, r, u, g) in store.verdicts_for_sha(sha)
        ]

    def drain_overrides() -> int:
        """Drain merged-PR captures -> the override ledger. Observational: NO engine call.
        A capture failure is the AUDIT mechanism failing — surface it, never swallow
        (completeness P3; mirrors C1's sink isolation). The event is not re-queued: the
        ledger is idempotent and reconciliation backfills a dropped capture."""
        batch = override_sink.drain()
        for ev in batch:
            try:
                rec = capture_override(ev, verdict_lookup, ledger, policy_version=POLICY_VERSION)
                if rec is not None:
                    _log.info("gate.override-ledger seq=%d %s", rec.seq, render_ledger_line(rec))
            except Exception:
                _log.exception("gate.override-ledger CAPTURE FAILED delivery=%s sha=%s",
                               ev.delivery_id, ev.head_sha)
        return len(batch)

    return receiver, executor, watchdog, publisher, provider, drain_overrides


def _poll_loop(
    executor: Executor,
    watchdog: Watchdog,
    publisher: Publisher,
    drain_overrides: Callable[[], int],
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            # Increment A ordering: PUBLISH first — a freshly-armed RESET must reach the actuator (surface ->
            # in_progress, blocking) BEFORE the executor may claim that delivery (the claim_next reset-gate is
            # the load-bearing fail-closed guard; this ordering only reduces latency). Then run the executor +
            # watchdog (which arm CONCLUSION publications), then publish again so those conclusions drain the
            # same tick. A GitHub outage leaves resets unpublished -> deliveries wait in 'queued' (fail-closed).
            publisher.drain_once()
            n = executor.drain()
            watchdog.sweep_once()
            publisher.drain_once()
            drain_overrides()  # C3: merged-PR captures -> override ledger (own error surface)
            if n:
                _log.info("processed %d delivery(ies)", n)
        except Exception:  # never let the loop die
            _log.exception("poll loop error")
        stop.wait(3.0)


def serve(host: str = "127.0.0.1", port: int = 8975) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    db = Path(tempfile.gettempdir()) / "gated-gate.db"
    receiver, executor, watchdog, publisher, _, drain_overrides = build(db)

    stop = threading.Event()
    poller = threading.Thread(
        target=_poll_loop, args=(executor, watchdog, publisher, drain_overrides, stop), daemon=True
    )
    poller.start()

    limiter = TokenBucketRateLimiter(capacity=20.0, refill_per_sec=5.0, clock=time.monotonic)
    httpd = ThreadingHTTPServer((host, port), _handler_factory(receiver, limiter))
    _log.info("gate listening on %s:%d  check=%s  image=%s  db=%s", host, port, CHECK_NAME, IMAGE, db)
    try:
        httpd.serve_forever()
    finally:
        stop.set()
        httpd.server_close()


if __name__ == "__main__":  # pragma: no cover
    serve()
