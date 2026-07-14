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

from core import ArtifactSpec, Reason, Verdict, VerdictType
from engine.runner import TrialReport

from .dedup import InMemoryDeliveryLog
from .executor import Executor, Watchdog
from .github_auth import FileKeySource, InstallationTokenProvider
from .github_live import RealGitHubCheckClient, RealJwtSigner, RealTokenFetcher, download_tarball
from http.server import ThreadingHTTPServer

from .http_server import _handler_factory  # reuse the transport handler
from .ledger import OverrideLedger, VerdictRow, capture_override, render_ledger_line
from .pipeline import (
    CapturingTrialReportSink,
    assert_detector_registered,
    default_detector_registry,
    extract_to_spec,
    make_check_updater,
    run_engine_check,
)
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


def build(
    db_path: Path,
) -> tuple[WebhookReceiver, Executor, Watchdog, InstallationTokenProvider, Callable[[], int]]:
    accepted_profile_digest = required_accepted_profile_digest()  # P1-3: fail boot if unset (no self-compute)
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
    store = GatingStore(db_path)
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
        token = provider.get_valid_token(event.installation_id)
        # PRIMARY: base repo by SHA (TOCTOU-proof; the base store mirrors the fork head).
        # CONTINGENCY (GATED_FORK_FETCH=1): same SHA, fetched from the fork repo — only
        # if base-by-SHA 404s live. The SHA (what we attest) is identical either way.
        fetch_repo = event.repo_full_name
        if FORK_FETCH and event.head_repo_full_name:
            fetch_repo = event.head_repo_full_name
        download_tarball(fetch_repo, event.head_sha, str(ws / "head.tar"), token)
        return extract_to_spec(ws / "head.tar", ws)

    # 3.5-close #1.5: capture the trial report so the Check Run summary carries the attested detector_id
    # + image_digest. Fan out to the audit log too. Single-writer safe (Executor max_workers=1 below).
    _log_sink = _LoggingTrialReportSink()
    report_capture = CapturingTrialReportSink()

    class _FanoutSink:
        def record(self, report: object) -> None:
            _log_sink.record(report)       # type: ignore[arg-type]
            report_capture.record(report)  # type: ignore[arg-type]

    report_sink = _FanoutSink()

    # 3.5-close #1.3: the enforced detector is resolved by NAME through the trusted registry (enforced ==
    # accepted). Boot assertion — fail HERE if the accepted detector does not resolve, not per-PR.
    detector_registry = default_detector_registry(
        detector_id=DETECTOR_ID, entrypoint=("python3", "/artifact/main.py"),
        accepted_profile_digest=accepted_profile_digest)  # P1-3: enforce the externally-accepted profile
    # boot assertion: resolve revalidates the resolved profile against the accepted digest — a mismatch
    # (wrong ceremony output, or a drifted live detector) fails boot here, not per-PR.
    assert_detector_registered(detector_registry.resolve, DETECTOR_ID)

    def job_runner(event: GatingEvent) -> Verdict:
        from .artifact import extraction_workspace
        from .detector_registry import DetectorResolutionError

        with extraction_workspace() as ws:
            artifact = artifact_source(event, ws)
            try:
                # S3-completion: consume run_engine_check's AUTHORITATIVE EngineRunResult return (verdict is
                # its derived property). The report_sink/report_capture summary is now audit-SECONDARY — the
                # merge DECISION (verdict) is the direct return, never report_capture.last. (The full
                # admit_run_result typestate is the CP2 wiring increment.)
                return run_engine_check(
                    artifact, image=IMAGE, resolve=detector_registry.resolve_bundle, detector_id=DETECTOR_ID,
                    trials=TRIALS, first_fail=SHORT_CIRCUIT, report_sink=report_sink,
                ).verdict
            except DetectorResolutionError:
                # enforced detector unregistered / drifted -> block (never enforce an unverified detector).
                return Verdict(VerdictType.ERROR, Reason.DETECTOR_UNRESOLVED)

    client = RealGitHubCheckClient(provider, next(iter(installs)), budget=budget)
    updater = make_check_updater(client, name=CHECK_NAME, report_capture=report_capture)

    executor = Executor(store, job_runner, updater, max_workers=1)
    watchdog = Watchdog(store, updater, timeout_seconds=WATCHDOG_TIMEOUT)

    def verdict_lookup(sha: str) -> list[VerdictRow]:
        return [
            VerdictRow(status=s, verdict=v, reason=r, updated_at=u)
            for (s, v, r, u) in store.verdicts_for_sha(sha)
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

    return receiver, executor, watchdog, provider, drain_overrides


def _poll_loop(
    executor: Executor,
    watchdog: Watchdog,
    drain_overrides: Callable[[], int],
    stop: threading.Event,
) -> None:
    while not stop.is_set():
        try:
            n = executor.drain()
            watchdog.sweep_once()
            drain_overrides()  # C3: merged-PR captures -> override ledger (own error surface)
            if n:
                _log.info("processed %d delivery(ies)", n)
        except Exception:  # never let the loop die
            _log.exception("poll loop error")
        stop.wait(3.0)


def serve(host: str = "127.0.0.1", port: int = 8975) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    db = Path(tempfile.gettempdir()) / "gated-gate.db"
    receiver, executor, watchdog, _, drain_overrides = build(db)

    stop = threading.Event()
    poller = threading.Thread(
        target=_poll_loop, args=(executor, watchdog, drain_overrides, stop), daemon=True
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
