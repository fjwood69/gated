"""gate/webhook.py — the webhook receiver (Increment 2.1).

The entry-point trust boundary of the Promotion Gate. Harness-agnostic PURE logic
(no HTTP, no GitHub write, no I/O beyond the injected seams) so it is fully testable
with stub payloads — ``WebhookReceiver.handle(headers, raw_body, source) -> ReceiverResult``.

2.1 is a RECEIVER, not a writer: on a gating event it ENQUEUES a ``GatingEvent`` and
returns 202 immediately, decoupling the ack from GitHub's API latency (a synchronous
Check Run write here would risk GitHub's ~10s delivery timeout -> re-delivery ->
duplicate check). Creating the Check Run — with durable Claim-Process-Complete
idempotency — is 2.2, where the persistent store lives.

The order is fail-closed and each gate must pass before the next:

  1. signature present + well-formed          (else REJECTED, 401)
  2. HMAC-SHA256 over the RAW body matches     (else REJECTED, 401)   <- AUTHENTICATION
     ── everything past here is genuinely-from-GitHub ──
  3. app-id header matches OUR App             (else REJECTED, 403)   <- AUTHORIZATION
  4. body parses as JSON                       (else REJECTED, 400, fail-closed)
  5. installation.id is one WE gate            (else REJECTED, 403)   <- AUTHORIZATION
     ── the headline catch: GitHub-signed != authorized-for-this-install ──
     ── empty allowlist => nothing is authorized => reject-all (fail-closed) ──
  6. delivery-id not already handled           (else IGNORED/REPLAY, 200, idempotent)
  7. classify event:
       ping / non-pull_request  -> IGNORED, 200 (acked, never choked on)
       pull_request, non-gating -> IGNORED, 200
       pull_request, gating     -> ENQUEUE GatingEvent, record delivery-id -> ACCEPTED, 202
                                    (backpressure -> ERROR 503, GitHub retries)

Every REJECTED / ERROR decision is emitted to the audit sink — the trust boundary is
where security events happen, so it is where the audit trail starts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .audit import AuditSink, LoggingAuditSink, RejectionEvent
from .dedup import DeliveryLog
from .queue import GatingEvent, GatingSink, OverrideCaptureEvent, OverrideSink, SinkFull
from .secret import SecretMissingError, SecretSource

# PR actions that mean "the code to gate has (re)appeared". `synchronize` (a new push
# to the PR head) MUST be gated with the same rigor as `opened` — else a force-push
# past a stale PASS is unguarded. `reopened` re-arms a PR.
GATING_ACTIONS = frozenset({"opened", "synchronize", "reopened"})

_SHA256_HEX_LEN = 64
_SIG_PREFIX = "sha256="


class Headers(Protocol):
    """Case-insensitive header access (``email.message.Message`` satisfies this;
    a test double is provided in the tests). ``name`` is positional-only so both
    ``Message.get(name, failobj=...)`` and a ``get(name, default=...)`` double
    structurally match."""

    def get(self, name: str, /) -> str | None: ...


class ReceiverOutcome(Enum):
    ACCEPTED = "accepted"  # gating event -> enqueued for the async executor
    IGNORED = "ignored"    # authentic + authorized but nothing to gate (or a replay)
    REJECTED = "rejected"  # a security gate failed -> 4xx, no processing
    ERROR = "error"        # our side failed (backpressure) -> 5xx, GitHub retries


class Reason(Enum):
    # accepted
    GATING_EVENT = "gating_event"
    # ignored (authentic + authorized)
    NON_PULL_REQUEST_EVENT = "non_pull_request_event"
    NON_GATING_ACTION = "non_gating_action"
    REPLAY = "replay"
    MERGE_CAPTURED = "merge_captured"        # C3: closed+merged handed to the override ledger
    CLOSED_UNMERGED = "closed_unmerged"      # C3: a discarded PR — no override to record
    # rejected (security)
    SIGNATURE_MISSING = "signature_missing"
    SIGNATURE_MALFORMED = "signature_malformed"
    SIGNATURE_MISMATCH = "signature_mismatch"
    UNAUTHORIZED_APP = "unauthorized_app"
    UNAUTHORIZED_INSTALLATION = "unauthorized_installation"
    BODY_UNPARSEABLE = "body_unparseable"
    SECRET_UNAVAILABLE = "secret_unavailable"
    # error (our side)
    BACKPRESSURE = "backpressure"


@dataclass(frozen=True)
class ReceiverResult:
    outcome: ReceiverOutcome
    reason: Reason
    status_code: int
    delivery_id: str | None = None
    head_sha: str | None = None  # set on ACCEPTED: the SHA the gating event was bound to


def _is_hex(s: str) -> bool:
    try:
        int(s, 16)
    except ValueError:
        return False
    return True


def _check_signature(secret: bytes, raw_body: bytes, header: str | None) -> Reason | None:
    """Return a rejection Reason, or None if the signature is valid. Fail-closed:
    a missing or malformed signature is rejected, never skipped."""
    if not header:
        return Reason.SIGNATURE_MISSING
    if not header.startswith(_SIG_PREFIX):
        return Reason.SIGNATURE_MALFORMED
    provided = header[len(_SIG_PREFIX):]
    if len(provided) != _SHA256_HEX_LEN or not _is_hex(provided):
        return Reason.SIGNATURE_MALFORMED
    expected = hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    # constant-time compare — no early-exit timing side channel on the digest
    if not hmac.compare_digest(expected, provided):
        return Reason.SIGNATURE_MISMATCH
    return None


class WebhookReceiver:
    """Verifies, authorizes, classifies, and (for gating events) enqueues. Never
    writes to GitHub and never blocks on a downstream — transport-agnostic."""

    def __init__(
        self,
        *,
        secret_source: SecretSource,
        app_id: int,
        authorized_installations: frozenset[int],
        gating_sink: GatingSink,
        delivery_log: DeliveryLog,
        audit_sink: AuditSink | None = None,
        override_sink: OverrideSink | None = None,
    ) -> None:
        self._secret_source = secret_source
        self._app_id = app_id
        self._authorized_installations = authorized_installations
        self._gating_sink = gating_sink
        self._delivery_log = delivery_log
        self._audit = audit_sink if audit_sink is not None else LoggingAuditSink()
        # C3: where a merged-PR capture is handed off. None => C3 disabled (closed events
        # fall through as non-gating), so the receiver is backward-compatible.
        self._override_sink = override_sink

    def handle(
        self, headers: Headers, raw_body: bytes, source: str | None = None
    ) -> ReceiverResult:
        delivery_id = headers.get("X-GitHub-Delivery") or None

        # 1-2. AUTHENTICATION — the signature over the RAW body.
        try:
            secret = self._secret_source.webhook_secret()
        except SecretMissingError:
            # We cannot verify -> we cannot trust -> fail closed (do NOT process).
            return self._reject(Reason.SECRET_UNAVAILABLE, 503, delivery_id, source)
        sig_fail = _check_signature(secret, raw_body, headers.get("X-Hub-Signature-256"))
        if sig_fail is not None:
            return self._reject(sig_fail, 401, delivery_id, source)

        # 3. AUTHORIZATION (App) — is this webhook config even OUR App? GitHub sends
        # the target App identity in headers on every delivery.
        target_type = headers.get("X-GitHub-Hook-Installation-Target-Type")
        target_id = headers.get("X-GitHub-Hook-Installation-Target-ID")
        if target_type != "integration" or target_id != str(self._app_id):
            return self._reject(Reason.UNAUTHORIZED_APP, 403, delivery_id, source)

        # 4. Parse — safe now (authenticated). Unparseable authentic body = fail closed.
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._reject(Reason.BODY_UNPARSEABLE, 400, delivery_id, source)
        if not isinstance(payload, dict):
            return self._reject(Reason.BODY_UNPARSEABLE, 400, delivery_id, source)

        # 5. AUTHORIZATION (installation) — the headline catch. A genuinely
        # GitHub-signed webhook for an installation we DON'T gate must be rejected.
        # An empty allowlist authorizes NOTHING -> reject-all (fail-closed by design).
        installation_id = self._installation_id(payload)
        if installation_id is None or installation_id not in self._authorized_installations:
            return self._reject(Reason.UNAUTHORIZED_INSTALLATION, 403, delivery_id, source)

        # 6. Replay — idempotent, NOT a rejection. GitHub re-delivers legitimately.
        if delivery_id is not None and self._delivery_log.seen(delivery_id):
            return ReceiverResult(ReceiverOutcome.IGNORED, Reason.REPLAY, 200, delivery_id)

        # 7. Classify + act.
        return self._classify_and_act(headers, payload, delivery_id, installation_id, source)

    def _classify_and_act(
        self,
        headers: Headers,
        payload: dict[str, object],
        delivery_id: str | None,
        installation_id: int,
        source: str | None,
    ) -> ReceiverResult:
        event = headers.get("X-GitHub-Event")
        action = payload.get("action") if isinstance(payload.get("action"), str) else None

        if event == "pull_request" and action in GATING_ACTIONS:
            return self._gate(payload, delivery_id, installation_id, source,
                              action or "", self._head_sha(payload))
        if event == "check_run" and action == "rerequested":
            # the developer's RE-RUN lever: an ERROR check posted `action_required` has
            # no "re-run" for transient infra faults except this — GitHub fires a
            # check_run/rerequested event; gate it like a fresh push on the same SHA.
            return self._gate(payload, delivery_id, installation_id, source,
                              "rerequested", self._check_run_head_sha(payload))
        if event == "pull_request" and action == "closed":
            # C3 override capture: a merged close is the audit trigger; a DISCARDED PR
            # (closed unmerged) has nothing to override — drop it (board mandate).
            return self._closed(payload, delivery_id, source)
        if event == "pull_request":
            self._record(delivery_id)
            return ReceiverResult(
                ReceiverOutcome.IGNORED, Reason.NON_GATING_ACTION, 200, delivery_id
            )
        # ping (webhook setup handshake), push, other check_run actions — ack + ignore.
        self._record(delivery_id)
        return ReceiverResult(
            ReceiverOutcome.IGNORED, Reason.NON_PULL_REQUEST_EVENT, 200, delivery_id
        )

    def _gate(
        self,
        payload: dict[str, object],
        delivery_id: str | None,
        installation_id: int,
        source: str | None,
        action: str,
        head_sha: str | None,
    ) -> ReceiverResult:
        repo_full_name = self._repo_full_name(payload)
        if repo_full_name is None or head_sha is None:
            # A gating event with no head SHA / repo is malformed; we cannot bind a
            # GatingEvent -> fail closed rather than pretend.
            return self._reject(Reason.BODY_UNPARSEABLE, 400, delivery_id, source)

        gating_event = GatingEvent(
            delivery_id=delivery_id or "",
            repo_full_name=repo_full_name,          # ALWAYS the base repo (check + ledger)
            head_sha=head_sha,
            action=action,
            installation_id=installation_id,
            head_repo_full_name=self._head_repo_full_name(payload),  # fork repo (C2 fetch hint)
        )
        try:
            self._gating_sink.enqueue(gating_event)
        except SinkFull:
            # Backpressure — do NOT record the delivery-id: return 503 so GitHub
            # re-delivers once the runner drains (never a dropped, unqueued PR).
            return self._reject(Reason.BACKPRESSURE, 503, delivery_id, source, ReceiverOutcome.ERROR)

        self._record(delivery_id)  # enqueued -> record for replay idempotency
        return ReceiverResult(
            ReceiverOutcome.ACCEPTED, Reason.GATING_EVENT, 202, delivery_id, head_sha=head_sha
        )

    def _closed(
        self,
        payload: dict[str, object],
        delivery_id: str | None,
        source: str | None,
    ) -> ReceiverResult:
        """C3: a `pull_request` closed. Merged -> hand a capture to the override ledger;
        discarded (unmerged) -> drop. Observational only: this NEVER enqueues a gating job
        and NEVER changes a merge decision."""
        if not self._is_merged(payload) or self._override_sink is None:
            # unmerged close, or C3 not wired — nothing to record.
            self._record(delivery_id)
            return ReceiverResult(
                ReceiverOutcome.IGNORED, Reason.CLOSED_UNMERGED, 200, delivery_id
            )
        repo_full_name = self._repo_full_name(payload)
        head_sha = self._head_sha(payload)
        if repo_full_name is None or head_sha is None:
            return self._reject(Reason.BODY_UNPARSEABLE, 400, delivery_id, source)

        capture = OverrideCaptureEvent(
            delivery_id=delivery_id or "",
            repo_full_name=repo_full_name,
            head_sha=head_sha,
            pr_number=self._pr_number(payload),
            merged_by=self._merged_by(payload),
            merged_at=self._merged_at(payload),
        )
        try:
            self._override_sink.enqueue(capture)
        except SinkFull:
            # Backpressure — do NOT record the delivery-id: 503 so GitHub re-delivers the
            # merged close (the ledger's delivery_id UNIQUE makes re-delivery idempotent).
            return self._reject(Reason.BACKPRESSURE, 503, delivery_id, source, ReceiverOutcome.ERROR)

        self._record(delivery_id)
        return ReceiverResult(
            ReceiverOutcome.IGNORED, Reason.MERGE_CAPTURED, 200, delivery_id, head_sha=head_sha
        )

    def _reject(
        self,
        reason: Reason,
        status: int,
        delivery_id: str | None,
        source: str | None,
        outcome: ReceiverOutcome = ReceiverOutcome.REJECTED,
    ) -> ReceiverResult:
        # The trust boundary is where security events happen -> where the audit starts.
        self._audit.record_rejection(
            RejectionEvent(
                reason=reason.value,
                status_code=status,
                delivery_id=delivery_id,
                source=source,
            )
        )
        return ReceiverResult(outcome, reason, status, delivery_id)

    def _record(self, delivery_id: str | None) -> None:
        if delivery_id is not None:
            self._delivery_log.record(delivery_id)

    @staticmethod
    def _installation_id(payload: dict[str, object]) -> int | None:
        inst = payload.get("installation")
        if isinstance(inst, dict):
            iid = inst.get("id")
            if isinstance(iid, int):
                return iid
        return None

    @staticmethod
    def _repo_full_name(payload: dict[str, object]) -> str | None:
        repo = payload.get("repository")
        if isinstance(repo, dict):
            name = repo.get("full_name")
            if isinstance(name, str) and name:
                return name
        return None

    @staticmethod
    def _head_sha(payload: dict[str, object]) -> str | None:
        pr = payload.get("pull_request")
        if isinstance(pr, dict):
            head = pr.get("head")
            if isinstance(head, dict):
                sha = head.get("sha")
                if isinstance(sha, str) and sha:
                    return sha
        return None

    @staticmethod
    def _check_run_head_sha(payload: dict[str, object]) -> str | None:
        run = payload.get("check_run")
        if isinstance(run, dict):
            sha = run.get("head_sha")
            if isinstance(sha, str) and sha:
                return sha
        return None

    @staticmethod
    def _head_repo_full_name(payload: dict[str, object]) -> str | None:
        """The FORK's repo (`pull_request.head.repo.full_name`) — differs from the base for
        a cross-repo PR; a fetch hint only. None for same-repo PRs / non-PR events."""
        pr = payload.get("pull_request")
        if isinstance(pr, dict):
            head = pr.get("head")
            if isinstance(head, dict):
                repo = head.get("repo")
                if isinstance(repo, dict):
                    name = repo.get("full_name")
                    if isinstance(name, str) and name:
                        return name
        return None

    @staticmethod
    def _is_merged(payload: dict[str, object]) -> bool:
        pr = payload.get("pull_request")
        return isinstance(pr, dict) and pr.get("merged") is True

    @staticmethod
    def _pr_number(payload: dict[str, object]) -> int | None:
        n = payload.get("number")
        return n if isinstance(n, int) else None

    @staticmethod
    def _merged_by(payload: dict[str, object]) -> str | None:
        pr = payload.get("pull_request")
        if isinstance(pr, dict):
            mb = pr.get("merged_by")
            if isinstance(mb, dict):
                login = mb.get("login")
                if isinstance(login, str) and login:
                    return login
        # fall back to the event sender (the actor who triggered the close)
        sender = payload.get("sender")
        if isinstance(sender, dict):
            login = sender.get("login")
            if isinstance(login, str) and login:
                return login
        return None

    @staticmethod
    def _merged_at(payload: dict[str, object]) -> str | None:
        pr = payload.get("pull_request")
        if isinstance(pr, dict):
            ts = pr.get("merged_at")
            if isinstance(ts, str) and ts:
                return ts
        return None
