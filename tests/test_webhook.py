"""Increment 2.1 done-when — the webhook receiver, ADVERSARIAL shape.

Run from the gated/ root:  python3 -m unittest discover -s tests

2.1 is a PURE receiver: a gating event is ENQUEUED (202), never written to GitHub
synchronously (that + durable idempotency is 2.2). The security property is the
REJECTIONS, so the test proves the door is closed by ATTEMPTING each way through it:

  valid signed pull_request (opened + synchronize) -> ACCEPTED, event enqueued
  forged signature                                 -> REJECTED (+ audited)
  tampered body (signed A, delivered B)            -> REJECTED
  missing / malformed signature header             -> REJECTED
  valid GitHub signature but wrong app-id          -> REJECTED   (authz, not authn)
  valid GitHub signature but wrong installation    -> REJECTED   (the headline catch)
  EMPTY allowlist                                  -> REJECTED   (fail-closed by design)
  replayed delivery-id                             -> IGNORED, not re-enqueued
  ping / unknown event                             -> IGNORED, acked, not choked on
  non-gating action                                -> IGNORED, no enqueue
  sink backpressure (SinkFull)                     -> ERROR 5xx, delivery NOT recorded
"""
from __future__ import annotations

import hashlib
import hmac
import json
import unittest

from gate.audit import RejectionEvent
from gate.dedup import InMemoryDeliveryLog
from gate.queue import GatingEvent, SinkFull
from gate.secret import StaticSecretSource
from gate.webhook import Reason, ReceiverOutcome, WebhookReceiver

_SECRET = b"s3cr3t-webhook-key"
_APP_ID = 424242
_INSTALL_OK = 9001
_INSTALL_OTHER = 9999


class _Headers:
    """Case-insensitive header double (mimics email.message.Message.get)."""

    def __init__(self, items: dict[str, str]) -> None:
        self._items = {k.lower(): v for k, v in items.items()}

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._items.get(name.lower(), default)


class _RecordingSink:
    """Records enqueued gating events."""

    def __init__(self) -> None:
        self.events: list[GatingEvent] = []

    def enqueue(self, event: GatingEvent) -> None:
        self.events.append(event)


class _FullSink:
    """Always at capacity — models backpressure."""

    def enqueue(self, event: GatingEvent) -> None:
        raise SinkFull("runner saturated")


class _RecordingAudit:
    def __init__(self) -> None:
        self.rejections: list[RejectionEvent] = []

    def record_rejection(self, event: RejectionEvent) -> None:
        self.rejections.append(event)


def _body(
    *, action: str = "opened", installation_id: int = _INSTALL_OK, head_sha: str = "a" * 40
) -> bytes:
    return json.dumps(
        {
            "action": action,
            "installation": {"id": installation_id},
            "repository": {"full_name": "acme/widgets"},
            "pull_request": {"head": {"sha": head_sha}},
        }
    ).encode("utf-8")


def _sign(secret: bytes, raw_body: bytes) -> str:
    return "sha256=" + hmac.new(secret, raw_body, hashlib.sha256).hexdigest()


def _headers(
    raw_body: bytes,
    *,
    event: str = "pull_request",
    delivery: str = "d-1",
    signature: str | None = "__auto__",
    app_id: int = _APP_ID,
    target_type: str = "integration",
) -> _Headers:
    items: dict[str, str] = {
        "X-GitHub-Event": event,
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Hook-Installation-Target-Type": target_type,
        "X-GitHub-Hook-Installation-Target-ID": str(app_id),
    }
    if signature == "__auto__":
        items["X-Hub-Signature-256"] = _sign(_SECRET, raw_body)
    elif signature is not None:
        items["X-Hub-Signature-256"] = signature
    return _Headers(items)


class WebhookReceiverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sink = _RecordingSink()
        self.audit = _RecordingAudit()
        self.log = InMemoryDeliveryLog()
        self.receiver = WebhookReceiver(
            secret_source=StaticSecretSource(_SECRET),
            app_id=_APP_ID,
            authorized_installations=frozenset({_INSTALL_OK}),
            gating_sink=self.sink,
            delivery_log=self.log,
            audit_sink=self.audit,
        )

    # ---- accepted (the happy paths) --------------------------------------

    def test_valid_opened_accepted_and_event_enqueued(self) -> None:
        body = _body(action="opened", head_sha="c" * 40)
        r = self.receiver.handle(_headers(body), body)
        self.assertIs(r.outcome, ReceiverOutcome.ACCEPTED)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(r.head_sha, "c" * 40)
        self.assertEqual(len(self.sink.events), 1)
        self.assertEqual(self.sink.events[0].head_sha, "c" * 40)
        self.assertEqual(self.sink.events[0].repo_full_name, "acme/widgets")
        self.assertEqual(self.sink.events[0].installation_id, _INSTALL_OK)

    def test_synchronize_gated_same_as_opened(self) -> None:
        # H1: a new push (synchronize) must be gated with the same rigor as opened.
        body = _body(action="synchronize", head_sha="d" * 40)
        r = self.receiver.handle(_headers(body, delivery="d-sync"), body)
        self.assertIs(r.outcome, ReceiverOutcome.ACCEPTED)
        self.assertEqual(self.sink.events[0].action, "synchronize")

    # ---- rejected: authentication ----------------------------------------

    def test_forged_signature_rejected_and_audited(self) -> None:
        body = _body()
        bad = "sha256=" + "0" * 64
        r = self.receiver.handle(_headers(body, signature=bad), body, source="1.2.3.4")
        self.assertIs(r.outcome, ReceiverOutcome.REJECTED)
        self.assertIs(r.reason, Reason.SIGNATURE_MISMATCH)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.sink.events, [])
        # the boundary logged the security event (source carried through)
        self.assertEqual(len(self.audit.rejections), 1)
        self.assertEqual(self.audit.rejections[0].reason, "signature_mismatch")
        self.assertEqual(self.audit.rejections[0].source, "1.2.3.4")

    def test_tampered_body_rejected(self) -> None:
        signed = _body(head_sha="a" * 40)
        delivered = _body(head_sha="b" * 40)  # different bytes than were signed
        headers = _Headers(
            {
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "d-tamper",
                "X-GitHub-Hook-Installation-Target-Type": "integration",
                "X-GitHub-Hook-Installation-Target-ID": str(_APP_ID),
                "X-Hub-Signature-256": _sign(_SECRET, signed),
            }
        )
        r = self.receiver.handle(headers, delivered)
        self.assertIs(r.reason, Reason.SIGNATURE_MISMATCH)
        self.assertEqual(self.sink.events, [])

    def test_missing_signature_rejected(self) -> None:
        body = _body()
        r = self.receiver.handle(_headers(body, signature=None), body)
        self.assertIs(r.reason, Reason.SIGNATURE_MISSING)
        self.assertEqual(r.status_code, 401)

    def test_malformed_signature_rejected(self) -> None:
        body = _body()
        r = self.receiver.handle(_headers(body, signature="garbage"), body)
        self.assertIs(r.reason, Reason.SIGNATURE_MALFORMED)

    def test_wrong_prefix_signature_rejected(self) -> None:
        body = _body()
        sha1ish = "sha1=" + "a" * 40
        r = self.receiver.handle(_headers(body, signature=sha1ish), body)
        self.assertIs(r.reason, Reason.SIGNATURE_MALFORMED)

    # ---- rejected: authorization (authenticated but not authorized) ------

    def test_wrong_app_id_rejected(self) -> None:
        # Genuinely GitHub-signed, but the webhook config belongs to another App.
        body = _body()
        headers = _headers(body, app_id=_APP_ID + 1)
        assert headers.get("X-Hub-Signature-256") == _sign(_SECRET, body)
        r = self.receiver.handle(headers, body)
        self.assertIs(r.outcome, ReceiverOutcome.REJECTED)
        self.assertIs(r.reason, Reason.UNAUTHORIZED_APP)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.sink.events, [])

    def test_wrong_installation_rejected_the_headline_catch(self) -> None:
        # AUTHENTICATED (valid HMAC) but NOT AUTHORIZED (an install we don't gate).
        body = _body(installation_id=_INSTALL_OTHER)
        r = self.receiver.handle(_headers(body), body)
        self.assertIs(r.outcome, ReceiverOutcome.REJECTED)
        self.assertIs(r.reason, Reason.UNAUTHORIZED_INSTALLATION)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(self.sink.events, [])

    def test_empty_allowlist_fails_closed(self) -> None:
        # An unconfigured allowlist must authorize NOTHING (the classic footgun is
        # "empty => allow all"). A valid, authentic webhook is still rejected.
        receiver = WebhookReceiver(
            secret_source=StaticSecretSource(_SECRET),
            app_id=_APP_ID,
            authorized_installations=frozenset(),  # empty
            gating_sink=self.sink,
            delivery_log=self.log,
            audit_sink=self.audit,
        )
        body = _body(installation_id=_INSTALL_OK)
        r = receiver.handle(_headers(body), body)
        self.assertIs(r.outcome, ReceiverOutcome.REJECTED)
        self.assertIs(r.reason, Reason.UNAUTHORIZED_INSTALLATION)
        self.assertEqual(self.sink.events, [])

    def test_authentic_but_unparseable_body_rejected(self) -> None:
        raw = b"{not json"
        headers = _Headers(
            {
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "d-badjson",
                "X-GitHub-Hook-Installation-Target-Type": "integration",
                "X-GitHub-Hook-Installation-Target-ID": str(_APP_ID),
                "X-Hub-Signature-256": _sign(_SECRET, raw),  # authentic bytes
            }
        )
        r = self.receiver.handle(headers, raw)
        self.assertIs(r.reason, Reason.BODY_UNPARSEABLE)
        self.assertEqual(r.status_code, 400)

    # ---- ignored: authentic + authorized, nothing to gate ----------------

    def test_ping_event_acked_not_choked(self) -> None:
        # GitHub sends a ping on webhook setup; choking on it fails setup.
        body = json.dumps(
            {"zen": "Keep it simple.", "installation": {"id": _INSTALL_OK}}
        ).encode()
        r = self.receiver.handle(_headers(body, event="ping", delivery="d-ping"), body)
        self.assertIs(r.outcome, ReceiverOutcome.IGNORED)
        self.assertIs(r.reason, Reason.NON_PULL_REQUEST_EVENT)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.sink.events, [])

    def test_check_run_rerequested_is_gated(self) -> None:
        # the re-run lever for an action_required (ERROR) check: check_run/rerequested
        # must gate the SAME head SHA, not be dropped as a non-pull_request event.
        body = json.dumps(
            {
                "action": "rerequested",
                "installation": {"id": _INSTALL_OK},
                "repository": {"full_name": "acme/widgets"},
                "check_run": {"head_sha": "f" * 40},
            }
        ).encode("utf-8")
        r = self.receiver.handle(_headers(body, event="check_run", delivery="d-rerun"), body)
        self.assertIs(r.outcome, ReceiverOutcome.ACCEPTED)
        self.assertEqual(self.sink.events[0].head_sha, "f" * 40)
        self.assertEqual(self.sink.events[0].action, "rerequested")

    def test_check_run_other_action_ignored(self) -> None:
        body = _body()
        r = self.receiver.handle(_headers(body, event="check_run", delivery="d-cr"), body)
        self.assertIs(r.outcome, ReceiverOutcome.IGNORED)
        self.assertEqual(self.sink.events, [])

    def test_unknown_event_ignored(self) -> None:
        body = _body()
        r = self.receiver.handle(_headers(body, event="push", delivery="d-push"), body)
        self.assertIs(r.reason, Reason.NON_PULL_REQUEST_EVENT)
        self.assertEqual(self.sink.events, [])

    def test_non_gating_action_ignored(self) -> None:
        body = _body(action="labeled")
        r = self.receiver.handle(_headers(body, delivery="d-label"), body)
        self.assertIs(r.outcome, ReceiverOutcome.IGNORED)
        self.assertIs(r.reason, Reason.NON_GATING_ACTION)
        self.assertEqual(self.sink.events, [])

    # ---- replay: idempotent, not a rejection -----------------------------

    def test_replayed_delivery_ignored_and_not_reenqueued(self) -> None:
        body = _body(head_sha="e" * 40)
        first = self.receiver.handle(_headers(body, delivery="dup"), body)
        second = self.receiver.handle(_headers(body, delivery="dup"), body)
        self.assertIs(first.outcome, ReceiverOutcome.ACCEPTED)
        self.assertIs(second.outcome, ReceiverOutcome.IGNORED)
        self.assertIs(second.reason, Reason.REPLAY)
        self.assertEqual(len(self.sink.events), 1)  # NOT enqueued twice

    # ---- error: backpressure -> fail-closed, delivery not recorded -------

    def test_backpressure_is_error_and_not_recorded(self) -> None:
        receiver = WebhookReceiver(
            secret_source=StaticSecretSource(_SECRET),
            app_id=_APP_ID,
            authorized_installations=frozenset({_INSTALL_OK}),
            gating_sink=_FullSink(),
            delivery_log=self.log,
            audit_sink=self.audit,
        )
        body = _body()
        r = receiver.handle(_headers(body, delivery="d-full"), body)
        self.assertIs(r.outcome, ReceiverOutcome.ERROR)
        self.assertIs(r.reason, Reason.BACKPRESSURE)
        self.assertGreaterEqual(r.status_code, 500)
        # NOT recorded -> GitHub's re-delivery re-attempts once the runner drains.
        self.assertFalse(self.log.seen("d-full"))


if __name__ == "__main__":
    unittest.main()
