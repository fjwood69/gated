"""gate/http_server.py — thin stdlib transport for the webhook receiver.

Zero-dependency (Apache-core purity): the receiver logic lives in ``webhook.py``;
this only reads the raw request bytes + headers, applies the transport-layer guards
(body-size cap, per-source rate limit), and maps ``ReceiverResult`` to an HTTP
response. A reference server for the podman-on-NUC build — a production deployment may
front the same ``WebhookReceiver`` with any WSGI/ASGI stack.

Run:  python3 -m gate.http_server   (needs GATED_WEBHOOK_SECRET,
      GATED_APP_ID, GATED_INSTALLATION_IDS set)
"""
from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import LoggingAuditSink
from .dedup import InMemoryDeliveryLog
from .queue import InMemoryGatingSink
from .ratelimit import RateLimiter, TokenBucketRateLimiter
from .secret import EnvSecretSource
from .webhook import ReceiverResult, WebhookReceiver

# GitHub caps webhook payloads at ~25 MiB; anything larger is definitionally
# not-from-GitHub and is rejected on the declared Content-Length BEFORE the body is
# read into memory. The per-source rate limit bounds the flood case.
_MAX_BODY_BYTES = 25 * 1024 * 1024


def _handler_factory(
    receiver: WebhookReceiver, limiter: RateLimiter
) -> type[BaseHTTPRequestHandler]:
    class _WebhookHandler(BaseHTTPRequestHandler):
        server_version = "gated-gate/2.1"

        def do_POST(self) -> None:  # noqa: N802 (stdlib dispatch name)
            source = self.client_address[0] if self.client_address else "unknown"
            if not limiter.allow(source):
                self._respond(429, {"reason": "rate_limited"})
                return
            length = self._content_length()
            if length is None or length > _MAX_BODY_BYTES:
                self._respond(413, {"reason": "body_too_large"})
                return
            raw_body = self.rfile.read(length)
            # ``self.headers`` is an email.message.Message -> case-insensitive .get
            result = receiver.handle(self.headers, raw_body, source)
            self._respond(
                result.status_code,
                {"outcome": result.outcome.value, "reason": result.reason.value},
            )

        def do_GET(self) -> None:  # noqa: N802 (stdlib dispatch name)
            # Ingress-liveness: an external monitor points here THROUGH the tunnel, so a
            # dropped tunnel / hung server goes dark and alerts — distinguishing
            # "blocking because the gate judged the code" from "blocking because deaf".
            if self.path.split("?", 1)[0] == "/health":
                self._respond(200, {"status": "ok"})
            else:
                self._respond(404, {"reason": "not_found"})

        def _content_length(self) -> int | None:
            raw = self.headers.get("Content-Length")
            if raw is None:
                return None
            try:
                value = int(raw)
            except ValueError:
                return None
            return value if value >= 0 else None

        def _respond(self, status: int, body: dict[str, str]) -> None:
            payload = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, fmt: str, *args: object) -> None:
            # Quiet the default access log; security events go through the audit sink.
            return

    return _WebhookHandler


def build_reference_receiver() -> WebhookReceiver:
    """Wire a receiver from env for the reference (podman-on-NUC) run. Gating events
    land in an in-memory sink (2.1 has no consumer yet — the executor is 2.3)."""
    app_id = int(os.environ["GATED_APP_ID"])
    installs = frozenset(
        int(x) for x in os.environ.get("GATED_INSTALLATION_IDS", "").split(",") if x
    )
    return WebhookReceiver(
        secret_source=EnvSecretSource(),
        app_id=app_id,
        authorized_installations=installs,
        gating_sink=InMemoryGatingSink(),
        delivery_log=InMemoryDeliveryLog(),
        audit_sink=LoggingAuditSink(),
    )


def serve(host: str = "0.0.0.0", port: int = 8969) -> None:
    receiver = build_reference_receiver()
    # 20 tokens, refilled 5/s per source — generous for GitHub, caps a flood.
    limiter = TokenBucketRateLimiter(
        capacity=20.0, refill_per_sec=5.0, clock=time.monotonic
    )
    httpd = ThreadingHTTPServer((host, port), _handler_factory(receiver, limiter))
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


__all__ = ["serve", "build_reference_receiver", "ReceiverResult"]


if __name__ == "__main__":  # pragma: no cover - reference entry point
    serve()
