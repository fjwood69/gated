"""C3 — the Override-Ledger capture. Run from gated/:  python3 -m unittest discover -s tests

The load-bearing done-tests: an admin-merge past a recorded non-PASS verdict appends a
tamper-evident HUMAN_OVERRIDE; a clean PASS-merge is SILENT; an unattestable merge records
an UNVERIFIABLE with the RIGHT sub-reason; the chain detects tampering; the delivery_id is
idempotent; the capture NEVER re-computes (no engine); and the auditor-facing line does NOT
overclaim "required check bypassed" (the truthful-capture headline). No podman — the verdict
rows are supplied directly so the CLASSIFIER + LEDGER are what is under test.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from gate.dedup import InMemoryDeliveryLog
from gate.ledger import (
    OutcomeKind,
    OverrideKind,
    OverrideLedger,
    UnverifiableReason,
    VerdictRow,
    capture_override,
    classify_merge,
    render_ledger_line,
)
from gate.queue import InMemoryOverrideSink, OverrideCaptureEvent, SinkFull
from gate.secret import StaticSecretSource
from gate.webhook import Reason, ReceiverOutcome, WebhookReceiver

_APP_ID = 4249290
_INSTALL_OK = 111
_SECRET = b"shhh-c3"


def _row(status: str, verdict: str | None = None, reason: str | None = None, t: float = 1.0,
         gate_outcome: str | None = None) -> VerdictRow:
    return VerdictRow(status=status, verdict=verdict, reason=reason, updated_at=t, gate_outcome=gate_outcome)


def _ledger() -> OverrideLedger:
    d = Path(tempfile.mkdtemp(prefix="mv-c3-"))
    return OverrideLedger(d / "override-ledger.db")


def _event(delivery: str = "closed-1", sha: str = "a" * 40, pr: int | None = 7) -> OverrideCaptureEvent:
    return OverrideCaptureEvent(
        delivery_id=delivery, repo_full_name="acme/widgets", head_sha=sha,
        pr_number=pr, merged_by="admin-alice", merged_at="2026-07-09T18:00:00Z",
    )


# ---- the classifier (pure taxonomy) ------------------------------------------

class ClassifyMergeTests(unittest.TestCase):
    def test_fail_is_human_override(self) -> None:
        o = classify_merge([_row("done", "fail", "EGRESS_ONE")])
        self.assertIs(o.kind, OutcomeKind.HUMAN_OVERRIDE)
        self.assertEqual(o.verdict, "fail")
        self.assertEqual(o.reason, "EGRESS_ONE")

    def test_error_verdict_is_human_override(self) -> None:
        o = classify_merge([_row("done", "error", "OBSERVATION_INCOMPLETE")])
        self.assertIs(o.kind, OutcomeKind.HUMAN_OVERRIDE)
        self.assertEqual(o.verdict, "error")

    def test_pass_is_no_override(self) -> None:
        self.assertIs(classify_merge([_row("done", "pass")]).kind, OutcomeKind.NO_OVERRIDE)

    def test_no_rows_is_never_evaluated(self) -> None:
        o = classify_merge([])
        self.assertIs(o.kind, OutcomeKind.UNVERIFIABLE)
        self.assertIs(o.sub_reason, UnverifiableReason.NEVER_EVALUATED)

    def test_processing_is_in_flight_even_with_a_stale_done(self) -> None:
        # F2 staleness: a newer check in flight must NOT be masked by an older done verdict.
        o = classify_merge([_row("done", "pass", t=1.0), _row("processing", t=2.0)])
        self.assertIs(o.sub_reason, UnverifiableReason.EVALUATION_IN_FLIGHT)

    def test_error_status_is_infra_not_verdict_error(self) -> None:
        # F3: delivery status='error' is retryable infra, NOT the gate's ERROR verdict.
        o = classify_merge([_row("error")])
        self.assertIs(o.sub_reason, UnverifiableReason.INFRA_ERROR)

    def test_allowing_done_plus_error_row_is_infra_error_not_no_override(self) -> None:
        # board C5, "infra cannot disappear": classify_merge returns from the `done` branch BEFORE the tail
        # error check, so a passing/neutral done row + an error row for the SAME sha would have MASKED the
        # error as NO_OVERRIDE. The infra fault (which blocked and was merged past) must be surfaced.
        o = classify_merge([_row("done", "pass", t=1.0), _row("error", t=2.0)])
        self.assertIs(o.kind, OutcomeKind.UNVERIFIABLE)
        self.assertIs(o.sub_reason, UnverifiableReason.INFRA_ERROR)
        # and the neutral-gate variant of "allowing" is masked identically without the fix.
        o2 = classify_merge([_row("done", verdict=None, gate_outcome="neutral_gate", t=1.0),
                             _row("error", t=2.0)])
        self.assertIs(o2.sub_reason, UnverifiableReason.INFRA_ERROR)

    def test_blocking_done_wins_over_a_coexisting_error_row(self) -> None:
        # C5 precedence: a DEFINITE blocking done outcome (a merged-past blocking verdict) is the salient,
        # most-specific fact and WINS even if an error row also exists for the sha.
        o = classify_merge([_row("done", "fail", "EGRESS_ONE", t=1.0), _row("error", t=2.0)])
        self.assertIs(o.kind, OutcomeKind.HUMAN_OVERRIDE)
        self.assertEqual(o.verdict, "fail")

    def test_error_only_force_merge_is_captured_not_silent(self) -> None:
        # the skeptic probe (RESOLVED): a force-merge past an infra-only sha is an UNVERIFIABLE/INFRA_ERROR
        # audit record — captured, NOT silently NO_OVERRIDE, and NOT mislabelled HUMAN_OVERRIDE (no verdict
        # was produced). capture_override appends every UNVERIFIABLE, so it is on the record.
        o = classify_merge([_row("error", t=1.0)])
        self.assertIs(o.kind, OutcomeKind.UNVERIFIABLE)
        self.assertIsNone(o.verdict)

    def test_lowercase_pass_is_allowing_uppercase_is_indeterminate(self) -> None:
        # dissent P1c + Fred ruling: the classifier matches the PERSISTED WIRE values (VerdictType.value ==
        # lowercase). A real 'pass' is ALLOWING (a clean merge -> NO_OVERRIDE). An uppercase 'PASS'/'FAIL' is
        # an UNKNOWN verdict (no documented historical uppercase wire format) -> INDETERMINATE, never trusted
        # as allowing/blocking.
        self.assertIs(classify_merge([_row("done", "pass")]).kind, OutcomeKind.NO_OVERRIDE)
        self.assertIs(classify_merge([_row("done", "PASS")]).sub_reason,
                      UnverifiableReason.INDETERMINATE_GATE)
        self.assertIs(classify_merge([_row("done", "FAIL", "EGRESS_ONE")]).sub_reason,
                      UnverifiableReason.INDETERMINATE_GATE)

    def test_contradictory_terminals_are_ambiguous(self) -> None:
        o = classify_merge([_row("done", "pass", t=1.0), _row("done", "fail", "EGRESS_ONE", t=2.0)])
        self.assertIs(o.sub_reason, UnverifiableReason.AMBIGUOUS)

    def test_block_gate_merged_past_is_human_override(self) -> None:
        # CP2 closure 1: a blocking NON-RUN gate (verdict=None) merged past IS a human override — not
        # NO_OVERRIDE. The gate outcome is classified independently of any engine verdict.
        o = classify_merge([_row("done", verdict=None, reason="block_action_required",
                                 gate_outcome="block_gate")])
        self.assertIs(o.kind, OutcomeKind.HUMAN_OVERRIDE)
        self.assertIsNone(o.verdict)                         # no fabricated engine verdict
        self.assertEqual(o.reason, "block_action_required")  # the stable gate-outcome reason

    def test_neutral_gate_merged_past_is_no_override(self) -> None:
        o = classify_merge([_row("done", verdict=None, reason="skip_neutral", gate_outcome="neutral_gate")])
        self.assertIs(o.kind, OutcomeKind.NO_OVERRIDE)

    def test_done_with_no_verdict_and_no_gate_is_indeterminate(self) -> None:
        # a historical (pre-CP2) done row, or an unaccounted write: NEVER a clean success.
        o = classify_merge([_row("done", verdict=None, gate_outcome=None)])
        self.assertIs(o.kind, OutcomeKind.UNVERIFIABLE)
        self.assertIs(o.sub_reason, UnverifiableReason.INDETERMINATE_GATE)

    def test_neutral_gate_plus_block_gate_is_ambiguous(self) -> None:
        o = classify_merge([_row("done", gate_outcome="neutral_gate", t=1.0),
                            _row("done", gate_outcome="block_gate", t=2.0)])
        self.assertIs(o.sub_reason, UnverifiableReason.AMBIGUOUS)

    def test_contradictory_pass_with_block_gate_is_indeterminate(self) -> None:
        # board: validate the COMPLETE pair — a PASS verdict tagged block_gate is incoherent, NOT allowing.
        o = classify_merge([_row("done", "pass", gate_outcome="block_gate")])
        self.assertIs(o.sub_reason, UnverifiableReason.INDETERMINATE_GATE)

    def test_run_verdict_gate_with_no_verdict_is_indeterminate(self) -> None:
        o = classify_merge([_row("done", verdict=None, gate_outcome="run_verdict")])
        self.assertIs(o.sub_reason, UnverifiableReason.INDETERMINATE_GATE)

    def test_unknown_verdict_string_is_indeterminate_not_blocking(self) -> None:
        # an unknown verdict must NOT auto-classify as blocking (would fabricate a HUMAN_OVERRIDE).
        o = classify_merge([_row("done", "WEIRD_VALUE")])
        self.assertIs(o.sub_reason, UnverifiableReason.INDETERMINATE_GATE)

    def test_verdict_paired_with_a_gate_is_indeterminate(self) -> None:
        o = classify_merge([_row("done", "fail", "EGRESS_ONE", gate_outcome="neutral_gate")])
        self.assertIs(o.sub_reason, UnverifiableReason.INDETERMINATE_GATE)

    def test_latest_non_pass_reason_wins(self) -> None:
        o = classify_merge([
            _row("done", "fail", "EGRESS_ONE", t=1.0),
            _row("done", "fail", "NON_DETERMINISTIC", t=2.0),
        ])
        self.assertEqual(o.reason, "NON_DETERMINISTIC")  # the effective-at-merge (latest) one


# ---- the ledger (append / idempotency / chain / tamper) ----------------------

class OverrideLedgerTests(unittest.TestCase):
    def test_append_then_verify_chain(self) -> None:
        lg = _ledger()
        lg.append(delivery_id="d1", kind=OverrideKind.HUMAN_OVERRIDE, repo_full_name="acme/widgets",
                  pr=1, sha="a" * 40, verdict="fail", reason="EGRESS_ONE")
        lg.append(delivery_id="d2", kind=OverrideKind.UNVERIFIABLE, repo_full_name="acme/widgets",
                  pr=2, sha="b" * 40, sub_reason="NEVER_EVALUATED")
        self.assertEqual(lg.count(), 2)
        self.assertTrue(lg.verify_chain())

    def test_chain_links_prev_to_record_hash(self) -> None:
        lg = _ledger()
        r1 = lg.append(delivery_id="d1", kind=OverrideKind.HUMAN_OVERRIDE,
                       repo_full_name="r", pr=1, sha="a" * 40, verdict="fail", reason="X").record
        r2 = lg.append(delivery_id="d2", kind=OverrideKind.HUMAN_OVERRIDE,
                       repo_full_name="r", pr=2, sha="b" * 40, verdict="fail", reason="Y").record
        self.assertEqual(r2.prev_hash, r1.record_hash)  # linear chain
        self.assertEqual(lg.head_anchor(), (r2.seq, r2.record_hash))

    def test_idempotent_on_delivery_id(self) -> None:
        # F4: at-least-once webhooks — a re-delivery must NOT double-stamp or fork the chain.
        lg = _ledger()
        a = lg.append(delivery_id="dup", kind=OverrideKind.HUMAN_OVERRIDE,
                      repo_full_name="r", pr=1, sha="a" * 40, verdict="fail", reason="X")
        b = lg.append(delivery_id="dup", kind=OverrideKind.HUMAN_OVERRIDE,
                      repo_full_name="r", pr=1, sha="a" * 40, verdict="fail", reason="X")
        self.assertTrue(a.newly_appended)
        self.assertFalse(b.newly_appended)
        self.assertEqual(a.record.seq, b.record.seq)
        self.assertEqual(lg.count(), 1)

    def test_tamper_of_prior_record_is_detected(self) -> None:
        lg = _ledger()
        lg.append(delivery_id="d1", kind=OverrideKind.HUMAN_OVERRIDE, repo_full_name="r",
                  pr=1, sha="a" * 40, verdict="fail", reason="EGRESS_ONE")
        lg.append(delivery_id="d2", kind=OverrideKind.HUMAN_OVERRIDE, repo_full_name="r",
                  pr=2, sha="b" * 40, verdict="fail", reason="EGRESS_ONE")
        self.assertTrue(lg.verify_chain())
        # an attacker edits row 1's verdict FAIL->PASS to hide the override, in place.
        conn = lg._conn()  # type: ignore[attr-defined]
        conn.execute("UPDATE override_ledger SET verdict='PASS' WHERE seq=1")
        self.assertFalse(lg.verify_chain())  # the chain catches the edit


# ---- the capture handler (the done-tests) ------------------------------------

class CaptureOverrideTests(unittest.TestCase):
    def test_fail_merge_appends_human_override_with_fields(self) -> None:
        lg = _ledger()
        rows = [_row("done", "fail", "EGRESS_ONE")]
        rec = capture_override(_event(), lambda _sha: rows, lg, policy_version="v1")
        assert rec is not None
        self.assertIs(rec.kind, OverrideKind.HUMAN_OVERRIDE)
        self.assertEqual((rec.verdict, rec.reason, rec.pr, rec.merged_by), ("fail", "EGRESS_ONE", 7, "admin-alice"))
        self.assertEqual(rec.policy_version, "v1")  # capture-time metadata, carried
        self.assertEqual(lg.count(), 1)

    def test_pass_merge_records_nothing(self) -> None:
        lg = _ledger()
        rec = capture_override(_event(), lambda _sha: [_row("done", "pass")], lg)
        self.assertIsNone(rec)  # D-Q1: clean merge is silent
        self.assertEqual(lg.count(), 0)

    def test_never_evaluated_merge_records_unverifiable(self) -> None:
        lg = _ledger()
        rec = capture_override(_event(), lambda _sha: [], lg)
        assert rec is not None
        self.assertIs(rec.kind, OverrideKind.UNVERIFIABLE)
        self.assertEqual(rec.sub_reason, "NEVER_EVALUATED")

    def test_capture_reads_only_the_lookup_never_recomputes(self) -> None:
        # NFR6: the capture path touches ONLY the injected verdict lookup — no engine, no
        # sandbox. Proven by the lookup being the sole external call the outcome depends on.
        lg = _ledger()
        calls: list[str] = []

        def lookup(sha: str) -> list[VerdictRow]:
            calls.append(sha)
            return [_row("done", "fail", "EGRESS_ONE")]

        capture_override(_event(sha="c" * 40), lookup, lg)
        self.assertEqual(calls, ["c" * 40])  # exactly one store read, keyed by the merged SHA

    def test_capture_is_idempotent_across_redelivery(self) -> None:
        lg = _ledger()
        rows = [_row("done", "fail", "EGRESS_ONE")]
        capture_override(_event(delivery="dup"), lambda _s: rows, lg)
        capture_override(_event(delivery="dup"), lambda _s: rows, lg)
        self.assertEqual(lg.count(), 1)

    def test_ledger_write_failure_propagates_not_swallowed(self) -> None:
        # done-test 8 / P3: the AUDIT mechanism failing is itself audit-worthy — capture must
        # NOT silently swallow a ledger-append failure (the live drainer logs+surfaces it).
        class _ThrowingLedger:
            def append(self, **_kw: object) -> object:
                raise RuntimeError("ledger db locked")

        with self.assertRaises(RuntimeError):
            capture_override(_event(), lambda _s: [_row("done", "fail", "X")], _ThrowingLedger())  # type: ignore[arg-type]


# ---- truthful capture: the auditor-facing rendering --------------------------

class RenderLegibilityTests(unittest.TestCase):
    def test_human_override_line_does_not_claim_required_bypass(self) -> None:
        lg = _ledger()
        rec = capture_override(_event(), lambda _s: [_row("done", "fail", "EGRESS_ONE")], lg)
        assert rec is not None
        line = render_ledger_line(rec)
        # the headline done-test: the record must NOT imply a REQUIRED check was bypassed —
        # the gate never had the administration scope to know that.
        self.assertNotIn("required", line.lower())
        self.assertIn("gate verdict was fail", line)  # the persisted WIRE value (VerdictType.value)
        self.assertIn("did not approve", line)

    def test_unverifiable_line_states_no_backing_verdict(self) -> None:
        lg = _ledger()
        rec = capture_override(_event(), lambda _s: [], lg)
        assert rec is not None
        line = render_ledger_line(rec)
        self.assertNotIn("required", line.lower())
        self.assertIn("could not attest", line)

    def test_blocking_non_run_override_renders_gate_outcome_not_a_none_verdict(self) -> None:
        # CP2 closure 1: a blocking NON-RUN override (verdict=None, gate_outcome=block_gate) must render the
        # gate OUTCOME truthfully — never "the gate verdict was None" — and stay "required"-free (legibility).
        lg = _ledger()
        rec = capture_override(
            _event(),
            lambda _s: [_row("done", verdict=None, reason="block_action_required", gate_outcome="block_gate")],
            lg)
        assert rec is not None
        line = render_ledger_line(rec)
        self.assertIn("gate outcome was BLOCKING", line)
        self.assertNotIn("verdict was None", line)
        self.assertNotIn("required", line.lower())        # honours the sealed no-'required' legibility rule
        self.assertIn("did not approve", line)


# ---- the receiver routing (closed+merged -> capture; unmerged -> drop) --------

def _sign(secret: bytes, raw: bytes) -> str:
    return "sha256=" + hmac.new(secret, raw, hashlib.sha256).hexdigest()


class _Headers:
    def __init__(self, items: dict[str, str]) -> None:
        self._items = {k.lower(): v for k, v in items.items()}

    def get(self, name: str, default: str | None = None) -> str | None:
        return self._items.get(name.lower(), default)


def _closed_body(*, merged: bool, sha: str = "a" * 40) -> bytes:
    pr: dict[str, object] = {"head": {"sha": sha}, "merged": merged}
    if merged:
        pr["merged_by"] = {"login": "admin-alice"}
        pr["merged_at"] = "2026-07-09T18:00:00Z"
    return json.dumps({
        "action": "closed", "number": 7, "installation": {"id": _INSTALL_OK},
        "repository": {"full_name": "acme/widgets"}, "pull_request": pr,
        "sender": {"login": "admin-alice"},
    }).encode("utf-8")


def _closed_headers(raw: bytes, delivery: str = "c-1") -> _Headers:
    return _Headers({
        "X-GitHub-Event": "pull_request",
        "X-GitHub-Delivery": delivery,
        "X-GitHub-Hook-Installation-Target-Type": "integration",
        "X-GitHub-Hook-Installation-Target-ID": str(_APP_ID),
        "X-Hub-Signature-256": _sign(_SECRET, raw),
    })


class _NoGatingSink:
    def enqueue(self, event: object) -> None:  # gating must never fire on a closed event
        raise AssertionError("closed+merged must not enqueue a gating job")


class ReceiverClosedRoutingTests(unittest.TestCase):
    def _receiver(self, override_sink: object) -> WebhookReceiver:
        return WebhookReceiver(
            secret_source=StaticSecretSource(_SECRET), app_id=_APP_ID,
            authorized_installations=frozenset({_INSTALL_OK}),
            gating_sink=_NoGatingSink(), delivery_log=InMemoryDeliveryLog(),
            override_sink=override_sink,  # type: ignore[arg-type]
        )

    def test_merged_close_routes_to_override_sink(self) -> None:
        sink = InMemoryOverrideSink()
        body = _closed_body(merged=True, sha="e" * 40)
        r = self._receiver(sink).handle(_closed_headers(body), body)
        self.assertIs(r.reason, Reason.MERGE_CAPTURED)
        self.assertEqual(r.status_code, 200)  # observational — not 202, not a gating job
        captured = sink.drain()
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0].head_sha, "e" * 40)
        self.assertEqual(captured[0].merged_by, "admin-alice")
        self.assertEqual(captured[0].pr_number, 7)

    def test_unmerged_close_is_dropped(self) -> None:
        sink = InMemoryOverrideSink()
        body = _closed_body(merged=False)
        r = self._receiver(sink).handle(_closed_headers(body, "c-2"), body)
        self.assertIs(r.reason, Reason.CLOSED_UNMERGED)
        self.assertEqual(sink.drain(), [])  # a discarded PR has nothing to override

    def test_merged_close_backpressure_is_503_and_not_recorded(self) -> None:
        class _Full:
            def enqueue(self, event: object) -> None:
                raise SinkFull("full")

        body = _closed_body(merged=True)
        r = self._receiver(_Full()).handle(_closed_headers(body, "c-3"), body)
        self.assertIs(r.outcome, ReceiverOutcome.ERROR)
        self.assertEqual(r.status_code, 503)  # GitHub re-delivers; ledger idempotency absorbs it


if __name__ == "__main__":
    unittest.main()
