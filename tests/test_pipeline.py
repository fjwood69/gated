"""Increment 2.4 — engine integration + verdict->Check Run.

Run from the gated/ root:  python3 -m unittest discover -s tests

Non-podman: the out-of-band summary, the fail-closed conclusion mapping through the
updater, extract->spec, and hash-mismatch -> ERROR (not a silent pass). The real-engine
handshake (ObservedOCISandbox on podman) is a skip-unless-available regression that
proves the engine and gate meet: real container -> aggregated Verdict -> Check Run.
"""
from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    Reason,
    Verdict,
    VerdictType,
    tree_hash,
)
from unittest import mock

from gate.checkrun import CheckConclusion, CheckStatus
from gate.executor import Executor
from gate.pipeline import (
    CapturingTrialReportSink,
    assert_budget_fits_watchdog,
    assert_detector_registered,
    default_detector_registry,
    extract_to_spec,
    make_check_updater,
    make_job_runner,
)
from gate.queue import GatingEvent
from gate.store import GatingStore
from gate.summary import render_check_summary

_NAME = "gated/retry"
_IMAGE = "localhost/mori:local"
_REGISTRY = default_detector_registry()   # 3.5-close #1.3: the accepted "retry" detector, registered
_RESOLVE = _REGISTRY.resolve
_DETECTOR_ID = "retry"


def _event(delivery_id: str = "d1", sha: str = "a" * 40) -> GatingEvent:
    return GatingEvent(
        delivery_id=delivery_id, repo_full_name="acme/widgets", head_sha=sha,
        action="opened", installation_id=9001,
    )


class SummaryTests(unittest.TestCase):
    def test_pass_summary_readable(self) -> None:
        out = render_check_summary(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS), _NAME)
        self.assertIn("PASSED", out.title)
        self.assertIn("all trials passed", out.summary)

    def test_fail_summary_states_the_observation(self) -> None:
        out = render_check_summary(Verdict(VerdictType.FAIL, Reason.EGRESS_ONE), _NAME)
        self.assertIn("FAILED", out.title)
        self.assertIn("1 egress attempt observed", out.summary)

    def test_error_summary_says_blocked_and_human(self) -> None:
        out = render_check_summary(Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING), _NAME)
        self.assertIn("ERRORED", out.title)
        self.assertIn("human must review", out.summary)
        self.assertIn("blocked", out.summary)  # never implies it passed

    def test_integrity_mismatch_is_a_security_alert(self) -> None:
        # a hash mismatch must SCREAM (distinct security event), not read as a glitch
        out = render_check_summary(
            Verdict(VerdictType.ERROR, Reason.ARTIFACT_INTEGRITY_MISMATCH), _NAME
        )
        self.assertIn("SECURITY", out.title)
        self.assertIn("tampering", out.summary.lower())
        self.assertIn("blocked", out.summary.lower())
        self.assertIn("security review", out.summary.lower())

    def test_summary_only_consumes_typed_verdict(self) -> None:
        # structural anti-spoofing: the renderer's ONLY input is the Verdict — it cannot
        # reach artifact stdout/tmpfs even in principle. The ONLY inputs are the typed Verdict, the
        # check name, and (3.5-close #1.5) the ATTESTED detector_id + image_digest — engine-measured
        # IDENTITY, never artifact output. No parameter is a log / stdout / tmpfs channel.
        import inspect

        sig = inspect.signature(render_check_summary)
        self.assertEqual(list(sig.parameters), ["verdict", "check_name", "detector_id", "image_digest"])
        # the identity params are keyword-only and default to None (non-repudiation, not a data channel).
        for p in ("detector_id", "image_digest"):
            self.assertIs(sig.parameters[p].kind, inspect.Parameter.KEYWORD_ONLY)
            self.assertIsNone(sig.parameters[p].default)


class _FakeCheckClient:
    """Records the check-run lifecycle calls incl. the final conclusion + summary."""

    def __init__(self) -> None:
        self.created = False
        self.statuses: list[CheckStatus] = []
        self.final_conclusion: CheckConclusion | None = None
        self.final_summary: str | None = None

    def find_check_run(self, *, repo_full_name, head_sha, name):  # type: ignore[no-untyped-def]
        return None

    def create_check_run(self, *, repo_full_name, head_sha, name, status, external_id, conclusion=None, output=None):  # type: ignore[no-untyped-def]
        self.created = True
        self.statuses.append(status)
        return "cr-1"

    def update_check_run(self, *, repo_full_name, check_run_id, status, conclusion=None, output=None):  # type: ignore[no-untyped-def]
        self.statuses.append(status)
        if status is CheckStatus.COMPLETED:
            self.final_conclusion = conclusion
            self.final_summary = output.summary if output else None


class UpdaterMappingTests(unittest.TestCase):
    def _run(self, verdict: Verdict) -> _FakeCheckClient:
        client = _FakeCheckClient()
        updater = make_check_updater(client, name=_NAME)
        updater(_event(), verdict)
        return client

    def test_fail_maps_to_failure_and_blocks(self) -> None:
        c = self._run(Verdict(VerdictType.FAIL, Reason.EGRESS_ONE))
        self.assertIs(c.final_conclusion, CheckConclusion.FAILURE)
        self.assertIn("1 egress attempt observed", c.final_summary or "")

    def test_error_maps_to_action_required_fail_closed(self) -> None:
        # the ratified fail-closed mapping — NOT neutral (which would not block)
        c = self._run(Verdict(VerdictType.ERROR, Reason.TELEMETRY_MISSING))
        self.assertIs(c.final_conclusion, CheckConclusion.ACTION_REQUIRED)

    def test_pass_maps_to_success(self) -> None:
        c = self._run(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))
        self.assertIs(c.final_conclusion, CheckConclusion.SUCCESS)

    def test_lifecycle_order(self) -> None:
        c = self._run(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))
        self.assertEqual(c.statuses, [CheckStatus.QUEUED, CheckStatus.IN_PROGRESS, CheckStatus.COMPLETED])


class HashMismatchTests(unittest.TestCase):
    def test_hash_mismatch_maps_to_error_not_pass(self) -> None:
        # a corrupted/altered tarball -> sandbox raises ArtifactHashMismatchError ->
        # the executor maps it to ERROR (infra fault, blocks), never a silent PASS.
        d = Path(tempfile.mkdtemp(prefix="mv-pipe-"))
        store = GatingStore(d / "g.db")
        client = _FakeCheckClient()
        updater = make_check_updater(client, name=_NAME)

        def hash_mismatch_runner(_: GatingEvent) -> Verdict:
            raise ArtifactHashMismatchError("staged tree != claimed hash")

        ex = Executor(store, hash_mismatch_runner, updater)
        store.enqueue(_event())
        store.claim_next()
        ex.process_claimed(_event())
        self.assertEqual(store.status_of("d1"), "error")
        self.assertIs(client.final_conclusion, CheckConclusion.ACTION_REQUIRED)  # ERROR blocks


def _fixture_tarball(path: Path, script: bytes) -> None:
    with tarfile.open(path, "w") as tar:
        ti = tarfile.TarInfo("acme-widgets-abc/main.py")
        ti.size = len(script)
        tar.addfile(ti, io.BytesIO(script))


class BudgetOrderingTests(unittest.TestCase):
    def test_accepts_aggregate_within_watchdog(self) -> None:
        # 3 trials x 120s = 360s; x1.2 margin = 432s < 900s watchdog -> OK
        assert_budget_fits_watchdog(trials=3, per_trial_wall_clock=120.0, watchdog_timeout=900.0)

    def test_rejects_aggregate_exceeding_watchdog(self) -> None:
        # 8 trials x 120s = 960s -> races the 900s watchdog -> refuse (fail-closed startup)
        with self.assertRaises(ValueError):
            assert_budget_fits_watchdog(
                trials=8, per_trial_wall_clock=120.0, watchdog_timeout=900.0
            )


class IntegrityMismatchMappingTests(unittest.TestCase):
    def test_job_runner_maps_hash_mismatch_to_integrity_security_error(self) -> None:
        # the pipeline job-runner catches ArtifactHashMismatchError and returns the
        # DISTINCT integrity verdict (blocks via action_required, screams in the summary).
        def source(_: GatingEvent, ws: Path) -> ArtifactSpec:
            return ArtifactSpec(path=ws, tree_hash="sha256:whatever")

        job = make_job_runner(source, image=_IMAGE, resolve=_RESOLVE, detector_id=_DETECTOR_ID)
        with mock.patch(
            "gate.pipeline.run_engine_check",
            side_effect=ArtifactHashMismatchError("swap"),
        ):
            verdict = job(_event())
        self.assertIs(verdict.status, VerdictType.ERROR)
        self.assertIs(verdict.reason, Reason.ARTIFACT_INTEGRITY_MISMATCH)


class DetectorRegistryEnforcementTests(unittest.TestCase):
    """3.5-close #1.3: the live gate resolves its detector through the trusted registry (enforced ==
    accepted), and a boot assertion catches a mis-registered detector."""

    def test_boot_assertion_passes_for_registered_detector(self) -> None:
        assert_detector_registered(_RESOLVE, _DETECTOR_ID)  # does not raise

    def test_boot_assertion_fails_for_unregistered_detector(self) -> None:
        from gate.preflight import ConfigurationError
        with self.assertRaises(ConfigurationError):
            assert_detector_registered(_RESOLVE, "not-the-accepted-detector")

    # ---- adversarial (finding F): an unresolvable detector -> BLOCK (ERROR), never runs ----
    def test_job_runner_blocks_when_detector_does_not_resolve(self) -> None:
        from gate.detector_registry import DetectorRegistry
        from engine.retry import RetryCheck

        # a registry whose "retry" is registered under a DRIFTED (wrong) content-address -> resolve
        # refuses -> the job-runner must BLOCK with DETECTOR_UNRESOLVED, never run an unverified detector.
        drifted = DetectorRegistry()
        drifted.register("retry", lambda: RetryCheck(("python3", "/artifact/main.py")),
                         content_hash="accepted-addr-that-will-not-match")

        def source(_: GatingEvent, ws: Path) -> ArtifactSpec:
            # the detector resolves (and fails) before any sandbox runs, so the artifact is never used.
            return ArtifactSpec(path=ws, tree_hash="sha256:unused")

        job = make_job_runner(source, image=_IMAGE, resolve=drifted.resolve, detector_id="retry")
        verdict = job(_event())
        self.assertIs(verdict.status, VerdictType.ERROR)
        self.assertIs(verdict.reason, Reason.DETECTOR_UNRESOLVED)


class CheckRunProvenanceTests(unittest.TestCase):
    """3.5-close #1.5: the Check Run summary carries the ATTESTED detector_id + image_digest (non-
    repudiation on the merge-blocking path), sourced from the captured TrialReport — never artifact output."""

    def test_summary_carries_detector_and_image_when_captured(self) -> None:
        from engine.runner import ExecutionIdentity, TrialReport
        capture = CapturingTrialReportSink()
        capture.record(TrialReport(
            trials=(Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS),), trials_configured=1,
            short_circuited=False, aggregate=Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS),
            execution_identity=ExecutionIdentity(backend="ObservedOCISandbox",
                                                 image_ref="sha256:cafef00d", isolation_level="hermetic"),
            detector_id="retry"))
        client = _FakeCheckClient()
        make_check_updater(client, name=_NAME, report_capture=capture)(
            _event(), Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))
        self.assertIn("detector=retry", client.final_summary or "")
        self.assertIn("image=sha256:cafef00d", client.final_summary or "")

    def test_summary_omits_provenance_when_uncaptured(self) -> None:
        client = _FakeCheckClient()
        make_check_updater(client, name=_NAME)(  # no report_capture
            _event(), Verdict(VerdictType.PASS, Reason.UNANIMOUS_PASS))
        self.assertNotIn("detector=", client.final_summary or "")


class ExtractToSpecTests(unittest.TestCase):
    def test_extract_to_spec_hashes_shared_canon(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-e2s-"))
        tar = tmp / "a.tar"
        _fixture_tarball(tar, b"print('hi')\n")
        with tempfile.TemporaryDirectory() as ws:
            spec = extract_to_spec(tar, Path(ws))
            self.assertIsInstance(spec, ArtifactSpec)
            self.assertEqual(spec.tree_hash, tree_hash(spec.path))  # App == sandbox canon


# ---- real-engine handshake (skip unless podman + image) --------------------

_A_RETRY = (
    "import socket\n"
    "def _get():\n"
    "    s = socket.create_connection(('health-proxy', 8080), 3)\n"
    "    s.sendall(b'GET / HTTP/1.0\\r\\n\\r\\n')\n"
    "    r = s.recv(64); s.close()\n"
    "    if b'503' in r: raise OSError('transient')\n"
    "    return r\n"
    "for _ in range(3):\n"
    "    try:\n"
    "        _get(); break\n"
    "    except OSError:\n"
    "        continue\n"
).encode()

from sandbox.observed import ObservedOCISandbox  # noqa: E402

_PODMAN = ObservedOCISandbox.available(_IMAGE)


@unittest.skipUnless(_PODMAN, f"no OCI runtime can run {_IMAGE} hermetically")
class RealEngineHandshakeTests(unittest.TestCase):
    """The thing 2.4 exists to prove: a real podman run -> aggregated Verdict -> the
    gate's Check Run mapping, engine and gate meeting end-to-end."""

    def test_retry_artifact_passes_through_pipeline(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="mv-hs-"))
        tar = tmp / "art.tar"
        _fixture_tarball(tar, _A_RETRY)

        def source(_: GatingEvent, ws: Path) -> ArtifactSpec:
            return extract_to_spec(tar, ws)

        job = make_job_runner(source, image=_IMAGE, resolve=_RESOLVE, detector_id=_DETECTOR_ID, trials=2)
        verdict = job(_event())
        self.assertIs(verdict.status, VerdictType.PASS)

        client = _FakeCheckClient()
        make_check_updater(client, name=_NAME)(_event(), verdict)
        self.assertIs(client.final_conclusion, CheckConclusion.SUCCESS)


if __name__ == "__main__":
    unittest.main()
