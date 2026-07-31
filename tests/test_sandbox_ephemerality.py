"""tests/test_sandbox_ephemerality.py — the fail-CLOSED existence/teardown contract (board P1).

Ephemerality is a security property and the threat model is a MALICIOUS artifact, so a teardown that
CANNOT confirm destruction (the runtime timed out / errored / returned non-zero) MUST raise
``SandboxLeakError`` — never fail open by reading "can't tell" as "gone". These run with FAKE, unreachable
runtimes (no podman): ``/nonexistent-…`` triggers ``OSError``, ``false`` a non-zero exit, ``sleep`` a timeout.
"""
from __future__ import annotations

import socket
import tempfile
import threading
import time
import subprocess
import unittest
from pathlib import Path

import sandbox.observed as observed_mod
from core import ArtifactSpec, Existence, Fixtures, SandboxLeakError, TeardownUnverifiableError, tree_hash
from sandbox.observed import ObservedHandle, ObservedOCISandbox, reap_orphans
from sandbox.oci import (
    OCIHandle,
    OCISandbox,
    ResourceKind,
    WitnessNotProvisioned,
    probe_existence,
)

_MISSING = "/nonexistent-runtime-zzzqfx"  # an argv[0] that cannot exec -> OSError


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def _artifact_dir(body: str = "pass\n") -> ArtifactSpec:
    d = Path(tempfile.mkdtemp(prefix="mv-eph-art-"))
    (d / "main.py").write_text(body, encoding="utf-8")
    return ArtifactSpec(path=d, tree_hash=tree_hash(d))


def _wait_count(countfile: Path, want: int, within: float) -> int | None:
    """Poll the proxy's OWN countfile until it reads ``want`` (or ``within`` seconds elapse)."""
    deadline = time.monotonic() + within
    last: int | None = None
    while time.monotonic() < deadline:
        try:
            last = int(countfile.read_text().strip())
        except (OSError, ValueError):
            last = None
        if last == want:
            return last
        time.sleep(0.02)
    return last


def _oci_handle(container: str = "mv-eph-ctr") -> OCIHandle:
    snap = Path(tempfile.mkdtemp(prefix="mv-eph-"))
    return OCIHandle(id="i", artifact_hash="h", snapshot=snap, container=container, image_id="img")


def _obs_handle() -> ObservedHandle:
    snap = Path(tempfile.mkdtemp(prefix="mv-eph-o-"))
    return ObservedHandle(id="i", artifact_hash="h", snapshot=snap, container="mv-eph-c",
                          network="mv-eph-n", proxy="mv-eph-p", proxy_ip="10.0.0.2", baseline=0,
                          image_id="img")


class ProbeExistenceTests(unittest.TestCase):
    """The tri-state, exercised against REAL SUBPROCESSES.

    MIGRATED, not deleted. These previously passed a hand-built argv (``["echo", "myname"]``); the probe
    now builds its own listing argv, because a function handed a finished list cannot construct the
    control query that would prove the list's shape works. So the old form is unreachable BY DESIGN.

    What they still supply that the mock-based suite does NOT: a real fork/exec, a real exit status, a
    real decode. The trick is that ``listing_argv`` puts the subcommand words into ``/bin/echo``'s
    argv, so echo prints them back — giving a genuine, non-stubbed listing whose tokens are known.
    Deleting these would have quietly traded that coverage for convenience.
    """

    _ECHO = "/bin/echo"  # prints listing_argv's own subcommand words -> a real, known, non-stubbed listing

    def test_exists_when_the_channel_shows_witness_and_subject(self) -> None:
        # echo emits: ps -a --format {{.Names}}
        self.assertIs(probe_existence(self._ECHO, ResourceKind.CONTAINER, "-a", witness="ps").state,
                      Existence.EXISTS)

    def test_absent_when_the_channel_shows_the_witness_but_not_the_subject(self) -> None:
        self.assertIs(probe_existence(self._ECHO, ResourceKind.CONTAINER, "zz-not-emitted", witness="ps").state,
                      Existence.ABSENT)

    def test_unknown_when_the_witness_is_not_in_a_real_listing(self) -> None:
        """The core control, against a real process: the channel answered, but not with the witness."""
        self.assertIs(probe_existence(self._ECHO, ResourceKind.CONTAINER, "-a", witness="zz-no-witness").state,
                      Existence.UNKNOWN)

    def test_unknown_on_oserror(self) -> None:
        self.assertIs(probe_existence(_MISSING, ResourceKind.CONTAINER, "x", witness="w").state,
                      Existence.UNKNOWN)

    def test_unknown_on_nonzero_exit(self) -> None:
        # a FAILED listing with empty stdout is NOT proof of absence — non-zero return code -> UNKNOWN.
        self.assertIs(probe_existence("/bin/false", ResourceKind.CONTAINER, "x", witness="w").state,
                      Existence.UNKNOWN)

    def test_unknown_on_timeout(self) -> None:
        self.assertIs(probe_existence("/bin/sleep", ResourceKind.CONTAINER, "x", witness="w",
                                      timeout=0.05).state, Existence.UNKNOWN)

    def test_an_unprovisioned_witness_RAISES_rather_than_returning_a_tri_state(self) -> None:
        """Absence of CALIBRATION is not absence of EVIDENCE, so it cannot be reported in the evidence
        type. Raised before any subprocess runs."""
        with self.assertRaises(WitnessNotProvisioned):
            probe_existence(self._ECHO, ResourceKind.CONTAINER, "x", witness=None).state


class OCITeardownFailClosedTests(unittest.TestCase):
    # ⚠ TYPE CHANGED, DELIBERATELY. These pinned SandboxLeakError when one type carried both meanings.
    # An unreachable runtime / a non-zero probe is the INSTRUMENT failing, not a resource observed to
    # persist — so it is now TeardownUnverifiableError. Both remain TeardownError, so "teardown raises,
    # fail-closed" is unchanged; what changed is that the report no longer asserts a leak it never saw.
    def test_teardown_raises_when_runtime_unreachable(self) -> None:
        sb = OCISandbox(image="x", runtime=_MISSING)  # probe -> OSError -> UNKNOWN -> cannot confirm destroyed
        with self.assertRaises(TeardownUnverifiableError):
            sb.teardown(_oci_handle())

    def test_teardown_raises_on_nonzero_probe(self) -> None:
        sb = OCISandbox(image="x", runtime="false")  # probe -> returncode 1 -> UNKNOWN
        with self.assertRaises(TeardownUnverifiableError):
            sb.teardown(_oci_handle())


class ObservedTeardownFailClosedTests(unittest.TestCase):
    def test_teardown_raises_when_runtime_unreachable(self) -> None:
        sb = ObservedOCISandbox(image="x", runtime=_MISSING)
        with self.assertRaises(TeardownUnverifiableError):
            sb.teardown(_obs_handle())


class PartialPrepareFailClosedTests(unittest.TestCase):
    """A partial-setup failure runs cleanup, and the report must say what was actually established.

    ⚠ THIS TEST'S FAULT-INJECTION POINT MOVED, and the move is a real consequence worth naming.
    Previously a fake runtime (``false``) reached ``_create_network``, which exited non-zero after the
    snapshot was staged. Bootstrap-verify now refuses EARLIER — a runtime that cannot create and show a
    canary is refused before anything is staged — so ``false`` no longer reaches the cleanup path at all.
    Provisioning is therefore stubbed here, legitimately: it has its own tests, and this test's subject
    is the CLEANUP REPORT, not the guarantor.

    ⚠ AND THE EXPECTED EXCEPTION CHANGED. It previously asserted ``SandboxLeakError``. With a dead
    runtime the cleanup probes cannot answer, so the resources are UNPROVEN — not observed to persist.
    The ORIGINAL SETUP EXCEPTION is the certain fact and stays primary; unverifiability is ATTACHED.
    Asserting a leak here would have been the increment's own defect: lexicalising an unestablished
    claim as a finding, and demoting the real cause to ``__cause__`` where type-branching callers miss it.
    """

    def test_partial_prepare_keeps_the_setup_error_primary_and_attaches_unverifiability(self) -> None:
        sb = ObservedOCISandbox(image="x", runtime="false")
        art = _artifact_dir()
        orig_resolve = observed_mod.resolve_image_id
        orig_witness = observed_mod.ensure_container_witness
        observed_mod.resolve_image_id = lambda rt, img: "img-digest"
        observed_mod.ensure_container_witness = lambda rt, img, rid: f"moriverify-canary-{rid}"
        try:
            with self.assertRaises(subprocess.CalledProcessError) as cm:
                sb.prepare(art, Fixtures())
            attached = " ".join(str(x) for x in getattr(cm.exception, "__notes__", ())) + \
                       " ".join(str(a) for a in cm.exception.args)
            self.assertIn("UNPROVEN", attached,
                          "cleanup unverifiability must be ATTACHED to the original setup error")
            self.assertNotIn("OBSERVED TO PERSIST", attached,
                             "an unprobeable resource must never be reported as a proven leak")
        finally:
            observed_mod.resolve_image_id = orig_resolve
            observed_mod.ensure_container_witness = orig_witness


class ProxyCountAtAcceptTests(unittest.TestCase):
    """P2 focused negative: the count is taken at ``accept()``, so a SILENT client (connects, sends
    nothing) is counted well before the 5s handler peek-timeout, and an accepted-but-semaphore-blocked
    client is still counted. Scope note: this covers ACCEPTED connections; connections still in the
    kernel backlog (beyond ``listen()``) are not counted until accepted — the acknowledged boundary."""

    def _serve(self, mode: str = "fail_always") -> tuple[int, Path]:
        from observe.proxy import serve
        port = _free_port()
        countfile = Path(tempfile.mkdtemp(prefix="mv-eph-cnt-")) / "count"
        threading.Thread(target=serve, args=(port, str(countfile), mode), daemon=True).start()
        # The countfile is written AFTER listen(), so this wait is a readiness gate that
        # actually establishes readiness (see test_countfile_implies_listening below).
        self.assertEqual(_wait_count(countfile, 0, within=2.0), 0, "proxy did not initialise its countfile")
        return port, countfile

    def test_countfile_implies_listening(self) -> None:
        """REGRESSION (readiness race): the countfile is the signal every caller polls before
        starting the artifact — ``sandbox/observed.py`` waits for it, then runs the artifact against
        the proxy. Before the fix it was written BEFORE ``bind``/``listen``, so it witnessed only
        "the process got this far"; a caller could proceed and have its first connection REFUSED.
        A refused connection is never ``accept()``ed, so it is never counted — and the count is the
        gate's verdict input (``RetryCheck`` passes iff egress >= 2), so an uncounted attempt can
        turn a PASS into a FAIL.

        Asserted BEHAVIOURALLY, not structurally: a source-ordering check would still pass if a
        refactor preserved the ordering but broke the property (listen backlog 0, bind on the wrong
        interface). What callers depend on is "once the countfile exists, a connect succeeds", so
        that is what is tested — the runtime-state-assertion pattern this project applies to
        artifacts, applied to its own harness.

        Uses a DEDICATED throwaway proxy: the probe connection is ``accept()``ed and therefore
        counted, so it must never share an observer with a measurement assertion.

        DETERMINISM MATTERS HERE. Simply connecting after the countfile appears does NOT reliably
        detect the regression: in-process the racy window is microseconds wide, so the connect
        usually wins it and the test passes even against the buggy ordering (verified — the first
        version of this test did exactly that). A guard that only sometimes fires is the failure
        mode this suite exists to catch. So the property is forced instead of raced: a blocker
        socket HOLDS the port, ``bind``/``listen`` is guaranteed to fail, and the assertion is that
        the readiness signal never appears for a proxy that never served. (A second rejected
        version wrapped ``socket.listen`` to observe the ordering; that patch is process-global and
        sibling tests' daemon proxies polluted it — flaky for a different reason.)"""
        from observe import proxy as proxy_mod
        port = _free_port()
        countfile = Path(tempfile.mkdtemp(prefix="mv-eph-ready-")) / "count"

        # (1) DETERMINISTIC, race-free: HOLD the port, so bind/listen is guaranteed to FAIL. If the
        # readiness signal is published before listening, the countfile appears even though the
        # proxy never served — which is precisely the defect. No monkeypatching (socket.listen is
        # process-global and sibling daemon proxies pollute a spy) and no window to win.
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        taken_port = int(blocker.getsockname()[1])
        dead_countfile = Path(tempfile.mkdtemp(prefix="mv-eph-dead-")) / "count"
        bind_error: list[BaseException] = []

        def _serve_capturing() -> None:
            try:
                proxy_mod.serve(taken_port, str(dead_countfile), "fail_always")
            except BaseException as exc:  # noqa: BLE001 — the premise this test asserts
                bind_error.append(exc)

        try:
            threading.Thread(target=_serve_capturing, daemon=True).start()
            # Poll-until-deadline rather than a fixed sleep: fail the moment the countfile appears,
            # and stop as soon as the premise (bind raised) is established.
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline:
                self.assertFalse(
                    dead_countfile.exists(),
                    "the countfile appeared even though bind/listen FAILED — the readiness signal "
                    "witnesses 'the process got this far', not 'the proxy is serving'")
                if bind_error:
                    break
                time.sleep(0.02)
            # ASSERT THE TEST'S OWN PREMISE. If a platform ever let this bind succeed, the negative
            # above would pass VACUOUSLY — a guard that guards nothing. Fail loudly instead.
            self.assertTrue(
                bind_error,
                "serve() did not raise: the blocker failed to hold the port, so the negative "
                "assertion above proved nothing on this platform (vacuous guard)")
            self.assertFalse(
                dead_countfile.exists(),
                "the countfile appeared even though bind/listen FAILED — the readiness signal "
                "witnesses 'the process got this far', not 'the proxy is serving'. A caller "
                "polling it proceeds and its first connection is REFUSED; a refused connection is "
                "never accept()ed, so it is never counted, and the count is the verdict input")
        finally:
            blocker.close()

        # (2) the positive property callers depend on: once the countfile exists, a connect is
        # accepted — proving the socket was genuinely serving, not merely bound.
        threading.Thread(target=proxy_mod.serve,
                         args=(port, str(countfile), "fail_always"), daemon=True).start()
        self.assertEqual(_wait_count(countfile, 0, within=2.0), 0,
                         "proxy did not publish its readiness countfile")
        conn = socket.create_connection(("127.0.0.1", port), 3)
        conn.close()
        self.assertEqual(_wait_count(countfile, 1, within=2.0), 1,
                         "countfile existed but the proxy was not accepting — readiness signal lied")

    def test_silent_client_counted_before_peek_timeout(self) -> None:
        port, countfile = self._serve()
        conn = socket.create_connection(("127.0.0.1", port), 3)  # send NOTHING (slowloris)
        try:
            # count must reach 1 far inside the handler's 5s recv timeout — i.e. it was taken at accept.
            self.assertEqual(_wait_count(countfile, 1, within=2.0), 1)
        finally:
            conn.close()

    def test_accept_counts_under_semaphore_saturation(self) -> None:
        from observe.proxy import _MAX_INFLIGHT
        port, countfile = self._serve()
        # _MAX_INFLIGHT silent clients occupy every handler; the next accept still increments the count
        # BEFORE it blocks on the semaphore -> the count reaches _MAX_INFLIGHT+1 despite full saturation.
        conns = [socket.create_connection(("127.0.0.1", port), 3) for _ in range(_MAX_INFLIGHT + 1)]
        try:
            self.assertEqual(_wait_count(countfile, _MAX_INFLIGHT + 1, within=3.0), _MAX_INFLIGHT + 1)
        finally:
            for c in conns:
                c.close()


class ReaperFailClosedTests(unittest.TestCase):
    """The reaper's contract is UNCHANGED by the exception split: it normalises every
    cannot-confirm-a-clean-slate condition into its OWN SandboxLeakError, which its callers pin. The
    split applies to TEARDOWN, which reports per-resource; the reaper reports per-run."""

    # ``canary_image`` is a PLACEHOLDER in these two: both refuse before the image is ever used — the
    # first cannot resolve its runtime, the second cannot list — so the SandboxLeakError pins still pin
    # what they always pinned. The parameter is required precisely so its absence cannot go unasked.
    def test_reap_raises_when_listing_unreachable(self) -> None:
        with self.assertRaises(SandboxLeakError):
            reap_orphans(_MISSING, canary_image="zz-placeholder")

    def test_reap_raises_on_nonzero_listing(self) -> None:
        with self.assertRaises(SandboxLeakError):
            reap_orphans("false", canary_image="zz-placeholder")

    def test_reap_refuses_when_its_canary_image_cannot_be_resolved_LOCALLY(self) -> None:
        """A NEW branch, exercised by nobody before now: a usable runtime whose canary image is absent.

        Without a witness the reaper cannot tell an empty listing from a broken channel, so it must
        REFUSE rather than report a clean slate. Resolution is local-only by contract — this image is not
        pulled, and if it ever were, this test would stop failing for the wrong reason.
        """
        with self.assertRaises(SandboxLeakError):
            reap_orphans("podman", canary_image="zz-definitely-not-a-local-image-qfx")

    def test_reap_refuses_a_runtime_with_no_MEASURED_network_witness(self) -> None:
        """Absence of SUPPORT must not look like absence of EVIDENCE. An unmeasured runtime is refused at
        the map lookup, before any subprocess runs, so the failure says 'unsupported' and can never be
        mistaken for a quiet channel."""
        with self.assertRaises(SandboxLeakError) as caught:
            reap_orphans("nerdctl", canary_image="zz-placeholder")
        # The TYPE is the reaper's own contract; the MESSAGE is what keeps the two failures apart.
        self.assertIn("NOT IN THE SUPPORTED SET", str(caught.exception))
        self.assertNotIn("witness", str(caught.exception).split("(")[0])


if __name__ == "__main__":
    unittest.main()
