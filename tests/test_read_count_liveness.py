"""P3 — the count read consults the EXIT STATUS before the bytes, on both of its call sites.

THE DEFECT THIS CLOSES. ``_read_count`` parsed ``r.stdout`` and never looked at ``r.returncode``. That made
a load-bearing property EMERGENT instead of CONSTRUCTED: this call is the system's liveness witness for the
proxy (``exec`` needs a RUNNING container, and the proxy is that container's PID 1), and the reason a dead
proxy yielded "no reading" was only that podman 4.9.3 puts its exec error on STDERR and leaves stdout EMPTY,
so ``int("")`` happened to raise. ``_RUNTIMES`` admits ``nerdctl`` and ``docker`` as well; a runtime writing
anything numeric to stdout on an error path would have been PARSED INTO A COUNT.

WHY THAT IS A GATE DEFECT AND NOT UNTIDINESS. A frozen countfile read as a small, clean-looking integer is
the one direction this instrument must never fail in: every other saturation effect leaves the count
monotone and threshold-crossing, but a stale small number MAKES A FLOOD LOOK CLEAN.

The mutant these tests exist to kill is the deletion of ``if r.returncode != 0: return None``. Two DISJOINT
sites kill it, because behaviour and wiring are two claims:

  * ``_egress``      — the post-run read. Garbage-with-a-bad-exit must become a REFUSAL.
  * ``_start_proxy`` — the READINESS poll. Garbage-with-a-bad-exit must not be mistaken for "serving".

Each refusal test is paired with a POSITIVE CONTROL that the same code path CAN return a number. Without
one, every assertion here is satisfied by a function that returns ``None`` unconditionally — a control that
brackets one direction certifies nothing about the other.
"""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from typing import Any, Callable
from unittest import mock

from core import EgressAbsence
from sandbox.observed import NetworkIsolationError, ObservedHandle, ObservedOCISandbox

_RUNTIME = "/usr/bin/podman"


def _sandbox() -> ObservedOCISandbox:
    """A sandbox whose runtime is pinned, so no host runtime is required to exercise the read path."""
    sb = ObservedOCISandbox(image="scratch", runtime="podman")
    sb._exec_runtime = lambda: _RUNTIME  # type: ignore[method-assign]
    return sb


def _handle(proxy: str = "gated-proxy-x") -> ObservedHandle:
    return ObservedHandle(
        id="id", artifact_hash="h", snapshot=Path("/tmp"), container="c",
        network="n", proxy=proxy, proxy_ip="10.0.0.2", image_id="sha256:x",
    )


def _completed(rc: int, out: str, err: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(args=["x"], returncode=rc, stdout=out, stderr=err)


class _FakeClock:
    """A monotonic clock the test advances explicitly.

    Load-bearing rather than a convenience: the readiness budget is now WALL-CLOCK, so a test that let
    the real clock run would spend the whole deadline in real seconds on every run. Worse, it would be
    measuring the suite's wall time instead of the code's budget — and a test whose duration IS its
    assertion cannot distinguish "the deadline works" from "the machine was slow"."""

    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


class TheExitStatusIsConsultedBeforeTheBytes(unittest.TestCase):
    def test_nonzero_exit_is_a_refusal_even_when_stdout_parses(self) -> None:
        """THE MUTANT TARGET. A runtime that fails AND writes a parseable number to stdout must produce
        NO READING. Deleting the returncode check makes this return 7 — a fabricated count, sourced from
        an error path, on the value that decides the verdict."""
        with mock.patch("sandbox.observed.subprocess.run", return_value=_completed(1, "7")):
            self.assertIsNone(
                _sandbox()._read_count("p"),
                "a FAILED exec whose stdout happens to parse was accepted as a count — the exit status "
                "is the only thing distinguishing a reading from an error page",
            )

    def test_a_successful_read_returns_the_count(self) -> None:
        """THE POSITIVE CONTROL. Without it, the refusal assertions above and below are all satisfied by
        a function that returns None unconditionally, and the suite would certify a dead instrument."""
        with mock.patch("sandbox.observed.subprocess.run", return_value=_completed(0, "42\n")):
            self.assertEqual(_sandbox()._read_count("p"), 42)

    def test_the_measured_stopped_container_shape_is_a_refusal(self) -> None:
        """The shape MEASURED on podman 4.9.3 against a stopped container: rc 255, error on stderr, stdout
        empty. NOTE: this one passes with or without the fix — it is a REGRESSION WITNESS for the observed
        behaviour, not a mutant kill. Said plainly so it is never miscounted as evidence for the guard."""
        with mock.patch("sandbox.observed.subprocess.run", return_value=_completed(
                255, "", "Error: can only create exec sessions on running containers: container state improper")):
            self.assertIsNone(_sandbox()._read_count("p"))

    def test_a_wedged_runtime_is_a_refusal_and_not_a_raised_exception(self) -> None:
        """``TimeoutExpired`` used to escape ``_read_count`` -> ``_egress`` -> ``run()``. A raw exception is
        the shape the typed-absence taxonomy exists to replace; the fact is "the observer could not be
        read", and it must arrive as that."""
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd=["exec"], timeout=30)):
            self.assertIsNone(_sandbox()._read_count("p"))

    def test_a_vanished_runtime_binary_still_propagates(self) -> None:
        """THE DELIBERATE NON-INCLUSION, pinned so a later broadening is a decision rather than a drift.
        ``OSError`` is NOT absorbed: a missing runtime binary is the executor losing its own tooling, not
        the observer being unreadable, and swallowing it would make the readiness poll report that the
        PROXY failed to publish — naming the wrong subject."""
        with mock.patch("sandbox.observed.subprocess.run", side_effect=FileNotFoundError("no podman")):
            with self.assertRaises(FileNotFoundError):
                _sandbox()._read_count("p")


class TheRefusalReachesTheResult(unittest.TestCase):
    """BEHAVIOUR AND WIRING ARE TWO CLAIMS. The tests above prove what ``_read_count`` returns; these prove
    that what it returns is what ``_egress`` reports."""

    def test_egress_maps_a_refused_read_to_observer_unreadable(self) -> None:
        with mock.patch("sandbox.observed.subprocess.run", return_value=_completed(1, "7")):
            self.assertIs(_sandbox()._egress(_handle()), EgressAbsence.OBSERVER_UNREADABLE)

    def test_egress_reports_a_successful_read_as_the_number(self) -> None:
        """Positive control for the wiring, for the same reason as above."""
        with mock.patch("sandbox.observed.subprocess.run", return_value=_completed(0, "42")):
            self.assertEqual(_sandbox()._egress(_handle()), 42)

    def test_egress_maps_a_WEDGED_RUNTIME_to_observer_unreadable(self) -> None:
        """D3 — THE COMPOSITION, not its halves. ``_read_count(timeout) -> None`` and
        ``_egress(rc != 0) -> UNREADABLE`` were both covered while the pair they compose into was not:
        a wedged runtime reaching a TYPED absence rather than an escaping exception. Two green halves
        are not a green whole, which is the behaviour-vs-wiring split this file already respects
        elsewhere and did not apply to this pair until dissent said so."""
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=subprocess.TimeoutExpired(cmd=["exec"], timeout=30)):
            self.assertIs(_sandbox()._egress(_handle()), EgressAbsence.OBSERVER_UNREADABLE)


class TheReadinessPollIsNotFooledByAFailedExec(unittest.TestCase):
    """THE SECOND, DISJOINT MUTANT KILL. ``_start_proxy`` polls ``_read_count`` and treats any non-``None``
    as "the proxy is serving". Without the returncode check, a FAILED exec whose stdout parses satisfies
    that poll, and the artifact is released against a proxy never proven to be listening — a refused first
    connection is never accept()ed, so it is never counted, which under-counts the verdict input."""

    @staticmethod
    def _dispatch(
        rc_for_exec: int, out_for_exec: str, clock: _FakeClock | None = None,
    ) -> Callable[..., subprocess.CompletedProcess[str]]:
        def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            if "exec" in argv:
                if clock is not None:
                    clock.t += 0.5   # advance the FAKE clock: the deadline is reached in 0 REAL seconds
                return _completed(rc_for_exec, out_for_exec)
            if "inspect" in argv:
                return _completed(0, "10.0.0.2\n")
            return _completed(0, "")
        return run

    def test_a_failing_exec_with_parseable_stdout_never_satisfies_readiness(self) -> None:
        clock = _FakeClock()
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=self._dispatch(1, "7", clock)), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            with self.assertRaises(NetworkIsolationError) as ctx:
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x")
        self.assertIn("never published its readiness countfile", str(ctx.exception))

    def test_a_succeeding_exec_does_satisfy_readiness(self) -> None:
        """Positive control: the poll is not simply broken in the refusing direction."""
        clock = _FakeClock()
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=self._dispatch(0, "0", clock)), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            self.assertEqual(
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x"), "10.0.0.2")


class TheReadinessBudgetIsWallClockNotAnIterationCount(unittest.TestCase):
    """THE DISSENT FIX. ``_read_count`` maps a wedged runtime's ``TimeoutExpired`` to "no reading", which
    is right for ``_egress`` and wrong for this caller: the readiness poll reads "no reading" as "keep
    waiting", so under an ITERATION COUNT every absorbed timeout bought another 30s attempt — MEASURED at
    50 attempts, ~1500s, ending in a refusal that claimed to have waited 5s.

    These tests run on a FAKE CLOCK, so they assert the budget rather than the wall time of the suite."""

    def _ready_at(self, clock: _FakeClock, calls: list[int], ready_after: float,
                  step: float = 1.0) -> Callable[..., subprocess.CompletedProcess[str]]:
        """A HEALTHY proxy that becomes ready ``ready_after`` seconds in, polled at ``step`` per read.
        Used for the deadline's EDGE — the one arithmetic this fix introduces."""
        t0 = clock.t

        def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            if "exec" in argv:
                calls.append(1)
                clock.t += step
                if clock.t - t0 >= ready_after:
                    return _completed(0, "0")        # countfile published
                return _completed(1, "")             # not yet: cat finds no file
            if "inspect" in argv:
                return _completed(0, "10.0.0.2\n")
            return _completed(0, "")
        return run

    def test_a_proxy_ready_JUST_INSIDE_the_deadline_is_accepted(self) -> None:
        """EDGE, lower side. Ready at 29s against a 30s deadline must SUCCEED. Without this, an
        off-by-one that refused at the boundary would pass every other assertion in this class."""
        clock = _FakeClock()
        calls: list[int] = []
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=self._ready_at(clock, calls, ready_after=29.0)), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            self.assertEqual(
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x"), "10.0.0.2")

    def test_a_proxy_ready_JUST_OUTSIDE_the_deadline_is_refused(self) -> None:
        """EDGE, upper side. Ready at 31s against a 30s deadline must REFUSE — and refusing here is
        correct, not harsh: proceeding would release the artifact against a proxy with no readiness
        evidence, whose first egress attempts are refused and therefore never counted."""
        clock = _FakeClock()
        calls: list[int] = []
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=self._ready_at(clock, calls, ready_after=31.0)), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            with self.assertRaises(NetworkIsolationError):
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x")

    def _wedged(self, clock: _FakeClock, calls: list[int], exec_cost: float = 30.0
                ) -> Callable[..., subprocess.CompletedProcess[str]]:
        def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            if "exec" in argv:
                calls.append(1)
                clock.t += exec_cost          # the wedged call consumes its own subprocess timeout
                raise subprocess.TimeoutExpired(cmd=argv, timeout=30)
            if "inspect" in argv:
                return _completed(0, "10.0.0.2\n")
            return _completed(0, "")
        return run

    def test_a_wedged_runtime_is_refused_after_ONE_attempt_not_fifty(self) -> None:
        """THE MUTANT TARGET for this fix. Reverting to ``for _ in range(50)`` makes this 50, because the
        loop counts attempts instead of watching the clock — the ~25-minute hang, restored."""
        clock = _FakeClock()
        calls: list[int] = []
        with mock.patch("sandbox.observed.subprocess.run", side_effect=self._wedged(clock, calls)), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            with self.assertRaises(NetworkIsolationError):
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x")
        self.assertEqual(
            calls, [1],
            f"a wedged runtime was polled {len(calls)} times; one call already overruns the deadline, so "
            "any further attempt means the budget is being counted in iterations rather than seconds",
        )

    def test_the_refusal_reports_MEASURED_elapsed_and_not_a_restated_budget(self) -> None:
        """The old message said "within 5s" while the loop could run for 1500. The replacement quotes the
        deadline from the CONSTANT and reports elapsed from the CLOCK, so it cannot misdescribe the wait
        the way a hardcoded figure can."""
        clock = _FakeClock()
        calls: list[int] = []
        # exec_cost deliberately DIFFERENT from the deadline, so "what was waited" and "what was
        # budgeted" are two distinguishable numbers in the message rather than one repeated.
        with mock.patch("sandbox.observed.subprocess.run",
                        side_effect=self._wedged(clock, calls, exec_cost=31.0)), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            with self.assertRaises(NetworkIsolationError) as ctx:
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x")
        msg = str(ctx.exception)
        self.assertIn("31.0s", msg, f"the refusal does not report the MEASURED wait: {msg}")
        self.assertIn("30s deadline", msg, f"the refusal does not name its deadline: {msg}")

    def test_a_SLOW_BUT_HEALTHY_proxy_still_gets_its_full_deadline(self) -> None:
        """POSITIVE CONTROL, and the one that stops the fix over-correcting. A deadline that refused on
        the first empty read would be a fast gate and a wrong one — the countfile legitimately does not
        exist for the first few polls while the proxy binds and listens. Cheap reads must keep polling
        until the clock, not the attempt count, runs out."""
        clock = _FakeClock()
        calls: list[int] = []
        cheap = self._wedged(clock, calls, exec_cost=0.1)   # healthy-but-not-yet-ready reads

        def run(argv: list[str], **kw: Any) -> subprocess.CompletedProcess[str]:
            if "exec" in argv and len(calls) >= 3:          # ready on the 4th poll, well inside the deadline
                calls.append(1)
                return _completed(0, "0")
            return cheap(argv, **kw)

        with mock.patch("sandbox.observed.subprocess.run", side_effect=run), \
             mock.patch("sandbox.observed.time.monotonic", clock), \
             mock.patch("sandbox.observed.time.sleep"):
            self.assertEqual(
                _sandbox()._start_proxy("net", "proxy", "fail_always", "sha256:x"), "10.0.0.2")
        self.assertEqual(len(calls), 4, "the poll gave up before the deadline on a healthy slow start")


if __name__ == "__main__":
    unittest.main()
