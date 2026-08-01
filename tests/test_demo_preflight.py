"""Preflight: every refusal seen red, and the FALSE PASS the design exists to prevent.

The centrepiece is ``TheProbeMustBeTheFailingOperation``. Under a real netns denial, measured on a
disposable VM, `podman network create --internal --disable-dns` SUCCEEDS (rc=0) because it is a
config-object operation, while running a container attached to that network refuses (rc=126). A
preflight that stopped at create would therefore pass on exactly the machine it exists to refuse.
That is not a hypothetical; it was this project's first probe attempt.
"""
from __future__ import annotations

import subprocess
import unittest
from unittest import mock

from demo import preflight

_IMAGE = "docker.io/library/python:3.11-alpine"


def _cp(rc: int, out: str = "", err: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], rc, out, err)


class _Base(unittest.TestCase):
    def _with(self, responder):
        """Patch the runner. ``responder`` maps an argv to a CompletedProcess."""
        return mock.patch.object(preflight, "_run", responder)

    @staticmethod
    def _healthy(argv):
        if "--version" in argv:
            return _cp(0, "podman version 4.9.3\n")
        return _cp(0)


class TheChainStopsAtTheFirstRealFault(_Base):
    def test_a_missing_binary_is_named_as_such(self) -> None:
        with mock.patch.object(preflight.shutil, "which", return_value=None):
            r = preflight.check()
        self.assertFalse(r.ok())
        self.assertIn("not on PATH", r.refusal.precondition)

    def test_a_binary_that_does_not_answer_is_a_DIFFERENT_fault(self) -> None:
        """Installed-but-broken and absent are different problems with different remedies, and a
        refusal that conflated them would send the operator to the wrong place."""
        def responder(argv):
            return _cp(1, "", "cannot open storage config") if "--version" in argv else _cp(0)

        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(responder):
            r = preflight.check()
        self.assertIn("did not answer --version", r.refusal.precondition)
        self.assertIn("cannot open storage config", r.refusal.stderr)

    def test_a_missing_image_names_WHICH_image(self) -> None:
        def responder(argv):
            if "--version" in argv:
                return _cp(0, "podman version 4.9.3\n")
            if "exists" in argv:
                return _cp(1, "", "image not known")
            return _cp(0)

        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(responder):
            r = preflight.check(image=_IMAGE)
        self.assertIn(_IMAGE, r.refusal.precondition)
        self.assertIn("staging is a precondition", r.refusal.hint.lower())


class TheProbeMustBeTheFailingOperation(_Base):
    """THE FINDING, as a test. Measured on a VM under user.max_net_namespaces=0."""

    @staticmethod
    def _netns_denied(argv):
        """Reproduces the measured behaviour exactly: create SUCCEEDS, attach REFUSES."""
        if "--version" in argv:
            return _cp(0, "podman version 4.9.3\n")
        if "exists" in argv:
            return _cp(0)
        if "network" in argv and "create" in argv:
            return _cp(0, "the-network\n")          # <-- succeeds, as measured
        if argv[1] == "run":
            return _cp(126, "", "Error: creating network namespace for container abc123: "
                               "failed to create namespace: no space left on device")
        return _cp(0)

    def test_the_preflight_REFUSES_under_a_netns_denial(self) -> None:
        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(self._netns_denied):
            r = preflight.check(image=_IMAGE)
        self.assertFalse(r.ok(), "the preflight passed on a host that cannot run the demo")
        self.assertIn("ATTACHED", r.refusal.precondition)

    def test_a_probe_that_stopped_at_NETWORK_CREATE_would_have_PASSED(self) -> None:
        """The false pass, demonstrated rather than asserted: the weaker probe returns rc=0 on the
        very host the real probe refuses. This is why the capability check is attach-shaped."""
        create_rc = self._netns_denied(["podman", "network", "create", "--internal", "n"]).returncode
        attach_rc = self._netns_denied(["podman", "run", "--rm", "--network", "n", _IMAGE]).returncode
        self.assertEqual(create_rc, 0, "the weaker probe would have reported success")
        self.assertNotEqual(attach_rc, 0, "the real operation fails on this same host")

    def test_the_refusal_carries_VERBATIM_stderr_not_only_a_classification(self) -> None:
        """`no space left on device` is ENOSPC from a ucount limit, not a full disk. Text alone sends
        an operator to df; a classification alone cannot be checked. Both, or it is not actionable."""
        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(self._netns_denied):
            r = preflight.check(image=_IMAGE)
        rendered = r.refusal.render()
        self.assertIn("no space left on device", rendered)          # the evidence, verbatim
        self.assertIn("max_net_namespaces", rendered)               # the classification, as a hint
        self.assertIn("rather than a full", rendered)               # and the trap, named

    def test_a_network_CREATE_failure_is_reported_as_its_own_precondition(self) -> None:
        """A network-object failure and a namespace-capability failure are different faults; merging
        them would point the operator at the wrong subsystem."""
        def responder(argv):
            if "--version" in argv:
                return _cp(0, "podman version 4.9.3\n")
            if "exists" in argv:
                return _cp(0)
            if "network" in argv and "create" in argv:
                return _cp(125, "", "netavark: plugin not found")
            return _cp(0)

        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(responder):
            r = preflight.check(image=_IMAGE)
        self.assertIn("sealed network could not be created", r.refusal.precondition)
        self.assertIn("netavark", r.refusal.stderr)


class ThePositiveControl(_Base):
    """Without this, a preflight that refused EVERYTHING would satisfy every test above."""

    def test_a_healthy_host_PASSES_and_names_what_it_proved(self) -> None:
        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(self._healthy):
            r = preflight.check(image=_IMAGE)
        self.assertTrue(r.ok())
        self.assertTrue(any("attached to a sealed network" in p for p in r.passed),
                        "the report does not state that the REAL capability was exercised")

    def test_the_probe_network_is_always_cleaned_up(self) -> None:
        """Run-scoped names plus removal: preflight must not become a source of the residue its own
        contract lists as a precondition."""
        seen: list[list[str]] = []

        def responder(argv):
            seen.append(list(argv))
            return self._healthy(argv)

        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(responder):
            preflight.check(image=_IMAGE)
        self.assertTrue(any("network" in a and "rm" in a for a in seen),
                        "the probe network was left behind")

    def test_cleanup_runs_even_when_the_attach_REFUSES(self) -> None:
        """The failure path is where residue actually accumulates, so that is where it must be shown."""
        seen: list[list[str]] = []

        def responder(argv):
            seen.append(list(argv))
            return TheProbeMustBeTheFailingOperation._netns_denied(argv)

        with mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/podman"), \
             self._with(responder):
            preflight.check(image=_IMAGE)
        self.assertTrue(any("network" in a and "rm" in a for a in seen),
                        "a refused preflight left its probe network behind")


if __name__ == "__main__":
    unittest.main()
