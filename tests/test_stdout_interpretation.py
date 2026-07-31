"""The stdout-interpretation law: absence of output is not output of absence.

``probe_existence`` used to return ``ABSENT`` on returncode 0 with EMPTY STDOUT. A syntactically valid
but semantically WRONG query runs fine, exits 0, prints nothing — and that was read as "the container is
gone", by the function whose own docstring calls itself the destruction authority. Teardown then reports
success on a surviving container, which is a fail-OPEN in the mechanism that makes ephemerality a
security property rather than a hope.

The fix is a POSITIVE CONTROL: ABSENT requires a channel PROVEN LIVE IN THIS RUN. These tests exercise
that, in both directions, at every site that claims it.

TWO PRACTICES THIS FILE REFUSES, both of which shipped green-but-empty tests in this tree before:
  * no test CONSTRUCTS ITS OWN SUBJECT — the listing always comes from a stubbed runner, never from a
    value the assertion also computes;
  * no output-binding test IMPORTS THE SHIPPED CONSTANT it is meant to bind. The expected argv shapes
    below are RESTATED independently. Importing ``_LISTING`` would make the assertion agree with the
    code by construction, which is the seal comparing a value to itself.
"""
from __future__ import annotations

import pathlib
import subprocess
import unittest
from unittest import mock

from core import (
    Existence,
    TeardownCleanupError,
    ReplayedSandboxLeak,
    ReplayedTeardownIncomplete,
    SandboxLeakError,
    TeardownIncompleteError,
    TeardownUnverifiableError,
)
from sandbox.oci import (
    ProbeCause,
    ProbeReading,
    ResourceKind,
    UnsupportedRuntimeWitness,
    VerdictKind,
    ambient_network_witness,
    listing_argv,
    probe_container,
    probe_network,
)
from sandbox.oci import (
    WitnessCreateFailed,
    WitnessNameCollision,
    WitnessNotVisible,
    WitnessProvisioningError,
    ensure_container_witness,
)
from sandbox.observed import _SweepReport

_RT = "/usr/bin/podman"
_WITNESS = "moriverify-canary-abc123"
_SUBJECT = "moriverify-sbx-deadbeef"


def _runner(stdout: str = "", returncode: int = 0, raises: BaseException | None = None):
    """A stubbed runner. The listing is DATA supplied by the test, never something the assertion
    recomputes — so a passing assertion cannot be an artefact of the test agreeing with itself."""
    def _run(*_a: object, **_k: object) -> subprocess.CompletedProcess[str]:
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess([], returncode, stdout, "")
    return _run


class AbsentRequiresAProvenChannel(unittest.TestCase):
    """The core control, and the one the whole increment exists for."""

    def test_empty_listing_is_UNKNOWN_not_ABSENT(self) -> None:
        """THE DEFECT, stated as a test. rc 0 + empty stdout is a query that RAN and ANSWERED NOTHING.

        'It ran' is the instrument's report about its own operation. It is not an answer about the
        subject. Before the fix this returned ABSENT and teardown reported success."""
        with mock.patch.object(subprocess, "run", _runner(stdout="")):
            got = probe_container(_RT, _SUBJECT, witness=_WITNESS).state
        self.assertIs(got, Existence.UNKNOWN,
                      "an empty listing has no witness in it, so it proves nothing about the subject")

    def test_listing_without_the_witness_is_UNKNOWN_even_when_it_is_NOT_empty(self) -> None:
        """Non-emptiness is not liveness. A listing full of OTHER names still fails to show us a thing
        we KNOW exists, so its silence about the subject carries no information. This is the case a
        naive 'is stdout empty?' guard would wave through."""
        with mock.patch.object(subprocess, "run", _runner(stdout="someone-elses-container\nanother\n")):
            got = probe_container(_RT, _SUBJECT, witness=_WITNESS).state
        self.assertIs(got, Existence.UNKNOWN)

    def test_witness_present_and_subject_absent_is_ABSENT(self) -> None:
        """The POSITIVE side. With the channel proven live, silence about the subject IS informative —
        and this is the only path on which teardown may report success."""
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\nunrelated\n")):
            got = probe_container(_RT, _SUBJECT, witness=_WITNESS).state
        self.assertIs(got, Existence.ABSENT)

    def test_witness_present_and_subject_present_is_EXISTS(self) -> None:
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\n{_SUBJECT}\n")):
            got = probe_container(_RT, _SUBJECT, witness=_WITNESS).state
        self.assertIs(got, Existence.EXISTS)

    def test_a_subject_that_is_a_SUBSTRING_of_a_listed_name_is_not_EXISTS(self) -> None:
        """Matching is by whole token, not by containment — otherwise a longer unrelated name would
        report the subject as surviving, and teardown would raise on a container that is gone."""
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\n{_SUBJECT}-extra\n")):
            got = probe_container(_RT, _SUBJECT, witness=_WITNESS).state
        self.assertIs(got, Existence.ABSENT)


class EveryInabilityToTellIsUNKNOWN(unittest.TestCase):
    def test_nonzero_returncode_is_UNKNOWN(self) -> None:
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\n", returncode=1)):
            self.assertIs(probe_container(_RT, _SUBJECT, witness=_WITNESS).state, Existence.UNKNOWN)

    def test_oserror_is_UNKNOWN(self) -> None:
        with mock.patch.object(subprocess, "run", _runner(raises=OSError("boom"))):
            self.assertIs(probe_container(_RT, _SUBJECT, witness=_WITNESS).state, Existence.UNKNOWN)

    def test_timeout_is_UNKNOWN(self) -> None:
        with mock.patch.object(subprocess, "run", _runner(raises=subprocess.TimeoutExpired("x", 1))):
            self.assertIs(probe_container(_RT, _SUBJECT, witness=_WITNESS).state, Existence.UNKNOWN)

    def test_undecodable_output_is_UNKNOWN_and_does_NOT_ESCAPE_THE_TRI_STATE(self) -> None:
        """``text=True`` decodes the child's output, so undecodable bytes raise UnicodeDecodeError —
        which is NOT a SubprocessError and was NOT caught. A function whose entire contract is a
        tri-state could therefore THROW, mid-teardown, aborting the remaining destroys.

        MORE reachable under the unfiltered listing, not less: the output now contains names this
        process did not choose."""
        boom = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        with mock.patch.object(subprocess, "run", _runner(raises=boom)):
            self.assertIs(probe_container(_RT, _SUBJECT, witness=_WITNESS).state, Existence.UNKNOWN)


class TheListingIsUnfilteredAndPerKind(unittest.TestCase):
    """Argv shape, RESTATED here rather than imported — importing the shipped tuple would make these
    agree with the code by construction."""

    def test_container_listing_is_unfiltered_and_binds_the_all_flag(self) -> None:
        argv = listing_argv(_RT, ResourceKind.CONTAINER)
        self.assertEqual(argv, [_RT, "ps", "-a", "--format", "{{.Names}}"])
        self.assertNotIn("--filter", argv,
                         "the filter is DELETED, not centralised — it was the failure mode")

    def test_network_listing_is_unfiltered_and_uses_the_OTHER_format_field(self) -> None:
        """Containers report {{.Names}}; networks report {{.Name}}. A future 'harmonising' edit that
        unified them would silently empty one kind's listing — which under the old code read as
        ABSENT. This pins the difference so the harmonisation cannot pass quietly."""
        argv = listing_argv(_RT, ResourceKind.NETWORK)
        self.assertEqual(argv, [_RT, "network", "ls", "--format", "{{.Name}}"])
        self.assertNotIn("--filter", argv)

    def test_the_two_kinds_do_not_share_a_format_field(self) -> None:
        self.assertNotEqual(listing_argv(_RT, ResourceKind.CONTAINER)[-1],
                            listing_argv(_RT, ResourceKind.NETWORK)[-1])


class KindIsNamedNotPassed(unittest.TestCase):
    """Moving argv construction inside the probe created a NEW way to lie: probe a CONTAINER name under
    the NETWORK kind and the network witness passes, the network listing has no such name, and the
    verdict is ABSENT while the container lives. Naming the kind in the function removes the token that
    could be wrong."""

    def test_container_and_network_wrappers_query_different_things(self) -> None:
        seen: list[list[str]] = []

        def _capture(argv, *_a, **_k):  # type: ignore[no-untyped-def]
            seen.append(list(argv))
            return subprocess.CompletedProcess([], 0, "", "")

        with mock.patch.object(subprocess, "run", _capture):
            probe_container(_RT, _SUBJECT, witness=_WITNESS).state
            probe_network(_RT, _SUBJECT, runtime_name="podman").state
        self.assertNotEqual(seen[0], seen[1], "the two kinds must not issue the same query")
        self.assertIn("ps", seen[0])
        self.assertIn("network", seen[1])


class TheAmbientWitnessIsMeasuredNotAssumed(unittest.TestCase):
    def test_an_unmeasured_runtime_is_refused_BEFORE_any_subprocess(self) -> None:
        """Absence of SUPPORT must not look like absence of EVIDENCE. The refusal happens at the map
        lookup, so no listing is attempted and the failure cannot be mistaken for a quiet channel."""
        called = []

        def _tripwire(*_a: object, **_k: object) -> None:
            called.append(1)
            raise AssertionError("a subprocess ran for an unsupported runtime")

        with mock.patch.object(subprocess, "run", _tripwire):
            with self.assertRaises(UnsupportedRuntimeWitness):
                probe_network(_RT, _SUBJECT, runtime_name="zz-unmeasured-runtime").state
        self.assertEqual(called, [], "no subprocess may run before the support check")

    def test_the_measured_runtimes_resolve_to_DIFFERENT_ambient_networks(self) -> None:
        """Measured 2026-07-31 on the reference host: podman -> 'podman', docker -> 'bridge'. Asserted
        as a DIFFERENCE as well as by value: a map that returned one name for every runtime would be a
        guess wearing a map's clothes."""
        self.assertEqual(ambient_network_witness("podman"), "podman")
        self.assertEqual(ambient_network_witness("docker"), "bridge")
        self.assertNotEqual(ambient_network_witness("podman"), ambient_network_witness("docker"))

    def test_nerdctl_is_absent_from_the_map_because_it_was_not_measured(self) -> None:
        with self.assertRaises(UnsupportedRuntimeWitness):
            ambient_network_witness("nerdctl")


class EverySiteThreadsItsOwnWitness(unittest.TestCase):
    """Rule 2: a test at the FUNCTION says nothing about the CALL SITES. Both backends probe containers
    through an instance attribute, so a site that threaded the wrong value — or none — would fail here
    and nowhere else. The keyword is required, so 'passes no witness at all' is unrepresentable by
    construction; what remains checkable is that the value threaded is the INSTANCE'S OWN witness."""

    def test_both_backends_pass_their_instance_witness_to_the_container_probe(self) -> None:
        from sandbox.oci import OCISandbox
        from sandbox.observed import ObservedOCISandbox
        # Patched PER MODULE. ``observed.py`` does ``from sandbox.oci import probe_container``, which
        # binds the name into its OWN namespace, so patching the definition site would not reach it.
        # This is the same mistake made once before in this tree; it is written down here so the next
        # reader does not have to rediscover why the target differs per class.
        for cls, module in ((OCISandbox, "sandbox.oci"), (ObservedOCISandbox, "sandbox.observed")):
            sbx = cls.__new__(cls)
            sbx._runtime, sbx._runtime_path = "podman", _RT
            sbx._witness = _WITNESS
            with mock.patch(f"{module}.probe_container", return_value=Existence.ABSENT) as probe:
                sbx._container_state(_SUBJECT)
            self.assertEqual(probe.call_args.kwargs.get("witness"), _WITNESS,
                             f"{cls.__name__}._container_state did not thread its own witness")

    def test_an_unprepared_instance_REFUSES_rather_than_returning_a_tri_state(self) -> None:
        """⚠ THIS TEST PREVIOUSLY ASSERTED ``UNKNOWN``, AND IT WAS WRONG — I wrote it before the ruling
        that absence of CALIBRATION must not be reported in the evidence type.

        An instance built via ``__new__`` has no witness. Returning UNKNOWN there would let a lifecycle
        bug masquerade as a quiet channel: the caller cannot distinguish 'the instrument was never on'
        from 'the channel went silent', and only one of those is a fact about the subject. So it RAISES,
        before any subprocess runs — and the stub below would have been consulted had it not."""
        from sandbox.oci import OCISandbox, WitnessNotProvisioned
        sbx = OCISandbox.__new__(OCISandbox)
        sbx._runtime, sbx._runtime_path = "podman", _RT
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\nother\n")):
            with self.assertRaises(WitnessNotProvisioned):
                sbx._container_state(_SUBJECT)


class TheListingNeverLeaks(unittest.TestCase):
    """Unfiltered means the output carries names of containers this process does not own. A precedent
    in this tree baked ``str(exc)`` into a signed, published observation and it was found by review
    rather than by anything failing."""

    def test_no_failure_path_carries_the_listing_out_of_the_probe(self) -> None:
        sentinel = "zz-other-tenants-private-name"
        for rc in (0, 1):
            with mock.patch.object(subprocess, "run", _runner(stdout=f"{sentinel}\n", returncode=rc)):
                got = probe_container(_RT, _SUBJECT, witness=_WITNESS).state
            self.assertIs(got, Existence.UNKNOWN)
            self.assertNotIn(sentinel, got.value,
                             "the returned value must not carry listing content")

    def test_the_probe_returns_a_tri_state_rather_than_raising_on_any_path(self) -> None:
        """Every inability-to-tell must arrive as UNKNOWN, because a raise mid-teardown aborts the
        remaining destroys — strictly worse than a fail-closed verdict."""
        for boom in (OSError("x"), subprocess.TimeoutExpired("x", 1),
                     UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")):
            with mock.patch.object(subprocess, "run", _runner(raises=boom)):
                self.assertIs(probe_container(_RT, _SUBJECT, witness=_WITNESS).state, Existence.UNKNOWN)



class TheGuarantorIsItselfTested(unittest.TestCase):
    """``ensure_container_witness`` is the GUARANTOR of this increment's precondition.

    The law is "ABSENT requires a live control"; the precondition is "a control exists"; and this
    function is what makes that true. Its OWN failure modes had no test — so the fix for the defect that
    caused this whole round was itself a claim. Named because a guarantor audit is now a standing item:
    every new invariant has a precondition, the precondition has a guarantor, and the guarantor's
    failures are part of the discharge.
    """

    def test_a_non_zero_create_REFUSES_rather_than_returning_a_name(self) -> None:
        """U3, the name-only witness. ``create`` exiting non-zero (name collision, daemon refusal) used
        to return the name anyway: non-empty, so no emptiness guard caught it, absent from every
        listing, so every probe went UNKNOWN and every resource was reported a survivor."""
        with mock.patch.object(subprocess, "run", _runner(returncode=1)):
            with self.assertRaises(WitnessProvisioningError):
                ensure_container_witness(_RT, "sha256:zz", "abc123")

    def test_an_exception_during_create_REFUSES_rather_than_being_swallowed(self) -> None:
        for boom in (OSError("x"), subprocess.TimeoutExpired("x", 1)):
            with mock.patch.object(subprocess, "run", _runner(raises=boom)):
                with self.assertRaises(WitnessProvisioningError):
                    ensure_container_witness(_RT, "sha256:zz", "abc123")

    def test_created_but_INVISIBLE_refuses_bootstrap_verify_is_not_optional(self) -> None:
        """Creating it is not the same as being able to SEE it. A canary the listing cannot show is a
        canary that proves nothing, and accepting it would defer the failure to teardown — the worst
        moment to learn the instrument was never on."""
        calls = {"n": 0}

        def _create_ok_then_empty_listing(*_a: object, **_k: object):  # type: ignore[no-untyped-def]
            calls["n"] += 1
            # 1st call = create (succeeds); 2nd = the bootstrap listing, which does NOT contain it
            return subprocess.CompletedProcess([], 0, "" if calls["n"] > 1 else "", "")

        with mock.patch.object(subprocess, "run", _create_ok_then_empty_listing):
            with self.assertRaises(WitnessProvisioningError):
                ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertGreaterEqual(calls["n"], 2, "bootstrap-verify must actually issue a listing")

    def test_a_created_and_VISIBLE_canary_is_returned(self) -> None:
        """The known-good side. Without it, a guarantor that refused everything would pass every test
        above — refuses-the-bad and refuses-everything are indistinguishable from failures alone."""
        name_seen = {}

        def _create_then_list(argv, *_a, **_k):  # type: ignore[no-untyped-def]
            if "create" in argv:
                name_seen["n"] = argv[argv.index("--name") + 1]
                return subprocess.CompletedProcess([], 0, "", "")
            return subprocess.CompletedProcess([], 0, f"{name_seen['n']}\nother\n", "")

        with mock.patch.object(subprocess, "run", _create_then_list):
            got = ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertEqual(got, name_seen["n"])
        self.assertIn("canary-abc123", got, "the canary must be kind-segmented and rid-correlatable")


class PrepareProvisionsTheWitness(unittest.TestCase):
    """D1/D2: deleting the provisioning line from ``prepare()`` left every test green, which proved the
    line was DEAD CODE as far as the suite was concerned. These are what make it live."""

    def _artifact(self):  # type: ignore[no-untyped-def]
        import tempfile
        from core import ArtifactSpec, tree_hash
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "a.py").write_text("x = 1\n")
        return ArtifactSpec(path=d, tree_hash=tree_hash(d))

    def test_oci_prepare_stores_the_provisioned_witness_on_the_instance(self) -> None:
        import sandbox.oci as oci_mod
        from core import Fixtures
        sbx = oci_mod.OCISandbox.__new__(oci_mod.OCISandbox)
        sbx._runtime, sbx._runtime_path, sbx.image = "podman", _RT, "img"
        with mock.patch.object(oci_mod, "resolve_image_id", return_value="sha256:zz"), \
             mock.patch.object(oci_mod, "ensure_container_witness", return_value="zz-canary") as prov:
            sbx.prepare(self._artifact(), Fixtures())
        self.assertTrue(prov.called, "prepare() did not provision a witness")
        self.assertEqual(sbx._witness, "zz-canary", "prepare() did not STORE the provisioned witness")

    def test_observed_prepare_provisions_before_it_stages_anything(self) -> None:
        """Ordering matters: the refusal must land BEFORE the untrusted artifact is staged or run."""
        import sandbox.observed as obs_mod
        from core import Fixtures
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx.image = "podman", _RT, "img"
        with mock.patch.object(obs_mod, "resolve_image_id", return_value="sha256:zz"), \
             mock.patch.object(obs_mod, "ensure_container_witness", return_value="zz-canary") as prov, \
             mock.patch.object(obs_mod.ObservedOCISandbox, "_create_network",
                               side_effect=RuntimeError("stop after provisioning")):
            with self.assertRaises(Exception):
                sbx.prepare(self._artifact(), Fixtures())
        self.assertTrue(prov.called, "prepare() did not provision a witness")
        self.assertEqual(sbx._witness, "zz-canary", "prepare() did not STORE the provisioned witness")


class TheWitnessSurvivesAFailedTeardown(unittest.TestCase):
    """L2/L3: the raise INVITES a retry, so destroying the instrument in ``finally`` disarms the very
    response the error asks for — and a repeat with no witness reports all-unproven forever."""

    def _sandbox(self):  # type: ignore[no-untyped-def]
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path = "podman", _RT
        sbx._witness = _WITNESS
        return sbx

    def _handle(self):  # type: ignore[no-untyped-def]
        from sandbox.observed import ObservedHandle
        return ObservedHandle(id="h1", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-nonexistent"),
                              container="c1", network="n1", proxy="p1", proxy_ip="10.0.0.2",
                              baseline=0, image_id="sha256:zz")

    def test_the_witness_is_RETAINED_when_teardown_could_not_be_verified(self) -> None:
        sbx, h = self._sandbox(), self._handle()
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport([], ["c1"], [])):
            with self.assertRaises(TeardownUnverifiableError):
                sbx.teardown(h)
        self.assertEqual(sbx._witness, _WITNESS,
                         "the witness was dropped on the FAILURE path — a retry would be uncalibrated")

    def test_the_witness_is_dropped_only_on_a_clean_verdict(self) -> None:
        sbx, h = self._sandbox(), self._handle()
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport()), \
             mock.patch.object(sbx, "_force_remove"):
            sbx.teardown(h)
        self.assertIsNone(sbx._witness, "a clean teardown must release the witness")

    def test_a_second_teardown_REPLAYS_rather_than_re_probing(self) -> None:
        """Teardown is documented idempotent. Without a tombstone the repeat re-probes with no witness,
        turning a defensive ``finally: teardown()`` into an error generator."""
        sbx, h = self._sandbox(), self._handle()
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport()) as sweep, \
             mock.patch.object(sbx, "_force_remove"):
            sbx.teardown(h)
            sbx.teardown(h)
        self.assertEqual(sweep.call_count, 1,
                         "the second teardown re-probed instead of replaying the recorded verdict")


class TheSweepDestroysEvenWhenUncalibrated(unittest.TestCase):
    """C3: an unreadable probe is a reason to distrust the REPORT, never a reason to skip the WORK."""

    def test_destroys_are_attempted_with_no_witness_and_everything_is_reported_UNPROVEN(self) -> None:
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, None
        with mock.patch.object(sbx, "_force_remove") as rm, \
             mock.patch.object(sbx, "_force_remove_network") as rmnet:
            report = sbx._teardown_infra("n1", "p1", "c1")
        self.assertEqual(report.present, [],
                         "nothing may be reported as OBSERVED TO PERSIST with no instrument")
        self.assertEqual(sorted(report.unproven), ["c1", "n1", "p1"],
                         "every resource must be reported unproven")
        self.assertTrue(report.causes, "an all-unproven report must SAY WHY, once, on the aggregate")
        self.assertEqual(rm.call_count, 2, "container destroys were SKIPPED when uncalibrated")
        self.assertTrue(rmnet.called, "the network destroy was SKIPPED when uncalibrated")

    def test_an_EMPTY_STRING_witness_is_uncalibrated_too_not_a_probe_precondition_failure(self) -> None:
        """The entry check uses the PROBE'S OWN predicate. ``is None`` let ``""`` through to the probe,
        which then raised the precondition failure the entry check exists to make unreachable."""
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, ""
        with mock.patch.object(sbx, "_force_remove"), mock.patch.object(sbx, "_force_remove_network"):
            report = sbx._teardown_infra("n1", "p1", "c1")
        self.assertEqual(sorted(report.unproven), ["c1", "n1", "p1"])
        self.assertEqual(report.present, [])


class AnUnknownThatCannotSayWhyIsTheSameDefectOneLevelUp(unittest.TestCase):
    """FOUND BY A RED TEST I COULD NOT DIAGNOSE FROM ITS OWN MESSAGE.

    A real-podman keystone failed in the full suite and passed both alone and at file level. The verdict
    said the containers were UNVERIFIED — and there was no way to tell from it whether the listing had
    failed to run, run and errored, or run cleanly without the witness in it. Those are three different
    events with three different responses, and the increment that exists to stop 'absence of output'
    reading as 'output of absence' was emitting exactly that shape in its own report.

    Deduplicated on the aggregate, and carrying our OWN names only — never the listing content.
    """

    def test_a_listing_that_never_RAN_says_so(self) -> None:
        with mock.patch.object(subprocess, "run", _runner(raises=OSError("no such binary"))):
            r = probe_container(_RT, _SUBJECT, witness=_WITNESS)
        self.assertIs(r.state, Existence.UNKNOWN)
        self.assertIs(r.cause, ProbeCause.LISTING_DID_NOT_RUN)

    def test_a_listing_that_ran_and_FAILED_says_so(self) -> None:
        with mock.patch.object(subprocess, "run", _runner(stdout="", returncode=125)):
            r = probe_container(_RT, _SUBJECT, witness=_WITNESS)
        self.assertIs(r.cause, ProbeCause.LISTING_EXITED_NONZERO)
        self.assertIn("125", r.detail)

    def test_a_listing_that_ran_CLEANLY_without_the_witness_says_THAT(self) -> None:
        """The interesting one: rc 0, output present, witness gone. Something destroyed the canary —
        a different event from a broken client, and the only one that points at another actor."""
        with mock.patch.object(subprocess, "run", _runner(stdout="someone-elses\nanother\n")):
            r = probe_container(_RT, _SUBJECT, witness=_WITNESS)
        self.assertIs(r.cause, ProbeCause.WITNESS_NOT_IN_LISTING)

    def test_the_three_causes_are_DISTINCT_and_ALL_REACHABLE(self) -> None:
        """A closed set is only worth having if every member is reachable and no two arrivals collapse
        into one. Three labels that read alike would be one label wearing three coats."""
        got = []
        for stub in (_runner(raises=OSError("x")), _runner(returncode=125),
                     _runner(stdout="unrelated\n")):
            with mock.patch.object(subprocess, "run", stub):
                got.append(probe_container(_RT, _SUBJECT, witness=_WITNESS).cause)
        self.assertEqual(len(set(got)), 3, "two arrival paths at UNKNOWN report the same cause")
        self.assertEqual(set(got), set(ProbeCause),
                         "a ProbeCause member is unreachable — an enum nothing can produce is a claim")

    def test_an_ANSWER_carries_no_cause_at_all(self) -> None:
        """``cause`` is None if and only if the probe answered about the SUBJECT. An answer needs no
        excuse, and a cause attached to one would be a confidence label masquerading as evidence."""
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\n{_SUBJECT}\n")):
            self.assertIsNone(probe_container(_RT, _SUBJECT, witness=_WITNESS).cause)
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{_WITNESS}\n")):
            self.assertIsNone(probe_container(_RT, _SUBJECT, witness=_WITNESS).cause)

    def test_the_cause_never_carries_the_LISTING(self) -> None:
        sentinel = "zz-other-tenants-private-name"
        with mock.patch.object(subprocess, "run", _runner(stdout=f"{sentinel}\n")):
            r = probe_container(_RT, _SUBJECT, witness=_WITNESS)
        self.assertNotIn(sentinel, r.describe(),
                         "the diagnostic leaked names this process does not own")
        self.assertNotIn(sentinel, r.detail)

    def test_diagnosability_is_NOT_a_per_call_site_choice(self) -> None:
        """⚠ THIS IS WHY THE SHAPE CHANGED. The first version threaded an OPTIONAL accumulator, so a
        call site could omit it and the same UNKNOWN was diagnosable at one site and mute at another —
        the guarantee that every site passed it living in prose. Returning the cause makes a mute
        reading unrepresentable: rule 2 answered in the type rather than in a comment."""
        with mock.patch.object(subprocess, "run", _runner(stdout="")):
            r = probe_container(_RT, _SUBJECT, witness=_WITNESS)
        self.assertIsNotNone(r.cause, "an UNKNOWN arrived with no cause — the mute path is back")


class TheTwoGuardsProveDifferentThings(unittest.TestCase):
    """P1-1. THE STATE THE FIRST DISCHARGE NEVER CONSTRUCTED, and the reason it never did.

    I reasoned that "create failed yet the canary is visible" was unconstructible, concluded the
    return-code check was defence-in-depth behind bootstrap-verify, and then BUILT THE MUTATION FROM
    THAT CONCLUSION — removing both guards together. The harness faithfully tested my error and
    reported a coverage gap where there was a load-bearing control. A mutation cannot catch a belief
    the author reasoned into the mutation.

    The state is constructible, and the design constructs it: canary names are deterministic, leaked
    canaries are anticipated (the reaper is unwired), so a repeated rid fails ``create`` on a name
    conflict WHILE the stale namesake is listed. Bootstrap-verify alone would then find the name,
    pass, and ADOPT a container this session did not create.

    Asserted by TYPE, never by message text: a message assertion pins the prose, not the control.
    """

    def _stub(self, *, create_rc: int, listed: bool):  # type: ignore[no-untyped-def]
        """create exits ``create_rc``; the listing contains the canary name iff ``listed``.

        The name is READ BACK OFF THE CREATE ARGV rather than recomputed here — the test supplies the
        listing as data and never derives the expected value from the same expression it asserts on.
        """
        seen: dict[str, str] = {}

        def _run(argv, *_a, **_k):  # type: ignore[no-untyped-def]
            if "create" in argv:
                seen["name"] = argv[argv.index("--name") + 1]
                return subprocess.CompletedProcess([], create_rc, "", "")
            body = f"{seen.get('name', '')}\nunrelated\n" if listed else "unrelated\nother\n"
            return subprocess.CompletedProcess([], 0, body, "")

        return _run

    def test_a_failed_create_WITH_a_listed_namesake_refuses_as_a_COLLISION(self) -> None:
        """The adoption hazard, constructed. Refuses, and returns NO NAME — the caller cannot proceed
        with a witness whose lifetime belongs to a dead session."""
        with mock.patch.object(subprocess, "run", self._stub(create_rc=125, listed=True)):
            with self.assertRaises(WitnessNameCollision) as caught:
                ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertIsInstance(caught.exception, WitnessProvisioningError,
                              "every provisioning refusal must remain catchable as one family")

    def test_a_failed_create_with_NO_namesake_is_an_ORDINARY_create_failure(self) -> None:
        """The discriminator has to cut BOTH ways. If every failed create reported a collision the type
        would carry no information — refuses-the-bad and refuses-everything are indistinguishable."""
        with mock.patch.object(subprocess, "run", self._stub(create_rc=125, listed=False)):
            with self.assertRaises(WitnessCreateFailed) as caught:
                ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertNotIsInstance(caught.exception, WitnessNameCollision,
                                 "an ordinary create failure was reported as a stale-namesake collision")

    def test_bootstrap_verify_alone_would_ADOPT_the_namesake(self) -> None:
        """WHY THE PAIR IS A PAIR, stated as a test rather than as a comment.

        Same state, with the return-code guard's decision removed: the listing shows the name, so a
        liveness-only guarantor is satisfied and hands back a witness it did not create. This is what
        the mutation should have constructed and did not.
        """
        listing_only = self._stub(create_rc=125, listed=True)

        def _create_always_ok(argv, *a, **k):  # type: ignore[no-untyped-def]
            r = listing_only(argv, *a, **k)
            return subprocess.CompletedProcess([], 0, r.stdout, "") if "create" in argv else r

        with mock.patch.object(subprocess, "run", _create_always_ok):
            adopted = ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertIn("canary-abc123", adopted,
                      "liveness alone accepts the namesake — which is precisely why exclusivity is "
                      "checked separately, and why removing the return-code guard is not a no-op")

    def test_created_but_invisible_is_a_DIFFERENT_type_from_a_failed_create(self) -> None:
        """Liveness and exclusivity fail differently, so a test can say WHICH refused."""
        def _create_ok_empty_listing(argv, *_a, **_k):  # type: ignore[no-untyped-def]
            return subprocess.CompletedProcess([], 0, "" if "create" not in argv else "", "")

        with mock.patch.object(subprocess, "run", _create_ok_empty_listing):
            with self.assertRaises(WitnessNotVisible) as caught:
                ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertNotIsInstance(caught.exception, WitnessCreateFailed,
                                 "an invisible witness was reported as a create failure")

    def test_the_three_refusals_are_distinguishable_types(self) -> None:
        """Guard identity, asserted directly. Same type + same family = a label, not a measurement."""
        self.assertTrue(issubclass(WitnessNameCollision, WitnessCreateFailed))
        self.assertFalse(issubclass(WitnessNotVisible, WitnessCreateFailed))
        for t in (WitnessCreateFailed, WitnessNameCollision, WitnessNotVisible):
            self.assertTrue(issubclass(t, WitnessProvisioningError))


class ACrashedSweepNeverMintsACleanVerdict(unittest.TestCase):
    """P1-2, and the defect was VERIFIED LIVE before the fix.

    Any exception out of the sweep other than the two intended verdicts left ``present``/``unproven``
    at their seeded ``[]``; the ``finally`` read those empties as CLEAN, dropped the witness, deleted
    the snapshot, and the next ``teardown()`` returned silently. Measured: 1st raised · witness → None
    · tombstone clean · 2nd silent. A crashed computation holding a permanent clean certificate,
    inside the increment whose subject is refusing to certify by silence.
    """

    def _sandbox(self):  # type: ignore[no-untyped-def]
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        return sbx

    def _handle(self, snapshot: pathlib.Path):  # type: ignore[no-untyped-def]
        from sandbox.observed import ObservedHandle
        return ObservedHandle(id="h-crash", artifact_hash="a", snapshot=snapshot, container="c1",
                              network="n1", proxy="p1", proxy_ip="10.0.0.2", baseline=0,
                              image_id="sha256:zz")

    def _snapshot(self) -> pathlib.Path:
        import tempfile
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "evidence.txt").write_text("what the artifact staged\n")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_an_unanticipated_raise_is_recorded_as_INCOMPLETE_not_as_clean(self) -> None:
        sbx, snap = self._sandbox(), self._snapshot()
        h = self._handle(snap)
        boom = RuntimeError("the runtime client died mid-sweep")
        with mock.patch.object(sbx, "_teardown_infra", side_effect=boom):
            with self.assertRaises(RuntimeError):
                sbx.teardown(h)
        verdict = sbx._verdict_store()["h-crash"]
        self.assertIs(verdict.kind, VerdictKind.INCOMPLETE,
                      "a sweep that never reached a verdict was tombstoned as one")

    def test_the_original_exception_stays_PRIMARY(self) -> None:
        """The crash is the certain fact. Recording a verdict must not supplant it — a caller branching
        on exception type would otherwise be handed a teardown error for a runtime failure."""
        sbx, h = self._sandbox(), self._handle(self._snapshot())
        with mock.patch.object(sbx, "_teardown_infra", side_effect=RuntimeError("primary")):
            with self.assertRaises(RuntimeError) as caught:
                sbx.teardown(h)
        self.assertEqual(str(caught.exception), "primary")
        self.assertNotIsInstance(caught.exception, TeardownIncompleteError)

    def test_the_witness_and_the_snapshot_are_RETAINED_after_a_crash(self) -> None:
        """The evidence a re-probe needs. Dropping the witness disarms the instrument; deleting the
        snapshot destroys the staged tree — on the ONE path where someone must go and look."""
        sbx, snap = self._sandbox(), self._snapshot()
        with mock.patch.object(sbx, "_teardown_infra", side_effect=RuntimeError("x")), \
             mock.patch.object(sbx, "_force_remove") as rm:
            with self.assertRaises(RuntimeError):
                sbx.teardown(self._handle(snap))
        self.assertEqual(sbx._witness, _WITNESS, "the witness was destroyed on the crash path")
        self.assertTrue(snap.exists(), "the snapshot was destroyed on the crash path — evidence loss")
        self.assertFalse(rm.called, "nothing should have been force-removed after the sweep crashed")

    def test_the_repeat_RE_RAISES_rather_than_returning_silently(self) -> None:
        """The live-verified consequence: before the fix the second call returned silently, so a
        defensive ``finally: teardown()`` reported success for a session nobody ever measured."""
        sbx, h = self._sandbox(), self._handle(self._snapshot())
        with mock.patch.object(sbx, "_teardown_infra", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                sbx.teardown(h)
        with self.assertRaises(ReplayedTeardownIncomplete):
            sbx.teardown(h)

    def test_a_precondition_failure_inside_the_sweep_is_NOT_re_quieted(self) -> None:
        """``WitnessNotProvisioned`` mid-sweep is a LOGIC error — the entry check makes it unreachable.
        Catching it per item would dress a precondition failure as a measurement."""
        from sandbox.oci import WitnessNotProvisioned
        sbx, h = self._sandbox(), self._handle(self._snapshot())
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_force_remove_network"), \
             mock.patch.object(sbx, "_container_state", side_effect=WitnessNotProvisioned("logic")):
            with self.assertRaises(WitnessNotProvisioned):
                sbx.teardown(h)
        self.assertIs(sbx._verdict_store()["h-crash"].kind, VerdictKind.INCOMPLETE)


class TheOtherBackendCrashesTheSameWay(unittest.TestCase):
    """RULE 2, FOUND BY THE HARNESS AGAIN. Seeding the verdict CLEAN at the ``OCISandbox`` site stayed
    GREEN while the identical mutation at the observed site reddened — because every crashed-sweep test
    above exercises one backend. A fix at one site is a claim about the other until something fails."""

    def _sandbox(self):  # type: ignore[no-untyped-def]
        import sandbox.oci as oci_mod
        sbx = oci_mod.OCISandbox.__new__(oci_mod.OCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        return sbx

    def _handle(self, snapshot: pathlib.Path):  # type: ignore[no-untyped-def]
        from sandbox.oci import OCIHandle
        return OCIHandle(id="oh1", artifact_hash="a", snapshot=snapshot, container="c1",
                         image_id="sha256:zz")

    def _snapshot(self) -> pathlib.Path:
        import tempfile
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "staged.txt").write_text("evidence\n")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_a_crashed_teardown_is_INCOMPLETE_and_keeps_its_evidence(self) -> None:
        sbx, snap = self._sandbox(), self._snapshot()
        h = self._handle(snap)
        with mock.patch.object(sbx, "_force_remove", side_effect=RuntimeError("client died")):
            with self.assertRaises(RuntimeError):
                sbx.teardown(h)
        self.assertIs(sbx._verdict_store()["oh1"].kind, VerdictKind.INCOMPLETE)
        self.assertEqual(sbx._witness, _WITNESS, "the witness was destroyed on the crash path")
        self.assertTrue(snap.exists(), "the snapshot was destroyed on the crash path — evidence loss")

    def test_the_repeat_RE_RAISES_rather_than_returning_silently(self) -> None:
        sbx, h = self._sandbox(), self._handle(self._snapshot())
        with mock.patch.object(sbx, "_force_remove", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                sbx.teardown(h)
        with self.assertRaises(ReplayedTeardownIncomplete):
            sbx.teardown(h)

    def test_a_clean_teardown_still_releases_and_tombstones(self) -> None:
        """The known-good side: without it, a backend that crashed on EVERY path would pass the two
        tests above. Refuses-the-bad and refuses-everything are indistinguishable from failures alone."""
        sbx, snap = self._sandbox(), self._snapshot()
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_container_state", return_value=ProbeReading(Existence.ABSENT)):
            sbx.teardown(self._handle(snap))
        self.assertIs(sbx._verdict_store()["oh1"].kind, VerdictKind.CLEAN)
        self.assertIsNone(sbx._witness)
        self.assertFalse(snap.exists())


class UnverifiableIsNotALeak(unittest.TestCase):
    """THE INCREMENT'S CENTRAL CLAIM, AND NOTHING WAS ASSERTING IT.

    Making ``TeardownUnverifiableError`` a subclass of ``SandboxLeakError`` left the whole suite GREEN.
    Every test said "teardown raises, fail-closed" — which the collapsed taxonomy also satisfies — and
    none said the two are DIFFERENT KINDS OF CLAIM. ``EXISTS`` is an answer about the subject; ``UNKNOWN``
    is a report about the instrument. Collapsing them routes an operator to hunt a leak that may not
    exist while the true fault, a dead instrument, is demoted to a footnote — and it manufactures the
    alarm fatigue that devalues the real leak alarm when it finally fires.
    """

    def test_the_two_types_are_SIBLINGS_not_ancestor_and_descendant(self) -> None:
        from core import TeardownError
        self.assertFalse(issubclass(TeardownUnverifiableError, SandboxLeakError),
                         "an UNKNOWN probe would be catchable as a PROVEN leak")
        self.assertFalse(issubclass(SandboxLeakError, TeardownUnverifiableError))
        for t in (SandboxLeakError, TeardownUnverifiableError, TeardownIncompleteError):
            self.assertTrue(issubclass(t, TeardownError), "fail-closed callers must still catch one base")

    def test_an_UNVERIFIABLE_teardown_does_not_raise_a_LEAK(self) -> None:
        """At the raise site, not only in the taxonomy — both backends, because rule 2 applies here too."""
        import sandbox.observed as obs_mod
        from sandbox.observed import ObservedHandle
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        h = ObservedHandle(id="h9", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-none"),
                           container="c1", network="n1", proxy="p1", proxy_ip="10.0.0.2",
                           baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport([], ["c1"], [])):
            with self.assertRaises(TeardownUnverifiableError) as caught:
                sbx.teardown(h)
        self.assertNotIsInstance(caught.exception, SandboxLeakError,
                                 "an unprovable teardown was reported as a proven leak")

    def test_the_oci_backend_also_refuses_to_call_UNKNOWN_a_leak(self) -> None:
        import sandbox.oci as oci_mod
        from sandbox.oci import OCIHandle
        sbx = oci_mod.OCISandbox.__new__(oci_mod.OCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        h = OCIHandle(id="oh9", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-none"),
                      container="c1", image_id="sha256:zz")
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_container_state", return_value=ProbeReading(Existence.UNKNOWN, ProbeCause.LISTING_EXITED_NONZERO, "rc=1")):
            with self.assertRaises(TeardownUnverifiableError) as caught:
                sbx.teardown(h)
        self.assertNotIsInstance(caught.exception, SandboxLeakError)

    def test_a_PROVEN_leak_is_still_a_leak(self) -> None:
        """The positive control for the discriminator: a taxonomy that called nothing a leak would pass
        every assertion above."""
        import sandbox.oci as oci_mod
        from sandbox.oci import OCIHandle
        sbx = oci_mod.OCISandbox.__new__(oci_mod.OCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        h = OCIHandle(id="oh10", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-none"),
                      container="c1", image_id="sha256:zz")
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_container_state", return_value=ProbeReading(Existence.EXISTS)):
            with self.assertRaises(SandboxLeakError) as caught:
                sbx.teardown(h)
        self.assertNotIsInstance(caught.exception, TeardownUnverifiableError)


class TheVerdictIsStoredAsDataNotAsAnException(unittest.TestCase):
    """P2-replay. A held exception object accumulates tracebacks across replays, carries ``__notes__``
    written by whoever caught it last, is shared mutable state across every caller — and its message
    was composed SEPARATELY from the live one, so the replay said LESS than the first raise."""

    def _sandbox(self):  # type: ignore[no-untyped-def]
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        return sbx

    def _handle(self):  # type: ignore[no-untyped-def]
        from sandbox.observed import ObservedHandle
        return ObservedHandle(id="h2", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-nonexistent"),
                              container="c1", network="n1", proxy="p1", proxy_ip="10.0.0.2",
                              baseline=0, image_id="sha256:zz")

    def _leaked(self):  # type: ignore[no-untyped-def]
        sbx, h = self._sandbox(), self._handle()
        report = _SweepReport(["c1"], ["n1"], [])
        with mock.patch.object(sbx, "_teardown_infra", return_value=report), \
             mock.patch.object(sbx, "_force_remove"):
            with self.assertRaises(SandboxLeakError) as first:
                sbx.teardown(h)
        return sbx, h, first.exception

    def test_the_store_holds_no_exception_object(self) -> None:
        sbx, _h, _exc = self._leaked()
        stored = sbx._verdict_store()["h2"]
        self.assertNotIsInstance(stored, BaseException,
                                 "the tombstone holds a live exception — tracebacks and __notes__ "
                                 "accumulate on it across every replay")
        self.assertIs(stored.kind, VerdictKind.LEAK)

    def test_the_replay_does_not_UNDERSTATE_the_live_verdict(self) -> None:
        """The fidelity loss, pinned. The stored leak message dropped the unproven list entirely, so
        the same event read as strictly less on the second call than on the first."""
        sbx, h, live = self._leaked()
        with self.assertRaises(ReplayedSandboxLeak) as replayed:
            sbx.teardown(h)
        self.assertIn("n1", str(replayed.exception),
                      "the replayed verdict dropped the UNPROVEN resources the live one reported")
        self.assertIn("c1", str(replayed.exception))
        self.assertIn("c1", str(live))

    def test_the_replay_is_TYPED_as_a_replay_and_still_catchable_as_a_leak(self) -> None:
        """"The instrument is dark NOW" and "we stopped asking" are different facts. The subtype says
        which — while every existing fail-closed handler still catches it."""
        sbx, h, _live = self._leaked()
        with self.assertRaises(SandboxLeakError) as caught:
            sbx.teardown(h)
        self.assertIsInstance(caught.exception, ReplayedSandboxLeak)

    def test_the_replay_STAMPS_the_moment_it_was_measured(self) -> None:
        """``when`` is CONSUMED, not merely recorded. A field written by one side and read by nobody is
        the seed of the next credited-property defect."""
        sbx, h, _live = self._leaked()
        with self.assertRaises(SandboxLeakError) as caught:
            sbx.teardown(h)
        self.assertIn("REPLAYED", str(caught.exception))
        stored_year = str(int(sbx._verdict_store()["h2"].when))[:1]
        self.assertTrue(stored_year, "a verdict must carry the time it was measured")
        self.assertRegex(str(caught.exception), r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")

    def test_repeated_replays_do_not_SHARE_one_exception_object(self) -> None:
        sbx, h, _live = self._leaked()
        raised = []
        for _ in range(2):
            with self.assertRaises(SandboxLeakError) as caught:
                sbx.teardown(h)
            raised.append(caught.exception)
        self.assertIsNot(raised[0], raised[1],
                         "both replays raised the SAME object — notes and tracebacks accumulate on it")


class TheSnapshotIsDestroyedOnlyOnAReachedVerdict(unittest.TestCase):
    """RULED. On a PROVEN leak, deleting the snapshot is intended HYGIENE — it is ephemeral scratch and
    the leak claim is about runtime resources, not the staged tree. On any unverifiable or crashed
    path it is EVIDENCE DESTRUCTION, because that is exactly the state in which someone must re-probe."""

    def _sandbox(self):  # type: ignore[no-untyped-def]
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        return sbx

    def _snapshot(self) -> pathlib.Path:
        import tempfile
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "staged.txt").write_text("evidence\n")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def _teardown(self, report: _SweepReport):  # type: ignore[no-untyped-def]
        from sandbox.observed import ObservedHandle
        sbx, snap = self._sandbox(), self._snapshot()
        h = ObservedHandle(id="h3", artifact_hash="a", snapshot=snap, container="c1", network="n1",
                           proxy="p1", proxy_ip="10.0.0.2", baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", return_value=report), \
             mock.patch.object(sbx, "_force_remove"):
            try:
                sbx.teardown(h)
            except Exception:  # noqa: BLE001 — the verdict is asserted by the caller, not here
                pass
        return sbx, snap

    def test_a_clean_teardown_removes_the_snapshot(self) -> None:
        _sbx, snap = self._teardown(_SweepReport())
        self.assertFalse(snap.exists(), "a clean teardown must not leave scratch behind")

    def test_a_PROVEN_leak_removes_the_snapshot_as_hygiene(self) -> None:
        _sbx, snap = self._teardown(_SweepReport(["c1"], [], []))
        self.assertFalse(snap.exists(),
                         "a proven leak is a claim about runtime resources, not about the staged tree")

    def test_an_UNVERIFIABLE_teardown_RETAINS_the_snapshot(self) -> None:
        _sbx, snap = self._teardown(_SweepReport([], ["c1"], []))
        self.assertTrue(snap.exists(),
                        "the snapshot was destroyed on the one path where someone must re-probe")

    def test_a_failed_witness_RELEASE_is_HEARD_and_does_not_lose_the_verdict(self) -> None:
        """THE OPERATOR-VISIBLE-OR-ABSENT RULE. This test has now been wrong TWICE, in both directions,
        and the sequence is the finding:

          v1 asserted the RuntimeError propagates — written before the dissent found this call was BARE
             while its neighbour three lines below was guarded.
          v2 asserted the failure was recorded as a NOTE and swallowed. Green, and still wrong: on a
             CLEAN verdict both ``live()`` and ``replay()`` return before notes are ever formatted, so
             the note reached NOBODY. I asserted its presence in the STORE — an internal dict — which is
             a store-only assertion, not a control. Recording into a field with no consumer is this
             module's own defect class, committed inside the fix for it.

        Ruled: a note must be emitted or not written. So the cleanup failure is now HEARD —
        ``TeardownCleanupError`` — while the verdict itself stays CLEAN, because the measurement was
        clean and only what came after it failed. A surviving canary is not mere untidiness: it is the
        precondition for the namesake-collision state on the next session drawing the same rid.
        """
        from sandbox.observed import ObservedHandle
        sbx, snap = self._sandbox(), self._snapshot()
        h = ObservedHandle(id="h5", artifact_hash="a", snapshot=snap, container="c1", network="n1",
                           proxy="p1", proxy_ip="10.0.0.2", baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport()), \
             mock.patch.object(sbx, "_drop_witness", side_effect=RuntimeError("runtime vanished")):
            with self.assertRaises(TeardownCleanupError) as caught:
                sbx.teardown(h)
        self.assertIn("witness release FAILED", str(caught.exception),
                      "the cleanup failure was recorded where no surface emits it")
        stored = sbx._verdict_store()["h5"]
        self.assertIs(stored.kind, VerdictKind.CLEAN,
                      "the verdict was LOST or reclassified — the MEASUREMENT was clean")

    def test_the_replay_of_that_clean_verdict_is_SILENT(self) -> None:
        """The other half of not reclassifying: the cleanup failure is a fact about this call, not about
        the measurement, so a repeat replays the clean verdict and says nothing."""
        from sandbox.observed import ObservedHandle
        sbx, snap = self._sandbox(), self._snapshot()
        h = ObservedHandle(id="h6", artifact_hash="a", snapshot=snap, container="c1", network="n1",
                           proxy="p1", proxy_ip="10.0.0.2", baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport()), \
             mock.patch.object(sbx, "_drop_witness", side_effect=RuntimeError("x")):
            with self.assertRaises(TeardownCleanupError):
                sbx.teardown(h)
            sbx.teardown(h)  # replay: clean, silent

    def test_a_cleanup_failure_cannot_MASK_the_verdict(self) -> None:
        """``_dispose_snapshot`` runs inside ``finally``. A raise there replaces the leak alarm with a
        filesystem error — the finding disappears and an OSError arrives in its place."""
        from sandbox.observed import ObservedHandle
        import sandbox.oci as oci_mod
        sbx, snap = self._sandbox(), self._snapshot()
        h = ObservedHandle(id="h4", artifact_hash="a", snapshot=snap, container="c1", network="n1",
                           proxy="p1", proxy_ip="10.0.0.2", baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport(["c1"], [], [])), \
             mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(oci_mod, "_rmtree_resilient", side_effect=OSError("disk gone")):
            with self.assertRaises(SandboxLeakError):
                sbx.teardown(h)
        self.assertTrue(sbx._verdict_store()["h4"].notes,
                        "the cleanup failure was swallowed without a trace on the verdict")


class TheDissentFindings(unittest.TestCase):
    """Found by an adversarial review of the BUILT remediation, after 30/30 mutations went red.

    Third consecutive round in which a post-build review found what the discharge could not — which is
    now less a run of bad luck than a measured property of the method: a harness written by the author
    of the code shares the author's frame. These are the findings that survived being checked against
    the source (two others did not, and are recorded as refuted in the follow-on rather than fixed).
    """

    def _oci(self):  # type: ignore[no-untyped-def]
        import sandbox.oci as oci_mod
        sbx = oci_mod.OCISandbox.__new__(oci_mod.OCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        return sbx

    def _handle(self, container: str = "c1", hid: str = "d1"):  # type: ignore[no-untyped-def]
        from sandbox.oci import OCIHandle
        return OCIHandle(id=hid, artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-none"),
                         container=container, image_id="sha256:zz")

    def test_a_replay_REFUSES_when_the_stored_verdict_is_about_another_subject(self) -> None:
        """A verdict answers a question about a NAMED resource. Matching on the store key alone would
        let one handle inherit a clean certificate earned by another — the crash-path defect re-minted
        on the LIVE path, where it is silent."""
        sbx = self._oci()
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_container_state", return_value=ProbeReading(Existence.ABSENT)):
            sbx.teardown(self._handle(container="c1", hid="same-id"))
        with self.assertRaises(TeardownUnverifiableError):
            sbx.teardown(self._handle(container="c2-DIFFERENT", hid="same-id"))

    def test_the_same_subject_still_replays(self) -> None:
        """The discriminator must not refuse everything — that would break documented idempotence."""
        sbx = self._oci()
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_container_state", return_value=ProbeReading(Existence.ABSENT)) as probe:
            sbx.teardown(self._handle(container="c1", hid="same-id"))
            sbx.teardown(self._handle(container="c1", hid="same-id"))
        self.assertEqual(probe.call_count, 1, "the repeat re-probed instead of replaying")

    def test_a_crashed_verdict_NAMES_the_exception_that_crashed_it(self) -> None:
        """At the boundary where the crash is the only fact anyone has, the message excluded it by
        construction — while this very increment exists to stop reports that cannot say why."""
        sbx = self._oci()
        with mock.patch.object(sbx, "_force_remove", side_effect=RuntimeError("podman socket gone")):
            with self.assertRaises(RuntimeError):
                sbx.teardown(self._handle(hid="d2"))
        detail = sbx._verdict_store()["d2"].detail
        self.assertIn("RuntimeError", detail)
        self.assertIn("podman socket gone", detail)

    def test_a_crashed_verdict_does_NOT_claim_nothing_was_measured(self) -> None:
        """It cannot know that: destroys run BEFORE probes, so a crash may follow partial destruction
        and partial measurement. The only entitled claim is that no VERDICT was reached."""
        sbx = self._oci()
        with mock.patch.object(sbx, "_force_remove", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                sbx.teardown(self._handle(hid="d3"))
        detail = sbx._verdict_store()["d3"].detail
        self.assertNotIn("nothing was measured", detail)
        self.assertIn("NEVER REACHED A VERDICT", detail)

    def test_an_unmapped_verdict_kind_is_LOUD_not_silent(self) -> None:
        """A kind absent from the exception maps used to fall out as None — silence — so adding a
        verdict kind and forgetting the map would have created a third quiet path, in the one module
        where quiet paths are the subject."""
        from sandbox.oci import TeardownVerdict
        import sandbox.oci as oci_mod
        v = TeardownVerdict(VerdictKind.LEAK, "d", 0.0, "c1")
        with mock.patch.dict(oci_mod._LIVE_VERDICT_EXC, {}, clear=True):
            with self.assertRaises(AssertionError):
                v.live()
        with mock.patch.dict(oci_mod._REPLAY_VERDICT_EXC, {}, clear=True):
            with self.assertRaises(AssertionError):
                v.replay()

    def test_a_clean_verdict_stays_silent_on_both_paths(self) -> None:
        """The positive control for the check above: a taxonomy that raised for every kind would pass
        it while breaking every clean teardown."""
        from sandbox.oci import TeardownVerdict
        v = TeardownVerdict(VerdictKind.CLEAN, "d", 0.0, "c1")
        self.assertIsNone(v.live())
        self.assertIsNone(v.replay())

    def test_an_ordinary_create_failure_does_not_claim_there_was_no_namesake(self) -> None:
        """The collision probe is UNCALIBRATED BY CONSTRUCTION — no canary exists at that moment, so it
        can prove a namesake PRESENT and can never prove one ABSENT. The subtype means 'no collision
        seen', and the message must not read as 'no collision'."""
        def _rc1_then_empty(argv, *_a, **_k):  # type: ignore[no-untyped-def]
            return subprocess.CompletedProcess([], 1 if "create" in argv else 0, "", "")

        with mock.patch.object(subprocess, "run", _rc1_then_empty):
            with self.assertRaises(WitnessCreateFailed) as caught:
                ensure_container_witness(_RT, "sha256:zz", "abc123")
        self.assertIn("NO NAMESAKE WAS OBSERVED", str(caught.exception))
        self.assertIn("UNCALIBRATED", str(caught.exception))


class TheFoldFirstFixesAreThemselvesDischarged(unittest.TestCase):
    """The three fold-first fixes, each pinned by the mutation that proved them uncovered.

    All three went GREEN under mutation on the first run — i.e. I had fixed three real defects and
    tested none of them. That is rule 1 in its plainest form: the fix was a claim until something was
    seen to fail without it.
    """

    def test_a_cleanup_note_REACHES_the_live_exception(self) -> None:
        """FOLD-1b. Notes used to be rendered by ``replay()`` alone, so on a first teardown the
        operator got the verdict and never the cleanup failure that happened alongside it."""
        import sandbox.oci as oci_mod
        import sandbox.observed as obs_mod
        from sandbox.observed import ObservedHandle
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        h = ObservedHandle(id="f1", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-none"),
                           container="c1", network="n1", proxy="p1", proxy_ip="10.0.0.2",
                           baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", return_value=_SweepReport(["c1"], [], [])), \
             mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(oci_mod, "_rmtree_resilient", side_effect=OSError("disk gone")):
            with self.assertRaises(SandboxLeakError) as caught:
                sbx.teardown(h)
        self.assertIn("snapshot cleanup failed", str(caught.exception),
                      "the live exception omitted a cleanup failure recorded alongside it")

    def test_a_verdict_WITHOUT_a_subject_is_UNREPRESENTABLE(self) -> None:
        """FOLD-2. The first attempt gave ``subject`` a ``""`` default and guarded with
        ``if prior.subject and …`` — a fail-closed control with a representable skip state, which is
        fail-open by construction. Required-by-contract REMOVES the state rather than testing for it,
        so what is asserted here is that constructing one is impossible."""
        from sandbox.oci import TeardownVerdict
        with self.assertRaises(TypeError):
            TeardownVerdict(VerdictKind.CLEAN, "detail", 0.0)  # type: ignore[call-arg]

    def test_a_CRASHLESS_incomplete_is_LOUD(self) -> None:
        """FOLD-3. Silence is right only while a crash is propagating — then the crash is the primary
        fact. ``_crashed_verdict`` explicitly anticipates the other case, and there silence would let a
        fall-through bug in teardown itself surface as nothing at all."""
        from sandbox.oci import TeardownVerdict
        crashless = TeardownVerdict(VerdictKind.INCOMPLETE, "no verdict was ever assigned", 0.0, "c1")
        self.assertIsNotNone(crashless.live(),
                             "a fall-through with no exception in flight surfaced as silence")
        self.assertIsInstance(crashless.live(), TeardownIncompleteError)

    def test_an_incomplete_WITH_a_crash_in_flight_stays_silent(self) -> None:
        """The discriminator must cut both ways: if every INCOMPLETE raised, the crash that caused it
        would be supplanted by a teardown error and the caller would branch on the wrong type."""
        from sandbox.oci import TeardownVerdict
        crashed = TeardownVerdict(VerdictKind.INCOMPLETE, "boom", 0.0, "c1", crash_in_flight=True)
        self.assertIsNone(crashed.live(), "the propagating crash was supplanted by the verdict")

    def test_the_crash_path_still_records_crash_in_flight(self) -> None:
        """Binding the flag to reality: a genuine crash must set it, or the two tests above pass while
        the live path mints crashless incompletes for every real crash."""
        import sandbox.observed as obs_mod
        from sandbox.observed import ObservedHandle
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
        h = ObservedHandle(id="f2", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz-none"),
                           container="c1", network="n1", proxy="p1", proxy_ip="10.0.0.2",
                           baseline=0, image_id="sha256:zz")
        with mock.patch.object(sbx, "_teardown_infra", side_effect=RuntimeError("x")):
            with self.assertRaises(RuntimeError):
                sbx.teardown(h)
        self.assertTrue(sbx._verdict_store()["f2"].crash_in_flight,
                       "a real crash was recorded as a crashless fall-through")


class AForeignHandleIsRefusedNotIgnored(unittest.TestCase):
    """A silent ``return`` handed out unearned success: the caller believes its resources were torn
    down and verified, and the only function authorised to say so never looked at anything."""

    def test_both_backends_raise_on_a_handle_they_do_not_own(self) -> None:
        from sandbox.oci import OCIHandle, OCISandbox
        from sandbox.observed import ObservedHandle, ObservedOCISandbox
        oci_h = OCIHandle(id="x", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz"),
                          container="c", image_id="sha256:zz")
        obs_h = ObservedHandle(id="y", artifact_hash="a", snapshot=pathlib.Path("/tmp/zz"),
                               container="c", network="n", proxy="p", proxy_ip="10.0.0.2",
                               baseline=0, image_id="sha256:zz")
        for cls, foreign in ((OCISandbox, obs_h), (ObservedOCISandbox, oci_h)):
            sbx = cls.__new__(cls)
            sbx._runtime, sbx._runtime_path, sbx._witness = "podman", _RT, _WITNESS
            with self.assertRaises(TypeError):
                sbx.teardown(foreign)


class TheWitnessMustBeANonEmptyString(unittest.TestCase):
    """Positive shape, not truthiness. ``not witness`` admits any non-empty NON-STRING — a Mock, a
    list, a sentinel — as calibrated, after which ``witness not in listed`` compares that object
    against a list of strings and reports UNKNOWN forever, on a channel reported as proven live."""

    def test_a_truthy_non_string_witness_is_REFUSED(self) -> None:
        from sandbox.oci import WitnessNotProvisioned
        for bogus in (object(), ["a-list"], 12345):
            with mock.patch.object(subprocess, "run", _runner(stdout="anything\n")):
                with self.assertRaises(WitnessNotProvisioned):
                    probe_container(_RT, _SUBJECT, witness=bogus).state  # type: ignore[arg-type]


class AWholeKindRefusalCarriesItsCauseOnTheAggregate(unittest.TestCase):
    """A single whole-kind condition reported as N per-item entries with no cause left the operator
    reading N mysteries in place of one stated fact."""

    def test_an_unmeasured_runtime_marks_the_network_unproven_WITH_a_cause(self) -> None:
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        sbx._runtime, sbx._runtime_path, sbx._witness = "zz-unmeasured", _RT, _WITNESS
        with mock.patch.object(sbx, "_force_remove"), \
             mock.patch.object(sbx, "_force_remove_network"), \
             mock.patch.object(sbx, "_container_state", return_value=ProbeReading(Existence.ABSENT)):
            report = sbx._teardown_infra("n1", "p1", "c1")
        self.assertEqual(report.unproven, ["n1"], "only the NETWORK kind is refused for this runtime")
        self.assertEqual(len(report.causes), 1, "the cause belongs to the aggregate, stated once")
        self.assertIn("zz-unmeasured", report.causes[0])

    def test_the_cause_reaches_the_raised_verdict(self) -> None:
        import sandbox.observed as obs_mod
        sbx = obs_mod.ObservedOCISandbox.__new__(obs_mod.ObservedOCISandbox)
        verdict = sbx._verdict_for("c1", _SweepReport([], ["n1"], ["no ambient network measured"]))
        self.assertIn("no ambient network measured", verdict.detail,
                      "the cause was recorded and never surfaced — a field nobody reads")


if __name__ == "__main__":
    unittest.main()
