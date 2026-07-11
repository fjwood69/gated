"""3.5 job-4 UAT Phase 2 — the acceptance anchor on REAL podman. Run on the NUC:
python3 -m unittest discover -s tests   (self-skips where no OCI runtime can run the image)

The board's UAT Phase 2: the two-sided anchor run against a REAL HERMETIC sandbox, not the NoOp. It uses
a real exit-code detector (judges out-of-band by the artifact's exit code — the artifact cannot forge it)
against real fixtures that actually execute in the OCI container, plus a real blind holdout. The signed
report carries the REAL sandbox_config_hash (which is what distinguishes this from the fast NoOp proof).
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Command, Fixtures, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import CalibrationSet, Fixture, FixtureLabel
import subprocess

from gate.acceptance import (
    BlindHoldoutStore,
    run_acceptance_anchor,
    verify_report,
)
from gate.authority import AuthorityDomain, GovernanceApproval
from sandbox.oci import OCISandbox

IMAGE = "localhost/mori:local"
_HAVE_OCI = OCISandbox.available(IMAGE)

_HOLDOUT_KEY = b"cal-gov-holdout-key"
_SIGNER_KEY = b"cal-gov-report-key"
_BUDGET = ResourceBudget(wall_clock_seconds=30.0)

# Real fixtures that EXECUTE in the container, with DISTINCT visible vs holdout payloads (board #8:
# the holdout must not duplicate the visible corpus). Both a "bad" case exits nonzero, a "good" exits 0,
# but via different code so the corpus digests differ.
_BAD_VIS = b"raise SystemExit(1)\n"
_GOOD_VIS = b"raise SystemExit(0)\n"
_BAD_HOLD = b"import sys\nsys.exit(2)\n"          # distinct payload, still nonzero
_GOOD_HOLD = b"print('ok')\nraise SystemExit(0)\n"  # distinct payload, still zero


def _pinned_image_digest() -> str:
    """Resolve the mutable tag to an immutable image ID (digest) so the receipt binds a pinned image."""
    out = subprocess.run(["podman", "image", "inspect", "--format", "{{.Id}}", IMAGE],
                         capture_output=True, text=True, check=True)
    return "sha256:" + out.stdout.strip().removeprefix("sha256:")


class _ExitCodeDetector:
    """A real RuntimeAssertion judging OUT-OF-BAND by exit code only: FAIL (caught) on nonzero, else
    PASS. The artifact cannot write its own verdict — the exit code is observed by the host."""

    def __init__(self) -> None:
        self.fixtures = Fixtures()

    def entrypoint(self) -> Command:
        return Command(argv=("python3", "/artifact/main.py"))

    def assert_invariant(self, result: object) -> Verdict:
        exit_code = getattr(result, "exit_code", None)
        if exit_code != 0:
            return Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
        return Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _AlwaysPass:  # FN-deficient: never catches the bad
    def __init__(self) -> None:
        self.fixtures = Fixtures()

    def entrypoint(self) -> Command:
        return Command(argv=("python3", "/artifact/main.py"))

    def assert_invariant(self, result: object) -> Verdict:
        return Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _AlwaysFail:  # FP-happy: blocks the good
    def __init__(self) -> None:
        self.fixtures = Fixtures()

    def entrypoint(self) -> Command:
        return Command(argv=("python3", "/artifact/main.py"))

    def assert_invariant(self, result: object) -> Verdict:
        return Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)


def _cal_gov(*p: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="holdout", rationale="r", operation_id="o",
                              domain=AuthorityDomain.CALIBRATION_GOVERNANCE)


@unittest.skipUnless(_HAVE_OCI, f"no OCI runtime can run {IMAGE} hermetically")
class AcceptanceAnchorOnRealPodmanTests(unittest.TestCase):
    def test_two_sided_anchor_signs_a_real_accepted_receipt(self) -> None:
        visible = CalibrationSet(
            known_good=(Fixture("vg", FixtureLabel.KNOWN_GOOD, _GOOD_VIS),),
            known_bad=(Fixture("vb", FixtureLabel.KNOWN_BAD, _BAD_VIS),),
        )
        holdout = BlindHoldoutStore(Path(tempfile.mkdtemp(prefix="mv-hold-oci-")) / "h.db")
        holdout.append(Fixture("hb", FixtureLabel.KNOWN_BAD, _BAD_HOLD),
                       holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
        holdout.append(Fixture("hg", FixtureLabel.KNOWN_GOOD, _GOOD_HOLD),
                       holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))

        image_ref = _pinned_image_digest()
        report = run_acceptance_anchor(
            make_sandbox=lambda: OCISandbox(image=IMAGE),
            honest_detector=_ExitCodeDetector(), fn_deficient_detector=_AlwaysPass(),
            fp_happy_detector=_AlwaysFail(), detector_identity="det-exitcode-4tuple",
            visible_set=visible, blind_holdout_store=holdout, holdout_key=_HOLDOUT_KEY,
            signer_key=_SIGNER_KEY, signer_principal="cal-gov-1",
            signer_approval=_cal_gov("cal-gov-1"), image_ref=image_ref,
            now=100.0, budget=_BUDGET, trials=2)

        self.assertTrue(report.honest_passes, "honest exit-code detector must pass the visible set")
        self.assertTrue(report.refuses_on_fn, "an always-pass detector must be refused (misses the bad)")
        self.assertTrue(report.refuses_on_fp, "an always-fail detector must be refused (blocks the good)")
        self.assertTrue(report.generalises, "honest detector must generalise to the blind holdout")
        self.assertTrue(report.accepted)
        self.assertFalse(report.short_circuit)
        self.assertEqual(report.visible_coverage, 2)
        self.assertEqual(report.holdout_coverage, 2)
        self.assertTrue(verify_report(report, signer_key=_SIGNER_KEY))
        # the receipt binds a PINNED image digest + a genuinely-blind holdout + the real sandbox hash.
        self.assertEqual(report.image_ref, image_ref)
        self.assertTrue(report.image_ref.startswith("sha256:"))
        self.assertNotEqual(report.visible_corpus_digest, report.holdout_corpus_digest)
        self.assertTrue(report.sandbox_config_hash)


if __name__ == "__main__":
    unittest.main()
