"""3.5 job-4 — the two-sided acceptance anchor + blind holdout (the receipt). Run:
python3 -m unittest discover -s tests

The capstone: a SIGNED report proving the calibrator refuses on FN AND on FP, passes an honest detector,
and that the honest detector GENERALISES to a blind holdout the author never saw. Every confound closed:
short-circuit OFF (recorded), sandbox config hash (pinned), blind holdout (encrypted, author-invisible,
dual-controlled), self-grading (CALIBRATION_GOVERNANCE signer), coverage counts (no silent skip). Uses
the hermetic NoOp sandbox for a fast, deterministic proof of the LOGIC; UAT Phase 2 runs it on real
podman (the sandbox_config_hash distinguishes the two).
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from core import Command, Fixtures, IsolationLevel, Reason, ResourceBudget, Verdict, VerdictType
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from gate.acceptance import (
    BlindHoldoutError,
    BlindHoldoutStore,
    run_acceptance_anchor,
    sandbox_config_digest,
    verify_report,
)
from gate.authority import AuthorityDomain, GovernanceApproval
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_HOLDOUT_KEY = b"calibration-governance-holdout-key"
_SIGNER_KEY = b"calibration-governance-report-key"
_FAIL = Verdict(VerdictType.FAIL, Reason.EGRESS_ONE)
_PASS = Verdict(VerdictType.PASS, Reason.EGRESS_GE_2)


class _HermeticNoOp(NoOpSandbox):
    isolation_level: IsolationLevel = IsolationLevel.HERMETIC


def _factory():  # type: ignore[no-untyped-def]
    return lambda: _HermeticNoOp()


class _ScriptedDetector:
    def __init__(self, verdicts: list[Verdict]) -> None:
        self.fixtures = Fixtures()
        self._verdicts = verdicts
        self._i = 0

    def entrypoint(self) -> Command:
        return Command(argv=("true",))

    def assert_invariant(self, result: object) -> Verdict:
        v = self._verdicts[self._i]
        self._i += 1
        return v


def _cal_gov(*p: str) -> GovernanceApproval:
    return GovernanceApproval(principals=p, purpose="holdout", rationale="r", operation_id="o",
                              domain=AuthorityDomain.CALIBRATION_GOVERNANCE)


# visible two-sided set: 1 known-bad (vb), 1 known-good (vg). order in calibrate: bad then good.
_VISIBLE = CalibrationSet(
    known_good=(Fixture("vg", FixtureLabel.KNOWN_GOOD, b"good-visible"),),
    known_bad=(Fixture("vb", FixtureLabel.KNOWN_BAD, b"bad-visible"),),
)


def _holdout() -> BlindHoldoutStore:
    store = BlindHoldoutStore(Path(tempfile.mkdtemp(prefix="mv-hold-")) / "h.db")
    store.append(Fixture("hb", FixtureLabel.KNOWN_BAD, b"bad-holdout"),
                 holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
    store.append(Fixture("hg", FixtureLabel.KNOWN_GOOD, b"good-holdout"),
                 holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
    return store


def _run(store: BlindHoldoutStore, *, honest, fn, fp, signer=None):  # type: ignore[no-untyped-def]
    return run_acceptance_anchor(
        make_sandbox=_factory(), honest_detector=honest, fn_deficient_detector=fn,
        fp_happy_detector=fp, visible_set=_VISIBLE, blind_holdout_store=store,
        holdout_key=_HOLDOUT_KEY, signer_key=_SIGNER_KEY, signer_principal="cal-gov-1",
        signer_approval=signer or _cal_gov("cal-gov-1"),
        sandbox_config_hash=sandbox_config_digest(backend="noop", isolation="hermetic"),
        now=100.0, budget=_BUDGET, trials=3)


# honest: reused across BOTH the visible AND the holdout lane (same instance, 12 trials). Each set is
# bad-then-good: visible (vb,vg) then holdout (hb,hg) — catch each bad (FAIL x3), pass each good (PASS x3).
def _honest():  # type: ignore[no-untyped-def]
    return _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3 + [_FAIL] * 3 + [_PASS] * 3)


class AcceptanceAnchorTests(unittest.TestCase):
    def test_two_sided_acceptance_with_generalisation(self) -> None:
        store = _holdout()
        report = _run(
            store,
            honest=_honest(),                                   # visible: catches vb, passes vg
            fn=_ScriptedDetector([_PASS] * 3 + [_PASS] * 3),    # MISSES vb -> refused on FN
            fp=_ScriptedDetector([_FAIL] * 3 + [_FAIL] * 3),    # FPs vg -> refused on FP
        )
        # generalisation lane reuses the honest detector against the holdout (hb bad, hg good).
        self.assertTrue(report.honest_passes)
        self.assertTrue(report.refuses_on_fn)
        self.assertTrue(report.refuses_on_fp)
        self.assertTrue(report.generalises)
        self.assertTrue(report.accepted)
        self.assertFalse(report.short_circuit)                 # confound: short-circuit OFF, attested
        self.assertEqual(report.visible_coverage, 2)
        self.assertEqual(report.holdout_coverage, 2)           # no silent skip
        self.assertIn("provisional", report.claim)             # honest claim, not "proven"
        self.assertTrue(verify_report(report, signer_key=_SIGNER_KEY))
        self.assertFalse(verify_report(report, signer_key=b"forged"))

    def test_report_leaks_no_fixture_ids_or_content(self) -> None:
        store = _holdout()
        report = _run(store, honest=_honest(),
                      fn=_ScriptedDetector([_PASS] * 3 + [_PASS] * 3),
                      fp=_ScriptedDetector([_FAIL] * 3 + [_FAIL] * 3))
        blob = str(report._payload())
        for secret in ("hb", "hg", "bad-holdout", "good-holdout", "vb", "vg"):
            self.assertNotIn(secret, blob)  # only counts + booleans + digests

    def test_honest_detector_that_fails_holdout_is_not_accepted(self) -> None:
        # a detector that passes the VISIBLE set but a scripted run that misses on the holdout lane
        # (memorisation, not generalisation) -> generalises False -> not accepted.
        store = _holdout()
        # visible: FAIL,FAIL,FAIL (catch vb), PASS,PASS,PASS (pass vg); holdout: PASS...(MISS hb).
        detector = _ScriptedDetector([_FAIL] * 3 + [_PASS] * 3 + [_PASS] * 3 + [_PASS] * 3)
        report = _run(store, honest=detector,
                      fn=_ScriptedDetector([_PASS] * 3 + [_PASS] * 3),
                      fp=_ScriptedDetector([_FAIL] * 3 + [_FAIL] * 3))
        self.assertTrue(report.honest_passes)
        self.assertFalse(report.generalises)   # missed a holdout known-bad
        self.assertFalse(report.accepted)

    def test_self_grading_closure_requires_calibration_governance_signer(self) -> None:
        store = _holdout()
        gov_signer = GovernanceApproval(principals=("author",), purpose="p", rationale="r",
                                        operation_id="o", domain=AuthorityDomain.GOVERNANCE)
        with self.assertRaises(Exception):  # AcceptanceError — a GOVERNANCE signer cannot grade
            _run(store, honest=_honest(),
                 fn=_ScriptedDetector([_PASS] * 6), fp=_ScriptedDetector([_FAIL] * 6),
                 signer=gov_signer)


class BlindHoldoutTests(unittest.TestCase):
    def test_holdout_is_author_invisible_without_the_key(self) -> None:
        store = _holdout()
        with self.assertRaises(BlindHoldoutError):
            store.load(holdout_key=b"")           # no key -> cannot read (author-invisible)
        with self.assertRaises(BlindHoldoutError):
            store.load(holdout_key=b"wrong-key")  # wrong key -> MAC fails, cannot read

    def test_holdout_encrypted_at_rest(self) -> None:
        store = _holdout()
        # the raw ciphertext on disk must not contain the plaintext payloads.
        rows = store._conn().execute("SELECT ciphertext FROM blind_holdout").fetchall()
        raw = b"".join(bytes(r["ciphertext"]) for r in rows)
        self.assertNotIn(b"bad-holdout", raw)
        self.assertNotIn(b"good-holdout", raw)

    def test_holdout_write_requires_dual_calibration_governance(self) -> None:
        store = BlindHoldoutStore(Path(tempfile.mkdtemp(prefix="mv-hold2-")) / "h.db")
        fx = Fixture("x", FixtureLabel.KNOWN_BAD, b"y")
        with self.assertRaises(BlindHoldoutError):  # single principal
            store.append(fx, holdout_key=_HOLDOUT_KEY, approval=_cal_gov("only-one"))
        with self.assertRaises(BlindHoldoutError):  # GOVERNANCE domain, not CALIBRATION_GOVERNANCE
            store.append(fx, holdout_key=_HOLDOUT_KEY, approval=GovernanceApproval(
                principals=("a", "b"), purpose="p", rationale="r", operation_id="o",
                domain=AuthorityDomain.GOVERNANCE))
        self.assertGreater(store.append(fx, holdout_key=_HOLDOUT_KEY,
                                        approval=_cal_gov("cg1", "cg2")), 0)  # dual cal-gov -> ok

    def test_holdout_round_trips_with_the_key(self) -> None:
        store = _holdout()
        cs = store.load(holdout_key=_HOLDOUT_KEY)
        self.assertEqual({f.fixture_id for f in cs.known_bad}, {"hb"})
        self.assertEqual({f.fixture_id for f in cs.known_good}, {"hg"})
        self.assertEqual(cs.known_bad[0].payload, b"bad-holdout")  # in-memory plaintext, key-gated


if __name__ == "__main__":
    unittest.main()
