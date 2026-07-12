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
from core.chain import content_digest
from gate.signing import public_key
from core.identity import DetectorManifest, identity_for
from gate.acceptance import (
    AcceptanceError,
    BlindHoldoutError,
    BlindHoldoutStore,
    run_acceptance_anchor,
    verify_report,
)
from gate.authority import AuthorityDomain, GovernanceApproval
from sandbox.noop import NoOpSandbox

_BUDGET = ResourceBudget(wall_clock_seconds=1.0)
_HOLDOUT_KEY = b"calibration-governance-holdout-key"
_SIGNER_SEED = bytes(range(32, 64))
_SIGNER_PUB = public_key(_SIGNER_SEED)
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


_MANIFEST = DetectorManifest(check_type="egress", entrypoint=("python3", "main.py"),
                             impl_digest="detector-build-abc", eval_profile={"trials": 3})
_HOST_CLOSURE = "host-closure-digest-v1"


def _run(store: BlindHoldoutStore, *, honest, fn, fp, signer=None):  # type: ignore[no-untyped-def]
    return run_acceptance_anchor(
        make_sandbox=_factory(), honest_detector=honest, fn_deficient_detector=fn,
        fp_happy_detector=fp, detector_manifest=_MANIFEST, host_closure_digest=_HOST_CLOSURE,
        visible_set=_VISIBLE, blind_holdout_store=store, holdout_key=_HOLDOUT_KEY,
        signer_seed=_SIGNER_SEED, signer_principal="cal-gov-1",
        signer_approval=signer or _cal_gov("cal-gov-1"), now=100.0, budget=_BUDGET, trials=3)


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
        # board #3/#8: the receipt binds WHAT was tested, DERIVED from execution (not caller strings).
        expected_id = identity_for(_MANIFEST, host_closure_digest=_HOST_CLOSURE,
                                   artifact_image_digest=content_digest({"image": report.image_ref}))
        self.assertEqual(report.detector_identity, expected_id)  # COMPUTED, not a caller string
        self.assertEqual(report.image_ref, "<_HermeticNoOp>")    # DERIVED from the real sandbox
        self.assertEqual(report.trials, 3)
        self.assertNotEqual(report.visible_corpus_digest, report.holdout_corpus_digest)  # genuinely blind
        self.assertTrue(report.sandbox_config_hash)            # computed from the real sandbox
        self.assertTrue(verify_report(report, verify_key=_SIGNER_PUB))
        self.assertFalse(verify_report(report, verify_key=public_key(bytes(range(2, 34)))))

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

    def test_holdout_identical_to_visible_is_refused(self) -> None:
        # board #8: a holdout that duplicates the visible corpus proves memorisation, not
        # generalisation — the anchor refuses to sign such a receipt.
        store = BlindHoldoutStore(Path(tempfile.mkdtemp(prefix="mv-dup-")) / "h.db")
        # same ids + payloads + labels as _VISIBLE -> identical corpus digest.
        store.append(Fixture("vb", FixtureLabel.KNOWN_BAD, b"bad-visible"),
                     holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
        store.append(Fixture("vg", FixtureLabel.KNOWN_GOOD, b"good-visible"),
                     holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
        with self.assertRaises(AcceptanceError):
            _run(store, honest=_honest(),
                 fn=_ScriptedDetector([_PASS] * 6), fp=_ScriptedDetector([_FAIL] * 6))

    def test_holdout_partial_overlap_refused(self) -> None:
        # board #4: DISJOINTNESS, not just identical-corpus. A holdout sharing even ONE fixture (by
        # content) with the visible set is refused — a single leaked fixture is memorisation.
        store = BlindHoldoutStore(Path(tempfile.mkdtemp(prefix="mv-ov-")) / "h.db")
        store.append(Fixture("hb", FixtureLabel.KNOWN_BAD, b"bad-visible"),   # SAME payload as vb
                     holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
        store.append(Fixture("hg", FixtureLabel.KNOWN_GOOD, b"good-holdout"),  # distinct
                     holdout_key=_HOLDOUT_KEY, approval=_cal_gov("cg1", "cg2"))
        with self.assertRaises(AcceptanceError):
            _run(store, honest=_honest(),
                 fn=_ScriptedDetector([_PASS] * 6), fp=_ScriptedDetector([_FAIL] * 6))

    def test_lanes_without_one_attested_identity_are_refused(self) -> None:
        # board #3 (tightened): the receipt's environment is DERIVED from the lanes that actually ran.
        # A sandbox that drifts identity across trials leaves every lane unattestable -> the anchor
        # refuses to sign, rather than binding a probed-but-unrun environment.
        store = _holdout()
        n = {"i": 0}

        def drift() -> _HermeticNoOp:
            sb = _HermeticNoOp()
            sb.image = f"img-{n['i']}"  # type: ignore[attr-defined]
            n["i"] += 1
            return sb

        with self.assertRaises(AcceptanceError):
            run_acceptance_anchor(
                make_sandbox=drift, honest_detector=_honest(),
                fn_deficient_detector=_ScriptedDetector([_PASS] * 6),
                fp_happy_detector=_ScriptedDetector([_FAIL] * 6),
                detector_manifest=_MANIFEST, host_closure_digest=_HOST_CLOSURE,
                visible_set=_VISIBLE, blind_holdout_store=store, holdout_key=_HOLDOUT_KEY,
                signer_seed=_SIGNER_SEED, signer_principal="cal-gov-1",
                signer_approval=_cal_gov("cal-gov-1"), now=100.0, budget=_BUDGET, trials=3)

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


class OperationalSeparationTests(unittest.TestCase):
    """Board #4: the author/key separation is OPERATIONALLY real — a detector author (who holds only the
    detector + visible set) is powerless over the holdout and the receipt. Modelled as two disjoint
    key-holders: the AUTHOR (no holdout key, no CALIBRATION_GOVERNANCE approval, no signer seed) and
    CALIBRATION_GOVERNANCE (holds all three)."""

    # what the DETECTOR AUTHOR has: nothing calibration-governance. Distinct from _HOLDOUT_KEY/_SIGNER_SEED.
    _AUTHOR_GOVERNANCE = GovernanceApproval(("author",), purpose="p", rationale="r", operation_id="o",
                                            domain=AuthorityDomain.GOVERNANCE)

    def test_author_cannot_read_the_holdout(self) -> None:
        store = _holdout()
        with self.assertRaises(BlindHoldoutError):
            store.load(holdout_key=b"an-author-guessed-key")  # author lacks the cal-gov holdout key

    def test_author_cannot_inject_into_the_holdout(self) -> None:
        store = _holdout()
        with self.assertRaises(BlindHoldoutError):  # author holds only a GOVERNANCE approval
            store.append(Fixture("evil", FixtureLabel.KNOWN_GOOD, b"poison"),
                         holdout_key=_HOLDOUT_KEY, approval=self._AUTHOR_GOVERNANCE)

    def test_author_cannot_sign_the_acceptance_report(self) -> None:
        store = _holdout()
        with self.assertRaises(AcceptanceError):  # author cannot own the grader (self-grading closure)
            _run(store, honest=_honest(),
                 fn=_ScriptedDetector([_PASS] * 6), fp=_ScriptedDetector([_FAIL] * 6),
                 signer=self._AUTHOR_GOVERNANCE)

    def test_production_module_holds_no_baked_in_key_material(self) -> None:
        # the original failure was keys/plaintext committed alongside code. The production anchor holds
        # NO key: every key is an injected parameter. Assert no long byte-literal (a baked key) exists.
        import re
        src = (Path(__file__).resolve().parent.parent / "gate" / "acceptance.py").read_text()
        long_byte_literals = re.findall(r"b\"[^\"]{8,}\"|b'[^']{8,}'", src)
        self.assertEqual(long_byte_literals, [], f"acceptance.py must bake in no keys: {long_byte_literals}")
        # and the anchor's keys are required parameters (no defaults), so they must be supplied out-of-band.
        import inspect
        from gate.acceptance import run_acceptance_anchor
        params = inspect.signature(run_acceptance_anchor).parameters
        for k in ("holdout_key", "signer_seed"):
            self.assertIs(params[k].default, inspect.Parameter.empty)


if __name__ == "__main__":
    unittest.main()
