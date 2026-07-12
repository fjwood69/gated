"""gate/acceptance.py — 3.5 job-4: the TWO-SIDED ACCEPTANCE ANCHOR (the receipt).

The artifact that proves Calibration Mode works — not by assertion, but by a SIGNED report of a real
two-sided run: the calibrator REFUSES a detector that misses a known-bad (FN) AND refuses one that
false-positives a known-good (FP), PASSES an honest detector, and — the load-bearing part — that honest
detector GENERALISES to a BLIND HOLDOUT the detector's authors never saw. Every confound the board named
is closed in the report:

  * short-circuit ON  -> asserted OFF and recorded in the signed report (full distribution, no early out).
  * sandbox drift     -> the sandbox config hash is in the signed report (the run's environment is pinned).
  * fixtures-theatre  -> the BLIND HOLDOUT (encrypted, author-invisible) proves generalisation, not memo.
  * overfit           -> generalisation to the (rotatable) holdout is required for acceptance.
  * self-grading      -> the report is signed by a CALIBRATION_GOVERNANCE key the detector author lacks.
  * missing check-type -> the report records that every visible + holdout fixture actually produced a
                          verdict (coverage counts), so a silently-skipped fixture cannot inflate a pass.

Honest claim (reframe-2): a PASS says the detector "resists the CURRENT corpus" — provisional, the corpus
grows — never "proven safe". The blind holdout is DUAL-CONTROLLED and ENCRYPTED AT REST under a
CALIBRATION_GOVERNANCE-only key: the authoring side cannot read it (no key), so it cannot be overfit, and
a poisoned holdout needs two calibration-governance principals to land.

BLIND ONLY UNDER THE TRUSTED-DETECTOR MODEL (#4 — the fundamental in-process limit). Encryption hides the
holdout's CONTENT, but an AUTHOR-CONTROLLED detector needs no content: it can encode holdout membership in
the cross-fixture PASS/FAIL pattern it emits (~1 bit per fixture — the *verdict side-channel*). In-process
blindness against a detector the author supplies is therefore impossible. This anchor is blind ONLY because
the detectors arrive by NAME through a TRUSTED, content-addressed registry (``gate.detector_registry``),
never as caller objects — so the graded code is the detector-maintainer's, not the (untrusted) policy
author's. A deployment closes the residual channel by running each detector in its own container with
AGGREGATE-ONLY output (the ~1 bit/fixture pattern never returns to the author). Any "blind" claim below
holds ONLY under this trusted-detector model, never unconditionally.

Gate-side; imports engine (it RUNS the real calibrator) + core + the calibration/authority types.
Encryption here is a stdlib HMAC-keystream reference construction (encrypt-then-MAC); a deployment binds
a real AEAD/KMS — the STRUCTURE (author-invisible, key-gated, in-memory-only decrypt) is what this proves.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core import ResourceBudget, Sandbox
from gate import signing
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from core.chain import canonical_digest, content_digest
from engine.calibration import (
    DEFAULT_CALIBRATION_TRIALS,
    BackendGuard,
    BundleResolver,
    CalibrationResult,
    calibrate,
)
from gate.authority import AuthorityDomain, GovernanceApproval


class BlindHoldoutError(RuntimeError):
    """The blind holdout could not be read (wrong key / tampered ciphertext) or written (insufficient
    calibration-governance approval). Fail-closed: no acceptance without a trustworthy holdout."""


class AcceptanceError(RuntimeError):
    """The acceptance run could not be conducted honestly (e.g. short-circuit was on, or a required
    lane could not run). The anchor refuses to sign a report it cannot stand behind."""


# ---- the blind holdout: encrypted at rest, author-invisible, dual-controlled ---------------------

def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:n])


def _seal(plaintext: bytes, key: bytes, nonce: bytes) -> tuple[bytes, str]:
    ks = _keystream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).hexdigest()  # encrypt-then-MAC
    return ct, tag


def _unseal(ct: bytes, tag: str, key: bytes, nonce: bytes) -> bytes:
    if not hmac.compare_digest(hmac.new(key, nonce + ct, hashlib.sha256).hexdigest(), tag):
        raise BlindHoldoutError("blind-holdout MAC invalid — wrong key or tampered ciphertext")
    ks = _keystream(key, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks))


_HOLDOUT_SCHEMA = """
CREATE TABLE IF NOT EXISTS blind_holdout (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ciphertext BLOB NOT NULL,
    tag        TEXT NOT NULL
);
"""


class BlindHoldoutStore:
    """A restricted, encrypted-at-rest challenge set. Writing requires TWO CALIBRATION_GOVERNANCE
    principals (a poisoned holdout wrongly fails good detectors — dual control). Reading requires the
    holdout key, which the detector authoring side does NOT hold — so the holdout cannot be overfit,
    and it decrypts in-memory only (never written back to disk). The plaintext bundles the fixture's
    label + payload, so neither leaks at rest."""

    def __init__(self, path: Path) -> None:
        self._path = str(path)
        self._local = threading.local()
        self._lock = threading.Lock()
        conn = self._conn()
        conn.executescript(_HOLDOUT_SCHEMA)
        conn.commit()

    def _conn(self) -> sqlite3.Connection:
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._path, isolation_level=None, timeout=5.0)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def append(
        self, fixture: Fixture, *, holdout_key: bytes, approval: GovernanceApproval,
    ) -> int:
        """Add an encrypted holdout fixture. Dual CALIBRATION_GOVERNANCE control — a single principal,
        or a GOVERNANCE-domain approval, cannot poison the holdout."""
        if not approval.meets(2, domain=AuthorityDomain.CALIBRATION_GOVERNANCE):
            raise BlindHoldoutError(
                "blind-holdout writes require two distinct CALIBRATION_GOVERNANCE principals "
                "(a poisoned holdout wrongly fails honest detectors — dual control)"
            )
        if not holdout_key:
            raise BlindHoldoutError("refusing to seal a holdout fixture with an empty key")
        blob = json.dumps({
            "fixture_id": fixture.fixture_id, "label": fixture.label.value,
            "payload": fixture.payload.hex(), "evasion_class": fixture.evasion_class,
        }).encode("utf-8")
        with self._lock:
            cur = self._conn().execute(
                "INSERT INTO blind_holdout (ciphertext, tag) VALUES (?, ?)", (b"", ""))
            entry_id = int(cur.lastrowid or 0)
            ct, tag = _seal(blob, holdout_key, entry_id.to_bytes(8, "big"))
            self._conn().execute(
                "UPDATE blind_holdout SET ciphertext=?, tag=? WHERE id=?", (ct, tag, entry_id))
            return entry_id

    def load(self, *, holdout_key: bytes) -> CalibrationSet:
        """Decrypt the whole holdout in-memory into a CalibrationSet. Requires the key (author-
        invisible). Never writes plaintext to disk."""
        if not holdout_key:
            raise BlindHoldoutError("no holdout key — the challenge set is author-invisible by design")
        good: list[Fixture] = []
        bad: list[Fixture] = []
        for row in self._conn().execute("SELECT id, ciphertext, tag FROM blind_holdout ORDER BY id"):
            blob = _unseal(bytes(row["ciphertext"]), row["tag"], holdout_key,
                           int(row["id"]).to_bytes(8, "big"))
            obj = json.loads(blob)
            label = FixtureLabel(obj["label"])
            fx = Fixture(obj["fixture_id"], label, bytes.fromhex(obj["payload"]), obj["evasion_class"])
            (good if label is FixtureLabel.KNOWN_GOOD else bad).append(fx)
        return CalibrationSet(known_good=tuple(good), known_bad=tuple(bad))


# ---- the signed acceptance report ----------------------------------------------------------------

CALIBRATION_ENVELOPE_VERSION = 1
_ENVELOPE_DOMAIN = "gated.acceptance-envelope"


@dataclass(frozen=True)
class AcceptanceReport:
    """The signed receipt. Records the two-sided outcomes, the holdout generalisation, the confound
    closures (short_circuit OFF, sandbox config hash, coverage counts), the honest claim, and who
    signed it (a CALIBRATION_GOVERNANCE principal the detector author is not). Leaks NO fixture id or
    content — only counts + booleans + digests.

    3.5-close P1-3: the DETECTOR identity the receipt binds is the ``resolved_profile_digest`` — the
    ``ResolvedDetectorProfile.digest()`` the TRUSTED REGISTRY returned for the honest detector id (module
    bytes + entrypoint + trusted behavioral_config), NOT a caller-supplied ``DetectorManifest``. A caller
    can no longer sign-A-run-B by describing detector A while the resolver runs detector B: the signed id
    comes only from what the registry actually resolved. The ENVIRONMENT is bound separately as the
    ``measured_execution_identity`` — the parent-measured 4-tuple identity digest of the lanes that
    actually ran (never a probe, never a caller string). The signed payload is a domain-separated,
    schema-validated ``CalibrationEnvelope`` (``canonical_digest`` — rejects floats/type-confusion), so
    the receipt's identity is cross-language reproducible and tamper-evident on every field."""

    accepted: bool
    honest_passes: bool           # an honest detector PASSES the visible two-sided set
    refuses_on_fn: bool           # a known-bad-missing detector is REFUSED
    refuses_on_fp: bool           # a known-good-blocking detector is REFUSED
    generalises: bool             # the honest detector PASSES the blind holdout (not memorisation)
    short_circuit: bool           # asserted OFF
    resolved_profile_digest: str  # P1-3: the HONEST detector's RESOLVER-DERIVED profile digest (trusted)
    fn_control_profile_digest: str  # v3: the FN-deficient control's profile digest (which control refused)
    fp_control_profile_digest: str  # v3: the FP-happy control's profile digest (which control refused)
    measured_execution_identity: str  # parent-measured lane identity digest (env; not a caller string)
    trust_policy_id: str          # which observation trust policy governed the run (P1-5 content-addresses it)
    visible_corpus_digest: str    # digest of the exact visible fixtures (id+label+payload)
    holdout_corpus_digest: str    # digest of the exact blind-holdout fixtures
    trials: int                   # trials per fixture (the run's statistical depth)
    budget_wall_clock_ms: int     # the calibration wall-clock budget (ms; canonical — no float in the envelope)
    image_ref: str                # the PINNED sandbox image (a digest, not a mutable tag)
    sandbox_config_hash: str      # computed from the REAL sandbox isolation level + image_ref
    visible_coverage: int
    holdout_coverage: int
    signer_principal: str
    claim: str
    issued_at: float
    signature: str = ""

    def _envelope(self) -> dict[str, object]:
        """The CalibrationEnvelope — the SIGNED content, EXCLUDING ``signature``. Four domain groups:
        the resolver-derived detector identity, the calibration inputs, the measured execution identity,
        and the outcome/coverage. Every field except the signature is inside it, so a signature covers the
        whole receipt. Float-free (``issued_at`` is bound as integer ms) so ``canonical_digest`` accepts
        it — the schema validation is the point, not a workaround."""
        return {
            "resolved_profile_digest": self.resolved_profile_digest,
            "calibration_inputs": {
                "visible_corpus_digest": self.visible_corpus_digest,
                "holdout_corpus_digest": self.holdout_corpus_digest,
                "trials": self.trials,
                "budget_wall_clock_ms": self.budget_wall_clock_ms,
                "trust_policy_id": self.trust_policy_id,
                "fn_control_profile_digest": self.fn_control_profile_digest,
                "fp_control_profile_digest": self.fp_control_profile_digest,
            },
            "measured_execution_identity": self.measured_execution_identity,
            "outcome_and_coverage": {
                "accepted": self.accepted, "honest_passes": self.honest_passes,
                "refuses_on_fn": self.refuses_on_fn, "refuses_on_fp": self.refuses_on_fp,
                "generalises": self.generalises, "short_circuit": self.short_circuit,
                "visible_coverage": self.visible_coverage, "holdout_coverage": self.holdout_coverage,
                "image_ref": self.image_ref, "sandbox_config_hash": self.sandbox_config_hash,
                "signer_principal": self.signer_principal, "claim": self.claim,
                "issued_at_ms": int(round(self.issued_at * 1000)),
            },
        }


_HONEST_CLAIM = ("resists the CURRENT corpus (visible + blind holdout) — provisional, the corpus grows; "
                 "NOT a proof of absolute safety")


def _corpus_digest(cset: CalibrationSet) -> str:
    """A stable digest of the EXACT fixtures a lane ran — sorted (id, label, payload-hash). Binds the
    receipt to WHAT was tested, so a later corpus swap is detectable."""
    items = sorted(
        (f.fixture_id, f.label.value, hashlib.sha256(f.payload).hexdigest())
        for f in (*cset.known_bad, *cset.known_good)
    )
    return content_digest({"corpus": items})


def _content_hashes(cset: CalibrationSet) -> set[str]:
    """The set of fixture PAYLOAD hashes in a corpus — for the holdout disjointness check (overlap is
    by content, not id: a renamed duplicate is still a duplicate)."""
    return {hashlib.sha256(f.payload).hexdigest() for f in (*cset.known_bad, *cset.known_good)}


def _envelope_digest(report: AcceptanceReport) -> str:
    """The domain-separated, schema-validated digest of the CalibrationEnvelope — what gets signed. Uses
    ``canonical_digest`` (NFC-normalised, float-rejecting, domain-tagged, versioned), so the signed bytes
    are cross-language reproducible and a type-confusion cannot collide two distinct receipts."""
    return canonical_digest(_ENVELOPE_DOMAIN, report._envelope(), version=CALIBRATION_ENVELOPE_VERSION)


def _sign_report(unsigned: AcceptanceReport, signer: signing.Signer) -> AcceptanceReport:
    from dataclasses import replace

    return replace(unsigned, signature=signer.sign(_envelope_digest(unsigned).encode("utf-8")).hex())


def verify_report(report: AcceptanceReport, *, verifier: signing.Verifier) -> bool:
    """True iff the report's Ed25519 signature is valid under the CALIBRATION_GOVERNANCE ``Verifier``
    (3.5-close #1.4: a ``Verifier`` OBJECT holding only the public key — it cannot forge a receipt). The
    signature is over the domain-separated CalibrationEnvelope digest, so any tampered field (including the
    resolver-derived detector identity) invalidates it."""
    try:
        return verifier.verify(_envelope_digest(report).encode("utf-8"), bytes.fromhex(report.signature))
    except ValueError:
        return False


def run_acceptance_anchor(
    *,
    make_sandbox: Callable[[], Sandbox],
    honest_detector_id: str,
    fn_deficient_detector_id: str,
    fp_happy_detector_id: str,
    resolve: BundleResolver,
    trust_policy_id: str,
    visible_set: CalibrationSet,
    blind_holdout_store: BlindHoldoutStore,
    holdout_key: bytes,
    signer: signing.Signer,
    signer_principal: str,
    signer_approval: GovernanceApproval,
    now: float,
    budget: ResourceBudget,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
    backend_guard: BackendGuard | None = None,
) -> AcceptanceReport:
    """Conduct the two-sided acceptance run against REAL fixtures + a REAL sandbox and return a SIGNED,
    identity-bound report. Self-grading closure: ``signer_approval`` must be a CALIBRATION_GOVERNANCE
    principal (the author cannot own the grader). Runs, in order: honest detector on the visible set
    (must PASS), FN-deficient (must be REFUSED), FP-happy (must be REFUSED), honest detector on the blind
    holdout (must PASS — generalisation). ``accepted`` iff all four hold.

    The receipt binds WHAT was tested, DERIVED FROM THE REAL RUN not caller strings and not a probe
    (board #3, tightened): the ``image_ref`` / isolation / backend come from the PARENT-MEASURED
    ``execution_identity`` of the ACTUAL calibration lanes (measured by the runner from the sandbox it
    constructed, per trial — never fixture-reported), and ALL FOUR lanes must agree on that identity or
    the anchor refuses (an anchor whose lanes ran in different environments proves nothing). The removed
    ``make_sandbox()`` probe was a SEPARATE construction an adversarial factory could answer differently
    from the sandboxes that ran the fixtures; the identity now comes only from the sandboxes that DID run
    them.

    3.5-close P1-3 — the DETECTOR identity is RESOLVER-DERIVED, not caller-supplied: the receipt binds
    ``resolved_profile_digest = resolve_profile(honest_detector_id).digest()`` — the trusted registry's
    ``ResolvedDetectorProfile`` for the honest detector (module bytes + entrypoint + trusted
    behavioral_config), which ALSO revalidates that the resolved detector has not drifted. The caller no
    longer passes a ``DetectorManifest`` or ``host_closure_digest`` at all, so it cannot describe one
    detector while the resolver runs another (sign-A-run-B). The ENVIRONMENT is bound separately as the
    parent-measured lane identity (``measured_execution_identity``); the ``sandbox_config_hash`` is
    computed from the attested isolation + image. Also refuses if the visible + holdout corpora share any
    content (a holdout that duplicates the visible set proves memorisation)."""
    if not signer_approval.meets(1, domain=AuthorityDomain.CALIBRATION_GOVERNANCE):
        raise AcceptanceError(
            "the acceptance report must be signed by a CALIBRATION_GOVERNANCE principal — the detector "
            "author cannot own the harness that grades their detector (self-grading closure)"
        )
    holdout = blind_holdout_store.load(holdout_key=holdout_key)
    visible_corpus_digest = _corpus_digest(visible_set)
    holdout_corpus_digest = _corpus_digest(holdout)
    # board #4: DISJOINTNESS proven, not just "identical refused" — NO holdout fixture may share content
    # with the visible corpus (a single shared fixture is memorisation leaking into the holdout).
    overlap = _content_hashes(visible_set) & _content_hashes(holdout)
    if overlap:
        raise AcceptanceError(
            f"the blind holdout shares {len(overlap)} fixture(s) with the visible corpus — the holdout "
            "is not disjoint, so a PASS could be memorisation. The holdout must be fixtures the "
            "detector's authors never saw."
        )
    if not holdout.known_bad or not holdout.known_good:
        raise AcceptanceError(
            "the blind holdout must be two-sided (>=1 known-bad AND >=1 known-good) to prove "
            "generalisation on both sides"
        )
    # every detector arrives by NAME and is resolved ONLY through the trusted registry (``resolve``);
    # the anchor never accepts a detector object, so an author cannot smuggle in a holdout-gaming
    # detector. The honest id is graded on BOTH the visible and holdout lanes (same trusted build).
    def _cal(did: str, cset: CalibrationSet) -> CalibrationResult:  # thread the §1.6 guard uniformly
        return calibrate(make_sandbox, did, resolve, cset, budget,
                         trials=trials, backend_guard=backend_guard)

    honest = _cal(honest_detector_id, visible_set)
    fn = _cal(fn_deficient_detector_id, visible_set)
    fp = _cal(fp_happy_detector_id, visible_set)
    gen = _cal(honest_detector_id, holdout)

    # image + isolation DERIVED from the PARENT-MEASURED identity of the lanes that ACTUALLY ran (no
    # probe): every lane must have produced ONE attestable identity and all four must AGREE — else the
    # receipt has no honest environment to bind and the anchor refuses (fail-closed, board #3).
    lane_identities = [honest.execution_identity, fn.execution_identity,
                       fp.execution_identity, gen.execution_identity]
    if any(i is None for i in lane_identities) or len({
        i.digest() for i in lane_identities if i is not None
    }) != 1:
        raise AcceptanceError(
            "the acceptance lanes did not all run under ONE parent-measured execution identity — the "
            "run's environment is not attestable (a mixed or unmeasured sandbox), so no honest receipt "
            "can be signed. Every lane must run in the same pinned sandbox."
        )
    identity = honest.execution_identity
    assert identity is not None  # narrowed by the guard above (all four are non-None and equal)
    image_ref = identity.image_ref
    sandbox_config_hash = sandbox_config_digest(isolation=identity.isolation_level, image=image_ref)
    measured_execution_identity = identity.digest()
    # P1-3 v3 (atomicity): the DETECTOR identity comes from the SAME calibration op that ran it — the
    # honest lane's ``resolved_profile_digest`` (carried out of ``calibrate`` via the atomic bundle),
    # NOT a separate post-hoc resolution. The FN/FP control profile digests are bound too, so the receipt
    # records exactly WHICH controls established its refusal claims (board HOLD).
    resolved_profile_digest = honest.resolved_profile_digest
    if (resolved_profile_digest is None or fn.resolved_profile_digest is None
            or fp.resolved_profile_digest is None or gen.resolved_profile_digest is None):
        raise AcceptanceError(
            "a calibration lane did not carry a resolved-profile digest — the detector was not resolved "
            "through a profile-bearing registry, so the receipt cannot bind a trusted detector identity")
    # v4 P1-d: the VISIBLE-honest and HOLDOUT-honest lanes MUST resolve the SAME detector profile — else an
    # alternating resolver could grade the blind holdout with a DIFFERENT detector than the visible set, so
    # the receipt's single signed identity would not describe what actually judged the holdout.
    if gen.resolved_profile_digest != resolved_profile_digest:
        raise AcceptanceError(
            "the visible-honest and holdout-honest lanes resolved DIFFERENT detector profiles "
            f"({resolved_profile_digest} vs {gen.resolved_profile_digest}) — the honest detector must be "
            "the SAME across both lanes; refusing to sign (an alternating resolver cannot be trusted)")

    honest_passes = honest.passed
    refuses_on_fn = (not fn.passed) and len(fn.fn_failures) > 0
    refuses_on_fp = (not fp.passed) and len(fp.fp_failures) > 0
    generalises = gen.passed
    accepted = honest_passes and refuses_on_fn and refuses_on_fp and generalises

    unsigned = AcceptanceReport(
        accepted=accepted, honest_passes=honest_passes, refuses_on_fn=refuses_on_fn,
        refuses_on_fp=refuses_on_fp, generalises=generalises, short_circuit=False,
        resolved_profile_digest=resolved_profile_digest,
        fn_control_profile_digest=fn.resolved_profile_digest,
        fp_control_profile_digest=fp.resolved_profile_digest,
        measured_execution_identity=measured_execution_identity, trust_policy_id=trust_policy_id,
        visible_corpus_digest=visible_corpus_digest,
        holdout_corpus_digest=holdout_corpus_digest, trials=trials,
        budget_wall_clock_ms=int(round(budget.wall_clock_seconds * 1000)),
        image_ref=image_ref, sandbox_config_hash=sandbox_config_hash,
        visible_coverage=len(visible_set.known_good) + len(visible_set.known_bad),
        holdout_coverage=len(holdout.known_good) + len(holdout.known_bad),
        signer_principal=signer_principal, claim=_HONEST_CLAIM, issued_at=now,
    )
    return _sign_report(unsigned, signer)


def sandbox_config_digest(**config: object) -> str:
    """A stable digest of the sandbox configuration (backend, image, isolation level, flags) recorded
    in the report so a later sandbox drift is detectable — the run's environment is pinned."""
    return content_digest({"sandbox_config": config})


__all__ = [
    "BlindHoldoutError",
    "AcceptanceError",
    "BlindHoldoutStore",
    "AcceptanceReport",
    "run_acceptance_anchor",
    "verify_report",
    "sandbox_config_digest",
]
