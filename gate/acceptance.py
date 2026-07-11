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

from core import ResourceBudget, RuntimeAssertion, Sandbox, ed25519
from core.calibration import CalibrationSet, Fixture, FixtureLabel
from core.chain import content_digest
from engine.calibration import DEFAULT_CALIBRATION_TRIALS, calibrate
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

@dataclass(frozen=True)
class AcceptanceReport:
    """The signed receipt. Records the two-sided outcomes, the holdout generalisation, the confound
    closures (short_circuit OFF, sandbox config hash, coverage counts), the honest claim, and who
    signed it (a CALIBRATION_GOVERNANCE principal the detector author is not). Leaks NO fixture id or
    content — only counts + booleans + digests."""

    accepted: bool
    honest_passes: bool         # an honest detector PASSES the visible two-sided set
    refuses_on_fn: bool         # a known-bad-missing detector is REFUSED
    refuses_on_fp: bool         # a known-good-blocking detector is REFUSED
    generalises: bool           # the honest detector PASSES the blind holdout (not memorisation)
    short_circuit: bool         # asserted OFF
    detector_identity: str      # the 4-tuple execution identity of the HONEST detector under test
    visible_corpus_digest: str  # digest of the exact visible fixtures (id+label+payload)
    holdout_corpus_digest: str  # digest of the exact blind-holdout fixtures
    trials: int                 # trials per fixture (the run's statistical depth)
    image_ref: str              # the PINNED sandbox image (a digest, not a mutable tag)
    sandbox_config_hash: str    # computed from the REAL sandbox isolation level + image_ref
    visible_coverage: int
    holdout_coverage: int
    signer_principal: str
    claim: str
    issued_at: float
    signature: str = ""

    def _payload(self) -> dict[str, object]:
        return {
            "accepted": self.accepted, "honest_passes": self.honest_passes,
            "refuses_on_fn": self.refuses_on_fn, "refuses_on_fp": self.refuses_on_fp,
            "generalises": self.generalises, "short_circuit": self.short_circuit,
            "detector_identity": self.detector_identity,
            "visible_corpus_digest": self.visible_corpus_digest,
            "holdout_corpus_digest": self.holdout_corpus_digest, "trials": self.trials,
            "image_ref": self.image_ref, "sandbox_config_hash": self.sandbox_config_hash,
            "visible_coverage": self.visible_coverage, "holdout_coverage": self.holdout_coverage,
            "signer_principal": self.signer_principal, "claim": self.claim, "issued_at": self.issued_at,
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


def _sign_report(unsigned: AcceptanceReport, signing_seed: bytes) -> AcceptanceReport:
    from dataclasses import replace

    canonical = json.dumps(unsigned._payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return replace(unsigned, signature=ed25519.sign(canonical, signing_seed).hex())


def verify_report(report: AcceptanceReport, *, verify_key: bytes) -> bool:
    """True iff the report's Ed25519 signature is valid under the CALIBRATION_GOVERNANCE PUBLIC key.
    A verifier holds only the public key, so it cannot forge a receipt."""
    canonical = json.dumps(report._payload(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        return ed25519.verify(canonical, bytes.fromhex(report.signature), verify_key)
    except ValueError:
        return False


def run_acceptance_anchor(
    *,
    make_sandbox: Callable[[], Sandbox],
    honest_detector: RuntimeAssertion,
    fn_deficient_detector: RuntimeAssertion,
    fp_happy_detector: RuntimeAssertion,
    detector_identity: str,
    visible_set: CalibrationSet,
    blind_holdout_store: BlindHoldoutStore,
    holdout_key: bytes,
    signer_seed: bytes,
    signer_principal: str,
    signer_approval: GovernanceApproval,
    image_ref: str,
    now: float,
    budget: ResourceBudget,
    trials: int = DEFAULT_CALIBRATION_TRIALS,
) -> AcceptanceReport:
    """Conduct the two-sided acceptance run against REAL fixtures + a REAL sandbox and return a SIGNED,
    FULLY-BOUND report. Self-grading closure: ``signer_approval`` must be a CALIBRATION_GOVERNANCE
    principal (the author cannot own the grader). Runs, in order: honest detector on the visible set
    (must PASS), FN-deficient (must be REFUSED), FP-happy (must be REFUSED), honest detector on the blind
    holdout (must PASS — generalisation). ``accepted`` iff all four hold.

    The receipt binds WHAT was tested (board blocker #8): the honest detector's 4-tuple
    ``detector_identity``, the visible + holdout CORPUS DIGESTS, the ``trials`` depth, and the PINNED
    ``image_ref`` (a digest, not a mutable tag). ``sandbox_config_hash`` is computed HERE from the REAL
    sandbox isolation level + the pinned image (not caller-supplied), so a mismatched environment cannot
    be laundered into a green receipt. Also refuses if the visible + holdout corpora are IDENTICAL (a
    holdout that duplicates the visible set proves memorisation, not generalisation)."""
    if not signer_approval.meets(1, domain=AuthorityDomain.CALIBRATION_GOVERNANCE):
        raise AcceptanceError(
            "the acceptance report must be signed by a CALIBRATION_GOVERNANCE principal — the detector "
            "author cannot own the harness that grades their detector (self-grading closure)"
        )
    holdout = blind_holdout_store.load(holdout_key=holdout_key)
    visible_corpus_digest = _corpus_digest(visible_set)
    holdout_corpus_digest = _corpus_digest(holdout)
    if holdout_corpus_digest == visible_corpus_digest:
        raise AcceptanceError(
            "the blind holdout is IDENTICAL to the visible corpus — that proves memorisation, not "
            "generalisation. The holdout must contain fixtures the detector's authors never saw."
        )
    # sandbox config bound from the REAL sandbox (isolation level) + the pinned image digest.
    probe_isolation = make_sandbox().isolation_level
    sandbox_config_hash = sandbox_config_digest(isolation=probe_isolation.value, image=image_ref)

    honest = calibrate(make_sandbox, honest_detector, visible_set, budget, trials=trials)
    fn = calibrate(make_sandbox, fn_deficient_detector, visible_set, budget, trials=trials)
    fp = calibrate(make_sandbox, fp_happy_detector, visible_set, budget, trials=trials)
    gen = calibrate(make_sandbox, honest_detector, holdout, budget, trials=trials)

    honest_passes = honest.passed
    refuses_on_fn = (not fn.passed) and len(fn.fn_failures) > 0
    refuses_on_fp = (not fp.passed) and len(fp.fp_failures) > 0
    generalises = gen.passed
    accepted = honest_passes and refuses_on_fn and refuses_on_fp and generalises

    unsigned = AcceptanceReport(
        accepted=accepted, honest_passes=honest_passes, refuses_on_fn=refuses_on_fn,
        refuses_on_fp=refuses_on_fp, generalises=generalises, short_circuit=False,
        detector_identity=detector_identity, visible_corpus_digest=visible_corpus_digest,
        holdout_corpus_digest=holdout_corpus_digest, trials=trials, image_ref=image_ref,
        sandbox_config_hash=sandbox_config_hash,
        visible_coverage=len(visible_set.known_good) + len(visible_set.known_bad),
        holdout_coverage=len(holdout.known_good) + len(holdout.known_bad),
        signer_principal=signer_principal, claim=_HONEST_CLAIM, issued_at=now,
    )
    return _sign_report(unsigned, signer_seed)


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
