"""Receipts, the disagreement taxonomy, and the type a verdict table can be built from.

⚠ A RECEIPT IS NOT A LOG. The test for every field below is: NAME THE CHECK A SCEPTIC RUNS, AND THE
ROOT IT TRUSTS. If the answer is "trust the harness", the field does not belong here. That rules out
``verified: true``, a harness self-signature (which attests only that the harness held a key — a log
cosplaying as evidence, and worse than no field at all), and timings-as-evidence.

TWO TIERS, LABELLED IN THE RECEIPT ITSELF, because they are different KINDS of claim:

  TIER 1 — CHECKABLE NOW, against published roots. Digests against the release; the three-way binding
           of base + displayed diff -> derived for the mutated rows, which is a PURE FUNCTION and the
           only actual PROOF in the whole demo; the verdict recomputed as f(measured, expectation);
           nonce equality across every receipt in the run.

  TIER 2 — CHECKABLE ONLY BY RE-MEASUREMENT. The measured count and the boundary events. A
           measurement receipt is not a proof — it is A CHALLENGE IN A WELL-DEFINED FORMAT. So it
           carries the events rather than only their total, and the replay recipe, so the number is
           re-countable arithmetic over a disclosed artifact instead of an integer to be believed.

AND THE INSTRUMENT IS PINNED, which it was not in the first design. The pins covered DATA — release,
digest, member, policy — and bound nothing about the thing doing the measuring. The consequence is
not abstract: when drift first fires, every pinned quantity is exonerated BY CONSTRUCTION, so the
only available hypothesis is "the artifact changed", and the real cause sits in whatever was never
named. A drift detector that cannot exonerate its own instrument will misattribute, confidently, at
precisely the moment it first does its job.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Literal

# Exit codes are DISTINCT so that automation never routes a real finding into an infrastructure
# failure handler. Drift is a RESULT; the other two are refusals to produce one.
EXIT_AGREE = 0
EXIT_DRIFT = 2
EXIT_INSTRUMENT = 3
EXIT_PINS = 4


class PinInconsistent(Exception):
    """Two FROZEN claims contradict each other — the consumer's pin and the corpus's own record.

    Terminal, and detected BEFORE any container starts, because no measurement can adjudicate a
    contradiction between two things that were both written down in advance. The message must name
    both provenances and adjudicate NEITHER: the answer is not in either file, it is in a
    re-measurement, and a message that points at a side will be resolved by whoever edited last."""


class InstrumentInvalid(Exception):
    """The measuring apparatus is not in a state where its readings mean anything.

    Terminal. Never displayed as drift — that is the whole point of the class existing. Preflight
    failure, a witness that does not honour its contract, and A CONTROL ROW THAT DOES NOT READ ITS
    FLOOR all land here.

    ⚠ WHY THE CONTROL BELONGS HERE AND NOT IN DRIFT. A zero-egress artifact measuring nonzero is not
    a fact about the artifact; it is the counter failing to read a floor, which makes EVERY OTHER
    ROW'S NUMBER SUSPECT. Shown as a sixth drift row it would produce a table in which one row
    quietly means "do not believe the other five", with nothing telling a reader which row that is."""


@dataclass(frozen=True)
class Instrument:
    """What did the measuring. Recorded so drift has more than one available hypothesis."""

    gate_commit: str
    image_digest: str
    runtime: str
    runtime_version: str
    seal_mode: str
    witness_identity: str

    def render(self) -> str:
        return (f"gate {self.gate_commit[:12]} · image {self.image_digest[:19]}… · "
                f"{self.runtime} {self.runtime_version} · seal {self.seal_mode} · "
                f"witness {self.witness_identity}")


@dataclass(frozen=True)
class CorpusIdentity:
    """WHICH pinned artifact this row was drawn from. A receipt that cannot name its corpus cannot be
    tied to anything after a supersession, and every historical receipt becomes unattributable."""

    release: str
    outer_digest: str
    member: str
    member_digest: str


@dataclass(frozen=True)
class Receipt:
    """One row's evidence. Sealed AT ROW TIME, while the run's objects still exist."""

    run_nonce: str
    row: str
    kind: Literal["subject", "control", "positive"]
    corpus: CorpusIdentity
    instrument: Instrument

    # TIER 2 — the measurement. A challenge, not a proof.
    measured: int
    boundary_events: list[str]

    # TIER 1 — checkable now.
    expectation: int
    verdict: Literal["ADMIT", "BLOCK"]
    base_digest: str = ""
    derived_digest: str = ""
    displayed_diff: str = ""

    notes: list[str] = field(default_factory=list)

    def recomputed_verdict(self) -> str:
        """The verdict as ARITHMETIC, not as a stored string. A sceptic runs this themselves."""
        return "ADMIT" if self.measured >= self.expectation else "BLOCK"

    def self_consistent(self) -> bool:
        """Does the stored verdict follow from the stored operands? If not, something composed the
        table by hand — which is the defect the no-hardcoded-verdicts rule exists to prevent."""
        return self.verdict == self.recomputed_verdict()

    def to_json(self) -> str:
        payload = asdict(self)
        payload["_tier1"] = ["corpus", "instrument", "expectation", "verdict", "base_digest",
                             "derived_digest", "displayed_diff", "run_nonce"]
        payload["_tier2"] = ["measured", "boundary_events"]
        payload["_trust_root"] = (
            f"Tier 1 is verified against pin {self.corpus.outer_digest[:16]}… as published in release "
            f"{self.corpus.release}. If that publication channel is compromised, the Tier-1 checks "
            "here are vacuous. Tier 2 (the measured count) is a CLAIM — replay to check it. Scoped to "
            "this instance; it is not a statement about artifacts in general."
        )
        return json.dumps(payload, indent=2, sort_keys=True)

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()


@dataclass(frozen=True)
class PinBinding:
    """The pin's authority, passed IN so it cannot be forgotten.

    ⚠ THIS TYPE EXISTS BECAUSE THE WIRING WAS ABSENT AND INVISIBLE. ``pin.py`` declared that the
    authority for expectations lives in the consumer; ``receipt.py`` never imported it, so every
    binding lived in code that had not been written. Both modules were fully green while the
    anti-circularity design was entirely unwired — and each module's tests passed locally, which is
    exactly why nothing saw it.

    It is a PARAMETER rather than an import on purpose. Importing ``pin`` here would couple the type
    to one corpus and, worse, would let a test construct a ``CompletedRun`` that agrees with the pin
    BY CONSTRUCTION. Passing it in means an adversarial binding can be handed to it, which is the
    only way the seam itself gets tested rather than each end of it.
    """

    corpus_digest: str
    subject_members: frozenset[str]
    control_member: str
    control_floor: int
    positive_member: str
    positive_expected: int
    policy_expectation: int


class CompletedRun:
    """The ONLY thing a verdict table can be rendered from.

    ⚠ CONSTRUCTIBLE ONLY FROM A COMPLETE SET. Five subject receipts AND the control, all sharing one
    run nonce. The renderer takes this type as its input rather than reading a directory, so a
    half-populated table is not something that has to be prevented — it is something that cannot be
    expressed. Parse, do not validate.

    The control is part of the construction contract deliberately: without it the guarantee has a
    hole in exactly the row that validates every other row's number.
    """

    def __init__(self, receipts: list[Receipt], binding: PinBinding) -> None:
        # ⚠ THE BINDING IS REQUIRED BY THE SIGNATURE. The previous constructor took an INT — a COUNT,
        # not an identity — so five receipts for the SAME member plus a control satisfied every
        # check. That is exactly the defect ``pin.py``'s own comment names about exact sets ("one
        # member too few or one too many, and a content check cannot see that"), committed one level
        # up at TABLE level by the code that was supposed to enforce it.
        kinds = {"subject", "control", "positive"}
        bad_kind = [r.row for r in receipts if r.kind not in kinds]
        if bad_kind:
            raise InstrumentInvalid(f"receipts {bad_kind} carry an unknown kind")

        nonces = {r.run_nonce for r in receipts}
        if len(nonces) != 1:
            raise InstrumentInvalid(
                f"receipts span {len(nonces)} runs: {sorted(nonces)}. Every row must come from THIS "
                "run — mixing them is how a stale row survives into a fresh-looking table")

        # EVERY receipt must name the pinned corpus. Carried-but-never-adjudicated was how a receipt
        # from a superseded release could render beside fresh ones.
        foreign = sorted({r.corpus.outer_digest for r in receipts
                          if r.corpus.outer_digest != binding.corpus_digest})
        if foreign:
            raise InstrumentInvalid(
                f"receipt(s) name a corpus this consumer does not pin: {foreign}; pinned is "
                f"{binding.corpus_digest}. A table may not mix corpora — the rows would be answers "
                "to different questions displayed as one")

        # EVERY expectation must come from the POLICY, not from whatever the runner happened to pass.
        # Three plausible sources existed (the policy, a per-row count, or the corpus's own record —
        # the circular case the pin exists to prevent) and they yield DIFFERENT verdicts, while
        # self_consistent() passes for all three.
        off_policy = [(r.row, r.expectation) for r in receipts
                      if r.kind == "subject" and r.expectation != binding.policy_expectation]
        if off_policy:
            raise InstrumentInvalid(
                f"subject rows carry an expectation that is not the pinned policy "
                f"{binding.policy_expectation}: {off_policy}. The verdict is f(measured, expectation) "
                "and an unpinned expectation makes the verdict unpinned with it")

        subjects = [r for r in receipts if r.kind == "subject"]
        members = [r.corpus.member for r in subjects]
        if len(members) != len(set(members)):
            dupes = sorted({m for m in members if members.count(m) > 1})
            raise InstrumentInvalid(
                f"member(s) {dupes} appear more than once. A count-based check accepted five copies "
                "of one row as a complete table")
        if set(members) != set(binding.subject_members):
            missing = sorted(set(binding.subject_members) - set(members))
            extra = sorted(set(members) - set(binding.subject_members))
            raise InstrumentInvalid(
                f"the subject set does not match the pin — missing {missing}, unexpected {extra}. "
                "EXACT SET, not a minimum")

        controls = [r for r in receipts if r.kind == "control"]
        positives = [r for r in receipts if r.kind == "positive"]
        if len(controls) != 1 or len(positives) != 1:
            raise InstrumentInvalid(
                f"a table needs EXACTLY ONE zero control and ONE positive control; got "
                f"{len(controls)} and {len(positives)}. Both, or the floor is one-sided")
        control, positive = controls[0], positives[0]

        if control.corpus.member != binding.control_member:
            raise InstrumentInvalid(
                f"the control names {control.corpus.member!r}, not the pinned "
                f"{binding.control_member!r} — any receipt could otherwise stand in for the control")
        if positive.corpus.member != binding.positive_member:
            raise InstrumentInvalid(
                f"the positive control names {positive.corpus.member!r}, not the pinned "
                f"{binding.positive_member!r}")

        # ⚠ THE FLOOR IS TWO-SIDED NOW, AND THAT IS THE WHOLE FIX. Checking only `measured != 0`
        # detected OVER-reporting alone: a counter capturing NOTHING reads 0 here, passes, and then
        # every subject reads 0 and surfaces as DRIFT — a displayed RESULT — while the instrument is
        # dead. Every test this project had ever run used a live counter, so none of them could see
        # it. The positive control is the other side: a known-nonzero that must read EXACTLY its
        # value.
        if control.measured != binding.control_floor:
            raise InstrumentInvalid(
                f"THE CONTROL DID NOT READ ITS FLOOR: a zero-egress artifact measured "
                f"{control.measured}, expected {binding.control_floor}. This is not a fact about any "
                "artifact — it is the counter failing, and it makes every other row's number suspect")
        if positive.measured != binding.positive_expected:
            raise InstrumentInvalid(
                f"THE POSITIVE CONTROL DID NOT READ ITS KNOWN VALUE: measured {positive.measured}, "
                f"expected exactly {binding.positive_expected}. A counter reading LOW — including one "
                "reading nothing at all — passes a zero-floor check and then reports every row as "
                "drift. This is the other side of the floor, and it is an INVALID INSTRUMENT, not a "
                "finding about any artifact")

        inconsistent = [r.row for r in receipts if not r.self_consistent()]
        if inconsistent:
            raise InstrumentInvalid(
                f"rows {inconsistent} carry a verdict that does not follow from their own operands — "
                "the table was not computed from the measurements it displays")

        self.receipts = receipts
        self.binding = binding
        self.control = control
        self.positive = positive
        self.subjects = subjects
        self.nonce = nonces.pop()

    def drifted(self, expected: dict[str, int]) -> list[tuple[str, int, int]]:
        """Rows whose fresh measurement disagrees with the frozen expectation.

        This is the RESULT, not a failure. A drift detector that halts on drift detects nothing, and
        a halt-only design trains the one repair that must never be made: editing the expectation to
        match a drifted measurement so the run goes green.

        ⚠ NO SOFT SKIP. The previous version did ``want = expected.get(...)`` and then
        ``if want is not None``, so a row whose member could not be keyed was SILENTLY PASSED OVER —
        yielding an empty drift list over ZERO PERFORMED COMPARISONS, which reads identically to
        "everything agrees". An empty result is not a value. The constructor now guarantees the
        subject set matches the pin exactly, so an unkeyable row is a LOGIC error and says so.
        """
        out: list[tuple[str, int, int]] = []
        for r in self.subjects:
            key = r.corpus.member.split("/")[1] if "/" in r.corpus.member else r.corpus.member
            if key not in expected:
                raise InstrumentInvalid(
                    f"row {r.row} names member {r.corpus.member!r}, which has no frozen expectation "
                    f"under key {key!r}. Refusing to report 'no drift' over a comparison that was "
                    "never performed")
            want = expected[key]
            if r.measured != want:
                out.append((r.row, want, r.measured))
        return out
