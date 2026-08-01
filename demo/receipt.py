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


@dataclass
class Receipt:
    """One row's evidence. Sealed AT ROW TIME, while the run's objects still exist."""

    run_nonce: str
    row: str
    kind: Literal["subject", "control"]
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


class CompletedRun:
    """The ONLY thing a verdict table can be rendered from.

    ⚠ CONSTRUCTIBLE ONLY FROM A COMPLETE SET. Five subject receipts AND the control, all sharing one
    run nonce. The renderer takes this type as its input rather than reading a directory, so a
    half-populated table is not something that has to be prevented — it is something that cannot be
    expressed. Parse, do not validate.

    The control is part of the construction contract deliberately: without it the guarantee has a
    hole in exactly the row that validates every other row's number.
    """

    def __init__(self, receipts: list[Receipt], expected_rows: int) -> None:
        if len(receipts) != expected_rows + 1:
            raise InstrumentInvalid(
                f"a verdict table needs {expected_rows} subject receipts AND the control receipt; "
                f"got {len(receipts)}. A partial table is not renderable — see the RUN REPORT, which "
                "is always emitted and shows measurements as measurements rather than as verdicts")
        nonces = {r.run_nonce for r in receipts}
        if len(nonces) != 1:
            raise InstrumentInvalid(
                f"receipts span {len(nonces)} runs: {sorted(nonces)}. Every row must come from THIS "
                "run — mixing them is how a stale row survives into a fresh-looking table")
        controls = [r for r in receipts if r.kind == "control"]
        if len(controls) != 1:
            raise InstrumentInvalid(
                f"expected exactly ONE control receipt, got {len(controls)}. The control is what "
                "demonstrates the counter can read its floor; without it the other rows' numbers rest "
                "on nothing")
        control = controls[0]
        if control.measured != 0:
            # NOT drift. See InstrumentInvalid.
            raise InstrumentInvalid(
                f"THE CONTROL DID NOT READ ITS FLOOR: a zero-egress artifact measured "
                f"{control.measured}. This is not a fact about any artifact — it is the counter "
                "failing, and it makes every other row's number suspect. Refusing to render a table "
                "in which one row would quietly mean 'do not believe the other five'")
        inconsistent = [r.row for r in receipts if not r.self_consistent()]
        if inconsistent:
            raise InstrumentInvalid(
                f"rows {inconsistent} carry a verdict that does not follow from their own operands — "
                "the table was not computed from the measurements it displays")
        self.receipts = receipts
        self.control = control
        self.subjects = [r for r in receipts if r.kind == "subject"]
        self.nonce = nonces.pop()

    def drifted(self, expected: dict[str, int]) -> list[tuple[str, int, int]]:
        """Rows whose fresh measurement disagrees with the frozen expectation.

        This is the RESULT, not a failure. A drift detector that halts on drift detects nothing, and
        a halt-only design trains the one repair that must never be made: editing the expectation to
        match a drifted measurement so the run goes green.
        """
        out = []
        for r in self.subjects:
            want = expected.get(r.corpus.member.split("/")[1] if "/" in r.corpus.member
                                else r.corpus.member)
            if want is not None and r.measured != want:
                out.append((r.row, want, r.measured))
        return out
