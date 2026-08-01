"""Receipts, the disagreement taxonomy, and the type a verdict table can be built from.

⚠ A RECEIPT IS NOT A LOG. The test for every field below is: NAME THE CHECK A SCEPTIC RUNS, AND THE
ROOT IT TRUSTS. If the answer is "trust the harness", the field does not belong here. That rules out
``verified: true``, a harness self-signature (which attests only that the harness held a key — a log
cosplaying as evidence, and worse than no field at all), and timings-as-evidence.

TWO TIERS, LABELLED IN THE RECEIPT ITSELF, because they are different KINDS of claim:

  TIER 1 — CHECKABLE NOW, against published roots. Digests against the release; the three-way binding
           of base + displayed diff -> derived for the mutated rows, which is a PURE FUNCTION and the
           only actual PROOF in the whole demo; the verdict recomputed as f(measured, expectation);
           the seal chain from the run header through every row.

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

⚠ THE SCHEMA IS FROZEN BY THE FIRST SEAL. Receipts are sealed AT ROW TIME, so a field absent at the
first seal cannot be added later without invalidating every receipt already issued. Everything a
receipt must be able to claim is therefore present BEFORE any runner writes one: expectation
provenance, the seal/counter probes, and the chain link. This ordering is the reason the contract was
settled before ``run.py`` was written rather than during it — and it is why the ONE field that is
still missing (``witness_codes``, see ``Receipt``) is recorded as a KNOWN GAP rather than faked: a
field added after the first live seal invalidates every receipt already issued, and a field faked
before it is worse than absent.

⚠ LINKAGE IS NOT ATTESTATION, and the two must never be conflated. The chain below makes tampering
WITHIN a run detectable — a removed or reordered row breaks it. It says NOTHING about who sealed the
run, when, or on what machine. ``seal_mode`` remains SELF-REPORTED until an attestation exists.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Literal, Mapping, NewType, Sequence

# ⚠ CORRESPONDENCE IS DATA, NEVER COMPUTATION. These two namespaces relate to each other through a
# literal table in the pin and nowhere else. Making them distinct types means a member path used
# where a key is expected is a TYPE ERROR rather than a review finding — which is the mechanical
# form of the rule, and the reason the previous defect (``member.split("/")[1]``) was invisible.
MemberPath = NewType("MemberPath", str)
ExpectationKey = NewType("ExpectationKey", str)

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
    re-measurement, and a message that points at a side will be resolved by whoever edited last.

    ⚠ THIS CLASS WAS ORNAMENTAL FOR ONE INCREMENT — defined, documented, and raised NOWHERE. It is
    raised now by ``verify_measured_against_pin``, which is the case it was always for: the pin's
    frozen expectations against the corpus's own ``MEASURED.json``."""


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
                f"{self.runtime_version} · seal {self.seal_mode} (SELF-REPORTED) · "
                f"witness {self.witness_identity}")


@dataclass(frozen=True)
class SubjectPin:
    """ONE pinned subject: its member path, the key it answers to, and its FROZEN expectation.

    ⚠ THE EXPECTATION LIVES HERE, INSIDE THE BINDING. It used to arrive as a bare ``expected`` dict
    parameter to ``drifted()`` — a SECOND, unauthenticated input to the one computation the tool
    exists to perform, while the brief claimed the table's only input was a ``CompletedRun``. Nothing
    checked it, so a tampered dict could fabricate or erase drift undetectably, and keys it omitted
    were simply never compared."""

    member: MemberPath
    key: ExpectationKey
    expected_egress: int


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

    ⚠ AND ITS OWN WELL-FORMEDNESS IS ENFORCED, not assumed. Every downstream check reads as a control
    over malformed pins; a control whose PRECONDITION nothing enforces is the claim-not-a-control
    shape. A pin naming one fixture as both the zero and the positive control demands that one
    artifact read both 0 and 1 — unsatisfiable, and previously constructed without complaint.
    """

    corpus_digest: str
    subject_rows: frozenset[SubjectPin]

    # ⚠ THE EXACT CARDINALITY, NOT A MINIMUM. ``>= 1`` accepts a one-row table that renders and means
    # nothing — the empty-set defect at reduced volume. The number is pinned so that a table missing
    # four of five rows is refused as loudly as one missing all five.
    expected_cardinality: int

    control_member: MemberPath
    control_floor: int
    positive_member: MemberPath
    positive_expected: int
    policy_expectation: int

    # Provenance, recorded onto every receipt so a reader is never left inferring where a frozen
    # number came from.
    expectation_provenance: str

    def __post_init__(self) -> None:
        if not self.subject_rows:
            raise PinInconsistent(
                "the binding pins ZERO subject rows. Every set check then passes trivially — "
                "set() == set() — and the drift report returns [] over zero comparisons, which reads "
                "identically to 'everything agrees'. An empty result is not a value")
        if self.expected_cardinality != len(self.subject_rows):
            raise PinInconsistent(
                f"the binding pins {len(self.subject_rows)} subject rows but declares a cardinality "
                f"of {self.expected_cardinality}. Two frozen claims in one object disagree")

        members = [r.member for r in self.subject_rows]
        keys = [r.key for r in self.subject_rows]
        if len(set(members)) != len(members) or len(set(keys)) != len(keys):
            raise PinInconsistent(
                "the binding is not a bijection between members and keys — a member is pinned twice, "
                "or two members answer to one frozen expectation")

        if self.control_member == self.positive_member:
            raise PinInconsistent(
                f"the zero control and the positive control are the SAME member "
                f"{self.control_member!r}, which demands that one artifact read both "
                f"{self.control_floor} and {self.positive_expected}. Unsatisfiable")
        if self.control_member in set(members) or self.positive_member in set(members):
            raise PinInconsistent(
                "a control member is also pinned as a subject — the row that validates the other "
                "rows' numbers cannot also be one of the rows being validated")
        if self.positive_expected <= 0:
            raise PinInconsistent(
                f"the positive control expects {self.positive_expected}, which is not positive. A "
                "second zero control brackets the same direction twice and certifies nothing about "
                "under-reporting — the exact half-floor this control exists to close")

    def digest(self) -> str:
        """A stable identity for the authority itself, committed to by the run header."""
        payload = {
            "corpus_digest": self.corpus_digest,
            "subject_rows": sorted([r.member, r.key, str(r.expected_egress)]
                                   for r in self.subject_rows),
            "expected_cardinality": self.expected_cardinality,
            "control": [self.control_member, self.control_floor],
            "positive": [self.positive_member, self.positive_expected],
            "policy_expectation": self.policy_expectation,
            "expectation_provenance": self.expectation_provenance,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def expectations(self) -> Mapping[ExpectationKey, int]:
        return {r.key: r.expected_egress for r in self.subject_rows}


@dataclass(frozen=True)
class RunHeader:
    """THE FIRST SEALED OBJECT, written before any row runs.

    ⚠ WITHOUT IT, ROW 1 HAS NOTHING TO CHAIN TO. A chain that starts at row 1 leaves the first row
    unanchored, and — more importantly — leaves the whole SET unanchored: a uniformly stale run whose
    receipts all share one old nonce is internally consistent and passes every equality check. The
    header closes that structurally rather than by process hygiene, because it commits to the nonce,
    the instrument, and the binding digest BEFORE any measurement exists to be tempted by.
    """

    run_nonce: str
    instrument: Instrument
    binding_digest: str

    def digest(self) -> str:
        payload = {"run_nonce": self.run_nonce, "instrument": asdict(self.instrument),
                   "binding_digest": self.binding_digest, "_kind": "run-header"}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True)
class CorpusIdentity:
    """WHICH pinned artifact this row was drawn from. A receipt that cannot name its corpus cannot be
    tied to anything after a supersession, and every historical receipt becomes unattributable."""

    release: str
    outer_digest: str
    member: MemberPath
    member_digest: str

    # ⚠ THE ROW DECLARES WHICH FROZEN EXPECTATION IT ANSWERS TO. It is not inferred from ``member``.
    # The previous code derived it at the point of comparison with ``member.split("/")[1]`` — identity
    # by string surgery, shape-dependent and silent about it.
    #
    # ``None`` for control rows, NOT "": an empty string is indistinguishable from a caller who forgot
    # the field, and the default deferred that failure to table time — after ``run.py`` had already
    # SEALED the row. Absence is now explicit and fails fast.
    expectation_key: ExpectationKey | None = None


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
    # ⚠ OBSERVED EVENTS ONLY — never labels synthesised from the total. A runner that filled this with
    # ``f"boundary-attempt-{i+1}" for i in range(measured)`` would be putting COMPUTATION where a
    # sceptic reads DATA: N event-looking identifiers that corroborate nothing, because they were
    # derived from the very number they appear to support. Correspondence is data, never computation.
    #
    # EMPTY MEANS NOT RECORDED, and that is a statement about the observer, not about the artifact:
    # the boundary observer writes a count and no per-event record. While this is empty, ``measured``
    # is UNCORROBORATED — a total with nothing to re-count against. Human-facing labels belong in
    # ``notes``, which no one mistakes for evidence.
    #
    # ⚠ TUPLES, NOT LISTS. ``frozen=True`` blocks REBINDING, not ``.append()`` — a sealed receipt's
    # events could be extended after issuance and its digest recomputed to match, so the seal
    # certified whatever the object happened to hold when someone last asked.
    boundary_events: tuple[str, ...]

    # TIER 1 — checkable now.
    expectation: int

    # ⚠ CONTROLS DO NOT GET A SUBJECT VERDICT. The subject predicate is
    # ``measured >= ADMIT_AT_OR_ABOVE``; applied to a zero control it seals a HEALTHY control — one
    # correctly reading its floor — as ``BLOCK``, and applied to the positive control it judges it
    # against the demo policy rather than its own known value. Both are wrong-predicate artifacts in
    # append-only storage. Controls carry ``CONTROL``: they are not admitted or blocked, they are the
    # rows that decide whether the other rows' numbers mean anything.
    verdict: Literal["ADMIT", "BLOCK", "CONTROL"]

    # THE CHAIN LINK. Row N commits to row N-1; row 1 commits to the run header.
    prior_digest: str

    # Provenance of the frozen number this row was judged against, carried rather than inferred.
    expectation_provenance: str

    # ⚠ TWO FIELDS, EACH NAMED FOR WHAT IT ACTUALLY MEASURES — and NEITHER of them is the witness.
    # A single ``witness_verified: bool`` was drafted here and REJECTED before any seal, because it
    # collapsed three different things and its root was the harness. A sceptic cannot recheck a
    # boolean this process wrote about itself.
    #
    #   counter_readable_at_end — the count came back from the proxy's own storage after the
    #                            container exited. A genuine measurement THAT THE COUNTER SURVIVED.
    #
    # ⚠ THE GAP THIS LEAVES, STATED RATHER THAN PAPERED OVER. This does not see the failure that
    # actually matters. A row's frozen count depends on the witness returning a PERSISTENT 503; if
    # the witness served a success mid-row, the escape probe still passes (posture unchanged), the
    # count is still readable (not None), and the row measures 1 instead of 3 — with fresh receipts,
    # consistent digests, a valid chain, and an interpretation that is simply false. A bracket cannot
    # see the middle.
    #
    # The field that WOULD close it is the per-event response codes, from which "3 attempts / 3×503"
    # is recheckable by a sceptic against the corpus's own recorded ``witness_condition``. It is NOT
    # present because the boundary observer does not record codes — it writes only a count — and
    # deriving them from the configured mode would be COMPUTATION PRESENTED AS MEASUREMENT, which is
    # the same defect wearing a better name. See docs/ESCAPE-LEDGER.md.
    # ⚠ THERE IS NO ``seal_verified_at_start`` FIELD, AND ITS ABSENCE IS THE POINT. One was drafted
    # and the runner could only ever have set it to the literal ``True`` — ``prepare()`` RAISES on a
    # leak, so reaching the assignment entails the probe passed, and no production path could make it
    # False. An unfalsifiable field carries zero bits while reading as an affirmative claim, and its
    # root would be control flow rather than a measurement. The seal posture IS established (a leak
    # aborts the row before it runs); it is simply not something this receipt can evidence, so it is
    # not claimed here.
    counter_readable_at_end: bool

    base_digest: str = ""
    derived_digest: str = ""
    displayed_diff: str = ""
    notes: tuple[str, ...] = ()

    def recomputed_verdict(self) -> str:
        """The verdict as ARITHMETIC, not as a stored string. A sceptic runs this themselves.

        KIND-AWARE, because the subject predicate is not meaningful for a control. A control's
        correctness is decided against the pin's floor/known-value in ``CompletedRun``, not by the
        demo's ADMIT threshold."""
        if self.kind != "subject":
            return "CONTROL"
        return "ADMIT" if self.measured >= self.expectation else "BLOCK"

    def self_consistent(self) -> bool:
        """Does the stored verdict follow from the stored operands? If not, something composed the
        table by hand — which is the defect the no-hardcoded-verdicts rule exists to prevent."""
        return self.verdict == self.recomputed_verdict()

    def events_match_count(self) -> bool:
        """If events are disclosed, the total must be arithmetic over them.

        ⚠ AND IF THEY ARE NOT DISCLOSED, THIS CANNOT VOUCH FOR ANYTHING. Empty means the observer
        recorded no per-event data, so there is nothing to re-count and ``measured`` stands
        uncorroborated. Returning True there is NOT a pass — it is this check declining to speak,
        which is why ``uncorroborated()`` exists and why the trust root says so in the receipt
        itself. A check that reported "consistent" over zero events would be the empty-result-as-a-
        value defect wearing a Tier-1 label."""
        if not self.boundary_events:
            return True
        return len(self.boundary_events) == self.measured

    def uncorroborated(self) -> bool:
        """True when ``measured`` has no disclosed events to re-count. Read this before believing a
        count: it is the difference between a challenge a sceptic can run and a number to trust."""
        return not self.boundary_events

    def to_json(self) -> str:
        payload = asdict(self)
        payload["_tier1"] = ["corpus", "instrument", "expectation", "verdict", "base_digest",
                             "derived_digest", "displayed_diff", "run_nonce", "prior_digest",
                             "expectation_provenance", "counter_readable_at_end"]
        payload["_tier2"] = ["measured", "boundary_events"]
        payload["_trust_root"] = (
            f"Tier 1 is verified against pin {self.corpus.outer_digest[:16]}… as published in release "
            f"{self.corpus.release}. If that publication channel is compromised, the Tier-1 checks "
            + ("Tier 2 carries NO disclosed events, so `measured` is UNCORROBORATED — there is "
               "nothing here to re-count it against. " if not self.boundary_events else "")
            + "Tier 2 (the measured count) is a CLAIM — replay to check it. The seal "
            "chain makes tampering WITHIN this run detectable; it is NOT an attestation and says "
            "nothing about who sealed it or when. Scoped to this instance; it is not a statement "
            "about artifacts in general."
        )
        return json.dumps(payload, indent=2, sort_keys=True)

    def digest(self) -> str:
        """Deterministic over frozen bytes — every field is immutable, so this cannot drift."""
        return hashlib.sha256(self.to_json().encode()).hexdigest()


def verify_measured_against_pin(measured: Mapping[str, int], binding: PinBinding) -> None:
    """Cross-check the corpus's OWN record against the consumer's frozen expectations. PRE-RUN.

    ⚠ THIS IS THE CASE ``PinInconsistent`` WAS ALWAYS FOR, and until now it had no caller anywhere —
    the class was defined, documented, and ornamental. ``pin.py``'s docstring already CLAIMED this
    cross-check existed ("the corpus's own ``MEASURED.json`` is cross-checked against it"); it did
    not. A claim in prose that no code implements is the defect this repo keeps finding.

    Both sides are FROZEN, written in advance, and neither is measurement. So a disagreement cannot
    be adjudicated by running anything, and this function deliberately does not try: it names both
    provenances and refuses. It is TWO-DIRECTIONAL — a key the corpus records but the pin does not
    demand is as much a contradiction as the reverse, and the one-directional version let the corpus
    carry frozen claims that were never compared to anything.
    """
    want = binding.expectations()
    ours = {str(k) for k in want}
    theirs = set(measured)

    only_pin = sorted(ours - theirs)
    only_corpus = sorted(theirs - ours)
    if only_pin or only_corpus:
        raise PinInconsistent(
            f"the consumer's pin and the corpus's own record name different keys — "
            f"pinned-but-unrecorded {only_pin}, recorded-but-unpinned {only_corpus}. Both are frozen "
            f"claims written in advance ({binding.expectation_provenance} vs the corpus record), so "
            "no measurement can settle which is right. Re-measure and correct the wrong one")

    disagree = sorted((k, want[ExpectationKey(k)], measured[k]) for k in ours
                      if measured[k] != want[ExpectationKey(k)])
    if disagree:
        raise PinInconsistent(
            f"the consumer's pin and the corpus's own record disagree on frozen counts: "
            f"{disagree} (key, pinned, recorded). Provenances are {binding.expectation_provenance} "
            "and the corpus record. This is not drift — neither side is a fresh measurement")


class CompletedRun:
    """The ONLY thing a verdict table can be rendered from.

    ⚠ CONSTRUCTIBLE ONLY FROM A COMPLETE SET, in order, chained to a run header. The renderer takes
    this type as its input rather than reading a directory, so a half-populated table is not
    something that has to be prevented — it is something that cannot be expressed. Parse, do not
    validate.

    The controls are part of the construction contract deliberately: without them the guarantee has a
    hole in exactly the rows that validate every other row's number.
    """

    def __init__(self, header: RunHeader, receipts: Sequence[Receipt],
                 binding: PinBinding) -> None:
        # ⚠ IMMUTABLE FROM THE FIRST LINE. The previous constructor did ``self.receipts = receipts``,
        # aliasing the CALLER'S list — so a post-construction ``append`` injected unvalidated rows
        # into the very collection the table renders. The parsed object must be immutable, or the
        # parse is not a gate.
        rows = tuple(receipts)

        if header.binding_digest != binding.digest():
            raise InstrumentInvalid(
                f"the run header commits to binding {header.binding_digest[:16]}… but the binding "
                f"supplied is {binding.digest()[:16]}…. The authority changed after the run started")

        kinds = {"subject", "control", "positive"}
        bad_kind = [r.row for r in rows if r.kind not in kinds]
        if bad_kind:
            raise InstrumentInvalid(f"receipts {bad_kind} carry an unknown kind")

        nonces = {r.run_nonce for r in rows}
        if nonces != {header.run_nonce}:
            raise InstrumentInvalid(
                f"receipts do not all belong to the header's run: header {header.run_nonce!r}, "
                f"receipts {sorted(nonces)}. Mixing them is how a stale row survives into a "
                "fresh-looking table")

        # THE CHAIN. Row 1 commits to the header, row N to row N-1. A removed or reordered row breaks
        # it. This is LINKAGE, not attestation.
        expected_prior = header.digest()
        for r in rows:
            if r.prior_digest != expected_prior:
                raise InstrumentInvalid(
                    f"the seal chain is broken at row {r.row!r}: it commits to prior "
                    f"{r.prior_digest[:16]}… but the preceding sealed object is "
                    f"{expected_prior[:16]}…. A row was removed, reordered, or issued out of band")
            expected_prior = r.digest()

        unreadable = [r.row for r in rows if not r.counter_readable_at_end]
        if unreadable:
            raise InstrumentInvalid(
                f"rows {unreadable} finished with an UNREADABLE counter — the count could not be "
                "retrieved from the proxy's own storage after the container exited, so the number "
                "attributed to those rows is not a measurement. Invalid instrument, never drift")

        foreign = sorted({r.corpus.outer_digest for r in rows
                          if r.corpus.outer_digest != binding.corpus_digest})
        if foreign:
            raise InstrumentInvalid(
                f"receipt(s) name a corpus this consumer does not pin: {foreign}; pinned is "
                f"{binding.corpus_digest}. A table may not mix corpora — the rows would be answers "
                "to different questions displayed as one")

        off_policy = [(r.row, r.expectation) for r in rows
                      if r.kind == "subject" and r.expectation != binding.policy_expectation]
        if off_policy:
            raise InstrumentInvalid(
                f"subject rows carry an expectation that is not the pinned policy "
                f"{binding.policy_expectation}: {off_policy}. The verdict is f(measured, expectation) "
                "and an unpinned expectation makes the verdict unpinned with it")

        subjects = [r for r in rows if r.kind == "subject"]

        # A CONTROL ROW MUST NOT CARRY AN EXPECTATION KEY, and a subject MUST carry a NON-EMPTY one.
        # Truthiness alone admitted a whitespace key, which then reached a lookup.
        miskeyed = [r.row for r in rows
                    if (r.kind == "subject") != (r.corpus.expectation_key is not None
                                                 and r.corpus.expectation_key.strip() != "")]
        if miskeyed:
            raise InstrumentInvalid(
                f"rows {miskeyed} carry an expectation key inconsistent with their kind: subjects "
                "must name the frozen expectation they answer to, controls must name none")

        if len(subjects) != binding.expected_cardinality:
            raise InstrumentInvalid(
                f"the table has {len(subjects)} subject rows; the pin declares exactly "
                f"{binding.expected_cardinality}. Not a minimum — a table missing four of five rows "
                "renders and means nothing, which is the empty-set defect at reduced volume")

        members = [r.corpus.member for r in subjects]
        if len(members) != len(set(members)):
            dupes = sorted({m for m in members if members.count(m) > 1})
            raise InstrumentInvalid(
                f"member(s) {dupes} appear more than once. A count-based check accepted five copies "
                "of one row as a complete table")

        # EXACT SET OVER PAIRS. A member-only set cannot see a row that names a pinned member under
        # another pinned row's key; that row would then be compared against the wrong frozen number
        # and the disagreement would surface as DRIFT — a result — rather than as a broken table.
        pairs = {(r.corpus.member, r.corpus.expectation_key) for r in subjects}
        pinned_pairs = {(r.member, r.key) for r in binding.subject_rows}
        if pairs != pinned_pairs:
            raise InstrumentInvalid(
                f"the subject (member, key) set does not match the pin — missing "
                f"{sorted(pinned_pairs - pairs)}, unexpected {sorted(pairs - pinned_pairs)}. "
                "EXACT SET of PAIRS, not a minimum and not members alone")

        controls = [r for r in rows if r.kind == "control"]
        positives = [r for r in rows if r.kind == "positive"]
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

        # ⚠ THE FLOOR IS TWO-SIDED, AND THAT IS THE WHOLE POINT. Checking only `measured != 0`
        # detected OVER-reporting alone: a counter capturing NOTHING reads 0 here, passes, and then
        # every subject reads 0 and surfaces as DRIFT — a displayed RESULT — while the instrument is
        # dead. Every test this project had ever run used a live counter, so none could see it.
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

        inconsistent = [r.row for r in rows if not r.self_consistent()]
        if inconsistent:
            raise InstrumentInvalid(
                f"rows {inconsistent} carry a verdict that does not follow from their own operands — "
                "the table was not computed from the measurements it displays")

        miscounted = [r.row for r in rows if not r.events_match_count()]
        if miscounted:
            raise InstrumentInvalid(
                f"rows {miscounted} report a total that is not the length of the events they "
                "disclose — the events are decorative and the number cannot be re-counted")

        self.header = header
        self.receipts = rows
        self.binding = binding
        self.control = control
        self.positive = positive
        self.subjects = tuple(subjects)
        self.nonce = header.run_nonce

    def drifted(self) -> list[tuple[str, int, int]]:
        """Rows whose fresh measurement disagrees with the frozen expectation.

        This is the RESULT, not a failure. A drift detector that halts on drift detects nothing, and
        a halt-only design trains the one repair that must never be made: editing the expectation to
        match a drifted measurement so the run goes green.

        ⚠ NO PARAMETER. The expectations were a bare dict argument — a second, unauthenticated input
        to the one computation this tool exists to perform, while the design claimed a
        ``CompletedRun`` was the table's only input. A tampered dict could fabricate or erase drift
        undetectably, and omitted keys were silently never compared. The authority now arrives inside
        the binding, committed to by the run header, so the claim is true rather than aspirational.

        ⚠ NO KEY DERIVATION and NO SOFT SKIP. The key is carried on the row and checked against the
        pin as a PAIR at construction, so nothing here transforms a string, and the exact-cardinality
        and exact-pair checks make an unkeyed or uncompared row unconstructible rather than skipped.
        """
        expected = self.binding.expectations()
        out: list[tuple[str, int, int]] = []
        for r in self.subjects:
            key = r.corpus.expectation_key
            if key is None:                                  # unreachable via the gate; not assumed
                raise InstrumentInvalid(
                    f"row {r.row} reached the drift report with no expectation key. Refusing to "
                    "report 'no drift' over a comparison that was never performed")
            want = expected[key]
            if r.measured != want:
                out.append((r.row, want, r.measured))
        if len(out) > len(self.subjects):                    # arithmetic guard, never expected
            raise InstrumentInvalid("more drift rows than subjects — the report is not a projection")
        return out
