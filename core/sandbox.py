"""Increment 1.1 — the Sandbox Protocol (the interface; no backend yet).

The abstract contract every isolation backend implements. Interface only — no
execution — and, by design, no grader: a Sandbox runs code and reports *facts*;
judgement is out-of-band (NFR4).

Load-bearing invariants this contract encodes (Part 3 §2.2/§2.3, board-ratified):

  * NFR4 — no grader here, and no channel for one. A Sandbox reports execution
    facts (outcome, exit code, and — increment 1.4 — boundary telemetry) and
    nothing else. ``ExecutionResult`` deliberately has NO open ``metadata: dict``:
    an untyped bag is exactly how grader output / agent self-reports / in-process
    state would smuggle back into the "pure facts" object and erode NFR4 over
    increments. Every field is a typed, boundary-observed fact.

  * isolation is first-class, and its provenance travels with the facts.
    ``Sandbox.isolation_level`` is declared, and it is echoed onto every
    ``ExecutionResult`` alongside the artifact hash — so the Promotion Gate can
    enforce "a WEAK pass does not satisfy a HERMETIC required check."

  * SHA-bind closes TOCTOU. ``prepare()`` takes an ``ArtifactSpec`` (path bound to
    a content hash), never a bare path; the hash rides the handle and the result,
    so a verdict binds to the exact bytes that ran.

  * telemetry is a final-state read, not a stream. Boundary counters
    (conntrack/eBPF/veth) are read post-run. Any check needing in-flight ordering
    ("X egress before Y") forces an async revision + a known signature break —
    explicitly out of scope; sync ``run()`` is correct for the retry slice.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, runtime_checkable

if TYPE_CHECKING:  # a RUNTIME import would cycle: core.assertion imports THIS module for
    from core.assertion import Verdict  # Command/ExecutionResult/Fixtures. Forward ref only.


class TeardownError(Exception):
    """Base for every way teardown can fail to end in a PROVEN-clean state.

    It exists so a caller can say "any teardown problem" coherently, while the two subclasses below stay
    DISCRIMINABLE BY DEFAULT. They are not the same event and must not share a name: one is an answer
    about the SUBJECT (a resource was observed to persist), the other is a report about the INSTRUMENT
    (nothing could be observed at all). Collapsing them is the standing law's exact prohibition, and it
    would guarantee alarm fatigue that devalues the real leak alarm when it finally fires."""


class SandboxLeakError(TeardownError):
    """A resource was OBSERVED TO PERSIST after teardown — a PROVEN leak, on a channel proven live.

    Ephemerality is a security property, not hygiene: a surviving environment leaks state to the next run
    or lets the artifact outlive its verdict, so this must surface loudly and never be swallowed. This is
    the one sanctioned case of teardown raising.

    ⚠ RESERVED FOR ``EXISTS``. An ``UNKNOWN`` probe never justifies this type. The instrument can prove
    ABSENT and can prove EXISTS; it can NEVER prove "leaked" from UNKNOWN, and lexicalising an
    unestablished claim as a finding routes an operator to hunt a leak that may not exist while the true
    fault — a dead instrument — is demoted to a cause."""


class TeardownUnverifiableError(TeardownError):
    """Teardown could not be VERIFIED, because the probe could not answer — not because anything survived.

    Raised on ``UNKNOWN``, and on an uncalibrated sweep where no witness was ever provisioned. Still
    blocking and still fail-closed: "could not tell" must never read as "gone". But it is HONESTLY
    LABELLED, so the operator's first move is to check the instrument rather than to hunt a leak.

    Destruction is still ATTEMPTED before this is raised — an uncalibrated probe is a reason to distrust
    the report, not a reason to skip the work.

    ⚠ NOT the type for a sweep that never finished — see ``TeardownIncompleteError``. "The instrument
    could not answer" is itself a MEASURED outcome: the sweep ran, probed, and got nothing back. A sweep
    that crashed produced no reading at all, and reporting the two alike would credit a computation that
    never happened with a measurement it never took."""


class TeardownIncompleteError(TeardownError):
    """The teardown sweep NEVER REACHED A VERDICT — it raised somewhere the design did not anticipate.

    The third state, and it exists because the second was standing in for it. Previously an unexpected
    exception out of the sweep left the result lists at their empty initial values, and the ``finally``
    block read those empties as "nothing present, nothing unproven" — i.e. CLEAN — and tombstoned a
    permanent clean certificate for a computation that never completed. That is certification by silence,
    inside the increment whose subject is refusing to certify by silence.

    Distinguishable BY TYPE, not by message: a caller can branch on "did the sweep run?" separately from
    "what did it find?". Blocking like its siblings, and — unlike them — it means the session's evidence
    (witness, snapshot) is DELIBERATELY RETAINED, because the operator's next move is to re-probe."""


class TeardownCleanupError(TeardownError):
    """The verdict was reached and is CLEAN, but post-verdict cleanup failed — released witness, deleted
    snapshot. Raised so that a clean verdict's cleanup problem is HEARD.

    It exists because of a defect in its own increment's fix. Cleanup failures were recorded as notes on
    the verdict, and on a CLEAN verdict nothing ever formatted them: both the live and the replay
    surface return early for CLEAN, so the note reached no one. A field written by one side and read by
    nobody is precisely the shape this module exists to eliminate, and it had been reintroduced inside
    the remediation for it.

    NOT a re-classification of the verdict. The measurement happened and was clean; what failed came
    after, and conflating the two would corrupt replay semantics. So the verdict stays CLEAN in the
    tombstone — a repeat call replays clean and silent — and this surfaces once, on the call that
    actually did the cleanup. A surviving witness matters beyond tidiness: it is the precondition for
    the namesake-collision state on the next session that draws the same rid."""


class ReplayedSandboxLeak(SandboxLeakError):
    """A recorded ``SandboxLeakError``, RECONSTRUCTED at replay — a past measurement, not a fresh one.

    Teardown is idempotent, so a repeat call must not re-probe (by then the witness is released and every
    resource would come back unproven, turning a defensive ``finally: teardown()`` into an error
    generator). The verdict is therefore stored and re-raised — but stored AS DATA and reconstructed
    here, never as the original exception object held and thrown again. A held object accumulates
    tracebacks across replays, carries ``__notes__`` written by whoever caught it last, and is one shared
    mutable across every caller.

    The subtype is what distinguishes "the instrument is dark NOW" from "we stopped asking" — a caller
    seeing this knows nothing was measured at this moment. It remains a ``SandboxLeakError``, so every
    existing fail-closed handler catches it unchanged."""


class ReplayedTeardownUnverifiable(TeardownUnverifiableError):
    """A recorded ``TeardownUnverifiableError``, reconstructed at replay. See ``ReplayedSandboxLeak``."""


class ReplayedTeardownIncomplete(TeardownIncompleteError):
    """A recorded ``TeardownIncompleteError``, reconstructed at replay. See ``ReplayedSandboxLeak``.

    This is the ONLY way an incomplete verdict is ever raised: the first teardown does not raise it —
    the exception that crashed the sweep is the certain fact and stays primary — it only RECORDS it, so
    that the repeat cannot mistake the crash for a clean result."""


class Existence(Enum):
    """The tri-state result of a runtime existence probe (a destruction/orphan check). Crucially, a probe
    that CANNOT tell — the runtime timed out, errored, or returned non-zero — is ``UNKNOWN``, NEVER
    ``ABSENT``. Teardown may report success ONLY on a PROVEN ``ABSENT``: since ephemerality is
    security-critical and the threat model is a MALICIOUS artifact, treating "can't tell" as "gone" is a
    fail-OPEN (a container/network may survive while teardown claims it destroyed it). ``UNKNOWN`` after a
    teardown is exactly the ``SandboxLeakError`` "cannot CONFIRM destroyed" condition — raise, don't swallow."""

    EXISTS = "exists"
    ABSENT = "absent"
    UNKNOWN = "unknown"


class SandboxStartError(Exception):
    """The sandbox could not START the artifact process. NO RUN OCCURRED.

    THE REFUSAL CHANNEL, and the reason it exists rather than an ``ExecutionResult``. ``egress_attempts``
    is TOTAL (no default), so every constructed result must state something about the measurement. On a
    path where the container never started, NO VARIANT IS TRUE: an ``int`` is a measurement,
    ``NOT_OBSERVED`` is a capability claim the observing backend cannot make, and ``OBSERVER_UNREADABLE``
    asserts an observer ran and produced something uncertifiable. The measurement question WAS NEVER
    ASKED, and a total field would force an answer anyway — so the honest move is to construct no result.

    THE RULE THIS PRESERVES: an ``EgressAbsence`` variant describes the EPISTEMIC STATUS OF THE
    MEASUREMENT, never the CAUSE OF FAILURE. Without it the enum grows a variant per failure mode —
    RUN_NOT_COMPLETED today, IMAGE_PULL_FAILED next — until it is a error taxonomy wearing a
    measurement's name.

    Handled at the runner exactly as ``ImageResolutionError`` is: a fail-closed ERROR verdict with no
    identity coordinate, never a silent pass and never a result that lies about a count.

    NOTE the asymmetry with ``OCISandbox``, which swallows the same OSError into an error result. That is
    HONEST there: it genuinely has no observer, so its ``NOT_OBSERVED`` is true whether or not the
    container started. The same code shape is a lie only in the backend that HAS an observer."""


class EgressCapabilityContradiction(Exception):
    """A backend's DECLARED egress capability CONTRADICTS the value it reported. A HARNESS-INTEGRITY
    fault, never a fact about the artifact.

    NAMED FOR WHAT IS DETECTED, NOT FOR WHAT IS INFERRED. The check observes a contradiction between
    ``observes_egress`` and ``egress_attempts``; it INFERS that something bypassed the intended
    construction path. Naming it for the bypass would be wrong twice over: the bypass is what
    ``gate.backends.trusted_backend_guard`` detects (and it raises ``UntrustedBackendError``), and this
    contradiction CAN ARISE WITH NO BYPASS AT ALL — a regressed audited backend, a test double, or a
    Protocol-only backend on an unguarded path. This tree has spent a week on artifacts credited with a
    property ADJACENT to the one they have; the name is the cheapest place to stop doing it.

    ⚠ DELIBERATELY NOT A SUBCLASS OF ``SandboxStartError``. That type means NO RUN OCCURRED, and in this
    path a run DID occur — the check runs on a constructed result, after the session block exits. More
    practically: ``engine.runner.run_check`` catches ``SandboxStartError`` BY NAME and maps it to a
    per-trial ERROR verdict. Subclassing would invite any future refactor — moving the check inside the
    try, or a caller wrapping ``run_check`` — to SILENTLY RECLASSIFY A HARNESS-INTEGRITY EVENT AS AN
    ARTIFACT-TRIAL OUTCOME, charging the artifact for a defect of the harness.

    Core-side beside ``ImageResolutionError`` for that class's own stated reason: the engine catches it
    without importing a backend (engine ⊥ sandbox impl).

    IT DOES NOT LOOP, and that was traced rather than assumed: a DETERMINISTIC fault classified as
    transient INFRASTRUCTURE would spin forever if anything retried it. On the live gate path this becomes
    a TERMINAL blocking result ("this blocks the merge and a maintainer must investigate"), and the only
    retry in the executor re-attempts PUBLICATION to GitHub, never the check. On the recalibration path a
    dead worker's lease expires and the job is re-queued, but BOUNDED by ``max_attempts`` and then
    DEAD-LETTERED. It blocks once and surfaces; it never spins.

    IT CARRIES THE EVIDENCE, because propagation alone discards it. When this escapes ``run_check`` the
    loop's already-completed trials evaporate — no ``TrialReport`` is constructed on that path, which
    breaks the runner's own "the report is ALWAYS constructed" invariant. That is acceptable for a
    harness fault (a verdict is a statement about the artifact, and this is not one) ONLY IF THE
    EXCEPTION IS THE EVIDENCE VESSEL. So it carries the backend class, the declaration, the reported
    value, and the verdicts of the trials that did complete."""

    def __init__(self, *, backend: str, declared: bool, reported: object,
                 completed_trials: "tuple[Verdict, ...]" = ()) -> None:
        self.backend = backend
        self.declared = declared
        self.reported = reported
        self.completed_trials = completed_trials
        # THE VERDICTS GO IN THE MESSAGE, not only on the attribute. Verified against the live gate path:
        # this propagates to gate/executor.py, which converts any worker exception into
        # InfrastructureFailure(WORKER_FAULT, detail=repr(exc)) — fail-closed and blocking, which is the
        # right destination, but it STRINGIFIES the exception. Evidence held only on an attribute would be
        # discarded there, and "the exception is the evidence vessel" would be a claim the vessel does not
        # honour once it reaches its actual handler.
        trials = ", ".join(f"{v.status.name}/{v.reason.name}" for v in completed_trials) or "none"
        super().__init__(
            f"{backend} declares observes_egress={declared!r} but reported {reported!r} — a harness "
            f"integrity fault, not a fact about the artifact. Trials completed before the fault: {trials}")


class EgressCapabilityUndeclared(Exception):
    """A backend did not DECLARE ``observes_egress`` at all. NON-CONFORMANCE, not contradiction.

    A SEPARATE TYPE, and the separation is the point. Reading the capability with a default —
    ``getattr(sandbox, "observes_egress", False)`` — COALESCES UNDECLARED INTO DECLARED-FALSE, which
    MANUFACTURES A SPELLED ABSENCE AT THE CONSUMPTION SITE. Absence of output is not output of absence,
    and an undeclared backend holding a live observer would then pass a consistency check by inheriting
    a claim it never made.

    Distinct from ``EgressCapabilityContradiction`` because they are different faults with different
    fixes: a contradiction means the backend answered wrongly, non-conformance means it never answered.
    Sharing a type would be the same collapse this increment exists to undo, one level along.

    ⚠ NOT A VALUE. There is deliberately no ``UNDECLARED`` member of ``EgressAbsence``: an error is not
    a member of the domain it fails to inhabit.

    SCOPE, stated honestly: ``BaseSandbox`` supplies ``observes_egress = False``, so every inheritor
    always carries the attribute. This can only fire for a backend that satisfies the ``Sandbox``
    Protocol WITHOUT inheriting — which is exactly the population the inheritance-based guards cannot
    reach, and the reason the read is hard rather than defaulted."""


class ImageResolutionError(Exception):
    """A backend could not resolve its mutable image tag to an immutable local digest before run
    (image absent, or GC'd/pruned between resolve and run). 3.5-close #1.1: a FATAL identity error
    — an unresolvable image is an UNATTESTABLE run, mapped by the engine runner to ``Verdict(ERROR,
    IMAGE_UNRESOLVED)``, NEVER a silent pass. Core-side (like ``ArtifactHashMismatchError``) so the
    engine can catch it without importing a backend (engine ⊥ sandbox impl)."""


class IsolationLevel(Enum):
    """How strongly a backend isolates the artifact from the host and the check."""

    WEAK = "weak"          # subprocess — demo/local only; shares the host kernel
    HERMETIC = "hermetic"  # OCI container — the gate; network-off, ephemeral
    HARDENED = "hardened"  # microVM — deferred (Increment B)


@dataclass(frozen=True)
class ResourceBudget:
    """Limits a run must honour. Minimal by design — memory/CPU caps are added
    when a backend actually needs them. ``wall_clock_seconds`` IS the run timeout
    (no separate timeout parameter)."""

    wall_clock_seconds: float


@dataclass(frozen=True)
class Command:
    """The entrypoint executed inside the sandbox. argv only for now; working
    directory and environment are added when a backend needs them."""

    argv: tuple[str, ...]


@dataclass(frozen=True)
class ArtifactSpec:
    """The code under test, bound to its content hash.

    ``prepare()`` takes this — never a bare path — so a run is nailed to an exact
    tree. ``tree_hash`` (a content hash of the artifact tree, e.g. a git tree SHA
    or Merkle root) is echoed onto the handle and the ``ExecutionResult``, closing
    the TOCTOU race: the verdict binds to the exact bytes staged, so an artifact
    swapped between prepare and merge cannot inherit a stale PASS. (Ratified
    Part 3 redline.)
    """

    path: Path
    tree_hash: str


class BoundaryFaultMode(Enum):
    """The fault the boundary observer injects at the sandbox boundary (1.4/1.5)."""

    FAIL_ONCE = "fail_once"      # fail attempt 1, succeed after — the retry check
    FAIL_ALWAYS = "fail_always"  # fail every attempt — budget-exhaustion resilience


@dataclass(frozen=True)
class BoundaryFault:
    """A check's fault model, carried by Fixtures into prepare() so the sandbox can
    configure the boundary observer BEFORE the container starts — the artifact never
    sees or touches it. (Board-ratified over a run() param: the proxy is stood up in
    prepare, so the fault must be known then.)"""

    mode: BoundaryFaultMode


@dataclass(frozen=True)
class Fixtures:
    """Test scaffolding staged for a run — the boundary fault the check injects.

    This is the seam reserved (empty) at 1.1, now filled: ``boundary_fault`` tells
    the boundary observer how to behave (fail-once / fail-always). Applied AT THE
    BOUNDARY, never in-process (NFR4). Backends without an observer ignore it.
    """

    boundary_fault: BoundaryFault | None = None


@runtime_checkable
class SandboxHandle(Protocol):
    """Opaque handle a backend returns from prepare() and consumes in run()/
    teardown(). Its concrete shape is backend-private (a container id, a pid, a
    temp dir); the interface only carries it.

    Both members are read-only — a handle's identity and the artifact it staged
    are fixed at prepare() — so a frozen dataclass satisfies them:

      * ``id`` — correlates telemetry / logs.
      * ``artifact_hash`` — the ``ArtifactSpec.tree_hash`` bound at prepare();
        run() echoes it onto the result (the SHA-bind).
    """

    @property
    def id(self) -> str: ...

    @property
    def artifact_hash(self) -> str: ...


class EgressAbsence(Enum):
    """WHY THERE IS NO COUNT — a closed set, because ``None`` was carrying two meanings.

    ``egress_attempts: int | None`` conflated a CAPABILITY absence with an INSTRUMENT failure. Three of
    four backends have no boundary observer at all and left the field defaulted, so ``completed`` +
    ``None`` was their normal terminal state; ``ObservedOCISandbox`` produced the SAME spelling when its
    observer ran and the count could not be read. The field docstring documented only the first, which
    made it false about the second the day the second became possible.

    The original instruction was to REFUSE ``completed`` + ``None``. That was withdrawn as incoherent —
    it would have made the legitimate terminal state of three backends unrepresentable, i.e. the type
    lying in the other direction. The PURPOSE it served stands and is what this enum delivers: no
    consumer can inherit a false PASS by coalescing an absence into zero.

    THE MECHANISM, and it is the whole point. ``result.egress_attempts or 0`` yields literal ``0`` for
    ``None`` — a silent clean zero on a permanent record. It yields a TRUTHY ENUM MEMBER here, which
    either propagates into a comparison that raises or sits visibly in the record as a non-count.
    Inheriting a false PASS now requires someone to WRITE ``case OBSERVER_UNREADABLE: return 0`` — an
    explicit, reviewable act rather than an idiom.

    BARE VARIANTS, deliberately: no cause payload. Free text would invite consumers to pattern-match on
    diagnostics, which is exactly the untyped-stats-bag channel ``ExecutionResult`` exists to exclude.
    Two runs refused for different read-failure causes are the SAME VERDICT FACT; causes belong in logs.
    """

    NOT_OBSERVED = "not_observed"
    """No boundary observer exists. A STATIC CAPABILITY FACT ABOUT THE BACKEND CLASS — never a runtime
    outcome. It is derived from ``Sandbox.observes_egress`` rather than passed at construction, because a
    value passed in is a value a future backend can pass WRONGLY; deriving it is the difference between
    the type ASKING the question and the type ACCEPTING an answer.

    ⚠ An observing backend must NEVER report this. If its proxy fails to start or readiness is never
    established, that is a WHOLE-RUN REFUSAL, not a completed run with no observation — otherwise a third
    absence squats on the most innocent spelling, and an artifact that managed to kill its own observer
    early would inherit the variant that reads as "nothing to see here"."""

    OBSERVER_UNREADABLE = "observer_unreadable"
    """An observer ran and its product cannot be certified. The count is UNKNOWN, and unknown is not
    zero. Produced when the countfile cannot be read or parsed, and (once the drain probe lands) when the
    accept backlog cannot be shown to have drained — two producers, one verdict fact."""


@dataclass(frozen=True)
class ExecutionResult:
    """What a run produced — execution *facts*, never a verdict.

    ``outcome`` describes whether the process ran to completion, not whether it
    passed: "completed" means it exited on its own, not that the artifact is
    correct. ``isolation_level`` and ``artifact_hash`` are echoed so a downstream
    verdict can prove WHAT ran and under HOW MUCH isolation.

    There is deliberately NO ``artifact_verified`` flag: verification is enforced
    in ``prepare()`` (a hash mismatch raises ``ArtifactHashMismatchError`` and no
    handle is returned), so if a result exists at all, its ``artifact_hash`` was
    verified against the staged bytes. A perpetually-True flag would be vacuous.

    ``exit_code`` is the clean exit code of a run that exited on its own (None for
    timeout/error). ``raw_return_code`` is the raw OS return code as-is, for the
    grader's platform heuristics: on POSIX a negative value is ``-signum`` (a
    crash); on Windows a crash surfaces as a large positive code (no signals, so
    crash-vs-nonzero-exit is best-effort). None when nothing ran or the sandbox
    killed it.

    NFR4 — facts only. There is deliberately NO open ``metadata: dict``; adding
    one would reopen the grader-smuggling channel this object exists to close.
    Boundary telemetry (increment 1.4) attaches as typed, host-observed fields —
    a FINAL-STATE read of boundary counters, never in-process state the artifact
    could forge, and never an in-flight stream.
    """

    outcome: Literal["completed", "timeout", "error"]
    exit_code: int | None
    isolation_level: IsolationLevel
    artifact_hash: str
    egress_attempts: int | EgressAbsence
    """Boundary-observed count of outbound connection attempts (Increment 1.4),
    read from the sidecar proxy's own storage AFTER the run, from OUTSIDE the
    sandbox — never a value the artifact could write. A typed, named field, not an
    untyped stats bag (that would be a channel for artifact-influenced data to
    reach the verdict).

    ⚠ NO DEFAULT, deliberately. This field previously defaulted to ``None``, so a backend could OMIT it
    and thereby state an absence by accident — spelled absence at the construction site. With no default
    every backend must answer, and the type asks the question at the exact point where the answer is
    known. A fifth backend cannot forget.

    An ``int`` is a MEASUREMENT. An ``EgressAbsence`` says WHY there is no measurement, and the two
    reasons are not interchangeable: ``NOT_OBSERVED`` is a capability fact about the backend,
    ``OBSERVER_UNREADABLE`` is an instrument failure on a run that otherwise completed. Absence of
    output is not output of absence."""
    raw_return_code: int | None = None
    """Moved BELOW ``egress_attempts`` only because that field lost its default: a dataclass cannot place
    a non-default field after a defaulted one. Every construction site passes keywords, so no call
    changes. Recording the reason so it does not read as gratuitous churn."""
    image_digest: str | None = None
    """The IMMUTABLE image identity the trial ACTUALLY ran on (3.5-close #1.1). An OCI
    backend resolves the local image to its content digest (``<runtime> inspect .Id`` ->
    ``sha256:...``) BEFORE container start and executes THAT digest — never the mutable tag
    — so the attested execution binds the bytes that ran, closing the tag-TOCTOU. This is an
    ANTI-DRIFT / identity coordinate (which bytes), NOT runtime-behaviour assurance: a
    compromised host could verify the digest and then run something else (the unattested-TCB
    ceiling; see ARCHITECTURE.md). Measured host-side by the trusted sandbox object, never
    self-reported by the artifact. None for backends with no image (NoOp/Subprocess)."""

    @classmethod
    def from_run(
        cls,
        sandbox: "Sandbox",
        *,
        outcome: Literal["completed", "timeout", "error"],
        exit_code: int | None,
        artifact_hash: str,
        measured: "int | EgressAbsence | None" = None,
        raw_return_code: int | None = None,
        image_digest: str | None = None,
    ) -> "ExecutionResult":
        """Construct a result with everything derivable DERIVED from the backend object.

        A CONVENIENCE, AND THE SCOPE MATTERS. This does NOT stop a capability lie from being written:
        ``ExecutionResult`` is a public frozen dataclass and Python offers no way to close the raw
        constructor. (The overclaim lint flagged the stronger word here, which is the correct outcome —
        it is exactly the claim the design review refused, and the sentence was a denial of it rather
        than an assertion. The lint does not parse negation, and the safer habit is to not reach for the
        word at all when describing a control that does not deliver it.) The consistency control remains ``engine.runner._require_consistent_egress_capability``,
        which is the only site holding both the result and the backend object. What this buys is narrower
        and still worth having:

          * for a NON-OBSERVING backend the egress argument DOES NOT EXIST — the absence is derived, so
            there is no parameter through which to state it wrongly;
          * for an OBSERVING backend the parameter is constrained to a MEASUREMENT or
            ``OBSERVER_UNREADABLE``. ``NOT_OBSERVED`` is not an accepted answer, because a backend that
            HAS an observer cannot claim it has none.

        ⚠ IT DOES NOTHING FOR DECLARATION TRUTH. It derives FROM ``observes_egress``, so it trusts the
        declaration by construction. A backend declaring ``False`` while holding a live observer produces
        a perfectly consistent result here. That residual is answered by the admission brief in
        ``gate/backends.py``, not by any constructor shape.

        And it does not verify the COUNT. A measurement's integrity rests on where it comes from — the
        sidecar's own storage, read from outside the sandbox after the run — never on the shape of the
        call that packages it. Asking a constructor to validate a count would be crediting an API with a
        property it cannot have.
        """
        observes = sandbox.observes_egress
        if not observes:
            if measured is not None:
                raise EgressCapabilityContradiction(
                    backend=type(sandbox).__name__, declared=observes, reported=measured)
            egress: int | EgressAbsence = EgressAbsence.NOT_OBSERVED
        else:
            if measured is None or measured is EgressAbsence.NOT_OBSERVED:
                raise EgressCapabilityContradiction(
                    backend=type(sandbox).__name__, declared=observes, reported=measured)
            egress = measured
        return cls(
            outcome=outcome, exit_code=exit_code, isolation_level=sandbox.isolation_level,
            artifact_hash=artifact_hash, egress_attempts=egress,
            raw_return_code=raw_return_code, image_digest=image_digest,
        )

@runtime_checkable
class Sandbox(Protocol):
    """The contract every isolation backend implements.

    The object grades nothing (NFR4): it runs code and reports facts.
    ``isolation_level`` is first-class so a verdict can always state which
    isolation produced the facts it rests on.

    Lifecycle — ``prepare`` → ``run`` → ``teardown``, with ``session()`` for RAII.
    Ratified invariants:

      * ``prepare()`` is NOT idempotent — each call stages a fresh environment and
        returns a new handle.
      * ``run()`` is one-shot per handle at HERMETIC — a fresh container per run is
        the design; calling run() twice on one handle MUST NOT be assumed to reset
        state.
      * ``teardown()`` is idempotent — safe to call more than once; RAII relies on
        this for exception-safety.
    """

    isolation_level: IsolationLevel

    observes_egress: bool
    """Whether this backend class HAS a boundary observer at all. A STATIC CAPABILITY OF THE CLASS, not
    a property of any run.

    It exists so ``EgressAbsence.NOT_OBSERVED`` can be DERIVED rather than passed. Passing the variant at
    construction leaves the type accepting an answer, and an answer can be wrong — a fifth backend could
    hand back ``NOT_OBSERVED`` while holding a live observer, or an ``int`` while holding none, and
    nothing would object. Deriving it from the class means the question is asked where the answer is a
    fact about the code rather than a decision at a call site.

    Bound in BOTH directions by ``tests/test_egress_absence_contract.py``: a backend declaring ``False``
    must never emit an ``int``, and a backend declaring ``True`` must never emit ``NOT_OBSERVED`` (its
    observer failing is ``OBSERVER_UNREADABLE`` if the run completed, or a whole-run refusal if the
    observer never came up)."""

    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        """Stage the artifact tree + fixtures into a fresh isolated environment,
        binding ``artifact.tree_hash`` onto the returned handle. Not idempotent."""
        ...

    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        """Execute the entrypoint under the budget; return execution facts with
        provenance (isolation_level + the handle's bound artifact_hash) echoed.
        One-shot per handle at HERMETIC."""
        ...

    def teardown(self, handle: SandboxHandle) -> None:
        """Destroy the environment. Ephemeral: nothing survives a run. Idempotent."""
        ...

    def session(
        self, artifact: ArtifactSpec, fixtures: Fixtures
    ) -> AbstractContextManager[SandboxHandle]:
        """RAII: prepare on enter, teardown on exit — on EVERY path, including
        exceptions. Guarantees ephemerality (a security property) without relying
        on the caller to remember teardown; relies on ``teardown()`` idempotency."""
        ...
