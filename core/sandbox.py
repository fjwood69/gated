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
from typing import Literal, Protocol, runtime_checkable


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
    raw_return_code: int | None = None
    egress_attempts: int | None = None
    """Boundary-observed count of outbound connection attempts (Increment 1.4),
    read from the sidecar proxy's own storage AFTER the run, from OUTSIDE the
    sandbox — never a value the artifact could write. A typed, named field, not an
    untyped stats bag (that would be a channel for artifact-influenced data to
    reach the verdict). None when no boundary observer ran."""
    image_digest: str | None = None
    """The IMMUTABLE image identity the trial ACTUALLY ran on (3.5-close #1.1). An OCI
    backend resolves the local image to its content digest (``<runtime> inspect .Id`` ->
    ``sha256:...``) BEFORE container start and executes THAT digest — never the mutable tag
    — so the attested execution binds the bytes that ran, closing the tag-TOCTOU. This is an
    ANTI-DRIFT / identity coordinate (which bytes), NOT runtime-behaviour assurance: a
    compromised host could verify the digest and then run something else (the unattested-TCB
    ceiling; see ARCHITECTURE.md). Measured host-side by the trusted sandbox object, never
    self-reported by the artifact. None for backends with no image (NoOp/Subprocess)."""


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
