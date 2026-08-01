"""THE RUNNER. Fetch the pinned corpus, measure every row, and report what disagreed.

⚠ WHAT THIS TOOL IS. A DRIFT DETECTOR. It re-measures artifacts whose counts were frozen at a
published release and reports where fresh measurement disagrees. Drift is the RESULT — the thing the
tool exists to produce — not a failure. A drift detector that halts on drift detects nothing, and a
halt-only design trains the one repair that must never be made: editing the frozen expectation to
match a drifted measurement so the run goes green.

THREE DISAGREEMENT CLASSES, THREE EXIT CODES, because automation must never route a real finding into
an infrastructure-failure handler:

    PIN-INCONSISTENT  (4)  Two FROZEN claims contradict — the consumer's pin and the corpus's own
                           record. Detected BEFORE any container starts, because no measurement can
                           adjudicate a contradiction between two things written down in advance.
    INSTRUMENT-INVALID (3) The apparatus is not in a state where readings mean anything. Preflight,
                           a witness that did not honour its contract, a control that missed its
                           floor. TERMINAL, and never displayed as drift.
    DRIFT              (2) THE RESULT. Fresh measurement disagrees with the frozen expectation.
    AGREEMENT          (0) Every row matched.

⚠ THE SCHEMA IS NOT REOPENED HERE. Receipts are sealed at row time, so a field absent at the first
seal cannot be added later without invalidating every receipt already issued. ``receipt.py`` was
settled first and deliberately; if this runner needs something the contract does not carry, the
correct move is to STOP and amend the contract — not to bolt a field onto the report.

⚠ ONE BUFFER LINEAGE. For the mutated rows the displayed diff is rendered from the SAME in-memory
bytes that are hashed and written to the workspace. Nothing is re-read from disk between displaying
and hashing. "Display the diff, then mutate" would display an INTENTION: the reader would be shown
one thing and the container would run whatever the filesystem held a moment later.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Sequence

from core.artifact_hash import tree_hash
from core.sandbox import ArtifactSpec, Command, Fixtures, ResourceBudget
from demo import pin, preflight
from demo.fetch import CorpusIntegrityError, CorpusUnavailable, ensure_corpus
from demo.receipt import (
    EXIT_AGREE,
    EXIT_DRIFT,
    EXIT_INSTRUMENT,
    EXIT_PINS,
    CompletedRun,
    CorpusIdentity,
    ExpectationKey,
    Instrument,
    InstrumentInvalid,
    MemberPath,
    PinBinding,
    PinInconsistent,
    Receipt,
    RunHeader,
    SubjectPin,
    verify_measured_against_pin,
)
from sandbox.observed import NetworkIsolationError, ObservedOCISandbox

# The corpus fetch's two failure modes get their OWN codes. They are NOT the same event: one is
# transport and RETRYABLE, the other is integrity and TERMINAL, and a caller that cannot tell them
# apart will do the wrong one half the time. They live here rather than in the contract module
# because they are runner concerns, and the contract is closed.
EXIT_CORPUS_UNAVAILABLE = 5
EXIT_CORPUS_INTEGRITY = 6

IMAGE = "docker.io/library/python:3.11-alpine"
WALL_CLOCK_SECONDS = 60.0

# The two rows whose bytes are DERIVED from another member. Written out rather than inferred from
# the substring "mutated": correspondence is data, never computation.
DERIVED_FROM: dict[str, str] = {
    "fixtures/retry-swallow-v2-mutated-behavioural/main.py": "fixtures/retry-swallow-v2/main.py",
    "fixtures/retry-swallow-v2-mutated-cosmetic/main.py": "fixtures/retry-swallow-v2/main.py",
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def stage(name: str) -> None:
    """Progress carries STAGE NAMES, never numbers. "step 4 of 9" goes stale the moment a stage is
    added or removed, and a reader who sees 'step 4' twice cannot tell which run they are reading."""
    print(f"  [{name}]", file=sys.stderr, flush=True)


# --------------------------------------------------------------------------------------------
# THE RECOMPUTABLE HALF — a pure function a sceptic can rerun offline.
# The PROOF is the comparison in render_and_prove(), not the applier below.
# --------------------------------------------------------------------------------------------
def apply_unified(base: Sequence[str], diff: Sequence[str]) -> list[str]:
    """Apply a unified diff to ``base`` and return the derived lines. STRICT.

    ⚠ THIS FUNCTION IS NOT THE PROOF, and an earlier version of this docstring said it was. It
    APPLIES a diff; it decides nothing. The proof is the COMPARISON in ``render_and_prove``: the
    reconstructed text set equal to the derived bytes. A reader following the code to find out what
    proves the transformation would have landed here and stopped — an overclaim about what
    constitutes proof, in the demo whose entire subject is what constitutes proof.

    What this contributes is the recomputable half: base + displayed diff -> derived is a PURE
    FUNCTION over disclosed inputs, so a sceptic can rerun it offline from the receipt alone, with no
    container and no trust in this process. The verdict on whether it MATCHED is the caller's.

    It is deliberately strict rather than lenient. A permissive applier that resynchronises on
    mismatch would "succeed" against a diff that does not actually describe the transformation, and
    the proof would certify a correspondence that is not there.
    """
    out: list[str] = []
    src = 0
    i = 0
    while i < len(diff):
        line = diff[i]
        if not line.startswith("@@"):
            i += 1
            continue
        # ⚠ EVERY PARSE FAILURE IS TYPED. These raised raw IndexError/ValueError on ``@@`` and
        # ``@@ garbage @@``, escaping the refusal taxonomy entirely — and this function is billed as
        # the artifact an offline sceptic runs, so non-difflib input is precisely what it will meet.
        try:
            header = line.split("@@")[1].strip()      # e.g. "-3,7 +3,9"
            old_part = header.split()[0]              # "-3,7"
            if not old_part.startswith("-"):
                raise ValueError("hunk range does not start with '-'")
            old_start_raw = int(old_part[1:].split(",")[0])
        except (IndexError, ValueError) as exc:
            raise InstrumentInvalid(
                f"the displayed diff has a malformed hunk header {line!r}: {exc}") from exc
        # ⚠ ``@@ -0,0 +1 @@`` is what difflib emits for an EMPTY BASE. Subtracting 1 gave -1, which
        # tripped the ordering guard and refused a legitimate diff. Latent while every base is
        # non-empty — which is exactly how it would have survived to the day one was not.
        old_start = max(old_start_raw - 1, 0)
        if old_start < src:
            raise InstrumentInvalid(
                f"the displayed diff has a hunk starting at line {old_start + 1}, before the previous "
                "hunk ended — hunks must be ordered and non-overlapping")
        out.extend(base[src:old_start])
        src = old_start
        i += 1
        while i < len(diff) and not diff[i].startswith("@@"):
            h = diff[i]
            if h.startswith("+"):
                out.append(h[1:])
            elif h.startswith("-"):
                if src >= len(base) or base[src] != h[1:]:
                    raise InstrumentInvalid(
                        f"the displayed diff removes a line the base does not contain at position "
                        f"{src + 1}: {h[1:]!r}. The diff does not describe these bytes")
                src += 1
            elif h.startswith(" "):
                if src >= len(base) or base[src] != h[1:]:
                    raise InstrumentInvalid(
                        f"the displayed diff's context does not match the base at position "
                        f"{src + 1}. The diff does not describe these bytes")
                out.append(h[1:])
                src += 1
            elif h.startswith("\\"):
                # "\\ No newline at end of file". difflib never emits it, but a hand-written or
                # tool-produced diff will, and silently skipping it would let the DISPLAYED artifact
                # differ from what was proven.
                raise InstrumentInvalid(
                    "the displayed diff carries a no-newline marker, which this verifier does not "
                    "model. Refusing rather than proving a transformation it cannot represent")
            else:
                # ⚠ ANY OTHER PREFIX IS REFUSED. A bare ``i += 1`` silently ignored it, so a doctored
                # diff could carry payload lines that RENDER in the displayed artifact — read by a
                # human as part of the transformation — while the proof stepped straight over them.
                raise InstrumentInvalid(
                    f"the displayed diff contains a line with an unrecognised prefix: {h!r}. Every "
                    "line in a proven diff must be context, addition or removal — a line the proof "
                    "ignores is a line the reader is shown and the proof never checked")
            i += 1
    out.extend(base[src:])
    return out


def render_and_prove(base_bytes: bytes, derived_bytes: bytes, base_name: str,
                     derived_name: str) -> str:
    """Render the diff AND prove it corresponds — as ONE step, over ONE buffer lineage.

    ⚠ ORDER IS THE POINT. Displaying a diff and then producing the bytes shows an INTENTION: the
    reader is shown one transformation and the container runs whatever lands on disk. Here the diff
    is computed from the two byte strings ALREADY IN MEMORY, immediately re-applied to the base, and
    the result required to equal the derived bytes exactly. The same buffers are then hashed and
    written. There is no path between the display and the run that re-reads a file.
    """
    base_lines = base_bytes.decode().splitlines(keepends=True)
    derived_lines = derived_bytes.decode().splitlines(keepends=True)
    diff = list(difflib.unified_diff(base_lines, derived_lines,
                                     fromfile=base_name, tofile=derived_name, n=3))
    reconstructed = apply_unified(base_lines, diff)
    if "".join(reconstructed) != derived_bytes.decode():
        raise InstrumentInvalid(
            f"the displayed diff for {derived_name} does not reproduce the derived bytes when "
            "applied to the base. The demo would be showing a transformation it did not perform")
    return "".join(diff)


# --------------------------------------------------------------------------------------------
# Instrument identity
# --------------------------------------------------------------------------------------------
def _git_commit() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True,
                             cwd=Path(__file__).resolve().parent.parent, timeout=10)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _resolve_image_digest(runtime: str, image: str) -> str:
    """The IMMUTABLE image identity, resolved BEFORE the header is sealed.

    Returns "" when it cannot be resolved — the caller refuses rather than sealing a placeholder."""
    try:
        out = subprocess.run([runtime, "image", "inspect", "--format", "{{.Id}}", image],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _runtime_version(runtime: str) -> str:
    try:
        out = subprocess.run([runtime, "--version"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


# Values that mean "I could not find out". They must never be SEALED as an identity.
UNRESOLVED = ("", "unknown", "pending")


def require_nameable(gate_commit: str, runtime_version: str, image_digest: str) -> None:
    """Refuse BEFORE any row runs if the instrument cannot name itself.

    ⚠ THIS EXISTS AS A FUNCTION BECAUSE THE INLINE VERSION WAS UNTESTABLE. Its only test was a
    source-scan, so disabling the guard left the suite green — the red-proof harness caught it as
    NOT RED. A guard whose test cannot see it removed is not a control.

    Resolving the image digest before the header means the header CAN now fail; ``pending`` never
    could. So the resolution needs its own refusal, and this is the cheapest possible place to stop:
    nothing has been measured, nothing has been sealed.
    """
    unnameable = [n for n, v in (("gate commit", gate_commit),
                                 ("runtime version", runtime_version),
                                 ("image digest", image_digest))
                  if v in UNRESOLVED]
    if unnameable:
        raise InstrumentInvalid(
            f"the instrument cannot name itself: {unnameable} did not resolve. Receipts sealed under "
            "an unidentified instrument are bound to nothing — when drift first fires, every pinned "
            "quantity is exonerated by construction and the real cause sits in whatever was never "
            "named. Refusing before any row runs")


def read_recorded_counts(path: Path) -> dict[str, int]:
    """The corpus's OWN record, parsed strictly. TERMINAL on anything malformed.

    Every failure here is ``CorpusIntegrityError`` (exit 6), never a traceback and never
    ``CorpusUnavailable``: the artifact WAS obtained and its digest DID match, so retrying cannot
    help — the bytes are the pinned bytes and their contents are unusable."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusIntegrityError(
            f"{path.name} could not be parsed as JSON: {exc}. The archive matched its pinned digest, "
            "so this is not a transport problem and retrying will not change it") from exc
    if not isinstance(raw, dict) or "egress_counts" not in raw:
        raise CorpusIntegrityError(
            f"{path.name} has no 'egress_counts' object. A digest pins BYTES, NOT SEMANTICS — the "
            "archive is the one we pinned and its contents are not usable")
    counts = raw["egress_counts"]
    if not isinstance(counts, dict) or not counts:
        raise CorpusIntegrityError(
            f"{path.name} 'egress_counts' is not a non-empty object. An empty record would cross-"
            "check against nothing and pass — an empty result is not a value")
    out: dict[str, int] = {}
    for k, v in counts.items():
        if isinstance(v, bool) or not isinstance(v, int):
            # bool is an int subclass; `true` must not silently become 1.
            raise CorpusIntegrityError(
                f"{path.name} records a non-integer count for {k!r}: {v!r}. A count that needs "
                "coercion is not a count")
        out[str(k)] = v
    return out


def build_binding() -> PinBinding:
    """The consumer's authority, assembled from the pin and nowhere else."""
    return PinBinding(
        corpus_digest=pin.CORPUS_SHA256,
        subject_rows=frozenset(
            SubjectPin(MemberPath(m), ExpectationKey(k), pin.EXPECTED_EGRESS[k])
            for m, k in pin.SUBJECT_ROWS),
        expected_cardinality=pin.SUBJECT_CARDINALITY,
        control_member=MemberPath(pin.CONTROL_NAME),
        control_floor=pin.CONTROL_EXPECTED_EGRESS,
        positive_member=MemberPath(pin.POSITIVE_NAME),
        positive_expected=pin.POSITIVE_EXPECTED_EGRESS,
        policy_expectation=pin.ADMIT_AT_OR_ABOVE,
        expectation_provenance=pin.EXPECTATION_PROVENANCE,
    )


# --------------------------------------------------------------------------------------------
# One row
# --------------------------------------------------------------------------------------------
class RowPlan:
    """What a row is, before it has been measured. Named rather than tupled so a reader of the run
    report can see which rows were PLANNED and which produced a receipt — an unmeasured row is
    ABSENT from the report, never rendered as ``measured=0``, which is a measurement."""

    def __init__(self, name: str, kind: str, source: bytes,
                 key: str | None = None, derived_from: str | None = None) -> None:
        self.name = name
        self.kind = kind
        self.source = source
        self.key = key
        self.derived_from = derived_from


def plan_rows(corpus: Path) -> list[RowPlan]:
    """Materialise every row's bytes IN MEMORY, once. Controls come from the pin (consumer-side
    interim, per the promotion path); subjects come from the verified corpus."""
    rows: list[RowPlan] = []
    for member, key in sorted(pin.SUBJECT_ROWS):
        rows.append(RowPlan(member, "subject", (corpus / member).read_bytes(), key=key,
                            derived_from=DERIVED_FROM.get(member)))
    rows.append(RowPlan(pin.CONTROL_NAME, "control", pin.CONTROL_SOURCE.encode()))
    rows.append(RowPlan(pin.POSITIVE_NAME, "positive", pin.POSITIVE_SOURCE.encode()))
    return rows


def measure_row(plan: RowPlan, workspace: Path, runtime: str,
                ) -> tuple[int, list[str], str, bool, str]:
    """Run ONE row and return (measured, events, image_digest, counter_ok, seal_mode).

    TWO THINGS ARE ESTABLISHED HERE, AND NEITHER IS THE WITNESS'S BEHAVIOUR.

      seal posture   ``prepare()`` raises ``NetworkIsolationError`` if the sealed network is not
                     sealed, so a leaking row never runs. This is a CONTROL-FLOW guarantee, not a
                     receipt claim — which is why no ``seal_verified_at_start`` field exists: the
                     runner could only ever have written the literal ``True``.
      counter liveness ``egress_attempts`` comes back ``None`` if the proxy's storage cannot be read
                     after the container exits. That raises here rather than sealing a number.

    ⚠ WHAT IS NOT ESTABLISHED, STATED PLAINLY. A witness that answered correctly at the start and
    served a SUCCESS mid-row is invisible to both: the posture is unchanged, the counter is readable,
    and the row simply measures a smaller number with a valid receipt and a false interpretation. The
    field that would close it is per-event response codes, which this observer does not record. See
    ``receipt.py``. Nothing here is attestation either — ``seal_mode`` stays SELF-REPORTED.
    """
    row_dir = workspace / plan.name.replace("/", "__")
    if row_dir.exists():
        raise InstrumentInvalid(
            f"workspace {row_dir} already exists. Row workspaces are APPEND-ONLY — reusing one "
            "would let a previous run's bytes survive into this row")
    row_dir.mkdir(parents=True)

    # The buffer that was diffed and proven is what gets written here. NOTE the honest limit: the
    # sandbox then hashes the STAGED TREE from disk (``tree_hash``), so the receipt's member digest
    # covers the memory buffer while the sandbox attests disk bytes. The earlier comment claimed "no
    # re-read", which was false by two reads.
    (row_dir / "main.py").write_bytes(plan.source)

    spec = ArtifactSpec(path=row_dir, tree_hash=tree_hash(row_dir))
    sandbox = ObservedOCISandbox(IMAGE, runtime)
    # ⚠ A DETECTED SEAL LEAK MUST ENTER THE TAXONOMY. ``NetworkIsolationError`` derives from
    # ``Exception``, NOT from ``InstrumentInvalid`` — so the single most security-relevant event this
    # gate can observe produced a raw traceback and exit 1: no refusal class, no run report, and
    # partial receipts left on disk. A leak detector whose detection crashes is not a detector.
    try:
        handle = sandbox.prepare(spec, Fixtures())      # the escape probe lives in here
    except NetworkIsolationError as exc:
        raise InstrumentInvalid(
            f"THE SEALED NETWORK WAS NOT SEALED while preparing {plan.name}: {exc}. Nothing was "
            "measured for this row and nothing will be sealed. This is an invalid instrument — it "
            "is not a finding about any artifact") from exc
    try:
        result = sandbox.run(handle, Command(("python", "/artifact/main.py")),
                             ResourceBudget(wall_clock_seconds=WALL_CLOCK_SECONDS))
    finally:
        sandbox.teardown(handle)

    # ⚠ AN UNREADABLE COUNTER RAISES — IT IS NEVER SEALED AS ZERO. ``egress_attempts or 0`` turned a
    # proxy-storage outage into ``measured=0`` on a permanent, append-only receipt. Downstream refused
    # it at table time (exit 3, not drift), but the LYING BYTES were already on disk and this
    # function's own docstring promised terminal-invalid where it in fact continued. Zero is a
    # measurement; an outage is not.
    if result.egress_attempts is None:
        raise InstrumentInvalid(
            f"the boundary counter was UNREADABLE after {plan.name} exited — the count could not be "
            "retrieved from the proxy's own storage. No number is attributable to this row, and none "
            "will be sealed. This is an invalid instrument, never drift")
    measured = result.egress_attempts
    # ⚠ NO SYNTHESISED EVENTS. The observer records a COUNT and no per-event data, so this is EMPTY
    # and the receipt says the count is uncorroborated. Labels derived from the count would put
    # computation where a sceptic reads data.
    return (measured, [], result.image_digest or "", True, "sealed")


# --------------------------------------------------------------------------------------------
# The two artifacts
# --------------------------------------------------------------------------------------------
def run_report(header: RunHeader, receipts: Sequence[Receipt], planned: Sequence[RowPlan],
               note: str) -> str:
    """ALWAYS EMITTED, and it carries NO VERDICT COLUMN.

    ⚠ IT IS NOT A DEGRADED VERDICT TABLE. A report that showed verdicts for the rows it managed to
    measure would be a partial table — exactly the thing ``CompletedRun`` exists to make
    unrepresentable — reintroduced through the door marked "diagnostics". So it records what ran,
    what did not, and why, and adjudicates nothing.

    Rows that were never measured are ABSENT. They are not rendered as ``measured=0``: zero is a
    MEASUREMENT, and a row that did not run has not got one.
    """
    lines = [
        "RUN REPORT  (no verdicts — see the verdict table, which is all-or-nothing)",
        f"  run            {header.run_nonce}",
        f"  instrument     {header.instrument.render()}",
        f"  binding        {header.binding_digest[:16]}…",
        f"  header seal    {header.digest()[:16]}…",
        "",
        f"  planned rows   {len(planned)}",
        f"  sealed rows    {len(receipts)}",
    ]
    unmeasured = [p.name for p in planned if p.name not in {r.row for r in receipts}]
    if unmeasured:
        lines.append(f"  NOT MEASURED   {unmeasured}  (absent, not zero — zero is a measurement)")
    lines.append("")
    for r in receipts:
        lines.append(f"  {r.kind:<8} {r.row:<62} measured={r.measured} "
                     f"counter@end={'ok' if r.counter_readable_at_end else 'UNREADABLE'} "
                     f"{'UNCORROBORATED ' if r.uncorroborated() else ''}"
                     f"receipt={r.digest()[:12]}…")
    if note:
        lines += ["", f"  {note}"]
    return "\n".join(lines)


def verdict_table(run: CompletedRun, drift: Sequence[tuple[str, int, int]]) -> str:
    """ALL OR NOTHING, and its only input type is a ``CompletedRun``.

    ⚠ IT DOES NOT READ A DIRECTORY. Taking a glob of receipt files would make a half-populated table
    something that has to be PREVENTED; taking a parsed type makes it something that cannot be
    EXPRESSED. The set, the pairing, the controls and the chain were all established at construction,
    so nothing here needs to re-check them and nothing here is in a position to skip them.
    """
    drifted_rows = {d[0] for d in drift}
    lines = [
        "VERDICT TABLE",
        f"  corpus {run.binding.corpus_digest[:16]}…  ·  policy: ADMIT at or above "
        f"{run.binding.policy_expectation}  ·  expectations: {run.binding.expectation_provenance}",
        "",
        f"  {'row':<62} {'frozen':>7} {'measured':>9} {'verdict':>8}  drift",
    ]
    expectations = run.binding.expectations()
    for r in run.subjects:
        key = r.corpus.expectation_key
        frozen = expectations[key] if key is not None else 0
        flag = "◀ DRIFT" if r.row in drifted_rows else ""
        lines.append(f"  {r.row:<62} {frozen:>7} {r.measured:>9} {r.verdict:>8}  {flag}")
    lines += [
        "",
        f"  control  {run.control.row:<60} floor {run.binding.control_floor}, "
        f"read {run.control.measured}",
        f"  positive {run.positive.row:<60} known {run.binding.positive_expected}, "
        f"read {run.positive.measured}",
        "",
        "  The two controls bracket the counter from BOTH directions. A reading that is low, high or "
        "absent is an INVALID INSTRUMENT, not a finding about any artifact.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------------------------------
def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Re-measure the pinned demo corpus and report drift.")
    ap.add_argument("--cache", type=Path, default=Path.home() / ".cache" / "gated-demo")
    ap.add_argument("--workspace", type=Path, default=Path("workspace"))
    ap.add_argument("--runtime", default="podman")
    args = ap.parse_args(argv)

    binding = build_binding()
    nonce = uuid.uuid4().hex
    planned: list[RowPlan] = []
    receipts: list[Receipt] = []
    header: RunHeader | None = None

    try:
        stage("preflight")
        report = preflight.check(args.runtime, IMAGE)
        if not report.ok():
            # The refusal carries its own evidence — the command and its stderr. Reprinting a
            # summary instead would drop the one thing an operator needs to act on.
            assert report.refusal is not None                      # ok() is exactly this check
            print(report.refusal.render(), file=sys.stderr)
            raise InstrumentInvalid("preflight did not pass; nothing was measured")

        stage("fetch-corpus")
        corpus = ensure_corpus(args.cache)

        stage("cross-check-pin-against-corpus")
        # ⚠ A DIGEST-VALID BUT STRUCTURALLY UNUSABLE CORPUS IS AN INTEGRITY FAILURE, NOT A CRASH.
        # These three — JSONDecodeError, KeyError, and int()'s ValueError — were raised OUTSIDE the
        # four refusal classes, so a corpus that matched its pinned digest perfectly and then carried
        # malformed contents produced a raw traceback and exit 1 instead of CORPUS INTEGRITY (6).
        # Same shape as the seal-leak escape: a real, classifiable condition falling outside the
        # taxonomy because nothing named it. A digest pins BYTES, NOT SEMANTICS.
        #
        # The KEY IS READ FROM THE REAL FILE, not guessed. A ``.get(k, whole_dict)`` fallback would
        # have silently handed the cross-check every metadata key in the file ("format_version",
        # "note", "witness_condition") as if they were expectation keys.
        recorded = read_recorded_counts(corpus / "MEASURED.json")
        verify_measured_against_pin(recorded, binding)

        stage("resolve-instrument-identity")
        # ⚠ THE HEADER CAN NOW FAIL, AND THAT IS THE POINT. It previously sealed
        # ``image_digest="pending"`` — a value true at no instant — and every receipt chained from a
        # root committing to a placeholder. Resolving the real digest first means the resolution can
        # fail, so it needs its own refusal, BEFORE any row runs: the cheapest possible place to stop.
        #
        # A gate that cannot name itself must refuse rather than attest. Each of these degraded
        # silently to "unknown" and was sealed as the gate's identity.
        gate_commit = _git_commit()
        runtime_version = _runtime_version(args.runtime)
        image_digest = _resolve_image_digest(args.runtime, IMAGE)
        require_nameable(gate_commit, runtime_version, image_digest)

        stage("seal-run-header")
        instrument = Instrument(
            gate_commit=gate_commit, image_digest=image_digest, runtime=args.runtime,
            runtime_version=runtime_version, seal_mode="sealed",
            witness_identity="boundary-proxy: escape-probe at row start, count read after exit. "
                             "Per-event response codes are NOT recorded — see receipt.py")
        header = RunHeader(nonce, instrument, binding.digest())
        prior = header.digest()

        workspace = args.workspace / nonce
        workspace.mkdir(parents=True, exist_ok=False)
        planned = plan_rows(corpus)
        by_name = {p.name: p for p in planned}

        for plan in planned:
            stage(f"row:{plan.name}")
            base_digest = derived_digest = displayed_diff = ""
            if plan.derived_from is not None:
                stage("prove-diff-corresponds")
                # ⚠ THE BASE COMES FROM THE ALREADY-PLANNED ROW, NOT A SECOND READ. It was
                # ``(corpus / plan.derived_from).read_bytes()`` — a fresh read, so the derived row's
                # ``base_digest`` described different bytes from the ones the base row itself sealed,
                # and nothing cross-checked them. "No re-read" was false by two reads.
                base_plan = by_name.get(plan.derived_from)
                if base_plan is None:
                    raise InstrumentInvalid(
                        f"{plan.name} declares a base {plan.derived_from!r} that is not a planned "
                        "row, so the displayed diff could not be tied to any sealed receipt")
                base_bytes = base_plan.source
                # Render AND prove in one step, over the buffers that are about to be written.
                displayed_diff = render_and_prove(base_bytes, plan.source,
                                                  plan.derived_from, plan.name)
                base_digest = _sha256(base_bytes)
                derived_digest = _sha256(plan.source)
                print(displayed_diff)

            stage("measure")
            measured, events, row_image_digest, counter_ok, seal_mode = measure_row(
                plan, workspace, args.runtime)
            if row_image_digest and row_image_digest != image_digest:
                raise InstrumentInvalid(
                    f"row {plan.name} ran on image {row_image_digest} but the run header committed "
                    f"to {image_digest}. The image changed mid-run")

            stage("seal-row")
            row_instrument = Instrument(
                gate_commit=instrument.gate_commit, image_digest=image_digest,
                runtime=instrument.runtime, runtime_version=instrument.runtime_version,
                seal_mode=seal_mode, witness_identity=instrument.witness_identity)
            # RULING: a healthy zero-control must not be sealed as BLOCK. The verdict is recomputed
            # kind-aware by the receipt itself, so nothing here composes it by hand.
            expectation = binding.policy_expectation
            r = Receipt(
                run_nonce=nonce, row=plan.name, kind=plan.kind,  # type: ignore[arg-type]
                corpus=CorpusIdentity(
                    pin.CORPUS_RELEASE, pin.CORPUS_SHA256, MemberPath(plan.name),
                    _sha256(plan.source),
                    expectation_key=None if plan.key is None else ExpectationKey(plan.key)),
                instrument=row_instrument, measured=measured, boundary_events=tuple(events),
                notes=(f"boundary attempts observed: {measured}; per-event records are NOT produced "
                       "by this observer, so the count is uncorroborated",),
                expectation=expectation,
                verdict=("ADMIT" if measured >= expectation else "BLOCK")
                        if plan.kind == "subject" else "CONTROL",
                prior_digest=prior, expectation_provenance=binding.expectation_provenance,
                counter_readable_at_end=counter_ok,
                base_digest=base_digest, derived_digest=derived_digest,
                displayed_diff=displayed_diff)
            receipts.append(r)
            (workspace / plan.name.replace("/", "__") / "receipt.json").write_text(r.to_json())
            prior = r.digest()

        stage("build-verdict-table")
        completed = CompletedRun(header, receipts, binding)
        drift = completed.drifted()

        print()
        print(verdict_table(completed, drift))
        print()
        print(run_report(header, receipts, planned, ""))

        if drift:
            print()
            print(f"DRIFT: {len(drift)} row(s) disagree with the frozen expectation. This is the "
                  "RESULT, not a failure — do NOT edit the expectation to match.")
            for row, want, got in drift:
                print(f"  {row}: frozen {want}, measured {got}")
            return EXIT_DRIFT
        return EXIT_AGREE

    except PinInconsistent as exc:
        print(f"\nPIN-INCONSISTENT: {exc}", file=sys.stderr)
        print("\nNothing was measured. Two frozen claims contradict each other, and no measurement "
              "can adjudicate that.", file=sys.stderr)
        return EXIT_PINS
    except CorpusUnavailable as exc:
        print(f"\nCORPUS UNAVAILABLE: {exc}", file=sys.stderr)
        return EXIT_CORPUS_UNAVAILABLE
    except CorpusIntegrityError as exc:
        print(f"\nCORPUS INTEGRITY: {exc}", file=sys.stderr)
        return EXIT_CORPUS_INTEGRITY
    except InstrumentInvalid as exc:
        print(f"\nINSTRUMENT-INVALID: {exc}", file=sys.stderr)
        print("\nThis is NOT drift. No claim is made about any artifact.", file=sys.stderr)
        if header is not None:
            print()
            print(run_report(header, receipts, planned,
                             "the run halted on an invalid instrument; the rows above are sealed "
                             "but carry NO verdicts"), file=sys.stderr)
        return EXIT_INSTRUMENT


if __name__ == "__main__":
    raise SystemExit(main())
