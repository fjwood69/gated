"""Increment 1.4 — ObservedOCISandbox: HERMETIC + boundary observation.

Wraps the 1.3 hermetic container with an out-of-process boundary observer: the
counting fail-responder proxy (observe/proxy.py) runs as a sidecar on a SEALED
network, reachable only by a static host entry. The artifact's egress attempts hit
the proxy, which counts them in its OWN filesystem; run() reads the count from
OUTSIDE via ``exec cat`` after the sandbox exits and attaches it as
``egress_attempts``. The artifact can influence the count ONLY by issuing real
requests — it can neither forge nor erase it (NFR4).

SEALED NETWORK CONFIG (board-ratified amendment — supersedes bare ``--internal``):

    --internal --disable-dns   +   per-run  --add-host health-proxy:<proxy-ip>

``--internal`` blocks TCP egress but ``aardvark-dns`` FORWARDS external DNS queries
(a data-exfil channel — encode a secret in a lookup, read it from your DNS logs, no
TCP packet ever leaves). ``--disable-dns`` rips the resolver out; ``--add-host``
restores the ONE name the artifact legitimately needs (the proxy). STANDING RULE
(regression gate): any change to this network config must re-run the escape probe's
full residual-channel enumeration — a network-config change re-opens the channel
question.

The lifecycle owns THREE ephemeral resources — network + proxy + sandbox. Teardown
must converge to all-gone on every path, including partial failures; ``SandboxLeakError``
if any survive. The escape probe runs BEFORE the artifact; ``NetworkIsolationError``
(refuse to run) if any residual channel is reachable. This is calibration-of-the-
detector: a known-bad (attempted exfil) the isolation must catch.
"""
from __future__ import annotations

import hashlib
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from core import (
    ArtifactHashMismatchError,
    EgressAbsence,
    SandboxStartError,
    ImageResolutionError,
    ArtifactSpec,
    Command,
    Existence,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    Sandbox,
    SandboxHandle,
    SandboxLeakError,
    tree_hash,
)
from core.chain import content_digest
import shutil

from sandbox.base import BaseSandbox
from sandbox.oci import (
    NO_HEALTHCHECK_FLAGS,
    RESOURCE_PREFIX,
    artifact_run_argv,
    OCIRuntimeUnavailable,
    RuntimePathUnresolved,
    detect_runtime,
    exec_runtime_path,
    resolve_runtime_path,
    runtime_client_env,
    _ResolvedRuntimeMixin,
    _make_snapshot_readable,
    ProbeReading,
    ResourceKind,
    TeardownVerdict,
    UnsupportedRuntimeWitness,
    VerdictKind,
    ambient_network_witness,
    ensure_container_witness,
    listing_argv,
    probe_container,
    probe_network,
    resolve_image_id,
)

_Outcome = Literal["completed", "timeout", "error"]
_RUNTIMES = ("podman", "nerdctl", "docker")
ARTIFACT_MOUNT = "/artifact"
WORK_DIR = "/work"
PROXY_HOST = "health-proxy"   # the ONE name the artifact resolves (via --add-host)
PROXY_PORT = 8080
_COUNTFILE = "/tmp/mv_egress_count"
_PROXY_SRC = Path(__file__).resolve().parent.parent / "observe" / "proxy.py"

# READINESS BUDGET — a WALL-CLOCK DEADLINE, and the message quotes THIS constant rather than a second
# literal. The previous shape was ``for _ in range(50): ... time.sleep(0.1)`` with a message reading
# "within 5s", which silently assumed each ``_read_count`` was FREE. It never was — every iteration runs a
# real ``exec`` round-trip — so the stated budget was already wrong before anything absorbed a timeout, and
# once ``TimeoutExpired`` mapped to "no reading" the same loop could run 50 x 30s and still say "within 5s".
#
# TWO LITERALS AGREEING BY CONVENTION IS THE DEFECT THIS TREE KEEPS FINDING (``_SEALED_NETWORK_FLAGS``,
# ``NO_HEALTHCHECK_FLAGS``): the budget and the sentence describing it are ONE value here, so they cannot
# drift apart. The refusal additionally reports MEASURED elapsed, because a message that states what it
# observed cannot misdescribe its own budget the way a hardcoded figure can.
#
# ⚠⚠ READ THIS BEFORE CHANGING THE NUMBER. THREE FACTS ABOUT ITS PROVENANCE, HERE RATHER THAN IN A REVIEW,
# BECAUSE A NUMBER WHOSE PROVENANCE IS NOT VISIBLE AT THE POINT OF EDIT IS HOW THE LAST TWO DEFECTS HAPPENED.
#
#   1. THIS BUDGET USED TO ADAPT TO THE HOST AND NO LONGER DOES. As an iteration count, a slow host made
#      each poll slower AND still granted all fifty of them, so the effective budget grew with host
#      slowness — nobody designed that, but it was real and it was protective. A wall clock removes it.
#      MEASURED on the reference host (podman 4.9.3, 20 samples): exec round-trip median 89ms, so the old
#      shape afforded ~9.4s. On a 2s-per-exec loaded runner the old shape still gave 50 polls (~105s);
#      30s gives about 14. THE MARGIN IS NOW FIXED AND MUST COVER THE SLOWEST HOST GATED IS REQUIRED TO
#      RUN ON. Cutting it after measuring RTT on a fast machine would be cutting into a budget that no
#      longer stretches — which is exactly the mistake this comment exists to prevent.
#
#   2. 30s IS A DEFENSIBLE MARGIN, NOT A CALIBRATION. It is ~3x the old effective budget on the reference
#      host, and it bounds the wedged-runtime case at roughly one subprocess timeout past the deadline
#      (~60s) instead of the ~1500s an iteration count allowed. Chosen for headroom, not derived.
#
#   3. READINESS LATENCY ITSELF HAS NEVER BEEN MEASURED. Only the exec round-trip has. Nobody has timed how
#      long the proxy actually takes to bind, listen and publish the countfile, on any host. THAT
#      MEASUREMENT IS AVAILABLE TO BE TAKEN and would replace this margin with a real calibration; until
#      someone takes it, no one should read 30.0 as though it encodes one.
#
# NAMED FOR WHAT IT BOUNDS. It bounds ATTEMPT SCHEDULING — the deadline is consulted only BETWEEN polls, so
# a single wedged ``exec`` can overrun it by its own subprocess timeout. The composite bound is
# ``deadline + one subprocess timeout``, never the deadline alone. The earlier name said DEADLINE and read
# as "readiness waits at most this long", which is the adjacent-property defect in miniature: the value was
# credited with bounding the WAIT when it bounds the ATTEMPTS.
_READINESS_POLL_DEADLINE_SECONDS = 30.0
_READINESS_POLL_INTERVAL_SECONDS = 0.1

# Escape probe: each residual channel MUST fail; the proxy MUST be reachable.
# Exit 0 = sealed; non-zero = a channel leaked (refuse to run the artifact).
_ESCAPE_SCRIPT = f"""
import socket, sys
def reach(host, port, t=3):
    try:
        socket.create_connection((host, port), t).close(); return True
    except Exception:
        return False
leaks = []
if not reach({PROXY_HOST!r}, {PROXY_PORT}): leaks.append("proxy-unreachable")
if reach("1.1.1.1", 53): leaks.append("external-tcp")
if reach("host.containers.internal", 80): leaks.append("host.containers.internal")
try:
    socket.gethostbyname("example.com"); leaks.append("external-dns")
except Exception:
    pass
sys.exit(0 if not leaks else ("LEAK:" + ",".join(leaks)))
"""


# Imported, not restated: ``sandbox/oci.py`` names its own containers with the same prefix and the
# reaper below filters on it, so the two must be one value rather than two that agree today.
# SCOPE: ``sandbox/subprocess.py`` and ``gate/artifact.py`` still restate the literal for their own
# temp DIRECTORIES. Those are host paths, not podman resources, so the reaper cannot see them either
# way — out of scope here rather than overlooked.
_PREFIX = RESOURCE_PREFIX

# 3.5-close #1.1 (board amendment 4): the container IMAGE digest does NOT cover the host-mounted
# observer — ``_PROXY_SRC`` is bind-mounted into the proxy as ``/proxy.py``, and the sealed-network
# flags + escape-probe script are host-side config. Bind those into an ``observer_config_hash`` so
# OBSERVER DRIFT (a changed proxy, a loosened network, a weakened probe) is visible in the attested
# execution identity even when the image digest is unchanged. Computed once from the on-disk observer.
_SEALED_NETWORK_FLAGS = ("--internal", "--disable-dns")


@dataclass
class _SweepReport:
    """What one destroy-and-probe sweep established: two disjoint lists and the reasons, if any.

    A THIRD FIELD, because the second was carrying two jobs. ``unproven`` says WHICH resources could
    not be verified; ``causes`` says WHY, once per distinct reason rather than once per item. A
    whole-kind refusal (this runtime has no measured ambient network) previously arrived as N separate
    unproven entries with no cause attached at all — N mysteries in place of one stated fact, and the
    exact "confidence label is not a coverage claim" shape one level along.
    """

    present: list[str] = field(default_factory=list)
    unproven: list[str] = field(default_factory=list)
    causes: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        """True when the sweep found ANYTHING to report — i.e. the teardown was not clean.

        Defined explicitly. The dataclass would otherwise be truthy always, so a caller writing the
        obvious ``if report:`` would branch into the failure path on every clean teardown.
        """
        return bool(self.present or self.unproven)


def network_create_argv(runtime: str, name: str) -> list[str]:
    """The sealed-network create argv — the application site for the attested sealed-network flags.

    ``_SEALED_NETWORK_FLAGS`` is EXPANDED here rather than restated as literals, so the value that
    is *attested* (it is a member of ``_OBSERVER_CONFIG_HASH`` below) and the value that is *applied*
    cannot diverge. Before this, editing the literals at the create site left the identity unchanged
    while the posture moved — the identity attesting a network the container did not have — and
    editing the constant forced a recalibration for a posture that had not moved. Neither direction
    failed anything, which is what made it a defect rather than untidiness: a control that can lie,
    inside the mechanism that grants blocking authority.

    SEAM: kept as a free function returning the argv so the binding test asserts against an OUTPUT
    rather than against ``_create_network``'s internals. A shared argv builder (a LATER increment —
    no such builder exists in this module today; every other ``subprocess.run`` site here still
    hand-builds its list) can absorb this without the test changing.

    SCOPE OF THE GUARANTEE, because the word "the" above would otherwise overclaim. What is
    test-enforced is that ``_create_network``'s executed argv FOLLOWS this constant. What is NOT
    enforced is that this is the only expansion site: a second site re-expanding
    ``*_SEALED_NETWORK_FLAGS`` would be byte-identical and every test would stay green. Nor is the
    binding attested — ``_OBSERVER_CONFIG_HASH`` is computed ONCE AT IMPORT from the constant's
    value, while this function reads the module global AT CALL TIME, so an in-process mutation or a
    shadowed module attribute reproduces the original defect polarity with the identity unmoved. The
    seal is a CI-time source-integrity control, not a runtime one.
    """
    return [runtime, "network", "create", *_SEALED_NETWORK_FLAGS, name]


def _add_note(exc: BaseException, note: str) -> None:
    """Attach context WITHOUT supplanting the exception. ``add_note`` is PEP 678 (3.11+); the CI matrix
    includes 3.9 and 3.10, so degrade to an args append rather than assuming the newer interpreter — the
    kind of version assumption that has reddened three of five jobs in this tree before."""
    adder = getattr(exc, "add_note", None)
    if adder is not None:
        adder(note)
    else:  # pragma: no cover - exercised only on pre-3.11 interpreters
        exc.args = (*exc.args, note)


def attached_network_segment(network: str) -> list[str]:
    """Join a named network, and nothing else. The proxy sidecar's posture: it sits ON the sealed
    network but needs no ``--add-host``, because it is the thing being resolved rather than a resolver.

    Split out because it was the THIRD live statement of ``--network`` in the package — found by a
    single-source test over builder bodies, not by looking for it.
    """
    return ["--network", network]


def sealed_network_segment(network: str, proxy_ip: str) -> list[str]:
    """The SEALED posture: join the internal network, and restore the ONE name the artifact may resolve.

    Shared by the artifact run and the escape probe, deliberately — the probe must certify the SAME
    network posture the artifact will get, and two independent statements of it could drift with the
    probe still passing. ``--add-host`` is what makes the proxy reachable after ``--disable-dns`` rips
    the resolver out.
    """
    return [*attached_network_segment(network), "--add-host", f"{PROXY_HOST}:{proxy_ip}"]


def proxy_mount_spec() -> str:
    """The observer's own source, bind-mounted read-only. Its BYTES are hashed into
    ``_OBSERVER_CONFIG_HASH``, so a changed proxy is visible in the attested identity."""
    return f"type=bind,source={_PROXY_SRC},target=/proxy.py,readonly"


def proxy_run_argv(runtime: str, *, network: str, name: str, image_id: str, mode: str) -> list[str]:
    """The counting fail-responder sidecar. It sits ON the sealed network but needs no ``--add-host``:
    it is the thing being resolved, not a resolver."""
    return [
        runtime, "run", "-d", *NO_HEALTHCHECK_FLAGS,
        *attached_network_segment(network), "--name", name,
        "--mount", proxy_mount_spec(),
        image_id, "python3", "/proxy.py", str(PROXY_PORT), _COUNTFILE, mode,
    ]


def escape_probe_argv(runtime: str, *, network: str, proxy_ip: str, image_id: str) -> list[str]:
    """Calibration-of-the-detector: a known-bad the isolation must catch, run BEFORE the artifact.

    Uses ``sealed_network_segment`` so the posture it certifies is the posture the artifact receives.
    """
    return [
        runtime, "run", "-i", "--rm", *NO_HEALTHCHECK_FLAGS,
        *sealed_network_segment(network, proxy_ip),
        image_id, "python3", "-",
    ]


# ``no_healthcheck_flags`` IS A VALUE MEMBER, and it lands in the SAME COMMIT as the flag reaching the
# three builders. The ordering is deliberate: a Clause-M control that is live for even one commit while
# unattested is a fossil in the making, and this tree carried the archaeology until recently — the
# ``ObservedHandle.baseline`` field recorded a behaviour change that moved no identity, because the
# local half is unattested and nobody was structurally obliged to notice. THAT FIELD IS NOW DELETED,
# and this sentence is written in the past tense on purpose: it was updated in the same diff that
# removed it, having been caught pointing at a vestige that no longer existed.
#
# WHY A VALUE AND NOT BUILDER SOURCE. Builder-source hashing would cover these three CONSTRUCT sites, and
# it is the mechanism the NARROW ruling kept — but the ruling kept its DESIGN, not a live implementation.
# Nothing in this module hashes any builder's source today, and ``sandbox/oci.py`` says so itself. Adding
# the flag on the strength of a mechanism that is not built would be exactly the overclaim this
# increment's own brief had to strike.
_OBSERVER_CONFIG_HASH = content_digest({
    "proxy_src_sha256": hashlib.sha256(_PROXY_SRC.read_bytes()).hexdigest(),
    "escape_probe_sha256": hashlib.sha256(_ESCAPE_SCRIPT.encode("utf-8")).hexdigest(),
    "sealed_network_flags": list(_SEALED_NETWORK_FLAGS),
    "no_healthcheck_flags": list(NO_HEALTHCHECK_FLAGS),
    "proxy_port": PROXY_PORT,
    "proxy_host": PROXY_HOST,
})


def reap_orphans(runtime: str = "podman", *, canary_image: str) -> None:
    """Force-remove orphaned gated containers and networks by name prefix. A TEST/OPS UTILITY —
    **nothing invokes this at startup, and it does not guarantee a clean slate to anything.**

    RAII covers the normal and partial-failure paths; a hard crash of the engine process itself can
    still orphan resources, which is what this exists to clear when an operator or a test chooses to
    run it. It is NOT wired into engine or App boot, so no caller may assume a clean slate on the
    strength of its existence.

    *This docstring previously promised a startup clean-slate guarantee that nothing delivered — the
    only callers were tests. Wiring it at boot is a SEPARATE increment, because it would introduce
    resource deletion at startup and, being fail-closed, would turn a briefly-unlistable runtime into
    a refusal to start. It also selects by PREFIX rather than by instance, so on a host running two
    gated instances a booting instance would reap the other's live sandboxes. Those are real design
    questions, and they are not this increment's.*

    Fail CLOSED **for its own callers**: a listing that cannot run (error / timeout / non-zero) RAISES
    ``SandboxLeakError`` rather than reap nothing and report success — an unlistable runtime is exactly
    the state where an orphaned container/network could persist unseen. Each removal is re-probed; a
    resource not CONFIRMED gone raises.

    ``runtime`` is a NAME; every argv below is built around ``rt``, the resolved ABSOLUTE path. Before
    P2a's remediation this function used the bare name as ``argv[0]`` at all six of its invocation
    sites — invisible to the first static sweep, which saw only ``subprocess`` calls taking list
    literals and so missed both the ``_names``/``_rm`` indirection and the ``probe_existence`` calls.
    An unresolvable runtime is normalised into this function's OWN fail-closed contract
    (``SandboxLeakError``) rather than propagating ``RuntimePathUnresolved``: a caller that cannot list
    is in exactly the state this promises to refuse, and its two existing negative tests pin that
    exception type."""
    # FIRST, before resolution and before any subprocess: is this runtime SUPPORTED at all? Ordering is
    # load-bearing. Resolution runs a filesystem probe and fails for an ABSENT BINARY; the map fails for
    # an UNMEASURED RUNTIME. On a host where an unsupported runtime also happens not to be installed, the
    # resolution failure would mask the support failure and the operator would be told to install
    # something that still would not be trusted. Absence of support is decided first, and decided
    # statically. Normalised into the reaper's own contract like RuntimePathUnresolved below — the TYPE is
    # shared, the MESSAGE is not, because "not in the supported set" must never read as "witness not
    # found", which is indistinguishable from a broken channel.
    try:
        net_witness = ambient_network_witness(runtime)
    except UnsupportedRuntimeWitness as exc:
        raise SandboxLeakError(
            f"orphan reaper refuses runtime {runtime!r}: NOT IN THE SUPPORTED SET ({exc}). This is a "
            "refusal to probe, not a failed probe — no listing was attempted"
        ) from exc

    try:
        rt = exec_runtime_path(runtime)
    except RuntimePathUnresolved as exc:
        raise SandboxLeakError(
            f"orphan reaper cannot resolve runtime {runtime!r} to an absolute binary ({exc}) "
            "— cannot confirm a clean slate"
        ) from exc

    def _names(kind: ResourceKind, what: str, witness: str) -> list[str]:
        """Names under ``_PREFIX``, from a channel PROVEN LIVE — never from silence.

        This used to return ``r.stdout.split()`` on rc 0, so an empty result meant "clean slate". By this
        function's OWN stated standard that is already the raise branch: the reaper promises to raise
        "rather than reap nothing and report success", and a vacuously-empty listing does exactly that.
        It CERTIFIED BY SILENCE. Refusing outright was rejected too — a reaper that will not run on a
        genuinely empty host is obviously wrong. So neither: the listing is UNFILTERED and matched
        in-process, and the witness turns "empty" into PROVEN empty, at which point proceeding is sound.
        """
        try:
            r = subprocess.run(listing_argv(rt, kind), capture_output=True, text=True, timeout=30,
                               env=runtime_client_env())
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
            raise SandboxLeakError(
                f"orphan reaper could not list {what} ({type(exc).__name__}) — cannot confirm a clean slate"
            ) from exc
        if r.returncode != 0:
            raise SandboxLeakError(
                f"orphan reaper list of {what} returned {r.returncode} — cannot confirm a clean slate")
        listed = r.stdout.split()
        if witness not in listed:
            raise SandboxLeakError(
                f"orphan reaper's {what} listing did not contain its witness — the channel is not proven "
                "live, so an empty result proves nothing. Cannot confirm a clean slate")
        return [n for n in listed if n.startswith(_PREFIX)]

    def _rm(args: list[str]) -> None:
        # best-effort removal; a raw TimeoutExpired/OSError from rm would ESCAPE the reaper's
        # SandboxLeakError contract, so swallow it — the re-probe below is the sole destruction
        # authority and normalises every not-CONFIRMED-gone outcome to SandboxLeakError.
        try:
            subprocess.run(args, capture_output=True, timeout=30, env=runtime_client_env())
        except (OSError, subprocess.SubprocessError):
            pass

    # Normalised into the reaper's OWN fail-closed contract, exactly as RuntimePathUnresolved is above:
    # a caller that cannot obtain a witness is in precisely the state this function promises to refuse.
    # The TYPE is shared; the MESSAGE is not — "not in the supported set" must never read as "witness not
    # found", because the second is indistinguishable from a broken channel.
    try:
        image_id = resolve_image_id(rt, canary_image)
    except ImageResolutionError as exc:
        raise SandboxLeakError(
            f"orphan reaper could not resolve its canary image {canary_image!r} LOCALLY ({exc}) — the "
            "container witness cannot be created, so an empty listing would prove nothing. Resolution is "
            "local-only BY CONTRACT: the image must already be present, it is never pulled"
        ) from exc
    witness = ensure_container_witness(rt, image_id, uuid.uuid4().hex[:16])
    try:
        for c in _names(ResourceKind.CONTAINER, "containers", witness):
            if c == witness:
                continue  # the reaper's own witness is not an orphan
            _rm([rt, "rm", "-f", c])
            if probe_container(rt, c, witness=witness).state is not Existence.ABSENT:
                raise SandboxLeakError(f"orphan reaper could not CONFIRM container {c} destroyed")
        for n in _names(ResourceKind.NETWORK, "networks", net_witness):
            _rm([rt, "network", "rm", "-f", n])
            if probe_network(rt, n, runtime_name=runtime).state is not Existence.ABSENT:
                raise SandboxLeakError(f"orphan reaper could not CONFIRM network {n} destroyed")
    finally:
        _rm([rt, "rm", "-f", witness])


class NetworkIsolationError(Exception):
    """The sealed network is not sealed — a residual channel is reachable. Refuse
    to run the artifact (a leaked boundary makes the egress count meaningless)."""


@dataclass(frozen=True)
class ObservedHandle:
    id: str
    artifact_hash: str
    snapshot: Path
    container: str   # sandbox container name
    network: str     # --internal --disable-dns network name
    proxy: str       # proxy sidecar container name
    proxy_ip: str
    image_id: str    # 3.5-close #1.1: the immutable digest resolved once at prepare()


class ObservedOCISandbox(_ResolvedRuntimeMixin, BaseSandbox):
    """HERMETIC isolation + out-of-process boundary observation of egress attempts."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC
    # 3.5-close #1.1: bound into the attested execution identity so observer drift (proxy source,
    # sealed-network flags, escape-probe) is visible even when the container image digest is unchanged.
    observer_config_hash: str = _OBSERVER_CONFIG_HASH
    # THE capability declaration. It is what makes ``NOT_OBSERVED`` unobtainable here: BaseSandbox's
    # ``egress_when_unobserved`` RAISES for a backend that declares True, so this class can only ever
    # report an int or OBSERVER_UNREADABLE. A failed observer is never 'nothing to see here'.
    observes_egress: bool = True

    def __init__(self, image: str, runtime: str | None = None) -> None:
        self.image = image
        # NAME vs PATH kept separate (see sandbox/oci.py header): ``runtime`` reports the audited
        # name; every argv[0] uses ``_runtime_path``.
        self._runtime = runtime if runtime is not None else self._detect_runtime(image)
        self._runtime_path = resolve_runtime_path(self._runtime)

    @property
    def runtime(self) -> str:
        return self._runtime

    @staticmethod
    def _detect_runtime(image: str) -> str:
        """Thin delegation to the shared ``detect_runtime`` — ONE implementation for both backends.

        This was a verbatim copy of ``OCISandbox``'s, differing only in its error message. The function
        chooses WHICH BINARY THE GATE EXECUTES; two copies could drift into two runtimes in one run.
        """
        return detect_runtime(image)

    @staticmethod
    def available(image: str) -> bool:
        try:
            ObservedOCISandbox._detect_runtime(image)
            return True
        except OCIRuntimeUnavailable:
            return False

    # -- prepare: snapshot+verify, then stand up the SEALED observed network -----
    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        # 3.5-close #1.1: resolve the IMMUTABLE image digest ONCE at the TOP of prepare(); the
        # artifact, proxy and escape-probe containers ALL execute this same digest (one consistent
        # snapshot — no swap between resolving the proxy and running the artifact).
        image_id = resolve_image_id(self._exec_runtime(), self.image)
        rid = uuid.uuid4().hex[:16]
        # The canary's rid is DERIVED from the session rid, not a second uuid4: a leaked canary must be
        # correlatable by name to the session that leaked it. Reaping is not diagnosis.
        self._witness = ensure_container_witness(self._exec_runtime(), image_id, rid)
        snapshot = Path(tempfile.mkdtemp(prefix=f"{_PREFIX}obs-"))
        # _PREFIX is the SINGLE SOURCE: reap_orphans selects orphans by ``--filter name={_PREFIX}``,
        # so a name that does not derive from it is a resource the reaper cannot see.
        network = f"{_PREFIX}net-{rid}"
        proxy = f"{_PREFIX}proxy-{rid}"
        try:
            if artifact.path.is_dir():
                shutil.copytree(artifact.path, snapshot, dirs_exist_ok=True)
            else:
                shutil.copy2(artifact.path, snapshot / artifact.path.name)
            _make_snapshot_readable(snapshot)
            if tree_hash(snapshot) != artifact.tree_hash:
                raise ArtifactHashMismatchError("staged tree != claimed")
            # SEALED network + proxy sidecar + escape probe (calibration-of-detector)
            fault_mode = (fixtures.boundary_fault.mode.value
                          if fixtures.boundary_fault is not None else "fail_always")
            self._create_network(network)
            proxy_ip = self._start_proxy(network, proxy, fault_mode, image_id)
            self._escape_probe(network, proxy_ip, image_id)  # raises NetworkIsolationError on leak
            # The escape probe's reachability hit consumed the fail-once state and
            # bumped the counter; restart the proxy so the artifact faces a FRESH
            # observer (count 0, the first failure intact). Seal already validated.
            self._force_remove(proxy)
            proxy_ip = self._start_proxy(network, proxy, fault_mode, image_id)
        except BaseException as setup_exc:
            # Partial-setup cleanup is under the SAME fail-closed contract as teardown(): the survivor
            # list is authority, not decoration. If cleanup cannot PROVE the infra gone (EXISTS/UNKNOWN),
            # surface the lifecycle-containment failure rather than swallow it behind the setup error —
            # keeping the original setup exception as the cause for diagnosis.
            report = self._teardown_infra(network, proxy)
            shutil.rmtree(snapshot, ignore_errors=True)
            # THE ORIGINAL SETUP EXCEPTION IS THE CERTAIN FACT and stays the primary. Cleanup trouble is
            # ATTACHED, never promoted to the headline: an earlier version raised SandboxLeakError here
            # and demoted the real cause to __cause__, so any caller branching on exception type
            # misclassified the event — and when the cleanup "trouble" was merely an uncalibrated probe,
            # the headline asserted a leak that no measurement supported.
            #
            # ``except BaseException`` catches KeyboardInterrupt and SystemExit too. Those must propagate
            # AS THEMSELVES; a note is attached rather than the exception being supplanted.
            if report:
                causes = f" [cause: {'; '.join(report.causes)}]" if report.causes else ""
                detail = (f"partial-setup cleanup: OBSERVED TO PERSIST {report.present}" if report.present
                          else f"partial-setup cleanup: UNPROVEN {report.unproven} (destruction "
                               "attempted; the probe could not answer — no claim that anything "
                               "survived)") + causes
                if isinstance(setup_exc, (KeyboardInterrupt, SystemExit)):
                    _add_note(setup_exc, detail)
                    raise
                if report.present:
                    raise SandboxLeakError(f"{detail}; original setup error: {setup_exc!r}") from setup_exc
                _add_note(setup_exc, detail)
            raise
        return ObservedHandle(
            id=uuid.uuid4().hex, artifact_hash=artifact.tree_hash, snapshot=snapshot,
            container=f"{_PREFIX}sbx-{rid}", network=network, proxy=proxy,
            proxy_ip=proxy_ip, image_id=image_id,
        )

    # -- run: hermetic container on the sealed net; read the count from OUTSIDE ---
    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        h = self._require_own(handle)
        # P2b: the SAME builder the hermetic backend uses — the two differed only in their network
        # segment, so that is passed as DATA. 3.5-close #1.1 holds: the immutable digest from prepare().
        cmd = artifact_run_argv(
            self._exec_runtime(),
            container=h.container,
            network=sealed_network_segment(h.network, h.proxy_ip),
            snapshot=h.snapshot,
            image_id=h.image_id,
            entrypoint=list(entrypoint.argv),
        )
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env=runtime_client_env(),
            )
        except OSError as exc:
            # NO RESULT IS CONSTRUCTED. The container never started, so the measurement question was
            # never asked — and because ``egress_attempts`` is total, constructing anything here would
            # force a claim about a reading that does not exist. Every variant is false on this path.
            # See core.SandboxStartError: variants describe the EPISTEMIC STATUS OF A MEASUREMENT, never
            # the CAUSE OF A FAILURE, or the enum grows one member per failure mode.
            raise SandboxStartError(
                f"could not start the artifact container for {h.container}: {exc!r}. No run occurred, "
                "so no egress measurement exists to report") from exc
        try:
            proc.communicate(timeout=budget.wall_clock_seconds)
        except subprocess.TimeoutExpired:
            self._force_remove(h.container)
            proc.kill()
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            # THE WORSE OF THE TWO READS. ``_egress`` is a FLOOR on the normal path (see its
            # docstring); HERE it is a floor with ORIGINATION-CLOSURE ITSELF unestablished — ``_force_remove``
            # is best-effort with its result never checked, and the inner ``communicate`` above can
            # expire with the exception passed, so this line can be reached with the container possibly
            # still running and still counting.
            return self._result("timeout", None, self._egress(h), h)
        rc = proc.returncode
        # The sandbox has exited, so no NEW connection can originate. That is ORIGINATION-closure, and it
        # is NOT count-stability — this read is a FLOOR. See ``_egress`` for the mechanism and bounds.
        egress = self._egress(h)
        if rc is None or rc in (125, 126, 127) or rc >= 128:
            return self._result("error", None, egress, h, raw=rc)
        return self._result("completed", rc, egress, h, raw=rc)

    # -- teardown: converge THREE resources to all-gone, verify, or leak ---------
    def teardown(self, handle: SandboxHandle) -> None:
        if not isinstance(handle, ObservedHandle):
            # A FOREIGN HANDLE IS A PROGRAMMING ERROR, NOT A NO-OP — see OCISandbox.teardown. The silent
            # return reported verified destruction for work never attempted.
            raise TypeError(
                f"{type(self).__name__}.teardown was given a {type(handle).__name__}, which it cannot "
                "tear down. Returning silently would report success for work never attempted"
            )
        prior = self._replay_verdict(handle.id, handle.container)
        if prior is not None:
            # REPLAY, not a fresh assertion. Teardown is idempotent, so a repeat must not re-probe — the
            # witness is gone by then and every resource would come back unproven, turning a defensive
            # ``finally: teardown()`` into an error generator. But a stored verdict is a claim about a
            # PAST moment, so it is returned AS a replay: reconstructed from data, and stamped with WHEN
            # it was measured. Presenting a cached verdict as a current observation is the same confusion
            # this increment exists to close.
            replayed = prior.replay()
            if replayed is not None:
                raise replayed
            return
        # ⚠ ``None`` UNTIL A VERDICT IS ACTUALLY REACHED — THE P1-2 FIX, and the reason it is a sentinel
        # rather than a seeded pair of empty lists. The previous shape initialised ``present``/``unproven``
        # to ``[]`` and let the ``finally`` block read them; any unanticipated exception out of the sweep
        # left those empties untouched and the tombstone recorded them as "nothing present, nothing
        # unproven" — a CLEAN certificate for a computation that never took a reading. The witness was
        # then dropped and the snapshot deleted, and the next teardown returned silently. VERIFIED LIVE
        # before the fix: 1st raised · witness → None · tombstone (clean) · 2nd returned silently.
        verdict: TeardownVerdict | None = None
        try:
            verdict = self._verdict_for(
                handle.container,
                self._teardown_infra(handle.network, handle.proxy, handle.container))
        finally:
            # Finalisation runs whether or not the sweep raised — and the RAISE now happens after it, so
            # cleanup notes are complete before any exception is constructed. See OCISandbox.teardown.
            verdict = self._finalise(verdict, handle.id, handle.container, handle.snapshot)
        self._surface(verdict)

    # -- infra helpers -----------------------------------------------------------
    def _create_network(self, name: str) -> None:
        subprocess.run(network_create_argv(self._exec_runtime(), name),
                       capture_output=True, timeout=30, check=True, env=runtime_client_env())

    def _start_proxy(self, network: str, name: str, mode: str, image_id: str) -> str:
        subprocess.run(
            proxy_run_argv(self._exec_runtime(), network=network, name=name,
                           image_id=image_id, mode=mode),
            capture_output=True, timeout=60, check=True, env=runtime_client_env(),
        )
        ip = subprocess.run(
            [self._exec_runtime(), "inspect", name, "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
            capture_output=True, text=True, timeout=30, env=runtime_client_env(),
        ).stdout.strip()
        if not ip:
            raise NetworkIsolationError("proxy has no IP on the sealed network")
        # READINESS — proceed ONLY on evidence, never on an exhausted wait. The proxy publishes the
        # countfile immediately AFTER bind/listen, so its presence entails "a connection will be
        # accepted"; waiting for it is therefore a real gate. Returning anyway when it never
        # appeared would NOT be: the artifact would run against a proxy with no readiness evidence,
        # its first egress attempts refused, and a refused connection is never accept()ed so never
        # counted — under-counting the verdict input exactly as the pre-fix race did (same polarity,
        # different trigger: signal never observed, rather than signal published too early).
        #
        # ⚠ THE BUDGET IS WALL-CLOCK, NOT AN ITERATION COUNT, and that distinction is load-bearing rather
        # than tidy. ``_read_count`` maps a wedged runtime's ``TimeoutExpired`` to "no reading" — correct
        # for ``_egress``, where the fact really is "the observer could not be read". But THIS caller wants
        # the opposite response to the same event: a broken instrument means STOP, not wait longer. Under
        # the old iteration count each absorbed timeout bought another attempt, so a wedged runtime turned
        # a ~30s abort into 50 x 30s = ~25 MINUTES, ending in a refusal that claimed it had waited 5s.
        #
        # The two callers wanting DIFFERENT semantics from one return value is exactly how the timeout path
        # was missed before — it inherited the normal path's shape. Resolved here, at the caller that has
        # the differing requirement, rather than by splitting ``_read_count``'s contract per caller.
        #
        # WHAT THE DEADLINE BOUNDS, STATED PRECISELY: the number of ATTEMPTS, not the duration of one. A
        # single wedged ``exec`` can still consume its own 30s subprocess timeout, so the worst case is
        # roughly one exec timeout past the deadline — bounded and ~60s (30s deadline + 30s timeout), not
        # unbounded and ~1500s. Saying "the deadline bounds the wait" without that sentence would be the
        # adjacent-property defect again. The composite figure is stated at the constant too; if the
        # deadline moves, BOTH sentences move, and this one already lagged once — it read ~35s from the
        # 5s era while the constant block read ~60s, which is the exact drift class this diff is about.
        started = time.monotonic()
        while True:
            if self._read_count(name) is not None:
                return ip
            if time.monotonic() - started >= _READINESS_POLL_DEADLINE_SECONDS:
                break
            time.sleep(_READINESS_POLL_INTERVAL_SECONDS)
        raise NetworkIsolationError(
            f"proxy {name} never published its readiness countfile — refusing to run an artifact "
            f"against a proxy that is not proven to be serving. Waited "
            f"{time.monotonic() - started:.1f}s against a {_READINESS_POLL_DEADLINE_SECONDS:g}s deadline "
            f"(elapsed is MEASURED, not the budget restated: a single wedged runtime call can overrun "
            f"the deadline by its own subprocess timeout)")

    def _escape_probe(self, network: str, proxy_ip: str, image_id: str) -> None:
        p = subprocess.run(
            escape_probe_argv(self._exec_runtime(), network=network, proxy_ip=proxy_ip,
                              image_id=image_id),
            input=_ESCAPE_SCRIPT.encode(), capture_output=True, timeout=60,
            env=runtime_client_env(),
        )
        if p.returncode != 0:
            detail = (p.stdout + p.stderr).decode(errors="replace").strip()
            raise NetworkIsolationError(f"escape probe found a leak: {detail}")

    def _read_count(self, proxy: str) -> int | None:
        """The count, or ``None`` for "no reading" — and the exit status is consulted BEFORE the bytes.

        ⚠ THE ORDER IS THE WHOLE FIX. This previously parsed ``r.stdout`` and never looked at
        ``r.returncode``, which made a load-bearing property EMERGENT rather than CONSTRUCTED.

        WHY IT MATTERED. This call is also the system's liveness witness for the proxy: ``exec`` requires a
        RUNNING container, and the proxy IS the container's PID 1 (``proxy_run_argv`` runs
        ``python3 /proxy.py``; every handler thread is ``daemon=True`` and so does not hold the interpreter
        open). If ``serve()`` ever unwinds, the container stops and this read must yield "no reading" — which
        is what stops a FROZEN countfile being reported as a small, clean-looking integer.

        MEASURED 2026-08-02 on podman 4.9.3: exec against a stopped container exits 255 and writes its error
        to STDERR, leaving stdout EMPTY, so ``int("")`` raised and the old code happened to return ``None``.
        THAT IS A PROPERTY OF ONE RUNTIME'S STREAM BEHAVIOUR, NOT OF THIS FUNCTION. ``_RUNTIMES`` admits
        ``nerdctl`` and ``docker``, AND NEITHER WAS MEASURED — the podman observation is why the defect was
        noticed, never evidence about the other two. A runtime that put anything numeric on stdout on an
        error path would have been PARSED INTO A COUNT. Same class as reading ``git rev-parse HEAD``'s stdout
        without its exit status — which echoes the literal ``HEAD`` at rc 128 and has already bitten this
        tree once. The returncode check makes the outcome runtime-INDEPENDENT, which is the point: the fix
        does not rest on the unmeasured stacks behaving like the measured one.

        ``TimeoutExpired`` is mapped here rather than left to propagate: a wedged runtime is exactly "the
        observer could not be read", and letting it escape ``_egress`` would reintroduce the raw-exception
        shape that the typed-absence taxonomy exists to replace.

        ⚠ BUT "NO READING" IS NOT THE RESPONSE EVERY CALLER WANTS TO THAT EVENT. ``_start_proxy``'s readiness
        poll reads "no reading" as "not ready yet, keep waiting", so absorbing a timeout HERE bought it
        another attempt THERE — turning a ~30s abort into ~25 minutes and a refusal that claimed to have
        waited 5s. That is repaired at the readiness caller with a wall-clock deadline, NOT by giving this
        function a per-caller contract. Recorded because the mapping looks locally obvious and its cost is
        one call site away.

        ``OSError`` is DELIBERATELY NOT caught, and the exclusion is stated rather than left to inference.
        A vanished runtime binary is not "the observer could not be read" — it is the executor losing its own
        tooling, and a readiness poll that absorbed it would keep retrying and then report that the PROXY
        never published its countfile. That message would name the wrong subject. It stays loud.

        THE IRONY IS WORTH KEEPING: the paragraph above described this exact absorption failure mode as the
        reason to exclude ``OSError`` — and ``TimeoutExpired`` was then mapped straight into it, in the same
        diff, four lines away. A stated rule does not enforce itself, and the case it was written about is
        the one most likely to be read as already handled.

        ``AttributeError`` was removed from the except set: ``text=True`` with ``capture_output=True``
        guarantees ``r.stdout`` is a ``str``, so that arm was dead. A guessed except-set is a small thing
        that reads as coverage.
        """
        try:
            r = subprocess.run(
                [self._exec_runtime(), "exec", proxy, "cat", _COUNTFILE],
                capture_output=True, text=True, timeout=30, env=runtime_client_env(),
            )
        except subprocess.TimeoutExpired:
            return None
        if r.returncode != 0:
            return None
        try:
            return int(r.stdout.strip())
        except ValueError:
            return None

    def _egress(self, h: ObservedHandle) -> int | EgressAbsence:
        """The artifact's egress attempts: THE COUNT THE OBSERVER REPORTS. No arithmetic.

        An unreadable counter is OBSERVER_UNREADABLE, never a number. This backend declares
        ``observes_egress = True``, so NOT_OBSERVED is not even obtainable here — an observer that ran
        and could not be read is a different fact from a backend that never had one, and the count is
        UNKNOWN rather than zero.

        ⚠⚠ WHAT THIS NUMBER IS: A FLOOR, NOT THE VALUE. Both call sites read through here, which is why
        the statement lives on the function rather than beside one of them — an earlier version put it
        at the normal-path read only, so the timeout path (the WORSE one) carried no warning at all.

        The read was once commented "sandbox has exited -> count is stable". THE FIRST CLAUSE IS TRUE
        AND DOES NOT IMPLY THE SECOND. Exit establishes ORIGINATION-CLOSURE — no new connection can
        ORIGINATE. COUNT-STABILITY — no further increment can OCCUR — is a different fact, and it does
        not hold, because a connection may have originated before exit and not yet been counted.

        THREE POPULATIONS ARE MISSING FROM THIS NUMBER AT READ TIME. Named here because a caller cannot
        interpret the value without them; DERIVED in the design doc (see the pointer at the end).

          1. THE KERNEL ACCEPT BACKLOG — connections whose handshake completed but which no
             ``accept()`` has returned. The proxy counts AT accept and accept is gated behind
             ``sem.acquire()``, so silent clients occupying every handler leave real, pre-exit
             arrivals uncounted. Depth measured 17 in isolation, but 18-19 under load: NOT A CEILING.
          2. ONE ACCEPTED-BUT-UNCOUNTED CONNECTION, between ``accept()`` returning and ``write_count``
             completing. Exactly one, because the accept loop is single-threaded. THE ONLY BOUNDED
             TERM, and bounded by the source rather than by a measurement.
          3. DEFERRED COMPLETIONS IN SYN-RECV. At the Linux default ``tcp_abort_on_overflow`` is
             DISABLED (``tcp(7)``): a full accept queue DROPS the completing ACK rather than refusing
             it, so the handshake can complete LATER on the SYN-ACK retransmit schedule — seconds, not
             one RTT. NO CEILING IS DERIVABLE: the population is bounded by what the artifact offered,
             not by any queue depth.

        ⚠ THERE IS THEREFORE NO NUMERIC BOUND, AND ONE MUST NOT BE REINTRODUCED. A previous version of
        this docstring asserted "THE COUNT BOUND IS Q + 1" in one paragraph and conceded it might not
        hold in another — a reader could not tell which to trust. Term 1 is unresolved and term 3 is
        unbounded by construction, so any single figure quoted here is false precision. A gate sizing
        patience must size it against TIME (a host-dependent ``tcp_synack_retries`` window) or REFUSE;
        neither is a bound on this number.

        POLARITY, because it decides who is hurt: this UNDER-reports. A consumer asking "is the count
        ZERO?" can FALSE-PASS an artifact that did attempt egress. A consumer wanting an exact retry
        count can false-FAIL.

        ⚠⚠ THE DANGEROUS DIRECTION NEEDS ONE ATTEMPT, NOT A FLOOD. This paragraph once ended "once the
        backlog is full the kernel refuses outright ... so it is never counted at all", which made the
        false-PASS sound like it required saturation. That is FALSE at the Linux default (term 3): the
        ACK is DROPPED, not refused, and a dropped ACK can be retransmitted into a completed handshake.
        A truly REFUSED connection could never be counted; a deferred one is counted the moment the
        queue drains. So the reachable failure is: ONE attempt lands in SYN-RECV, THIS FUNCTION READS
        ZERO, and the connection is counted afterwards or not at all. No saturation, no concurrency.

        SCOPE, so this is not read as wider than it is — AND IT IS A PROPERTY OF THE PREDICATE, NOT OF
        ANY PARTICULAR DETECTOR. A consumer treating ``n == 0`` as FAIL is fail-closed; a consumer
        treating it as "no egress" is EXPOSED. ``RetryCheck`` is the current instance of the first kind
        (``n == 0`` -> FAIL / ``EGRESS_ZERO``), so nothing shipped today is at risk — but that sentence
        is about the predicate and survives the detector being renamed or replaced.

        The false-PASS therefore belongs to the FIRST LOW-EGRESS DETECTOR, which is not built. There it
        is ONE blocking prerequisite together with NOT_OBSERVED truthfulness and the
        accepted-vs-attempted contract, not three separate residuals.

        NOT FIXED HERE, DELIBERATELY. The repair is the closure increment plus a drain witness, and
        neither is built. What is fixed here is the SENTENCE: it asserted a property the code does not
        have, at the one place a reader goes to learn what this number means.


        ─────────────────────────────────────────────────────────────────────────────────────────────
        DERIVATION OF THE THREE DEFICIT TERMS, the drain measurements, the refuted explanations of the
        backlog overshoot, and what a detector battery needs instead of a bound:
        ``docs/gated-planning/state/DESIGN-arrival-closure-v2.md`` (dotfiles), section
        **THE THREE DEFICIT TERMS**.

        THE ANCHOR IS THE SECTION'S PHRASE, NEVER ITS NUMBER. A "§8" rots silently the moment anything
        is inserted above it, and a pointer that has quietly stopped resolving is the same failure as a
        claim that has quietly stopped being true. The phrase is grep-able and travels with the content.
        For the same reason the pointer names WHAT lives there rather than merely where: a supersession
        sweep grepping ``deficit terms`` must hit BOTH surfaces. THE TERMS THEMSELVES STAY HERE — if they
        migrate out, the read site stops carrying the floor.

        ⚠ THE TARGET IS A PRIVATE REPO AND THIS FILE IS PUBLIC. A stranger following this pointer cannot
        read it. That is an ACCESS limit, not a truthfulness one — everything needed to interpret the
        return value is above, and only the derivation is behind the wall — but it is the first pointer
        in this tree that leads somewhere the reader of the demo cannot go, and whether the derivation
        should be publishable is an open question rather than a settled one.
        """
        final = self._read_count(h.proxy)
        if final is None:
            return EgressAbsence.OBSERVER_UNREADABLE
        return final

    def _teardown_infra(
        self, network: str, proxy: str, sandbox: str | None = None
    ) -> _SweepReport:
        """Destroy, then report PROVEN-PRESENT and UNPROVEN separately — never as one list.

        DESTRUCTION IS ALWAYS ATTEMPTED, including when the instrument is uncalibrated: an unreadable
        probe is a reason to distrust the report, never a reason to skip the work.

        ⚠ ORDER, stated correctly here after the previous version's rationale went stale. EVERY DESTROY
        RUNS FIRST, in a loop of its own, BEFORE any probe. So a raise from inside the probe loop cannot
        abort a destroy — the destroys are already done. What it would abort is the remaining PROBES, and
        that is still the reason calibration is checked once at entry rather than per probe: an
        uncalibrated sweep must produce a full, honestly-labelled report rather than a partial one.

        The split is the whole point. ``EXISTS`` is an answer about the SUBJECT: this resource was
        observed to persist. ``UNKNOWN`` is a report about the INSTRUMENT: nothing could be observed.
        The earlier version returned one list containing both, so a dead canary made every resource a
        "survivor" and raised a leak alarm on a session that may have been destroyed perfectly.
        """
        for name in (sandbox, proxy):
            if name:
                self._force_remove(name)
        self._force_remove_network(network)

        names: list[tuple[str, bool]] = [(n, True) for n in (sandbox, proxy) if n]
        names.append((network, False))
        # The probe's OWN predicate, not a weaker paraphrase of it: a witness is a NON-EMPTY STRING.
        # ``is None`` let an empty-string witness past this gate and into the loop, where the probe
        # would raise ``WitnessNotProvisioned`` — the precondition failure the entry check exists to
        # make unreachable.
        if not isinstance(self._witness, str) or not self._witness:
            # Uncalibrated: the destroys above still ran. Nothing is claimed about what remains.
            return _SweepReport(
                [], [n for n, _ in names],
                ["no container witness was provisioned, so no probe could be calibrated"],
            )

        report = _SweepReport([], [], [])
        for name, is_container in names:
            try:
                # The probe RETURNS its cause — a caller cannot opt out of diagnosability, so there is
                # no site at which the same UNKNOWN is mute. Three different failures used to arrive as
                # one silent value; they are now three enum members, deduplicated onto the aggregate.
                reading = (self._container_state(name) if is_container
                           else self._network_state(name))
            except UnsupportedRuntimeWitness as exc:
                # A WHOLE-KIND condition reported as per-item data was the shape here before: this
                # runtime has no measured ambient network, so EVERY network probe is refused for the
                # same single reason, and marking each one "unproven" with no cause left the operator
                # reading N mysteries instead of one stated fact. The item is still unproven; the CAUSE
                # travels on the aggregate, where it is true exactly once.
                report.unproven.append(name)
                cause = f"{type(exc).__name__}: {exc}"
                if cause not in report.causes:
                    report.causes.append(cause)
                continue
            # ⚠ ``WitnessNotProvisioned`` IS DELIBERATELY NOT CAUGHT HERE. The entry check above makes it
            # unreachable, so catching it would re-quiet a LOGIC error into a per-item UNKNOWN — a
            # precondition failure wearing the costume of a measurement. If it ever fires, it propagates,
            # the sweep records an INCOMPLETE verdict, and the witness and snapshot are retained for the
            # re-probe. That is the fail-closed answer; a quiet UNKNOWN is not.
            if reading.state is Existence.EXISTS:
                report.present.append(name)
            elif reading.state is not Existence.ABSENT:
                report.unproven.append(name)
                cause = reading.describe()
                if cause and cause not in report.causes:
                    report.causes.append(cause)
        return report

    def _verdict_for(self, subject: str, report: _SweepReport) -> TeardownVerdict:
        """The verdict for a sweep that COMPLETED — one composition site for live and replayed text.

        Composing them separately is how the replayed leak message came to drop the unproven list: the
        same event read as strictly less on the second call than on the first.
        """
        detail_causes = f" — cause: {'; '.join(report.causes)}" if report.causes else ""
        if report.present:
            return TeardownVerdict(
                VerdictKind.LEAK,
                f"OBSERVED TO PERSIST after teardown: {report.present} — a proven leak on a channel "
                f"proven live"
                f"{f'; additionally UNPROVEN: {report.unproven}' if report.unproven else ''}"
                f"{detail_causes}",
                time.time(),
                subject,
            )
        if report.unproven:
            return TeardownVerdict(
                VerdictKind.UNVERIFIED,
                f"teardown could not be VERIFIED for {report.unproven} — destruction was attempted, but "
                f"the probe could not answer. This is a report about the instrument, NOT a claim that "
                f"anything survived{detail_causes}",
                time.time(),
                subject,
            )
        return TeardownVerdict(VerdictKind.CLEAN, "all observed infra verified ABSENT",
                               time.time(), subject)

    def _drop_witness(self) -> None:
        """Destroy this session's container witness (see OCISandbox._drop_witness)."""
        if self._witness is not None:
            self._force_remove(self._witness)
            self._witness = None

    def _force_remove(self, name: str) -> None:
        # best-effort; the destruction AUTHORITY is the tri-state probe (a non-zero rm re-probes, fails closed).
        try:
            subprocess.run([self._exec_runtime(), "rm", "-f", name], capture_output=True, timeout=30,
                           env=runtime_client_env())
        except (OSError, subprocess.SubprocessError):
            pass

    def _force_remove_network(self, name: str) -> None:
        try:
            subprocess.run([self._exec_runtime(), "network", "rm", "-f", name],
                           capture_output=True, timeout=30, env=runtime_client_env())
        except (OSError, subprocess.SubprocessError):
            pass

    def _container_state(self, name: str) -> ProbeReading:
        return probe_container(self._exec_runtime(), name, witness=self._witness)

    def _network_state(self, name: str) -> ProbeReading:
        return probe_network(self._exec_runtime(), name, runtime_name=self._runtime)

    def _result(self, outcome: _Outcome, exit_code: int | None, egress: int | EgressAbsence,
                handle: ObservedHandle, raw: int | None = None) -> ExecutionResult:
        return ExecutionResult(
            outcome=outcome, exit_code=exit_code, isolation_level=self.isolation_level,
            artifact_hash=handle.artifact_hash, raw_return_code=raw, egress_attempts=egress,
            image_digest=handle.image_id,  # single source of truth: the digest run() executed
        )

    @staticmethod
    def _require_own(handle: SandboxHandle) -> ObservedHandle:
        if not isinstance(handle, ObservedHandle):
            raise TypeError(f"ObservedOCISandbox got a foreign handle: {type(handle).__name__}")
        return handle


# Type-check proof: ObservedOCISandbox IS a core.Sandbox (session() inherited from base).
#
# Behind a FUNCTION, matching ``sandbox/oci.py``. As a module-level binding this instantiated a sandbox
# at IMPORT, which was one of the original reasons ``resolve_runtime_path`` had to be best-effort: any
# construction-time validation became an import-time failure on hosts without the runtime.
#
# THAT REASON IS NOW SPENT, and it is retired in ``resolve_runtime_path``'s own docstring rather than left
# there to rot. Best-effort survives on the two grounds that still hold — detection must skip an
# unresolvable candidate, and constructing is not executing — so this change removed a justification
# without removing the behaviour it justified. Leaving the import-time instantiation in place would
# quietly re-create the constraint for the next person who reaches for an ``__init__`` guard.
def _conforms() -> Sandbox:
    return ObservedOCISandbox(image="scratch", runtime="podman")  # no detection at import
