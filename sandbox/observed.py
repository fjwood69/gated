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

import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from core import (
    ArtifactHashMismatchError,
    ArtifactSpec,
    Command,
    ExecutionResult,
    Fixtures,
    IsolationLevel,
    ResourceBudget,
    Sandbox,
    SandboxHandle,
    SandboxLeakError,
    tree_hash,
)
import shutil

from sandbox.base import BaseSandbox
from sandbox.oci import OCIRuntimeUnavailable, _make_snapshot_readable, _selinux_enforcing
from sandbox.subprocess import _rmtree_resilient

_Outcome = Literal["completed", "timeout", "error"]
_RUNTIMES = ("podman", "nerdctl", "docker")
ARTIFACT_MOUNT = "/artifact"
WORK_DIR = "/work"
PROXY_HOST = "health-proxy"   # the ONE name the artifact resolves (via --add-host)
PROXY_PORT = 8080
_COUNTFILE = "/tmp/mv_egress_count"
_PROXY_SRC = Path(__file__).resolve().parent.parent / "observe" / "proxy.py"

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


_PREFIX = "moriverify-"


def reap_orphans(runtime: str = "podman") -> None:
    """Startup reaper (GLM mandate): force-remove any orphaned gated containers
    and networks by name prefix. RAII covers normal + partial-failure paths, but a
    hard crash of the engine process itself can still orphan resources; run this on
    engine startup for a guaranteed clean slate (no FD/IP-space exhaustion on CI)."""
    def _names(args: list[str]) -> list[str]:
        try:
            return subprocess.run(args, capture_output=True, text=True, timeout=30).stdout.split()
        except (OSError, subprocess.SubprocessError):
            return []
    for c in _names([runtime, "ps", "-a", "--filter", f"name={_PREFIX}", "--format", "{{.Names}}"]):
        subprocess.run([runtime, "rm", "-f", c], capture_output=True, timeout=30)
    for n in _names([runtime, "network", "ls", "--filter", f"name={_PREFIX}", "--format", "{{.Name}}"]):
        subprocess.run([runtime, "network", "rm", "-f", n], capture_output=True, timeout=30)


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
    baseline: int    # proxy count after the escape probe (subtracted from the final)


class ObservedOCISandbox(BaseSandbox):
    """HERMETIC isolation + out-of-process boundary observation of egress attempts."""

    isolation_level: IsolationLevel = IsolationLevel.HERMETIC

    def __init__(self, image: str, runtime: str | None = None) -> None:
        self.image = image
        self._runtime = runtime if runtime is not None else self._detect_runtime(image)

    @property
    def runtime(self) -> str:
        return self._runtime

    @staticmethod
    def _detect_runtime(image: str) -> str:
        for rt in _RUNTIMES:
            if shutil.which(rt) is None:
                continue
            try:
                probe = subprocess.run(
                    [rt, "run", "--rm", "--network=none", image, "true"],
                    capture_output=True, timeout=90,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            if probe.returncode == 0:
                return rt
        raise OCIRuntimeUnavailable(f"no runtime can run '{image}' hermetically")

    @staticmethod
    def available(image: str) -> bool:
        try:
            ObservedOCISandbox._detect_runtime(image)
            return True
        except OCIRuntimeUnavailable:
            return False

    # -- prepare: snapshot+verify, then stand up the SEALED observed network -----
    def prepare(self, artifact: ArtifactSpec, fixtures: Fixtures) -> SandboxHandle:
        snapshot = Path(tempfile.mkdtemp(prefix="moriverify-obs-"))
        rid = uuid.uuid4().hex[:16]
        network = f"moriverify-net-{rid}"
        proxy = f"moriverify-proxy-{rid}"
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
            proxy_ip = self._start_proxy(network, proxy, fault_mode)
            self._escape_probe(network, proxy_ip)  # raises NetworkIsolationError on leak
            # The escape probe's reachability hit consumed the fail-once state and
            # bumped the counter; restart the proxy so the artifact faces a FRESH
            # observer (count 0, the first failure intact). Seal already validated.
            self._force_remove(proxy)
            proxy_ip = self._start_proxy(network, proxy, fault_mode)
            baseline = 0
        except BaseException:
            self._teardown_infra(network, proxy)
            shutil.rmtree(snapshot, ignore_errors=True)
            raise
        return ObservedHandle(
            id=uuid.uuid4().hex, artifact_hash=artifact.tree_hash, snapshot=snapshot,
            container=f"moriverify-sbx-{rid}", network=network, proxy=proxy,
            proxy_ip=proxy_ip, baseline=baseline,
        )

    # -- run: hermetic container on the sealed net; read the count from OUTSIDE ---
    def run(
        self, handle: SandboxHandle, entrypoint: Command, budget: ResourceBudget
    ) -> ExecutionResult:
        h = self._require_own(handle)
        mount = (f"type=bind,source={h.snapshot},target={ARTIFACT_MOUNT},"
                 "readonly,bind-propagation=rprivate")
        if _selinux_enforcing():
            mount += ",relabel=private"
        cmd = [
            self._runtime, "run", "--rm", "--init", "--name", h.container,
            "--network", h.network, "--add-host", f"{PROXY_HOST}:{h.proxy_ip}",
            "--mount", mount, "--tmpfs", WORK_DIR, "--workdir", WORK_DIR,
            self.image, *entrypoint.argv,
        ]
        try:
            proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"},
            )
        except OSError:
            return self._result("error", None, None, h)
        try:
            proc.communicate(timeout=budget.wall_clock_seconds)
        except subprocess.TimeoutExpired:
            self._force_remove(h.container)
            proc.kill()
            try:
                proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                pass
            return self._result("timeout", None, self._egress(h), h)
        rc = proc.returncode
        egress = self._egress(h)  # sandbox has exited -> count is stable
        if rc is None or rc in (125, 126, 127) or rc >= 128:
            return self._result("error", None, egress, h, raw=rc)
        return self._result("completed", rc, egress, h, raw=rc)

    # -- teardown: converge THREE resources to all-gone, verify, or leak ---------
    def teardown(self, handle: SandboxHandle) -> None:
        if not isinstance(handle, ObservedHandle):
            return
        try:
            survivors = self._teardown_infra(handle.network, handle.proxy, handle.container)
            if survivors:
                raise SandboxLeakError(f"survived teardown: {survivors}")
        finally:
            _rmtree_resilient(handle.snapshot)

    # -- infra helpers -----------------------------------------------------------
    def _create_network(self, name: str) -> None:
        subprocess.run([self._runtime, "network", "create", "--internal",
                        "--disable-dns", name], capture_output=True, timeout=30, check=True)

    def _start_proxy(self, network: str, name: str, mode: str) -> str:
        subprocess.run(
            [self._runtime, "run", "-d", "--network", network, "--name", name,
             "--mount", f"type=bind,source={_PROXY_SRC},target=/proxy.py,readonly",
             self.image, "python3", "/proxy.py", str(PROXY_PORT), _COUNTFILE, mode],
            capture_output=True, timeout=60, check=True,
        )
        ip = subprocess.run(
            [self._runtime, "inspect", name, "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        if not ip:
            raise NetworkIsolationError("proxy has no IP on the sealed network")
        # readiness: wait until the proxy has written its count file (it is serving).
        for _ in range(50):
            if self._read_count(name) is not None:
                break
            time.sleep(0.1)
        return ip

    def _escape_probe(self, network: str, proxy_ip: str) -> None:
        p = subprocess.run(
            [self._runtime, "run", "-i", "--rm", "--network", network,
             "--add-host", f"{PROXY_HOST}:{proxy_ip}", self.image, "python3", "-"],
            input=_ESCAPE_SCRIPT.encode(), capture_output=True, timeout=60,
        )
        if p.returncode != 0:
            detail = (p.stdout + p.stderr).decode(errors="replace").strip()
            raise NetworkIsolationError(f"escape probe found a leak: {detail}")

    def _read_count(self, proxy: str) -> int | None:
        r = subprocess.run(
            [self._runtime, "exec", proxy, "cat", _COUNTFILE],
            capture_output=True, text=True, timeout=30,
        )
        try:
            return int(r.stdout.strip())
        except (ValueError, AttributeError):
            return None

    def _egress(self, h: ObservedHandle) -> int | None:
        """Artifact's attempts = final proxy count minus the escape-probe baseline."""
        final = self._read_count(h.proxy)
        return (final - h.baseline) if final is not None else None

    def _teardown_infra(self, network: str, proxy: str, sandbox: str | None = None) -> list[str]:
        for name in (sandbox, proxy):
            if name:
                self._force_remove(name)
        self._force_remove_network(network)
        survivors = [n for n in (sandbox, proxy) if n and self._container_exists(n)]
        if self._network_exists(network):
            survivors.append(network)
        return survivors

    def _force_remove(self, name: str) -> None:
        try:
            subprocess.run([self._runtime, "rm", "-f", name], capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass

    def _force_remove_network(self, name: str) -> None:
        try:
            subprocess.run([self._runtime, "network", "rm", "-f", name],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            pass

    def _container_exists(self, name: str) -> bool:
        try:
            out = subprocess.run(
                [self._runtime, "ps", "-a", "--filter", f"name=^{name}$",
                 "--format", "{{.Names}}"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return name in out.stdout.split()

    def _network_exists(self, name: str) -> bool:
        try:
            out = subprocess.run(
                [self._runtime, "network", "ls", "--filter", f"name=^{name}$",
                 "--format", "{{.Name}}"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False
        return name in out.stdout.split()

    def _result(self, outcome: _Outcome, exit_code: int | None, egress: int | None,
                handle: ObservedHandle, raw: int | None = None) -> ExecutionResult:
        return ExecutionResult(
            outcome=outcome, exit_code=exit_code, isolation_level=self.isolation_level,
            artifact_hash=handle.artifact_hash, raw_return_code=raw, egress_attempts=egress,
        )

    @staticmethod
    def _require_own(handle: SandboxHandle) -> ObservedHandle:
        if not isinstance(handle, ObservedHandle):
            raise TypeError(f"ObservedOCISandbox got a foreign handle: {type(handle).__name__}")
        return handle


_conforms: Sandbox = ObservedOCISandbox(image="scratch", runtime="podman")
