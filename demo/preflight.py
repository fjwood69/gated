"""Can this host actually run a sealed observed run? Refuse LEGIBLY if not.

An ORDERED capability chain, cheapest and most-specific first, so the refusal names the earliest
thing that is actually wrong rather than the last thing to fail.

⚠ THE PROBE THAT MATTERS IS THE ONE MOST PEOPLE WOULD NOT WRITE, and this is measured, not reasoned.
Under a real netns denial (`user.max_net_namespaces=0`, measured on a disposable VM):

    podman network create --internal --disable-dns   ->  rc=0, SUCCEEDS
    run a container ATTACHED to that network         ->  rc=126, refuses

Creating the sealed network is a CONFIG-OBJECT operation and needs no network namespace at all. A
preflight that creates the network and calls the capability proven would return a FALSE PASS on
precisely the machine it exists to refuse — and that was this project's own first probe attempt.

`--network=none` is not sufficient either. It creates an EMPTY namespace, so it fails under the same
denial, but it is ADJACENT to the sealed operation rather than identical: the sealed run also needs
ATTACHMENT TO A NAMED BRIDGE NETWORK. A host missing netavark, or denied bridge creation, passes
`--network=none` and fails the real thing.

    THE CAPABILITY PROBE IS: RUN A CONTAINER ATTACHED TO A REAL SEALED NETWORK. Nothing weaker.

REFUSAL CONTRACT: every refusal carries the precondition name, the exact command, the runtime's
VERBATIM stderr, and a remediation hint where one is mechanically derivable. Classification is
best-effort; EVIDENCE IS ALWAYS CARRIED. A refusal that only classifies is the absence-vs-silence
defect wearing a label — and the real netns refusal reads `no space left on device`, which is ENOSPC
from a ucount limit, not a full disk. An operator given that text alone goes to `df`; one given a
classification alone cannot check it. Both, or the refusal is not actionable.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid
from dataclasses import dataclass, field

# The sealed posture, restated here ONLY as the thing the probe must exercise. It is deliberately the
# same shape the engine uses; the sealed-operation contract (docs/SEALED-OPERATION-CONTRACT.md) is
# the written list both this and the runner conform to.
SEALED_FLAGS = ("--internal", "--disable-dns")
PROBE_TIMEOUT = 120


@dataclass
class Refusal:
    """Why the host cannot run the demo — with the evidence, always."""

    precondition: str
    command: str
    stderr: str
    hint: str = ""

    def render(self) -> str:
        lines = [f"PREFLIGHT REFUSED: {self.precondition}",
                 f"  command : {self.command}"]
        if self.stderr.strip():
            for ln in self.stderr.strip().splitlines():
                lines.append(f"  stderr  | {ln}")
        else:
            lines.append("  stderr  | <empty — the command produced no diagnostic>")
        if self.hint:
            lines.append(f"  hint    : {self.hint}")
        return "\n".join(lines)


@dataclass
class PreflightReport:
    passed: list[str] = field(default_factory=list)
    refusal: Refusal | None = None

    def ok(self) -> bool:
        return self.refusal is None


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, timeout=PROBE_TIMEOUT)


def check(runtime: str = "podman", image: str = "docker.io/library/python:3.11-alpine") -> PreflightReport:
    """Walk the chain. Stops at the FIRST failure — later probes would only report consequences."""
    report = PreflightReport()

    # 1 — the binary. Distinguishable with certainty, and the cheapest possible check.
    path = shutil.which(runtime)
    if path is None:
        report.refusal = Refusal(
            f"the container runtime {runtime!r} is not on PATH",
            f"command -v {runtime}", "",
            f"install {runtime}, or pass a runtime that is installed")
        return report
    report.passed.append(f"runtime present: {path}")

    # 2 — it answers. A binary that exists but cannot run is a different fault from one that is absent.
    version = _run([runtime, "--version"])
    if version.returncode != 0:
        report.refusal = Refusal(
            f"{runtime} is installed but did not answer --version",
            f"{runtime} --version", version.stderr,
            "the client may be broken, or its storage/config may be unreadable")
        return report
    report.passed.append(version.stdout.strip() or "runtime answered --version")

    # 3 — the image, PER IMAGE. Named separately because "some image is missing" is not actionable.
    present = _run([runtime, "image", "exists", image])
    if present.returncode != 0:
        report.refusal = Refusal(
            f"the sandbox image {image!r} is not present locally",
            f"{runtime} image exists {image}", present.stderr,
            f"`{runtime} pull {image}` on a networked host, or `{runtime} load` a checksummed "
            "tarball on an air-gapped one. Staging is a PRECONDITION, not part of the demo's timing")
        return report
    report.passed.append(f"image present: {image}")

    # 4 — THE CAPABILITY PROBE. Everything above is preparation; this is the one that decides.
    #
    # It creates a REAL sealed network and RUNS A CONTAINER ATTACHED TO IT, because that is the
    # operation the demo actually performs. Creating the network alone is measured to SUCCEED under a
    # netns denial, so a probe that stopped there would pass and then the demo would fail.
    net = f"gated-preflight-{uuid.uuid4().hex[:12]}"
    created = _run([runtime, "network", "create", *SEALED_FLAGS, net])
    if created.returncode != 0:
        report.refusal = Refusal(
            "the sealed network could not be created",
            f"{runtime} network create {' '.join(SEALED_FLAGS)} {net}", created.stderr,
            "this is a NETWORK-OBJECT failure, which is a different fault from the namespace "
            "capability checked next")
        return report
    try:
        attached = _run([runtime, "run", "--rm", "--network", net, image, "true"])
        if attached.returncode != 0:
            report.refusal = Refusal(
                "a container could not be ATTACHED to the sealed network — this is the operation the "
                "demo requires, and note that creating the network above SUCCEEDED",
                f"{runtime} run --rm --network {net} {image} true", attached.stderr,
                "if the stderr mentions a network namespace or 'no space left on device', that is "
                "usually ENOSPC from the user.max_net_namespaces ucount limit rather than a full "
                "disk: check `cat /proc/sys/user/max_net_namespaces`. Rootless container hosts also "
                "need subuid/subgid mappings and a working netavark/CNI plugin")
            return report
    finally:
        # Best-effort, and it must not mask the finding: a cleanup failure is not the subject.
        _run([runtime, "network", "rm", "-f", net])

    report.passed.append("a container attached to a sealed network and ran (the real capability)")
    return report
