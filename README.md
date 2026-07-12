# gated

**A promotion gate that judges what your code *does*, not what it *says*.**

`gated` runs a pull request's code in a hermetic sandbox, **observes its behaviour at the
boundary** (what it sends over the network, not what the source appears to do), and — as a
GitHub Check — **blocks the merge** when the code violates the invariant. It catches the
class of defect static review structurally cannot: code that reads as correct but *behaves*
otherwise.

The canonical example: a helper that looks like it retries a failed request but silently
swallows the failure. A reviewer reading the diff sees a retry. A linter sees valid code.
`gated` runs it, watches the socket, counts the egress attempts, and sees the truth.

## Why runtime, not static

Static analysis reasons about the *text* of a program. Any check that reads code can be
defeated by code written to read one way and run another. `gated` doesn't read the code — it
runs it under observation and asserts on the **observed boundary behaviour**. The invariant
is checked against reality, so passing it means the behaviour actually happened, not that the
source looked like it would.

This is a narrower, stronger claim than "we analysed your code": it's "we ran your code and
watched what it did."

## How it works

```
webhook ─▶ receiver ─▶ durable queue ─▶ hermetic sandbox ─▶ boundary observation ─▶ verdict ─▶ Check Run ─▶ branch protection
 (HMAC)     (fail-closed)  (SQLite)        (OCI / podman)      (egress proxy)         (PASS/FAIL/ERROR)         (blocks the merge)
```

| Layer | Package | What it is |
|-------|---------|-----------|
| **Contracts** | `core/` | The `Sandbox`, `RuntimeAssertion`, `Verdict` protocols + the artifact hash. |
| **Isolation** | `sandbox/` | Swappable backends: `subprocess` (WEAK) and `oci` (HERMETIC — podman, no network except the observed proxy). |
| **Observation** | `observe/` | The boundary proxy that counts what the artifact attempts over the wire. |
| **Judgement** | `engine/` | Multi-trial runner: N isolated trials, **unanimity** aggregation, first-fail short-circuit. |
| **The gate** | `gate/` | The GitHub App: webhook receiver, durable executor + watchdog, Check Run lifecycle, and the **override ledger**. |

### Fail-closed by construction

A verdict is `PASS`, `FAIL`, or `ERROR`. `ERROR` (the gate couldn't cleanly observe) maps to
GitHub's `action_required` — it **blocks**. A promotion gate that fails *open* — that lets a
merge through when it couldn't verify — is theatre. `gated` refuses to.

### Multi-trial unanimity

Behaviour can be non-deterministic. The engine runs N isolated trials (a fresh
sandbox + network per trial) and aggregates: any `FAIL` → `FAIL` (a flaky violation is still
a violation); `ERROR` only when no trial could be observed; `PASS` only on unanimous pass.
The `FAIL` path short-circuits (a unanimous `FAIL` is unrescuable), which is a pure latency
win — toggle it off to gather full distributions.

### The override ledger

Branch protection lets an admin merge past a failing required check. `gated` records that:
on a merge, it reads the recorded verdict for the merged commit and, if the merge went past a
non-`PASS` verdict, appends a **tamper-evident** (hash-chained), **append-only** record —
*"the gate verdict was FAIL; the PR merged anyway."* It records only what the gate itself can
attest, never more. Every merge is now either gate-approved or consciously-overridden-with-a-
record.

## Quickstart

```bash
# One vetted security dependency: PyNaCl (libsodium Ed25519 — one does not roll one's own crypto).
pip install "pynacl==1.5.0"
# Run the test suite.
python -m unittest discover -s tests -v
```

The sandbox/boundary tests self-skip if no OCI runtime (podman) or image is available, so the
suite is green on any machine; the boundary mechanism is exercised in full against real
podman where one is present.

Deploying the gate as a GitHub App (webhook config, App permissions, branch protection) is
documented in [`ARCHITECTURE.md`](ARCHITECTURE.md).

## Design & rigour

- **One vetted security dependency** — the core is otherwise stdlib-only; the single exception is
  **PyNaCl** (libsodium Ed25519) on the signing path, because one does not roll one's own crypto.
- **`mypy --strict`** across every package, `ruff`-clean.
- **`ARCHITECTURE.md`** — the layered design, trust boundaries, and the open-core boundary.
- **`COMPLETENESS.md`** — the seven-prompt completeness gate every increment passes before it
  ships (the discipline that keeps "looks done" from masquerading as "is done").

## Status

**Reference implementation — in-process mechanism, not security-complete.** The
boundary-observation mechanism is verified end-to-end on real podman, and the gate has **blocked
real merges on real GitHub** — including a **pull request from a fork** (untrusted cross-repo code):
the gate fetches the fork's code by its immutable commit SHA, runs it under observation, and blocks
the merge on a violation. It also records an **admin override** of a failing gate in a tamper-evident
audit ledger.

**Calibration mode** — the two-sided calibrator (a detector must catch every known-bad *and* pass
every known-good), a blind-holdout acceptance anchor, and separated measurement/governance
authorities — is **built and exercised on real podman**. It is a *reference*: as [`ARCHITECTURE.md`](ARCHITECTURE.md)
sets out, its blindness holds only under the **trusted-detector model** (the verdict side-channel
makes in-process blindness against author-supplied detectors impossible), signing is a seam for a
**KMS/HSM**, and the stores are in-memory references for an external content-addressed one. Read
"proven" as *proven through the path this repo runs* — **merge-ready ≠ security-complete ≠
live-proven**. It is **not production-integrated and not upgrade-safe**.

## Licence

Apache-2.0 — see [`LICENSE`](LICENSE).
