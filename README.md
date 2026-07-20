# gated

![A dense field of marks crossing a single vertical threshold; one red mark stopped exactly at the line](docs/assets/boundary.svg)

**A promotion gate that judges what your code *does*, not what it *says*.**

The reference implementation of the [PBGF Conformance Specification](https://moriapp.dev/pbgf-cs) — a standard for promotion verdicts on machine-produced code.

`gated` executes pull-request code inside a hermetic OCI sandbox, observes its
behaviour at the network boundary, and publishes a required GitHub Check. Code
that violates the accepted runtime invariant cannot merge.

The canonical example: a helper that looks like it retries a failed request but
silently swallows the failure. A reviewer reading the diff sees a retry. A
linter sees valid code. The agent that wrote it will explain, fluently, why it
is correct. `gated` runs it, watches the socket, counts the egress attempts,
and sees the truth.

> **Status:** reference implementation. The complete mechanism runs against real
> Podman and real GitHub — it has blocked real merges end-to-end — and carries a
> tamper-evident, append-only override ledger that records any merge past a
> failing check. This repository is not a plug-and-play production service or a
> security-complete sandbox. Merge-ready ≠ security-complete ≠ live-proven.

## Why runtime, not static

Static analysis reasons about the *text* of a program. Any check that reads
code can be defeated by code written to read one way and run another — and in
agentic workflows, the producer that wrote the code usually wrote the tests
too. `gated` doesn't read the code and doesn't trust the producer's tests: it
runs the artifact under observation and asserts on the **observed boundary
behaviour**. Passing means the behaviour actually happened, not that the
source looked like it would.

## How it works

```text
GitHub webhook
      │
      ▼
durable queue ──▶ policy admission ──▶ hermetic execution
                                           │
                                           ▼
                                  boundary observation
                                           │
                                           ▼
                                PASS / FAIL / ERROR
                                           │
                                           ▼
                              durable publication outbox
                                           │
                                           ▼
                          required GitHub Check + audit ledger
```

The verdict depends only on host-side observations and trusted policy inputs.
**The pull request cannot provide its own policy, fixtures, detector, or
verdict.**

## Core properties

- **Runtime evidence:** assertions evaluate observed behaviour, not source text.
- **Hermetic execution:** the production path uses Podman with sealed
  networking; the only egress is the observed proxy.
- **Fail closed:** `ERROR` — the gate could not cleanly observe — maps to
  GitHub `action_required` and **blocks**. This is the Check-Run surface of
  PBGF-CS's UNATTESTABLE verdict: absence of proof is never a pass. A gate
  that fails open is theatre; `gated` refuses to.
- **Multi-trial unanimity:** N isolated trials (fresh sandbox and network per
  trial). Any `FAIL` fails the verdict — a flaky violation is still a
  violation, so the `FAIL` path short-circuits. `PASS` requires unanimity.
- **Calibration before enforcement:** a detector holds blocking authority only
  after two-sided calibration — it must catch every known-bad fixture *and*
  pass every known-good one.
- **Separated authority:** measurement cannot promote itself into enforcement;
  enablement is a distinct, governed decision.
- **Post-run admission:** results are admitted only if policy, oracle and
  subject identity remain current at admission time.
- **Durable publication:** Check Run updates flow through a transactional,
  retrying outbox; a GitHub outage cannot silently drop a terminal result.

## The override ledger

Branch protection lets an admin merge past a failing required check. `gated`
records that: if a merge went past a non-`PASS` verdict, an **append-only,
hash-chained** record is written — *"the gate verdict was FAIL; the PR merged
anyway."* It records only what the gate itself can attest, never more. Every
merge is then either gate-approved or consciously overridden, with a record.

## Repository layout

- `core/` — shared contracts and value types
- `sandbox/` — subprocess and OCI execution backends
- `observe/` — host-side boundary observation
- `engine/` — trials, aggregation and runtime assertions
- `gate/` — calibration, governance, admission, GitHub App and durable stores
- `cli/` — command-line package
- `tests/` — unit, adversarial and real-Podman tests

See [ARCHITECTURE.md](ARCHITECTURE.md) for trust boundaries, invariants and
known deployment limits, and [COMPLETENESS.md](COMPLETENESS.md) for the
completeness gate every increment passes before it ships.

## Development

Requires Python 3.9 or later.

```bash
git clone https://github.com/<owner>/gated.git
cd gated

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Run the test suite:

```bash
python -W error -m unittest discover -s tests
```

Run the static gates:

```bash
mypy --strict core sandbox engine observe gate cli
ruff check .
python scripts/check-overclaim.py
python scripts/check-sterility.py
```

Tests requiring an OCI runtime self-skip when Podman or the configured test
image is unavailable; the boundary mechanism is exercised in full where one is
present.

## Deployment

The live adapter is in `gate/live_app.py`. A deployment requires:

- a GitHub App with webhook and Checks permissions;
- branch protection requiring the configured Check name;
- Podman and an immutable detector image;
- independently accepted detector-profile and policy identities;
- separate queue, policy, calibration and audit stores;
- protected signing and webhook secrets.

This setup is intentionally not presented as a one-command production install.
Read [ARCHITECTURE.md](ARCHITECTURE.md) before operating the live path.

## Security boundary

`gated` proves the mechanism implemented here; it does not prove the host.

The kernel, OCI runtime, observer, Python process and local key custody remain
trusted. Production hardening requires controls such as isolated detector
processes, externally signed content-addressed artifacts, KMS/HSM-backed keys
and independently managed governance authority.

In particular:

- merge-ready does not mean security-complete;
- security-complete does not mean live-proven;
- identity binding does not attest a compromised host;
- calibration blindness assumes a trusted detector.

The precise claims and residual risks are documented in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Relationship to PBGF-CS

This repository implements the four conformance requirements of
[PBGF-CS](https://moriapp.dev/pbgf-cs) — mechanical tier assignment, two-sided
calibration of blocking authority, bound and preregistered verdicts, and
fail-closed on absence of proof — through the path this repository runs.
Operated as published, on your own evidence, it supports a **Level 1
(self-attested)** conformance posture. Levels 2–3 (enforced separation,
independent attestation) require the deployment hardening described above.

## Licence

Apache-2.0 — see [LICENSE](LICENSE). Everything in this repository is free,
including for commercial production use; [COMMERCIAL.md](COMMERCIAL.md)
describes what is and isn't (spoiler: this repo is entirely free).
