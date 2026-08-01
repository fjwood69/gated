# Pre-registration: the first live run of `demo/run.py`

**Written and committed BEFORE the run.** Nothing below may be edited to match a result. If the
outcome does not fit a class here, that is a finding about this document, and the correction is
appended with a date — never a rewrite.

## Why pre-register this one

Every part of this runner has been tested in isolation and none of it has met a real runtime. The
first run is a **composition event**: the instrument-identity resolution, the pin↔corpus cross-check,
the per-row seal chain, the sealed sandbox and the boundary counter all execute together for the
first time. Composition is precisely what per-component tests structurally cannot see — a whole
increment of findings this week came from exactly that gap.

The specific hazard is not failure. It is a **legitimate result being read as a broken demo**, and
then "fixed" until it goes quiet. Deciding in advance what each outcome MEANS is the difference
between reading the result and reasoning about it afterwards, when the reasoning is contaminated by
wanting a clean first run.

## The command

```
python -m demo.run --cache ~/.cache/gated-demo --workspace /tmp/gated-demo-firstrun
```

Recorded before the run: `gated` commit, `podman --version`, the resolved image digest, and the
corpus digest `810e2f8f7c07269445fdfa89e2875ce907c091ffe54c8dbbd62c15936978088a`.

⚠ The image digest is recorded in the ENGINE'S form — `sha256:`-prefixed, as `resolve_image_id`
returns it. The first attempt (2026-08-01, exit 3) recorded bare hex from a second resolver that has
since been deleted; a pre-run record in a different format from the sealed one is the same
two-derivations defect displaced one layer out, into the evidence.

## What counts as a SUCCESSFUL first run

The run is a success if the pipeline **reaches a verdict table and every structural invariant holds**
— regardless of the numbers in it.

- [ ] preflight passes, or refuses with its evidence (command + stderr)
- [ ] the corpus fetch verifies both digest layers
- [ ] `read_recorded_counts` parses and the pin↔corpus cross-check passes
- [ ] the instrument names itself: real gate commit, runtime version, image digest — no
      `unknown`/`pending`
- [ ] a run header is sealed BEFORE any row runs
- [ ] all 7 rows produce receipts (5 subjects + zero control + positive control)
- [ ] the seal chain is unbroken: row 1 → header, row N → row N−1
- [ ] `CompletedRun` constructs — exact cardinality 5, exact (member, key) pairs, one corpus digest,
      one nonce
- [ ] the zero control reads **exactly 0** and the positive control reads **exactly 1**
- [ ] the two mutated rows display a diff whose reconstruction equals the derived bytes
- [ ] a VERDICT TABLE renders, and a RUN REPORT is emitted with no verdict column

## ⚠ EXIT 2 (DRIFT) IS A SUCCESSFUL FIRST RUN

**Ruled in advance.** A drift row means the tool did its job: it re-measured a frozen expectation and
found the world disagreeing. It is **the result**, not a defect in the runner, and every structural
invariant above can hold while it fires.

This is the outcome most likely to be misread on first contact as "the demo is broken", and the
misreading has a specific, corrupting repair attached to it — **editing the frozen expectation until
the run goes green**. That repair is banned. If drift fires:

1. the run is recorded as **successful**;
2. the drifting row's number is investigated as a **measurement question** (has the fixture, the
   image, the runtime or the observer changed?);
3. the pin is updated **only** through the ceremony in `pin.py` — a re-measurement, a new corpus
   release, both digest and counts moved in one commit, and a reviewer comparing digests.

## Exit codes, and what each MEANS

| Exit | Class | First-run meaning |
|---:|---|---|
| **0** | AGREEMENT | Success. Every row matched its frozen count. |
| **2** | DRIFT | **Success.** The detector detected. See above. |
| **3** | INSTRUMENT-INVALID | **Neither success nor P1** — see below. The instrument refused; the runner behaved correctly and the run establishes nothing. |
| **4** | PIN-INCONSISTENT | **Not a result.** Two frozen claims contradict; no measurement can settle it. |
| **5** | CORPUS UNAVAILABLE | Transport. Retryable, says nothing about integrity. |
| **6** | CORPUS INTEGRITY | Terminal. The bytes are pinned and their contents are unusable. |
| **1 / traceback** | **UNCLASSIFIED** | **The finding.** A condition escaping the taxonomy — the same defect class as the seal-leak escape. Any occurrence is a P1 regardless of what triggered it. |

## Named failure classes, decided now

### ⚠ EXIT 3 IS NEITHER A SUCCESSFUL RUN NOR A P1 — and that is why it is written down

Exit 2 is named a success and any traceback is named a P1, which leaves exit 3 sitting between them.
An unclassified middle is exactly what gets read generously late at night, and exit 3 is the outcome
most available to a generous reading: the taxonomy WORKED, the refusal was correct, nothing crashed —
so it feels like a pass. It is not.

**Exit 3 means the instrument refused. The runner behaved correctly and the run establishes nothing.**
No verdict table was produced, so no claim was made about any artifact, and NOTHING in the success
checklist above can be ticked on its evidence. The response is to diagnose the instrument and re-run —
never to record the attempt as a first run.

And exit 3 has two very different causes, which must not be conflated:

- **BENIGN** — preflight refused before anything ran (no rootless podman, image absent). The host is
  not ready; the runner is fine. Fix the host, re-run.
- **P1** — the instrument refused *after* rows began: a control mis-reading, an unreadable counter, a
  seal leak, an unnameable header. These say a measurement apparatus that was believed sound is not,
  and they are P1 exactly as listed below.

A single exit code covers both, so the class is decided by WHERE it fired, and the run report names
the stage. Read the stage before deciding which one happened.

**Expected-and-fine, not defects in the runner:**
- exit 3 from preflight on a host without a working rootless podman
- exit 5 if GitHub is unreachable
- exit 2 drift on any row

**P1 if seen — pre-committed so the reaction is not negotiated afterwards:**
- **any traceback / exit 1** — a condition outside the taxonomy
- the zero control reading non-zero, or the positive control reading anything but 1 (either is
  INSTRUMENT-INVALID, and it means no other row's number can be trusted)
- a broken seal chain
- a receipt sealed for a row that did not complete
- `measured` sealed for an unreadable counter
- the verdict table rendering with fewer than 5 subject rows
- a control row sealed `ADMIT` or `BLOCK` rather than `CONTROL`
- `boundary_events` non-empty (the observer records no per-event data; anything there is synthesised)

**Explicitly NOT evidence of anything, in either direction:**
- wall-clock duration
- the run "looking right" in the terminal
- a single clean run — one pass is n=1 against a composition this document exists because nobody has
  observed

## What a first run does NOT establish

- **Not determinism.** That needs repeats; a single run cannot speak to variance.
- **Not the witness contract.** A witness serving a success mid-row is invisible to every probe the
  receipt carries. Closing it needs per-event response codes, which moves `_OBSERVER_CONFIG_HASH` —
  its own increment.
- **Not attestation.** `seal_mode` is SELF-REPORTED. The chain makes tampering *within* a run
  detectable and says nothing about who sealed it or when.
- **Not the retry-engine flake.** Undiagnosed; 5 consecutive green suite runs are absence of
  recurrence, not a root cause.

## Recording

The run's stdout/stderr, the workspace, and every `receipt.json` are kept **whether it passes or
fails** — including the failing artifact if it fails. The last time an unexplained red appeared this
week only the final four lines survived, and the diagnosis died with the rest.


---

## Appended 2026-08-01 — attempt 1 did not become a first run

Exit 3 at stage `[measure]` on row 1, the P1 branch. Cause: this module carried its OWN image
resolver returning bare hex while the sandbox used `resolve_image_id` returning `sha256:`-prefixed —
one image, two derivations, and the comparison read a FORMAT disagreement as "the image changed
mid-run". Zero rows sealed; the taxonomy held; no verdict table.

Per this document, that attempt establishes nothing and is not recorded as a first run. The second
resolver is deleted (not aliased), and the guard that caught it is discharged two-sided so that
fixing the false positive did not remove its ability to fire.

Nothing above was edited to match the result.

## Appended 2026-08-01 — RESULT

Both attempts are recorded here. A pre-registration that records only the run it
accepted never rejected anything, which is the shape it exists to avoid.

**Attempt 1 — `18:10 BST, commit 5ec5433` — EXIT 3, NOT a first run.**
Fired at stage `[measure]` on row 1, the P1 branch. This module carried its own
image resolver returning bare hex while the sandbox used `resolve_image_id`
returning `sha256:`-prefixed: one image, two derivations, and the comparison read
a format disagreement as "the image changed mid-run". Zero rows sealed, nothing
written, taxonomy held. Per this document the attempt establishes nothing, and it
is not recorded as a first run. Artifacts: `/tmp/firstrun/`.

**Attempt 2 — `18:20 BST, commit 18dad77` — EXIT 0, the first run.**
Every checklist item above ticks: preflight, both digest layers, pin↔corpus
cross-check, an instrument that named itself (`sha256:b9943e88…`), a header sealed
before any row, 7 of 7 rows sealed with an unbroken chain, `CompletedRun`
constructed, **zero control read exactly 0 and positive control exactly 1**, both
mutated rows' diffs reproducing their derived bytes, and a verdict table plus a
run report with no verdict column. All five subjects matched their frozen counts
(3, 3, 1, 1, 2) — exit 0, no drift. Artifacts: `/tmp/firstrun2/`.

### What attempt 2 did NOT establish — recorded as prominently as what it did

- **Not determinism.** n=1. The runner has never repeated itself. The
  fifteen-runs-zero-variance figure elsewhere in this project is fixtures through
  the ENGINE, not through this runner, and is the limit most likely to be read as
  already-established because the number exists and is attached to something else.
  Three greens through the full runner path would close it cheaply.
- **Not the witness contract.** A witness serving a success mid-row remains
  invisible to every probe a receipt carries.
- **Not attestation.** `seal_mode` is self-reported; the chain is linkage only.
- **Not the retry-engine flake.** One red in three full-suite runs, never
  reproduced, five subsequent greens banked, root cause unknown — in the engine
  this demo demonstrates.

Nothing above this appendix was edited to match either result.

## Appended 2026-08-01 — the limit this document did not name

`FIRST-RUN.md` pre-registered what a successful RUN meant and said nothing about
HOSTS. Every run recorded here — attempt 1, attempt 2, and the three determinism
repeats — executed on a single machine: podman 4.9.3, Ubuntu 24.04, rootless, one
kernel, one storage configuration.

**n=1 hosts is a distinct limit from n=1 runs**, and repeating the run does not
touch it. Three identical tables from one machine say the runner is deterministic
*there*; they say nothing about a host with a different runtime major version,
storage backend, or namespace limits.

The preflight refusal carries the same gap and it matters more, because it is the
path offered to readers who CANNOT run the demo. It has been exercised against one
deliberately constructed denial on a disposable VM. A control demonstrated against
a failure I chose is not evidence about the failures a stranger's machine
produces — the same one-sided shape as a floor checked in only one direction.

**The cheapest close is a SECOND HOST**, not more runs on this one. A hosted
environment (e.g. Codespaces) would take machine diversity from one to two and
give readers without local podman a path. If it does not work there, that is a
finding worth having before someone else finds it.

Nothing above this appendix was edited.

## Appended 2026-08-01 — the host limit, PARTIALLY closed

A second host now exists. A fresh `git clone` of the public repository at
`b30dfe9` ran to **exit 0** with the frozen counts reproduced, on:

| axis | host 1 | host 2 |
|---|---|---|
| podman | 4.9.3 | **5.8.2** — a major-version boundary |
| base OS | Ubuntu 24.04 | **Fedora** |
| Python | 3.11 | **3.14.5** — newer than any version CI tests |
| containerisation | direct | **nested (container-in-container)** |

⚠ **PARTIALLY closed, and the remaining gap is the one that matters most.** What is
now demonstrated is that the demo reproduces across a podman major version, an
operating system, a Python version and a nesting boundary. What is NOT
demonstrated is **an unaffiliated person on hardware nobody here has touched**.
Host 2 was still this project's machine, this project's podman install, this
project's image staging. Those are the axes that were varied; the *operator* was
not one of them.

Naming the axes rather than the conclusion matters, because the next reader would
otherwise treat machine diversity as done — and for a demo whose whole proposition
is "run it yourself", the untested axis is precisely the stranger.

### Two findings the second host produced

**The preflight refusal fired for an ORDINARY reason.** It refused because the
sandbox image was not staged locally, naming the command, the empty stderr, and
the remediation. Until then that refusal had only been exercised against a denial
constructed for the purpose — a control demonstrated against a failure of its
author's choosing. This is the first time it answered a failure nobody arranged.

**The sealed network is the portability blocker, not the enforcement envelope.**
Under unprivileged nesting, all four of the hardened flags run. What fails is
running a container ON the sealed network: `/dev/net/tun` is absent, so pasta
cannot build the tap device. The control — the sealed network with NO hardened
flags — fails identically, which is what makes the attribution sound rather than
assumed.

**Consequence for any hosted environment offered to readers without local podman:
check `/dev/net/tun` before offering it.** The envelope is not the obstacle; the
network device is.

Nothing above this appendix was edited.
