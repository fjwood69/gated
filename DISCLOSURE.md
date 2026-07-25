# DISCLOSURE

## Purpose

This document is a defensive publication. It establishes the conception and
public-disclosure dates of the inventions disclosed here, to serve as prior art
against any later-filed claims by third parties, and to preserve the
maintainers' position with respect to their own filings.

**Conceived and disclosed is not the same as currently implemented.** This
document describes the subject matter as conceived, which is deliberately
broader than what the reference implementation embodies today; disclosure scope
is not an implementation claim, and nothing here should be read as asserting
that a described element is built, complete, or conformant. For what the
reference implementation actually covers — verified per requirement against the
tree, including what is **not** built — see *Relationship to PBGF-CS* in
[README.md](README.md).

## Subject matter

*Items below are conceived subject matter; embodiment status is solely in the
README table.*

The system disclosed here comprises, in combination:

1. **A behavioural verification gate at the promotion boundary** — execution
   of a candidate code artifact in a hermetic, observed container sandbox,
   with the measured behavioural outcome (not producer attestation, static
   form, or reasoning traces) determining whether the artifact is admitted to
   promotion (merge/release/deploy), enforced through a blocking check at the
   version-control boundary.

2. **Earned, revocable detector authority via two-sided adversarial
   calibration** — a detector acquires merge-blocking authority only after
   demonstrably (a) flagging every fixture in a protected known-bad corpus
   and (b) passing every fixture in a protected known-good corpus, where
   protected fixtures are inaccessible to the producer under evaluation;
   authority is bound to a pinned corpus version and lapses on material
   change to detector, environment, or corpus (typestate lifecycle:
   pending → calibrating → enabled → degraded, with governance-ratified
   transitions).

3. **Bound, preregistered, refutation-representable verdicts** — every
   verdict cryptographically bound to artifact digest, detector identity,
   corpus version, policy digest, and execution-environment identity;
   scenario expectations signed and durably persisted before execution;
   admissibility computed as signed-expectation versus signed-observation;
   evidence schema capable of recording any observed outcome under any
   scenario, with fields typed by provenance (configured / captured /
   measured) and explicit signed nulls.

4. **Fail-closed attestability** — a distinct UNATTESTABLE verdict, blocking
   promotion, produced whenever authority, signature verification, input
   freshness, or evidence completeness cannot be established; distinguished
   from both detector FAIL and infrastructure failure, with infrastructure
   failure never admissible as enforcement evidence.

5. **Policy-as-artifact consumption** — externally authored policy (e.g.
   signed OPA bundles) ingested as pinned, signature-verified build-time
   artifacts whose digests are bound into the verdict evidence, rather than
   queried live at decision time; unverifiable or stale bundles routing to
   UNATTESTABLE.

The governing framework and conformance requirements are published at:

- PBGF (framework): https://moriapp.dev/pbgf — published 5 July 2026
- PBGF-CS (conformance specification, draft v0.1):
  https://moriapp.dev/pbgf-cs — published 20 July 2026

## Dates

Every date below is a **git commit date** or a published site-deploy date,
cited to the commit or record it rests on — not a filesystem modification time.

**Conception (per subject-matter item):**

- **Item 5 (policy-as-artifact consumption):** 11 June 2026 — a policy-as-code
  specification, committed as `5fc7a63` in the author's planning repository.
- **Item 1 (behavioural verification gate at the promotion boundary):** first
  reduced to a working demonstration on 6 July 2026 — commit `19e64a8`,
  "runtime-vs-static enforcement — stake-in-the-ground".
- **Items 2, 3 and 4 (two-sided adversarial calibration; bound, preregistered,
  refutation-representable verdicts; fail-closed attestability):** recorded in
  the framework whitepaper, drafted and committed from 16 June 2026 (`9190988`)
  and publicly disclosed on 5 July 2026 (below); reduced to practice in the
  reference implementation from 10 July 2026.

**Reduction to practice:** 10 July 2026 — the initial commit of this
repository, `10ab03e`.

**First public disclosure:**

- **Framework (PBGF):** 5 July 2026 — the Promotion-Boundary framework published
  at https://moriapp.dev/pbgf (site-deploy commit `b012c8f`); a public, dated
  publication teaching subject-matter items 1–4, predating the reference
  implementation.
- **Conformance specification (PBGF-CS, draft v0.1):** 20 July 2026, at
  https://moriapp.dev/pbgf-cs.
- **This repository:** 20 July 2026 — the date it was first made publicly
  accessible, as evidenced by its git history and hosting-platform records.

**Lineage:** conceived within the author's mori programme; the promotion-gate
line of work was under active development by June 2026, and the programme's
agent-memory origins date to 8 April 2026 per its own disclosure, evidenced by
its earliest git history and cross-session state records.

## Evidence of dates

The development record is independently timestamped by, among other things:
the git commit history of this repository (including signed/sealed
checkpoints), continuous-integration run records, and externally hosted
design-decision records maintained contemporaneously with development.

## Author

Fred Wood. This disclosure is made by the author in a personal capacity; the
inventions are personal intellectual property developed on personal time and
equipment.

## Note

This document is a statement of dates and subject matter for prior-art
purposes. It is not a licence (see LICENSE), not a warranty, and not legal
advice. The author reserves all rights not expressly granted by LICENSE,
including the right to pursue patent protection for the subject matter
described above; a patent-attorney consultation is on record as planned.
