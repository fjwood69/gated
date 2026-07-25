# Commercial licensing

## What is free

Everything in this repository is licensed under **Apache-2.0**, and that grant
is unconditional. You may use, modify, and deploy gated — including
commercially, in production, at any scale — without payment, registration, or
notification. There is no per-seat, per-repo, or per-PR fee for anything in
this repository, and there never will be: Apache-2.0 does not permit us to
charge for it, and we chose the licence knowing that.

This repository is the **reference implementation** of the PBGF Conformance
Specification (https://moriapp.dev/pbgf-cs). It does **not** currently meet all
four §4 requirements — §4.1 (mechanical tier assignment) is not built, and §4.3
preregistration is absent — so it sits **below Level 1**, and running it as
published does not support a Level 1 conformance claim. The per-requirement
status, verified against this tree, is in *Relationship to PBGF-CS* in
[README.md](README.md).

## What is commercial

The commercial offering consists of things that are **not in this
repository**:

1. **Calibrated policy packs** — curated, adversarially maintained corpora of
   known-good/known-bad fixtures and detector configurations for specific
   domains (security, compliance, architecture, migration), pre-validated
   through the calibration ladder and hash-pinned per release. The engine that
   runs them is here and free; the crystallised domain content is licensed.

2. **Enforceability audit** — assessment of an organisation's existing
   standards against the PBGF tier model ("your standards, scored by
   enforceability rung"), with a remediation map.

3. **Enterprise attestation and operation** — supported deployment on your own
   infrastructure, independent calibration ratification, interoperable
   attestation envelopes, and the operational machinery for PBGF-CS Level 2/3
   conformance claims. There is no hosted service: gated runs where your code
   runs, and we do not take custody of your artifacts or your evidence.

Commercial licences for policy packs are offered **per organisation or per
repository band**. They are deliberately **not** metered per promotion or
per-PR: usage metering would require telemetry from the boundary, and a gate
that phones home about every promotion is a worse gate. Terms are by
arrangement; enquiries to the address in *Contact* below.

## The boundary, stated plainly

- If you build your own fixtures and calibrate your own detectors with this
  code: free, forever, no strings.
- If you want the fixtures, calibration, and attestation machinery we
  maintain: that is the product.

Nothing in this file modifies, conditions, or narrows the Apache-2.0 licence
on this repository's contents. If any statement here appears to conflict with
LICENSE, LICENSE wins.

## Trademarks

"gated" and associated marks identify this project and its maintainers.
Apache-2.0 §6 applies: the licence does not grant trademark rights. You may
state truthfully that your deployment uses gated or targets PBGF-CS
conformance; you may not imply certification, endorsement, or that a
deployment is "gated-verified" without a commercial attestation agreement.

## Contact

Commercial enquiries: fredjwood@proton.me
