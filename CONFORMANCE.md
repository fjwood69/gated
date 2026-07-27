# PBGF-CS: the path to Level 1

*`gated`'s statement of its own conformance position. Written 2026-07-27; positions verified at source against `origin/main` = `00cd252`. Anything not verified is marked as such.*

*Specification: [moriapp.dev/pbgf-cs](https://moriapp.dev/pbgf-cs) · how it is governed, and how to propose a change to it: [moriapp.dev/pbgf-cs/governance](https://moriapp.dev/pbgf-cs/governance). The specification and this implementation share an author; that circularity, and what would close it, are stated on the governance page rather than here.*

*This exists because two independent reviewers asked the same question: **if the reference implementation cannot reach Level 1, is the specification implementable?** That question deserves a document rather than an improvised answer.*

---

## 0. The short answer

**Yes — and nothing on the path is a research problem.**

`gated` is currently **below Level 1** on PBGF-CS v0.1. Five requirements-worth of work stand between it and a Level 1 claim. **Four are on the path** — three plumbing or artifact work on machinery that already exists, one a schema change. **The fifth is held deliberately**, pending a question the specification has to answer about itself.

That is the honest test of implementability, and it is the claim this document is for. It is a weaker opening than the one it replaces — an earlier draft said the longest item *had already been executed once, by hand, with the result published*. That was false, and the correction is instructive enough to state here rather than bury: the experiment in question stopped at a **ceiling** and never ran the adversary that would have turned it into a tier assignment. The item is therefore *execute and record*, not *transcribe*. The claim that survives is the one that mattered — none of the four requires solving an unsolved problem.

---

## 1. The prior question: is each requirement necessary?

Before *can it be implemented*, the fairer question is *should it exist*. PBGF-CS is not a set of opinions about good practice — each requirement extracts a measured finding from the framework's ~5,000 runs across 12 models and 8 vendors:

| Requirement | The measurement behind it |
|---|---|
| **§4.1** mechanical tier assignment | 16 realistic team conventions → 9 compiled to a check → **exactly 1 carried a Tier-1 ceiling, and that one was never adversarially tested**. Most of what engineering standards ask for cannot be enforced at the point it matters, so it gets asserted instead and nobody finds out. **The lab then published the ceiling as though it were a measurement** — which is the requirement demonstrating its own necessity on the author's data. |
| **§4.2** two-sided calibration | Instruction-following is inert (11 of 12 model×convention cells indistinguishable from no instruction) and self-report is worthless. A detector that has not demonstrated it catches known-bad *and* passes known-good has not earned authority. **Same experiment, second receipt:** the engine's two-sided test rejected that sole Tier-1 candidate as vacuous — it did not pass on the clean repository — so the corpus contained *no* working transformation-invariant check. Two-sided validation caught the check that would otherwise have been the lab's single success, and nobody read the result. |
| **§4.3** bound and preregistered | The lab's own seal-gate was marked done and never executed. A verdict not bound to what was evaluated, under which detector, in which environment, is a status bit. |
| **§4.4** fail-closed on absence of proof | A grader was rewritten to report SAFE only under audit. If absence of evidence can pass, the gate is theatre. |

**When defending a requirement, cite the receipt, not the reasoning.**

Note what the top two rows now share. §4.1 and §4.2 are both warranted by *the same experiment*, and in both cases the receipt is a failure of this lab's own — a ceiling mistaken for a measurement, and a two-sided rejection that went unread. A requirement whose necessity is demonstrated by its author's own error is better warranted than one demonstrated by a survey of other people's, because the counter-argument *"that would not happen to a careful team"* has already been answered.

---

## 2. What Level 1 requires — and what it does not

**Level 1 — self-attested.** All four §4 requirements met, with evidence chains that exist, are retained, and are queryable, **signed by the gate operator. The operator is trusted for both the evaluation and the record.**

That trust model is deliberate and it matters for implementability: **Level 1 is designed to be reachable by a single team with no external infrastructure.** The work is entirely in the four requirements. If Level 1 is not reachable that way, the specification has failed at its own design intent.

**Level 1 does NOT require** (these are Levels 2 and 3):

- protected fixtures demonstrably outside the producer's reach — L2
- calibration ratification by a party other than the detector's author — L2
- signing keys outside the evaluated workload's trust domain — L2
- crash-durable preregistration — L2
- an interoperable attestation envelope verifiable without operator infrastructure — L3
- execution identity rooted outside the operator — L3
- calibration independently reproducible from a published corpus digest — L3

**Note on "queryable":** Level 1 says the operator can query the record. `gated`'s evidence lives in operator-host stores with no export surface, which satisfies Level 1's letter and fails third-party inspection — but third-party inspection is Level 3 semantics, not a Level 1 requirement. **The export surface is on the roadmap for L3 reasons, not L1 ones.** Stating this precisely matters: conflating the two makes Level 1 look harder than it is.

---

## 3. Current position, per requirement

Verified at source, `0cf9613`.

### §4.1 mechanical tier assignment — **ABSENT**

No per-property tier record exists. No transformation/evasion attempts with outcomes, no classification artifact, no revalidation date. The only `ENFORCEABLE` occurrence in the tree was a `policy_state` comment conflating §4.2 authority with §4.1 property tier — removed 2026-07-25.

**What receipt #6 actually contains — verified against the raw artefacts, 2026-07-27.** Per-convention detail exists: `progress.jsonl` holds 16 records carrying `id`, `check_type`, `tier_ceiling`, `verdict` and the engine's validity result. What is absent is everything §4.1 turns on — **no transformation or evasion attempt, no outcome, no revalidation date**. The tier field that exists is `tier_ceiling`, assigned deterministically from each check's *type*: a **type-level upper bound on what a check could be, not a per-property finding about what it survived**.

**The pipeline exists and was never executed.** `checker.py` implements exactly the §4.1 shape — ceiling 1 with a false negative downgrades to Tier-2; ceiling 1 clean is Tier-1 with a combat log. No combat log and no checker output exists on disk. That is a stronger reason to say *not built* than "no records were kept", and it is a new position for a pattern this project keeps meeting: **a pipeline whose existence lets a reviewer infer that the classification happened.** Nothing was hidden; the code is there, and reading it is what produces the wrong conclusion.

**So §4.1 is not asking implementers to invent a method — the method is written.** What is missing is that it was never run, and no record type exists to hold what it would produce.

### §4.2 two-sided calibration — **DEMONSTRATED**

All five evidence elements present: detector identity by digest; corpus identity **and version as content-addressed digests** (`oracle_head`, `coverage_digest`); environment identity, parent-measured and never self-reported; coverage plus FN/FP/flaky/harness partitions covering both sides; and ratification via `GovernanceApproval` with **two distinct principals, domain-scoped**, enforced at boot.

*Optional tighten: per-fixture outcomes are derivable from coverage plus exhaustive failure partitions rather than recorded individually. Sound provided the partition set is exhaustive — worth confirming.*

### §4.3 bound and preregistered — **PARTIAL**

| Sub-requirement | Position |
|---|---|
| (1) **Bind** | PRESENT on the **calibration/acceptance** path — artifact digest, detector identity and version, corpus version, policy identity, execution-environment identity. **The promotion-verdict path is thinner**: store rows plus a Check Run, not the Ed25519 coordinate-bound envelope. |
| (2) **Preregister** | **ABSENT from `gated`.** See §5 — deliberately held. |
| (3) **Represent refutation** | PRESENT — the schema can record any observable outcome including the falsifying one. |
| (4) **Sign at claim granularity, typed by provenance** | **PARTIAL.** Every field an admissibility decision reads is signed, and evidence not produced is an explicit signed null. But provenance typing is **two-class, enforced structurally** — MEASURED `runtime_subject` feeds the subject digest; `calibration_context` is signed as REPORTED and must not, with a context-isolation test. The spec requires **three** classes (*configured / captured / measured*), and REPORTED coarsens *configured* and *captured* together. Stronger mechanism than a naming convention; does not satisfy the letter. |

### §4.4 fail-closed on absence of proof — **PARTIAL**

The UNATTESTABLE record **names the unestablished element** (ten typed reasons), is distinct from FAIL, and infrastructure failure propagates to WORKER_FAULT rather than being relabelled as a governance outcome. **Freshness bounds are declared for the snapshot input only, not per-input across every consumed input** — so the evidence clause is not fully met.

---

## 4. The path — ordered, with reasons

### Step 1 — §4.3(1): bind the promotion verdict
**Character:** plumbing. The machinery exists and is exercised on the calibration path; this extends it to the path everyone actually hits.

**Why first:** it is the **unconditional** half of §4.3, it is the gap an auditor asks about (*"you can show me the calibration envelope — show me the merge verdict"*), and it does not depend on any unresolved question. It is also the least defensible gap to leave open, because the strongest attestation currently sits on the path nobody uses.

### Step 2 — §4.4: declare freshness bounds per input
**Character:** small, mechanical. Enumerate every consumed input; attach a declared freshness bound to each; route staleness past a bound to UNATTESTABLE, which the mechanism already does for the snapshot input.

**Why second:** cheapest closure on the list, and it prepares for externally supplied policy inputs (OPA bundles), where bundle freshness is a named future input.

### Step 3 — §4.1: execute the pipeline and record
**Character:** running an existing, preserved pipeline and recording what it returns — not a discovery, and not a transcription either.

Per enforced property, emit a signed record carrying: the candidate deterministic check attempted; the transformation and evasion attempts **with their outcomes**; the resulting classification (ENFORCEABLE / VERIFIABLE-AT-PROMOTION / ADVISABLE); the ratification date; and the **revalidation due date**.

**Not a backfill.** An earlier draft of this document said receipt #6 already contained the inputs for sixteen records, and that the work was to give an existing experiment a schema. That was wrong: the measurement stopped at the ceiling, and the outcomes §4.1 needs were never produced. Nor is it a cold start — the corpus (`corpus.jsonl`), the maker inputs (`inputs_real.jsonl`), the check engine and the adversarial checker are all preserved and runnable. **The job is to run the adversary over the 16-convention corpus, record per-property outcomes, and decide a revalidation policy that does not exist in any form.**

**Sequencing inside the step: red-team the graph cycle first.** It is one check, and it decides whether Tier-1 on that corpus is one or zero before the other fifteen are worth touching. Two things must be resolved together: the engine already recorded that check as **vacuous** — it does not pass on a clean repository — so the implementation needs fixing before an adversary tells you anything about the *concept*. A cycle may well be transformation-invariant; the emitted check was not a working check. Both outcomes are publishable. Only one of them is currently claimed anywhere.

**Why third rather than first:** steps 1 and 2 are cheap and unblock nothing else. But note it is also the one with the most *external* value — the resulting records are publishable material nobody else has: which properties were attempted, exactly how each was defeated, and why each sits where it does. That value survives the correction intact; what changed is that the records have to be *earned* rather than transcribed.

**Do not skip the revalidation date.** ENFORCEABLE decays: "transformation-invariant" means *transformation-invariant relative to adversary capability level C*, and C rises with each model generation. A property genuinely enforceable in June can be advisable by December with no policy change and no notification. The revalidation field is what makes the buyer question answerable — *where is your proof, and when was it last revalidated against the current model generation?*

### Step 4 — §4.3(4): split REPORTED into configured and captured
**Character:** schema change, therefore a board cycle and a migration.

The mechanism is already stronger than the spec requires in *enforcement*; it is coarser in *vocabulary*. Splitting REPORTED restores the three-class distinction without weakening the structural isolation.

**Explicitly rejected: amending the specification to describe two-class typing as sufficient.** That would be loosening a requirement from friction — on the requirement that governs loosening. If the three-class distinction turns out to be unnecessary, that case is made in public under §8, not by an author quietly widening his own spec to fit his own code.

---

## 5. What is deliberately **not** on the path, and why

### §4.3(2) preregistration — HELD, pending a specification question

The requirement reads: *"Preregister the expectation **where the evaluation is scenario-based.**"*

That conditional is doing real work. Calibration against a sealed fixture set with known ground-truth labels **is** scenario-based, and the labels sealed before the run are the pre-committed expectation. A promotion verdict on an artifact nobody has seen before arguably **is not** scenario-based — there is no prediction to preregister, because the point is that the outcome is unknown.

If that reading holds, §4.3(2) does not attach to the promotion-verdict path, and gated's position improves without a line of code.

**I am not taking that reading.** The strict interpretation is published in the README, deliberately, because *the specification's own author should not raise his implementation's score by reinterpreting his own conditional* — that is the shape of loosening a requirement from friction, however sound the textual argument.

**So the conditional is raised as a §8 clarification question, to be examined at arm's length. Until it is settled, preregistration is not built** — because building the wrong mechanism is worse than the gap, and because a mechanism built to satisfy a requirement that does not attach is exactly the built-not-bound pattern this project keeps catching in other people's work and its own.

**Implementability note, and it matters for the question this document answers:** preregistration is **already implemented** — in `gated-uat`, whose signed manifest commits the complete denominator before any cell executes. So *"§4.3(2) is absent from gated"* does not mean the requirement is unsatisfiable. It means one tree has it and the other has not needed it yet.

---

## 6. Effort shape

Hours are not offered, because an honest estimate needs the person who will do the work. The *shape* is more useful:

| Step | Shape | Blocked on |
|---|---|---|
| §4.3(1) promotion-verdict binding | Plumbing — extend existing machinery to a second path | Nothing |
| §4.4 per-input freshness | Small and mechanical — enumerate, attach, route | Nothing |
| §4.1 execute + record | Execute an existing, preserved pipeline; record outcomes; author a revalidation policy. Not transcription, not a cold start | Nothing |
| §4.3(4) three-class typing | Schema change → board cycle + migration | Nothing |
| §4.3(2) preregistration | **Held** | A specification clarification, not code |

**Nothing on this path is a research problem.** That is the answer to *is the specification implementable*, and it is falsifiable: if any of the four turns out to require an unsolved problem, that is a finding about the specification and it will be published as one.

---

## 7. After Level 1

Stated so the ladder's shape is visible, not as a commitment:

**Level 2** adds enforced fixture separation (⚠ currently **failed** — publishing the repository made the corpus producer-readable, so ecological runs will need held-back fixtures), ratification by a party other than the detector's author (satisfied in-process today; whether in-process separation meets L2's intent is itself worth a clarification question), signing keys outside the evaluated workload's trust domain (not evidenced — in-process signing is a documented reference limit), and crash-durable preregistration (already demonstrated in `gated-uat`).

**Level 3** adds an interoperable envelope verifiable without operator infrastructure (a projector over `gated-uat`'s published record exists; `gated` itself emits none), execution identity rooted outside the operator, and calibration independently reproducible from a published corpus digest.

**One honest note about Level 3.** Some of it cannot be closed by a single operator at all — an append-only local record cannot testify to its own truncation, and a timestamp on a truncated head is still a timestamp. Closing it requires an integrity witness the operator does not control. That is a property of the problem, not a gap in the implementation, and any Level 3 claim that does not rest on such a witness should be disbelieved — including this project's.

*That paragraph was written from principle. It now has a receipt.* Adversarial review of `gated`'s own override ledger — the hash-chained record of every merge that landed on a non-`PASS` verdict — established the same conclusion against real code, and sharpened it. `verify_chain()` answers *has this been altered*, never *is this all of it*: **deleting every row from a populated ledger leaves it returning true**, measured against the recovered production file rather than reasoned about. The host that holds the ledger also holds any credential that could rewrite a checkpoint it publishes, so a locally-anchored checkpoint constrains nothing. And **an RFC-3161 timestamp alone is insufficient for a specific reason** — a host that has truncated simply timestamps the truncated head, which is why "add a TSA" reads like closure and is not. What is required is a transparency-log-shaped witness (Rekor, Trillian, a SCITT transparency service). `gated`'s stated limits now carry this; the finding is recorded there rather than only here.

---

## 8. Why this document exists

Two reviewers, independently, asked whether a specification its own author cannot satisfy is implementable. It is a fair question and the fair answer is a path, not a defence.

The path is four items. One is running a pipeline that already exists and recording what it returns. Two are plumbing. One is a schema change. **A fifth is held** pending a question the specification has to answer about itself, and is already implemented elsewhere.

This document has itself been corrected once, on 2026-07-27, in the direction that made it weaker: the §4.1 item was described as a backfill of an experiment already run, and it is not. The correction is left visible rather than smoothed away, because a path document that quietly improves its own position is worth exactly as much as a gate that grades its own homework.

**A specification an author cannot immediately pass is evidence the specification has teeth. A specification nobody can pass is dead.** This document exists so the difference is checkable rather than asserted — and so that if the path turns out to be wrong, it is wrong in public.

*Feedback is invited, particularly evidence that any step here is harder than it is stated to be.*
