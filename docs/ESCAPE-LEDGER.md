# Escape ledger

Every entry here is a way a discharge set was **complete on its own terms and blind anyway**. Each was
found from outside the frame that produced it — by a consult, or by a suite the author had not run.

**This file is a gate, not a memory aid.** A discharge is not complete until its record states, for each
entry below, either how it was answered or **"N/A because …"**. Skipping is therefore an act rather than
an omission — which is the only reason a checklist like this survives contact with someone in a hurry.

**When to consult it: while DESIGNING the discharge set, not after it fails.** The entries describe axes
you will not think of, so reading them afterwards is reading them too late.

**Scope of the obligation.** Binding for any change touching the sandbox/probe/witness/teardown family —
specifically anything that alters a **producer of probe inputs** or the **composition of teardown**. Pure
documentation changes are exempt. When in doubt the ceremony is cheap and the escape is not.

---

## E1 — Shape blindness: enumerating known-bad instead of proving known-good

**Found by:** post-build consult, P2a.

A static sweep enumerated one known-bad shape (`head.attr == "_runtime"`) and **skipped everything it did
not recognise** — including `cmd = [...]` then `Popen(cmd)`, which was the shape of *both* sites that
execute as the gate during a verdict. Reverting both to the bare name left the entire suite green.

**Ask of a new discharge set:** does the assertion PROVE a positive property, or enumerate negatives? If
it enumerates, the evasion set is unbounded and the set is a claim.

## E2 — Argument blindness: the control governed the container, not the contents

**Found by:** post-build consult, P2b.

Routing proved the argv *list object* came from a registered builder — and the posture travelled **into**
that builder as an argument, hand-writable at every call site. Ten mutations, all red, none of which
attacked a builder's arguments. `network=["--network=host"]` passed 36 tests.

**Ask:** for every value the control governs, is it checked where it is *used* or only where it is
*assembled*? Mutate the arguments, not only the call.

## E3 — Producer and composition blindness: the lie was in nobody's frame

**Found by:** post-build consult, stdout-interpretation law.

Fifteen mutations across four axes plus per-call-site, all red, tree green on restore — and the defect was
in a **producer of an input** (`ensure_container_witness` returning a name whose creation had failed) and
in the **composition** of three individually-defensible components: one treated `UNKNOWN` as the end of
the story ("fail closed"), the next treated it as the start of a survivor report. Each was discharged
inside its own frame. **The composition was nobody's frame.**

The single mutation that would have caught it: **delete the witness-creation line from `prepare()`.** The
unit tests supplied witnesses directly, so nothing would have reddened — proving that line was dead code
as far as the discharge set was concerned.

**Asks:**
- **Deletion-mutate what you RELY on**, not only what you changed. Every line the increment depends on —
  including lines in files it never textually touched — is part of its semantic diff.
- **Name the guarantor.** Every new invariant has a precondition; the precondition has a guarantor; test
  the guarantor's own failure modes. (Here: law = "ABSENT requires a live control"; precondition = "a
  control exists"; guarantor = `ensure_container_witness`; *its* failures were never discharged.)
- **Cross call sites with producer states** in a matrix. Empty cells are the gap, found by bookkeeping.
- **Vary the construction path** — run the same assertions on a `__new__`-built instance and a normal one.
- **Discharge over the reference closure, not the diff** — run every test file referencing any symbol
  touched *or relied on*.

## E4 — Hit-list blindness: a grep result read as a summary

**Found by:** the full suite, stdout-interpretation law.

A grep for changed symbols listed the file containing five tests of the old signature. The file was
listed and **never opened**, and the increment was reported as having no prior coverage.

**Ask:** a grep hit list is a **checklist**. The discharge is open while any hit lacks a verdict —
*migrated*, *asserted-unchanged*, or *out-of-scope because …*.

**And there is a mechanical answer, which was available and not used.** Call-graph impact analysis, run
on the symbol BEFORE editing it, enumerates the callers rather than the files. Run afterwards on the very
same symbol it reported `Tests` as the **largest directly-affected module — 36 hits, direct, 10 direct
callers**. That is the ranking that would have redirected attention from "the grep listed a file" to "the
test surface is the dominant consumer of this signature". A checklist you read is weaker than a list the
tool computes; use both, and run the analysis before the edit, not after the suite.

⚠ Its blind spots are real and already recorded elsewhere in this project: a call graph cannot see a
coupling that travels through a dynamic read, so a **zero** there is absence of modelling, not absence of
risk. It is a strong instrument for enumerating callers and a vacuous one for content-hash couplings —
which is itself an instance of the standing law about confidence labels.

## E5 — Green-first: a mutation on a red tree carries no information

**Found by:** the board, stdout-interpretation law.

Targeted-green looked like discharge while the full suite was red. On a red tree you cannot distinguish
**mutation-red** from **broken-red**, so every mutation result is uninterpretable.

**Ask:** the FULL suite must be green *before* any mutation is run. Green is a precondition for a
mutation being informative, not a nicety to confirm afterwards.

## E6 — Cross-actor time: the harness varies lines within ONE thread

**Found by:** post-discharge consult, stdout-interpretation law. **Standing and unclosed.**

Fifteen mutations, then fourteen more on a green tree, then eight gap tests — and every one of them
varied a **line of code inside a single thread of a single process**. The witness is a
shared-namespace, **deterministically named**, **deliberately persistent** resource whose lifetime is
governed by actors outside the session's frame: a leaked canary from a dead session, a concurrent
sandbox on the same host, a reaper that selects by prefix, a client-side timeout whose operation
completes daemon-side and is then retried. Interleavings, stale-name collisions and failure-then-retry
are **states no single-line mutation constructs**, so the discharge set could be exhaustive over its
axis and silent about this one. The verdict store is check-then-act with no atomicity.

**And the sharper half.** The one mutation that touched this axis was built *from my own conclusion
that the guard it removed was redundant* — so the harness faithfully tested my error and returned
green. **A mutation cannot catch a belief the author reasoned into it.** Escapes of this shape are
only findable from outside the frame that produced the set: a consult, an integration injection, or an
explicitly constructed collision.

**Asks of every discharge touching this family:**
- Answer E6 explicitly — *how was cross-actor state constructed*, or **"N/A because …"**.
- Name the actors that can touch each resource, and say which are in-frame.
- For any check-then-act, state whether the window is closed, bounded, or accepted.

**Disposition today — ASSERT-AND-ACCEPT, RULED.** The single-writer precondition is **asserted, not
enforced**: no host lockfile is required in this increment, because the reaper is a test/ops utility
that nothing invokes at startup. **An unenforced precondition remains a claim** (rule 1) — naming it
here is the control *for now*, and explicitly not a substitute for enforcement later. The
namesake-adoption path *is* closed in code (see `WitnessNameCollision`), which bounds the hazard
without closing the axis.

**E6 RE-OPENS AS BLOCKING WHEN THE REAPER IS WIRED.** Prefix-not-instance selection plus live canaries
makes single-writer insufficient at that point: enforce it or redesign the selection. A docstring
hazard note is not a gate; this entry is.

---

## Known dual sites — logged, not fixed

**Deferring the work and logging the hazard are different actions.** A deferred refactor with no entry
here is invisible; the ledger is the only artifact that accumulates across increments, and this shape
has now arrived four times. Each was found by review or by a full suite, never by the discharge set
that shipped alongside it.

| # | The two sites | How it was found | State |
|---|---|---|---|
| 1 | Two `run()` argv sites hand-building `cmd = [...]` | P2a consult — reverting both to a bare name left the suite green | CLOSED |
| 2 | `_SEALED_NETWORK_FLAGS` attested-but-restated | review — editing the literals moved the posture, identity unmoved | CLOSED |
| 3 | `_PREFIX` selected-by-reaper vs created-by-backends | review — two strings that happened to agree | CLOSED |
| 4 | **The six-step teardown finalisation protocol, in `OCISandbox` and `ObservedOCISandbox`** | dissent review | **OPEN — refactor deferred** |

**#4 in full.** `_finalise` / `_surface` / `_release_witness` / `_dispose_snapshot` now live on the
mixin, but the *sequence* — crashed-verdict → subject → store → conditional release → dispose → surface —
is written out in both backends. Coordination between two copies of an ordered protocol is the stated
failure attractor: a fix applied to one is a claim about the other (rule 2), and this increment has
already paid that toll twice (the crash-seed mutation went red at one site and green at the other; the
`_exists_` helper was wrong in two files).

**Ask of the next increment touching teardown:** move the sequence itself into the mixin as one method
taking the varying sweep callable, and delete both copies. Until then, **every change to the protocol
must be applied and discharged at BOTH sites in the same commit.**

---

## Standing rules these serve

1. A test that has never been seen to fail is a claim, not a control.
2. A test seen to fail at ONE site is a claim about every other site it claims to cover.
3. A red test is disagreement between test and code, not proof of a defect — establish direction first.
4. An empty result is not a value; a confidence label is not a coverage claim.
5. A discharge set can be exhaustive over the shape you are thinking in and blind to a second axis — and
   that gap is only findable from outside the frame that produced the set.
6. A mutation cannot catch a belief the author reasoned to — the mutation encodes the same belief. A
   harness built on a conclusion tests the conclusion, faithfully, and reports green.
