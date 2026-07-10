# The completeness gate

A mandatory step in every increment's loop — not a thing to *remember* to ask (which
failed on 2.2), but a required gate no increment closes without.

```
design → /consult → board → build → verify → COMPLETENESS PASS → board-final
```

The completeness pass runs a **fixed set of prompts** (freeform "anything missing?"
gets answered "nope, ship it" — targeted prompts force the real gaps out). Each of the
seven below has caught a real hole in Step 1 or Step 2, so they are the specific
failure classes *this build actually produces*.

## The seven prompts (run every increment)

1. **What can't the fakes/tests structurally exercise?** Concurrency, timing, clock
   skew, real-API semantics, operational-lifecycle edges (uninstall, key-rotation).
   Sequential fakes are blind to interleaving. Name what's untestable-until-live and
   whether the design is correct-*by-construction* under it, or merely untested.
   *(Found: the 2.2 upsert race under concurrent same-SHA delivery.)*
2. **Is any fail-*open* path hiding inside the fail-closed design?** Every "this
   blocks" claim: does it *actually* block, or just look like it? Trace every
   non-PASS / error / timeout / crash path to "does merge get prevented — yes or no."
   *(Found: `ERROR → action_required` — verified via GitHub Docs it DOES block.)*
3. **Does the audit/observability trail have a hole here?** Do this increment's
   security-and-lifecycle events get *recorded*, or does the trail go silent between
   the last audited event and the next? (The NIST/commercial hook.)
   *(Found: the 2.2 lifecycle-transition silence → `LifecycleSink`.)*
4. **What does this increment *assume* that isn't verified?** Every input, every trust
   assumption, every "GitHub does X" — verified or assumed? Which assumptions are
   load-bearing? *(The policy-from-HEAD self-grading class.)*
5. **Is any control trivially defeated by misconfiguration?** Does the security
   property survive an empty / absent / default config, or fail *open* when
   unconfigured? *(Found: the empty-allowlist → reject-all fix.)*
6. **What's the dependency this increment's safety silently rests on?** Is it
   *recorded and gated* (a hard dependency), or assumed-and-forgotten?
   *(The "upsert is safe only via serialisation" class → closed in the store.)*
7. **What did we defer, and is the deferral still safe?** Re-check every "→ later":
   still fail-closed, still pre-deployment-only, still blocked-by-a-hard-dependency?

## Disposition tags (every finding gets one)

- **fix now** — real, cheap, or fail-open.
- **standing invariant** — write to `ARCHITECTURE.md` (the ERROR→hard-block,
  policy-from-base, verdict-from-observation-only class).
- **logged forward → increment N** — with the dependency made **hard**, not "before".
- **declined-with-reasoning** — over-paranoid / no exploitable path; *named*, never
  silently dropped.

## The honesty rule

The pass must produce findings **or** explicitly assert "ran prompts 1–7, here's why
each is clear." **An all-green pass with no reasoning is itself a theatre-of-
verification flag** — prompt 1 (what can't the fakes test) is *never* fully clean in an
against-fakes increment. "Nothing missing" is the signal to look harder, not to relax.
The pass proves it *ran*, not that everything is perfect.
