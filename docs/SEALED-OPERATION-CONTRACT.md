# The sealed-operation contract

**What a host must actually be able to do for a sealed observed run to happen — and, for each, the
probe that exercises EXACTLY it.**

This exists so that `demo/preflight.py` and the runner conform to *the same written list* rather than
to each other. Without it, preflight probes what its author remembered the runner doing.

Every argv below is **generated from the shipped builders**, not transcribed: the builder is named next
to it so a reader can regenerate the list and catch drift.

---

## 1. The operations

| # | Operation | Argv (from the named builder) |
|---|---|---|
| O1 | create the sealed network | `network create --internal --disable-dns NET` — `network_create_argv` |
| O2 | run a sidecar **attached to that network** | `run -d --network NET --name PROXY --mount …` — `proxy_run_argv` |
| O3 | resolve the sidecar's address | `inspect NAME --format {{…IPAddress}}` |
| O4 | run a container attached to the network **with a static host entry** | `run -i --rm --network NET --add-host health-proxy:IP …` — `escape_probe_argv` |
| O5 | run the artifact, sealed, with a read-only mount and a tmpfs | `run --rm --init --name C --network NET --add-host health-proxy:IP --mount …,readonly,bind-propagation=rprivate --tmpfs /work …` — `artifact_run_argv` |
| O6 | read the counter from **outside** the sandbox | `exec PROXY cat /tmp/mv_egress_count` |
| O7 | create a container **without starting it** (the listing witness) | `create --name CANARY IMG true` — `canary_container_argv` |
| O8 | list containers and networks, unfiltered | `ps -a --format {{.Names}}` · `network ls --format {{.Name}}` — `listing_argv` |
| O9 | destroy containers and networks | `rm -f NAME` · `network rm -f NAME` |

The sealed posture itself is `--internal --disable-dns` plus a per-run `--add-host`, expanded from
`_SEALED_NETWORK_FLAGS` at one site so the attested value and the applied value cannot diverge.

## 2. ⚠ WHICH PROBE — the finding that makes this document necessary

**MEASURED on a disposable VM, 2026-07-31, under an exact denial** (`user.max_net_namespaces=0`,
`user.max_user_namespaces` untouched; in-window `/proc` readings recorded):

| Probe | Result under netns denial |
|---|---|
| **O1 — `network create --internal --disable-dns`** | **rc=0 — SUCCEEDS** |
| `unshare --user` | rc=0 (user namespaces unaffected — the denial is exact) |
| `run --network=host` | rc=0 (no new netns needed) |
| **run attached to the named network** | **rc=126 — refuses** |

**Creating the sealed network is a CONFIG-OBJECT operation. It does not need a network namespace.**
A preflight that creates the network and calls the capability proven would return a **FALSE PASS on
exactly the machine it exists to refuse** — and that was the shape of this project's own first probe
attempt, retired here with its reason on the record.

> **The capability probe is: RUN A CONTAINER ATTACHED TO THE SEALED NETWORK.** Nothing weaker.

### 2.1 And `--network=none` is not good enough either

`detect_runtime`'s existing capability probe is `run --rm --network=none IMG true`
(`capability_probe_argv`). **A correction to a claim made repeatedly in this project's own planning
records, including committed ones: it is NOT true that "nothing in the tree exercises netns creation".
That probe does** — `--network=none` creates a new, empty network namespace, and it was measured
failing (rc=126) under the same denial.

What is true, stated precisely:

1. It exercises **an** netns creation, so the capability is not wholly unprobed; and
2. It fails **closed** but with a **generic** message (`no OCI runtime can run '<image>' hermetically`)
   that neither names the cause nor carries the runtime's verbatim stderr; and
3. It is **adjacent to, not identical with, the sealed operation.** `--network=none` needs an *empty*
   namespace; O2/O4/O5 additionally need **attachment to a named bridge network**. A host missing
   netavark/CNI plugins, or denied bridge creation, would **pass** `--network=none` and **fail** the
   sealed run.

So the preflight probe is O5-shaped, and the value of this document is the distinction between (1) and
(3) — which no amount of reasoning produced, and one denial measured in ten minutes did.

## 3. The refusal contract

For every operation above, a refusal carries:

- **the precondition name** (which operation failed),
- **the probe command**, verbatim,
- **the runtime's stderr**, verbatim,
- a **remediation hint**, where one is mechanically derivable.

**Classify where mechanical; carry raw evidence ALWAYS.** A refusal that only classifies is the
absence-vs-silence defect wearing a label; a refusal that carries evidence stays legible even when its
classification is wrong.

### 3.1 ⚠ Why "classify AND carry" is not belt-and-braces

The measured netns refusal reads, verbatim:

```
Error: creating network namespace for container dc743ac5…:
       failed to create namespace: no space left on device
```

`no space left on device` is `ENOSPC` **from the ucount limit** — not a full disk. An operator handed
that text alone goes to `df` and finds nothing wrong. An operator handed a classification alone
(`netns unavailable`) cannot check the claim. Both, and only both, are actionable.

## 4. Distinguishability at the point of failure — stated, not assumed

| Condition | Distinguishable? |
|---|---|
| runtime binary absent | **YES** — `command -v` |
| runtime too old | **YES** — parse `--version` |
| image absent | **YES** — `image exists`, **per image** |
| rootless misconfigured (subuid/subgid) | **YES if pre-checked**; NO if inferred from stderr |
| **netns capability denied** | **ONLY by attempting O5.** Text varies by version — measured once, on one kernel; treat the string as evidence, never as a matcher |
| disk / quota | PARTIAL |
| SELinux / AppArmor denials | **NO**, not reliably |
| stale name collision | YES — and avoidable with run-scoped names |

## 5. Residue

A crashed run leaves resources behind **by design** — a retained canary is the instrument a re-probe
needs, and destroying it on an unverifiable path is evidence destruction. That is the **gate's**
behaviour and it is deliberate.

Any **caller** running many sealed rows in one invocation therefore accumulates residue, and must
clean up after itself and **report what it removed**. Residue is a precondition *inside* this refusal
contract, not an afterthought: prior-run leftovers are checked, bounded, and named.
