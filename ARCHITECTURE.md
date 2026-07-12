# gated — architecture

The enforcement engine for the Promotion-Boundary Governance Framework
([moriapp.dev/pbgf](https://moriapp.dev/pbgf)). Everything in this tree is the
**open Apache core**.

> ## Scope — a reference implementation, not a finished product
>
> This tree proves the **mechanism** of a runtime promotion gate: a hermetic sandbox +
> host-side out-of-band boundary observation + a calibration/acceptance spine with
> separated authorities. The mechanism is exercised end-to-end on **real podman and real
> GitHub**, and that is exactly what "proven" means here — *proven through the deployed
> path this repo runs*, not *proven secure in every deployment*.
>
> It is an **in-process reference implementation and is NOT security-complete.** Several
> controls are structural seams a real deployment must harden, not finished guarantees:
> signing is a `Signer`/`Verifier` seam that must be backed by a **KMS/HSM** (the in-process
> seed is reference-only); the calibration **verdict side-channel** is only closed by running
> each detector in its **own container with aggregate-only output** (see the trusted-detector
> invariant below); the detector/artifact/holdout stores are in-memory references for an
> external **content-addressed, signed** store. It is **not production-integrated and not
> upgrade-safe** — schemas and APIs may change with no migration path.
>
> Three distinct bars, kept separate throughout: **merge-ready ≠ security-complete ≠
> live-proven.** The security engineering rules near the end of this document say which
> claims are which.

## Layers

| Layer | Role | Lands |
|-------|------|-------|
| `core/`    | **Contracts** — interfaces + value types everything depends on (the standard). Changes rarely; changes break things. | 1.1 ✓ |
| `sandbox/` | **Implementations** of `core.Sandbox` — the swappable isolation backends. | 1.2 subprocess/WEAK · 1.3 oci/HERMETIC · microvm deferred |
| `engine/`  | **Orchestration** — uses the contracts + a backend to run checks (select backend, run trials, multi-trial/unanimity, emit Verdict). | 1.5 |
| `observe/` | **Boundary observation** — host-side flow counting (conntrack/eBPF/veth). | 1.4 |
| `gate/`    | **The Promotion Gate** — binds the verdict at the GitHub merge boundary (webhook trust boundary, Check Run semantics). Harness-agnostic core; GitHub App = first adapter. | 2.1 webhook+HMAC · 2.2 Check Run lifecycle · 2.3 executor · later |
| `cli/`     | **`mori-verify` entry point** — thin wrapper. | later |

## Placement rule — one question decides where a file goes

- Is it an interface or value type everything depends on? → **`core/`**
  (`Sandbox` Protocol, `IsolationLevel`, `ResourceBudget`, `ExecutionResult`,
  `ArtifactSpec`, and later the `RuntimeAssertion` Protocol and `Verdict`).
  Changes rarely; changes break things.
- Is it a backend that implements `core.Sandbox`? → **`sandbox/`**
  (`subprocess.py` = WEAK, `oci.py` = HERMETIC, `microvm.py` = deferred). Many;
  swappable.
- Is it logic that uses the contracts to actually run a check? → **`engine/`**
  (select backend, run trials, apply multi-trial/unanimity, emit `Verdict`).

## The load-bearing invariant — verdict is out-of-band only

**A verdict may depend ONLY on out-of-band observation the artifact cannot write —
the process exit code and (from 1.4) host-side boundary telemetry. It must NEVER
depend on anything the artifact itself produced** (files it wrote, a tmpfs it
scratched to, stdout it emitted). Any channel from artifact → verdict lets the
artifact grade its own homework — the theatre-of-verification the whole framework
exists to kill. Concretely: the HERMETIC output `tmpfs` is scratch/audit only; no
grader may parse it. This is why `ExecutionResult` carries no untyped `metadata`
dict and no artifact-written fields. It is a standing rule across every increment,
not a 1.3 note.

## The load-bearing invariant — the judged cannot control the judging

**Only the CODE-UNDER-TEST comes from the PR `HEAD` (the mutable, untrusted
artifact). Everything that DEFINES or PERFORMS the judgement — policy definitions,
check / `RuntimeAssertion` selection, fixtures, and calibration / known-bad data —
MUST come from the protected base ref (or an external immutable source the PR cannot
touch), NEVER from the PR `HEAD`.** If the artifact under test can edit the policy
that judges it, it grades its own homework — the same defeat as an artifact writing
its own verdict (the grader-rewrite), one layer up. This is the same principle as the
out-of-band-observation invariant above: *the thing being judged cannot control the
judging.* It applies to EVERY increment that reads anything — 2.3's `ArtifactSpec`
builder bifurcates code (`HEAD`) from policy (base ref); no later increment reads
policy / checks / fixtures / calibration from `HEAD`. (Promoted from a 2.3 redline to
a standing invariant — board seal condition on 2.1, 2026-07.)

## The load-bearing invariant — the engine needs no tier store at enforce time

**Enforcing a check (running the sandbox on the PR head and computing the `Verdict`)
requires only the image + artifact + entrypoint — NEVER the tier store.** The tier /
calibration stores are consulted at ENABLE time (calibration) and at DISPATCH time (the
gatekeeper's tier decision), not inside `run_engine_check`. This is what makes the 3.3
survivable-DEGRADED safe: when the tier store is momentarily unreachable, an already-ENABLED
check attested by a fresh signed snapshot can keep enforcing, because the enforcement path
has no dependency on the store that just blipped. If enforcement ever grows a tier-store
dependency, snapshot-survivability becomes unsound — so this separation is a standing
invariant, not an accident. (3.3, 2026-07.)

## The load-bearing invariant — measurement authority ≠ governance authority

**The component that MEASURES a detector's fitness holds NO authority to change
enforcement state. A tier change requires a SEPARATE governance authority acting on a
SIGNED measurement.** The re-calibration runner emits a signed attestation (PASS / FAIL /
ERROR) bound to the 4-tuple identity + oracle head — and its key is *not* in the
tier-write authorised set. A FAIL never demotes and a PASS never enables *by itself*; a
separate authority (`GOVERNANCE` for enable/demote, `CALIBRATION_GOVERNANCE` for
holdout injection / acceptance-report signing / triggering re-calibration) must act on
that attestation, and the two roles cannot do each other's job (`GovernanceApproval`
carries an `AuthorityDomain`; `meets()` checks it). This is the deepest form of the
system's separation-of-powers — *the judged cannot control the judging* (out-of-band
verdict), *the author cannot control the grader* (policy from base ref, not `HEAD`), and
now *the meter cannot move the tier* (measurement ≠ governance). Violate it anywhere —
let the thing that measures also enforce — and the calibration loop becomes a
convincingly-instrumented bypass: a self-grading detector that promotes itself on a
measurement it authored. It is a standing rule across every calibration-mode increment
(3.5, 2026-07), not a local note.

## The load-bearing invariant — the detector that judges must be trusted, not caller-supplied

**A calibration / acceptance entry point takes a detector by NAME plus an injected trusted
resolver — NEVER a detector object, lambda, or path.** The four entry points (`calibrate`,
`run_acceptance_anchor`, `run_recalibration`, `run_calibration`) accept a `detector_id` and a
`DetectorResolver`; the only thing that turns a name into runnable code is a trusted,
content-addressed **`DetectorRegistry`** (`gate/detector_registry.py`) that refuses unregistered
ids, refuses a built detector whose declared `content_id` ≠ its (optionally Ed25519-signed)
registration, and hands back trusted code. The gate holds the registry; the engine takes only a
`Callable[[str], RuntimeAssertion]`, so `engine ⊥ gate` is preserved.

**Why a name and not an object — the verdict side-channel (a fundamental in-process limit).** The
blind holdout is encrypted at rest, which hides its *content*. But an **author-controlled detector
needs no content**: it can encode holdout membership in the cross-fixture PASS/FAIL pattern it emits
— roughly **one bit per fixture**. So in-process blindness against a detector the author supplies is
*impossible*, no matter how well the holdout is encrypted. Everywhere this repo says "genuinely
blind" it means **blind under the trusted-detector model** — blind because the graded detector is the
maintainer's registered code, not the (untrusted) author's.

**Trusted-detector boundary (name the TCB).** *Untrusted:* the policy author and the calibration
caller — they may want a detector that games the holdout. *Trusted (the TCB):* the detector
maintainer who registers content-addressed, signed detector code, and the gate host that holds the
registry and the holdout key. Author-controlled code sharing a host process with a decrypted holdout
is **not** isolated from it — stating the boundary precisely is the point.

**Deploy target (what closes the residual channel).** The in-process registry proves the *structure*
— named + trusted-only + verified-on-resolve + no caller code. A deployment closes the residual ~1
bit/fixture side-channel and hardens the seam by running **each detector in its own container**, with
**authenticated IPC**, **no network**, **read-only inputs**, **strict resource limits**, and — the
key move — **aggregate-only output** (the harness returns only the final tallies, so the per-fixture
PASS/FAIL pattern never travels back to the author). The registry itself is backed by an **external,
content-addressed, signed artifact store** (e.g. signed OCI images), and signing by a **KMS/HSM**.
None of these are TEE/MPC-grade requirements — they are ordinary container hygiene the reference
deliberately defers. (3.5 #4 / Option B, 2026-07.)

**Named residuals of the v4 identity hardening (trusted-process model — hygiene, not runtime assurance).**
Resolution PINS one process-lifetime bundle (assertion + validated profile digest + frozen entrypoint
command), so the executed command and the signed profile cannot diverge, the cached digest is never
recomputed from a mutable object, and the trusted `behavioral_config` is deep-frozen at registration.
Three residuals remain, closed only at the deploy tier:
- **First-resolve read.** At first resolution the profile is a hash of the module's **source file bytes**
  while the runnable object comes from Python's **already-imported** module. A swap between import and that
  single read is a first-resolve-only window; strong closure is an **immutable verified execution process**
  (a custom loader binding the exact loaded bytes is deploy-tier, not built here).
- **Registry-update blast radius.** The authorized target is the ENABLED policy's bound subject
  (`current_attestation`), matched exactly on restore. A detector **v1→v2** registry update therefore
  leaves every ENABLED policy bound to v1 **UNATTESTABLE** (restore refused) until it is re-accepted with
  the new version — the correct fail-closed posture, stated so operators know the blast radius.
- **In-process monkeypatch.** The loaded host-side object could be monkeypatched in process; the registry
  is hygiene against file/config drift, not a guarantee the object still implements the hashed bytes. The
  trusted-process model is the boundary; an immutable execution process is the deploy-tier close.

## 3.5-close hardening — exactly what it binds, and what it does NOT

The close increment narrows every claim to what the in-process reference *establishes* — **identity /
anti-drift / config-integrity** — and names the deploy-tier controls that would buy more. What it binds:

- **Execution identity is the bytes that ran, not a tag (§1.1).** An OCI backend resolves the local
  image `.Id` at the top of `prepare()` and executes *that immutable digest* (artifact + proxy +
  escape-probe), recording the same variable in `ExecutionResult.image_digest`; an image absent/GC'd
  before run is a **fatal `IMAGE_UNRESOLVED` ERROR, never a silent pass**. This closes the tag-TOCTOU.
  It is **identity, not runtime-behaviour assurance**: a compromised host could match the digest and run
  something else — that is the unattested-TCB ceiling below. `observer_config_hash` additionally binds
  the **bind-mounted proxy source + sealed-network flags + escape-probe** (the image digest does not
  cover the host-mounted observer, so observer drift would otherwise be invisible).
- **Detector content-address is anti-drift, not anti-smuggling, and is SoD-conditional (§1.2).** The
  registry computes the address from the detector's **module bytes** (not a self-declared attribute, not
  an AST, not EOL-normalized) and refuses a drifted detector. For *first-party* detector code this is a
  **configuration-integrity / anti-drift** control (it catches a bad rollout / revert / mis-selection),
  **not** a boundary against a malicious deployer — whoever can edit the module can re-sign the address.
  It becomes *authorization* only under **separation of duties** (source-signer ≠ image-builder), a
  deploy-tier property; in the reference it is **hygiene, not authorization**.
- **Enforced == accepted (§1.3).** The live gate resolves its detector through the *same* registry
  calibration uses; an unregistered or drifted detector **blocks (`DETECTOR_UNRESOLVED`)**, and a
  **boot assertion** fails at startup (not per-PR) if the accepted detector does not resolve. This is
  single-detector identity continuity; **per-policy `accepted_detector_id` selection is named-next**.
- **The signing seam is real (§1.4).** Acceptance + measurement receipts sign/verify through injected
  `Signer` / `Verifier` **objects**, never raw seeds — so a deployment swaps a KMS/HSM behind the seam.
- **Non-repudiation on the existing blocking path (§1.5).** The Check Run summary carries the attested
  `detector_id` + `image_digest` (engine-measured identity, never artifact output). No heavy local
  signed enforcement receipt is built: the **Check Run + branch protection + C3 override ledger are
  already the merge-blocking artifacts**, and a same-host signer would be false assurance.

### Split the receipts (two threats, two moments)
A single signature must not imply both claims. **Calibration acceptance receipt:** "detector X approved
for policy Y" (`gate/acceptance.py`). **Enforcement runtime record:** "artifact A ran under detector X in
image D → verdict V" (the trial report + the enriched Check Run). Keep them distinct.

### The calibration-time TCB (two halves — both in-process-unproven, both deploy-hardened)
- **(a) Trusted detectors.** An untrusted detector's `assert_invariant` runs **host-side** during
  calibration and could `socket.connect()` to exfil the holdout (`--network=none` is sandbox-side, not
  host-side). This is the concrete mechanism behind the narrowed blindness claim — blindness holds *under
  the trusted-detector model* precisely because untrusted detector code could exfil host-side. Mitigated
  by the registry/trusted-detector binding; a deployment adds **netns/firewall on the calibration host
  process**.
- **(b) Audited backends (§1.6).** `calibrate()` only *declared* `HERMETIC` before — a declaration, not
  proof of no-egress / observer-isolation. The **trusted-backend construction guard** (`gate/backends.py`)
  now confines security-relevant calibration to the **audited backends** (`OCISandbox`,
  `ObservedOCISandbox`) via a module-private capability token, verifying the **returned object**. The
  token is a within-runtime *construction guard*, **not authorization** against a malicious deployer —
  real authority is a **build-time signed manifest of trusted-backend module hashes** (deploy-tier). So
  claim no-egress / observer-isolation **only for the audited backends**, never the generic `Sandbox`
  interface.

### The 6th — unmeasured runtime TCB (the deploy ceiling)
The host kernel, OCI runtime, egress observer, and verdict aggregator are a **trusted-but-unattested
TCB**. Static identity binding ≠ runtime-behaviour assurance: a compromised host can verify the right
digest and then run/mutate a different container, replay/suppress egress, or bypass the observed
namespace. This is gated's documented deploy ceiling — hermetic sandbox + boundary observation is the
in-process **floor**; **TEE/TPM measured-boot + eBPF signed observations** are the deploy hardening that
closes it. **Named, not built** (building attestation into the reference would violate its scope).

### 7c — closed by design (verified against code)
Untrusted-telemetry parsing cannot reach the verdict: `sandbox/oci.py` and `sandbox/observed.py`
`DEVNULL` the artifact's stdout+stderr, and `ExecutionResult` is typed facts only (exit-code int +
host-observed egress counter) — there is no parse of artifact output, no `pickle`, no regex-DoS surface.
Not a deferral; the architecture cannot be hit.

### Named-next increments (deploy-bar — not dropped)
- **`policy → accepted_detector_id` per-policy selection.** Migration alone lets the gate run any
  *registered* detector; per-policy binding authorizes a specific detector for a specific policy.
  **Anti-rollback is a hard prerequisite of this increment** — the moment multiple accepted detectors can
  exist per policy, an older-but-valid one could be selected, so rollback protection must land with it.
- **Runtime attestation** — TEE/TPM measured-boot + eBPF signed egress (the 6th) + netns isolation of the
  calibration host process (calibration-TCB half (a)).

## The rule to hold — Apache-core purity

Everything in `core/`, `sandbox/`, `engine/`, `observe/`, `cli/` is the open
Apache core: **no proprietary dependencies — no external gateway, broker, or memory
service.** If a file needs those, it is private authoring tooling and belongs in a
separate location, not this tree. This is the open-core / extraction boundary.

## Security engineering rules (durable — apply to every increment)

These are standing rules for any security-relevant change, learned the hard way on the 3.5 review.
They decide which "proven" claims are real.

1. **No custom cryptography on a security path.** Don't hand-roll — or even "repair" — a crypto
   primitive for security use; a canonical-looking check still carries side-channel and
   implementation-review risk. Use a vetted library (PyNaCl / `cryptography`) or a KMS/HSM. A
   pure-stdlib primitive is educational/test code at most, explicitly labelled non-production, on **no**
   security path. (An earlier pure-Python Ed25519 here accepted malleable `S+L` signatures and ran in
   variable time — wrong by construction; it was deleted, replaced by PyNaCl behind a `Signer` seam.)
2. **No Python type or "capability" object is an authorization boundary.** `isinstance(x, Capability)`
   is forgeable by anyone who can call `Capability()` — it enforces a *convention* (optionally
   CI-checked within one tree), not authority. Real authority is an authenticated service / DB boundary
   the caller cannot mint by constructing an object. Don't sell a sole-constructor class as *security*.
3. **Trace the actual execution before claiming a property is closed.** Attest from what really ran, not
   a proxy. A single `make_sandbox()` probe does not describe the sandboxes each trial executed in —
   derive execution identity from *every* real trial (image digest, backend, observer/config, isolation)
   and fail-closed if they differ. "Derived from execution" must mean *each* execution. (3.5 #3.)
4. **Every security property names its adversary AND its trusted process.** "Blind holdout" is
   meaningless without "blind against whom, and what runs trusted." State it precisely — e.g. *policy
   authors cannot read the holdout; the detector maintainer and the gate host can; blindness against
   author-controlled detector code requires process isolation* (the trusted-detector invariant above).
5. **"Proven" requires exercising the deployed call path.** A subsystem whose security logic the live app
   never invokes is *mechanism-proven*, not proven. Keep the three bars distinct — **merge-ready ≠
   security-complete ≠ live-proven** — and label reference-only mechanisms as such.

## Status

- **1.1 — `core/` contracts** (board-ratified): `Sandbox` Protocol + value types;
  `ArtifactSpec` SHA-bind, provenance (`isolation_level` + `artifact_hash`) echoed
  on `ExecutionResult`, RAII `session()`. `mypy --strict` clean. No grader here
  (NFR4); no untyped `metadata` dict on the facts object.
- **Next — 1.2** `SubprocessSandbox` (WEAK) → `sandbox/subprocess.py`. The engine
  must treat a WEAK pass as **insufficient** for a real merge gate.

### Step 2 — the gate (`gate/`)

- **2.1 — webhook receiver** (board-ratified, revised after the completeness pass):
  a PURE receiver. Authenticate (HMAC-SHA256 over the RAW body, constant-time,
  fail-closed), then **authorize** (app-id header + installation-id allowlist —
  GitHub-signed ≠ authorized-for-this-install; **empty allowlist ⇒ reject-all**),
  classify (`ping`/unknown acked-and-ignored; `pull_request`
  `opened`/`synchronize`/`reopened` gated with equal rigor), replay via a delivery-id
  seam (idempotent, not rejected), and — on a gating event — **enqueue a
  `GatingEvent` and return 202**, never writing to GitHub synchronously (a
  synchronous Check Run write would couple the ack to GitHub's ~10s delivery timeout
  → re-delivery → duplicate). Seams: `SecretSource` (env backend; secret-manager
  deferred), `GatingSink` (bounded ⇒ backpressure → 503), `AuditSink` (every
  reject/error logged — the boundary is where the audit trail starts). Transport adds
  a body-size cap + per-source token-bucket rate limit. **No IP allowlist** (board:
  crypto boundary, not geographic). Adversarial done-test (each rejection is an
  attempt-that-must-fail). `mypy --strict` clean, zero-dep.
- **2.2 — SHA-bound Check Run lifecycle** (built to the against-fakes line;
  board interim-ratified): `CheckRunLifecycle` (`queued→in_progress→completed`, bound
  to the exact `head_sha`); `upsert_check_run` idempotent create — GitHub is **not**
  queryable by `external_id` (write-only), so find via
  `GET commits/{sha}/check-runs?check_name` → PATCH-if-found-else-POST (one mechanism
  covers crash-retry **and** `reopened`); `verdict_to_conclusion`
  (PASS→success / FAIL→failure / **ERROR→action_required**, with a pinned fail-closed
  invariant: non-PASS ∈ blocking set). Auth: `InstallationTokenProvider` against seams
  (App-JWT bounds, per-install cache + refresh margin, `checks:write` least-privilege,
  `KeySource` seam). Done-when = **lifecycle correctness, not merge-gating** (that is
  2.5). Tested against fakes; `mypy --strict` clean, zero-dep.
- **Convention — the Check Run name is the upsert idempotency key, so it MUST be
  gated-namespaced** (e.g. `gated/retry`). The upsert finds by
  `(commit SHA, check_name)`; a bare name risks colliding with another tool's check on
  the same SHA. A closed-unmerged PR mid-check is benign (its check completes harmlessly;
  a later `reopened` on the same SHA re-uses the run); explicit `closed` handling is 2.6.
  (Board 2.2 what's-missing #4/#2.)
- **Against-fakes methodology + the 2.5 model-verification rule:** the live GitHub
  adapters (real PyJWT RS256 `JwtSigner`, HTTPS `TokenFetcher`, `urllib`
  `GitHubCheckClient`) are deferred to **one live wire-up at 2.5**. The fakes encode a
  *model* of GitHub, and that model has already been wrong once (`external_id`). So
  **2.5 is a MODEL-VERIFICATION increment, not a swap**: before the end-to-end is
  trusted, hit the real API and confirm every fake-assumed behaviour (upsert/query
  shape, multi-run/latest-wins, conclusion values). Live adapters need
  **exponential backoff + circuit breakers** (a transient GitHub 5xx must retry, not
  wedge). Two behaviours fakes structurally cannot test, to confirm at wire-up:
  **(a) [RESOLVED via GitHub Docs — passing conclusions are only
  `success`/`skipped`/`neutral`, so `action_required` blocks; live UAT smoke-tests it
  but it is NOT a fail-open risk]** `action_required` BLOCKS the merge; **(b) the
  install token refreshes mid-check** when a verdict computation runs longer than the
  refresh margin (~27s/run × N trials); **(c) the `iat` back-date (60s) absorbs real
  gate-host↔GitHub clock skew** (works on the NUC where clocks are close; a deployment
  flake otherwise); **(d) the install-token cache invalidates on a 401 / App-uninstall**
  — TTL-based expiry doesn't cover a token that dies *early* by uninstall (key-rotation
  IS handled: the private key is re-read from the `KeySource` on every mint);
  **(e) the pending Check Run APPEARS fast enough to close the interim merge window** —
  the async safety case needs the required-by-name check *visible to branch protection*
  before a fast-merger can merge, not just that a non-PASS conclusion blocks (both must
  hold); **(f) the install token is still valid at POST time** (not just check-start) —
  the engine run is ~27s×N but the Check Run POST is at the END, so a near-expiry token
  must be refreshed at post-time, not only at claim.
- **Held — 2.3 ArtifactSpec builder + async executor (the consumer):** carries the
  five pillars — **persistent SQLite delivery-log + Claim-Process-Complete** and the
  **fail-closed watchdog** (both deferred here from 2.2; consumer-state); a
  **bounded-concurrency semaphore** propagating backpressure to the 2.1 receiver
  (saturated ⇒ 503); **`pull_request` only** + ephemeral **`checks:write`** token
  (H2); **`git core.hooksPath=/dev/null`** against malicious repo hooks (5B); and the
  **policy read from the protected base ref — never PR `HEAD`** (the Oracle-attack
  standing invariant).
- **⛔ Hard dependency — 2.3 BLOCKS 2.5.** The 2.1 async-deferral safety case holds
  *only* because persistence lands (2.3) before anything is live (2.5). This is a
  **blocking prerequisite, not a sequence preference**: 2.5 branch-protection must not
  be wired on a real repo until 2.3's persistent delivery-log + watchdog exist — a
  wedged PR is a UI nuisance without branch protection, a full dev-halt with it, and a
  crash *loses the delivery record* without persistence.
- **Physical resource protections (single-node reality).** Done in 2.3: `busy_timeout`
  + connect-timeout on every SQLite conn (no `database is locked` crash); the
  retry-trap fix (errored deliveries re-queue on re-delivery, never wedge); the
  same-SHA guard blocks only on `processing` (errored/done siblings stay claimable);
  reject-all-symlinks; `extraction_workspace` RAII purges host scratch on every exit.
  **Deferred to the 2.5 live adapters** (fakes can't exercise real I/O): the tarball
  **download MUST stream with a running byte-cap** (abort the socket before a
  multi-GB blob hits RAM/disk → OOM); **every outbound GitHub call needs hard
  `connect`/`read` timeouts** (a hung socket must not starve the thread pool → total
  503 outage); the watchdog should also **`rm -rf` orphaned extraction dirs** (disk).
- **2.4 engine integration (BUILT, real on podman).** `ArtifactSpec → Sandbox → Verdict`
  wired to the executor; verdict → Check Run with an out-of-band summary. Fail-closed
  mapping `PASS→success / FAIL→failure / ERROR→action_required` (locked; `neutral`
  banned). A hash mismatch surfaces as a **distinct security event**
  (`ARTIFACT_INTEGRITY_MISMATCH` — the audit *screams* "possible TOCTOU tamper", still
  blocks), not a generic ERROR. The posted **conclusion is recorded as an audit fact**
  (not merely derivable). **P5 ENFORCED, not documented:** `assert_budget_fits_watchdog`
  is a fail-closed startup check — `trials × per_trial_wall_clock × margin <
  watchdog_timeout` (the budget is applied PER TRIAL, so the *aggregate* is what must fit)
  — the App refuses to boot on violation. The summary is composed from the typed
  `Verdict` only (structural anti-spoofing). Sandbox re-verifies `tree_hash` (TOCTOU);
  aggregation stays in the engine; `RuntimeAssertion` reads only `ExecutionResult`, never
  `/work` (audit-only).
- **2.4 → 2.5 stream seam:** the fetch seam is **path-based** (`extract_to_spec(tar_path)`),
  so 2.5's download streams to a **byte-capped file on disk** — the interface never
  demands bytes-in-RAM, so no refactor and no OOM-by-buffering.
- **2.5 — the acceptance anchor (live wire-up, board-ratified).** Model-verification
  GATES the done-test: confirm each fake-assumed behaviour against REAL GitHub *before*
  trusting acceptance. Startup is fail-closed: `assert_budget_fits_watchdog` **and**
  `verify_check_required` (the elevated footgun — the App reads its own repo's branch
  protection and REFUSES TO START unless the exact check name it posts is a *required*
  context; a name mismatch would make the gate advisory = **invisible fail-open**).
  New live surfaces + their pins:
  - **Ingress** (github.com → your host via a public HTTPS ingress / tunnel): the HTTP
    server binds **127.0.0.1 only** (tunnel → localhost); the tunnel is **untrusted**
    (the 2.1 HMAC is the boundary) and must pass the **raw body unmodified** (verify: a
    signed webhook through the tunnel still passes HMAC); **ingress-liveness monitoring**
    so "blocking because deaf" (tunnel down, no webhooks) is distinguishable from
    "blocking because judged".
  - **Interim window** — DATA-GATED: do NOT pre-emptively reverse async-202. Verify live
    with a **race-shaped adversarial timing test** (script a merge attempt at PR-open,
    before the check could post), not a happy-path "it blocked". Async holds if GitHub
    blocks a never-reported required check; only if a real race exists, add a *fast*
    `queued`-create (one ~200ms call, not the 5A engine-coupled reversal).
  - **Done-test** must include a **fork PR** (confirm the H2 `pull_request`-not-
    `pull_request_target` / token-scope fix live, not just same-repo).
  - **Live adapters:** real PyJWT signer + HTTPS token fetch + `urllib` GitHubCheckClient
    with hard connect/read timeouts + backoff; **streaming byte-capped** tarball
    download-to-file; **`RateLimitBudget`** (shed → 503 below floor); **token pre-refresh**
    before `exp−skew`; **graceful shutdown** (finish in-flight); tracing; watchdog
    `rm -rf` orphans. App scoped to the **private UAT repo only**.
  - done-test proper: **Output B (swallowing-helper) BLOCKED at merge, deterministically;
    fixed-B PASSES + merges** — via boundary observation. marker-4 = one real
    webhook→verdict→Check Run latency.
- **2.5 live findings (model-verification against real GitHub, App promotion-gate-uat):**
  the App-JWT → installation-token chain, the Check Run create/find/update lifecycle
  (find by `(commit SHA, check_name)`), branch-protection set (`strict` + required-by-name
  + `enforce_admins`), the check-name-match fail-closed assertion (+ its negative), and a
  streamed byte-capped tarball download → shared-canon hash — **all confirmed live**.
  **Scope finding:** reading/writing branch protection needs the `administration`
  permission, which the App's minimal runtime token (`checks:write`/`contents:read`/
  `pull_requests:read`/`metadata:read`) deliberately lacks → the fail-closed
  check-name-match verify is a **deploy-time admin operation** (owner/operator
  credential), not the App's runtime token. Keeps the runtime token minimal.
- **Held — for the live done-test:** action_required-actually-blocks + pending-blocks
  (need a PR + merge attempt), raw-body-passthrough (signed webhook via the funnel),
  the full end-to-end (PR with Output B → FAIL → merge blocked; fixed → merges),
  marker-4. The real adapters (`gate/github_live.py`) are built + partly live-verified.
- **Held — later:** 2.6 override ledger (`closed` + `merged` → `HUMAN_OVERRIDE`).
