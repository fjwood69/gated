# gated — architecture

The enforcement engine for the Promotion-Boundary Governance Framework
([moriapp.dev/pbgf](https://moriapp.dev/pbgf)). Everything in this tree is the
**open Apache core**.

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

## The rule to hold — Apache-core purity

Everything in `core/`, `sandbox/`, `engine/`, `observe/`, `cli/` is the open
Apache core: **no proprietary dependencies — no external gateway, broker, or memory
service.** If a file needs those, it is private authoring tooling and belongs in a
separate location, not this tree. This is the open-core / extraction boundary.

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
