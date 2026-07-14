<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **gated** (3786 symbols, 8675 relationships, 206 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/gated/context` | Codebase overview, check index freshness |
| `gitnexus://repo/gated/clusters` | All functional areas |
| `gitnexus://repo/gated/processes` | All execution flows |
| `gitnexus://repo/gated/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->

<!-- The block below is OUTSIDE the gitnexus markers so `gitnexus analyze` / wiki regeneration does NOT overwrite it. -->

## Re-index with GitNexus BEFORE every GitNexus call

When this repo shares a GitNexus index with other repos, the index goes stale between almost every edit,
and an intricate build churns it constantly. A stale/absent `impact` / `detect_changes` reading is
**VACUOUS** (it measures the graph's ignorance, not the code's safety). So, EVERY time, before any
`impact` / `detect_changes` / `context`, re-index from the repo root (`gitnexus analyze` — or the runner
in the box above).

- In a multi-repo index, **pass the repo name** to the MCP calls (it errors "Multiple repositories indexed" otherwise).
- **Trust a reading only when its `epistemic` tag is `EXACT`.** Cadence: **edit → re-index (gitnexus analyze) → THEN read impact.**
- Through intricate sections (a concurrency worker/relay), use GitNexus **regularly** — re-index + impact at each build step, not just at seal.
