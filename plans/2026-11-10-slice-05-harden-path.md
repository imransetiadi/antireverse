---
title: "Plan — Slice 05 Harden path"
aliases: [Plan 05]
project: anti-reverse
doc: PLAN
slice: 5
version: 0.1.0
status: done
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# Slice 05 — Harden Path Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: a decision with alternatives goes through Jev, and completion claims are checked with Jev before they are made.

**Goal:** A developer runs `antireverse harden <dir> --profile balanced` in their own CI over a web bundle they own; it applies behaviour-preserving transforms, proves behaviour with the bundle's own tests, writes a cost report, and (with `--register`) registers a Build and its Manifest with the API; the Console shows the Build on the App.

**Architecture:** A new `@antireverse/harden` package holds the transform engine (Babel 8 AST pipeline, passes behind a `Pass` interface), the equivalence runner, the report, the CLI and the register client — Babel lives only here. The protocol gains Build and Manifest schemas. The API stores Builds per App and serves them. The Console adds a Build list and Build detail. The reference app `ar-range` gains a small browser bundle with its own test, as the thing to harden end to end. Shield, Guard and the Policy path are untouched; Shield's runtime dependency list stays empty.

**Tech stack additions (this slice only, in `@antireverse/harden`):** `@babel/core`, `@babel/parser`, `@babel/traverse`, `@babel/generator`, `@babel/types` — all `8.1.0`. No other new dependency anywhere.

**Spec:** [tickets/05-harden-path.md](../tickets/05-harden-path.md). Background: [SDD.md](../SDD.md) §8 (Harden design), §4 (interfaces); [SECURITY.md](../SECURITY.md) §2 (stated limits), TA-01/03/05, SC-SUP-*; [PERFORMANCE.md](../PERFORMANCE.md) PB-10, PB-11, PB-12; [UIUX.md](../UIUX.md) §7 (SCR-07 Build detail), §8, §10. Everything in the slice 01 plan's Global Constraints and Verified library facts still binds, plus slice 02's additions.

## Global Constraints (additions)

- **No new dependency outside `@antireverse/harden`.** Babel is a dependency of that package only. Shield stays zero-runtime-dependency.
- **Local-first.** The CLI never sends source or the unprotected bundle anywhere. Only `--register` contacts the API, and it sends only the Manifest.
- **Determinism.** Given the same inputs, profile and seed, `harden` produces byte-identical output. The seed defaults to a value derived from a tenant secret and the Build id; a `--seed <n>` overrides it for reproducible local runs.
- **Behaviour is never changed.** The equivalence gate (the bundle's own test command run against the protected output) must pass, or the harden fails and writes nothing.
- **Budgets are a gate.** `balanced`: runtime overhead ≤ 15 %, size overhead ≤ 35 % on protected modules (gzip). If a file would exceed a budget, string encryption is skipped for that file (mangle-only), the report records it, and the harden still succeeds. A module is never shipped over budget.
- **Profiles:** `light` = mangling only. `balanced` = mangling + scoped string encryption (decoded value bound to a local at its use site; no per-access decode call). `maximum` = `balanced` in this slice (heavier passes are later). The integrity self-check is the opt-in `--integrity` pass, not in any default profile.
- **Mangling touches local bindings only** — never imports, exports (the public export name is preserved), global references, or object property keys.
- **String encryption transforms plain string literals only** — never template literals, import/export source strings, or non-computed object/class property keys.
- **Build id** `bld_<24 hex>`; **Build version** is the developer's own version string (1–64 chars, from `--build-version` or the bundle's `package.json` version), not a monotonic number.
- **The Manifest contains no source and no secret:** Build id, App id, Environment, version, per-artifact `{ path, sha256, bytes }`, profile, seed id (not the seed value), transform summary (counts per pass), costs (`size_overhead_pct`, `run_overhead_pct`), equivalence result, created-at. Max 1,000 artifacts, Manifest ≤ 256 KB.
- **Node engine:** Babel 8 asks for Node ≥ 22.18; this machine runs 22.12, which works with an `EBADENGINE` warning at install. `.nvmrc` note added; CI should use ≥ 22.18. Do not raise the root engines floor (other workspaces run on 22.12).
- **Responsible use (SECURITY.md §2):** Harden is a defensive build-time step on a bundle the developer owns; the equivalence gate enforces that it changes no behaviour; it adds no capability to the software; it is not for evading detection. The CLI banner and `--help` state this in one line.

## Review Focus

1. **A transform changes behaviour** — a module that imports, exports, reads a global, uses string-keyed objects, template literals, non-ASCII strings, `this`, getters/setters: the protected output behaves identically, proven by the module's own tests. *(Harden)*
2. **Budget silently exceeded** — a string-heavy or tiny file: the report shows the real gzip and runtime overhead, and any file over budget is mangle-only with a recorded reason; nothing over budget is written. *(Harden)*
3. **Source or secret leaves the machine** — capture all network during a `--register` run: only the Manifest is sent, never source, the unprotected bundle, the seed value, or a key in a log. *(Harden)*
4. **A tampered Manifest or cross-tenant Build** — another Organization cannot register or read a Build for the App; a Manifest with a bad shape, 1,001 artifacts, or over 256 KB is refused with a problem document. *(API)*
5. **Non-determinism** — the same inputs and seed give byte-identical output across two runs and two machines (same Node); a different seed gives a different name set and string table but identical behaviour. *(Harden)*

## Contracts

### P1 — Protocol (`packages/protocol/src/build.ts`, isomorphic entry)

```ts
export const BUILD_LIMITS = { artifactsMax: 1000, manifestBytesMax: 262144, versionMax: 64, listed: 50 } as const
export const PROFILES = ["light", "balanced", "maximum"] as const        // type Profile
ArtifactDigestSchema      = { path: string 1..256 (storable text), sha256: 64 hex, bytes: int >= 0 }
TransformSummarySchema    = { mangled: int>=0, strings_encrypted: int>=0, files_mangle_only: int>=0, integrity: boolean }
BuildCostsSchema          = { size_overhead_pct: number, run_overhead_pct: number|null }   // run null when not measured
BuildManifestSchema       = { format: 1, build_id, app_id, environment, version, profile,
                              seed_id: 16 hex, artifacts: ArtifactDigest[1..1000], transform: TransformSummary,
                              costs: BuildCosts, equivalence: "passed"|"skipped", created_at }
RegisterBuildRequestSchema  = { manifest: BuildManifest }          // the CLI sends the Manifest it built
BuildSchema               = BuildManifest + { registered_at }       // as the API returns it
BuildResponseSchema       = { build: Build }
ListBuildsResponseSchema  = { builds: Build[] }                     // newest first, at most 50
```

Server entry: `newId("bld")`; `seedId(seedValue): string` (16 hex of SHA-256 of the seed value, so the Manifest identifies the seed without revealing it). `ID_PATTERNS.bld`.

### P2 — API additions

| Method and path | Key | Success | Notes |
|---|---|---|---|
| `POST /v1/apps/:appId/builds` | admin | 201 `BuildResponse` | Registers a Build; the server stamps `registered_at`; `build_id` must be fresh for the App (409 `conflict` on a repeat) |
| `GET /v1/apps/:appId/builds` | admin | 200 `ListBuildsResponse` | Newest first |
| `GET /v1/apps/:appId/builds/:buildId` | admin | 200 `BuildResponse` | 404 outside the Organization or unknown |

Migration `apps/api/migrations/0004_builds.sql`: `builds (organization_id, app_id, build_id, environment, version, profile, manifest jsonb, registered_at)`, primary key `(organization_id, app_id, build_id)`, row-level security as every tenant table. The Manifest's `app_id`/`environment` must match the route and the key's App; a mismatch is 400. Reuse the existing body limit, problem kinds (add nothing new except reuse `conflict` from slice 02), and the "never log a key/body" rule.

### P3 — Harden package (`packages/harden`, name `@antireverse/harden`)

```ts
// engine (pure, no I/O)
interface PassContext { rng: () => number; seed: number; types: typeof import("@babel/types") }
interface Pass { name: "mangle" | "strings"; run(ast: File, ctx: PassContext): { count: number } }
interface HardenOptions { profile: Profile; seed: number; protectionMap?: Record<string, "skip">;
                          budget?: { sizePct: number; runPct: number } }
interface FileResult { path: string; code: string; skipped: boolean; mangleOnly?: string /* reason */;
                       renamed: number; stringsEncrypted: number }
interface HardenResult { files: FileResult[]; transform: TransformSummary }
function harden(files: Record<string, string>, options: HardenOptions): HardenResult   // deterministic, never throws on valid JS; reports a parse error per file

// equivalence (I/O: runs the customer's test command)
function checkEquivalence(args: { dir: string; testCommand: string; protected: Record<string,string> }):
  Promise<{ passed: boolean; output: string }>            // writes protected files to a temp copy, runs the command there

// manifest + report
function buildManifest(args: {...}): BuildManifest        // hashes artifacts, computes costs, fills the summary
function formatReport(manifest, { json }): string

// register client (I/O: one POST)
function registerBuild(args: { endpoint; key; appId; manifest }): Promise<{ build: Build } | { error }>

// CLI: bin "antireverse"
//   antireverse harden <dir> --profile balanced [--seed n] [--map file] [--integrity]
//     [--register --endpoint URL --key-env AR_ADMIN_KEY --app APPID --environment ENV --build-version V] [--json]
```

Rules: the engine is deterministic and pure; a seeded PRNG (mulberry32) drives names and the string table; string decoding binds the value to a local at the use site; the budget guard measures per-file gzip and, when over, re-emits that file mangle-only and records the reason; `--integrity` wraps already-bundled (non-ESM) output and is refused with a clear message on ESM input; the CLI reads the admin key from the named environment variable only (never an argument), prints no key, and exits non-zero on any failure.

### P4 — Console additions

- App detail gains a **Builds** section (newest first): version, profile, equivalence result, size and run overhead, created-at; a row links to the Build.
- **Build detail** `/apps/[appId]/builds/[buildId]` (SCR-07, trimmed to this slice): header with version and profile; the cost figures against their budgets (a bullet-style bar is enough); the transform summary; the artifact list (path, bytes, short hash). No RRS yet (slice 12).
- API client: `listBuilds`, `getBuild`. Copy keys for the section and page in the catalog, in the UIUX voice.
- Navigation: the App's tab row gains **Builds** beside Live and Policy.

### P5 — Reference app bundle (`apps/range`)

- Add `apps/range/web/` : a small browser entry (a few modules with real logic — a pure calculation, a string-keyed lookup, a function reading a global) and a `*.test.ts` that exercises them. A tiny build step (esbuild is already available via Vite? no — keep it dependency-free: ship the modules as plain ESM and let the harden operate on them directly, with the test as the equivalence command). The end-to-end test hardens this directory.

## Tasks

Order: Task 1 → (Task 2 ‖ Task 3 ‖ Task 5) → Task 4 → Task 6 → Task 7.

### Task 1: Protocol — Build and Manifest (contract P1)
Failing tests first: the schemas, `newId("bld")`, `seedId` (16 hex, stable, differs per seed, never equals the seed), limits (1,001 artifacts rejected, 256 KB, version length), unknown keys stripped, `EXAMPLE_BUILD_MANIFEST`. Update `entrypoints.test.ts`. Then implement; `npx vitest run --project protocol`, `tsc`, `biome`; then whole-repo `npx vitest run` to confirm nothing else broke.

### Task 2: API — register and read Builds (contract P2)
Failing tests first (Review Focus 4): register → 201; list newest first; detail; another Organization → 404; a Shield key → 403; a Manifest whose app/environment mismatch the route or key → 400; a repeat build id → 409; 1,001 artifacts / oversize → 400; no key in any log line; migration applied once. Then implement; per-project checks + a curl smoke test against a real server.

### Task 3: Harden — engine, CLI, equivalence (contract P3)
Owner of `packages/harden`. Failing tests first, using the spike's verified Babel 8 forms (named imports from core/parser/generator/types; `import traverse from "@babel/traverse"`):
- mangle: locals renamed, imports/exports/globals/keys intact, export name preserved, deterministic from seed, collision-free (Review Focus 1, 5).
- strings: plain literals encrypted and bound at use site; template literals, import/export sources and non-computed keys untouched; non-ASCII and escapes preserved (Review Focus 1).
- determinism: same seed → byte-identical; two seeds → different names and table, same behaviour (Review Focus 5).
- budget guard: a string-heavy file is re-emitted mangle-only with a reason; the report carries real gzip/runtime figures; nothing over budget (Review Focus 2).
- protection map: a skipped file is byte-identical.
- equivalence runner: runs a given test command against the protected copy; a behaviour-breaking transform is caught.
- integrity (`--integrity`): detects a one-byte patch on bundled input; refuses ESM input with a clear message.
- CLI: reads the key from the named env var only; `--json`; non-zero exit on failure; no key printed; the responsible-use line in `--help`.
Then implement; `npx vitest run --project harden`, `tsc`, `biome`; add `harden` to the root `vitest.config.ts` projects (coordinator does the root wiring in Task 1 or here — note it in the report rather than editing the root silently if another lane holds it).

### Task 4: Console — Builds section and Build detail (contract P4)
Failing tests first: the client calls; the Builds section renders version/profile/equivalence/cost newest first; the Build detail shows costs against budget, the transform summary and the artifact list; empty state; tokens/vocabulary; navigation tab. Then implement; `vitest --project console`, `typecheck`, `biome`, `next build`.

### Task 5: Reference app bundle (contract P5)
Add `apps/range/web/` modules and their test; a script `harden:demo` is not needed. Keep it dependency-free. Failing test first for the modules' own behaviour, then the modules.

### Task 6: End to end
- HTTP/CLI journey: run `harden` over `apps/range/web` on `balanced` with a fixed seed; assert behaviour (the module test passes against the output), determinism (two runs byte-identical), the report's budgets, then register against an in-process API and read the Build back; a second Organization cannot read it. Capture network to prove only the Manifest left.
- Browser journey: register a Build (via the CLI or a seeded fixture through the API), then in the Console open the App, see the Build in the list, open it, and see its profile, cost and artifacts.

### Task 7: Documentation, memory, full verification
README (the `harden` command, profiles, budgets, `--integrity` caveat, local-first, the Node ≥ 22.18 note, back-up-nothing-leaves line), ticket proof table, MEMORY.md (decisions D-031…, handoff), PRD slice table. `npm run verify`, `npm run e2e`, `npm run bench`. Independent review; fix confirmed findings test-first; Jev-verify the completion claims.

## Verified library facts (from the spike, 2026-11-10)

Evidence: the spike report of 2026-11-10 (task `aeb3284bd69e9e82f`); spike dir `scratchpad/spikes/f-harden` (to be cleaned up).

- **Pins (in `@antireverse/harden` only):** `@babel/core`, `@babel/parser`, `@babel/traverse`, `@babel/generator`, `@babel/types` all `8.1.0`. ~3.1 MB for the five, ~9.9 MB with transitive deps.
- **Babel 8 ESM imports:** `import { transformSync, transformFromAstSync, parse } from "@babel/core"`; `import { parse } from "@babel/parser"`; `import traverse from "@babel/traverse"` (default **is** the function — no `.default.default`); `import { generate } from "@babel/generator"`; `import * as t from "@babel/types"`.
- **Mangle:** `path.scope.rename(old, new)`; skip `binding.kind === "module"` and export declarations; property keys are not bindings so they are safe; `export const X` is safe because Babel re-emits `export { renamed as X }`.
- **Strings:** transform `StringLiteral` only; skip import/export parents and non-computed `ObjectProperty` keys and template literals; bind the decoded value to a local at the use site to avoid the per-access cost that otherwise adds ~92 % runtime on hot paths.
- **Integrity:** an `eval`-based hash wrapper (FNV-1a over the captured payload) detects a one-byte change and does not fire on the untouched output, but it roughly doubles size and cannot run ESM — so it is opt-in and post-bundle only.
- **Determinism:** mulberry32(seed) + a name alphabet + a `used` set and per-scope collision check gives byte-identical output for one seed and different output for another, behaviour preserved.
- **Cost (gzip):** mangling is runtime-neutral and size-neutral or smaller on real files (can enlarge gzip only on very repetitive names); string encryption with per-access decode blows both budgets on small/string-heavy files — hence binding at use site and the per-file budget guard.
- **Node:** Babel 8 `engines.node` is `^22.18.0 || >=24.11.0`; 22.12 installs with an `EBADENGINE` warning and runs.

## Deliberately not in this slice

Leak scan and secret detection; Canaries and Watermark; origin lock and Clone Beacon; control-flow flattening, opaque predicates, dead-code injection; code virtualization; federated CI identity signing the Manifest; a CI gate on a resistance score; mobile and desktop.

## Amendments after the independent review

| Finding | Severity | Fix |
|---|---|---|
| A local `class` was renamed inconsistently (declaration vs references) → ReferenceError at runtime | CRITICAL | `mangle.ts` assigns one new name per binding identifier node and renames every scope that owns it to the same name (a class is bound in two scopes sharing one id node) |
| The mangler could emit a JavaScript reserved word as an identifier → SyntaxError | HIGH | `rng.ts` always excludes a `RESERVED_WORDS` set from generated names |
| A file could ship over the 35 % size budget (mangle-only and `light` were not re-checked) | MED-HIGH | `engine.ts` adds a final budget gate on the shipped output for every profile; over budget → emit unchanged with a recorded reason |
| A direct `eval` that reads a local was broken by mangling (detection used `scope.hasBinding("eval")`, always true) | MED-LOW | `mangle.ts` detects any direct `eval(...)` call and skips mangling the whole file |

Also: the 409 conflict problem text was made generic ("Conflict" / "This resource was changed by someone else…") so it reads correctly for both Policy and Build conflicts. Decisions taken with Jev: transform engine (1.0), balanced composition (0.71), CLI report-only-by-default (1.0), new-epoch issue-time check in slice 02's follow-up (0.94). The review's fixes were not themselves open decisions (the reviewer gave the smallest fix for each).
