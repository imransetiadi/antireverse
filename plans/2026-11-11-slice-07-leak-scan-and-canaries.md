---
title: "Plan — Slice 07 Leak scan and Canaries"
aliases: [Plan 07]
project: anti-reverse
doc: PLAN
slice: 7
version: 0.1.0
status: done
updated: 2026-11-11
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

# Slice 07 — Leak Scan and Canaries Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: a decision with real alternatives goes through Jev; if you cannot reach Jev, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** Harden fails a build that is about to leak a secret, plants per-Build Canaries and registers them; Shield recognises a Canary in use and the detector opens a High Incident naming the Canary and its Build.

**Architecture:** The protocol gains Canary and leak-scan types, optional Manifest fields, a bundle field carrying active Canaries, and the `canary-touched` rule. Harden gains a leak-scan stage before the transforms and a Canary planting stage after them. The API stores Canaries with their Build, puts the active ones in the signed Policy Bundle, and the slice-06 detector opens the Incident. Shield matches decoy routes and decoy keys locally and adds a signal to the Event — never the key. The Console shows leak-scan results and Canaries on a Build, and the Build on a Canary Incident. No new dependency.

**Spec:** [tickets/07-leak-scan-and-canaries.md](../tickets/07-leak-scan-and-canaries.md). Background: [SDD.md](../SDD.md) §5.1, §8 (Canaries, Leak scan), §9 (`canary.touched`); [SECURITY.md](../SECURITY.md) TA-05, O2; [PERFORMANCE.md](../PERFORMANCE.md) PB-11, PB-16, PB-17; [UIUX.md](../UIUX.md) §7 SCR-07 markers, §16 CLI rules. Earlier plans' constraints and amendments still bind (notably slice 05: deterministic, local-first, report-only by default, budget gate, equivalence gate; slice 06: detector, grouping, alerts).

## Global Constraints (additions)

- **Identifiers:** Canary `cny_<24 hex>`.
- **Canary kinds:** `key` (a decoy API key) and `route` (a decoy path on the customer's own origin). The SDD's "decoy configuration string" is planted as a config object that carries the decoy key and a decoy route, so it is detected through them.
- **Per Build:** 1 decoy key and 2 decoy routes (constant `CANARY_PLAN = { key: 1, route: 2 }`).
- **Values derive from the seed:** `HMAC-SHA256(key = "antireverse/canary/v1/" + seed, message = "<kind>/<index>")`, encoded to the formats below; the Canary id is `cny_` + the first 24 hex of `HMAC(... , "id/<kind>/<index>")`. The same input and seed reproduce the output byte for byte; no network call.
- **Decoy key format:** neutral and believable as the customer's own key, never a third-party provider's prefix: `ak_live_` + 32 base62 characters. It must not match any leak-scan rule.
- **Decoy route format:** `/api/internal/<8 base36>/<word>` where `<word>` is chosen from a short fixed list (`export`, `debug`, `config`, `backup`, `sync`) by the HMAC.
- **Planting:** after all transforms, as plain text (never string-encrypted), into exactly one emitted JavaScript file (the first protected file in sorted path order), as a single behaviour-neutral expression statement `void {apiKey:"…",internalApi:"…",exportUrl:"…"};` — no binding, no global, no side effect. Planting counts toward the size budget; if it would exceed the budget the harden fails with a clear message (it never silently drops Canaries). An excluded (`skip`) file is never planted into.
- **Leak scan:** runs on every input file before any transform, and on the bundle's file set. Rules (constants, each with an id):

| Rule id | Finds |
|---|---|
| `source-map` | a `*.map` file, or a `sourceMappingURL=` comment (including inline `data:` maps) |
| `private-key` | `-----BEGIN … PRIVATE KEY-----` |
| `aws-access-key` | `AKIA` / `ASIA` + 16 upper-case alphanumerics |
| `github-token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 alphanumerics |
| `stripe-secret` | `sk_live_` / `rk_live_` + ≥ 24 alphanumerics |
| `slack-token` | `xox[abprs]-…` |
| `google-api-key` | `AIza` + 35 of `[0-9A-Za-z_-]` |
| `secret-assignment` | a string of ≥ 16 characters with Shannon entropy ≥ 3.5 bits/char assigned to a name matching `secret|token|password|passwd|api[_-]?key|private[_-]?key|client[_-]?secret` |
| `internal-url` | an `http(s)://` URL whose host is `localhost`, a loopback, private (10/8, 172.16/12, 192.168/16) or link-local address, or ends in `.internal`, `.local`, `.corp`, `.lan` |

- **Findings:** `{ rule, path, line, masked, fingerprint }`. `masked` shows at most the first 4 characters then `…` (and never more than a quarter of the value); `fingerprint` = hex SHA-256 of `rule + "\0" + path + "\0" + value`, first 32 hex. The value itself is never printed, logged, written to the report or uploaded.
- **Allowlist:** a JSON file, default `.antireverse/leak-allow.json` relative to the working directory, overridable with `--leak-allow <file>`: `{ "version": 1, "allow": [{ "fingerprint": "<32 hex>", "reason": "<1–200 chars>" }] }`. A malformed file fails the harden. Suppressed findings are counted in the report.
- **Failure:** any unsuppressed finding → exit code 3 (distinct from other failures), the report lists the findings, nothing is written to `--out`, nothing is registered. There is no flag to skip the scan.
- **Manifest (format stays 1, new optional fields):** `leak_scan: { status: "clean" | "suppressed", suppressed: int }` and `canaries: Canary[]` (≤ 10) where `Canary = { id, kind, value }`. Older Manifests without them stay valid. Decoy values are not secrets; the Manifest still carries no secret and no source.
- **Bundle:** `BundlePayload` gains `canaries: [{ id, kind: "key" | "route", value }]` (≤ 100): the Canaries of the App and Environment from its most recent 20 Builds. Older Shields strip the field (plain `z.object`). The bundle's conditional-fetch identity (ETag) must change when the Canary set changes; a Shield applies a same-version bundle whose Canary set changed. Canaries reach Shield within 15 s of registration (PB-16).
- **Shield matching (observe only):** a request matches a key Canary when the `Authorization: Bearer <v>` token, the `x-api-key` header, or the `api_key` query parameter equals a decoy key exactly; a route Canary when the raw or canonical path (the slice-02 forms) equals the decoy route. A match adds the signal `{ id: "canary.touched:<cny id>", confidence: 1 }` to that request's Event. Shield never changes the response for a Canary, never sends a header value, and its lookups are O(1) set lookups (bench budget unchanged: p99 ≤ 0.5 ms).
- **Detection:** rule `canary-touched` (title "Canary used", severity `high`, threshold 1, window 300 s) counts each Event signal `canary.touched:<id>` whose Canary belongs to the Event's Organization, App and Environment (unknown or foreign ids are ignored). Counting key adds the Canary id: (Organization, App, Environment, rule, Canary id, prefix). Grouping: same App, Environment, rule, Canary and prefix while `open` or `acknowledged`. The Incident carries `canary_id` and `build_id` (nullable for other rules). Evidence: Events of that prefix carrying that Canary's signal. A new Canary Incident alerts through slice-06 channels; the webhook payload's `incident` includes the new fields.
- **Budgets:** PB-17 Canary use → Incident ≤ 60 s p95 (expected ~1 s here); PB-11 size budget includes the planted statement.

## Review Focus

1. **No secret ever leaves:** a finding's value never appears in stdout/stderr, `--json`, the report, the Manifest or a request; decoy key values never leave the customer's server from Shield (only the Canary id). *(harden, shield)*
2. **Leak scan catches what string encryption would hide**, and never reports a planted Canary. *(harden)*
3. **Determinism and behaviour:** same input + seed → byte-identical output including Canaries; equivalence still passes; planting never creates a global or a side effect; budget never silently exceeded. *(harden)*
4. **Tenancy:** a Canary id from another Organization or App in a signal never opens an Incident; Canary values of one Organization never appear in another's bundle. *(API)*
5. **Propagation:** a newly registered Build's Canaries reach a running Shield within 15 s even though the Policy version did not change. *(API, shield)*

## Contracts

### P1 — Protocol

- `packages/protocol/src/canaries.ts` (isomorphic): `CANARY_KINDS = ["key", "route"]`, `CANARY_PLAN`, `CANARY_LIMITS = { perBuild: 10, perBundle: 100, buildsInBundle: 20 }`, `CanarySchema { id, kind, value }` (value pattern per kind: `^ak_live_[0-9A-Za-z]{32}$`, `^/api/internal/[0-9a-z]{8}/(export|debug|config|backup|sync)$`), `LEAK_RULES` (ids and titles, table above), `LeakScanSummarySchema { status, suppressed }`, `LeakAllowlistSchema`, `canarySignalId(id)` and `parseCanarySignal(signalId) → cny id | null`, `EXAMPLE_CANARIES`.
- `build.ts`: `BuildManifestSchema` gains optional `leak_scan` and `canaries` (default absent; round-trips); `BuildSchema` exposes them.
- `policy.ts`: `BundlePayloadSchema` gains optional `canaries` (≤ 100).
- `incidents.ts`: `DETECTION_RULES` gains `{ key: "canary-touched", title: "Canary used", severity: "high", threshold: 1, window_s: 300 }`; `IncidentSchema` and `DetectionSchema` gain `canary_id: string | null` and `build_id: string | null` (Detection: `canary_id` only).
- `ID_PATTERNS.cny`; server entry `deriveCanaries(seed: number): Canary[]` (HMAC as above, deterministic, known-answer vector pinned) and `leakFingerprint(rule, path, value)`.

### P2 — Harden (`packages/harden`)

- `src/leaks/rules.ts`, `src/leaks/scan.ts`: `scanLeaks(files: { path, text }[], fileNames: string[], allow: Allowlist) → { findings, suppressed }`; line numbers; masking; fingerprints from the protocol.
- `src/canaries.ts`: `plantCanaries(outputFiles, canaries) → outputFiles` (one statement, one file, never a skipped file).
- `engine.ts`: order = leak scan (input) → transforms → plant → budget gate (planting counted) → emit. Report gains `leak_scan` (`{ status, findings: [...masked], suppressed }`) and `canaries` (`[{ id, kind }]` — values only in `--json` and the Manifest, since they are decoys the developer may want to test with).
- CLI: `--leak-allow <file>`; exit code 3 on leaks; human output lines `✓ leak scan clean` / `✗ leak scan: N findings` (rule, path:line, masked, fingerprint) and `✓ N Canaries planted` (+ "not watched: pass --register" when not registering); Manifest carries `leak_scan` and `canaries`.

### P3 — API (`apps/api`)

- Migration `0007_canaries.sql`: `canaries (organization_id, id, app_id, environment, build_id, kind, value, created_at)` with the standard RLS; unique (organization_id, id); `incidents` and `detections` gain nullable `canary_id` (and `incidents.build_id`); a change to the one-active-Incident index so Canary Incidents group by Canary too.
- Build registration stores the Manifest's Canaries in the same transaction (409 on a Canary id already registered to another Build).
- Bundle issuer adds the active Canaries (latest 20 Builds of the App and Environment, ≤ 100) and folds a digest of the Canary set into the ETag.
- Detector: the `canary-touched` rule from the Event's signals, verifying each Canary id in the tenant transaction; Incident and Detection carry the Canary and Build ids.
- Build and Incident routes expose the new fields (Build detail: `leak_scan`, `canaries` as `{ id, kind }` — values are not returned by the API).

### P4 — Shield (`packages/shield-node`)

- Policy store holds `canaryKeys: Map<value, id>` and `canaryRoutes: Map<path, id>` built once per applied bundle.
- Express middleware: extract bearer token, `x-api-key`, `api_key` query parameter; look up; check the raw and canonical path; add signals. Never logs or emits the value. Same-version bundle with a changed Canary set is applied (poller/verify adjust; tests).
- Bench: a case with 100 Canaries loaded; budget unchanged.

### P5 — Console (`apps/console`)

- Build detail: a **Leak scan** fact (Clean / Clean with N suppressed) and a **Canaries** panel (count, kind word, id); Build list shows the Canary count.
- Incident page: when `canary_id` is set, facts show the Canary (kind + id) and a link to its Build; the list shows the "Canary used" title like any rule.
- Catalog keys, tokens only, stub API extended.

## Tasks

Order: Task 1 (protocol) → Tasks 2–5 in parallel (harden ‖ API ‖ Shield ‖ Console) → Task 6 → Task 7.

### Task 1: Protocol (P1)
Failing tests first: schemas and limits, value patterns, optional Manifest fields round-trip and old Manifests still parse, bundle field stripped by an old schema copy, `deriveCanaries` known-answer vector and determinism, `leakFingerprint`, signal helpers, rule table, entrypoint export lists.

### Task 2: Harden (P2)
Failing tests first: each leak rule positive and negative; a secret inside a string that `balanced` would encrypt is still found; no value in any output channel; allowlist suppresses by fingerprint, malformed allowlist fails; exit code 3 and nothing written or registered; planted Canaries never reported; determinism with Canaries; behaviour equivalence across seeds with Canaries; no global created (run the output and compare `globalThis` keys); budget gate with planting; skipped file never planted.

### Task 3: API (P3)
Failing tests first: registration stores Canaries (tenancy, duplicate id 409); bundle includes only the App+Environment's Canaries, ≤ 100, latest 20 Builds; ETag changes with the Canary set; detector opens a High Canary Incident from one signalled Event, joins on repeat, ignores unknown and foreign ids; Incident/Build responses carry the new fields and never Canary values; alert payload includes the new fields.

### Task 4: Shield (P4)
Failing tests first: bearer, `x-api-key`, `api_key` and route matches (raw and canonical) add the signal; a near miss does not; the response is unchanged; the value never appears in the Event or a log; same-version bundle with new Canaries is applied; bench with 100 Canaries within budget.

### Task 5: Console (P5)
Failing tests first: Build detail leak-scan fact and Canaries panel; Incident page Canary facts and Build link; copy pins; build.

### Task 6: End to end
HTTP: harden a copy of the reference bundle with a planted test secret (a documented example value such as AWS's `AKIAIOSFODNN7EXAMPLE`) → exit 3 with a masked finding and nothing registered; add its fingerprint to an allowlist → harden passes, registers the Build with Canaries; the reference app's Shield picks up the bundle; a request with the decoy key as a bearer token and one to a decoy route → one High "Canary used" Incident per Canary within 60 s naming the Build, and a signed alert. Browser: the Build shows its Canaries and leak-scan result; the Canary Incident links to the Build.

### Task 7: Docs, memory, review
README, ticket proof, MEMORY.md, PRD slice table; `npm run verify`, `npm run e2e`, `npm run bench`; independent review; fixes test-first; Jev-verify completion claims.

## Residual risks known up front

- Canary values derive from the 32-bit build seed so that output stays reproducible. An attacker who brute-forces the seed from the mangled output could recompute the Canaries and avoid them. Deriving from a tenant secret (SDD §8 diversity) is the later fix.
- A decoy route on the customer's origin is only seen where Shield runs.

## Deliberately not in this slice

Watermark and *Identify build* · origin lock and Clone Beacon · client-side Canary reads (Guard) · blocking on Canary use (09) · control-plane allocation · Canary retirement.

## Amendments

- **A1 — Seed normalisation (Jev: normalize_uint32, 0.96).** Harden normalises the seed once with `seed >>> 0` and passes that value to both the PRNG and `deriveCanaries`, so two seeds that give the same transforms give the same Canaries (`--seed -5` equals `4294967291`).
- **A2 — Protocol as built.** `ID_PATTERNS.cny` lives in `constants.ts`; extra exports `CANARY_ROUTE_WORDS`, `CANARY_VALUE_PATTERNS`, `CANARY_SIGNAL_PREFIX`, `LEAK_LIMITS`, `EXAMPLE_CANARY_INCIDENT`; the Incident schema does not tie `rule === "canary-touched"` to non-null `canary_id`/`build_id` (the API guarantees it). Known answers for seed 1: key `cny_33d265fca16c848eb2f23f43` = `ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE`; routes `/api/internal/un539n4s/backup`, `/api/internal/60nekyby/backup`.
- **A3 — The planted statement matches `secret-assignment`.** The scan runs on the input before planting, so a hardened output is never re-scanned by Harden; a future output scan must exclude the Build's own Canaries by value.
- **A4 — Build responses carry Canaries as id and kind (Jev: ids_only, 1.0).** `BuildSchema` overrides `canaries` with `BuildCanarySummarySchema { id, kind }`; a value given to it is stripped. Values exist only in the developer's local report/Manifest and in Shield's signed bundle.
- **A5 — Route Canaries match regardless of case (Jev: case_insensitive, 1.0).** Express and slice-02 Rules ignore case, so a request reaching the decoy's handler in any case is signalled. Keys stay exact. Several `x-api-key` headers joined by Node are not split; `api_key` is read with `URLSearchParams`. A malformed Canary entry refuses the whole bundle (as a malformed Rule does), and the applied Policy stays.
- **A6 — Console as built (Jev: accept_all, 0.95).** The Incident page reads the Build to show the Canary's kind (falls back to the id); the Build list shows a Canary count ("—" before slice 07); a **Markers** section on the Build holds the leak-scan fact and the Canaries panel (UIUX SCR-07).
- **A7 — API as built.** At most 4 distinct Canary ids are counted per Event (bounded detector cost); an empty Canary set omits the bundle member; Canary ids are unique per Organization; database checks tie `canary-touched` to non-null `canary_id`/`build_id`. Evidence is limited to the counted Canaries too (A12).
- **A8 — Harden as built.** `hardenBundle()` = allowlist → leak scan of every non-`node_modules`/`.git` file (non-UTF-8 files listed as not scanned) → transforms → planting in the first protected file that fits the budget → integrity wrapper (covers the Canaries). Exit 3 on leaks, 2 on a bad allowlist. When no file can hold the Canaries within budget the harden fails (exit 1) — Jev was split (0.4); the owner chose to keep failing the build on 2026-11-11.
- **A9 — Planting falls through to the next protected file that fits the budget** (review L5): better than failing on the first file; the run fails only when no file fits.
- **A10 — Canaries scoped to App and version when registering (Jev: derive_with_app_version, 0.88; review M3).** With `--register`, `deriveCanaries(seed, { appId, version })` uses HMAC key `antireverse/canary/v2/<seed>` and prefixes `<appId>\n<version>\n`, so a pinned `--seed` can register many Builds and each Canary names one Build. Without `--register`, seed only (v1). Same inputs still reproduce byte for byte.
- **A11 — Review fixes (Jev: fix_all_latin1, 0.84).** M1 `secret-assignment` accepts a TypeScript type annotation; M2 unquoted `NAME=value` / `name: value` in config files; M4 a file that is not valid UTF-8 is scanned as Latin-1 (only files with a NUL byte are skipped, and listed); L1 never plant into declaration files; L2 Shield refuses an older same-version bundle (no Canary rollback by replay); L3 bearer with several spaces or a tab; L4 line lookup no longer quadratic. Residual: symlinked files are not scanned; detector writes per signalled Event have no in-flight bound; Shield's 10k event buffer can drop a Canary Event under a flood; extra internal-URL forms (`0.0.0.0`, `127.1`, escaped slashes) are not flagged.
- **A12 — Canary evidence lists only Events that counted (owner's decision 2026-11-11; Jev leaned 0.46).** `ruleConditionSql("canary-touched")` applies the same rule as `touchedCanaries`: the Canary must be among the Event's first 4 distinct Canary signals in signal order. Proven by `apps/api/test/canaries.test.ts` ("never one naming it past the per-Event cap"), seen red first. `jev_review`: escalate on low confidence (no defect named).
