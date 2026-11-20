---
title: "Plan — Slice 18g synthetic probes"
aliases: [Plan 18g]
project: anti-reverse
doc: PLAN
slice: 18
version: 0.1.0
status: done
updated: 2026-11-20
language: en
tags:
  - anti-reverse
  - plan
---

# Slice 18g — Synthetic probes Implementation Plan

> Test first. One worker. Verify by running commands.

**Spec:** [tickets/18g-synthetic-probes.md](../tickets/18g-synthetic-probes.md).

## Global constraints

- The probe reaches the API over HTTP on its listening address only. No database read or write stands in for a request; no `refreshPolicy()` or `flush()` on the probe's Shield.
- Probe keys exist in memory only. No log line carries a key or an identifier of the probe Organization.
- No port 8787 or 3000; tests bind port 0 or run in process. No sleeps in the runner's unit tests: clock, sleep and timers are injected.
- New database objects in migration `0043_probes.sql`. The registry is an operator table like `slo_minutes`: owner only, no `organization_id` column (it is not tenant data and must not be taken for a tenant table by the purge or the retention catalog).
- `apps/console/tsconfig.json` is not touched; no `next typegen`.

## Tasks

Each task: the test first, seen failing, then the code.

1. **Protocol** (`packages/protocol/src/slo.ts`, `test/slo.test.ts`)
   - Catalog: `probe: boolean` per SLO. SLO-06: `probe: true`, `good_within_ms: 30_000`, targets p95 30 s and p99 60 s, `measured: false` with the reason "probes are off" (the report turns it to measured while probes run). SLO-04: indicator names the probe's samples. SLO-08: sharper reason.
   - `ProbeLegSchema`, `ProbeStatusSchema`; `SloReportSchema.probes` (nullable).
   - `PROBES_VARIABLE`, `PROBE_PATH_PREFIX`, `PROBE_BOUNDS` (30 s / 60 s / 5 s / 30 s).
2. **Settings** (`apps/api/src/probe/settings.ts`): `readProbeSettings(env)`.
3. **Registry** (`migrations/0043_probes.sql`, `stores/system-organizations.ts`): `system_organizations(kind, org_id, app_id, created_at)`, owner only.
4. **Tenant** (`probe/tenant.ts`): find or create the probe Organization and App (system-actor audit entries, 7-day Event retention), revoke its old keys, insert fresh ones; answer the keys in memory.
5. **Runner** (`probe/runner.ts`): one cycle over a `ProbeTransport` (publish, decide, request, find Event); SLO samples; status; warnings; timer without overlap; stop. Unit tests with a scripted transport and a manual clock.
6. **Transport** (`probe/transport.ts`): the real one — `fetch` to the API, a `createShield` from `@antireverse/shield-node`, a loopback `node:http` server behind its middleware.
7. **Service** (`slo/service.ts`): `attachProbes(status)`; SLO-06 measured in the report, the metrics and the alert loop while attached; `probes` in the report.
8. **Server** (`server.ts`, `main.ts`, `index.ts`): `StartApiOptions.probes`; start after the jobs; stop first on close.
9. **Integration** (`apps/api/test/probe-server.test.ts`): `startApi` with probes on and fast Shield timers; one real cycle; SLO-06 and SLO-04 samples; a second Organization untouched; a restart keeps one probe Organization and the old keys answer 401.
10. **Console** (`features/ops/probe-status.tsx`, `app/ops/page.tsx`, messages, `scripts/stub-ops.mjs`, test helpers): the "Synthetic probes" section.
11. **Gate** (`tools/gate/src/catalog.ts`): the performance criterion's gap names PB-13 and PB-15 as measured only by an in-process probe.
12. **Docs:** README (Configuration, Operator SLO dashboard), PRD row 18, ticket "As built" and "Proof".

## Verification

- `npx vitest run --project protocol --project api --project console --project gate --project e2e`
- `npx tsc -b`
- `npx biome check <changed files>`
- Not run by the worker: the release gate and Playwright.
