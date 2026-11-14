---
title: "Plan — Slice 17a Usage metering"
aliases: [Plan 17a]
project: anti-reverse
doc: PLAN
slice: 17
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - plan
---

# Slice 17a — Usage metering Implementation Plan

> Test first. One worker per workspace. Verify by running commands.

**Spec:** [tickets/17a-usage-metering.md](../tickets/17a-usage-metering.md).

## Global constraints

- **Migration 0036:**
  - **`usage_daily`** (organization_id, app_id, environment, day date, requests bigint, sandbox_seconds bigint): primary key on all four keys, tenant RLS. The request role gets only what ingest and the Assessment finish need, preferably through a definer bound to `app.tenant_id`. Increment with `INSERT … ON CONFLICT DO UPDATE` inside the ingest transaction, using the RETURNING count.
  - **`usage_device_salts`** (month date primary key, salt bytea): owner-only, no tenant column.
  - **`usage_devices`** (organization_id, app_id, month, device_ref): primary key on all four.
  - **`usage_monthly_devices`** (organization_id, app_id, month, devices).
  - **Rollup:** a daily owner job closes months before the current one. It writes the distinct counts, deletes those references, and deletes the salt.
  - **Recording a device:** a definer creates the current month's salt on first use, writes the reference, and is granted to the request role. The attest route has no tenant session, so check how it resolves the Organization and App.
- **Sandbox seconds:** recorded where an Assessment's end is stored (`stores/assessments.ts`). It is idempotent per Assessment: the end is recorded once, guarded by the status transition.
- **Route:** `GET /v1/usage?month=` with Protocol schemas. It is refused while a deletion is pending (the existing gate) and rate-limited per Organization (reuse the audit read limiter or an equivalent).
- **Catalog:** the 18b/18c catalog tests.
  - `usage_daily`, `usage_devices` and `usage_monthly_devices` go in `RETENTION_CLASSES` as kept, with a reason (13 months of usage history; enforce it with the retention sweep, or state it). Prefer sweeping rows older than 13 months.
  - Add the same tables to `EXPORT_TABLES` and the purge seed.
  - `usage_device_salts` goes in `GLOBAL_TABLES`.
- **Job:** a daily usage rollup job like the purge and retention jobs (`runOnce`/`flush`, started in `startApi`), or folded into the retention job.
- **Console:** Settings nav "Usage" (`app-shell.tsx`), `/settings/usage`, a month picker as a GET form (no client JS needed), and a chart following the dataviz conventions already in the Console, if any.
- **TC-CON-010:** an HTTP e2e (`tests/e2e/*.http.test.ts`) that runs a real Shield middleware against the API with N requests, flushes, and compares the metered count.

## A1 — As built (2026-11-14)

- **Sandbox seconds:** recorded by a definer trigger on the Assessment status transition (it also covers restart interruptions), capped at the tier budget plus 120 s.
- **Requests:** the counter sits inside `insertEvents`.
- **Device references:**
  - HMAC is computed in Node, with month salts in `usage-salts.json` (D-090).
  - Daily cap of 50,000 new references per App, tracked in `usage_device_days`, with an over-cap flag.
  - The rollup is folded into the retention job with its own budget; it counts each closed App-month once and deletes references in batches.
  - A month closes 1 hour after it ends.
- **Usage reads** share the per-Organization read limit (D-091).
- **Console:** month form without JS, an SVG daily chart with a table equivalent, and stub parity, including the API's `too-many-requests` problem.
