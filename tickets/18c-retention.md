---
title: "Ticket 18c — Retention: configurable event retention and the daily retention job"
aliases: [Ticket 18c]
project: anti-reverse
doc: TICKET
slice: 18
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SECURITY]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# 18c: Retention

**What to build:** An Org Owner can choose how long request metadata (Events) is kept, and a daily job makes the SECURITY §8 defaults true for the data Airverse holds. This covers PRD FR-CON-11 (retention), SECURITY §8 (default retention) and OPERATION §17 (nightly jobs).

**Blocked by:** nothing.

**Status:** done on 2026-11-14. Plan: [plans/2026-11-14-slice-18c-retention.md](../plans/2026-11-14-slice-18c-retention.md).

**Decisions:**
- Scope (Jev 0.65, confidence 0.59, D-085): the core sweep.
  - Builds and audit entries are not pruned in this slice.
- Default (owner, 2026-11-14, after Jev 0.42, D-086):
  - New Organizations keep Events 30 days.
  - Organizations that exist at release are set to 395 days.
  - Choices are 7, 30, 90, 180 and 395 days.

## Acceptance criteria

Setting

- [x] **`GET /v1/organization/retention`** returns:
  - the Event retention;
  - the fixed periods: Guard reports 30 days, evidence 395 days, artifacts 30 days after the Assessment;
  - the last run for this Organization (time and rows removed per table).
- [x] **`PUT /v1/organization/retention`** with `{ event_retention_days }` (one of 7, 30, 90, 180, 395):
  - It takes the admin key only.
  - It is audited as `organization.retention.update`.
  - Shortening is sensitive: it requires `X-Airverse-Reason` and the response says from when older Events go.
- [x] Migration: existing Organizations get 395 days; new Organizations get 30 days.

Daily job

- [x] An owner-only security-definer `retention_sweep` runs from an in-process daily job. It removes, per Organization:
  - Events received before the Organization's retention; Guard Events after at most 30 days.
  - Containments that ended (lifted or expired) longer ago than the Event retention, since they hold the account reference.
  - Incidents whose `last_seen` is older than 395 days, with their Detections and alert deliveries; an Incident still referenced by a containment that has not ended is skipped.
  - Alert deliveries older than 395 days.
  - Assessments that finished more than 395 days ago.
  - Expired artifacts, through the existing `assessment_artifacts_expire`.
- [x] Deletes are batched so that one run never holds long locks; a run that is cut short continues at the next run.
- [x] Each run records rows removed per table per Organization. Only the most recent 30 runs are kept.
- [x] A catalog test classifies every tenant table as swept (with its rule) or kept (with its reason). A new table that is not classified fails the test.

Console

- [x] **Settings → Data controls → Retention:**
  - A table of what is kept and for how long.
  - The Event retention choice; shortening asks for a reason and states what will be removed.
  - The last run's counts.
- [x] Incident evidence notes that Events older than the retention are removed.

Quality

- [x] `npm run verify` passes.
- [x] Playwright covers changing the retention.
- [x] An end-to-end test seeds old and new rows in every swept table, runs the job, and finds exactly the old ones gone.

## Proof

| Criteria | Proven by |
|---|---|
| Setting, routes, audit, reason when shortening, gate, locked read | `apps/api/test/retention-routes.test.ts`, `audit-coverage.test.ts`, `packages/protocol/test/retention.test.ts` |
| Migration defaults (existing 395, new 30), privileges, catalog classification | `apps/api/test/retention-db.test.ts` (an unclassified new table fails the test) |
| Sweep rules, batching and fairness, FK cases, Set up kept, subject erasure keeps Set up, artifact counts | `apps/api/test/retention-sweep.test.ts`. Disabling the Guard rule fails it; removing the containment check fails 4 tests |
| Console | `apps/console/test/retention-*.test.*`, `stub-retention.test.ts`, `tests/e2e/retention.e2e.ts` |
| Quality | `npm run verify` (7,880 tests in 280 files, type-check, lint) · Playwright 24/24 |

**Independent reviews:** two, each reproducing what it reported.
- **API:** 2 MEDIUM and 2 LOW.
  - One Organization's backlog starving the others.
  - The sweep resetting the Set up steps.
  - Artifacts missing from per-Organization counts.
  - Incident steps scanning every row.
- **Console:** 1 MEDIUM and 3 LOW.
  - Shortening without JavaScript failed silently.
  - A table name like `constructor` crashed the section.
  - A 401 and a pending-deletion 403 were shown as "could not be read".

All were fixed test-first, together with a locked read for PUT and subject erasure keeping Set up. Jev verified 4 of 4 completion claims. Jev's review of the change summary escalated: safe_to_apply 0.17 at low confidence, limited by the test gap. It was judged from a summary without the tests, so the owner decides (see the report).

## Honest limits

- **Builds are not pruned.** A Build has no end of life yet, and old Builds still serve clone beacons and canary lookups, so "life of the Build + 13 months" is not enforced.
- **The audit log is kept for the Organization's lifetime.** That meets "at least one year"; pruning would need a verify checkpoint.
- **Network mode is not built,** so there are no full addresses to truncate.
- **Old Incidents lose their evidence.** Incident evidence reads Events by time span, so an older Incident shows no evidence once its Events age out. The Incident page says so.
- **Owner functions bypass row-level security.** The sweep, the purge and subject erasure write tables with forced row-level security as the database owner, which works because the owner bypasses it (true in PGlite, where the owner is the superuser). A managed Postgres needs the owner role to have BYPASSRLS.
- **Artifact expiry is not batched** and also covers Organizations with a pending deletion, as before this slice.
- **Backups** expire after 35 days (as in 18b).
