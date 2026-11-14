---
title: "Ticket 17a — Usage metering"
aliases: [Ticket 17a]
project: anti-reverse
doc: TICKET
slice: 17
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# 17a: Usage metering

**What to build:** An Org Owner can see each month's usage per App: protected requests, monthly active Guard devices and Prove sandbox minutes, plus the current Apps count and the Event retention setting. This covers PRD story 10, FR-CON-08 (metering part), PRD §16 dimensions and QASUITE TC-CON-010.

**Out of scope:** prices, plans, limits and invoices. They wait for Q4 and slice 17b.

**Status:** done on 2026-11-14. Plan: [plans/2026-11-14-slice-17a-usage-metering.md](../plans/2026-11-14-slice-17a-usage-metering.md).

**Blocked by:** nothing. Design: core counters (Jev 0.86, confidence 0.84, D-089).

## Acceptance criteria

Metering

- [x] **Protected requests:**
  - Counted at ingest, in the same transaction as the insert.
  - Only newly stored Events count, so retries are not counted twice.
  - Stored per Organization, App, Environment and UTC day.
  - Exact even after retention deletes Events.
- [x] **Prove sandbox minutes:** the seconds of each Assessment that ran (from start to finish, or the call log's seconds), recorded once when it finishes, per App and UTC day.
- [x] **Monthly active Guard devices:** counted at `POST /v1/attest`, per App and UTC month, as a distinct count of a monthly reference.
  - The reference is a keyed hash of the per-App device subject.
  - The key is a random salt per month, kept in an owner-only table.
  - After a month closes, its distinct count is rolled up into a monthly total. Its references and its salt are then deleted, so references from different months cannot be linked.
  - No raw device identifier is stored.

Reading

- [x] **`GET /v1/usage?month=YYYY-MM`** (admin key; defaults to the current UTC month) returns:
  - totals and a per-App breakdown for requests, Guard devices and sandbox minutes;
  - daily request counts;
  - the current Apps count and the Event retention;
  - seats reported as not applicable (no member accounts yet).
- [x] **Range:** months in the future and months older than 13 months are refused.
- [x] **Rate limit:** reads share an existing per-Organization limit.

Console

- [x] **Settings → Usage:** a month picker, totals, a per-App table and a daily requests chart, in the restyled design (D-053).

Quality

- [x] TC-CON-010: a synthetic load of a known number of requests through Shield to the API is metered within 1%, and exactly when nothing is dropped.
- [x] Usage tables are covered by the catalog tests: purge, export and retention classes.
- [x] `npm run verify` passes; Playwright covers the Usage page.

## Proof

| Criteria | Proven by |
|---|---|
| Requests at ingest, retry-safe, exact after retention | `apps/api/test/usage-metering.test.ts`, `usage-db.test.ts` |
| Sandbox seconds, once per run, outage not billed | `usage-db.test.ts` |
| Guard devices: verdicts, daily cap, salts outside the database, unlinkable after rollup, restart-safe | `usage-db.test.ts`, `usage-metering.test.ts`, `usage-salts.test.ts` (salt bytes found in no file of the PGlite data directory) |
| `GET /v1/usage` | `usage-routes.test.ts`, `packages/protocol/test/usage.test.ts` |
| Catalog (purge, export, retention classes) | `data-purge`, `data-export`, `retention-db` tests |
| Console | `apps/console/test/usage-*.test.*`, `stub-usage.test.ts`, `tests/e2e/usage.e2e.ts` |
| TC-CON-010 | `tests/e2e/usage-metering.http.test.ts`: 600 requests through the real Shield are metered as exactly 600; the test fails when the ingest counter is removed |
| Quality | `npm run verify` (7,967 tests in 289 files, type-check, lint) · Playwright 25/25 |

**Independent reviews:** two, each reproducing what it reported. All findings were fixed test-first.
- **API** (3 MEDIUM, 2 LOW):
  - An interrupted run billed the outage.
  - Anyone could inflate the device count.
  - Salts were recoverable from PGlite files.
  - The rollup rescanned on every call.
  - Minutes did not add up.
- **Console** (1 MEDIUM, 2 LOW, 1 info):
  - The devices note overstated what is counted.
  - The picker showed the wrong month at UTC midnight.
  - Stub drift on repeated `month` and on the 429 text.

**Jev:** verified 4 of 4 completion claims. Its review of the change summary escalated (safe_to_apply 0.28, limited by the test gap); it was judged from a summary without the tests.

## Honest limits

- **Requests are counted as received by the API.** Requests Shield drops (buffer overflow, giving up after retries) and batches the API refuses are not metered.
- **A real browser can still inflate the device count up to the daily cap,** because Guard's signals are reported by the client. Past the cap the count is shown as a lower bound.
- **The salt file is deleted, not securely erased.** A deleted month's key can linger on disk until it is overwritten. The database and its backups never hold it.
- **Seats** do not exist until members exist.
