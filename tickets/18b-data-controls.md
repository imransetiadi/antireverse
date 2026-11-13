---
title: "Ticket 18b — Data controls: export and deletion"
aliases: [Ticket 18b]
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
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# 18b: Data controls — export and deletion

**What to build:** An Org Owner can export all of their Organization's data, delete the Organization (with a 7-day grace they can cancel), and export or erase one end user's records by actor hash. (PRD story 61, FR-CON-11 export and deletion; SECURITY §8 deletion and access requests; OPERATION §17 report; QASUITE TC-CON-007.) Configurable retention and the daily retention job are slice 18c.

**Blocked by:** nothing. Owner chose 18b, export and deletion first (Jev 0.42, confidence 0.32, so asked), and a 7-day grace (2026-11-13, D-080). Jev: streamed export and a definer purge (0.86), subject erasure of events and ended blocks (0.94) (D-081).

**Status:** done on 2026-11-14 — plan in [plans/2026-11-13-slice-18b-data-controls.md](../plans/2026-11-13-slice-18b-data-controls.md)

## Acceptance criteria

Organization export

- [x] `GET /v1/organization/export` streams NDJSON: a manifest line first, then every tenant table's rows (keyset paging, bounded memory), then a closing line with per-table counts and a SHA-256 over all preceding lines, signed with the audit key. Key hashes, never keys. Admin key only; rate-limited; audited.

Organization deletion

- [x] `POST /v1/organization/deletion` (typed confirmation of the Organization name, reason required) marks the Organization pending with `purge_after` = now + 7 days. From then on every key of the Organization is refused (`organization-deletion-pending`) except for deletion status, cancel and export. Audited.
- [x] `DELETE /v1/organization/deletion` cancels while pending (reason required); everything works again. Audited.
- [x] A daily in-process job purges Organizations past `purge_after` by an owner-only security-definer function that deletes every row of that Organization in every tenant table, the audit chain included, in one transaction, and records a tombstone with a deletion report (rows per table, times) signed with the audit key. The report is available from `GET /v1/deletions/:id/report` with the deletion id given at request time.
- [x] A test enumerates every table with an `organization_id` column from the catalog and fails if any row of a purged Organization remains, so a table added later cannot be missed (TC-CON-007).

Subject requests

- [x] `POST /v1/subjects/export` with `{ ip_hash }` returns that actor's Events and containments; `POST /v1/subjects/erase` (reason required) erases matching Events and ended (lifted or expired) actor containments, keeps active blocks until they end and lists them in its report. Both audited with counts. The hash is computed by the customer with the Shield key (`actorHash`); Airverse never receives the address.

Console

- [x] **Settings → Data controls**: Export (download), end-user request by actor hash (export, erase with reason and confirmation), and Delete Organization (typed name, reason, the date the data will be erased, Cancel deletion while pending) — in the restyled design (D-053).

Quality

- [x] `npm run verify` passes; an end-to-end test exports an Organization with data in every area, requests deletion, sees the keys refused, runs the purge, finds no rows left in any table and reads the signed report.

## Proof

| Criteria | Proven by |
|---|---|
| Export (signed, bounded memory, audit chain to its head) | `apps/api/test/data-export.test.ts`; `packages/protocol/test/data-controls.test.ts` |
| Deletion, gate, cancel, purge job, signed report | `apps/api/test/data-deletion.test.ts`, `data-purge.test.ts` (catalog-wide: every table with `organization_id`, and every table must have one), `data-pending.test.ts` (no Assessments, re-checks or live streams while pending; D-082 pinned) |
| Subject requests | `apps/api/test/data-subjects.test.ts` (active blocks kept; no actor hash in audit entries) |
| Console | `apps/console/test/data-*.test.*`; `tests/e2e/data-controls.e2e.ts` (export, subject erase, request deletion → every page redirected with the banner → cancel) |
| TC-CON-007 | `tests/e2e/data-controls.http.test.ts` (export verified, keys refused, purge, no row left in any table, second Organization intact, signed report); fails when the purge skips one table |
| Quality | `npm run verify` — 7,814 tests in 271 files, type-check, lint · Playwright 23/23 |

Two independent reviews (API, Console) reproduced 4 MEDIUM and 3 LOW in the API (export memory by rows, Assessments and re-checks running while pending, an inconsistent signed export, live streams outliving the deletion, a catalog blind spot, the actor hash kept in audit entries) and 3 MEDIUM and 5 LOW in the Console (a 500 on `/` while pending, an unbounded body read before the session check, stub drift, stale notices, the actor hash in URLs, cross-site downloads, stub rate-limit and validation order); all fixed test-first, except the beacon staying open while pending, which the owner decided (D-082). Jev verified 4 of 4 completion claims.

## Honest limits

- **Actor hashes in older audit entries.** From the 18b review on, `subject.export`, `subject.erase` and `containment.create` entries name an end user by a derived reference (`subj_` + the first 32 hex characters of SHA-256 of `antireverse/audit-subject/v1`, the Organization id and the actor hash; `auditSubjectRef`), never by the actor hash. Entries written before that (a `containment.create` summary "Blocked the Actor iph_…") keep the hash: the chain is append-only, and rewriting it would break every signed head handed out. They go only with the Organization's purge.
- **Export consistency is per page.** Each page is read in its own transaction; a change made while an export streams may appear in one table and not in another. The audit chain is the exception: it is exported first, up to the signed head named in the manifest (`audit_head`, `consistency: "per-page"`).
- **In-memory state after a purge.** The purge job evicts the Detector's windows and Policy coverage and the Clone Beacon's per-Build limits and known tokens of the purged Organization. What stays until it expires on its own: the per-Organization rate-limit windows (audit reads and exports, 1 minute; Policy simulations, 1 minute; inventory buckets, minutes; email-channel and confirmation caps, the UTC day), the notifier's in-flight count (until the deliveries in flight end), attestation nonces (by App, until their TTL), and unknown-token entries of the beacon cache (10 minutes, not tied to an Organization). None holds tenant data beyond identifiers and counts.
- **Public endpoints while pending (D-082).** The Clone Beacon and the attestation endpoints have no key and stay open while a deletion is pending; what they record is removed by the purge.

## Out of scope — 18c and later

Configurable retention and the daily retention job for SECURITY §8 defaults · regional storage · backups (35-day backup expiry is the erasure bound for backups; documented) · per-user accounts.
