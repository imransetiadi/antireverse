---
title: "Plan — Slice 18b Data controls"
aliases: [Plan 18b]
project: anti-reverse
doc: PLAN
slice: 18
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SECURITY]]"
  - "[[OPERATION]]"
  - "[[QASUITE]]"
---

# Slice 18b — Data controls Implementation Plan

> Test first; one worker per workspace; verify by running commands. CLAUDE.md Rule 1: list real forks in the report.

**Goal:** An Org Owner can take all their data out, erase one end user, and delete the Organization so that nothing of it remains.

**Spec:** [tickets/18b-data-controls.md](../tickets/18b-data-controls.md); SECURITY §8; OPERATION §17; QASUITE TC-CON-007; PRD FR-CON-11.

## Global constraints

- **Export:** NDJSON, `content-type: application/x-ndjson`, attachment name `airverse-<org id>-<UTC date>.ndjson`. Line 1 `{"kind":"manifest","format":"airverse.export.v1","organization_id","generated_at","tables":[…]}`; then `{"kind":"row","table":"<name>","row":{…}}` per row, tables in a fixed order, each paged by primary key (500 per page, yielding between pages); last line `{"kind":"end","counts":{table:n},"sha256":<hex over the bytes of all preceding lines>,"signature":<Ed25519 by the audit key, base64url>,"key_id"}`. Verifiable with `/v1/audit/public-key`. Credential tables export their hashes, prefixes and last4 only. Artifact bytes as base64. Rate limit: shares the 20/min per-Organization audit read budget. Audited `organization.export`.
- **Deletion state:** migration 0033: `organization_deletions` (id `del_<24 hex>`, organization_id, organization_name, requested_at, requested_by key id, reason, purge_after, cancelled_at, purged_at, report jsonb, report_signature) — owner-managed, not under tenant RLS for the purge record; the request role reads only its own Organization's pending row through a definer function. A pending deletion = a row with neither `cancelled_at` nor `purged_at`. At most one pending per Organization (partial unique index).
- **Gate:** `requireKey` refuses keys (admin and Shield) of an Organization with a pending deletion with 403 `organization-deletion-pending`, except `GET /v1/organization/deletion`, `DELETE /v1/organization/deletion`, `GET /v1/organization/export`. Ingest from Shield is refused too (no new data while pending).
- **Purge:** owner-only `organization_purge(org text, at timestamptz)` security definer: deletes from every table with `organization_id` (derived from the catalog inside the function, children before parents), the audit tables included (the append-only trigger allows it only inside this function, e.g. via a transaction-local setting the request role cannot set because it cannot execute the function), then the `organizations` row; returns counts per table. The job writes `purged_at`, the report and its signature. Job: `createPurgeJob({ db, now, logger, everyMs = 86_400_000 })` with `runOnce()` for tests and `flush()` on close, started in `startApi` like the re-check job.
- **Subject requests:** body `{ ip_hash }` matching `ACTOR_HASH_PATTERN`. Export: events with `payload->'actor'->>'ip_hash'` = hash (uses `events_by_actor_hash`), containments with that hash; NDJSON same line format with kind `subject`. Erase: reason required; deletes those events and containments that are lifted or expired; report `{ events_erased, containments_erased, active_containments: [{id, expires_at}] }`. Audited `subject.export` / `subject.erase` with counts and the hash.
- **Audit:** new actions `organization.export`, `organization.deletion.request`, `organization.deletion.cancel`, `subject.export`, `subject.erase`; deletion request, cancel and subject erase are sensitive (reason required). The audit coverage test must stay green.
- **Console:** `/settings/data` (Settings nav "Data controls"); server actions forward the reason header; downloads through session-checked route handlers like the audit export.

## Tasks

1. Protocol: schemas (export lines, deletion status, subject request/report), new audit actions, problem codes. 2. API: migration 0033, purge function, gate, routes, job, catalog-wide test, export verification test. 3. Console: Data controls page. 4. e2e (TC-CON-007) and docs.

## A1 — As built (2026-11-13/14)

Migrations 0033 (deletions, purge function, gate function) and 0034 (review: pending Organizations left out of the Assessment queue and re-checks, purge retry columns, `events_by_subject`). Forks accepted: the report is public by its random deletion id (Jev 0.71); public keyless routes stay open during the grace (owner, D-082); per-table page sizes for large rows; the export's audit tables come first, bounded by the signed head in the manifest (Jev 0.84); a derived `subj_` reference in audit entries (Jev 0.80); the Console redirects every page to Data controls while pending (Jev 0.87); the actor hash kept out of Console URLs (Jev 1.0); download routes refuse cross-site requests, the 18a audit export included.
