---
title: "Ticket 18a — Audit log"
aliases: [Ticket 18a]
project: anti-reverse
doc: TICKET
slice: 18
version: 0.1.0
status: done
updated: 2026-11-13
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"

# 18a: Audit log

**What to build:** An append-only, hash-chained audit log of every administrative and security-relevant action, visible to the tenant and exportable, so an Org Owner can answer "who changed this policy?" (PRD story 7, FR-CON-06; SECURITY O6, SC-LOG-01; OPERATION retention ≥ 1 year; QASUITE TC-CON-004).

**Blocked by:** nothing. Owner chose 18a (2026-11-13). Jev: explicit entries in the same transaction, coverage enforced by a route-table test, an optional reason that sensitive actions require (0.99).

**Status:** done on 2026-11-13 — plan in [plans/2026-11-13-slice-18a-audit-log.md](../plans/2026-11-13-slice-18a-audit-log.md)

## Acceptance criteria

- [x] Every mutating administrative API route writes one audit entry in the same transaction as its change: action, target ids, actor (the admin key's id and kind — no user accounts yet), time, request id, a reason when given, and a short summary without secrets. A change that cannot write its entry does not commit.
- [x] Entries are append-only (the request role cannot UPDATE or DELETE) and hash-chained per Organization: sequence, previous hash, entry hash over canonical JSON. `GET /v1/audit/verify` recomputes the chain and reports the first broken sequence.
- [x] `GET /v1/audit` lists entries newest first with filters (action, App, target id, time range) and cursor paging; `GET /v1/audit/export` streams NDJSON with the hashes so a third party can verify. Admin key only; tenant-isolated.
- [x] A reason (`X-Airverse-Reason`, ≤ 500 characters) is accepted on every mutating route and required on sensitive ones: promoting a Rule or virtual patch to enforce, containment, signing Rules of Engagement, deleting a target. The Console asks for it there.
- [x] Console **Settings → Audit log**: the list with filters, an entry's details, chain status, and Export — in the restyled design (D-053).
- [x] A route-table test enumerates every non-GET administrative route and fails when one writes no entry (TC-CON-004 part 1); a test alters a stored entry directly and sees verification name it (part 2). Entries are kept at least one year (no deletion job shorter than that).
- [x] `npm run verify` passes; an end-to-end test performs a policy promotion with a reason in the Console and finds it in the audit log with actor, reason and a valid chain.

## Proof

| Criteria | Proven by |
|---|---|
| Entries in the change's transaction, coverage | `apps/api/test/audit-coverage.test.ts` (walks the route table; one entry per mutating admin route; no secrets in any summary) |
| Chain, append-only, tamper, signed head | `apps/api/test/audit.test.ts` (gapless seq under concurrency, edits/deletions/truncation detected, trigger-maintained head, Ed25519 signed head) |
| Reason | `apps/api/test/audit.test.ts`, `packages/protocol/test/audit.test.ts` (percent-encoded UTF-8, codes, secrets refused) |
| Console | `apps/console/test/audit-*.test.*`; `tests/e2e/audit.e2e.ts` (promote with a reason, entry with actor and reason, chain verified, export) |
| Quality | `npm run verify` — 7,678 tests, type-check, lint · Playwright 22/22 |

Two independent reviews (API, Console) reproduced: a reused Rule id enforcing a new path without a reason, verify holding the database, undetectable tail truncation and a corruptible head, unsafe or secret-bearing reasons, a crash on out-of-range dates, the reason wiped after a refusal, focus loss, and mismatched secret checks; all fixed test-first. Jev verified the completion claims.

## Honest limits

The actor is the admin key, not a person (no user accounts yet). The chain detects tampering and, with a kept signed head, truncation; it does not prevent an owner with database access from rewriting history and re-signing with a key they hold. The verify and export reads are limited to 20 per Organization per minute.

## Out of scope

Members and per-user actors (with accounts) · second approver · step-up authentication · SIEM streaming.
