---
title: "Plan — Slice 18a Audit log"
aliases: [Plan 18a]
project: anti-reverse
doc: PLAN
slice: 18
version: 0.1.0
status: done
updated: 2026-11-13
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"

# Slice 18a — Audit log Implementation Plan

> Test first; one worker per workspace; verify by running commands. CLAUDE.md Rule 1: list real forks in the report.

**Goal:** Every administrative change answers who, when, what and why, and tampering is detectable.

**Spec:** [tickets/18a-audit-log.md](../tickets/18a-audit-log.md); SECURITY O6, SC-LOG-01, SC-IAM-03; SDD §API `/v1/audit`; QASUITE TC-CON-004; OPERATION retention.

## Global constraints

- **Ids:** `aud_<24 hex>`. **Entry:** `{ id, organization_id, seq, at, actor: { kind: "admin_key", key_id }, action, app_id?, target: { kind, id }, reason?, summary, request_id, prev_hash, hash }`. `action` from a closed protocol enum named `<resource>.<verb>` (e.g. `policy.rule.promote`, `containment.create`, `api_key.create`, `alert_channel.delete`). `summary` ≤ 500 chars, never keys, tokens, secrets, email addresses in clear, or Canary values.
- **Hash:** `hash = sha256(prev_hash ‖ canonicalJson(entry without hash))`, genesis `prev_hash` = 64 zeros; `seq` from 1 per Organization, gapless. Concurrency: take a per-Organization lock (a chain-head row `FOR UPDATE`) inside the transaction.
- **Storage:** migration 0031: `audit_entries` (RLS + FORCE; request role SELECT and INSERT only, no UPDATE/DELETE), `audit_heads` (one row per Organization), indexes for listing and filters. No deletion job (retention ≥ 1 year).
- **Reason:** header `X-Airverse-Reason`, trimmed, 1–500 chars, no control characters; 400 `reason-required` on sensitive routes without it. Sensitive: Rule promote to enforce, patch promote to enforce, containment create, Rules of Engagement sign, target delete.
- **Coverage test:** walk Hono's route table; every non-GET route under `/v1` except public ones (ingest, attest, beacon, confirmations, organization signup handled explicitly) must be in an action map and produce exactly one entry when called successfully.
- **Console:** `/settings/audit`; reason field in the confirmation dialogs of the sensitive actions (forwarded as the header by the server actions).

## Tasks

1. Protocol: audit schemas, action enum, `auditHash`. 2. API: table, helper, every route, list/verify/export, coverage and tamper tests. 3. Console: Audit log page, reason in sensitive dialogs. 4. e2e and docs.

## A1 — Protocol and API as built (2026-11-13)

Migration 0031 (`audit_entries`, `audit_heads`), helper `src/audit.ts`, read routes `src/routes/audit.ts`; 25 actions over 22 mutating admin routes; excluded: Shield-key ingest (events, inventory), public routes (beacon, attest, confirmation) and the dry runs (policy simulate, prove authorize). Accepted as built: any newly enforced Rule counts as a promotion (publish or rollback); every patch enforce needs a reason; no-op successes write nothing; a test alert is audited before its send; server-generated request ids; names quoted in summaries with key and email shapes scrubbed; numeric cursor; export is the whole chain. Jev (1.0): the reason header carries percent-encoded UTF-8 (`encodeAuditReason`), length checked after decoding.

## A2 — Independent review of the API (2026-11-13)

Reproduced: F1 MEDIUM a reused Rule id enforced a new path without a reason (promotion now also covers changed enforcement fields); F2 MEDIUM verify held the single PGlite lock for the whole chain (paged, yielding, rate-limited); F3 MEDIUM tail truncation undetectable and the request role could corrupt the head (Jev 0.99: a trigger maintains the head, the request role loses write access to it, and verify/export carry a head signed by a separate Ed25519 audit key published at `/v1/audit/public-key`); F4–F6 LOW unsafe characters, raw non-ASCII header bytes, and secrets slipping the scrubber or arriving in reasons (reasons that look like keys, tokens or emails are refused); F7 `first_broken_seq` wording.

## A3 — Console and close-out (2026-11-13)

Settings → Audit log (filters, paging, details, chain status with the signed head, the audit public key, Export through a session-checked route), and a reason field in every sensitive dialog. The Console review's fixes: dates clamped to 2000–2099 with a fallback when the API refuses filters, the reason kept after a refusal, focus after Load more, one shared `holdsSecretShape`, refusals mapped by `code` (`AUDIT_REASON_ERROR_CODES`), the stub matching the API (now started with tsx), and the chain verified only on the unfiltered first load with a "Verify chain" button otherwise (Jev 0.58).
