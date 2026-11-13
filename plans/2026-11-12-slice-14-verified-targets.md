---
title: "Plan — Slice 14 Verified Targets and Rules of Engagement"
aliases: [Plan 14]
project: anti-reverse
doc: PLAN
slice: 14
version: 0.1.0
status: done
updated: 2026-11-12
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[UIUX]]"
---

# Slice 14 — Verified Targets and Rules of Engagement Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** No test can ever be pointed at a host the Organization has not proven it owns, outside signed Rules of Engagement.

**Architecture:** Protocol defines targets, Rules of Engagement and the authorization contract. The API stores targets and signed versions under RLS, verifies ownership through injectable `Resolver` and `Fetcher` seams (real DNS and a guarded HTTPS client in production, fakes in tests), re-checks daily, and exposes a pure `authorize`. The Console adds the pages. Shield is unchanged. No new dependency.

**Spec:** [tickets/14-verified-targets.md](../tickets/14-verified-targets.md); PRD FR-PRV-01, FR-PRV-02, stories 52–53; SDD §8 (Pentest flow), Verified Target and Rules of Engagement bullets; SECURITY TA abuse of Prove, Z7; D-069. Earlier plans bind (tenancy and RLS; admin key; D-053 design; never log tokens).

## Global Constraints (additions)

- **Identifiers:** target `tgt_<24 hex>`, Rules of Engagement version `roe_<24 hex>`.
- **Host:** lower-case DNS name, 1–253 characters, at least two labels, each label 1–63 of `a-z 0-9 -` not starting or ending with `-`, punycode allowed; refused: IP literals, a trailing dot handled by normalising, and names equal to or under `localhost`, `local`, `internal`, `intranet`, `lan`, `home.arpa`, `example`, `invalid`, `test`, `onion`. At most 50 targets per Organization; unique per Organization.
- **Token:** 32 random bytes as 43 base64url characters; DNS value `airverse-verification=<token>`; file content exactly the token (surrounding whitespace ignored). Tokens are stored and shown only to admins; never logged.
- **Verification:** DNS TXT at `_airverse-challenge.<host>` (any TXT string equal to the value, chunks joined), then the file `https://<host>/.well-known/airverse-verification.txt`. Fetcher rules: resolve A and AAAA; refuse unless every address is public (no private, loopback, link-local, CGNAT, multicast, reserved, IPv4-mapped private, unique-local, documentation ranges); connect to a checked address only (no second resolution — pin the address, send SNI and Host for the name); TLS with certificate validation; GET only; no redirects (a 3xx fails); 5 s total timeout; body cap 1 KB; no cookies or credentials. Rate limit: 10 verification attempts per target per hour. Status: `pending` → `verified` (method dns | file, at) → `lapsed` (reason, at) → `verified` again.
- **Re-check:** every target verified for more than 24 h is re-checked by the API's scheduler (interval and jitter as other periodic jobs); failure → `lapsed` with the reason. Test seam for time.
- **Rules of Engagement version:** `{ scope: [target ids, 1–50, verified at signing], exclusions: [path prefixes starting with "/", ≤ 50, ≤ 256 chars], intensity: "passive" | "safe-active" | "full", window: { days: subset of mon..sun (≥ 1), from: "HH:MM", to: "HH:MM" UTC, to after from or crossing midnight }, contacts: [emails, 1–5] }`; signing requires `confirm` equal to the exact phrase `I authorise <intensity> testing` (for example `I authorise safe-active testing`), documented in protocol and typed by the admin in the Console; stored with `signed_by` (admin key id), `signed_at`, `content_sha256` of the canonical JSON; immutable (no UPDATE grant); the newest signed version is current; signing a version whose scope includes a non-verified target is refused.
- **authorize({ organizationId, host, path, intensity, at }) → { allowed: true, roe_id } | { allowed: false, reason }** with reasons `target_unknown`, `target_not_verified`, `no_rules_of_engagement`, `out_of_scope`, `path_excluded`, `intensity_exceeds`, `outside_window`. Intensity order passive < safe-active < full. Path normalised (dot segments, percent-decoding once) before the exclusion test; excluded when it equals a prefix or starts with prefix + "/". Exposed as a function in the API (for slice 15) and as `POST /v1/prove/authorize` for admins (a dry check, nothing started).
- **API:** `GET/POST /v1/targets`, `GET/DELETE /v1/targets/:id`, `POST /v1/targets/:id/verify`; `GET /v1/rules-of-engagement` (versions, newest first), `GET /v1/rules-of-engagement/current`, `POST /v1/rules-of-engagement` (sign a new version). Admin key only; tenancy via RLS; deleting a target in the current scope is refused (sign a new version first).
- **Console:** "Prove" section with "Targets" (add host, instructions with copy buttons for both methods, Verify, status chip Pending/Verified/Lapsed with method and last check) and "Rules of Engagement" (current version, history, a form to write and sign a new version with a typed confirmation, a dry "Check a test" form calling authorize).

## Review Focus

1. **SSRF:** the file fetch can never reach a private, loopback, metadata or internal address (DNS rebinding, IPv6 forms, IPv4-mapped, redirects, slow responses, huge bodies, TLS tricks).
2. **Ownership:** token reuse across Organizations or hosts, case and trailing dots, wildcard DNS, CNAME chains, TXT splitting, a lapsed target still authorised.
3. **authorize:** every refusal reason reachable and correct; window edges and midnight crossing; path normalisation; intensity order; current version selection.
4. **Tenancy and immutability:** another Organization sees nothing; signed versions cannot be changed; signing records who and what.

## Tasks

Order: Task 1 (protocol) → Tasks 2–3 in parallel (API ‖ Console) → Task 4 (e2e) → Task 5 (review, docs).

## Residual risks known up front

- No user identity behind the admin key; control of a name proven only at check time.

## Deliberately not in this slice

Campaigns and egress enforcement · step-up and dual approval · IP-range targets · email to contacts.

## Amendments
- **A1 — Protocol as built (Jev: fail_closed_set, 0.98).** `src/prove.ts` (browser safe) and `src/prove-crypto.ts` (token, content hash); host rules follow the WHATWG address test (a numeric last label is an address) and refuse Unicode; the token appears only in the single-target response; a midnight-crossing window belongs to the day it starts; `GET …/current` answers `{ version: null }` when none is signed; the hash covers the five content fields. Changed to fail closed: exclusions match case-insensitively after treating backslashes as slashes, collapsing slashes, dropping `;params` and decoding until stable; a window may run 00:00–24:00; authorization also needs a successful ownership check within the last 26 hours; example.com, example.net and example.org are refused.
- **A2 — API and Console as built (Jev: accept_with_two_changes 0.68; reasons_and_test 0.98).** Migration 0021 (targets with fixed host and token; Rules of Engagement versions INSERT and SELECT only; RLS with FORCE); a strict public-address classifier for the file fetch (pins the first checked address, validates the certificate, no redirects, 5 s, 1 KB; test-only TLS options never read from configuration); hourly re-check job outside transactions that never overwrites a newer manual verify; `createAuthorize` for slice 15; Console "Prove" section with Targets, Rules of Engagement (typed phrase, All day), and Check a test; intensity explanations written by the team (passive: only what any visitor sees; safe-active: harmless probes, never changes data; full: may change data or load the host) — for the owner to review. Changed: a re-check that fails only on our own resolver lapses after 3 consecutive runs (authorize still refuses after 26 h); lapsed targets are re-checked daily and recover on their own; the 409s carry reasons `target_in_scope`, `target_limit`, `target_duplicate`, which the Console maps exactly; a test keeps the verify result on screen after revalidation.
- **A3 — Review fixes (to do, test first; Jev fix_set 0.68).** An independent review reproduced 2 MEDIUM and 5 LOW findings (scripts in the scratchpad: pure.ts, fetch.mts, api.mts, auth.mts). F1 exclusions fold harder: Unicode NFKC, zero-width and control characters removed, cut at a decoded NUL, trailing dots and spaces per segment and `:` alternate-stream suffixes stripped; a path that still holds U+FFFD or a non-ASCII letter counts as excluded whenever any exclusion exists. F2 verification limits are kept per Organization and host (they survive delete) plus 60 per Organization per hour. F3 a manual verify is recorded only if it started after the last recorded check. F4 more internal names refused (corp, home, lan, svc, cluster.local, default, localdomain, arpa) and one public failure reason `not_reachable` replaces `address_not_public` and `resolve_failed` in responses. F5 the due-targets function listing every Organization's ids to the job role is accepted and documented. F6 authorize judges freshness (and, for slice 15, the time) by the API's clock; the dry check may pass `at` for the window only. F7 168.63.129.16 refused.
  - *F5, as built:* `prove_due_targets` (migrations 0021, 0022) is a security-definer function the request role can call with or without a tenant; it returns only (Organization id, target id) of every Organization's due targets — no host, token or status — and every later read or write runs in that Organization's transaction. Accepted; recorded as a database comment on the function in migration 0023.
- **A4 — Review fixes as built (Jev: accept_and_update_message, 0.89).** F1 exclusions decode `%uXXXX` and `%XX` each pass, then cut at NUL, apply NFKC, remove every control and format character, drop `;params`, `:stream` suffixes and trailing dots and spaces per segment; a remaining U+FFFD or non-ASCII letter or mark counts as excluded (so `/admin%2e` is now excluded). F2 migration 0023 `verify_limits` per Organization and host (10 per hour) and per Organization (60 per hour), replacing the per-target counters. F3 a manual verify whose target changed meanwhile answers 409 and keeps the newer record. F4 `not_reachable` replaces two file reasons in responses; corp, home, svc, cluster.local, default, localdomain, arpa refused. F6 `createAuthorize` judges everything at the API clock; the dry check uses `at` for the window only. F7 168.63.129.16 refused. Reviewer scripts: every path variant excluded; delete and re-add no longer resets the limit (10 accepted, 320 refused). The Console limit message names both limits.
