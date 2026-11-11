---
title: "Ticket 08 — Abuse rules"
aliases: [Ticket 08]
project: anti-reverse
doc: TICKET
slice: 8
version: 0.1.0
status: done
updated: 2026-11-11
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# 08: Abuse rules

**What to build:** A Rule can limit how often one client may call a route, and a login route can be protected against credential stuffing: after too many failed attempts from one address, further attempts are refused for a while, and a wave of failures from one network opens an Incident.

**Blocked by:** 02 (done). Owner approved the design on 2026-11-11 (D-063).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-08-abuse-rules.md](../plans/2026-11-11-slice-08-abuse-rules.md)

## Acceptance criteria

Rules

- [x] A Rule may carry a limit: a number of requests per window, counted per client address or per device (the attested device; the address when there is no valid token), counting all requests or only failed responses (401 and 403 by default). Its action is throttle.
- [x] Limit Rules follow monitor first and the existing promotion confirmations, and travel in a part of the signed bundle that older Shields ignore.

Shield

- [x] Over the limit, an enforced Rule answers 429 with `Retry-After` before the handler; in monitor the response is unchanged and the Event records what would have happened. Counters are in memory per instance, bounded, behind a counter-store interface. Overhead stays within PB-01.
- [x] A failure-counting limit counts responses after the handler and refuses further requests to that route once the limit is passed, until the window clears.

Detection

- [x] A High "Credential stuffing" Incident opens when one network prefix reaches 50 failed logins on Login protection Rules within 5 minutes (Shield's own 429s count once per client); alerts and Containment work as for other Incidents. Plain request limits open no Incident (owner, D-064).

Console

- [x] The Rule form offers the limit fields and a "Login protection" preset (10 failures per 5 minutes per address, monitor); the rule list shows the limit; the live feed and evidence show "Throttled" — in the restyled design (D-053).

Quality

- [x] `npm run verify` passes; an end-to-end test protects the reference app's login route, shows a burst of failed logins refused with 429 while another client still logs in, sees the Incident and alert, and shows monitor mode changing nothing.

## Decisions taken with Jev

- Limit Rules with in-memory sliding-window counters keyed by address or device, a counter-store interface for Redis later (0.94).
- Failure-counting limits, a Login protection preset and a Credential stuffing Incident (0.92).

- Review fixes: in-flight slots for failure limits, an exact window up to 1,000, no counting on a refused request, Shield stamps the Login protection Rule on each Event (D-064, owner). Full list: plan amendments A1–A8.

## Proof

| Criteria | Proven by |
|---|---|
| Rules and bundle | `packages/protocol/test/policy.test.ts` (limit, `limit_rules`, headroom 64,974 of 65,536 bytes); `apps/api/test/policies.test.ts`, `bundle.test.ts` |
| Shield | `packages/shield-node/test/counter-store.test.ts`, `limits*.test.ts` (exact window, in-flight slots, device and address, preflights, never-block, fail open) |
| Detection | `apps/api/test/credential-stuffing*.test.ts` (stamped Events and the older-Shield fallback) |
| Console | `apps/console/test/policy-limit.test.ts`, `policy-*.test.*`; `tests/e2e/abuse-rules.e2e.ts` (Login protection preset, promotion, Throttled in Chromium) |
| Quality | `npm run verify` — 5,635 tests, type-check, lint · `tests/e2e/abuse-rules.http.test.ts` (14: limits in monitor and enforce, login protection, 1,000 parallel guesses → 10 reach the handler, one wave → one Incident) · `npm run e2e` — 15 journeys · `npm run bench` — 50 limit Rules p99 about 110 µs under load |

An independent review reproduced 1 HIGH (parallel guesses passed a failure limit), 4 MEDIUM and 4 LOW findings — all fixed test-first; the reviewer's scripts confirm each fix. Jev verified 5 of 5 completion claims.

## Honest limits

Counters are per Shield instance: with several instances the effective limit is the configured one times the instance count, until a shared store exists. Users behind one shared address share a counter. An attacker who spreads attempts over many addresses stays under per-address limits.

## Out of scope — later slices

Redis counter store · limits per account, session or API key · challenge · percentage rollout · scraping and enumeration packs.
