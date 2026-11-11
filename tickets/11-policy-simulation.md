---
title: "Ticket 11 — Policy simulation"
aliases: [Ticket 11]
project: anti-reverse
doc: TICKET
slice: 11
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
  - "[[UIUX]]"
---

# 11: Policy simulation

**What to build:** Before publishing, an admin runs a draft Policy against the last 24 hours of recorded requests of an App and Environment and sees, per Rule, what it would have done: how many requests it would have blocked, refused for a missing signature or throttled, how many clients that touches, and how much could not be judged.

**Blocked by:** 02 (done) and 06 (done). Owner approved the design on 2026-11-11 (D-066).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-11-policy-simulation.md](../plans/2026-11-11-slice-11-policy-simulation.md)

## Acceptance criteria

API

- [x] `POST /v1/apps/:appId/policy/simulate` takes draft Rules (the publish shape) and an Environment and replays the stored Events of the last 24 hours (newest first, capped) without storing or publishing anything.
- [x] Per Rule the result gives: matched requests, would-block, would-fail-signature, would-throttle, distinct clients affected, up to 5 sample routes with counts, and requests that could not be judged; plus totals, the period covered and whether the cap cut the period short.
- [x] Route matching uses the stored route template conservatively: a template the matcher cannot judge is counted as "could not be judged", never as a match. Limits are replayed in time order per client. Virtual patches are not simulated and the result says so.
- [x] Tenant-scoped, admin key only, rate-limited; invalid drafts are refused as on publish.

Console

- [x] The Policy page has "Simulate" for the Rules as shown (and for a Rule being added), a result panel per Rule labelled an estimate, and the promote-to-enforce confirmation shows the Rule's latest simulation — in the restyled design (D-053).

Quality

- [x] `npm run verify` passes; an end-to-end test sends known traffic through a real Shield, simulates a block Rule, a signature Rule and a limit Rule, and gets the expected counts; then publishes and enforces the same Rules and sees real decisions consistent with the estimate.

## Decisions taken with Jev

- Slice 11 next (0.81). API replay over stored route templates with an explicit "could not be judged" count; limits replayed in time order; patches not simulated (1.0).

- Review fixes: everything the simulation cannot be sure of is counted as could not be judged (unusual route shapes, limits above 1,000, the never-block list, signed requests with a body, window edges, device limits, clients without an actor key); limit counters are tainted by requests Shield may have counted; a per-Rule promotion estimate. Full list: plan amendments A1–A7.

## Proof

| Criteria | Proven by |
|---|---|
| Contract | `packages/protocol/test/simulation.test.ts` |
| Replay never over-claims | `apps/api/test/simulation-property.test.ts` (300 generated drafts through Shield's real decision code), `simulation-parity.test.ts` (3,000 requests, identical counts), `simulation-replay.test.ts` |
| Endpoint, nothing stored, limits | `apps/api/test/simulation.test.ts` (every table compared before and after; tenancy; 429) |
| Matches reality | `tests/e2e/policy-simulation.http.test.ts` (10: estimate 82 refusals from 7 clients, then enforced on a real Shield: 82 from 7; promotion estimate 30 from 3 equals a real promotion) |
| Console | `apps/console/test/simulation*.test.*`; `tests/e2e/policy-simulation.e2e.ts` (panel, promotion estimate, Simulate with this Rule, in Chromium) |
| Quality | `npm run test` — 5,875 tests, three full runs in a row · `npm run e2e` — 16 journeys |

An independent review compared the replay with a real enforcing Shield and reproduced 3 HIGH, 3 MEDIUM and 5 LOW findings (over-claims and confident misses); all fixed test-first. Random runs afterwards (30 seeds × 4 modes): 0 over-claims, 0 confident misses. Jev verified 4 of 4 completion claims.

## Honest limits

An estimate from the last 24 hours only: traffic that did not happen cannot be predicted. It never claims a refusal it cannot be sure of, so for limit Rules much can end up as could not be judged (about a quarter of real throttles are named for limit-only drafts). Not simulated: virtual patches, blocks on individual clients, Shield's decoded paths, device limits (lower bound), whether Shield checks bodies on a route. Without an actor key clients cannot be told apart. With several Shield instances the real limits are looser than the replayed ones.

## Out of scope — later slices

Simulating patches · longer history · scheduled simulations · comparing Policy versions.
