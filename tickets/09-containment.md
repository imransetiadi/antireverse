---
title: "Ticket 09 — Containment"
aliases: [Ticket 09]
project: anti-reverse
doc: TICKET
slice: 9
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

# 09: Containment

**What to build:** From an Incident, an analyst blocks the attacking Actor for a limited time in one or two interactions, and every Shield of that App and Environment enforces it within 30 seconds. Blocks expire on their own, can be lifted early, are audited, and can never hit an address the Organization has declared must never be blocked.

**Blocked by:** 02 (done) and 06 (done).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-09-containment.md](../plans/2026-11-11-slice-09-containment.md)

## Acceptance criteria

Actor identity (D-017)

- [x] Shield adds to every Event a keyed hash of the client address (`actor.ip_hash`): HMAC over the full IPv4 address or the IPv6 /64 with an **actor key the customer holds** (`AR_ACTOR_KEY`), never sent to Airverse — so Airverse cannot recover the address (owner's decision, plan amendment A7). Without the key no hash is sent and only network blocks are possible. The full address never leaves the customer's server.
- [x] An Incident shows its Actors: the distinct hashes in its evidence with their request counts.

Containment

- [x] From an Incident, an admin blocks an Actor (by hash) for 15 minutes, 1 hour (default) or 24 hours, after a confirmation that names the target, the App and Environment, the blast radius and the expiry. Blocking the Incident's whole network prefix is a separate action with a stronger confirmation (the prefix typed).
- [x] A block applies only to the Incident's App and Environment. Every Shield there enforces it within 30 s (PB-15): matching requests get the standard block response, and their Events record the containment that blocked them.
- [x] A block expires on its own — Shield also enforces the expiry, even when it cannot reach the API — and can be lifted early. Every create and lift records who (key id) and when.
- [x] At most 150 active blocks per App and Environment (plan amendment A1: keeps the signed bundle within its 64 KB limit); a request beyond that is refused with a clear message.
- [x] Requests blocked by a containment do not count toward the Blocked burst rule (one attack, one Incident).

Never-block allowlist

- [x] An Organization keeps a list of address ranges (CIDR) that can never be blocked by containment. Shield checks it before any containment block; the API refuses a prefix block that overlaps it.

Console

- [x] The Incident page has a containment bar (block Actor first, then block network) with blast radius and expiry, the Incident's Actors, and its blocks with **Lift**. An App page lists its active blocks. Settings has the allowlist.

Quality

- [x] Shield's overhead stays within budget with 150 blocks and an allowlist loaded.
- [x] `npm run verify` passes; an end-to-end test drives an attack through Shield, opens the Incident, blocks the Actor from the Console, sees the next request blocked within 30 s while another client is not, lifts the block and sees the request pass again.

## Decisions taken with Jev

- Block by the keyed address hash by default, network prefix as a separately confirmed option (0.95).
- Blocks ride in the signed Policy Bundle; push channel deferred (0.99).
- Containment blocks do not count toward Blocked burst (1.0).
- Scope App + Environment; TTL 15 min / 1 h / 24 h; audit; never-block allowlist (0.99); cap 150 per App and Environment (0.88).
- Lifts are final (database trigger) and 409s carry a machine-readable reason (1.0); an `actorHashing` status flag (0.62). The customer-held actor key was the owner's decision (Jev leaned 0.48). Full list: plan amendments A1–A10.

## Proof

| Criteria | Proven by |
|---|---|
| Actor hash with a customer-held key; no full address | `packages/protocol/test/actor.test.ts` (known answers computed independently); `packages/shield-node/test/actor-key.test.ts`, `address.test.ts` (200,000-case agreement in review); `tests/e2e/containment.http.test.ts` (hash ≠ Shield-key hash; no address in any Event) |
| Block from an Incident, scope, expiry, lift, audit, cap | `apps/api/test/containment.test.ts`, `containments-db.test.ts` (lift is final); `packages/shield-node/test/containment.test.ts` (expiry by Shield's clock, offline); `containment.http.test.ts` (attacker blocked in 3.2–5.9 s, bystander served; lift 2.0–4.0 s) |
| Never-block list | API overlap tests; Shield allowlist tests; `containment.http.test.ts` (bystander allowlisted passes a network block, still blocked by a Rule) |
| One attack, one Incident | `apps/api/test/detector.test.ts`, `containment.test.ts`; `containment.http.test.ts` (25 contained requests, no new Incident) |
| Console | `apps/console/test/containment-*.test.*`; `tests/e2e/containment.e2e.ts` |
| Quality | `npm run verify` — 3,249 tests, type-check, lint · `npm run e2e` — 9 journeys · `npm run bench` — worst p99 19.58 µs with 150 blocks, 100 ranges and an actor key |

An independent review found F1 (MEDIUM: the actor hash was keyed with the Shield key, which the API receives on every request, so an address could be recovered in about 256 tries) — fixed by the owner's decision for a customer-held actor key — and F2 (LOW: zone-id spellings made the Event prefix and the block matcher disagree) — fixed with one address rule. It confirmed the 150 cap and idempotency under 159 concurrent requests, final lifts, scope, and that a confirmation link cannot create a block. Jev verified all 8 completion claims (0.80–0.98, auto).

## Out of scope — later slices

Automated Playbooks and their blast-radius guardrails · push channel · blocking by device, session or account · Organization-wide blocks · notes and assignment on Incidents · safe mode switch.
