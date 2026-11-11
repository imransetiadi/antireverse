---
title: "Plan — Slice 09 Containment"
aliases: [Plan 09]
project: anti-reverse
doc: PLAN
slice: 9
version: 0.1.0
status: done
updated: 2026-11-11
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# Slice 09 — Containment Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** One-click, time-limited, audited containment of an Actor from an Incident, enforced by every Shield of the App and Environment within 30 s, never touching allowlisted addresses.

**Architecture:** Shield adds a keyed address hash to Events (D-017). The API stores containments and an Organization allowlist, and ships the active blocks and the allowlist in the signed Policy Bundle (as slice 07 ships Canaries). Shield enforces blocks locally before Rules, honouring expiry and the allowlist. The detector ignores containment blocks for Blocked burst. The Console adds the containment bar, Actors, blocks and the allowlist. No new dependency.

**Spec:** [tickets/09-containment.md](../tickets/09-containment.md). Background: [SDD.md](../SDD.md) §5.3, §7 (dynamic list), §11 (Playbook guardrails); MEMORY D-017, D-027, D-029, D-037, D-038, D-040; [PERFORMANCE.md](../PERFORMANCE.md) PB-15; [UIUX.md](../UIUX.md) J3, SCR-05 (CONTAIN), §8 containment bar. Earlier plans and amendments still bind (notably slice 02 bundle verification and path forms; slice 06 detector, grouping, alerts; slice 07 bundle ETag digest and same-version re-issue with later `issued_at`, replay refusal).

## Global Constraints (additions)

- **Identifiers:** containment `cnt_<24 hex>`, allowlist entry `alw_<24 hex>`, actor hash `iph_<32 hex>`.
- **Actor hash:** `iph_` + first 32 hex of `HMAC-SHA256(key = the Shield key string, message = "antireverse/actor/v1\n" + subject)`, where subject is the full IPv4 address in dotted form, or for IPv6 the /64 written as the first four hextets expanded to 4 hex digits each, lower case, joined by `:` (IPv4-mapped IPv6 → the IPv4 form). Unknown address → `null`. Computed once per request in Shield; never logged. A Shield with no key sends `null`. The API never computes it (it stores only SHA-256 of the key).
- **Event:** `actor.ip_hash` (nullable; optional for older Shields — absent means null) and `decision.containment_id` (nullable; optional, absent = null). Both keep the privacy allowlist (D-025).
- **Containment:** `{ id, app_id, environment, incident_id | null, target: { kind: "actor", ip_hash } | { kind: "prefix", ip_prefix }, created_at, expires_at, created_by (admin key id), lifted_at | null, lifted_by | null, status: "active" | "expired" | "lifted" }` (status computed from the server clock). TTL choices `CONTAINMENT_TTLS = [900, 3600, 86400]` seconds, default 3600.
- **Creation rules (`POST /v1/incidents/:incidentId/containments`):** body `{ target: { kind: "actor", ip_hash } | { kind: "prefix" }, ttl_s, confirm_prefix? }`. An actor hash must occur in the Incident's evidence window (its App, Environment, prefix and time span); a prefix block uses the Incident's own `ip_prefix` and requires `confirm_prefix` equal to it. Refused (409 `conflict`, fixed text) when: the Incident is resolved; a prefix block overlaps the allowlist; an active block with the same target exists (return it as 200 instead — idempotent); the App+Environment has 150 active blocks.
- **Lift:** `POST /v1/containments/:id/lift` → 200; lifting an expired or lifted block is 409. Every create and lift records the admin key id and time; containments are never deleted.
- **Allowlist:** per Organization, ≤ 100 entries `{ id, cidr, note (≤ 80), created_at, created_by }`; IPv4 /8–/32, IPv6 /16–/128, normalised (host bits zero, else 400). Routes `GET/POST /v1/allowlist`, `DELETE /v1/allowlist/:id`.
- **Bundle:** `BundlePayload` gains optional `blocks: [{ id, kind: "actor", ip_hash, expires_at } | { id, kind: "prefix", ip_prefix, expires_at }]` (≤ 150; active only, for the Shield key's App and Environment) and optional `allowlist: [cidr]` (≤ 100, the Organization's). The ETag folds a digest of both; a change re-issues the bundle at the same Policy version with a later `issued_at` (slice 07). The bundle stays ≤ 65,536 bytes with 50 Rules, 100 Canaries, 150 blocks and 100 allowlist entries (test: 60,607 bytes).
- **Shield enforcement (before Rules):** if the client address is inside any allowlist CIDR → no containment block. Else a block matches when (`actor` and the request's hash equals) or (`prefix` and the request's prefix equals), and `expires_at` is after Shield's clock. Match → the standard block response (`403 {"error":"request_blocked"}`, as slice 02), Event `decision: { action: "block", mode: "enforce", rule_id: null, containment_id }`. Lookups are O(1) (Set/Map); the hash is computed only when actor blocks are loaded. A Shield that cannot reach the API keeps enforcing until each entry's expiry. Fail open on any error.
- **Detector:** an Event with `decision.containment_id` set does not count toward `blocked-burst` (TS predicate and SQL condition, defined once — `rules.ts`).
- **Incident detail:** gains `actors: [{ ip_hash, events }]` (≤ 10, by count desc then hash, over the Incident's evidence window) and `containments: Containment[]` (newest first).
- **Budgets:** PB-15 action → enforcement ≤ 30 s (expected ~5 s: Shield's poll); Shield bench p99 ≤ 0.5 ms with 150 blocks + 100 allowlist entries.

## Review Focus

1. **Privacy:** no full address in any Event, log, bundle or API; the API cannot compute an actor hash. *(shield, API)*
2. **Allowlist always wins** in Shield, and the API refuses overlapping prefix blocks. *(shield, API)*
3. **Expiry** enforced by Shield's clock even offline; lifted/expired blocks leave the bundle; replay of an older bundle cannot resurrect or drop blocks. *(shield, API)*
4. **Tenancy and scope:** a block of App A never reaches App B, another Environment or another Organization; only admins create/lift; actor hash must come from the Incident. *(API)*
5. **One attack, one Incident:** containment blocks never open Blocked-burst Incidents. *(API)*

## Contracts

### P1 — Protocol
`containment.ts` (isomorphic): `CONTAINMENT_TTLS`, `CONTAINMENT_LIMITS = { activePerAppEnv: 150, allowlistMax: 100, actorsListed: 10 }`, `ActorHashSchema`, `ContainmentTargetSchema`, `ContainmentSchema`, `CreateContainmentRequestSchema` (refine: prefix needs `confirm_prefix`), `ContainmentResponseSchema { containment }`, `ListContainmentsResponseSchema`, `AllowlistEntrySchema`, `CreateAllowlistEntryRequestSchema`, `ListAllowlistResponseSchema`, `parseCidr`/`cidrContains` helpers (isomorphic, no Node built-ins), `EXAMPLE_*`. `events.ts`: `actor.ip_hash`, `decision.containment_id` optional-nullable. `policy.ts`: bundle `blocks`, `allowlist`. `incidents.ts`: detail `actors`, `containments`. Server entry: `actorHash(shieldKey, address)` (known-answer vectors for IPv4, IPv6 /64, IPv4-mapped) for Shield and tests. `ID_PATTERNS.cnt`, `ID_PATTERNS.alw`.

### P2 — API
Migration `0008_containment.sql` (containments, allowlist; RLS; append-and-update-lift only; indexes for active-by-app-env). Stores, routes (table above), bundle issuer (`blocks`, `allowlist`, digest in ETag), detector predicate, Incident detail `actors` + `containments`, `GET /v1/containments?app_id=&environment=&status=`.

### P3 — Shield
Compute `ip_hash`; containment matcher before Rules with allowlist and expiry; Event fields; bundle verification of `blocks`/`allowlist` by hand (malformed → refuse bundle, as Rules); bench case.

### P4 — Console
Incident page: containment bar (Block actor — pick from Actors, default the top one — TTL select 15 min / 1 h / 24 h; Block network with typed confirmation), Actors card, blocks list with Lift; Incident list shows a "Contained" marker when an active block exists; App page "Containment" section listing active blocks with Lift; `/settings/allowlist` (add CIDR + note, remove with confirmation). Copy states blast radius ("Blocks 1 Actor in production of shop-web for 1 hour" / "Blocks every client in 203.0.113.0/24 …") and expiry. Catalog keys, tokens only.

## Tasks

Order: Task 1 (protocol) → Tasks 2–4 in parallel (API ‖ Shield ‖ Console) → Task 5 (e2e) → Task 6 (review, docs).

1. **Protocol** — failing tests first: schemas, limits, refines, CIDR parse/contains (v4/v6 edge cases), `actorHash` vectors, optional Event fields round-trip and old Events still parse, bundle size test, entrypoints.
2. **API** — failing tests first per Review Focus 2–5 and the creation rules; bundle carries only the App+Env's active blocks and the Org allowlist; ETag changes on create/lift/expiry; lifted/expired leave; detector exclusion; Incident detail actors.
3. **Shield** — failing tests first per Review Focus 1–3: hash vectors, actor/prefix match, allowlist wins, expiry by Shield clock, offline keeps enforcing until expiry, response = standard block, Event fields, no address in Event/log, bench.
4. **Console** — failing tests first: containment bar with blast radius/expiry and confirmations, Actors, blocks + Lift, Contained marker, App containment section, allowlist settings, copy pins, build.
5. **End to end** — HTTP: attack through Shield → Incident → Actor listed → block actor 1 h → the attacker's next request blocked within 30 s (measure) while a second client in the same /24 passes → no new Blocked-burst Incident from the blocked requests → lift → passes again; prefix block with confirmation blocks both clients; allowlisted address never blocked; another Org/App unaffected. Browser: Incident → Block actor → confirmation → block shown → Lift.
6. **Review and docs** — independent review reproducing findings; fixes test-first; Jev-verify claims; README, ticket proof, MEMORY, PRD.

## Residual risks known up front

- A second Shield key for the same App+Environment, or a key rotation, changes actor hashes: existing actor blocks stop matching (prefix blocks unaffected).
- IPv6 hashing at /64 groups everything behind one /64; IPv4 hashing per address is evaded by an attacker who rotates addresses (then block the prefix).
- Enforcement waits for Shield's poll (default 5 s); a push channel is a later slice.

## Deliberately not in this slice

Automated Playbooks · push channel · device/session/account Actors · Organization-wide blocks · notes and assignment · safe mode.

## Amendments

- **A1 — 150 active blocks per App and Environment (Jev: cap_150, 0.88).** At 300 the worst-case bundle measured 81,907 bytes, over the 65,536 bytes every Shield enforces; raising the limit would make deployed Shields refuse bundles. At 150 the worst case is 60,607 bytes (184 would be the most that fits). Network-prefix blocks cover attacks with many addresses.
- **A2 — Protocol as built (Jev: accept_all, 0.75).** Event `actor.ip_hash` and `decision.containment_id` default to null when absent (older Events still parse; producers must set them); `ttl_s` required; allowlist note may be empty; a lifted containment carries `lifted_at`/`lifted_by` exactly when its status is `lifted`; IPv4 ranges are written as IPv4 CIDRs (IPv6 CIDRs never contain IPv4-mapped addresses and mapped-range CIDRs are refused); canonical CIDR text: IPv4 dotted without leading zeros, IPv6 RFC 5952, host bits zero, /8–/32 and /16–/128. Actor-hash known answer (key `ark_dev_` + 43 × `A`): `203.0.113.7` → `iph_2932b22cf89905dbc929c64247ddad3e`; IPv6 /64 `2001:db8:0:1::/64` → `iph_d78c52b682710159027de8721a764da9`.
- **A3 — Shield as built (Jev: accept_all, 0.73).** A contained request's Event route is `(unmatched)` (it never reached a router); the allowlist is checked only after a block matches (same result, cheaper); when an actor and a prefix block both match, the actor block's id is recorded; duplicate targets keep the longer expiry; `shield.decide()` stays Rules-only and `ShieldStats` is unchanged; the actor hash is computed on every request because every Event carries it. The allowlist exempts a client from Containment only, never from Rules. Bench worst p99 21.38 µs with 50 Rules, 100 Canaries, 150 blocks and 100 CIDRs.
- **A4 — API as built (Jev: accept_all_add_trigger, 1.0).** An Actor not in the Incident's evidence → 409; a wrong `confirm_prefix` → 400 on that path; conflicts keep type `conflict` with fixed texts; `GET /v1/containments` and the Incident's `containments` capped at 200; a bundle re-issued in the same millisecond is dated previous + 1 ms; bundle `blocks` and `allowlist` oldest first; `POST /v1/allowlist` → 201 `{ entry }` (protocol `AllowlistEntryResponseSchema`); the Console's "Contained" marker reads `GET /v1/containments?status=active` (with `app_id` when filtered). Added: a database trigger makes a lift final (no un-lift, no change of who lifted).
- **A5 — Machine-readable conflict reason (Jev: reason_member, 1.0).** A 409 carries `reason` (`CONFLICT_REASONS`: incident-resolved, actor-unknown, prefix-allowlisted, containment-limit, containment-ended, allowlist-duplicate, allowlist-limit) beside its fixed text; the Console maps the reason to its own copy instead of re-reading state after a 409.
- **A6 — Console as built (Jev: accept_all, 0.64).** Containment confirmations are server-rendered steps in the address (three interactions from alert to block: open the Incident, Block actor, confirm); a Containment tab on the App (`/apps/[appId]/containment`, one section per Environment, "N of 150 active blocks"); the allowlist is called **Never block** in the navigation (route `/settings/allowlist`); expiry shown as `HH:MM UTC` computed at render (the API stamps the real expiry); the Incidents list reads active blocks once per page and still renders, with a note, if that read fails.
- **A7 — Customer-held actor key (owner's decision 2026-11-11; Jev leaned 0.48; review F1).** The review showed the Shield key is not a private hashing key: the API receives it on every request, so with the /24 beside the hash it could recover a full IPv4 address in about 256 tries. Shield now keys the actor hash with a separate `actorKey` (config option, or env `AR_ACTOR_KEY`, ≥ 32 characters) that the customer sets and never sends to Anti Reverse. Without it Shield sends `ip_hash: null`: Incidents have no Actors and only network blocks are possible; the Console says why. Shield never falls back to the Shield key. This replaces "HMAC with the Shield key" in Global Constraints.
- **A8 — One address rule in Shield (review F2, LOW).** Event prefix, actor hash and containment use the same parser, so zone-id spellings can no longer be attributed to a prefix yet escape its block.
- **A9 — Actor key details (Jev: stats_flag_silent, 0.62).** Option `actorKey`, env `AR_ACTOR_KEY` (option wins); ≥ 32 characters, no whitespace, and never equal to the Shield key; an unusable value logs one warning without the value; an absent key is silent. `ShieldStats.actorHashing` (additive) tells whether hashing is on; the reference app's startup line reports it. Shield's Event prefix now comes from the same parser as the hash and the matcher (A8).
- **A10 — End-to-end clients.** Two clients in one /24 are produced through Shield's `clientAddress` option behind a simulated trusted reverse proxy (`X-Forwarded-For`), since this machine's loopback has only 127.0.0.1 (Jev 0.9).
