---
title: "Plan — Slice 08 Abuse rules"
aliases: [Plan 08]
project: anti-reverse
doc: PLAN
slice: 8
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

# Slice 08 — Abuse Rules Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** A burst of requests, or of failed logins, from one client is throttled; a wave from one network opens an Incident.

**Architecture:** Protocol adds an optional `limit` to a Rule, the `throttle` action, a `limit_rules` bundle member and the Event fields. Shield keeps bounded in-memory sliding-window counters behind a `CounterStore` interface, decides before the handler and counts failures after it. The API stores, validates and ships limit Rules and adds the `credential-stuffing` detection. The Console adds the form fields, the preset and the "Throttled" decision. No new dependency.

**Spec:** [tickets/08-abuse-rules.md](../tickets/08-abuse-rules.md); PRD FR-SHD-04, FR-SHD-06, FR-SHD-08; SDD §10 (counters), §11; PERFORMANCE PB-01 (counter update 0.01 ms); SECURITY TA-07, TA-13. Earlier plans bind (slice 02 rule matching, raw and canonical paths, broad-rule confirmation, monitor never changes a response; slice 04 separate bundle members and HEAD/GET, preflight exemption; slice 06 detector and Incidents; slice 09 Containment and the never-block list; D-004 fail open; D-053 design; privacy allowlist).

## Global Constraints (additions)

- **Rule:** optional `limit: { requests: 1–100,000, window_s: 1–3,600, key: "ip" | "device", count: "requests" | "failures" }` (`count` default `requests`). A Rule with a limit must have action `throttle`; a Rule without one must not. Failure statuses are fixed in this slice: 401 and 403.
- **Bundle:** new optional member `limit_rules` (bundle rule shape plus `limit`, no `name`); Rules with a limit never appear in `rules`. `rules + signature_rules + limit_rules ≤ 50`. Older Shields strip it.
- **Decision:** action `throttle` joins the decision actions; Event `decision.rule_id` names the limit Rule. Enforced and over the limit → `429` with `Retry-After: <seconds until the window allows one more>` and body `{"error":"rate_limited"}`; monitor → response unchanged, Event records throttle/monitor.
- **Order:** containment → rules and signature rules (existing order) → limit rules in bundle order → patches. Every matching limit Rule counts the request (so monitor limits see real traffic) unless an earlier terminal decision already refused it; the first enforced limit over its threshold wins.
- **Counting:** sliding window (two fixed sub-windows weighted, or a log of ≤ `requests` timestamps — implementer's choice, documented and tested at boundaries). `count: "requests"`: the request is counted at decision time; refused when the count including it exceeds `requests`. `count: "failures"`: counted when the response closes with 401 or 403; a request is refused at decision time when the key's failures in the window already reach `requests`. Throttled responses are not counted as failures.
- **Keys:** `ip` = the client address Shield already derives (IPv6 by /64); `device` = the attested device id when the attestation is valid, else the address. Counter keys are kept in memory only, never sent or logged. Addresses on the never-block list are never throttled. CORS preflights are exempt. HEAD counts with GET.
- **Store:** `CounterStore` interface (`hit(key, windowMs, now) → count`, `peek`, bounded size) with `MemoryCounterStore`: at most 100,000 keys, expired entries swept, when full the oldest idle key is dropped; a full table never refuses a request (fail open). Option `counterStore` on `createShield` for a custom store (sync or async is the implementer's call; the request path must not await a network call in this slice).
- **API:** policy publish accepts and validates `limit`; broad-rule confirmation applies to limit Rules as to block Rules; detection rule `credential-stuffing` (title "Credential stuffing", High): Events on routes where the decision names a limit Rule, or with status 401/403/429 on a route covered by a limit Rule of the published Policy — more than 50 within 5 minutes per (App, Environment, network prefix).
- **Console:** Rule form: action selector Block / Throttle; limit fields (requests, window, key, count); preset button "Login protection" filling 10 failures per 300 s per address, monitor; rule list tag "10 failures / 5 min per address"; decision chip "Throttled" (own glyph, word, colour); Incident view for Credential stuffing like Blocked burst.
- **Budgets:** PB-01 with 50 limit Rules matched and counted; bench scenario added.

## Review Focus

1. **Counter correctness:** window boundaries, clock steps back, bursts, concurrency within one process, memory bound, eviction never over-counting.
2. **Bypass:** path variants (encoded, dot segments, trailing slash, case), HEAD, methods lists, IPv6 rotation inside a /64, spoofed forwarding headers (trusted-proxy handling as existing), device fallback abuse (dropping the token must not reset or escape the ip counter).
3. **Lockout:** never-block list honoured; monitor changes nothing; failures counted only for 401/403; throttled requests not self-extending forever.
4. **Old Shields:** `limit_rules` ignored, never turned into blocks.
5. **Detection:** no duplicate Incidents with Blocked burst; grouping; Containment.

## Tasks

Order: Task 1 (protocol) → Tasks 2–4 in parallel (API ‖ Shield ‖ Console) → Task 5 (e2e) → Task 6 (review, docs).

## Residual risks known up front

- Per-instance counters; shared addresses; distributed attackers.

## Deliberately not in this slice

Redis store · account, session and API-key keys · challenge · rollout percentage.

## Amendments
- **A1 — Protocol as built (Jev: accept_with_two_changes, 0.96).** `RULE_ACTIONS` gains `throttle`; `limit` on a Rule (present ⇔ action throttle; never with `requires`); `limit_rules` bundle member (entries write `count`; `rules` and `signature_rules` accept block only and refuse a limit); `LIMIT_*` constants, `RATE_LIMITED_RESPONSE_BODY`, `EXAMPLE_LIMIT_RULE`; `credential-stuffing` (High, 50 in 300 s, fires on reaching the threshold like `blocked-burst`). The decision action `throttle` already existed, as did the Console's "Throttled" chip. Changed: an input Rule with a limit and no action defaults to throttle; the largest-bundle headroom is re-pinned with limit Rules as the longest entries.
- **A2 — Bundle headroom.** With all 50 Rules as limit Rules of the longest form and every other member at its limit, the bundle is 64,974 bytes of 65,536 (562 spare); the longest-form blocks that fit drop from 182 to 153 (limit 150). The detection fires on the 50th Event (the Global Constraints' "more than 50" is superseded).
- **A3 — Console as built (Jev: accept_fix_wording, 0.89).** Rule form: Block / Throttle; limit, window (with a readable hint), counted per address or device, all requests or failed responses; "Require a signed request" disabled under Throttle; "Login protection" preset (POST, 10 failed responses per 300 s per address; a new Rule is always monitor). Rule list tag (for example "10 failed responses / 5 min per address"), "Counted per Shield instance." under an enforced limit, promotion wording "will be refused". Throttled rows match Blocked rows (no Rule name is shown on any Event — the brief was wrong to ask for one). Changed: the number field is labelled "Limit"; the `/**` guardrail for a throttle Rule reads "A Rule that limits every request cannot be enforced."
- **A4 — API as built (Jev: conservative-template-match 0.95; dedupe_and_per_org_cache 0.92).** Limit Rules stored, returned and rolled back with `limit`; the existing broad-rule guardrail applies; `limit_rules` in Policy order, absent when empty (the pre-slice bundle string is unchanged). Migration 0019. `credential-stuffing` counts a throttle decision naming a Rule, or a 401/403/429 (not Shield's own enforced block) on a route covered by a limit Rule of the Policy version the Event names. Coverage compares the Event's route template with the Rule's pattern conservatively (undecidable means not covered: parameterised-by-regex, `(unmatched)` and `(mount)` routes are not counted by the status clause); one pattern text serves JS and SQL with a parity test. Enforced throttles never count toward `blocked-burst`. Changed: a failure on a covered route counts toward Credential stuffing only, not also Failed sign-in burst; the version cache and waiting-Event bounds are per Organization, and a version above the latest published one is ignored without a read.
- **A5 — Detector follow-ups (Jev: publish_hook, 0.98).** Per-Organization bounds (50 Policy versions, 200 App Environments, 1,000 waiting Events; 1,000 Organizations and 10,000 waiting Events overall); the latest published version is read with the Rules and believed for 10 s; a publish or rollback tells the Detector at once (in process). An Event that cannot wait or whose read failed is judged not covered. Known limit: with several API instances a publish handled elsewhere is learned through the 10 s fallback.
- **A6 — Shield as built (Jev: device_also_counts_ip_hash_keys, 0.86).** `MemoryCounterStore` (two weighted sub-windows; 100,000 keys; last-use order in a linked list after the bench showed Map eviction slowing down); `limit_rules` read tolerantly; a `rules` or `signature_rules` entry carrying a limit refuses the bundle; 429 with `Retry-After` (window + 1 at the edge) and the fixed body; the refusing Rule does not count the refused request; earlier matching limits keep their count; failures counted when the response closes (in-flight requests can pass slightly over); Shield's own 403s are not failures; an unknown client address is not limited; counters survive a republish; `shield.decide()` never returns throttle; fail open on store or clock errors. Changed: a device-keyed limit also counts the address and refuses at 5 × the limit there, so dropping the token or minting devices cannot multiply the budget without bound; keys given to a store are hashed with a per-process secret. Evidence so far: `npm run verify` 5,554 tests; bench limit scenarios p99 41–54 µs.
- **A7 — Review fixes (to do, test first).** An independent review reproduced 1 HIGH, 4 MEDIUM and 4 LOW findings (scripts in the scratchpad `rev/`). Shield (Jev fix_set, 0.96): F1 failure limits reserve an in-flight slot per key at decision time (refused when failures + in flight reach the limit; released at close), so parallel guesses cannot pass the limit; F2 an exact sliding log (the last N timestamps) for limits up to 1,000, weighted sub-windows above that and "about" in the Console tag; F3 all matching limit Rules are evaluated first and the request counts on every one only when none refuses; F6 a CORS preflight is not counted but is refused when the client is already over a matching limit; F7 an address Shield cannot parse is keyed by its trimmed raw text (bounded) with a one-time warning and a stat; F8 a refused request refreshes its key's last use. Detection (Jev shield_stamps_failure_limit, 0.94; owner 2026-11-11 "narrow it"): Shield stamps `decision.limit_rule_id` (optional, nullable) with the failure-counting limit Rule that matched a request, throttled or not; Credential stuffing counts only Events carrying it with status 401/403 or a throttle by that Rule, Shield's own 429s once per client per window; Failed sign-in burst leaves those Events out; plain request limits open no Incident in this slice (they show in the feed); Events from older Shields fall back to the coverage guess.
- **A8 — Review fixes as built (Jev: accept_all, 0.68).** Shield: in-flight slots per key for failure limits (1,000 parallel guesses → 10 reach the handler); an exact log for limits up to 1,000 (worst real window 10 of 10) bounded at 100,000 keys and 2,000,000 hit times (under 60 MB), the idlest key dropped first; all matching Rules looked at before any count; preflights matched by OPTIONS, never counted, refused once over; unparsed addresses limited by their text; a refused client stays out of eviction; every Event carries `limit_rule_id` (absent from older Shields, so the API can tell). Detection: stamped Events decide; older Shields fall back to the coverage guess narrowed to failure-counting Rules; throttles count once per client per fixed 300 s window in monitor and enforce; the app's own 429 counts toward nothing; the version cache is a weight budget of 256 per Organization. Bench: limit scenarios p99 68–76 µs, worst attested 942 µs.
