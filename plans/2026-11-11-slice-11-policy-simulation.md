---
title: "Plan — Slice 11 Policy simulation"
aliases: [Plan 11]
project: anti-reverse
doc: PLAN
slice: 11
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
  - "[[UIUX]]"
---

# Slice 11 — Policy Simulation Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** An admin sees what a draft Policy would have done to the last 24 hours before publishing it.

**Architecture:** Protocol defines the simulate request and result. The API replays stored Events of the App and Environment against the draft Rules with the existing route-template matcher (`apps/api/src/detect/coverage.ts`), a pure replay engine, and returns the result; nothing is stored. The Console adds Simulate and a result panel. Shield is unchanged. No new dependency.

**Spec:** [tickets/11-policy-simulation.md](../tickets/11-policy-simulation.md); PRD slice 11, `/v1/policies/{id}/simulate` in SDD §15; earlier plans bind (slice 02 Policy shapes and publish validation; slice 04 signature Rules; slice 08 limits, coverage matcher and its conservative rule; D-053 design; tenancy; privacy allowlist).

## Global Constraints (additions)

- **Request:** `POST /v1/apps/:appId/policy/simulate` body `{ environment, rules: [PolicyRuleInput…] }` — the same validation as publish (≤ 50 Rules; limits; requires). Admin key. Nothing is written.
- **Events replayed:** `request.decision` Events of that App and Environment with `ts` in the last 24 h, oldest first for the replay, at most 50,000 (the newest 50,000 when there are more; `truncated: true` and the actual `from`).
- **Rule matching per Event:** method as Shield does (HEAD with GET; empty methods = all); path by the route-template matcher → `covered`, `not covered` or `undecidable`. Templates not starting with `/` (`(unmatched)`, `(mount)/…`) and patterns the matcher cannot decide are `undecidable` for that Rule.
- **Outcome per matched Event (mode is ignored: the simulation shows what enforce would do):**
  - block Rule → `would_block`.
  - `requires: "signature"` → `would_fail_signature` when the Event's signature is not valid with body checked or none (`signature` null from an older Shield → `undecidable`).
  - limit Rule → replay a sliding exact window in `ts` order per key: `ip` = `actor.ip_hash` (null → one shared "unknown" client, reported), `device` = attested device when the Event records a valid attestation device id if stored, else the ip hash; `count: "failures"` counts 401/403 and throttles further requests once the limit is reached; `would_throttle` for requests over the limit. Events the real Shield already blocked or throttled count as matched but not again as outcomes of the draft (they did not reach the app) — report them as `already_refused`.
  - First terminal outcome wins across Rules in Policy order, as in Shield (block and signature Rules before limit Rules).
- **Result:** `{ period: { from, to }, events, truncated, undecidable_events, not_simulated: ["patches"], rules: [{ index, id?, name, matched, would_block, would_fail_signature, would_throttle, already_refused, undecidable, clients_affected, sample_routes: [{ route, method, count }] ≤ 5 }], totals: { would_refuse, clients_affected } }`. `clients_affected` = distinct `actor.ip_hash` among would-refuse Events (never the hashes themselves).
- **Limits:** at most 6 simulations per minute per Organization (429 with `Retry-After`); a simulation over 10 s is cut off with `truncated: true` rather than failing.
- **Console:** Policy page: button "Simulate" (current Rules of the selected Environment) and "Simulate with this Rule" on the add-Rule form; result panel: caption "Estimate from the last 24 hours of recorded requests", per Rule a row with would refuse (split by kind), clients affected, could not be judged, sample routes; notes for truncated periods and "Virtual patches are not simulated."; the promote confirmation shows that Rule's figures from the latest simulation in this page view when present. Sentence case, no hyphens in prose.

## Review Focus

1. **Truthfulness:** no over-claim — undecidable never counted as a match or a pass; estimate label; truncated periods visible.
2. **Parity with Shield:** method semantics, Rule order, limit window math (exact log), failure limits, signature requirement conditions — compare against real Shield decisions on the same traffic.
3. **Tenancy and safety:** nothing stored or published; another Organization's App is 404; cost bounded (cap, time limit, rate limit); no hashes or addresses in the result.
4. **Console:** figures shown match the API; stale results are not shown for a changed Rule.

## Tasks

Order: Task 1 (protocol) → Tasks 2–3 in parallel (API ‖ Console) → Task 4 (e2e) → Task 5 (review, docs).

## Residual risks known up front

- Estimates from templates; 24 h only; per-instance counters differ from one replayed counter.

## Deliberately not in this slice

Patches · longer history · scheduling · version comparison.

## Amendments
- **A1 — Protocol as built (Jev: four_changes, 0.55 — low confidence on wire-shape details, not a product decision; noted to the owner).** `SimulatePolicyRequestSchema` reuses the publish Rules schema; `SimulationResultSchema`, `SIMULATION_LIMITS`, `EXAMPLE_SIMULATION_RESULT` in `policy.ts`; unknown keys stripped at every level so no hash or address can ride along. Changed: the response is `{ simulation }`; `not_simulated` is an array of strings (today `["patches"]`); every draft Rule gets a row whose `index` is its position; `matched` counts Events whose method and route matched, `undecidable` counts Events whose route could not be judged plus matched Events whose outcome could not be judged; sample counts are at least 1.
- **A2 — API as built (Jev: fix_device_unknown_index, 0.95).** Pure engine `src/simulate/replay.ts` and route `src/routes/simulate.ts`; the replay equals real Shield decisions on 3,000 generated requests for block, signature, address and failure limits; route judging is conservative (a template segment with a wildcard or group makes the rest undecidable; a literal against a `:param` is undecidable). Stored Events carry no device id, no preflight flag, and a refused request carries the refusing Rule's pattern as its route. An Event another Rule may have refused is not counted on limits (under-claims); `already_refused` = enforced decisions only; limits above 1,000 replayed exactly; only valid drafts use the rate limit (per API process); the never-block list, Containments and in-flight slots are not simulated; a time-limit cut ends the period at the last Event replayed. Changed: device limits replay attested Events against the address at 5 × the limit and others at 1 ×, with the gap counted as could not be judged (a lower bound); an Event without an address hash is never throttled and counts as could not be judged; an index for the read; protocol comments aligned (sample routes are the top 5 among would-refuse Events).
- **A3 — Console as built (Jev: exact_list_and_note, 0.75).** One Server Action reads the Policy itself and appends the typed Rule for "Simulate with this Rule" (needs JavaScript; nothing published or revalidated); the result lives in page state keyed by Environment and version; panel with period, per-Rule figures, totals, notes and an empty state; a 429 reads "Too many simulations. Try again in N s."; unknown `not_simulated` values shown verbatim. Changed: the promote confirmation shows an estimate only from a simulation of exactly the current Rules, and says "as if every Rule were enforced"; a failed simulation keeps the last successful result with the error above it. Known limit: the figure assumes every Rule is enforced, so promoting one Rule while an earlier one stays in monitor can refuse more than shown.
- **A4 — Device limits, strict (Jev: strict, 1.0).** The 5 × address bound could claim a throttle Shield would not apply (a throttled device retrying inflates the replayed address counter). Replaced: under a device limit an attested Event that would pass 1 × the limit on its address is never claimed as throttled; it counts as could not be judged and on no limit. Index `events_replay` (migration 0020). The Console shows "No requests would be refused" for a Rule without samples.
- **A5 — Review fixes (to do, test first).** An independent review compared the replay with a real enforcing Shield and reproduced 3 HIGH, 3 MEDIUM and 5 LOW findings (scripts in the scratchpad `s11adv/`). Engine (Jev fix_set, 0.81): F1 a route template with any segment that is not a plain literal or `:param` (regex, arrays) is could not be judged; F2 for limits above 1,000 a request past the limit is could not be judged; F3 an Event whose network prefix overlaps a never-block range is could not be judged for limit Rules; F4 a valid signature with the body unchecked is could not be judged; F6 `unknown_client_events` per Rule and in totals, `clients_affected` leaves them out, and the Console says clients are unknown without an actor key; F8 a throttle claim that would vanish if the window edge moved 5 ms is could not be judged; F9 the replay yields to the event loop and caps stored timestamps (beyond: could not be judged and truncated); F10 only a replayed draft uses the rate budget, on a sliding window; F11 Events stamped up to 5 minutes ahead are included; F7 (an unjudgeable Event can shift which later request is named; totals equal) documented. `not_simulated` lists patches, containments, decoded paths, device limits and body verification, each explained in the Console. Promotion (Jev if_promoted_per_rule, 0.92): F5 for every monitor Rule the result carries `if_promoted` — what the currently enforced Rules plus this one would refuse — and the confirmation shows that figure with the time of the run; the panel keeps the all-enforced view. Console column renamed "Routes refused most".
- **A6 — Review fixes as built (Jev undecidable_now_field_later, 1.0).** Reviewer scripts after the fixes: route shapes 8 over-claims and 12 confident misses → 0 and 0; limits above 1,000 500 over-claims → 0; never-block list 4 → 0 (with the Organization's list passed, as the route does); body unchecked 2 → 0; window edge never claimed; 50 limits × 50,000 clients 1,408 ms / +540 MB → 206 ms / +84 MB; no actor key: clients unknown instead of "1 client"; a run of a missing App no longer uses the budget. Added: under a signature Rule a signed request with a body is could not be judged and counted on no limit (an enforcing Shield refuses it when its content type is not in `bodyVerified`, which the API cannot see); judging it exactly needs Shield to record that — a follow-up. A route segment is judged only if it is plain text over `A-Z a-z 0-9 . _ ~ -` or a whole `:name`.
- **A7 — Never over-claim on limits (Jev: taint 1.0; confirm_refine_later 0.79).** Invariant in `replay.ts`: for every limit counter the replay's count never exceeds Shield's, so a claimed throttle is always real. A request Shield may have counted but the replay could not judge (including requests the real Shield already refused) taints the covering counters until it leaves the window (+ 5 ms); a pass on a tainted counter, or one within 5 ms of a window edge, is could not be judged and not counted. Attested requests under a device limit are never judged. A property test runs 300 generated drafts and sequences through Shield's real decision code and asserts no per-Event over-claim. Random runs (30 seeds × 4 modes): over-claims 0, confident misses 0; limit-only drafts claim 22 of 92 real refusals, mixed drafts about 1,415 of 1,554. Follow-up recorded: a two-count refinement (certain and possible hits) to judge more passes for generous limits; the Shield Event recording whether a body was in `bodyVerified`.
