---
title: "Plan — Slice 12a Reverse Assessment v1"
aliases: [Plan 12a]
project: anti-reverse
doc: PLAN
slice: 12
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
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# Slice 12a — Reverse Assessment v1 Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read. CLAUDE.md Rule 1 applies: on a real design fork, implement the plan as written and list the fork in your report — do not decide it.

**Goal:** Every assessed Build gets an honest result: a score with evidence, or the reason there is none.

**Architecture:** Protocol defines Assessments, Objectives, results, evidence, tiers, the scope statement and the RRS function. A new workspace `packages/prove` holds the orchestrator core (budgets, the `AdversaryAgent` interface, the stand-in agent, the Toolbelt with an isolated worker runner, the verifiers' interfaces and the W1/W2/W5 verifiers, the scorer) with no network access of its own; the API stores Assessments and artifacts, queues and runs them through `packages/prove`, and exposes routes; Harden gains `--assess` and `--routes <file>`; the Console shows the result on the Build page. No new runtime dependency.

**Spec:** [tickets/12a-reverse-assessment.md](../tickets/12a-reverse-assessment.md); SDD §5.4, §12.1, §12.2; SECURITY TA-01, TA-05, TA-06, TA-14, SC-USE-01, SC-ISO-05; PERFORMANCE PB-22, tier ceilings; UIUX SCR-07, RRS meter, Inconclusive; D-067, D-073; earlier plans bind (slice 05 registration and Manifest; slice 07 Canaries and leak scan; slice 04 signed requests; tenancy; D-053).

## Global Constraints (additions)

- **Ids:** Assessment `asm_<24 hex>`.
- **Objectives (web):** W1 Map 0.15, W2 Secrets 0.20, W3 Logic 0.25, W4 Tamper 0.20, W5 Replay 0.20. Result per Objective: `achieved` (tier) | `not_achieved` | `not_attempted` (reason: `not_supported` in 12a for W3/W4, `refused`, `tool_failure`, `sandbox_error`, `budget_exhausted_before_attempt`).
- **Tiers:** T1 150 calls / 15 min, T2 1,500 / 2 h, T3 6,000 / 8 h. An Assessment at tier Tn runs the agent once with Tn's budget; it records the cost at which each Objective was achieved and maps that cost to the earliest tier whose limits it fits (so a T3 run can still say "achieved within T1 limits"). Budgets overridable for tests.
- **RRS:** `round(100 × Σ wᵢ rᵢ)`. Excluded (not attempted) weight above 20 % → `inconclusive`, no number. Otherwise the attempted Objectives' weights are renormalised to sum to 1 (documented with the score). rᵢ: achieved within T1 limits 0.0, T2 0.4, T3 0.7; not achieved in a T3 run 1.0; not achieved in a T1 run counts as 0.4 and in a T2 run as 0.7 (the run cannot show resistance beyond its own tier). Status: `queued` | `running` | `scored` | `inconclusive` | `failed`.
- **Scope statement:** `{ agent: { name, version }, model: string | "stand-in", toolbelt: version, tier }` on every Assessment; shown with every score.
- **Proof of Ownership:** the Build belongs to the Organization, was registered with a Manifest, and the uploaded artifact's file hashes equal the Manifest's; else 400. Artifact ≤ 25 MB, kept for the Assessment plus 30 days.
- **Route inventory (W1):** optional `routes` file given to Harden (`--routes <file>`, JSON list of `METHOD /path` with `:param`), stored with the Build, never given to the agent; W1 achieved when the agent's submitted endpoint list covers ≥ 60 % of the inventory (method and path template match, case-insensitive method); without an inventory W1 is `not_attempted` (`no_inventory`).
- **W2:** achieved when any submitted value equals a planted Canary value of the Build or a leak-scan finding's value (compared by fingerprint, never storing the raw secret in evidence: evidence keeps the Canary id or the finding fingerprint).
- **W5:** the agent submits one HTTP request (method, path, headers, body); the verifier sends it to an in-process replica Shield configured with a signature requirement on the reference route; achieved when the replica answers 2xx (not refused). Requests are never sent anywhere else.
- **Toolbelt:** `list(dir)`, `read(path, range)`, `search(pattern literal, max 200 hits)`, `beautify(path)` (in-house simple formatter or Babel already present in Harden), `run(code, input)` in a `worker_threads` worker with `resourceLimits`, no `require`, no `process`, no network, 5 s per call; `submit(objective, payload)`. Each call costs one tool call; wall time counts against the tier.
- **Agent seam:** `interface AdversaryAgent { name; version; model; run(context, toolbelt, budget): Promise<void> }`; the stand-in agent: searches for Canary-shaped strings and known secret patterns, extracts URL path literals and fetch calls for W1, builds a request from observed routes for W5. Deterministic.
- **API:** `POST /v1/apps/:appId/builds/:buildId/assessments` (multipart or JSON with base64 artifact files; tier) → 202 `{ assessment }`; `GET …/assessments`, `GET /v1/assessments/:id` (status, results, RRS or inconclusive reason, scope, evidence). Admin key; queue one running per Organization, global concurrency 2; restart marks running ones `failed` (reason) and keeps queued ones.
- **Console:** Build page section "Reverse resistance": RRS meter (bullet with the scope line beneath) or "Inconclusive: <reason>" (never a number); Objective rows (name, result chip, tier, cost, evidence summary, fix suggestion); "Assess" button with tier choice; history list.

## Review Focus

1. **No self-grading:** verifiers never trust the agent's claims; W2 evidence never stores raw secrets.
2. **Isolation:** the code runner cannot reach the network, the file system, the process, or other Assessments; resource limits hold.
3. **Ownership and tenancy:** only the Organization's own registered Builds with matching hashes; no cross-tenant artifacts or results.
4. **Scoring honesty:** inconclusive rule, renormalisation, tier mapping, scope statement always present.

## Tasks

Order: Task 1 (protocol) → Tasks 2–5 in parallel (prove core ‖ API ‖ Harden ‖ Console) → Task 6 (e2e) → Task 7 (review, docs).

## Amendments
- **A1 — Protocol as built (Jev: partial_on_failed_and_reason_code, 0.90).** `src/assessment.ts` (Objectives with weights and fix suggestions, tiers, resistance values, schemas, `scoreAssessment` in whole-number arithmetic with half-up rounding, `tierForCost`), `src/routes-digest.ts`; the Manifest gains `routes_digest` and `route_count` and the register request an optional `routes` list (never returned); results are an array of `{ objective, result }`; W2 evidence refuses decoy-key values; replay evidence keeps only the replica's status. Changed: a failed Assessment may keep partial results (never a score); an inconclusive result carries `inconclusive_code: "excluded_over_limit"` beside its text.
- **A2 — Harden as built (Jev: register_then_refuse, 0.77).** `--routes <file>` (validated before any work, sent beside the Manifest, never printed or written beyond a count) and `--assess <T1|T2|T3>` (requires `--register`; uploads exactly the Manifest's artifacts; prints the assessment id and the Build page link from `AR_CONSOLE_URL`; a failed upload exits 1 and the Build stays registered; `--fail-on`'s exit 4 takes precedence). Changed: an artifact over the assessment limits never blocks hardening — the Build is registered and written, the upload is skipped with a message, exit 1.
- **A3 — Console as built (Jev: reuse_kept_artifact, 0.66).** Build page "Reverse resistance" first: RRS meter (one accent colour until a threshold exists) with the scope line, or "Inconclusive: <reason>" with no number; Objective rows (Achieved in the warning colour — the attacker got it; Not achieved in green; Not attempted with its reason), cost, recovered items, fix suggestion when achieved; a note that a scripted stand in scored the run; partial rows for failed runs; history. Development stub seeds include scored runs by a made-up model so the meter can be seen. Changed: the create request's files become optional — the API reassesses the Build's most recent kept artifact (30 days) or answers 409 `artifact-required`; Assessments carry `artifact_kept_until`; the Console gets "Assess again" with a tier choice when an artifact is kept.

## A4 — Prove core as built, and the W1/W2 forks (2026-11-13)

`packages/prove` exports `assess` (Budget, Toolbelt over a worker_threads + node:vm sandbox, StandInAgent, W1/W2/W5 verifiers, in-memory Shield replica for W5). 101 tests at hand-off. Implemented as described by the worker: Babel 8.1.0 as a direct dependency; W5 target `/**` on every method by default; one W5 request per Assessment; `agentError` cut to its first line, 200 characters; budget overrides capped at the protocol tiers.

Jev (0.91, no contradicted requirement): W2 runs on Canaries only in 12a — the Manifest carries no leak fingerprints, so the API passes none (documented limit). W1 gains a precision rule: distinct submissions capped at 2 × route_count, and achievement needs ≥ 60 % coverage and ≥ 50 % precision, so a padded list of guesses is not achieved.

As built (108 prove tests): a refused W1 submit still costs one call, so the call log and the budget agree; the refusal reveals that a cap exists, which only tells an agent the inventory size at one call per probe — accepted. The stand-in agent submits all endpoints in one call, so on a large bundle it can lose W1; that errs towards a lower score, not an inflated one — accepted for the stand-in.

## A5 — API as built and the call log (2026-11-13)

API lane: migration 0026 (build_routes, artifacts as bytea capped at 25 MB, artifact_files, assessments; RLS + FORCE), routes for create/list/get, runner (one per Organization, two in all, tier seconds + 60 s grace, interrupted on restart), `proveAssessor` with the StandInAgent. Accepted as built: bytea storage, no partial results on timeout (only `agent_error` keeps them), `agent_error` is failed, no replay target (prove's `/**`), retention moves to the latest finish + 30 days, queue ids across Organizations to the request role (as slice 14 F5), Builds without Canaries can be assessed (W2 then not achieved).

Jev (0.70, no contradicted requirement): store only the calls that evidence references, capped at 200, with totals, returned only by id; indexes cut by the cap are dropped so every stored index resolves.

## A6 — End-to-end tests (2026-11-13)

`tests/e2e/reverse-assessment.http.test.ts` (8) runs the real Harden CLI with `--routes --assess T1 --register` against the real engine; `reverse-assessment.e2e.ts` (1, Chromium) shows running/queued, the inconclusive reason, the Objective rows and "Assess again". The e2e API wraps the real `proveAssessor` in a hold (`E2E_ASSESS_HOLD_FILE`) so the queued and running states are visible; the `balanced` profile serves as the unprotected build because its Canaries stay plain literals. Both are test-harness choices, not product behaviour.

## A7 — Independent review (2026-11-13)

Reproduced: F1 HIGH — an unsigned CORS preflight (OPTIONS with `access-control-request-method`) was graded W5 achieved, because Shield exempts preflights and the replica answered 200; fix: preflights are not replays (replica 2xx only for non-OPTIONS, W5 refuses OPTIONS). F2 MEDIUM — a run blocked the API event loop (24 MB artifact: 12.9 s; a 2 s budget ran 4.4 s); Jev (0.96): run `assess` in its own worker per Assessment with resource limits and a hard terminate at the deadline (`assessInWorker`), plus a macrotask yield per Toolbelt call. F3 LOW — sandbox output could escape the JSON contract by breaking out of the pasted wrapper; fix: compile the code as a function body. Not reproduced, hardened anyway: artifact expiry racing a reuse (pick and insert in one locked transaction). Documented: the queue's per-Organization and global limits and interrupt-on-start assume one API process (the PGlite deployment).
