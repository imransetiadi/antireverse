---
title: "Ticket 12a — Reverse Assessment v1 (orchestrator, stand-in agent, W1/W2/W5)"
aliases: [Ticket 12a]
project: anti-reverse
doc: TICKET
slice: 12
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
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# 12a: Reverse Assessment v1 — orchestrator, stand-in agent, Map, Secrets and Replay

**What to build:** A registered Build can be assessed: an adversary agent works on the protected bundle inside a budget, independent verifiers decide which Objectives it achieved, and the Build page shows the Reverse Resistance Score with evidence — or says why there is no score. The agent is a deterministic stand-in until a real model is configured (owner D-067); the seam for a real agent is in place. This part covers Objectives W1 Map, W2 Secrets and W5 Replay; W3 Logic and W4 Tamper follow in 12b, so scores stay inconclusive until then.

**Blocked by:** 05 (done). Owner D-067; Jev split 12a/12b (0.47 vs 0.47 — tie, chosen for smaller increments), D-073.

**Status:** done on 2026-11-13 — plan in [plans/2026-11-13-slice-12a-reverse-assessment.md](../plans/2026-11-13-slice-12a-reverse-assessment.md)

## Acceptance criteria

- [x] An admin (or `antireverse harden --register --assess`) requests an Assessment of a registered Build at tier T1, T2 or T3. Only Builds of the Organization, with their planted Canaries, can be assessed (Proof of Ownership); the artifact is uploaded with the request and kept for the Assessment plus 30 days.
- [x] An orchestrator runs queued Assessments one at a time per Organization within the tier's budget (tool calls and time; T1 150 calls / 15 min, T2 1,500 / 2 h, T3 6,000 / 8 h, configurable for tests), with an `AdversaryAgent` seam and a deterministic stand-in agent that uses only the Toolbelt.
- [x] The Toolbelt gives the agent read-only access to the artifact (list, read, search, beautify) and a code runner in an isolated worker without network or file access, with time and memory limits. Every call is recorded.
- [x] Verifiers decide Objectives independently of the agent: W1 Map against a route inventory the tenant supplies with the Build and the agent never sees (coverage threshold 0.6); W2 Secrets against the Build's planted Canaries and leak-scan findings; W5 Replay by sending the agent's submitted request to a replica Shield that requires a signed request. W3 and W4 are not attempted in this part.
- [x] RRS follows SDD §12.1: rᵢ by the earliest tier achieved; not attempted is excluded; more than 20 % excluded makes the Assessment inconclusive with no number; every result carries the scope statement (agent name and version, model or "stand-in", toolbelt version, tier).
- [x] Evidence per Objective (what was recovered, how, at what cost, which calls) is stored and shown on the Build page with a fix suggestion; the Build page shows the RRS meter or the inconclusive reason, and the Objective rows — in the restyled design (D-053).
- [x] `npm run verify` passes; an end-to-end test hardens the reference app, registers it with a route inventory, runs a T1 Assessment with the stand-in agent, and sees W2 achieved on an unprotected build (a planted Canary recovered), W1 judged, W5 refused against the replica, W3/W4 not attempted, and the Assessment inconclusive with its reason on the Build page.

## Decisions taken with Jev

- W2 runs on Canaries only (the Manifest carries no leak fingerprints); W1 needs ≥ 60 % coverage and ≥ 50 % precision, with submissions capped at 2 × the inventory (0.91). Only evidence-referenced calls are stored, at most 200 (0.70). Each Assessment runs in its own worker with a hard deadline (0.96). Full list: plan amendments A1–A7.

## Proof

| Criteria | Proven by |
|---|---|
| Request, Proof of Ownership, retention | `apps/api/test/assessments*.test.ts`, `build-routes.test.ts`; `tests/e2e/reverse-assessment.http.test.ts` (8) |
| Orchestrator, budgets, queue | `packages/prove/test/budget.test.ts`, `assess*.test.ts`; `apps/api/test/assessment-runner.test.ts`, `assessment-engine.test.ts` |
| Toolbelt and isolation | `packages/prove/test/toolbelt.test.ts`, `sandbox.test.ts`, `assess-worker.test.ts` |
| Verifiers and RRS | `packages/prove/test/verifiers.test.ts`, `replica.test.ts`; `packages/protocol/test/assessment.test.ts` |
| Evidence and Build page | `apps/console/test/assessment-*.test.*`; `tests/e2e/reverse-assessment.e2e.ts` (Chromium) |
| Quality | `npm run verify` — 7,128 tests, type-check, lint · e2e HTTP 8/8 and browser 3/3 |

An independent review reproduced 1 HIGH (a CORS preflight graded as a replay), 1 MEDIUM (a run blocked the API event loop) and 1 LOW (sandbox output outside JSON); all fixed test-first. Jev verified the completion claims.

## Honest limits

The stand-in agent is scripted, so scores measure the verifiers and the pipeline, not real resistance, until a real model is configured; the result says so. Local isolation is a separate worker, not the hosted isolated account (SDD §12.2). W2 checks Canaries only, not leak-scan findings. Every 12a Assessment is inconclusive (W3/W4 excluded = 45 %). The queue limits assume one API process.

## Out of scope

W3 Logic and W4 Tamper (12b) · a real model agent and spend caps (after the owner's key, D-067) · CI gate (13) · hosted sandbox account · calibration.
