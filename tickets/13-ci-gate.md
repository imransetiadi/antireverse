---
title: "Ticket 13 — CI gate on the Reverse Resistance Score"
aliases: [Ticket 13]
project: anti-reverse
doc: TICKET
slice: 13
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
  - "[[QASUITE]]"
  - "[[UIUX]]"

# 13: CI gate on the Reverse Resistance Score

**What to build:** A pipeline step that fails when a Build's Reverse Resistance Score is below the team's threshold, so a regression never reaches production (PRD story 51, FR-PRV-05).

**Blocked by:** 12 (done). Jev: a CLI flag now, a per-App threshold in the Console later (0.94 combined); no score fails closed unless the team opts out (0.89).

**Status:** done on 2026-11-13 — plan in [plans/2026-11-13-slice-13-ci-gate.md](../plans/2026-11-13-slice-13-ci-gate.md)

## Acceptance criteria

- [x] `antireverse harden --register --assess <tier> --min-rrs <0–100>` waits for the Assessment it queued and exits 5 when the RRS is below the threshold, printing the score, the threshold and the weakest Objectives. At or above: exit 0.
- [x] `antireverse gate --assessment <asm_id> --min-rrs <n>` (with `--endpoint` and `--key-env`) does the same for an Assessment queued by an earlier step.
- [x] Waiting polls the Assessment with backoff until it finishes or `--wait <seconds>` runs out (default: the tier's seconds plus 5 minutes).
- [x] No score — inconclusive, failed, or still unfinished when the wait ends — exits 6 with the reason, unless `--on-no-score pass`, which passes with a warning and reports the gate as skipped.
- [x] `--json` reports the gate (as `rrs_gate` in `harden`, whose `gate` is the findings gate; as `gate` in `antireverse gate`) (`passed` | `failed` | `no_score` | `skipped`, rrs, threshold, status, reason). The key is never printed.
- [x] `npm run verify` passes; an end-to-end test runs the real CLI against a real API: a scored Assessment above the threshold exits 0, below exits 5, an inconclusive one exits 6 and passes with `--on-no-score pass`.

## Proof

| Criteria | Proven by |
|---|---|
| Flags, wait, exits, output | `packages/harden/test/cli-gate.test.ts` (fake clock and fetch: boundary, backoff, Retry-After, timeouts, clock jumps, key never printed) |
| End to end | `tests/e2e/ci-gate.http.test.ts` (10: real CLI and API, exits 0/5/6, `antireverse gate`, `--on-no-score pass`, full `--wait`) |
| Quality | `npm run verify` — 7,416 tests, type-check, lint |

The e2e caught the wait ending 5 s early; an independent review reproduced a wall-clock deadline, retries of requests that can never succeed, the key echoed through `--key-env`, and a missing `rrs_gate`; all fixed test-first. A value of `--key-env` that looks like an Airverse key is refused without being echoed. Jev verified the completion claims.

## Out of scope

A per-App threshold in the Console (later, onboarding) · gating on Pentest Findings (slice 15) · CI provider templates.
