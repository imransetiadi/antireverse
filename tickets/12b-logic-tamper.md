---
title: "Ticket 12b — Reverse Assessment: W3 Logic and W4 Tamper"
aliases: [Ticket 12b]
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
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# 12b: Reverse Assessment — W3 Logic and W4 Tamper

**What to build:** The last two web Objectives get verifiers, so an Assessment can finally produce a Reverse Resistance Score. W3 checks whether the agent reimplemented a function the tenant designated, against hidden test vectors; W4 checks whether the agent made a modified bundle run with its integrity check neutralised.

**Blocked by:** 12a (done). Jev: `--logic` file (1.0); owner: a Build without a tamper check counts W4 as achieved (2026-11-13, D-075).

**Status:** done on 2026-11-13 — plan in [plans/2026-11-13-slice-12b-logic-tamper.md](../plans/2026-11-13-slice-12b-logic-tamper.md)

## Acceptance criteria

- [x] `antireverse harden --logic logic.json` designates up to 5 protected functions, each with an id, a description and up to 2 public examples shown to the agent, and 10–200 hidden test vectors that the agent never sees. The Manifest carries their digest and count; the API stores the vectors with the Build and never returns them.
- [x] W3 is achieved when, for any one designated function, the agent's submitted reimplementation (a JS function body) returns the expected output for every hidden vector, run in the sandbox. Without a designated function W3 is not attempted (`not_designated`) and the Console says how to add one.
- [x] W4: the agent submits a modified version of one artifact JS file. The verifier runs it in the sandbox with stub browser globals and a per-run nonce. It is achieved when no integrity-check failure occurs, code that ran set the nonce marker, and the code that ran is still the original protected code with only a small edit (common prefix plus suffix ≥ 90 % of the original). A Build without `--integrity` has no tamper check, so a small marker edit achieves W4 (owner, D-075). Deleting the protected code and printing the marker never counts.
- [x] The stand-in agent attempts W3 (from the public examples) and W4 (a scripted marker edit) deterministically.
- [x] With W1–W5 decided, an Assessment is scored: the Build page shows the RRS meter, its scope statement and per-Objective evidence with fix suggestions — in the restyled design (D-053).
- [x] `npm run verify` passes; an end-to-end test hardens the reference app with `--logic` and with and without `--integrity`, runs a T1 Assessment and sees a score on the Build page.

## Decisions taken with Jev and the owner

- `--logic` file with hidden vectors, all must pass (Jev 1.0). A Build without a tamper check counts W4 achieved (owner, D-075). No JavaScript file → W4 not attempted, `no_runnable_file` (owner, D-076). Every Prove sandbox runs in a child process under the Node permission model (Jev 1.0). W4 needs the marker inside code that completed (or failed like the original) plus a behavioural trace (Jev 0.74). Full list: plan amendments A1–A3.

## Proof

| Criteria | Proven by |
|---|---|
| `--logic` | `packages/harden/test/cli-logic.test.ts`; `packages/protocol/test/logic*.test.ts`; `apps/api/test/build-logic.test.ts` |
| W3 | `packages/prove/test/logic.test.ts` |
| W4 | `packages/prove/test/tamper.test.ts` (including the hardened reference bundles as fixtures) |
| Sandboxes | `packages/prove/test/sandbox.test.ts` (child process, permission model, refused `import()`, prototype pollution withheld) |
| Stand-in, scoring, judging budget | `packages/prove/test/stand-in.test.ts`, `assess*.test.ts` |
| Build page | `apps/console/test/assessment-*.test.*`; `tests/e2e/reverse-assessment-12b.e2e.ts` |
| Quality | `npm run verify` — 7,327 tests, type-check, lint · e2e HTTP 12/12 and browser 4/4 |

Independent review, three rounds: F1 sandbox escape through the `import()` promise (also in 12a), F2 forged W4, F3 2 MB bundle out of memory, F4 judging past the deadline; then N1 toJSON forgery of the result line, N2 W4 credited without protected code running, N3 judging starvation — all reproduced, fixed test-first and re-run. Jev verified the completion claims.

## Honest limits

The stand-in agent is scripted. Harden's integrity check is a tamper signal, not tamper-proofing, so a determined agent defeats it. The sandbox has no real browser: a bundle that needs one may fail before the marker, which counts as not achieved. A further adversarial pass on the new sandbox design (parser differentials, other routes to host objects, trace replay) was stopped by model safeguards before it ran; it must be completed before a real model agent is enabled. The behavioural trace records names only and falls back to text similarity when the original touches no browser global.

## Out of scope

A real model agent (owner key, D-067) · CI gate (13) · Guard runtime attestation inside the sandbox · calibration.
