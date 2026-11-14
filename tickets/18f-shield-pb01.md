---
title: "Ticket 18f — Shield within PB-01 on large bodies"
aliases: [Ticket 18f]
project: anti-reverse
doc: TICKET
slice: 18
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PERFORMANCE]]"
  - "[[QASUITE]]"
---

# 18f: Shield within PB-01 on large bodies

**What to build:** Shield's added latency on an attested and signed route meets PB-01 (p50 ≤ 0.5 ms, p99 ≤ 1.5 ms) with margin on the release gate's worst scenario: a benign 108 KB JSON body with `\u` escapes through the middleware and `verifyBody`, with the first catalog's 9 patches and 50 Rules. The release gate measured p50 542 µs and p99 1,716 µs (18e).

**Status:** done on 2026-11-14.

**Blocked by:** nothing. Chosen by Jev at 0.86, confidence 0.84 (D-098).

## Acceptance criteria

- [x] **Profile first:** the report names where the time goes in that scenario, with measurements.
- [x] **Behaviour unchanged:** every existing Shield test passes untouched. For any rewritten scan or verify step, a differential test compares old and new results on a corpus that includes hostile inputs: escapes, surrogate pairs, deep nesting, huge strings, invalid JSON.
- [x] **No new backtracking or quadratic paths:** a growth test (4× the input costs about 4× the time) covers the changed code.
- [x] **Margin:** on this machine, with the bench run three times, the scenario's p50 is at most 400 µs and its p99 at most 1,200 µs in every run. No other bench scenario regresses by more than 10 %.
- [x] **Gate:** `npm run gate:release` reports `bench-shield` as pass.
- [x] `npm run verify` passes.

## Out of scope

Changing the budget, or changing what Shield inspects.

## As built

Only `packages/shield-node/src/patches.ts` changed. The approach was chosen by Jev at 0.93.

- **Lazy escape form.** One pass collects the distinct code units that `\uXXXX` escapes decode to. The decoded form is built and scanned only for a condition whose needle contains one of those units; for `json_key`, JSON whitespace and `:` count too. With more than 16 distinct units it is always scanned.
- **Character probes.** On texts of 1,024 characters or more, up to 8 distinct needle characters are looked up once per text. If one is absent, the scan is skipped.
- **One shared `TextDecoder`** instead of one per body.

## Proof

| Criteria | Proven by |
|---|---|
| Profile | Before the change the body side took 330 µs of about 350: the escape form (85 µs to build and fold) and 7 conditions scanned on both forms (about 200 µs). After: 46 µs |
| Behaviour unchanged | `packages/shield-node/test/patches-differential.test.ts` against `test/reference/patches-before-18f.ts` (HEAD before 18f): 236 patches, about 125 hostile texts in five encodings, 6,000 generated bodies. Eight mutations of the new code each fail it. 1,665 existing tests pass untouched |
| Growth | Seven shapes at 240 K and 960 K characters: ratios 3.7 to 5.0 |
| Margin | Three bench runs on an idle machine: p50 55–58 µs, p99 487–600 µs (before: 345–377 and 1,050–1,321). Largest p50 change elsewhere +7.0 % |
| Gate | `npm run gate:release` on 2026-11-14: `bench-shield` passes (worst PB-01 p99 518 µs); verify 8,201 tests in 314 files; Playwright 26/26; every runnable check passes; verdict `blocked`, exit 2 |

**Independent review:** found no difference between the new matcher and the reference: 214,020 bodies and 23.1 million comparisons, including every string of up to 4 tokens around the escape, quote, colon and whitespace junctions. Its 7 own mutations were all caught by the slice's tests. Following its one suggestion, the generated test now catches the `json_key` tail and the cap of 16 on its own.

**Jev:** verified 3 of 3 completion claims. Its gate on the worker's diff escalated (safe_to_apply 0.64, low confidence on correctness) before the independent review.

## Honest limits

- **The bench body is a best case.** It lacks `_` and `o`, so the probes skip most scans. A benign body that holds every probed character of a needle saves only the escape-form half.
- **Hostile bodies that defeat both shortcuts are slower than before,** by up to 1.45×, and stay linear (for example 240 KB of escapes that decode to needle characters: 1.06 ms to 1.57 ms).
- **Not covered by the review:** bodies above about 1 MB, and Node versions other than 22.12.
- **The reference copy** under `test/reference/` is the yardstick and must not be edited to follow `src`.
