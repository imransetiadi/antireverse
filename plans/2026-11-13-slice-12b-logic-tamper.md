---
title: "Plan — Slice 12b W3 Logic and W4 Tamper"
aliases: [Plan 12b]
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
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# Slice 12b — W3 Logic and W4 Tamper Implementation Plan

> **For agentic workers:** test first; one worker per workspace; verify by running commands and reading their output. CLAUDE.md Rule 1: implement as written and list real forks in your report.

**Goal:** Assessments of web Builds produce an honest score.

**Spec:** [tickets/12b-logic-tamper.md](../tickets/12b-logic-tamper.md); SDD §12.1; QASUITE §4 (designated protected functions, tamper kit); SECURITY TA-01, TA-03; 12a plan and amendments A1–A7 bind.

## Global constraints

- **Logic file** (`--logic <file>`): `{ functions: [{ id: /^[a-z][a-z0-9-]{0,31}$/, description (1–500 chars), examples: [{input, output}] (0–2), vectors: [{input, output}] (10–200) }] }`, 1–5 functions; `input` is a JSON array of arguments, `output` any JSON value; the whole file ≤ 1 MB. Manifest gains `logic_digest` (SHA-256 of the canonical JSON of the hidden part) and `logic_count`, mirroring `routes_digest`/`route_count`. Registration carries `logic` beside `routes`; the API checks the digest, stores it in its own table, never returns vectors. What the agent sees per function: id, description, examples.
- **W3 verifier:** submission `{ function_id, body }` (JS function body; parameters are the input array spread as `a0..aN` and also `args`). Each vector runs in the sandbox (one worker for the batch, per-vector timeout 1 s, total ≤ 20 s); output compared by canonical JSON equality. Achieved when every vector of that function passes. Up to 3 W3 submissions per run. Evidence names the function id and the pass count, never vectors. Without logic: `not_attempted` reason `not_designated` (new protocol reason, text "No protected function was designated; add --logic to Harden").
- **W4 verifier:** each run gets a nonce (16 hex). Submission `{ path, code }` for a `.js`/`.mjs`/`.cjs` artifact file, ≤ 2 × original size. Run in a fresh sandbox worker with stub globals (`window`, `document`, `self`, `navigator`, `location`, `localStorage` as permissive proxies swallowing calls), `eval` replaced by a recorder that calls the real indirect eval, 5 s timeout. Achieved when: (1) no error whose message contains "integrity check failed"; (2) `globalThis.__airverse_tamper === nonce` after the run (errors after the marker are tolerated); (3) similarity: for Builds hardened with integrity, some recorded eval'd string, else the submitted file, has common prefix + common suffix ≥ 90 % of the original (the original payload for integrity Builds, the original file otherwise). Up to 3 W4 submissions per run. The Manifest's `transform.integrity` tells which case applies.
- **Stand-in:** W3 — submits a lookup over the public examples (expected not achieved on hidden vectors); W4 — inserts `globalThis.__airverse_tamper="<nonce>";` at the start of the payload/file and, for integrity Builds, rewrites the wrapper's hash comparison (`__h(__payload)!==` check) so the edited payload runs.
- **Scoring:** unchanged (12a). W1 `no_inventory` (0.15) alone stays under 20 %, so a Build with logic and without routes is still scored, renormalised.
- **Console:** the RRS meter appears for scored Assessments (already built in 12a); W3 `not_designated` shows the Harden hint; W4 evidence names the file, never code.

## Tasks

1. Protocol: logic schemas and digest, Manifest fields, `not_designated`, submission shapes. 2. Harden: `--logic`. 3. Prove: W3/W4 verifiers, Toolbelt submit, stand-in, `assess`/`assessInWorker` inputs (`logic`, `integrity`). 4. API: registration storage (migration 0029), pass logic and integrity to the engine. 5. Console: hints and copy. 6. e2e and independent review.

## A1 — Lanes as built (2026-11-13)

- Protocol: `src/logic.ts`, `logicDigest` (server entry; full function list sorted by id, Jev 0.88), Manifest `logic_digest`/`logic_count` (count ≥ 1), `not_designated` ("no protected function was designated (add --logic to Harden)"), `LogicSubmissionSchema`, `TamperSubmissionSchema`, `TAMPER_LIMITS`. W3/W4 fix texts live only in the protocol's `OBJECTIVES` (no hyphens, per the Console catalog check).
- Harden: `--logic <file>` (≤ 1 MB on disk, validated, never in output or uploads). The e2e writes the reference logic file at run time, like `routes.json`, designating `discounted(cents, pct)` of `apps/range/web/src/pricing.ts`; it must never sit inside the bundle folder.
- API: migration 0029 `build_logic` (RLS + FORCE, SELECT/INSERT only), digest check at registration, never returned; the runner forwards `logic` and `integrity`.
- Console: `not_designated` hint, W4 evidence as the summary only, scored stub run.

## A2 — E2E gap and independent review (2026-11-13)

- The reference app hardens to `.ts` files only, so the stand-in had no W4 file and W4 was recorded `not_achieved` (scored as resistance with no check). Owner, after Jev 0.36: with no `.js/.mjs/.cjs` file W4 is `not_attempted` with reason `no_runnable_file` ("no JavaScript file to run (assess the bundled output)"). The 12b e2e assesses the reference app bundled into one file (esbuild), ESM and, with `--integrity`, a classic script.
- Review F1 HIGH (reproduced by me too): `import("x").constructor.constructor` inside a vm context in a worker thread reaches the host's `process` and `node:fs` — Toolbelt `run` (12a), W3 and W4. Jev 1.0: every sandbox runs in a child process under `node --permission` with no grants, empty env, JSON IPC, import() neutralised, child messages untrusted. In 12a only the stand-in's own code ran there; in 12b W4 runs tenant artifact code, so this blocks the slice.
- F2 HIGH: W4 achieved on integrity Builds without neutralising the check (marker prefix, a recorded but failing eval, forged message). Fix: only completed evals count; the marker must be set inside a counted eval; evidence says "evaluated", not "ran".
- F3 HIGH: Babel analysis of a 2 MB bundle exceeded the 256 MB assess worker; moved into the tamper child, bounded.
- F4 MEDIUM: judging after the run could exceed the deadline; judging gets its own budget and an Objective that runs out becomes `sandbox_error`.

## A3 — Re-review (2026-11-13)

F1–F4 re-run: fixed. New: N1 HIGH — the `import()` promise is still a child main-realm object; polluting its `Object.prototype` with `toJSON` read the IPC token and forged a W4 "achieved". Fix: refuse sources with dynamic `import()`/`import.meta` before compiling, build result lines from checked primitives, keep the token in a closure, check built-in prototypes after the run. N2 HIGH — the counted-eval rule credited `marker; throw 0; payload` and a hooked stub global; Jev (0.74) behavioural trace: an eval counts only when it completes normally with the marker statement inside its source, stub globals are frozen, and the tampered run must reproduce ≥ 90 % of the original's recorded interactions with the stub globals (textual fallback when the original has none). N3 MEDIUM — three slow W3 bodies used the whole judging budget and made the run inconclusive; the budget is split per submission and anything judged gives a verdict.

## A4 — Real bundles and close-out (2026-11-13)

The N2 rule rejected the stand-in's honest edit on the real hardened reference bundles: Harden's string decoder needs `atob` and `TextDecoder`, absent from the sandbox, so even the original threw. Fixed: the W4 context provides `atob`, `btoa`, `TextDecoder`, `TextEncoder`; a run counts when it completes normally or ends with exactly the baseline's error; the marker rule is unchanged. The hardened bundles are prove fixtures. The prototype snapshot covers Error, Map, Set, WeakMap, WeakSet and Symbol too. A fresh adversarial review of the new design was stopped by model safeguards; recorded as pending before any real model agent.
