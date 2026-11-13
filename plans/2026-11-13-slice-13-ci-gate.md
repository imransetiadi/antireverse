---
title: "Plan — Slice 13 CI gate"
aliases: [Plan 13]
project: anti-reverse
doc: PLAN
slice: 13
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

# Slice 13 — CI gate Implementation Plan

> Test first; verify by running commands and reading their output. CLAUDE.md Rule 1: list real forks in the report.

**Goal:** CI fails honestly on a low or missing Reverse Resistance Score.

**Spec:** [tickets/13-ci-gate.md](../tickets/13-ci-gate.md); PRD story 51, FR-PRV-05; slice 19's `--fail-on` (exit 4) and 12's `--assess` bind.

## Global constraints

- Exit codes: 0 ok · 1 failure · 2 usage · 3 leak scan · 4 findings at or above `--fail-on` · **5 RRS below `--min-rrs`** · **6 no score** (inconclusive, failed, or wait ended). When both 4 and 5/6 apply, the lowest non-zero gate code wins and both gates are reported.
- `--min-rrs <int 0–100>` needs `--assess` (in `harden`) or `--assessment` (in `gate`); `--wait <seconds>` 1–86,400, default tier seconds + 300; `--on-no-score fail|pass`, default `fail`.
- Polling: GET `/v1/assessments/:id` with the admin key from `--key-env`; backoff 2 s doubling to 30 s; network errors retried within the wait; 4xx other than 429 stop with exit 1.
- Output: human lines name the score, threshold, status and the two lowest-scoring decided Objectives; `--json` adds `gate`. Never print the key or evidence content beyond Objective names and results.
- `antireverse gate` is a new subcommand in packages/harden's CLI (same binary).

## Tasks

1. Harden CLI: flags, the wait loop (injectable clock and fetch for tests), the `gate` subcommand, exit codes, usage text, JSON. 2. e2e: real CLI and API, with the fake assessor where a fixed score is needed. 3. README and docs.

## A1 — As built and reviewed (2026-11-13)

Harden `--min-rrs`/`--wait`/`--on-no-score` and `antireverse gate` in `src/gate.ts`. Jev (0.99): a progress line on stderr every 60 s, a per-poll timeout, the polled id checked. The e2e caught the wait ending 5 s early (a reserve accepted by me); fixed: poll until the deadline, last poll's timeout `min(15 s, max(left, 2 s))`, overrun ≤ 2 s. Independent review: F1 MEDIUM wall-clock deadline (monotonic clock), F2 retrying requests that can never succeed (validate key and endpoint, stop on a non-network TypeError), F3 the key echoed when passed as the `--key-env` value, F4 no `rrs_gate` when the Assessment was not queued; plus Retry-After, 408, the id on no-score lines, and `--out` written before waiting.
