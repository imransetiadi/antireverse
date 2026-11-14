---
title: "Ticket 18e — Release-gate runner"
aliases: [Ticket 18e]
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
  - "[[QASUITE]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[OPERATION]]"
---

# 18e: Release-gate runner

**What to build:** `npm run gate:release` checks a release candidate against every line of QASUITE §16 (release exit criteria) and SECURITY §12 (release security gate), runs every check that exists today, and writes a signed report. It never calls a release releasable while any line is unchecked. This covers the OPERATION §19 line "all release gates green".

**Status:** done on 2026-11-14. Plan: [plans/2026-11-14-slice-18e-release-gate-runner.md](../plans/2026-11-14-slice-18e-release-gate-runner.md).

**Blocked by:** nothing. Design: tri-state runner (Jev 1.0, D-096).

## Acceptance criteria

- [x] **Criteria catalog:** a declarative catalog with one entry per line of QASUITE §16 and SECURITY §12. A test parses both documents and fails if a line has no entry. Each entry is mapped to one of:
  - checks that run;
  - not checkable yet, with the reason and the slice that will add the check.
- [x] **Runnable checks:**
  - **Static and unit:** `npm run verify`, which covers lint, types and all unit, integration and HTTP e2e tests.
  - **Browser:** the Playwright suite.
  - **Matrices:** the audit-coverage, tenant isolation, authorization and privacy subsets, reported as separate criteria.
  - **Resistance:** the RRS gate (slice 13) on the reference Build with the stand-in agent, as a regression check against a recorded baseline. TC-PRV-006 itself is not checkable until a real agent runs (owner, D-097).
  - **Performance budgets:**
    - the Shield bench against PB-01 and PB-02;
    - a short local load smoke of the API against PB-21 (Control API reads and writes), SLO-02 (ingest ack p99) and SLO-01 (attestation p95/p99);
    - other budgets are not checkable, with reasons.
  - **Dependency vulnerabilities:** an npm audit only with an explicit `--online` flag, because it contacts the registry. Without the flag the criterion is not checkable.
- [x] **States:** each criterion is `pass`, `fail` or `not-checkable`, with evidence: command, duration, an excerpt of the output, and the measured numbers.
  - The verdict is `releasable` only when every criterion passes. Otherwise it is `blocked`, and the report lists the reasons.
  - A separate line says whether every checkable criterion passed.
  - The exit code is 0 only for `releasable`. A fail or a not-checkable criterion gives a non-zero exit, with distinct codes.
- [x] **Report:** JSON and Markdown in `reports/gate/<timestamp>/`, gitignored.
  - The JSON carries the git commit, whether the tree is dirty, and the tool versions.
  - It is signed with Ed25519 using a gate key kept outside the repository (path from `AR_GATE_KEY_FILE`; generated on first use beside the user's data, never committed).
  - A `gate:verify-report` command checks a report's signature.
- [x] **Options:** `--only <ids>`, `--skip-slow` (skips are reported as not checked, never as pass), `--online`.
- [x] **Quality:**
  - Unit tests for the catalog, the verdict logic, signing and verification, and the parsing of each check's output.
  - A test with injected check results proves a fail, or one not-checkable criterion, blocks the release.
  - Running the real gate once completes, and its verdict is `blocked`, listing the not-checkable lines.

## Proof

| Criteria | Proven by |
|---|---|
| Catalog covers every line of QASUITE §16 and SECURITY §12; drift fails | `tools/gate/test/catalog.test.ts`, `review.test.ts` (other list markers, a line added to a copied document) |
| Verdict logic, exit codes, options | `verdict.test.ts`, `gate.test.ts`, `cli.test.ts` |
| Checks and parsers (skipped tests, signals, thresholds, bench samples) | `checks.test.ts`, `parsers.test.ts`, `load.test.ts`, `matrix.test.ts`, `run.test.ts`, `review.test.ts` |
| Signing, verification, key outside the repository | `sign.test.ts`, `review.test.ts` |
| Real run | `npm run gate:release` on 2026-11-14: verify 8,191 tests in 313 files pass, Playwright 26/26, all four matrices pass, stand-in RRS 24 ≥ 24, load smoke passes, Shield bench fails PB-01; verdict `blocked`, exit 1; `gate:verify-report` says valid, local key |

**Independent review:** one, reproducing what it reported: 1 HIGH, 5 MEDIUM and 1 LOW, all fixed test-first.
- Skipped and todo tests counted as passing.
- Two checks ignored the exit code and signal.
- Unreadable thresholds were dropped silently.
- Catalog drift went undetected for other list markers and inside the runner.
- `gate:verify-report` accepted any key.
- The key-inside-repository guard could be bypassed.
- A timeout could leave detached processes running.

**Jev:** verified 3 of 3 completion claims on the final run. The worker's earlier gate review escalated (safe_to_apply 0.07) because verify had not yet passed inside the gate; it passes in the final run.

## What the gate found

- **PB-01 breach.** On the 108 KB JSON body scenario the Shield bench measured p50 542 µs against 500 µs and p99 1,716 µs against 1,500 µs. Earlier runs measured 496 µs and 582 µs at p50, so the scenario sits at its limit. The owner decides: Shield work, or an accepted regression on the record.
- **ESM integrity gap.** The stand-in achieves W4 Tamper because Harden's integrity option refuses ESM input. Recorded for a Harden follow-up.
- **13 lines are not checkable yet,** each with its reason and future slice in the report.

## Honest limits

- **The load smoke is optimistic.** It measures client-side round trips against an in-process API on one machine.
- **The bench is sensitive to machine load,** so PB-01 results vary between runs.
- **The port trap** that found the test fetching port 8787 was re-run over the `api` and `console` projects only.
- **`report.md` is unsigned;** only `report.json` carries the signature.
