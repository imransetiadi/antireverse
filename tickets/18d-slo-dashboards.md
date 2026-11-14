---
title: "Ticket 18d — SLO measurement, burn alerts and the operator dashboard"
aliases: [Ticket 18d]
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
  - "[[OPERATION]]"
  - "[[QASUITE]]"
---

# 18d: SLO dashboards

**What to build:** An Airverse operator can see, for every SLO that can be measured in this product, how it has done over the rolling 30 days: attainment, the error budget left and the burn rates. The API alerts when the budget burns too fast, and every alert names its runbook. This covers PERFORMANCE §3 and OPERATION §7 (dashboards per SLO, multi-window burn alerting, runbooks) and the GA checklist line "every SLO has a dashboard, an alert and a runbook".

**Out of scope:** the release-gate runner (QASUITE §16 / SECURITY §12) and synthetic probes. Both come in a later slice.

**Status:** done on 2026-11-14. Plan: [plans/2026-11-14-slice-18d-slo-dashboards.md](../plans/2026-11-14-slice-18d-slo-dashboards.md).

**Blocked by:** nothing. Scope chosen by Jev at 0.87, confidence 0.85 (D-092).

## SLOs measured here

| SLO | Indicator, as measured in-process |
|---|---|
| SLO-01 Attestation | `POST /v1/attest` and its challenge: good = not 5xx and server time ≤ 120 ms (p99 bound). Latency p95/p99 are shown. |
| SLO-02 Ingest | `POST /v1/events`: good = acknowledged within 150 ms. |
| SLO-03 Policy distribution | Bundle and key-set fetches: good = served (not 5xx). |
| SLO-04 Event freshness | Received to published on the live bus within 5 s (PB-13). |
| SLO-05 Detection latency | Event received to Detection recorded within 10 s (PB-14). |
| SLO-07 Control API | Other `/v1` routes with an admin key: good = not 5xx, and reads ≤ 200 ms / writes ≤ 500 ms. |
| SLO-09 Alert delivery | Incident created to alert delivered within 60 s (PB-18). |
| SLO-10 Prove | T1 Assessments with a result within 30 min of creation (PB-22). |

4xx responses caused by the client are left out of SLO-01, -02, -03 and -07 entirely: they count as neither good nor bad (D-093).

Not measured here, and stated on the dashboard:
- SLO-06 enforcement propagation needs a probe through a Shield.
- SLO-08 Console page loads needs browser measurement.

## Acceptance criteria

- [x] **SLI recording:** in-process, cheap on the hot path, aggregated into per-minute buckets (good, total, latency histogram) in an operator table with no tenant identifiers. Kept 35 days, swept by the daily job.
- [x] **Per SLO:** objective, 30-day attainment, error budget left, and burn rates over 5 m, 30 m, 1 h, 6 h and 3 d.
- [x] **Burn alerts:**
  - page at 14.4× over 1 h, confirmed over 5 m;
  - page at 6× over 6 h, confirmed over 30 m;
  - ticket at 1× over 3 d.
  - Each alert is logged (counts only) and sent to an optional operator webhook. It names the SLO and its runbook, fires once per episode, and resolves.
- [x] **Runbooks:** every SLO maps to a runbook in OPERATION §9; a test fails if one is missing.
- [x] **Operator access:**
  - `GET /v1/ops/slo` (JSON) and `GET /metrics` (Prometheus text format) take only an operator token from `AR_OPS_TOKEN`, compared in constant time.
  - Without the variable the endpoints answer 404.
  - Admin and Shield keys are refused.
- [x] **Operator dashboard in the Console:**
  - `/ops` signs in with the operator token, in a cookie separate from the tenant session.
  - It shows one panel per SLO: attainment against objective, budget left, burn rates, latency percentiles where defined, alert state and runbook.
  - It is not linked from the tenant navigation.
- [x] **Quality:**
  - `npm run verify` passes.
  - A test drives a known mix of good and bad requests and checks attainment and burn exactly.
  - Playwright covers the ops dashboard.

## Proof

| Criteria | Proven by |
|---|---|
| Catalog, objectives from PERFORMANCE §3, runbooks from OPERATION §9 | `packages/protocol/test/slo.test.ts` |
| Recording, table, sweep, restart, idempotent flush | `apps/api/test/slo-recorder.test.ts`, `slo-server.test.ts` |
| Classification and exact mix of good and bad requests; client time left out | `slo-routes.test.ts` (fails when 5xx are not counted), `slo-client-time.test.ts`, `tests/e2e/slo.http.test.ts` |
| Feeds | `detector.test.ts`, `notifier.test.ts`, `assessment-runner.test.ts` |
| Math and alerts (min events, holding state, persisted state, webhook signature, close) | `slo-evaluate.test.ts`, `slo-service.test.ts` |
| Access | `slo-routes.test.ts`, `slo-server.test.ts` |
| Console | `apps/console/test/ops-*.test.*`, `stub-ops.test.ts` (compared with the real routes), `tests/e2e/ops.e2e.ts` |
| Quality | `npm run verify` (8,077 tests in 302 files, type-check, lint) · Playwright 26/26 |

**Independent reviews:** two, each reproducing what it reported. All findings were fixed test-first.

- **API** (1 HIGH, 4 MEDIUM, 2 LOW):
  - Anonymous slow or aborted uploads were counted as bad events and could page.
  - Sparse SLOs fired again on every bad event.
  - Alert state was lost on restart.
  - Tenant destinations were timed as Control API.
  - Dropped alerts did not show in SLO-09.
  - HEAD requests and keyless routes were misclassified.
  - Shutdown could wait on the webhook.
- **Console** (1 HIGH, 2 MEDIUM, 3 LOW):
  - The e2e spec read stale counts behind the read cache.
  - The at-threshold marker disagreed with the API.
  - "OK" showed beside an overspent budget.
  - Small formatting issues and stub drift.

**Jev:** verified 4 of 4 completion claims. Its review of the change summary escalated (safe_to_apply 0.15, limited by the test gap); it was judged from a summary without the tests.

## Honest limits

- **Per instance.** Measurements are in-process and per API instance.
- **Not measured yet:** SLO-06 (needs a probe through a Shield) and SLO-08 (needs browser measurement). The release-gate runner and synthetic probes are a later slice.
- **SLO-10:** Assessments interrupted at start-up are not counted.
- **SLO-05:** Events dropped before detection are not counted.
- **Alert state:** a crash between saving the alert state and the minute's flush can lose one transition. An empty 3-day window keeps a ticket alert firing until events arrive.
- **Connection failures to alert destinations** are treated as the destination's, so an outage of our own network that looks like a refused connection is not counted.
- **The operator cookie holds the static token for 8 h.** If stolen, it opens `/metrics` until the token is rotated.
