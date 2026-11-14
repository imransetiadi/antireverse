---
title: "Plan — Slice 18d SLO dashboards"
aliases: [Plan 18d]
project: anti-reverse
doc: PLAN
slice: 18
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - plan
---

# Slice 18d — SLO dashboards Implementation Plan

> Test first. One worker per workspace. Verify by running commands.

**Spec:** [tickets/18d-slo-dashboards.md](../tickets/18d-slo-dashboards.md).

## Global constraints

- **Protocol** (`packages/protocol/src/slo.ts`):
  - SLO definitions: id, name, objective, target ms where defined, runbook id, and measured true/false.
  - Burn windows and thresholds.
  - Response schemas.
- **Recording** (`apps/api/src/slo/`):
  - The recorder lives in memory: per SLO and per minute, it holds good and total counts plus a fixed-bucket latency histogram.
  - It is flushed every minute to the owner-only table `slo_minutes` (minute, slo, good, total, histogram).
  - It is fed from:
    - Hono middleware: route class from the route template, status, ms.
    - The bus publish (freshness).
    - The detector (detection latency).
    - The notifier (delivery latency).
    - The Assessment end (Prove).
  - Nothing tenant-specific is stored.
  - `slo_minutes` is classified in the global tables for the 18b/18c catalog tests, and sweeps after 35 days run in the existing retention job or in its own job.
- **Evaluation:**
  - A pure function from buckets to attainment, budget and burn per window, with a test on synthetic buckets.
  - An alert state machine (firing/resolved per rule) evaluated every minute.
  - It sends to `AR_OPS_WEBHOOK_URL` if set, reusing the webhook sender and signing, and logs counts only.
- **Access:**
  - Operator auth middleware for `AR_OPS_TOKEN`: at least 32 characters, compared with `timingSafeEqual` on hashes. Unset means 404.
  - The routes are `GET /v1/ops/slo` and `GET /metrics`.
  - Tenant keys are refused.
  - These routes are not counted in SLO-07, and not audited as tenant actions.
- **Console:**
  - `/ops/sign-in` (operator token) and `/ops` (dashboard).
  - A separate cookie, httpOnly, SameSite=Strict, scoped to the `/ops` path.
  - A server-side fetch with the token.
  - The restyled design and the dataviz conventions used in 17a.
  - Stub support.

## A1 — As built (2026-11-14)

- **Migration 0037:** `slo_minutes`, plus `slo_alerts` (firing states that survive restarts) and `slo_flushes` (idempotent flushes).
- **Sweep:** the SLO job runs its own sweep every minute.
- **Alerts:** need at least 3 events in the long window (Jev 0.94). An empty window keeps the current state, and an alert resolves only on evidence.
- **Reads:** cached for 15 s.
- **Classification (D-093, D-094):**
  - Left out: client 4xx, slow or aborted uploads (a failed body read now answers 400), keyless routes, and routes that wait on a tenant-chosen destination.
  - SLO-09 counts our own drops as bad and leaves out failures of the destination.
- **Console (D-095):** the `ar_ops` cookie, the `/ops/expired` route handler, and an "Objective missed" state. The threshold tolerance is shared through the protocol (`atThreshold`).
