---
title: "Plan — Slice 18c Retention"
aliases: [Plan 18c]
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
related:
  - "[[SECURITY]]"
  - "[[OPERATION]]"
---

# Slice 18c — Retention Implementation Plan

> Test first. One worker per workspace. Verify by running commands.

**Goal:** the SECURITY §8 defaults hold for the data Airverse keeps, and Event retention is configurable.

**Spec:** [tickets/18c-retention.md](../tickets/18c-retention.md).

## Global constraints

- **Migration 0035:**
  - `organizations.event_retention_days int NOT NULL DEFAULT 30`, with a CHECK that it is one of 7, 30, 90, 180 or 395. The migration sets existing rows to 395.
  - The request role changes the value only through a definer bound to `app.tenant_id`, or through a column grant under RLS, following the existing patterns.
  - Table `retention_runs` (organization_id, ran_at, counts jsonb), under tenant RLS for SELECT only. Keep the 30 newest per Organization. It goes with the Organization's purge, so the catalog test must stay green.
  - Index the events sweep: either `(organization_id, received_at)`, or the existing `events_recent` if the plan uses it.
- **Sweep:** `retention_sweep(at timestamptz, batch int)`.
  - Owner-only security definer with no grant to `ar_app`, as with `organization_purge`.
  - Children first: alert deliveries and detections, then incidents.
  - Each table is bounded by `batch` rows per call. The function returns counts per Organization and per table, and whether anything is left.
  - The job loops calls until nothing is left or `maxCallsPerRun` is reached.
  - **Guard Events:** classify them by the payload field that marks Guard telemetry.
  - **Containment end time:** `coalesce(lifted_at, expires_at)`.
- **Job:**
  - `createRetentionJob({ db, now, logger, everyMs = 86_400_000, firstRunMs, batch, maxCallsPerRun })`, with `runOnce()` and `flush()`.
  - Started in `startApi` beside the purge, and also running the existing artifact expiry.
  - Logs carry counts only.
  - On purge, the job needs nothing in memory.
- **API:**
  - Routes: `GET` and `PUT /v1/organization/retention`, with Protocol schemas.
  - Audit action `organization.retention.update` (before → after). It is sensitive when shortening.
  - The problem code for an invalid value follows existing validation problems.
  - Refused while a deletion is pending, by the existing gate.
- **Catalog test:** `RETENTION_CLASSES` names every table that has `organization_id` as `swept` (rule) or `kept` (reason). The test fails on an unclassified table.
- **Console:**
  - A Retention section on `/settings/data`, using the existing confirm-step patterns from 18b: reason, focus, server action that forwards the reason header.
  - Stub support in `scripts/stub-data.mjs`.
  - Incident evidence gets a one-line note.

## Tasks

1. Protocol: schemas, audit action.
2. API: migration 0035, sweep function, job, routes, catalog test, end-to-end sweep test.
3. Console: Retention section, incident note, Playwright.
4. Review, then docs.

## A1 — As built (2026-11-14)

- **Migration 0035:**
  - The setting, `retention_runs` and `retention_sweep_state`.
  - `setup_milestones`, backfilled from Events.
  - The sweep indexes.
  - `retention_sweep`, `retention_record` and `assessment_artifacts_expire_by_organization`.
  - `subject_erase` redefined to keep Set up's first-done instants.
- **Forks accepted:**
  - An Incident still named by a block waits for that block (Jev 1.0, D-087).
  - One run row per Organization per run, with `complete` (D-087).
  - Guard Event = `payload.attestation.status = 'valid'` (D-087).
  - No new index on `events` (D-087).
  - Set up's first-done instants kept in `setup_milestones`, written by the sweep and by subject erasure (Jev 0.71, D-088).
  - Each sweep call serves a rotating window of Organizations with equal shares, and the Guard and delivery steps have their own budgets (D-088).
- **Console:** the confirm step also renders server-side from the action state, so shortening works without JavaScript.
