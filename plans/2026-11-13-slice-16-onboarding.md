---
title: "Plan — Slice 16 Onboarding"
aliases: [Plan 16]
project: anti-reverse
doc: PLAN
slice: 16
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

# Slice 16 — Onboarding wizard and docs Implementation Plan

> Test first; one worker per workspace; verify by running commands. CLAUDE.md Rule 1: list real forks in the report.

**Goal:** A new team reaches its first protected request in minutes, guided by the Console.

**Spec:** [tickets/16-onboarding.md](../tickets/16-onboarding.md); PRD §8 stories 1–3, G1, FR-CON-03; UIUX SCR-01, §8 components, D-053; QASUITE TC-CON-001.

## Global constraints

- **Setup endpoint:** `GET /v1/apps/:appId/setup?environment=` → `{ setup: { environment, shield: { done_at }, guard: { done_at }, harden: { done_at } } }`; Environment defaults to the App's first; timestamps ISO or null; "Guard done" = the earliest Event whose attestation verdict is genuine (as slice 03 records it); computed with MIN() over indexed columns, under RLS; add an index in a new migration only if a query plan needs one. Protocol schema `AppSetupResponseSchema`.
- **Console route:** `/apps/[appId]/setup`; the step order is fixed; a step done shows its time; the current step opens; the waiting state uses the existing live event stream for Shield and polls the setup endpoint every 5 s otherwise (stops when all done or the tab is hidden).
- **Snippets:** reuse `shield-snippet.ts`, `PolicyKeySnippet`, `Snippet`; add Node `http` (only if Shield's middleware works on a plain `http` server — verify with a test; else omit and say so), Guard (script tag and options as packages/guard documents), Harden (`npx antireverse harden <dir> --out <dir> --register --endpoint … --key-env AR_ADMIN_KEY --app <id> --environment <env> --build-version <v>`).
- **Troubleshooting:** per step, 3–5 causes with how to check (wrong key, Shield not mounted first, policy key missing, Guard origin not allowed, Build not registered).
- **Docs:** Markdown in `docs/`; commands in fenced blocks; a test extracts the shell commands from Getting started and checks each flag exists in the CLI's usage text.

## Tasks

1. Protocol + API: setup schema and endpoint. 2. Console: Set up page, steps, waiting state, App list badge, redirect after creation. 3. Docs. 4. e2e TC-CON-001 (HTTP and browser).

## A1 — API as built (2026-11-13)

`AppSetupResponseSchema`; `GET /v1/apps/:appId/setup` in `routes/apps.ts`, SQL in `stores/setup.ts`; migration 0030 adds a partial index for the first valid attestation. Guard is done at the first Event whose attestation status is `valid`, whatever the verdict (Jev 1.0: a headless test browser gets a suspect verdict with Guard correctly installed). Steps are dated by `received_at` (Shield's own clock is unbounded). The Shield step filters the Environment over `events_recent` (one Shield key per App today; a per-Environment index when keys per Environment arrive). The default Environment is that of the App's earliest Shield key.

## A2 — Console and docs as built (2026-11-13)

Set up page with three steps, a framework picker (Express; Node `http` works through `shield.express()` on a plain server, with routes recorded as `(unmatched)` — Jev 1.0), the live waiting state, "Set up: n of 3" in the Apps list and App nav; after creation the guide shows inline with the one-time key plus a link (no redirect, which would lose the key — Jev 0.81). The docs lane found and the lanes fixed: the Shield install line named an unpublished npm package (now a path install, with a note); `harden` ignored unknown flags (now exit 2); the W5 fix text named attestation enforcement that does not exist; the README was stale; and `npx antireverse` exited 0 without running because the entry check compared the bin's symlink path (fixed with realpath; a CI gate through the bin had passed silently since slice 13). Docs in `docs/` with a test that checks every flag and link.
