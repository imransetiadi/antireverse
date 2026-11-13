---
title: "Ticket 16 — Onboarding wizard and docs reaching G1"
aliases: [Ticket 16]
project: anti-reverse
doc: TICKET
slice: 16
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

# 16: Onboarding wizard and docs reaching G1

**What to build:** A guided set-up per App that ends with the first protected request on screen (PRD stories 2 and 3, FR-CON-03, UIUX SCR-01), and docs a developer can follow without reading protocol documents — so that signup to first protected request takes at most 15 minutes (G1, TC-CON-001).

**Blocked by:** 02, 03, 05 (done). Jev: a setup endpoint (0.89); Express and plain Node `http`, other frameworks named as not supported yet (0.87).

**Status:** done on 2026-11-13 — plan in [plans/2026-11-13-slice-16-onboarding.md](../plans/2026-11-13-slice-16-onboarding.md)

## Acceptance criteria

- [x] `GET /v1/apps/:appId/setup?environment=<env>` returns, per step, when it was first done: Shield (first Event), Guard (first Event with a genuine Guard attestation), Harden (first registered Build) — `null` while not done. Admin key only; tenant-isolated; cheap (indexed).
- [x] The App's **Set up** page shows the three steps in order with the current one open: a framework picker (Express; plain Node `http`; others listed as not supported yet, never a fake snippet), copyable snippets with the App's real values (API URL, Environment, policy public key; the Shield key only right after creation, otherwise how to find it), Guard's script tag and settings, and the Harden command with `--register`. A live "Waiting for the first event from <App>…" state turns into "First protected request received" without a reload; a "Having trouble?" panel lists the common causes per step.
- [x] Creating an App shows the set-up guide inline, beside the one-time Shield key, with a link to the App's Set up page (a redirect would lose the key — Jev 0.81); the Apps list and App pages show "Set up: n of 3" until done.
- [x] Docs in `docs/`: Getting started (signup to first protected request), Shield, Guard, Harden and CI gate, Reverse Assessment — each with copyable commands; a test checks every flag and link and runs the commands that work offline.
- [x] In the restyled design (D-053), accessible (keyboard, focus, labels, live region for the waiting state).
- [x] `npm run verify` passes; an end-to-end test (TC-CON-001) scripts signup → App → Shield on the reference server → first protected request on screen and records the elapsed time (budget 15 minutes; expected seconds), then the Guard and Harden steps turn done.

## Proof

| Criteria | Proven by |
|---|---|
| Setup endpoint | `apps/api/test/setup.test.ts` (steps, Environments, tenancy, keys, query plans); `tests/e2e/onboarding.http.test.ts` (real Shield, attestation and Harden) |
| Set up page, waiting state, n of 3 | `apps/console/test/setup-*.test.*`, `shield-plain-http.test.ts` |
| Docs | `tests/e2e/docs.test.ts` (every flag and link; the offline commands run) |
| TC-CON-001 | `tests/e2e/onboarding.e2e.ts` — signup to first protected request on screen in 1.9 s (budget 15 min), then Guard and Harden done |
| Quality | `npm run verify` — 7,504 tests, type-check, lint · Playwright 21/21 |

The docs lane found an unpublished npm install line, ignored unknown Harden flags, a W5 fix text naming a non-existent enforcement, a stale README, and `npx antireverse` exiting 0 without running (a silent CI pass since slice 13) — all fixed test-first. The independent review reproduced focus loss when a step completes, a Build version taken from Airverse's commit, a hard-coded Environment and an untokened Guard example; all fixed. Jev verified the completion claims.

## Out of scope

User accounts, invitations, roles, SSO (stories 4–6) · a per-App RRS threshold · adapters for other frameworks.
