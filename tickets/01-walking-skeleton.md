---
title: "Ticket 01 — Walking skeleton"
aliases: [Ticket 01]
project: anti-reverse
doc: TICKET
slice: 1
version: 0.1.0
status: done
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# 01: Walking skeleton

**What to build:** A person creates an Organization and an App in the Console, adds Shield to an Express server using the key the Console shows, sends a request to that server, and sees that request appear in the Console's live feed within five seconds — with Shield in Monitor mode, unable to block anything.

**Blocked by:** None (can start immediately).

**Status:** done on 2026-11-10 — plan in [plans/2026-11-10-slice-01-walking-skeleton.md](../plans/2026-11-10-slice-01-walking-skeleton.md)

## Acceptance criteria

Journey

- [x] Creating an Organization returns an admin key that is shown exactly once, and signs the browser in.
- [x] Creating an App returns a Shield key that is shown exactly once, with a copyable set-up snippet.
- [x] A request to an Express server running Shield appears in the Console live feed within 5 s (PB-13) without a page reload.
- [x] The live indicator shows the connection state: Live, Reconnecting.

Safety — the customer's product stays up

- [x] Shield never changes a response: Monitor mode only, and the response is identical when Shield throws internally or the ingest endpoint is unreachable (fail-open).
- [x] Shield makes no network or disk call on the request path; events leave in background batches.
- [x] Shield adds p99 ≤ 0.5 ms per request on a route without attestation (PB-02), measured by a benchmark in the repository.
- [x] Shield's runtime dependency list is empty.

Privacy and tenancy

- [x] An Event carries method, route template, status, latency, a truncated network prefix and the Decision — and no query string, body, header or full address.
- [x] Events belong to the Organization that owns the key that sent them; tenant and App identifiers supplied by a client are ignored.
- [x] A second Organization can neither list nor stream another Organization's Events (cross-tenant test).

Platform hygiene

- [x] Ingest rejects a missing or invalid key (401), an invalid batch (400) and an oversized batch (413) with problem-details responses.
- [x] Keys are stored hashed; no key appears in any log line or error message.
- [x] Re-sending the same batch does not duplicate Events.
- [x] The Console holds the admin key in an httpOnly cookie; no key is readable by page scripts or placed in a URL.

Quality

- [x] The screens added (onboarding, Apps, live feed) use the tokens, vocabulary and states of UIUX.md.
- [x] `npm test` passes from a clean install; one end-to-end test covers the whole journey; the README reproduces it by hand.

## Proof

| Criteria | Proven by |
|---|---|
| Journey | `tests/e2e/journey.e2e.ts` (browser: keys shown once and gone after navigation, snippet, row within 5 s, Live) · `tests/e2e/journey.http.test.ts` · `apps/console/test/live-feed.test.tsx` (Live, Reconnecting, recovery, catch-up) |
| Safety | `packages/shield-node/test/express.test.ts`, `emitter.test.ts`, `shield.test.ts` (empty dependencies, process exit) · `npm run bench` (worst p99 under 20 µs against 500 µs) · `journey.http.test.ts` (ingest unreachable) |
| Privacy and tenancy | `packages/protocol/test/values.test.ts` · `packages/shield-node/test/routes.test.ts`, `mounts.test.ts` · `apps/api/test/ingest.test.ts`, `events.test.ts`, `stream.test.ts`, `db.test.ts` |
| Platform hygiene | `apps/api/test/ingest.test.ts`, `auth.test.ts`, `organizations.test.ts`, `stream-limits.test.ts` · `apps/console/test/session.test.ts` · browser journey (httpOnly cookie, no key in a URL) |
| Quality | `npm run verify` — 558 tests, type-check, lint · `apps/console/test/t.test.ts`, `components.test.tsx` |

Clean install: a copy of the repository without installed packages was installed with `npm ci` and `npm run verify` passed there (558 tests). Not proven by a test: the token values in the stylesheet against UIUX.md §4 — they were checked by eye in a browser.

## Out of scope — later slices

Policy Bundles and Rules (02) · Guard and attestation (03) · signed requests (04) · Harden (05) · Detections and Incidents (06) · user accounts, roles and SSO · sampling and rollups · API rate limiting · ClickHouse and event-log adapters · CI pipeline and deployment.
