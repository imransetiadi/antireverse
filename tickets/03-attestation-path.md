---
title: "Ticket 03 — Attestation path"
aliases: [Ticket 03]
project: anti-reverse
doc: TICKET
slice: 3
version: 0.1.0
status: done
updated: 2026-11-11
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# 03: Attestation path

**What to build:** Guard, a small browser library, completes a challenge with the Attestation service and receives a short-lived Attestation Token. The customer's frontend sends the token with API requests; Shield verifies it offline with keys from the signed Policy Bundle and records a verdict on every request's Event. The Console shows the verdict per request. This slice observes only: nothing is blocked on a verdict yet.

**Blocked by:** 01 (done).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-03-attestation-path.md](../plans/2026-11-11-slice-03-attestation-path.md)

## Acceptance criteria

Guard (browser)

- [x] `@antireverse/guard` runs in browsers without a build step, has no runtime dependency, stays under 35 KB gzip (PB-05), never blocks rendering and never throws into the page.
- [x] `init({ appId, endpoint })` then `attest()` obtains a token; Guard re-attests before expiry; `headers()` returns the header to send.
- [x] Signals v1: automation (webdriver, headless markers) and environment inconsistency. A random first-party device identifier is kept in local storage; no personal data is collected. A non-extractable session key is created and bound to the token by its thumbprint (request signing comes in slice 04).

Attestation service (API)

- [x] `POST /v1/attest/challenge` issues a single-use nonce valid for 60 s; `POST /v1/attest` checks it and returns an Ed25519-signed token (TTL 5 min) carrying the App, a pseudonymous device id, the verdict, a risk score, the signal ids and the session key thumbprint. Both are public, allow cross-origin calls without credentials, are rate-limited, and keep only the caller's network prefix.
- [x] Attestation keys are separate from policy keys and rotate daily; the next key is published at least an hour before it signs anything, so every Shield already holds it.

Shield

- [x] Shield reads the token from the `ar-attestation` header and verifies it offline (signature, key id, audience, issuer, expiry with small skew, lifetime ≤ 5 min), caching verified tokens until they expire; overhead stays within PB-01.
- [x] Every Event records the attestation status (valid, missing, invalid, expired) and, when valid, the verdict and risk. Nothing is blocked on it.

Console

- [x] The live feed and Incident evidence show the verdict per request as word + icon + colour: Trusted, Suspect, Hostile, No token, Invalid, Expired — in the restyled design (D-053).

Quality

- [x] `npm run verify` passes; an end-to-end test loads a page with Guard in a real browser, attests, calls the reference API through Shield with the token, and sees the request's verdict in the Console; a forged, expired or other-App token is recorded as invalid or expired.

## Decisions taken with Jev

- Observe-only scope; session key bound now, request signing in slice 04 (0.99).
- Guard written as plain JavaScript modules with type annotations — browser-ready, no new dependency (0.9).
- Key rollover with a pre-published next key, endpoints, token claims, verdict table, Shield verification and Console chips as in the plan (0.76).
- Shield checks each bundle key id against its key (0.55); 10 s Guard request timeout and the lockfile entry (0.56); token cache keyed by token hash (0.96); review fixes (0.73). Full list: plan amendments A1–A7.

## Proof

| Criteria | Proven by |
|---|---|
| Guard: browser-ready, no dependency, never throws, 7.2 KB gzip | `packages/guard/test/*` (114 tests incl. hostile options, timeouts, non-extractable key); `tests/e2e/attestation.e2e.ts` (loaded straight from source in Chromium) |
| Attestation service: nonces, limits, CORS, claims, key rollover | `apps/api/test/attest.test.ts`, `attestation-keys.test.ts`; `tests/e2e/attestation.http.test.ts` |
| Shield verification, cache, Event field, response unchanged | `packages/shield-node/test/attestation*.test.ts` (differential test against the protocol verifier); `attestation.http.test.ts` (valid, missing, forged, foreign key, other App, expired) · bench attested p99 69 µs (PB-01 1.5 ms) |
| Console verdict per request | `apps/console/test/attestation-chip.test.tsx`, `live-feed.test.tsx`; `attestation.e2e.ts` (Chromium earns Hostile, risk 100; a request without a token shows No token) |
| Quality | `npm run verify` — 4,029 tests, type-check, lint · `npm run e2e` — 11 journeys · `npm run bench` |

An independent review found F1 (MEDIUM: made-up App ids could reset a real App's limit window) and F2–F5 (LOW: two processes on one key file, a never-served key signing after downtime, a failed key write retried on every use, `createGuard` throwing on hostile options) — all fixed test-first. Shield's verifier and the protocol's agreed on 1,332 crafted tokens. Jev verified 6 of 6 claims; the limit claim came back for review (0.73) and was confirmed from the test output.

## Honest limits

A token shows that a Guard-like client completed the handshake recently — not that the client is genuine. Anyone can script the handshake with clean signals. Challenge programs, Harden-protected Guard and request signing (slice 04) raise that cost; Shield decides, Guard only reports (D-005). When the per-address limit table is full of active windows, new callers get 429 for up to a minute. Behind a reverse proxy the API sees one address for everyone (no trusted-proxy option yet).

## Out of scope — later slices

Request signing and replay protection (04) · rules that act on the verdict (policy expressions) · challenge programs · Guard self-protection by Harden · remote config and kill switch · integrity and hooking signals · Shield grace period.
