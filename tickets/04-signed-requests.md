---
title: "Ticket 04 — Signed requests"
aliases: [Ticket 04]
project: anti-reverse
doc: TICKET
slice: 4
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

# 04: Signed requests

**What to build:** Guard signs each API request with its non-extractable session key — method, path, body hash, a timestamp and a single-use nonce. Shield verifies the signature offline against the session key carried in the Attestation Token, refuses stale and replayed requests, and binds the body through the app's own body parser. An admin marks routes as requiring a signed request (monitor first, then enforce); on those routes a request captured and replayed from a script is rejected.

**Blocked by:** 03 (done).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-04-signed-requests.md](../plans/2026-11-11-slice-04-signed-requests.md)

## Acceptance criteria

Guard

- [x] `guard.sign({ method, url, body })` returns the headers to send (`ar-attestation`, `ar-signature`, `ar-content-sha256`); `guard.fetch(input, init)` signs and sends in one call. Supported bodies: none, string, ArrayBuffer and typed arrays, Blob, URLSearchParams; other bodies are sent with the attestation only and are therefore unsigned. Guard never throws into the page.

Attestation

- [x] The Attestation Token also carries the session public key (`cnf.jwk`); the API refuses a key whose thumbprint does not match `cnf.jkt`.

Shield

- [x] Shield verifies the ECDSA P-256 signature against the token's key over method, request target, body hash, timestamp, nonce and the token id; a timestamp more than 60 s off is stale; a nonce seen before (per Shield instance, for twice the window) is a replay.
- [x] `shield.verifyBody`, passed as the body parser's `verify` hook, checks the received body against the signed hash and refuses a mismatch before the handler runs. Without the hook a request with a body is recorded as "body not checked".
- [x] Every Event records the signature status: valid, missing, invalid, stale, replayed — and whether the body was checked.
- [x] A Rule can require a signed request. On a matching route, a request whose signature is not valid (or whose body was not checked) is recorded under monitor and gets the standard block response under enforce. Promotion to enforce uses the existing confirmations.
- [x] Shield's overhead on a signed request stays within PB-01.

Console

- [x] The Rule form offers "Require a signed request"; the rule list shows it. The live feed and Incident evidence show the signature status beside the client verdict, in the restyled design.

Quality

- [x] `npm run verify` passes; an end-to-end test signs requests from Guard in a real browser, enforces the requirement on a route, and shows that a captured request replayed from a script — and a request with a tampered body — is rejected while the browser's own requests pass.

## Decisions taken with Jev

- Body bound by a signed `ar-content-sha256` header checked through the parser's `verify` hook (0.98).
- Session public key carried in the token; routes opt in through a Rule requirement with monitor/enforce (0.92).
- Requirement rules travel in `signature_rules` so older Shields ignore them; a full nonce store refuses (0.51). Owner: fail closed on internal errors where an enforced requirement applies; close the body bypass with both a signed content type and `bodyVerified: { types }`. Review fixes (0.91). Full list: plan amendments A1–A7.

## Proof

| Criteria | Proven by |
|---|---|
| Guard signing, exact target, content type, never throws | `packages/guard/test/sign.test.ts` (signatures verified by the protocol reference) |
| Canonical string identical everywhere | `packages/protocol/test/signature*.test.ts` (example SHA-256 `37d40ba4…102f6`, recomputed with printf; openssl P1363 known answer); Shield differential tests against the protocol verifier |
| Replay, stale, body binding, requirement rules, monitor unchanged, fail closed, preflight, HEAD | `packages/shield-node/test/signature*.test.ts`, `match.test.ts`, `block.test.ts`; `tests/e2e/signed-requests.http.test.ts` (12 tests) |
| Bundle split and attest key check | `apps/api/test/bundle.test.ts`, `attest.test.ts`, `policies.test.ts` |
| Console | `apps/console/test/signature-chip.test.tsx`, `policy-*.test.*`; `tests/e2e/signed-requests.e2e.ts` (browser request Signed; the captured replay from Node gets 403 and shows Replayed) |
| Quality | `npm run verify` — 4,423 tests, type-check, lint · `npm run e2e` — 12 journeys · `npm run bench` — signed p99 171 µs (PB-01 1.5 ms) |

An independent review found F1 (MEDIUM: a content type the hooked parser skips let a tampered body through), F2 (MEDIUM: HEAD bypassed GET rules), F3 (MEDIUM: an enforced requirement blocked CORS preflights), and LOW F4–F6 (trailing `?`, a 1 s replay edge, a non-standard refusal response) — all fixed test-first. Jev verified 5 of 6 claims; it contradicted "stale and unsigned requests are rejected and every request records its status" (0.8). I disagree: the e2e asserts 403 with `stale` and `missing` statuses and a signature field on every Event; the only nuance is that Shields older than this slice report none ("Not reported").

## Honest limits

Replay protection is per Shield instance: a replay sent to a different instance within the window is not caught until a shared nonce store exists. A script that drives a real browser with Guard signs genuine requests; signing stops replay and tampering, not automation.

## Out of scope — later slices

Shared nonce store (Redis) · policy expressions on verdicts and signals · challenge responses · other frameworks than Express.
