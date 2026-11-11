---
title: "Ticket 02 — Policy path"
aliases: [Ticket 02]
project: anti-reverse
doc: TICKET
slice: 2
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
  - "[[UIUX]]"
---

# 02: Policy path

**What to build:** A person adds a Rule for an App in the Console; the API publishes it as a signed Policy Bundle; Shield fetches the bundle, verifies it and applies it; a request to a matching route is blocked when the Rule is in Enforce mode, or passes and is marked "would have blocked" in Monitor mode; either way the Decision is visible in the live feed.

**Blocked by:** 01 (done).

**Status:** done on 2026-11-10 — plan in [plans/2026-11-10-slice-02-policy-path.md](../plans/2026-11-10-slice-02-policy-path.md)

## Acceptance criteria

Journey

- [x] In the Console a person can add a Rule (path pattern, methods, mode) to an App's Environment, see the Policy's version, and see its history.
- [x] A new Rule starts in Monitor mode; promoting it to Enforce asks for confirmation and names the Environment.
- [x] After publishing, every Shield of that App and Environment applies the Policy within 15 s (PB-16).
- [x] A request matching an Enforce Rule gets the block response and never reaches the application's handler; the live feed shows it as Blocked.
- [x] A request matching a Monitor Rule is served unchanged; the live feed shows it as Blocked with the Monitor mark ("would have blocked").
- [x] Rolling back to an earlier version is one action and takes effect within 15 s.

Safety — the customer's product stays up

- [x] Shield decides locally: no network or disk call on the request path. Fetching and verifying bundles happens in the background.
- [x] A bundle that is tampered with, wrongly signed, expired at load, older than the applied one, or issued for another Shield key is refused; the last valid Policy stays in force and one warning is logged.
- [x] Without a configured policy public key, or before the first valid bundle, Shield observes only.
- [x] When the API is unreachable Shield keeps enforcing the last valid Policy; past `not_after` it reports the Policy as stale and still enforces it.
- [x] Any internal error while deciding lets the request through (fail-open) and is counted.
- [x] A Rule that would block every request cannot be published in Enforce mode.
- [x] Shield still adds p99 ≤ 0.5 ms per request with 50 Rules loaded (PB-02), and its runtime dependency list stays empty.

Security and privacy

- [x] A block Rule cannot be bypassed by letter case, a trailing slash or a query string in the request path.
- [x] Policies belong to an Organization: another Organization can neither read nor publish them; a Shield key receives only the bundle of its own App and Environment.
- [x] The signing key never leaves the API; only the public key is exposed. No key appears in a log line.
- [x] A blocked request's Event carries the Rule's own pattern as the route, never the concrete path; the block response reveals no Rule identifier.

Quality

- [ ] The Policy screen and the Blocked states use the tokens, vocabulary and states of UIUX.md (Monitor is dashed, Enforce is solid; confirmation states the effect). *Partly met: tokens, vocabulary, states and the dashed/solid marks are proven; the confirmation names the Environment and the pattern or version but cannot state the effect in numbers until simulation exists (slice 11).*
- [x] `npm run verify` passes; the HTTP journey and the browser journey cover publish → block → visible → rollback.

## Proof

| Criteria | Proven by |
|---|---|
| Journey | `tests/e2e/policy.e2e.ts` (add, promote with confirmation, Blocked row, rollback, marked row; broad Rule needs the typed Environment) · `tests/e2e/policy.http.test.ts` (applied within 15 s, blocked without running the handler, Monitor marks, rollback) · `apps/console/test/policy-*.test.ts(x)` |
| Safety | `packages/shield-node/test/policy.test.ts`, `verify.test.ts`, `poller.test.ts`, `block.test.ts`, `decide.test.ts` · `npm run bench` (worst p99 7.4 µs with 50 Rules, budget 500 µs) · guardrail and broad-Rule tests in `apps/api/test/policies.test.ts` |
| Security and privacy | `packages/shield-node/test/match.test.ts`, `static.test.ts` (express.static, encoded and dot-segment paths) · `apps/api/test/policies.test.ts`, `bundle.test.ts`, `signer.test.ts` |
| Quality | `npm run verify` — 1,455 tests, type-check, lint · `apps/console/test/t.test.ts`, `policy-components.test.tsx` |

Completion claims verified by Jev (`jev_verify`, 5 of 5 verified) on 2026-11-10.

## Out of scope — later slices

Conditions (`when`: rate, attestation, signals) · actions other than block · percentage rollout · per-route fail-closed · Dynamic Lists · push channel (polling only) · simulation against past traffic (slice 11) · Safe mode switch · audit log · managed key service for signing.
