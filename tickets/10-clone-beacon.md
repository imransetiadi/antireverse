---
title: "Ticket 10 — Clone Beacon"
aliases: [Ticket 10]
project: anti-reverse
doc: TICKET
slice: 10
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

# 10: Clone Beacon

**What to build:** A developer tells Harden which origins their frontend is served from. Harden plants a small Clone Beacon in the protected bundle. When a copy of that bundle runs on any other origin — a phishing clone or a mirror — the beacon reports the origin, and Anti Reverse opens a High "Clone detected" Incident naming the origin and the Build, and alerts the Organization's channels. Real visitors on an allowed origin cause no request to Anti Reverse.

**Blocked by:** 05 (done) and 06 (done).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-10-clone-beacon.md](../plans/2026-11-11-slice-10-clone-beacon.md)

## Acceptance criteria

Harden (opt-in, local-first)

- [x] `antireverse harden … --origin https://shop.example.com [--origin …] --register` plants a Clone Beacon; without `--origin` no beacon is planted. `--origin` without `--register` is a usage error (a beacon nobody watches is pointless). Origins are canonical `scheme://host[:port]` (http or https), at most 20.
- [x] The beacon runs once when the bundle loads in a browser: on an allowed origin, or on a local development origin (localhost, loopback, private addresses, `.local`, `.test`, `file:`), it does nothing; elsewhere it sends one small report (`navigator.sendBeacon`, no CORS preflight). It never throws, and outside a browser it is a no-op, so the equivalence check still passes.
- [x] The beacon token is derived like Canaries (seed, App, version), so output stays reproducible and no network call is needed to transform. The Manifest records the allowed origins and the token; the report shows "Clone Beacon: on (N origins)".

API

- [x] `POST /v1/beacon` is public, takes a body of at most 1 KB, and always answers 204 — it never reveals whether a token is valid.
- [x] A report counts only when the token belongs to a registered Build, the origin is canonical, not local and not one of that Build's allowed origins, and the request's `Origin` header equals it. Only the reporter's network prefix is kept, never its full address.
- [x] Abuse is bounded: at most 20 new origins and 600 reports per Build per hour; one Detection per Build and origin per hour; the excess is dropped and counted.
- [x] A counted report opens (or joins) a **High "Clone detected"** Incident for the App, Environment and origin, naming the Build, within 60 s; it alerts through the existing channels.

Console

- [x] A Build shows its Clone Beacon (on/off and the allowed origins). A "Clone detected" Incident shows the origin and links to the Build; containment does not apply to it and the page says so.

Quality

- [x] `npm run verify` passes; an end-to-end test hardens the reference bundle with an allowed origin, loads it in a real browser from the allowed origin (no report) and from a clone origin (Incident and signed alert), and forged reports cannot exceed the limits.

## Decisions

- Report only on a mismatch with the origins embedded at harden time; allowed origins come only from `--origin` (owner's decision 2026-11-11; Jev 0.65).
- Clone Beacon only; an origin lock that stops the app is deferred to a later opt-in (Jev 0.86).
- Public endpoint protections and the Incident rule as written above (Jev 0.83).
- Enlarge the reference app so it carries Canaries and the beacon (owner's decision 2026-11-11; Jev 0.56). Review fixes (Jev 0.94), App-scoped tokens and reports, trailing-dot grouping (1.0), beacon guards kept (0.94). Full list: plan amendments A1–A8.

## Proof

| Criteria | Proven by |
|---|---|
| Harden flags, planting, token, Manifest, inert outside a browser | `packages/harden/test/beacon.test.ts` (vm contexts; client local check pinned against the protocol over ~12,000 origins), `cli-beacon.test.ts`; `packages/protocol/test/beacon.test.ts`, `derive.test.ts` (token known answers checked independently) |
| Endpoint always 204, validation, limits, flood protection, tenancy, privacy | `apps/api/test/beacon.test.ts`; `tests/e2e/clone-beacon.http.test.ts` (identical responses across 13 cases; 30 forged origins → 20 Incidents; another Organization sees nothing) |
| Clone Incident and alert | `beacon.test.ts`; `clone-beacon.http.test.ts` (one High Incident naming origin and Build; one signed alert without the token) |
| Real browser: allowed origin silent, clone reports | `tests/e2e/clone-beacon.e2e.ts` (Chromium mapping `shop.example` and `clone.example` to the same server; zero reports from the allowed name, one from the clone; Incident in the Console in 44 ms) |
| Console | `apps/console/test/clone-beacon-components.test.tsx`; `clone-beacon.e2e.ts` (origin as plain text, Build link, no containment) |
| Quality | `npm run verify` — 3,598 tests, type-check, lint · `npm run e2e` — 10 journeys (run at 23:16 UTC) · `npm run bench` — worst p99 16.17 µs |

An independent review found F1 (MEDIUM: an anonymous flood of made-up tokens could make every tenant's reports drop), F2 (MEDIUM: the owner's own site opened with a trailing dot reported itself), F3 (MEDIUM: forgery scaled with the number of Builds), F4 (LOW: another Organization could register a victim's token first), F5 (LOW: a failed registration left a written bundle) and F6 (LOW: an endpoint containing `</script>` could break out). All fixed test-first. Jev verified the completion claims: 6 of 7 at 0.88–0.98; the whole-repository claim came back for review and was confirmed directly from the command output.

## Out of scope — later slices

Origin lock · Console-managed allowed origins · takedown workflow · Watermark and *Identify build* · Guard-attested reports · mobile and desktop clones.
