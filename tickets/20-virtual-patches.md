---
title: "Ticket 20 — Exposure: virtual patches"
aliases: [Ticket 20]
project: anti-reverse
doc: TICKET
slice: 20
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

# 20: Exposure — virtual patches

**What to build:** For a known vulnerability with a request-level exploit, Shield recognises the exploit request and records it — or, once an admin enforces the patch, refuses it — but only in an App and Environment that actually runs the vulnerable version. Patches come from a small catalog that Anti Reverse maintains; they start in monitor, an admin promotes them to enforce, and they drop out when the Finding is fixed or withdrawn.

**Blocked by:** 19 (done) and 02 (done). Owner approved the design on 2026-11-11 (D-061).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-20-virtual-patches.md](../plans/2026-11-11-slice-20-virtual-patches.md)

## Acceptance criteria

Catalog

- [x] A versioned patch catalog in the API. Each patch names the advisories it covers (CVE or GHSA ids checked against OSV when written, pinned by a test), the package, its conditions, one exploit request that must match and one benign request that must not. The first catalog covers 3–5 well-known npm advisories with a request-level exploit. Tests use a fixture catalog.

Matching (Shield)

- [x] Conditions on method, path, query keys and values, header names and values and the raw body; operators equals, contains, starts with, ends with, longer than, present; at most 8 per patch, all must hold; no regular expressions. The body is checked only through `shield.verifyBody`; a patch whose body condition could not be checked is recorded as "body not checked" and never blocks.
- [x] A match records the patch on the Event. Under monitor the response is unchanged; under enforce the request gets the standard block response before the handler. Overhead stays within PB-01.

Activation (API)

- [x] A patch is shipped, in monitor, in the signed bundle of every App and Environment with an open or ignored Finding for one of its advisories, and removed when none remains. Older Shields ignore it.
- [x] An admin promotes a patch to enforce per App and Environment with the usual confirmation and switches it back in one action.
- [x] The first match opens a High "Exploit attempt" Incident grouped per App, Environment and advisory, with alerts.

Console

- [x] The Finding page shows whether a patch is available, its mode, its hits and the promote/return actions; the App's Policy page lists active patches — in the restyled design (D-053).

Quality

- [x] `npm run verify` passes; an end-to-end test registers a Build with a vulnerable fixture package, sees the patch in monitor (exploit request recorded, response unchanged), promotes it, sees the exploit request refused while a benign request passes, sees the Incident and alert, upgrades the package and sees the patch removed.

## Decisions taken with Jev

- Slice 20 next (1.0). Curated catalog with verified advisory ids and reference requests (0.98). Declarative conditions without regular expressions (0.66). Automatic monitor, manual enforce, optional bundle member, Exploit attempt Incident (0.92).

- After two reviews: conditions matched as the real parsers read the request (qs key split, charsets, JSON escapes), `json_key`, an `undecodable` state, D-062 (owner). Full list: plan amendments A1–A12.

## Proof

| Criteria | Proven by |
|---|---|
| Catalog (9 patches, 4 advisories checked against OSV) | `apps/api/test/patch-catalog.test.ts` (ids, ranges, every exploit matches, every benign request does not) |
| Matching | `packages/protocol/test/patches.test.ts`; `packages/shield-node/test/patches*.test.ts` (differential against the protocol; Express: monitor unchanged, enforce 403, fail open) · bench 108 KB body p99 about 1 ms |
| Activation, modes, Incidents | `apps/api/test/patches.test.ts`; `tests/e2e/exposure-patches.http.test.ts` (7), `exposure-patches-qs.http.test.ts` (real qs patch, 2) |
| Console | `apps/console/test/patches-*.test.*`; `tests/e2e/exposure-patches.e2e.ts` (Enforce with typed confirmation, Back to monitor, in Chromium) |
| Quality | `npm run verify` — 5,273 tests, type-check, lint · `npm run e2e` — 14 journeys · `npm run bench` — worst attested p99 927 µs (PB-01 1,500 µs) |

Two independent reviews reproduced 2 HIGH + 6 further findings, then 4 HIGH evasions + 3 MEDIUM + 3 LOW (charsets, qs notations, false alerts and false positives); all fixed test-first except the documented limits. Jev verified 6 of 6 completion claims.

## Honest limits

A patch stops the known shape of an exploit, not every variant; upgrading is the fix. Only Express with Shield. Body conditions need `shield.verifyBody` on the route's parser. Not caught: a deeper path segment (`a.__proto__.x`), a top-level `__proto__[x]` form key, apps that turn on qs `allowDots`, a query past 16,384 characters on servers that raise Node's header limit. May match ordinary traffic once enforced: two unrelated keys named `constructor` and `prototype`, or `<__proto__` inside text — run in monitor first and read the hits.

## Out of scope — later slices

Customer-written patches · other frameworks · automatic catalog updates · response-side patches.
