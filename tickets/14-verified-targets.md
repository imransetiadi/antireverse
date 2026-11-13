---
title: "Ticket 14 — Verified Targets and Rules of Engagement"
aliases: [Ticket 14]
project: anti-reverse
doc: TICKET
slice: 14
version: 0.1.0
status: done
updated: 2026-11-12
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[UIUX]]"
---

# 14: Verified Targets and Rules of Engagement

**What to build:** Before Airverse may ever test a host, the Organization proves it owns it and signs Rules of Engagement that say what may be tested, when and how hard. Ownership is re-checked every day. A single check that every future test must pass refuses anything outside a verified host and a current signed Rules of Engagement.

**Blocked by:** 01 (done). Owner approved starting on 2026-11-12 and chose the ownership methods (D-069).

**Status:** done on 2026-11-13 — plan in [plans/2026-11-12-slice-14-verified-targets.md](../plans/2026-11-12-slice-14-verified-targets.md)

## Acceptance criteria

Verified Targets

- [x] An admin adds a host (a DNS name, never an IP address or a name under localhost, local, internal or similar) and gets a random token and the two ways to prove ownership: a TXT record at `_airverse-challenge.<host>` holding the token, or the token as the content of `https://<host>/.well-known/airverse-verification.txt`.
- [x] "Verify" checks DNS first, then the file. The file fetch only reaches public addresses (every address the name resolves to is checked; no redirects; 5 s timeout; 1 KB cap; HTTPS with a valid certificate). The result and its method are recorded.
- [x] A verified host is re-checked every 24 hours; a failed re-check marks it lapsed (with the reason) and it no longer counts as verified until it passes again.
- [x] Hosts are per Organization; a host verified by one Organization is independent of another's.

Rules of Engagement

- [x] An admin writes Rules of Engagement: scope (verified hosts of the Organization), excluded path prefixes, intensity (passive, safe-active, full), a UTC window (days and hours) and contact emails, and signs them with a typed confirmation. A signed version is immutable; a change is a new version; one version is current.
- [x] Each signed version records who signed (the admin key id), when, and a hash of its content.

Authorization

- [x] `authorize({ host, path, intensity, at })` refuses unless the host is verified now, it is in the current signed Rules of Engagement, the path is not excluded, the intensity is at most the signed one, and the time is inside the window — and says which rule refused. Slice 15 must call it before any traffic.

Console

- [x] Pages to add and verify hosts (with copyable instructions and status), and to write, sign and view Rules of Engagement versions — in the restyled design (D-053).

Quality

- [x] `npm run verify` passes; an end-to-end test verifies a host through a stand-in DNS resolver and through the file method against a local HTTPS server allowed only in tests, signs Rules of Engagement in the Console, and shows `authorize` refusing an unverified host, an excluded path, a stronger intensity and a time outside the window.

## Decisions taken with Jev

- DNS record or well-known file, signed immutable versions, a pure authorization check (Jev 0.51 vs DNS only 0.45; owner chose both methods).

- Review fixes: exclusions folded hard (encodings, case, Unicode, separators, alternate streams); verification limits per host and per Organization; internal names refused; one public failure reason; authorization by the API clock. Full list: plan amendments A1–A4.

## Proof

| Criteria | Proven by |
|---|---|
| Host rules, tokens, Rules of Engagement, authorization | `packages/protocol/test/prove*.test.ts` |
| Guarded fetch, address classifier, verification, re-check | `apps/api/test/prove-*.test.ts` (local TLS server; private, loopback, metadata, mapped and translated addresses refused) |
| Routes, tenancy, immutability, limits | `apps/api/test/prove.test.ts`, `prove-db.test.ts` |
| Console | `apps/console/test/prove-*.test.*`; `tests/e2e/prove-targets.e2e.ts` (add, copy, verify, sign, Check a test in Chromium) |
| Quality | `tests/e2e/prove-targets.http.test.ts` (15) · `npm run test` — 6,765 tests · type checks and lint clean |

An independent review reproduced 2 MEDIUM and 5 LOW findings (path exclusion bypasses, a verify limit reset by delete, an older verify overwriting a newer one, internal name discovery, authorization by the caller's time, an Azure platform address); all fixed test-first. Jev verified 4 of 4 completion claims (the "never reaches a private address" claim at 0.67, backed by the review's classifier and fetcher runs).

## Honest limits

Without user accounts, "signed by an Owner" means signed with the Organization's admin key; who held the key is not known. DNS and the file prove control of the name at check time only; the daily re-check narrows that window.

## Out of scope — later slices

Pentest Campaigns and egress enforcement (15) · step-up authentication and dual approval · IP-range targets · email delivery to contacts.
