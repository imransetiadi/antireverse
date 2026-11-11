---
title: "Ticket 07 — Leak scan and Canaries"
aliases: [Ticket 07]
project: anti-reverse
doc: TICKET
slice: 7
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

# 07: Leak scan and Canaries

**What to build:** Harden scans a developer's bundle for leaks before protecting it and fails the build on a source map, a secret, or an internal URL that is about to ship. It also plants Canaries — decoy keys and decoy routes unique to the Build — and registers them with the Build. Shield on the customer's API recognises a Canary when an attacker uses one, and the detector opens a High Incident that names the Canary and the Build it came from.

**Blocked by:** 05 (done) and 06 (done).

**Status:** done on 2026-11-11 — plan in [plans/2026-11-11-slice-07-leak-scan-and-canaries.md](../plans/2026-11-11-slice-07-leak-scan-and-canaries.md)

## Acceptance criteria

Leak scan (local, in the customer's CI)

- [x] `antireverse harden` scans every input file before any transform, plus the bundle's file set, and fails (non-zero exit, nothing written, nothing registered) on: a source map (`.map` file or `sourceMappingURL` comment), a private key block, a known secret-key format, a high-entropy value assigned to a secret-like name, or an internal URL (loopback, private address, `.internal` / `.local` / `.corp` host).
- [x] A secret present in the input is caught even though string encryption would hide it in the output.
- [x] Findings show the rule, the file and line, a masked value and a fingerprint (SHA-256 of rule, path and value) — never the value. Nothing about a finding is uploaded.
- [x] A committed allowlist file of fingerprints (each with a reason) suppresses a reviewed false positive; the report counts suppressed findings.

Canaries

- [x] Each harden plants Canaries unique to the Build: at least one decoy key and two decoy routes, as plain-text strings the leak scan never reports. Values derive from the build seed (and, when registering, the App and build version — plan amendment A10), so the same inputs still reproduce the output byte for byte; no network call is needed to transform.
- [x] Decoy keys look like the customer's own API key and never imitate a third-party provider's format.
- [x] Planting changes no behaviour (the equivalence check still passes) and stays inside the size budget.
- [x] `--register` sends the Canaries with the Build Manifest; without it the report warns that the Canaries are not watched.

Detection

- [x] Shield receives the active Canaries of its App and Environment in the signed Policy Bundle within 15 s of registration.
- [x] A request carrying a decoy key (Authorization bearer, `x-api-key` header or `api_key` query parameter) or requesting a decoy route is recorded with a `canary.touched` signal naming the Canary; the key value never leaves the customer's server. Shield only observes: it does not change the response.
- [x] One such request opens a **High** "Canary used" Incident within 60 s (PB-17) that names the Canary and its Build, and alerts through the slice-06 channels. Repeated use while the Incident is open joins it.
- [x] Shield's overhead stays within budget with Canaries loaded.

Console

- [x] A Build shows its leak-scan result and its Canaries (kind, id, planted count); an Incident from a Canary links to its Build.

Quality

- [x] `npm run verify` passes; an end-to-end test fails a harden on a planted test secret, passes it once allowlisted, registers the Build, sends a request with the decoy key through Shield on the reference app, and sees the Canary Incident and its signed alert.

## Decisions taken with Jev

- Canary values derived locally from the build seed and registered with the Manifest (1.0).
- Shield matches Canaries from the signed bundle; the detector raises the Incident (0.99).
- Decoy keys look like the customer's own key, never a provider's format (1.0).
- Leak scan of the input and the file set; suppressions through a committed fingerprint allowlist (0.99).
- Seed normalised to uint32 (0.96); Build responses show Canaries as id and kind only (1.0); route Canaries match in any case (1.0); Canaries scoped to App and version when registering (0.88); fix all review findings, non-UTF-8 files scanned as Latin-1 (0.84). Full list: plan amendments A1–A11.

## Proof

| Criteria | Proven by |
|---|---|
| Leak scan rules, masking, fingerprints, allowlist, exit 3 | `packages/harden/test/leaks.test.ts`, `cli-leaks.test.ts`; `tests/e2e/canaries.http.test.ts` (real CLI: AWS example key → exit 3, only `AKIA…` shown, nothing written or registered; allowlisted → suppressed 1) |
| Secret hidden by string encryption still caught; non-UTF-8 and unquoted config files | `leaks.test.ts` (scan runs on the input; Latin-1; `.env`/YAML; TypeScript annotations) |
| Canaries: derivation, planting, determinism, behaviour, budget, never in a declaration file | `packages/protocol/test/derive.test.ts` (v1 and v2 known answers, checked independently), `packages/harden/test/canaries.test.ts`, `cli.test.ts` (50 seeds) |
| Registration, bundle, propagation ≤ 15 s, no values in responses | `apps/api/test/canaries.test.ts`; `canaries.http.test.ts` (Shield received them in 4.5–5.2 s; Build responses `{id, kind}` only) |
| Shield matching, response unchanged, value never sent, replay refused | `packages/shield-node/test/canary.test.ts`; `canaries.http.test.ts` (Shield vs control range identical; stored Events carry only the id) · bench worst p99 10.67 µs with 100 Canaries |
| High "Canary used" Incident ≤ 60 s naming the Build, signed alert | `apps/api/test/canaries.test.ts`, `detection-server.test.ts`; `canaries.http.test.ts` (~0.2 s; alert verified) |
| Console | `apps/console/test/builds-*.test.*`, `incidents-components.test.tsx`; `tests/e2e/canaries.e2e.ts` |
| Quality | `npm run verify` — 2,402 tests, type-check, lint · `npm run e2e` — 7 journeys · `npm run bench` |

An independent review reproduced M1 (TypeScript-annotated secrets missed), M2 (unquoted `.env`/YAML values missed), M3 (a pinned seed allowed only one Build per Organization), M4 (a non-UTF-8 file was skipped yet reported clean) and LOW L1–L5; all fixed test-first except L5, recorded as an amendment (planting falls through to the next file). Jev verified all 8 completion claims (0.94–1.0, auto).

## Out of scope — later slices

Watermark and *Identify build* · origin lock and Clone Beacon (10) · client-side Canary reads by Guard · blocking on Canary use (Containment, 09) · scanning vendor code for sensitivity · fetching allocations from the control plane · Canary retirement UI.
