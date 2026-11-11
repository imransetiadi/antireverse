---
title: "Ticket 05 — Harden path"
aliases: [Ticket 05]
project: anti-reverse
doc: TICKET
slice: 5
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

# 05: Harden path

**What to build:** A developer runs the Anti Reverse CLI in their own CI over a web bundle they own. On the `balanced` profile it applies behaviour-preserving transforms (identifier mangling, string encryption with lazy decode, an integrity self-check), each build structurally different from the last through a per-build seed. It verifies behaviour by running the bundle's own tests against the protected output, writes a protection report (what changed, size and runtime cost), and registers a Build with its Manifest (artifact hashes, profile, costs) with the API. The Console shows the Build on the App, with its profile, its cost and a pass/fail equivalence result.

**Blocked by:** 01 (done). Independent of 02.

**Status:** done on 2026-11-10 — plan in [plans/2026-11-10-slice-05-harden-path.md](../plans/2026-11-10-slice-05-harden-path.md)

## Acceptance criteria

Protection (local, in the customer's CI)

- [x] `antireverse harden <dir> --profile balanced` reads a built web bundle and writes a protected bundle plus a report; nothing of the source leaves the machine except the Build Manifest the developer chooses to register.
- [x] Transforms on `balanced`: identifier mangling (rename local bindings only, never imports, exports, globals or property keys) and string-literal encryption whose decoded value is bound to a local at its use site so there is no per-access cost. `light` is mangling only. Each sits behind a `Pass` interface so it can be replaced. (A spike on this machine confirmed the engine; its findings shape this scope.)
- [x] The integrity self-check is an opt-in `--integrity` pass, documented as a post-bundle step for already-bundled (non-ESM) code, not part of the default profiles — because its wrapper roughly doubles size and cannot execute ESM. When enabled it detects a later one-byte change to a protected region at run time (proven by a test that patches the output and sees the check fire) and never fires on the untouched bundle.
- [x] Two hardenings of the same source with different seeds differ structurally (name set and string-table order differ); the same seed reproduces the same output byte for byte.
- [x] Behaviour is unchanged: the bundle's own test command is run against the protected output and must pass; a transform that breaks a test fails the harden with a clear message, and the protected bundle is not written.
- [x] Budgets are a gate, never silently exceeded: `balanced` keeps runtime overhead at most 15 % and size overhead at most 35 % on the protected modules (PB-10, PB-11); both are measured and in the report. If a file would exceed a budget, the heavier pass (string encryption) is skipped for that file, the file is reported as mangle-only with the reason, and the harden still succeeds — it never ships a module over budget.
- [x] A protection map can exclude a path from protection; an excluded file is emitted unchanged.
- [x] The CLI prints a short report (modules protected, size delta, run delta, equivalence result) and exits non-zero on any failure; `--json` prints the machine-readable report.

Registration and the Console

- [x] `antireverse harden … --register` uploads a Build Manifest (version, per-artifact SHA-256, profile, transform summary, size and run costs) authenticated with a key; the source and the unprotected bundle are never uploaded.
- [x] The Build appears on the App in the Console with its version, profile, equivalence result, size and run cost, and the transform summary; Builds are listed newest first.
- [x] Builds belong to an Organization: another Organization can neither read nor register a Build for the App.

Safety and integrity

- [x] The harden is deterministic given its inputs and seed; no network call is needed to transform (only `--register` contacts the API).
- [x] No key appears in a log line or in the report; the Manifest contains no source and no secret.

Quality

- [x] The Build list and Build detail use the tokens, vocabulary and states of UIUX.md.
- [x] `npm run verify` passes; an end-to-end test hardens the reference app's bundle, runs its tests against the output, registers the Build and reads it back from the Console's API.

## Proof

| Criteria | Proven by |
|---|---|
| Protection + determinism + budget | `packages/harden/test/engine.test.ts`, `rng.test.ts`, `behaviour.test.ts` (classes, reserved words, eval across 10 seeds), `budget.test.ts` (nothing ships over budget) · `npm run bench` |
| Behaviour unchanged | `equivalence.test.ts`; `tests/e2e/harden.http.test.ts` (the reference bundle's own check passes against the protected output) |
| Integrity opt-in / post-bundle | `integrity.test.ts` |
| Local-first + privacy | `register.test.ts`, `cli.test.ts`; `harden.http.test.ts` "only the Manifest leaves the machine" |
| API register/read + tenancy | `apps/api/test/builds.test.ts`; `harden.http.test.ts`, `harden.e2e.ts` |
| Console Build view | `apps/console/test/builds-*.test.*`; `harden.e2e.ts` |
| Quality | `npm run verify` — 1,668 tests, type-check, lint |

An independent review found F1 (local classes broke at runtime — CRITICAL), F2 (reserved-word identifiers), F3 (could ship over budget), F4 (eval). All four fixed test-first. Completion claims Jev-verified (`jev_verify`): 5 of 6 verified; the compound repo-green claim flagged for review and confirmed directly.

## Responsible use

Harden transforms a bundle the developer supplies from their own project in their own CI. It changes no behaviour (the equivalence gate enforces this), adds no capability to the software, and is the defensive counterpart used by commercial app-shielding and JavaScript-obfuscation tools. It is not for evading security or malware detection, and nothing here hides what the software does from its owner: the developer holds the source, the seed and the report.

## Out of scope — later slices

Leak scan and secret detection (07) · Canaries and Watermark (07) · origin lock and Clone Beacon (10) · control-flow flattening, opaque predicates, dead-code injection (later `balanced`/`maximum` work) · code virtualization (Phase 3) · CI gate on a resistance score (12/13) · federated CI identity for the Manifest signature (later) · mobile and desktop Surfaces (Phase 2/3).
