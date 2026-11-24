---
title: "Plan — Slice 23 installable SDK packages and their supply chain"
aliases: [Plan 23]
project: anti-reverse
doc: PLAN
slice: 23
version: 0.1.0
status: done
updated: 2026-11-24
language: en
tags:
  - anti-reverse
  - plan
---

# Slice 23 — Installable SDK packages and their supply chain Implementation Plan

> Test first. One worker. Verify by running commands.

**Spec:** [tickets/23-sdk-packages-supply-chain.md](../tickets/23-sdk-packages-supply-chain.md).

## Global constraints

- Nothing is published. No `npm publish` (not even `--dry-run`), `npm link`, `npm login`, `npm adduser` or `npm config set`. The packed manifests keep `"private": true`.
- The source `package.json` files of the four packages are not changed: workspace development keeps importing TypeScript source.
- No runtime behaviour of a package changes. No npm dependency is added: `tsc`, `npm pack` and Node built-ins only.
- Lesson L-009: every delete goes through one function that takes an explicit path, accepts only the repository's own build folders or a folder under the operating system's temporary directory made for the purpose, and refuses a folder that is not empty and does not carry the build marker. Tests inject temporary folders for every output; no test writes into the repository.
- Every npm child process runs with a temporary cache and empty user and global configuration files; the user's npm cache and configuration are never read or written. Install scripts are disabled.
- The signing key is the gate's (`tools/gate/src/sign.ts`): outside the repository, never printed. Tests use a key file in their own temporary folder.
- Tests run in process or on a port the operating system picks; never 8787 or 3000. No request leaves the machine.
- `sec12-sdk-artifacts` stays not checkable. The new checks are a criterion of the gate's own.
- `apps/console/tsconfig.json` is not touched; no `next typegen`. `MEMORY.md` and `brand/` are not touched.

## Tasks

Each task: the test first, seen failing, then the code — except where the ticket's "Not test-first" says otherwise.

1. **Workspace `tools/sdk`** — `package.json`, `tsconfig.json`, the `sdk` Vitest project, the root `tsconfig.json` reference, `dist/` in `.gitignore`, the lockfile entry.
2. **Safe delete** (`src/safe.ts`, `test/safe.test.ts`) — `cleanBuildDir(target, layout)`: absolute, normalised, one of the layout's own folders, not a symbolic link, empty or marked; everything else refused by name.
3. **Build** (`src/packages.ts`, `src/build.ts`, `packages/*/tsconfig.build.json`, `test/build.test.ts`) — `tsc` per package into a given folder; relative `.ts` specifiers in declarations rewritten to `.js`; declarations not reachable from a public entry removed; Guard copied. Tests: file sets, no `.ts` specifier, no `@antireverse/` in Shield, the source manifests unchanged and still pointing at `src`.
4. **Stage and pack** (`src/stage.ts`, `src/pack.ts`, `test/reproducible.test.ts`) — generated manifest, `dist/`, `LICENSE`, `NOTICE`, `README.md`; modes normalised; one isolated `npm pack`. Test: two clean builds in two folders, the second with changed modes and times, give byte-identical tarballs; one version for all four.
5. **Closure, SBOM, allowlist** (`src/closure.ts`, `src/sbom.ts`, `src/allowlist.ts`, `allowlist.json`, `test/sbom-allowlist.test.ts`) — the packed runtime closure from the lockfile; CycloneDX 1.5 JSON without time or random parts; the allowlist by name and version, install scripts, zero dependencies for Shield and Guard.
6. **Manifest, signature, verify** (`src/manifest.ts`, `src/cli.ts`, `test/manifest.test.ts`) — `sdk-manifest.json` signed through the gate's `signReport`; `verifyArtifacts(dir)`; the trust rule of `gate:verify-report`; the commands `sdk:build`, `sdk:pack`, `sdk:verify`, `sdk:allowlist`.
7. **Install smoke test** (`src/registry.ts`, `test/install-smoke.test.ts`) — a loopback registry from the repository's `node_modules`, a real `npm install` of the four tarballs in a temporary project, then plain Node: Shield, the `antireverse` bin, a Harden run, Guard, a type check of a consumer, and what must not be in the installed tree.
8. **Behaviour equivalence** (`src/dist-plugin.ts`, `vitest.dist.config.ts`, `test/equivalence.test.ts`) — the three suites again on the compiled output, redirected at resolve time, with a load guard; compared test by test with a run on the source.
9. **Gate** (`tools/gate/src/{matrix,catalog,checks}.ts` and tests) — five fixed-file checks, the criterion `gate-sdk-artifacts-local`, the sharper gap of `sec12-sdk-artifacts`.
10. **Skill** (`skills/airverse-setup`, its drift test) — `--tarballs` in the preflight (read-only check of the manifest), the skill text, the test cases.
11. **Documents** — README, `docs/*.md`, SECURITY (one as-built paragraph), PRD slice table, the ticket's As built and Proof.

## Verification

- New and affected tests; the `protocol`, `shield-node`, `guard`, `harden`, `api`, `range`, `gate`, `e2e` and `sdk` Vitest projects.
- `npx tsc -b`; `npx biome check` on the changed files.
- The five new gate checks on their own, with their run time.
- `npm run sdk:pack` and `npm run sdk:verify` once by hand, with `AR_GATE_KEY_FILE` pointing at a temporary key.
- Not run by the worker: the full release gate, Playwright.
