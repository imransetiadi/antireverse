---
title: "Ticket 23 — Installable SDK packages and their supply chain"
aliases: [Ticket 23]
project: anti-reverse
doc: TICKET
slice: 23
version: 0.1.0
status: done
updated: 2026-11-28
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[SECURITY]]"
  - "[[PRD]]"
  - "[[OPERATION]]"
---

# 23: Installable SDK packages and their supply chain

**What to build:** The four packages a project installs or that they depend on — `@antireverse/protocol`, `@antireverse/shield-node`, `@antireverse/guard`, `@antireverse/harden` — as plain JavaScript with type declarations, packed into tarballs by one command, with the evidence a careful installer wants beside them: the tarballs are reproducible, they install and run on plain Node 22.12 outside the repository, the compiled code behaves like the source, every runtime dependency is on a reviewed list, each package has a bill of materials, and a signed manifest lists every file with its digest. "Build, pack, verify" (D-127).

**Out of scope:** publishing to npm or anywhere else; a CI release pipeline; provenance from a trusted builder; two-person release; version numbers and a release process; rings, a kill switch for SDK versions and a yank procedure (SC-SUP-01 and SC-SUP-05); CDN delivery of Guard (SC-SUP-04); the engines (SC-SUP-06); `@antireverse/prove`, which no project installs.

**Blocked by:** nothing. Approved by the owner on 2026-11-24 (D-127).

**Status:** done on 2026-11-24. One independent review (no HIGH, 4 MEDIUM, 8 LOW, 1 unconfirmed): all fixed, see Review; the fixes are not independently reviewed. Jev on the finished change: see Proof and Review. One finding on the way changed the design (D-140): see Design, Protocol. Plan: [plans/2026-11-24-slice-23-sdk-packages-supply-chain.md](../plans/2026-11-24-slice-23-sdk-packages-supply-chain.md).

## Design

**Two shapes, one source (D-128).** The source `package.json` files are not changed: inside the repository every consumer keeps resolving the packages to their TypeScript source. The published shape is made at pack time: `tsc` compiles `protocol`, `shield-node` and `harden` (a `tsconfig.build.json` each) and Guard's files are copied; a staging folder per package then gets `dist/`, `LICENSE`, `NOTICE`, a `README.md` and a generated `package.json` whose `exports`, `types` and `bin` point at `./dist`, with runtime dependencies only. `npm pack` runs on the staging folders.

**Build details.** TypeScript rewrites relative `.ts` specifiers to `.js` in the JavaScript it emits but not in declarations; the build rewrites those. Declarations that cannot be reached from a package's public entries are removed: nobody can import them, and for Shield they are the only files that mention the protocol.

**Protocol (D-129, changed by D-140).** Shield imports the protocol for types only; its compiled JavaScript imports nothing but Node's own modules, and its public declarations (four files) need only `node:http`. So the packed Shield has no dependency and no reference to another `@antireverse` package. Harden uses the protocol's schemas and functions at run time. The first design made the packed Harden depend on the packed protocol at the exact version. The install test then showed what that means while the `@antireverse` scope is not registered on npm: npm asks the registry for `@antireverse/protocol` on every install; with the four tarballs together the local one wins, but Harden installed alone gets whatever a registry serves under that name — today a 404, tomorrow the code of whoever registers the scope, running inside the command that reads the admin key. So Harden now carries the compiled protocol (`dist/_protocol`, the same bytes as the protocol tarball's `dist`) and its imports of it are rewritten to relative paths at build time; its packed dependencies are Babel and zod. **No packed package depends on another `@antireverse` package**, and the staging and the closure both refuse one that would. The staged dependencies are derived, not written by hand: the source manifest's `dependencies` and those of what it vendors, exact versions only.

**Version (D-130).** The version is the one in each package's own `package.json` (0.0.0 today); the pack refuses when the four differ. The packed manifests keep `"private": true`, so `npm publish` refuses them: nothing here is a release. The signed manifest records the source commit.

**Folders.** `npm run sdk:build` writes `packages/<name>/dist`. `npm run sdk:pack` builds, stages under `dist/sdk-work` and writes `dist/sdk`: four tarballs, four bills of materials, `sdk-manifest.json`. All are ignored by git. Every function takes its folders as arguments (a layout); tests build in temporary folders and never write into the repository.

**Deleting (L-009).** One function in the tooling's source removes a build folder (the tests remove the temporary folder they made with `mkdtemp` themselves). It takes an absolute, normalised path that must be one of the layout's own folders — for the repository layout exactly the four `dist` folders, `dist/sdk` and `dist/sdk-work`; for a test layout a folder under the operating system's temporary directory whose first part starts with `airverse-sdk-` — must not be a symbolic link, and must be empty or carry a marker file the build writes. Anything else is refused by name. The commands print each folder before removing it.

**Reproducibility.** `npm pack` already sorts entries and fixes times and owners; file modes pass through, so staging sets them (644, 755 for the bin). Every npm child runs with a temporary cache and empty configuration files, so the user's npm settings cannot change the result. The check: two clean builds in two folders, the second with modes and times disturbed before staging, give byte-identical tarballs.

**Install smoke test (D-131).** The test packs the third-party closure (zod, Babel and what they need: 39 packages) from the repository's own `node_modules`, serves it from a registry on a loopback port the system picks — which answers 404 for every other name — and runs a real `npm install --ignore-scripts` of the four tarballs in an empty project in a temporary folder. No network, no user cache. Then, on plain Node: Shield loads and reports itself disabled without a key; `antireverse --help` and a real Harden run work; Guard imports with nothing but relative `.js` specifiers; a TypeScript consumer of all four type-checks; and the installed tree holds no TypeScript source, no `tsx` and no path into the repository. Harden is also installed alone, against a registry that offers a decoy `@antireverse/protocol`: the name is never asked for.

**Behaviour equivalence (D-132).** The whole test suites of the three compiled packages run a second time against the compiled output: a Vitest plugin redirects every module under a package's `src` to its compiled file and `@antireverse/protocol` to the compiled protocol, and fails the run if a source module of those packages is ever loaded — by Vitest, or by a process a test starts (a load guard in `NODE_OPTIONS`). A fixed, small list names the test files left out and why; another names every test file that starts a process or reads source text, with what the compiled run does about it. The run is compared test by test with a run on the source. Harden's suite runs against the build that already carries the vendored protocol, so the rewritten imports are covered by it. Vitest's on-disk transform cache is off for this run: a cached module is not passed through the plugin again.

**Bill of materials and allowlist (D-133, D-134).** A CycloneDX 1.5 JSON document per package, written by a small generator from `package-lock.json` for the packed runtime closure: no timestamp and no random serial number, so its bytes can be hashed in the manifest. `tools/sdk/allowlist.json` lists every third-party runtime dependency by name and exact version per package; the check fails on anything in the closure that is not listed, on a listed entry that is gone, on an install script in the closure, and on any dependency of Shield or Guard at all.

**Signed manifest and verify (D-139).** `sdk-manifest.json` lists each tarball's name, version, file, size and SHA-256 and the same for its bill of materials, with the source commit and the tool versions, signed with the gate's local Ed25519 key through `tools/gate/src/sign.ts`. `npm run sdk:verify -- <dir>` fails on a size or digest mismatch, a missing file, an extra file, a bad signature, and — like `gate:verify-report` — on a signer that is neither the local gate key nor the fingerprint given with `--expect`. **What it proves:** the files are the ones that the holder of that key signed on their machine. It is not provenance: nothing says which source or which builder produced them.

**Gate (D-135).** One criterion of the gate's own, `gate-sdk-artifacts-local`, with five fixed-file checks: `sdk-reproducible`, `sdk-install-smoke`, `sdk-equivalence`, `sdk-sbom-allowlist`, `sdk-signed-manifest`. `sec12-sdk-artifacts` keeps no check; its reason names what is still missing.

**Skill (D-136) and READMEs (D-137).** The skill's preflight takes `--tarballs <dir>`: read-only, it checks the manifest (files, sizes, digests, no extra file, the signature against the embedded key) and prints the signer's fingerprint. The skill uses tarballs when the user names a folder and the check passes, and the clone otherwise. Each tarball carries its guide from `docs/` as its README under a generated header.

## Decisions

| # | Decision | Jev |
|---|---|---|
| D-128 | The published shape is made at pack time in a staging folder with a generated `package.json`; the source manifests are not changed | `staged-manifest` 1.00, confidence 1.00; no requirement contradicted. Rejected: `publishConfig` (npm does not apply it to `exports` or `bin`), conditional exports with a custom condition (every workspace tool would need it), pointing the source at `dist` (workspace development would need a build) |
| D-129 | Packed Shield ships only the declarations reachable from its public entry and has no dependency; packed Harden depends on the packed protocol at the exact version | `public-dts-only-and-exact-dep` 0.99, confidence 0.99; no requirement contradicted. Rejected: Shield depending on the protocol (ends zero dependencies), bundling with esbuild and a declaration bundler (new dependencies), an optional peer dependency |
| D-130 | The version is each package's own `package.json` version, unchanged (0.0.0); the pack refuses when the four differ; `"private": true` stays in the packed manifest; the commit goes into the signed manifest | `package-json-version` 0.94, confidence 0.93; no requirement contradicted. Rejected: a version derived from the commit (no committed source of truth), bumping to 0.1.0 now (suggests a release), a command-line flag |
| D-131 | The install smoke test gets third-party packages from a loopback registry filled from the repository's `node_modules`; a real `npm install` with a temporary cache | `loopback-registry` 0.98, confidence 0.98; no requirement contradicted. Rejected: `--offline` with the user's cache (not guaranteed, and it is the user's), a hand-assembled `node_modules` (npm never reads the packed manifests), the network |
| D-132 | The whole suites of protocol, shield-node and harden run again on the compiled output through a redirect with a load guard, compared test by test with the source run | `full-suites-redirected` 1.00, confidence 1.00; no requirement contradicted. Rejected: a hand-picked subset, the smoke test alone, new golden-output tests |
| D-133 | CycloneDX 1.5 JSON from our own generator over the lockfile closure, without time or serial number | `cyclonedx-own` 1.00, confidence 1.00; no requirement contradicted. Rejected: SPDX (needs a creation time and a unique namespace), `npm sbom` (the workspace's tree, random serial number), both formats |
| D-134 | The allowlist pins name and exact version of every package in the closure | `name-version` 0.95, confidence 0.94; no requirement contradicted. Rejected: names only, name, version and integrity (the lockfile and the bill of materials carry the integrity), direct dependencies only |
| D-135 | A new workspace `tools/sdk` with its own Vitest project; one gate criterion with five fixed-file checks | `tools-sdk-five-checks` 0.93, confidence 0.92; no requirement contradicted. Rejected: one check for everything (the report would not say which property failed), inside `tools/gate`, a custom executor without test files |
| D-136 | The skill's preflight gets `--tarballs <dir>` and checks the manifest read-only; the skill prefers a verified tarball folder the user names, otherwise the clone | `preflight-tarballs-flag` 1.00, confidence 1.00; no requirement contradicted. Rejected: finding tarballs in the clone by itself, changing the skill text only, leaving the skill as it is |
| D-137 | Each tarball's README is a generated header followed by its guide copied from `docs/`; the protocol's is the header alone | `guide-with-header` 0.87, confidence 0.85; no requirement contradicted. Rejected: a three-line pointer, no README, hand-written READMEs in the packages |
| D-138 | SECURITY.md gets one marked as-built paragraph under the supply-chain table; the table and §12 are not changed | `one-as-built-paragraph` 1.00, confidence 1.00; no requirement contradicted. Rejected: no change, editing the control rows |
| D-140 | (after the install test) Harden carries the compiled protocol and imports it by relative path; no packed package depends on another `@antireverse` package. Replaces the Harden half of D-129 | `vendor-protocol-into-harden` 0.96, confidence 0.95; no requirement contradicted. Rejected: keeping the dependency with tests and a warning (installing Harden alone could still fetch the name), npm `bundleDependencies`, stopping to ask first. The unregistered npm scope itself is the owner's to decide |
| D-139 | `sdk:verify` trusts the local gate key or the fingerprint given with `--expect`; it never creates a key. (Review L4: with `--expect`, only that fingerprint) | `local-key-or-expect` 0.99, confidence 0.99; no requirement contradicted. Rejected: any valid signature, always requiring `--expect` |

## Acceptance criteria

1. One command compiles `protocol`, `shield-node` and `harden` to JavaScript and declarations and prepares Guard; no emitted file names a `.ts` module; the source manifests are unchanged and workspace consumers still load the TypeScript source.
2. One command writes four tarballs; the packed manifests point at `./dist`, keep `"private": true`, carry one version and runtime dependencies only; Shield and Guard have none; no packed package depends on, or imports, another `@antireverse` package.
3. Two clean builds give byte-identical tarballs, also when file modes and times differ.
4. The tarballs install with a real `npm install` in an empty project outside the repository with no network, and on plain Node: `createShield` reports disabled without a key; `antireverse --help` and a Harden run on a small bundle work and the protected bundle behaves like the original; Guard imports as plain ES modules; a TypeScript consumer type-checks; the installed tree has no TypeScript source, no `tsx` and no path into the repository. Harden alone installs and runs, and never asks a registry for an `@antireverse` name, also when the registry offers one.
5. The test suites of protocol, shield-node and harden pass on the compiled output with the same tests and results as on the source; a source module of those packages cannot be loaded in that run, by Vitest or by a child process; the tests that only read source text are named as such.
6. Each package has a CycloneDX bill of materials of its packed runtime closure, identical across runs; the allowlist check fails on an unlisted dependency, a changed version, a stale entry, an install script, and any dependency of Shield or Guard.
7. A signed manifest lists every tarball and bill of materials with size and SHA-256; `sdk:verify` fails on a changed file, a missing file, an extra file, a changed manifest, a bad signature and an unknown signer; no command prints or stores a private key in the repository.
8. No command deletes anything but the build folders of its layout: a folder outside them, a symbolic link, a relative path and a folder that is not empty and not marked are refused.
9. The gate has `gate-sdk-artifacts-local` with five checks, each failing when a listed file is missing or holds no test; `sec12-sdk-artifacts` has no check and stays not checkable, and its reason names the local criterion and what it does not prove.
10. The skill's preflight checks a tarball folder read-only and reports a failed check as a problem; the clone path works as before; the skill's drift test passes.

| D-141 | (review M3) The `@antireverse/protocol` development dependency is removed from the source manifests of shield-node and harden; the workspace resolves it through the root link npm makes for every workspace | `drop-devdependency` 1.00, confidence 1.00; no requirement contradicted. Rejected: keep and document, a `file:` spec (untested install behaviour), removing it from Shield only |
| D-142 | (review L2) Packed Harden declares the Node range its direct dependencies declare (Babel's `^22.18.0 || >=24.11.0`), read at staging; the other three keep `>=22.12` | `declare-babel-range` 1.00, confidence 1.00; no requirement contradicted. Rejected: `>=22.18`, keeping `>=22.12` |
| D-143 | (review, unconfirmed finding) In the equivalence check a test file with a result that is not passed is run once more, alone, in the same mode; then everything must have passed in both modes and agree | `rerun-failed-files-once` 0.99, confidence 0.99; no requirement contradicted. Rejected: `--retry` on the whole runs, accepting "failed in both", leaving it |

D-137's confidence is 0.85; it is a technical choice with no requirement contradicted and was followed.

## As built

| Part | Where |
|---|---|
| The four packages, their entries, what Harden vendors | `tools/sdk/src/packages.ts` |
| The one function that removes a folder, and the layouts | `tools/sdk/src/safe.ts` |
| Build: `tsc`, declaration specifiers, pruning, vendoring | `tools/sdk/src/build.ts`, `packages/{protocol,shield-node,harden}/tsconfig.build.json` |
| Staging and the generated manifest and README | `tools/sdk/src/stage.ts` |
| Isolated `npm pack` | `tools/sdk/src/pack.ts`, `tools/sdk/src/exec.ts` |
| Closure, bill of materials, allowlist | `tools/sdk/src/{closure,sbom,allowlist}.ts`, `tools/sdk/allowlist.json` |
| Manifest, signature, verify; the whole pack; the commands | `tools/sdk/src/{manifest,pipeline,cli}.ts` |
| Loopback registry (test support) | `tools/sdk/src/registry.ts` |
| Redirect plugin and the compiled-output run | `tools/sdk/src/dist-plugin.ts`, `tools/sdk/vitest.dist.config.ts` |
| Tests (7 files, 127 tests after the review) | `tools/sdk/test/` |
| Gate | `tools/gate/src/{matrix,catalog,checks}.ts` |
| Skill | `skills/airverse-setup/{SKILL.md,scripts/preflight.mjs,evals/express-tarballs-changed-file}` |

Root: the scripts `sdk:build`, `sdk:pack`, `sdk:verify`, `sdk:allowlist`; the Vitest project `sdk`; the `tsc -b` reference; `dist/` in `.gitignore`; two entries for the new workspace in `package-lock.json`, added by hand (see Honest limits). No npm dependency was added. After the review two source manifests lost a development dependency (D-141) and `packages/shield-node/src/types.ts` and `shield.ts` got a type-only change (M4: the compiled JavaScript is byte-identical before and after).

**Sizes (this machine, 0.0.0):** protocol 197 kB, shield-node 87 kB, guard 33 kB, harden 256 kB. `npm run sdk:pack` takes about one second.

**Run time added to the gate (measured, this machine):** the five checks run alone (`--only`) took 45.7 s wall before the review and 52.2 s after it; `sdk-equivalence` is most of it (the three suites twice, one run after the other). Their tests also run inside `npm run verify`: the `sdk` project alone takes about 45 s there.

**The install smoke test needs no network.** It needs `npm` on the path and the repository's `node_modules` (it packs the 39 third-party packages of the closure from there). When a closure package is not installed, `npm pack` fails and the test says which folder.

**Found on the way:**

- The dependency-confusion exposure of a dependency between packed packages (D-140). The same exposure exists today in the documented clone path: installing `packages/shield-node` from a clone makes npm ask the registry for `@antireverse/protocol` (ticket 22, H2). Registering the `@antireverse` scope on npm would close it; that is the owner's decision.
- `@antireverse/harden` declares `@babel/core`, which no compiled module imports (it imports generator, parser, traverse and types). It is kept, because the dependency set is the source's; dropping it would remove about 25 packages from what a project installs. `sdk:pack` prints a note.
- `package-lock.json` is behind the workspaces' manifests in ways that are not this slice's: a `--package-lock-only` run adds `license` fields and two development dependencies of an existing workspace. Left as it was.
- Vitest keeps transformed modules on disk between runs (`fsModuleCache`). A cached test file carried the compiled paths of an earlier run, so a mock in one Harden test silently missed; the compiled-output run now turns the cache off.
- The first run of `sdk:pack` in the repository was refused by the safe-delete function (staging emptied `dist/sdk-work/stage`, which is not one of the six folders). Nothing was removed. The temporary layouts were then given the same three kinds of folder as the repository's, so a test meets the same refusal.
- The gate's scan for test names took a helper called `test(…)` in the equivalence test for tests that did not run; the helper was renamed.

## Proof

| Criterion | Proving test | Red, then green |
|---|---|---|
| 1 | `build.test.ts` (15 tests) | Red: no `src/build.ts`; then one wrong assertion (the entry's own name in a comment). Mutation: without the declaration rewrite the build itself fails ("the declaration … is missing"), every test of the file is skipped. Green: 15 passed |
| 2 | `reproducible.test.ts` "the packed shape" (4 tests), `build.test.ts` "Harden carries the compiled protocol…" | Red with the code missing; after D-140 the expectations were changed first (no `@antireverse` dependency) and the old code failed them. Green |
| 3 | `reproducible.test.ts` "two clean builds give the same four files, byte for byte" | Mutation: staging without `chmod` → 2 failed (different SHA-256; `cli.js` mode 644). Green: 7 passed |
| 4 | `install-smoke.test.ts` (12 tests) | First run 3 failed: npm asked the registry for `@antireverse/protocol` (the finding behind D-140), the sample bundle was too small for the Canaries, the consumer passed `{}` where the types want a key and an endpoint. Green after D-140 and the corrected test: 12 passed |
| 5 | `equivalence.test.ts` (8 tests) | First run 2 failed (one Harden test with a mock: a symbolic link in the temporary path gave one file two names; then the cache above). Mutation: without the redirect, 98 of 100 files fail with "a source module was loaded in a run on the compiled output". Green: 4,265 tests on the compiled output, each with the result of the source run |
| 6 | `sbom-allowlist.test.ts` (18 tests) | Red: with an empty allowlist 6 failed. Green with the list written from the closure and read through |
| 7 | `manifest.test.ts` (16 tests) | Red with the code missing. Mutation: without the extra-file rule and with every signer trusted → 3 failed. Green: 16 passed |
| 8 | `safe.test.ts` (33 tests) | Red with the code missing; red again (4 tests) when the temporary layouts were tightened. Every refusal that names a folder outside the test's own runs with a `remove` that only records |
| 9 | `tools/gate/test/catalog.test.ts` "slice 23…" (3), `matrix.test.ts`, `checks.test.ts` "slice 23: so do the SDK checks", `cli.test.ts` | Red: 7 tests. Green: 150 in the gate project. Run for real: `gate:release --only` the five checks → all pass, `gate-sdk-artifacts-local` pass, `sec12-sdk-artifacts` not checkable |
| 10 | `tools/gate/test/skill-airverse-setup.test.ts` "preflight with tarballs" (6 tests) and the existing 13 | Red: 7 tests. Green: 19 passed |

**Not test-first:**

- `stage.ts` was written with the mode normalisation already in it; the reproducibility test was shown to fail by removing it (above).
- `closure.ts`, `sbom.ts` and `allowlist.ts` were written against the test file in one step; the red was the empty allowlist, not each function.
- `manifest.ts`, `pipeline.ts` and `cli.ts` likewise; the mutation above is the evidence that the verify tests can fail.
- `registry.ts` has no test of its own: the install test uses it, and its "decoy" case shows that it serves what it is given and 404s the rest.
- The repository layout of `sdk:pack` was first exercised by hand, not by a test (it writes into the repository); that is how the refusal above was found. The shapes are now the same in tests.
- Documents, the skill text and the new skill test case have no failing test first, except where the drift test reads them.

**Commands run (2026-11-24):**

- `npx vitest run --project protocol --project shield-node --project guard --project harden --project api --project range --project gate --project e2e --project sdk` → 294 files, 7,438 tests passed (160 s).
- `npx tsc -b` → clean. `npx biome check` on the changed files → clean.
- `npm run gate:release -- --only sdk-reproducible,sdk-install-smoke,sdk-equivalence,sdk-sbom-allowlist,sdk-signed-manifest` with a temporary key → the five pass in 45.7 s (exit 2: the other lines are not checked).
- `npm run sdk:pack` twice and `npm run sdk:verify -- dist/sdk` with a temporary key → the same digests both times; valid. The build folders were removed again afterwards.
- Not run: the full release gate, Playwright, the Console project.

**Jev on the finished change (`jev_gate`):** action `escalate` — composite 0.76, `safe_to_apply` 0.39 (below the review line), test gap rated low. Nine claims verified, none contradicted; two with low confidence: the install claim (0.30: the evidence text did not itself show the Node version) and "the delete function refuses every folder that is not a build folder" (0.37: a claim about every folder, shown by 20 named cases and the shape rule, not proven). An independent review is the next step; nothing here was accepted on Jev's word.

## Honest limits

- **Local only.** No CI pipeline, no provenance attestation, no second approver, no published package, no rings, no yank. `sec12-sdk-artifacts` stays not checkable. *(2026-11-28: three packages were published since, by hand; see "Published (2026-11-28)".)*
- **The signature is a local key's.** It shows that the holder of the key signed these files. It does not show where they were built or from which source; the commit in the manifest is what the builder's working tree said, and "with uncommitted changes" is recorded, not refused.
- **Reproducible on one machine with one toolchain.** Not shown across Node, npm, TypeScript versions or operating systems.
- **The loopback registry is filled from `node_modules`**, which is trusted as `npm ci` left it; its contents are not compared with the lockfile's integrity again. The test shows that npm resolves the packed manifests, not what the public registry serves.
- **The bill of materials and the allowlist describe the lockfile's closure.** A project that installs a tarball resolves Babel's and zod's ranges itself and may get other transitive versions.
- **Harden's own dependencies still come from a registry** when a project installs it. Only the `@antireverse` name is taken out of that.
- **The vendored protocol is a second copy** in a project that installs both Harden and the protocol tarball. Nothing shares state between them today.
- **One test file is left out of the compiled run** (`packages/harden/test/cli-bin.test.ts`). Two tests read source files as text and are about the source in both runs (Shield's import check, the protocol's import graph). Guard has no compiled form, so there is nothing to compare; its files are copied.
- **Type declarations:** the guides' Shield snippets compile under `--strict` without `skipLibCheck`; the consumer of all four packages is still checked with `skipLibCheck` (Babel's and zod's declarations are not ours), with `@ts-expect-error` lines that show the types are real.
- **Timing-budget tests** in the suites can fail under load; the equivalence check runs the two suites one after the other and runs a file that did not pass once more, alone (D-143). A test that fails twice under load still fails the check.
- **`package-lock.json` was edited by hand:** two entries for `tools/sdk`, and the removed development dependency in the entries of shield-node and harden. An offline, isolated `npm install --package-lock-only` accepts it and would additionally write a `license` field into the workspace entries (`tools/sdk` among them) and two development dependencies (`@antireverse/prove`, `@antireverse/range`) that a workspace's manifest has and the lockfile lacks; those are older differences and were not taken. The link `node_modules/@antireverse/sdk-tools` was made by hand in this working copy; `npm ci` makes it elsewhere.
- **A test whose build fails can leave its folder** under the operating system's temporary directory (seen twice during mutation runs).
- **The skill** was not run by a model on the new path; its new test case is written, not executed.
- **Tested on Node 22.12, npm 10.9, macOS.** Babel 8 asks for Node ≥ 22.18 and warns below it.

## Review

One independent review of the uncommitted change (2026-11-24): no HIGH; the delete function and the tarballs held under attack. Every finding was reproduced by a failing test before its fix, except where "Not test-first in the review round" says otherwise.

| # | Finding | Fix | Failing test first |
|---|---|---|---|
| M1 | Three Shield tests start `fixtures/exit.mjs` in a child process, which imported the source: outside the Vitest load guard, so the compiled run tested the source there, and the wording overclaimed | The fixture imports the compiled files when `AR_SDK_COMPILED_ROOT` is set and the test then starts it with plain `node`; the compiled run sets it and puts a load guard for child processes into `NODE_OPTIONS` (`tools/sdk/src/child-guard.mjs`); a list of every test file outside the Vitest guard, checked against a scan | The damaged compiled Shield (every `unref()` removed) still passed the compiled run of `shield.test.ts`: exit 0 where a failure was expected; the scan and the child-guard tests failed for want of the list and the guard |
| M2 | The skill's preflight called a folder that someone changed and signed again `verified` and `ok` | `intact` and `trusted`; without `--signer` the preflight fails; `--integrity-only` is the user's explicit way on, and the result still says not trusted; the skill asks the user for the fingerprint; a new test case for a model | 6 drift tests failed, the re-signed folder among them |
| M3 | The clone path asked the registry for `@antireverse/protocol`; the documents did not say so | D-141 (the development dependency is gone); README, SECURITY and the getting-started guide state the exposure, what a user can do and what is still the owner's to do | The clone-inside-project install against an empty local registry asked for `@antireverse/protocol`; now it asks for `express` and `@types/express` only |
| M4 | The guides' Shield snippet did not compile under `--strict` (`key: process.env.…`) | `ShieldConfig.key`, `policyPublicKey` and `actorKey` accept `undefined`, as the run time already does | The guides' snippets against the packed types: TS2322 four times |
| L1 | `sdk:allowlist` emptied build folders without naming them | Named first, on the error stream (its output is the list); the header and README say what each command empties | The command printed nothing on the error stream |
| L2 | Packed Harden declared `>=22.12` while Babel needs more | D-142; one sentence about Node in README, guide and skill; installs under `engine-strict` observed | Harden's staged engines were `>=22.12`; the `engine-strict` test did not exist |
| L3 | Preflight crashed on a manifest holding `null`; `sdk:verify` printed an engine error on a 40 MB manifest | Both cap the manifest at 1 MB, check its shape and always answer in their own form | Both reproduced as failing tests |
| L4 | `sdk:verify --expect X` passed when the local key had signed and X was another key | With `--expect` only that fingerprint is trusted | Reproduced |
| L5 | The README did not say that `sdk:pack` creates the local key | Said, with where it is and that it is a secret | — (document) |
| L6 | "One function removes a folder" was not exact: tests remove their `mkdtemp` folder themselves | The claim is corrected (source and ticket) | — (wording) |
| L7 | The allowlist pinned name and version only | Each entry carries the lockfile's integrity; other bytes, no integrity, another registry, and one version with two integrities all fail | Reproduced. Result: nothing legitimate broke — all 39 packages have an integrity and come from the npm registry |
| L8 | Packed READMEs carried clone-only commands and links to files not in the tarball; numbers in this ticket disagreed; the lockfile entry and link | `packedGuide` rewrites the three guides for the installed package and fails when a guide no longer holds what it replaces; the numbers are 39 everywhere; the lockfile as described under Honest limits | The packed READMEs matched `packages/…`, `npx tsx` and relative links |
| unconfirmed | A timing-budget test can fail under load in one of the two equivalence runs | D-143 | The merge and selection functions did not exist; the load itself was not reproduced on demand |

**What was found by the audit for M1** (every test file of the three suites that starts a process, a worker, or reads `src` by path):

- `packages/shield-node/test/shield.test.ts` and `fixtures/exit.mjs`: the child process above; fixed. The same file's import check reads `src` as text.
- `packages/protocol/test/entrypoints.test.ts`: reads `src` as text for the import graph.
- `packages/harden/test/cli-bin.test.ts`: child processes on `src/cli.ts`; left out of the compiled run, as before.
- `packages/harden/test/helpers.ts` and `behaviour.test.ts`: `import()` of computed paths, which are hardened output files in a temporary folder, not source.
- `packages/harden/src/equivalence.ts` (product code): starts the user's test command through a shell; its tests run commands on generated bundles. With the child guard in `NODE_OPTIONS` those commands could not load a source module either.
- No worker threads, no `fork`.

**Wording corrected:** the compiled run proves that no source module of the three packages is loaded, by Vitest or by a child Node process; it does not turn a test about source text into a test of the compiled files, and it says so (the plugin's header, the gate's notes, criterion 5).

**M4 changes no behaviour:** the three compiled packages were built before and after the change; every `.js` file is byte-identical, and only `shield-node/types.d.ts` differs.

**Not test-first in the review round:** L5 and L6 are wording. The child guard's hooks file was written with its test in one step. The M1 test that first failed used a compiled run of `shield.test.ts` on the damaged files (30 s of waiting for three hung children); after the fix it was replaced by a faster one that starts the fixture directly, intact and damaged — that final form was never seen failing against the unfixed code. The D-143 merge functions are unit-tested; a real load-induced failure followed by a successful second run was not produced on purpose.

**Commands run after the fixes (2026-11-24):** the nine Vitest projects → 294 files, 7,458 tests passed (169 s); `npx tsc -b` clean; `npx biome check` on the changed files clean; the five SDK gate checks alone → all pass, 52.2 s; `apps/console/tsconfig.json` unchanged.

**Jev on the fixes (`jev_gate`):** action `escalate` — composite 0.66, `safe_to_apply` 0.37, low confidence throughout. Six claims verified, none contradicted; the claim about the load guard at 0.46, the others between 0.55 and 0.91. The fixes are not independently reviewed; that is the next step.

**Limits after the review:**

- The scan for tests outside the guard is a pattern over test sources (`spawn`, `execFile`, `fork`, workers, type-stripping flags, `src` by path); a child started in a way the pattern does not know would be missed by the list, though the `NODE_OPTIONS` guard would still refuse it a source module if it inherits the environment. A child started with a cleaned environment would escape both.
- `--integrity-only` exists: a user can choose to install an intact folder from an unknown signer. The skill is told not to choose it; the new test case for that was written, not run.
- D-141 makes the protocol an undeclared dependency of two workspaces: it works with npm workspaces, which is what this repository uses; a stricter package manager would refuse it.
- `express` and `@types/express` are still asked from the registry when Shield's folder is installed from a clone inside a project. They are public names owned by their projects, so that is ordinary; it is the reason to keep the clone beside the project.
- The `@antireverse` scope was unregistered when this slice was built. The owner registered it on 2026-11-28 (the owner's statement, not checked from the repository); nothing is published under it. *(Later the same day 0.1.0 of three packages was published under it; see "Published (2026-11-28)".)*

## 23b: Preparing the first release (2026-11-28)

**What changed outside the code:** on 2026-11-28 the owner decided to publish to npm and registered the `@antireverse` organisation there. First version 0.1.0; Shield, Guard and Harden only; `@antireverse/protocol` stays unpublished and private.

**What to build:** everything the owner needs to publish by hand with their own login and one-time code, and nothing that publishes. **Nothing was published by this slice, and no document says that the packages are on npm.**

### Decisions

| # | Decision | Jev |
|---|---|---|
| D-144 | All four packages move to 0.1.0 and the rule of D-130 stays (the four share one version). The protocol is versioned with the others because Harden ships a copy of it; it is not released: it keeps `"private": true` and the release build never packs it | `all-four-0-1-0` 0.98, confidence 0.98; no requirement contradicted. Rejected: protocol stays 0.0.0 (a released Harden's bill of materials would name a version that says nothing), a version line of its own (a second rule) |
| D-145 | The release build is a command of its own, `npm run sdk:release`, writing to a folder of its own, `dist/sdk-release`; `sdk:pack` and `dist/sdk` are unchanged, so everything in `dist/sdk` is private at all times | `separate-command-and-folder` 0.99, confidence 0.99; no requirement contradicted. Rejected: a `--release` flag writing into `dist/sdk`, a flag writing elsewhere |

Decided by the owner and the brief, not put to Jev: which packages, the version, what the release refuses, what the manifest and the README must say, and that the two checks only read.

### As built

- **Versions.** `packages/{protocol,shield-node,guard,harden}/package.json` and their four lockfile entries say 0.1.0; Shield's `SDK_VERSION`, which it sends with every batch of Events, says 0.1.0 (the one run-time change of this slice, and what a version is).
- **`npm run sdk:release`** (`tools/sdk/src/release.ts`, `pipeline.ts`, `stage.ts`, `cli.ts`). Before anything is built or removed it reads the repository's state and refuses: uncommitted changes (changed, staged or untracked files), a `HEAD` that is not `refs/remotes/origin/main` (the remote-tracking ref as it is — **nothing is fetched**; when the ref is missing it says to run `git fetch origin`), an `origin` URL with credentials (refused without repeating them) or one that is not `https://host/owner/name` or `git@host:owner/name`. Then: build as always, stage only the three released packages, pack into `dist/sdk-release`.
- **The publishable manifest** has no `private` field, `publishConfig: { "access": "public" }`, `description`, `keywords`, `license` (Apache-2.0, refused otherwise), `repository` (`git+https://…​.git` with the package's `directory`), `homepage` (the package's guide in the repository), `bugs`; `engines`, `exports`, `types`, `bin`, `files` and `dependencies` as in the ordinary pack. The ordinary pack's manifests are unchanged, key for key.
- **The README for the npm page** (`stagedReadme` with a release): the package's name and one-line description; an "Early release" block (no hosted service — the API and Console are run by the user from the repository; a local single-process system; the release gate is blocked; scores are from a scripted stand-in; built from which commit; a local signature, no provenance attestation); install by name; then the guide from `docs/`, as before, with the package-specific sentences for an install by name, its own title removed, and every link to another document as an absolute URL into the repository. The guides' "Honest limits" sections come with them.
- **The release manifest**: `kind: "release"`, the repository, the commit, `dirty: false`, the three packages with tarball and bill of materials; signed like every other. `sdk:verify` accepts it. Harden's bill of materials names the protocol it carries by version and by a SHA-256 over the carried files (there is no protocol tarball beside it in a release).
- **`npm run sdk:release-check -- <dir>`** and **`npm run sdk:published-check -- <dir>`** (`tools/sdk/src/publish.ts`): both verify the folder first (a trusted signer, kind `release`, exactly the three names, no `private` inside a tarball) and ask no registry when that fails. They ask with `npm view <name>@<version> dist.integrity`, with npm's configuration left out and a cache in a temporary folder. The first wants every version absent and then prints `npm login` and three `npm publish "<absolute path>" --access public` lines; the second wants every version present with the local tarball's sha512. Neither runs a command that writes.
- **Folders.** `dist/sdk-release` is a sixth named folder of the delete function, and temporary layouts have a `release` folder of the same kind.
- **Gate.** `tools/sdk/test/release.test.ts` is a second fixed file of the check `sdk-signed-manifest`; the criterion's first note says what the release build is and that these checks need no network and no npm login.
- **Documents.** README: "Publishing (owner only)", the commands table, the version in the tarball example. Nothing says the packages are published.
- **Also fixed:** the README's and the Harden guide's example used `--test "npm test"`, which works only when the bundle folder itself holds the tests (MEMORY §11, from slice 22). Both now show `--test "node /absolute/path/to/test-bundle.mjs"`, and the README says where the command runs.

### Proof

| Item | Proving test | Red, then green |
|---|---|---|
| Versions | `release.test.ts` "the four packages are 0.1.0…" | Red with the file (0.0.0); green after the four manifests, the lockfile and `SDK_VERSION` |
| What the release refuses | `release.test.ts`, 6 tests on small git repositories of their own, and the remote's 2 | Red: no `src/release.ts`. Green |
| The publishable shape; the ordinary pack unchanged; the same compiled files; reproducible | `release.test.ts` "the release folder" (5 tests) | Red: no release mode. Green |
| The npm page | `release.test.ts` "the README for the npm page" (3 tests) | Red as above; one more red on a link pattern of the test itself |
| The release manifest, verify, Harden's bill of materials | `release.test.ts` "the signed release manifest" (3 tests) | Red as above. Green |
| The owner's two checks | `release.test.ts` "the owner's checks, against a loopback registry" (6 tests): absent, present, unreachable, not a release folder, same bytes, missing and other bytes | Red: no `src/publish.ts`. Green |
| The commands and scripts | `release.test.ts` "the commands" (2 tests) | Red, green |
| The release folder in the delete function | `safe.test.ts` (the layout test) | Red: `layout.release` undefined. Green |
| Gate | `catalog.test.ts`, `matrix.test.ts` (slice 23 tests, changed first) | Red: 3 tests. Green |
| `--test` example | `skill-airverse-setup.test.ts` "the guides' --test example" | Red: both documents showed `--test "npm test"`. Green |

**In a temporary clone with a local commit (never pushed), by hand:** with the changes copied in and uncommitted, `sdk:release` refused ("uncommitted changes (27)"); committed locally, it refused ("HEAD 226d03089993 is not origin/main (7aacbe69dd0c…)"); with the clone's `origin/main` ref moved to that commit and `origin` still a local path, it refused ("the origin remote is not a repository URL"); with the clone's `origin` set to the project's https URL (nothing fetched or pushed) it built three tarballs in under a second. `sdk:verify` accepted the folder; `sdk:release-check` asked the public registry read-only, found all three versions absent and printed the four commands; `sdk:published-check` said "not on the registry" three times and exited 1. The clone and its tarballs were removed: they were built from a commit that exists nowhere else and must not be published.

**Commands run (2026-11-28):** the nine Vitest projects → 295 files, 7,485 tests passed (193 s); `npx tsc -b` clean; `npx biome check` on the changed files clean; the five SDK gate checks alone → all pass, `gate-sdk-artifacts-local` pass, 71 s wall (52 s before this slice; the release tests are in `sdk-signed-manifest`, 45 tests); `apps/console/tsconfig.json` unchanged. Not run: the full gate, Playwright, the Console project.

**Jev on the finished change (`jev_gate`):** action `escalate` — composite 0.63, `safe_to_apply` 0.29, correctness confidence 0. Seven claims verified, none contradicted; "release-check prints commands only when…" at 0.40 and the test-run claim at 0.25. Not independently reviewed: that comes before the owner publishes.

**Not test-first:** the keyword lists and the wording of the README's status block were written with the code; the tests pin the phrases that matter. The CLI's `release` command itself is not run by a test (the working tree of a test run is rarely clean); its parts are, and the clone run above exercised it. The CLI's two checks are tested against the public registry only by that one manual run; their logic is tested against a loopback registry.

### What the owner does, in order

1. Have this slice committed and pushed to `main`; in a clone with `node_modules` installed: `git fetch origin`, `git status` (clean), `HEAD` on `origin/main`.
2. `npm run sdk:release` — it prints the three tarballs, the commit and the signing key's fingerprint.
3. `npm run sdk:release-check -- dist/sdk-release` — online. Read the list; it must end with "ready" and four commands.
4. `npm login` (once, with the account that owns the `@antireverse` organisation), then the three `npm publish … --access public` lines as printed, each with the one-time code npm asks for.
5. `npm run sdk:published-check -- dist/sdk-release` — it must say "published".
6. Only then are README, guides and skill changed to "install from npm" (not part of this slice).

### Limits

- **Nothing is published**, and nothing here has been run against a real publish: `sdk:published-check` has only ever seen a loopback registry answer "present". *(True when written. Published later on 2026-11-28; `sdk:published-check` has since run against the real registry.)*
- **`origin/main` is the local remote-tracking ref.** A clone that has not fetched can build a release from a commit that `main` has since left behind; the command says "as this clone last fetched it" and fetches nothing.
- **One person, one local key.** No provenance attestation (npm's `--provenance` needs a supported CI), no second approver. The README on the npm page says so.
- **The registry check is a moment in time:** a version absent at the check can be taken by the first `npm publish` only; the second and third could in principle fail, leaving a partial release that `sdk:published-check` would report.
- **A published version is permanent.** A mistake in 0.1.0 is fixed by 0.1.1, not by publishing again.
- **The README's status block will age:** it says the gate is blocked and scores are from a stand-in; when that changes, the text in `stage.ts` has to change before the next release.
- **`npm view` output is parsed:** an npm version that words a missing package differently could make the check report "unreachable" instead of "absent". It fails closed.
- ~~Harden's `@babel/core` dependency is still declared and unused~~ — removed in the pre-publish review (S1), below.

### Pre-publish review (2026-11-28)

One independent review of the uncommitted 23b change: "fix before publishing" — one blocker, three should-fix, notes. Contents, manifests, install by name, guards and checks otherwise held. Every finding below was fixed with a failing test first, except where said.

| # | Decision | Jev |
|---|---|---|
| D-146 | Every text a user reads shows `npx --no-install antireverse …`; never a bare `npx antireverse`, and never `npx @antireverse/harden` either (the scope is the owner's, but that form runs whatever is latest on the registry instead of the version the project's lockfile pins) | `no-install-only` 0.97, confidence 0.96; no requirement contradicted. Rejected: allowing the scoped form as an alternative, showing `./node_modules/.bin/antireverse` |

| # | Finding | Fix | Failing test first |
|---|---|---|---|
| B1 | Harden's packed README (and the guides, the root README, the skill's printed command) said `npx antireverse`. The unscoped name `antireverse` is not registered on npm: where the command is not installed, npx downloads and runs whatever is published under that name — in a user's CI, with the admin key in the environment | D-146, in `stage.ts`, `docs/harden.md`, `docs/getting-started.md`, `README.md`, the skill and its preflight (`["npx", "--no-install", "antireverse"]`), each with the one sentence why. The Console's snippets and the command's own `--help` never showed `npx antireverse` (the Console shows the clone's `npx tsx` form) and are unchanged | `release.test.ts` "no documented command can fetch…" (3 tests) failed on `docs/harden.md` and both Harden READMEs; the skill's drift test on the printed command |
| S1 | `@babel/core` was a declared dependency that nothing imports: 20 more packages in every install, for good once published | Removed from `packages/harden/package.json`. Checked first: no file of Harden's source, tests or bench imports it; `@babel/{generator,parser,traverse,types}` declare no peer dependency. Lockfile: the 20 entries only it needed are gone and `escalade` is now development-only, taken from npm's own offline result; the allowlist is regenerated. Harden's closure is 18 third-party packages (39 before) | The closure, bill-of-materials and manifest tests were changed first and failed; then the whole Harden suite on source (506 tests) and on the compiled output, and the install smoke test |
| S2 | The clean-tree check did not see git-ignored files or skip-worktree files; an ignored `.env.local` in Guard's source folder, a file under an ignored `src/dist/`, and an unseen edit all shipped | `releaseState` refuses an ignored or untracked file in any of the four source folders and any file marked skip-worktree or assume-unchanged. And staging a release takes an allowlist: every file that would ship must be compiled or copied from a source file the release commit tracks (`git ls-tree HEAD`), in its own package or, inside the vendored protocol, in the protocol's | `release.test.ts` "what a clean `git status` hides" (4 tests) and "a release ships only files of tracked sources" (2 tests): all red first |
| S3 | `release.test.ts` read the checkout's `origin`; with a local-path origin the suite, and the gate check, failed. Three tests failed when the checkout sat under `<tmp>/airverse-sdk-*` | The tests use the pinned public repository. The delete rule no longer applies its temporary kinds inside the repository, wherever the repository is | `safe.test.ts` "inside the repository the temporary kinds do not apply…" red first; then six SDK test files (134 tests) run green inside a clone at `<tmp>/airverse-sdk-relproof2/repo` with a local-path origin |

**Notes fixed:**

- Shield's packed README no longer speaks of "the reference target" (its row of the variables table is gone, the other two say "your code"); Harden's says "not a commit of the Airverse repository". `packedGuide` fails when the guide no longer holds these texts.
- `antireverse --help` said "the equivalence gate proves it"; it now says that the gate checks it with `--test`.
- `antireverse -v` and `--version` print the package's version, read from its own `package.json` (tested on the source bin and on the installed tarball).
- `sdk:release-check` and `sdk:published-check` print "Registry asked" only when one was; when the folder itself is refused they say that no registry was asked.
- The printed commands quote paths for a POSIX shell with single quotes (tested with a space, `$`, a backtick, `!` and `'` in the path, by letting a shell echo the argument back).
- A signed release folder holding a tarball whose manifest is `private` is refused by both checks before any registry is asked (automated).
- The public repository is pinned in `tools/sdk/src/packages.ts`; a release is refused when `origin` is another repository.
- The `0.0.0` in `packages/protocol/src/events.ts` is the value of the exported example `EXAMPLE_EVENT_BATCH` (`sdk: { name: "shield-node", version: "0.0.0" }`): sample data that tests and documentation use, not this package's version and not a comment. It ships inside Harden's copy of the protocol as that example and was left.

**Found while fixing B1:** `npx --no-install antireverse`, where the command is not installed, still asks the registry whether a package of that name exists (one metadata request) before it stops; it downloads no tarball and runs nothing. The test shows this against a registry that offers a decoy `antireverse` whose command prints a marker: with `--no-install` the marker never appears and no tarball is requested; with `--yes` it does. The sentence in the texts says "never downloads or runs", not "never asks".

**In a temporary clone under `<tmp>/airverse-sdk-relproof2` (local commit 1ecac6c, never pushed; nothing fetched):** `sdk:release` refused, in turn: uncommitted changes (37); `HEAD` not `origin/main`; an origin that is a local path; an origin that is another repository; an ignored `packages/guard/src/.env.local` (with `git status` empty); a skip-worktree edit of `packages/harden/src/rng.ts` (with `git status` empty). Then, with the clone's origin set to the project's URL and its `origin/main` ref at the local commit, it built: shield-node 87,348 bytes (31 entries), guard 33,592 (12), harden 256,991 (114); Harden's dependencies are `@babel/generator`, `@babel/parser`, `@babel/traverse`, `@babel/types` and `zod`. `sdk:release-check` asked the public registry read-only: all three absent, "ready", commands printed with single quotes. The clone and its tarballs were removed.

**Not test-first in this round:** the `npx --no-install` test passed at once (it describes npm's behaviour); the first version of it, which expected no registry request at all, failed and led to the finding above. The README's and the ticket's wording. Equivalence and the install smoke test were not run inside the clone (the six other SDK test files were).

**Commands run after the fixes (2026-11-28):** the nine Vitest projects → 295 files, 7,501 tests passed; `npx tsc -b` clean; `npx biome check` clean. The five SDK gate checks alone then failed twice on `sdk-signed-manifest` although its 56 tests passed: the gate's scan for test names had taken a string handed to a RegExp's `test` method, and then a comment quoting that shape, for tests that did not run. The test was rewritten; third run: all five pass, `gate-sdk-artifacts-local` pass, 100 s wall on a busy machine (71 s before this round). The Console was not touched and its project was not run; no full gate, no Playwright. `apps/console/tsconfig.json` unchanged.

**Jev on the fixes (`jev_gate`):** action `escalate` — composite 0.70, `safe_to_apply` 0.40. Six claims verified, none contradicted (0.48 to 0.98). Not independently reviewed again.

**Still open for the owner:** reserve the unscoped name `antireverse` on npm (not done, not this slice's to do). Until then `--no-install` is what stands between a missing install and someone else's code. *(Done later on 2026-11-28: a placeholder `antireverse@0.0.1`, D-150.)*

**Limits after the review:**

- The allowlist of what ships covers the code (`dist/`). `README.md`, `LICENSE` and `NOTICE` are read from the working tree, which the clean-tree and skip-worktree checks cover.
- The ignored-file check looks at the four source folders, not at the whole repository: an ignored file elsewhere cannot reach a tarball through the build, and is not refused.
- The pinned repository URL has to be changed in `packages.ts` if the project moves.
- Removing `@babel/core` leaves its 20 packages in an existing `node_modules` until the next `npm ci`; nothing uses them.

### Time budgets run last (2026-11-28)

**What happened.** The full release gate failed twice in a row on the uncommitted tree, on one test: `packages/guard/test/integrity.test.ts`, "worst-case time of plan() (third review F8, PB-06) › 64 Builds of 32 nested same-name paths…" — `expected 25.42 to be less than 25`, then `expected 25.59 to be less than 25`. Guard's code had not changed. Alone the test reads 5.6 ms; inside the full parallel `npm test` (401 files, now with the heavier `sdk` project) about 25 ms. The best of five runs that the test already takes does not filter a slowdown that lasts.

| # | Decision | Jev |
|---|---|---|
| D-147 | (coordinator) Budgets and best-of-five stay as they are; tests with a wall-clock budget run outside the parallel phase | `isolate-timing` 0.69, confidence 0.65; no requirement contradicted. `more-runs` 0.29. Agreed by the coordinator: the contention is sustained (4.4 times), so more runs would not filter it |
| D-148 | The test files that hold such a test run **whole**, late and one at a time; no test file is changed and nothing is extracted | `whole-files-late` 0.87, confidence 0.84; no requirement contradicted. Rejected: extracting each test into a `*.timing.test.ts` file with shared helper modules (it means rewriting the helpers of a 3,000-line security test file before a release), a mix of both. **This differs from what the coordinator's brief suggested** (extraction); the reason is risk, and the cost is that about 900 tests that have no time bound run late too |
| D-149 | Which files: those whose bound measures CPU work, a ratio of two measured times, or the start of a process or worker. A deliberate wait with slack, a poll-interval budget and a hang guard with ample headroom stay where they are | `cpu-and-startup-bound` 0.89, confidence 0.87; no requirement contradicted. Rejected: every file with any time bound (about 40 files, most of api and e2e, minutes of sequential time), only the two that had failed. **This is narrower than "every test that asserts a wall-clock budget"** in the brief; every such assertion is listed below with its numbers |

**As built.**

- `vitest.timing.ts` (repository root) lists the files, each with its project, its kind (`cpu`, `ratio`, `start-up`) and why. Thirteen files today.
- `vitest.config.ts`: every package project comes from one helper; a project with listed files excludes them and gets a twin named `<project>-timing` (`guard-timing`, `shield-node-timing`, `harden-timing`, `prove-timing`, `api-timing`) with the same root, environment and timeout, `fileParallelism: false` and its own `sequence.groupOrder` (1 to 5). Vitest 5.1 runs groups from lowest to highest and gives a project with one worker and an explicit group a group of its own (read in `node_modules/vitest`, and proven by a run, below). No test runs twice and none is skipped.
- `tools/sdk/vitest.dist.config.ts`: the compiled-output run has the same twins from the same list (`shield-node-timing-dist`, `harden-timing-dist`), and the equivalence check's source run names the twins too, so the two runs still hold the same tests.
- `tools/gate/src/matrix.ts`: a file a matrix selects is run in the project that includes it; `campaign-safety` keeps its two redaction files, now run in `api-timing`.
- `tools/gate/test/timing.test.ts`: the list against the root configuration and the matrices, and a real run whose JSON shows every late file starting after the last ordinary file ended, the late files not overlapping, each file once.
- README, Development: how to run one package's tests (`--project guard --project guard-timing`) and where a new timing test goes.

**The files that run late** (values: alone / inside the full run before the change / in the late phase after it):

| File | Kind | Bound | Alone | Full run before | Late phase after |
|---|---|---|---|---|---|
| `packages/guard/test/integrity.test.ts` | cpu | 25 ms (PB-06), five sites | 8.7 | 22.9 (25.4 and 25.6 in the gate) | 8.1 to 8.9 |
| `packages/shield-node/test/decide.test.ts` | cpu | p99 0.5 ms | 0.21 | 0.34 | 0.10 to 0.12 |
| `packages/shield-node/test/patches-differential.test.ts` | ratio | under 10 | 4.8 | 5.1 | 4.6 to 4.9 |
| `packages/shield-node/test/shield.test.ts` | start-up | 2,000 ms | 529 | 793 | 522 to 532 |
| `packages/harden/test/leaks.test.ts` | ratio | under 30 | 21.4 | 12.9 (failed once in the equivalence run) | 10.2 to 10.7 |
| `packages/prove/test/sandbox.test.ts` | start-up | 1,000 ms | 48 | 433 | 41 to 42 |
| `packages/prove/test/assess-worker.test.ts` | start-up | 1.5 s | 1.04 | 1.35 (1.96 and 2.70, failed, beside a second suite) | 1.0 |
| `packages/prove/test/logic.test.ts` | start-up | a 5 s batch limit | — | failed once beside a second suite (a timeout where a refusal was expected) | passed |
| `packages/prove/test/tamper.test.ts` | start-up | 3,000 ms | 372 | 445 | not measured after it was added |
| `packages/prove/test/stand-in.test.ts` | ratio | under 10 | 2.7 | up to 9.3; 10.8 (failed) in one full run | not measured after it was added |
| `apps/api/test/integrity-review.test.ts` | cpu | 250 ms | 16 to 22 | up to 186 | not measured after it was added |
| `apps/api/test/campaign-review-redact.test.ts` | cpu, ratio | 250 ms | 87 | 67 | 13 to 15 |
| `apps/api/test/campaign-review2-redact.test.ts` | cpu | 250 ms | 57 | 50 | 16 to 19 |

The last four were found after the first choice of eight: `assess-worker` and `logic` failed in the busy phase of the first loaded proof runs, `stand-in` failed in one plain full run, and `integrity-review` came out of a search of the measurements for bounds that move with load and came within 40 % of their limit.

**Every upper bound on a measured time in the Vitest projects**, with its largest value alone and inside the full run before the change (found by a temporary hook that logged every `toBeLessThan` and `toBeLessThanOrEqual`; removed again). One row per file and bound; the last column is the full-run value as a share of the bound.

| File | Bound | Alone | Full run | Share |
|---|---|---|---|---|
| `packages/harden/test/cli-gate.test.ts` | 9000 | 8500 | 8500 | 94 % |
| `packages/guard/test/integrity.test.ts` | 25 | 8.7 | 22.9 | 92 % |
| `packages/prove/test/assess-worker.test.ts` | 1.5 | 1 | 1.4 | 90 % |
| `apps/api/test/slo-service.test.ts` | 2000 | 1503 | 1503 | 75 % |
| `packages/shield-node/test/decide.test.ts` | 0.5 | 0.209 | 0.339 | 68 % |
| `packages/shield-node/test/patches-differential.test.ts` | 10 | 4.8 | 5.1 | 51 % |
| `packages/prove/test/sandbox.test.ts` | 1000 | 48.1 | 433 | 43 % |
| `packages/harden/test/leaks.test.ts` | 30 | 21.4 | 12.9 | 43 % |
| `packages/shield-node/test/shield.test.ts` | 2000 | 529 | 793 | 40 % |
| `tests/e2e/policy.http.test.ts` | 15000 | 6014 | 5766 | 38 % |
| `apps/api/test/campaign-review-redact.test.ts` | 250 | 86.8 | 67.3 | 27 % |
| `apps/api/test/notifier.test.ts` | 1500 | 310 | 317 | 21 % |
| `apps/api/test/campaign-review2-redact.test.ts` | 250 | 56.6 | 49.9 | 20 % |
| `packages/prove/test/assess.test.ts` | 8000 | 1507 | 1535 | 19 % |
| `tests/e2e/containment.http.test.ts` | 30000 | 4952 | 5669 | 19 % |
| `packages/prove/test/sandbox.test.ts` | 3000 | 502 | 559 | 19 % |
| `tests/e2e/canaries.http.test.ts` | 15000 | 2376 | 2697 | 18 % |
| `packages/prove/test/assess-worker.test.ts` | 5000 | 802 | 803 | 16 % |
| `packages/shield-node/test/transport.test.ts` | 1000 | 153 | 159 | 16 % |
| `apps/api/test/prove-assessor.test.ts` | 2000 | 301 | 305 | 15 % |
| `packages/prove/test/tamper.test.ts` | 3000 | 372 | 445 | 15 % |
| `apps/api/test/smtp-client.test.ts` | 2000 | 253 | 252 | 13 % |
| `packages/prove/test/logic.test.ts` | 3000 | 258 | 330 | 11 % |
| `apps/api/test/prove-assessor.test.ts` | 3000 | 302 | 306 | 10 % |
| `packages/prove/test/assess.test.ts` | 2000 | 201 | 202 | 10 % |
| `apps/api/test/alert-channels.test.ts` | 1500 | 102 | 108 | 7 % |
| `apps/api/test/campaign-review6-runner.test.ts` | 3000 | 209 | 211 | 7 % |
| `tools/gate/test/run.test.ts` | 8000 | 505 | 509 | 6 % |
| `packages/shield-node/test/counter-store.test.ts` | 0.01 | 0 | 0 | 5 % |
| `tests/e2e/journey.http.test.ts` | 5000 | 229 | 227 | 5 % |
| `apps/api/test/campaign-redact.test.ts` | 500 | 19.1 | 15.9 | 3 % |
| `tests/e2e/detection.http.test.ts` | 10000 | 209 | 205 | 2 % |
| `packages/shield-node/test/patches.test.ts` | 500 | 0.702 | 10 | 2 % |
| `packages/protocol/test/patches.test.ts` | 500 | 1.7 | 9.6 | 2 % |
| `packages/shield-node/test/block.test.ts` | 2000 | 12.4 | 35.9 | 2 % |
| `packages/protocol/test/patches.test.ts` | 1000 | 2 | 17.3 | 2 % |
| `packages/harden/test/leaks.test.ts` | 30000 | 228 | 388 | 1 % |
| `packages/shield-node/test/patches-differential.test.ts` | 2000 | 9.9 | 16.3 | 1 % |
| `packages/harden/test/leaks.test.ts` | 2000 | 6.3 | 12.6 | 1 % |
| `apps/api/test/campaign-review2-transport.test.ts` | 1500 | 5.3 | 6.9 | 0 % |
| `apps/api/test/campaign-review-redact.test.ts` | 100 | 0.324 | 0.453 | 0 % |
| `apps/api/test/assessment-engine.test.ts` | 1000 | 3.4 | 4 | 0 % |
| `tests/e2e/canaries.http.test.ts` | 60000 | 202 | 206 | 0 % |
| `apps/range/test/main.test.ts` | 3000 | 5.7 | 9.4 | 0 % |
| `apps/api/test/integrity.test.ts` | 2000 | 3.2 | 4.4 | 0 % |
| `tests/e2e/campaign-scope.http.test.ts` | 5000 | 6 | 11 | 0 % |
| `apps/api/test/assessment-engine.test.ts` | 2000 | 4.7 | 4.2 | 0 % |
| `packages/shield-node/test/transport.test.ts` | 2000 | 1.3 | 3.5 | 0 % |
| `packages/protocol/test/policy.test.ts` | 50 | 0.025 | 0.029 | 0 % |
| `packages/shield-node/test/express.test.ts` | 5000 | 0.189 | 0.371 | 0 % |
| `tests/e2e/clone-beacon.http.test.ts` | 60000 | 1 | 1 | 0 % |

Rows that stay in the parallel phase are waits and guards: `cli-gate` 8,500 of 9,000 ms and `slo-service` 1,503 of 2,000 ms are timers (the same value alone and under load); the end-to-end budgets wait for poll intervals; the rest have five times or more of headroom in the full run. The browser journeys (`*.e2e.ts`, Playwright) hold budgets too and are not part of `npm test`.

**Proof.**

| What | Result |
|---|---|
| The order | `timing.test.ts` "a real run": in the JSON report every late file starts at or after the end of the last ordinary file, and no two late files overlap. Red first: the list, the twins and the matrix mapping did not exist |
| The whole `npm test`, before | 401 files, 9,598 tests, 256 s; Guard's worst site 22.9 ms of 25 |
| After, nothing else running | 402 files, 9,603 tests, 261 s (with the first eight files late); Guard 8.9 ms |
| After, the final list of thirteen files, plain `npm test` twice | 402 files, 9,603 tests passed both times; 333 s and 307 s. The run is longer than before (256 s): the late files, Prove's with their deliberate waits among them, now run one after another, and the machine had been under load for an hour |
| After, with a second `vitest run --project api` beside it, four runs | 434 s and 449 s (eight files), 394 s and 445 s (eleven files). Guard in the late phase: 8.7, 8.8, 8.1, 8.5 ms. In the same runs the order test's child ran Guard's late file during the busy phase and read 19.4, 22.5, 14.8 and 28.9 ms: the same code, the same machine, the only difference being when it ran |
| What still failed under that extra load | First two runs (before the lighter order test): `mail-message` (a property test, 5 s test timeout), `kill-switch-drill` (20 s test timeout), `assess-worker` (since listed), and the order test itself, which then also judged whether its child's tests passed (it no longer does). Second run of the next pair: `logic.test.ts` (since listed). Third pair: none |
| A real regression still fails | With `plan()` made to do its work three times (a temporary edit of `packages/guard/src/integrity.js`, restored; `git diff` empty afterwards) the two worst-case budget tests still passed alone — the budget has three to four times of headroom when nothing else runs — and a behaviour test failed instead (it counts reads). With five times the work both budget tests failed: 35.0 and 26.9 ms against 25 |

**Commands run at the end (2026-11-28):** `npx tsc -b` exit 0; `npx biome check` on the changed files clean; `gate:release --only` the five SDK checks and `campaign-safety` → all pass (`campaign-safety` 483 tests in 32 files, two of them now in `api-timing`), 114 s for the six. The full gate and Playwright were not run. `apps/console/tsconfig.json` unchanged.

**Jev on the change (`jev_gate`):** action `review` — composite 0.82, `safe_to_apply` 0.57; five claims verified, none contradicted (0.50 to 0.96). Not independently reviewed.

**Limits.**

- A budget on a developer's machine is a proxy: 25 ms here is not 25 ms on a phone. Running the tests alone makes the number repeatable; it does not make it a device measurement.
- Run alone, the budget tests have headroom again, so a regression of less than about three times passes them. That was always so on a quiet machine; the full run had hidden it by eating the headroom.
- The late phase is quiet only as far as this run goes. Another process on the machine still slows it: the gate should not run beside other work.
- The list is kept by a rule and by hand. A new test with a CPU, ratio or start-up bound in a file that is not listed runs in the busy phase until someone lists the file. The search over logged assertions found four files the first reading had missed; it is not automated.
- Two tests failed under the extra load only because of their test timeout (`mail-message`, 88 ms alone; `kill-switch-drill`): not time budgets, not moved.
- About 900 tests without a time bound now run late with their files. It costs a few seconds.
- `vitest run --project guard` alone no longer runs Guard's integrity tests; the twin has to be named. The README and the configuration's header say so.

## Published (2026-11-28)

**Facts** (the owner published; the coordinator verified; this section records it).

- `@antireverse/shield-node@0.1.0`, `@antireverse/guard@0.1.0` and `@antireverse/harden@0.1.0` are on registry.npmjs.org, dist-tag `latest`, built by `sdk:release` from commit `bf1767ab62bb7fb3f882401a9a89ed9771650dd3` in a fresh clone.
- `@antireverse/protocol` is not published and will not be: Harden carries its own copy.
- The unscoped name `antireverse` is held by a placeholder package with no code and no command (`antireverse@0.0.1`, D-150, source in `releases/placeholder-antireverse/`).
- npm `dist.integrity`: shield-node `sha512-Zfry5DTiNT5CWSUJ6XyTjarZwwlognXESayoVUZ/0sJdQf6TWC78YjSa/pwEHhFoeY3EJeLpOHUgn/tFnU+/zQ==`; guard `sha512-Voprp7dbUcNhwW1EdjvDzKMCTSg1TsfYE8NRAWl2ZobnKueN6UJ8QExDe0zUqwLU1NKrSHnIAk5MrFztjp8Ugw==`; harden `sha512-zWGUnyvwcWWF3jqgA47HKenNeqXOvgMqt7ruYoLB493mwkcvf83WYS7lWQUvmVVMIgQpFkBjW/RZy02cswuM7A==`.

**The surprise: staged publishing.** npm did not release the first `npm publish` of each package. It staged it ([docs](https://docs.npmjs.com/staged-publishing/)): the package appeared with a placeholder version `0.0.0-stage`, and 0.1.0 stayed hidden until the owner approved it on npmjs.com under "Staged Packages". Until then `npm view <name>@0.1.0` answered 404, `sdk:published-check` reported the packages absent, and a repeated publish answered `409 Conflict … Cannot publish over previously staged version`. Each package now lists two versions, `0.0.0-stage` and `0.1.0`. Nothing in 23b had foreseen this; the procedure in the README has the step now.

**What was verified, by which command.**

| What | Command | Result |
|---|---|---|
| The registry holds the bytes of the release folder | `npm run sdk:published-check -- dist/sdk-release` (coordinator, after approval) | passed |
| An install by name works | a real `npm install` of the three packages from the registry on Node 22.12 (coordinator) | worked |
| The committed record is signed and whole | `npm run sdk:record-check -- releases/0.1.0` | ok; signer `d21935e30391a6f9320366bb7e41ed2989c675ed168ea0672b92fb1ffaec0196`, commit `bf1767a…` |
| The registry matches the record | `npm run sdk:record-check -- releases/0.1.0 --online` (read-only `npm view`) | the three packages "same" |
| The record's integrities are the published ones | `release.test.ts`, "the release record": the values above are pinned in the test | passes |
| The unscoped name | `npm view antireverse name version maintainers` | `antireverse@0.0.1`, the owner's account |

**What changed in the repository.**

- **Guides.** `README.md`, `docs/getting-started.md`, `docs/shield.md`, `docs/guard.md` and `docs/harden.md` install from npm at the exact version; tarballs and the clone are alternatives; the clone is still how the API and Console run. `docs/harden.md` shows `npx --no-install antireverse` in every command and tells a clone on Node 22.12 its own form once (D-152). `docs/getting-started.md` keeps the clone's commands: it is the page for running Airverse, and a test runs them.
- **Release record** `releases/0.1.0/`: the signed `sdk-manifest.json` and the three bills of materials, copied unchanged from the release folder, and `integrity.json` (sha512 per tarball; derived, not signed). No tarball. `tools/sdk/src/record.ts`, `npm run sdk:record-check -- <dir> [--online] [--expect <fingerprint>]`; Biome leaves `releases/*.*.*` alone so the bytes stay the signed ones.
- **Staging in the tools.** `sdk:release-check` prints two notes after the commands (staging and approval; the harmless 409). `sdk:published-check` tells "the name is there, the version is not listed: may be staged" from "absent".
- **Skill.** The preflight answers `mode: "npm"` with exact versions when no folder is named, without a clone and without asking a registry (D-151). `SKILL.md` installs exact versions with `--save-exact`, never `latest`, and reports the version; new eval case `express-npm-install`.
- **Local packs say what they are.** The header of an `sdk:pack` README, the local manifest's statement and the local bill of materials said "not published"; they now say "local build, not a release". The release statement and the 0.1.0 record are untouched.
- **Gate.** `sec12-sdk-artifacts` stays not checkable; its reason now says that 0.1.0 was published by hand with a local signature and what is still missing (a protected CI pipeline, provenance, two people). No gate check asks the network.

**Decisions.**

| ID | Decision | Jev |
|---|---|---|
| D-151 | With no folder named, the preflight answers for npm, with the exact released version | 1.00, nothing contradicted |
| D-152 | `docs/harden.md` shows the installed command form in its body; the clone form is named once | 0.98, nothing contradicted (the other candidate contradicted "copy the commands unchanged") |

**Limits.**

- No provenance attestation: the signature is the owner's local key. One person built, approved and published.
- `0.0.0-stage` stays listed beside `0.1.0` for each package.
- The text of each npm page is frozen inside 0.1.0. It names its build commit and still carries the sentence that the unscoped name is not the project's; it changes only with a new version.
- The maintainer's npm name and email are public on the registry.
- Nothing checks the registry again on a schedule; `sdk:record-check --online` is run by hand. No gate check uses the network, so the gate does not know whether the registry still matches.
- `integrity.json` is not signed. It is recomputable only by someone who has the tarballs; `--online` compares it with the registry, and the signed manifest's SHA-256 covers the same tarballs.
- **The Console still says the packages are not published** and shows clone commands: `apps/console/src/lib/messages/en.ts` (`setup.unpublished`, `setup.guard.serve`, `setup.harden.where`), `apps/console/src/features/apps/shield-snippet.ts` (`SHIELD_INSTALL`, `hardenCommand`, the Guard import path), `apps/console/src/features/setup/setup-guide.tsx`, with `apps/console/test/setup-components.test.tsx` and `tests/e2e/journey.e2e.ts` asserting those texts. Not changed here: it is interface text with a browser test, and wants its own slice.
- The new eval case was written, not run.

**Before the next release.**

- Bump the three packages' versions; nothing here did. A published version can never be reused.
- The versions written out in text: `RELEASED_VERSION` in `skills/airverse-setup/scripts/preflight.mjs` and the `@0.1.0` in the README and the four guides. A test (`release.test.ts`, "the guides after the first release") ties them to the newest folder under `releases/`, so they must move when the next record is committed, not before.
- The status block that `tools/sdk/src/stage.ts` writes at the top of each npm page ("Early release", the blocked gate, the stand-in scores): reread it against what is true then.
- The `--no-install` sentence in `stage.ts` now says the unscoped name is the project's placeholder; the next version's npm pages will carry it.
- The guides changed, so a rebuild of 0.1.0 no longer gives the published bytes. That is expected; the record, not a rebuild, is the reference for 0.1.0.
- Expect staging again for a first publish of a new package name; whether a new version of an existing package is staged was not observed.
- Commit the record of the next release under `releases/<version>/` after `sdk:published-check` passes, and add its integrities to the test.
- Still missing for `sec12-sdk-artifacts`: a release built in CI with provenance, and a second approver.

