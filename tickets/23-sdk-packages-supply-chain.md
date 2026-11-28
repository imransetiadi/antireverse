---
title: "Ticket 23 — Installable SDK packages and their supply chain"
aliases: [Ticket 23]
project: anti-reverse
doc: TICKET
slice: 23
version: 0.1.0
status: done
updated: 2026-11-24
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

- **Local only.** No CI pipeline, no provenance attestation, no second approver, no published package, no rings, no yank. `sec12-sdk-artifacts` stays not checkable.
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
- The `@antireverse` scope was unregistered when this slice was built. The owner registered it on 2026-11-28 (the owner's statement, not checked from the repository); nothing is published under it.
