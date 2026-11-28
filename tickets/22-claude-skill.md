---
title: "Ticket 22 — A Claude skill that sets Airverse up in a project"
aliases: [Ticket 22]
project: anti-reverse
doc: TICKET
slice: 22
version: 0.1.0
status: done
updated: 2026-11-24
language: en
tags:
  - anti-reverse
  - ticket
related:
  - "[[PRD]]"
  - "[[QASUITE]]"
---

# 22: Claude skill `airverse-setup`

**What to build:** A skill for Claude that, in a user's own project, adds Shield to the server, Guard to the pages and the Harden step to the build and CI, following the guides in `docs/`, and reports what it verified.

**Asked for by:** the owner, 2026-11-24 ("can Airverse be made a Claude skill?" → yes for the set-up path).

**Out of scope:** an MCP server for the API (operating Airverse from Claude), publishing the packages to npm, a plugin marketplace entry, any skill that launches Campaigns or changes Policies.

**Status:** done on 2026-11-24. Four trial runs, one independent review (2 HIGH, 5 MEDIUM, 6 LOW, all fixed: see Review). The fixes are not independently reviewed, and the corrected skill was not run again on the sample projects.

## Decisions

| # | Decision | Jev |
|---|---|---|
| D-119 | The skill lives in `skills/airverse-setup/` at the repository root: a lean `SKILL.md` (workflow, key rules, decision points, honest limits), a read-only preflight script, and pointers to the clone's `docs/*.md` instead of copies; a test in `tools/gate/test` fails when the skill names a flag, variable, method or guide that no longer exists | 0.98 at confidence 0.98, no requirement contradicted. Rejected: copies of the guides in the skill (drift), `.claude/skills` in this repository (loads only for sessions inside it), a plugin marketplace entry (larger than a first slice) |

## Acceptance criteria

1. `skills/airverse-setup/SKILL.md` has a name, a description that says when to use it, and a body under 500 lines.
2. Every guide path, Harden flag, `AR_` variable and Shield or Guard call it names exists in the repository (test).
3. The skill folder holds no key; the body says keys travel only through environment variables and that Harden is obfuscation, not secrecy (test).
4. `scripts/preflight.mjs` only reads; it finds the clone from `--repo`, `AIRVERSE_REPO` or the working directory, refuses a folder that is not this repository, and prints a Harden command that runs from another folder (test).
5. Tried on sample projects with and without the skill; results recorded below.
6. README says how to install it, what it will not do, and its limits.

## As built

- `skills/airverse-setup/SKILL.md`: preflight, keys, Shield, Guard, Harden, CI, honest limits, what not to do, report shape.
- `skills/airverse-setup/scripts/preflight.mjs`: prints JSON (`repo`, `packages`, `harden.command`, `node`, `notes`, `problems`); exit 0 or 1.
- `skills/airverse-setup/evals/`: two test cases in the layout `claude plugin eval` reads (prompt, expected outcome, one assertion per file).
- `tools/gate/test/skill-airverse-setup.test.ts`: 13 tests (criteria 1 to 4). Seen failing first (10 of 10, files missing), then passing; after the review, four strengthened or new tests seen failing, then passing.
- `README.md`: section "Claude skill", contents link, layout row.

## Trial runs (2026-11-24)

Four runs by fresh agents on two sample projects made for the purpose (not real projects): each project once with the skill and once without. No Airverse API was running and no key existed, by design.

| Case | With the skill | Without the skill |
|---|---|---|
| **Next.js site, user pastes a Shield key and asks for Shield** | Changed nothing; said Next.js is not supported; wrote the key nowhere; told the user to rotate it; offered three ways on | The same outcome |
| **Express shop with an esbuild bundle, a Stripe-looking key in the source, GitHub Actions** | Shield before the routes, keys from the environment, Guard bundled, Harden scripts and a CI step that fails without the secret; found the key in the source, left the line, told the user to rotate it; no allowlist entry; report in the skill's shape, saying nothing was verified against an API | Also wired all three and wrote no key. Added things nobody asked for: signed-request body verification, a loader that lets the server start **without** Shield on an older Node, a switch that turns Guard off, a run-time config route; removed the user's line holding the key; a CI step that warns and passes when the admin key is missing |

What the trial showed:

- **This model reads the guides well without the skill.** On the refusal case the skill changed nothing. Its value was in the larger case: a smaller change, no unrequested switches, a pipeline that fails rather than skips, and a report that separates verified from not verified.
- **The fixture was weaker than intended.** The planted key was an unused constant, so esbuild dropped it and the leak scan never saw it. Both runs found it by reading the source. The skill now says to look through the source as well, and the assertions were reworded.
- **Changes made to the skill afterwards:** how the package link behaves across machines; a localhost Guard endpoint in the bundle trips the leak scan; look for secrets in the source; a missing key fails the CI step; do not add what was not asked for.
- **Not graded formally.** The assertions in `evals/` were read against the two reports by me, not scored by a grader, and no viewer was generated. The improved skill was not run again.

Subagents in this repository's sessions inherit `CLAUDE.md`, so both arms consulted Jev; a user's own session would not.

## Review (2026-11-24)

One independent reviewer checked the skill against the guides and sources and carried the mechanical steps out on a small Express app. No finding concerned a key being written or a destructive action.

| # | Severity | Finding | Fix |
|---|---|---|---|
| H1 | HIGH | `--test "<the project's test command>"` does not work as the skill said: Harden runs the command inside a temporary copy of the bundle folder (`packages/harden/src/equivalence.ts`). `npm test` failed with ENOENT; `cd <project> && npm test` passed while testing the unprotected build | The skill explains where the command runs, forbids the `cd`, and says to leave equivalence unproven rather than fake it. `docs/harden.md` says the same |
| H2 | HIGH | The 404 for `@antireverse/protocol` seen in both Express trial runs was reproduced: it happens when the clone is a real folder inside the project. `install-links` avoids it but then Node refuses to load TypeScript from `node_modules` | The skill says to keep the clone beside the project, in CI too, and not to use `install-links` |
| M1 | MEDIUM | A local or private Guard endpoint fails the leak scan, the skill forbade allowlisting, and Airverse is local-only today: a dead end | The user chooses: a public hostname, or an allowlist entry with their own reason |
| M2 | MEDIUM | `harden.command` starts with this machine's Node path and holds paths with spaces; copied into CI it leaks a home path and breaks | Preflight also prints `harden.portable`; the skill says which form goes where and to quote each element |
| M3 | MEDIUM | "Run through tsx" did not say where tsx comes from | The skill names the three ways and that each changes how the server starts |
| M4 | MEDIUM | Importing Guard through a bundler had no install step, and `packages.guard` pointed at `src` | Preflight prints `packages.guard` (the package) and `packages.guardFiles` (the files to serve) |
| M5 | MEDIUM | The drift test missed invented methods, options and a variable with a digit, and five of its call checks could not fail | Calls are now taken from the skill's text and checked against Shield's sources and Guard's type file; options, package names, the preflight fields the skill names and every file of the skill folder (for keys) are checked |
| LOW | | `--out` equal to the bundle folder overwrites it; report a found secret by file and line, never the value; `--repo=<path>` was ignored and `--repo --json` took a flag as the path; the example key in a test case was format-valid; npm records a relative path; "fails on Node older than 22.23" was stronger than the guide | All corrected |

What held: preflight in every form tried (paths with spaces, a symlink, missing path, Node 20 and 22.23.4) and that it only reads; Shield install and start through tsx; Guard's files served as JavaScript; Harden's report mode and a planted key stopping it with exit 3; flags, exit codes, variables, methods, supported frameworks and Console labels against the guides.

Not tested by the review: anything against a running API or Console, Node 22.13 to 22.22, pnpm and yarn, whether the description triggers.

Still slipping through the drift test, by its design: a real variable used in the wrong role, one real flag swapped for another, an exit code, a Console label.

## Honest limits

- A skill is instructions for a model. A run can still be wrong; the user must read the diff and the report.
- Tried on two made-up projects, four runs, one model. No run was verified against a running API or Console.
- The skill works only from a clone: the packages are not on npm, and `npm install <folder>` records a path that must exist on every machine that installs the project.
- The clone must sit outside the project folder (H2). That is a packaging gap of the unpublished packages; the skill works around it.
- *Note, 2026-11-28:* the two lines above were true when written. Shield, Guard and Harden 0.1.0 are on npm since then and the skill installs from npm by default; see `tickets/23-sdk-packages-supply-chain.md`, "Published (2026-11-28)".
- README's own Harden example still shows `--test "npm test"`, which works only when the bundle folder itself holds the tests (H1); `docs/harden.md` explains.
- The drift test checks names, not meaning: a flag that keeps its name and changes behaviour passes.
