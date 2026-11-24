---
name: airverse-setup
description: Set up Airverse (the anti-reverse-engineering toolkit, packages @antireverse/*) in the user's own web project. Adds the Shield middleware to an Express or plain Node http server, adds Guard to the pages, runs Harden over the built bundle, registers the Build, and adds the Harden step and score gate to CI. Use this whenever the user wants to install, integrate, wire up or try Airverse, Shield, Guard, Harden or "antireverse" in an app, protect a frontend bundle or an API with it, or asks why a set-up step in the Airverse Console is not marked Done, even if they name only one of the parts.
---

# Set up Airverse in a project

Airverse has three parts a project installs, in this order, and a Console that marks each one **Done** when it sees it work:

1. **Shield**: middleware on the Node server. Records each request and applies the App's Policy.
2. **Guard**: a small browser library. Gets an attestation token and signs requests.
3. **Harden**: a build step over the web bundle. Mangles, encrypts strings, plants Canaries, registers the Build.

Your job is to make these changes in the user's project, prove each one works, and say honestly what it does and does not give them.

## Where the details live

The packages are **not on npm**. They live in a clone of the Airverse repository, and so do the guides. Read the guide for a part before you change code for it; they are reviewed and kept current, and this skill deliberately does not repeat them:

| Part | Guide in the clone |
|---|---|
| The whole path, Console steps | `docs/getting-started.md` |
| Shield | `docs/shield.md` |
| Guard | `docs/guard.md` |
| Harden, registering, CI gate, exit codes | `docs/harden.md` |
| What the score means | `docs/reverse-assessment.md` |

If a guide and this skill disagree, the guide wins.

## Step 0: preflight

Run the preflight script that ships with this skill. It only reads.

```bash
node <this skill's folder>/scripts/preflight.mjs --repo <path to the Airverse clone>
```

Leave `--repo` out if `AIRVERSE_REPO` is set or you are inside the clone. It prints JSON:

- `repo.path`, `packages.shield`, `packages.guard`, `packages.guardFiles`, `packages.docs`, `packages.tsx`: where things are.
- `harden.command`: the command (an array) that runs Harden from any folder, on this machine, now. Quote each element when you run it: the paths may contain spaces. The `antireverse` bin is not a substitute: it fails on Node 22.12 and was tested only on 22.23.4.
- `harden.portable`: the same command starting with plain `node`. Use this form, with the clone's path as the project will see it, in npm scripts and CI files, so that no path from this machine's home directory is written into the project.
- `node.stripsTypes`: whether this Node can load Shield's TypeScript entry by itself.
- `problems`: why it failed. No clone is the usual one: ask the user where their clone is, or whether to clone the repository; do not guess a path. After cloning, `npm install` in the clone.

**Keep the clone outside the project folder**, beside it for example, and do the same in CI (check the project and the clone out as sibling folders). With the clone inside the project, npm tries to fetch Shield's unpublished development dependencies and fails with a 404.

Then look at the user's project before proposing anything: which server framework, how the frontend is built and where the built files land, the test command, the CI system, how environment variables are supplied.

## Keys

The Console shows the **admin key** and each App's **Shield key** once. Treat them like passwords:

- They reach code only through an environment variable (`AR_SHIELD_KEY` for Shield; for Harden, a variable whose *name* you pass with `--key-env`). Never write a key into a source file, a config file, a CI file, a commit or your reply, and never ask the user to paste one into the chat.
- Tell the user which variable to set and where (their shell, their secret store, the CI's secrets); let them set it.
- The **Policy public key** and the **App ID** are not secrets. They may appear in code and config.
- If you find a key already committed in the project, say so and recommend rotating it in the Console.

## Step 1: Shield

Read `docs/shield.md`. In short:

- Supported: **Express** and plain **Node `http`**. For Next.js, Fastify, Koa or anything else, stop and tell the user it is not supported yet. Do not improvise an adapter: a wrong adapter silently records nothing or blocks the wrong thing.
- Install from the clone: `npm install <packages.shield>` in the user's project. npm links the folder and records a relative path to it in `package.json`, so the clone must sit at the same place relative to the project wherever the project is installed (a teammate's machine, CI, the production host). Say so in your report. Keep to this plain form; do not switch npm to copying the package (`install-links`), because Node refuses to load TypeScript from inside `node_modules`. If the install fails, report the error rather than restructuring the project around it.
- Add `createShield({ key, endpoint, policyPublicKey })` and `app.use(shield.express())` **before** the routes, on the application rather than a mounted router. Read `key` and `policyPublicKey` from `AR_SHIELD_KEY` and `AR_POLICY_PUBLIC_KEY`; make the endpoint configurable too.
- Call `await shield.close()` where the server shuts down.
- Shield's entry point is TypeScript. If `node.stripsTypes` is false, plain `node` cannot start the server. The ways out are: add `tsx` to the project as a development dependency and start the server with it, start it with `node --experimental-strip-types`, or move to a newer Node. Each changes how the user's server starts, so propose one and say which you used; for a quick check, `packages.tsx` runs a file without adding anything to the project.
- Without `AR_POLICY_PUBLIC_KEY` Shield only observes. That is the right first state: get the first request into the live feed, then let the user add Rules in the Console, in monitor before enforce.

**Prove it:** start the server with the key set, send one request, and check the Console's Set up page says **First protected request received** (or ask the user to confirm it). If you cannot reach a running API, verify what you can (the server starts, `shield.stats().disabledReason` is empty) and say plainly that the end-to-end check was not done. A missing or malformed key does not crash the server; Shield disables itself and logs one line, so "the server still works" proves nothing.

## Step 2: Guard

Read `docs/guard.md`. In short:

- Either serve the files of `packages.guardFiles` from the site (for example at `/guard/`), or, with a bundler, `npm install <packages.guard>` and import `@antireverse/guard`.
- `createGuard({ appId, endpoint })`, then `await guard.attest()` before the first API call, and send `guard.headers()` with calls; or use `guard.fetch()` to sign requests.
- Signed request bodies need the server side too: `bodyVerified`, `shield.verifyBody` in the body parser and `shield.errorHandler()` after the routes. Only add this if the user wants signed requests.
- The page's Content-Security-Policy `connect-src` must allow the Airverse API and `'self'`.

- The endpoint you give Guard ends up in the bundle, and Harden's leak scan treats a local or private address there (`http://127.0.0.1:8787`) as an internal URL. Build with the real endpoint before hardening. If the real endpoint is itself internal, which is likely while Airverse runs only on the user's own machines, show the user the finding and let them choose: a public hostname, or an allowlist entry with their own reason. That is their decision, not a way for you to get a build through.

A token shows that a Guard-like client completed the handshake, not that the client is genuine. Do not describe Guard as bot protection.

## Step 3: Harden

Read `docs/harden.md`. In short, using `harden.command` from the preflight, run in the user's project:

1. **Report only first**: `harden <bundle-dir> --profile balanced`. Nothing is written.
2. Look through the frontend *source* for secrets yourself as well: a bundler drops an unused constant, so a key can sit in the repository without ever reaching the bundle the scan reads. Report what you find by file and line, never the value, and recommend rotating it; whether to delete the line is the user's call.
3. If the **leak scan** fails (exit 3), stop and show the user the findings. A real secret in a client bundle must be removed and rotated; only a reviewed false positive goes into `.antireverse/leak-allow.json`, with the user's agreement and a reason. Never add an allowlist entry just to get past the scan.
4. **Write and prove equivalence**: add `--out <dir> --test "<command>"`. Harden runs that command inside a temporary copy of the bundle folder with the protected files in place, not in the project root, so `npm test` as it stands will not find the project. Give a command that tests the files in its current directory, naming the test script by absolute path. Do not `cd` back into the project in that command: it would test the unprotected build and "prove" nothing. If the project has no test that can run against a folder of built files, say so and leave equivalence unproven rather than faking it. `<dir>` must be a different folder from the bundle folder, or the input is overwritten. Serve `<dir>` exactly as written; Harden must be the last step that touches those files.
5. **Register**, when the user has an App: `--register --endpoint <url> --key-env <VAR> --app <appId> --environment <env> --build-version <v>`. The Environment must be the one the App was created with. Add `--origin <origin>` for each origin the bundle is served from if they want the Clone Beacon, and `--fail-on high` to fail on known-vulnerable dependencies.
6. `--integrity` and tamper detection by Guard exclude each other for one Build; the guide explains. Ask which the user wants only if they care about tamper detection.

Harden is for software the user owns. If the bundle is someone else's, or the aim is to hide behaviour from a store review, a scanner or a customer, decline that part.

## Step 4: CI

Add the Harden command to the project's pipeline after the build and before the deploy, with the admin key from the CI's secret store under the name given to `--key-env`. A missing key should fail the step, not skip it: a pipeline that quietly ships an unregistered, unhardened build looks protected and is not. The pipeline needs a checkout of the Airverse repository beside the project's checkout, not inside it, with `npm install` run in it, since the packages are not on npm; use Node 22.18 or newer there. Write the command in its `harden.portable` form.

For a score gate, add `--assess T1 --min-rrs <n>` (with `--routes` and `--logic` files the user writes), or a later `gate --assessment <id> --min-rrs <n> --endpoint <url> --key-env <VAR>` step. Exit codes are listed in `docs/harden.md`; make the pipeline fail on any non-zero exit. Ask the user for the threshold instead of inventing one.

## Be honest about what this gives them

Say these when they apply; the user will make decisions on your summary:

- Mangling and string encryption are **obfuscation, not secrecy**. The decoder ships in the bundle. Real secrets must not be in client code at all.
- The Reverse Resistance Score comes from a **scripted stand-in** until a real model is configured: it measures the pipeline, not real resistance.
- Shield's limits, replay protection and counters are per instance. Policies arrive by polling, within about 15 seconds.
- Airverse today is a local, single-process system without user accounts. It is fine for a pilot on the user's own machines, not a hosted production service.

## What not to do

- Do not add what was not asked for. Signed requests, actor keys, a Clone Beacon, a vulnerability gate, a switch that turns protection off, a loader that lets the server start without Shield: each is a decision with consequences. Mention the ones that fit and let the user choose.
- Do not launch a Pentest Campaign, flip a kill switch, delete an Organization, or promote a Rule to enforce for the user. Those are their actions in the Console.
- Do not change the Airverse clone to make an integration work; report the gap.
- Do not mark a step done because the code compiles. Done means the Console saw it, or you say exactly what was not verified.

## Report

Finish with a short summary in this shape:

```markdown
## Airverse set-up

**Done and verified:** <part: how it was verified>
**Done, not verified:** <part: what is missing to verify it>
**Not done:** <part: why>

**You need to:** <variables to set and where, Console actions>
**Limits to know:** <the ones that apply>
```
