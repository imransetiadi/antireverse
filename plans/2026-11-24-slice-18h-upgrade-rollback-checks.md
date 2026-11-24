---
title: "Plan — Slice 18h upgrade and rollback checks"
aliases: [Plan 18h]
project: anti-reverse
doc: PLAN
slice: 18
version: 0.1.0
status: done
updated: 2026-11-24
language: en
tags:
  - anti-reverse
  - plan
---

# Slice 18h — Upgrade and rollback checks Implementation Plan

> Test first. One worker. Verify by running commands.

**Spec:** [tickets/18h-upgrade-rollback-checks.md](../tickets/18h-upgrade-rollback-checks.md).

## Global constraints

- The three checklist lines (`qa16-upgrade`, `qa16-rollback`, `sec12-kill-switches`) stay not checkable. Nothing local turns them green; the new checks are criteria of the gate's own.
- Tests run in process or on ports the operating system picks; never 8787 or 3000. No request leaves the machine.
- Data directories live under the operating system's temporary directory and are removed. The developer's `apps/api/.data` is never opened, copied or written.
- No migration is added or edited. No npm dependency is added.
- The backup tool prints names, counts and sizes only, and refuses to overwrite without `--force`.
- `apps/console/tsconfig.json` is not touched; no `next typegen`.

## Tasks

Each task: the test first, seen failing, then the code — except where the ticket's "Not test-first" says otherwise.

1. **Era seeds** (`apps/api/test/era-seed.ts`)
   - One seed step per migration that creates tables, in SQL against that migration's schema; two Organizations; keys as hashes of keys generated for the run; an audit chain hashed with the protocol's `auditHash`.
   - `applyEra` (one migration through `migrate()`, then its seed) and `snapshotTables` (every table as JSON).
2. **Upgrade test** (`apps/api/test/upgrade.test.ts`)
   - One database walks 0001…head. After each step: no table without a row. For every step below the head: dump, load as a new database, `migrate()` to the head, `migrate()` again (applies nothing, changes nothing), every earlier row found with every earlier column, then `attachDb` and the app on it: row-level security per tenant and without a tenant, and the routes with the seeded keys (Apps, Events, signed Policy Bundle, audit verification, Incidents, Campaigns).
   - `attachDb(pg)` extracted from `openDb` (`apps/api/src/db/db.ts`): the start-up path over an instance that is already open.
3. **Backup and restore** (`apps/api/src/key-files.ts`, `apps/api/src/backup/backup.ts`, `cli.ts`, `apps/api/test/backup.test.ts`)
   - `KEY_FILES`: the five files beside the data directory, re-exported by `server.ts`.
   - `backupDataDir`: lock, copy to `<to>.partial-<pid>`, manifest (files with size and SHA-256, directories), rename.
   - `restoreDataDir`: read and verify the manifest and every file first; refuse an existing target without `force`; lock; stage beside the target; swap by renames, undone in reverse on a failure.
   - `runBackupCli(argv, io)`; root scripts `data:backup`, `data:restore`.
4. **Rollback rehearsal** (`apps/api/test/rollback-rehearsal.test.ts`)
   - The schema before the head on disk with era seeds and key files → backup → `startApi` (upgrade) and writes over HTTP → both commands refused while it runs → a key file replaced, another removed → restore refused without `--force`, then done → the directory read without the API: old schema, same rows, same key files → `startApi` serves the old state with the keys intact → nothing printed or logged holds key material.
5. **Kill-switch drill** (`tests/e2e/kill-switch-drill.http.test.ts`)
   - A real Shield in front of an Express handler: Rule to monitor and back, Policy roll back, `AR_SHIELD_DISABLED`.
   - The Campaign harness: operator kill and enable, suspend and resume; the service flag `AR_PROVE_CAMPAIGNS` by starting the API with and without it.
   - Audit entries of every switch that is an API action.
6. **Gate** (`tools/gate/src/catalog.ts`, `matrix.ts`, `checks.ts`; tests `catalog`, `matrix`, `cli`)
   - Checks `upgrade-local`, `rollback-local`, `kill-switch-drill` as fixed-file matrices. Criteria `gate-upgrade-local`, `gate-rollback-local`, `gate-kill-switch-drill` (the last also lists `campaign-safety`). Sharper gap reasons on the three checklist lines.
7. **Documents**: README (Release gate, Backup and restore, Commands), OPERATION §10 as-built note, PRD row 18, the ticket.

## Verification

- `npx vitest run --project api --project gate` and `npx vitest run --project e2e`.
- `npx tsc -b`; `npx biome check` on the changed files.
- `npm run gate:release -- --only upgrade-local,rollback-local,kill-switch-drill` with a throw-away `AR_GATE_KEY_FILE`: the three checks pass; their durations are the time added to the gate.
- Mutations of the upgrade test: a temporary migration that rewrites and deletes rows, and one that opens a row-level security policy, must each fail it.
- Not run by the worker: the full release gate and the Playwright suite.
