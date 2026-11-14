---
title: "Plan — Slice 18e Release-gate runner"
aliases: [Plan 18e]
project: anti-reverse
doc: PLAN
slice: 18
version: 0.1.0
status: done
updated: 2026-11-14
language: en
tags:
  - anti-reverse
  - plan
---

# Slice 18e — Release-gate runner Implementation Plan

> Test first. Verify by running commands.

**Spec:** [tickets/18e-release-gate-runner.md](../tickets/18e-release-gate-runner.md).

## Global constraints

- **Location:** a new workspace `tools/gate` (`@antireverse/gate`), or `scripts/gate` if a workspace is too heavy. It is TypeScript run with `tsx`, and the root scripts are `gate:release` and `gate:verify-report`.
- **Child processes:** checks run as child processes with timeouts. Their output is captured and trimmed.
- **Ports:** the e2e config uses ports 18787 and 13000. The load smoke starts its own API on a free port. Never use ports 8787 or 3000.
- **Catalog test:** it reads QASUITE.md §16 and SECURITY.md §12 checklists, so a new line in either document fails the test until it is mapped.
- **Thresholds:** read from the documents' own numbers where practical (PERFORMANCE §2 for PB-01, PB-02 and PB-21; §3 for SLO targets), or from protocol constants. They are not duplicated by hand.
- **Signing:** Ed25519 through node:crypto. The key file has mode 0600 and lives outside the repository. The report embeds the public key and its fingerprint.
- **No network** unless `--online`.

## A1 — As built (2026-11-14)

- **Workspace:** `tools/gate` (`@antireverse/gate`), with a `gate` project in the root Vitest config.
- **RRS (D-097):** TC-PRV-006 is not checkable until a real agent runs. The stand-in run is the criterion `gate-rrs-regression`, judged against `tools/gate/baselines/rrs-stand-in.json` (24 on both profiles).
- **Integrity:** `runGate` compares the documents with the catalog on every run and reports it as the criterion `gate-integrity`.
- **Matrices:** whole test files chosen by test name, run with the JSON reporter; every matching name must have run and passed.
- **Strictness added by the review:** skipped or todo tests fail; any signal fails; an unreadable threshold fails; SLO targets are read from PERFORMANCE §3 and cross-checked with the protocol catalog.
- **Key guard:** the key file is refused inside the repository by device and inode comparison along the path.
- **Side fixes:** three load-sensitive tests made robust; a Console test that fetched `127.0.0.1:8787` now stubs `fetch`; Biome ignores `reports/gate`.
