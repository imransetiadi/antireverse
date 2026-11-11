---
title: "Plan — Slice 02 policy path"
aliases: [Plan 02]
project: anti-reverse
doc: PLAN
slice: 2
version: 0.1.0
status: done
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - plan
related:
  - "[[PRD]]"
  - "[[SDD]]"
  - "[[SECURITY]]"
  - "[[PERFORMANCE]]"
  - "[[UIUX]]"
---

# Slice 02 — Policy Path Implementation Plan

> **For agentic workers:** implement task by task, test first. Each task is owned by one worker and touches only its own workspace. A task is finished only when its verification commands were run and their output read.

**Goal:** A Rule added in the Console is published as a signed Policy Bundle; Shield fetches, verifies and applies it; matching requests are blocked (Enforce) or marked (Monitor); the Decision is visible in the live feed; rollback is one action.

**Architecture:** The protocol package gains the Policy contract. The API stores Policy versions per App and Environment, signs a bundle with Ed25519 on demand and serves it to the Shield key of that App and Environment. Shield polls for the bundle in the background, verifies signature, audience, version and expiry with `node:crypto`, compiles the Rules into a matcher and decides synchronously on the request path. The Console adds a Policy screen.

**Tech stack:** unchanged from slice 01 — no new dependency anywhere. Ed25519 through `node:crypto`.

**Spec:** [tickets/02-policy-path.md](../tickets/02-policy-path.md). Background: [SDD.md](../SDD.md) §7, §10, §18; [SECURITY.md](../SECURITY.md) SC-KEY-01…03; [PERFORMANCE.md](../PERFORMANCE.md) PB-01, PB-02, PB-16; [UIUX.md](../UIUX.md) §4.2, §7 (SCR-08), §8, §10. Everything in the slice 01 plan's *Global Constraints* and *Verified library facts* still binds ([plan 01](2026-11-10-slice-01-walking-skeleton.md)), including its amendments.

## Global Constraints (additions)

- **No new dependencies.** Shield's runtime dependency list stays empty; Shield validates the bundle by hand, without zod.
- **Rule:** `id` `rul_<24 hex>`; `name` 1–80 characters; `path` pattern 1–256 characters; `methods` 0–8 HTTP methods (empty = all); `action` `block`; `mode` `monitor` | `enforce`. A Policy holds 0–50 Rules, in order.
- **Path pattern:** starts with `/`; segments are literal text (`A–Z a–z 0–9 . _ ~ -`), `*` (exactly one segment) or a final `**` (zero or more segments). Examples: `/api/admin/**`, `/api/users/*/export`, `/login`.
- **Matching:** against the request path without query string; case-insensitive; one trailing slash is ignored; `**` also matches zero segments (`/api/admin/**` matches `/api/admin`). The first Rule in order whose path and method match in Enforce mode decides; otherwise the first matching Monitor Rule marks the request; otherwise the request is allowed.
- **Decision values:** Enforce match → `{ action: "block", mode: "enforce", ruleId, policyVersion }`; Monitor match → `{ action: "block", mode: "monitor", ruleId, policyVersion }` and the request proceeds; no match → `{ action: "allow", mode: "monitor" when policyVersion is 0, else "enforce", ruleId: null, policyVersion }`.
- **Block response:** status 403, `content-type: application/json`, body `{"error":"request_blocked"}`. Nothing else: no Rule identifier, no header.
- **Event of a blocked request:** `request.route` is the Rule's `path` pattern, `request.status` 403, `decision` as above with `rule_id`. Never the concrete path.
- **Bundle payload** (a JSON string, signed as bytes exactly as transmitted): `{ format: 1, audience, app_id, environment, version, issued_at, not_after, rules: [{ id, path, methods, action, mode }] }`. `audience` = first 32 hex characters of the SHA-256 of the Shield key it is issued for. `not_after` = `issued_at` + 7 days. The API re-issues a bundle that is older than 24 h. Maximum size 65,536 bytes.
- **Signature:** Ed25519 over the UTF-8 bytes of the bundle string; transmitted base64url (86 characters). Public key transmitted base64url (43 characters, raw 32 bytes). `key_id` = first 16 hex characters of the SHA-256 of the raw public key.
- **Shield acceptance:** signature verifies with the configured `policyPublicKey`; `format` is 1; `audience` equals the Shield's own; `version` ≥ the applied version; `not_after` is in the future at load; every Rule passes the same bounds as above. Anything else: refuse, keep the last valid Policy, warn once per condition.
- **Shield defaults:** poll every 5,000 ms with jitter, conditional on `ETag`; response body capped at 131,072 bytes; request timeout as for events. Policy version 0 with no Rules is the built-in Policy.
- **Guardrail:** the API refuses a Policy in which an Enforce Rule has the path `/**` (it would block every request).
- **Budgets:** PB-16 publish → applied ≤ 15 s; PB-02 Shield p99 ≤ 0.5 ms with 50 Rules.
- **Signing key:** an Ed25519 key pair owned by the API. With a data directory it is created once in the file `signing-key.json` beside the database (mode 0600); in memory otherwise. Only the public key is ever returned. This is development key handling; a managed key service replaces it later.

## Review Focus

1. **Bypass of a block Rule** — `/API/Admin/x`, `/api/admin/`, `/api/admin?x=1`, `/api/admin` against `/api/admin/**` must all match; a different path (`/api/administrator`) must not. *(Shield)*
2. **A bundle that should not be trusted** — one flipped byte, a valid signature from another key, another Shield key's bundle, an older version, an expired one, 200 Rules, a 1 MB body, invalid JSON: each refused, last valid Policy kept. *(Shield)*
3. **The API unreachable for days** — Shield keeps enforcing; after `not_after` it reports stale; requests are never delayed. *(Shield)*
4. **Publishing mistakes** — a Rule blocking everything in Enforce mode, 51 Rules, a malformed pattern, another Organization's App: each refused with a problem document naming the field. *(API)*
5. **Concurrent publishes** — two publishes at once yield two consecutive versions, never a lost or duplicated one. *(API)*

## Contracts

### P1 — Protocol (`packages/protocol/src/policy.ts`, exported from the isomorphic entry)

```ts
export const RULE_ACTIONS = ["block"] as const
export const POLICY_LIMITS = { rulesMax: 50, pathMax: 256, methodsMax: 8, nameMax: 80, bundleBytesMax: 65_536, versionsListed: 20 } as const
export const PATH_PATTERN: RegExp                     // the grammar of the Global Constraints
export const BLOCK_RESPONSE_BODY = '{"error":"request_blocked"}'

PolicyRuleSchema        = { id, name, path, methods, action, mode }
PolicyRuleInputSchema   = { id?, name, path, methods? (default []), action? (default "block"), mode? (default "monitor") }
PublishPolicyRequestSchema  = { rules: PolicyRuleInput[0..50] }
PolicySchema            = { app_id, environment, version (int >= 0), rules: PolicyRule[], published_at (ISO or null for version 0) }
PolicyResponseSchema    = { policy: Policy }
PolicyVersionsResponseSchema = { versions: [{ version, published_at, rule_count, enforced_count }] }   // newest first, at most 20
RollbackPolicyRequestSchema  = { version }             // int >= 1
BundlePayloadSchema     = { format: 1, audience, app_id, environment, version, issued_at, not_after, rules: [{ id, path, methods, action, mode }] }
SignedBundleSchema      = { bundle: string <= 65536, signature: base64url 86, key_id: 16 hex }
SigningKeyResponseSchema = { key_id, algorithm: "Ed25519", public_key: base64url 43 }
```

Server entry additions: `newId("rul")`; `bundleAudience(shieldKey: string): string`; `keyIdOf(publicKeyRaw: Uint8Array): string`.

Event schema change: none in shape. `decision.rule_id` accepts a Rule identifier; `request.route` accepts a path pattern (it already accepts bounded text).

### P2 — HTTP API additions

| Method and path | Key | Success | Notes |
|---|---|---|---|
| `GET /v1/signing-key` | none | 200 `SigningKeyResponse` | The public key Shield needs |
| `GET /v1/apps/:appId/policies/:environment` | admin | 200 `PolicyResponse` | Version 0 with no Rules when nothing was published |
| `PUT /v1/apps/:appId/policies/:environment` | admin | 201 `PolicyResponse` | Publishes the next version; assigns `id` to Rules without one; 400 on the guardrail |
| `GET /v1/apps/:appId/policies/:environment/versions` | admin | 200 `PolicyVersionsResponse` | — |
| `POST /v1/apps/:appId/policies/:environment/rollback` | admin | 201 `PolicyResponse` | Publishes the Rules of an earlier version as the next version; 404 for an unknown version |
| `GET /v1/policy-bundle` | shield | 200 `SignedBundle` with `ETag`; 304 on `If-None-Match` | The bundle of the key's App and Environment, version 0 included |

Schema (`apps/api/migrations/0002_policies.sql`): table `policy_versions (organization_id, app_id, environment, version, rules jsonb, published_at, published_by)` with primary key `(organization_id, app_id, environment, version)`, row-level security like every tenant table. The next version is computed inside the publishing transaction.

`AppDeps` gains `signer: { keyId: string; publicKey: string; sign(data: Uint8Array): string }`; `startApi` builds it from the data directory. `openDb` is unchanged.

### P3 — Shield additions

```ts
interface ShieldConfig {            // additions
  policyPublicKey?: string          // base64url Ed25519 public key; without it Shield observes only
  policyPollIntervalMs?: number     // 5000
}
type Transport = (request: { method?: "POST" | "GET"; url: string; headers: Record<string, string>;
                             body?: string; timeoutMs: number })
  => Promise<{ status: number; body?: string; etag?: string }>
interface Decision { action: "allow" | "block"; mode: "monitor" | "enforce"; ruleId: string | null; policyVersion: number }
interface DecideInput { method: string; path: string }          // concrete path, used locally only
interface ShieldStats {             // additions
  policyVersion: number; policyStale: boolean; policyRules: number; lastPolicyError: string | null }
interface Shield { refreshPolicy(): Promise<void> }              // fetch now; never rejects
```

New modules: `policy/match.ts` (compile a pattern, match a path), `policy/verify.ts` (signature, audience, bounds — hand-written validation), `policy/poller.ts` (lazy unref'd timer, ETag, backoff, 401 pause), `policy/store.ts` (the applied Policy). `decide` reads the applied Policy only.

### P4 — Console additions

- Route `/apps/[appId]/policy?environment=` (default `development`): Environment switch, current version, Rule list (name, pattern, methods, mode mark), add-Rule form, per-Rule actions *Promote to enforce* / *Back to monitor* / *Remove*, version history with *Roll back*.
- Server Actions: `publishRuleAction` (add), `setRuleModeAction`, `removeRuleAction`, `rollbackPolicyAction`. Each publishes one new version and re-renders. Promoting to Enforce and rolling back need a confirmation that names the Environment.
- The App-created screen and the Policy screen show the policy public key as `AR_POLICY_PUBLIC_KEY` for the set-up snippet.
- Live feed: a Blocked Decision in Enforce mode is a solid chip; in Monitor mode it is the dashed chip plus the Monitor mark. An Allowed Decision under a published Policy has no Monitor mark.
- Navigation between Live and Policy for an App.
- Copy keys to add (English): `policy.title` "Policy", `policy.version` "Version {version}", `policy.none` "No Rules yet. Shield observes every request and blocks nothing.", `policy.rule.name` "Rule name", `policy.rule.path` "Path pattern", `policy.rule.path.help` "For example /api/admin/** — * is one segment, ** is everything below.", `policy.rule.methods` "Methods", `policy.rule.methods.all` "All methods", `policy.rule.add` "Add Rule", `policy.rule.promote` "Promote to enforce", `policy.rule.demote` "Back to monitor", `policy.rule.remove` "Remove", `policy.confirm.promote` "Promote to enforce in {environment}? Requests matching {path} will be blocked.", `policy.confirm.rollback` "Roll back {environment} to the Rules of version {version}?", `policy.history` "History", `policy.rollback` "Roll back", `policy.applied` "Shields apply a new version within 15 seconds.", `policy.key.title` "Policy public key", `policy.key.help` "Shield accepts only Policies signed with this key.", `policy.guardrail` "A Rule that blocks every request cannot be enforced.", `nav.live` "Live", `nav.policy` "Policy".

## Tasks

Order: Task 1 → three lanes in parallel (**A:** 2 · **B:** 3, 4 · **C:** 5) → Task 6 → Task 7.

### Task 1: Protocol — Policy contract

**Files:** `packages/protocol/src/policy.ts`, exports, `test/policy.test.ts`; update `test/entrypoints.test.ts`.

- [ ] Failing tests: pattern grammar accepts `/`, `/login`, `/api/admin/**`, `/api/users/*/export`, `/a.b_c~d-e` and rejects `api`, `/a//b`, `/a/**/b`, `/a/*x`, `/a b`, `/a?x`, `/a#x`, `/%61`, 257 characters, control characters; Rule defaults (`methods` `[]`, `action` `block`, `mode` `monitor`); 51 Rules rejected; method list of 9 rejected and unknown method text rejected; `bundleAudience` is 32 lowercase hex and differs per key; `keyIdOf` is 16 hex; `SignedBundleSchema` rejects a 65,537-character bundle and a signature of the wrong length; unknown keys are stripped.
- [ ] Run (fail) → implement → run (pass).

### Task 2: API — Policies, signing, bundle

**Files:** `apps/api/migrations/0002_policies.sql`, `src/signer.ts`, `src/stores/policies.ts`, `src/routes/policies.ts`, `src/routes/bundle.ts`, wiring in `app.ts`/`server.ts`/`index.ts`, tests.

- [ ] Failing tests
  - signing key: `GET /v1/signing-key` returns a key that verifies a signature made by the signer; the response and the log never contain the private key; a data directory keeps the same key across restarts and the file mode is 0600.
  - read: an App without a published Policy has version 0 and no Rules.
  - publish: version 1 then 2; Rules keep their order; a Rule without `id` gets one, with `id` keeps it; `published_at` set.
  - validation: 51 Rules, a malformed pattern, an unknown method, an Enforce Rule with `/**` → 400 with `errors[].path` naming the Rule and field; nothing stored.
  - tenancy: another Organization gets 404 on read, publish, versions and rollback; a Shield key gets 403 on the admin routes.
  - versions: newest first, at most 20, with `rule_count` and `enforced_count`.
  - rollback: publishes the Rules of the named version as the next version; unknown version → 404.
  - concurrency: 10 parallel publishes give versions 1–10 exactly once each.
  - bundle: a Shield key gets a `SignedBundle` whose signature verifies with the public key, whose payload has `audience = bundleAudience(key)`, the App, the Environment, the current version and its Rules, `not_after = issued_at + 7 d`; version 0 before any publish; an admin key → 403; no key → 401.
  - bundle caching: same `ETag` while nothing changes; `If-None-Match` → 304 without body; a publish changes the `ETag`; a bundle older than 24 h (injected clock) is re-issued with a new `issued_at`.
  - isolation: the bundle of App A's production key never contains Rules of App A's development Environment or of another App.
  - `HEAD` and bodies: none of the new routes opens a stream; request bodies obey the existing limit.
- [ ] Run (fail) → implement → run (pass).

### Task 3: Shield — matcher, verification, Policy store

**Files:** `packages/shield-node/src/policy/*`, tests.

- [ ] Failing tests
  - matcher: the Review Focus 1 table; `*` matches exactly one segment; `**` zero or more; literal dots; method list empty = all; method match is exact uppercase.
  - order: first Enforce match wins over an earlier Monitor match being merely recorded; Monitor match alone marks; no match allows; `policyVersion` reported.
  - verification: a valid bundle (signed in the test with `node:crypto`) is applied; each case of Review Focus 2 is refused with a distinct `lastPolicyError` and the previous Policy stays applied; a bundle with the same version and newer `issued_at` refreshes `not_after`; a bundle with extra unknown keys is accepted and the keys ignored.
  - no `policyPublicKey`: nothing is fetched, `policyVersion` stays 0, one informational warning.
  - staleness: after `not_after` passes (injected clock) `policyStale` is true and Rules still apply.
- [ ] Run (fail) → implement → run (pass).

### Task 4: Shield — poller, `decide`, middleware, benchmark

**Files:** `packages/shield-node/src/policy/poller.ts`, changes in `shield.ts`, `decide.ts`, `express.ts`, `transport.ts`, `types.ts`, `bench/overhead.bench.ts`, tests; `apps/range` gains `AR_POLICY_PUBLIC_KEY` and a route `GET /api/admin/reports`.

- [ ] Failing tests
  - poller (fake transport, fake clock): first fetch soon after creation, then every 5,000 ms with jitter; sends `If-None-Match`; 304 changes nothing; a failing transport backs off and never rejects; 401 pauses 60,000 ms; the timer is unref'd (child-process exit test still passes); `refreshPolicy()` fetches at once; `close()` stops it.
  - middleware: with an Enforce Rule on `/api/admin/**`, `GET /api/admin/reports` answers 403 with exactly the block body and the handler never runs; `GET /api/products/1` is untouched; the Event has route `/api/admin/**`, status 403, Decision block/enforce with the Rule's id; the concrete path is in no Event.
  - Monitor Rule: response identical with and without Shield; Event has the real route template and Decision block/monitor.
  - fail-open: when matching throws, the request proceeds and `internalErrors` increases.
  - `decide` stays synchronous and does no I/O; the default transport handles `GET` with a capped response body.
  - benchmark: 50 Rules loaded, a path matching none, p99 ≤ 500 µs.
- [ ] Run (fail) → implement → run (pass); `npm run bench` passes.

### Task 5: Console — Policy screen and Blocked states

**Files:** `apps/console/src/app/apps/[appId]/policy/page.tsx`, `src/features/policy/*`, actions, API client additions, components, catalog, tests.

- [ ] Failing tests
  - API client: the five new calls send the session key, validate responses, map problems to typed errors.
  - actions: `publishRuleAction` appends a Rule in Monitor mode and publishes; `setRuleModeAction` changes only that Rule; `removeRuleAction`; `rollbackPolicyAction`; each requires a session; validation errors from the API come back per field; the guardrail message is shown for the block-everything case.
  - components: the Rule list shows name, pattern, methods ("All methods" when empty) and the mode mark (dashed Monitor, solid Enforce); promoting opens a confirmation naming Environment and pattern; the version history offers Roll back with its confirmation; the empty state reads `policy.none`.
  - live feed: a block/enforce Event renders the solid Blocked chip without Monitor mark; block/monitor renders the dashed chip with it; allow under `policy_version` ≥ 1 renders Allowed without the Monitor mark; allow at version 0 keeps it.
  - copy: every key of P4 reads exactly as specified.
- [ ] Run (fail) → implement → run (pass); type-check, lint and `next build` pass.

### Task 6: End to end

- [ ] HTTP journey: publish an Enforce Rule for `/api/admin/**`; within 15,000 ms a request to the customer server's `/api/admin/reports` answers 403 and its handler did not run; the stream delivers the Blocked Event with the pattern as route; a Monitor Rule on `/api/products/**` leaves the response unchanged and marks the Event; rollback to the version without the Enforce Rule lets the request through again within 15,000 ms; a second Organization cannot read or publish the Policy.
- [ ] Browser journey: add the Rule in the Console, promote it with the confirmation, see the Blocked row; roll back and see an Allowed row.

### Task 7: Documentation and full verification

- [ ] README (Policies, `AR_POLICY_PUBLIC_KEY`, limits), ticket proof table, memory; `npm run verify`, `npm run e2e`, `npm run bench`; independent review and fixes.

## Deliberately not in this slice

Conditions on Rules, other actions, percentage rollout, per-route fail-closed, Dynamic Lists, a push channel, simulation, Safe mode, an audit log, managed signing keys, key rotation.

## Amendments after the independent review

Decisions marked *Jev* were taken with `jev_decide` (owner's rule, 2026-11-10); the broad-Rule choice was the owner's.

| Finding | Change | Decided by |
|---|---|---|
| Static files under a blocked path were reachable through encoded, dot-segment, double-slash and backslash variants | Shield matches the raw path and resolved forms at each decoding depth (0–3 rounds, backslash as text and as a separator); a Rule matches when any form matches. Only adds blocks | Jev (dual matching, 0.72); the extra depths came from the fix lane's own reproduction |
| Concurrent Console edits could silently undo each other | Publish and rollback carry `expected_version`; a stale one is refused with 409 `conflict`; every Policy form carries the version the page showed | Jev (1.0) |
| Long paths cost about 3 ms per request | The path is split once per decision; `*` costs O(1) per Rule | — |
| After a database reset Shields refused every new Policy | Every database has a random `epoch` in the signed bundle; versions compare within one epoch; a bundle of a new epoch must be issued after the applied one | Jev (epoch 1.0; issue-time check 0.94) |
| `/*` and `/*/**` could be enforced like any Rule | An enforced Rule whose first segment is a wildcard needs `allow_broad` at the API and, in the Console, a stronger confirmation with the Environment typed; `/**` stays refused | Owner (Jev leaned to the literal guardrail only, 0.45) |

New API route: `GET /v1/apps/:appId/policies/:environment/versions/:version` (the Console reads a rollback target to decide whether the stronger confirmation applies). Migration `0003_epoch.sql`.
