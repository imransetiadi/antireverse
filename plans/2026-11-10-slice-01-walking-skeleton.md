---
title: "Plan — Slice 01 walking skeleton"
aliases: [Plan 01]
project: anti-reverse
doc: PLAN
slice: 1
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
  - "[[QASUITE]]"
  - "[[UIUX]]"
---

# Slice 01 — Walking Skeleton Implementation Plan

> **For agentic workers:** implement this plan task by task, test first. Each task is owned by exactly one worker and touches only the files it lists. Steps use checkbox (`- [ ]`) syntax for tracking. A task is finished only when its verification commands were run and their output read.

**Goal:** A person creates an Organization and an App in the Console, adds Shield to an Express server, sends a request, and sees it in the Console live feed within five seconds — with Shield in Monitor mode.

**Architecture:** An npm-workspaces monorepo. `@antireverse/protocol` defines the wire contract once. `@antireverse/shield-node` (zero runtime dependencies) decides locally and ships Events in background batches. `@antireverse/api` (Hono on Node, embedded PostgreSQL with row-level security) authenticates keys, ingests Events idempotently and fans them out over server-sent events. `@antireverse/console` (Next.js App Router) keeps the admin key in an httpOnly cookie, calls the API from the server only and proxies the live stream to the browser.

**Tech stack:** Node 22, TypeScript, npm workspaces, Hono, PGlite (PostgreSQL in-process), zod, Express (for the reference target and the Shield adapter), Next.js + React + Tailwind, Vitest, Playwright, Biome. Exact pins are in *Verified library facts* at the end.

**Spec:** [tickets/01-walking-skeleton.md](../tickets/01-walking-skeleton.md) — acceptance criteria. Background: [PRD.md](../PRD.md) §9, [SDD.md](../SDD.md) §4–§11, [SECURITY.md](../SECURITY.md) §7–§8, [PERFORMANCE.md](../PERFORMANCE.md) §2–§5, [QASUITE.md](../QASUITE.md) §6, [UIUX.md](../UIUX.md) §4–§12. Vocabulary: [MEMORY.md](../MEMORY.md) §3.

**Version control:** the folder is not a Git repository and nothing is committed unless the owner asks. Each task ends with a verification record instead of a commit.

## Global Constraints

Every task's requirements include this section.

- **Runtime:** Node `>=22.12`, ESM only (`"type": "module"`), npm workspaces. No global installs. All dependency versions are exact pins.
- **Workspace names:** `@antireverse/protocol`, `@antireverse/shield-node`, `@antireverse/api`, `@antireverse/console`, `@antireverse/range`, `@antireverse/e2e`.
- **Ports:** API `8787`, Console `3000`, range `4010`; every server binds `127.0.0.1` unless `HOST` says otherwise; tests listen on port `0`.
- **Keys:** admin key `aro_<43 base64url chars>`; Shield key `ark_<prod|stg|dev>_<43 base64url chars>` (32 random bytes). Stored only as SHA-256 hex. Returned exactly once, at creation. Never written to a log line, an error message or a URL.
- **Identifiers:** `org_<24 hex>`, `app_<24 hex>`, `key_<24 hex>` (12 random bytes). Event identifiers are UUID version 7.
- **Tenancy:** every tenant-owned row carries `organization_id`; row-level security is enabled and forced on every tenant table; request queries run as the non-superuser role `ar_app` inside one transaction with `app.tenant_id` set for that transaction only.
- **Trust:** Organization, App and Environment of an Event come from the Shield key. Values supplied by a client are ignored.
- **Privacy allowlist for an Event:** `event_id`, `ts`, `type`, `surface`, `request.method`, `request.route` (the route template, or the literal `(unmatched)`), `request.status`, `request.latency_ms`, `decision.*`, `actor.ip_prefix` (IPv4 `a.b.c.0/24`; IPv6 the first three groups without leading zeros followed by `::/48`; IPv4-mapped IPv6 is treated as IPv4), `signals` (empty in this slice). Unknown keys are stripped at every level before storage.
- **Limits:** batch 1–500 Events; request body ≤ 262,144 bytes; `route` ≤ 256 characters; `status` 100–599; `latency_ms` 0–600,000; names 1–80 characters after trimming; event list `limit` 1–200 (default 50); at most 20 concurrent live streams per Organization.
- **Errors:** `application/problem+json` with `type`, `title`, `status`, optional `detail` and `errors: [{ path, message }]`. Unauthenticated → 401 with `WWW-Authenticate: Bearer`. Wrong kind of key → 403. A resource outside the caller's Organization → 404.
- **Shield safety:** `decide` is synchronous and performs no I/O. Shield never throws into the host application, never changes a response and never keeps the process alive. Runtime `dependencies` of `@antireverse/shield-node` stay empty.
- **Shield transport:** the default transport uses `node:http`/`node:https` with an unref'd socket, never `fetch`, so an in-flight send cannot delay process exit. One Event is recorded per request on the response's `close` event.
- **Shield defaults:** flush interval 1,000 ms; batch size 100; buffer 10,000 Events (drop oldest, count drops); request timeout 5,000 ms; up to 3 attempts per batch with backoff 500 / 1,000 / 2,000 ms plus jitter; after a 401 or 403, pause sending for 60,000 ms.
- **Budgets:** PB-02 — Shield adds p99 ≤ 0.5 ms per request; PB-13 — an Event is visible in the Console within 5 s.
- **Interface:** tokens, vocabulary and states exactly as UIUX.md §4, §10, §11; dark theme only; every user-facing string comes from the message catalog; no emoji as icons.
- **Language:** glossary terms of MEMORY.md §3 in code, tests and copy (`Organization`, `App`, `Environment`, `Event`, `Decision`, `Monitor mode`, `Shield`).
- **Tests:** red, then green. Tests exercise behaviour through a module's interface. Synthetic data only.
- **Parallel work rule:** a worker edits only its own workspace directory, runs no `npm install`, and reports any change it needs in root files or another workspace instead of making it.

## Review Focus

Conditions the ticket implies and that are most likely to bite a real user. Each has its pinning test in the task named.

1. **Ingest is down or slow while the customer's server is busy** — responses stay identical, memory stays bounded, drops are counted, no unhandled rejection, the process still exits. *(Tasks 5, 6)*
2. **A batch is half valid** — the whole batch is refused with the path of the first invalid Event and nothing is stored. *(Task 4)*
3. **A stream consumer disappears, or the API restarts while the Console is open** — subscriptions are released; the Console shows Reconnecting and recovers without a reload. *(Tasks 4, 10)*
4. **Requests with parameters, nested routers, query strings or no matching route** — only the route template or `(unmatched)` is recorded; identifiers and secrets in the URL never leave the server. *(Task 6)*
5. **The wrong key in the wrong place** — malformed, unknown, revoked, an admin key at ingest, a Shield key at Console endpoints, another Organization's App identifier — each gets 401, 403 or 404 without revealing whether the resource exists. *(Tasks 3, 4)*

## File structure

```text
package.json  tsconfig.base.json  biome.json  vitest.config.ts  .gitignore  .nvmrc  .npmrc  README.md
.claude/launch.json
packages/
  protocol/         src/index.ts  events.ts  api.ts  problem.ts  constants.ts      (isomorphic)
                    src/server.ts  ids.ts  keys.ts                                   (node:crypto; entry "./server")
                    test/*.test.ts
  shield-node/      src/index.ts  shield.ts  decide.ts  emitter.ts  express.ts  ip.ts  uuidv7.ts  types.ts
                    test/*.test.ts   bench/overhead.bench.ts
apps/
  api/              migrations/0001_init.sql
                    src/main.ts  app.ts  config.ts  log.ts  problem.ts  bus.ts
                    src/db/db.ts  migrate.ts
                    src/auth/authenticate.ts
                    src/stores/organizations.ts  apps.ts  keys.ts  events.ts
                    src/routes/organizations.ts  apps.ts  ingest.ts  events.ts  health.ts
                    test/*.test.ts
  range/            src/server.ts  main.ts     test/server.test.ts
  console/          src/app/layout.tsx  globals.css  page.tsx
                    src/app/sign-in/page.tsx  apps/page.tsx  apps/new/page.tsx  apps/[appId]/live/page.tsx
                    src/app/api/apps/[appId]/events/stream/route.ts
                    src/app/actions.ts
                    src/lib/session.ts  api.ts  format.ts  t.ts  messages/en.ts
                    src/components/*.tsx
                    src/features/live-feed/feed-state.ts  use-event-stream.ts  live-feed.tsx
                    test/*.test.ts(x)
tests/
  e2e/              helpers/servers.ts  journey.http.test.ts  journey.e2e.ts  playwright.config.ts
```

Responsibilities: one file, one job. `app.ts` only composes routes; stores only run SQL; routes only translate HTTP to store and bus calls.

## Contracts

These are the decisions every task shares. Names and shapes are exact.

### C1 — Protocol package

Entry `@antireverse/protocol` (safe for browsers): constants, zod schemas, inferred types.

```ts
export const PROTOCOL_VERSION = 1
export const ENVIRONMENTS = ['production', 'staging', 'development'] as const
export type Environment = (typeof ENVIRONMENTS)[number]
export const UNMATCHED_ROUTE = '(unmatched)'
export const LIMITS = { batchMax: 500, bodyBytesMax: 262_144, routeMax: 256, nameMax: 80,
                        listDefault: 50, listMax: 200, streamsPerOrganization: 20 } as const

// One Event as Shield sends it
ShieldEventSchema = {
  event_id: uuid (version 7),
  ts: ISO-8601 UTC datetime string,
  type: 'request.decision',
  surface: 'api',
  request: { method: string 1..16 uppercase, route: string 1..256, status: int 100..599, latency_ms: number 0..600000 },
  decision: { action: 'allow'|'monitor'|'challenge'|'throttle'|'block'|'deceive',
              mode: 'monitor'|'enforce', rule_id: string|null, policy_version: int >= 0 },
  actor: { ip_prefix: string <= 64 | null },
  signals: array (max 32) of { id: string <= 64, confidence: number 0..1 },
}
EventBatchSchema  = { protocol: literal 1, sdk: { name: string <= 32, version: string <= 32 }, events: ShieldEvent[1..500] }
StoredEventSchema = ShieldEvent + { organization_id, app_id, environment, received_at }

// API bodies
CreateOrganizationRequestSchema  = { name }                       // trimmed, 1..80
CreateOrganizationResponseSchema = { organization: { id, name, created_at }, admin_key: { key, prefix, last4 } }
OrganizationResponseSchema       = { organization: { id, name, created_at } }
CreateAppRequestSchema           = { name, environment? }         // default 'development'
CreateAppResponseSchema          = { app: { id, name, created_at }, shield_key: { key, prefix, last4, environment } }
AppResponseSchema                = { app: { id, name, created_at } }
ListAppsResponseSchema           = { apps: App[] }
ListEventsResponseSchema         = { events: StoredEvent[] }      // newest first
IngestResponseSchema             = { accepted: int, duplicates: int }
ProblemSchema                    = { type, title, status, detail?, errors?: [{ path, message }] }
```

All object schemas strip unknown keys. Entry `@antireverse/protocol/server` (Node only):

```ts
export function newId(prefix: 'org' | 'app' | 'key'): string
export type KeyKind = 'admin' | 'shield'
export function generateKey(kind: 'admin'): GeneratedKey
export function generateKey(kind: 'shield', environment: Environment): GeneratedKey
export interface GeneratedKey { key: string; prefix: string; last4: string }   // prefix = scheme + first 6 secret chars
export function parseKey(key: unknown): { kind: 'admin' } | { kind: 'shield'; environment: Environment } | null
export function hashKey(key: string): string                                    // SHA-256, 64 lowercase hex
```

### C2 — HTTP API

| Method and path | Key | Success | Notes |
|---|---|---|---|
| `POST /v1/organizations` | none | 201 `CreateOrganizationResponse` | Creates the Organization and its first admin key |
| `GET /v1/organization` | admin | 200 `OrganizationResponse` | The caller's Organization |
| `POST /v1/apps` | admin | 201 `CreateAppResponse` | Creates the App and one Shield key for the chosen Environment |
| `GET /v1/apps` | admin | 200 `ListAppsResponse` | Newest first |
| `GET /v1/apps/:appId` | admin | 200 `AppResponse` | 404 outside the Organization |
| `GET /v1/apps/:appId/events?limit=` | admin | 200 `ListEventsResponse` | 404 outside the Organization; 400 on a bad limit |
| `GET /v1/apps/:appId/events/stream` | admin | 200 `text/event-stream` | Messages: `id: <event_id>`, `event: security-event`, `data: <StoredEvent JSON>`; comment heartbeat every 15 s; 429 over the stream limit |
| `POST /v1/events` | shield | 202 `IngestResponse` | Atomic per batch; idempotent on `(organization, event_id)` |
| `GET /healthz` | none | 200 `{ "status": "ok" }` | — |

### C3 — Shield

```ts
export interface ShieldConfig {
  key: string
  endpoint: string                      // base URL of the Airverse API
  flushIntervalMs?: number              // 1000
  maxBatchSize?: number                 // 100
  maxBufferSize?: number                // 10000
  requestTimeoutMs?: number             // 5000
  disabled?: boolean                    // default: process.env.AR_SHIELD_DISABLED === '1'
  clientAddress?: (req: unknown) => string | undefined   // default: the socket's remote address
  logger?: { warn(message: string): void }               // default: console; one line per distinct condition
  transport?: Transport                 // injectable for tests; default: node:http(s) request on an unref'd socket
  now?: () => number                    // injectable clock, milliseconds
}
export type Transport = (request: { url: string; headers: Record<string, string>; body: string; timeoutMs: number })
  => Promise<{ status: number }>
export interface Decision { action: 'allow'; mode: 'monitor'; ruleId: null; policyVersion: 0 }
export interface ShieldStats { buffered: number; sent: number; dropped: number; failedBatches: number;
                               internalErrors: number; disabledReason: string | null; lastError: string | null }
export interface Shield {
  decide(input: { method: string; route: string }): Decision
  express(): (req: any, res: any, next: (err?: unknown) => void) => void
  flush(): Promise<void>
  close(): Promise<void>
  stats(): ShieldStats
}
export function createShield(config: ShieldConfig): Shield   // never throws; bad config yields a disabled Shield
```

### C4 — API internals

```ts
// db/db.ts
export interface Queryable { query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }> }
export type Scope = { organizationId: string } | 'none'
export interface Db { tx<T>(scope: Scope, fn: (q: Queryable) => Promise<T>): Promise<T>; close(): Promise<void> }
export function openDb(options?: { dataDir?: string }): Promise<Db>      // no dataDir = in-memory; applies migrations

// bus.ts
export interface EventBus {
  publish(event: StoredEvent): void
  subscribe(filter: { organizationId: string; appId: string }, onEvent: (event: StoredEvent) => void): () => void
  count(organizationId?: string): number
}
export function createEventBus(): EventBus

// app.ts
export interface AppDeps { db: Db; bus: EventBus; now?: () => Date; heartbeatMs?: number;
                           logger?: { info(line: string): void; warn(line: string): void } }
export function createApp(deps: AppDeps): Hono
```

### C5 — Schema (`apps/api/migrations/0001_init.sql`)

```sql
CREATE TABLE organizations (
  id text PRIMARY KEY, name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE apps (
  id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE api_keys (
  id text PRIMARY KEY, organization_id text NOT NULL REFERENCES organizations(id),
  kind text NOT NULL CHECK (kind IN ('admin','shield')),
  app_id text REFERENCES apps(id),
  environment text CHECK (environment IN ('production','staging','development')),
  key_hash text NOT NULL UNIQUE, prefix text NOT NULL, last4 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
  CHECK ((kind = 'shield') = (app_id IS NOT NULL AND environment IS NOT NULL)));
CREATE TABLE events (
  organization_id text NOT NULL, event_id uuid NOT NULL,
  app_id text NOT NULL, environment text NOT NULL,
  ts timestamptz NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
  type text NOT NULL, payload jsonb NOT NULL,
  PRIMARY KEY (organization_id, event_id));
CREATE INDEX events_recent ON events (organization_id, app_id, received_at DESC, event_id DESC);
```

followed by: the role `ar_app` (no login, no superuser, no bypass) with `SELECT, INSERT, UPDATE` on the four tables; `ENABLE` and `FORCE ROW LEVEL SECURITY` on each; one policy per table comparing the tenant column (`id` for `organizations`, `organization_id` elsewhere) with `NULLIF(current_setting('app.tenant_id', true), '')` in both `USING` and `WITH CHECK` (the setting reverts to an empty string, not NULL, after a transaction); and

```sql
CREATE FUNCTION auth_lookup_key(p_hash text)
RETURNS TABLE (key_id text, organization_id text, kind text, app_id text, environment text)
LANGUAGE sql SECURITY DEFINER SET search_path = public
AS $$ SELECT id, organization_id, kind, app_id, environment
      FROM api_keys WHERE key_hash = p_hash AND revoked_at IS NULL $$;
REVOKE ALL ON FUNCTION auth_lookup_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_lookup_key(text) TO ar_app;
```

The Event primary key includes the Organization so that one tenant can never occupy another tenant's event identifiers.

### C6 — Console

- **Session:** cookie `ar_admin` holds the admin key: `httpOnly`, `sameSite: 'lax'`, `path: '/'`, `secure` when `NODE_ENV === 'production'`, `maxAge` 604,800 s.
- **Server-only API client** (`src/lib/api.ts`): reads `AR_API_URL` (default `http://127.0.0.1:8787`), sends the key from the cookie, validates every response with the protocol schemas, maps problems to typed errors (`UnauthorizedError`, `NotFoundError`, `ValidationError`, `ApiError`) whose messages never contain a key.
- **Routes:** `/` (create Organization or go to sign-in; signed-in users go to `/apps`) · `/sign-in` (paste an admin key) · `/apps` (list, empty state) · `/apps/new` (create App; shows the Shield key once with the set-up snippet and a waiting state) · `/apps/[appId]/live` (live feed) · `GET /api/apps/[appId]/events/stream` (proxy; `appId` must match `^app_[0-9a-f]{24}$`).
- **Server Actions** (`src/app/actions.ts`): `createOrganizationAction`, `signInAction`, `signOutAction`, `createAppAction`. Results that contain a key are returned to the page through action state and rendered once; they are never placed in a URL.
- **Live feed state** (`feed-state.ts`, pure):

```ts
export type Connection = 'connecting' | 'live' | 'reconnecting'
export interface FeedState { events: StoredEvent[]; pending: StoredEvent[]; connection: Connection }
export const FEED_CAP = 500
export const RENDER_INTERVAL_MS = 250
export function initialFeed(events: StoredEvent[]): FeedState        // newest first
export function receive(state: FeedState, event: StoredEvent): FeedState   // queues; ignores known event_id
export function flushPending(state: FeedState): FeedState            // merges pending, newest first, caps at 500
export function setConnection(state: FeedState, connection: Connection): FeedState
```

- **Copy (message catalog keys → English):**

| Key | Text |
|---|---|
| `onboarding.title` | Create your organization |
| `onboarding.name` | Organization name |
| `onboarding.submit` | Create organization |
| `key.admin.title` | Admin key — shown once |
| `key.admin.help` | Save this key now. It is your sign-in until user accounts arrive. |
| `signin.title` | Sign in with an admin key |
| `signin.submit` | Sign in |
| `signin.invalid` | That key was not accepted. |
| `apps.title` | Apps |
| `apps.empty` | No Apps yet. Create one to get a Shield key. |
| `apps.new` | New App |
| `app.name` | App name |
| `app.environment` | Environment |
| `app.create` | Create App |
| `key.shield.title` | Shield key — shown once |
| `shield.monitor` | Shield starts in monitor mode — it observes and cannot block anything yet. |
| `live.title` | Live |
| `live.waiting` | Waiting for the first event from {app}… |
| `live.state.live` | Live |
| `live.state.reconnecting` | Reconnecting |
| `live.state.connecting` | Connecting |
| `live.col.time` · `live.col.decision` · `live.col.method` · `live.col.route` · `live.col.status` · `live.col.latency` · `live.col.network` | Time · Decision · Method · Route · Status · Latency · Network |
| `decision.allow` | Allowed |
| `mode.monitor` | Monitor |
| `session.signout` | Sign out |
| `copy` · `copied` | Copy · Copied |

---

## Tasks

Order: Task 0 → Task 1 → three lanes in parallel (**A:** 2, 3, 4 · **B:** 5, 6, 7 · **C:** 8, 9, 10) → Task 11 → Task 12.

### Task 0: Workspace scaffold

**Files:** create every root file in *File structure*; a `package.json` and `tsconfig.json` per workspace with all dependencies of *Verified library facts*; one placeholder source file and one trivial passing test per workspace; `apps/console` scaffolded with the verified `create-next-app` command and then trimmed.

**Interfaces — produces:** root scripts `test` (single run of all unit and integration tests), `typecheck`, `check` (format and lint), `fix`, `bench`, `e2e`, `dev`, `dev:api`, `dev:console`, `dev:range`, `verify` (= `check` + `typecheck` + `test`).

- [ ] **Step 1:** write the root and workspace manifests with exact pins; `.npmrc` contains `save-exact=true`.
- [ ] **Step 2:** run `npm install` once. Expected: exit code 0.
- [ ] **Step 3:** add one trivial test per workspace; run `npm run verify`. Expected: every workspace reports one passing test; type-check and format checks are clean.
- [ ] **Step 4:** record the versions actually installed (`npm ls --depth=0 --workspaces`) in the task report.

### Task 1: Protocol

**Files:** `packages/protocol/src/*`, `packages/protocol/test/*`. **Interfaces — produces:** contract C1.

- [ ] **Step 1 — failing tests**
  - `ids`: `newId('org')` matches `^org_[0-9a-f]{24}$`; 1,000 identifiers are unique.
  - `keys`: admin key matches `^aro_[A-Za-z0-9_-]{43}$`; Shield keys start `ark_prod_`, `ark_stg_`, `ark_dev_` for the three Environments; `parseKey` returns kind and Environment for each and `null` for `''`, `'aro_short'`, `'ark_xxx_' + 43 chars`, `42`, `undefined`; `hashKey` returns 64 lowercase hex characters, is deterministic, differs between keys; `prefix` is the scheme plus the first 6 secret characters and `last4` the last 4.
  - `events`: the documented example parses; an unknown key at top level, inside `request` and inside `actor` is absent from the output; rejected: `route` of 257 characters, `status` 99 and 600, negative `latency_ms`, a non-UUID `event_id`, a non-ISO `ts`, an unknown `type`, a batch with 0 and with 501 Events, `protocol: 2`.
  - `api`: `name` is trimmed; `''` and 81 characters are rejected; `environment` defaults to `'development'`; an unknown Environment is rejected.
- [ ] **Step 2:** run the protocol tests. Expected: fail — modules not found.
- [ ] **Step 3:** implement C1.
- [ ] **Step 4:** run the protocol tests. Expected: pass.

### Task 2: API — database and tenancy

**Files:** `apps/api/migrations/0001_init.sql`, `src/db/*`, `test/db.test.ts`. **Interfaces — consumes:** nothing. **Produces:** `openDb`, `Db`, `Queryable`, `Scope` (C4), schema C5.

- [ ] **Step 1 — failing tests**
  - a fresh in-memory database has the four tables; opening the same data directory twice applies migrations once.
  - inside `tx(scope, …)` `current_user` is `ar_app` for every scope; the session role is still `ar_app` after a callback throws and after an SQL error (fail-closed: the session is switched once after migrations, never per transaction).
  - opening a data directory that another live process holds fails with a clear error (pid lock file beside the directory); a stale lock of a dead pid is replaced.
  - as Organization A an App is inserted; as Organization B `SELECT` on `apps` returns 0 rows, also when filtering by A's App identifier.
  - as Organization B inserting an App row with A's `organization_id` is rejected.
  - with scope `'none'`: `SELECT` on `apps` and on `api_keys` returns 0 rows; `auth_lookup_key(hash)` returns the key's Organization, kind, App and Environment; a revoked key returns no row.
  - 20 concurrent `tx` calls with 20 Organizations each read back their own `app.tenant_id`.
  - after `tx` resolves or rejects, the next `tx` with scope `'none'` reads an empty `app.tenant_id`.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement. **Step 4:** run. Expected: pass.

### Task 3: API — authentication, Organizations, Apps

**Files:** `src/app.ts`, `problem.ts`, `log.ts`, `auth/authenticate.ts`, `stores/organizations.ts`, `stores/apps.ts`, `stores/keys.ts`, `routes/organizations.ts`, `routes/apps.ts`, `routes/health.ts`, `test/organizations.test.ts`, `test/apps.test.ts`, `test/auth.test.ts`. **Consumes:** C1, Task 2. **Produces:** `createApp` with the first five rows of C2 and `/healthz`.

- [ ] **Step 1 — failing tests** (all through `app.request`)
  - `POST /v1/organizations {"name":" Acme "}` → 201, body matches the schema, name is `Acme`, key matches the admin format; the database holds `key_hash = hashKey(key)` and no column contains the key.
  - bad bodies → 400 problem documents: empty name (`errors[0].path` is `name`), 81 characters, missing body, invalid JSON.
  - `GET /v1/organization`: admin key → 200; no header, malformed key, unknown key → 401 with `WWW-Authenticate: Bearer`; a Shield key → 403.
  - `POST /v1/apps`: default Environment yields a key starting `ark_dev_`; `production` yields `ark_prod_`; an unknown Environment → 400.
  - `GET /v1/apps` for two Organizations lists only the caller's Apps, newest first.
  - `GET /v1/apps/:appId` with another Organization's App → 404; a malformed identifier → 404.
  - a logger captured during all of the above never receives a line containing any issued key.
  - `GET /healthz` → 200 `{"status":"ok"}`.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement. **Step 4:** run. Expected: pass.

### Task 4: API — ingest, Event list, live stream

**Files:** `src/bus.ts`, `stores/events.ts`, `routes/ingest.ts`, `routes/events.ts`, `src/main.ts`, `config.ts`, `test/bus.test.ts`, `test/ingest.test.ts`, `test/events.test.ts`, `test/stream.test.ts`. **Consumes:** Tasks 2, 3. **Produces:** the remaining rows of C2; `main.ts` serving on `HOST`/`PORT` with `AR_DATA_DIR`.

- [ ] **Step 1 — failing tests**
  - bus: an Event reaches only subscribers of its Organization and App; unsubscribing twice is harmless; a subscriber that throws does not stop the others; `count()` reflects subscriptions.
  - ingest: a valid batch of 3 → 202 `{accepted:3,duplicates:0}`; listing returns the 3 newest first, stamped with Organization, App and Environment of the key.
  - `organization_id`, `app_id`, `environment` placed by the client in the batch or in an Event do not affect what is stored.
  - the same batch again → 202 `{accepted:0,duplicates:3}`; 3 rows remain.
  - an invalid Event at index 1 → 400, `errors[0].path` begins `events.1`, 0 rows stored.
  - 501 Events → 400; a body over 262,144 bytes → 413; no key → 401; an admin key → 403; a revoked Shield key → 401.
  - stored payloads never contain `query`, `headers`, `ip` or any other key outside the allowlist, even when sent.
  - list: `limit` of `0`, `201`, `abc` → 400; default returns at most 50.
  - stream: after subscribing, posting an Event delivers one message whose `event` is `security-event`, `id` equals the `event_id` and `data` parses as a `StoredEvent`.
  - stream isolation: Organization B asking for A's App → 404; B's own stream receives nothing when A ingests.
  - stream cleanup: after the reader is cancelled `bus.count()` is 0.
  - heartbeat: with `heartbeatMs: 50` a comment line arrives within 200 ms.
  - stream limit: the 21st concurrent stream of one Organization → 429.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement; ingest inserts and publishes after the transaction commits, and publishes only rows that were newly stored. Nothing but SQL is awaited inside a transaction (all transactions share one in-process lock). The 413 path is tested both with and without a `content-length` header, and the unread body is drained with a bound. **Step 4:** run. Expected: pass.

### Task 5: Shield — core

**Files:** `packages/shield-node/src/types.ts`, `decide.ts`, `ip.ts`, `uuidv7.ts`, `emitter.ts`, `shield.ts`, `index.ts`, `test/ip.test.ts`, `uuidv7.test.ts`, `decide.test.ts`, `emitter.test.ts`, `shield.test.ts`, `test/fixtures/exit.mjs`. **Consumes:** types and (in tests only) schemas of C1. **Produces:** C3 without `express()`.

- [ ] **Step 1 — failing tests**
  - `truncateIp`: `203.0.113.77` → `203.0.113.0/24`; `::ffff:203.0.113.77` → `203.0.113.0/24`; `2001:db8:abcd:12::1` → `2001:db8:abcd::/48`; `::1` → `0:0:0::/48`; `2001:db8::1` → `2001:db8:0::/48`; `''`, `'not-an-ip'`, `undefined` → `null`.
  - `uuidv7`: matches the version-7 pattern; the first 48 bits equal the clock's milliseconds; values created at increasing times sort ascending as strings.
  - `decide` returns `{ action:'allow', mode:'monitor', ruleId:null, policyVersion:0 }` and its return value is not a Promise.
  - emitter (fake transport, fake clock): nothing is sent before the interval; at 1,000 ms one request to `{endpoint}/v1/events` with `authorization: Bearer <key>` and `content-type: application/json` whose body passes `EventBatchSchema`.
  - 250 buffered Events produce three requests of 100, 100 and 50 in order.
  - with `maxBufferSize: 10`, 15 Events leave the newest 10 and `stats().dropped === 5`.
  - a rejecting transport is attempted 3 times with the documented backoff, then the batch is dropped and `failedBatches === 1`; no unhandled rejection is raised.
  - responses 500 and 429 are retried; 400 and 413 are dropped without retry; 401 pauses sending for 60,000 ms and sets `lastError`.
  - the transport receives `timeoutMs` equal to `requestTimeoutMs`; the default transport, pointed at a local server that never answers, rejects after that time.
  - `flush()` sends everything buffered; `close()` flushes and stops the timer; recording after `close()` does nothing.
  - a child Node process that creates a Shield against a local server that never answers, records one Event, waits for the flush to start and returns, exits with code 0 within 2 s (neither the timer nor the in-flight send holds the process).
  - `createShield` with a missing or malformed key, with `disabled: true`, or with `AR_SHIELD_DISABLED=1` returns a Shield whose `stats().disabledReason` is set, logs one warning and records nothing; it never throws.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement. **Step 4:** run. Expected: pass. Confirm `dependencies` in `package.json` is empty.

### Task 6: Shield — Express adapter, contract, benchmark

**Files:** `packages/shield-node/src/express.ts`, `test/express.test.ts`, `test/contract.test.ts`, `bench/overhead.bench.ts`. **Consumes:** Task 5. **Produces:** `Shield.express()`; script `bench`.

- [ ] **Step 1 — failing tests** (a real Express app on port 0, called with `fetch`)
  - `GET /api/products/42?token=secret` returns the same status, headers and body with and without Shield; it yields one Event with method `GET`, route `/api/products/:id`, status 200, a non-negative numeric `latency_ms`, a loopback prefix, Decision `allow` in mode `monitor`; the serialized Event contains none of `42`, `token`, `secret`.
  - a router mounted at `/v1` with `GET /users/:id` records route `/v1/users/:id`.
  - a request matching no route records status 404 and route `(unmatched)`.
  - a handler that throws records status 500 and the application's own error response is unchanged.
  - when `decide` or event recording throws internally, the response is still 200 and `stats().internalErrors` increases.
  - with a transport that always rejects, 100 requests all return 200 and no unhandled rejection is raised.
  - a router mounted at `/orgs/:orgId` with `GET /apps/:appId` records route `/orgs/:orgId/apps/:appId`, never the concrete identifiers.
  - a request the client aborts before the response ends still yields exactly one Event.
  - contract: every batch captured from the adapter passes `EventBatchSchema`.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement. **Step 4:** run. Expected: pass.
- [ ] **Step 5 — benchmark:** `bench/overhead.bench.ts` invokes the middleware directly 200,000 times with minimal request and response doubles, prints p50 and p99 of the added time in microseconds, and exits non-zero when p99 exceeds 500 µs. Run `npm run bench`. Expected: exit code 0 and the printed figures recorded in the task report.

### Task 7: Reference target (`ar-range`)

**Files:** `apps/range/src/server.ts`, `main.ts`, `test/server.test.ts`. **Consumes:** Tasks 5, 6. **Produces:** `createRangeServer({ shield })`; `main.ts` reading `AR_SHIELD_KEY`, `AR_API_URL`, `HOST`, `PORT`.

- [ ] **Step 1 — failing test:** with a Shield built on a fake transport, `GET /`, `GET /api/products/7` and `POST /api/login` answer 200, 200 and 401 and yield three Events with routes `/`, `/api/products/:id`, `/api/login`.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement. **Step 4:** run. Expected: pass.

### Task 8: Console — foundation

**Files:** `apps/console/src/app/layout.tsx`, `globals.css`, `src/lib/*`, `src/components/*`, `test/session.test.ts`, `api.test.ts`, `format.test.ts`, `t.test.ts`. **Consumes:** C1. **Produces:** tokens of UIUX.md §4 as CSS variables; `session`, server-only `api`, `t`, `format`; components `Button`, `Input`, `Card`, `PageHeader`, `EnvironmentTag`, `DecisionChip`, `LiveIndicator`, `KeyReveal`, `Snippet`, `EmptyState`.

- [ ] **Step 1 — failing tests**
  - `session`: the cookie is written with exactly the options of C6; `secure` is true only in production.
  - `api`: sends `Authorization: Bearer <key>` to `AR_API_URL`; a 401 becomes `UnauthorizedError`, a 404 `NotFoundError`, a 400 `ValidationError` carrying `errors`; a response that fails its schema becomes `ApiError`; no error message contains the key.
  - `format`: time renders as `HH:MM:SS` with the ISO value available for a title; latency renders `<1 ms`, `3 ms`, `1.2 s`; status maps to the classes `ok` (2xx–3xx), `client` (4xx), `server` (5xx).
  - `t`: returns the catalog text, substitutes `{app}`, and throws on an unknown key.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement, including the token sheet and the two font families. **Step 4:** run. Expected: pass.

### Task 9: Console — onboarding, sign-in, Apps

**Files:** `src/app/page.tsx`, `sign-in/page.tsx`, `apps/page.tsx`, `apps/new/page.tsx`, `actions.ts`, `test/actions.test.ts`. **Consumes:** Task 8. **Produces:** the four Server Actions and the pages of C6 except the live feed.

- [ ] **Step 1 — failing tests** (actions called with the API client replaced by a fake)
  - `createOrganizationAction` with a valid name stores the admin key in the session and returns `{ ok: true, organization, adminKey }`; with an empty name returns `{ ok: false, errors }` and stores nothing.
  - `signInAction` stores the key only when the API accepts it; otherwise returns the `signin.invalid` message.
  - `createAppAction` returns `{ ok: true, app, shieldKey }` and requires a session.
  - `signOutAction` clears the session.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement actions and pages; pages redirect to `/` without a session. **Step 4:** run. Expected: pass.

### Task 10: Console — live feed

**Files:** `src/features/live-feed/*`, `src/app/apps/[appId]/live/page.tsx`, `src/app/api/apps/[appId]/events/stream/route.ts`, `test/feed-state.test.ts`, `live-feed.test.tsx`, `stream-route.test.ts`. **Consumes:** Tasks 8, 9. **Produces:** the live feed screen and the stream proxy.

- [ ] **Step 1 — failing tests**
  - feed state: `initialFeed` orders newest first; `receive` queues an Event and ignores a known `event_id`; `flushPending` merges, keeps newest first and caps at 500; `setConnection` changes only the connection.
  - component (fake `EventSource`): initial Events render as rows; with none, the waiting text names the App; a `security-event` message adds a row within one render interval; `open` shows Live, `error` shows Reconnecting; the Decision reads Allowed and the mode tag reads Monitor.
  - proxy route: an `appId` that does not match the pattern → 404 without calling the API; no session → 401; an upstream 404 is passed through; any non-success upstream response keeps its own status and content type; a successful response has `content-type: text/event-stream` and `cache-control: no-cache, no-transform` and forwards the upstream body; the upstream fetch receives the request's abort signal.
- [ ] **Step 2:** run. Expected: fail. **Step 3:** implement. **Step 4:** run. Expected: pass.

### Task 11: End to end

**Files:** `tests/e2e/*`. **Consumes:** everything. **Produces:** the two journey tests; `journey.http.test.ts` runs inside `npm test`, the browser journey inside `npm run e2e`.

- [ ] **Step 1 — HTTP journey** (`journey.http.test.ts`, no browser): start the API in-process on port 0 with an in-memory database; create an Organization and an App over HTTP; start an Express server with Shield using the returned key; open the stream; send `GET /api/products/1`; assert that a `security-event` for route `/api/products/:id` arrives in ≤ 5,000 ms, that the list endpoint returns it, that a second Organization receives 404 for both list and stream, and that the Express response was 200.
- [ ] **Step 2 — browser journey** (`journey.e2e.ts`, matched only by Playwright): start API and Console; in the browser create an Organization, then an App; read the Shield key from the page; start an Express server with Shield in the test process; request it; assert a row with route `/api/products/:id` and Decision Allowed is visible in ≤ 5,000 ms without reload; assert the `ar_admin` cookie is `httpOnly`; assert no visited URL contains `aro_` or `ark_`.
- [ ] **Step 3:** run both. Expected: pass. Fix integration defects in the owning workspace with a failing test first.

### Task 12: Developer experience, documentation, full verification

**Files:** `README.md`, `.claude/launch.json`, root scripts. **Consumes:** everything.

- [ ] **Step 1:** `README.md` — what exists, quickstart (install, start API and Console, create Organization and App, run the reference target with the key, watch the live feed), scripts, what is deliberately missing, where the specifications are.
- [ ] **Step 2:** `.claude/launch.json` with one configuration each for the API, the Console and the reference target.
- [ ] **Step 3:** run `npm run verify`, `npm run e2e`, `npm run bench`. Expected: all exit 0. Record the outputs.
- [ ] **Step 4:** tick the acceptance criteria in the ticket that are proven, each with the command that proves it.

## Deliberately not in this slice

Policy Bundles, Rules, Dynamic Lists, attestation, request signing, sampling and rollups, Detections, user accounts, API rate limiting, key rotation and revocation endpoints, OpenAPI generation, ClickHouse and event-log adapters, CI, deployment. Adding any of them here is a defect.

## Verified library facts

Evidence and working code: [2026-11-10-slice-01-spike-findings.md](2026-11-10-slice-01-spike-findings.md). Read the section for your workspace before writing code; the snippets there ran on this machine. Version-matched Next.js documentation is in `node_modules/next/dist/docs` at the repository root.

### Pins

| Where | Packages |
|---|---|
| Root (dev) | `typescript` 7.0.2 · `vitest` 5.1.0 · `@biomejs/biome` 2.6.6 · `tsx` 4.23.15 · `concurrently` 10.0.7 · `@types/node` 22.20.5 · `@vitejs/plugin-react` 6.3.0 · `@testing-library/react` 16.3.3 · `@testing-library/dom` 10.4.2 · `happy-dom` 21.0.4 · `@playwright/test` 1.65.0 |
| `protocol` | `zod` 4.6.7 |
| `api` | `hono` 4.13.17 · `@hono/node-server` 2.1.6 · `@hono/zod-validator` 0.9.1 · `@electric-sql/pglite` 0.5.16 · `zod` 4.6.7 |
| `shield-node` | runtime: none · dev: `express` 5.3.0, `@types/express` 5.0.6 |
| `range`, `e2e` | `express` 5.3.0 (`@types/express` 5.0.6) |
| `console` | `next` 16.4.6 · `react` 19.3.1 · `react-dom` 19.3.1 · `tailwindcss` 4.3.5 · `@tailwindcss/turbopack` 4.3.5 · `zod` 4.6.7 · `@types/react` 19.3.0 · `@types/react-dom` 19.3.0 |

### Rules that follow from the spikes

**Toolchain**

- Relative imports carry the `.ts` extension (`./events.ts`); `allowImportingTsExtensions`, `erasableSyntaxOnly`, `verbatimModuleSyntax` and `noEmit` are on. Never a `.js` suffix — Turbopack does not map it. No enums, no parameter properties.
- Workspace packages export source: `"exports": { ".": "./src/index.ts" }`. No build step, no `transpilePackages`.
- TypeScript 7 defaults `types` to an empty list: every Node workspace sets `"types": ["node"]`. Removed options (`baseUrl`, `moduleResolution: node`) must not appear.
- Type-check: `tsc -b` from the root for the Node workspaces; the Console uses `next typegen && tsc --noEmit`. `*.tsbuildinfo` is ignored by Git and Biome.
- Services run with `tsx`. Biome uses `linter.rules.preset: "recommended"`.
- Vitest 5 has no workspace file. One root `vitest.config.ts` with inline `test.projects`, each with an explicit `include` (`test/**/*.test.{ts,tsx}`), `environment: 'node'` except the Console project (`happy-dom` plus the React plugin and a setup file that sets `globalThis.IS_REACT_ACT_ENVIRONMENT = true` and registers `afterEach(cleanup)`). `jsdom` is not used (current versions need a newer Node).
- HTTP tests of Express apps: `http.createServer(app).listen(0, '127.0.0.1')` plus `fetch`; always `server.closeAllConnections()` before `close()`.

**API**

- Exactly one process owns the PGlite data directory. Open with `await PGlite.create(dataDir)`. Migrate as the default superuser, then `SET ROLE ar_app` once for the session. Request code receives only the transaction object; calling the outer handle inside a transaction deadlocks.
- `set_config('app.tenant_id', $1, true)` with a bound parameter sets the tenant for the transaction. One parameter must not be used with two inferred types in one statement.
- One in-memory instance per test file (about 0.7 s), never per test case.
- zod 4: `z.object` strips unknown keys (wanted); `z.uuidv7()`; `z.iso.datetime()` accepts the `Z` form that `Date#toISOString` produces; map issues to `{ path, message }` yourself. Deprecated string-method validators are not used.
- Malformed JSON surfaces as an `HTTPException` — convert it in `app.onError`. `bodyLimit` answers 413 without reading the body when `content-length` is present: drain it (bounded) in `onError`.
- SSE: `streamSSE`; subscribe, heartbeat interval, `stream.onAbort`, await until aborted, clean up in `finally`. In tests cancel the reader and await one tick before asserting on subscriber counts. `server.close()` never resolves while a stream is open — shutdown aborts streams, then `closeAllConnections()`.

**Shield**

- Typed against `node:http` only; no `express` import in `src`. Protocol is imported with `import type` only.
- The exact route template needs the `req.route` accessor technique of the findings file (capture `baseUrl` at first assignment, substitute mount parameters back); `req.baseUrl` alone is the concrete URL. Express stays pinned exactly because this relies on router internals; the route table test guards it.
- `finish` does not fire on client abort; record on `close`.
- `fetch` can hold a finishing process until its timeout; the default transport is `node:http` with an unref'd socket. The flush timer is lazy and unref'd.

**Console**

- `create-next-app` refuses the directory name `console`: scaffold as `console-app`, then rename the directory and set the package name.
- Delete `cacheComponents` and `partialPrefetching` from the generated `next.config.ts`; keep the Tailwind Turbopack loader rule. With Cache Components on, page redirects are not real 307s and show-once state lingers.
- The session guard is an async Server Component that reads the cookie and calls `redirect()` with no `Suspense` or `loading.tsx` above it.
- The stream proxy is a `GET` Route Handler: read the cookie from `request.cookies`, `fetch(upstream, { signal: request.signal, cache: 'no-store' })`, return `new Response(upstream.body, …)`; export no segment config.
- Fonts through `next/font/google` (needs network at build). There is no `next lint`; use Biome.
- Neither happy-dom nor Node 22.12 defines `EventSource`: component tests stub it with `vi.stubGlobal`.

**End to end**

- Playwright 1.65.0 needs Chromium headless-shell build 1254, about 100 MB, which is not in this machine's shared cache. One-time install: `npx playwright install --only-shell --no-remove chromium`. Playwright files are named `*.e2e.ts` so Vitest never collects them. The browser journey runs the Console with `next dev`.
- Every server exposes a cheap health route, honours `PORT`, and exits on `SIGTERM`.

## Amendments after the independent review

An independent review of the finished code confirmed eight defects that the first 505 green tests had not caught. Each was fixed test-first; the contracts above changed as follows.

| Finding | Change |
|---|---|
| A stalled stream consumer pinned memory and escaped the stream limit | A live stream holds back at most 1,024 messages or 1,048,576 characters; beyond that the connection is cut, not merely unsubscribed. `rule_id` is at most 64 characters |
| Shield recorded concrete URL segments below a mount and for regular-expression mounts | The path above the point where Shield is installed is recorded as `(mount)`; a regular-expression mount, or a literal mount segment that looks like an identifier, yields `(unmatched)`. Known limit: a regular-expression mount without capture groups that matches non-numeric text is not detectable |
| Ingest accepted values outside the privacy allowlist | `actor.ip_prefix` must match the `/24` or `/48` prefix form (`IP_PREFIX_PATTERN`); free text excludes control characters and lone surrogates; `ts` must lie in the years 2000–2099 |
| `HEAD` on the stream route leaked a stream slot | The API answers 405 with `Allow: GET`; the Console's proxy exports its own `HEAD` that never calls the API |
| The live feed silently missed Events | New Console route `GET /api/apps/[appId]/events` (list proxy). The feed reads it whenever its stream opens and merges the result; on 401 it hands over to sign-in, on 404 it stops retrying |
| Unstorable input gave 500 and a body value reached the log | Such input is now a 400; the API logs the kind of an unexpected error and its SQL state, never its message |
| Shield dropped Events silently on 400, 404 or 3xx | One warning per condition (`rejected`); `stats().dropped` now counts every Event that was not delivered |
| Listener warning once 11 streams were open | The shutdown signal accepts any number of listeners |
