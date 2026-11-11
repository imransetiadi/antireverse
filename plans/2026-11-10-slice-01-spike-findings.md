---
title: "Slice 01 — spike findings"
project: anti-reverse
doc: RESEARCH
status: final
updated: 2026-11-10
language: en
tags:
  - anti-reverse
  - research
---

# Slice 01 — spike findings

Five throwaway experiments run on 2026-11-10 (macOS arm64, Node 22.12.0, npm 10.9.0) before the plan was finalised. Every snippet below ran. The plan's *Verified library facts* section is the binding summary; this file is the evidence and the working code.

## A — Embedded PostgreSQL (PGlite) with row-level security

**Verdict:** works with caveats

PGlite 0.5.16 (PostgreSQL 18.6 in WASM) enforces row-level security correctly: with a non-superuser role plus ENABLE/FORCE RLS and USING/WITH CHECK on current_setting('app.tenant_id', true), cross-tenant rows are invisible, cross-tenant inserts/updates fail with 42501, no-tenant sees nothing, and the superuser bypasses everything. set_config($1, true) with a bound parameter works inside db.transaction() and is reset after commit/rollback (to an empty string, not NULL, so policies need NULLIF). A SECURITY DEFINER lookup function, JSONB, ON CONFLICT, multi-statement migrations, 20 concurrent transactions (strictly serialised by an internal mutex, zero interleaving), persistence and a kill -9 during writes all behaved correctly, and performance is ample for slice 01 (cold start ~0.65-0.85 s, reopen ~0.1-0.2 s, feed query on 100k rows under 1.5 ms). The serious caveats: the default user is a superuser (fail-open unless the session is switched to the app role), the `username` option is only a SET ROLE (session_user stays postgres, RESET ROLE escapes), and there is NO data-directory lock, so a second process that merely opens and closes the same dataDir while the first is live produced stale reads and then an unopenable database (PANIC: could not locate a valid checkpoint record). Not verified: behaviour on OS crash/power loss (PGlite starts Postgres with fsync off, -F), behaviour under Next.js/bundlers, and TypeScript 7 compilation of the types (only the .d.ts was read; scripts were plain .mjs). The node:sqlite fallback is not needed; for the record it is NOT usable on Node v22.12.0 without --experimental-sqlite.

**Versions:** @electric-sql/pglite 0.5.16; PostgreSQL (embedded in PGlite, from select version()) 18.6; node v22.12.0; npm 10.9.0; SQLite via node:sqlite (only with --experimental-sqlite) 3.47.0

### Recommendation

Use @electric-sql/pglite 0.5.16 for local development and tests behind a small Db interface; do not use the node:sqlite fallback.

Concretely:
1. Ownership: exactly one process (the Hono API) creates the PGlite instance, as a module-level singleton created with `await PGlite.create(dataDir)` (file-backed dir for dev, no argument for tests). The Next.js console never opens the dataDir; it reads through the API, and the SSE feed is served by (or proxied from) the API process. Add a startup guard of our own (for example a lock file with the pid next to the dataDir) because PGlite has none.
2. Start-up sequence: run the migration runner as the default superuser (one transaction per .sql file, schema_migrations with version + checksum), then issue `SET ROLE app_user` once at session level so everything afterwards is fail-closed. For later migrations use RESET ROLE, migrate, SET ROLE app_user.
3. Db interface: expose only `withTenant(tenantId, fn(tx))` (db.transaction + `select set_config('app.tenant_id', $1, true)`) and a narrow tenant-less path for `select * from lookup_api_key($1)`. Never hand the raw handle to request code; inside the callback only the tx object may be used, and no network I/O may be awaited there.
4. Schema rules: every tenant table gets tenant_id, ENABLE + FORCE ROW LEVEL SECURITY, and a policy with both USING and WITH CHECK on `NULLIF(current_setting('app.tenant_id', true), '')::uuid`; organizations uses `id = <that expression>` so an org is created by generating the id in app code and setting the tenant to it first. app_user is created NOLOGIN NOSUPERUSER NOBYPASSRLS with table grants only; api_keys gets no grant and is reached only via the SECURITY DEFINER function (SET search_path, REVOKE FROM PUBLIC, GRANT EXECUTE TO app_user).
5. Events: index (tenant_id, received_at DESC); ingest with INSERT ... ON CONFLICT DO NOTHING passing the JS object directly as the jsonb parameter; batch with a single jsonb_to_recordset($1::jsonb) statement; decide whether event id uniqueness should be (tenant_id, id).
6. Tests: one in-memory instance per test file (~0.7 s), or build one migrated instance, dumpDataDir('none') after waitReady, and start each file from loadDataDir (~170 ms). Include RLS regression tests for the three proven cases (cross-tenant invisible and insert rejected with 42501, no tenant sees nothing, superuser bypasses).
7. Production adapter: same SQL against a real Postgres, connecting as the non-superuser role directly with BEGIN / set_config / COMMIT per request. Still to verify before relying on it: the definer function with a non-superuser owner, the types under TypeScript 7.0.2, and PGlite inside any bundled build.

### Gotchas

- No data-directory lock: a second process that opens the same dataDir gets no error, reads stale data, and corrupts the directory. Verified outcome after a read-only open+close by a second process while a writer was live: 'PANIC: could not locate a valid checkpoint record' and the dataDir could not be opened again. Exactly ONE process may own the PGlite dataDir; the Next.js console must not open it and must go through the API process (including for the SSE feed).
- Two PGlite instances on the same dataDir in the same process also open silently and the second reads stale data. Keep a single module-level instance (beware dev-server hot reload creating a second one); not verified under Next.js or a bundler.
- The default user 'postgres' is a superuser with BYPASSRLS; FORCE ROW LEVEL SECURITY does not constrain it. Without an explicit role switch every query bypasses all policies.
- The `username` constructor option is not a real login: session_user stays 'postgres', it works even for a NOLOGIN role, and RESET ROLE returns to superuser. It gives no more isolation than SET ROLE. An unknown username throws 22023 'role ... does not exist'.
- SET ROLE / SET LOCAL ROLE are defence in depth, not a boundary against SQL the application itself sends (RESET ROLE and set_config to another tenant both work inside the session). Never pass user-supplied SQL text to the database; in production connect as the non-superuser role directly.
- After a transaction that used set_config('app.tenant_id', $1, true), current_setting('app.tenant_id', true) returns '' (empty string), not NULL. A policy that casts it directly to uuid then fails with 22P02 on the next tenant-less query. Always wrap with NULLIF(..., '').
- All transactions are serialised by one in-process mutex. Any await on slow work (network, timers) inside db.transaction() blocks every other query. Keep transactions short and do I/O outside.
- Awaiting db.query() or db.transaction() on the outer handle from inside a transaction callback deadlocks forever (promise never settles). Use only the tx object inside the callback; the Db interface should not expose the raw handle to request code.
- Methods called before the instance is ready can hang: `new PGlite(dir)` followed immediately by `await db.dumpDataDir()` never settled. Use `await PGlite.create(...)` or `await db.waitReady` first.
- A parameter used with two different inferred types in one statement fails with 42P08 'inconsistent types deduced for parameter $1' (e.g. the same $1 for a uuid column and a text column). Use separate parameters or explicit casts.
- exec() takes no bound parameters ('there is no parameter $1'); it is for migrations only. Use query() for anything with values.
- ON CONFLICT (id) DO NOTHING on a globally unique event id silently drops an insert whose id already exists under another tenant (affectedRows 0, no error). If event ids are client-generated, make the uniqueness (tenant_id, id) or generate ids server-side.
- PGlite starts Postgres with fsync disabled (-F in defaultStartParams). kill -9 of the process lost nothing in one try each (default and relaxedDurability), but durability on OS crash or power loss was not verified. Treat PGlite as development/test storage only.
- Disk and start-up footprint: an empty data dir is 38 MB, 96 MB after ~100k events; a cold in-memory instance costs ~0.65-0.85 s, so a fresh instance per test file is fine but a fresh instance per test case is expensive. Restoring a pre-migrated dumpDataDir blob via loadDataDir takes ~170 ms uncompressed.
- The package is 26 MB on disk with WASM and .data assets loaded from dist at runtime; bundling it into a Next.js server build was not verified. Keeping PGlite only in the Hono API process avoids the question.
- The SECURITY DEFINER lookup was proven with a superuser owner. On a production server where the migration role is not a true superuser, the function owner must be the table owner and api_keys must not use FORCE RLS (or the owner needs BYPASSRLS). Not verified in this spike.
- LISTEN/NOTIFY works as app_user (pg_notify inside a tenant transaction was delivered to db.listen), but only inside the process that owns the instance.
- Leftover spike data directories (about 450 MB of data-s* folders) remain in the spike directory; nothing was deleted, so remove the spike directory by hand when finished.

### Working snippets

**Type signatures from the .d.ts (dist/interface-ymvJB3xs.d.ts, re-exported by dist/index.d.ts)**

````text
declare class PGlite extends BasePGlite implements PGliteInterface, AsyncDisposable {
    constructor(dataDir?: string, options?: PGliteOptions);
    constructor(options?: PGliteOptions);
    static create<O extends PGliteOptions>(options?: O): Promise<PGlite & PGliteInterfaceExtensions<O['extensions']>>;
    static create<O extends PGliteOptions>(dataDir?: string, options?: O): Promise<PGlite & PGliteInterfaceExtensions<O['extensions']>>;
    readonly dataDir?: string;
    readonly waitReady: Promise<void>;
    get ready(): boolean;
    get closed(): boolean;
    close(): Promise<void>;
    [Symbol.asyncDispose](): Promise<void>;
    isInTransaction(): boolean;
    listen(channel: string, callback: (payload: string) => void, tx?: Transaction): Promise<(tx?: Transaction) => Promise<void>>;
}
// inherited from BasePGlite
query<T>(query: string, params?: any[], options?: QueryOptions): Promise<Results<T>>;
sql<T>(sqlStrings: TemplateStringsArray, ...params: any[]): Promise<Results<T>>;
exec(query: string, options?: QueryOptions): Promise<Array<Results>>;
transaction<T>(callback: (tx: Transaction) => Promise<T>): Promise<T>;
runExclusive<T>(fn: () => Promise<T>): Promise<T>;

interface PGliteOptions<TExtensions extends Extensions = Extensions> {
    noInitDb?: boolean;
    dataDir?: string;
    username?: string;
    database?: string;
    fs?: Filesystem;
    pgDataProxyFs?: utils.FS;
    debug?: DebugLevel;            // 0 | 1 | 2 | 3 | 4 | 5
    relaxedDurability?: boolean;
    extensions?: TExtensions;
    loadDataDir?: Blob | File;
    icuDataDir?: Blob | File;
    initialMemory?: number;
    pgliteWasmModule?: WebAssembly.Module;
    initdbWasmModule?: WebAssembly.Module;
    fsBundle?: Blob | File;
    parsers?: ParserOptions;
    serializers?: SerializerOptions;
    startParams?: string[];
    initDbStartParams?: string[];
    postgresqlconf?: string[] | string;
    onStdout?: (text: string) => boolean;
    onStderr?: (text: string) => boolean;
}
interface QueryOptions {
    rowMode?: RowMode;             // 'array' | 'object'
    parsers?: ParserOptions;
    serializers?: SerializerOptions;
    blob?: Blob | File;
    onNotice?: (notice: NoticeMessage) => void;
    paramTypes?: number[];
}
type Results<T = { [key: string]: any }> = {
    rows: Row<T>[];
    affectedRows?: number;
    command?: string;
    rowCount?: number;
    fields: { name: string; dataTypeID: number }[];
    blob?: Blob;
};
interface Transaction {
    query<T>(query: string, params?: any[], options?: QueryOptions): Promise<Results<T>>;
    sql<T>(sqlStrings: TemplateStringsArray, ...params: any[]): Promise<Results<T>>;
    exec(query: string, options?: QueryOptions): Promise<Array<Results>>;
    rollback(): Promise<void>;
    listen(channel: string, callback: (payload: string) => void): Promise<(tx?: Transaction) => Promise<void>>;
    get closed(): boolean;
}
````

**Schema, RLS policies and SECURITY DEFINER lookup that ran (schema.sql / migrations/0001_init.sql, trimmed)**

````text
CREATE ROLE app_user NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;

CREATE TABLE events (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  app_id uuid NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL
);
CREATE INDEX events_tenant_received_idx ON events (tenant_id, received_at DESC);

ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;
-- NULLIF is required: after any transaction used set_config(..., true) the GUC reads '' (not NULL)
CREATE POLICY events_tenant ON events
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON apps, events TO app_user;

-- organizations: a tenant may only see / insert its own row (id generated in app code, tenant set to it first)
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY; ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_self ON organizations
  USING (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE ON organizations TO app_user;

-- api_keys: NO grant to app_user; lookup only through the definer function
CREATE FUNCTION lookup_api_key(p_hash text)
RETURNS TABLE (tenant_id uuid, app_id uuid)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$ SELECT k.tenant_id, k.app_id FROM public.api_keys k WHERE k.key_hash = p_hash $$;
REVOKE ALL ON FUNCTION lookup_api_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_api_key(text) TO app_user;
````

**Fail-closed adapter shape that ran (s9-misc.mjs failclosed): migrate as superuser, then drop the session to the app role**

````text
import { PGlite } from '@electric-sql/pglite'
import { migrate } from './migrate.mjs'

const db = await PGlite.create(dataDirOrUndefined)   // create() resolves when ready
await migrate(db, './migrations')                   // runs as superuser 'postgres'
await db.exec('SET ROLE app_user')                  // session-level, once; survives errors and rollbacks

const withTenant = (tenant, fn) => db.transaction(async (tx) => {
  await tx.query(`select set_config('app.tenant_id', $1, true)`, [tenant])  // bound param, tx-local
  return fn(tx)                                     // ONLY use tx inside; db.query here deadlocks
})

// create-organization flow: id generated by the app, tenant set to that id, WITH CHECK passes
await withTenant(A, tx => tx.query(`insert into organizations(id,name) values ($1,'Org A')`, [A]))
// API-key auth before the tenant is known: no tenant set, definer function does the lookup
const key = await db.query('select * from lookup_api_key($1)', [hash])

// later migrations: await db.exec('RESET ROLE'); await migrate(...); await db.exec('SET ROLE app_user')
````

**Alternative per-transaction role switch that ran (s2-rls.mjs) - works, auto-reverts, but fail-open outside the wrapper**

````text
const asTenant = (tenant, fn) => db.transaction(async (tx) => {
  await tx.exec('SET LOCAL ROLE app_user')
  if (tenant) await tx.query(`select set_config('app.tenant_id', $1, true)`, [tenant])
  return fn(tx)
})
// after the transaction: current_user = 'postgres' again, app.tenant_id = ''
````

**Migration runner that ran (migrate.mjs)**

````text
export async function migrate(db, dir) {
  await db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`)
  const done = new Map((await db.query('SELECT version, checksum FROM schema_migrations')).rows.map(r => [r.version, r.checksum]))
  const applied = []
  for (const file of readdirSync(dir).filter(f => f.endsWith('.sql')).sort()) {
    const sql = readFileSync(join(dir, file), 'utf8')
    const checksum = createHash('sha256').update(sql).digest('hex')
    if (done.has(file)) {
      if (done.get(file) !== checksum) throw new Error(`migration ${file} changed after being applied`)
      continue
    }
    await db.transaction(async (tx) => {
      await tx.exec(sql) // multi-statement, simple-query protocol; whole file rolls back on error
      await tx.query('INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)', [file, checksum])
    })
    applied.push(file)
  }
  return applied
}
````

**Idempotent ingest and batch insert forms that ran (s6-perf.mjs)**

````text
// single event, JS object straight into jsonb, idempotent on id
await tx.query(
  `insert into events(id,tenant_id,app_id,payload) values ($1,$2,$3,$4) on conflict (id) do nothing`,
  [id, tenant, appId, payloadObject])            // affectedRows: 1 fresh, 0 duplicate

// 500 rows in one statement, one parameter (15.8 ms in-memory)
await tx.query(
  `insert into events(id,tenant_id,app_id,payload)
   select id,tenant_id,app_id,payload
   from jsonb_to_recordset($1::jsonb) as r(id uuid, tenant_id uuid, app_id uuid, payload jsonb)
   on conflict (id) do nothing`, [JSON.stringify(rows)])

// live-feed page (0.7-1.5 ms on 100k rows; Index Scan on events_tenant_received_idx)
await tx.query(`select id, received_at, payload from events order by received_at desc limit 50`)
````

## B — Hono API, validation, server-sent events

**Verdict:** works with caveats

hono 4.13.17 + @hono/node-server 2.1.6 + zod 4.6.7 + @hono/zod-validator 0.9.1 do everything slice 01 needs: 28 vitest tests pass and tsc 7.0.2 --noEmit is clean in the spike directory. Proven: zod-validated POST with 256 KB limit and RFC 9457 problem+json for 400/401/413/404; typed bearer principal via c.set/c.get; streamSSE with id/event/data, heartbeat comments, and leak-free cleanup (listener count back to 0 after 50 cycles both through app.request() and over real sockets); reader.cancel() on app.request() bodies triggers the abort path; serve() on 127.0.0.1:0 with port discovery, graceful and forced shutdown; publish-to-client latency under 1.2 ms direct and through a fetch-and-re-stream proxy, with client aborts propagating upstream in 2-5 ms. Caveats found by running, not from docs: (1) hono's bodyLimit leaves the oversized body unread, and over a real socket that made clients see ECONNRESET/EPIPE instead of (or right after) the 413 — a bounded drain in onError fixed it deterministically; (2) server.close() alone never returns while an SSE stream is open and also waits ~4 s on undici's spare sockets, so shutdown needs an app-level abort signal plus closeIdleConnections/closeAllConnections; (3) aborting the signal passed to app.request() does NOT trigger cleanup, only cancelling the body does. Not verified: the proxy inside a real Next.js route handler (I used a @hono/node-server fetch handler), browser EventSource behaviour, HTTP/2, slow-client backpressure, Last-Event-ID replay, and behaviour behind real reverse proxies.

**Versions:** node 22.12.0; npm 10.9.0; hono 4.13.17; @hono/node-server 2.1.6; @hono/zod-validator 0.9.1 (peer: zod ^3.25.0 || ^4.0.0, hono >=4.11.2 — fits); zod 4.6.7; vitest 5.1.0; typescript 7.0.2 (used only for tsc --noEmit); @types/node 22.x (installed as @types/node@22); @hono/node-server (v1 comparison tarball, not installed) 1.19.18

### Recommendation

Build the API service as planned with hono 4.13.17, @hono/node-server 2.1.6, zod 4.6.7 and @hono/zod-validator 0.9.1.

Structure
- Export createApp(deps) returning new Hono<AppEnv>() with deps = { bus, key lookup, heartbeatMs, shutdown: AbortSignal }. Keep serve() in a separate entry file so every route test uses app.request() with no sockets.
- One problem(c, status, title, detail, extras) helper built on c.body with Content-Type application/problem+json; use it from the auth middleware, bodyLimit onError, the zValidator hook, app.notFound and app.onError (map HTTPException there so malformed JSON is also problem+json).
- Middleware order on ingest: auth -> bodyLimit(256*1024) -> zValidator('json', schema, hook) -> handler. In bodyLimit's onError, drain the unread body up to a cap (8 MB worked) and add Connection: close only if the cap is exceeded. Add an explicit Content-Type check if a 415 is wanted.
- Auth via createMiddleware<AppEnv>() that sets c.set('principal', ...); read with c.get('principal') / c.var.principal.
- Schemas: z.strictObject at the top level and on any nested object that must reject unknown keys; z.uuidv7() for event ids; z.iso.datetime({offset: true}) (or the default Z-only form — pick one and make the SDK match); z.enum([...]); error bodies from issues mapped to {pointer, code, detail} plus z.prettifyError for detail. Use top-level format functions, never the deprecated z.string().email()/.uuid()/.datetime() methods.

SSE
- Use the exact handler pattern in the snippet: subscribe, setInterval heartbeat comment, stream.onAbort(finish), shutdown signal listener, initial ': connected' write, await done, cleanup in finally. Expose bus.listenerCount for leak tests.
- Tests: read frames from res.body with a small reader helper, end each test with reader.cancel() and one awaited tick, assert listenerCount === 0. Keep one real-socket test file that uses listen(app.fetch, 0) for latency, disconnect and shutdown, and always call server.closeAllConnections() in teardown.

Server lifecycle
- listen() wrapper around serve({fetch, hostname:'127.0.0.1', port}) that resolves with info.port; shutdown(server, abortController, graceMs) as in the snippet (abort signal, close, sweep closeIdleConnections, forced closeAllConnections after the grace period). Wire it to SIGINT/SIGTERM.

Console proxy
- The fetch-and-re-stream pattern (return new Response(upstream.body, {status: upstream.status, headers: upstream.headers})) is sound in Node: unbuffered and abort-propagating without extra signal wiring. Before relying on it, repeat the two measurements (event latency, upstream listener count after client abort) inside the actual Next.js 16 route handler, since that was not covered here.

SDK implication
- Shield should cap its own payload well under 256 KB and treat ingest network errors (ECONNRESET/EPIPE) as non-fatal with retry, since an oversized body can surface as a socket error rather than a 413 if the server-side drain is ever removed.

Spike files, all under /private/tmp/claude-501/-Users-imboyy-Library-Application-Support-Claude-scratch-workspaces-1d3c3090-ace9-4ca6-b667-e892972fcb45-c1a12376-4ec4-4a62-bd0d-b4cfa30ed99d-scratch-2026-11-10-7036ee/6a952bc2-d47e-4d4a-a1dd-ec2c02c63bbb/scratchpad/spikes/b-hono-sse : src/app.ts, src/server.ts, test/helpers.ts, test/01-post.test.ts, test/02-sse.test.ts, test/03-server.test.ts, test/04-proxy.test.ts, test/05-zod.test.ts, test/06-413-drain.test.ts, test/07-misc.test.ts, test/types.test-d.ts. Re-run with `npx vitest run --reporter=verbose --silent=false` and `npx tsc -p .` from that directory. All servers were stopped; nothing is listening on 39120-39139.

### Gotchas

- hono bodyLimit never reads the body when Content-Length is present; it responds 413 with the body unread. Over a real socket @hono/node-server then force-closes the connection ~500 ms later, and undici clients saw ECONNRESET (on the 413 or on the next keep-alive request) or EPIPE. Drain the body (bounded) in onError, or the Shield SDK will see flaky network errors instead of a clean 413.
- A Request built from a string for app.request() has no content-length header, so in-process tests hit bodyLimit's stream-counting path while real clients hit the header path. Test 413 both ways.
- A non-JSON Content-Type does not give 415: zValidator('json') validates {} and returns a 400 about missing fields; a schema with only optional fields would pass. Add an explicit content-type check if 415 matters.
- Malformed JSON is an HTTPException(400) thrown by hono/validator, not a zod failure — it bypasses the zValidator hook and must be converted to problem+json in app.onError.
- Aborting the AbortSignal passed to app.request(url, {signal}) does NOT run SSE cleanup; only cancelling the response body does. Tests must call reader.cancel() and then await one tick before asserting.
- The streamSSE callback must keep awaiting until abort/shutdown; when it returns the stream closes. Put unsubscribe and clearInterval in finally so both the client-disconnect and server-shutdown paths clean up.
- writeSSE field order on the wire is event, data, id (then retry). It throws if id or event contain CR/LF; multi-line data becomes multiple data: lines.
- server.close() never resolves while an SSE response is open, and it also waited ~4 s for a spare socket undici opens after an aborted fetch (never-used connections are not closed as idle). Test teardown should call server.closeAllConnections(); production shutdown needs the app-level signal plus a forced fallback.
- After closeAllConnections() the fetch client read rejects with TypeError 'terminated' (cause UND_ERR_SOCKET); after a signal-driven shutdown it sees a clean end (done=true). The console must treat both as 'reconnect'.
- Proxy with hard-coded SSE response headers relabels upstream errors: a proxied 401 problem came back as text/event-stream. Forward upstream status and content-type, or branch on up.ok.
- Passing req.signal into the proxy's upstream fetch is not needed for abort propagation and made node-server print 'Error: aborted' to stderr on each disconnect.
- Proxy results were measured with a @hono/node-server fetch handler, not a Next.js route handler — that still needs its own check.
- zod 4 issues include a `pattern` field with the full regex for uuid/datetime; map issues to {pointer, code, detail} instead of returning them raw.
- z.iso.datetime() rejects offsets like +09:00 unless {offset: true}, and requires seconds. Decide which the SDK emits and pin it.
- z.strictObject() is not recursive — nested z.object() still strips unknown keys silently.
- z.uuid() in zod 4 is RFC-strict (version/variant bits); arbitrary 8-4-4-4-12 hex needs z.guid(). z.uuidv7() exists and accepts uppercase.
- z.record(valueSchema) with one argument is a type error in zod 4 (TS2554) even though it runs; z.record with an enum key is exhaustive (use z.partialRecord).
- z.flattenError collapses nested paths to the top-level key; use issues or z.treeifyError for field-level detail.
- vitest 5.1.0 printed no console.log output in a default run here; logs appeared when run with --reporter=verbose --silent=false (I did not isolate which flag was responsible).
- Promise.withResolvers resolve cannot be passed directly as an event listener under strict TS (parameter type mismatch); wrap it: const finish = () => resolve().
- Node 22.12 cannot run .ts files directly without a flag; the spike ran all TypeScript through vitest. The plan's tsx dependency covers this for the real service.
- @hono/node-server v2 is ESM-first ("type":"module"), requires Node >=20, and no longer ships @hono/node-server/vercel.

### Working snippets

**problem+json helper, typed env, bearer auth middleware (src/app.ts)**

````text
export type Principal = { kind: 'app-key'; appId: string; orgId: string }
export type AppEnv = { Variables: { principal: Principal; requestId: string } }

export function problem(c: Context, status: ContentfulStatusCode, title: string, detail?: string, extras: Record<string, unknown> = {}) {
  const body = { type: `https://antireverse.dev/problems/${title.toLowerCase().replaceAll(' ', '-')}`, title, status,
    ...(detail ? { detail } : {}), instance: c.req.path, ...extras }
  return c.body(JSON.stringify(body), status, { 'Content-Type': 'application/problem+json' })
}

const app = new Hono<AppEnv>()
const auth = createMiddleware<AppEnv>(async (c, next) => {   // from 'hono/factory'
  const m = c.req.header('Authorization')?.match(/^Bearer (\S+)$/i)
  const principal = m ? deps.keys.get(m[1]!) : undefined
  if (!principal) {
    c.header('WWW-Authenticate', 'Bearer realm="antireverse"')
    return problem(c, 401, 'Unauthorized', m ? 'Unknown API key.' : 'Missing or malformed Authorization header.')
  }
  c.set('principal', principal)
  await next()
})
````

**POST route: body limit with bounded drain, zod validation, error mapping (src/app.ts)**

````text
export const IngestBody = z.strictObject({
  eventId: z.uuidv7(),
  occurredAt: z.iso.datetime({ offset: true }),
  mode: z.enum(['monitor', 'enforce']),
  request: z.object({ method: z.string().min(1), path: z.string().min(1), status: z.number().int() }),
})

/** discard up to `cap` bytes of an unread request body; true if fully drained */
export async function drainBody(req: Request, cap: number): Promise<boolean> {
  if (!req.body || req.bodyUsed) return true
  const reader = req.body.getReader()
  let n = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) return true
    n += value.byteLength
    if (n > cap) { void reader.cancel().catch(() => {}); return false }
  }
}

app.post('/v1/ingest/events',
  auth,
  bodyLimit({
    maxSize: 256 * 1024,
    onError: async (c) => {
      // unread body => node-server kills the socket ~500ms later; clients see ECONNRESET/EPIPE
      if (!(await drainBody(c.req.raw, 8 * 1024 * 1024))) c.header('Connection', 'close')
      return problem(c, 413, 'Payload Too Large', 'Body exceeds 262144 bytes.')
    },
  }),
  zValidator('json', IngestBody, (result, c) => {
    if (!result.success) {
      return problem(c, 400, 'Invalid Request Body', z.prettifyError(result.error), {
        errors: result.error.issues.map((i) => ({ pointer: `/${i.path.join('/')}`, code: i.code, detail: i.message })),
      })
    }
  }),
  (c) => {
    const body = c.req.valid('json')      // typed IngestBody
    const p = c.get('principal')          // typed Principal
    deps.bus.publish({ id: body.eventId, type: 'request.observed', appId: p.appId, data: body })
    return c.json({ accepted: true, appId: c.var.principal.appId }, 202)
  },
)

app.notFound((c) => problem(c, 404, 'Not Found'))
app.onError((err, c) => {
  if (err instanceof HTTPException)       // e.g. 'Malformed JSON in request body' from hono/validator
    return problem(c, err.status, err.status === 400 ? 'Bad Request' : 'HTTP Error', err.message)
  console.error(err)
  return problem(c, 500, 'Internal Server Error')
})
````

**SSE endpoint with heartbeat, disconnect + shutdown cleanup (src/app.ts)**

````text
export class Bus {
  #em = new EventEmitter()
  constructor() { this.#em.setMaxListeners(0) }
  publish(e: FeedEvent) { this.#em.emit('event', e) }
  subscribe(fn: (e: FeedEvent) => void): () => void { this.#em.on('event', fn); return () => this.#em.off('event', fn) }
  get listenerCount() { return this.#em.listenerCount('event') }
}

app.get('/v1/feed', auth, (c) => {
  const { appId } = c.get('principal')
  return streamSSE(c, async (stream) => {
    const { promise: done, resolve } = Promise.withResolvers<void>()
    const finish = () => resolve()
    const unsubscribe = deps.bus.subscribe((e) => {
      if (e.appId !== appId) return
      void stream.writeSSE({ id: e.id, event: e.type, data: JSON.stringify(e.data) })
    })
    const hb = setInterval(() => void stream.write(': hb\n\n'), deps.heartbeatMs)
    stream.onAbort(finish)                                           // client disconnect (body cancelled)
    deps.shutdown.addEventListener('abort', finish, { once: true })  // server shutdown
    try {
      await stream.write(': connected\n\n')   // first bytes immediately
      await done
    } finally {
      clearInterval(hb)
      unsubscribe()
      deps.shutdown.removeEventListener('abort', finish)
    }
    // returning => streamSSE closes the stream => response ends cleanly
  })
})
````

**vitest: SSE through app.request(), two events then cancel (test/02-sse.test.ts)**

````text
it('reads first two events then cancel() -> abort/cleanup path runs', async () => {
  const { app, bus } = make()
  const res = await app.request('/v1/feed', { headers: { Authorization: `Bearer ${KEY}` } })
  expect(res.headers.get('content-type')).toBe('text/event-stream')
  const r = sseReader(res.body!)                 // splits on '\n\n', skips ':' comment frames in nextEvent()
  expect(await r.next()).toBe(': connected')
  expect(bus.listenerCount).toBe(1)

  bus.publish(ev(1))
  bus.publish({ ...ev(99), appId: 'other_app' }) // filtered out
  bus.publish(ev(2))
  expect(await r.nextEvent()).toEqual({ event: 'request.observed', data: '{"n":1}', id: 'id-1' })
  expect(await r.nextEvent()).toEqual({ event: 'request.observed', data: '{"n":2}', id: 'id-2' })

  await r.reader.cancel()
  await new Promise((r) => setTimeout(r, 0))     // cleanup runs asynchronously after onAbort
  expect(bus.listenerCount).toBe(0)
})
````

**listen on port 0 and shut down gracefully with a forced fallback (src/server.ts)**

````text
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { serve } from '@hono/node-server'

export function listen(fetch: (req: Request) => Response | Promise<Response>, port = 0, hostname = '127.0.0.1') {
  return new Promise<{ server: Server; port: number; url: string }>((resolve, reject) => {
    const server = serve({ fetch, hostname, port }, (info: AddressInfo) => {
      resolve({ server: server as Server, port: info.port, url: `http://${hostname}:${info.port}` })
    }) as Server
    server.once('error', reject)
  })
}

/** 1. abort app signal -> SSE handlers return; 2. close() stops accepting; 3. sweep idle sockets, force after graceMs */
export function shutdown(server: Server, ac: AbortController, graceMs = 2000): Promise<'graceful' | 'forced'> {
  return new Promise((resolve) => {
    let forced = false
    ac.abort()
    const sweep = setInterval(() => server.closeIdleConnections(), 20)
    const force = setTimeout(() => { forced = true; server.closeAllConnections() }, graceMs)
    server.close(() => { clearInterval(sweep); clearTimeout(force); resolve(forced ? 'forced' : 'graceful') })
  })
}
````

**SSE proxy handler that stayed unbuffered and propagated aborts (test/04-proxy.test.ts, variant A)**

````text
const proxy = await listen(async (req) => {
  const up = await fetch(`${upstream.url}/v1/feed`, {
    headers: { Authorization: req.headers.get('authorization') ?? '' },
    // signal: req.signal  -> also works, but logs 'Error: aborted' to stderr on every disconnect
  })
  return new Response(up.body, { status: up.status, headers: up.headers })  // keeps upstream content-type for 401 problem+json
}, 39121)
````

## C — Next.js console foundations

**Verdict:** works with caveats

The whole console design works on this machine with next 16.4.6, react 19.3.1, typescript 7.0.2, tailwindcss 4.3.5 and biome 2.6.6 in an npm-workspaces monorepo: `next dev` and `next build && next start` both succeed, a TS-source workspace package is consumed from Server and Client Components with no `transpilePackages`, and the SSE proxy streams unbuffered in both modes with the upstream closing within about 10 ms of client disconnect when `request.signal` is passed. useActionState, the httpOnly cookie, the cookie-guarded page and the live feed were all exercised end to end (curl plus a real browser). The main caveat is that create-next-app 16.4.6 turns on `cacheComponents: true` + `partialPrefetching: true` by default, which changes three things this design cares about: `redirect()` from a page returns HTTP 200 with a client-side redirect instead of 307, `dynamic`/`runtime` segment exports become build errors, and a "shown once" useActionState result survives back/forward navigation in a hidden Activity. With Cache Components off, a page that reads the cookie outside any Suspense returns a real 307 and the shown-once value is gone after navigating away. Other caveats: the directory name `console` is rejected by create-next-app, Turbopack does not resolve `./x.js` to `./x.ts` inside the source package, and a stale `tsconfig.tsbuildinfo` gave wrong tsc results. Not verified: font build without network, any self-hosted font alternative, Safari handling of the Secure cookie over http, and behaviour behind a reverse proxy.

**Versions:** node 22.12.0; npm 10.9.0; create-next-app 16.4.6; next 16.4.6 (engines node >=20.9.0); react / react-dom 19.3.1 (scaffold pinned 19.3.0); typescript 7.0.2 (scaffold wrote ^5, resolved 5.9.3; both build); tailwindcss 4.3.5 (scaffold pinned 4.3.3); @tailwindcss/turbopack 4.3.5 (scaffold pinned 4.3.3); @biomejs/biome 2.6.6 (scaffold pinned 2.4.2); zod 4.6.7; @types/node 22.20.5 (scaffold wrote ^20); @types/react 19.3.0

### Recommendation

Scaffold apps/console with the command in the first snippet (scaffold as `console-app`, then rename the directory and package), install from the monorepo root with npm, and bump to react 19.3.1, typescript 7.0.2, tailwindcss and @tailwindcss/turbopack 4.3.5, biome 2.6.6 (then `biome migrate` and delete the template public/*.svg), @types/node 22.

For slice 01, delete `cacheComponents: true` and `partialPrefetching: true` from the generated next.config.ts and keep the turbopack CSS loader rule. The console is fully auth-gated and dynamic, so Cache Components buys nothing yet and costs three things that were measured: no real 307 from page-level redirects, banned `dynamic`/`runtime` exports, and the admin key lingering in a hidden Activity after navigation. If the team prefers to keep it on, the plan must instead gate with src/proxy.ts (verified 307), wrap every cookie read in <Suspense>, and explicitly clear the show-once state on navigation.

Do not add transpilePackages. In packages/protocol keep `"exports": "./src/index.ts"` and write relative imports extensionless (or `.ts` with `allowImportingTsExtensions` in each consumer); never `.js` suffixes.

Auth: one `"use server"` module with the sign-in action setting the httpOnly, sameSite lax cookie through `await cookies()`; a `server-only` session helper; the guard as an async Server Component (page or layout) that awaits the cookie and calls `redirect("/login")` with no Suspense or loading.tsx above it. Create-organization uses useActionState with a discriminated-union state and no redirect.

Live feed: a GET Route Handler at src/app/api/feed/route.ts exactly as in the snippet: read the cookie from `request.cookies`, fetch the API stream with `signal: request.signal` and `cache: "no-store"`, return `new Response(upstream.body, { headers })`. Export no segment config. The client uses EventSource and validates each event with the shared zod schema.

Fonts and CSS: use the layout.tsx and globals.css snippets as they are.

Scripts: `typecheck` should be `next typegen && tsc --noEmit` with incremental off or the tsbuildinfo removed; `lint` is `biome check` (there is no `next lint`). Remember `next build` now type-checks everything the tsconfig includes.

Engineers should read <root>/node_modules/next/dist/docs before writing Next code, starting with 01-app/02-guides/upgrading/version-16.md.

Spike files are in /private/tmp/claude-501/-Users-imboyy-Library-Application-Support-Claude-scratch-workspaces-1d3c3090-ace9-4ca6-b667-e892972fcb45-c1a12376-4ec4-4a62-bd0d-b4cfa30ed99d-scratch-2026-11-10-7036ee/6a952bc2-d47e-4d4a-a1dd-ec2c02c63bbb/scratchpad/spikes/c-nextjs-console (app in apps/console, currently in the Cache Components off state; the generated config is saved as logs/next.config.ts.cc-on). All servers on ports 39140-39142 are stopped.

### Gotchas

- create-next-app refuses the directory name `console` ("console is a core module name"). Scaffold as another name, then rename the directory and set the package name (for example @scope/console).
- create-next-app 16.4.6 with --yes writes `cacheComponents: true` and `partialPrefetching: true` into next.config.ts even though --cache-components was not passed. This is a real architectural choice, not a cosmetic default.
- With cacheComponents ON, `redirect()` from a page never produced an HTTP 307 in testing: under <Suspense> it is 200 + `<meta http-equiv=refresh content="1;url=/login">` (a 1 second flash of fallback), and with `export const instant = false` it is 200 with the redirect only in the RSC payload. Only proxy.ts gave a real 307 in that mode.
- Even with cacheComponents OFF, a redirect thrown beneath a <Suspense> boundary is 200 + meta refresh. Keep the cookie guard above any Suspense. A loading.tsx would also create such a boundary; that specific case was not tested.
- With cacheComponents ON, routes stay mounted in a hidden Activity: a useActionState result meant to be shown once (the admin key) was still in the DOM after navigating away and reappeared on back/forward. With it OFF the state was gone. The ON case was observed under next dev and the OFF case under next start.
- With cacheComponents ON, `export const dynamic` and `export const runtime` (including 'nodejs') in a route handler or page are build errors.
- Turbopack does not map `./file.js` to `./file.ts` inside the TS-source workspace package. Use extensionless relative imports, or `.ts` suffixes plus `allowImportingTsExtensions` in every consumer tsconfig. Plain Node 22.12 cannot import the package at all (ERR_UNKNOWN_FILE_EXTENSION), so the API and SDK need tsx or another loader; that side belongs to the other spikes.
- tsconfig has `incremental: true` and TS 7.0.2 writes tsconfig.tsbuildinfo into the app directory. A stale tsbuildinfo gave wrong results in both directions when .next/types appeared or disappeared (passed after `rm -rf .next`, kept failing after `next typegen`). Delete it or disable incremental for CI typechecks.
- A standalone `tsc --noEmit` on a clean checkout fails with `Cannot find name 'LayoutProps'` until `next typegen`, `next dev` or `next build` has generated .next/types.
- Because `next build` type-checks with the project `tsc`, it checks every file matched by tsconfig include, including tests and the workspace package source, using the console's compiler options.
- Without `signal: request.signal` on the upstream fetch, the upstream SSE connection stayed open about 3.6 s after the client left (single measurement). With it, it closed in about 10 ms.
- The scaffold pins react 19.3.0, tailwindcss and @tailwindcss/turbopack 4.3.3, biome 2.4.2, typescript ^5 and @types/node ^20, all behind the intended pins. Bumping them worked, but biome 2.6.6 reports that biome.json's schema is 2.4.2 and that `recommended` is deprecated (run `biome migrate`), and `biome check` fails on the template's public/*.svg files (noSvgWithoutTitle).
- Tailwind is wired through a Turbopack loader rule (`@tailwindcss/turbopack`) in next.config.ts, not PostCSS. Keep that rule when editing next.config.ts and keep its version in step with tailwindcss. Building with `--webpack` under this setup was not tested.
- npm workspaces hoists everything to the root node_modules, so apps/console/node_modules does not exist and the version-matched docs are at <root>/node_modules/next/dist/docs. `next dev` rewrites the AGENTS.md block in apps/console, which says to commit it.
- `import "server-only"` compiled and type-checked without the server-only package installed. Installing it explicitly was not needed here.
- The cookie was set with `secure: NODE_ENV === "production"`, so `next start` over plain http emits a Secure cookie. curl still sent it to 127.0.0.1; browser behaviour for that case (Safari in particular) was not verified, since the browser sign-in test ran under next dev.
- Server Action form posts check the Origin header against the host. The curl test sent a matching Origin; a console served behind a different public host or proxy may need extra configuration (not tested).
- next/font/google needs network at build time. It worked here; an offline or CI-without-egress build was not tested.

### Working snippets

**Scaffold commands (ran from the monorepo's apps/ directory)**

````text
npx --yes create-next-app@16.4.6 console-app --ts --app --tailwind --src-dir --biome --use-npm \
  --import-alias "@/*" --no-react-compiler --no-agent-feedback --disable-git --skip-install --yes
mv console-app console   # "console" itself is rejected: core module name
# apps/console/package.json: name -> "@spike/console", add "@spike/protocol": "*"
cd ../ && npm install
npm install -w @spike/console --save-exact react@19.3.1 react-dom@19.3.1
npm install -w @spike/console --save-exact -D typescript@7.0.2 tailwindcss@4.3.5 \
  @tailwindcss/turbopack@4.3.5 @biomejs/biome@2.6.6 @types/node@22
````

**packages/protocol (TS source export, no build step, no transpilePackages)**

````text
// package.json
{ "name": "@spike/protocol", "version": "0.0.0", "private": true, "type": "module",
  "exports": "./src/index.ts", "dependencies": { "zod": "4.6.7" } }

// src/index.ts
import { z } from "zod";
export const ShieldEvent = z.object({
  id: z.string(), appId: z.string(), method: z.string(), path: z.string(),
  at: z.iso.datetime(),
});
export type ShieldEvent = z.infer<typeof ShieldEvent>;
export { MAX_FEED_ROWS } from "./limits";          // extensionless: OK
export { PROTOCOL_VERSION } from "./version.ts";   // OK with allowImportingTsExtensions
// export ... from "./version.js"  -> Turbopack: Module not found: Can't resolve './version.js'
````

**next.config.ts (Cache Components off variant that gave a real 307 and true show-once)**

````text
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // create-next-app generated `cacheComponents: true, partialPrefetching: true` here; removed.
  turbopack: {
    rules: {
      "*.css": { loaders: ["@tailwindcss/turbopack"], as: "*.css" },
    },
  },
};
export default nextConfig;
````

**src/app/actions.ts (useActionState action + cookie action)**

````text
"use server";
import { PROTOCOL_VERSION } from "@spike/protocol";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { ADMIN_COOKIE } from "@/lib/session";

export type CreateOrgState =
  | { status: "idle" }
  | { status: "error"; message: string }
  | { status: "created"; orgId: string; adminKey: string; protocol: string };

export async function createOrg(_prev: CreateOrgState, formData: FormData): Promise<CreateOrgState> {
  const name = String(formData.get("name") ?? "").trim();
  if (!name) return { status: "error", message: "Name is required" };
  return { status: "created", orgId: `org_${name.toLowerCase()}`,
    adminKey: `ark_${crypto.randomUUID()}`, protocol: PROTOCOL_VERSION };
}

export async function signIn(formData: FormData): Promise<void> {
  const store = await cookies();
  store.set(ADMIN_COOKIE, String(formData.get("adminKey") ?? ""), {
    httpOnly: true, sameSite: "lax", secure: process.env.NODE_ENV === "production",
    path: "/", maxAge: 60 * 60 * 8,
  });
  redirect("/feed"); // 303 for no-JS form posts, client navigation otherwise
}

export async function signOut(): Promise<void> {
  (await cookies()).delete(ADMIN_COOKIE);
  redirect("/login");
}
````

**src/app/setup/create-org-form.tsx (Client Component, shown once, no redirect)**

````text
"use client";
import { useActionState } from "react";
import { type CreateOrgState, createOrg } from "../actions";

const initial: CreateOrgState = { status: "idle" };

export function CreateOrgForm() {
  const [state, formAction, pending] = useActionState(createOrg, initial);
  return (
    <form action={formAction} className="flex flex-col gap-3 max-w-md">
      <input name="name" placeholder="Organization name" className="border border-line bg-surface-1 px-3 py-2" />
      <button type="submit" disabled={pending} className="bg-signal text-surface-0 px-3 py-2 font-medium">
        {pending ? "Creating..." : "Create organization"}
      </button>
      {state.status === "error" && <p className="text-danger">{state.message}</p>}
      {state.status === "created" && (
        <output data-testid="admin-key" className="font-mono text-sm text-ink-muted">
          {state.orgId} / {state.adminKey} / {state.protocol} (shown once)
        </output>
      )}
    </form>
  );
}
````

**Cookie read + redirect guard (real 307 with Cache Components off, no Suspense above it)**

````text
// src/lib/session.ts
import "server-only"; // resolved by Next itself; the package was not installed
import { cookies } from "next/headers";
export const ADMIN_COOKIE = "ar_admin_key";
export async function readAdminKey(): Promise<string | undefined> {
  return (await cookies()).get(ADMIN_COOKIE)?.value;
}

// src/app/direct/page.tsx
import { redirect } from "next/navigation";
import { readAdminKey } from "@/lib/session";

export default async function Direct() {
  const key = await readAdminKey();
  if (!key) redirect("/login"); // HTTP 307 Location: /login (CC off, not inside <Suspense>)
  return <main className="p-8">direct, key ...{key.slice(-4)}</main>;
}
````

**src/proxy.ts (optional gate; real 307 in either Cache Components mode)**

````text
import { type NextRequest, NextResponse } from "next/server";

export function proxy(request: NextRequest) {
  if (!request.cookies.has("ar_admin_key")) {
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
}

export const config = { matcher: ["/proxied/:path*"] };
````

**src/app/api/feed/route.ts (SSE proxy; no segment config exports)**

````text
import type { NextRequest } from "next/server";
import { ADMIN_COOKIE } from "@/lib/session";

const UPSTREAM = process.env.API_URL ?? "http://127.0.0.1:39141";

export async function GET(request: NextRequest) {
  const key = request.cookies.get(ADMIN_COOKIE)?.value;
  if (!key) return new Response("unauthorized", { status: 401 });

  const upstream = await fetch(`${UPSTREAM}/events`, {
    headers: { accept: "text/event-stream", authorization: `Bearer ${key}` },
    cache: "no-store",
    signal: request.signal, // client disconnect aborts the upstream request (~10 ms)
  });
  if (!upstream.ok || !upstream.body) return new Response("upstream error", { status: 502 });

  return new Response(upstream.body, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
````

**src/app/feed/live-feed.tsx (Client Component using the workspace zod schema)**

````text
"use client";
import { ShieldEvent } from "@spike/protocol";
import { useEffect, useState } from "react";

export function LiveFeed() {
  const [events, setEvents] = useState<ShieldEvent[]>([]);
  useEffect(() => {
    const es = new EventSource("/api/feed");
    es.addEventListener("shield", (e) => {
      const parsed = ShieldEvent.safeParse(JSON.parse((e as MessageEvent).data));
      if (parsed.success) setEvents((prev) => [parsed.data, ...prev].slice(0, 50));
    });
    return () => es.close();
  }, []);
  return (
    <ul className="font-mono text-sm">
      {events.map((e) => (
        <li key={e.id} data-testid="feed-row">{e.at} {e.method} {e.path}</li>
      ))}
    </ul>
  );
}
````

**src/app/layout.tsx (fonts)**

````text
import type { Metadata } from "next";
import { IBM_Plex_Sans, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const plexSans = IBM_Plex_Sans({ variable: "--font-plex-sans", subsets: ["latin"], display: "swap" });
const jetbrainsMono = JetBrains_Mono({ variable: "--font-jetbrains-mono", subsets: ["latin"], display: "swap" });

export const metadata: Metadata = { title: "Spike console" };

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${plexSans.variable} ${jetbrainsMono.variable} h-full antialiased`}>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
````

**src/app/globals.css (Tailwind 4.3.5, dark-only tokens)**

````text
@import "tailwindcss";

/* Dark-only: tokens live on :root, no prefers-color-scheme branch. */
:root {
  color-scheme: dark;
  --surface-0: #0b0d10;
  --surface-1: #13161b;
  --line: #262b33;
  --ink: #e6e9ee;
  --ink-muted: #8b94a3;
  --signal: #4ade80;
  --danger: #f87171;
}

@theme inline {
  --color-surface-0: var(--surface-0);
  --color-surface-1: var(--surface-1);
  --color-line: var(--line);
  --color-ink: var(--ink);
  --color-ink-muted: var(--ink-muted);
  --color-signal: var(--signal);
  --color-danger: var(--danger);
  --font-sans: var(--font-plex-sans), ui-sans-serif, system-ui, sans-serif;
  --font-mono: var(--font-jetbrains-mono), ui-monospace, monospace;
}

body {
  background: var(--surface-0);
  color: var(--ink);
}
````

**spike/upstream.mjs (the node:http SSE upstream used for the proxy test)**

````text
import http from "node:http";
const port = Number(process.env.PORT ?? 39141);
let n = 0;
http.createServer((req, res) => {
  const id = ++n;
  console.log(`${new Date().toISOString()} upstream OPEN #${id} ${req.url} auth=${req.headers.authorization ?? "-"}`);
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache", connection: "keep-alive" });
  let seq = 0;
  const send = () => res.write(`event: shield\ndata: ${JSON.stringify({ id: `${id}-${++seq}`, appId: "app_1", method: "GET", path: "/x", at: new Date().toISOString() })}\n\n`);
  send();
  const t = setInterval(send, 500);
  req.on("close", () => { clearInterval(t); console.log(`${new Date().toISOString()} upstream CLOSE #${id} after ${seq} events`); });
}).listen(port, "127.0.0.1");
````

## D — TypeScript 7 toolchain and Shield mechanics

**Verdict:** works with caveats

The planned toolchain works end to end on Node 22.12.0: an npm-workspaces monorepo with source-exported packages type-checks under typescript@7.0.2 in about a quarter of a second, runs under tsx@4.23.15 and under plain node with --experimental-strip-types, passes 75 vitest@5.1.0 tests, and is clean under Biome 2.6.6. TypeScript 7 is the native compiler: `require("typescript")` exposes only `version`, so any tool that needs the TS JavaScript API will not work with it; tsx, vitest and Biome do not use it, but Next.js 16 was not tested here. Express 5.3.0 has three traps for the middleware: `req.baseUrl` is the concrete URL (not a template) for parameterised mounts, the router restores `req.baseUrl` before an app-level error handler answers (naive template `/boom` instead of `/api/v1/boom`), and `finish` does not fire on client aborts. An accessor on `req.route` that captures the base at match time, plus recording on `close`, fixed all three in tests. An in-flight `fetch` delays process exit until its AbortSignal.timeout fires (1.5 s measured), whereas an unref'd timer plus node:http with an unref'd socket never delays exit. Not verified: Next.js with TS 7, `vitest --typecheck` with TS 7 (no type-test files existed), Biome's VCS ignore-file integration (spike dir is not a git repo), and consuming the emitted .d.ts files for a published SDK.

**Versions:** node 22.12.0; npm 10.9.0; typescript 7.0.2 (native binary via @typescript/typescript-darwin-arm64); tsx 4.23.15 (esbuild 0.28.2); vitest 5.1.0 (vite 8.3.7, rolldown); @biomejs/biome 2.6.6; express 5.3.0 (router 2.2.0, path-to-regexp 8.4.2, finalhandler 2.1.1); @types/express 5.0.6; zod 4.6.7; supertest 7.3.2 (superagent 10.4.2, @types/supertest 7.2.1); @types/node 22.20.5

### Recommendation

Build slice 01 on this layout: npm workspaces, `"type": "module"`, packages exporting `./src/index.ts`, one tsconfig.base.json as in the snippet, a root solution tsconfig, and `tsc -b` as the single typecheck command (about 0.25 s). Ignore `*.tsbuildinfo` in git and Biome.

- **Runner:** use `tsx` / `tsx watch` for development, but keep `erasableSyntaxOnly`, `verbatimModuleSyntax` and `.ts` import extensions so `node --experimental-strip-types` also works.
- **Tests:** vitest 5.1.0 with `test.projects: ["packages/*", "apps/*"]`; test HTTP with `http.createServer(app).listen(0, "127.0.0.1")` plus fetch and a `stop()` helper that calls `closeAllConnections()`. Skip supertest; it works but adds nothing here.
- **Biome:** the biome.json in the snippet; `biome check --write .` locally, `biome ci . --error-on-warnings` in CI.
- **Shield middleware:** type it against `node:http` only (no express import), import protocol with `import type` only, wrap everything in try/catch with `next()` outside, record on `res.once("close")`, capture the peer address and `hrtime.bigint()` at entry, and use the `req.route` accessor for exact templates. Keep the route test table (nested router, param mount, error handler, 404, abort, keep-alive) as a regression guard, since the accessor depends on router 2.2.0 internals; pin express 5.3.0 exactly.
- **Batching:** fixed ring with overwrite and a dropped counter, lazy `setTimeout().unref()`, flush that never rejects, optional `close()` for the host. For the transport I would use `node:http` with an unref'd socket rather than fetch, because it is the only variant that never delayed exit; fetch with AbortSignal.timeout is simpler but can hold a finishing process for up to the timeout. If fetch is kept, set the timeout to 2 s or less and document the delay.
- **Helpers:** take the pooled UUIDv7 and `truncateIp` as written, with their tests.

Before pinning typescript@7.0.2 repo-wide, run a separate check that Next.js 16.4.6 builds and type-checks with it, since TS 7 ships no JS compiler API. If that fails, the fallback is TS 7 for the Node packages and whatever Next supports for the console package.

Everything is in /private/tmp/claude-501/-Users-imboyy-Library-Application-Support-Claude-scratch-workspaces-1d3c3090-ace9-4ca6-b667-e892972fcb45-c1a12376-4ec4-4a62-bd0d-b4cfa30ed99d-scratch-2026-11-10-7036ee/6a952bc2-d47e-4d4a-a1dd-ec2c02c63bbb/scratchpad/spikes/d-toolchain-shield (sources under packages/ and apps/, throwaway probes and benchmarks under probe/). All servers started during the spike were stopped; no listener remains on 39160-39179.

### Gotchas

- typescript@7.0.2 has no JavaScript compiler API: `require("typescript")` returns only `{ version, versionMajorMinor }` (main export is lib/version.cjs; the real API is under `typescript/unstable/*`). Anything that imports the TS API (Next.js build-time type check, typescript-eslint, ts-jest, API extractors) is at risk. Next.js 16.4.6 with TS 7 was NOT tested in this spike and needs its own check before pinning.
- TS 7 `types` defaults to an empty list: without `"types": ["node"]`, `process` and `node:fs` do not resolve (TS2591). A Next.js or DOM package will need its own `types`/`lib`.
- TS 7 hard-removes `baseUrl`, `moduleResolution: node|node10|classic`, `target: es5`, `module: amd`, `outFile`, `downlevelIteration`, and `esModuleInterop/allowSyntheticDefaultImports/alwaysStrict: false`; `ignoreDeprecations` does not restore them. Copy-pasted tsconfigs from older projects will fail.
- `tsc -b` with noEmit writes a `tsconfig.tsbuildinfo` next to each package tsconfig and always reports projects as out of date (it still finishes in ~0.25 s). Add `*.tsbuildinfo` to .gitignore and the Biome ignore list.
- With source exports each consumer re-checks the dependency's source under the consumer's own tsconfig, so all packages must share compatible compiler options (one base config).
- Node 22.12.0 type stripping needs `--experimental-strip-types`, prints an ExperimentalWarning, requires `.ts` in relative import specifiers, rejects enums/parameter properties, and refuses .ts files physically under node_modules. It only works for workspace packages because npm symlinks them.
- vitest 5.1.0 requires Node `^22.12.0 || ^24 || >=26`: this machine's 22.12.0 is the exact minimum.
- Express 5 `req.baseUrl` is the concrete matched URL, not a template: a router mounted at `/orgs/:orgId` yields `/api/orgs/9`, which would explode route cardinality unless the mount params are substituted back.
- Express 5 restores `req.baseUrl` and `req.params` when routing leaves a router, but not `req.route`. Consequences at response time: an app-level error handler sees baseUrl `''` (naive template `/boom` instead of `/api/v1/boom`); a 404 has baseUrl and params undefined; a route that called next() and fell through to 404 leaves a stale `req.route`.
- router 2.2.0 assigns `req.route` twice per match (index.js:281 and lib/route.js:115); by the second assignment `req.params` has been replaced by the route's own params when mergeParams is off. The accessor must capture only on the first assignment. This relies on router internals, so pin express and keep the test that covers it.
- Responses ended by middleware (static files, auth rejections via `app.use`) and all unmatched requests have no route; the event's `route` is null and the console must handle that.
- `res.on('finish')` does not fire when the client aborts; only `close` does, with `res.writableFinished === false`. Use `close` to get one event per request.
- A server started with `app.listen(port)` and no host binds `::` (dual stack), so IPv4 clients arrive as `::ffff:a.b.c.d`. The truncation helper must treat mapped addresses as IPv4.
- Behind a proxy `req.socket.remoteAddress` is the proxy's address; trusted `X-Forwarded-For` handling was out of scope and not tested.
- An in-flight `fetch` holds the process open until it settles or its AbortSignal.timeout fires (1.5 s measured). The unref'd timer alone does not prevent this; only `http.request` with an unref'd socket gave zero exit delay.
- Because the flush timer is unref'd and no exit hook is installed, events still in the ring when a short-lived process exits are lost. That is acceptable for monitor mode but needs an explicit `close()` the host may call on SIGTERM.
- The UUIDv7 generator is monotonic per process via module state: a caller-supplied timestamp earlier than the last one is clamped forward. Tests that pass a fixed timestamp must run last or use a future value.
- truncateIp does not canonicalise the /48 text: `::1` becomes `0:0:0::/48`, `2001:db8::1` becomes `2001:db8:0::/48`. Stable, but not RFC 5952 form.
- Biome 2.6.6 uses `linter.rules.preset: "recommended"`; `recommended: true` is deprecated. Unused imports/variables, `any` and non-null assertions are warnings and do not fail `biome check` unless `--error-on-warnings` is passed. Empty `catch {}` blocks are not flagged by the recommended set.
- With port 0 + fetch tests, `server.close()` without `server.closeAllConnections()` waits about 5 s per server for undici's keep-alive sockets.
- Publishing shield-node later: emitting with `--rewriteRelativeImportExtensions` rewrote the .js imports to `./batcher.js`, but the emitted index.d.ts still imports `./batcher.ts` and `@spike/protocol` types, and `test/` was emitted too. A separate build tsconfig and a decision on bundling protocol types are needed; consumer-side resolution of those .d.ts files was not verified.

### Working snippets

**tsconfig.base.json (TS 7.0.2, Node 22 ESM, strict, no emit) and per-package / root configs**

````text
// tsconfig.base.json
{
  "compilerOptions": {
    "target": "es2024",
    "lib": ["es2024"],
    "module": "nodenext",
    "moduleResolution": "nodenext",
    "types": ["node"],            // TS 7 default is [] - nothing from @types is auto-included
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noFallthroughCasesInSwitch": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "verbatimModuleSyntax": true,
    "isolatedModules": true,
    "erasableSyntaxOnly": true,   // keeps code runnable by node --experimental-strip-types
    "allowImportingTsExtensions": true,
    "noUncheckedSideEffectImports": true,
    "moduleDetection": "force",
    "skipLibCheck": true,
    "noEmit": true
  }
}

// packages/*/tsconfig.json and apps/*/tsconfig.json
{ "extends": "../../tsconfig.base.json", "include": ["src", "test"] }

// root tsconfig.json - `tsc -b` checks everything; writes */tsconfig.tsbuildinfo (gitignore it)
{
  "files": [],
  "references": [{ "path": "packages/protocol" }, { "path": "packages/shield-node" }, { "path": "apps/range" }]
}
````

**Source-export package.json files (npm workspaces)**

````text
// root package.json
{ "private": true, "type": "module", "workspaces": ["packages/*", "apps/*"],
  "devDependencies": { "typescript": "7.0.2", "tsx": "4.23.15", "vitest": "5.1.0", "@biomejs/biome": "2.6.6", "@types/node": "^22" } }

// packages/protocol/package.json
{ "name": "@spike/protocol", "private": true, "type": "module", "exports": "./src/index.ts",
  "dependencies": { "zod": "4.6.7" } }

// packages/shield-node/package.json - protocol is a devDependency: only `import type` is used
{ "name": "@spike/shield-node", "private": true, "type": "module", "exports": "./src/index.ts",
  "devDependencies": { "@spike/protocol": "*", "express": "5.3.0", "@types/express": "^5" } }

// inside packages: relative imports carry the real extension
import type { ShieldEvent } from "@spike/protocol";
import { Batcher, type BatcherOptions } from "./batcher.ts";
````

**biome.json (2.6.6)**

````text
{
  "$schema": "./node_modules/@biomejs/biome/configuration_schema.json",
  "files": {
    "includes": ["**", "!**/dist", "!**/.next", "!**/coverage", "!**/*.tsbuildinfo"]
  },
  "formatter": { "enabled": true, "indentStyle": "space", "indentWidth": 2, "lineWidth": 120 },
  "linter": { "enabled": true, "rules": { "preset": "recommended" } },
  "assist": { "enabled": true, "actions": { "source": { "organizeImports": "on" } } }
}
// check:  biome check .            (CI: biome ci . --error-on-warnings)
// fix:    biome check --write .    (add --unsafe for unsafe fixes)
````

**Exact route template: capture baseUrl at match time (packages/shield-node/src/index.ts)**

````text
type Req = IncomingMessage & { baseUrl?: string; route?: { path?: unknown }; params?: Record<string, unknown> };

function formatRoute(base: string, p: unknown): string {
  if (typeof p === "string") return base + p || "/";
  if (Array.isArray(p)) return `${base}[${p.map(String).join("|")}]`;
  return base + String(p); // RegExp
}

/** Replace mount-path segments that equal a param value with ":name" (/api/orgs/9 -> /api/orgs/:orgId). */
function templateBase(base: string, params: Record<string, unknown> | undefined): string {
  if (base === "" || params === undefined) return base;
  const segs = base.split("/");
  for (const [name, value] of Object.entries(params)) {
    if (typeof value !== "string" || value === "") continue;
    for (let i = segs.length - 1; i > 0; i--) {
      let seg = segs[i] as string;
      try { seg = decodeURIComponent(seg); } catch {}
      if (seg === value) { segs[i] = `:${name}`; break; }
    }
  }
  return segs.join("/");
}

export function trackRoute(req: Req): () => string | null {
  let route = req.route;
  let base = "";
  Object.defineProperty(req, "route", {
    configurable: true,
    enumerable: true,
    get: () => route,
    set: (r: { path?: unknown } | undefined) => {
      // router sets req.route twice per match (Router.handle, then Route.dispatch); only the first
      // assignment still sees the mount layer's params.
      if (r !== route) base = templateBase(req.baseUrl ?? "", req.params);
      route = r;
    },
  });
  return () => (route?.path === undefined ? null : formatRoute(base, route.path));
}
````

**Middleware body: never throws, records on 'close' (packages/shield-node/src/index.ts)**

````text
const mw = (req: IncomingMessage, res: ServerResponse, next: Next): void => {
  try {
    const start = process.hrtime.bigint();
    const peer = req.socket.remoteAddress; // capture now, not at close
    const route = trackRoute(req as Req);
    // 'close' fires exactly once for every response, including client aborts ('finish' does not).
    res.once("close", () => {
      try {
        const ev: ShieldEvent = {
          id: uuidv7(),
          ts: Date.now(),
          method: req.method ?? "GET",
          route: route(),
          status: res.statusCode,
          latencyUs: Number((process.hrtime.bigint() - start) / 1000n),
          ipPrefix: truncateIp(peer),
          mode: "monitor",
        };
        batcher.record(ev);
        sink?.(ev, { aborted: !res.writableFinished });
      } catch {}
    });
  } catch {}
  next();
};
````

**Batcher core: ring buffer, lazy unref'd timer, flush that never rejects (packages/shield-node/src/batcher.ts)**

````text
record(ev: ShieldEvent): void {
  this.#ring[this.#head] = ev;
  this.#head = (this.#head + 1) % this.#cap;
  if (this.#size < this.#cap) this.#size++;
  else this.#dropped++;
  if (this.#timer === undefined) this.#arm();
}

#arm(): void {
  // setTimeout (not setInterval), armed lazily: an idle process has no timer at all.
  this.#timer = setTimeout(() => {
    this.#timer = undefined;
    void this.flush();
  }, this.#o.flushIntervalMs);
  this.#timer.unref();
}

async flush(): Promise<void> {
  if (this.#inFlight || this.#size === 0) return;
  this.#inFlight = true;
  try {
    const body: IngestBatch = { appId: this.#o.appId, events: this.#drain(this.#o.maxBatch) };
    const res = await fetch(this.#o.endpoint, {
      method: "POST",
      headers: { "content-type": "application/json", ...(this.#o.apiKey ? { authorization: `Bearer ${this.#o.apiKey}` } : {}) },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(this.#o.timeoutMs),
    });
    await res.body?.cancel(); // release the keep-alive socket
    if (!res.ok) throw new Error(`ingest responded ${res.status}`);
  } catch (err) {
    try { this.#o.onError?.(err); } catch {}   // batch is dropped, never retried
  } finally {
    this.#inFlight = false;
    if (this.#size > 0 && this.#timer === undefined) this.#arm();
  }
}

// Measured alternative with zero exit delay (probe/exit2.ts): exits in 4 ms against a hanging endpoint
const req = http.request(url, { method: "POST", signal: AbortSignal.timeout(1500) }, (res) => res.resume());
req.on("socket", (s) => s.unref());
req.on("error", () => {});
req.end(json);
````

**UUIDv7 with node:crypto (packages/shield-node/src/uuidv7.ts)**

````text
import { randomFillSync } from "node:crypto";

const HEX: string[] = [];
for (let i = 0; i < 256; i++) HEX.push((i + 0x100).toString(16).slice(1));

const POOL_SIZE = 4096; // one randomFillSync call costs ~0.8us regardless of size
const pool = new Uint8Array(POOL_SIZE);
let poolPos = POOL_SIZE;
let lastMs = 0;
let seq = 0; // 12-bit counter in rand_a: strict order within one millisecond
const b = new Uint8Array(16);

export function uuidv7(nowMs: number = Date.now()): string {
  if (poolPos + 10 > POOL_SIZE) { randomFillSync(pool); poolPos = 0; }
  let ms = nowMs;
  if (ms <= lastMs) {
    ms = lastMs;                       // same ms, or clock went backwards
    seq = (seq + 1) & 0xfff;
    if (seq === 0) ms = lastMs + 1;    // counter overflow: borrow the next ms
  } else {
    seq = (((pool[poolPos] as number) << 8) | (pool[poolPos + 1] as number)) & 0x7ff;
  }
  lastMs = ms;
  b[0] = Math.floor(ms / 0x10000000000) & 0xff; // division: JS bit ops truncate to 32 bits
  b[1] = Math.floor(ms / 0x100000000) & 0xff;
  b[2] = Math.floor(ms / 0x1000000) & 0xff;
  b[3] = Math.floor(ms / 0x10000) & 0xff;
  b[4] = Math.floor(ms / 0x100) & 0xff;
  b[5] = ms & 0xff;
  b[6] = 0x70 | (seq >>> 8);           // version 7
  b[7] = seq & 0xff;
  b[8] = ((pool[poolPos + 2] as number) & 0x3f) | 0x80; // variant 10xx
  for (let i = 9; i < 16; i++) b[i] = pool[poolPos + i - 6] as number;
  poolPos += 10;
  let s = "";
  for (let i = 0; i < 16; i++) {
    s += HEX[b[i] as number];
    if (i === 3 || i === 5 || i === 7 || i === 9) s += "-";
  }
  return s;
}
````

**IP truncation with net.isIP only (packages/shield-node/src/ip.ts)**

````text
import { isIP } from "node:net";

function v6Groups(addr: string): number[] | null {
  let a = addr;
  const zone = a.indexOf("%");
  if (zone !== -1) a = a.slice(0, zone);
  if (isIP(a) !== 6) return null;
  const lastColon = a.lastIndexOf(":");
  const tail = a.slice(lastColon + 1);
  if (tail.includes(".")) { // trailing dotted quad
    const o = tail.split(".").map(Number);
    a = `${a.slice(0, lastColon + 1)}${(((o[0] as number) << 8) | (o[1] as number)).toString(16)}:${(((o[2] as number) << 8) | (o[3] as number)).toString(16)}`;
  }
  const halves = a.split("::");
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const groups = [...head, ...new Array<string>(fill).fill("0"), ...rest].map((g) => Number.parseInt(g, 16));
  return groups.length === 8 ? groups : null;
}

export function truncateIp(addr: unknown): string | null {
  if (typeof addr !== "string" || addr.length === 0 || addr.length > 64) return null;
  if (isIP(addr) === 4) {
    const o = addr.split(".");
    return `${Number(o[0])}.${Number(o[1])}.${Number(o[2])}.0/24`;
  }
  // fast path for what a dual-stack listener reports for IPv4 clients
  if (addr.length > 7 && addr.charCodeAt(0) === 58 && addr.slice(0, 7).toLowerCase() === "::ffff:") {
    const rest = addr.slice(7);
    if (isIP(rest) === 4) {
      const o = rest.split(".");
      return `${Number(o[0])}.${Number(o[1])}.${Number(o[2])}.0/24`;
    }
  }
  const g = v6Groups(addr);
  if (g === null) return null;
  const mapped = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff;
  if (mapped) {
    const hi = g[6] as number;
    const lo = g[7] as number;
    return `${hi >>> 8}.${hi & 0xff}.${lo >>> 8}.0/24`;
  }
  return `${(g[0] as number).toString(16)}:${(g[1] as number).toString(16)}:${(g[2] as number).toString(16)}::/48`;
}
````

**Test pattern: port 0 + fetch, with the shutdown that avoids a 5 s wait; vitest root config**

````text
// vitest.config.ts (root)
import { defineConfig } from "vitest/config";
export default defineConfig({ test: { projects: ["packages/*", "apps/*"] } });

// in a test file
async function listen(app: express.Express, host: string) {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  return { server, port: (server.address() as AddressInfo).port };
}

// fetch (undici) keeps sockets alive; server.close() alone then waits out keepAliveTimeout (5 s).
function stop(server: http.Server) {
  return new Promise<void>((resolve) => {
    server.close(() => resolve());
    server.closeAllConnections();
  });
}

// client abort case
await fetch(`${base}/slow`, { signal: AbortSignal.timeout(50) }).catch(() => {});
````

## E — Test tooling

**Verdict:** works with caveats

Proven on this machine (Node 22.12.0, npm workspaces): vitest@5.1.0 runs a node project, a React 19.3.1 DOM project and a child-process e2e project from one root vitest.config.ts via test.projects (9 tests pass, exit 0); v8 coverage works; Playwright 1.65.0 passes 2 tests against two local node:http servers started by a webServer array. Two real caveats: jsdom@31.0.0 (latest) crashes the Vitest worker on Node 22.12.0 (it needs Node ^22.22.2), so use happy-dom@21.0.4 (works, faster) or pin jsdom@28.1.0 (works); and Playwright 1.65.0 needs chromium build 1254, which is NOT in ~/Library/Caches/ms-playwright (only 1243/1248), so a 104,957,869-byte (about 100 MB) headless-shell download is required. I downloaded the headless shell only into a spike-local PLAYWRIGHT_BROWSERS_PATH (the shared cache was not touched), so the real repo still has to download it once. Vitest-driven child-process servers are cleaned up on pass, fail, startup failure, SIGINT and SIGTERM; SIGKILL of the runner leaks them (unavoidable with this pattern). Not verified: Next.js startup time under webServer, PORT=0 ephemeral ports (kept inside the assigned port range instead), and whether a default `playwright install` would garbage-collect the older cached builds.

**Versions:** node 22.12.0; npm 10.9.0; vitest 5.1.0; @vitest/coverage-v8 5.1.0; vite (peer of vitest, auto-installed) 8.3.7; @vitejs/plugin-react 6.3.0; react / react-dom 19.3.1; @testing-library/react 16.3.3; @testing-library/dom 10.4.2; happy-dom (works) 21.0.4; jsdom (works on Node 22.12.0) 28.1.0; jsdom (latest, FAILS on Node 22.12.0) 31.0.0; @playwright/test 1.65.0; playwright chromium-headless-shell build 1254 (Chrome 158.0.8127.18); typescript (tsc --noEmit passes on spike sources) 7.0.2; @types/react / @types/react-dom 19.3.0; @types/node 22.20.5

### Recommendation

1) Root devDependencies: vitest@5.1.0, @vitest/coverage-v8@5.1.0, @vitejs/plugin-react@6.3.0, @testing-library/react@16.3.3, @testing-library/dom@10.4.2, happy-dom@21.0.4, @playwright/test@1.65.0. Do not add jsdom (31.x cannot run on Node 22.12.0); if jsdom is ever required, pin 28.1.0 or raise Node to >=22.22.2. 2) One root vitest.config.ts using `test.projects` with inline projects (name, root, environment, explicit `include: ['src/**/*.test.{ts,tsx}']`); node for API/SDK packages, happy-dom plus the react plugin for the console's client components. No vitest.workspace file. Scripts: "test": "vitest run", "test:cov": "vitest run --coverage", single project via `vitest run --project <name>`. If coverage.include is set, use '**/src/**/*.{ts,tsx}'. 3) For every DOM project add a setupFiles entry that sets globalThis.IS_REACT_ACT_ENVIRONMENT = true and registers afterEach(cleanup). Test the live feed with a FakeEventSource class installed via vi.stubGlobal('EventSource', ...) and vi.unstubAllGlobals() in afterEach; wrap synchronous fake emissions in act() from @testing-library/react, and use findBy*/waitFor for asynchronous arrivals. 4) Playwright: before the first e2e run execute `npx playwright install --only-shell --no-remove chromium` (about 100 MB, build 1254, lands in ~/Library/Caches/ms-playwright); keep a single chromium project with devices['Desktop Chrome'] headless. Use the playwright.config.ts above: a webServer array with one entry per process (API, customer Express app with Shield, Next console), each with name, env PORT, a `url` pointing at a health route, reuseExistingServer: false, stdout/stderr 'pipe', gracefulShutdown SIGTERM 2 s; give the API 20 s and Next 60-120 s startup timeout (measure the real Next start in the build). Name Playwright files *.e2e.ts with a matching testMatch so Vitest never collects them. 5) For the Vitest-driven integration journey (API + Shield SDK + ingest + SSE without a browser), add an `e2e` project with globalSetup using the spawn-server.ts and global-setup.ts above: getFreePort, spawn with detached: true, poll /health, project.provide URLs, return the stopAll teardown, keep the process 'exit' safety net, fileParallelism: false, testTimeout about 20 s. Every server process in the slice must therefore expose a cheap GET /health, honour a PORT env variable, and exit on SIGTERM. Spike files are in /private/tmp/claude-501/-Users-imboyy-Library-Application-Support-Claude-scratch-workspaces-1d3c3090-ace9-4ca6-b667-e892972fcb45-c1a12376-4ec4-4a62-bd0d-b4cfa30ed99d-scratch-2026-11-10-7036ee/6a952bc2-d47e-4d4a-a1dd-ec2c02c63bbb/scratchpad/spikes/e-test-tooling (vitest.config.ts, playwright.config.ts, packages/ui/vitest.setup.ts, packages/ui/src/LiveFeed.test.tsx, packages/ui/src/fake-event-source.ts, e2e-vitest/spawn-server.ts, e2e-vitest/global-setup.ts, e2e/feed.e2e.ts).

### Gotchas

- jsdom@31.0.0 (latest) is unusable on Node 22.12.0: the Vitest worker fails to start (undici 8 needs Node >=22.19, jsdom 31 needs ^22.22.2). jsdom 30.x has the same engine floor, 29.x needs ^22.13. Only jsdom <=28.1.0 fits this Node. Use happy-dom@21.0.4 (engines >=20) or upgrade Node.
- npm only WARNS (EBADENGINE) on these engine mismatches; the install succeeds and the failure appears at test time. Other planned pins may have the same problem on Node 22.12.0 - watch the EBADENGINE lines on the real install.
- Vitest 5 has no workspace file: vitest.workspace.ts is silently ignored and defineWorkspace is not exported. Only test.projects works.
- Vitest 5 default exclude is only **/node_modules/** and **/.git/** - build output such as dist/ or .next/ is no longer excluded. Give each project an explicit include (src/**) so compiled test files are never picked up.
- Vitest `globals` is off by default, so @testing-library/react does not auto-cleanup and does not set IS_REACT_ACT_ENVIRONMENT. Without the setup file, un-acted state updates give no warning at all and DOM from earlier tests leaks into later ones.
- Neither happy-dom 21 nor jsdom 28 defines EventSource (and Node 22.12 has no global one); the component test must stub it. MessageEvent and Event exist in both.
- Vitest auto-selects the 'minimal' reporter when it detects an AI-agent environment (std-env isAgent) and also disables watch there; console.log from passing tests is then hidden. Pass --reporter=verbose (or default) when you need the logs. In a normal non-CI TTY, bare `vitest` starts watch mode, so scripts must use `vitest run`.
- coverage.include globs resolved against the repo root for a full run but against the project's root when filtered with --project (a root-relative 'packages/*/src/**' reported 0 files with --project core). Use '**/src/**/*.{ts,tsx}' which worked both ways.
- @vitest/coverage-v8 must be the exact same version as vitest (peer is pinned to 5.1.0).
- Playwright 1.65.0 needs chromium build 1254; the shared cache (1243, 1248) does not satisfy it. The spike's copy lives only in the spike directory (PLAYWRIGHT_BROWSERS_PATH), so the real repo needs a one-time download of about 100 MB (headless shell only).
- `playwright install` has a `--no-remove` flag ('do not remove unused browsers'), which implies a default install may delete cached builds no registered installation uses. Whether it would remove the existing 1243/1248/webkit builds was not verified; pass --no-remove to be safe.
- `npx playwright install --only-shell chromium` also wants ffmpeg-1013 (already in the shared cache, so no extra download there).
- Playwright test files must not match Vitest's default include: named them *.e2e.ts with testMatch '**/*.e2e.ts'. Conversely the Vitest e2e files use *.e2e.test.ts under a separate directory and an explicit include.
- Playwright webServer stdout defaults to 'ignore'; set stdout: 'pipe' to see server logs. reuseExistingServer: false makes the run fail if the port is already taken, which is the safer default for fixed ports.
- Killing the Vitest runner with SIGKILL leaks the spawned servers (detached process groups survive). SIGINT and SIGTERM were cleaned up. Free-port probing means the next run still starts, but orphans stay until killed.
- Signalling Vitest (SIGINT/SIGTERM) during a long-running test left the forks test worker process orphaned (ppid 1) still executing the hanging test; I had to kill three such workers by hand. Keep e2e test timeouts short.
- Port probing with net.createServer then spawning has a small race window between probe and bind; acceptable locally. Letting the child bind PORT=0 and reporting its port removes the race but was not run in this spike.
- tsc 7.0.2 type-checked the spike sources (strict, moduleResolution Bundler, jsx react-jsx, skipLibCheck) with exit 0; nothing beyond that was tested for TypeScript 7.
- The Next.js server was replaced by a node:http stub; real `next dev`/`next start` readiness time and its behaviour under SIGTERM via webServer are not verified.

### Working snippets

**vitest.config.ts (repo root) - projects with different environments; ran with 9 passing tests**

````text
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Root-only options (reporters, coverage) live here; each project sets its own environment.
    projects: [
      {
        extends: true,
        test: { name: 'core', root: './packages/core', environment: 'node', include: ['src/**/*.test.ts'] },
      },
      {
        extends: true,
        plugins: [react()],
        test: {
          name: 'ui',
          root: './packages/ui',
          environment: 'happy-dom',
          include: ['src/**/*.test.{ts,tsx}'],
          setupFiles: ['./vitest.setup.ts'], // resolved against the project root
        },
      },
      {
        extends: true,
        test: {
          name: 'e2e',
          environment: 'node',
          include: ['e2e-vitest/**/*.e2e.test.ts'],
          globalSetup: ['./e2e-vitest/global-setup.ts'],
          testTimeout: 20_000,
          hookTimeout: 30_000,
          fileParallelism: false,
        },
      },
    ],
  },
});

// Alternative that also ran: export default defineConfig({ test: { projects: ['packages/*'] } })
// with packages/ui/vitest.config.ts:
//   export default defineProject({ plugins: [react()], test: { name: 'ui', environment: 'happy-dom', setupFiles: ['./vitest.setup.ts'] } });
// Commands: npx vitest run | npx vitest run --project ui | npx vitest run --coverage
````

**packages/ui/vitest.setup.ts - required because Vitest globals are off**

````text
// Testing Library only auto-registers cleanup and the act environment flag when
// afterEach/beforeAll exist as globals, which they do not with Vitest's default globals: false.
import { cleanup } from '@testing-library/react';
import { afterEach } from 'vitest';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => cleanup());
````

**Fake EventSource + component test (React 19.3.1, @testing-library/react 16.3.3, happy-dom) - passing**

````text
// fake-event-source.ts (trimmed)
type Listener = (e: MessageEvent) => void;
export class FakeEventSource {
  static instances: FakeEventSource[] = [];
  static readonly CLOSED = 2;
  readyState = 0;
  onopen: ((e: Event) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  private listeners = new Map<string, Set<Listener>>();
  constructor(public url: string, public init?: EventSourceInit) { FakeEventSource.instances.push(this); }
  addEventListener(type: string, fn: Listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type)!.add(fn);
  }
  removeEventListener(type: string, fn: Listener) { this.listeners.get(type)?.delete(fn); }
  close() { this.readyState = 2; }
  // test controls
  open() { this.readyState = 1; this.onopen?.(new Event('open')); }
  emit(type: string, data: unknown) {
    const e = new MessageEvent(type, { data: JSON.stringify(data) });
    for (const fn of this.listeners.get(type) ?? []) fn(e);
  }
  listenerCount(type: string) { return this.listeners.get(type)?.size ?? 0; }
}

// LiveFeed.test.tsx
import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

beforeEach(() => { FakeEventSource.instances = []; vi.stubGlobal('EventSource', FakeEventSource); });
afterEach(() => { vi.unstubAllGlobals(); });

it('subscribes and renders incoming events (sync act)', () => {
  render(<LiveFeed url="/api/apps/a1/events/stream" />);
  const es = FakeEventSource.instances[0]!;
  act(() => es.open());
  expect(screen.getByTestId('status').textContent).toBe('open');
  act(() => {
    es.emit('shield-event', { id: 'e1', method: 'GET', path: '/login' });
    es.emit('shield-event', { id: 'e2', method: 'POST', path: '/orders' });
  });
  const rows = screen.getAllByRole('row');
  expect(rows[0]!.textContent).toBe('POST/orders'); // newest first
});

it('renders events emitted outside act, awaited with findBy/waitFor', async () => {
  render(<LiveFeed url="/s" />);
  const es = FakeEventSource.instances[0]!;
  setTimeout(() => es.emit('shield-event', { id: 'e9', method: 'PUT', path: '/async' }), 20);
  expect(await screen.findByText('/async')).toBeTruthy();
  await waitFor(() => expect(screen.getAllByRole('row')).toHaveLength(1));
});

it('closes the EventSource on unmount', () => {
  const { unmount } = render(<LiveFeed url="/s" />);
  const es = FakeEventSource.instances[0]!;
  unmount();
  expect(es.readyState).toBe(FakeEventSource.CLOSED);
  expect(es.listenerCount('shield-event')).toBe(0);
});
````

**playwright.config.ts - two local servers via webServer; ran, 2 passed**

````text
import { defineConfig, devices } from '@playwright/test';

const API_PORT = 39181;
const WEB_PORT = 39182;
const API_URL = `http://127.0.0.1:${API_PORT}`;
const WEB_URL = `http://127.0.0.1:${WEB_PORT}`;

export default defineConfig({
  testDir: './e2e',
  testMatch: '**/*.e2e.ts', // keeps Playwright files out of Vitest's *.test.* / *.spec.* default include
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  timeout: 30_000,
  expect: { timeout: 5_000 },
  reporter: [['list']],
  use: { baseURL: WEB_URL, trace: 'retain-on-failure' },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: [
    {
      name: 'api',
      command: 'node e2e/servers/api.mjs',
      env: { PORT: String(API_PORT) },
      url: `${API_URL}/health`,
      timeout: 20_000,
      reuseExistingServer: false,
      stdout: 'pipe',
      stderr: 'pipe',
      gracefulShutdown: { signal: 'SIGTERM', timeout: 2_000 },
    },
    {
      name: 'web',
      command: 'node e2e/servers/web.mjs',
      env: { PORT: String(WEB_PORT), API_URL },
      url: `${WEB_URL}/health`,
      timeout: 60_000, // budget for a real Next.js start; the stub needed well under 1 s
      reuseExistingServer: false,
      stdout: 'pipe',
      stderr: 'pipe',
      gracefulShutdown: { signal: 'SIGTERM', timeout: 2_000 },
    },
  ],
});

// e2e/feed.e2e.ts (the SSE assertion that passed)
//   await page.goto('/');
//   await expect(page.getByTestId('status')).toHaveText('open');
//   const res = await request.post(`${API_URL}/events`, { data: { method: 'GET', path: '/checkout' } });
//   await expect(page.getByRole('row', { name: 'GET /checkout' })).toBeVisible({ timeout: 5_000 });
````

**e2e-vitest/spawn-server.ts - spawn on a free port, wait for readiness, always kill (trimmed, ran)**

````text
import { type ChildProcess, spawn } from 'node:child_process';
import net from 'node:net';

export type Running = { name: string; url: string; pid: number; stop: () => Promise<void> };
const live = new Set<ChildProcess>();

// Last resort: if the runner exits without awaiting teardown, kill every group synchronously.
process.on('exit', () => { for (const child of live) killGroup(child, 'SIGKILL'); });

function killGroup(child: ChildProcess, signal: NodeJS.Signals) {
  if (child.pid === undefined) return;
  try { process.kill(-child.pid, signal); } catch { /* already gone */ } // negative pid = process group
}

export async function getFreePort(from: number, to: number): Promise<number> {
  for (let port = from; port <= to; port++) {
    const free = await new Promise<boolean>((resolve) => {
      const probe = net.createServer();
      probe.once('error', () => resolve(false));
      probe.listen(port, '127.0.0.1', () => probe.close(() => resolve(true)));
    });
    if (free) return port;
  }
  throw new Error(`no free port in ${from}-${to}`);
}

export async function startServer(opts: { name: string; command: string; args: string[]; port: number;
  env?: Record<string, string>; healthPath?: string; timeoutMs?: number }): Promise<Running> {
  const { name, command, args, port, env = {}, healthPath = '/health', timeoutMs = 15_000 } = opts;
  const url = `http://127.0.0.1:${port}`;
  const child = spawn(command, args, {
    env: { ...process.env, ...env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true, // own process group, so npm/npx/tsx/next grandchildren die with it
  });
  live.add(child);
  let output = '';
  child.stdout?.on('data', (c) => (output += c));
  child.stderr?.on('data', (c) => (output += c));
  const exited = new Promise<number | null>((resolve) => {
    child.once('exit', (code) => { live.delete(child); resolve(code); });
    child.once('error', () => resolve(-1));
  });
  const stop = async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    killGroup(child, 'SIGTERM');
    const timer = setTimeout(() => killGroup(child, 'SIGKILL'), 3_000);
    await exited;
    clearTimeout(timer);
  };
  const deadline = Date.now() + timeoutMs;
  let earlyExit: number | null | undefined;
  void exited.then((code) => (earlyExit = code));
  for (;;) {
    if (earlyExit !== undefined) throw new Error(`[${name}] exited with ${earlyExit} before ready\n${output}`);
    try {
      const res = await fetch(url + healthPath, { signal: AbortSignal.timeout(1_000) });
      if (res.ok) break;
    } catch { /* not listening yet */ }
    if (Date.now() > deadline) { await stop(); throw new Error(`[${name}] not ready at ${url}${healthPath} after ${timeoutMs}ms\n${output}`); }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { name, url, pid: child.pid!, stop };
}
````

**e2e-vitest/global-setup.ts + test usage - provide/inject and guaranteed teardown (ran)**

````text
import type { TestProject } from 'vitest/node';
import { getFreePort, type Running, startServer } from './spawn-server';

declare module 'vitest' {
  export interface ProvidedContext { apiUrl: string; webUrl: string }
}

export default async function setup(project: TestProject) {
  const started: Running[] = [];
  const stopAll = async () => { await Promise.allSettled(started.reverse().map((s) => s.stop())); };
  try {
    const apiPort = await getFreePort(39183, 39190);
    const api = await startServer({ name: 'api', command: process.execPath, args: ['e2e/servers/api.mjs'], port: apiPort });
    started.push(api);
    const webPort = await getFreePort(apiPort + 1, 39199);
    const web = await startServer({ name: 'web', command: process.execPath, args: ['e2e/servers/web.mjs'], port: webPort, env: { API_URL: api.url } });
    started.push(web);
    project.provide('apiUrl', api.url);
    project.provide('webUrl', web.url);
  } catch (err) {
    await stopAll(); // a half-started stack must not leak
    throw err;
  }
  return stopAll; // teardown: Vitest runs it after the run, pass or fail
}

// journey.e2e.test.ts
//   import { expect, inject, it } from 'vitest';
//   const apiUrl = inject('apiUrl');
//   const stream = await fetch(`${apiUrl}/stream`, { signal: ac.signal });
//   const reader = stream.body!.pipeThrough(new TextDecoderStream()).getReader();
//   await fetch(`${apiUrl}/events`, { method: 'POST', body: JSON.stringify({ method: 'GET', path: '/vitest' }) });
//   ...read until buf.includes('"path":"/vitest"'); ac.abort(); expect(buf).toContain('event: shield-event');
````

