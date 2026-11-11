// Slice 20 over HTTP/CLI: Virtual patches. The fixture advisories are imported with the real `vulns:sync --fixture`
// command into a fresh data directory, and the API starts on it with the fixture patch catalog of the API tests
// (apps/api/test/fixtures/patch-catalog.ts): the shipped catalog covers qs, lodash and xml2js, which no fixture
// advisory names, so none of its entries could activate here. The real harden CLI registers a Build whose lockfile
// names vuln-range 2.0.5 (GHSA-fx01-0001-rang, High) and @fixture/vuln-scoped 4.2.0 (GHSA-fx01-0005-scop, Critical):
// the query-key patch and the JSON body patch become active in monitor and ship in the signed bundle. A real Express
// app with Shield (`express.json({ verify: shield.verifyBody })`, `bodyVerified`, `errorHandler()`) records the
// exploit requests and answers them normally; an "Exploit attempt" Incident opens once with a signed alert; enforce
// needs the patch id typed; once enforced, the exploit gets the block response before the handler while a benign
// request passes; back to monitor restores it. A body patch on a parser without the hook is recorded as "body not
// checked" and never blocks. Blocking the Actor of the Incident reaches Shield. Upgrading the packages (a new Build)
// removes the patches. Another Organization sees nothing.
//
// Two clients: Shield is configured as behind a trusted reverse proxy (its public `clientAddress` option reads
// X-Forwarded-For) and the test plays that proxy for two documentation addresses, as the slice 09 test does.
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http, { type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BLOCK_RESPONSE_BODY,
  BundlePayloadSchema,
  ContainmentResponseSchema,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Finding,
  type Incident,
  IncidentDetailResponseSchema,
  ListEventsResponseSchema,
  ListFindingsResponseSchema,
  ListIncidentsResponseSchema,
  ListPatchesResponseSchema,
  PatchModeResponseSchema,
  type PatchSummary,
  ProblemSchema,
  SignedBundleSchema,
  type StoredEvent,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { actorHash, verifyWebhookSignature } from "@antireverse/protocol/server";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { FIXTURE_PATCH_CATALOG } from "../../apps/api/test/fixtures/patch-catalog.ts";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
/** PB-14: a Detection is recorded within 10 s of the Event that completes it; alerts use the short test backoff. */
const DETECTION_BUDGET_MS = 15_000;
/** How long to listen for an alert that must not come. */
const QUIET_MS = 1_500;
const CONSOLE_URL = "http://127.0.0.1:39941";

/** vuln-range [2.0.0, 2.1.1) is HIGH (GHSA-fx01-0001-rang); its patch matches `__proto__` in a query key on GET. */
const QUERY = {
  patch: "vp_fixture_range_query",
  advisory: "GHSA-fx01-0001-rang",
  pkg: "vuln-range",
  exploit: "/search?q[__proto__][x]=1",
  benign: "/search?q=__proto__",
};
/** @fixture/vuln-scoped < 5.0.0 is CRITICAL (GHSA-fx01-0005-scop); its patch matches "pwn" in a POST /upload body. */
const BODY = {
  patch: "vp_fixture_scoped_body",
  advisory: "GHSA-fx01-0005-scop",
  pkg: "@fixture/vuln-scoped",
  exploit: JSON.stringify({ data: "pwn" }),
  benign: JSON.stringify({ data: "ok" }),
};

const ATTACKER = "198.51.100.7";
const BYSTANDER = "198.51.100.8";
const ACTOR_KEY = randomBytes(32).toString("base64url");

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const syncPath = join(root, "apps/api/src/vulns/cli.ts");
const fixtureAdvisories = join(root, "apps/api/test/fixtures/advisories.json");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

interface Received {
  signature: string;
  rawBody: string;
}

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

let api: RunningApi;
let receiver: http.Server;
let shield: Shield;
/** The customer's server (body parser with Shield's hook) and a legacy one whose parser lacks the hook. */
let customer: http.Server;
let customerUrl: string;
let legacy: http.Server;
let legacyUrl: string;
let adminKey: string;
let shieldKey: string;
let appId: string;
let signingSecret: string;
let workDir: string;
let vulnerableLock: string;
let upgradedLock: string;
let attackerHash: string;
let exploitIncident: Incident;
const temps: string[] = [];
const received: Received[] = [];
/** Every handler call, as `METHOD path`, and the bodies the upload handlers received. */
const handled: string[] = [];
const bodies: unknown[] = [];
const warnings: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

function call(path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return fetch(`${api.url}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}

async function until<T>(what: string, budgetMs: number, probe: () => Promise<T | undefined>): Promise<T> {
  const started = Date.now();
  for (;;) {
    const value = await probe();
    if (value !== undefined) return value;
    if (Date.now() - started > budgetMs) throw new Error(`${what}: not within ${budgetMs} ms`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

function run(args: string[], options: { cwd: string; env?: Record<string, string> }): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [tsxCli, ...args],
      { cwd: options.cwd, env: { ...process.env, ...options.env }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

/** Runs the real CLI (`antireverse harden <reference bundle> … --register --lockfile`) in its own process. */
function harden(version: string, lockfile: string): Promise<CliRun> {
  return run(
    [
      cliPath,
      "harden",
      webDir,
      "--profile",
      "balanced",
      "--seed",
      "3",
      "--register",
      "--endpoint",
      api.url,
      "--key-env",
      KEY_ENV,
      "--app",
      appId,
      "--environment",
      "development",
      "--build-version",
      version,
      "--lockfile",
      lockfile,
    ],
    { cwd: workDir, env: { [KEY_ENV]: adminKey } },
  );
}

/** A package-lock v3 with the given packages (name → version). */
function lockfile(dir: string, packages: Record<string, string>): string {
  const entries: Record<string, unknown> = { "": { name: "shop-web", version: "1.0.0" } };
  for (const [name, version] of Object.entries(packages)) entries[`node_modules/${name}`] = { version };
  const path = join(dir, "package-lock.json");
  writeFileSync(path, JSON.stringify({ name: "shop-web", version: "1.0.0", lockfileVersion: 3, packages: entries }));
  return path;
}

async function listFindings(): Promise<Finding[]> {
  const response = await call(`/v1/findings?app_id=${appId}`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListFindingsResponseSchema.parse(await response.json()).findings;
}

async function patches(key = adminKey): Promise<PatchSummary[]> {
  const response = await call(`/v1/apps/${appId}/patches?environment=development`, { key });
  expect(response.status).toBe(200);
  return ListPatchesResponseSchema.parse(await response.json()).patches;
}

const patchOf = async (id: string) => (await patches()).find((p) => p.id === id);

function setMode(patchId: string, body: unknown, key = adminKey): Promise<Response> {
  return call(`/v1/apps/${appId}/patches/${patchId}/mode`, { method: "POST", key, body });
}

/** Sets the mode as an admin (with the confirmation when going to enforce), then has Shield fetch its bundle. */
async function switchMode(patchId: string, mode: "monitor" | "enforce"): Promise<void> {
  const response = await setMode(patchId, {
    environment: "development",
    mode,
    ...(mode === "enforce" ? { confirm: patchId } : {}),
  });
  expect(response.status).toBe(200);
  expect(PatchModeResponseSchema.parse(await response.json()).patch).toMatchObject({ id: patchId, mode });
  expect((await bundleOf(shieldKey)).patches?.find((p) => p.id === patchId)?.mode).toBe(mode);
  await applied();
}

/** Shield polls on its own; refreshPolicy fetches and applies the current bundle now. */
async function applied(): Promise<void> {
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
}

async function bundleOf(key: string) {
  const response = await call("/v1/policy-bundle", { key });
  expect(response.status).toBe(200);
  return BundlePayloadSchema.parse(JSON.parse(SignedBundleSchema.parse(await response.json()).bundle));
}

async function storedEvents(): Promise<{ events: StoredEvent[]; raw: string }> {
  const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
  expect(response.status).toBe(200);
  const raw = await response.text();
  return { events: ListEventsResponseSchema.parse(JSON.parse(raw)).events, raw };
}

async function exploitIncidents(key = adminKey): Promise<Incident[]> {
  const response = await call(`/v1/incidents?app_id=${appId}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents.filter((i) => i.rule === "exploit-attempt");
}

const exploitAlerts = (advisory: string) =>
  received.filter((r) => {
    const body = JSON.parse(r.rawBody) as { type: string; incident: Incident | null };
    return (
      body.type === "incident.opened" &&
      body.incident?.rule === "exploit-attempt" &&
      body.incident.advisory_id === advisory
    );
  });

interface Sent {
  path: string;
  method?: string;
  body?: string;
  client?: string;
  base?: string;
}

/**
 * Sends one request to a customer's server and waits for its Event. Requests go one at a time, so the newest Event
 * is this request's.
 */
async function through(request: Sent) {
  const before = (await storedEvents()).events.length;
  const handledBefore = handled.length;
  const headers: Record<string, string> = { "x-forwarded-for": request.client ?? BYSTANDER };
  if (request.body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(`${request.base ?? customerUrl}${request.path}`, {
    method: request.method ?? "GET",
    headers,
    ...(request.body === undefined ? {} : { body: request.body }),
  });
  const body = await response.text();
  const event = await until("Event stored", VISIBLE_BUDGET_MS, async () => {
    const { events } = await storedEvents();
    if (events.length <= before) return undefined;
    return [...events].sort((a, b) => b.event_id.localeCompare(a.event_id))[0];
  });
  return { status: response.status, body, event, handlerRan: handled.length > handledBefore };
}

const exploitQuery = (client = ATTACKER) => through({ path: QUERY.exploit, client });
const benignQuery = (client = BYSTANDER) => through({ path: QUERY.benign, client });
const exploitBody = (base?: string) =>
  through({ method: "POST", path: "/upload", body: BODY.exploit, client: ATTACKER, ...(base ? { base } : {}) });

/** Shield's clientAddress: the address the (trusted) proxy forwarded, else the socket's. */
function forwardedFor(req: unknown): string | undefined {
  const request = req as IncomingMessage;
  const forwarded = request.headers["x-forwarded-for"];
  return typeof forwarded === "string" && forwarded !== "" ? forwarded : request.socket?.remoteAddress;
}

async function serve(app: express.Express): Promise<{ server: http.Server; url: string }> {
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

beforeAll(async () => {
  receiver = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      received.push({
        signature: String(req.headers["ar-signature"] ?? ""),
        rawBody: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200).end();
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
  const hookUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hooks/antireverse-e2e`;

  // The advisories come in through the real sync command, before the API owns the data directory.
  const dataDir = join(tempDir("antireverse-e2e-patches-"), "pg");
  const synced = await run([syncPath, "--fixture", fixtureAdvisories], { cwd: root, env: { AR_DATA_DIR: dataDir } });
  expect(synced.code, synced.stderr).toBe(0);
  expect(`${synced.stdout}${synced.stderr}`).toMatch(/advisories received=10 inserted=10/);

  api = await startApi({
    dataDir,
    allowPrivateAlertUrls: true,
    alertBackoffMs: 10,
    consoleUrl: CONSOLE_URL,
    logger: { info() {}, warn() {} },
    patches: FIXTURE_PATCH_CATALOG,
  });
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;
  shieldKey = created.shield_key.key;
  attackerHash = actorHash(ACTOR_KEY, ATTACKER) ?? "";
  expect(attackerHash).toMatch(/^iph_[0-9a-f]{32}$/);

  const channel = await call("/v1/alert-channels", {
    method: "POST",
    key: adminKey,
    body: { kind: "webhook", name: "Ops webhook", url: hookUrl },
  });
  expect(channel.status).toBe(201);
  signingSecret = CreateAlertChannelResponseSchema.parse(await channel.json()).signing_secret ?? "";

  workDir = tempDir("antireverse-e2e-ci-");
  vulnerableLock = lockfile(tempDir("antireverse-e2e-lock-"), {
    [QUERY.pkg]: "2.0.5",
    [BODY.pkg]: "4.2.0",
    "safe-pkg": "1.0.0",
  });
  upgradedLock = lockfile(tempDir("antireverse-e2e-lock-"), {
    [QUERY.pkg]: "2.1.1",
    [BODY.pkg]: "5.0.0",
    "safe-pkg": "1.0.0",
  });

  // The customer's server: Shield first, then the body parser with Shield's verify hook, the routes, and Shield's
  // error handler, which renders the block response of an enforced body match.
  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    clientAddress: forwardedFor,
    actorKey: ACTOR_KEY,
    flushIntervalMs: 200,
    bodyVerified: { types: ["application/json"] },
    inventory: false,
    logger: { warn: (line: string) => warnings.push(line) },
  });
  const app = express();
  app.disable("x-powered-by");
  app.use(shield.express());
  app.use(express.json({ verify: shield.verifyBody }));
  app.get("/search", (_req, res) => {
    handled.push("GET /search");
    res.json({ results: [] });
  });
  app.post("/upload", (req, res) => {
    handled.push("POST /upload");
    bodies.push(req.body);
    res.json({ stored: true });
  });
  app.use(shield.errorHandler());
  ({ server: customer, url: customerUrl } = await serve(app));

  // An older part of the same App: its JSON parser has no verify hook, so Shield never sees the body.
  const old = express();
  old.disable("x-powered-by");
  old.use(shield.express());
  old.use(express.json());
  old.post("/upload", (req, res) => {
    handled.push("POST /upload (legacy)");
    bodies.push(req.body);
    res.json({ stored: true });
  });
  ({ server: legacy, url: legacyUrl } = await serve(old));
});

afterAll(async () => {
  await shield?.close();
  for (const server of [customer, legacy, receiver]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
  // Shield never logs bodies, query values or patch data.
  for (const line of warnings) expect(line).not.toMatch(/pwn|__proto__|vp_fixture/);
});

describe("slice 20 Virtual patches over HTTP/CLI", () => {
  it("activates the patches of a vulnerable Build in monitor and ships them in Shield's bundle", async () => {
    // Before the Build: every catalog patch listed, none active, none shipped.
    for (const item of await patches()) expect(item).toMatchObject({ active: false, shipped: false, mode: "monitor" });
    expect((await bundleOf(shieldKey)).patches).toBeUndefined();

    const result = await harden("1.0.0", vulnerableLock);
    expect(result.code, result.stderr).toBe(0);
    const findings = await listFindings();
    const queryFinding = findings.find((f) => f.advisory_id === QUERY.advisory);
    const bodyFinding = findings.find((f) => f.advisory_id === BODY.advisory);
    expect(queryFinding).toMatchObject({ package: QUERY.pkg, version: "2.0.5", status: "open", severity: "high" });
    expect(bodyFinding).toMatchObject({ package: BODY.pkg, version: "4.2.0", status: "open", severity: "critical" });

    const listed = await patches();
    expect(listed.filter((p) => p.active).map((p) => p.id)).toEqual(expect.arrayContaining([QUERY.patch, BODY.patch]));
    expect(listed.filter((p) => p.active)).toHaveLength(2);
    expect(listed.find((p) => p.id === QUERY.patch)).toMatchObject({
      package: QUERY.pkg,
      mode: "monitor",
      active: true,
      shipped: true,
      findings: [queryFinding?.id],
      hits_24h: 0,
      last_hit: null,
    });
    expect(listed.find((p) => p.id === BODY.patch)).toMatchObject({
      mode: "monitor",
      active: true,
      shipped: true,
      findings: [bodyFinding?.id],
    });
    // The other advisory of vuln-range (1.0.0 – 1.2.0) does not cover 2.0.5; same advisory, other package: never.
    expect(listed.find((p) => p.id === "vp_fixture_range_medium")?.active).toBe(false);
    expect(listed.find((p) => p.id === "vp_fixture_wrong_package")?.active).toBe(false);

    // The signed bundle Shield fetches carries both, in monitor, with the activating advisory; Critical first.
    const shipped = (await bundleOf(shieldKey)).patches ?? [];
    expect(shipped.map((p) => [p.id, p.mode, p.advisory])).toEqual([
      [BODY.patch, "monitor", BODY.advisory],
      [QUERY.patch, "monitor", QUERY.advisory],
    ]);
    await applied();
  });

  it("monitor: records the exploit requests (query key and JSON body) and leaves the responses unchanged", async () => {
    const benign = await benignQuery();
    expect([benign.status, benign.body, benign.handlerRan]).toEqual([200, JSON.stringify({ results: [] }), true]);
    expect(benign.event.decision).toMatchObject({ action: "allow", patch_id: null, patch_body: null });

    const query = await exploitQuery();
    expect([query.status, query.body, query.handlerRan]).toEqual([200, JSON.stringify({ results: [] }), true]);
    expect(query.event.decision).toMatchObject({
      action: "block",
      mode: "monitor",
      rule_id: null,
      patch_id: QUERY.patch,
      patch_body: "checked",
    });
    expect(query.event.request).toMatchObject({ method: "GET", status: 200 });
    expect(query.event.actor.ip_hash).toBe(attackerHash);

    bodies.length = 0;
    const body = await exploitBody();
    expect([body.status, body.body, body.handlerRan]).toEqual([200, JSON.stringify({ stored: true }), true]);
    expect(bodies).toEqual([{ data: "pwn" }]);
    expect(body.event.decision).toMatchObject({
      action: "block",
      mode: "monitor",
      patch_id: BODY.patch,
      patch_body: "checked",
    });
    const benignBody = await through({ method: "POST", path: "/upload", body: BODY.benign });
    expect(benignBody.status).toBe(200);
    expect(benignBody.event.decision).toMatchObject({ action: "allow", patch_id: null });

    // One High "Exploit attempt" Incident for the query advisory, with its signed alert.
    exploitIncident = await until("Exploit attempt Incident", DETECTION_BUDGET_MS, async () =>
      (await exploitIncidents()).find((i) => i.advisory_id === QUERY.advisory),
    );
    expect(exploitIncident).toMatchObject({
      app_id: appId,
      environment: "development",
      rule: "exploit-attempt",
      title: "Exploit attempt",
      severity: "high",
      status: "open",
      advisory_id: QUERY.advisory,
      ip_prefix: null,
    });
    const alert = await until("exploit alert", DETECTION_BUDGET_MS, async () => exploitAlerts(QUERY.advisory)[0]);
    expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, Math.floor(Date.now() / 1000))).toBe(
      true,
    );
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert.rawBody));
    expect(payload.incident).toMatchObject({ id: exploitIncident.id, advisory_id: QUERY.advisory });
    expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${exploitIncident.id}`);
    // The body patch's advisory has its own Incident.
    await until("body Exploit attempt Incident", DETECTION_BUDGET_MS, async () =>
      (await exploitIncidents()).find((i) => i.advisory_id === BODY.advisory),
    );

    // A second hit joins the open Incident: still one, one alert.
    expect((await exploitQuery()).event.decision.patch_id).toBe(QUERY.patch);
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect((await exploitIncidents()).filter((i) => i.advisory_id === QUERY.advisory)).toHaveLength(1);
    expect(exploitAlerts(QUERY.advisory)).toHaveLength(1);

    // Hits are counted; nothing of the bodies is stored.
    expect((await patchOf(QUERY.patch))?.hits_24h).toBe(2);
    expect((await patchOf(QUERY.patch))?.last_hit).not.toBeNull();
    expect((await patchOf(BODY.patch))?.hits_24h).toBe(1);
    expect((await storedEvents()).raw).not.toContain("pwn");
  });

  it("promotes to enforce only with the patch id typed; the exploit is refused before the handler, benign passes", async () => {
    for (const body of [
      { environment: "development", mode: "enforce" },
      { environment: "development", mode: "enforce", confirm: BODY.patch },
    ]) {
      const refused = await setMode(QUERY.patch, body);
      expect(refused.status).toBe(400);
      expect(ProblemSchema.parse(await refused.json()).errors).toEqual([
        { path: "confirm", message: "Must equal the id of the patch." },
      ]);
    }
    expect((await patchOf(QUERY.patch))?.mode).toBe("monitor");

    await switchMode(QUERY.patch, "enforce");
    const query = await exploitQuery();
    expect([query.status, query.body, query.handlerRan]).toEqual([403, BLOCK_RESPONSE_BODY, false]);
    expect(query.event.decision).toMatchObject({ action: "block", mode: "enforce", patch_id: QUERY.patch });
    expect(query.event.request).toMatchObject({ status: 403 });
    const benign = await benignQuery();
    expect([benign.status, benign.handlerRan]).toEqual([200, true]);
    expect(benign.event.decision.patch_id).toBeNull();

    // The JSON body patch, enforced: refused in verifyBody, rendered by Shield's error handler.
    await switchMode(BODY.patch, "enforce");
    bodies.length = 0;
    const body = await exploitBody();
    expect([body.status, body.body, body.handlerRan]).toEqual([403, BLOCK_RESPONSE_BODY, false]);
    expect(bodies).toEqual([]);
    expect(body.event.decision).toMatchObject({
      action: "block",
      mode: "enforce",
      patch_id: BODY.patch,
      patch_body: "checked",
    });
    expect(body.event.request).toMatchObject({ status: 403 });
    const benignBody = await through({ method: "POST", path: "/upload", body: BODY.benign });
    expect([benignBody.status, benignBody.handlerRan]).toEqual([200, true]);

    // Back to monitor, in one action: the exploit passes again and is recorded.
    await switchMode(QUERY.patch, "monitor");
    const again = await exploitQuery();
    expect([again.status, again.handlerRan]).toEqual([200, true]);
    expect(again.event.decision).toMatchObject({ mode: "monitor", patch_id: QUERY.patch });
  });

  // Plan A6 F2 / A8: a body never checked is recorded as allow (monitor) with the patch and "unchecked", and counts
  // nowhere: no Exploit attempt Detection or Incident, no hit.
  it("never blocks on a body Shield did not see: recorded as allow, body unchecked, counted nowhere, although shipped enforce", async () => {
    expect((await bundleOf(shieldKey)).patches?.find((p) => p.id === BODY.patch)?.mode).toBe("enforce");
    const incidentsBefore = (await exploitIncidents()).map((i) => [i.id, i.detection_count]);
    const hitsBefore = (await patchOf(BODY.patch))?.hits_24h;
    const alertsBefore = received.length;
    bodies.length = 0;
    const result = await exploitBody(legacyUrl);
    expect([result.status, result.body, result.handlerRan]).toEqual([200, JSON.stringify({ stored: true }), true]);
    expect(bodies).toEqual([{ data: "pwn" }]);
    expect(result.event.decision).toMatchObject({
      action: "allow",
      mode: "monitor",
      rule_id: null,
      patch_id: BODY.patch,
      patch_body: "unchecked",
    });
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect((await exploitIncidents()).map((i) => [i.id, i.detection_count])).toEqual(incidentsBefore);
    expect((await patchOf(BODY.patch))?.hits_24h).toBe(hitsBefore);
    expect(received.length).toBe(alertsBefore);
    await switchMode(BODY.patch, "monitor");
  });

  it("contains the Actor of the Exploit attempt Incident: their next request is refused, a bystander passes", async () => {
    const detail = await call(`/v1/incidents/${exploitIncident.id}`, { key: adminKey });
    expect(detail.status).toBe(200);
    const { actors, evidence } = IncidentDetailResponseSchema.parse(await detail.json());
    expect(actors.map((a) => a.ip_hash)).toEqual([attackerHash]);
    expect(evidence.length).toBeGreaterThan(0);
    for (const event of evidence) expect(event.decision.patch_id).toBe(QUERY.patch);

    const response = await call(`/v1/incidents/${exploitIncident.id}/containments`, {
      method: "POST",
      key: adminKey,
      body: { target: { kind: "actor", ip_hash: attackerHash }, ttl_s: 3600 },
    });
    expect(response.status).toBe(201);
    const block = ContainmentResponseSchema.parse(await response.json()).containment;
    expect((await bundleOf(shieldKey)).blocks).toEqual([
      { id: block.id, kind: "actor", ip_hash: attackerHash, expires_at: block.expires_at },
    ]);
    await applied();

    // The attacker's next request, even a benign one, is refused; the bystander's passes.
    const contained = await benignQuery(ATTACKER);
    expect([contained.status, contained.body, contained.handlerRan]).toEqual([403, BLOCK_RESPONSE_BODY, false]);
    expect(contained.event.decision).toMatchObject({ action: "block", mode: "enforce", containment_id: block.id });
    expect((await benignQuery(BYSTANDER)).status).toBe(200);

    // Lifted, so that the attacker's requests reach the patches again below.
    const lifted = await call(`/v1/containments/${block.id}/lift`, { method: "POST", key: adminKey });
    expect(lifted.status).toBe(200);
    await applied();
    expect((await benignQuery(ATTACKER)).status).toBe(200);
  });

  it("drops the patches after the upgrade (a new Build): absent from the bundle, the exploit passes unpatched", async () => {
    const result = await harden("1.1.0", upgradedLock);
    expect(result.code, result.stderr).toBe(0);
    for (const finding of await listFindings()) expect(finding.status).toBe("fixed");

    const listed = await patches();
    for (const item of listed) expect(item).toMatchObject({ active: false, shipped: false, findings: [] });
    expect((await bundleOf(shieldKey)).patches).toBeUndefined();
    await applied();

    const query = await exploitQuery();
    expect([query.status, query.handlerRan]).toEqual([200, true]);
    expect(query.event.decision).toMatchObject({ action: "allow", patch_id: null, patch_body: null });
    const body = await exploitBody();
    expect([body.status, body.handlerRan]).toEqual([200, true]);
    expect(body.event.decision).toMatchObject({ action: "allow", patch_id: null });
  });

  it("keeps the App's patches from another Organization and from a Shield key", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    expect((await call(`/v1/apps/${appId}/patches?environment=development`, { key })).status).toBe(404);
    expect((await setMode(QUERY.patch, { environment: "development", mode: "monitor" }, key)).status).toBe(404);
    expect(
      (await setMode(QUERY.patch, { environment: "development", mode: "enforce", confirm: QUERY.patch }, key)).status,
    ).toBe(404);
    expect(await exploitIncidents(key)).toEqual([]);
    // A Shield key is not an admin key.
    expect((await call(`/v1/apps/${appId}/patches?environment=development`, { key: shieldKey })).status).toBe(403);
    // Nothing changed for the owner.
    expect((await patchOf(QUERY.patch))?.mode).toBe("monitor");
  });
});
