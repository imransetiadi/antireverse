// Slice 20 with the REAL catalog (plan A6): the API starts with its shipped Virtual patch catalog (no `patches`
// option) on a data directory holding one real-format OSV advisory, GHSA-hrpp-h998-j3pp / CVE-2022-24999 (qs
// prototype poisoning), imported with the real `vulns:sync --fixture` command. The record in
// fixtures/osv-qs-GHSA-hrpp-h998-j3pp.json copies the fields the sync reads from https://api.osv.dev/v1/vulns/
// GHSA-hrpp-h998-j3pp (advisory data only; the affected ranges equal those pinned in
// apps/api/test/patch-catalog.test.ts). The real harden CLI registers a Build whose lockfile ships qs 6.10.2 (in
// [6.10.0, 6.10.3)): `vp_qs_proto_query_key` becomes active and ships in monitor; enforced with its id typed, a real
// Express app with Shield refuses `a[__proto__][x]=1` and the qs-split key `a[b=c][__proto__]=x` before the handler,
// while `q=__proto__` (the word as a value) passes.
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BLOCK_RESPONSE_BODY,
  BundlePayloadSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListEventsResponseSchema,
  ListFindingsResponseSchema,
  ListPatchesResponseSchema,
  PatchModeResponseSchema,
  type PatchSummary,
  SignedBundleSchema,
  type StoredEvent,
} from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;

const PATCH = "vp_qs_proto_query_key";
const ADVISORY = "GHSA-hrpp-h998-j3pp";
const CVE = "CVE-2022-24999";
const EXPLOITS = ["/search?a[__proto__][x]=1", "/search?a[b=c][__proto__]=x"];
const BENIGN = "/search?q=__proto__";
const OK_BODY = JSON.stringify({ results: [] });

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const syncPath = join(root, "apps/api/src/vulns/cli.ts");
const qsAdvisory = fileURLToPath(new URL("./fixtures/osv-qs-GHSA-hrpp-h998-j3pp.json", import.meta.url));
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

let api: RunningApi;
let shield: Shield;
let customer: http.Server;
let customerUrl: string;
let adminKey: string;
let shieldKey: string;
let appId: string;
const temps: string[] = [];
const handled: string[] = [];

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

async function patches(): Promise<PatchSummary[]> {
  const response = await call(`/v1/apps/${appId}/patches?environment=development`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListPatchesResponseSchema.parse(await response.json()).patches;
}

async function bundlePatches() {
  const response = await call("/v1/policy-bundle", { key: shieldKey });
  expect(response.status).toBe(200);
  return BundlePayloadSchema.parse(JSON.parse(SignedBundleSchema.parse(await response.json()).bundle)).patches;
}

async function storedEvents(): Promise<StoredEvent[]> {
  const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListEventsResponseSchema.parse(await response.json()).events;
}

/** One request to the customer's server and its Event (requests go one at a time). */
async function through(path: string) {
  const before = (await storedEvents()).length;
  const handledBefore = handled.length;
  const response = await fetch(`${customerUrl}${path}`);
  const body = await response.text();
  const event = await until("Event stored", VISIBLE_BUDGET_MS, async () => {
    const events = await storedEvents();
    if (events.length <= before) return undefined;
    return [...events].sort((a, b) => b.event_id.localeCompare(a.event_id))[0];
  });
  return { status: response.status, body, event, handlerRan: handled.length > handledBefore };
}

beforeAll(async () => {
  const dataDir = join(tempDir("antireverse-e2e-qs-"), "pg");
  const synced = await run([syncPath, "--fixture", qsAdvisory], { cwd: root, env: { AR_DATA_DIR: dataDir } });
  expect(synced.code, synced.stderr).toBe(0);
  expect(`${synced.stdout}${synced.stderr}`).toMatch(/advisories received=1 inserted=1/);

  // No `patches` option: the catalog Anti Reverse ships.
  api = await startApi({ dataDir, logger: { info() {}, warn() {} } });
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;
  shieldKey = created.shield_key.key;

  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    inventory: false,
    logger: { warn() {} },
  });
  const app = express();
  app.disable("x-powered-by");
  app.use(shield.express());
  app.get("/search", (_req, res) => {
    handled.push("GET /search");
    res.json({ results: [] });
  });
  customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  customerUrl = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await shield?.close();
  if (customer) {
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 20 with the real catalog: the qs patch (GHSA-hrpp-h998-j3pp)", () => {
  it("activates vp_qs_proto_query_key for a Build that ships qs 6.10.2, and ships it in monitor", async () => {
    expect((await patches()).find((p) => p.id === PATCH)).toMatchObject({ active: false, shipped: false });

    const lockDir = tempDir("antireverse-e2e-qs-lock-");
    const lockfile = join(lockDir, "package-lock.json");
    writeFileSync(
      lockfile,
      JSON.stringify({
        name: "shop-web",
        version: "1.0.0",
        lockfileVersion: 3,
        packages: {
          "": { name: "shop-web", version: "1.0.0" },
          "node_modules/qs": { version: "6.10.2" },
          "node_modules/safe-pkg": { version: "1.0.0" },
        },
      }),
    );
    const result = await run(
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
        "1.0.0",
        "--lockfile",
        lockfile,
      ],
      { cwd: tempDir("antireverse-e2e-qs-ci-"), env: { [KEY_ENV]: adminKey } },
    );
    expect(result.code, result.stderr).toBe(0);

    const findingsResponse = await call(`/v1/findings?app_id=${appId}`, { key: adminKey });
    const findings = ListFindingsResponseSchema.parse(await findingsResponse.json()).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      package: "qs",
      version: "6.10.2",
      advisory_id: ADVISORY,
      aliases: [CVE],
      severity: "high",
      fixed_versions: expect.arrayContaining(["6.10.3"]),
      status: "open",
    });

    const listed = await patches();
    expect(listed.find((p) => p.id === PATCH)).toMatchObject({
      package: "qs",
      advisories: [ADVISORY, CVE],
      mode: "monitor",
      active: true,
      shipped: true,
      findings: [findings[0]?.id],
    });
    // Only qs patches are active; the lodash and xml2js ones stay off.
    for (const item of listed.filter((p) => p.active)) expect(item.package).toBe("qs");
    const shipped = (await bundlePatches()) ?? [];
    expect(shipped.find((p) => p.id === PATCH)).toMatchObject({ mode: "monitor", advisory: ADVISORY });

    await shield.refreshPolicy();
    expect(shield.stats().lastPolicyError).toBeNull();
    // Monitor: recorded, answered normally.
    const monitored = await through(EXPLOITS[0] ?? "");
    expect([monitored.status, monitored.body, monitored.handlerRan]).toEqual([200, OK_BODY, true]);
    expect(monitored.event.decision).toMatchObject({ action: "block", mode: "monitor", patch_id: PATCH });
  });

  it("enforced with its id typed, refuses both exploit shapes before the handler and lets q=__proto__ pass", async () => {
    const unconfirmed = await call(`/v1/apps/${appId}/patches/${PATCH}/mode`, {
      method: "POST",
      key: adminKey,
      body: { environment: "development", mode: "enforce" },
    });
    expect(unconfirmed.status).toBe(400);
    const response = await call(`/v1/apps/${appId}/patches/${PATCH}/mode`, {
      method: "POST",
      key: adminKey,
      body: { environment: "development", mode: "enforce", confirm: PATCH },
    });
    expect(response.status).toBe(200);
    expect(PatchModeResponseSchema.parse(await response.json()).patch).toMatchObject({ id: PATCH, mode: "enforce" });
    expect((await bundlePatches())?.find((p) => p.id === PATCH)?.mode).toBe("enforce");
    await shield.refreshPolicy();
    expect(shield.stats().lastPolicyError).toBeNull();

    for (const path of EXPLOITS) {
      const refused = await through(path);
      expect([path, refused.status, refused.body, refused.handlerRan]).toEqual([path, 403, BLOCK_RESPONSE_BODY, false]);
      expect(refused.event.decision).toMatchObject({ action: "block", mode: "enforce", patch_id: PATCH });
    }
    const benign = await through(BENIGN);
    expect([benign.status, benign.body, benign.handlerRan]).toEqual([200, OK_BODY, true]);
    expect(benign.event.decision).toMatchObject({ action: "allow", patch_id: null });
  });
});
