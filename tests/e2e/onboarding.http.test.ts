// Slice 16 over HTTP: `GET /v1/apps/:appId/setup` goes from null to timestamps through the real pieces, not rows
// written by a test: a real Shield in front of ar-range (Shield), a token from the real Attestation service that Shield
// verifies offline (Guard), and the real harden CLI registering a Build (Harden). A request carrying a token Shield
// cannot verify does not count for Guard. Each step keeps its first time. The API runs on a temporary data directory.
import { execFile } from "node:child_process";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { cpSync, mkdtempSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  type AppSetup,
  AppSetupResponseSchema,
  ATTESTATION_HEADER,
  AttestResponseSchema,
  ChallengeResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListEventsResponseSchema,
} from "@antireverse/protocol";
import { jwkThumbprint } from "@antireverse/protocol/server";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

let api: RunningApi;
let adminKey: string;
let appId: string;
let shield: Shield;
let range: http.Server;
let rangeUrl: string;
const temps: string[] = [];
/** The set-up after each step, to check that earlier times never move. */
const seen: AppSetup[] = [];

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

async function setup(): Promise<AppSetup> {
  const response = await call(`/v1/apps/${appId}/setup`, { key: adminKey });
  expect(response.status).toBe(200);
  return AppSetupResponseSchema.parse(await response.json()).setup;
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

async function eventCount(): Promise<number> {
  const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListEventsResponseSchema.parse(await response.json()).events.length;
}

/** One request through Shield (with `token` when given); resolves once its Event is stored. */
async function through(token?: string): Promise<void> {
  const before = await eventCount();
  const response = await fetch(`${rangeUrl}/api/products/7`, {
    headers: token === undefined ? {} : { [ATTESTATION_HEADER]: token },
  });
  expect(response.status).toBe(200);
  await response.text();
  await until("Event stored", VISIBLE_BUDGET_MS, async () => ((await eventCount()) > before ? true : undefined));
}

/** A token from the real Attestation service, obtained as Guard does (challenge, then attest with a session key). */
async function attest(): Promise<string> {
  const challenge = await call("/v1/attest/challenge", { method: "POST", body: { app_id: appId } });
  expect(challenge.status).toBe(200);
  const { nonce } = ChallengeResponseSchema.parse(await challenge.json());
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: exported.x, y: exported.y };
  const response = await call("/v1/attest", {
    method: "POST",
    body: {
      app_id: appId,
      nonce,
      device: randomBytes(16).toString("base64url"),
      signals: ["automation.webdriver"],
      cnf: { jkt: jwkThumbprint(jwk), jwk },
    },
  });
  expect(response.status).toBe(200);
  return AttestResponseSchema.parse(await response.json()).token;
}

beforeAll(async () => {
  api = await startApi({
    dataDir: join(tempDir("antireverse-e2e-onboarding-pg-"), "pg"),
    logger: { info() {}, warn() {} },
  });
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;

  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: created.shield_key.key,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  range = http.createServer(createRangeServer({ shield }));
  await new Promise<void>((resolve) => range.listen(0, "127.0.0.1", resolve));
  rangeUrl = `http://127.0.0.1:${(range.address() as AddressInfo).port}`;
}, 30_000);

afterAll(async () => {
  await shield?.close();
  if (range) {
    range.closeAllConnections();
    await new Promise<void>((resolve) => range.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 16 set-up over HTTP, with the real Shield, Attestation service and Harden", () => {
  it("starts with nothing done, in the Environment of the App's Shield key", async () => {
    const start = await setup();
    expect(start).toEqual({
      environment: "development",
      shield: { done_at: null },
      guard: { done_at: null },
      harden: { done_at: null },
    });
  });

  it("dates Shield at the first Event, and an unverifiable token does not count for Guard", async () => {
    const before = Date.now();
    await through();
    const afterShield = await setup();
    const shieldAt = Date.parse(afterShield.shield.done_at ?? "");
    expect(shieldAt).toBeGreaterThanOrEqual(before - 1_000);
    expect(shieldAt).toBeLessThanOrEqual(Date.now());
    expect(afterShield.guard.done_at).toBeNull();
    expect(afterShield.harden.done_at).toBeNull();

    // A token Shield cannot verify (malformed) is recorded, but is not a genuine Guard attestation.
    await through("not.a-real.token");
    const stillNoGuard = await setup();
    expect(stillNoGuard.guard.done_at).toBeNull();
    expect(stillNoGuard.shield.done_at).toBe(afterShield.shield.done_at);
    seen.push(stillNoGuard);
  });

  it("dates Guard at the first Event whose attestation Shield verified", async () => {
    const token = await attest();
    await through(token);
    const afterGuard = await setup();
    expect(afterGuard.guard.done_at).not.toBeNull();
    expect(Date.parse(afterGuard.guard.done_at ?? "")).toBeGreaterThanOrEqual(
      Date.parse(afterGuard.shield.done_at ?? ""),
    );
    expect(afterGuard.shield.done_at).toBe(seen[0]?.shield.done_at);
    expect(afterGuard.harden.done_at).toBeNull();
    // A second attested request keeps the first time.
    await through(await attest());
    expect((await setup()).guard.done_at).toBe(afterGuard.guard.done_at);
    seen.push(afterGuard);
  });

  it("dates Harden at the first Build the real CLI registers", async () => {
    const bundleDir = join(tempDir("antireverse-e2e-onboarding-bundle-"), "web");
    cpSync(webDir, bundleDir, { recursive: true });
    const workDir = tempDir("antireverse-e2e-onboarding-ci-");
    const register = (version: string) =>
      new Promise<{ code: number; stderr: string }>((resolve) => {
        execFile(
          process.execPath,
          [
            tsxCli,
            cliPath,
            "harden",
            bundleDir,
            "--profile",
            "balanced",
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
          ],
          { cwd: workDir, env: { ...process.env, [KEY_ENV]: adminKey } },
          (error, _stdout, stderr) => {
            resolve({ code: error === null ? 0 : typeof error.code === "number" ? error.code : -1, stderr });
          },
        );
      });
    const first = await register("1.0.0");
    expect(first.code, first.stderr).toBe(0);
    const done = await setup();
    expect(done.harden.done_at).not.toBeNull();
    expect(done.shield.done_at).toBe(seen[1]?.shield.done_at);
    expect(done.guard.done_at).toBe(seen[1]?.guard.done_at);

    // A second Build keeps the first time.
    const second = await register("1.0.1");
    expect(second.code, second.stderr).toBe(0);
    expect((await setup()).harden.done_at).toBe(done.harden.done_at);
  }, 60_000);
});
