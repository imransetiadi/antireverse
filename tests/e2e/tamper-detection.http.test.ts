// Slice 21a over HTTP/CLI: the harden CLI plants the integrity marker in a copy of the reference bundle
// (`--register`), records its files in the --json report and the Manifest, and registers the Build. Attestations
// are then made exactly as Guard makes them (challenge, then attest with a session key), each carrying a hand-built
// integrity report: the SHA-256 of the bytes on disk, as a browser would hash what it received (the Guard collector
// that sends real reports is slice 21b). A matching report opens nothing and arms the Build; a file with one byte
// changed opens exactly one High "Tampered Build" Incident naming the Build, the file and the observed hash, with
// one signed alert; a mixed deploy of two Builds opens none; a forged flood stays within the caps. No report
// changes the answer of the attestation, and another Organization sees nothing.
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  AttestationClaimsSchema,
  AttestResponseSchema,
  type BuildManifest,
  BuildResponseSchema,
  ChallengeResponseSchema,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  INTEGRITY_LIMITS,
  type Incident,
  IncidentDetailResponseSchema,
  ListIncidentsResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { jwkThumbprint, verifyWebhookSignature } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** A counted report opens an Incident within 60 s. */
const INCIDENT_BUDGET_MS = 60_000;
/** Alerts use the short test backoff; one arrives well within this. */
const ALERT_BUDGET_MS = 15_000;
/** How long to wait for something that must not happen (reports are judged after the response). */
const QUIET_MS = 1_500;
const CONSOLE_URL = "http://127.0.0.1:39941";
const ORIGIN = "https://shop.example";

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
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

/** One hardened and registered Build: its id, its output directory and the marker's files in order. */
interface Deployed {
  buildId: string;
  outDir: string;
  files: string[];
  manifest: BuildManifest;
}

let api: RunningApi;
let receiver: http.Server;
let adminKey: string;
let organizationId: string;
let appId: string;
let signingSecret: string;
let bundleDir: string;
let first: Deployed;
let second: Deployed;
const temps: string[] = [];
const received: Received[] = [];
/** The API's clock runs ahead of the wall clock by this much: a test moves it to start a new minute of the attest limiter. */
let aheadMs = 0;
const apiNow = () => new Date(Date.now() + aheadMs);
/** A minute later for the API: the caller's attestation budget (60 requests a minute per network) is whole again. */
const nextMinute = () => {
  aheadMs += 61_000;
};

const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const exported = publicKey.export({ format: "jwk" });
const JWK = { kty: "EC" as const, crv: "P-256" as const, x: String(exported.x), y: String(exported.y) };
const JKT = jwkThumbprint(JWK);

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

function call(
  path: string,
  init: { method?: string; key?: string; body?: unknown; origin?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  if (init.origin !== undefined) headers.origin = init.origin;
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
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

const quiet = () => new Promise((resolve) => setTimeout(resolve, QUIET_MS));

/** Runs the real CLI binary (`antireverse harden …`) in its own process. */
function harden(args: string[], cwd: string): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [tsxCli, cliPath, "harden", ...args],
      { cwd, env: { ...process.env, [KEY_ENV]: adminKey }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

/** Hardens the reference bundle and registers the Build, as a deploy does. */
async function deploy(seed: number, version: string): Promise<Deployed & { json: Record<string, unknown> }> {
  const outDir = join(tempDir("antireverse-e2e-tamper-out-"), "protected");
  const run = await harden(
    [
      bundleDir,
      "--profile",
      "balanced",
      "--seed",
      String(seed),
      "--out",
      outDir,
      "--json",
      "--register",
      "--endpoint",
      api.url,
      "--key-env",
      KEY_ENV,
      "--app",
      appId,
      "--environment",
      "production",
      "--build-version",
      version,
    ],
    tempDir("antireverse-e2e-ci-"),
  );
  expect(run.code, run.stderr).toBe(0);
  const json = JSON.parse(run.stdout) as {
    integrity_marker: { files: string[] };
    registered: { build_id: string };
  };
  const buildId = json.registered.build_id;
  const manifest = await api.db.tx({ organizationId }, async (q) => {
    const { rows } = await q.query<{ manifest: BuildManifest }>(
      "SELECT manifest FROM builds WHERE build_id = $1::text",
      [buildId],
    );
    return rows[0]?.manifest;
  });
  if (manifest === undefined) throw new Error("The Build was not registered.");
  return { buildId, outDir, files: json.integrity_marker.files, manifest, json };
}

/** The SHA-256 of bytes as an integrity report carries it: 43 base64url characters. */
const wireHash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("base64url");
/** What a browser would report for a file of a deploy: the hash of the bytes it was served. */
const served = (deployed: Deployed, path: string) => wireHash(readFileSync(join(deployed.outDir, path)));
/** The matching report of every file of the marker. */
const matching = (deployed: Deployed) => deployed.files.map((path, i) => ({ i, h: served(deployed, path) }));

/**
 * One attestation as Guard makes it: a challenge, then the attest request with the session key and, when given, an
 * integrity report; the page's origin travels as the `Origin` header, as a browser sends it (`null` sends none).
 * Returns the response.
 */
async function attest(
  integrity?: { build: string; files: { i: number; h: string }[]; skipped: number },
  origin: string | null = ORIGIN,
): Promise<Response> {
  const challenged = await call("/v1/attest/challenge", { method: "POST", body: { app_id: appId } });
  expect(challenged.status, await challenged.clone().text()).toBe(200);
  const { nonce } = ChallengeResponseSchema.parse(await challenged.json());
  return call("/v1/attest", {
    method: "POST",
    ...(origin === null ? {} : { origin }),
    body: {
      app_id: appId,
      nonce,
      device: randomBytes(16).toString("base64url"),
      signals: [],
      cnf: { jkt: JKT, jwk: JWK },
      ...(integrity === undefined ? {} : { integrity }),
    },
  });
}

/** Attests with a report and checks the answer is an ordinary token: the report is invisible to the client. */
async function report(
  deployed: Pick<Deployed, "buildId">,
  files: { i: number; h: string }[],
  origin: string | null = ORIGIN,
): Promise<void> {
  const response = await attest({ build: deployed.buildId, files, skipped: 0 }, origin);
  expect(response.status, await response.clone().text()).toBe(200);
  const body = AttestResponseSchema.parse(await response.json());
  const claims = AttestationClaimsSchema.parse(
    JSON.parse(Buffer.from(body.token.split(".")[1] ?? "", "base64url").toString()),
  );
  expect(claims).toMatchObject({ verdict: "trusted", risk: 5, sig: [] });
}

async function armedAt(buildId: string): Promise<Date | null> {
  return api.db.tx({ organizationId }, async (q) => {
    const { rows } = await q.query<{ at: Date | null }>(
      "SELECT integrity_first_match_at AS at FROM builds WHERE build_id = $1::text",
      [buildId],
    );
    return rows[0]?.at ?? null;
  });
}

async function listIncidents(key = adminKey, query = `?app_id=${appId}`): Promise<Incident[]> {
  const response = await call(`/v1/incidents${query}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents;
}

const tamperIncidents = async () => (await listIncidents()).filter((i) => i.rule === "tampered-build");

const tamperAlerts = () =>
  received.filter((r) => {
    const body = JSON.parse(r.rawBody) as { type: string; incident: Incident | null };
    return body.type === "incident.opened" && body.incident?.rule === "tampered-build";
  });

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

  api = await startApi({
    allowPrivateAlertUrls: true,
    alertBackoffMs: 10,
    consoleUrl: CONSOLE_URL,
    now: apiNow,
    logger: { info() {}, warn() {} },
  });
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  organizationId = organization.organization.id;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;

  const channel = await call("/v1/alert-channels", {
    method: "POST",
    key: adminKey,
    body: { kind: "webhook", name: "Ops webhook", url: hookUrl },
  });
  expect(channel.status).toBe(201);
  signingSecret = CreateAlertChannelResponseSchema.parse(await channel.json()).signing_secret ?? "";
  expect(signingSecret).toMatch(/^whsec_/);

  // A copy of the reference bundle: never hardened in place.
  bundleDir = join(tempDir("antireverse-e2e-tamper-bundle-"), "web");
  cpSync(webDir, bundleDir, { recursive: true });
});

afterAll(async () => {
  if (receiver) {
    receiver.closeAllConnections();
    await new Promise<void>((resolve) => receiver.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 21a tamper detection over HTTP", () => {
  it("harden --register plants the integrity marker; the Manifest lists its files and names the bytes on disk", async () => {
    const deployed = await deploy(21, "21.0.0");
    first = deployed;
    expect(first.buildId).toMatch(/^bld_[0-9a-f]{24}$/);
    // The planted file first, then the other protected files; the Canaries sit in the same file.
    expect(deployed.json.integrity_marker).toEqual({
      files: first.files,
      planted_in: deployed.json.canaries_planted_in,
      dropped: 0,
    });
    expect(first.files[0]).toBe(deployed.json.canaries_planted_in);
    expect([...first.files].sort()).toEqual(["check.ts", "src/index.ts", "src/pricing.ts", "src/reports.ts"]);
    expect(first.manifest.integrity).toEqual({ files: first.files });
    // The opt-in self-check wrapper is another feature and stays off (D-099).
    expect(first.manifest.transform.integrity).toBe(false);

    // The marker is in the planted file as plain text: the Build id and the paths, never a hash.
    const planted = readFileSync(join(first.outDir, first.files[0] ?? ""), "utf8");
    expect(planted).toContain('Symbol.for("ar.build")');
    expect(planted).toContain(
      `{b:${JSON.stringify(first.buildId)},f:[${first.files.map((f) => JSON.stringify(f)).join(",")}]}`,
    );
    for (const artifact of first.manifest.artifacts) {
      expect(planted).not.toContain(artifact.sha256);
      // What the Manifest registered is exactly what is on disk, byte for byte.
      const bytes = readFileSync(join(first.outDir, artifact.path));
      expect({
        path: artifact.path,
        sha256: createHash("sha256").update(bytes).digest("hex"),
        bytes: bytes.length,
      }).toEqual(artifact);
    }

    // The Build read back names the marker's files; it starts unarmed.
    const detail = await call(`/v1/apps/${appId}/builds/${first.buildId}`, { key: adminKey });
    expect(BuildResponseSchema.parse(await detail.json()).build.integrity).toEqual({ files: first.files });
    expect(await armedAt(first.buildId)).toBeNull();
  }, 120_000);

  it("ignores a mismatch on a Build never seen clean: nothing opens before the Build is armed", async () => {
    await report(first, [{ i: 0, h: wireHash(Buffer.from("never served")) }]);
    await quiet();
    expect(await listIncidents()).toEqual([]);
    expect(await armedAt(first.buildId)).toBeNull();
  });

  it("a matching report opens nothing and arms the Build", async () => {
    await report(first, matching(first));
    const at = await until(
      "the Build armed",
      INCIDENT_BUDGET_MS,
      async () => (await armedAt(first.buildId)) ?? undefined,
    );
    await report(first, matching(first));
    await quiet();
    expect(await listIncidents()).toEqual([]);
    expect((await armedAt(first.buildId))?.toISOString()).toBe(at.toISOString());
    expect(tamperAlerts()).toEqual([]);
  }, 90_000);

  it("drops a report without an Origin header and one from a local origin", async () => {
    const changed = wireHash(Buffer.from("dev build"));
    await report(first, [{ i: 0, h: changed }], null);
    await report(first, [{ i: 0, h: changed }], "http://localhost:5173");
    await quiet();
    expect(await listIncidents()).toEqual([]);
  });

  it("a one-byte mismatch opens exactly one High 'Tampered Build' Incident naming the Build, the file and the observed hash", async () => {
    const path = first.files[1] ?? "";
    const bytes = Buffer.from(readFileSync(join(first.outDir, path)));
    bytes[bytes.length >> 1] = (bytes[bytes.length >> 1] ?? 0) ^ 0x01;
    const observed = createHash("sha256").update(bytes).digest("hex");
    // The other files are still the registered ones: only the changed file is reported on.
    await report(
      first,
      first.files.map((file, i) => ({ i, h: i === 1 ? wireHash(bytes) : served(first, file) })),
    );
    const [incident] = await until("a Tampered Build Incident", INCIDENT_BUDGET_MS, async () => {
      const found = await tamperIncidents();
      return found.length > 0 ? found : undefined;
    });
    expect(incident).toMatchObject({
      app_id: appId,
      environment: "production",
      rule: "tampered-build",
      title: "Tampered Build",
      severity: "high",
      status: "open",
      build_id: first.buildId,
      artifact_path: path,
      observed_sha256: observed,
      ip_prefix: null,
      origin: null,
      detection_count: 1,
    });
    expect(first.manifest.artifacts.find((artifact) => artifact.path === path)?.sha256).not.toBe(observed);
    // Its Detection keeps the page's origin and the reporter's network prefix only; no Events, no Actors.
    const detail = await call(`/v1/incidents/${incident?.id}`, { key: adminKey });
    const text = await detail.text();
    const parsed = IncidentDetailResponseSchema.parse(JSON.parse(text));
    expect(parsed.detections).toHaveLength(1);
    expect(parsed.detections[0]).toMatchObject({
      rule: "tampered-build",
      artifact_path: path,
      observed_sha256: observed,
      origin: ORIGIN,
      ip_prefix: "127.0.0.0/24",
    });
    expect(parsed.evidence).toEqual([]);
    expect(parsed.actors).toEqual([]);
    expect(text).not.toContain('"127.0.0.1"');
    await quiet();
    expect(await tamperIncidents()).toHaveLength(1);
  }, 90_000);

  it("alerts once, signed, naming the Build, the file and the observed hash", async () => {
    const [alert] = await until("one tamper alert", ALERT_BUDGET_MS, async () => {
      const found = tamperAlerts();
      return found.length > 0 ? found : undefined;
    });
    const [incident] = await tamperIncidents();
    expect(
      verifyWebhookSignature(signingSecret, alert?.signature ?? "", alert?.rawBody ?? "", apiNow().getTime() / 1000),
    ).toBe(true);
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert?.rawBody ?? ""));
    expect(payload.incident).toMatchObject({
      id: incident?.id,
      rule: "tampered-build",
      title: "Tampered Build",
      severity: "high",
      build_id: first.buildId,
      artifact_path: first.files[1],
      observed_sha256: incident?.observed_sha256,
    });
    expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${incident?.id}`);
    for (const leak of [adminKey, signingSecret]) expect(alert?.rawBody).not.toContain(leak);
    await quiet();
    expect(tamperAlerts()).toHaveLength(1);
  }, 30_000);

  it("a mixed deploy of two Builds opens none: a file of the other recent Build is stale, not tampered", async () => {
    nextMinute();
    second = await deploy(22, "21.1.0");
    expect(second.buildId).not.toBe(first.buildId);
    // Another seed: every protected file differs between the two Builds.
    for (const path of first.files) expect(served(second, path)).not.toBe(served(first, path));
    await report(second, matching(second));
    await until("the second Build armed", INCIDENT_BUDGET_MS, async () => (await armedAt(second.buildId)) ?? undefined);
    const before = await tamperIncidents();

    // A page of the new deploy still gets the old deploy's files from a cache, and the other way round.
    await report(
      second,
      second.files.map((path, i) => ({ i, h: i === 0 ? served(second, path) : served(first, path) })),
    );
    await report(
      first,
      first.files.map((path, i) => ({ i, h: served(second, path) })),
    );
    await quiet();
    expect(await tamperIncidents()).toEqual(before);
    expect(tamperAlerts()).toHaveLength(1);
  }, 180_000);

  it("a forged flood stays within the caps: one Incident, at most 20 new observed hashes an hour, one alert", async () => {
    nextMinute();
    const forged = Array.from({ length: 25 }, (_, n) => wireHash(Buffer.from(`forged-${n}`)));
    for (const h of forged) await report(first, [{ i: 2, h }]);
    const limit = INTEGRITY_LIMITS.newHashesPerHour;
    // One observed hash was already recorded this hour; the flood may add the rest of the 20.
    await until("the flood judged", INCIDENT_BUDGET_MS, async () =>
      (await tamperIncidents())[0]?.detection_count === limit ? true : undefined,
    );
    await quiet();
    const incidents = await tamperIncidents();
    expect(incidents).toHaveLength(1);
    expect(incidents[0]).toMatchObject({
      build_id: first.buildId,
      detection_count: limit,
      status: "open",
      // The Incident says that the cap hid distinct hashes.
      detections_capped: true,
    });
    const detail = IncidentDetailResponseSchema.parse(
      await (await call(`/v1/incidents/${incidents[0]?.id}`, { key: adminKey })).json(),
    );
    expect(new Set(detail.detections.map((d) => `${d.artifact_path} ${d.observed_sha256}`)).size).toBe(limit);
    expect(tamperAlerts()).toHaveLength(1);
  }, 120_000);

  it("keeps the Incident and the Build away from another Organization", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    expect(await listIncidents(key, "")).toEqual([]);
    expect(await listIncidents(key, `?app_id=${appId}`)).toEqual([]);
    const [incident] = await tamperIncidents();
    expect((await call(`/v1/incidents/${incident?.id}`, { key })).status).toBe(404);
    expect((await call(`/v1/apps/${appId}/builds/${first.buildId}`, { key })).status).toBe(404);
  });
});
