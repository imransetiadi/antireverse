// Slice 07 over HTTP/CLI: the harden CLI fails a copy of the reference bundle that carries a documented example
// secret (exit 3, masked finding, nothing written or registered); once its fingerprint is allowlisted the harden
// passes and registers the Build with its Canaries. A running Shield in front of the reference target (ar-range)
// receives the Canaries in the signed Policy Bundle; a request with the decoy key and requests to the decoy
// routes open one High "Canary used" Incident per Canary, naming the Canary and its Build, with a signed alert.
// Shield never changes the response and never sends the decoy key; another Organization sees nothing.
import { execFile } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BuildResponseSchema,
  BundlePayloadSchema,
  type Canary,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  EXAMPLE_CANARIES,
  type Incident,
  IncidentDetailResponseSchema,
  ListBuildsResponseSchema,
  ListEventsResponseSchema,
  ListIncidentsResponseSchema,
  SignedBundleSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { deriveCanaries, leakFingerprint, verifyWebhookSignature } from "@antireverse/protocol/server";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield, type Transport } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-16: a registered Build's Canaries reach Shield within 15 s. */
const PROPAGATION_BUDGET_MS = 15_000;
/** PB-17: Canary use opens an Incident within 60 s. */
const INCIDENT_BUDGET_MS = 60_000;
/** Alerts use the short test backoff; one arrives well within this. */
const ALERT_BUDGET_MS = 15_000;
/** How long to listen for an alert that must not come. */
const QUIET_MS = 1_500;
const CONSOLE_URL = "http://127.0.0.1:39941";

/** AWS's documented example access key id: a test value, never a real credential. */
const AWS_EXAMPLE = "AKIAIOSFODNN7EXAMPLE";
const LEAK_FILE = "src/vendor-config.ts";
const SEED = 1;
/** The version of the registered Build: a registered run scopes its Canaries to App and version (A10). */
const VERSION = "7.0.0";
/** A key of the same shape that is not a Canary, for the control requests. */
const NOT_A_CANARY_KEY = "ak_live_0000000000000000000000000000ZZZZ";

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";
const EQUIV_COMMAND = "node --experimental-strip-types check.ts";

interface Received {
  at: number;
  signature: string;
  rawBody: string;
}

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

let api: RunningApi;
let shield: Shield;
let range: http.Server;
let rangeUrl: string;
/** The same application with a disabled Shield: what the responses must look like. */
let control: http.Server;
let controlUrl: string;
let receiver: http.Server;
let adminKey: string;
let shieldKey: string;
let appId: string;
let signingSecret: string;
let bundleDir: string;
let workDir: string;
let outDir: string;
let marker: string;
let leakFingerprintHex: string;
let canaries: Canary[] = [];
/** The registered Build's decoy key. */
let keyCanary: Canary;
let buildId: string;
let registeredAt = 0;
const temps: string[] = [];
const received: Received[] = [];
/** Bundles Shield received (through its own poller), with the time and their Canary ids. */
const bundlesSeen: { at: number; canaryIds: string[] }[] = [];
const timings: { shieldMs?: number; apiBundleMs?: number; incidentMs: number[]; alertMs: number[] } = {
  incidentMs: [],
  alertMs: [],
};

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
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/** Runs the real CLI binary (`antireverse harden …`) in its own process, with `cwd` as the working directory. */
function harden(args: string[], cwd: string): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [tsxCli, cliPath, "harden", ...args],
      { cwd, env: { ...process.env, [KEY_ENV]: adminKey, AR_E2E_MARKER: marker }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

function registerArgs(version = VERSION): string[] {
  return [
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
  ];
}

async function listIncidents(key = adminKey, query = `?app_id=${appId}`): Promise<Incident[]> {
  const response = await call(`/v1/incidents${query}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents;
}

async function canaryIncidents(): Promise<Incident[]> {
  return (await listIncidents()).filter((incident) => incident.rule === "canary-touched");
}

const openedAlerts = () =>
  received.filter((r) => {
    const body = JSON.parse(r.rawBody) as { type: string; incident: Incident | null };
    return body.type === "incident.opened" && body.incident?.rule === "canary-touched";
  });

/** One request to both the protected range and the control range; the answers must be identical. */
async function sameAsControl(path: string, headers: Record<string, string> = {}): Promise<number> {
  const sentAt = Date.now();
  const [viaShield, viaControl] = await Promise.all([
    fetch(`${rangeUrl}${path}`, { headers }),
    fetch(`${controlUrl}${path}`, { headers }),
  ]);
  const [a, b] = [await viaShield.text(), await viaControl.text()];
  expect({ status: viaShield.status, type: viaShield.headers.get("content-type"), body: a }).toEqual({
    status: viaControl.status,
    type: viaControl.headers.get("content-type"),
    body: b,
  });
  return sentAt;
}

/** Shield's transport in this test: the same contract as the default one, over fetch, recording each bundle. */
const observingTransport: Transport = async ({ method = "POST", url, headers, body, timeoutMs }) => {
  const response = await fetch(url, {
    method,
    headers,
    ...(body === undefined ? {} : { body }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (method !== "GET") {
    await response.arrayBuffer();
    return { status: response.status };
  }
  const text = await response.text();
  if (response.status === 200) {
    const signed = SignedBundleSchema.parse(JSON.parse(text));
    const payload = BundlePayloadSchema.parse(JSON.parse(signed.bundle));
    bundlesSeen.push({ at: Date.now(), canaryIds: (payload.canaries ?? []).map((c) => c.id) });
  }
  const etag = response.headers.get("etag");
  return etag === null ? { status: response.status, body: text } : { status: response.status, body: text, etag };
};

beforeAll(async () => {
  receiver = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      received.push({
        at: Date.now(),
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
  shieldKey = created.shield_key.key;

  const channel = await call("/v1/alert-channels", {
    method: "POST",
    key: adminKey,
    body: { kind: "webhook", name: "Ops webhook", url: hookUrl },
  });
  expect(channel.status).toBe(201);
  signingSecret = CreateAlertChannelResponseSchema.parse(await channel.json()).signing_secret ?? "";
  expect(signingSecret).toMatch(/^whsec_/);

  // A copy of the reference bundle (never written in place) with one documented example secret added.
  bundleDir = join(tempDir("antireverse-e2e-bundle-"), "web");
  cpSync(webDir, bundleDir, { recursive: true });
  writeFileSync(
    join(bundleDir, LEAK_FILE),
    `// Vendor settings copied from a tutorial.\nexport const awsAccessKeyId = "${AWS_EXAMPLE}";\n`,
  );
  workDir = tempDir("antireverse-e2e-ci-");
  outDir = join(tempDir("antireverse-e2e-out-"), "protected");
  marker = join(tempDir("antireverse-e2e-marker-"), "test-ran");

  // Shield in front of the range, polling the Policy Bundle on its default interval (5 s).
  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    transport: observingTransport,
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  range = http.createServer(createRangeServer({ shield }));
  await new Promise<void>((resolve) => range.listen(0, "127.0.0.1", resolve));
  rangeUrl = `http://127.0.0.1:${(range.address() as AddressInfo).port}`;

  const disabled = createShield({ key: shieldKey, endpoint: api.url, disabled: true, logger: { warn() {} } });
  control = http.createServer(createRangeServer({ shield: disabled }));
  await new Promise<void>((resolve) => control.listen(0, "127.0.0.1", resolve));
  controlUrl = `http://127.0.0.1:${(control.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await shield?.close();
  for (const server of [range, control, receiver]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 07 leak scan and Canaries over HTTP", () => {
  it("fails the harden on a planted example secret: exit 3, masked finding, nothing written, run or registered", async () => {
    const args = [
      bundleDir,
      "--profile",
      "balanced",
      "--seed",
      String(SEED),
      "--out",
      outDir,
      "--test",
      "node -e \"require('node:fs').writeFileSync(process.env.AR_E2E_MARKER, 'ran')\"",
      ...registerArgs(),
    ];
    const json = await harden([...args, "--json"], workDir);
    expect(json.code, json.stderr).toBe(3);
    const report = JSON.parse(json.stdout) as {
      leak_scan: {
        status: string;
        findings: { rule: string; path: string; line: number; masked: string; fingerprint: string }[];
        suppressed: number;
      };
    };
    expect(report.leak_scan.findings).toHaveLength(1);
    const [finding] = report.leak_scan.findings;
    expect(report.leak_scan).toEqual({
      status: "failed",
      findings: [finding],
      suppressed: 0,
      not_scanned: [],
      decoded_as_latin1: [],
    });
    expect(finding).toMatchObject({ rule: "aws-access-key", path: LEAK_FILE, line: 2 });
    expect(finding?.masked).toMatch(/^.{0,4}…$/);
    leakFingerprintHex = finding?.fingerprint ?? "";
    expect(leakFingerprintHex).toBe(leakFingerprint("aws-access-key", LEAK_FILE, AWS_EXAMPLE));

    // The human report names the rule, the place, the mask and the fingerprint — never the value.
    const human = await harden(args, workDir);
    expect(human.code, human.stderr).toBe(3);
    expect(human.stdout).toContain("✗ leak scan: 1 finding");
    expect(human.stdout).toContain(
      `  aws-access-key  ${LEAK_FILE}:2  ${finding?.masked ?? "?"}  ${leakFingerprintHex}`,
    );
    for (const run of [json, human]) {
      for (const leak of [AWS_EXAMPLE, AWS_EXAMPLE.slice(4), adminKey]) {
        expect(run.stdout).not.toContain(leak);
        expect(run.stderr).not.toContain(leak);
      }
    }

    // Nothing written, the equivalence command never ran, nothing registered.
    expect(existsSync(outDir)).toBe(false);
    expect(existsSync(marker)).toBe(false);
    const builds = await call(`/v1/apps/${appId}/builds`, { key: adminKey });
    expect(ListBuildsResponseSchema.parse(await builds.json()).builds).toEqual([]);
  }, 60_000);

  it("passes once the fingerprint is allowlisted (--leak-allow), and reports the Canaries as not watched", async () => {
    const dir = tempDir("antireverse-e2e-ci-alt-");
    mkdirSync(join(dir, "reviewed"));
    writeFileSync(
      join(dir, "reviewed/leaks.json"),
      JSON.stringify({ version: 1, allow: [{ fingerprint: leakFingerprintHex, reason: "AWS documented example" }] }),
    );
    const run = await harden(
      [bundleDir, "--profile", "balanced", "--seed", String(SEED), "--leak-allow", "reviewed/leaks.json"],
      dir,
    );
    expect(run.code, run.stderr).toBe(0);
    expect(run.stdout).toContain("✓ leak scan clean (1 suppressed)");
    expect(run.stdout).toContain("✓ 3 Canaries planted in src/pricing.ts (not watched: pass --register)");
    // Unregistered, the Canaries derive from the seed only (v1): seed 1 gives the protocol's example Canaries.
    expect(deriveCanaries(SEED)).toEqual(EXAMPLE_CANARIES);
    for (const canary of EXAMPLE_CANARIES) expect(run.stdout).toContain(`  - ${canary.kind} ${canary.id}`);
    expect(run.stdout).not.toContain(AWS_EXAMPLE);
  }, 60_000);

  it("passes with the committed allowlist and registers the Build with 3 Canaries; responses carry no values", async () => {
    mkdirSync(join(workDir, ".antireverse"));
    writeFileSync(
      join(workDir, ".antireverse/leak-allow.json"),
      JSON.stringify({ version: 1, allow: [{ fingerprint: leakFingerprintHex, reason: "AWS documented example" }] }),
    );
    const run = await harden(
      [
        bundleDir,
        "--profile",
        "balanced",
        "--seed",
        String(SEED),
        "--out",
        outDir,
        "--test",
        EQUIV_COMMAND,
        "--json",
        ...registerArgs(),
      ],
      workDir,
    );
    registeredAt = Date.now();
    expect(run.code, run.stderr).toBe(0);
    const report = JSON.parse(run.stdout) as {
      equivalence: string;
      leak_scan: unknown;
      canaries: Canary[];
      canaries_planted_in: string;
      registered: { build_id: string };
    };
    expect(report.equivalence).toBe("passed");
    expect(report.leak_scan).toEqual({
      status: "suppressed",
      findings: [],
      suppressed: 1,
      not_scanned: [],
      decoded_as_latin1: [],
    });
    canaries = report.canaries;
    // Registered, the Canaries are scoped to the App and the version (A10): not the seed-only example ones.
    expect(canaries).toEqual(deriveCanaries(SEED, { appId, version: VERSION }));
    expect(canaries.map((c) => c.kind).sort()).toEqual(["key", "route", "route"]);
    for (const example of EXAMPLE_CANARIES) {
      expect(canaries.map((c) => c.id)).not.toContain(example.id);
      expect(canaries.map((c) => c.value)).not.toContain(example.value);
    }
    keyCanary = canaries.find((c) => c.kind === "key") as Canary;
    expect(report.canaries_planted_in).toBe("src/pricing.ts");
    buildId = report.registered.build_id;
    expect(buildId).toMatch(/^bld_[0-9a-f]{24}$/);
    expect(run.stdout + run.stderr).not.toContain(AWS_EXAMPLE);

    // The protected files were written; the Canaries are planted as plain text in one file.
    expect(readdirSync(join(outDir, "src")).sort()).toEqual([
      "index.ts",
      "pricing.ts",
      "reports.ts",
      "vendor-config.ts",
    ]);
    expect(readFileSync(join(outDir, "src/pricing.ts"), "utf8")).toContain(keyCanary.value);

    // The Build read back: leak-scan summary and Canaries as id and kind only — never a value.
    const detail = await call(`/v1/apps/${appId}/builds/${buildId}`, { key: adminKey });
    expect(detail.status).toBe(200);
    const detailText = await detail.text();
    const { build } = BuildResponseSchema.parse(JSON.parse(detailText));
    expect(build.leak_scan).toEqual({ status: "suppressed", suppressed: 1 });
    const raw = (JSON.parse(detailText) as { build: { canaries: Record<string, unknown>[] } }).build.canaries;
    expect(raw.map((c) => Object.keys(c).sort())).toEqual([
      ["id", "kind"],
      ["id", "kind"],
      ["id", "kind"],
    ]);
    expect(raw.map((c) => c.id).sort()).toEqual(canaries.map((c) => c.id).sort());
    const listText = await (await call(`/v1/apps/${appId}/builds`, { key: adminKey })).text();
    expect(ListBuildsResponseSchema.parse(JSON.parse(listText)).builds.map((b) => b.build_id)).toEqual([buildId]);
    for (const text of [detailText, listText]) {
      for (const canary of canaries) expect(text).not.toContain(canary.value);
      expect(text).not.toContain(AWS_EXAMPLE);
    }
  }, 60_000);

  it("delivers the Canaries to the running Shield within 15 s, in the signed bundle", async () => {
    const ids = canaries.map((c) => c.id).sort();
    // API side: the bundle of the App and Environment carries the Canaries, values included.
    const apiBundle = await until("bundle has the Canaries", PROPAGATION_BUDGET_MS, async () => {
      const response = await call("/v1/policy-bundle", { key: shieldKey });
      if (response.status !== 200) return undefined;
      const payload = BundlePayloadSchema.parse(JSON.parse(SignedBundleSchema.parse(await response.json()).bundle));
      return (payload.canaries?.length ?? 0) > 0 ? payload : undefined;
    });
    timings.apiBundleMs = Date.now() - registeredAt;
    expect([...(apiBundle.canaries ?? [])].sort((a, b) => (a.id < b.id ? -1 : 1))).toEqual(
      [...canaries].sort((a, b) => (a.id < b.id ? -1 : 1)),
    );

    // Shield side: its own poller (default interval) fetches the bundle with the Canaries.
    const seen = await until("Shield received the Canaries", PROPAGATION_BUDGET_MS, async () =>
      bundlesSeen.find((b) => b.at >= registeredAt && b.canaryIds.length === 3),
    );
    timings.shieldMs = seen.at - registeredAt;
    expect(seen.canaryIds.sort()).toEqual(ids);
    expect(timings.shieldMs).toBeLessThanOrEqual(PROPAGATION_BUDGET_MS);
    expect(shield.stats().lastPolicyError).toBeNull();
  }, 30_000);

  it("opens one High 'Canary used' Incident per Canary within 60 s; the responses are unchanged", async () => {
    expect(await canaryIncidents()).toEqual([]);
    const key = canaries.find((c) => c.kind === "key") as Canary;
    const [route1, route2] = canaries.filter((c) => c.kind === "route") as [Canary, Canary];

    // Controls first: a non-Canary key and a non-Canary route change nothing and open nothing.
    await sameAsControl("/api/products/7", { authorization: `Bearer ${NOT_A_CANARY_KEY}` });
    await sameAsControl("/api/internal/aaaaaaaa/backup");

    const sentAt = new Map<string, number>();
    sentAt.set(key.id, await sameAsControl("/api/products/7", { authorization: `Bearer ${key.value}` }));
    sentAt.set(route1.id, await sameAsControl(route1.value));
    await sameAsControl(route1.value.toUpperCase());
    sentAt.set(route2.id, await sameAsControl(route2.value.toUpperCase()));

    const incidents = await until("three Canary Incidents", INCIDENT_BUDGET_MS, async () => {
      const found = await canaryIncidents();
      return found.length >= 3 ? found : undefined;
    });
    expect(incidents).toHaveLength(3);
    expect(incidents.map((i) => i.canary_id).sort()).toEqual(canaries.map((c) => c.id).sort());
    for (const incident of incidents) {
      timings.incidentMs.push(Date.parse(incident.created_at) - (sentAt.get(incident.canary_id ?? "") ?? 0));
      expect(incident).toMatchObject({
        app_id: appId,
        environment: "development",
        rule: "canary-touched",
        title: "Canary used",
        severity: "high",
        status: "open",
        build_id: buildId,
        ip_prefix: "127.0.0.0/24",
      });
    }
    for (const ms of timings.incidentMs) expect(ms).toBeLessThanOrEqual(INCIDENT_BUDGET_MS);
    // Nothing else was raised by the control requests.
    expect((await listIncidents()).filter((i) => i.rule !== "canary-touched")).toEqual([]);

    // Evidence: Events of that prefix carrying that Canary's signal.
    for (const incident of incidents) {
      const detail = await call(`/v1/incidents/${incident.id}`, { key: adminKey });
      expect(detail.status).toBe(200);
      const text = await detail.text();
      const { evidence, detections } = IncidentDetailResponseSchema.parse(JSON.parse(text));
      expect(detections.every((d) => d.rule === "canary-touched" && d.canary_id === incident.canary_id)).toBe(true);
      expect(evidence.length).toBeGreaterThan(0);
      for (const event of evidence) {
        expect(event.signals.map((s) => s.id)).toContain(`canary.touched:${incident.canary_id}`);
      }
      expect(text).not.toContain(key.value);
    }
  }, 90_000);

  it("alerts once per Canary Incident with a valid signature, naming the Canary and the Build only", async () => {
    const alerts = await until("three Canary alerts", ALERT_BUDGET_MS, async () => {
      const found = openedAlerts();
      return found.length >= 3 ? found : undefined;
    });
    const incidents = await canaryIncidents();
    const created = Math.min(...incidents.map((i) => Date.parse(i.created_at)));
    for (const alert of alerts) timings.alertMs.push(alert.at - created);
    const nowS = Math.floor(Date.now() / 1000);
    for (const alert of alerts) {
      expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, nowS)).toBe(true);
      const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert.rawBody));
      expect(payload.incident).toMatchObject({ rule: "canary-touched", severity: "high", build_id: buildId });
      expect(payload.incident?.canary_id).toMatch(/^cny_[0-9a-f]{24}$/);
      expect(alert.rawBody).toContain(`"canary_id":"${payload.incident?.canary_id}"`);
      expect(alert.rawBody).toContain(`"build_id":"${buildId}"`);
      expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${payload.incident?.id}`);
      for (const leak of [keyCanary.value, "ak_live_", AWS_EXAMPLE, adminKey, shieldKey, signingSecret]) {
        expect(alert.rawBody).not.toContain(leak);
      }
    }
    expect(alerts.map((a) => JSON.parse(a.rawBody).incident.canary_id).sort()).toEqual(
      canaries.map((c) => c.id).sort(),
    );
  }, 30_000);

  it("joins repeated use (x-api-key header, api_key query, two-space bearer) to the open Incident without a new alert", async () => {
    const key = canaries.find((c) => c.kind === "key") as Canary;
    const before = (await canaryIncidents()).find((i) => i.canary_id === key.id);
    expect(before).toBeDefined();
    await sameAsControl("/api/products/8", { "x-api-key": key.value });
    // Several spaces after the scheme still carry the token (A11 L3).
    await sameAsControl("/api/products/10", { authorization: `Bearer  ${key.value}` });
    await sameAsControl(`/api/products/9?api_key=${encodeURIComponent(key.value)}`);
    const joined = await until("repeat use joined", INCIDENT_BUDGET_MS, async () => {
      const incident = (await canaryIncidents()).find((i) => i.canary_id === key.id);
      return incident && incident.detection_count > (before?.detection_count ?? 0) ? incident : undefined;
    });
    expect(joined.id).toBe(before?.id);
    expect(await canaryIncidents()).toHaveLength(3);
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect(openedAlerts()).toHaveLength(3);
  }, 90_000);

  it("never sends the decoy key from Shield: the stored Events carry only the Canary id", async () => {
    await shield.flush();
    const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
    expect(response.status).toBe(200);
    const text = await response.text();
    const { events } = ListEventsResponseSchema.parse(JSON.parse(text));
    const signals = events.flatMap((e) => e.signals.map((s) => s.id));
    const count = (id: string) => signals.filter((s) => s === `canary.touched:${id}`).length;
    const [route1, route2] = canaries.filter((c) => c.kind === "route") as [Canary, Canary];
    // Key: bearer, x-api-key, two-space bearer, api_key. Route 1: lower and upper case. Route 2: upper case.
    // Controls: none.
    expect(count(keyCanary.id)).toBe(4);
    expect(count(route1.id)).toBe(2);
    expect(count(route2.id)).toBe(1);
    expect(signals).toHaveLength(7);
    for (const leak of [keyCanary.value, "ak_live_", NOT_A_CANARY_KEY, "api_key", "Bearer"]) {
      expect(text).not.toContain(leak);
    }
  });

  it("keeps the Build, its Canaries and its Incidents away from another Organization", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    const otherApp = CreateAppResponseSchema.parse(
      await (await call("/v1/apps", { method: "POST", key, body: { name: "other-web" } })).json(),
    );
    expect(await listIncidents(key, "")).toEqual([]);
    expect(await listIncidents(key, `?app_id=${appId}`)).toEqual([]);
    const [incident] = await canaryIncidents();
    expect((await call(`/v1/incidents/${incident?.id}`, { key })).status).toBe(404);
    expect((await call(`/v1/apps/${appId}/builds`, { key })).status).toBe(404);
    expect((await call(`/v1/apps/${appId}/builds/${buildId}`, { key })).status).toBe(404);
    expect((await call(`/v1/apps/${appId}/events`, { key })).status).toBe(404);

    // The other Organization's Shield bundle carries no Canary of this one.
    const response = await call("/v1/policy-bundle", { key: otherApp.shield_key.key });
    expect(response.status).toBe(200);
    const bundleText = SignedBundleSchema.parse(await response.json()).bundle;
    expect(BundlePayloadSchema.parse(JSON.parse(bundleText)).canaries).toBeUndefined();
    for (const canary of canaries) expect(bundleText).not.toContain(canary.value);

    console.info(
      `canaries e2e: registration -> API bundle ${timings.apiBundleMs} ms, -> Shield ${timings.shieldMs} ms; ` +
        `Canary request -> Incident ${timings.incidentMs.join(", ")} ms; Incident -> alert ${timings.alertMs.join(", ")} ms`,
    );
  });

  it("registers two Builds with the same --seed and different versions, each with its own Canaries", async () => {
    const run = (version: string) =>
      harden([bundleDir, "--profile", "balanced", "--seed", String(SEED), "--json", ...registerArgs(version)], workDir);
    const builds: { buildId: string; canaries: Canary[] }[] = [];
    for (const version of ["1.0.0", "1.0.1"]) {
      const result = await run(version);
      expect(result.code, result.stderr).toBe(0);
      const report = JSON.parse(result.stdout) as { canaries: Canary[]; registered: { build_id: string } };
      expect(report.canaries).toEqual(deriveCanaries(SEED, { appId, version }));
      const detail = await call(`/v1/apps/${appId}/builds/${report.registered.build_id}`, { key: adminKey });
      expect(detail.status).toBe(200);
      expect(BuildResponseSchema.parse(await detail.json()).build.version).toBe(version);
      builds.push({ buildId: report.registered.build_id, canaries: report.canaries });
    }
    const ids = [...builds.flatMap((b) => b.canaries.map((c) => c.id)), ...canaries.map((c) => c.id)];
    expect(new Set(ids).size).toBe(9);

    // --app must be an App id: anything else is a usage error and registers nothing.
    const bad = await harden(
      [bundleDir, "--profile", "balanced", "--seed", String(SEED), ...registerArgs()].map((arg) =>
        arg === appId ? "shop-web" : arg,
      ),
      workDir,
    );
    expect(bad.code, bad.stderr).toBe(2);
    const list = await call(`/v1/apps/${appId}/builds`, { key: adminKey });
    expect(ListBuildsResponseSchema.parse(await list.json()).builds).toHaveLength(3);
  }, 60_000);
});
