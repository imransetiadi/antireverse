// Slice 19 over HTTP/CLI: the fixture advisories are imported with the real `vulns:sync --fixture` command into a
// fresh data directory; the API starts on it. The harden CLI hardens the reference bundle with `--register
// --lockfile <lockfile>` naming a package version a Critical fixture advisory affects: the register response's
// findings summary lists it, `GET /v1/findings` shows it open with its aliases and fixed version, a "Vulnerable
// component" Incident carries the advisory and a signed alert reaches a local receiver. `--fail-on high` and
// `--fail-on critical` exit 4; after the upgrade to the fixed version the gate passes and the old Finding is fixed.
// Shield's runtime inventory (projectRoot = a folder with a vulnerable lockfile) produces a runtime Finding.
// Another Organization sees no Finding.
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Finding,
  FindingDetailResponseSchema,
  type FindingsSummary,
  type Incident,
  ListFindingsResponseSchema,
  ListIncidentsResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { verifyWebhookSignature } from "@antireverse/protocol/server";
import { createShield, type Shield } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** Alerts use the short test backoff; one arrives well within this. */
const ALERT_BUDGET_MS = 15_000;
/** Shield starts its inventory 1 s after creation without a Policy key; with retries it is sent well within this. */
const INVENTORY_BUDGET_MS = 15_000;
/** How long to listen for an alert that must not come. */
const QUIET_MS = 1_500;
const CONSOLE_URL = "http://127.0.0.1:39941";

/** Fixture advisory GHSA-fx01-0005-scop: `@fixture/vuln-scoped` < 5.0.0, CRITICAL, alias CVE-2026-90005. */
const CRITICAL = { id: "GHSA-fx01-0005-scop", cve: "CVE-2026-90005", pkg: "@fixture/vuln-scoped", fixed: "5.0.0" };
/** Fixture advisory GHSA-fx01-0001-rang: `vuln-range` [2.0.0, 2.1.1) is HIGH, alias CVE-2026-90001. */
const HIGH = { id: "GHSA-fx01-0001-rang", cve: "CVE-2026-90001", pkg: "vuln-range", fixed: "2.1.1" };

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const syncPath = join(root, "apps/api/src/vulns/cli.ts");
const fixtureAdvisories = join(root, "apps/api/test/fixtures/advisories.json");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

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

interface JsonReport {
  registered?: { build_id: string };
  components: { count: number; skipped: number } | null;
  findings: FindingsSummary | null;
  gate: unknown;
}

let api: RunningApi;
let receiver: http.Server;
let shield: Shield | undefined;
let adminKey: string;
let shieldKey: string;
let appId: string;
let signingSecret: string;
let workDir: string;
let vulnerableLock: string;
let upgradedLock: string;
let firstBuildId: string;
let criticalFindingId: string;
/** The last Build that shipped the vulnerable version: its Finding moved there (second review M-A). */
let lastVulnerableBuildId: string;
const temps: string[] = [];
const received: Received[] = [];

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

/** Runs the real CLI binary (`antireverse harden <reference bundle> … --register`) in its own process. */
function harden(version: string, lockfile: string, extra: string[] = []): Promise<CliRun> {
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
      ...extra,
    ],
    { cwd: workDir, env: { [KEY_ENV]: adminKey } },
  );
}

/** A package-lock v3 with the given packages (name → version); one dev dependency that no advisory names. */
function lockfile(dir: string, packages: Record<string, string>, file = "package-lock.json"): string {
  const entries: Record<string, unknown> = { "": { name: "shop-web", version: "1.0.0" } };
  for (const [name, version] of Object.entries(packages)) entries[`node_modules/${name}`] = { version };
  entries["node_modules/safe-dev-tool"] = { version: "3.1.4", dev: true };
  const path = join(dir, file);
  writeFileSync(path, JSON.stringify({ name: "shop-web", version: "1.0.0", lockfileVersion: 3, packages: entries }));
  return path;
}

async function listFindings(key = adminKey, query = `?app_id=${appId}`): Promise<Finding[]> {
  const response = await call(`/v1/findings${query}`, { key });
  expect(response.status).toBe(200);
  return ListFindingsResponseSchema.parse(await response.json()).findings;
}

async function listIncidents(key = adminKey, query = `?app_id=${appId}`): Promise<Incident[]> {
  const response = await call(`/v1/incidents${query}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents;
}

const vulnerableIncidents = async () =>
  (await listIncidents()).filter((incident) => incident.rule === "vulnerable-component");

/** The incident.opened alerts of vulnerable-component Incidents. */
const openedAlerts = () =>
  received.filter((r) => {
    const body = JSON.parse(r.rawBody) as { type: string; incident: Incident | null };
    return body.type === "incident.opened" && body.incident?.rule === "vulnerable-component";
  });

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

  // The advisories come in through the real sync command (fixture source, no network), before the API owns the
  // data directory (PGlite allows one owner at a time).
  const dataDir = join(tempDir("antireverse-e2e-vulns-"), "pg");
  const synced = await run([syncPath, "--fixture", fixtureAdvisories], {
    cwd: root,
    env: { AR_DATA_DIR: dataDir },
  });
  expect(synced.code, synced.stderr).toBe(0);
  // Counts only: no advisory id or package name in the command's output.
  expect(`${synced.stdout}${synced.stderr}`).toMatch(/advisories received=10 inserted=10/);
  expect(`${synced.stdout}${synced.stderr}`).not.toMatch(/GHSA-|vuln-|fixture\//);

  api = await startApi({
    dataDir,
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
  expect(shieldKey).toMatch(/^ark_dev_/);

  const channel = await call("/v1/alert-channels", {
    method: "POST",
    key: adminKey,
    body: { kind: "webhook", name: "Ops webhook", url: hookUrl },
  });
  expect(channel.status).toBe(201);
  signingSecret = CreateAlertChannelResponseSchema.parse(await channel.json()).signing_secret ?? "";
  expect(signingSecret).toMatch(/^whsec_/);

  workDir = tempDir("antireverse-e2e-ci-");
  vulnerableLock = lockfile(tempDir("antireverse-e2e-lock-"), { [CRITICAL.pkg]: "4.2.0", "safe-pkg": "1.0.0" });
  upgradedLock = lockfile(tempDir("antireverse-e2e-lock-"), { [CRITICAL.pkg]: CRITICAL.fixed, "safe-pkg": "1.0.0" });
});

afterAll(async () => {
  await shield?.close();
  if (receiver) {
    receiver.closeAllConnections();
    await new Promise<void>((resolve) => receiver.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 19 Exposure: CVE Findings over HTTP/CLI", () => {
  it("registers a hardened Build with a vulnerable lockfile: summary, open Finding, Incident and a signed alert", async () => {
    expect(await listFindings()).toEqual([]);

    const result = await harden("1.0.0", vulnerableLock, ["--json"]);
    expect(result.code, result.stderr).toBe(0);
    const report = JSON.parse(result.stdout) as JsonReport;
    firstBuildId = report.registered?.build_id ?? "";
    expect(firstBuildId).toMatch(/^bld_[0-9a-f]{24}$/);
    // Three components read (the dev one included); only names and versions are counted, never printed.
    expect(report.components).toEqual({ count: 3, skipped: 0 });
    expect(report.findings).toEqual({
      open: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      items: [
        {
          advisory: CRITICAL.id,
          package: CRITICAL.pkg,
          version: "4.2.0",
          severity: "critical",
          fixed: [CRITICAL.fixed],
        },
      ],
    });
    expect(result.stdout).not.toContain("safe-pkg");
    expect(result.stdout).not.toContain(adminKey);

    // GET /v1/findings: open, with its aliases and fixed version, found in that Build.
    const findings = await listFindings();
    expect(findings).toHaveLength(1);
    const [finding] = findings as [Finding];
    criticalFindingId = finding.id;
    expect(finding).toMatchObject({
      app_id: appId,
      environment: "development",
      source: "build",
      build_id: firstBuildId,
      package: CRITICAL.pkg,
      version: "4.2.0",
      dev: false,
      advisory_id: CRITICAL.id,
      aliases: [CRITICAL.cve],
      severity: "critical",
      fixed_versions: [CRITICAL.fixed],
      status: "open",
      ignore: null,
    });
    // The filters of the Console narrow to it: by CVE alias, by Build, by severity, by source.
    expect((await listFindings(adminKey, `?advisory_id=${CRITICAL.cve}`)).map((f) => f.id)).toEqual([finding.id]);
    expect((await listFindings(adminKey, `?build_id=${firstBuildId}`)).map((f) => f.id)).toEqual([finding.id]);
    expect(await listFindings(adminKey, `?app_id=${appId}&severity=high`)).toEqual([]);
    expect(await listFindings(adminKey, `?app_id=${appId}&source=runtime`)).toEqual([]);

    // The detail carries the advisory (affected ranges).
    const detail = await call(`/v1/findings/${finding.id}`, { key: adminKey });
    expect(detail.status).toBe(200);
    const body = FindingDetailResponseSchema.parse(await detail.json());
    expect(body.advisory.id).toBe(CRITICAL.id);
    expect(body.advisory.affected[0]?.package.name).toBe(CRITICAL.pkg);

    // One Critical "Vulnerable component" Incident with the advisory.
    const incidents = await vulnerableIncidents();
    expect(incidents).toHaveLength(1);
    const [incident] = incidents as [Incident];
    expect(incident).toMatchObject({
      app_id: appId,
      environment: "development",
      rule: "vulnerable-component",
      title: "Vulnerable component",
      severity: "critical",
      status: "open",
      advisory_id: CRITICAL.id,
      ip_prefix: null,
    });

    // The alert reaches the receiver, signed with the channel's secret.
    const alert = await until("alert received", ALERT_BUDGET_MS, async () => openedAlerts()[0]);
    expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, Math.floor(Date.now() / 1000))).toBe(
      true,
    );
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert.rawBody));
    expect(payload.type).toBe("incident.opened");
    expect(payload.incident).toEqual(incident);
    expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${incident.id}`);
    for (const leak of [adminKey, shieldKey, signingSecret, "safe-pkg"]) expect(alert.rawBody).not.toContain(leak);
  });

  it("fails the CI step with --fail-on high and --fail-on critical (exit 4) without a second Incident", async () => {
    const high = await harden("1.0.1", vulnerableLock, ["--fail-on", "high"]);
    expect(high.code, high.stderr).toBe(4);
    expect(high.stdout).toContain("open findings: critical 1, high 0, medium 0, low 0, unknown 0");
    expect(high.stdout).toContain(`${CRITICAL.id}  ${CRITICAL.pkg}@4.2.0  critical  fixed in ${CRITICAL.fixed}`);
    expect(high.stderr).toContain("findings gate failed");
    expect(high.stderr).toContain("at or above high");

    const critical = await harden("1.0.2", vulnerableLock, ["--fail-on", "critical", "--json"]);
    expect(critical.code, critical.stderr).toBe(4);
    const report = JSON.parse(critical.stdout) as JsonReport;
    expect(report.registered?.build_id).toMatch(/^bld_/);
    expect(report.findings?.open.critical).toBe(1);
    expect(critical.stderr).toContain("at or above critical");
    lastVulnerableBuildId = report.registered?.build_id ?? "";

    // Second review M-A: one open Finding per identity, moved to the newest Build that ships it (same id); the
    // Incident is grouped per advisory: still one, one alert.
    const open = await listFindings(adminKey, `?app_id=${appId}&status=open`);
    expect(open).toHaveLength(1);
    expect(open[0]).toMatchObject({ id: criticalFindingId, build_id: lastVulnerableBuildId });
    expect(new Set(open.map((f) => f.advisory_id))).toEqual(new Set([CRITICAL.id]));
    expect(await vulnerableIncidents()).toHaveLength(1);
    expect((await vulnerableIncidents())[0]?.status).toBe("open");
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect(openedAlerts()).toHaveLength(1);
  });

  it("passes the gate after the upgrade to the fixed version, and the older Builds' Findings are fixed", async () => {
    const upgraded = await harden("1.1.0", upgradedLock, ["--fail-on", "high", "--json"]);
    expect(upgraded.code, upgraded.stderr).toBe(0);
    const report = JSON.parse(upgraded.stdout) as JsonReport;
    expect(report.findings).toEqual({ open: { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }, items: [] });

    const findings = await listFindings();
    expect(findings).toHaveLength(1);
    for (const finding of findings) expect(finding.status).toBe("fixed");
    expect(findings.find((f) => f.id === criticalFindingId)).toMatchObject({
      build_id: lastVulnerableBuildId,
      status: "fixed",
      ignore: null,
    });
    expect(await listFindings(adminKey, `?app_id=${appId}&status=open`)).toEqual([]);

    // A fixed Finding cannot be ignored or reopened.
    expect(
      (
        await call(`/v1/findings/${criticalFindingId}/ignore`, {
          method: "POST",
          key: adminKey,
          body: { reason: "accepted", until: new Date(Date.now() + 7 * 86_400_000).toISOString() },
        })
      ).status,
    ).toBe(409);
    expect((await call(`/v1/findings/${criticalFindingId}/reopen`, { method: "POST", key: adminKey })).status).toBe(
      409,
    );
    // No new alert for the upgrade.
    expect(openedAlerts()).toHaveLength(1);
  });

  it("produces a runtime Finding from Shield's runtime inventory", async () => {
    // The server's installed packages: vuln-range 2.0.5 is in the HIGH range [2.0.0, 2.1.1).
    const projectRoot = tempDir("antireverse-e2e-server-");
    lockfile(projectRoot, { [HIGH.pkg]: "2.0.5", express: "5.3.0" });
    const warnings: string[] = [];
    shield = createShield({
      key: shieldKey,
      endpoint: api.url,
      projectRoot,
      flushIntervalMs: 200,
      logger: { warn: (line) => warnings.push(line) },
    });
    expect(shield.stats().inventory).toBe("pending");
    await until("inventory sent", INVENTORY_BUDGET_MS, async () =>
      shield?.stats().inventory === "sent" ? true : undefined,
    );

    const runtime = await until("runtime Finding", ALERT_BUDGET_MS, async () => {
      const found = await listFindings(adminKey, `?app_id=${appId}&source=runtime`);
      return found.length > 0 ? found : undefined;
    });
    expect(runtime).toHaveLength(1);
    expect(runtime[0]).toMatchObject({
      app_id: appId,
      environment: "development",
      source: "runtime",
      build_id: null,
      package: HIGH.pkg,
      version: "2.0.5",
      advisory_id: HIGH.id,
      aliases: [HIGH.cve],
      severity: "high",
      fixed_versions: ["1.2.4", HIGH.fixed],
      status: "open",
    });

    // A High Finding opens its own Incident (another advisory) and alerts.
    const incident = await until("runtime Incident", ALERT_BUDGET_MS, async () =>
      (await vulnerableIncidents()).find((i) => i.advisory_id === HIGH.id),
    );
    expect(incident).toMatchObject({ severity: "high", status: "open", title: "Vulnerable component" });
    const alert = await until("runtime alert", ALERT_BUDGET_MS, async () =>
      openedAlerts().find((r) => JSON.parse(r.rawBody).incident?.advisory_id === HIGH.id),
    );
    expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, Math.floor(Date.now() / 1000))).toBe(
      true,
    );
    // Shield never logs package names.
    for (const line of warnings) expect(line).not.toMatch(/vuln-range|express|safe-dev-tool/);
  });

  it("keeps Findings away from another Organization and from a Shield key", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    expect(await listFindings(key, "")).toEqual([]);
    expect(await listFindings(key, `?app_id=${appId}`)).toEqual([]);
    expect(await listFindings(key, `?advisory_id=${CRITICAL.id}`)).toEqual([]);
    const [runtime] = await listFindings(adminKey, `?app_id=${appId}&source=runtime`);
    for (const id of [criticalFindingId, runtime?.id ?? ""]) {
      expect((await call(`/v1/findings/${id}`, { key })).status).toBe(404);
      expect(
        (
          await call(`/v1/findings/${id}/ignore`, {
            method: "POST",
            key,
            body: { reason: "not mine", until: new Date(Date.now() + 7 * 86_400_000).toISOString() },
          })
        ).status,
      ).toBe(404);
      expect((await call(`/v1/findings/${id}/reopen`, { method: "POST", key })).status).toBe(404);
    }
    expect((await listIncidents(key, "")).filter((i) => i.rule === "vulnerable-component")).toEqual([]);
    // Nothing changed for the owner.
    expect((await listFindings(adminKey, `?app_id=${appId}&source=runtime`))[0]?.status).toBe("open");

    // A Shield key is not an admin key.
    expect((await call("/v1/findings", { key: shieldKey })).status).toBe(403);
    expect((await call(`/v1/findings/${criticalFindingId}`, { key: shieldKey })).status).toBe(403);
  });
});
