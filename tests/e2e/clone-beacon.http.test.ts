// Slice 10 over HTTP/CLI: the harden CLI plants a Clone Beacon in a copy of the reference bundle (`--origin
// https://shop.example --register`), records it in the --json report and the Manifest, and registers the Build,
// whose responses show the allowed origins but never the token. Reports are then posted to the public
// `POST /v1/beacon` exactly as a browser's navigator.sendBeacon sends them (text/plain body, Origin header):
// only a foreign origin whose Origin header matches opens one High "Clone detected" Incident naming the origin
// and the Build, with one signed alert; allowed, local, repeated, mismatched, unknown, malformed and oversize
// reports change nothing, and every answer is the same empty 204. A forged flood is bounded by the per-Build
// limit of new origins, and another Organization sees nothing.
import { execFile } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BEACON_LIMITS,
  type BuildManifest,
  BuildResponseSchema,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Incident,
  IncidentDetailResponseSchema,
  ListBuildsResponseSchema,
  ListIncidentsResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { deriveBeaconToken, verifyWebhookSignature } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** A counted report opens an Incident within 60 s (ticket 10). */
const INCIDENT_BUDGET_MS = 60_000;
/** Alerts use the short test backoff; one arrives well within this. */
const ALERT_BUDGET_MS = 15_000;
/** How long to wait for something that must not happen (reports are judged after the 204). */
const QUIET_MS = 1_500;
const CONSOLE_URL = "http://127.0.0.1:39941";

const SEED = 10;
const VERSION = "10.0.0";
const ALLOWED = "https://shop.example";
const CLONE = "https://clone.example";
const MIRROR = "https://mirror.example";

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

/** One answer of `POST /v1/beacon`, as the bytes a client sees (the Date header aside). */
interface BeaconAnswer {
  status: number;
  headers: string[];
  body: string;
}

let api: RunningApi;
let receiver: http.Server;
let adminKey: string;
let organizationId: string;
let appId: string;
let signingSecret: string;
let bundleDir: string;
let outDir: string;
let buildId: string;
let token: string;
const temps: string[] = [];
const received: Received[] = [];
const answers: { what: string; answer: BeaconAnswer }[] = [];
const timings: { incidentMs?: number; alertMs?: number } = {};

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

function registerArgs(): string[] {
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
    VERSION,
  ];
}

/**
 * Posts a report as navigator.sendBeacon does: a `text/plain;charset=UTF-8` POST, with the page's origin as the
 * `Origin` header (`undefined` sends none). Answers are recorded for the byte-identity check.
 */
function postBeacon(what: string, body: string | Buffer, origin: string | undefined): Promise<BeaconAnswer> {
  const url = new URL("/v1/beacon", api.url);
  const payload = typeof body === "string" ? Buffer.from(body, "utf8") : body;
  return new Promise((resolve, reject) => {
    const request = http.request(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "text/plain;charset=UTF-8",
          "content-length": String(payload.length),
          ...(origin === undefined ? {} : { origin }),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const headers: string[] = [];
          for (let i = 0; i < response.rawHeaders.length; i += 2) {
            const name = response.rawHeaders[i] ?? "";
            if (name.toLowerCase() === "date") continue;
            headers.push(`${name}: ${response.rawHeaders[i + 1]}`);
          }
          const answer = { status: response.statusCode ?? 0, headers, body: Buffer.concat(chunks).toString("latin1") };
          answers.push({ what, answer });
          resolve(answer);
        });
      },
    );
    request.on("error", reject);
    request.end(payload);
  });
}

/** A report body as the planted beacon sends it: the App id, the beacon token and the page's origin. */
const report = (t: string, o: string, a = appId) => JSON.stringify({ a, t, o });

async function listIncidents(key = adminKey, query = `?app_id=${appId}`): Promise<Incident[]> {
  const response = await call(`/v1/incidents${query}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents;
}

const cloneIncidents = async () => (await listIncidents()).filter((i) => i.rule === "clone-origin");

const cloneAlerts = () =>
  received.filter((r) => {
    const body = JSON.parse(r.rawBody) as { type: string; incident: Incident | null };
    return body.type === "incident.opened" && body.incident?.rule === "clone-origin";
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
  bundleDir = join(tempDir("antireverse-e2e-beacon-bundle-"), "web");
  cpSync(webDir, bundleDir, { recursive: true });
  outDir = join(tempDir("antireverse-e2e-beacon-out-"), "protected");
});

afterAll(async () => {
  if (receiver) {
    receiver.closeAllConnections();
    await new Promise<void>((resolve) => receiver.close(() => resolve()));
  }
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 10 Clone Beacon over HTTP", () => {
  it("refuses --origin without --register (exit 2, nothing written)", async () => {
    const run = await harden([bundleDir, "--seed", String(SEED), "--origin", ALLOWED], tempDir("antireverse-e2e-ci-"));
    expect(run.code, run.stderr).toBe(2);
    expect(run.stderr).toContain("--origin needs --register");
  });

  it("plants the beacon with --origin --register, records it in --json and the Manifest; the Build hides the token", async () => {
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
        "--origin",
        ALLOWED,
        "--json",
        ...registerArgs(),
      ],
      tempDir("antireverse-e2e-ci-"),
    );
    expect(run.code, run.stderr).toBe(0);
    const json = JSON.parse(run.stdout) as {
      equivalence: string;
      canaries_planted_in: string;
      beacon: { token: string; origins: string[]; planted_in: string };
      registered: { build_id: string };
    };
    expect(json.equivalence).toBe("passed");
    token = deriveBeaconToken(SEED >>> 0, { appId, version: VERSION });
    expect(token).toMatch(/^bcn_[0-9a-f]{24}$/);
    // The Canaries and the beacon are planted together, in the reference app's reports module (A3, A4).
    expect(json.beacon).toEqual({ token, origins: [ALLOWED], planted_in: "src/reports.ts" });
    expect(json.canaries_planted_in).toBe("src/reports.ts");
    buildId = json.registered.build_id;
    expect(buildId).toMatch(/^bld_[0-9a-f]{24}$/);

    // The protected file carries the beacon statement as plain text: the report URL, the token, the origin.
    const planted = readFileSync(join(outDir, "src/reports.ts"), "utf8");
    expect(planted).toContain(`navigator.sendBeacon(${JSON.stringify(`${api.url}/v1/beacon`)}`);
    expect(planted).toContain(JSON.stringify(token));
    expect(planted).toContain(ALLOWED);
    for (const other of ["src/index.ts", "src/pricing.ts"]) {
      expect(readFileSync(join(outDir, other), "utf8")).not.toContain(token);
    }

    // The Manifest as stored: the beacon's token and origins.
    const manifest = await api.db.tx({ organizationId }, async (q) => {
      const { rows } = await q.query<{ manifest: BuildManifest }>(
        "SELECT manifest FROM builds WHERE build_id = $1::text",
        [buildId],
      );
      return rows[0]?.manifest;
    });
    expect(manifest?.beacon).toEqual({ token, origins: [ALLOWED] });

    // The Build read back: the origins, never the token.
    const detail = await call(`/v1/apps/${appId}/builds/${buildId}`, { key: adminKey });
    expect(detail.status).toBe(200);
    const detailText = await detail.text();
    expect(BuildResponseSchema.parse(JSON.parse(detailText)).build.beacon).toEqual({ origins: [ALLOWED] });
    const listText = await (await call(`/v1/apps/${appId}/builds`, { key: adminKey })).text();
    expect(ListBuildsResponseSchema.parse(JSON.parse(listText)).builds.map((b) => b.build_id)).toEqual([buildId]);
    for (const text of [detailText, listText]) {
      expect(text).not.toContain(token);
      expect(text).not.toContain(token.slice(4));
    }
  }, 120_000);

  it("ignores reports from the allowed origin (also with a trailing dot) and a local origin (204, no Incident)", async () => {
    expect(await postBeacon("allowed", report(token, ALLOWED), ALLOWED)).toMatchObject({ status: 204, body: "" });
    const local = "http://localhost:5173";
    expect(await postBeacon("local", report(token, local), local)).toMatchObject({ status: 204, body: "" });
    // A browser on http(s)://shop.example. (trailing dot) is on the allowed origin too.
    const dotted = `${ALLOWED}.`;
    expect(await postBeacon("allowed, trailing dot", report(token, dotted), dotted)).toMatchObject({ status: 204 });
    await quiet();
    expect(await listIncidents()).toEqual([]);
  });

  it("opens one High 'Clone detected' Incident for a foreign origin within 60 s, naming the origin and the Build", async () => {
    const sentAt = Date.now();
    expect(await postBeacon("clone", report(token, CLONE), CLONE)).toMatchObject({ status: 204, body: "" });
    const [incident] = await until("a clone Incident", INCIDENT_BUDGET_MS, async () => {
      const found = await cloneIncidents();
      return found.length > 0 ? found : undefined;
    });
    timings.incidentMs = Date.parse(incident?.created_at ?? "") - sentAt;
    expect(timings.incidentMs).toBeLessThanOrEqual(INCIDENT_BUDGET_MS);
    expect(incident).toMatchObject({
      app_id: appId,
      environment: "development",
      rule: "clone-origin",
      title: "Clone detected",
      severity: "high",
      status: "open",
      origin: CLONE,
      build_id: buildId,
      ip_prefix: null,
      canary_id: null,
      detection_count: 1,
    });
    // Its Detection keeps the reporter's network prefix only; no Events, no Actors.
    const detail = await call(`/v1/incidents/${incident?.id}`, { key: adminKey });
    expect(detail.status).toBe(200);
    const text = await detail.text();
    const parsed = IncidentDetailResponseSchema.parse(JSON.parse(text));
    expect(parsed.detections).toHaveLength(1);
    expect(parsed.detections[0]).toMatchObject({ rule: "clone-origin", origin: CLONE, ip_prefix: "127.0.0.0/24" });
    expect(parsed.evidence).toEqual([]);
    expect(parsed.actors).toEqual([]);
    expect(text).not.toContain(token);
    expect(text).not.toContain('"127.0.0.1"');
  }, 90_000);

  it("alerts once, signed, naming the origin and the Build and never the token", async () => {
    const [alert] = await until("one clone alert", ALERT_BUDGET_MS, async () => {
      const found = cloneAlerts();
      return found.length > 0 ? found : undefined;
    });
    const [incident] = await cloneIncidents();
    timings.alertMs = (alert?.at ?? 0) - Date.parse(incident?.created_at ?? "");
    expect(verifyWebhookSignature(signingSecret, alert?.signature ?? "", alert?.rawBody ?? "", Date.now() / 1000)).toBe(
      true,
    );
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert?.rawBody ?? ""));
    expect(payload.incident).toMatchObject({
      id: incident?.id,
      rule: "clone-origin",
      title: "Clone detected",
      severity: "high",
      origin: CLONE,
      build_id: buildId,
    });
    expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${incident?.id}`);
    for (const leak of [token, token.slice(4), adminKey, signingSecret]) expect(alert?.rawBody).not.toContain(leak);
    await quiet();
    expect(cloneAlerts()).toHaveLength(1);
  }, 30_000);

  it("records no second Detection for the same origin within the hour", async () => {
    for (let i = 0; i < 3; i++) await postBeacon("clone again", report(token, CLONE), CLONE);
    await quiet();
    const incidents = await cloneIncidents();
    expect(incidents).toHaveLength(1);
    expect(incidents[0]?.detection_count).toBe(1);
    expect(cloneAlerts()).toHaveLength(1);
  });

  it("does not count a report whose Origin header is missing or differs; the matching one counts", async () => {
    await postBeacon("no origin header", report(token, MIRROR), undefined);
    await postBeacon("other origin header", report(token, MIRROR), CLONE);
    await postBeacon("case-different origin header", report(token, MIRROR), "https://MIRROR.example");
    await quiet();
    expect((await cloneIncidents()).map((i) => i.origin)).toEqual([CLONE]);

    // The same report with the matching header counts: the drops above were the header check.
    await postBeacon("mirror", report(token, MIRROR), MIRROR);
    const incidents = await until("a mirror Incident", INCIDENT_BUDGET_MS, async () => {
      const found = await cloneIncidents();
      return found.length === 2 ? found : undefined;
    });
    expect(incidents.map((i) => i.origin).sort()).toEqual([CLONE, MIRROR]);
  }, 90_000);

  it("answers unknown tokens, malformed and oversize reports with the same empty 204, and records nothing", async () => {
    const before = await cloneIncidents();
    const unknown = `bcn_${"0".repeat(24)}`;
    const elsewhere = "https://elsewhere.example";
    await postBeacon("unknown token", report(unknown, elsewhere), elsewhere);
    await postBeacon("not json", "{t:", elsewhere);
    await postBeacon("empty", "", elsewhere);
    await postBeacon("wrong shape", JSON.stringify({ app: appId, token, origin: elsewhere }), elsewhere);
    await postBeacon("other App id", report(token, elsewhere, `app_${"0".repeat(24)}`), elsewhere);
    await postBeacon("not canonical", report(token, `${elsewhere}/path`), `${elsewhere}/path`);
    await postBeacon("bad utf-8", Buffer.from([0x7b, 0xff, 0xfe, 0x7d]), elsewhere);
    const padded = JSON.stringify({ a: appId, t: token, o: elsewhere, pad: "x".repeat(BEACON_LIMITS.bodyBytesMax) });
    expect(Buffer.byteLength(padded)).toBeGreaterThan(BEACON_LIMITS.bodyBytesMax);
    await postBeacon("oversize", padded, elsewhere);
    await quiet();
    expect(await cloneIncidents()).toEqual(before);
    expect(cloneAlerts()).toHaveLength(2);

    // Every answer so far — counted, ignored, dropped — is the same bytes.
    expect(answers.length).toBeGreaterThanOrEqual(15);
    const [first] = answers;
    expect(first?.answer.status).toBe(204);
    expect(first?.answer.body).toBe("");
    expect(first?.answer.headers.map((h) => h.toLowerCase())).toContain("cache-control: no-store");
    for (const { what, answer } of answers) expect({ what, answer }).toEqual({ what, answer: first?.answer });
  }, 30_000);

  it("bounds a forged flood of distinct origins by the per-Build limit of new origins", async () => {
    const flood = Array.from({ length: 30 }, (_, i) => `https://forged-${i}.example`);
    await Promise.all(flood.map((origin) => postBeacon("flood", report(token, origin), origin)));
    // Two origins were already detected this hour; the flood may add the rest of the 20.
    const limit = BEACON_LIMITS.newOriginsPerHour;
    await until("the flood judged", INCIDENT_BUDGET_MS, async () =>
      (await cloneIncidents()).length >= limit ? true : undefined,
    );
    await quiet();
    const incidents = await cloneIncidents();
    expect(incidents).toHaveLength(limit);
    expect(new Set(incidents.map((i) => i.origin)).size).toBe(limit);
    expect(incidents.every((i) => i.build_id === buildId && i.severity === "high")).toBe(true);
    await until("the flood's alerts", ALERT_BUDGET_MS, async () => (cloneAlerts().length >= limit ? true : undefined));
    await quiet();
    expect(cloneAlerts()).toHaveLength(limit);
    for (const answer of answers.filter((a) => a.what === "flood")) expect(answer.answer).toEqual(answers[0]?.answer);
  }, 90_000);

  it("keeps the clone Incidents and the Build's beacon away from another Organization", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    expect(await listIncidents(key, "")).toEqual([]);
    expect(await listIncidents(key, `?app_id=${appId}`)).toEqual([]);
    const [incident] = await cloneIncidents();
    expect((await call(`/v1/incidents/${incident?.id}`, { key })).status).toBe(404);
    expect((await call(`/v1/apps/${appId}/builds/${buildId}`, { key })).status).toBe(404);

    console.info(
      `clone-beacon e2e: report -> Incident ${timings.incidentMs} ms; Incident -> alert ${timings.alertMs} ms`,
    );
  });
});
