// Shared by the Campaign tests (slice 15a): a real API (startApi) with Campaigns on, a stand-in resolver, and one
// local test target — apps/range with its seeded weaknesses behind node:https, with the TLS fixture certificate for
// shop.acme-shop.io, on a free loopback port. The API reaches it only through the Campaign transport's test-only
// option (test CA, the port, loopback allowed). Everything binds 127.0.0.1; no request leaves the machine.
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { type CampaignEngineRunner, type Resolver, type RunningApi, startApi } from "@antireverse/api";
import {
  AuditExportLineSchema,
  type Campaign,
  type CampaignExchange,
  type CampaignFinding,
  type CampaignRequest,
  CampaignResponseSchema,
  CreateOrganizationResponseSchema,
  campaignAuthorisationPhrase,
  confirmationPhrase,
  type Intensity,
  ListCampaignFindingsResponseSchema,
  ListCampaignRequestsResponseSchema,
  RulesOfEngagementResponseSchema,
  TargetResponseSchema,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import { runCampaignEngine } from "@antireverse/prove";
import { createRangeServer, createRequestLog, type RangeHostile, type RangeRequestLog } from "@antireverse/range";
import { expect } from "vitest";

const tls = (name: string) =>
  readFileSync(new URL(`../../../apps/api/test/fixtures/prove-tls/${name}`, import.meta.url), "utf8");
export const CA = tls("ca.pem");
/** The name the fixture certificate is issued for: the one host a local target can have. */
export const HOST = "shop.acme-shop.io";
/** Monday 2026-11-16 10:00 UTC. */
export const T0 = Date.parse("2026-11-16T10:00:00.000Z");
export const OPS_TOKEN = "ops-token-for-campaign-tests-0123456789";
export const silent = { info() {}, warn() {} };

/** One request as the test target saw it, before anything else. */
export interface Hit {
  method: string;
  url: string;
  host: string | undefined;
  userAgent: string | undefined;
  campaign: string | undefined;
  cookie: boolean;
  bodyBytes: number;
  /** Whether the client dropped the connection before the response ended. */
  aborted: boolean;
}

export interface Target {
  port: number;
  /** Every request the target received, the ownership file's included. */
  hits: Hit[];
  /** The Campaign probes among them (everything but the ownership file). */
  probes(): Hit[];
  /** The range's own log (what reached the application). */
  range: RangeRequestLog;
  /** The content of the ownership file, or null for a 404. */
  token: string | null;
  /** Replaces the application: a new ar-range with these options. */
  serve(options?: { hostile?: RangeHostile; slowMs?: number; weaknesses?: boolean }): void;
  /** Answers every probe itself instead of the application (the ownership file excepted). */
  intercept: ((req: IncomingMessage, res: ServerResponse) => void) | null;
  reset(): void;
  close(): Promise<void>;
}

/** A Shield that lets everything through: the Campaign tests are not about Shield. */
const passthrough = { express: () => (_req: unknown, _res: unknown, next: () => void) => next() };

export async function startTarget(): Promise<Target> {
  const range = createRequestLog();
  let app = createRangeServer({ shield: passthrough, weaknesses: true, log: range });
  const target: Target = {
    port: 0,
    hits: [],
    probes: () => target.hits.filter((hit) => hit.url !== VERIFICATION_FILE_PATH),
    range,
    token: null,
    serve(options = {}) {
      app = createRangeServer({ shield: passthrough, weaknesses: true, log: range, ...options });
    },
    intercept: null,
    reset() {
      target.hits.length = 0;
      range.clear();
      target.intercept = null;
      target.token = null;
      target.serve();
    },
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  const server: Server = createServer({ key: tls("key.pem"), cert: tls("cert.pem") }, (req, res) => {
    const hit: Hit = {
      method: req.method ?? "",
      url: req.url ?? "",
      host: req.headers.host,
      userAgent: req.headers["user-agent"],
      campaign: [req.headers["x-airverse-campaign"]].flat()[0],
      cookie: req.headers.cookie !== undefined || req.headers.authorization !== undefined,
      bodyBytes: 0,
      aborted: false,
    };
    target.hits.push(hit);
    req.on("data", (chunk: Buffer) => {
      hit.bodyBytes += chunk.byteLength;
    });
    res.on("close", () => {
      hit.aborted = !res.writableFinished;
    });
    if (req.url === VERIFICATION_FILE_PATH) {
      if (target.token === null) res.writeHead(404).end();
      else res.end(`${target.token}\n`);
      return;
    }
    if (target.intercept !== null) return target.intercept(req, res);
    app(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  target.port = (server.address() as AddressInfo).port;
  return target;
}

const dnsError = (code: string) => Object.assign(new Error(code), { code });

/** TXT records and addresses by name; `lookups` counts the address lookups per host. */
export function fakeDns() {
  const txt = new Map<string, string[][]>();
  const addresses = new Map<string, string[] | (() => string[])>();
  const lookups = new Map<string, number>();
  const resolver: Resolver = {
    async txt(name) {
      const records = txt.get(name);
      if (records === undefined) throw dnsError("ENOTFOUND");
      return records;
    },
    async addresses(host) {
      lookups.set(host, (lookups.get(host) ?? 0) + 1);
      const answer = addresses.get(host);
      if (answer === undefined) throw dnsError("ENOTFOUND");
      return typeof answer === "function" ? answer() : answer;
    },
  };
  return { txt, addresses, lookups, resolver };
}

export interface Harness {
  api: RunningApi;
  target: Target;
  dns: ReturnType<typeof fakeDns>;
  clock: { ms: number };
  /** The engine the next Campaigns run: null for the real stand-in in its worker. */
  engine: { run: CampaignEngineRunner | null };
  close(): Promise<void>;
}

/** Spacing and deadline of the test transport: the budgets themselves are the protocol's and are not shortened. */
export const FAST = { minSpacingMs: 15, requestTimeoutMs: 400 };

export async function startHarness(options: { enabled?: boolean; production?: boolean } = {}): Promise<Harness> {
  const target = await startTarget();
  const dns = fakeDns();
  dns.addresses.set(HOST, ["127.0.0.1"]);
  const clock = { ms: T0 };
  const engine: Harness["engine"] = { run: null };
  const api = await startApi({
    logger: silent,
    now: () => new Date(clock.ms),
    prove: { resolver: dns.resolver },
    recheck: { setTimer: () => ({}), clearTimer: () => {} },
    ops: { token: OPS_TOKEN, webhook: null },
    campaigns: {
      enabled: options.enabled ?? true,
      // `production`: no test-only option at all, as the API runs outside tests.
      ...(options.production === true ? {} : { testing: { ca: CA, port: target.port, allowLoopback: true, ...FAST } }),
      engine: (run) => (engine.run ?? runCampaignEngine)(run),
    },
  });
  return {
    api,
    target,
    dns,
    clock,
    engine,
    close: async () => {
      await api.close();
      await target.close();
    },
  };
}

export function call(
  api: RunningApi,
  path: string,
  init: { method?: string; key?: string; body?: unknown; reason?: string | null } = {},
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  if (init.key && (init.method ?? "GET") !== "GET" && init.reason !== null) {
    headers["x-airverse-reason"] = init.reason ?? "End-to-end test";
  }
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return fetch(`${api.url}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}

export const ops = (api: RunningApi, path: string, body?: unknown) =>
  call(api, path, { method: body === undefined ? "GET" : "POST", key: OPS_TOKEN, body, reason: null });

export interface Org {
  id: string;
  key: string;
  targetId: string;
  token: string;
  roeId: string;
}

/**
 * A new Organization with the host as a Verified Target (proven through the stand-in DNS) and signed Rules of
 * Engagement that cover it at any time of the week. The test target then serves this Organization's ownership file.
 */
export async function setupOrg(
  h: Harness,
  name: string,
  roe: { exclusions?: string[]; intensity?: Intensity; window?: { days: string[]; from: string; to: string } } = {},
): Promise<Org> {
  const { api } = h;
  const created = CreateOrganizationResponseSchema.parse(
    await (await call(api, "/v1/organizations", { method: "POST", body: { name } })).json(),
  );
  const key = created.admin_key.key;
  const added = TargetResponseSchema.parse(
    await (await call(api, "/v1/targets", { method: "POST", key, body: { host: HOST } })).json(),
  );
  h.dns.txt.set(added.verification.dns_name, [[added.verification.dns_value]]);
  expect((await call(api, `/v1/targets/${added.target.id}/verify`, { method: "POST", key })).status).toBe(200);
  const org: Org = {
    id: created.organization.id,
    key,
    targetId: added.target.id,
    token: added.verification.file_content,
    roeId: "",
  };
  org.roeId = await signRoe(h, org, roe);
  h.target.token = org.token;
  return org;
}

export async function signRoe(
  h: Harness,
  org: Org,
  roe: { exclusions?: string[]; intensity?: Intensity; window?: { days: string[]; from: string; to: string } } = {},
): Promise<string> {
  const intensity = roe.intensity ?? "safe-active";
  const signed = await call(h.api, "/v1/rules-of-engagement", {
    method: "POST",
    key: org.key,
    body: {
      scope: [org.targetId],
      exclusions: roe.exclusions ?? [],
      intensity,
      window: roe.window ?? { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], from: "00:00", to: "24:00" },
      contacts: ["security@acme-shop.io"],
      confirm: confirmationPhrase(intensity),
    },
  });
  expect(signed.status).toBe(201);
  return RulesOfEngagementResponseSchema.parse(await signed.json()).version.id;
}

export const campaignBody = (org: Org, intensity: "passive" | "safe-active" = "safe-active") => ({
  target_id: org.targetId,
  intensity,
  confirm: campaignAuthorisationPhrase(HOST),
  staging: true,
});

export async function createCampaign(
  h: Harness,
  org: Org,
  intensity: "passive" | "safe-active" = "safe-active",
): Promise<Campaign> {
  const response = await call(h.api, "/v1/campaigns", {
    method: "POST",
    key: org.key,
    body: campaignBody(org, intensity),
  });
  expect(response.status, await response.clone().text()).toBe(202);
  return CampaignResponseSchema.parse(await response.json()).campaign;
}

export async function readCampaign(h: Harness, org: Org, id: string): Promise<Campaign> {
  const response = await call(h.api, `/v1/campaigns/${id}`, { key: org.key });
  expect(response.status).toBe(200);
  return CampaignResponseSchema.parse(await response.json()).campaign;
}

/** Creates a Campaign and waits until it ended. */
export async function runCampaign(
  h: Harness,
  org: Org,
  intensity: "passive" | "safe-active" = "safe-active",
): Promise<Campaign> {
  const created = await createCampaign(h, org, intensity);
  await h.api.campaigns.idle();
  return readCampaign(h, org, created.id);
}

export async function requestsOf(h: Harness, org: Org, id: string): Promise<CampaignRequest[]> {
  const response = await call(h.api, `/v1/campaigns/${id}/requests`, { key: org.key });
  return ListCampaignRequestsResponseSchema.parse(await response.json()).requests;
}

export async function findingsOf(h: Harness, org: Org, id: string): Promise<CampaignFinding[]> {
  const response = await call(h.api, `/v1/campaigns/${id}/findings`, { key: org.key });
  return ListCampaignFindingsResponseSchema.parse(await response.json()).findings;
}

export async function until(condition: () => boolean | Promise<boolean>, what: string, ms = 10_000): Promise<void> {
  const started = Date.now();
  while (!(await condition())) {
    if (Date.now() - started > ms) throw new Error(`Timed out waiting for ${what}.`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

/** What a scripted engine can do: exactly what the real one can. */
export interface ScriptContext {
  request(probe: unknown): Promise<CampaignExchange>;
}

/**
 * A scripted engine in place of the worker, for the scope-escape tests: it asks the gate for whatever the test wants
 * (other methods, absolute URLs, more requests than the budget). Unlike a terminated worker it may keep asking after
 * a stop, which the gate must then refuse.
 */
export function scripted(script: (context: ScriptContext) => Promise<void>): CampaignEngineRunner {
  return (options) =>
    new Promise<void>((resolve, reject) => {
      const onAbort = () => reject(new DOMException("The Campaign was stopped.", "AbortError"));
      if (options.signal?.aborted) return onAbort();
      options.signal?.addEventListener("abort", onAbort, { once: true });
      script({ request: (probe) => options.request(probe) }).then(resolve, reject);
    });
}

/** A second local HTTPS server (same certificate) that must never be contacted: it only counts. */
export async function startDecoy(): Promise<{ port: number; hits: string[]; close(): Promise<void> }> {
  const hits: string[] = [];
  const server = createServer({ key: tls("key.pem"), cert: tls("cert.pem") }, (req, res) => {
    hits.push(`${req.method} ${req.url}`);
    res.end("decoy");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as AddressInfo).port,
    hits,
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** The audit entries of an Organization, oldest first, read through the export. */
export async function auditOf(h: Harness, org: Org) {
  const exported = await (await call(h.api, "/v1/audit/export", { key: org.key })).text();
  return exported
    .trim()
    .split("\n")
    .slice(1)
    .map((line) => AuditExportLineSchema.parse(JSON.parse(line)));
}
