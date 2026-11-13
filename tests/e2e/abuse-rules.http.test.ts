// Slice 08 over HTTP: abuse rules. A real Express app with Shield (search, cart, login and health routes) and the
// real API. Limit Rules are published in monitor first: requests over the limit get the app's own response and
// their Events record throttle/monitor. Promoted to enforce (the publish names the version it was based on; a
// broad limit Rule needs `allow_broad`), a client over the request limit gets 429 with `Retry-After` and the
// rate-limited body before the handler, while a second address is served; HEAD counts with GET and every reading of
// the path counts on the same Rule. Login protection (10 failed responses per 300 s per address) lets the app answer
// 401 ten times and then refuses before the handler; a successful login is not a failure; another client of the same
// /24 still logs in. The wave of failed and throttled logins opens exactly one High "Credential stuffing" Incident
// with a signed alert — no "Failed sign-in burst", no "Blocked burst" — and blocking its Actor reaches Shield. The
// never-block list exempts an address from every limit; CORS preflights are neither counted nor refused. The signed
// bundle carries limit Rules in `limit_rules` only. Another Organization sees none of it.
//
// Clients: Shield is configured as behind a trusted reverse proxy (its public `clientAddress` option reads
// X-Forwarded-For) and the test plays that proxy for documentation addresses, as the slice 09 test does. Requests go
// out with `node:http` directly, not `fetch`: `fetch` resolves dot segments before sending, and the path variants
// must reach the server as written.
//
// Counters live in the Shield instance and survive a republish, and a counter belongs to one Rule and one client:
// every scenario therefore uses a client address of its own. The three /24s keep the Detector's per-prefix counts
// apart: only the login wave of 203.0.113.0/24 reaches the threshold of 50.
import { randomBytes } from "node:crypto";
import http, { type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  AllowlistEntryResponseSchema,
  BLOCK_RESPONSE_BODY,
  BundlePayloadSchema,
  ContainmentResponseSchema,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Incident,
  IncidentDetailResponseSchema,
  ListEventsResponseSchema,
  ListIncidentsResponseSchema,
  type Policy,
  PolicyResponseSchema,
  type PolicyRuleInput,
  RATE_LIMITED_RESPONSE_BODY,
  SignedBundleSchema,
  type StoredEvent,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { actorHash, verifyWebhookSignature } from "@antireverse/protocol/server";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
/** PB-14: a Detection is recorded within 10 s of the Event that completes it. */
const DETECTION_BUDGET_MS = 10_000;
/** PB-18: an alert arrives within 60 s; with the short test backoff it arrives in well under the test timeout. */
const ALERT_BUDGET_MS = 15_000;
/** How long to wait for an Incident or alert that must not come, once the Events behind it are stored. */
const QUIET_MS = 2_000;
const CONSOLE_URL = "http://127.0.0.1:39941";

/** The request limit: 5 requests per 60 s per address on GET /api/search. */
const SEARCH = { path: "/api/search", requests: 5, window_s: 60 };
/** Login protection, as the Console's preset fills it: 10 failed responses per 300 s per address on POST /login. */
const LOGIN = { path: "/login", requests: 10, window_s: 300 };
/** A limit on every method of one route: 2 requests per 60 s per address (the preflight scenario). */
const CART = { path: "/api/cart", requests: 2, window_s: 60 };
/** The managed rule "Credential stuffing": 50 failed or throttled requests from one network prefix in 5 minutes. */
const STUFFING = 50;

/** 198.51.100.0/24: the request-limit clients, one per scenario. */
const MONITORED = "198.51.100.10";
const LIMITED = "198.51.100.11";
const NEIGHBOUR = "198.51.100.12";
const HEAD_CLIENT = "198.51.100.13";
const VARIANT_CLIENT = "198.51.100.14";
const PREFLIGHT_CLIENT = "198.51.100.15";
const UNLISTED = "198.51.100.16";
/** 203.0.113.0/24: the credential-stuffing wave and a legitimate user of the same network. */
const ATTACKER = "203.0.113.7";
const BYSTANDER = "203.0.113.8";
const LOGIN_PREFIX = "203.0.113.0/24";
/** The rest of the wave: five more clients of the attacker's /24, ten wrong passwords each. */
const WAVE = ["203.0.113.21", "203.0.113.22", "203.0.113.23", "203.0.113.24", "203.0.113.25"];
/** The client of the parallel guesses (plan A7 F1), in a /24 that sends no other login. */
const PARALLEL = "198.51.100.30";
const PARALLEL_GUESSES = 1_000;
/** 192.0.2.0/24: the login client of the monitor phase, and the address put on the never-block list. */
const MONITORED_LOGIN = "192.0.2.20";
const OFFICE = "192.0.2.50";
const OFFICE_CIDR = `${OFFICE}/32`;

const PASSWORD = "correct horse battery staple";
/** The customer-held actor key Shield keys address hashes with (slice 09). */
const ACTOR_KEY = randomBytes(32).toString("base64url");
const hashOf = (client: string): string => actorHash(ACTOR_KEY, client) ?? "";

interface Received {
  signature: string;
  rawBody: string;
}

interface Answer {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

let api: RunningApi;
let shield: Shield;
let customer: http.Server;
let customerPort: number;
let receiver: http.Server;
let adminKey: string;
let shieldKey: string;
let appId: string;
let signingSecret: string;
let otherOrgAdminKey: string;
let otherOrgShieldKey: string;
/** The Policy as published in monitor (version 1) and as promoted (version 2). */
let monitored: Policy;
let enforced: Policy;
/** Rule ids by Rule name. */
const ruleIds: Record<string, string> = {};
let incident: Incident;
const received: Received[] = [];
/** Every handler call of the customer's app, as `METHOD route`. */
const handled: string[] = [];

const calls = (entry: string): number => handled.filter((one) => one === entry).length;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

function call(path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  // Slice 18a: every change carries a reason, as an operator gives one; sensitive changes refuse to go without.
  if (init.key && (init.method ?? "GET") !== "GET") headers["x-airverse-reason"] = "End-to-end test";
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
    await pause(50);
  }
}

/**
 * One request from `client` through the customer's server, with the path exactly as written (no client-side
 * normalisation) on a connection of its own.
 */
function send(
  client: string,
  method: string,
  path: string,
  init: { json?: unknown; headers?: Record<string, string> } = {},
): Promise<Answer> {
  const payload = init.json === undefined ? undefined : JSON.stringify(init.json);
  return new Promise<Answer>((resolve, reject) => {
    const request = http.request(
      {
        host: "127.0.0.1",
        port: customerPort,
        method,
        path,
        agent: false,
        headers: {
          "x-forwarded-for": client,
          ...(payload === undefined
            ? {}
            : { "content-type": "application/json", "content-length": String(Buffer.byteLength(payload)) }),
          ...init.headers,
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () =>
          resolve({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          }),
        );
        response.on("error", reject);
      },
    );
    request.on("error", reject);
    request.end(payload);
  });
}

const search = (client: string, path = SEARCH.path, method = "GET") => send(client, method, path);
const login = (client: string, password: string) =>
  send(client, "POST", LOGIN.path, { json: { user: "ada", password } });

/** A throttle response: 429, `Retry-After` in whole seconds from 1 up to `maxS`, JSON, and nothing of the app. */
function expectThrottled(answer: Answer, maxS: number, method = "GET"): void {
  expect(answer.status).toBe(429);
  expect(answer.headers["retry-after"]).toMatch(/^[1-9][0-9]*$/);
  const retryAfter = Number(answer.headers["retry-after"]);
  expect(retryAfter).toBeGreaterThanOrEqual(1);
  expect(retryAfter).toBeLessThanOrEqual(maxS);
  expect(answer.headers["content-type"]).toMatch(/^application\/json/);
  expect(answer.body).toBe(method === "HEAD" ? "" : RATE_LIMITED_RESPONSE_BODY);
  if (method !== "HEAD") expect(JSON.parse(answer.body)).toEqual({ error: "rate_limited" });
}

/** The Events of one client (by its keyed address hash) on one route, oldest first, once `enough` holds. */
function eventsOf(
  client: string,
  route: string,
  enough: (events: StoredEvent[]) => boolean,
  what: string,
): Promise<StoredEvent[]> {
  const hash = hashOf(client);
  return until(what, VISIBLE_BUDGET_MS, async () => {
    const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
    expect(response.status).toBe(200);
    const { events } = ListEventsResponseSchema.parse(await response.json());
    const mine = events
      .filter((event) => event.actor.ip_hash === hash && event.request.route === route)
      .sort((a, b) => (a.event_id < b.event_id ? -1 : 1));
    return enough(mine) ? mine : undefined;
  });
}

const isThrottle = (event: StoredEvent, mode: "monitor" | "enforce") =>
  event.decision.action === "throttle" && event.decision.mode === mode;

/** What an Event says was decided: `allow`, or the action with the mode of the Rule that decided. */
const decided = (event: StoredEvent): string =>
  event.decision.action === "allow" ? "allow" : `${event.decision.action}/${event.decision.mode}`;

async function listIncidents(key = adminKey, query = `?app_id=${appId}`): Promise<Incident[]> {
  const response = await call(`/v1/incidents${query}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents;
}

/** The incident.opened alerts received, as their Incidents. */
const openedAlerts = () =>
  received
    .map((r) => ({ ...r, payload: JSON.parse(r.rawBody) as { type: string; incident: Incident | null } }))
    .filter((r) => r.payload.type === "incident.opened");

function publish(body: {
  rules: PolicyRuleInput[];
  expected_version?: number;
  allow_broad?: boolean;
}): Promise<Response> {
  return call(`/v1/apps/${appId}/policies/development`, { method: "PUT", key: adminKey, body });
}

/** The bundle the API serves to a Shield key: the parsed payload and the JSON exactly as signed. */
async function bundleOf(key: string) {
  const response = await call("/v1/policy-bundle", { key });
  expect(response.status).toBe(200);
  const raw = JSON.parse(SignedBundleSchema.parse(await response.json()).bundle) as Record<string, unknown>;
  return { payload: BundlePayloadSchema.parse(raw), raw };
}

/** Applies the published Policy to the running Shield now, instead of waiting for its poller. */
async function applied(version: number): Promise<void> {
  await shield.refreshPolicy();
  expect(shield.stats()).toMatchObject({ policyVersion: version, lastPolicyError: null });
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
  const hookUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hooks/abuse-e2e`;

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

  const otherOrg = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
  );
  otherOrgAdminKey = otherOrg.admin_key.key;
  otherOrgShieldKey = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: otherOrgAdminKey, body: { name: "shop-web" } })).json(),
  ).shield_key.key;

  const channel = await call("/v1/alert-channels", {
    method: "POST",
    key: adminKey,
    body: { kind: "webhook", name: "Ops webhook", url: hookUrl },
  });
  expect(channel.status).toBe(201);
  signingSecret = CreateAlertChannelResponseSchema.parse(await channel.json()).signing_secret ?? "";
  expect(signingSecret).toMatch(/^whsec_/);

  // The customer's server: Shield first, then the body parser, then the routes.
  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    clientAddress: (req: unknown) => {
      const request = req as IncomingMessage;
      const forwarded = request.headers["x-forwarded-for"];
      return typeof forwarded === "string" && forwarded !== "" ? forwarded : request.socket?.remoteAddress;
    },
    actorKey: ACTOR_KEY,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  const app = express();
  app.disable("x-powered-by");
  app.use(shield.express());
  app.use(express.json());
  app.get("/health", (_req, res) => {
    handled.push("GET /health");
    res.json({ ok: true });
  });
  // Express answers HEAD with the GET route: the handler runs for both.
  app.get("/api/search", (req, res) => {
    handled.push(`${req.method} /api/search`);
    res.json({ results: [] });
  });
  app.options("/api/cart", (_req, res) => {
    handled.push("OPTIONS /api/cart");
    res.set({ "access-control-allow-origin": "https://shop.example", "access-control-allow-methods": "POST" });
    res.status(204).end();
  });
  app.post("/api/cart", (_req, res) => {
    handled.push("POST /api/cart");
    res.json({ items: 1 });
  });
  app.post("/login", (req, res) => {
    handled.push("POST /login");
    if ((req.body as { password?: unknown } | undefined)?.password === PASSWORD) res.json({ signed_in: true });
    else res.status(401).json({ error: "invalid_credentials" });
  });
  customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  customerPort = (customer.address() as AddressInfo).port;
});

afterAll(async () => {
  await shield?.close();
  for (const server of [customer, receiver]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 08 abuse rules over HTTP", () => {
  it("changes no response in monitor and records throttle/monitor on the requests over the limit", async () => {
    // Without `mode` a Rule is published in monitor; without `action` a Rule with a limit throttles.
    const response = await publish({
      expected_version: 0,
      rules: [
        { name: "Admin area", path: "/api/admin/**", mode: "enforce" },
        {
          name: "Search limit",
          path: SEARCH.path,
          methods: ["GET"],
          limit: { requests: SEARCH.requests, window_s: SEARCH.window_s, key: "ip" },
        },
        {
          name: "Login protection",
          path: LOGIN.path,
          methods: ["POST"],
          limit: { requests: LOGIN.requests, window_s: LOGIN.window_s, key: "ip", count: "failures" },
        },
        { name: "Cart limit", path: CART.path, limit: { requests: CART.requests, window_s: CART.window_s, key: "ip" } },
      ],
    });
    expect(response.status).toBe(201);
    monitored = PolicyResponseSchema.parse(await response.json()).policy;
    for (const rule of monitored.rules) ruleIds[rule.name] = rule.id;
    expect(monitored.rules.map((r) => [r.name, r.action, r.mode, r.limit])).toEqual([
      ["Admin area", "block", "enforce", undefined],
      ["Search limit", "throttle", "monitor", { requests: 5, window_s: 60, key: "ip", count: "requests" }],
      ["Login protection", "throttle", "monitor", { requests: 10, window_s: 300, key: "ip", count: "failures" }],
      ["Cart limit", "throttle", "monitor", { requests: 2, window_s: 60, key: "ip", count: "requests" }],
    ]);
    await applied(monitored.version);
    expect(shield.stats().policyRules).toBe(4);

    // 8 requests against a limit of 5: every one is the app's own answer.
    for (let i = 0; i < 8; i++) {
      const answer = await search(MONITORED);
      expect(answer.status, `request ${i + 1}`).toBe(200);
      expect(answer.headers["retry-after"]).toBeUndefined();
      expect(JSON.parse(answer.body)).toEqual({ results: [] });
    }
    expect(calls("GET /api/search")).toBe(8);

    // 12 failed logins against a limit of 10 failures: twelve times the app's 401.
    for (let i = 0; i < 12; i++) {
      const answer = await login(MONITORED_LOGIN, "wrong");
      expect(answer.status, `login ${i + 1}`).toBe(401);
      expect(JSON.parse(answer.body)).toEqual({ error: "invalid_credentials" });
      await pause(10); // a failure is counted when its response has closed
    }
    expect(calls("POST /login")).toBe(12);

    // The Events: requests 6 to 8 would have been throttled by the search limit, logins 11 and 12 by the protection.
    const searches = await eventsOf(MONITORED, "/api/search", (events) => events.length >= 8, "search Events");
    expect(searches).toHaveLength(8);
    for (const event of searches) expect(event.request).toMatchObject({ method: "GET", status: 200 });
    // (The mode of an allow Event is the Policy's, not a Rule's: only the action is compared for those.)
    expect(searches.map(decided)).toEqual([...Array(5).fill("allow"), ...Array(3).fill("throttle/monitor")]);
    for (const event of searches.filter((e) => isThrottle(e, "monitor"))) {
      expect(event.decision).toMatchObject({
        rule_id: ruleIds["Search limit"],
        policy_version: monitored.version,
        containment_id: null,
        patch_id: null,
      });
    }
    const logins = await eventsOf(MONITORED_LOGIN, "/login", (events) => events.length >= 12, "login Events");
    expect(logins).toHaveLength(12);
    for (const event of logins) expect(event.request).toMatchObject({ method: "POST", status: 401 });
    const marked = logins.filter((e) => isThrottle(e, "monitor"));
    expect(marked).toHaveLength(2);
    for (const event of marked) expect(event.decision.rule_id).toBe(ruleIds["Login protection"]);
    // The address itself never leaves the customer's server.
    expect(JSON.stringify([...searches, ...logins])).not.toContain(MONITORED);
  });

  it("promotes to enforce only on the version the edit was based on; a broad limit Rule needs allow_broad", async () => {
    const promoted: PolicyRuleInput[] = monitored.rules.map((rule) => ({ ...rule, mode: "enforce" as const }));

    // A promotion decided on an older version is refused.
    expect((await publish({ rules: promoted, expected_version: 0 })).status).toBe(409);
    // A limit Rule whose first segment is a wildcard is enforced only when acknowledged; every path, never.
    const broad = promoted.map((rule) => (rule.name === "Search limit" ? { ...rule, path: "/*/search" } : rule));
    expect((await publish({ rules: broad, expected_version: monitored.version })).status).toBe(400);
    const everything = promoted.map((rule) => (rule.name === "Search limit" ? { ...rule, path: "/**" } : rule));
    expect((await publish({ rules: everything, expected_version: monitored.version, allow_broad: true })).status).toBe(
      400,
    );
    const current = await call(`/v1/apps/${appId}/policies/development`, { key: adminKey });
    expect(PolicyResponseSchema.parse(await current.json()).policy.version).toBe(monitored.version);

    const response = await publish({ rules: promoted, expected_version: monitored.version });
    expect(response.status).toBe(201);
    enforced = PolicyResponseSchema.parse(await response.json()).policy;
    expect(enforced.version).toBe(monitored.version + 1);
    // The same Rules, by id, now in enforce with their limits unchanged.
    expect(enforced.rules.map((r) => [r.id, r.mode, r.limit])).toEqual(
      monitored.rules.map((r) => [r.id, "enforce", r.limit]),
    );
    await applied(enforced.version);
  });

  it("answers requests over an enforced limit with 429, Retry-After and the rate-limited body; another address passes", async () => {
    const before = calls("GET /api/search");
    for (let i = 0; i < SEARCH.requests; i++) expect((await search(LIMITED)).status, `request ${i + 1}`).toBe(200);
    for (let i = 0; i < 3; i++) expectThrottled(await search(LIMITED), 2 * SEARCH.window_s + 1);
    // Refused before the handler.
    expect(calls("GET /api/search")).toBe(before + SEARCH.requests);

    // A second client address has a counter of its own.
    const neighbour = await search(NEIGHBOUR);
    expect(neighbour.status).toBe(200);
    expect(JSON.parse(neighbour.body)).toEqual({ results: [] });
    // Still refused: asking again while refused earns nothing.
    expectThrottled(await search(LIMITED), 2 * SEARCH.window_s + 1);

    // Counters survive the republish (plan A6): the client that was over the limit in monitor is refused at once.
    expectThrottled(await search(MONITORED), 2 * SEARCH.window_s + 1);

    const events = await eventsOf(LIMITED, "/api/search", (all) => all.length >= 9, "throttled Events");
    expect(events.map((e) => `${decided(e)} ${e.request.status}`)).toEqual([
      ...Array(5).fill("allow 200"),
      ...Array(4).fill("throttle/enforce 429"),
    ]);
    for (const event of events.filter((e) => isThrottle(e, "enforce"))) {
      expect(event.decision).toMatchObject({ rule_id: ruleIds["Search limit"], policy_version: enforced.version });
      expect(event.actor).toMatchObject({ ip_prefix: "198.51.100.0/24", ip_hash: hashOf(LIMITED) });
    }
  });

  it("counts HEAD with GET", async () => {
    for (const method of ["GET", "HEAD", "GET", "HEAD", "GET"]) {
      expect((await search(HEAD_CLIENT, SEARCH.path, method)).status, method).toBe(200);
    }
    expectThrottled(await search(HEAD_CLIENT, SEARCH.path, "HEAD"), 2 * SEARCH.window_s + 1, "HEAD");
    expectThrottled(await search(HEAD_CLIENT), 2 * SEARCH.window_s + 1);
  });

  it("counts encoded, dot-segment, case and trailing-slash readings of the path on the same Rule", async () => {
    // Five spellings of the limited route; whatever the app makes of each (it serves some and knows not others),
    // none is refused and each one counts.
    const variants = ["/API/Search", "/api/search/?q=1", "/api/./search", "/api/x/../search", "/api/%73earch"];
    for (const path of variants) expect((await search(VARIANT_CLIENT, path)).status, path).not.toBe(429);
    // The sixth request is over the limit, as written and in any other spelling.
    expectThrottled(await search(VARIANT_CLIENT), 2 * SEARCH.window_s + 1);
    for (const path of ["/api/%2e/search", "/api/x/%2e%2e/search", "/Api/Search/"]) {
      expectThrottled(await search(VARIANT_CLIENT, path), 2 * SEARCH.window_s + 1);
    }
  });

  it("never counts a CORS preflight to a limited route, and refuses one only once the client is over the limit", async () => {
    const preflight = { origin: "https://shop.example", "access-control-request-method": "POST" };
    // Six preflights against a limit of 2 on every method of the route: each is the app's own 204.
    for (let i = 0; i < 6; i++) {
      const answer = await send(PREFLIGHT_CLIENT, "OPTIONS", CART.path, { headers: preflight });
      expect(answer.status, `preflight ${i + 1}`).toBe(204);
      expect(answer.headers["access-control-allow-origin"]).toBe("https://shop.example");
    }
    expect(calls("OPTIONS /api/cart")).toBe(6);
    // The limit is untouched: two requests pass, the third is refused.
    for (let i = 0; i < CART.requests; i++) {
      expect((await send(PREFLIGHT_CLIENT, "POST", CART.path, { json: { sku: "a" } })).status).toBe(200);
    }
    expectThrottled(await send(PREFLIGHT_CLIENT, "POST", CART.path, { json: { sku: "a" } }), 2 * CART.window_s + 1);
    expect(calls("POST /api/cart")).toBe(CART.requests);
    // Over the limit, a preflight is refused too (plan A7 F6), before the handler; still not counted.
    expectThrottled(
      await send(PREFLIGHT_CLIENT, "OPTIONS", CART.path, { headers: preflight }),
      2 * CART.window_s + 1,
      "OPTIONS",
    );
    expect(calls("OPTIONS /api/cart")).toBe(6);
  });

  it("lets the app answer ten failed logins, then refuses before the handler; a success is not a failure", async () => {
    const before = calls("POST /login");
    for (let i = 0; i < 5; i++) expect((await login(ATTACKER, `guess-${i}`)).status).toBe(401);
    // A successful login before the limit: served, and not counted.
    const success = await login(ATTACKER, PASSWORD);
    expect(success.status).toBe(200);
    expect(JSON.parse(success.body)).toEqual({ signed_in: true });
    // Five more failures: the app's 401 ten times in all. Had the success counted, the last would be a 429.
    for (let i = 5; i < LOGIN.requests; i++) {
      const answer = await login(ATTACKER, `guess-${i}`);
      expect(answer.status, `failure ${i + 1}`).toBe(401);
      expect(JSON.parse(answer.body)).toEqual({ error: "invalid_credentials" });
    }
    expect(calls("POST /login")).toBe(before + 11);
    await pause(50); // the tenth failure is counted when its response has closed

    // Over the limit: refused before the handler, the right password included.
    expectThrottled(await login(ATTACKER, "guess-10"), 2 * LOGIN.window_s + 1);
    expectThrottled(await login(ATTACKER, PASSWORD), 2 * LOGIN.window_s + 1);
    expect(calls("POST /login")).toBe(before + 11);

    // Another client of the same /24 still logs in, and gets the app's own answer for a wrong password.
    const bystander = await login(BYSTANDER, PASSWORD);
    expect(bystander.status).toBe(200);
    expect(JSON.parse(bystander.body)).toEqual({ signed_in: true });
    expect((await login(BYSTANDER, "typo")).status).toBe(401);
    expect(calls("POST /login")).toBe(before + 13);
  });

  it("does not take one throttled client retrying for a wave", async () => {
    // So far from the network: the attacker's 10 failures and 2 throttles, the bystander's 1 failure. The attacker
    // keeps trying: 40 more attempts, every one refused. Shield's own 429s count once per client per window
    // (plan A7, D-064), so this is 12 counted Events, far below 50: no Incident.
    for (let i = 0; i < 40; i++) expect((await login(ATTACKER, `retry-${i}`)).status).toBe(429);
    const retries = await eventsOf(ATTACKER, "/login", (all) => all.length >= 53, "attacker Events");
    // Every login Event names the login-protection Rule that matched it, throttled or not.
    for (const event of retries) expect(event.decision.limit_rule_id).toBe(ruleIds["Login protection"]);
    await pause(QUIET_MS);
    expect(await listIncidents()).toEqual([]);
    expect(openedAlerts()).toEqual([]);
  });

  it("opens one High Credential stuffing Incident for a wave from one network, with a signed alert and no other Incident", async () => {
    // Five more clients of the same /24, ten wrong passwords each, then one throttled attempt each: 55 more
    // counted Events, 67 in all.
    for (const client of WAVE) {
      for (let i = 0; i < LOGIN.requests; i++) {
        expect((await login(client, `wave-${i}`)).status, `${client} failure ${i + 1}`).toBe(401);
      }
      await pause(20); // the tenth failure is counted when its response has closed
      expectThrottled(await login(client, "wave-10"), 2 * LOGIN.window_s + 1);
    }

    incident = await until("Incident opened", DETECTION_BUDGET_MS, async () => (await listIncidents())[0]);
    expect(incident).toMatchObject({
      app_id: appId,
      environment: "development",
      rule: "credential-stuffing",
      severity: "high",
      title: "Credential stuffing",
      status: "open",
      ip_prefix: LOGIN_PREFIX,
      detection_count: 1,
    });

    const alert = await until("alert received", ALERT_BUDGET_MS, async () => openedAlerts()[0]);
    const nowS = Math.floor(Date.now() / 1000);
    expect(alert.signature).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, nowS)).toBe(true);
    expect(verifyWebhookSignature(signingSecret, alert.signature, `${alert.rawBody} `, nowS)).toBe(false);
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert.rawBody));
    expect(payload.type).toBe("incident.opened");
    expect(payload.incident).toMatchObject({ id: incident.id, rule: "credential-stuffing", severity: "high" });
    expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${incident.id}`);
    for (const leak of [ATTACKER, BYSTANDER, ...WAVE, PASSWORD, adminKey, shieldKey, signingSecret]) {
      expect(alert.rawBody).not.toContain(leak);
    }

    // The evidence: failed and throttled logins of the network on the protected route, and nothing else.
    const response = await call(`/v1/incidents/${incident.id}`, { key: adminKey });
    expect(response.status).toBe(200);
    const { detections, evidence, actors } = IncidentDetailResponseSchema.parse(await response.json());
    expect(detections).toHaveLength(1);
    expect(detections[0]).toMatchObject({ rule: "credential-stuffing", ip_prefix: LOGIN_PREFIX });
    expect(detections[0]?.count).toBeGreaterThanOrEqual(STUFFING);
    expect(evidence.length).toBeGreaterThan(0);
    for (const event of evidence) {
      expect(event.request).toMatchObject({ method: "POST", route: "/login" });
      expect([401, 429]).toContain(event.request.status);
      expect(event.actor.ip_prefix).toBe(LOGIN_PREFIX);
      expect(event.decision.limit_rule_id).toBe(ruleIds["Login protection"]);
    }
    expect(evidence.some((e) => isThrottle(e, "enforce") && e.decision.rule_id === ruleIds["Login protection"])).toBe(
      true,
    );
    // The clients whose attempts reached the threshold are Actors of the Incident (the evidence window ends with
    // the 50th counted Event: the last client's attempts may come after it).
    const hashes = actors.map((actor) => actor.ip_hash);
    for (const client of [ATTACKER, ...WAVE.slice(0, 3)]) expect(hashes, client).toContain(hashOf(client));

    // One wave, one Incident: no "Failed sign-in burst" (the 61 failures are on a login-protection Rule), no
    // "Blocked burst" (a throttle is not a block), and the request-limit scenarios and the monitor phase of the
    // other networks stay below every threshold.
    await pause(QUIET_MS);
    const all = await listIncidents();
    expect(all.map((i) => [i.id, i.rule])).toEqual([[incident.id, "credential-stuffing"]]);
    expect(all.filter((i) => i.rule === "failed-signin-burst" || i.rule === "blocked-burst")).toEqual([]);
    expect(openedAlerts().map((a) => a.payload.incident?.rule)).toEqual(["credential-stuffing"]);
  }, 60_000);

  it("lets at most 10 of 1,000 parallel wrong passwords from one address reach the handler", async () => {
    const before = calls("POST /login");
    // All 1,000 are sent at once over 100 kept-alive connections, so 100 guesses are in flight together: more
    // connections at once overflow the listen backlog on macOS (kern.ipc.somaxconn 128) and are reset.
    const agent = new http.Agent({ keepAlive: true, maxSockets: 100 });
    const answers = await Promise.all(
      Array.from(
        { length: PARALLEL_GUESSES },
        (_, i) =>
          new Promise<number>((resolve, reject) => {
            const payload = JSON.stringify({ user: "ada", password: `parallel-${i}` });
            const request = http.request(
              {
                host: "127.0.0.1",
                port: customerPort,
                method: "POST",
                path: LOGIN.path,
                agent,
                headers: {
                  "x-forwarded-for": PARALLEL,
                  "content-type": "application/json",
                  "content-length": String(Buffer.byteLength(payload)),
                },
              },
              (response) => {
                response.resume();
                response.on("end", () => resolve(response.statusCode ?? 0));
                response.on("error", reject);
              },
            );
            request.on("error", reject);
            request.end(payload);
          }),
      ),
    );
    agent.destroy();
    const reached = calls("POST /login") - before;
    const failed = answers.filter((status) => status === 401).length;
    const refused = answers.filter((status) => status === 429).length;
    expect(reached).toBeLessThanOrEqual(LOGIN.requests);
    expect(reached).toBeGreaterThanOrEqual(1);
    expect(failed).toBe(reached);
    expect(failed + refused).toBe(PARALLEL_GUESSES);
    console.info(
      `abuse e2e: ${PARALLEL_GUESSES} parallel guesses -> ${reached} reached the handler, ${refused} got 429`,
    );
  }, 60_000);

  it("contains the Actor of the Incident: Shield blocks the attacker everywhere, the bystander passes", async () => {
    expect((await send(ATTACKER, "GET", "/health")).status).toBe(200);
    const response = await call(`/v1/incidents/${incident.id}/containments`, {
      method: "POST",
      key: adminKey,
      body: { target: { kind: "actor", ip_hash: hashOf(ATTACKER) }, ttl_s: 3600 },
    });
    expect(response.status).toBe(201);
    const { containment } = ContainmentResponseSchema.parse(await response.json());
    expect(containment).toMatchObject({
      incident_id: incident.id,
      target: { kind: "actor", ip_hash: hashOf(ATTACKER) },
      status: "active",
    });
    expect((await bundleOf(shieldKey)).payload.blocks?.map((block) => block.id)).toEqual([containment.id]);
    await applied(enforced.version);

    // A Containment comes before every limit: the block response, on an unruled page and on the login route.
    const before = calls("POST /login");
    const home = await send(ATTACKER, "GET", "/health");
    expect([home.status, home.body]).toEqual([403, BLOCK_RESPONSE_BODY]);
    const signIn = await login(ATTACKER, PASSWORD);
    expect([signIn.status, signIn.body]).toEqual([403, BLOCK_RESPONSE_BODY]);
    expect(signIn.headers["retry-after"]).toBeUndefined();
    expect(calls("POST /login")).toBe(before);
    expect((await send(BYSTANDER, "GET", "/health")).status).toBe(200);
    expect((await login(BYSTANDER, PASSWORD)).status).toBe(200);

    // The contained requests open nothing new.
    await pause(QUIET_MS);
    expect((await listIncidents()).map((i) => i.id)).toEqual([incident.id]);
  });

  it("never throttles an address on the never-block list", async () => {
    const added = await call("/v1/allowlist", {
      method: "POST",
      key: adminKey,
      body: { cidr: OFFICE_CIDR, note: "Office gateway" },
    });
    expect(added.status).toBe(201);
    expect(AllowlistEntryResponseSchema.parse(await added.json()).entry.cidr).toBe(OFFICE_CIDR);
    expect((await bundleOf(shieldKey)).payload.allowlist).toEqual([OFFICE_CIDR]);
    await applied(enforced.version);

    // Far over the request limit and over the failure limit: always the app's own answer.
    for (let i = 0; i < 12; i++) expect((await search(OFFICE)).status, `search ${i + 1}`).toBe(200);
    for (let i = 0; i < 14; i++) {
      expect((await login(OFFICE, "forgotten")).status, `login ${i + 1}`).toBe(401);
      await pause(10);
    }
    expect((await login(OFFICE, PASSWORD)).status).toBe(200);
    const events = await eventsOf(OFFICE, "/api/search", (all) => all.length >= 12, "office Events");
    expect(events.filter((e) => e.decision.action === "throttle")).toEqual([]);

    // The list exempts that address only: one that is not on it meets the limit as before.
    for (let i = 0; i < SEARCH.requests; i++) expect((await search(UNLISTED)).status).toBe(200);
    expectThrottled(await search(UNLISTED), 2 * SEARCH.window_s + 1);
  });

  it("ships limit Rules in limit_rules only: an older Shield, which reads rules, finds no throttle entry", async () => {
    const { payload, raw } = await bundleOf(shieldKey);
    expect(payload.version).toBe(enforced.version);
    // `rules` as signed: the one block Rule, with nothing of a limit in it.
    expect(raw.rules).toEqual([
      { id: ruleIds["Admin area"], path: "/api/admin/**", methods: [], action: "block", mode: "enforce" },
    ]);
    expect(JSON.stringify(raw.rules)).not.toMatch(/throttle|limit/);
    expect(JSON.stringify(raw.signature_rules ?? [])).not.toMatch(/throttle|limit/);
    // The limit Rules, in Policy order, complete (`count` written) and without their names.
    expect(raw.limit_rules).toEqual([
      {
        id: ruleIds["Search limit"],
        path: SEARCH.path,
        methods: ["GET"],
        action: "throttle",
        mode: "enforce",
        limit: { requests: 5, window_s: 60, key: "ip", count: "requests" },
      },
      {
        id: ruleIds["Login protection"],
        path: LOGIN.path,
        methods: ["POST"],
        action: "throttle",
        mode: "enforce",
        limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
      },
      {
        id: ruleIds["Cart limit"],
        path: CART.path,
        methods: [],
        action: "throttle",
        mode: "enforce",
        limit: { requests: 2, window_s: 60, key: "ip", count: "requests" },
      },
    ]);
    // What a Shield from before slice 08 is left with once it drops the member it does not know: no Rule that
    // could refuse a search, a cart or a login request.
    const { limit_rules: _unknown, ...older } = raw;
    const olderRules = BundlePayloadSchema.parse(older).rules;
    expect(olderRules.map((rule) => rule.path)).toEqual(["/api/admin/**"]);
  });

  it("keeps the Policy, the Incident and the limits away from another Organization", async () => {
    const policyPath = `/v1/apps/${appId}/policies/development`;
    expect((await call(policyPath, { key: otherOrgAdminKey })).status).toBe(404);
    expect((await call(`${policyPath}/versions`, { key: otherOrgAdminKey })).status).toBe(404);
    expect((await call(policyPath, { method: "PUT", key: otherOrgAdminKey, body: { rules: [] } })).status).toBe(404);
    expect((await call(`/v1/apps/${appId}/events`, { key: otherOrgAdminKey })).status).toBe(404);

    expect(await listIncidents(otherOrgAdminKey, "")).toEqual([]);
    expect(await listIncidents(otherOrgAdminKey, `?app_id=${appId}`)).toEqual([]);
    expect((await call(`/v1/incidents/${incident.id}`, { key: otherOrgAdminKey })).status).toBe(404);
    const contain = await call(`/v1/incidents/${incident.id}/containments`, {
      method: "POST",
      key: otherOrgAdminKey,
      body: { target: { kind: "actor", ip_hash: hashOf(ATTACKER) }, ttl_s: 3600 },
    });
    expect(contain.status).toBe(404);

    // The other Organization's bundle carries none of the Rules, the block or the never-block range.
    const foreign = await bundleOf(otherOrgShieldKey);
    expect(foreign.raw.limit_rules).toBeUndefined();
    expect(foreign.payload.rules).toEqual([]);
    expect(foreign.payload.blocks ?? []).toEqual([]);
    expect(foreign.payload.allowlist ?? []).toEqual([]);

    // Nothing changed for the owner.
    const mine = await call(policyPath, { key: adminKey });
    expect(PolicyResponseSchema.parse(await mine.json()).policy).toEqual(enforced);
    expect((await listIncidents()).map((i) => [i.id, i.status])).toEqual([[incident.id, "open"]]);
  });
});
