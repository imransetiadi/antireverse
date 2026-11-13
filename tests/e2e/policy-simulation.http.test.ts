// Slice 11 over HTTP: policy simulation. A real Express app with Shield and the real API. With no Rule published,
// known traffic goes through Shield and every request is the app's own answer: 30 admin reads from three clients,
// 20 unsigned orders from two, 40 searches from one client and 5 from another, 12 failed logins from one, six
// reads of a parameterised route and four requests to a mounted handler (recorded as `(unmatched)`). A draft of
// four Rules — a block Rule, a signature requirement, a request limit and Login protection — is then simulated and
// the result is compared figure by figure; a literal Rule against the parameterised route and any Rule against
// the `(unmatched)` Events are counted as "could not be judged", never as refused. Every monitor Rule's row also says what
// promoting that Rule alone would refuse (`if_promoted`, plan A5 F5): with a broad monitor Rule before it, a nested
// Rule refuses nothing when every Rule is enforced but every admin read once it alone is promoted — and a real
// Shield with that Rule promoted refuses exactly that. Nothing is stored or published
// by a simulation. The same Rules are then published in enforce, the same traffic is sent again, and the requests
// Shield really refuses are compared with the estimate. Last: validation as on publish, tenancy, the key kind and
// the rate limit.
//
// Clients: as in the slice 08 test, Shield reads X-Forwarded-For and the test plays the trusted proxy for
// documentation addresses; requests go out with `node:http`. Every traffic group has addresses of its own.
//
// Timing: the limits are replayed on the recorded times, and Shield counts on its own clock. Both rounds of
// traffic are sent one request after the other and take well under the shortest window (60 s), so every request of
// a round is inside one window in the replay and in Shield alike: the estimate and the real refusals are equal, not
// only close. (A round that took longer than a window would let early requests leave it, in both alike.)
//
// The rate limit is 6 simulations a minute per Organization and API process: the Organization of the traffic runs
// five in this file; the seventh in a minute is shown with an Organization of its own.
import { randomBytes } from "node:crypto";
import http, { type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BLOCK_RESPONSE_BODY,
  BundlePayloadSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListEventsResponseSchema,
  type Policy,
  PolicyResponseSchema,
  type PolicyRuleInput,
  RATE_LIMITED_RESPONSE_BODY,
  SIMULATION_LIMITS,
  SIMULATION_NOT_SIMULATED,
  SignedBundleSchema,
  SimulatePolicyResponseSchema,
  type SimulationResult,
  type StoredEvent,
} from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
const DAY_MS = 24 * 3_600_000;

/** The request limit of the draft: 10 requests per 60 s per address on GET /api/search. */
const SEARCH = { path: "/api/search", requests: 10, window_s: 60 };
/** The gap between two failed logins, so that the replay can judge every one (see `sendRound`). */
const LOGIN_GAP_MS = 25;
/** Login protection of the draft: 10 failed responses per 300 s per address on POST /login. */
const LOGIN = { path: "/login", requests: 10, window_s: 300 };

/** 198.51.100.0/24: admin readers (10 requests each), order clients (10 each), searchers (40 and 5). */
const ADMINS = ["198.51.100.21", "198.51.100.22", "198.51.100.23"];
const BUYERS = ["198.51.100.31", "198.51.100.32"];
const HEAVY_SEARCHER = "198.51.100.41";
const LIGHT_SEARCHER = "198.51.100.42";
/** 203.0.113.0/24: the client of the failed logins. */
const GUESSER = "203.0.113.50";
/** 192.0.2.0/24: the reader of the parameterised route and the client of the mounted handler. */
const BROWSER = "192.0.2.61";
const ASSET_CLIENT = "192.0.2.62";
const ALL_CLIENTS = [...ADMINS, ...BUYERS, HEAVY_SEARCHER, LIGHT_SEARCHER, GUESSER, BROWSER, ASSET_CLIENT];

const PRODUCT_IDS = ["41", "42", "43", "44", "45", "46"];
const ASSETS = ["/assets/app.js", "/assets/app.css", "/assets/img/logo.svg", "/assets/app.js"];
/** Requests of one round: 30 + 20 + 45 + 12 + 6 + 4. */
const ROUND = 117;
const UNMATCHED = "(unmatched)";

/** The draft: the Rules in Policy order. Without `mode` a Rule is monitor; a simulation ignores the mode. */
const DRAFT: PolicyRuleInput[] = [
  { name: "Admin area", path: "/api/admin/**" },
  { name: "Signed orders", path: "/api/orders", methods: ["POST"], requires: "signature" },
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
];

/** Two nested block Rules, both in monitor (plan A5, F5): the broad one comes first. */
const NESTED: PolicyRuleInput[] = [
  { name: "API", path: "/api/**", mode: "monitor" },
  { name: "Admin only", path: "/api/admin/**", mode: "monitor" },
];

/** The customer-held actor key Shield keys address hashes with (slice 09). */
const ACTOR_KEY = randomBytes(32).toString("base64url");
const hashOf = (client: string): string => actorHash(ACTOR_KEY, client) ?? "";

interface Answer {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: string;
}

/** What one round of the traffic was answered with, per group, in the order sent. */
interface Round {
  admin: Answer[];
  orders: Answer[];
  heavy: Answer[];
  light: Answer[];
  logins: Answer[];
  products: Answer[];
  assets: Answer[];
}

let api: RunningApi;
let shield: Shield;
let customer: http.Server;
let customerPort: number;
let adminKey: string;
let shieldKey: string;
let appId: string;
let otherOrgAdminKey: string;
/** The Policy and Shield's view of it before the first simulation. */
let untouched: Policy;
let untouchedStats: { policyVersion: unknown; policyRules: unknown };
/** The Events of the first round (no Rule published), and the estimate the draft got from them. */
let recorded: StoredEvent[];
let estimate: SimulationResult;
/** The F5 estimate: two nested monitor Rules simulated against the first round. */
let nested: SimulationResult;
/** Every handler call of the customer's app, as `METHOD route`. */
const handled: string[] = [];

const calls = (entry: string): number => handled.filter((one) => one === entry).length;
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const statuses = (answers: Answer[]): number[] => answers.map((answer) => answer.status);

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

/** One request from `client` through the customer's server, on a connection of its own. */
function send(client: string, method: string, path: string, json?: unknown): Promise<Answer> {
  const payload = json === undefined ? undefined : JSON.stringify(json);
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

/**
 * One round of the known traffic, one request after the other: the same requests, clients and order every time.
 */
async function sendRound(): Promise<Round> {
  const round: Round = { admin: [], orders: [], heavy: [], light: [], logins: [], products: [], assets: [] };
  for (let i = 0; i < 30; i++) round.admin.push(await send(ADMINS[i % 3] as string, "GET", "/api/admin/users"));
  for (let i = 0; i < 20; i++) {
    round.orders.push(await send(BUYERS[i % 2] as string, "POST", "/api/orders", { sku: "rope", quantity: 1 }));
  }
  for (let i = 0; i < 40; i++) round.heavy.push(await send(HEAVY_SEARCHER, "GET", `${SEARCH.path}?q=${i}`));
  for (let i = 0; i < 5; i++) round.light.push(await send(LIGHT_SEARCHER, "GET", `${SEARCH.path}?q=${i}`));
  for (let i = 0; i < 12; i++) {
    round.logins.push(await send(GUESSER, "POST", LOGIN.path, { user: "ada", password: `guess-${i}` }));
    // About 25 ms apart, in both rounds (plan 11 A9). Shield counts a failure when the response has closed; the
    // replay cannot tell whether Shield had counted it before reading a request that arrives within 10 ms of the
    // previous response, so such a request is could not be judged — and back-to-back logins would make the
    // Login protection figure depend on load (2 throttles or none). 25 ms keeps every login past that margin.
    await pause(LOGIN_GAP_MS);
  }
  for (const id of PRODUCT_IDS) round.products.push(await send(BROWSER, "GET", `/api/products/${id}`));
  for (const path of ASSETS) round.assets.push(await send(ASSET_CLIENT, "GET", path));
  return round;
}

/** The newest Events of the App (at most 200, the most a read gives). */
async function listEvents(): Promise<StoredEvent[]> {
  const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListEventsResponseSchema.parse(await response.json()).events;
}

function simulate(rules: unknown, key: string | null = adminKey, app = appId): Promise<Response> {
  return call(`/v1/apps/${app}/policy/simulate`, {
    method: "POST",
    ...(key === null ? {} : { key }),
    body: { environment: "development", rules },
  });
}

async function simulated(rules: PolicyRuleInput[]): Promise<SimulationResult> {
  const response = await simulate(rules);
  expect(response.status).toBe(200);
  return SimulatePolicyResponseSchema.parse(await response.json()).simulation;
}

function publish(body: unknown, key = adminKey): Promise<Response> {
  return call(`/v1/apps/${appId}/policies/development`, { method: "PUT", key, body });
}

async function currentPolicy(): Promise<Policy> {
  const response = await call(`/v1/apps/${appId}/policies/development`, { key: adminKey });
  expect(response.status).toBe(200);
  return PolicyResponseSchema.parse(await response.json()).policy;
}

/** The bundle the API serves to the Shield key, as signed. */
async function bundle(): Promise<Record<string, unknown>> {
  const response = await call("/v1/policy-bundle", { key: shieldKey });
  expect(response.status).toBe(200);
  const raw = JSON.parse(SignedBundleSchema.parse(await response.json()).bundle) as Record<string, unknown>;
  BundlePayloadSchema.parse(raw);
  return raw;
}

/** A Rule's row of a result with nothing matched, refused or left unjudged, to spread over. */
const row = (index: number, name: string) => ({
  index,
  name,
  matched: 0,
  would_block: 0,
  would_fail_signature: 0,
  would_throttle: 0,
  already_refused: 0,
  undecidable: 0,
  clients_affected: 0,
  unknown_client_events: 0,
  sample_routes: [],
});

/** `if_promoted` of a monitor Rule's row: what the enforced Rules plus this one would refuse (plan A5, F5). */
const promoted = (would_refuse: number, clients_affected: number, undecidable = 0) => ({
  would_refuse,
  clients_affected,
  unknown_client_events: 0,
  undecidable,
});

async function organizationWithApp(name: string): Promise<{ adminKey: string; appId: string; shieldKey: string }> {
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name } })).json(),
  );
  const created = CreateAppResponseSchema.parse(
    await (
      await call("/v1/apps", { method: "POST", key: organization.admin_key.key, body: { name: "shop-web" } })
    ).json(),
  );
  return { adminKey: organization.admin_key.key, appId: created.app.id, shieldKey: created.shield_key.key };
}

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });
  ({ adminKey, appId, shieldKey } = await organizationWithApp("Acme"));
  otherOrgAdminKey = (await organizationWithApp("Other")).adminKey;

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
  app.get("/api/admin/users", (_req, res) => {
    handled.push("GET /api/admin/users");
    res.json({ users: [] });
  });
  app.post("/api/orders", (_req, res) => {
    handled.push("POST /api/orders");
    res.json({ ordered: true });
  });
  app.get("/api/search", (_req, res) => {
    handled.push("GET /api/search");
    res.json({ results: [] });
  });
  // Every password is wrong: the app's own 401.
  app.post("/login", (_req, res) => {
    handled.push("POST /login");
    res.status(401).json({ error: "invalid_credentials" });
  });
  app.get("/api/products/:id", (req, res) => {
    handled.push("GET /api/products/:id");
    res.json({ id: req.params.id });
  });
  // A mounted handler is no route: Shield records its requests without a route template.
  app.use("/assets", (_req, res) => {
    handled.push("USE /assets");
    res.type("text/plain").send("asset");
  });
  customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  customerPort = (customer.address() as AddressInfo).port;

  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  untouchedStats = { policyVersion: shield.stats().policyVersion, policyRules: shield.stats().policyRules };
  untouched = await currentPolicy();
});

afterAll(async () => {
  await shield?.close();
  if (customer) {
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 11 policy simulation over HTTP", () => {
  it("records the known traffic through Shield with no Rule published: every request is the app's own answer", async () => {
    expect(untouched).toMatchObject({ version: 0, rules: [] });
    expect(untouchedStats.policyRules).toBe(0);

    const round = await sendRound();
    expect(statuses(round.admin)).toEqual(Array(30).fill(200));
    expect(statuses(round.orders)).toEqual(Array(20).fill(200));
    expect(statuses(round.heavy)).toEqual(Array(40).fill(200));
    expect(statuses(round.light)).toEqual(Array(5).fill(200));
    expect(statuses(round.logins)).toEqual(Array(12).fill(401));
    expect(statuses(round.products)).toEqual(Array(6).fill(200));
    expect(statuses(round.assets)).toEqual(Array(4).fill(200));
    expect(handled).toHaveLength(ROUND);

    recorded = await until("Events of the first round", VISIBLE_BUDGET_MS, async () => {
      const events = await listEvents();
      return events.length >= ROUND ? events : undefined;
    });
    expect(recorded).toHaveLength(ROUND);
    for (const event of recorded) {
      expect(event.type).toBe("request.decision");
      expect(event.environment).toBe("development");
      expect(event.decision.action).toBe("allow");
      // Unsigned, and recorded as such: what a signature Rule is judged on.
      expect(event.signature).toEqual({ status: "missing", body: null });
    }
    // What was recorded, as `METHOD route status` per client: route templates, never the paths.
    const seen = (client: string) =>
      recorded
        .filter((event) => event.actor.ip_hash === hashOf(client))
        .map((event) => `${event.request.method} ${event.request.route} ${event.request.status}`);
    for (const client of ADMINS) expect(seen(client)).toEqual(Array(10).fill("GET /api/admin/users 200"));
    for (const client of BUYERS) expect(seen(client)).toEqual(Array(10).fill("POST /api/orders 200"));
    expect(seen(HEAVY_SEARCHER)).toEqual(Array(40).fill("GET /api/search 200"));
    expect(seen(LIGHT_SEARCHER)).toEqual(Array(5).fill("GET /api/search 200"));
    expect(seen(GUESSER)).toEqual(Array(12).fill("POST /login 401"));
    expect(seen(BROWSER)).toEqual(Array(6).fill("GET /api/products/:id 200"));
    expect(seen(ASSET_CLIENT)).toEqual(Array(4).fill(`GET ${UNMATCHED} 200`));
  });

  it("estimates per Rule what the draft would have done: exact figures, totals, period and one row per Rule in order", async () => {
    const before = Date.now();
    const response = await simulate(DRAFT);
    const after = Date.now();
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    const text = await response.text();
    const body = JSON.parse(text) as Record<string, unknown>;
    expect(Object.keys(body)).toEqual(["simulation"]);
    estimate = SimulatePolicyResponseSchema.parse(body).simulation;

    expect(estimate.rules).toEqual([
      {
        // Every admin read, whoever sent it. The four `(unmatched)` requests may have been below /api/admin: not judged.
        ...row(0, "Admin area"),
        matched: 30,
        would_block: 30,
        undecidable: 4,
        clients_affected: 3,
        sample_routes: [{ route: "/api/admin/users", method: "GET", count: 30 }],
        // Every draft Rule is in monitor: each row says what promoting that Rule alone would refuse. Here no Rule
        // takes another's requests, so it is the same as the all-enforced figure.
        if_promoted: promoted(30, 3, 4),
      },
      {
        // Every order came with a JSON body and without a signature: still refused. (Plan A6: only a SIGNED request
        // with a body is could not be judged, since the API cannot see whether Shield checks bodies on the route —
        // none of these orders is signed, so the figures are unchanged by that fix.) The `(unmatched)` requests
        // were GET: the Rule's method rules them out.
        ...row(1, "Signed orders"),
        matched: 20,
        would_fail_signature: 20,
        clients_affected: 2,
        sample_routes: [{ route: "/api/orders", method: "POST", count: 20 }],
        if_promoted: promoted(20, 2),
      },
      {
        // 45 searches matched; the client of 40 is over 10 per 60 s from its 11th on, the client of 5 never is.
        ...row(2, "Search limit"),
        matched: 45,
        would_throttle: 30,
        undecidable: 4,
        clients_affected: 1,
        sample_routes: [{ route: "/api/search", method: "GET", count: 30 }],
        if_promoted: promoted(30, 1, 4),
      },
      {
        // Ten failed logins are let through to the app; the 11th and 12th are over the limit.
        ...row(3, "Login protection"),
        matched: 12,
        would_throttle: 2,
        clients_affected: 1,
        sample_routes: [{ route: "/login", method: "POST", count: 2 }],
        if_promoted: promoted(2, 1),
      },
    ]);
    // A draft Rule that was never published has no id.
    for (const rule of estimate.rules) expect(rule).not.toHaveProperty("id");
    // The Shield has an actor key: every refused request names its client.
    expect(estimate.totals).toEqual({ would_refuse: 82, clients_affected: 7, unknown_client_events: 0 });
    expect(estimate.events).toBe(ROUND);
    expect(estimate.truncated).toBe(false);
    expect(estimate.not_simulated).toEqual([...SIMULATION_NOT_SIMULATED]);
    // The four `(unmatched)` requests: not judged for two Rules, refused by none.
    expect(estimate.undecidable_events).toBe(4);

    // The period: the 24 hours up to the moment of the simulation.
    const from = Date.parse(estimate.period.from);
    const to = Date.parse(estimate.period.to);
    expect(to - from).toBe(SIMULATION_LIMITS.windowHours * 3_600_000);
    expect(to - from).toBe(DAY_MS);
    expect(to).toBeGreaterThanOrEqual(before);
    expect(to).toBeLessThanOrEqual(after);
    // When it ran: the end of the period (no Event is stamped later than the simulation).
    expect(estimate.ran_at).toBe(estimate.period.to);

    // Counts only: no address, no address hash, no concrete path.
    for (const client of ALL_CLIENTS) {
      expect(text).not.toContain(client);
      expect(text).not.toContain(hashOf(client));
    }
    for (const path of ["/api/products/42", "/assets/", "?q="]) expect(text).not.toContain(path);
  });

  it("counts what it cannot judge as could not be judged, never as matched or refused", async () => {
    const simulation = await simulated([
      // A literal against the template /api/products/:id: the id of each request is not recorded.
      { name: "One product", path: "/api/products/42", mode: "enforce" },
      // The path of a `(unmatched)` request is not recorded: a block Rule, a limit and a requirement alike.
      { name: "Assets", path: "/assets/**", mode: "enforce" },
      { name: "Asset limit", path: "/assets/**", limit: { requests: 1, window_s: 60, key: "ip" } },
      { name: "Signed assets", path: "/assets/**", methods: ["GET"], requires: "signature" },
      // A Rule the recorded templates decide: no request of them can be below /internal.
      { name: "Internal", path: "/internal/**", mode: "enforce" },
    ]);
    expect(simulation.rules).toEqual([
      // The six product reads (one of them was /api/products/42) and the four `(unmatched)` requests.
      { ...row(0, "One product"), undecidable: 10 },
      { ...row(1, "Assets"), undecidable: 4 },
      // The two monitor Rules: promoted alone they refuse nothing either, and judge the same 4 not.
      { ...row(2, "Asset limit"), undecidable: 4, if_promoted: promoted(0, 0, 4) },
      { ...row(3, "Signed assets"), undecidable: 4, if_promoted: promoted(0, 0, 4) },
      { ...row(4, "Internal"), undecidable: 4 },
    ]);
    expect(simulation.totals).toEqual({ would_refuse: 0, clients_affected: 0, unknown_client_events: 0 });
    expect(simulation.undecidable_events).toBe(10);
    expect(simulation.events).toBe(ROUND);
    expect(simulation.truncated).toBe(false);
    expect(simulation.not_simulated).toEqual([...SIMULATION_NOT_SIMULATED]);
  });

  it("says what promoting one monitor Rule would refuse when an earlier monitor Rule covers its requests (F5)", async () => {
    // Every Rule enforced, the broad Rule takes every request below /api first and the admin Rule refuses
    // nothing. Promoted alone (the broad Rule stays in monitor and refuses nothing), the admin Rule refuses
    // every admin read: that is what the promote confirmation must show.
    nested = await simulated(NESTED);
    expect(nested.rules).toEqual([
      {
        // 30 admin reads, 20 orders, 45 searches and 6 product reads; the `(unmatched)` requests are not judged.
        ...row(0, "API"),
        matched: 101,
        would_block: 101,
        undecidable: 4,
        // Three admin readers, two buyers, two searchers and the product reader.
        clients_affected: 8,
        sample_routes: [
          { route: "/api/search", method: "GET", count: 45 },
          { route: "/api/admin/users", method: "GET", count: 30 },
          { route: "/api/orders", method: "POST", count: 20 },
          { route: "/api/products/:id", method: "GET", count: 6 },
        ],
        if_promoted: promoted(101, 8, 4),
      },
      {
        ...row(1, "Admin only"),
        matched: 30,
        would_block: 0,
        undecidable: 4,
        if_promoted: promoted(30, 3, 4),
      },
    ]);
    expect(nested.totals).toEqual({ would_refuse: 101, clients_affected: 8, unknown_client_events: 0 });
    expect(nested.events).toBe(ROUND);
  });

  it("stores and publishes nothing: the Policy, the bundle and Shield are as before, and Shield allows everything", async () => {
    // The same draft again: the same figures (the Events are the same), and still nothing kept.
    const again = await simulated(DRAFT);
    expect(again.rules).toEqual(estimate.rules);
    expect(again.totals).toEqual(estimate.totals);
    expect(again.events).toBe(estimate.events);

    expect(await currentPolicy()).toEqual(untouched);
    const versions = await call(`/v1/apps/${appId}/policies/development/versions`, { key: adminKey });
    expect(versions.status).toBe(200);
    expect(JSON.stringify(await versions.json())).not.toMatch(/Admin area|Signed orders|Search limit|Login protection/);
    const served = await bundle();
    expect(served.rules).toEqual([]);
    expect(served.signature_rules ?? []).toEqual([]);
    expect(served.limit_rules ?? []).toEqual([]);

    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ ...untouchedStats, lastPolicyError: null });
    // Requests the draft would refuse are served: an admin read, an unsigned order, a search of the client that
    // the estimate has far over the limit.
    const before = handled.length;
    expect((await send(ADMINS[0] as string, "GET", "/api/admin/users")).status).toBe(200);
    expect((await send(BUYERS[0] as string, "POST", "/api/orders", { sku: "rope", quantity: 1 })).status).toBe(200);
    expect((await send(HEAVY_SEARCHER, "GET", SEARCH.path)).status).toBe(200);
    expect(handled.length).toBe(before + 3);
    const all = await until("Events of the three requests", VISIBLE_BUDGET_MS, async () => {
      const events = await listEvents();
      return events.length >= ROUND + 3 ? events : undefined;
    });
    for (const event of all) expect(event.decision.action).toBe("allow");
  });

  it("is consistent with reality: the same Rules enforced refuse the same traffic as estimated", async () => {
    const known = new Set((await listEvents()).map((event) => event.event_id));
    expect(known.size).toBe(ROUND + 3);

    // The draft as simulated, enforced. Counters are per Rule and Shield instance: these Rules start at zero.
    const response = await publish({
      expected_version: 0,
      rules: DRAFT.map((rule) => ({ ...rule, mode: "enforce" })),
    });
    expect(response.status).toBe(201);
    const enforced = PolicyResponseSchema.parse(await response.json()).policy;
    expect(enforced.rules.map((rule) => [rule.name, rule.mode])).toEqual(DRAFT.map((rule) => [rule.name, "enforce"]));
    const idOf = (name: string) => enforced.rules.find((rule) => rule.name === name)?.id;
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: enforced.version, policyRules: 4, lastPolicyError: null });

    // The same traffic again.
    const handledBefore = {
      admin: calls("GET /api/admin/users"),
      orders: calls("POST /api/orders"),
      search: calls("GET /api/search"),
      login: calls("POST /login"),
    };
    const round = await sendRound();
    const [admin, orders, search, login] = estimate.rules;
    if (!admin || !orders || !search || !login) throw new Error("the estimate has four rows");

    // What the clients got. Block and signature Rules: every matched request is refused, as estimated.
    expect(statuses(round.admin)).toEqual(Array(30).fill(403));
    for (const answer of [...round.admin, ...round.orders]) expect(answer.body).toBe(BLOCK_RESPONSE_BODY);
    expect(round.admin.filter((answer) => answer.status === 403)).toHaveLength(admin.would_block);
    expect(statuses(round.orders)).toEqual(Array(20).fill(403));
    expect(round.orders.filter((answer) => answer.status === 403)).toHaveLength(orders.would_fail_signature);
    // The limits: the first ten pass, the rest of the round is refused; the lighter client is never refused.
    expect(statuses(round.heavy)).toEqual([...Array(10).fill(200), ...Array(30).fill(429)]);
    expect(statuses(round.light)).toEqual(Array(5).fill(200));
    expect(statuses(round.logins)).toEqual([...Array(10).fill(401), 429, 429]);
    const throttled = [...round.heavy, ...round.light, ...round.logins].filter((answer) => answer.status === 429);
    for (const answer of throttled) expect(answer.body).toBe(RATE_LIMITED_RESPONSE_BODY);
    expect([...round.heavy, ...round.light].filter((answer) => answer.status === 429)).toHaveLength(
      search.would_throttle,
    );
    expect(round.logins.filter((answer) => answer.status === 429)).toHaveLength(login.would_throttle);
    // What the estimate did not count as refused is served: also what it could not judge.
    expect(statuses(round.products)).toEqual(Array(6).fill(200));
    expect(statuses(round.assets)).toEqual(Array(4).fill(200));
    // Refused before the handler.
    expect(calls("GET /api/admin/users")).toBe(handledBefore.admin);
    expect(calls("POST /api/orders")).toBe(handledBefore.orders);
    expect(calls("GET /api/search")).toBe(handledBefore.search + 45 - search.would_throttle);
    expect(calls("POST /login")).toBe(handledBefore.login + 12 - login.would_throttle);

    // What Shield recorded: per Rule, the refusals and the distinct clients refused equal the estimate.
    const fresh = await until("Events of the second round", VISIBLE_BUDGET_MS, async () => {
      const events = (await listEvents()).filter((event) => !known.has(event.event_id));
      return events.length >= ROUND ? events : undefined;
    });
    expect(fresh).toHaveLength(ROUND);
    const refusedBy = (name: string, action: "block" | "throttle") =>
      fresh.filter(
        (event) =>
          event.decision.action === action &&
          event.decision.mode === "enforce" &&
          event.decision.rule_id === idOf(name),
      );
    const clientsOf = (events: StoredEvent[]) => new Set(events.map((event) => event.actor.ip_hash)).size;
    const real = {
      admin: refusedBy("Admin area", "block"),
      orders: refusedBy("Signed orders", "block"),
      search: refusedBy("Search limit", "throttle"),
      login: refusedBy("Login protection", "throttle"),
    };
    expect(real.admin).toHaveLength(admin.would_block);
    expect(real.orders).toHaveLength(orders.would_fail_signature);
    expect(real.search).toHaveLength(search.would_throttle);
    expect(real.login).toHaveLength(login.would_throttle);
    expect(clientsOf(real.admin)).toBe(admin.clients_affected);
    expect(clientsOf(real.orders)).toBe(orders.clients_affected);
    expect(clientsOf(real.search)).toBe(search.clients_affected);
    expect(clientsOf(real.login)).toBe(login.clients_affected);
    // In total: every refusal of the round is one of the four Rules, and there are as many as estimated.
    const refused = fresh.filter((event) => event.decision.action !== "allow");
    expect(refused).toHaveLength(estimate.totals.would_refuse);
    expect(clientsOf(refused)).toBe(estimate.totals.clients_affected);
    expect(refused.length).toBe(real.admin.length + real.orders.length + real.search.length + real.login.length);
  }, 60_000);

  it("promotes the nested Rule alone on a real Shield: the real refusals equal its if_promoted figure (F5)", async () => {
    const current = await currentPolicy();
    const known = new Set((await listEvents()).map((event) => event.event_id));
    // The two nested Rules, the broad one still in monitor and the admin Rule promoted, as the Console does it.
    const response = await publish({
      expected_version: current.version,
      rules: NESTED.map((rule) => (rule.name === "Admin only" ? { ...rule, mode: "enforce" } : rule)),
    });
    expect(response.status).toBe(201);
    const policy = PolicyResponseSchema.parse(await response.json()).policy;
    const adminOnly = policy.rules.find((rule) => rule.name === "Admin only");
    expect(policy.rules.map((rule) => [rule.name, rule.mode])).toEqual([
      ["API", "monitor"],
      ["Admin only", "enforce"],
    ]);
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: policy.version, policyRules: 2, lastPolicyError: null });

    // The admin reads of a round, as recorded when the estimate was made: 30 from three clients.
    const before = calls("GET /api/admin/users");
    const answers: Answer[] = [];
    for (let i = 0; i < 30; i++) answers.push(await send(ADMINS[i % 3] as string, "GET", "/api/admin/users"));
    const expected = nested.rules[1]?.if_promoted;
    if (!expected) throw new Error("the monitor Rule has if_promoted");
    expect(answers.filter((answer) => answer.status === 403)).toHaveLength(expected.would_refuse);
    expect(statuses(answers)).toEqual(Array(30).fill(403));
    expect(calls("GET /api/admin/users")).toBe(before);
    // The all-enforced figure (0) would have told the admin that promoting changes nothing.
    expect(nested.rules[1]?.would_block).toBe(0);
    // Other routes below /api are still served: the broad Rule is in monitor.
    expect((await send(BROWSER, "GET", "/api/products/7")).status).toBe(200);

    const fresh = await until("Events of the promoted Rule", VISIBLE_BUDGET_MS, async () => {
      const events = (await listEvents()).filter((event) => !known.has(event.event_id));
      return events.length >= 31 ? events : undefined;
    });
    const refused = fresh.filter(
      (event) =>
        event.decision.action === "block" &&
        event.decision.mode === "enforce" &&
        event.decision.rule_id === adminOnly?.id,
    );
    expect(refused).toHaveLength(expected.would_refuse);
    expect(new Set(refused.map((event) => event.actor.ip_hash)).size).toBe(expected.clients_affected);
    expect(
      fresh.filter((event) => event.decision.action === "block" && event.decision.mode === "enforce"),
    ).toHaveLength(expected.would_refuse);
  });

  it("refuses an invalid draft with 400 as a publish does, and an unknown Environment", async () => {
    const tooMany = Array.from({ length: 51 }, (_, i) => ({ name: `Rule ${i}`, path: `/r/${i}` }));
    const invalid: [string, unknown][] = [
      ["a path without a leading slash", [{ name: "Bad path", path: "api/admin" }]],
      ["no name", [{ name: "  ", path: "/api/admin/**" }]],
      [
        "a limit together with a signature requirement",
        [
          {
            name: "Both",
            path: "/api/orders",
            requires: "signature",
            limit: { requests: 5, window_s: 60, key: "ip" },
          },
        ],
      ],
      [
        "a limit of zero requests",
        [{ name: "Zero", path: "/api/search", limit: { requests: 0, window_s: 60, key: "ip" } }],
      ],
      ["an enforced Rule for every path", [{ name: "Everything", path: "/**", mode: "enforce" }]],
      ["more than 50 Rules", tooMany],
      ["no list of Rules", "all"],
    ];
    const current = (await currentPolicy()).version;
    for (const [what, rules] of invalid) {
      const simulation = await simulate(rules);
      const publication = await publish({ rules, expected_version: current });
      expect(publication.status, `publish: ${what}`).toBe(400);
      expect(simulation.status, `simulate: ${what}`).toBe(400);
      expect(simulation.headers.get("content-type")).toMatch(/^application\/problem\+json/);
      const refusedDraft = (await simulation.json()) as { type?: string; errors?: unknown[] };
      const refusedPublish = (await publication.json()) as { type?: string; errors?: unknown[] };
      expect(refusedDraft.type, what).toBe(refusedPublish.type);
      // The same values are named, at the same place of the Rules.
      expect(refusedDraft.errors, what).toEqual(refusedPublish.errors);
      expect(refusedDraft.errors?.length, what).toBeGreaterThan(0);
    }
    expect((await currentPolicy()).version).toBe(current);

    const noEnvironment = await call(`/v1/apps/${appId}/policy/simulate`, {
      method: "POST",
      key: adminKey,
      body: { rules: DRAFT },
    });
    expect(noEnvironment.status).toBe(400);
    const unknownEnvironment = await call(`/v1/apps/${appId}/policy/simulate`, {
      method: "POST",
      key: adminKey,
      body: { environment: "moon", rules: DRAFT },
    });
    expect(unknownEnvironment.status).toBe(400);
  });

  it("answers 404 to another Organization, 403 to a Shield key and 401 without a key", async () => {
    const foreign = await simulate(DRAFT, otherOrgAdminKey);
    expect(foreign.status).toBe(404);
    const text = await foreign.text();
    expect(text).not.toContain("simulation");
    expect(text).not.toContain("would_");
    // An App that does not exist reads the same.
    const missing = await simulate(DRAFT, adminKey, `${appId.slice(0, -4)}0000`);
    expect([missing.status, appId.endsWith("0000")]).toEqual([404, false]);

    expect((await simulate(DRAFT, shieldKey)).status).toBe(403);
    expect((await simulate(DRAFT, null)).status).toBe(401);
  });

  it("answers the 7th simulation of a minute with 429 and Retry-After; drafts that were refused do not count", async () => {
    const busy = await organizationWithApp("Busy");
    const run = (rules: unknown) => simulate(rules, busy.adminKey, busy.appId);
    // Refused drafts cost nothing: three of them before the six that count.
    for (let i = 0; i < 3; i++) expect((await run([{ name: "Bad path", path: "api/admin" }])).status).toBe(400);
    for (let i = 0; i < SIMULATION_LIMITS.perMinute; i++) {
      const response = await run(DRAFT);
      expect(response.status, `simulation ${i + 1}`).toBe(200);
      // An App without recorded requests: an estimate of nothing, one row per Rule.
      const { simulation } = SimulatePolicyResponseSchema.parse(await response.json());
      expect(simulation.events).toBe(0);
      expect(simulation.rules).toEqual(
        DRAFT.map((rule, index) => ({ ...row(index, rule.name), if_promoted: promoted(0, 0) })),
      );
    }
    const seventh = await run(DRAFT);
    expect(seventh.status).toBe(429);
    expect(seventh.headers.get("content-type")).toMatch(/^application\/problem\+json/);
    expect(seventh.headers.get("retry-after")).toMatch(/^[1-9][0-9]*$/);
    const retryAfter = Number(seventh.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect(JSON.stringify(await seventh.json())).not.toContain("would_");
    // Still refused, whatever is sent that could be replayed.
    expect((await run([])).status).toBe(429);

    // The limit is per Organization: the first Organization, with four simulations behind it, is served.
    const mine = await simulate([{ name: "Admin area", path: "/api/admin/**" }]);
    expect(mine.status).toBe(200);
  });
});
