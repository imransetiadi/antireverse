import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { UNMATCHED_ROUTE } from "@antireverse/protocol";
import express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { Shield, Transport } from "../src/index.ts";
import { captureShield, exchange, KEY, type Listening, listen } from "./helpers.ts";

const VERSION_7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Called when the next request for /slow has reached its handler. */
let onSlow: (() => void) | undefined;

/** The application under test: the same routes with or without Shield. */
function makeApp(shield?: Shield): express.Express {
  const app = express();
  if (shield) app.use(shield.express());
  app.get("/api/products/:id", (req, res) => {
    res.setHeader("x-product", "yes");
    res.json({ id: req.params.id, name: "Synthetic product" });
  });
  app.post("/api/login", (_req, res) => void res.status(401).json({ error: "invalid_credentials" }));
  app.get("/slow", (_req, res) => {
    onSlow?.();
    setTimeout(() => res.send("slow"), 300);
  });
  app.get("/boom", () => {
    throw new Error("synthetic failure");
  });
  app.use("/blocked", (_req, res) => void res.status(403).send("ended by middleware"));

  const users = express.Router();
  users.get("/users/:id", (req, res) => void res.json({ id: req.params.id }));
  app.use("/v1", users);

  const orgApps = express.Router();
  orgApps.get("/apps/:appId", (req, res) => void res.json({ appId: req.params.appId }));
  app.use("/orgs/:orgId", orgApps);

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).json({ error: "internal", message: String(err) });
  });
  return app;
}

const open: Listening[] = [];
async function serve(app: express.Express, host?: string): Promise<Listening> {
  const listening = await listen(app, host);
  open.push(listening);
  return listening;
}

afterEach(async () => {
  for (const listening of open.splice(0)) await listening.stop();
  vi.restoreAllMocks();
});

describe("shield.express(): the response is never changed", () => {
  it.each([
    ["GET", "/api/products/42?token=secret"],
    ["POST", "/api/login"],
    ["GET", "/v1/users/7"],
    ["GET", "/no/such/route"],
    ["GET", "/boom"],
    ["GET", "/blocked/x"],
    ["HEAD", "/api/products/42"],
  ])("%s %s gives the same status, headers and body with and without Shield", async (method, path) => {
    const captured = captureShield();
    const withShield = await serve(makeApp(captured.shield));
    const without = await serve(makeApp());
    const observed = await exchange(withShield.base + path, { method });
    const plain = await exchange(without.base + path, { method });
    expect(observed).toEqual(plain);
    expect(await captured.events(1)).toHaveLength(1);
  });
});

describe("shield.express(): one Event per request, from the allowlist only", () => {
  it("records method, route template, status, latency, network prefix and the Decision", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    const before = Date.now();
    const response = await exchange(`${base}/api/products/42?token=secret`);
    expect(response.status).toBe(200);

    const events = await captured.events(1);
    expect(events).toHaveLength(1);
    const event = events[0] as (typeof events)[number];
    expect(event.event_id).toMatch(VERSION_7);
    expect(Date.parse(event.ts)).toBeGreaterThanOrEqual(before - 1);
    expect(Date.parse(event.ts)).toBeLessThanOrEqual(Date.now());
    expect(event.ts).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    expect(event).toMatchObject({
      type: "request.decision",
      surface: "api",
      request: { method: "GET", route: "/api/products/:id", status: 200 },
      decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 0 },
      actor: { ip_prefix: "127.0.0.0/24" },
      signals: [],
    });
    expect(typeof event.request.latency_ms).toBe("number");
    expect(event.request.latency_ms).toBeGreaterThanOrEqual(0);
    expect(event.request.latency_ms).toBeLessThan(5_000);

    // Nothing of the concrete URL: not the identifier, not the query string.
    // (Identifier, time, latency and the actor hash are generated values and could contain "42" by chance.)
    const fromRequest = JSON.stringify({
      ...event,
      event_id: "",
      ts: "",
      request: { ...event.request, latency_ms: 0 },
      actor: { ...event.actor, ip_hash: event.actor.ip_hash === null ? null : "" },
    });
    for (const forbidden of ["42", "token", "secret"]) expect(fromRequest).not.toContain(forbidden);
  });

  it("sends exactly the allowlisted keys, and nothing of the URL, in the body that leaves the process", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    await exchange(`${base}/api/products/zq-distinct-identifier?token=zq-distinct-secret&email=zq%40example.test`, {
      headers: { authorization: "Bearer zq-distinct-credential", cookie: "session=zq-distinct-cookie" },
    });
    await captured.events(1);
    expect(captured.requests).toHaveLength(1);
    const body = captured.requests[0]?.body as string;
    expect(body).not.toContain("zq");
    expect(body).not.toContain("example.test");
    const raw = JSON.parse(body) as { events: Record<string, unknown>[] };
    const event = raw.events[0] as Record<string, Record<string, unknown>>;
    expect(Object.keys(raw).sort()).toEqual(["events", "protocol", "sdk"]);
    expect(Object.keys(event).sort()).toEqual(
      [
        "actor",
        "attestation",
        "decision",
        "event_id",
        "request",
        "signals",
        "signature",
        "surface",
        "ts",
        "type",
      ].sort(),
    );
    expect(event.attestation).toEqual({ status: "missing", verdict: null, risk: null });
    expect(event.signature).toEqual({ status: "missing", body: null });
    expect(Object.keys(event.request ?? {}).sort()).toEqual(["latency_ms", "method", "route", "status"]);
    expect(Object.keys(event.decision ?? {}).sort()).toEqual([
      "action",
      "containment_id",
      "mode",
      "patch_body",
      "patch_id",
      "policy_version",
      "rule_id",
    ]);
    expect(Object.keys(event.actor ?? {}).sort()).toEqual(["ip_hash", "ip_prefix"]);
  });

  it("records the template of a route inside a mounted router", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    await exchange(`${base}/v1/users/7?expand=1`);
    expect((await captured.events(1))[0]?.request.route).toBe("/v1/users/:id");
  });

  it("restores the parameters of the mount path: /orgs/:orgId/apps/:appId, never the identifiers", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    const response = await exchange(`${base}/orgs/org-9f3a/apps/app-77c1`);
    expect(response.status).toBe(200);
    const events = await captured.events(1);
    expect(events[0]?.request.route).toBe("/orgs/:orgId/apps/:appId");
    const body = captured.requests.map((request) => request.body).join("\n");
    expect(body).not.toContain("org-9f3a");
    expect(body).not.toContain("app-77c1");
  });

  it("records status 404 and the route (unmatched) when no route matches", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    const response = await exchange(`${base}/no/such/route/zq-identifier?zq=1`);
    expect(response.status).toBe(404);
    const events = await captured.events(1);
    expect(events[0]?.request).toMatchObject({ method: "GET", route: UNMATCHED_ROUTE, status: 404 });
    expect(UNMATCHED_ROUTE).toBe("(unmatched)");
    expect(captured.requests[0]?.body).not.toContain("zq");
  });

  it("records (unmatched) for a response ended by middleware, and the upper-case method", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    await exchange(`${base}/blocked/anything`, { method: "delete" });
    await exchange(`${base}/api/login`, { method: "POST", body: "{}" });
    const events = await captured.events(2);
    expect(events.map((event) => event.request)).toMatchObject([
      { method: "DELETE", route: UNMATCHED_ROUTE, status: 403 },
      { method: "POST", route: "/api/login", status: 401 },
    ]);
  });

  it("records status 500 when a handler throws", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    const response = await exchange(`${base}/boom`);
    expect(response.status).toBe(500);
    expect(JSON.parse(response.body)).toEqual({ error: "internal", message: "Error: synthetic failure" });
    expect((await captured.events(1))[0]?.request).toMatchObject({ route: "/boom", status: 500 });
  });

  it("still records exactly one Event when the client aborts before the response ends", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    // Abort once the request has arrived, not after a fixed time: on a busy machine a short timeout can fire
    // before the request was even sent.
    const abort = new AbortController();
    const arrived = new Promise<void>((resolve) => {
      onSlow = resolve;
    });
    const pending = fetch(`${base}/slow`, { signal: abort.signal });
    await arrived;
    abort.abort();
    await expect(pending).rejects.toThrow();
    const events = await captured.events(1);
    expect(events).toHaveLength(1);
    expect(events[0]?.request).toMatchObject({ method: "GET", route: "/slow" });
    await sleep(350); // the handler's late res.send() runs against the closed socket: it must not add an Event
    expect(captured.recorded()).toBe(1);
  });

  it("records one Event per response on a reused connection, and one when the middleware is mounted twice", async () => {
    const captured = captureShield();
    const app = express();
    app.use(captured.shield.express());
    app.use(captured.shield.express());
    app.get("/users/:id", (_req, res) => void res.send("ok"));
    const { base } = await serve(app);
    for (let i = 0; i < 3; i++) await exchange(`${base}/users/${i}`); // fetch keeps the connection alive
    const events = await captured.events(3);
    await sleep(30);
    expect(captured.recorded()).toBe(3);
    expect(events.map((event) => event.request.route)).toEqual(["/users/:id", "/users/:id", "/users/:id"]);
    expect(new Set(events.map((event) => event.event_id)).size).toBe(3);
  });

  it("uses clientAddress when given, and records only its prefix", async () => {
    const seen: unknown[] = [];
    const captured = captureShield({
      clientAddress: (req) => {
        seen.push(req);
        return "2001:db8:abcd:12::beef";
      },
    });
    const { base } = await serve(makeApp(captured.shield));
    await exchange(`${base}/api/products/1`);
    const events = await captured.events(1);
    expect(events[0]?.actor.ip_prefix).toBe("2001:db8:abcd::/48");
    expect(seen).toHaveLength(1);
    // The actor hash is hex and could contain "beef" by chance: it is removed before the check.
    expect(captured.requests[0]?.body?.replace(/iph_[0-9a-f]{32}/g, "iph_")).not.toContain("beef");
  });

  it("treats the IPv4-mapped address of a dual-stack listener as IPv4, and truncates IPv6 to /48", async () => {
    const captured = captureShield();
    const { port } = await serve(makeApp(captured.shield), "::");
    await exchange(`http://127.0.0.1:${port}/api/products/1`);
    await exchange(`http://[::1]:${port}/api/products/1`);
    const events = await captured.events(2);
    expect(events.map((event) => event.actor.ip_prefix)).toEqual(["127.0.0.0/24", "0:0:0::/48"]);
  });
});

describe("shield.express(): failures inside Shield stay inside Shield", () => {
  it("answers 200 and counts an internal error when decide throws", async () => {
    const captured = captureShield();
    vi.spyOn(captured.shield, "decide").mockImplementation(() => {
      throw new Error("decide exploded");
    });
    const { base } = await serve(makeApp(captured.shield));
    const response = await exchange(`${base}/api/products/42`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ id: "42", name: "Synthetic product" });
    for (let i = 0; i < 200 && captured.shield.stats().internalErrors === 0; i++) await sleep(5);
    expect(captured.shield.stats().internalErrors).toBe(1);
  });

  it.each([
    [
      "the clock throws",
      {
        now: () => {
          throw new Error("clock exploded");
        },
      },
    ],
    ["the clock returns nonsense", { now: () => Number.NaN }],
    [
      "clientAddress throws",
      {
        clientAddress: () => {
          throw new Error("address exploded");
        },
      },
    ],
  ])("answers 200 and counts an internal error when recording fails: %s", async (_name, config) => {
    const captured = captureShield(config);
    const { base } = await serve(makeApp(captured.shield));
    const response = await exchange(`${base}/api/products/42`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ id: "42", name: "Synthetic product" });
    for (let i = 0; i < 200 && captured.shield.stats().internalErrors === 0; i++) await sleep(5);
    expect(captured.shield.stats().internalErrors).toBeGreaterThanOrEqual(1);
  });

  it("answers 100 requests with 200 while ingest rejects every batch, without an unhandled rejection", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => void unhandled.push(reason);
    process.on("unhandledRejection", onUnhandled);
    try {
      let attempts = 0;
      const transport: Transport = async () => {
        attempts += 1;
        throw new Error("connect ECONNREFUSED 127.0.0.1:1");
      };
      const captured = captureShield({ transport, flushIntervalMs: 5 });
      const { base } = await serve(makeApp(captured.shield));
      const statuses: number[] = [];
      for (let i = 0; i < 100; i++) statuses.push((await exchange(`${base}/api/products/${i}`)).status);
      expect(statuses).toEqual(new Array(100).fill(200));
      await captured.shield.close();
      await sleep(20);
      expect(attempts).toBeGreaterThan(0);
      const stats = captured.shield.stats();
      expect(stats).toMatchObject({ sent: 0, buffered: 0, internalErrors: 0 });
      expect(stats.failedBatches).toBeGreaterThan(0);
      expect(stats.lastError).toEqual(expect.any(String));
      // The line about observing only (no policyPublicKey), then one line for "ingest unreachable", however many
      // batches fail.
      expect(captured.warnings).toEqual([expect.stringMatching(/observes only/), expect.stringMatching(/ingest/)]);
      for (const line of captured.warnings) expect(line).not.toContain(KEY);
      expect(unhandled).toEqual([]);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  it("logs one line when ingest refuses the key, and never the key", async () => {
    const captured = captureShield({ transport: async () => ({ status: 401 }) });
    const { base } = await serve(makeApp(captured.shield));
    await exchange(`${base}/api/products/1`);
    await captured.events(1);
    await exchange(`${base}/api/products/2`);
    await captured.events(2);
    expect(captured.shield.stats().lastError).toContain("401");
    expect(captured.warnings).toEqual([expect.stringMatching(/observes only/), expect.stringMatching(/401/)]);
    for (const line of captured.warnings) expect(line).not.toContain(KEY);
  });

  it("calls next() exactly once and never throws, even for objects that are not a request and a response", () => {
    const captured = captureShield();
    const middleware = captured.shield.express();
    let nexts = 0;
    const next = (): void => {
      nexts += 1;
    };
    const response = Object.assign(new EventEmitter(), { statusCode: 200 }) as unknown as ServerResponse;
    expect(() => middleware({} as IncomingMessage, response, next)).not.toThrow(); // no socket, no method
    expect(() => middleware({ socket: {}, method: 7 } as unknown as IncomingMessage, response, next)).not.toThrow();
    expect(() => middleware(Object.freeze({}) as IncomingMessage, {} as ServerResponse, next)).not.toThrow();
    expect(() => middleware(null as unknown as IncomingMessage, null as unknown as ServerResponse, next)).not.toThrow();
    expect(nexts).toBe(4);
    expect(() => response.emit("close")).not.toThrow();
    expect(captured.shield.stats().internalErrors).toBeGreaterThan(0);
  });

  it("does not swallow what the host's own next() does", () => {
    const captured = captureShield();
    const response = Object.assign(new EventEmitter(), { statusCode: 200 }) as unknown as ServerResponse;
    const request = { method: "GET", socket: { remoteAddress: "127.0.0.1" } } as unknown as IncomingMessage;
    expect(() =>
      captured.shield.express()(request, response, () => {
        throw new Error("the host's own failure");
      }),
    ).toThrow("the host's own failure");
    expect(captured.shield.stats().internalErrors).toBe(0);
  });

  it("records nothing after close()", async () => {
    const captured = captureShield();
    const { base } = await serve(makeApp(captured.shield));
    await captured.shield.close();
    expect((await exchange(`${base}/api/products/1`)).status).toBe(200);
    await sleep(30);
    expect(captured.recorded()).toBe(0);
    expect(captured.requests).toEqual([]);
  });
});
