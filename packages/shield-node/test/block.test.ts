// The middleware under a published Policy: an Enforce Rule blocks, a Monitor Rule marks, everything else is as
// before. Review focus 1 is exercised here against a real Express application: whatever spelling of the path
// Express would route to the handler, Shield must block.
import { EventEmitter } from "node:events";
import type { IncomingMessage, ServerResponse } from "node:http";
import net from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import { BLOCK_RESPONSE_BODY, EventBatchSchema, type ShieldEvent, UNMATCHED_ROUTE } from "@antireverse/protocol";
import express from "express";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BLOCK_BODY } from "../src/express.ts";
import { createShield, type Shield, type ShieldConfig } from "../src/index.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, type FakeApi, fakeApi, payload, rule, signed } from "./policy-helpers.ts";

const signer = createSigner();

const ADMIN = rule(0xa1, { path: "/api/admin/**", mode: "enforce" });
const PRODUCTS = rule(0xb2, { path: "/api/products/**", mode: "monitor" });
const LOGIN = rule(0xc3, { path: "/api/login", mode: "enforce", methods: ["DELETE"] });
const RULES = [PRODUCTS, ADMIN, LOGIN];

interface Protected {
  shield: Shield;
  api: FakeApi;
  warnings: string[];
  /** Waits until `count` Events were recorded in total, flushes, and returns every Event sent so far, in order. */
  events(count: number): Promise<ShieldEvent[]>;
  /** Everything that left the process towards the API, as text. */
  sent(): string;
}

/** A Shield that has applied a Policy with `rules` (version 7). */
async function protect(rules = RULES, config: Partial<ShieldConfig> = {}): Promise<Protected> {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000, // tests refresh explicitly
    flushIntervalMs: 3_600_000, // tests flush explicitly
    logger: { warn: (message) => void warnings.push(message) },
    ...config,
  });
  api.publish(signed(signer, payload(KEY, { version: 7, rules, issued_at: new Date().toISOString() })));
  await shield.refreshPolicy();
  expect(shield.stats()).toMatchObject({ policyVersion: 7, policyRules: rules.length, lastPolicyError: null });
  shields.push(shield);
  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    warnings,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
    sent: () => [...api.posts, ...api.gets].map((request) => `${request.url} ${request.body ?? ""}`).join("\n"),
  };
}

interface App {
  app: express.Express;
  /** How often each handler ran. */
  ran: Record<string, number>;
}

/** The application under test: the same routes with or without Shield. `install` says where Shield goes. */
function makeApp(shield?: Shield, install: "app" | "router" | "subapp" | "param-mount" = "app"): App {
  const ran: Record<string, number> = {};
  const count = (name: string): void => {
    ran[name] = (ran[name] ?? 0) + 1;
  };
  const app = express();
  app.disable("x-powered-by");
  const middleware = shield?.express();

  const routes = (target: express.Router, prefix: string): void => {
    target.get(`${prefix}/admin/reports`, (_req, res) => {
      count("reports");
      res.json({ reports: ["synthetic"] });
    });
    target.all(`${prefix}/admin`, (_req, res) => {
      count("admin");
      res.send("admin root");
    });
    target.get(`${prefix}/administrator`, (_req, res) => {
      count("administrator");
      res.send("a different path");
    });
    target.get(`${prefix}/products/:id`, (req, res) => {
      count("product");
      res.setHeader("x-product", "yes");
      res.json({ id: req.params.id, name: "Synthetic product" });
    });
    target.post(`${prefix}/login`, (_req, res) => {
      count("login");
      res.status(401).json({ error: "invalid_credentials" });
    });
    target.delete(`${prefix}/login`, (_req, res) => {
      count("logout");
      res.status(204).end();
    });
    target.get(`${prefix}/:section/list`, (req, res) => {
      count("list");
      res.send(`list of ${req.params.section}`);
    });
  };

  if (install === "app") {
    if (middleware) app.use(middleware);
    routes(app, "/api");
  } else if (install === "router") {
    const api = express.Router();
    if (middleware) api.use(middleware);
    routes(api, "");
    app.use("/api", api);
  } else if (install === "subapp") {
    const api = express();
    api.disable("x-powered-by");
    if (middleware) api.use(middleware);
    routes(api, "");
    app.use("/api", api);
  } else {
    // /:scope is "api" for the requests of these tests: the Rule is written against the full path.
    const api = express.Router({ mergeParams: true });
    if (middleware) api.use(middleware);
    routes(api, "");
    app.use("/:scope", api);
  }
  return { app, ran };
}

const open: Listening[] = [];
const shields: Shield[] = [];
async function serve(app: express.Express): Promise<Listening> {
  const listening = await listen(app);
  open.push(listening);
  return listening;
}

afterEach(async () => {
  for (const listening of open.splice(0)) await listening.stop();
  for (const shield of shields.splice(0)) await shield.close();
  vi.restoreAllMocks();
});

/** One request with the request target exactly as given: `fetch` and `http.request` would rewrite or refuse some. */
function raw(port: number, target: string, method = "GET"): Promise<{ status: number; head: string; body: string }> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(`${method} ${target} HTTP/1.1\r\nHost: target.test\r\nConnection: close\r\n\r\n`);
    });
    let data = "";
    socket.setEncoding("latin1");
    socket.on("data", (chunk: string) => {
      data += chunk;
    });
    socket.on("error", reject);
    socket.on("close", () => {
      const split = data.indexOf("\r\n\r\n");
      const head = split === -1 ? data : data.slice(0, split);
      resolve({
        status: Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0),
        head,
        body: split === -1 ? "" : data.slice(split + 4),
      });
    });
  });
}

describe("the block response", () => {
  it("is the protocol's: Shield repeats the body because it has no runtime dependency", () => {
    expect(BLOCK_BODY).toBe(BLOCK_RESPONSE_BODY);
    expect(BLOCK_BODY).toBe('{"error":"request_blocked"}');
  });
});

describe("an Enforce Rule on /api/admin/**", () => {
  it("answers 403 with exactly the block body; the handler never runs", async () => {
    const guarded = await protect();
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);

    const response = await exchange(`${base}/api/admin/reports`);
    expect(response.status).toBe(403);
    expect(response.body).toBe(BLOCK_RESPONSE_BODY);
    // Nothing but what a response needs: no Rule identifier, no header of Shield's own.
    expect(response.headers).toEqual([
      ["connection", "keep-alive"],
      ["content-length", String(BLOCK_RESPONSE_BODY.length)],
      ["content-type", "application/json"],
      ["keep-alive", "timeout=5"],
    ]);
    expect(ran).toEqual({});
  });

  it("records one Event: the Rule's pattern as route, status 403, Decision block in Enforce mode with the Rule", async () => {
    const guarded = await protect();
    const { app } = makeApp(guarded.shield);
    const { base } = await serve(app);
    await exchange(`${base}/api/admin/reports/zq-quarterly?token=zq-secret`);

    const events = await guarded.events(1);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      type: "request.decision",
      request: { method: "GET", route: "/api/admin/**", status: 403 },
      decision: { action: "block", mode: "enforce", rule_id: ADMIN.id, policy_version: 7 },
      actor: { ip_prefix: "127.0.0.0/24" },
    });
    expect(events[0]?.request.latency_ms).toBeGreaterThanOrEqual(0);
    await sleep(30);
    expect(guarded.shield.stats()).toMatchObject({ buffered: 0, sent: 1, internalErrors: 0 });
    // The concrete path is used inside the process only.
    expect(guarded.sent()).not.toContain("zq");
    expect(guarded.sent()).not.toContain("reports");
  });

  it("leaves other routes untouched: same status, headers and body with and without Shield", async () => {
    const guarded = await protect();
    const withShield = await serve(makeApp(guarded.shield).app);
    const without = await serve(makeApp().app);
    for (const [method, path] of [
      ["POST", "/api/login"],
      ["GET", "/api/administrator"],
      ["GET", "/api/orders/list"],
      ["GET", "/nothing/here"],
    ] as const) {
      expect(await exchange(withShield.base + path, { method }), path).toEqual(
        await exchange(without.base + path, { method }),
      );
    }
    const events = await guarded.events(4);
    expect(events.map((event) => [event.request.route, event.request.status, event.decision])).toEqual([
      [
        "/api/login",
        401,
        {
          action: "allow",
          mode: "enforce",
          rule_id: null,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
          limit_rule_id: null,
        },
      ],
      [
        "/api/administrator",
        200,
        {
          action: "allow",
          mode: "enforce",
          rule_id: null,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
          limit_rule_id: null,
        },
      ],
      [
        "/api/:section/list",
        200,
        {
          action: "allow",
          mode: "enforce",
          rule_id: null,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
          limit_rule_id: null,
        },
      ],
      [
        UNMATCHED_ROUTE,
        404,
        {
          action: "allow",
          mode: "enforce",
          rule_id: null,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
          limit_rule_id: null,
        },
      ],
    ]);
  });

  it("answers a blocked HEAD with 403 and no body, and a blocked POST without reading its body", async () => {
    const guarded = await protect();
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    const head = await exchange(`${base}/api/admin/reports`, { method: "HEAD" });
    expect(head.status).toBe(403);
    expect(head.body).toBe("");
    const post = await exchange(`${base}/api/admin`, { method: "POST", body: "x".repeat(10_000) });
    expect(post.status).toBe(403);
    expect(post.body).toBe(BLOCK_RESPONSE_BODY);
    expect(ran).toEqual({});
    const events = await guarded.events(2);
    expect(events.map((event) => [event.request.method, event.request.route, event.request.status])).toEqual([
      ["HEAD", "/api/admin/**", 403],
      ["POST", "/api/admin/**", 403],
    ]);
  });

  it("a Rule with methods blocks those methods only", async () => {
    const guarded = await protect();
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    expect((await exchange(`${base}/api/login`, { method: "DELETE" })).status).toBe(403);
    expect((await exchange(`${base}/api/login`, { method: "POST" })).status).toBe(401);
    expect(ran).toEqual({ login: 1 });
    const events = await guarded.events(2);
    expect(events.map((event) => [event.request.route, event.decision.action, event.decision.rule_id])).toEqual([
      ["/api/login", "block", LOGIN.id],
      ["/api/login", "allow", null],
    ]);
  });

  it("one Event and one answer when the middleware is mounted twice", async () => {
    const guarded = await protect();
    const app = express();
    app.use(guarded.shield.express());
    app.use(guarded.shield.express());
    let ran = 0;
    app.get("/api/admin/reports", (_req, res) => {
      ran += 1;
      res.send("reports");
    });
    const { base } = await serve(app);
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(403);
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(403);
    expect(await guarded.events(2)).toHaveLength(2);
    await sleep(30);
    expect(guarded.shield.stats().sent).toBe(2);
    expect(ran).toBe(0);
  });

  it("stops blocking when a later Policy no longer holds the Rule", async () => {
    const guarded = await protect();
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(403);
    guarded.api.publish(signed(signer, payload(KEY, { version: 8, rules: [], issued_at: new Date().toISOString() })));
    await guarded.shield.refreshPolicy();
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(200);
    expect(ran).toEqual({ reports: 1 });
    const events = await guarded.events(2);
    expect(events.map((event) => [event.request.route, event.decision.action, event.decision.policy_version])).toEqual([
      ["/api/admin/**", "block", 7],
      ["/api/admin/reports", "allow", 8],
    ]);
  });
});

describe("bypass attempts against a real Express application", () => {
  // Every request target here either is blocked or never reaches a handler below /api/admin. The targets marked
  // `routed` do reach the handler when Shield is absent: for those the 403 is what stands between client and data.
  const targets: [target: string, routed: boolean][] = [
    ["/api/admin/reports", true],
    ["/API/Admin/Reports", true],
    ["/api/ADMIN/reports/", true],
    ["/api/admin/reports?x=1", true],
    ["/api/admin/reports/?x=1&next=/api/login", true],
    ["/api/admin/reports?", true],
    ["/api/admin/reports#fragment", true],
    ["/api/admin", true],
    ["/api/admin/", true],
    ["/api/admin?x=1", true],
    ["/API/ADMIN", true],
    ["http://target.test/api/admin/reports", true], // absolute form: Express routes on the path
    ["http://target.test/api/admin/reports?x#y", true],
    ["/api\\admin\\reports#", true], // Express reads a target with a fragment through the legacy parser, which turns \ into /
    ["/api/admin\\reports#", true],
    ["/api/admin/reports//", false],
    ["/api/admin//reports", false],
    ["/api/admin/./reports", false],
    ["/api/admin/reports/../reports", false],
    ["/api/admin/reports%00", false],
    ["/api/admin/reports;x=1", false],
    ["/api/admin/%72eports", false],
  ];

  it.each(["app", "router", "subapp", "param-mount"] as const)(
    "Shield installed on the %s: no spelling reaches the handlers",
    async (install) => {
      const guarded = await protect();
      const protectedApp = makeApp(guarded.shield, install);
      const plainApp = makeApp(undefined, install);
      const withShield = await serve(protectedApp.app);
      const without = await serve(plainApp.app);

      for (const [target, routed] of targets) {
        const before = (plainApp.ran.reports ?? 0) + (plainApp.ran.admin ?? 0);
        const plain = await raw(without.port, target);
        const reached = (plainApp.ran.reports ?? 0) + (plainApp.ran.admin ?? 0) > before;
        // Pins what Express itself does with the target, where Shield sees the whole path.
        if (install === "app") expect(reached, `without Shield, ${target}`).toBe(routed);

        const blocked = await raw(withShield.port, target);
        if (reached) {
          expect(plain.status, target).toBeLessThan(300);
          expect(blocked.status, target).toBe(403);
          expect(blocked.body, target).toBe(BLOCK_RESPONSE_BODY);
        } else {
          expect([403, 404], target).toContain(blocked.status);
        }
      }
      expect(protectedApp.ran).toEqual({});
      await guarded.events(targets.length);
      expect(guarded.sent()).not.toMatch(/reports|fragment|target\.test/i);
    },
  );

  it.each(["app", "router", "subapp", "param-mount"] as const)(
    "Shield installed on the %s: a different path is not blocked",
    async (install) => {
      const guarded = await protect();
      const { app, ran } = makeApp(guarded.shield, install);
      const { port } = await serve(app);
      for (const target of [
        "/api/administrator",
        "/API/Administrator/",
        "/api/administrator?x=/api/admin/",
        "/api/orders/list",
      ]) {
        expect((await raw(port, target)).status, target).toBe(200);
      }
      expect((await raw(port, "/api/admin-old")).status).toBe(404);
      expect((await raw(port, "/api/admin.json")).status).toBe(404);
      expect(ran).toEqual({ administrator: 3, list: 1 });
      const events = await guarded.events(6);
      expect(events.every((event) => event.decision.action === "allow" && event.decision.rule_id === null)).toBe(true);
    },
  );

  it("an encoded or dot-segment spelling is blocked: a middleware after Shield may decode what Express does not", async () => {
    const guarded = await protect();
    const { app, ran } = makeApp(guarded.shield);
    const { port } = await serve(app);
    // None of these is /api/admin/... to the router, but `express.static` and others decode and resolve the path
    // before they read it (test/static.test.ts). Shield matches the canonical form as well, and blocks.
    const targets = [
      "/api/%61dmin/reports",
      "/api/admin%2Freports",
      "/api/x/../admin/reports",
      "/api/./admin/reports",
      "//api/admin/reports",
    ];
    for (const target of targets) {
      const response = await raw(port, target);
      expect(response.status, target).toBe(403);
      expect(response.body, target).toBe(BLOCK_RESPONSE_BODY);
    }
    expect(ran).toEqual({});
    const events = await guarded.events(targets.length);
    expect(events.map((event) => [event.request.route, event.decision.action, event.decision.rule_id])).toEqual(
      targets.map(() => ["/api/admin/**", "block", ADMIN.id]),
    );
  });
});

describe("known limits, pinned so that a change is noticed", () => {
  it("a route parameter that Express decodes is caught by the canonical form of the path", async () => {
    // /api/:section/list is one route for every section. Express decodes the parameter after routing, so the
    // handler sees "admin" for /api/%61dmin/list. The text is not below /api/admin, its decoded form is: blocked.
    // A star in the Rule (/api/*/list) catches every section whatever its spelling.
    const literal = await protect();
    const first = makeApp(literal.shield);
    const { port } = await serve(first.app);
    const encoded = await raw(port, "/api/%61dmin/list");
    expect(encoded.status).toBe(403);
    expect(encoded.body).toBe(BLOCK_RESPONSE_BODY);
    expect((await raw(port, "/api/admin/list")).status).toBe(403);
    expect((await raw(port, "/api/orders/list")).status).toBe(200);
    expect(first.ran).toEqual({ list: 1 });

    const starred = await protect([rule(9, { path: "/api/*/list", mode: "enforce" })]);
    const second = makeApp(starred.shield);
    const other = await serve(second.app);
    expect((await raw(other.port, "/api/%61dmin/list")).status).toBe(403);
    expect(second.ran).toEqual({});
  });

  it("review F2: Express answers HEAD with the GET handler, so a Rule for GET alone stops HEAD too", async () => {
    const guarded = await protect([rule(9, { path: "/api/admin/**", mode: "enforce", methods: ["GET"] })]);
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(403);
    const head = await exchange(`${base}/api/admin/reports`, { method: "HEAD" });
    expect(head.status).toBe(403);
    expect(head.body).toBe("");
    expect(ran).toEqual({}); // the handler never ran
    // A Rule for POST alone does not stop HEAD.
    const post = await protect([rule(10, { path: "/api/admin/**", mode: "enforce", methods: ["POST"] })]);
    const other = makeApp(post.shield);
    const second = await serve(other.app);
    expect((await exchange(`${second.base}/api/admin/reports`, { method: "HEAD" })).status).toBe(200);
  });
});

describe("a Monitor Rule on /api/products/**", () => {
  it("changes nothing for the client: same status, headers and body with and without Shield", async () => {
    const guarded = await protect();
    const withShield = await serve(makeApp(guarded.shield).app);
    const without = await serve(makeApp().app);
    for (const path of ["/api/products/42?token=secret", "/api/products/42/", "/API/Products/7"]) {
      expect(await exchange(withShield.base + path), path).toEqual(await exchange(without.base + path));
    }
    expect((await exchange(`${withShield.base}/api/products/42`)).status).toBe(200);
  });

  it("records the real route template and the Decision block in Monitor mode with the Rule", async () => {
    const guarded = await protect();
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    await exchange(`${base}/api/products/zq-item?token=zq-secret`);
    await exchange(`${base}/api/products/zq-item/no/such/route`);
    expect(ran).toEqual({ product: 1 });
    const events = await guarded.events(2);
    expect(events.map((event) => [event.request.route, event.request.status, event.decision])).toEqual([
      [
        "/api/products/:id",
        200,
        {
          action: "block",
          mode: "monitor",
          rule_id: PRODUCTS.id,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
          limit_rule_id: null,
        },
      ],
      [
        UNMATCHED_ROUTE,
        404,
        {
          action: "block",
          mode: "monitor",
          rule_id: PRODUCTS.id,
          policy_version: 7,
          containment_id: null,
          patch_id: null,
          patch_body: null,
          limit_rule_id: null,
        },
      ],
    ]);
    expect(guarded.sent()).not.toContain("zq");
  });

  it("an Enforce Rule later in the list still blocks what an earlier Monitor Rule also matches", async () => {
    const guarded = await protect([rule(1, { path: "/api/**", mode: "monitor" }), ADMIN]);
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(403);
    expect((await exchange(`${base}/api/products/1`)).status).toBe(200);
    expect(ran).toEqual({ product: 1 });
    const events = await guarded.events(2);
    expect(events.map((event) => [event.decision.mode, event.decision.rule_id])).toEqual([
      ["enforce", ADMIN.id],
      ["monitor", rule(1).id],
    ]);
  });
});

describe("fail-open: an error while deciding never blocks and never breaks a request", () => {
  it("lets the request through and counts an internal error when matching throws", async () => {
    const guarded = await protect();
    vi.spyOn(guarded.shield, "decide").mockImplementation(() => {
      throw new Error("matching exploded");
    });
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    const response = await exchange(`${base}/api/admin/reports`);
    expect(response.status).toBe(200);
    expect(JSON.parse(response.body)).toEqual({ reports: ["synthetic"] });
    expect(ran).toEqual({ reports: 1 });
    expect(guarded.shield.stats().internalErrors).toBe(1);
    const events = await guarded.events(1);
    expect(events[0]).toMatchObject({
      request: { route: "/api/admin/reports", status: 200 },
      decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 0 },
    });
  });

  it.each([
    ["nothing", undefined],
    ["null", null],
    ["text", "block"],
    ["a Decision with an unknown action", { action: "explode", mode: "enforce", ruleId: null, policyVersion: 7 }],
  ])("lets the request through when decide returns %s", async (_name, value) => {
    const guarded = await protect();
    vi.spyOn(guarded.shield, "decide").mockImplementation(() => value as never);
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    expect((await exchange(`${base}/api/admin/reports`)).status).toBe(200);
    expect(ran).toEqual({ reports: 1 });
  });

  it("lets the request through when the response has already started: Shield cannot answer 403 any more", async () => {
    const guarded = await protect();
    const app = express();
    app.use((_req, res, next) => {
      res.write("started "); // something in front of Shield already sent the headers
      next();
    });
    app.use(guarded.shield.express());
    app.get("/api/admin/reports", (_req, res) => void res.end("by the handler"));
    const { base } = await serve(app);
    const response = await exchange(`${base}/api/admin/reports`);
    expect(response.status).toBe(200);
    expect(response.body).toBe("started by the handler");
    expect(guarded.shield.stats().internalErrors).toBe(1);
    const events = await guarded.events(1);
    expect(events[0]).toMatchObject({
      request: { route: "/api/admin/reports", status: 200 },
      decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 0 },
    });
  });

  it("still blocks when only the recording fails: the clock throws", async () => {
    let broken = false;
    const guarded = await protect(RULES, {
      now: () => {
        if (broken) throw new Error("clock exploded");
        return Date.now();
      },
    });
    broken = true;
    const { app, ran } = makeApp(guarded.shield);
    const { base } = await serve(app);
    const response = await exchange(`${base}/api/admin/reports`);
    expect(response.status).toBe(403);
    expect(response.body).toBe(BLOCK_RESPONSE_BODY);
    expect(ran).toEqual({});
    expect((await exchange(`${base}/api/administrator`)).status).toBe(200);
    expect(guarded.shield.stats().internalErrors).toBeGreaterThanOrEqual(2);
  });
});

describe("the middleware called directly", () => {
  it("a blocked request: next() is not called, the response is ended once, and 'close' records the Event", async () => {
    const guarded = await protect();
    const middleware = guarded.shield.express();
    const written: unknown[] = [];
    const headers: Record<string, unknown> = {};
    const response = Object.assign(new EventEmitter(), {
      statusCode: 200,
      headersSent: false,
      setHeader: (name: string, value: unknown) => {
        headers[name] = value;
      },
      end: (chunk: unknown) => {
        written.push(chunk);
      },
    });
    let nexts = 0;
    const request = { method: "GET", url: "/api/admin/keys?x=1", socket: { remoteAddress: "203.0.113.77" } };
    middleware(request as unknown as IncomingMessage, response as unknown as ServerResponse, () => {
      nexts += 1;
    });
    expect(nexts).toBe(0);
    expect(response.statusCode).toBe(403);
    expect(headers).toEqual({ "content-type": "application/json" });
    expect(written).toEqual([BLOCK_RESPONSE_BODY]);
    response.emit("close");
    const events = await guarded.events(1);
    expect(events[0]).toMatchObject({
      request: { method: "GET", route: "/api/admin/**", status: 403 },
      decision: { action: "block", mode: "enforce", rule_id: ADMIN.id },
      actor: { ip_prefix: "203.0.113.0/24" },
    });
  });

  it("prefers the path Express routes on (baseUrl + path) over the raw URL, and the original URL over the mounted one", async () => {
    const guarded = await protect();
    const middleware = guarded.shield.express();
    const call = (request: Record<string, unknown>): number => {
      const response = Object.assign(new EventEmitter(), {
        statusCode: 200,
        headersSent: false,
        setHeader: () => {},
        end: () => {},
      });
      let nexts = 0;
      middleware(
        { method: "GET", socket: {}, ...request } as unknown as IncomingMessage,
        response as unknown as ServerResponse,
        () => {
          nexts += 1;
        },
      );
      return nexts;
    };
    expect(call({ url: "/reports", baseUrl: "/api/admin", path: "/reports", originalUrl: "/api/admin/reports" })).toBe(
      0,
    );
    expect(call({ url: "/reports", originalUrl: "/api/admin/reports" })).toBe(0); // no Express getter: the original URL
    expect(call({ url: "/api/admin/reports" })).toBe(0); // plain node:http
    expect(call({ url: "/reports" })).toBe(1);
    expect(call({ url: "/x", baseUrl: "", path: "/api/admin" })).toBe(0);
    // A request without a URL has no path: no Rule matches it, and that is not an error.
    expect(call({})).toBe(1);
    expect(call({ url: 42 })).toBe(1);
    expect(guarded.shield.stats().internalErrors).toBe(0);
  });
});

describe("requests never wait for the API", () => {
  it("answers at once while a Policy request and the ingest are both stuck", async () => {
    const guarded = await protect();
    guarded.api.policyAnswer(() => new Promise(() => {})); // never answers
    void guarded.shield.refreshPolicy();
    const { app } = makeApp(guarded.shield);
    const { base } = await serve(app);
    const started = performance.now();
    for (let i = 0; i < 20; i++) {
      expect((await exchange(`${base}/api/admin/reports`)).status).toBe(403);
      expect((await exchange(`${base}/api/products/${i}`)).status).toBe(200);
    }
    expect(performance.now() - started).toBeLessThan(2_000);
  });
});
