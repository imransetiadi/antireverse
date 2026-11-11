// Regression guard for the route template. The technique relies on internals of router 2.2.0 (Express 5.3.0, pinned
// exactly): the router assigns `req.route` and `req.params` with plain assignments while `req.baseUrl` still holds
// the concrete mount path. If an Express upgrade changes that, this table fails before a concrete URL can leak.
import http from "node:http";
import { setTimeout as sleep } from "node:timers/promises";
import { UNMATCHED_ROUTE } from "@antireverse/protocol";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type Captured, captureShield, type Listening, listen } from "./helpers.ts";

const ok: express.RequestHandler = (_req, res) => void res.send("ok");
const pass: express.RequestHandler = (_req, _res, next) => next();
/** Called when the next request for /slow has reached its handler. */
let onSlow: (() => void) | undefined;

function makeApp(captured: Captured): express.Express {
  const app = express();
  app.use(captured.shield.express());
  app.get("/", ok);
  app.get("/users/:id", (req, res) => void res.json(req.params));
  app.get(["/multi/a", "/multi/b"], ok);
  app.get(/^\/re\/(\d+)$/, ok);
  app.get("/fallthrough", pass);
  app.get("/slow", (_req, res) => {
    onSlow?.();
    setTimeout(() => res.send("slow"), 300);
  });
  app.use("/mw-only", (_req, res) => void res.send("ended by middleware"));

  const api = express.Router();
  const v1 = express.Router(); // no mergeParams
  v1.get("/", ok);
  v1.get("/items/:itemId", ok);
  v1.get("/boom", () => {
    throw new Error("boom");
  });
  v1.get("/async-boom", async () => {
    throw new Error("async boom");
  });
  api.use("/v1", v1);
  api.use("/orgs/:orgId", v1);
  app.use("/api", api);

  // A router with its own middleware in front of its routes, as almost every real router has (auth, parsing).
  const things = express.Router();
  things.use(pass);
  things.use("/things", pass);
  things.get("/things/:thingId", ok);
  app.use("/tenants/:tenantId", things);

  // Parameterised mounts nested three deep, without and with mergeParams.
  for (const [prefix, options] of [
    ["/nested", {}],
    ["/merged", { mergeParams: true }],
  ] as const) {
    const members = express.Router(options);
    members.use(pass);
    members.get("/members/:memberId", ok);
    const teams = express.Router(options);
    teams.use("/teams/:teamId", members);
    app.use(`${prefix}/:orgId`, teams);
  }

  // The same parameter name at two levels.
  const inner = express.Router();
  inner.get("/c/:id", ok);
  const outer = express.Router();
  outer.use("/b/:id", inner);
  app.use("/same/:id", outer);

  // A mount path whose parameters are only part of a segment, a wildcard mount and a RegExp mount.
  const file = express.Router();
  file.get("/meta", ok);
  app.use("/files/:name.:ext", file);
  const wild = express.Router();
  wild.get("/", ok);
  app.use("/wild/*path", wild);
  const numbered = express.Router();
  numbered.get("/show", ok);
  app.use(/^\/rx\/(\d+)/, numbered);

  // A mounted application.
  const sub = express();
  sub.get("/inner/:x", ok);
  app.use("/sub/:tenant", sub);

  // A router that matches the mount but none of its routes, followed by a sibling that answers.
  const first = express.Router();
  first.get("/never", ok);
  const second = express.Router();
  second.get("/reports/:reportId", ok);
  app.use("/accounts/:accountId", first);
  app.use("/accounts/:accountId", second);

  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    res.status(500).send(String(err));
  });
  return app;
}

describe("route template of an Express 5 request", () => {
  const captured = captureShield();
  let listening: Listening;
  let seen = 0;
  beforeAll(async () => {
    listening = await listen(makeApp(captured));
  });
  afterAll(() => listening.stop());

  async function hit(path: string, init?: RequestInit): Promise<{ status: number; route: string; body: string }> {
    const before = captured.requests.length;
    const response = await fetch(listening.base + path, init);
    await response.arrayBuffer();
    seen += 1;
    const events = await captured.events(seen);
    expect(events).toHaveLength(seen); // exactly one Event per request
    const body = captured.requests
      .slice(before)
      .map((request) => request.body)
      .join("\n");
    return { status: response.status, route: (events.at(-1) as (typeof events)[number]).request.route, body };
  }

  const cases: [path: string, status: number, route: string][] = [
    // The table of the spike.
    ["/", 200, "/"],
    ["/users/42?x=1", 200, "/users/:id"],
    ["/multi/b", 200, "[/multi/a|/multi/b]"],
    ["/re/123", 200, "/^\\/re\\/(\\d+)$/"],
    ["/api/v1/items/7", 200, "/api/v1/items/:itemId"],
    ["/api/v1", 200, "/api/v1/"],
    ["/api/orgs/9/items/7", 200, "/api/orgs/:orgId/items/:itemId"],
    ["/nope", 404, UNMATCHED_ROUTE],
    ["/api/v1/zzz", 404, UNMATCHED_ROUTE],
    ["/api/orgs/9/zzz", 404, UNMATCHED_ROUTE],
    ["/fallthrough", 404, "/fallthrough"],
    ["/api/v1/boom", 500, "/api/v1/boom"],
    ["/api/v1/async-boom", 500, "/api/v1/async-boom"],
    ["/api/orgs/9/boom", 500, "/api/orgs/:orgId/boom"],
    ["/mw-only/x", 200, UNMATCHED_ROUTE],
    // Beyond the spike: every way a concrete segment of a mount path could survive.
    ["/tenants/t-81/things/9", 200, "/tenants/:tenantId/things/:thingId"],
    ["/nested/o-1/teams/t-2/members/m-3", 200, "/nested/:orgId/teams/:teamId/members/:memberId"],
    ["/merged/o-1/teams/t-2/members/m-3", 200, "/merged/:orgId/teams/:teamId/members/:memberId"],
    ["/nested/7/teams/7/members/7", 200, "/nested/:orgId/teams/:teamId/members/:memberId"],
    ["/merged/7/teams/7/members/7", 200, "/merged/:orgId/teams/:teamId/members/:memberId"],
    ["/nested/teams/teams/teams/members/members", 200, "/nested/:orgId/teams/:teamId/members/:memberId"],
    ["/same/1/b/2/c/3", 200, "/same/:id/b/:id/c/:id"],
    ["/same/5/b/5/c/5", 200, "/same/:id/b/:id/c/:id"],
    ["/tenants/a%20b%2Fc/things/9", 200, "/tenants/:tenantId/things/:thingId"],
    ["/tenants/%E2%9C%93/things/9", 200, "/tenants/:tenantId/things/:thingId"],
    ["/files/report.pdf/meta", 200, "/files/:name.:ext/meta"],
    ["/wild/a/b/c", 200, "/wild/*path/"],
    // A regular-expression mount has no template: its capture is never shown as ":0" beside literal text.
    ["/rx/123/show", 200, UNMATCHED_ROUTE],
    ["/sub/acme/inner/5", 200, "/sub/:tenant/inner/:x"],
    ["/accounts/a-55/reports/r-66", 200, "/accounts/:accountId/reports/:reportId"],
    ["/accounts/a-55/missing", 404, UNMATCHED_ROUTE],
    // Routing is case-insensitive by default: the client's spelling of a mount path must not become the template.
    ["/API/V1/items/7", 200, "/api/v1/items/:itemId"],
    ["/Tenants/T-81/Things/9", 200, "/tenants/:tenantId/things/:thingId"],
  ];

  it.each(cases)("%s -> %i %s", async (path, status, route) => {
    const result = await hit(path);
    expect(result.status).toBe(status);
    expect(result.route).toBe(route);
  });

  it("never sends a concrete identifier of a mount path", async () => {
    const identifiers = ["zqorg", "zqteam", "zqmember", "zqtenant", "zqthing", "zqaccount", "zqreport", "zqfile"];
    const bodies = [
      (await hit("/nested/zqorg/teams/zqteam/members/zqmember?zqquery=zqvalue")).body,
      (await hit("/merged/zqorg/teams/zqteam/members/zqmember")).body,
      (await hit("/tenants/zqtenant/things/zqthing")).body,
      (await hit("/accounts/zqaccount/reports/zqreport")).body,
      (await hit("/accounts/zqaccount/zqmissing")).body,
      (await hit("/files/zqfile.zqext/meta")).body,
      (await hit("/wild/zqa/zqb")).body,
      (await hit("/sub/zqtenant/inner/zqx")).body,
    ];
    for (const body of bodies) {
      expect(body).not.toBe("");
      expect(body).not.toContain("zq");
      for (const identifier of identifiers) expect(body.toLowerCase()).not.toContain(identifier);
    }
  });

  it("serves HEAD through the GET route; POST to a GET-only route is an unmatched 404", async () => {
    expect((await hit("/users/1", { method: "HEAD" })).route).toBe("/users/:id");
    const post = await hit("/users/1", { method: "POST" });
    expect(post.status).toBe(404);
    expect(post.route).toBe(UNMATCHED_ROUTE);
  });

  it("records the route of an aborted request once", async () => {
    // Abort once the request has arrived, not after a fixed time: on a busy machine a short timeout can fire
    // before the request was even sent.
    const abort = new AbortController();
    const arrived = new Promise<void>((resolve) => {
      onSlow = resolve;
    });
    const aborted = fetch(`${listening.base}/slow`, { signal: abort.signal }).catch(() => {});
    await arrived;
    abort.abort();
    await aborted;
    seen += 1;
    const events = await captured.events(seen);
    expect(events).toHaveLength(seen);
    expect(events.at(-1)?.request.route).toBe("/slow");
    await sleep(350);
    expect(captured.recorded()).toBe(seen);
  });

  it("records one Event per response on a reused socket", async () => {
    const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });
    const ports = new Set<number>();
    for (let i = 0; i < 3; i++) {
      await new Promise<void>((resolve, reject) => {
        http
          .get(`${listening.base}/users/${i}`, { agent }, (res) => {
            ports.add(res.socket.localPort as number);
            res.resume();
            res.on("end", resolve);
          })
          .on("error", reject);
      });
    }
    agent.destroy();
    seen += 3;
    const events = await captured.events(seen);
    await sleep(30);
    expect(ports.size).toBe(1);
    expect(captured.recorded()).toBe(seen);
    expect(events.slice(-3).map((event) => event.request.route)).toEqual(["/users/:id", "/users/:id", "/users/:id"]);
  });
});

describe("route template: a route that passes the request on", () => {
  it("does not let the parameters of an earlier pass-through route rename a later mount path", async () => {
    const captured = captureShield();
    const app = express();
    app.use(captured.shield.express());
    app.all("/:first/*rest", pass); // matches almost everything and calls next()
    const reports = express.Router();
    reports.get("/reports/:reportId", ok);
    app.use("/accounts/:accountId", reports);
    const listening = await listen(app);
    try {
      await (await fetch(`${listening.base}/accounts/a-55/reports/r-66`)).text();
      await (await fetch(`${listening.base}/elsewhere/x/y`)).text();
      const events = await captured.events(2);
      expect(events.map((event) => [event.request.status, event.request.route])).toEqual([
        [200, "/accounts/:accountId/reports/:reportId"],
        [404, "/:first/*rest"], // the route did match; the template still holds nothing concrete
      ]);
    } finally {
      await listening.stop();
    }
  });
});
