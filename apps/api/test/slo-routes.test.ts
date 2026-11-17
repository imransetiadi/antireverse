import { SLO_CATALOG, type SloReport, SloReportSchema, type SloStatus } from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { classifyRoute, KEYLESS_ROUTES, TENANT_DESTINATION_ROUTES } from "../src/slo/middleware.ts";
import { createSloService, type SloService } from "../src/slo/service.ts";
import {
  batchOf,
  bearer,
  createAppFor,
  createOrganization,
  json,
  makeTestApi,
  shieldEvent,
  type TestApi,
} from "./helpers.ts";

// Slice 18d: the request feed of the SLIs through the real app (route classes, status and latency), the operator
// endpoints `GET /v1/ops/slo` and `GET /metrics` and their access. A known mix of good and bad requests, with an
// injected clock and an injected latency clock, gives exactly known attainment and burn rates.

const TOKEN = "op_".padEnd(40, "x7");
const NOW = Date.parse("2026-11-14T10:00:10.000Z");

let db: OwnedDb;
let failing = false;
let api: TestApi;
let slo: SloService;
let admin: string;
let shield: string;
let appId: string;
let organizationId: string;

/** The latency clock: every request lasts `duration` ms. */
let duration = 10;
let base = 0;
/** Every reading is `duration` after the last: arrival, body read (if any) and end are each `duration` apart. */
const monotonic = () => {
  base += duration;
  return base;
};

async function request(path: string, init: RequestInit = {}, ms = 10): Promise<Response> {
  duration = ms;
  return api.app.request(path, init);
}

async function failingRequest(path: string, init: RequestInit = {}, ms = 10): Promise<Response> {
  failing = true;
  try {
    return await request(path, init, ms);
  } finally {
    failing = false;
  }
}

let eventMs = NOW - 1_000;
const ingest = (ms: number, key = shield) =>
  request("/v1/events", json(batchOf([shieldEvent(eventMs++)]), bearer(key)), ms);

async function report(): Promise<SloReport> {
  const res = await request("/v1/ops/slo", { headers: bearer(TOKEN) });
  expect(res.status).toBe(200);
  return SloReportSchema.parse(await res.json());
}

const of = (r: SloReport, id: string): SloStatus => {
  const found = r.slos.find((s) => s.id === id);
  if (found === undefined) throw new Error(id);
  return found;
};

beforeAll(async () => {
  const real = await openDb();
  // A database whose request transactions fail while `failing` is set: the route then answers 500.
  db = { ...real, tx: (scope, fn) => (failing ? Promise.reject(new Error("db down")) : real.tx(scope, fn)) };
  slo = createSloService({ db, now: () => new Date(NOW) });
  api = await makeTestApi({ db, now: () => new Date(NOW), slo, opsToken: TOKEN, monotonic });
  const organization = await createOrganization(api);
  admin = organization.admin_key.key;
  organizationId = organization.organization.id;
  const created = await createAppFor(api, admin);
  shield = created.shield_key.key;
  appId = created.app.id;
  // Start from nothing: the set-up requests above are not part of the mix.
  await slo.recorder.flush();
  await db.owner((q) => q.query("DELETE FROM slo_minutes"));
});
afterAll(async () => {
  await api.close();
});

describe("route classes", () => {
  it("classifies attestation, ingest, distribution and the Control API, and leaves out ops, health and public routes", () => {
    expect(classifyRoute("POST", "/v1/attest")).toEqual({ slo: "SLO-01", variant: "all" });
    expect(classifyRoute("POST", "/v1/attest/challenge")).toEqual({ slo: "SLO-01", variant: "all" });
    expect(classifyRoute("OPTIONS", "/v1/attest")).toBeNull();
    expect(classifyRoute("POST", "/v1/events")).toEqual({ slo: "SLO-02", variant: "all" });
    expect(classifyRoute("GET", "/v1/policy-bundle")).toEqual({ slo: "SLO-03", variant: "all" });
    expect(classifyRoute("GET", "/v1/signing-key")).toEqual({ slo: "SLO-03", variant: "all" });
    expect(classifyRoute("GET", "/v1/apps")).toEqual({ slo: "SLO-07", variant: "read" });
    expect(classifyRoute("HEAD", "/v1/apps")).toEqual({ slo: "SLO-07", variant: "read" });
    expect(classifyRoute("POST", "/v1/apps")).toEqual({ slo: "SLO-07", variant: "write" });
    expect(classifyRoute("PATCH", "/v1/incidents/:incidentId")).toEqual({ slo: "SLO-07", variant: "write" });
    for (const [method, path] of [
      ["GET", "/v1/ops/slo"],
      ["GET", "/metrics"],
      ["GET", "/healthz"],
      ["GET", "(unmatched)"],
      ["GET", "/v1/apps/:appId/events/stream"],
      ["POST", "/v1/beacon"],
      ["POST", "/v1/organizations"],
      ["POST", "/v1/alert-recipients/confirm"],
      ["POST", "/v1/inventory"],
    ] as const) {
      expect(classifyRoute(method, path), `${method} ${path}`).toBeNull();
    }
  });

  it("gives every route of the app a class or an explicit exclusion", () => {
    // Keyless public routes (no admin key, so not the Control API): listed here, one by one.
    const keyless = [
      "POST /v1/beacon",
      "POST /v1/organizations",
      "POST /v1/alert-recipients/confirm",
      "GET /v1/audit/public-key",
      "GET /v1/deletions/:deletionId/report",
    ];
    expect([...KEYLESS_ROUTES].sort()).toEqual(keyless.map((entry) => entry.split(" ")[1]).sort());
    // Routes that wait on a destination the tenant chose.
    const tenantDestination = [
      "POST /v1/alert-channels",
      "POST /v1/alert-channels/:channelId/test",
      "POST /v1/targets/:targetId/verify",
    ];
    expect([...TENANT_DESTINATION_ROUTES].sort()).toEqual([...tenantDestination].sort());
    const other = [
      "GET /v1/ops/slo",
      // Slice 15a: the operator's switches of Pentest Campaigns (the operator token, not the Control API).
      "GET /v1/ops/prove",
      "POST /v1/ops/prove/kill",
      "POST /v1/ops/prove/enable",
      "POST /v1/ops/prove/organizations/:id/suspend",
      "POST /v1/ops/prove/organizations/:id/resume",
      "GET /v1/apps/:appId/events/stream",
      "POST /v1/inventory",
      "OPTIONS /v1/attest",
      "OPTIONS /v1/attest/challenge",
    ];
    const unclassified: string[] = [];
    for (const route of api.app.routes) {
      if (route.method === "ALL" || !route.path.startsWith("/v1/")) continue;
      if (classifyRoute(route.method, route.path) === null) unclassified.push(`${route.method} ${route.path}`);
    }
    expect([...new Set(unclassified)].sort()).toEqual([...keyless, ...tenantDestination, ...other].sort());
  });
});

describe("a known mix of requests", () => {
  it("gives exactly the attainment, budget and burn of the requests made", async () => {
    // SLO-02: 6 acknowledged in time, 2 acknowledged late (> 150 ms), 1 server error; 2 client errors not counted.
    for (let i = 0; i < 6; i++) expect((await ingest(20)).status).toBe(202);
    for (let i = 0; i < 2; i++) expect((await ingest(151)).status).toBe(202);
    expect((await failingRequest("/v1/events", json(batchOf([shieldEvent(eventMs++)]), bearer(shield)))).status).toBe(
      500,
    );
    expect((await request("/v1/events", json({ nope: 1 }, bearer(shield)))).status).toBe(400);
    expect((await request("/v1/events", json(batchOf([shieldEvent(eventMs++)])))).status).toBe(401);

    // SLO-01: 3 challenges in time, 1 late (> 120 ms); a refused one (unknown App) not counted.
    for (let i = 0; i < 3; i++)
      expect((await request("/v1/attest/challenge", json({ app_id: appId }), 30)).status).toBe(200);
    expect((await request("/v1/attest/challenge", json({ app_id: appId }), 130)).status).toBe(200);
    expect(
      (await request("/v1/attest/challenge", json({ app_id: "app_00000000000000000000000000" }), 10)).status,
    ).toBeGreaterThanOrEqual(400);

    // SLO-03: served twice (slow, but SLO-03 has no latency bound), one server error.
    for (let i = 0; i < 2; i++) expect((await request("/v1/signing-key", {}, 1_000)).status).toBe(200);
    expect((await failingRequest("/v1/policy-bundle", { headers: bearer(shield) })).status).toBe(500);

    // SLO-07: a read in time (150) and a late one (250); a write in time (400) and a late one (600); a 401 not counted.
    expect((await request("/v1/apps", { headers: bearer(admin) }, 150)).status).toBe(200);
    expect((await request("/v1/apps", { headers: bearer(admin) }, 250)).status).toBe(200);
    expect((await request("/v1/apps", json({ name: "Two" }, bearer(admin)), 400)).status).toBe(201);
    expect((await request("/v1/apps", json({ name: "Three" }, bearer(admin)), 600)).status).toBe(201);
    expect((await request("/v1/apps", {}, 5)).status).toBe(401);

    // Not counted anywhere.
    expect((await request("/healthz")).status).toBe(200);
    expect((await request("/nowhere")).status).toBe(404);
    expect((await request("/metrics", { headers: bearer(TOKEN) })).status).toBe(200);

    const r = await report();
    const ingestStatus = of(r, "SLO-02");
    expect([ingestStatus.good, ingestStatus.total]).toEqual([6, 9]);
    expect(ingestStatus.attainment).toBeCloseTo(6 / 9, 12);
    // Burn: error rate 3/9 over the budget rate 0.0005; every window holds the same minute.
    for (const w of ["5m", "30m", "1h", "6h", "3d"] as const) {
      expect(ingestStatus.burn[w], w).toBeCloseTo(3 / 9 / 0.0005, 6);
    }
    expect(ingestStatus.budget_remaining).toBeCloseTo(1 - 3 / 9 / 0.0005, 6);
    expect(ingestStatus.latency).toEqual([
      // 9 batches: 6 at ≤ 25 ms, 2 at ≤ 200 ms, the 500 at 10 ms: p99 is the 9th = 200 ms bucket.
      { variant: "all", percentile: 99, target_ms: 150, observed_ms: 200, met: false },
    ]);

    const attest = of(r, "SLO-01");
    expect([attest.good, attest.total]).toEqual([3, 4]);
    expect(attest.burn["5m"]).toBeCloseTo(1 / 4 / 0.0001, 6);
    expect(attest.latency.map((l) => [l.percentile, l.observed_ms, l.met])).toEqual([
      [95, 150, false],
      [99, 150, false],
    ]);

    const distribution = of(r, "SLO-03");
    expect([distribution.good, distribution.total]).toEqual([2, 3]);

    const control = of(r, "SLO-07");
    expect([control.good, control.total]).toEqual([2, 4]);
    expect(control.burn["1h"]).toBeCloseTo(2 / 4 / 0.001, 6);
    expect(control.latency).toEqual([
      { variant: "read", percentile: 95, target_ms: 200, observed_ms: 300, met: false },
      { variant: "write", percentile: 95, target_ms: 500, observed_ms: 750, met: false },
    ]);

    // SLO-04: each of the 8 Events stored was published at once (the injected clock does not move).
    expect([of(r, "SLO-04").good, of(r, "SLO-04").total]).toEqual([8, 8]);
    for (const id of ["SLO-05", "SLO-09", "SLO-10"]) expect(of(r, id).total, id).toBe(0);
    for (const id of ["SLO-06", "SLO-08"]) {
      expect(of(r, id)).toMatchObject({ measured: false, total: 0, attainment: null, alerts: [] });
    }
    expect(r.slos.map((s) => s.id)).toEqual(SLO_CATALOG.map((s) => s.id));
    expect(r.slos.every((s) => s.runbook.startsWith("RB-"))).toBe(true);
    // Nothing of the tenant in the report.
    const text = JSON.stringify(r);
    for (const value of [organizationId, appId, admin, shield]) expect(text).not.toContain(value);
  });

  it("fires the fast burn alert on the next evaluation and shows it in the report", async () => {
    const transitions = await slo.runOnce();
    expect(transitions.some((t) => t.slo === "SLO-02" && t.rule.id === "fast" && t.state === "firing")).toBe(true);
    const fast = of(await report(), "SLO-02").alerts.find((a) => a.rule === "fast");
    expect(fast).toEqual({ rule: "fast", severity: "page", state: "firing", since: new Date(NOW).toISOString() });
    // Once per episode.
    expect((await slo.runOnce()).filter((t) => t.slo === "SLO-02" && t.rule.id === "fast")).toEqual([]);
  });

  it("serves the figures in Prometheus text format", async () => {
    const res = await request("/metrics", { headers: bearer(TOKEN) });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");
    const text = await res.text();
    expect(text).toContain("# TYPE airverse_slo_good gauge");
    expect(text).toContain('airverse_slo_good{slo="SLO-02"} 6\n');
    expect(text).toContain('airverse_slo_total{slo="SLO-02"} 9\n');
    expect(text).toContain('airverse_slo_objective{slo="SLO-02"} 0.9995\n');
    expect(text).toMatch(/airverse_slo_attainment\{slo="SLO-02"\} 0\.6666/);
    expect(text).toMatch(/airverse_slo_burn_rate\{slo="SLO-02",window="5m"\} 666\.66/);
    expect(text).toMatch(/airverse_slo_error_budget_remaining\{slo="SLO-02"\} -665\.66/);
    expect(text).toContain('airverse_slo_alert_firing{slo="SLO-02",rule="fast",severity="page"} 1\n');
    expect(text).toContain('airverse_slo_attainment{slo="SLO-05"} NaN\n');
    // Unmeasured SLOs are left out.
    expect(text).not.toContain('slo="SLO-06"');
    for (const value of [organizationId, appId]) expect(text).not.toContain(value);
  });
});

describe("operator access", () => {
  it("refuses no token, a wrong token, and admin and Shield keys", async () => {
    for (const path of ["/v1/ops/slo", "/metrics"]) {
      expect((await request(path)).status, path).toBe(401);
      expect((await request(path, { headers: bearer(admin) })).status, path).toBe(401);
      expect((await request(path, { headers: bearer(shield) })).status, path).toBe(401);
      expect((await request(path, { headers: bearer(`${TOKEN.slice(0, -1)}y`) })).status, path).toBe(401);
      expect((await request(path, { headers: bearer(`${TOKEN}x`) })).status, path).toBe(401);
      expect((await request(path, { headers: { authorization: TOKEN } })).status, path).toBe(401);
    }
  });

  it("answers 404 when no operator token is configured", async () => {
    // On the same database (not closed here: the file's API closes it).
    const other = await makeTestApi({ db, slo: createSloService({ db }) });
    for (const path of ["/v1/ops/slo", "/metrics"]) {
      expect((await other.app.request(path, { headers: bearer(TOKEN) })).status, path).toBe(404);
      expect((await other.app.request(path)).status, path).toBe(404);
    }
  });
});
