// Slice 17a over HTTP, QASUITE TC-CON-010: a synthetic load of a known number of requests to a customer's Express
// server, through the real Shield middleware of each of two Apps (two Environments), to the real API on a free port.
// After Shield flushed, the metered requests equal the requests made (within 1%, and exactly when Shield dropped
// nothing), per App and in total; a batch sent again adds nothing.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListEventsResponseSchema,
  type UsageResponse,
  UsageResponseSchema,
} from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** Requests per App: N = 600 in all. */
const LOAD = { storefront: 350, backOffice: 250 } as const;
const N = LOAD.storefront + LOAD.backOffice;
/** Requests in flight at once. */
const CONCURRENCY = 50;

let api: RunningApi;
let admin: string;
const apps: Record<
  keyof typeof LOAD,
  { id: string; key: string; shield?: Shield; url?: string; server?: http.Server }
> = {
  storefront: { id: "", key: "" },
  backOffice: { id: "", key: "" },
};

async function post(path: string, body: unknown, key?: string): Promise<Response> {
  return fetch(`${api.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) },
    body: JSON.stringify(body),
  });
}

async function usage(): Promise<UsageResponse> {
  const res = await fetch(`${api.url}/v1/usage`, { headers: { authorization: `Bearer ${admin}` } });
  expect(res.status).toBe(200);
  return UsageResponseSchema.parse(await res.json());
}

/** A customer server for one App: Express with that App's Shield in front of one route. */
async function customerServer(key: string): Promise<{ shield: Shield; server: http.Server; url: string }> {
  // Large buffer and batches so that nothing is dropped by the load itself; flushed explicitly below.
  const shield = createShield({ key, endpoint: api.url, flushIntervalMs: 100, maxBatchSize: 500 });
  expect(shield.stats().disabledReason).toBeNull();
  const app = express();
  app.use(shield.express());
  app.get("/api/products/:id", (req, res) => {
    res.json({ id: req.params.id });
  });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { shield, server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });
  const created = await post("/v1/organizations", { name: "Load Co" });
  expect(created.status).toBe(201);
  admin = CreateOrganizationResponseSchema.parse(await created.json()).admin_key.key;
  for (const [name, environment] of [
    ["storefront", "production"],
    ["backOffice", "staging"],
  ] as const) {
    const res = await post("/v1/apps", { name, environment }, admin);
    expect(res.status).toBe(201);
    const app = CreateAppResponseSchema.parse(await res.json());
    const customer = await customerServer(app.shield_key.key);
    apps[name] = { id: app.app.id, key: app.shield_key.key, ...customer };
  }
}, 30_000);

afterAll(async () => {
  for (const app of Object.values(apps)) {
    await app.shield?.close();
    if (app.server) {
      app.server.closeAllConnections();
      await new Promise<void>((resolve) => app.server?.close(() => resolve()));
    }
  }
  await api?.close();
});

describe("TC-CON-010: metering of protected requests over HTTP", () => {
  it("meters N requests through Shield exactly (and so within 1%), per App and in total", async () => {
    const work = (Object.keys(LOAD) as (keyof typeof LOAD)[]).flatMap((name) =>
      Array.from({ length: LOAD[name] }, (_, i) => `${apps[name].url}/api/products/${i}`),
    );
    expect(work.length).toBe(N);
    for (let i = 0; i < work.length; i += CONCURRENCY) {
      const responses = await Promise.all(work.slice(i, i + CONCURRENCY).map((url) => fetch(url)));
      for (const res of responses) {
        expect(res.status).toBe(200);
        await res.arrayBuffer();
      }
    }
    for (const app of Object.values(apps)) await app.shield?.flush();

    const sent = Object.values(apps).reduce((sum, app) => sum + (app.shield?.stats().sent ?? 0), 0);
    const dropped = Object.values(apps).reduce((sum, app) => sum + (app.shield?.stats().dropped ?? 0), 0);
    expect(dropped).toBe(0);
    expect(sent).toBe(N);

    const body = await usage();
    const metered = body.totals.requests;
    expect(Math.abs(metered - N)).toBeLessThanOrEqual(N * 0.01);
    // Nothing dropped: exact.
    expect(metered).toBe(N);
    const perApp = Object.fromEntries(body.apps.map((app) => [app.app_id, app.requests]));
    expect(perApp).toEqual({ [apps.storefront.id]: LOAD.storefront, [apps.backOffice.id]: LOAD.backOffice });
    expect(body.daily.reduce((sum, day) => sum + day.requests, 0)).toBe(N);
  }, 60_000);

  it("adds nothing for a batch Shield already sent, sent again", async () => {
    const before = (await usage()).totals.requests;
    const res = await fetch(`${api.url}/v1/apps/${apps.storefront.id}/events?limit=200`, {
      headers: { authorization: `Bearer ${admin}` },
    });
    const { events } = ListEventsResponseSchema.parse(await res.json());
    expect(events.length).toBe(200);
    const batch = events.map(({ organization_id, app_id, environment, received_at, ...event }) => event);
    const again = await post(
      "/v1/events",
      { protocol: 1, sdk: { name: "shield-node", version: "0.0.0" }, events: batch },
      apps.storefront.key,
    );
    expect(again.status).toBe(202);
    expect(await again.json()).toEqual({ accepted: 0, duplicates: 200 });
    expect((await usage()).totals.requests).toBe(before);
  });
});
