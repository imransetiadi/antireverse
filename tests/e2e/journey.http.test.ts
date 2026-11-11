// The slice 01 journey without a browser: API in-process, a customer Express server with Shield,
// and the live stream read over a real socket. Proves ticket 01's journey, safety and tenancy criteria.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListEventsResponseSchema,
  type StoredEvent,
  StoredEventSchema,
} from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;

let api: RunningApi;
let shield: Shield;
let customer: http.Server;
let customerUrl: string;
let adminKey: string;
let appId: string;

async function post(path: string, body: unknown, key?: string): Promise<Response> {
  return fetch(`${api.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(key ? { authorization: `Bearer ${key}` } : {}) },
    body: JSON.stringify(body),
  });
}

async function createOrganization(name: string) {
  const response = await post("/v1/organizations", { name });
  expect(response.status).toBe(201);
  return CreateOrganizationResponseSchema.parse(await response.json());
}

/** Opens the live stream and resolves with the first `security-event` whose route matches. */
async function firstStreamedEvent(
  key: string,
  app: string,
  route: string,
  signal: AbortSignal,
): Promise<{ event: StoredEvent; id: string }> {
  const response = await fetch(`${api.url}/v1/apps/${app}/events/stream`, {
    headers: { authorization: `Bearer ${key}` },
    signal,
  });
  expect(response.status).toBe(200);
  expect(response.headers.get("content-type")).toContain("text/event-stream");
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) throw new Error("stream ended before the event arrived");
    buffer += decoder.decode(value, { stream: true });
    let boundary = buffer.indexOf("\n\n");
    while (boundary !== -1) {
      const frame = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      boundary = buffer.indexOf("\n\n");
      const fields = new Map<string, string>();
      for (const line of frame.split("\n")) {
        if (line.startsWith(":")) continue;
        const colon = line.indexOf(":");
        if (colon > 0) fields.set(line.slice(0, colon), line.slice(colon + 1).trimStart());
      }
      if (fields.get("event") !== "security-event") continue;
      const event = StoredEventSchema.parse(JSON.parse(fields.get("data") ?? ""));
      if (event.request.route === route) {
        await reader.cancel();
        return { event, id: fields.get("id") ?? "" };
      }
    }
  }
}

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });

  const organization = await createOrganization("Acme");
  adminKey = organization.admin_key.key;

  const created = await post("/v1/apps", { name: "shop-web" }, adminKey);
  expect(created.status).toBe(201);
  const app = CreateAppResponseSchema.parse(await created.json());
  appId = app.app.id;

  shield = createShield({ key: app.shield_key.key, endpoint: api.url, flushIntervalMs: 200 });
  expect(shield.stats().disabledReason).toBeNull();

  const customerApp = express();
  customerApp.use(shield.express());
  customerApp.get("/api/products/:id", (req, res) => {
    res.json({ id: req.params.id });
  });
  customer = http.createServer(customerApp);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  customerUrl = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await shield?.close();
  if (customer) {
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 01 journey over HTTP", () => {
  it("shows a request to the customer's server in the live stream within the budget, unchanged and private", async () => {
    const abort = new AbortController();
    const streamed = firstStreamedEvent(adminKey, appId, "/api/products/:id", abort.signal);
    // Let the subscription register before the request is made.
    await new Promise((resolve) => setTimeout(resolve, 100));

    const startedAt = Date.now();
    const response = await fetch(`${customerUrl}/api/products/4711?token=secret-value`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ id: "4711" });

    const { event, id } = await Promise.race([
      streamed,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(`no event within ${VISIBLE_BUDGET_MS} ms`)), VISIBLE_BUDGET_MS),
      ),
    ]).finally(() => abort.abort());
    const visibleMs = Date.now() - startedAt;

    expect(visibleMs).toBeLessThanOrEqual(VISIBLE_BUDGET_MS);
    expect(id).toBe(event.event_id);
    expect(event.app_id).toBe(appId);
    expect(event.environment).toBe("development");
    expect(event.request).toMatchObject({ method: "GET", route: "/api/products/:id", status: 200 });
    expect(event.decision).toMatchObject({ action: "allow", mode: "monitor" });
    expect(event.actor.ip_prefix).toBe("127.0.0.0/24");

    // Nothing from the concrete URL leaves the customer's server.
    const serialised = JSON.stringify(event);
    expect(serialised).not.toContain("4711");
    expect(serialised).not.toContain("token");
    expect(serialised).not.toContain("secret-value");
  });

  it("lists the Event for its Organization", async () => {
    const response = await fetch(`${api.url}/v1/apps/${appId}/events`, {
      headers: { authorization: `Bearer ${adminKey}` },
    });
    expect(response.status).toBe(200);
    const { events } = ListEventsResponseSchema.parse(await response.json());
    expect(events.some((event) => event.request.route === "/api/products/:id")).toBe(true);
  });

  it("hides the App's Events from a second Organization", async () => {
    const other = await createOrganization("Other");
    const headers = { authorization: `Bearer ${other.admin_key.key}` };

    const list = await fetch(`${api.url}/v1/apps/${appId}/events`, { headers });
    expect(list.status).toBe(404);

    const stream = await fetch(`${api.url}/v1/apps/${appId}/events/stream`, { headers });
    expect(stream.status).toBe(404);
    await stream.body?.cancel();
  });

  it("keeps the customer's server answering when ingest is unreachable", async () => {
    const offline = createShield({
      key: `ark_dev_${"A".repeat(43)}`,
      endpoint: "http://127.0.0.1:9",
      flushIntervalMs: 50,
      logger: { warn() {} },
    });
    const app = express();
    app.use(offline.express());
    app.get("/ping", (_req, res) => {
      res.send("pong");
    });
    const server = http.createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/ping`;
    try {
      for (let i = 0; i < 25; i += 1) {
        const response = await fetch(url);
        expect(response.status).toBe(200);
        expect(await response.text()).toBe("pong");
      }
    } finally {
      await offline.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
