// Slice 02 over HTTP: publish a Policy, Shield applies it, a matching request is blocked or marked,
// the Decision reaches the live stream, rollback restores the previous behaviour.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BLOCK_RESPONSE_BODY,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  PolicyResponseSchema,
  type PolicyRuleInput,
  type StoredEvent,
  StoredEventSchema,
} from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-16: a published Policy is applied within 15 seconds. */
const APPLIED_BUDGET_MS = 15_000;

let api: RunningApi;
let shield: Shield;
let customer: http.Server;
let customerUrl: string;
let adminKey: string;
let appId: string;
const handled: string[] = [];

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

async function publish(rules: PolicyRuleInput[], key = adminKey): Promise<number> {
  const response = await call(`/v1/apps/${appId}/policies/development`, { method: "PUT", key, body: { rules } });
  expect(response.status).toBe(201);
  return PolicyResponseSchema.parse(await response.json()).policy.version;
}

/** Polls (without refreshPolicy) until Shield reports the version, and returns how long it took. */
async function untilApplied(version: number): Promise<number> {
  const started = Date.now();
  while (shield.stats().policyVersion !== version) {
    if (Date.now() - started > APPLIED_BUDGET_MS) throw new Error(`version ${version} not applied in time`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return Date.now() - started;
}

/** Collects stream Events until `predicate` holds for one of them. */
async function streamedEvent(predicate: (event: StoredEvent) => boolean, signal: AbortSignal): Promise<StoredEvent> {
  const response = await call(`/v1/apps/${appId}/events/stream`, { key: adminKey });
  expect(response.status).toBe(200);
  const reader = (response.body as ReadableStream<Uint8Array>).getReader();
  signal.addEventListener("abort", () => void reader.cancel().catch(() => {}));
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) throw new Error("stream ended");
    buffer += decoder.decode(value, { stream: true });
    let boundary = buffer.indexOf("\n\n");
    while (boundary !== -1) {
      const frame = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      boundary = buffer.indexOf("\n\n");
      const data = frame
        .split("\n")
        .find((line) => line.startsWith("data:"))
        ?.slice(5)
        .trim();
      if (!data) continue;
      const event = StoredEventSchema.parse(JSON.parse(data));
      if (predicate(event)) {
        await reader.cancel();
        return event;
      }
    }
  }
}

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;

  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: created.shield_key.key,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });

  const app = express();
  app.use(shield.express());
  app.get("/api/admin/reports", (_req, res) => {
    handled.push("/api/admin/reports");
    res.json({ reports: [] });
  });
  app.get("/api/products/:id", (req, res) => {
    handled.push("/api/products/:id");
    res.json({ id: req.params.id });
  });
  customer = http.createServer(app);
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

describe("slice 02 policy path over HTTP", () => {
  it("blocks a request matching an Enforce Rule within the budget, without running the handler", async () => {
    const version = await publish([
      { name: "Admin area", path: "/api/admin/**", mode: "enforce" },
      { name: "Products", path: "/api/products/**", mode: "monitor" },
    ]);
    const appliedMs = await untilApplied(version);
    expect(appliedMs).toBeLessThanOrEqual(APPLIED_BUDGET_MS);

    const abort = new AbortController();
    const blocked = streamedEvent(
      (event) => event.decision.action === "block" && event.decision.mode === "enforce",
      abort.signal,
    );
    await new Promise((resolve) => setTimeout(resolve, 100));

    handled.length = 0;
    for (const path of ["/api/admin/reports", "/API/Admin/Reports", "/api/admin/reports/?x=1", "/api/admin"]) {
      const response = await fetch(`${customerUrl}${path}`);
      expect(response.status, path).toBe(403);
      expect(await response.text()).toBe(BLOCK_RESPONSE_BODY);
    }
    expect(handled).toEqual([]);

    const event = await blocked.finally(() => abort.abort());
    expect(event.request).toMatchObject({ route: "/api/admin/**", status: 403 });
    expect(event.decision).toMatchObject({ action: "block", mode: "enforce", policy_version: version });
    expect(event.decision.rule_id).toMatch(/^rul_[0-9a-f]{24}$/);
    expect(JSON.stringify(event)).not.toContain("reports");
  });

  it("serves a request matching a Monitor Rule unchanged and marks it as would-have-blocked", async () => {
    const abort = new AbortController();
    const marked = streamedEvent(
      (event) => event.decision.action === "block" && event.decision.mode === "monitor",
      abort.signal,
    );
    await new Promise((resolve) => setTimeout(resolve, 100));

    handled.length = 0;
    const response = await fetch(`${customerUrl}/api/products/7`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ id: "7" });
    expect(handled).toEqual(["/api/products/:id"]);

    const event = await marked.finally(() => abort.abort());
    expect(event.request).toMatchObject({ route: "/api/products/:id", status: 200 });
  });

  it("restores the previous behaviour after a rollback, within the budget", async () => {
    const rolled = await call(`/v1/apps/${appId}/policies/development/rollback`, {
      method: "POST",
      key: adminKey,
      body: { version: 1 },
    });
    // Version 1 holds the Enforce Rule; publish an empty Policy first so that a rollback to it means something.
    expect(rolled.status).toBe(201);
    const empty = await publish([]);
    await untilApplied(empty);
    expect((await fetch(`${customerUrl}/api/admin/reports`)).status).toBe(200);

    const back = await call(`/v1/apps/${appId}/policies/development/rollback`, {
      method: "POST",
      key: adminKey,
      body: { version: 1 },
    });
    expect(back.status).toBe(201);
    const version = PolicyResponseSchema.parse(await back.json()).policy.version;
    expect(await untilApplied(version)).toBeLessThanOrEqual(APPLIED_BUDGET_MS);
    expect((await fetch(`${customerUrl}/api/admin/reports`)).status).toBe(403);
  });

  it("refuses a Rule that would block every request", async () => {
    const response = await call(`/v1/apps/${appId}/policies/development`, {
      method: "PUT",
      key: adminKey,
      body: { rules: [{ name: "Everything", path: "/**", mode: "enforce" }] },
    });
    expect(response.status).toBe(400);
  });

  it("keeps the Policy away from a second Organization", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    expect((await call(`/v1/apps/${appId}/policies/development`, { key })).status).toBe(404);
    expect(
      (await call(`/v1/apps/${appId}/policies/development`, { method: "PUT", key, body: { rules: [] } })).status,
    ).toBe(404);
  });
});
