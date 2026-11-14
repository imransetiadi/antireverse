// Slice 18d over HTTP: the real API (startApi, free port) with an operator token and an operator webhook on a local
// receiver. Real requests (sign-up, an App, Event batches, bundle and key fetches, a client error) are measured and
// reported at GET /v1/ops/slo and GET /metrics, which take the operator token only. A burn of SLO-01 then fires the
// fast page once: the webhook receives it signed with AR_OPS_WEBHOOK_SECRET, naming the SLO and its runbook.
import { once } from "node:events";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  EXAMPLE_SHIELD_EVENT,
  SloReportSchema,
} from "@antireverse/protocol";
import { verifyWebhookSignature } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const TOKEN = "e2e-operator-token-".padEnd(48, "Q");
const SECRET = "e2e-webhook-secret-".padEnd(48, "S");

let api: RunningApi;
let receiver: Server;
const received: { headers: Record<string, string | string[] | undefined>; body: string }[] = [];
let admin = "";
let shield = "";
let organizationId = "";
let appId = "";

const auth = (key: string) => ({ authorization: `Bearer ${key}` });

async function post(path: string, body: unknown, key?: string): Promise<Response> {
  return fetch(`${api.url}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(key === undefined ? {} : auth(key)) },
    body: JSON.stringify(body),
  });
}

function uuidv7(ms: number, n: number): string {
  const hex = ms.toString(16).padStart(12, "0");
  const tail = n.toString(16).padStart(12, "0");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7000-8000-${tail}`;
}

beforeAll(async () => {
  receiver = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      received.push({ headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      res.writeHead(204).end();
    });
  });
  receiver.listen(0, "127.0.0.1");
  await once(receiver, "listening");
  const port = (receiver.address() as AddressInfo).port;
  api = await startApi({
    logger: { info() {}, warn() {} },
    smtp: null,
    ops: { token: TOKEN, webhook: { url: `http://127.0.0.1:${port}/ops/alerts`, secret: SECRET } },
  });
  const created = await post("/v1/organizations", { name: "SLO Co" });
  expect(created.status).toBe(201);
  const org = CreateOrganizationResponseSchema.parse(await created.json());
  admin = org.admin_key.key;
  organizationId = org.organization.id;
  const app = await post("/v1/apps", { name: "Storefront" }, admin);
  expect(app.status).toBe(201);
  const parsed = CreateAppResponseSchema.parse(await app.json());
  shield = parsed.shield_key.key;
  appId = parsed.app.id;
}, 30_000);

afterAll(async () => {
  await api?.close();
  receiver?.closeAllConnections();
  await new Promise<void>((resolve) => receiver?.close(() => resolve()));
});

describe("SLOs over HTTP", () => {
  it("measures real requests and reports them to the operator only", async () => {
    const start = Date.now();
    for (let i = 0; i < 5; i++) {
      const event = { ...EXAMPLE_SHIELD_EVENT, event_id: uuidv7(start, i), ts: new Date(start).toISOString() };
      const res = await post(
        "/v1/events",
        { protocol: 1, sdk: { name: "e2e", version: "0.0.0" }, events: [event] },
        shield,
      );
      expect(res.status).toBe(202);
    }
    expect((await post("/v1/events", { nope: true }, shield)).status).toBe(400);
    expect((await fetch(`${api.url}/v1/signing-key`)).status).toBe(200);
    expect((await fetch(`${api.url}/v1/apps`, { headers: auth(admin) })).status).toBe(200);

    for (const key of [admin, shield, "x".repeat(48)]) {
      expect((await fetch(`${api.url}/v1/ops/slo`, { headers: auth(key) })).status).toBe(401);
      expect((await fetch(`${api.url}/metrics`, { headers: auth(key) })).status).toBe(401);
    }
    const res = await fetch(`${api.url}/v1/ops/slo`, { headers: auth(TOKEN) });
    expect(res.status).toBe(200);
    const text = await res.text();
    const report = SloReportSchema.parse(JSON.parse(text));
    const ingest = report.slos.find((s) => s.id === "SLO-02");
    // 5 batches acknowledged (each well within 150 ms on a local run is likely but not guaranteed: total is exact).
    expect(ingest?.total).toBe(5);
    expect(report.slos.find((s) => s.id === "SLO-04")?.total).toBe(5);
    expect(report.slos.find((s) => s.id === "SLO-03")?.total).toBe(1);
    // The sign-up is not a Control API request; the App's creation and the list are.
    expect(report.slos.find((s) => s.id === "SLO-07")?.total).toBe(2);
    for (const value of [organizationId, appId, admin, shield]) expect(text).not.toContain(value);

    const metrics = await fetch(`${api.url}/metrics`, { headers: auth(TOKEN) });
    expect(metrics.headers.get("content-type")).toBe("text/plain; version=0.0.4; charset=utf-8");
    expect(await metrics.text()).toContain('airverse_slo_total{slo="SLO-02"} 5\n');
  });

  it("fires the fast page once on a burn and posts it signed to the operator webhook", async () => {
    // A burn of SLO-01 (99.99 %): 50 bad of 100 in this minute.
    for (let i = 0; i < 100; i++) api.slo.recorder.record("SLO-01", i % 2 === 0, 5);
    const fired = await api.slo.runOnce();
    expect(fired.filter((t) => t.slo === "SLO-01").map((t) => t.rule.id)).toEqual(["fast", "slow", "ticket"]);
    expect((await api.slo.runOnce()).filter((t) => t.slo === "SLO-01")).toEqual([]);
    await api.slo.flush();
    const alerts = received.map((r) => ({ r, body: JSON.parse(r.body) })).filter(({ body }) => body.slo === "SLO-01");
    expect(alerts.map(({ body }) => body.rule)).toEqual(["fast", "slow", "ticket"]);
    const fast = alerts[0];
    expect(fast?.body).toMatchObject({ type: "slo.alert", state: "firing", runbook: "RB-03", severity: "page" });
    const signature = String(fast?.r.headers["ar-signature"]);
    expect(verifyWebhookSignature(SECRET, signature, fast?.r.body ?? "", Math.floor(Date.now() / 1000))).toBe(true);
    for (const value of [organizationId, appId]) expect(fast?.r.body).not.toContain(value);
  });
});
