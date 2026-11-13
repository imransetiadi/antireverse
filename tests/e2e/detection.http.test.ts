// Slice 06 over HTTP: a burst of requests blocked by Shield on the reference target (ar-range) becomes a
// Detection, opens a High Incident and sends one signed webhook alert to a local receiver; a second burst joins
// the Incident; acknowledge and resolve; a burst after resolve opens a new Incident; tenancy and key roles hold.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  BLOCK_RESPONSE_BODY,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Incident,
  IncidentDetailResponseSchema,
  ListAlertChannelsResponseSchema,
  ListIncidentsResponseSchema,
  PolicyResponseSchema,
  TestAlertChannelResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { verifyWebhookSignature } from "@antireverse/protocol/server";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-14: a Detection is recorded within 10 s of the Event that completes it. */
const DETECTION_BUDGET_MS = 10_000;
/** PB-18: an alert arrives within 60 s; with the short test backoff it arrives in well under the test timeout. */
const ALERT_BUDGET_MS = 15_000;
/** The managed rule "Blocked burst": 20 enforced blocks from one network prefix within 5 minutes. */
const BURST = 20;
/** How long to listen for an alert that must not come. */
const QUIET_MS = 1_500;
const CONSOLE_URL = "http://127.0.0.1:39941";

interface Received {
  at: number;
  signature: string;
  rawBody: string;
}

let api: RunningApi;
let shield: Shield;
let range: http.Server;
let rangeUrl: string;
let receiver: http.Server;
let hookUrl: string;
let adminKey: string;
let shieldKey: string;
let appId: string;
let signingSecret: string;
let channelId: string;
const received: Received[] = [];
/** Timings observed by the bursts, reported by the last test. */
const timings: { incidentMs: number[]; alertMs: number[] } = { incidentMs: [], alertMs: [] };

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
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

async function listIncidents(key = adminKey, query = `?app_id=${appId}`): Promise<Incident[]> {
  const response = await call(`/v1/incidents${query}`, { key });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents;
}

/** Blocked-burst Incidents only (the e2e must never see another rule; asserted separately). */
async function blockedIncidents(key = adminKey, status = ""): Promise<Incident[]> {
  const incidents = await listIncidents(key, `?app_id=${appId}${status === "" ? "" : `&status=${status}`}`);
  return incidents.filter((incident) => incident.rule === "blocked-burst");
}

/** The incident.opened alerts received for one rule. */
const opened = (rule = "blocked-burst") =>
  received.filter((r) => {
    const body = JSON.parse(r.rawBody) as { type: string; incident: Incident | null };
    return body.type === "incident.opened" && body.incident?.rule === rule;
  });

/** Sends BURST requests to the blocked admin route through Shield; resolves with the time of the last one. */
async function burst(): Promise<number> {
  for (let i = 0; i < BURST; i++) {
    const response = await fetch(`${rangeUrl}/api/admin/reports`);
    expect(response.status).toBe(403);
    expect(await response.text()).toBe(BLOCK_RESPONSE_BODY);
  }
  return Date.now();
}

beforeAll(async () => {
  receiver = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      received.push({
        at: Date.now(),
        signature: String(req.headers["ar-signature"] ?? ""),
        rawBody: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200).end();
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
  hookUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hooks/antireverse-e2e`;

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

  // The Enforce Rule that blocks the range's admin area, published as the slice 02 journey does.
  const published = await call(`/v1/apps/${appId}/policies/development`, {
    method: "PUT",
    key: adminKey,
    body: { rules: [{ name: "Admin area", path: "/api/admin/**", mode: "enforce" }] },
  });
  expect(published.status).toBe(201);
  const version = PolicyResponseSchema.parse(await published.json()).policy.version;

  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats()).toMatchObject({ policyVersion: version, lastPolicyError: null });

  range = http.createServer(createRangeServer({ shield }));
  await new Promise<void>((resolve) => range.listen(0, "127.0.0.1", resolve));
  rangeUrl = `http://127.0.0.1:${(range.address() as AddressInfo).port}`;

  const channel = await call("/v1/alert-channels", {
    method: "POST",
    key: adminKey,
    body: { kind: "webhook", name: "Ops webhook", url: hookUrl },
  });
  expect(channel.status).toBe(201);
  const body = CreateAlertChannelResponseSchema.parse(await channel.json());
  channelId = body.channel.id;
  signingSecret = body.signing_secret ?? "";
  expect(signingSecret).toMatch(/^whsec_/);
});

afterAll(async () => {
  await shield?.close();
  for (const server of [range, receiver]) {
    if (!server) continue;
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 06 detection path over HTTP", () => {
  it("opens a High Incident within 10 s of a burst of blocked requests, and alerts once with a valid signature", async () => {
    expect(await listIncidents()).toEqual([]);

    const last = await burst();
    const incident = await until("Incident opened", DETECTION_BUDGET_MS, async () => (await listIncidents())[0]);
    timings.incidentMs.push(Date.now() - last);
    expect(Date.now() - last).toBeLessThanOrEqual(DETECTION_BUDGET_MS);
    expect(incident).toMatchObject({
      app_id: appId,
      environment: "development",
      rule: "blocked-burst",
      severity: "high",
      title: "Blocked burst",
      status: "open",
      detection_count: 1,
    });
    // Every request came from 127.0.0.1, so the whole burst shares one network prefix.
    expect(incident.ip_prefix).toBe("127.0.0.0/24");

    const alert = await until("alert received", ALERT_BUDGET_MS, async () => opened()[0]);
    timings.alertMs.push(alert.at - last);

    // The signature verifies against the raw body with the secret shown at creation, and with nothing else.
    const nowS = Math.floor(Date.now() / 1000);
    expect(alert.signature).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
    expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, nowS)).toBe(true);
    const wrongSecret = `${signingSecret.slice(0, -1)}${signingSecret.endsWith("A") ? "B" : "A"}`;
    expect(verifyWebhookSignature(wrongSecret, alert.signature, alert.rawBody, nowS)).toBe(false);
    expect(verifyWebhookSignature(signingSecret, alert.signature, `${alert.rawBody} `, nowS)).toBe(false);

    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(alert.rawBody));
    expect(payload.type).toBe("incident.opened");
    expect(payload.incident).toEqual(incident);
    expect(payload.console_url).toBe(`${CONSOLE_URL}/incidents/${incident.id}`);
    // Exactly the documented keys: nothing else rides along.
    expect(Object.keys(JSON.parse(alert.rawBody)).sort()).toEqual(["console_url", "incident", "type"]);
    for (const leak of [adminKey, shieldKey, signingSecret, "aro_", "ark_", "whsec_", hookUrl, "reports"]) {
      expect(alert.rawBody).not.toContain(leak);
    }

    // The detail holds the Detection and Events as evidence (allowlisted, the blocked route template only).
    const detail = await call(`/v1/incidents/${incident.id}`, { key: adminKey });
    expect(detail.status).toBe(200);
    const { detections, evidence } = IncidentDetailResponseSchema.parse(await detail.json());
    expect(detections).toHaveLength(1);
    expect(detections[0]).toMatchObject({ rule: "blocked-burst", ip_prefix: "127.0.0.0/24", count: BURST });
    expect(evidence.length).toBeGreaterThan(0);
    for (const event of evidence) {
      expect(event.request).toMatchObject({ route: "/api/admin/**", status: 403 });
      expect(event.decision).toMatchObject({ action: "block", mode: "enforce" });
    }
    // 20 responses with status 403 stay below the 30 of "Failed sign-in burst": this is the only Incident.
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect(await listIncidents()).toHaveLength(1);
    expect(received.filter((r) => JSON.parse(r.rawBody).type === "incident.opened")).toHaveLength(1);
  });

  it("joins a second burst to the open Incident without a second alert", async () => {
    const [before] = await blockedIncidents();
    await burst();
    const joined = await until("second Detection joined", DETECTION_BUDGET_MS, async () => {
      const [incident] = await blockedIncidents();
      return incident && incident.detection_count === 2 ? incident : undefined;
    });
    expect(joined.id).toBe(before?.id);
    expect(await blockedIncidents()).toHaveLength(1);
    await new Promise((resolve) => setTimeout(resolve, QUIET_MS));
    expect(opened()).toHaveLength(1);

    // Shield's own enforced blocks answer 403 but are not failed sign-ins (plan amendment A7): 40 blocked
    // requests raise one Incident and one alert, never a "Failed sign-in burst".
    expect(await listIncidents()).toHaveLength(1);
    expect(opened("failed-signin-burst")).toHaveLength(0);
  });

  it("acknowledges, then resolves; an illegal transition is a conflict", async () => {
    const [incident] = await blockedIncidents();
    const id = incident?.id ?? "";
    const patch = (status: string) => call(`/v1/incidents/${id}`, { method: "PATCH", key: adminKey, body: { status } });

    const acknowledged = await patch("acknowledged");
    expect(acknowledged.status).toBe(200);
    expect(((await acknowledged.json()) as { incident: Incident }).incident.status).toBe("acknowledged");
    expect((await patch("acknowledged")).status).toBe(409);

    const resolved = await patch("resolved");
    expect(resolved.status).toBe(200);
    expect(((await resolved.json()) as { incident: Incident }).incident.status).toBe("resolved");
    expect((await patch("acknowledged")).status).toBe(409);
    expect((await blockedIncidents(adminKey, "resolved")).map((i) => i.id)).toEqual([id]);
  });

  it("opens a new Incident (never reopens a resolved one) and alerts again after a burst following resolve", async () => {
    const [resolved] = await blockedIncidents();
    const last = await burst();
    const fresh = await until("new Incident opened", DETECTION_BUDGET_MS, async () => {
      const open = await blockedIncidents(adminKey, "open");
      return open[0];
    });
    timings.incidentMs.push(Date.now() - last);
    expect(fresh.id).not.toBe(resolved?.id);
    expect(fresh).toMatchObject({ status: "open", detection_count: 1, severity: "high" });

    const alert = await until("second alert", ALERT_BUDGET_MS, async () => opened()[1]);
    timings.alertMs.push(alert.at - last);
    expect(verifyWebhookSignature(signingSecret, alert.signature, alert.rawBody, Math.floor(Date.now() / 1000))).toBe(
      true,
    );
    expect(WebhookAlertPayloadSchema.parse(JSON.parse(alert.rawBody)).incident?.id).toBe(fresh.id);

    // The resolved one stays resolved; newest first.
    const all = await blockedIncidents();
    expect(all.map((i) => [i.id, i.status])).toEqual([
      [fresh.id, "open"],
      [resolved?.id, "resolved"],
    ]);
    expect(opened()).toHaveLength(2);
    // Still no "Failed sign-in burst" from Shield's own blocks.
    expect((await listIncidents()).filter((incident) => incident.rule === "failed-signin-burst")).toHaveLength(0);
    expect(opened("failed-signin-burst")).toHaveLength(0);
  });

  it("sends a signed test alert and never shows the channel URL or secret again", async () => {
    const tested = await call(`/v1/alert-channels/${channelId}/test`, { method: "POST", key: adminKey });
    expect(tested.status).toBe(200);
    const { delivery } = TestAlertChannelResponseSchema.parse(await tested.json());
    expect(delivery).toMatchObject({
      channel_id: channelId,
      incident_id: null,
      outcome: "delivered",
      status_code: 200,
    });
    const test = received.find((r) => JSON.parse(r.rawBody).type === "test");
    expect(test).toBeDefined();
    expect(verifyWebhookSignature(signingSecret, test?.signature ?? "", test?.rawBody ?? "", Date.now() / 1000)).toBe(
      true,
    );

    const list = await call("/v1/alert-channels", { key: adminKey });
    expect(list.status).toBe(200);
    const text = await list.text();
    const { channels } = ListAlertChannelsResponseSchema.parse(JSON.parse(text));
    expect(channels.map((c) => c.id)).toEqual([channelId]);
    expect(channels[0]).toMatchObject({ kind: "webhook", host: "127.0.0.1", url_last4: "-e2e" });
    for (const leak of [hookUrl, "/hooks/antireverse", signingSecret, "whsec_", '"url"']) {
      expect(text).not.toContain(leak);
    }
  });

  it("keeps Incidents and channels away from another Organization and from a Shield key", async () => {
    const [incident] = await blockedIncidents();
    const id = incident?.id ?? "";
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    expect(await listIncidents(key, "")).toEqual([]);
    expect(await listIncidents(key, `?app_id=${appId}`)).toEqual([]);
    expect((await call(`/v1/incidents/${id}`, { key })).status).toBe(404);
    expect((await call(`/v1/incidents/${id}`, { method: "PATCH", key, body: { status: "acknowledged" } })).status).toBe(
      404,
    );
    const otherChannels = await call("/v1/alert-channels", { key });
    expect(ListAlertChannelsResponseSchema.parse(await otherChannels.json()).channels).toEqual([]);
    expect((await call(`/v1/alert-channels/${channelId}/test`, { method: "POST", key })).status).toBe(404);
    expect((await call(`/v1/alert-channels/${channelId}`, { method: "DELETE", key })).status).toBe(404);
    // Nothing changed for the owner.
    expect((await blockedIncidents()).find((i) => i.id === id)?.status).toBe("open");

    // A Shield key is not an admin key.
    expect((await call("/v1/incidents", { key: shieldKey })).status).toBe(403);
    expect((await call(`/v1/incidents/${id}`, { key: shieldKey })).status).toBe(403);
    expect(
      (await call(`/v1/incidents/${id}`, { method: "PATCH", key: shieldKey, body: { status: "resolved" } })).status,
    ).toBe(403);
    expect((await call("/v1/alert-channels", { key: shieldKey })).status).toBe(403);

    // Removing the channel: 204, then gone.
    expect((await call(`/v1/alert-channels/${channelId}`, { method: "DELETE", key: adminKey })).status).toBe(204);
    const after = await call("/v1/alert-channels", { key: adminKey });
    expect(ListAlertChannelsResponseSchema.parse(await after.json()).channels).toEqual([]);

    // Observed timings, for the slice report.
    console.info(
      `detection e2e: last blocked request -> Incident ${timings.incidentMs.join(", ")} ms; -> alert ${timings.alertMs.join(", ")} ms`,
    );
  });
});
