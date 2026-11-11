import { once } from "node:events";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import {
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  canarySignalId,
  DETECTION_RULES,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_CANARIES,
  ListIncidentsResponseSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { newId, verifyWebhookSignature } from "@antireverse/protocol/server";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { type RunningApi, startApi } from "../src/server.ts";
import { batchOf, bearer, captureLogger, json, shieldEvent, tick, within } from "./helpers.ts";

interface Hit {
  headers: IncomingMessage["headers"];
  body: string;
}

async function receiver(answerAfterMs = 0) {
  const hits: Hit[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      hits.push({ headers: req.headers, body: Buffer.concat(chunks).toString("utf8") });
      setTimeout(() => res.writeHead(204).end(), answerAfterMs);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address() as AddressInfo;
  return {
    hits,
    url: `http://127.0.0.1:${port}/hook`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

async function setUp(api: RunningApi, url: string) {
  const org = CreateOrganizationResponseSchema.parse(
    await (await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }))).json(),
  );
  const admin = org.admin_key.key;
  const app = CreateAppResponseSchema.parse(
    await (await fetch(`${api.url}/v1/apps`, json({ name: "Storefront" }, bearer(admin)))).json(),
  );
  const created = await fetch(
    `${api.url}/v1/alert-channels`,
    json({ kind: "webhook", name: "Local", url }, bearer(admin)),
  );
  return { admin, organizationId: org.organization.id, appId: app.app.id, shield: app.shield_key.key, created };
}

const blockedBatch = () =>
  batchOf(
    Array.from({ length: DETECTION_RULES[0].threshold }, (_, i) => ({
      ...shieldEvent(Date.now() + i),
      decision: {
        action: "block",
        mode: "enforce",
        rule_id: null,
        policy_version: 1,
        containment_id: null,
        patch_id: null,
        patch_body: null,
      },
    })),
  );

describe("startApi: detection and alerts", () => {
  const running: RunningApi[] = [];
  const closers: (() => Promise<void>)[] = [];
  afterEach(() => {
    vi.unstubAllEnvs();
  });
  afterAll(async () => {
    for (const api of running) await api.close();
    for (const close of closers) await close();
  });

  it("detects a blocked burst and delivers one signed incident.opened alert to a local webhook", async () => {
    const r = await receiver();
    closers.push(r.close);
    const logger = captureLogger();
    const api = await startApi({
      logger,
      allowPrivateAlertUrls: true,
      consoleUrl: "http://console.example:3000",
      alertBackoffMs: 5,
    });
    running.push(api);
    const { admin, shield, created } = await setUp(api, r.url);
    expect(created.status).toBe(201);
    const { signing_secret: secret } = CreateAlertChannelResponseSchema.parse(await created.json());

    const ingest = await fetch(`${api.url}/v1/events`, json(blockedBatch(), bearer(shield)));
    expect(ingest.status).toBe(202);

    await within(
      (async () => {
        while (r.hits.length === 0) await tick(10);
      })(),
      5_000,
      "the alert",
    );
    const hit = r.hits[0];
    const nowS = Math.floor(Date.now() / 1_000);
    expect(verifyWebhookSignature(String(secret), String(hit?.headers["ar-signature"]), String(hit?.body), nowS)).toBe(
      true,
    );
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(String(hit?.body)));
    expect(payload.type).toBe("incident.opened");
    expect(payload.console_url).toBe(`http://console.example:3000/incidents/${payload.incident?.id}`);

    const list = ListIncidentsResponseSchema.parse(
      await (await fetch(`${api.url}/v1/incidents`, { headers: bearer(admin) })).json(),
    );
    expect(list.incidents.map((incident) => incident.id)).toEqual([payload.incident?.id]);

    await tick(50);
    expect(r.hits).toHaveLength(1);
    for (const line of logger.lines) {
      expect(line).not.toContain(String(secret));
      expect(line).not.toContain(r.url);
    }
  });

  it("wires the publish hook: failures naming a version published a moment ago open Credential stuffing, not a Failed sign-in burst", async () => {
    const r = await receiver();
    closers.push(r.close);
    const api = await startApi({ logger: captureLogger(), allowPrivateAlertUrls: true, alertBackoffMs: 5 });
    running.push(api);
    const { admin, shield, appId } = await setUp(api, r.url);
    const publish = async (rules: unknown[]) => {
      const res = await fetch(`${api.url}/v1/apps/${appId}/policies/development`, {
        ...json({ rules }, bearer(admin)),
        method: "PUT",
      });
      expect(res.status).toBe(201);
    };
    const failures = (version: number, count: number, status: number) =>
      batchOf(
        Array.from({ length: count }, (_, i) => ({
          ...shieldEvent(Date.now() + i),
          request: { method: "POST", route: "/login", status, latency_ms: 1 },
          // A Shield from before plan amendment A7: no limit_rule_id, so the coverage guess judges it.
          decision: (({ limit_rule_id: _stamp, ...legacy }) => ({ ...legacy, policy_version: version }))(
            shieldEvent(0).decision,
          ),
          actor: { ip_prefix: "203.0.113.0/24", ip_hash: `iph_${String(i).padStart(32, "0")}` },
        })),
      );
    const rules = async () =>
      ListIncidentsResponseSchema.parse(
        await (await fetch(`${api.url}/v1/incidents`, { headers: bearer(admin) })).json(),
      ).incidents.map((incident) => incident.rule);

    // Version 1 without a limit Rule; one Event makes the Detector read that it is the latest.
    await publish([{ name: "Admin", path: "/api/admin/**" }]);
    expect((await fetch(`${api.url}/v1/events`, json(failures(1, 1, 401), bearer(shield)))).status).toBe(202);
    await tick(100);
    // Version 2 protects the login route; the failures naming it follow at once.
    await publish([
      {
        name: "Login protection",
        path: "/login",
        methods: ["POST"],
        limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
      },
    ]);
    expect((await fetch(`${api.url}/v1/events`, json(failures(2, 50, 401), bearer(shield)))).status).toBe(202);
    await within(
      (async () => {
        while ((await rules()).length === 0) await tick(10);
      })(),
      5_000,
      "the Incident",
    );
    await tick(100);
    expect(await rules()).toEqual(["credential-stuffing"]);
  });

  it("drains an alert in flight on close() before the database closes", async () => {
    const r = await receiver(200);
    closers.push(r.close);
    const api = await startApi({ logger: captureLogger(), allowPrivateAlertUrls: true, alertBackoffMs: 5 });
    const { shield, organizationId } = await setUp(api, r.url);
    expect((await fetch(`${api.url}/v1/events`, json(blockedBatch(), bearer(shield)))).status).toBe(202);
    await within(
      (async () => {
        while (r.hits.length === 0) await tick(5);
      })(),
      5_000,
      "the alert request",
    );
    // The receiver answers after 200 ms: close() waits for the answer and its delivery record, then closes
    // the database.
    const { db } = api;
    const originalClose = db.close.bind(db);
    let deliveriesAtClose = -1;
    db.close = async () => {
      deliveriesAtClose = await db.tx({ organizationId }, async (q) => {
        const { rows } = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM alert_deliveries");
        return rows[0]?.n ?? -1;
      });
      return originalClose();
    };
    await within(api.close(), 5_000, "the server to stop");
    expect(deliveriesAtClose).toBe(1);
  });

  it("reads AR_ALLOW_PRIVATE_ALERT_URLS: private destinations are refused unless it is 1", async () => {
    const off = await startApi({ logger: captureLogger() });
    running.push(off);
    const refused = await setUp(off, "http://127.0.0.1:39901/hook");
    expect(refused.created.status).toBe(400);

    vi.stubEnv("AR_ALLOW_PRIVATE_ALERT_URLS", "1");
    const on = await startApi({ logger: captureLogger() });
    running.push(on);
    const accepted = await setUp(on, "http://127.0.0.1:39901/hook");
    expect(accepted.created.status).toBe(201);

    // The option wins over the environment.
    const overridden = await startApi({ logger: captureLogger(), allowPrivateAlertUrls: false });
    running.push(overridden);
    expect((await setUp(overridden, "http://127.0.0.1:39901/hook")).created.status).toBe(400);
  });

  it("reads AR_CONSOLE_URL for the links in alerts", async () => {
    vi.stubEnv("AR_CONSOLE_URL", "https://console.example.org");
    const r = await receiver();
    closers.push(r.close);
    const api = await startApi({ logger: captureLogger(), allowPrivateAlertUrls: true, alertBackoffMs: 5 });
    running.push(api);
    const { shield } = await setUp(api, r.url);
    await fetch(`${api.url}/v1/events`, json(blockedBatch(), bearer(shield)));
    await within(
      (async () => {
        while (r.hits.length === 0) await tick(10);
      })(),
      5_000,
      "the alert",
    );
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(String(r.hits[0]?.body)));
    expect(payload.console_url).toBe(`https://console.example.org/incidents/${payload.incident?.id}`);
  });

  it("alerts a Canary Incident once, with its canary_id and build_id in the signed payload and no Canary value", async () => {
    const r = await receiver();
    closers.push(r.close);
    const logger = captureLogger();
    const api = await startApi({ logger, allowPrivateAlertUrls: true, alertBackoffMs: 5 });
    running.push(api);
    const { admin, appId, shield, created } = await setUp(api, r.url);
    const { signing_secret: secret } = CreateAlertChannelResponseSchema.parse(await created.json());
    const manifest = { ...EXAMPLE_BUILD_MANIFEST, build_id: newId("bld"), app_id: appId, canaries: EXAMPLE_CANARIES };
    const registered = await fetch(`${api.url}/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)));
    expect(registered.status).toBe(201);
    const key = EXAMPLE_CANARIES[0];
    const event = { ...shieldEvent(Date.now()), signals: [{ id: canarySignalId(String(key?.id)), confidence: 1 }] };
    expect((await fetch(`${api.url}/v1/events`, json(batchOf([event]), bearer(shield)))).status).toBe(202);

    await within(
      (async () => {
        while (r.hits.length === 0) await tick(10);
      })(),
      5_000,
      "the alert",
    );
    const hit = r.hits[0];
    const nowS = Math.floor(Date.now() / 1_000);
    expect(verifyWebhookSignature(String(secret), String(hit?.headers["ar-signature"]), String(hit?.body), nowS)).toBe(
      true,
    );
    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(String(hit?.body)));
    expect(payload.incident).toMatchObject({
      rule: "canary-touched",
      title: "Canary used",
      severity: "high",
      canary_id: key?.id,
      build_id: manifest.build_id,
    });
    for (const canary of EXAMPLE_CANARIES) {
      expect(String(hit?.body)).not.toContain(canary.value);
      for (const line of logger.lines) expect(line).not.toContain(canary.value);
    }
    await tick(50);
    expect(r.hits).toHaveLength(1);
  });
});
