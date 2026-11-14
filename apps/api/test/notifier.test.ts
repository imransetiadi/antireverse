import { once } from "node:events";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import {
  AlertDeliverySchema,
  DETECTION_RULES,
  type Incident,
  IncidentSchema,
  WebhookAlertPayloadSchema,
} from "@antireverse/protocol";
import { generateSigningSecret, newId, verifyWebhookSignature } from "@antireverse/protocol/server";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { type AlertFetch, createNotifier, type NotifierDeps } from "../src/notify/notifier.ts";
import type { Resolve } from "../src/notify/ssrf.ts";
import { insertChannel } from "../src/stores/alert-channels.ts";
import { recordDetection } from "../src/stores/incidents.ts";
import { captureLogger, createAppFor, createOrganization, makeTestApi, type TestApi, within } from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const CONSOLE = "http://console.test";

interface Received {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body: string;
}

interface Receiver {
  url: string;
  port: number;
  received: Received[];
  /** Answers each request; the default answers 200 with a short body. */
  handler: (req: Received, res: ServerResponse) => void;
  close(): Promise<void>;
}

const receivers: Receiver[] = [];

async function receiver(): Promise<Receiver> {
  const received: Received[] = [];
  const state: Receiver = {
    url: "",
    port: 0,
    received,
    handler: (_, res) => res.writeHead(200, { "content-type": "text/plain" }).end("ok"),
    close: async () => {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const entry = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      received.push(entry);
      state.handler(entry, res);
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  state.port = (server.address() as AddressInfo).port;
  state.url = `http://127.0.0.1:${state.port}/hooks/ar`;
  receivers.push(state);
  return state;
}

describe("notifier", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let organizationId: string;
  let otherOrganizationId: string;
  let appId: string;
  let slackAppId: string;
  let otherAppId: string;
  /** Every URL and secret handed to a channel: none may appear in a log line or a delivery record. */
  const secrets: string[] = [];
  const logger = captureLogger();

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    organizationId = a.organization.id;
    otherOrganizationId = b.organization.id;
    otherAppId = (await createAppFor(api, b.admin_key.key, { name: "Other storefront" })).app.id;
    appId = (await createAppFor(api, a.admin_key.key, { name: "Storefront" })).app.id;
    slackAppId = (await createAppFor(api, a.admin_key.key, { name: "Shop <!channel> & co" })).app.id;
  });
  afterEach(async () => {
    for (const r of receivers.splice(0)) await r.close();
    // Each test starts without channels: an Incident alerts every channel of its Organization.
    for (const org of [organizationId, otherOrganizationId]) {
      await api.db.tx({ organizationId: org }, (q) => q.query("DELETE FROM alert_channels"));
    }
  });
  afterAll(async () => {
    // Nothing secret reached a log line or a delivery record, in any test of this file.
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ row: unknown }>("SELECT row_to_json(d) AS row FROM alert_deliveries d"),
    );
    expect(rows.length).toBeGreaterThan(5);
    const stored = JSON.stringify(rows);
    expect(logger.lines.length).toBeGreaterThan(0);
    for (const secret of secrets) {
      expect(stored).not.toContain(secret);
      for (const line of logger.lines) expect(line).not.toContain(secret);
    }
    for (const line of logger.lines) expect(line).not.toMatch(/whsec_|127\.0\.0\.1|hooks\.example\.com/);
    await api.close();
  });

  /** Stores a channel directly (the routes have their own tests) and returns its id and secret. */
  async function channel(kind: "webhook" | "slack", url: string, org = organizationId) {
    const id = newId("chn");
    const signingSecret = kind === "webhook" ? generateSigningSecret() : null;
    secrets.push(url);
    if (signingSecret !== null) secrets.push(signingSecret);
    await api.db.tx({ organizationId: org }, (q) =>
      insertChannel(q, { id, organizationId: org, kind, name: `${kind} channel`, url, signingSecret }),
    );
    return { id, signingSecret };
  }

  async function removeChannel(id: string, org = organizationId) {
    await api.db.tx({ organizationId: org }, (q) => q.query("DELETE FROM alert_channels WHERE id = $1", [id]));
  }

  /** Opens a real Incident (deliveries refer to it) on a fresh prefix. */
  let prefixCounter = 0;
  async function openIncident(forApp = appId, org = organizationId): Promise<Incident> {
    prefixCounter++;
    const ts = new Date(clock.ms).toISOString();
    const result = await api.db.tx({ organizationId: org }, (q) =>
      recordDetection(q, {
        organizationId: org,
        appId: forApp,
        environment: "development",
        rule: DETECTION_RULES[0],
        ipPrefix: `192.0.${prefixCounter}.0/24`,
        count: 20,
        windowStart: ts,
        windowEnd: ts,
        detectedAt: now(),
      }),
    );
    expect(result.opened).toBe(true);
    return IncidentSchema.parse(result.incident);
  }

  async function deliveriesOf(channelId: string) {
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{
        id: string;
        channel_id: string;
        incident_id: string | null;
        attempt: number;
        outcome: string;
        status_code: number | null;
        at: Date;
      }>("SELECT * FROM alert_deliveries WHERE channel_id = $1 ORDER BY attempt, at, id", [channelId]),
    );
    return rows.map((row) => AlertDeliverySchema.parse({ ...row, at: row.at.toISOString() }));
  }

  function notifier(overrides: Partial<NotifierDeps> = {}) {
    const sleeps: number[] = [];
    const instance = createNotifier({
      db: api.db,
      now,
      allowPrivate: true,
      consoleUrl: CONSOLE,
      backoffMs: 7,
      logger,
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      ...overrides,
    });
    return { instance, sleeps };
  }

  it("records SLO-09 per channel: delivered within 60 s of the Incident's creation is good, late is bad, a destination's failure is not counted (slice 18d)", async () => {
    const recorded: [string, boolean, number][] = [];
    const slo = { record: (id: string, good: boolean, ms: number) => recorded.push([id, good, ms]) };
    const fast = await receiver();
    const failing = await receiver();
    // The tenant's endpoint answers 500: the destination's failure (Jev, exclude_destination_failures, 0.83).
    failing.handler = (_, res) => res.writeHead(500).end();
    await channel("webhook", fast.url);
    const broken = await channel("webhook", failing.url);
    // Nobody listens there: connection refused, also the destination's.
    const closed = await receiver();
    const refusedUrl = closed.url;
    await closed.close();
    await channel("webhook", refusedUrl);
    const incident = await openIncident();
    clock.ms += 5_000;
    const { instance } = notifier({ slo });
    instance.incidentOpened(incident, organizationId);
    await instance.drain();
    expect(recorded).toEqual([["SLO-09", true, 5_000]]);

    // Delivered, but 61 s after the Incident's creation: bad. A test alert is not counted.
    recorded.length = 0;
    await removeChannel(broken.id);
    const late = await openIncident();
    clock.ms += 61_000;
    const second = notifier({ slo }).instance;
    second.incidentOpened(late, organizationId);
    await second.drain();
    expect(recorded).toEqual([["SLO-09", false, 61_000]]);
  });

  it("records SLO-09 bad for an alert dropped (queue full, stopped) or whose job failed before any channel (review M4)", async () => {
    const recorded: [string, boolean, number][] = [];
    const slo = { record: (id: string, good: boolean, ms: number) => recorded.push([id, good, ms]) };
    const r = await receiver();
    await channel("webhook", r.url);
    const incident = await openIncident();
    clock.ms += 2_000;

    // Its own logger: the file's logger counts queue-full drops elsewhere.
    const full = notifier({ slo, maxPending: 0, logger: captureLogger() }).instance;
    full.incidentOpened(incident, organizationId);
    await full.drain();
    expect(recorded).toEqual([["SLO-09", false, 2_000]]);

    recorded.length = 0;
    const stopped = notifier({ slo, logger: captureLogger() }).instance;
    await stopped.drain();
    stopped.incidentOpened(incident, organizationId);
    expect(recorded).toEqual([["SLO-09", false, 2_000]]);

    recorded.length = 0;
    const down = notifier({
      slo,
      logger: captureLogger(),
      db: { ...api.db, tx: () => Promise.reject(new Error("db down")) },
    }).instance;
    down.incidentOpened(incident, organizationId);
    await down.drain();
    expect(recorded).toEqual([["SLO-09", false, 2_000]]);
    expect(r.received).toHaveLength(0);
  });

  it("delivers a signed incident.opened webhook that verifies with the protocol's verifier", async () => {
    const r = await receiver();
    const { id, signingSecret } = await channel("webhook", r.url);
    const incident = await openIncident();
    const { instance } = notifier();

    instance.incidentOpened(incident, organizationId);
    await instance.drain();

    expect(r.received).toHaveLength(1);
    const [request] = r.received;
    expect(request?.method).toBe("POST");
    expect(request?.url).toBe("/hooks/ar");
    expect(request?.headers["content-type"]).toBe("application/json");
    const header = String(request?.headers["ar-signature"]);
    expect(header).toMatch(/^t=[0-9]+,v1=[0-9a-f]{64}$/);
    expect(header).toContain(`t=${Math.floor(clock.ms / 1_000)},`);
    expect(
      verifyWebhookSignature(String(signingSecret), header, String(request?.body), Math.floor(clock.ms / 1_000)),
    ).toBe(true);
    expect(
      verifyWebhookSignature(generateSigningSecret(), header, String(request?.body), Math.floor(clock.ms / 1_000)),
    ).toBe(false);

    const payload = WebhookAlertPayloadSchema.parse(JSON.parse(String(request?.body)));
    expect(payload).toEqual({ type: "incident.opened", incident, console_url: `${CONSOLE}/incidents/${incident.id}` });

    const deliveries = await deliveriesOf(id);
    expect(deliveries).toEqual([
      {
        id: expect.stringMatching(/^dlv_/),
        channel_id: id,
        incident_id: incident.id,
        attempt: 1,
        outcome: "delivered",
        status_code: 200,
        at: now().toISOString(),
      },
    ]);
  });

  it("delivers the Slack text format, unsigned, escaping the App name", async () => {
    const r = await receiver();
    const { id } = await channel("slack", r.url);
    const incident = await openIncident(slackAppId);
    const { instance } = notifier();

    instance.incidentOpened(incident, organizationId);
    await instance.drain();

    expect(r.received).toHaveLength(1);
    expect(r.received[0]?.headers["ar-signature"]).toBeUndefined();
    expect(JSON.parse(String(r.received[0]?.body))).toEqual({
      text: `High — Blocked burst on Shop &lt;!channel&gt; &amp; co (development): ${CONSOLE}/incidents/${incident.id}`,
    });
    expect((await deliveriesOf(id)).map((d) => d.outcome)).toEqual(["delivered"]);
  });

  it("retries a failing channel at most 3 times with doubling backoff, recording every attempt", async () => {
    const r = await receiver();
    let calls = 0;
    r.handler = (_, res) => {
      calls++;
      res.writeHead(calls < 3 ? 500 : 204).end();
    };
    const { id } = await channel("webhook", r.url);
    const incident = await openIncident();
    const { instance, sleeps } = notifier();

    instance.incidentOpened(incident, organizationId);
    await instance.drain();

    expect(r.received).toHaveLength(3);
    expect(sleeps).toEqual([7, 14]);
    expect((await deliveriesOf(id)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", 500],
      [2, "failed", 500],
      [3, "delivered", 204],
    ]);
  });

  it("gives up after 3 failed attempts", async () => {
    const r = await receiver();
    r.handler = (_, res) => res.writeHead(503).end("unavailable");
    const { id } = await channel("webhook", r.url);
    const { instance, sleeps } = notifier();

    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();

    expect(r.received).toHaveLength(3);
    expect(sleeps).toEqual([7, 14]);
    expect((await deliveriesOf(id)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", 503],
      [2, "failed", 503],
      [3, "failed", 503],
    ]);
  });

  it("uses 1,000 / 2,000 ms backoff by default", async () => {
    const r = await receiver();
    r.handler = (_, res) => res.writeHead(500).end();
    await channel("webhook", r.url);
    const { instance, sleeps } = notifier({ backoffMs: undefined });
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(sleeps).toEqual([1_000, 2_000]);
  });

  it("does not follow a redirect: a 3xx is a failed attempt and the target is never contacted", async () => {
    const target = await receiver();
    const r = await receiver();
    r.handler = (_, res) => res.writeHead(302, { location: target.url }).end();
    const { id } = await channel("webhook", r.url);
    const { instance } = notifier();

    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();

    expect(target.received).toHaveLength(0);
    expect((await deliveriesOf(id)).map((d) => [d.outcome, d.status_code])).toEqual([
      ["failed", 302],
      ["failed", 302],
      ["failed", 302],
    ]);
  });

  it("records a timed-out attempt as failed without a status code", async () => {
    const r = await receiver();
    r.handler = () => {};
    const { id } = await channel("webhook", r.url);
    const { instance } = notifier({ timeoutMs: 100 });

    instance.incidentOpened(await openIncident(), organizationId);
    await within(instance.drain(), 5_000, "the notifier to drain");

    expect((await deliveriesOf(id)).map((d) => [d.outcome, d.status_code])).toEqual([
      ["failed", null],
      ["failed", null],
      ["failed", null],
    ]);
  });

  it("reads no more than 4 KB of a response: an endless body does not hold the delivery", async () => {
    const r = await receiver();
    r.handler = (_, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.write("x".repeat(64 * 1024));
      // Never ends.
    };
    const { id } = await channel("webhook", r.url);
    const { instance } = notifier({ timeoutMs: 10_000 });

    instance.incidentOpened(await openIncident(), organizationId);
    await within(instance.drain(), 3_000, "the notifier to drain");
    expect((await deliveriesOf(id)).map((d) => [d.outcome, d.status_code])).toEqual([["delivered", 200]]);
  });

  it("never lets a failing channel hold back another", async () => {
    const fast = await receiver();
    const slow = await receiver();
    let releaseSlow: () => void = () => {};
    const slowReleased = new Promise<void>((resolve) => {
      releaseSlow = resolve;
    });
    slow.handler = (_, res) => {
      void slowReleased.then(() => res.writeHead(500).end());
    };
    fast.handler = (_, res) => {
      res.writeHead(200).end();
      releaseSlow();
    };
    // The slow channel is created first, so it is not simply served after the fast one.
    await channel("webhook", slow.url);
    const fastChannel = await channel("webhook", fast.url);
    const { instance } = notifier({ timeoutMs: 3_000 });

    instance.incidentOpened(await openIncident(), organizationId);
    await within(instance.drain(), 5_000, "the notifier to drain");
    expect((await deliveriesOf(fastChannel.id)).map((d) => d.outcome)).toEqual(["delivered"]);
  });

  it("stops retrying once the channel is deleted", async () => {
    const r = await receiver();
    r.handler = (_, res) => res.writeHead(500).end();
    const { id } = await channel("webhook", r.url);
    const { instance } = notifier({
      sleep: async () => {
        await removeChannel(id);
      },
    });
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(r.received).toHaveLength(1);
  });

  it("alerts only the Incident's own Organization", async () => {
    const mine = await receiver();
    const theirs = await receiver();
    await channel("webhook", mine.url);
    await channel("webhook", theirs.url, otherOrganizationId);
    const { instance } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(mine.received).toHaveLength(1);
    expect(theirs.received).toHaveLength(0);
  });

  describe("fairness and bounds (F2, F3)", () => {
    it("caps pending alerts per Organization: one Organization's hanging channels never drop another's alert", async () => {
      const hanging = await receiver();
      hanging.handler = () => {};
      const healthy = await receiver();
      await channel("webhook", hanging.url);
      const theirs = await channel("webhook", healthy.url, otherOrganizationId);
      const { instance } = notifier({ timeoutMs: 30_000, drainMs: 300, maxPending: 5, maxPendingPerOrg: 2 });

      const flood: Incident[] = [];
      for (let i = 0; i < 5; i++) flood.push(await openIncident());
      for (const incident of flood) instance.incidentOpened(incident, organizationId);
      const other = await openIncident(otherAppId, otherOrganizationId);
      instance.incidentOpened(other, otherOrganizationId);

      await within(
        (async () => {
          while (healthy.received.length === 0) await new Promise((resolve) => setTimeout(resolve, 10));
        })(),
        3_000,
        "the other Organization's alert",
      );
      const { rows } = await api.db.tx({ organizationId: otherOrganizationId }, (q) =>
        q.query<{ outcome: string }>("SELECT outcome FROM alert_deliveries WHERE channel_id = $1", [theirs.id]),
      );
      await within(
        (async () => {
          while (rows.length === 0) {
            await new Promise((resolve) => setTimeout(resolve, 10));
            const again = await api.db.tx({ organizationId: otherOrganizationId }, (q) =>
              q.query<{ outcome: string }>("SELECT outcome FROM alert_deliveries WHERE channel_id = $1", [theirs.id]),
            );
            rows.push(...again.rows);
          }
        })(),
        3_000,
        "the other Organization's delivery record",
      );
      expect(rows.map((row) => row.outcome)).toEqual(["delivered"]);
      // Organization A got its 2 in; the other 3 were dropped and logged with ids only.
      expect(hanging.received.length).toBe(2);
      const dropped = logger.lines.filter((line) => line.startsWith("alert dropped"));
      expect(dropped.filter((line) => line.includes("reason=queue-full"))).toHaveLength(3);
      for (const incident of flood.slice(2)) expect(dropped.some((line) => line.includes(incident.id))).toBe(true);
      await instance.drain();
    });

    it("bounds one attempt, host lookup included, by the attempt timeout", async () => {
      const { id } = await channel("webhook", "https://hanging.example.com/ar");
      let lookups = 0;
      const { instance } = notifier({
        allowPrivate: false,
        timeoutMs: 100,
        resolve: () => {
          lookups++;
          return new Promise(() => {});
        },
        fetch: async () => {
          throw new Error("never reached");
        },
      });
      instance.incidentOpened(await openIncident(), organizationId);
      const started = Date.now();
      await within(instance.drain(), 2_000, "the drain");
      expect(Date.now() - started).toBeLessThan(1_500);
      expect(lookups).toBe(3);
      expect((await deliveriesOf(id)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
        [1, "failed", null],
        [2, "failed", null],
        [3, "failed", null],
      ]);
    });
  });

  describe("SSRF check at send time", () => {
    function fakeFetch() {
      const calls: { url: string; address: string; family: number }[] = [];
      const fetch: AlertFetch = async (url, _init, pin) => {
        calls.push({ url, address: pin.address, family: pin.family });
        return new Response("ok", { status: 200 });
      };
      return { calls, fetch };
    }

    it("refuses on every attempt when the host now resolves to a private address, and sends nothing", async () => {
      const answer = { address: "10.0.0.7" };
      const resolve: Resolve = async () => [{ address: answer.address, family: 4 }];
      const { calls, fetch } = fakeFetch();
      const { id } = await channel("webhook", "https://hooks.example.com/rebind");
      const { instance } = notifier({ allowPrivate: false, resolve, fetch });

      instance.incidentOpened(await openIncident(), organizationId);
      await instance.drain();
      expect(calls).toHaveLength(0);
      expect((await deliveriesOf(id)).map((d) => [d.outcome, d.status_code])).toEqual([
        ["failed", null],
        ["failed", null],
        ["failed", null],
      ]);
      await removeChannel(id);
    });

    it("checks again on each attempt and connects to the vetted address", async () => {
      const answers = ["127.0.0.1", "93.184.216.34"];
      const resolve: Resolve = async () => [{ address: answers.shift() ?? "10.9.9.9", family: 4 }];
      const { calls, fetch } = fakeFetch();
      const { id } = await channel("webhook", "https://hooks.example.com/pinned");
      const { instance } = notifier({ allowPrivate: false, resolve, fetch });

      instance.incidentOpened(await openIncident(), organizationId);
      await instance.drain();
      expect(calls).toEqual([{ url: "https://hooks.example.com/pinned", address: "93.184.216.34", family: 4 }]);
      expect((await deliveriesOf(id)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
        [1, "failed", null],
        [2, "delivered", 200],
      ]);
      await removeChannel(id);
    });

    it("refuses http: at send time without the flag", async () => {
      const { calls, fetch } = fakeFetch();
      const { id } = await channel("webhook", "http://hooks.example.com/plain");
      const { instance } = notifier({
        allowPrivate: false,
        resolve: async () => [{ address: "93.184.216.34", family: 4 }],
        fetch,
      });
      instance.incidentOpened(await openIncident(), organizationId);
      await instance.drain();
      expect(calls).toHaveLength(0);
      expect((await deliveriesOf(id)).map((d) => d.outcome)).toEqual(["failed", "failed", "failed"]);
      await removeChannel(id);
    });

    it("pins the default transport to the vetted address while keeping the host name", async () => {
      const r = await receiver();
      const url = `http://alerts.test:${r.port}/hooks/pinned`;
      const { id } = await channel("webhook", url);
      // alerts.test resolves nowhere in real DNS: only the pinned address can reach the receiver.
      const { instance } = notifier({ resolve: async () => [{ address: "127.0.0.1", family: 4 }] });

      instance.incidentOpened(await openIncident(), organizationId);
      await instance.drain();
      expect(r.received).toHaveLength(1);
      expect(r.received[0]?.headers.host).toBe(`alerts.test:${r.port}`);
      expect((await deliveriesOf(id)).map((d) => d.outcome)).toEqual(["delivered"]);
      await removeChannel(id);
    });
  });

  describe("test alerts", () => {
    it("sends one signed test alert synchronously and returns its delivery", async () => {
      const r = await receiver();
      const { id, signingSecret } = await channel("webhook", r.url);
      const { instance } = notifier();

      const delivery = await instance.test(id, organizationId);
      expect(delivery).toEqual({
        id: expect.stringMatching(/^dlv_/),
        channel_id: id,
        incident_id: null,
        attempt: 1,
        outcome: "delivered",
        status_code: 200,
        at: now().toISOString(),
      });
      expect(r.received).toHaveLength(1);
      const body = String(r.received[0]?.body);
      expect(JSON.parse(body)).toEqual({ type: "test", incident: null, console_url: null });
      const header = String(r.received[0]?.headers["ar-signature"]);
      expect(verifyWebhookSignature(String(signingSecret), header, body, Math.floor(clock.ms / 1_000))).toBe(true);
      expect(await deliveriesOf(id)).toEqual([delivery]);
      await removeChannel(id);
    });

    it("makes one attempt only, and returns the failure", async () => {
      const r = await receiver();
      r.handler = (_, res) => res.writeHead(500).end();
      const { id } = await channel("slack", r.url);
      const { instance, sleeps } = notifier();
      const delivery = await instance.test(id, organizationId);
      expect(delivery).toMatchObject({ attempt: 1, outcome: "failed", status_code: 500 });
      expect(r.received).toHaveLength(1);
      expect(JSON.parse(String(r.received[0]?.body))).toEqual({ text: expect.stringContaining("Test alert") });
      expect(sleeps).toEqual([]);
      await removeChannel(id);
    });

    it("returns null for an unknown channel or another Organization's", async () => {
      const r = await receiver();
      const { id } = await channel("webhook", r.url, otherOrganizationId);
      const { instance } = notifier();
      expect(await instance.test(newId("chn"), organizationId)).toBeNull();
      expect(await instance.test(id, organizationId)).toBeNull();
      expect(r.received).toHaveLength(0);
      await removeChannel(id, otherOrganizationId);
    });
  });

  describe("drain", () => {
    it("waits for deliveries in flight", async () => {
      const r = await receiver();
      r.handler = (_, res) => {
        setTimeout(() => res.writeHead(200).end(), 150);
      };
      const { id } = await channel("webhook", r.url);
      const { instance } = notifier();
      instance.incidentOpened(await openIncident(), organizationId);
      await instance.drain();
      expect((await deliveriesOf(id)).map((d) => d.outcome)).toEqual(["delivered"]);
      await removeChannel(id);
    });

    it("waits no longer than its bound, and accepts no new alert afterwards", async () => {
      const r = await receiver();
      r.handler = () => {};
      const { id } = await channel("webhook", r.url);
      const { instance } = notifier({ timeoutMs: 30_000, drainMs: 100 });
      instance.incidentOpened(await openIncident(), organizationId);
      const started = Date.now();
      await within(instance.drain(), 2_000, "the bounded drain");
      expect(Date.now() - started).toBeLessThan(1_500);

      const before = r.received.length;
      instance.incidentOpened(await openIncident(), organizationId);
      await instance.drain();
      expect(r.received.length).toBe(before);
      await removeChannel(id);
    });
  });
});
