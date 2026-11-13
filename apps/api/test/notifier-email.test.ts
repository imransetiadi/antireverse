import { AlertDeliverySchema, DETECTION_RULES, type Incident, IncidentSchema } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { decodeQuotedPrintable } from "../src/mail/message.ts";
import type { MailEnvelope, MailResult } from "../src/mail/smtp.ts";
import { createNotifier, type NotifierDeps } from "../src/notify/notifier.ts";
import { insertChannel, insertRecipients } from "../src/stores/alert-channels.ts";
import { recordDetection } from "../src/stores/incidents.ts";
import { captureLogger, createAppFor, createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const CONSOLE = "https://console.airverse.example";
const SENDER = { address: "alerts@airverse.example", name: "Airverse" };

describe("notifier: email channels (slice 06b)", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let organizationId: string;
  let appId: string;
  const logger = captureLogger();
  /** Each call to the mailer: the batch it was given. */
  const batches: MailEnvelope[][] = [];
  let outcome: (message: MailEnvelope, call: number) => MailResult = () => ({ ok: true, code: 250 });
  const mailer = {
    async send(messages: readonly MailEnvelope[]): Promise<MailResult[]> {
      batches.push([...messages]);
      const call = batches.length;
      return messages.map((message) => outcome(message, call));
    },
  };

  beforeAll(async () => {
    api = await makeTestApi({ now });
    const a = await createOrganization(api, "Organization A");
    organizationId = a.organization.id;
    appId = (await createAppFor(api, a.admin_key.key, { name: "Shop" })).app.id;
    // App names with control characters are refused since slice 06b; one stored before is left as it is, and is
    // still kept inside its one body line.
    await api.db.owner((q) => q.query("UPDATE apps SET name = $2 WHERE id = $1", [appId, "Shop\r\nBcc: eve@x.io"]));
  });
  afterEach(async () => {
    batches.length = 0;
    outcome = () => ({ ok: true, code: 250 });
    await api.db.tx({ organizationId }, (q) => q.query("DELETE FROM alert_channels"));
  });
  afterAll(async () => {
    for (const line of logger.lines) expect(line).not.toMatch(/@x\.io|@example\.com/);
    await api.close();
  });

  /** An email channel with the given recipients; those named in `confirmed` are confirmed. */
  async function emailChannel(addresses: string[], confirmed: string[]): Promise<string> {
    const id = newId("chn");
    await api.db.tx({ organizationId }, async (q) => {
      await insertChannel(q, { id, organizationId, kind: "email", name: "Mail", url: null, signingSecret: null });
      await insertRecipients(q, { organizationId, channelId: id, addresses });
    });
    await api.db.owner((q) =>
      q.query(
        "UPDATE alert_recipients SET status = 'confirmed', confirmed_at = $2 WHERE channel_id = $1 AND address = ANY($3)",
        [id, now().toISOString(), confirmed],
      ),
    );
    return id;
  }

  let prefix = 0;
  async function openIncident(): Promise<Incident> {
    prefix++;
    const ts = now().toISOString();
    const result = await api.db.tx({ organizationId }, (q) =>
      recordDetection(q, {
        organizationId,
        appId,
        environment: "production",
        rule: DETECTION_RULES[0],
        ipPrefix: `192.0.${prefix}.0/24`,
        count: 20,
        windowStart: ts,
        windowEnd: ts,
        detectedAt: now(),
      }),
    );
    return IncidentSchema.parse(result.incident);
  }

  function notifier(overrides: Partial<NotifierDeps> = {}) {
    const sleeps: number[] = [];
    const instance = createNotifier({
      db: api.db,
      now,
      consoleUrl: CONSOLE,
      backoffMs: 7,
      logger,
      email: { mailer, sender: SENDER },
      sleep: async (ms) => {
        sleeps.push(ms);
      },
      ...overrides,
    });
    return { instance, sleeps };
  }

  async function deliveries(channelId: string) {
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<Record<string, unknown> & { at: Date }>(
        "SELECT id, channel_id, incident_id, attempt, outcome, status_code, at FROM alert_deliveries WHERE channel_id = $1 ORDER BY attempt",
        [channelId],
      ),
    );
    return rows.map((row) => AlertDeliverySchema.parse({ ...row, at: row.at.toISOString() }));
  }

  async function lastSent(channelId: string): Promise<Record<string, string | null>> {
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ address: string; last_sent_at: Date | null }>(
        "SELECT address, last_sent_at FROM alert_recipients WHERE channel_id = $1",
        [channelId],
      ),
    );
    return Object.fromEntries(rows.map((row) => [row.address, row.last_sent_at?.toISOString() ?? null]));
  }

  it("mails an opened Incident to confirmed recipients only, one message each, in one batch", async () => {
    const channelId = await emailChannel(["alice@x.io", "bob@x.io", "carol@x.io"], ["alice@x.io", "carol@x.io"]);
    const incident = await openIncident();
    const { instance } = notifier();
    instance.incidentOpened(incident, organizationId);
    await instance.drain();

    expect(batches).toHaveLength(1);
    const [batch] = batches as [MailEnvelope[]];
    expect(batch.map((mail) => mail.to)).toEqual(["alice@x.io", "carol@x.io"]);
    for (const mail of batch) {
      expect(mail.from).toBe(SENDER.address);
      expect(mail.data).not.toContain("bob@x.io");
      expect(mail.data).toContain("Subject: [Airverse] High: Blocked burst");
      const split = mail.data.indexOf("\r\n\r\n");
      const headers = mail.data.slice(0, split);
      const body = mail.data.slice(split + 4);
      // The App name is tenant text: it is in the body, cleaned to one line, never in a header.
      expect(headers).not.toContain("Shop");
      expect(headers).not.toMatch(/^Bcc:/im);
      const text = decodeQuotedPrintable(body);
      expect(text).toContain("App: ShopBcc: eve@x.io\r\n");
      expect(text).toContain("Environment: production");
      expect(text).toContain(`Open in the Console: ${CONSOLE}/incidents/${incident.id}`);
    }
    expect(await deliveries(channelId)).toEqual([
      expect.objectContaining({ incident_id: incident.id, attempt: 1, outcome: "delivered", status_code: 250 }),
    ]);
    expect(await lastSent(channelId)).toEqual({
      "alice@x.io": now().toISOString(),
      "bob@x.io": null,
      "carol@x.io": now().toISOString(),
    });
  });

  it("sends nothing and records nothing when no recipient has confirmed", async () => {
    const channelId = await emailChannel(["alice@x.io"], []);
    const { instance } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(batches).toEqual([]);
    expect(await deliveries(channelId)).toEqual([]);
  });

  it("retries on the webhook schedule, the failed recipients only, and records each attempt", async () => {
    const channelId = await emailChannel(["alice@x.io", "bob@x.io"], ["alice@x.io", "bob@x.io"]);
    // Bob's server refuses twice, then accepts.
    outcome = (message, call) =>
      message.to === "bob@x.io" && call < 3 ? { ok: false, code: 451 } : { ok: true, code: 250 };
    const { instance, sleeps } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();

    expect(batches.map((batch) => batch.map((mail) => mail.to))).toEqual([
      ["alice@x.io", "bob@x.io"],
      ["bob@x.io"],
      ["bob@x.io"],
    ]);
    expect(sleeps).toEqual([7, 14]);
    expect((await deliveries(channelId)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", 451],
      [2, "failed", 451],
      [3, "delivered", 250],
    ]);
  });

  it("does not retry a permanent (5xx) refusal, and keeps retrying the temporary ones", async () => {
    const channelId = await emailChannel(["alice@x.io", "bob@x.io"], ["alice@x.io", "bob@x.io"]);
    // Alice's address is refused for good; Bob's is refused once for now.
    outcome = (message, call) => {
      if (message.to === "alice@x.io") return { ok: false, code: 550 };
      return call === 1 ? { ok: false, code: 451 } : { ok: true, code: 250 };
    };
    const { instance, sleeps } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(batches.map((batch) => batch.map((mail) => mail.to))).toEqual([["alice@x.io", "bob@x.io"], ["bob@x.io"]]);
    expect(sleeps).toEqual([7]);
    expect((await deliveries(channelId)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", 550],
      [2, "delivered", 250],
    ]);
  });

  it("records a permanent refusal of every recipient as failed at once, without a retry", async () => {
    const channelId = await emailChannel(["alice@x.io"], ["alice@x.io"]);
    outcome = () => ({ ok: false, code: 554 });
    const { instance, sleeps } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(batches).toHaveLength(1);
    expect(sleeps).toEqual([]);
    expect((await deliveries(channelId)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", 554],
    ]);
  });

  it("does not retry a confirmation mail refused for good", async () => {
    const channelId = await emailChannel(["alice@x.io"], []);
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ id: string }>("SELECT id FROM alert_recipients WHERE channel_id = $1", [channelId]),
    );
    outcome = () => ({ ok: false, code: 550 });
    const { instance, sleeps } = notifier();
    instance.confirmations(organizationId, [
      { recipientId: String(rows[0]?.id), address: "alice@x.io", token: "T".repeat(43) },
    ]);
    await instance.drain();
    expect(batches).toHaveLength(1);
    expect(sleeps).toEqual([]);
  });

  it("counts a confirmation whose data went out without a final reply as sent: no retry (F4)", async () => {
    const channelId = await emailChannel(["alice@x.io"], []);
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ id: string }>("SELECT id FROM alert_recipients WHERE channel_id = $1", [channelId]),
    );
    outcome = () => ({ ok: false, code: null, dataSent: true });
    const { instance, sleeps } = notifier();
    instance.confirmations(organizationId, [
      { recipientId: String(rows[0]?.id), address: "alice@x.io", token: "T".repeat(43) },
    ]);
    await instance.drain();
    expect(batches).toHaveLength(1);
    expect(sleeps).toEqual([]);
  });

  it("still retries an alert whose data went out without a final reply (F4)", async () => {
    await emailChannel(["alice@x.io"], ["alice@x.io"]);
    outcome = () => ({ ok: false, code: null, dataSent: true });
    const { instance } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(batches).toHaveLength(3);
  });

  it("holds confirmation mails to the per-Organization queue limit, like alerts (F2)", async () => {
    const channelId = await emailChannel(["alice@x.io"], []);
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ id: string }>("SELECT id FROM alert_recipients WHERE channel_id = $1", [channelId]),
    );
    const hanging = {
      calls: 0,
      send(_messages: readonly MailEnvelope[], signal?: AbortSignal): Promise<MailResult[]> {
        hanging.calls++;
        return new Promise((resolve) => signal?.addEventListener("abort", () => resolve([{ ok: false, code: null }])));
      },
    };
    const { instance } = notifier({ email: { mailer: hanging, sender: SENDER }, maxPendingPerOrg: 2, drainMs: 20 });
    const mail = { recipientId: String(rows[0]?.id), address: "alice@x.io", token: "T".repeat(43) };
    for (let i = 0; i < 3; i++) instance.confirmations(organizationId, [mail]);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(hanging.calls).toBe(2);
    expect(logger.lines.some((line) => /confirmation mails dropped .*reason=queue-full/.test(line))).toBe(true);
    await instance.drain();
  });

  it("sends through a pool of 4 connections, at most 2 for confirmations, alerts first (F2)", async () => {
    const victim = await emailChannel(["victim@x.io"], ["victim@x.io"]);
    const pendingIds = await (async () => {
      const id = await emailChannel(["flood@x.io"], []);
      const { rows } = await api.db.tx({ organizationId }, (q) =>
        q.query<{ id: string }>("SELECT id FROM alert_recipients WHERE channel_id = $1", [id]),
      );
      return String(rows[0]?.id);
    })();
    let inFlight = 0;
    let most = 0;
    const flood = {
      send(messages: readonly MailEnvelope[], signal?: AbortSignal): Promise<MailResult[]> {
        batches.push([...messages]);
        if (messages.every((m) => m.to === "victim@x.io")) return Promise.resolve([{ ok: true, code: 250 }]);
        inFlight++;
        most = Math.max(most, inFlight);
        // A server that never answers the flood: each connection is held until the notifier stops.
        return new Promise((resolve) =>
          signal?.addEventListener("abort", () => {
            inFlight--;
            resolve(messages.map(() => ({ ok: false, code: null })));
          }),
        );
      },
    };
    const { instance } = notifier({ email: { mailer: flood, sender: SENDER }, drainMs: 30 });
    for (let i = 0; i < 50; i++) {
      instance.confirmations(organizationId, [
        { recipientId: pendingIds, address: "flood@x.io", token: "T".repeat(43) },
      ]);
    }
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(most).toBe(2);
    instance.incidentOpened(await openIncident(), organizationId);
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(await deliveries(victim)).toEqual([expect.objectContaining({ outcome: "delivered", status_code: 250 })]);
    expect(most).toBeLessThanOrEqual(4);
    await instance.drain();
  });

  it("gives up after 3 attempts when the server cannot be reached", async () => {
    const channelId = await emailChannel(["alice@x.io"], ["alice@x.io"]);
    outcome = () => ({ ok: false, code: null });
    const { instance } = notifier();
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(batches).toHaveLength(3);
    expect((await deliveries(channelId)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", null],
      [2, "failed", null],
      [3, "failed", null],
    ]);
    expect(await lastSent(channelId)).toEqual({ "alice@x.io": null });
  });

  it("records one failed attempt without retrying when SMTP is not configured", async () => {
    const channelId = await emailChannel(["alice@x.io"], ["alice@x.io"]);
    const { instance } = notifier({ email: undefined });
    instance.incidentOpened(await openIncident(), organizationId);
    await instance.drain();
    expect(batches).toEqual([]);
    expect((await deliveries(channelId)).map((d) => [d.attempt, d.outcome, d.status_code])).toEqual([
      [1, "failed", null],
    ]);
  });

  it("sends the test alert to confirmed recipients, one attempt", async () => {
    const channelId = await emailChannel(["alice@x.io", "bob@x.io"], ["bob@x.io"]);
    const { instance } = notifier();
    const delivery = await instance.test(channelId, organizationId);
    expect(delivery).toMatchObject({ channel_id: channelId, incident_id: null, attempt: 1, outcome: "delivered" });
    expect(batches.map((batch) => batch.map((mail) => mail.to))).toEqual([["bob@x.io"]]);
    await instance.drain();
  });

  it("sends confirmation mails and stamps the recipients they reached", async () => {
    const channelId = await emailChannel(["alice@x.io"], []);
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ id: string }>("SELECT id FROM alert_recipients WHERE channel_id = $1", [channelId]),
    );
    const { instance } = notifier();
    instance.confirmations(organizationId, [
      { recipientId: String(rows[0]?.id), address: "alice@x.io", token: "T".repeat(43) },
    ]);
    await instance.drain();
    expect(batches).toHaveLength(1);
    const data = String(batches[0]?.[0]?.data);
    const body = decodeQuotedPrintable(data.slice(data.indexOf("\r\n\r\n") + 4));
    expect(body).toContain(`${CONSOLE}/alerts/confirm?token=${"T".repeat(43)}`);
    expect(await lastSent(channelId)).toEqual({ "alice@x.io": now().toISOString() });
  });
});
