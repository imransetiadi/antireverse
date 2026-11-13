// Slice 06b over HTTP: email alerts through a local SMTP server (apps/api/test/fake-smtp.ts, STARTTLS with the test
// CA). The API is started with SMTP settings read by the real reader from an AR_SMTP_* set. An email channel with two
// recipients mails each one confirmation link; one recipient confirms by the public endpoint; a burst of blocked
// requests (as detection.http.test.ts drives it) opens an Incident and exactly one alert mail goes to the confirmed
// recipient only. Header safety, the test alert, the limits of confirmation, the API without SMTP, permanent and
// temporary SMTP failures, and tenancy are checked end to end.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { decodeQuotedPrintable, type RunningApi, readSmtpSettings, startApi } from "@antireverse/api";
import {
  type AlertChannel,
  CreateAlertChannelResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type Incident,
  ListAlertChannelsResponseSchema,
  ListIncidentsResponseSchema,
  PolicyResponseSchema,
  ResendConfirmationResponseSchema,
  TestAlertChannelResponseSchema,
} from "@antireverse/protocol";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  type FakeSmtp,
  type FakeSmtpOptions,
  type ReceivedMail,
  SMTP_PASSWORD,
  SMTP_USER,
  startFakeSmtp,
} from "../../apps/api/test/fake-smtp.ts";

const CONSOLE_URL = "http://127.0.0.1:39951";
const SENDER = "alerts@airverse.example";
const CA_FILE = fileURLToPath(new URL("../../apps/api/test/fixtures/smtp-tls/ca.pem", import.meta.url));
/** PB-14 and PB-18 budgets, as in detection.http.test.ts. */
const DETECTION_BUDGET_MS = 10_000;
const MAIL_BUDGET_MS = 15_000;
/** How long to listen for a mail (or a retry) that must not come. */
const QUIET_MS = 1_500;
const BURST = 20;

const ORG_NAME = "Acme Mail Org";
const CHANNEL_NAME = "On-call mail";
// The App name reaches the body of an alert mail. Names with line breaks or format characters are refused at creation
// (plan amendment A3: one name rule for App and channel names), so the App gets a clean name.
const APP_NAME = "shop-web";
/** Names the API refuses with 400, each with a fake header line after the break or the hidden character. */
const UNSAFE_NAMES = [
  "Ops\r\nBcc: evil@attacker.example",
  "Ops\nBcc: evil@attacker.example",
  "Ops\rBcc: evil@attacker.example",
  "Ops\u0085Bcc: evil@attacker.example",
  "Ops\u2028Bcc: evil@attacker.example",
  "Ops\u2029Bcc: evil@attacker.example",
  "Ops\u202eBcc: evil@attacker.example",
  "Ops\u200bBcc: evil@attacker.example",
];
/** The fixed subjects of every mail Airverse sends: no tenant text reaches a header except the typed address in To. */
const SUBJECTS = ["[Airverse] Confirm alert emails", "[Airverse] Test alert", "[Airverse] High: Blocked burst"];
const ALICE = "alice@example.com";
const BOB = "bob@example.com";

const EXPECTED_HEADERS = [
  "From",
  "To",
  "Subject",
  "Date",
  "Message-ID",
  "MIME-Version",
  "Content-Type",
  "Content-Transfer-Encoding",
  "Auto-Submitted",
];

/** SMTP settings of a test API, through the real reader of AR_SMTP_*. */
function smtpSettingsFor(port: number) {
  const settings = readSmtpSettings({
    AR_SMTP_HOST: "127.0.0.1",
    AR_SMTP_PORT: String(port),
    AR_SMTP_TLS: "starttls",
    AR_SMTP_USER: SMTP_USER,
    AR_SMTP_PASSWORD: SMTP_PASSWORD,
    AR_SMTP_FROM: SENDER,
    AR_SMTP_TEST_CA_FILE: CA_FILE,
  });
  if (settings === null) throw new Error("SMTP settings expected");
  return settings;
}

interface ParsedMail {
  envelope: ReceivedMail;
  /** Unfolded header fields, in order. */
  headers: { name: string; value: string }[];
  /** The raw header lines as sent (before unfolding). */
  rawHeaderLines: string[];
  body: string;
}

function parseMail(mail: ReceivedMail): ParsedMail {
  const split = mail.data.indexOf("\r\n\r\n");
  expect(split).toBeGreaterThan(0);
  const rawHeaderLines = mail.data.slice(0, split).split("\r\n");
  const headers: { name: string; value: string }[] = [];
  for (const line of rawHeaderLines) {
    if (line.startsWith(" ") || line.startsWith("\t")) {
      const last = headers.at(-1);
      expect(last).toBeDefined();
      if (last) last.value += line;
      continue;
    }
    const colon = line.indexOf(":");
    expect(colon).toBeGreaterThan(0);
    headers.push({ name: line.slice(0, colon), value: line.slice(colon + 1).trim() });
  }
  return { envelope: mail, headers, rawHeaderLines, body: decodeQuotedPrintable(mail.data.slice(split + 4)) };
}

const headerOf = (mail: ParsedMail, name: string) => mail.headers.find((h) => h.name === name)?.value;

async function until<T>(
  what: string,
  budgetMs: number,
  probe: () => Promise<T | undefined> | T | undefined,
): Promise<T> {
  const started = Date.now();
  for (;;) {
    const value = await probe();
    if (value !== undefined) return value;
    if (Date.now() - started > budgetMs) throw new Error(`${what}: not within ${budgetMs} ms`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

const quiet = () => new Promise((resolve) => setTimeout(resolve, QUIET_MS));

function caller(base: () => string) {
  return (path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<Response> => {
    const headers: Record<string, string> = {};
    if (init.key) headers.authorization = `Bearer ${init.key}`;
    if (init.body !== undefined) headers["content-type"] = "application/json";
    return fetch(`${base()}${path}`, {
      method: init.method ?? (init.body === undefined ? "GET" : "POST"),
      headers,
      ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
    });
  };
}

/** The token of a confirmation mail's link. */
function tokenOf(mail: ReceivedMail): string {
  const token = /\/alerts\/confirm\?token=([A-Za-z0-9_-]{43})(?![A-Za-z0-9_-])/.exec(parseMail(mail).body)?.[1];
  expect(token).toBeDefined();
  return token as string;
}

let smtp: FakeSmtp;
const smtpOptions: FakeSmtpOptions = { mode: "starttls" };
let api: RunningApi;
let shield: Shield;
let range: http.Server;
let rangeUrl: string;
let organizationId: string;
let adminKey: string;
let appId: string;
let channel: AlertChannel;
let aliceToken: string;
const call = caller(() => api.url);

const mailsTo = (address: string, from = 0) => smtp.mails.slice(from).filter((mail) => mail.to.includes(address));
const rcptCount = (address: string) => smtp.commands.filter((line) => line.endsWith(`RCPT TO:<${address}>`)).length;

async function listIncidents(): Promise<Incident[]> {
  const response = await call(`/v1/incidents?app_id=${appId}`, { key: adminKey });
  expect(response.status).toBe(200);
  return ListIncidentsResponseSchema.parse(await response.json()).incidents.filter((i) => i.rule === "blocked-burst");
}

/** A burst of blocked requests through Shield, then the new open Incident it opens. */
async function openIncident(): Promise<Incident> {
  const before = new Set((await listIncidents()).map((incident) => incident.id));
  for (let i = 0; i < BURST; i++) {
    const response = await fetch(`${rangeUrl}/api/admin/reports`);
    expect(response.status).toBe(403);
  }
  return until("Incident opened", DETECTION_BUDGET_MS, async () =>
    (await listIncidents()).find((incident) => !before.has(incident.id) && incident.status === "open"),
  );
}

async function resolveIncident(id: string): Promise<void> {
  const response = await call(`/v1/incidents/${id}`, { method: "PATCH", key: adminKey, body: { status: "resolved" } });
  expect(response.status).toBe(200);
}

/** The delivery records of an Incident on the email channel, read from the API's database (no endpoint lists them). */
async function deliveriesOf(incidentId: string) {
  return api.db.tx({ organizationId }, async (q) => {
    const { rows } = await q.query<{ attempt: number; outcome: string; status_code: number | null }>(
      "SELECT attempt, outcome, status_code FROM alert_deliveries WHERE channel_id = $1 AND incident_id = $2 ORDER BY attempt",
      [channel.id, incidentId],
    );
    return rows;
  });
}

async function channelNow(key = adminKey): Promise<AlertChannel | undefined> {
  const response = await call("/v1/alert-channels", { key });
  expect(response.status).toBe(200);
  return ListAlertChannelsResponseSchema.parse(await response.json()).channels.find((c) => c.id === channel.id);
}

const recipientsOf = (c: AlertChannel | undefined) =>
  c?.kind === "email" ? c.recipients.map((r) => [r.address, r.status]) : [];

beforeAll(async () => {
  smtp = await startFakeSmtp(smtpOptions);
  api = await startApi({
    smtp: smtpSettingsFor(smtp.port),
    alertBackoffMs: 10,
    consoleUrl: CONSOLE_URL,
    logger: { info() {}, warn() {} },
  });

  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { body: { name: ORG_NAME } })).json(),
  );
  organizationId = organization.organization.id;
  adminKey = organization.admin_key.key;
  const created = await call("/v1/apps", { key: adminKey, body: { name: APP_NAME } });
  expect(created.status).toBe(201);
  const app = CreateAppResponseSchema.parse(await created.json());
  appId = app.app.id;

  const published = await call(`/v1/apps/${appId}/policies/development`, {
    method: "PUT",
    key: adminKey,
    body: { rules: [{ name: "Admin area", path: "/api/admin/**", mode: "enforce" }] },
  });
  expect(published.status).toBe(201);
  const version = PolicyResponseSchema.parse(await published.json()).policy.version;
  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: app.shield_key.key,
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
});

afterAll(async () => {
  await shield?.close();
  if (range) {
    range.closeAllConnections();
    await new Promise<void>((resolve) => range.close(() => resolve()));
  }
  await api?.close();
  await smtp?.close();
});

describe("slice 06b email alerts over HTTP and a local STARTTLS SMTP server", () => {
  it("mails each of two recipients exactly one plain-text confirmation link without tenant text", async () => {
    const listed = await call("/v1/alert-channels", { key: adminKey });
    expect(ListAlertChannelsResponseSchema.parse(await listed.json()).smtp_configured).toBe(true);

    const response = await call("/v1/alert-channels", {
      key: adminKey,
      body: { kind: "email", name: CHANNEL_NAME, recipients: [ALICE, ` ${BOB.toUpperCase()} `] },
    });
    expect(response.status).toBe(201);
    const text = await response.text();
    const body = CreateAlertChannelResponseSchema.parse(JSON.parse(text));
    channel = body.channel;
    expect(channel.kind).toBe("email");
    expect(recipientsOf(channel)).toEqual([
      [ALICE, "pending"],
      [BOB, "pending"],
    ]);
    expect(text).not.toContain("token");

    await until("two confirmation mails", MAIL_BUDGET_MS, () => (smtp.mails.length >= 2 ? true : undefined));
    await quiet();
    expect(mailsTo(ALICE)).toHaveLength(1);
    expect(mailsTo(BOB)).toHaveLength(1);
    expect(smtp.mails).toHaveLength(2);
    expect(smtp.authInClear).toBe(false);

    const tokens = new Set<string>();
    for (const address of [ALICE, BOB]) {
      const [received] = mailsTo(address);
      if (!received) throw new Error("mail expected");
      expect(received.to).toEqual([address]);
      expect(received.from).toBe(SENDER);
      expect(received.overTls).toBe(true);
      const mail = parseMail(received);
      expect(mail.headers.map((h) => h.name)).toEqual(EXPECTED_HEADERS);
      expect(headerOf(mail, "Subject")).toBe("[Airverse] Confirm alert emails");
      expect(headerOf(mail, "To")).toBe(`<${address}>`);
      expect(headerOf(mail, "Content-Type")).toBe("text/plain; charset=UTF-8");
      const links = mail.body.match(/https?:\/\/\S+/g) ?? [];
      expect(links).toHaveLength(1);
      expect(links[0]).toMatch(new RegExp(`^${CONSOLE_URL}/alerts/confirm\\?token=[A-Za-z0-9_-]{43}$`));
      // No Organization, App or channel name: nothing a tenant wrote reaches a stranger.
      for (const tenantText of [ORG_NAME, "Acme", CHANNEL_NAME, "shop-web", "Bcc", appId, organizationId]) {
        expect(received.data).not.toContain(tenantText);
        expect(mail.body).not.toContain(tenantText);
      }
      tokens.add(tokenOf(received));
    }
    expect(tokens.size).toBe(2);
    const [first] = mailsTo(ALICE);
    aliceToken = tokenOf(first as ReceivedMail);
  });

  it("refuses the test alert with 409 no-confirmed-recipients while nobody has confirmed", async () => {
    const before = smtp.mails.length;
    const response = await call(`/v1/alert-channels/${channel.id}/test`, { method: "POST", key: adminKey });
    expect(response.status).toBe(409);
    expect(await response.json()).toMatchObject({ status: 409, reason: "no-confirmed-recipients" });
    await quiet();
    expect(smtp.mails).toHaveLength(before);
  });

  it("confirms one recipient through the public endpoint with the token from its mail", async () => {
    const response = await call("/v1/alert-recipients/confirm", { body: { token: aliceToken } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ confirmed: true });
    const now = await channelNow();
    expect(recipientsOf(now)).toEqual([
      [ALICE, "confirmed"],
      [BOB, "pending"],
    ]);
  });

  it("sends the test alert, after a confirmation, to the confirmed recipient only", async () => {
    const before = smtp.mails.length;
    const response = await call(`/v1/alert-channels/${channel.id}/test`, { method: "POST", key: adminKey });
    expect(response.status).toBe(200);
    expect(TestAlertChannelResponseSchema.parse(await response.json()).delivery).toMatchObject({
      channel_id: channel.id,
      incident_id: null,
      outcome: "delivered",
      status_code: 250,
    });
    await quiet();
    const sent = smtp.mails.slice(before);
    expect(sent.map((mail) => mail.to)).toEqual([[ALICE]]);
    expect(headerOf(parseMail(sent[0] as ReceivedMail), "Subject")).toBe("[Airverse] Test alert");
  });

  it("opens an Incident and sends exactly one alert mail, to the confirmed recipient only", async () => {
    const before = smtp.mails.length;
    const incident = await openIncident();
    expect(incident).toMatchObject({ severity: "high", title: "Blocked burst", environment: "development" });

    await until("alert mail", MAIL_BUDGET_MS, () => (smtp.mails.length > before ? true : undefined));
    await quiet();
    const sent = smtp.mails.slice(before);
    expect(sent).toHaveLength(1);
    expect(mailsTo(BOB, before)).toHaveLength(0);
    const [received] = sent as [ReceivedMail];
    expect(received.to).toEqual([ALICE]);
    expect(received.from).toBe(SENDER);
    expect(received.overTls).toBe(true);

    const mail = parseMail(received);
    expect(headerOf(mail, "From")).toBe(`"Airverse" <${SENDER}>`);
    expect(headerOf(mail, "To")).toBe(`<${ALICE}>`);
    expect(headerOf(mail, "Subject")).toBe("[Airverse] High: Blocked burst");
    expect(headerOf(mail, "Message-ID")).toMatch(/^<[0-9a-f]{32}@airverse\.example>$/);
    expect(headerOf(mail, "Date")).toMatch(/^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} \+0000$/);
    const openedAt = `${incident.created_at.slice(0, 19).replace("T", " ")} UTC`;
    const lines = mail.body.split("\r\n");
    expect(lines.slice(0, 6)).toEqual([
      "Incident: Blocked burst",
      "Severity: High",
      `App: ${APP_NAME}`,
      "Environment: development",
      `Opened at: ${openedAt}`,
      `Open in the Console: ${CONSOLE_URL}/incidents/${incident.id}`,
    ]);
    for (const leak of [adminKey, aliceToken, BOB, CHANNEL_NAME, ORG_NAME, SMTP_PASSWORD]) {
      expect(received.data).not.toContain(leak);
    }
    expect(await deliveriesOf(incident.id)).toEqual([{ attempt: 1, outcome: "delivered", status_code: 250 }]);
    await resolveIncident(incident.id);
  });

  it("refuses names with line breaks or hidden characters, and lets no tenant text add a header or a recipient", async () => {
    // One name rule for App and channel names: CR, LF, NEL, U+2028/2029, a bidi override and a zero-width space are
    // refused with 400, so no name with a fake "Bcc:" line is ever stored.
    for (const name of UNSAFE_NAMES) {
      const app = await call("/v1/apps", { key: adminKey, body: { name } });
      expect(app.status, JSON.stringify(name)).toBe(400);
      const channelResponse = await call("/v1/alert-channels", {
        key: adminKey,
        body: { kind: "email", name, recipients: [ALICE] },
      });
      expect(channelResponse.status, JSON.stringify(name)).toBe(400);
    }
    // Joiners and marks a name may need stay allowed (ZWJ, ZWNJ, LRM, RLM).
    const joined = await call("/v1/apps", { key: adminKey, body: { name: "shop\u200dweb\u200c\u200e\u200f" } });
    expect(joined.status).toBe(201);

    // The only tenant text that reaches a header is the address typed for a recipient (in To). An address with a line
    // break, a fake Bcc line or an SMTP command is not an address.
    for (const recipient of [
      `${ALICE}\r\nBcc: evil@attacker.example`,
      `${ALICE}\nBcc: evil@attacker.example`,
      `${ALICE}>\r\nRCPT TO:<evil@attacker.example`,
      `${ALICE}\u2028Bcc: evil@attacker.example`,
      `${ALICE}\u0085Bcc: evil@attacker.example`,
      `alice,evil@attacker.example`,
      `"alice\r\nBcc: evil"@attacker.example`,
    ]) {
      const response = await call("/v1/alert-channels", {
        key: adminKey,
        body: { kind: "email", name: "Ops", recipients: [recipient] },
      });
      expect(response.status, JSON.stringify(recipient)).toBe(400);
    }

    // Every mail so far (confirmations, test alert, Incident alert) has exactly the headers Airverse writes, a fixed
    // subject (the Incident title comes from the rule table, not from a tenant), To naming its one envelope recipient,
    // and an envelope with one recipient.
    expect(smtp.mails.length).toBeGreaterThanOrEqual(4);
    for (const received of smtp.mails) {
      expect(received.to).toHaveLength(1);
      expect(received.to[0]).toMatch(/^(alice|bob)@example\.com$/);
      const mail = parseMail(received);
      expect(mail.headers.map((h) => h.name)).toEqual(EXPECTED_HEADERS);
      expect(SUBJECTS).toContain(headerOf(mail, "Subject"));
      expect(headerOf(mail, "To")).toBe(`<${received.to[0]}>`);
      for (const line of mail.rawHeaderLines) {
        expect(line).toMatch(/^[\x20-\x7e]{1,78}$/);
        expect(line).not.toMatch(/^\s*(Bcc|Cc):/i);
      }
      for (const line of mail.body.split("\r\n")) {
        expect(line).not.toMatch(/^(Bcc|Cc):/i);
      }
    }
    expect(smtp.commands.some((line) => line.includes("attacker.example"))).toBe(false);
  });

  it("records a 550 reply as failed and does not retry it; retries a 451 reply", async () => {
    // Permanent: refused at RCPT with 550 — one attempt, recorded as failed with the code.
    smtpOptions.refuse = { [ALICE]: "550 5.1.1 No such user" };
    let rcpts = rcptCount(ALICE);
    const permanent = await openIncident();
    await until("550 recorded", MAIL_BUDGET_MS, async () =>
      (await deliveriesOf(permanent.id)).length ? true : undefined,
    );
    await quiet();
    expect(await deliveriesOf(permanent.id)).toEqual([{ attempt: 1, outcome: "failed", status_code: 550 }]);
    expect(rcptCount(ALICE) - rcpts).toBe(1);
    await resolveIncident(permanent.id);

    // Temporary: 451 — tried again on the alert schedule, three attempts in all, each recorded.
    smtpOptions.refuse = { [ALICE]: "451 4.3.0 Try again later" };
    rcpts = rcptCount(ALICE);
    const temporary = await openIncident();
    await until("three 451 attempts", MAIL_BUDGET_MS, async () =>
      (await deliveriesOf(temporary.id)).length >= 3 ? true : undefined,
    );
    await quiet();
    expect(await deliveriesOf(temporary.id)).toEqual([
      { attempt: 1, outcome: "failed", status_code: 451 },
      { attempt: 2, outcome: "failed", status_code: 451 },
      { attempt: 3, outcome: "failed", status_code: 451 },
    ]);
    expect(rcptCount(ALICE) - rcpts).toBe(3);
    await resolveIncident(temporary.id);

    delete smtpOptions.refuse;
  });

  it("keeps the channel's recipients away from another Organization", async () => {
    const other = CreateOrganizationResponseSchema.parse(
      await (await call("/v1/organizations", { body: { name: "Other" } })).json(),
    );
    const key = other.admin_key.key;
    const listed = await call("/v1/alert-channels", { key });
    const text = await listed.text();
    expect(ListAlertChannelsResponseSchema.parse(JSON.parse(text)).channels).toEqual([]);
    for (const leak of [ALICE, BOB, channel.id, CHANNEL_NAME]) expect(text).not.toContain(leak);

    const recipients = channel.kind === "email" ? channel.recipients : [];
    const before = smtp.mails.length;
    for (const recipient of recipients) {
      const resend = await call(`/v1/alert-channels/${channel.id}/recipients/${recipient.id}/resend`, {
        method: "POST",
        key,
      });
      expect(resend.status).toBe(404);
      const body = await resend.text();
      expect(body).not.toContain(recipient.address);
    }
    expect((await call(`/v1/alert-channels/${channel.id}/test`, { method: "POST", key })).status).toBe(404);
    expect((await call(`/v1/alert-channels/${channel.id}`, { method: "DELETE", key })).status).toBe(404);
    await quiet();
    expect(smtp.mails).toHaveLength(before);
    // The owner still sees both, unchanged.
    expect(recipientsOf(await channelNow())).toEqual([
      [ALICE, "confirmed"],
      [BOB, "pending"],
    ]);
  });
});

describe("slice 06b confirmation limits", () => {
  let limitsApi: RunningApi;
  let offsetMs = 0;
  let key: string;
  const limitsCall = caller(() => limitsApi.url);
  const confirm = async (token: string) => {
    const response = await limitsCall("/v1/alert-recipients/confirm", { body: { token } });
    expect(response.status).toBe(200);
    return ((await response.json()) as { confirmed: boolean }).confirmed;
  };
  async function emailChannel(name: string, recipients: string[]): Promise<AlertChannel> {
    const before = smtp.mails.length;
    const response = await limitsCall("/v1/alert-channels", { key, body: { kind: "email", name, recipients } });
    expect(response.status).toBe(201);
    await until("confirmation mails", MAIL_BUDGET_MS, () =>
      recipients.every((address) => mailsTo(address, before).length === 1) ? true : undefined,
    );
    return CreateAlertChannelResponseSchema.parse(await response.json()).channel;
  }
  const latestToken = (address: string) => tokenOf(mailsTo(address).at(-1) as ReceivedMail);

  beforeAll(async () => {
    limitsApi = await startApi({
      smtp: smtpSettingsFor(smtp.port),
      alertBackoffMs: 10,
      consoleUrl: CONSOLE_URL,
      now: () => new Date(Date.now() + offsetMs),
      logger: { info() {}, warn() {} },
    });
    key = CreateOrganizationResponseSchema.parse(
      await (await limitsCall("/v1/organizations", { body: { name: "Limits" } })).json(),
    ).admin_key.key;
  });

  afterAll(async () => {
    await limitsApi?.close();
  });

  it("answers 429 with Retry-After for the 4th confirmation mail of one address in a day", async () => {
    const carol = "carol@example.com";
    const created = await emailChannel("Carol", [carol]);
    const recipient = created.kind === "email" ? created.recipients[0] : undefined;
    const resend = () =>
      limitsCall(`/v1/alert-channels/${created.id}/recipients/${recipient?.id}/resend`, { method: "POST", key });
    for (let n = 2; n <= 3; n++) {
      const response = await resend();
      expect(response.status).toBe(202);
      expect(ResendConfirmationResponseSchema.parse(await response.json()).recipient.status).toBe("pending");
      await until(`confirmation mail ${n}`, MAIL_BUDGET_MS, () => (mailsTo(carol).length === n ? true : undefined));
    }
    const fourth = await resend();
    expect(fourth.status).toBe(429);
    const retryAfter = Number(fourth.headers.get("retry-after"));
    expect(Number.isInteger(retryAfter)).toBe(true);
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(86_400);
    const problemText = await fourth.text();
    expect(JSON.parse(problemText)).toMatchObject({ status: 429 });
    expect(problemText).not.toContain(carol);
    await quiet();
    expect(mailsTo(carol)).toHaveLength(3);

    // Only the newest link works; the replaced ones are dead.
    const tokens = mailsTo(carol).map(tokenOf);
    expect(await confirm(tokens[0] as string)).toBe(false);
    expect(await confirm(tokens[2] as string)).toBe(true);
  });

  it("counts victim+1@ and v.ictim@gmail.com as one address: the 4th confirmation in an Organization is 429", async () => {
    const plus = "victim+1@gmail.com";
    const dotted = "v.ictim@gmail.com";
    const plain = "victim@gmail.com";
    const first = await emailChannel("Victim variants", [plus, dotted]);
    await emailChannel("Victim plain", [plain]);
    // Three mails in all, one per variant: the count of the normalised address is spent.
    expect(mailsTo(plus)).toHaveLength(1);
    expect(mailsTo(dotted)).toHaveLength(1);
    expect(mailsTo(plain)).toHaveLength(1);

    const recipient = first.kind === "email" ? first.recipients.find((r) => r.address === plus) : undefined;
    const before = smtp.mails.length;
    const fourth = await limitsCall(`/v1/alert-channels/${first.id}/recipients/${recipient?.id}/resend`, {
      method: "POST",
      key,
    });
    expect(fourth.status).toBe(429);
    expect(Number(fourth.headers.get("retry-after"))).toBeGreaterThanOrEqual(1);
    const text = await fourth.text();
    for (const address of [plus, dotted, plain, "victim"]) expect(text).not.toContain(address);
    await quiet();
    expect(smtp.mails).toHaveLength(before);
  });

  it("answers {confirmed:false} alike for an unknown, a used and an expired token", async () => {
    expect(await confirm("A".repeat(43))).toBe(false);

    const dan = "dan@example.com";
    await emailChannel("Dan", [dan]);
    const used = latestToken(dan);
    expect(await confirm(used)).toBe(true);
    expect(await confirm(used)).toBe(false);

    const eve = "eve@example.com";
    const created = await emailChannel("Eve", [eve]);
    offsetMs = 72 * 3600 * 1000 + 60_000;
    try {
      expect(await confirm(latestToken(eve))).toBe(false);
    } finally {
      offsetMs = 0;
    }
    const listed = await limitsCall("/v1/alert-channels", { key });
    const eveChannel = ListAlertChannelsResponseSchema.parse(await listed.json()).channels.find(
      (c) => c.id === created.id,
    );
    expect(recipientsOf(eveChannel)).toEqual([[eve, "pending"]]);
  });

  it("refuses the 6th attempt of one token even with the right token while it is valid", async () => {
    const fay = "fay@example.com";
    const gus = "gus@example.com";
    const created = await emailChannel("Fay and Gus", [fay, gus]);
    const fayToken = latestToken(fay);
    const gusToken = latestToken(gus);

    // Five attempts while the token is expired (the clock 72 h ahead) spend its attempts.
    offsetMs = 72 * 3600 * 1000 + 60_000;
    try {
      for (let i = 0; i < 5; i++) expect(await confirm(fayToken)).toBe(false);
      // The control: one attempt only for Gus's token.
      expect(await confirm(gusToken)).toBe(false);
    } finally {
      offsetMs = 0;
    }
    // Back within 72 hours: the 6th attempt of Fay's token confirms nothing; Gus's 2nd attempt confirms.
    expect(await confirm(fayToken)).toBe(false);
    expect(await confirm(gusToken)).toBe(true);
    const listed = await limitsCall("/v1/alert-channels", { key });
    const found = ListAlertChannelsResponseSchema.parse(await listed.json()).channels.find((c) => c.id === created.id);
    expect(recipientsOf(found)).toEqual([
      [fay, "pending"],
      [gus, "confirmed"],
    ]);
  });
});

describe("slice 06b without SMTP settings", () => {
  it("refuses an email channel with 409 smtp-not-configured and lists smtp_configured false", async () => {
    const noSmtp = await startApi({ smtp: null, logger: { info() {}, warn() {} } });
    try {
      const plainCall = caller(() => noSmtp.url);
      const key = CreateOrganizationResponseSchema.parse(
        await (await plainCall("/v1/organizations", { body: { name: "No mail" } })).json(),
      ).admin_key.key;
      const before = smtp.mails.length;
      const response = await plainCall("/v1/alert-channels", {
        key,
        body: { kind: "email", name: "Mail", recipients: ["hal@example.com"] },
      });
      expect(response.status).toBe(409);
      expect(await response.json()).toMatchObject({ status: 409, reason: "smtp-not-configured" });
      const listed = ListAlertChannelsResponseSchema.parse(
        await (await plainCall("/v1/alert-channels", { key })).json(),
      );
      expect(listed).toEqual({ channels: [], smtp_configured: false });
      expect(smtp.mails).toHaveLength(before);
    } finally {
      await noSmtp.close();
    }
  });
});
