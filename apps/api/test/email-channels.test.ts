import { createHash } from "node:crypto";
import {
  ALERT_EMAIL_LIMITS,
  type AlertChannel,
  type AlertRecipient,
  ConfirmAlertRecipientResponseSchema,
  CreateAlertChannelResponseSchema,
  ListAlertChannelsResponseSchema,
  ResendConfirmationResponseSchema,
  TestAlertChannelResponseSchema,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openDb } from "../src/db/db.ts";
import { createAddressHasher } from "../src/mail/address-key.ts";
import { decodeQuotedPrintable } from "../src/mail/message.ts";
import type { MailEnvelope, MailResult } from "../src/mail/smtp.ts";
import { createNotifier, type Notifier } from "../src/notify/notifier.ts";
import {
  bearer,
  captureLogger,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
  tick,
  within,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const SENDER = { address: "alerts@airverse.example", name: "Airverse" };
const CONSOLE = "https://console.airverse.example";

type EmailChannel = Extract<AlertChannel, { kind: "email" }>;

describe("email alert channels (slice 06b)", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const sent: MailEnvelope[] = [];
  /** Decides each message's result; default: accepted. */
  let outcome: (message: MailEnvelope) => MailResult = () => ({ ok: true, code: 250 });
  const mailer = {
    async send(messages: readonly MailEnvelope[]): Promise<MailResult[]> {
      sent.push(...messages);
      return messages.map((message) => outcome(message));
    },
  };
  let notifier: Notifier;
  let adminA: string;
  let adminB: string;
  /** Every token seen: none may appear in a response other than through a mail, or in a log line. */
  const tokens: string[] = [];
  const logger = captureLogger();
  const hasher = createAddressHasher();

  beforeAll(async () => {
    const db = await openDb();
    notifier = createNotifier({
      db,
      now,
      consoleUrl: CONSOLE,
      backoffMs: 1,
      logger,
      email: { mailer, sender: SENDER },
      sleep: async () => {},
    });
    // The routes queue their mails on this notifier, so that the test sees them and can drain it.
    api = await makeTestApi({
      db,
      now,
      notifier,
      email: { mailer, sender: SENDER },
      addressHasher: hasher,
    });
    adminA = (await createOrganization(api, "Organization A")).admin_key.key;
    adminB = (await createOrganization(api, "Organization B")).admin_key.key;
  });
  afterAll(async () => {
    for (const line of [...api.logger.lines, ...logger.lines]) {
      for (const token of tokens) expect(line).not.toContain(token);
      expect(line).not.toMatch(/@example\.com|@x\.io/);
    }
    expectNoKeyLogged(api);
    await notifier.drain();
    await api.close();
  });

  /** Waits until the notifier sent `count` mails in all. */
  async function mailsSent(count: number): Promise<MailEnvelope[]> {
    await within(
      (async () => {
        while (sent.length < count) await tick(5);
      })(),
      5_000,
      `${count} mails`,
    );
    await tick(10);
    return sent;
  }

  function tokenOf(message: MailEnvelope): string {
    const body = decodeQuotedPrintable(message.data.slice(message.data.indexOf("\r\n\r\n") + 4));
    const token = /\/alerts\/confirm\?token=([A-Za-z0-9_-]{43})/.exec(body)?.[1];
    if (token === undefined) throw new Error("no token in the mail");
    tokens.push(token);
    return token;
  }

  async function create(body: unknown, key = adminA): Promise<Response> {
    return api.app.request("/v1/alert-channels", json(body, bearer(key)));
  }

  async function createEmail(recipients: string[], key = adminA, name = "On-call"): Promise<EmailChannel> {
    const res = await create({ kind: "email", name, recipients }, key);
    expect(res.status).toBe(201);
    const { channel } = CreateAlertChannelResponseSchema.parse(await res.json());
    if (channel.kind !== "email") throw new Error("not an email channel");
    return channel;
  }

  async function confirm(token: string): Promise<{ status: number; text: string }> {
    const res = await api.app.request("/v1/alert-recipients/confirm", json({ token }));
    return { status: res.status, text: await res.text() };
  }

  async function list(key = adminA): Promise<EmailChannel[]> {
    const res = await api.app.request("/v1/alert-channels", { headers: bearer(key) });
    const body = ListAlertChannelsResponseSchema.parse(await res.json());
    return body.channels.filter((channel): channel is EmailChannel => channel.kind === "email");
  }

  async function resend(channelId: string, recipientId: string, key = adminA): Promise<Response> {
    return api.app.request(`/v1/alert-channels/${channelId}/recipients/${recipientId}/resend`, {
      method: "POST",
      headers: bearer(key),
    });
  }

  it("says in the channel list whether SMTP is configured", async () => {
    const res = await api.app.request("/v1/alert-channels", { headers: bearer(adminA) });
    expect(ListAlertChannelsResponseSchema.parse(await res.json()).smtp_configured).toBe(true);

    const bare = await makeTestApi({ now });
    const admin = (await createOrganization(bare, "No SMTP")).admin_key.key;
    const listed = await bare.app.request("/v1/alert-channels", { headers: bearer(admin) });
    expect(ListAlertChannelsResponseSchema.parse(await listed.json())).toEqual({
      channels: [],
      smtp_configured: false,
    });
    // Without SMTP no email channel can be created; the reason says why.
    const refused = await bare.app.request(
      "/v1/alert-channels",
      json({ kind: "email", name: "Mail", recipients: ["a@x.io"] }, bearer(admin)),
    );
    expect((await expectProblem(refused, 409)).reason).toBe("smtp-not-configured");
    await bare.close();
  });

  let channel: EmailChannel;
  let tokenAlice: string;
  let tokenBob: string;

  it("creates an email channel: recipients pending, one confirmation mail each, no token in the response", async () => {
    const before = sent.length;
    const res = await create({ kind: "email", name: "On-call", recipients: [" Alice@Example.com", "bob@example.com"] });
    expect(res.status).toBe(201);
    const text = await res.text();
    expect(text).not.toMatch(/token/i);
    const body = CreateAlertChannelResponseSchema.parse(JSON.parse(text));
    expect(body).not.toHaveProperty("signing_secret");
    if (body.channel.kind !== "email") throw new Error("kind");
    channel = body.channel;
    expect(channel).toEqual({
      id: expect.stringMatching(/^chn_[0-9a-f]{24}$/),
      kind: "email",
      name: "On-call",
      recipients: [
        {
          id: expect.stringMatching(/^rcp_[0-9a-f]{24}$/),
          address: "alice@example.com",
          status: "pending",
          confirmed_at: null,
          last_sent_at: null,
        },
        {
          id: expect.stringMatching(/^rcp_[0-9a-f]{24}$/),
          address: "bob@example.com",
          status: "pending",
          confirmed_at: null,
          last_sent_at: null,
        },
      ],
      active: true,
      created_at: new Date(T0).toISOString(),
    });

    const mails = (await mailsSent(before + 2)).slice(before);
    expect(mails.map((mail) => mail.to).sort()).toEqual(["alice@example.com", "bob@example.com"]);
    for (const mail of mails) {
      expect(mail.from).toBe(SENDER.address);
      // One recipient per message: the other address appears nowhere, nor does any tenant text.
      const other = mail.to === "alice@example.com" ? "bob@example.com" : "alice@example.com";
      expect(mail.data).not.toContain(other);
      expect(mail.data).not.toContain("On-call");
      expect(mail.data).not.toContain("Organization A");
      expect(mail.data).toContain(`To: <${mail.to}>`);
      expect(mail.data).toContain("Subject: [Airverse] Confirm alert emails");
    }
    tokenAlice = tokenOf(mails.find((mail) => mail.to === "alice@example.com") as MailEnvelope);
    tokenBob = tokenOf(mails.find((mail) => mail.to === "bob@example.com") as MailEnvelope);
    expect(tokenAlice).not.toBe(tokenBob);

    // The tokens are stored hashed only.
    const { rows } = await api.db.owner((q) =>
      q.query<{ row: unknown }>("SELECT row_to_json(r) AS row FROM alert_recipients r"),
    );
    const stored = JSON.stringify(rows);
    expect(stored).not.toContain(tokenAlice);
    expect(stored).not.toContain(tokenBob);

    // The accepted mails are stamped on their recipients.
    const [listed] = await list();
    expect(listed?.recipients.map((r) => r.last_sent_at)).toEqual([
      new Date(T0).toISOString(),
      new Date(T0).toISOString(),
    ]);
  });

  it("confirms a recipient once by its token; unknown, used and expired tokens get the same answer", async () => {
    const first = await confirm(tokenAlice);
    expect(first.status).toBe(200);
    expect(ConfirmAlertRecipientResponseSchema.parse(JSON.parse(first.text))).toEqual({ confirmed: true });

    const used = await confirm(tokenAlice);
    const unknown = await confirm("Z".repeat(43));
    clock.ms += ALERT_EMAIL_LIMITS.confirmationTtlS * 1_000 + 1_000;
    const expired = await confirm(tokenBob);
    clock.ms = T0;
    for (const answer of [used, unknown, expired]) {
      expect(answer.status).toBe(200);
      expect(answer.text).toBe(JSON.stringify({ confirmed: false }));
    }
    // A malformed token is a plain 400: its shape says nothing about any recipient.
    const malformed = await api.app.request("/v1/alert-recipients/confirm", json({ token: "short" }));
    await expectProblem(malformed, 400);

    const [listed] = await list();
    expect(listed?.recipients.map((r) => [r.address, r.status, r.confirmed_at])).toEqual([
      ["alice@example.com", "confirmed", new Date(T0).toISOString()],
      ["bob@example.com", "pending", null],
    ]);
  });

  it("resends a confirmation: a new mail and token, the old link stops working", async () => {
    const bob = channel.recipients[1] as AlertRecipient;
    const before = sent.length;
    const res = await resend(channel.id, bob.id);
    expect(res.status).toBe(202);
    const { recipient } = ResendConfirmationResponseSchema.parse(await res.json());
    expect(recipient).toMatchObject({ id: bob.id, address: "bob@example.com", status: "pending" });
    const [mail] = (await mailsSent(before + 1)).slice(before);
    expect(mail?.to).toBe("bob@example.com");
    const fresh = tokenOf(mail as MailEnvelope);
    expect(fresh).not.toBe(tokenBob);
    expect(JSON.parse((await confirm(tokenBob)).text)).toEqual({ confirmed: false });
    expect(JSON.parse((await confirm(fresh)).text)).toEqual({ confirmed: true });
  });

  it("refuses a resend for a confirmed recipient, an unknown one, or another Organization's", async () => {
    const alice = channel.recipients[0] as AlertRecipient;
    expect((await expectProblem(await resend(channel.id, alice.id), 409)).reason).toBe("recipient-confirmed");
    await expectProblem(await resend(channel.id, newId("rcp")), 404);
    await expectProblem(await resend(newId("chn"), alice.id), 404);
    await expectProblem(await resend(channel.id, "not-an-id"), 404);
    await expectProblem(await resend(channel.id, alice.id, adminB), 404);
  });

  it("sends at most 3 confirmation mails per address per day, across Organizations", async () => {
    const address = "capped@x.io";
    const toAddress = () => sent.filter((mail) => mail.to === address).length;
    const a = await createEmail([address]);
    await mailsSent(sent.length);
    const recipientId = (a.recipients[0] as AlertRecipient).id;
    expect((await resend(a.id, recipientId)).status).toBe(202);
    expect((await resend(a.id, recipientId)).status).toBe(202);
    await within(
      (async () => {
        while (toAddress() < 3) await tick(5);
      })(),
      5_000,
      "three mails",
    );
    const refused = await resend(a.id, recipientId);
    await expectProblem(refused, 429);
    const retryAfter = Number(refused.headers.get("retry-after"));
    expect(retryAfter).toBe(12 * 3600);

    // Another Organization adds the same address: the channel is created, but no fourth mail goes out.
    const b = await createEmail([address], adminB);
    await tick(30);
    expect(toAddress()).toBe(3);
    expect(b.recipients[0]).toMatchObject({ status: "pending", last_sent_at: null });

    // The next UTC day, the address gets mail again.
    clock.ms = T0 + 12 * 3600 * 1_000;
    expect((await resend(a.id, recipientId)).status).toBe(202);
    await within(
      (async () => {
        while (toAddress() < 4) await tick(5);
      })(),
      5_000,
      "the fourth mail",
    );
    clock.ms = T0;
  });

  it("sends the test alert only to confirmed recipients, and refuses it when none has confirmed", async () => {
    const lonely = await createEmail(["nobody@x.io"]);
    await tick(20);
    const refused = await api.app.request(`/v1/alert-channels/${lonely.id}/test`, {
      method: "POST",
      headers: bearer(adminA),
    });
    expect((await expectProblem(refused, 409)).reason).toBe("no-confirmed-recipients");

    const before = sent.length;
    const res = await api.app.request(`/v1/alert-channels/${channel.id}/test`, {
      method: "POST",
      headers: bearer(adminA),
    });
    expect(res.status).toBe(200);
    const { delivery } = TestAlertChannelResponseSchema.parse(await res.json());
    expect(delivery).toMatchObject({
      channel_id: channel.id,
      incident_id: null,
      outcome: "delivered",
      status_code: 250,
    });
    const mails = sent.slice(before);
    // Alice and Bob confirmed above; the test alert reaches both, one message each.
    expect(mails.map((mail) => mail.to).sort()).toEqual(["alice@example.com", "bob@example.com"]);
    for (const mail of mails) expect(mail.data).toContain("Subject: [Airverse] Test alert");
  });

  it("refuses an invalid recipient list", async () => {
    for (const recipients of [
      [],
      ["a@x.io", "A@X.IO"],
      ["a@x.io", "b@x.io", "c@x.io", "d@x.io", "e@x.io", "f@x.io"],
      ["a@x.io\r\nRCPT TO:<v@x.io>"],
    ]) {
      await expectProblem(await create({ kind: "email", name: "Bad", recipients }), 400);
    }
  });

  it("removes recipients with their channel: a pending token then confirms nothing", async () => {
    const before = sent.length;
    const doomed = await createEmail(["doomed@x.io"]);
    const [mail] = (await mailsSent(before + 1)).slice(before);
    const token = tokenOf(mail as MailEnvelope);
    const deleted = await api.app.request(`/v1/alert-channels/${doomed.id}`, {
      method: "DELETE",
      headers: bearer(adminA),
    });
    expect(deleted.status).toBe(204);
    expect(JSON.parse((await confirm(token)).text)).toEqual({ confirmed: false });
    const { rows } = await api.db.owner((q) =>
      q.query("SELECT id FROM alert_recipients WHERE channel_id = $1", [doomed.id]),
    );
    expect(rows).toEqual([]);
  });

  it("keeps one Organization's recipients out of another's list", async () => {
    const listedB = await list(adminB);
    expect(listedB.flatMap((c) => c.recipients.map((r) => r.address))).toEqual(["capped@x.io"]);
  });

  it("allows at most 5 confirmation attempts per token, counted even while the token is unknown", async () => {
    const pending = await createEmail(["late@x.io"]);
    await tick(20);
    const recipientId = (pending.recipients[0] as AlertRecipient).id;
    const setToken = (token: string) =>
      api.db.owner((q) =>
        q.query("UPDATE alert_recipients SET token_hash = $2, token_expires_at = $3 WHERE id = $1", [
          recipientId,
          createHash("sha256").update(token).digest("hex"),
          new Date(clock.ms + 3_600_000).toISOString(),
        ]),
      );
    // Five guesses of a token nobody holds yet are answered as any unknown token.
    const guessed = "G".repeat(43);
    for (let i = 0; i < ALERT_EMAIL_LIMITS.confirmAttemptsPerToken; i++) {
      expect(await confirm(guessed)).toEqual({ status: 200, text: JSON.stringify({ confirmed: false }) });
    }
    // Once its attempts are spent, the token confirms nothing, even after it becomes a recipient's token.
    await setToken(guessed);
    expect(await confirm(guessed)).toEqual({ status: 200, text: JSON.stringify({ confirmed: false }) });
    // A fresh token is unaffected.
    const fresh = "F".repeat(43);
    await setToken(fresh);
    expect(JSON.parse((await confirm(fresh)).text)).toEqual({ confirmed: true });
  });

  it("keys the per-address mail count with the server secret, never a plain hash of the address", async () => {
    const { rows } = await api.db.owner((q) =>
      q.query<{ address_hash: string }>("SELECT address_hash FROM confirmation_mail_counts"),
    );
    const stored = rows.map((row) => row.address_hash);
    expect(stored).toContain(hasher.hash("capped@x.io"));
    expect(stored).not.toContain(createHash("sha256").update("capped@x.io").digest("hex"));
  });

  it("records a refused mail as a failed delivery with the SMTP code", async () => {
    outcome = (message) => (message.to === "bob@example.com" ? { ok: false, code: 550 } : { ok: true, code: 250 });
    const res = await api.app.request(`/v1/alert-channels/${channel.id}/test`, {
      method: "POST",
      headers: bearer(adminA),
    });
    const { delivery } = TestAlertChannelResponseSchema.parse(await res.json());
    expect(delivery).toMatchObject({ outcome: "failed", status_code: 550, attempt: 1 });
    outcome = () => ({ ok: true, code: 250 });
  });

  it("caps the public confirmation endpoint at 600 requests a minute in all, whoever calls", async () => {
    let limited: Response | undefined;
    for (let i = 0; i <= ALERT_EMAIL_LIMITS.confirmPerMinute + 1; i++) {
      const token = `${String(i).padStart(6, "0")}${"W".repeat(37)}`;
      const res = await api.app.request("/v1/alert-recipients/confirm", json({ token }));
      if (res.status === 429) {
        limited = res;
        break;
      }
      expect(res.status).toBe(200);
    }
    if (limited === undefined) throw new Error("never limited");
    await expectProblem(limited, 429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
  });
});
