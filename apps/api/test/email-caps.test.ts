import { ALERT_EMAIL_LIMITS, type AlertChannel, CreateAlertChannelResponseSchema } from "@antireverse/protocol";
import { afterEach, describe, expect, it } from "vitest";
import { createAddressHasher } from "../src/mail/address-key.ts";
import { capAddress } from "../src/mail/caps.ts";
import type { MailEnvelope, MailResult } from "../src/mail/smtp.ts";
import { createNotifier, type EmailDeps } from "../src/notify/notifier.ts";
import {
  bearer,
  captureLogger,
  createOrganization,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
  tick,
} from "./helpers.ts";

// The review of slice 06b (F1, F3, F6): who can make Airverse mail an address, how often, and what a tenant learns.

const T0 = Date.parse("2026-11-10T12:00:00.000Z");
const SENDER = { address: "alerts@airverse.example", name: "Airverse" };
type EmailChannel = Extract<AlertChannel, { kind: "email" }>;

const opened: TestApi[] = [];
afterEach(async () => {
  for (const api of opened.splice(0)) await api.close();
});

async function harness(options: { confirmationsPerDay?: number } = {}) {
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const sent: MailEnvelope[] = [];
  const mailer = {
    async send(messages: readonly MailEnvelope[]): Promise<MailResult[]> {
      sent.push(...messages);
      return messages.map(() => ({ ok: true, code: 250 }));
    },
  };
  const email: EmailDeps = { mailer, sender: SENDER, ...options };
  const base = await makeTestApi({ now });
  const notifier = createNotifier({ db: base.db, now, logger: captureLogger(), email, sleep: async () => {} });
  const api = await makeTestApi({ db: base.db, now, notifier, email, addressHasher: createAddressHasher() });
  opened.push(api);
  const org = async (name: string) => (await createOrganization(api, name)).admin_key.key;
  const create = (key: string, recipients: string[]) =>
    api.app.request("/v1/alert-channels", json({ kind: "email", name: "Mail", recipients }, bearer(key)));
  const channel = async (key: string, recipients: string[]): Promise<EmailChannel> => {
    const res = await create(key, recipients);
    expect(res.status).toBe(201);
    const parsed = CreateAlertChannelResponseSchema.parse(await res.json()).channel;
    if (parsed.kind !== "email") throw new Error("kind");
    return parsed;
  };
  const remove = (key: string, id: string) =>
    api.app.request(`/v1/alert-channels/${id}`, { method: "DELETE", headers: bearer(key) });
  const resend = (key: string, c: EmailChannel, index = 0) =>
    api.app.request(`/v1/alert-channels/${c.id}/recipients/${c.recipients[index]?.id}/resend`, {
      method: "POST",
      headers: bearer(key),
    });
  const flush = async () => {
    for (let i = 0; i < 5; i++) await tick(5);
  };
  return { api, clock, sent, org, create, channel, remove, resend, flush };
}

describe("capAddress (F1)", () => {
  it("drops a +tag for every domain, and dots for Gmail, whose two domains are one", () => {
    expect(capAddress("victim+0x1@gmail.com")).toBe("victim@gmail.com");
    expect(capAddress("v.ic.tim@googlemail.com")).toBe("victim@gmail.com");
    expect(capAddress("vic.tim+urgent.call@gmail.com")).toBe("victim@gmail.com");
    expect(capAddress("a.b+c@example.com")).toBe("a.b@example.com");
    expect(capAddress("a.b@example.com")).toBe("a.b@example.com");
    expect(capAddress("+only@example.com")).toBe("+only@example.com");
  });
});

describe("confirmation-mail caps (F1)", () => {
  it("counts +tag and Gmail dot variants as one address: at most 3 mails to one inbox a day", async () => {
    const h = await harness();
    const key = await h.org("A");
    for (const address of [
      "victim+1@gmail.com",
      "v.ictim@gmail.com",
      "victim+2@googlemail.com",
      "vic.tim+x@gmail.com",
    ]) {
      const c = await h.channel(key, [address]);
      await h.remove(key, c.id);
    }
    await h.flush();
    expect(h.sent).toHaveLength(ALERT_EMAIL_LIMITS.confirmationMailsPerAddressPerDay);
  });

  it("sends at most 20 confirmation mails per Organization a day; the rest stay pending without a link", async () => {
    const h = await harness();
    const key = await h.org("A");
    const channels: EmailChannel[] = [];
    for (let c = 0; c < 5; c++) {
      channels.push(
        await h.channel(
          key,
          [0, 1, 2, 3, 4].map((i) => `user${c}x${i}@corp.example`),
        ),
      );
    }
    await h.flush();
    expect(h.sent).toHaveLength(ALERT_EMAIL_LIMITS.confirmationMailsPerOrganizationPerDay);
    const last = channels.at(-1) as EmailChannel;
    const refused = await h.resend(key, last, 4);
    await expectProblem(refused, 429);
    expect(Number(refused.headers.get("retry-after"))).toBe(12 * 3600);
    // Another Organization is not held back by A's use.
    const other = await h.org("B");
    await h.channel(other, ["someone@corp.example"]);
    await h.flush();
    expect(h.sent).toHaveLength(ALERT_EMAIL_LIMITS.confirmationMailsPerOrganizationPerDay + 1);
  });

  it("caps the confirmation mails of the whole service a day (AR_SMTP_CONFIRMATIONS_PER_DAY)", async () => {
    const h = await harness({ confirmationsPerDay: 4 });
    await h.channel(await h.org("A"), ["a1@x.io", "a2@x.io", "a3@x.io"]);
    await h.channel(await h.org("B"), ["b1@x.io", "b2@x.io", "b3@x.io"]);
    await h.flush();
    expect(h.sent).toHaveLength(4);
  });

  it("allows at most 20 email-channel creations per Organization a day, deletions notwithstanding", async () => {
    const h = await harness();
    const key = await h.org("A");
    for (let i = 0; i < ALERT_EMAIL_LIMITS.emailChannelsPerOrganizationPerDay; i++) {
      const c = await h.channel(key, [`n${i}@x.io`]);
      await h.remove(key, c.id);
    }
    const refused = await h.create(key, ["late@x.io"]);
    expect((await expectProblem(refused, 429)).type).toMatch(/too-many-requests$/);
    expect(Number(refused.headers.get("retry-after"))).toBe(12 * 3600);
    h.clock.ms = T0 + 12 * 3600 * 1_000;
    expect((await h.create(key, ["late@x.io"])).status).toBe(201);
  });
});

describe("what a tenant learns from a resend (F6)", () => {
  it("answers the same whether or not another Organization mailed the address today", async () => {
    const h = await harness();
    const a = await h.org("A");
    const b = await h.org("B");
    // A uses up the address's mails of the day.
    const mine = await h.channel(a, ["alice@corp.example"]);
    expect((await h.resend(a, mine)).status).toBe(202);
    expect((await h.resend(a, mine)).status).toBe(202);
    await h.flush();
    const toAlice = () => h.sent.filter((mail) => mail.to === "alice@corp.example").length;
    expect(toAlice()).toBe(3);

    async function probe(key: string, address: string): Promise<number[]> {
      const c = await h.channel(key, [address]);
      const statuses: number[] = [];
      for (let i = 0; i < 3; i++) statuses.push((await h.resend(key, c)).status);
      return statuses;
    }
    const alice = await probe(b, "alice@corp.example");
    const bob = await probe(b, "bob@corp.example");
    expect(alice).toEqual(bob);
    expect(alice).toEqual([202, 202, 429]);
    await h.flush();
    // Nothing more reached Alice: the silent cap for all Organizations held, and her recipient in B stays pending.
    expect(toAlice()).toBe(3);
  });
});

describe("the public confirmation endpoint (F3)", () => {
  it("does not count malformed bodies against the global minute", async () => {
    const h = await harness();
    for (let i = 0; i < ALERT_EMAIL_LIMITS.confirmPerMinute + 5; i++) {
      const res = await h.api.app.request("/v1/alert-recipients/confirm", json({ token: "x" }));
      expect(res.status).toBe(400);
    }
    const valid = await h.api.app.request("/v1/alert-recipients/confirm", json({ token: "Q".repeat(43) }));
    expect(valid.status).toBe(200);
  });
});
