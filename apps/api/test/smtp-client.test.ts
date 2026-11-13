import { createServer } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import type { SmtpSettings } from "../src/mail/settings.ts";
import { createSmtpMailer, dotStuff, type MailEnvelope, SMTP_TIMEOUTS } from "../src/mail/smtp.ts";
import {
  type FakeSmtp,
  type FakeSmtpOptions,
  SMTP_PASSWORD,
  SMTP_TEST_CA,
  SMTP_USER,
  startFakeSmtp,
} from "./fake-smtp.ts";

const FROM = "alerts@airverse.example";
const running: FakeSmtp[] = [];

afterEach(async () => {
  for (const server of running.splice(0)) await server.close();
});

async function server(options: FakeSmtpOptions): Promise<FakeSmtp> {
  const started = await startFakeSmtp(options);
  running.push(started);
  return started;
}

function settings(port: number, patch: Partial<SmtpSettings> = {}): SmtpSettings {
  return {
    host: "127.0.0.1",
    port,
    tls: "starttls",
    user: SMTP_USER,
    password: SMTP_PASSWORD,
    from: { address: FROM, name: "Airverse" },
    ca: SMTP_TEST_CA,
    ...patch,
  };
}

const mail = (to: string, data = "Subject: hi\r\n\r\nHello.\r\n"): MailEnvelope => ({ from: FROM, to, data });

describe("SMTP client", () => {
  it("has the plan's timeouts: 10 s connect, 30 s per command, 60 s in all", () => {
    expect(SMTP_TIMEOUTS).toEqual({ connectMs: 10_000, commandMs: 30_000, totalMs: 60_000 });
  });

  it("delivers over STARTTLS with AUTH PLAIN, one message per recipient on one connection, then QUITs", async () => {
    const smtp = await server({ mode: "starttls" });
    const mailer = createSmtpMailer({ settings: settings(smtp.port) });
    const results = await mailer.send([mail("alice@example.com"), mail("bob@example.com")]);
    expect(results).toEqual([
      { ok: true, code: 250 },
      { ok: true, code: 250 },
    ]);
    expect(smtp.connections).toBe(1);
    expect(smtp.mails.map((m) => [m.from, m.to, m.overTls])).toEqual([
      [FROM, ["alice@example.com"], true],
      [FROM, ["bob@example.com"], true],
    ]);
    expect(smtp.commands).toEqual([
      "EHLO airverse.example",
      "STARTTLS",
      "[tls] EHLO airverse.example",
      "[tls] AUTH PLAIN",
      `[tls] MAIL FROM:<${FROM}>`,
      "[tls] RCPT TO:<alice@example.com>",
      "[tls] DATA",
      `[tls] MAIL FROM:<${FROM}>`,
      "[tls] RCPT TO:<bob@example.com>",
      "[tls] DATA",
      "[tls] QUIT",
    ]);
    expect(smtp.authInClear).toBe(false);
  });

  it("uses AUTH LOGIN when PLAIN is not offered", async () => {
    const smtp = await server({ mode: "starttls", auth: ["LOGIN"] });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: true, code: 250 }]);
    expect(smtp.commands).toContain("[tls] AUTH LOGIN");
    expect(smtp.authInClear).toBe(false);
  });

  it("delivers over implicit TLS", async () => {
    const smtp = await server({ mode: "implicit" });
    const results = await createSmtpMailer({ settings: settings(smtp.port, { tls: "implicit" }) }).send([
      mail("alice@example.com"),
    ]);
    expect(results).toEqual([{ ok: true, code: 250 }]);
    expect(smtp.mails[0]?.overTls).toBe(true);
  });

  it("refuses to go on when STARTTLS is not offered: no AUTH and no mail in the clear", async () => {
    const smtp = await server({ mode: "plain" });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: false, code: null }]);
    expect(smtp.authInClear).toBe(false);
    expect(smtp.commands.some((line) => line.startsWith("AUTH") || line.startsWith("MAIL"))).toBe(false);
    expect(smtp.mails).toEqual([]);
  });

  it("refuses when STARTTLS is offered but fails, even if AUTH is offered in the clear", async () => {
    const smtp = await server({ mode: "starttls", starttlsReply: "454 4.7.0 TLS not available", authBeforeTls: true });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: false, code: 454 }]);
    expect(smtp.authInClear).toBe(false);
    expect(smtp.mails).toEqual([]);
  });

  it("ignores AUTH advertised before TLS and authenticates only after it", async () => {
    const smtp = await server({ mode: "starttls", authBeforeTls: true });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: true, code: 250 }]);
    expect(smtp.authInClear).toBe(false);
  });

  it("aborts when the server sends data after its STARTTLS reply (response injection)", async () => {
    const smtp = await server({ mode: "starttls", injectAfterStarttls: "250 injected\r\n" });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: false, code: null }]);
    expect(smtp.authInClear).toBe(false);
    expect(smtp.mails).toEqual([]);
  });

  it("validates the certificate: an unknown CA or another host name is refused before AUTH", async () => {
    const smtp = await server({ mode: "starttls" });
    const unknownCa = await createSmtpMailer({ settings: settings(smtp.port, { ca: undefined }) }).send([
      mail("alice@example.com"),
    ]);
    expect(unknownCa).toEqual([{ ok: false, code: null }]);
    const other = await server({ mode: "implicit", cert: "other" });
    const wrongHost = await createSmtpMailer({ settings: settings(other.port, { tls: "implicit" }) }).send([
      mail("alice@example.com"),
    ]);
    expect(wrongHost).toEqual([{ ok: false, code: null }]);
    expect(smtp.mails).toEqual([]);
    expect(other.mails).toEqual([]);
    expect(smtp.commands.some((line) => line.includes("AUTH"))).toBe(false);
  });

  it("refuses when no supported AUTH mechanism is offered", async () => {
    const smtp = await server({ mode: "starttls", auth: ["CRAM-MD5"] });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: false, code: null }]);
    expect(smtp.mails).toEqual([]);
  });

  it("reports bad credentials with the reply code", async () => {
    const smtp = await server({ mode: "starttls", password: "other" });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: false, code: 535 }]);
  });

  it("handles a refused recipient on its own: the others are still delivered", async () => {
    const smtp = await server({ mode: "starttls", refuse: { "bob@example.com": "550 5.1.1 No such user" } });
    const results = await createSmtpMailer({ settings: settings(smtp.port) }).send([
      mail("alice@example.com"),
      mail("bob@example.com"),
      mail("carol@example.com"),
    ]);
    expect(results).toEqual([
      { ok: true, code: 250 },
      { ok: false, code: 550 },
      { ok: true, code: 250 },
    ]);
    expect(smtp.mails.map((m) => m.to)).toEqual([["alice@example.com"], ["carol@example.com"]]);
    expect(smtp.commands).toContain("[tls] RSET");
  });

  it("checks the reply to MAIL and to the end of DATA", async () => {
    const busy = await server({ mode: "starttls", mailReply: "451 4.3.0 Try later" });
    expect(await createSmtpMailer({ settings: settings(busy.port) }).send([mail("a@x.io")])).toEqual([
      { ok: false, code: 451 },
    ]);
    const full = await server({ mode: "starttls", dataReply: "552 5.3.4 Too big" });
    expect(await createSmtpMailer({ settings: settings(full.port) }).send([mail("a@x.io")])).toEqual([
      { ok: false, code: 552 },
    ]);
  });

  it("marks a message whose data was sent but whose final reply never came (F4)", async () => {
    const smtp = await server({ mode: "starttls", silentOn: "DATA-END" });
    const results = await createSmtpMailer({
      settings: settings(smtp.port),
      timeouts: { connectMs: 1_000, commandMs: 150, totalMs: 3_000 },
    }).send([mail("alice@example.com"), mail("bob@example.com")]);
    expect(results).toEqual([
      { ok: false, code: null, dataSent: true },
      { ok: false, code: null },
    ]);
    const refused = await server({ mode: "starttls", refuse: { "bob@example.com": "550 5.1.1 No such user" } });
    const plain = await createSmtpMailer({ settings: settings(refused.port) }).send([mail("bob@example.com")]);
    expect(plain).toEqual([{ ok: false, code: 550 }]);
  });

  it("normalises line endings and dot-stuffs the data", async () => {
    const smtp = await server({ mode: "starttls" });
    const data = "Subject: dots\n\n.leading dot\r.\r\n..two\nend";
    await createSmtpMailer({ settings: settings(smtp.port) }).send([mail("alice@example.com", data)]);
    expect(smtp.mails[0]?.data).toBe("Subject: dots\r\n\r\n.leading dot\r\n.\r\n..two\r\nend");
  });

  it("dot-stuffs every line that starts with a dot", () => {
    expect(dotStuff(".\r\n.a\r\nb.\r\n..")).toBe("..\r\n..a\r\nb.\r\n...");
  });

  it("never sends to or from an address that could break a command", async () => {
    const smtp = await server({ mode: "starttls" });
    const mailer = createSmtpMailer({ settings: settings(smtp.port) });
    const results = await mailer.send([
      mail("alice@example.com>\r\nRCPT TO:<eve@example.com"),
      mail("bob@example.com"),
    ]);
    expect(results).toEqual([
      { ok: false, code: null },
      { ok: true, code: 250 },
    ]);
    expect(smtp.commands.some((line) => line.includes("eve@"))).toBe(false);
  });

  it("times out a silent server: per command, at connect and in all", async () => {
    const silent = await server({ mode: "starttls", silentOn: "EHLO" });
    const started = Date.now();
    const results = await createSmtpMailer({
      settings: settings(silent.port),
      timeouts: { connectMs: 200, commandMs: 150, totalMs: 5_000 },
    }).send([mail("alice@example.com")]);
    expect(results).toEqual([{ ok: false, code: null }]);
    expect(Date.now() - started).toBeLessThan(2_000);

    const slow = await server({ mode: "starttls", replyDelayMs: 60 });
    const total = Date.now();
    const cut = await createSmtpMailer({
      settings: settings(slow.port),
      timeouts: { connectMs: 1_000, commandMs: 1_000, totalMs: 250 },
    }).send([mail("alice@example.com")]);
    expect(cut).toEqual([{ ok: false, code: null }]);
    expect(Date.now() - total).toBeLessThan(2_000);

    // A listener that accepts nothing: the TCP connect never completes within the bound (a full backlog), or the
    // greeting never comes. Either way the session ends within its bounds.
    const mute = createServer(() => {});
    await new Promise<void>((resolve) => mute.listen(0, "127.0.0.1", resolve));
    const port = (mute.address() as { port: number }).port;
    const muted = Date.now();
    const none = await createSmtpMailer({
      settings: settings(port),
      timeouts: { connectMs: 150, commandMs: 150, totalMs: 1_000 },
    }).send([mail("alice@example.com")]);
    expect(none).toEqual([{ ok: false, code: null }]);
    expect(Date.now() - muted).toBeLessThan(2_000);
    await new Promise<void>((resolve) => mute.close(() => resolve()));
  });

  it("fails every message when nothing listens, and is stopped by the caller's signal", async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, "127.0.0.1", resolve));
    const port = (closed.address() as { port: number }).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    expect(await createSmtpMailer({ settings: settings(port) }).send([mail("a@x.io"), mail("b@x.io")])).toEqual([
      { ok: false, code: null },
      { ok: false, code: null },
    ]);

    const slow = await server({ mode: "starttls", silentOn: "MAIL" });
    const stop = new AbortController();
    const pending = createSmtpMailer({ settings: settings(slow.port) }).send([mail("a@x.io")], stop.signal);
    setTimeout(() => stop.abort(), 100);
    expect(await pending).toEqual([{ ok: false, code: null }]);
  });

  it("answers an empty batch without connecting", async () => {
    const smtp = await server({ mode: "starttls" });
    expect(await createSmtpMailer({ settings: settings(smtp.port) }).send([])).toEqual([]);
    expect(smtp.connections).toBe(0);
  });
});
