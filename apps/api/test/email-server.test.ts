import {
  CreateAlertChannelResponseSchema,
  CreateOrganizationResponseSchema,
  ListAlertChannelsResponseSchema,
  TestAlertChannelResponseSchema,
} from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decodeQuotedPrintable } from "../src/mail/message.ts";
import { type RunningApi, startApi } from "../src/server.ts";
import { type FakeSmtp, SMTP_PASSWORD, SMTP_TEST_CA, SMTP_USER, startFakeSmtp } from "./fake-smtp.ts";
import { bearer, captureLogger, json, tick, within } from "./helpers.ts";

const running: { close(): Promise<void> }[] = [];

afterEach(async () => {
  vi.unstubAllEnvs();
  for (const item of running.splice(0).reverse()) await item.close();
});

describe("email alerts through the started API and a local SMTP server", () => {
  it("refuses to start on a partial AR_SMTP_* set, naming the missing variable and no value", async () => {
    vi.stubEnv("AR_SMTP_HOST", "smtp.example.com");
    vi.stubEnv("AR_SMTP_PASSWORD", SMTP_PASSWORD);
    const failure = await startApi({ logger: captureLogger() }).then(
      (api) => {
        running.push(api);
        return null;
      },
      (error: unknown) => error as Error,
    );
    expect(failure?.message).toBe("AR_SMTP_USER is required when any AR_SMTP_* variable is set.");
    expect(failure?.message).not.toContain(SMTP_PASSWORD);
  });

  it("confirms a recipient by the mailed link and sends the test alert to it alone; the password is never logged", async () => {
    const smtp: FakeSmtp = await startFakeSmtp({ mode: "starttls" });
    running.push(smtp);
    const logger = captureLogger();
    const api: RunningApi = await startApi({
      logger,
      consoleUrl: "https://console.airverse.example",
      smtp: {
        host: "127.0.0.1",
        port: smtp.port,
        tls: "starttls",
        user: SMTP_USER,
        password: SMTP_PASSWORD,
        from: { address: "alerts@airverse.example", name: "Airverse" },
        ca: SMTP_TEST_CA,
      },
    });
    running.push(api);

    const org = CreateOrganizationResponseSchema.parse(
      await (await fetch(`${api.url}/v1/organizations`, json({ name: "Acme" }))).json(),
    );
    const admin = org.admin_key.key;
    const listed = await fetch(`${api.url}/v1/alert-channels`, { headers: bearer(admin) });
    expect(ListAlertChannelsResponseSchema.parse(await listed.json()).smtp_configured).toBe(true);

    const created = await fetch(
      `${api.url}/v1/alert-channels`,
      json({ kind: "email", name: "On-call", recipients: ["alice@example.com", "bob@example.com"] }, bearer(admin)),
    );
    expect(created.status).toBe(201);
    const { channel } = CreateAlertChannelResponseSchema.parse(await created.json());

    await within(
      (async () => {
        while (smtp.mails.length < 2) await tick(10);
      })(),
      10_000,
      "two confirmation mails",
    );
    const toAlice = smtp.mails.find((mail) => mail.to.includes("alice@example.com"));
    expect(toAlice?.overTls).toBe(true);
    const data = String(toAlice?.data);
    const token = /token=([A-Za-z0-9_-]{43})/.exec(
      decodeQuotedPrintable(data.slice(data.indexOf("\r\n\r\n") + 4)),
    )?.[1];
    expect(token).toBeDefined();

    const confirmed = await fetch(`${api.url}/v1/alert-recipients/confirm`, json({ token }));
    expect(await confirmed.json()).toEqual({ confirmed: true });

    const before = smtp.mails.length;
    const tested = await fetch(`${api.url}/v1/alert-channels/${channel.id}/test`, {
      method: "POST",
      headers: bearer(admin),
    });
    expect(tested.status).toBe(200);
    expect(TestAlertChannelResponseSchema.parse(await tested.json()).delivery).toMatchObject({
      outcome: "delivered",
      status_code: 250,
    });
    const alerts = smtp.mails.slice(before);
    expect(alerts.map((mail) => mail.to)).toEqual([["alice@example.com"]]);
    expect(smtp.authInClear).toBe(false);

    for (const line of logger.lines) {
      expect(line).not.toContain(SMTP_PASSWORD);
      expect(line).not.toContain(String(token));
      expect(line).not.toContain("@example.com");
    }
    expect(logger.lines).toContain(`email alerts on: smtp host=127.0.0.1 port=${smtp.port} tls=starttls`);
  });
});
