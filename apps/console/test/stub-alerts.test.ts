// @vitest-environment node
import {
  ALERT_EMAIL_LIMITS,
  type AlertChannel,
  ConfirmAlertRecipientResponseSchema,
  CreateAlertChannelResponseSchema,
  ListAlertChannelsResponseSchema,
  ProblemSchema,
  ResendConfirmationResponseSchema,
  TestAlertChannelResponseSchema,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createAlertStore } from "../scripts/stub-alerts.mjs";

// The stand-in API answers alert channels (slices 06 and 06b) in the shape of the protocol: the Console is looked at
// against the same contract the real API serves. Every 2xx body is parsed with its response schema and must come
// back unchanged; every refusal is a problem document with the API's status, reason and Retry-After.

const ORG = "org_0123456789abcdef01234567";
const NOW = Date.parse("2026-11-13T10:00:00.000Z");

interface Answer {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

function parsed<T>(
  schema: { safeParse(value: unknown): { success: boolean; data?: T; error?: unknown } },
  body: unknown,
): T {
  const result = schema.safeParse(body);
  expect(result.success ? [] : (result.error as { issues: unknown[] }).issues).toEqual([]);
  expect(result.data).toEqual(body);
  return result.data as T;
}

function setUp(options: { smtpConfigured?: boolean } = {}) {
  const clock = { ms: NOW };
  const alerts = createAlertStore({ ...options, now: () => clock.ms });
  alerts.seed(ORG);
  const call = (method: string, path: string, body?: unknown): Answer => {
    const answer = alerts.handle(ORG, method, path, body);
    if (answer === null) throw new Error(`no answer for ${method} ${path}`);
    return answer as Answer;
  };
  const list = () => parsed(ListAlertChannelsResponseSchema, call("GET", "/v1/alert-channels").body);
  const emailChannel = () =>
    list().channels.find((one) => one.kind === "email") as Extract<AlertChannel, { kind: "email" }>;
  return { alerts, call, list, emailChannel, clock };
}

function refusal(answer: Answer, status: number) {
  expect(answer.status).toBe(status);
  return parsed(ProblemSchema, answer.body);
}

describe("stub alert channels", () => {
  it("seeds a webhook, a Slack and an email channel with one confirmed and one pending recipient", () => {
    const { list, emailChannel } = setUp();
    const { channels, smtp_configured } = list();
    expect(channels.map((one) => one.kind)).toEqual(["webhook", "slack", "email"]);
    expect(smtp_configured).toBe(true);
    expect(emailChannel().recipients.map((one) => one.status)).toEqual(["confirmed", "pending"]);
  });

  it("says when SMTP is not configured, and then refuses email with 409 smtp-not-configured", () => {
    const { list, call, emailChannel } = setUp({ smtpConfigured: false });
    expect(list().smtp_configured).toBe(false);
    const create = call("POST", "/v1/alert-channels", { kind: "email", name: "Mail", recipients: ["a@example.com"] });
    expect(refusal(create, 409).reason).toBe("smtp-not-configured");
    const channel = emailChannel();
    const pending = channel.recipients[1];
    expect(refusal(call("POST", `/v1/alert-channels/${channel.id}/recipients/${pending?.id}/resend`), 409).reason).toBe(
      "smtp-not-configured",
    );
    expect(refusal(call("POST", `/v1/alert-channels/${channel.id}/test`), 409).reason).toBe("smtp-not-configured");
  });

  it("creates an email channel with lower-cased pending recipients and no secret", () => {
    const { call } = setUp();
    const answer = call("POST", "/v1/alert-channels", {
      kind: "email",
      name: " Mail ",
      recipients: [" A@Example.com", "b@example.com"],
    });
    expect(answer.status).toBe(201);
    const { channel } = parsed(CreateAlertChannelResponseSchema, answer.body);
    if (channel.kind !== "email") throw new Error("not an email channel");
    expect(channel.name).toBe("Mail");
    expect(channel.recipients.map((one) => [one.address, one.status, one.last_sent_at])).toEqual([
      ["a@example.com", "pending", new Date(NOW).toISOString()],
      ["b@example.com", "pending", new Date(NOW).toISOString()],
    ]);
  });

  it("refuses recipients the protocol refuses: none, six, invalid, repeated", () => {
    const { call } = setUp();
    for (const recipients of [
      [],
      ["a", "b", "c", "d", "e", "f"].map((local) => `${local}@example.com`),
      ["not an address"],
      ["a@example.com", "A@example.com"],
      "a@example.com",
    ]) {
      const problem = refusal(call("POST", "/v1/alert-channels", { kind: "email", name: "Mail", recipients }), 400);
      expect(problem.errors?.[0]?.path.startsWith("recipients")).toBe(true);
    }
  });

  it("refuses a test alert to an email channel no recipient of which has confirmed", () => {
    const { call } = setUp();
    const created = call("POST", "/v1/alert-channels", { kind: "email", name: "Mail", recipients: ["a@example.com"] });
    const id = (created.body as { channel: { id: string } }).channel.id;
    expect(refusal(call("POST", `/v1/alert-channels/${id}/test`), 409).reason).toBe("no-confirmed-recipients");
  });

  it("delivers a test alert to an email channel with a confirmed recipient", () => {
    const { call, emailChannel } = setUp();
    const answer = call("POST", `/v1/alert-channels/${emailChannel().id}/test`);
    expect(answer.status).toBe(200);
    expect(parsed(TestAlertChannelResponseSchema, answer.body).delivery.outcome).toBe("delivered");
  });

  it("resends a confirmation (202), refuses a confirmed recipient (409) and caps mails per address per day (429)", () => {
    const { call, emailChannel, clock } = setUp();
    const channel = emailChannel();
    const [confirmed, pending] = channel.recipients;
    const resend = (id: string | undefined) => call("POST", `/v1/alert-channels/${channel.id}/recipients/${id}/resend`);

    expect(refusal(resend(confirmed?.id), 409).reason).toBe("recipient-confirmed");
    expect(refusal(resend("rcp_ffffffffffffffffffffffff"), 404).status).toBe(404);

    // The seed sent the pending recipient its first mail today: two more are allowed.
    for (let mail = 2; mail <= ALERT_EMAIL_LIMITS.confirmationMailsPerAddressPerDay; mail++) {
      const answer = resend(pending?.id);
      expect(answer.status).toBe(202);
      const { recipient } = parsed(ResendConfirmationResponseSchema, answer.body);
      expect(recipient.status).toBe("pending");
    }
    const limited = resend(pending?.id);
    refusal(limited, 429);
    expect(Number(limited.headers?.["retry-after"])).toBeGreaterThan(0);

    // A new UTC day: allowed again.
    clock.ms += 86_400_000;
    expect(resend(pending?.id).status).toBe(202);
  });

  it("confirms a recipient by the token of its latest link, once, and answers false alike otherwise", () => {
    const { alerts, emailChannel } = setUp();
    const channel = emailChannel();
    const pending = channel.recipients[1];
    const token = alerts.confirmationToken(ORG, pending?.id ?? "");
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const confirm = (body: unknown) => alerts.confirm(body) as Answer;
    const yes = confirm({ token });
    expect(yes.status).toBe(200);
    expect(parsed(ConfirmAlertRecipientResponseSchema, yes.body)).toEqual({ confirmed: true });
    const after = emailChannel().recipients[1];
    expect(after?.status).toBe("confirmed");
    expect(after?.confirmed_at).toBe(new Date(NOW).toISOString());

    expect(confirm({ token }).body).toEqual({ confirmed: false });
    expect(confirm({ token: "A".repeat(43) }).body).toEqual({ confirmed: false });
    refusal(confirm({ token: "short" }), 400);
    refusal(confirm(undefined), 400);
  });

  it("expires a link after 72 hours", () => {
    const { alerts, emailChannel, clock } = setUp();
    const token = alerts.confirmationToken(ORG, emailChannel().recipients[1]?.id ?? "");
    clock.ms += ALERT_EMAIL_LIMITS.confirmationTtlS * 1000 + 1;
    expect(alerts.confirm({ token }).body).toEqual({ confirmed: false });
  });

  it("limits confirmation requests per minute, all callers together, with 429 and Retry-After", () => {
    const { alerts } = setUp();
    let last: Answer = { status: 0, body: null };
    for (let attempt = 0; attempt <= ALERT_EMAIL_LIMITS.confirmPerMinute; attempt++) {
      last = alerts.confirm({ token: "B".repeat(43) }) as Answer;
    }
    refusal(last, 429);
    expect(last.headers?.["retry-after"]).toBe("60");
  });

  it("confirms nothing once a token's attempts are spent", () => {
    const { alerts, emailChannel } = setUp();
    const token = alerts.confirmationToken(ORG, emailChannel().recipients[1]?.id ?? "");
    const wrong = `${token?.slice(0, 42)}${token?.endsWith("A") ? "B" : "A"}`;
    for (let attempt = 0; attempt < ALERT_EMAIL_LIMITS.confirmAttemptsPerToken; attempt++)
      alerts.confirm({ token: wrong });
    expect(alerts.confirm({ token: wrong }).body).toEqual({ confirmed: false });
    for (let attempt = 0; attempt < ALERT_EMAIL_LIMITS.confirmAttemptsPerToken; attempt++) {
      expect(alerts.confirm({ token: "C".repeat(43) }).body).toEqual({ confirmed: false });
    }
    // The real token still works: attempts are counted per token.
    expect(alerts.confirm({ token }).body).toEqual({ confirmed: true });
  });

  it("keeps webhook and Slack channels as before: create, test, delete", () => {
    const { call, list } = setUp();
    const created = call("POST", "/v1/alert-channels", {
      kind: "webhook",
      name: "Hook",
      url: "https://alerts.acme.test/in",
    });
    expect(created.status).toBe(201);
    const { channel } = parsed(CreateAlertChannelResponseSchema, created.body);
    expect(
      parsed(TestAlertChannelResponseSchema, call("POST", `/v1/alert-channels/${channel.id}/test`).body),
    ).toBeTruthy();
    expect(call("DELETE", `/v1/alert-channels/${channel.id}`).status).toBe(204);
    expect(list().channels.some((one) => one.id === channel.id)).toBe(false);
    refusal(call("POST", "/v1/alert-channels", { kind: "slack", name: "x", url: "http://127.0.0.1/x" }), 400);
  });
});
