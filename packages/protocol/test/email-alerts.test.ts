import { describe, expect, it } from "vitest";
import {
  ALERT_EMAIL_LIMITS,
  ALERT_RECIPIENT_STATUSES,
  type AlertChannel,
  AlertChannelSchema,
  type AlertRecipient,
  AlertRecipientSchema,
  CONFIRMATION_TOKEN_PATTERN,
  CONFLICT_REASONS,
  type ConfirmAlertRecipientRequest,
  ConfirmAlertRecipientRequestSchema,
  type ConfirmAlertRecipientResponse,
  ConfirmAlertRecipientResponseSchema,
  type CreateAlertChannelRequest,
  CreateAlertChannelRequestSchema,
  CreateAlertChannelResponseSchema,
  EMAIL_ADDRESS_PATTERN,
  EXAMPLE_ALERT_CHANNEL,
  EXAMPLE_EMAIL_CHANNEL,
  ID_PATTERNS,
  type ListAlertChannelsResponse,
  ListAlertChannelsResponseSchema,
  type ResendConfirmationResponse,
  ResendConfirmationResponseSchema,
} from "../src/index.ts";

import { SAFE_NAMES, UNSAFE_NAMES } from "./names.ts";

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;
const TOKEN = "A".repeat(43);

describe("email alert constants (slice 06b)", () => {
  it("has the limits of the plan's Global Constraints", () => {
    expect(ALERT_EMAIL_LIMITS).toEqual({
      recipientsMax: 5,
      addressMax: 254,
      localPartMax: 64,
      confirmationTtlS: 72 * 3600,
      confirmationMailsPerAddressPerDay: 3,
      confirmationMailsPerOrganizationPerDay: 20,
      confirmationMailsPerDay: 500,
      emailChannelsPerOrganizationPerDay: 20,
      confirmAttemptsPerToken: 5,
      confirmPerMinute: 600,
    });
    expect(Object.isFrozen(ALERT_EMAIL_LIMITS)).toBe(true);
  });

  it("lists the recipient statuses and the rcp identifier", () => {
    expect(ALERT_RECIPIENT_STATUSES).toEqual(["pending", "confirmed"]);
    expect(ID_PATTERNS.rcp.test("rcp_0123456789abcdef01234567")).toBe(true);
    expect(ID_PATTERNS.rcp.test("chn_0123456789abcdef01234567")).toBe(false);
  });

  it("names the conflicts of email channels", () => {
    expect(CONFLICT_REASONS).toEqual(
      expect.arrayContaining(["smtp-not-configured", "recipient-confirmed", "no-confirmed-recipients"]),
    );
  });

  it("has a confirmation token of 32 bytes as 43 base64url characters", () => {
    expect(CONFIRMATION_TOKEN_PATTERN.test(TOKEN)).toBe(true);
    expect(CONFIRMATION_TOKEN_PATTERN.test(`${"-_".repeat(21)}a`)).toBe(true);
    for (const token of ["A".repeat(42), "A".repeat(44), `${"A".repeat(42)}=`, `${"A".repeat(42)}+`, ""]) {
      expect(CONFIRMATION_TOKEN_PATTERN.test(token), token).toBe(false);
    }
  });
});

describe("EMAIL_ADDRESS_PATTERN", () => {
  it("accepts plain lower-case addresses", () => {
    for (const address of [
      "alice@example.com",
      "ops+alerts@sub.example.co.uk",
      "a.b-c_d@x-y.example",
      "o'brien@example.org",
      "1@2.example",
    ]) {
      expect(EMAIL_ADDRESS_PATTERN.test(address), address).toBe(true);
    }
  });

  it("refuses anything that could break an SMTP command or a header", () => {
    for (const address of [
      "alice@example.com\r\nRCPT TO:<x@y.z>",
      "alice@example.com\n",
      "alice\u0000@example.com",
      "<alice@example.com>",
      "alice@example.com>",
      "alice @example.com",
      "Alice@example.com",
      "alice@EXAMPLE.com",
      '"alice"@example.com',
      "alice@[127.0.0.1]",
      "alice@localhost",
      "alice@example",
      "alice@@example.com",
      "@example.com",
      "alice@",
      ".alice@example.com",
      "alice.@example.com",
      "al..ice@example.com",
      "alice@-example.com",
      "alice@example-.com",
      "alice@exa..mple.com",
      "alïce@example.com",
      "alice@exämple.com",
      "alice@example.com ",
      "alice,bob@example.com",
      "alice;bob@example.com",
      "alice:bob@example.com",
      "",
    ]) {
      expect(EMAIL_ADDRESS_PATTERN.test(address), JSON.stringify(address)).toBe(false);
    }
  });
});

describe("AlertRecipientSchema", () => {
  const recipient = EXAMPLE_EMAIL_CHANNEL.kind === "email" ? EXAMPLE_EMAIL_CHANNEL.recipients[0] : undefined;

  it("parses the documented recipient and never carries a token", () => {
    const parsed: AlertRecipient = AlertRecipientSchema.parse({ ...recipient, token: TOKEN, token_hash: "x" });
    expect(parsed).toEqual(recipient);
    expect(Object.keys(parsed).sort()).toEqual(["address", "confirmed_at", "id", "last_sent_at", "status"]);
  });

  it("requires a rcp id, a valid address, a known status and ISO times or null", () => {
    const with_ = (patch: Record<string, unknown>) => ({ ...recipient, ...patch });
    expect(ok(AlertRecipientSchema, with_({ id: "chn_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(AlertRecipientSchema, with_({ address: "not an address" }))).toBe(false);
    expect(ok(AlertRecipientSchema, with_({ status: "bounced" }))).toBe(false);
    expect(ok(AlertRecipientSchema, with_({ confirmed_at: "yesterday" }))).toBe(false);
    expect(ok(AlertRecipientSchema, with_({ last_sent_at: null }))).toBe(true);
  });

  it("ties confirmed_at to the status: set when confirmed, null when pending", () => {
    const at = "2026-11-10T09:00:00.000Z";
    expect(ok(AlertRecipientSchema, { ...recipient, status: "confirmed", confirmed_at: at })).toBe(true);
    expect(ok(AlertRecipientSchema, { ...recipient, status: "confirmed", confirmed_at: null })).toBe(false);
    expect(ok(AlertRecipientSchema, { ...recipient, status: "pending", confirmed_at: at })).toBe(false);
    expect(ok(AlertRecipientSchema, { ...recipient, status: "pending", confirmed_at: null })).toBe(true);
  });
});

describe("AlertChannelSchema of kind email", () => {
  it("parses the documented email channel unchanged: recipients, never a URL", () => {
    const parsed: AlertChannel = AlertChannelSchema.parse(EXAMPLE_EMAIL_CHANNEL);
    expect(parsed).toEqual(EXAMPLE_EMAIL_CHANNEL);
    expect(Object.keys(parsed).sort()).toEqual(["active", "created_at", "id", "kind", "name", "recipients"]);
  });

  it("requires 1..5 recipients", () => {
    if (EXAMPLE_EMAIL_CHANNEL.kind !== "email") throw new Error("example");
    const one = EXAMPLE_EMAIL_CHANNEL.recipients[0] as AlertRecipient;
    const many = (n: number) =>
      Array.from({ length: n }, (_, i) => ({
        ...one,
        id: `rcp_${String(i).padStart(24, "0")}`,
        address: `a${i}@x.io`,
      }));
    expect(ok(AlertChannelSchema, { ...EXAMPLE_EMAIL_CHANNEL, recipients: [] })).toBe(false);
    expect(ok(AlertChannelSchema, { ...EXAMPLE_EMAIL_CHANNEL, recipients: many(5) })).toBe(true);
    expect(ok(AlertChannelSchema, { ...EXAMPLE_EMAIL_CHANNEL, recipients: many(6) })).toBe(false);
  });

  it("keeps a URL channel without recipients, and an email channel without host or url_last4", () => {
    expect(AlertChannelSchema.parse({ ...EXAMPLE_ALERT_CHANNEL, recipients: [] })).toEqual(EXAMPLE_ALERT_CHANNEL);
    expect(ok(AlertChannelSchema, { ...EXAMPLE_ALERT_CHANNEL, kind: "email" })).toBe(false);
    const { recipients: _, ...emailWithout } = EXAMPLE_EMAIL_CHANNEL as Extract<AlertChannel, { kind: "email" }>;
    expect(ok(AlertChannelSchema, { ...emailWithout, kind: "email", host: "x.io", url_last4: "abcd" })).toBe(false);
  });

  it("is listed with the smtp_configured flag", () => {
    const list: ListAlertChannelsResponse = ListAlertChannelsResponseSchema.parse({
      channels: [EXAMPLE_ALERT_CHANNEL, EXAMPLE_EMAIL_CHANNEL],
      smtp_configured: false,
    });
    expect(list.smtp_configured).toBe(false);
    expect(ok(ListAlertChannelsResponseSchema, { channels: [] })).toBe(false);
    expect(ok(ListAlertChannelsResponseSchema, { channels: [], smtp_configured: "yes" })).toBe(false);
  });

  it("is created without a signing secret", () => {
    expect(ok(CreateAlertChannelResponseSchema, { channel: EXAMPLE_EMAIL_CHANNEL })).toBe(true);
    expect(
      ok(CreateAlertChannelResponseSchema, { channel: EXAMPLE_EMAIL_CHANNEL, signing_secret: `whsec_${TOKEN}` }),
    ).toBe(false);
  });
});

describe("CreateAlertChannelRequestSchema of kind email", () => {
  const request = (patch: Record<string, unknown>) => ({
    kind: "email",
    name: "On-call",
    recipients: ["alice@example.com"],
    ...patch,
  });

  it("trims and lower-cases each recipient", () => {
    const parsed: CreateAlertChannelRequest = CreateAlertChannelRequestSchema.parse(
      request({ recipients: ["  Alice@Example.COM ", "bob@example.com"] }),
    );
    expect(parsed).toEqual({ kind: "email", name: "On-call", recipients: ["alice@example.com", "bob@example.com"] });
  });

  it("requires 1..5 recipients", () => {
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: [] }))).toBe(false);
    const five = ["a@x.io", "b@x.io", "c@x.io", "d@x.io", "e@x.io"];
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: five }))).toBe(true);
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: [...five, "f@x.io"] }))).toBe(false);
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: undefined }))).toBe(false);
  });

  it("refuses duplicates after lower-casing, at the path of the repeat", () => {
    const result = CreateAlertChannelRequestSchema.safeParse(request({ recipients: ["a@x.io", "b@x.io", "A@X.IO"] }));
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.path)).toEqual([["recipients", 2]]);
  });

  it("refuses an invalid or over-long address at its path", () => {
    const local = "a".repeat(64);
    const label = "b".repeat(63);
    const at254 = `${local}@${label}.${label}.${"c".repeat(254 - 64 - 1 - 63 - 1 - 63 - 1)}`;
    expect(at254.length).toBe(254);
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: [at254] }))).toBe(true);
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: [`${at254}d`] }))).toBe(false);
    expect(ok(CreateAlertChannelRequestSchema, request({ recipients: [`${local}a@x.io`] }))).toBe(false);
    const result = CreateAlertChannelRequestSchema.safeParse(
      request({ recipients: ["a@x.io", "x@y.z\r\nRCPT TO:<v@w.io>"] }),
    );
    expect(result.error?.issues.map((issue) => issue.path)).toEqual([["recipients", 1]]);
  });

  it("refuses a URL on an email channel and recipients on a URL channel by stripping them", () => {
    expect(CreateAlertChannelRequestSchema.parse(request({ url: "https://x.io" }))).not.toHaveProperty("url");
    const webhook = CreateAlertChannelRequestSchema.parse({
      kind: "webhook",
      name: "W",
      url: "https://hooks.example.com/ar",
      recipients: ["a@x.io"],
    });
    expect(webhook).not.toHaveProperty("recipients");
    expect(ok(CreateAlertChannelRequestSchema, { kind: "webhook", name: "W", recipients: ["a@x.io"] })).toBe(false);
  });
});

describe("alert channel names (one rule with App names)", () => {
  it("refuses control characters, line separators, bidi overrides and zero-width space; allows ZWJ, ZWNJ, LRM, RLM", () => {
    for (const name of UNSAFE_NAMES) {
      for (const body of [
        { kind: "email", name, recipients: ["a@x.io"] },
        { kind: "webhook", name, url: "https://hooks.example.com/ar" },
      ]) {
        const result = CreateAlertChannelRequestSchema.safeParse(body);
        expect(result.success, JSON.stringify(name)).toBe(false);
        expect(result.error?.issues.map((issue) => issue.path)).toEqual([["name"]]);
      }
    }
    for (const name of SAFE_NAMES) {
      expect(
        CreateAlertChannelRequestSchema.safeParse({ kind: "email", name, recipients: ["a@x.io"] }).success,
        name,
      ).toBe(true);
    }
    // A channel stored before this rule is still valid in a response.
    expect(AlertChannelSchema.parse({ ...EXAMPLE_ALERT_CHANNEL, name: "Ops\u2028old" }).name).toBe("Ops\u2028old");
  });
});

describe("confirmation and resend", () => {
  it("takes a token and answers a boolean", () => {
    const request: ConfirmAlertRecipientRequest = ConfirmAlertRecipientRequestSchema.parse({ token: TOKEN, x: 1 });
    expect(request).toEqual({ token: TOKEN });
    expect(ok(ConfirmAlertRecipientRequestSchema, { token: "short" })).toBe(false);
    expect(ok(ConfirmAlertRecipientRequestSchema, {})).toBe(false);
    const response: ConfirmAlertRecipientResponse = ConfirmAlertRecipientResponseSchema.parse({ confirmed: false });
    expect(response).toEqual({ confirmed: false });
    expect(Object.keys(ConfirmAlertRecipientResponseSchema.parse({ confirmed: true, address: "a@x.io" }))).toEqual([
      "confirmed",
    ]);
  });

  it("answers a resend with the recipient", () => {
    if (EXAMPLE_EMAIL_CHANNEL.kind !== "email") throw new Error("example");
    const recipient = EXAMPLE_EMAIL_CHANNEL.recipients[0];
    const response: ResendConfirmationResponse = ResendConfirmationResponseSchema.parse({ recipient });
    expect(response).toEqual({ recipient });
  });
});
