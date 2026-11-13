import { EXAMPLE_INCIDENT } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  alertMail,
  buildMessage,
  cleanHeaderText,
  confirmationMail,
  decodeQuotedPrintable,
  encodeQuotedPrintable,
  SUBJECT_TITLE_MAX,
  subjectFor,
  testAlertMail,
} from "../src/mail/message.ts";

const FROM = { address: "alerts@airverse.example", name: "Airverse" };
const DATE = new Date("2026-11-10T08:20:01.000Z");

function build(subject: string, body = "Hello.\n", to = "alice@example.com", fromName = "Airverse") {
  return buildMessage({
    from: { ...FROM, name: fromName },
    to,
    subject,
    body,
    date: DATE,
    messageId: "<0123456789abcdef@airverse.example>",
  });
}

/** The header section and the body of a message, split at the first empty line. */
function split(message: string): { headers: string[]; body: string } {
  const at = message.indexOf("\r\n\r\n");
  expect(at).toBeGreaterThan(0);
  return { headers: message.slice(0, at).split("\r\n"), body: message.slice(at + 4) };
}

/** The header fields of a header section: continuation lines (starting with a space) unfolded into their field. */
function fields(headers: string[]): string[] {
  const out: string[] = [];
  for (const line of headers) {
    if (line.startsWith(" ")) out[out.length - 1] += line;
    else out.push(line);
  }
  return out;
}

/** Decodes the RFC 2047 encoded words of an unfolded header value (B encoding, UTF-8). */
function decodeWords(value: string): string {
  return value
    .replace(/\?= =\?/g, "?==?")
    .replace(/=\?UTF-8\?B\?([A-Za-z0-9+/=]*)\?=/g, (_, b64: string) => Buffer.from(b64, "base64").toString("utf8"));
}

function headerValue(message: string, name: string): string {
  const field = fields(split(message).headers).find((line) => line.startsWith(`${name}: `));
  if (field === undefined) throw new Error(`no ${name}`);
  return field.slice(name.length + 2);
}

/** A deterministic pseudo-random sequence (no dependency): the same cases on every run. */
function random(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1_103_515_245) + 12_345) >>> 0;
    return state / 0x1_0000_0000;
  };
}

const NASTY = [
  "\r",
  "\n",
  "\r\n",
  "\u0000",
  " ",
  " ",
  "\u0085",
  "\u000b",
  "\u000c",
  "\u001b",
  "\u007f",
  "​",
  "‮",
  "﻿",
  "\ud800",
  "\udfff",
  ":",
  ";",
  "<",
  ">",
  '"',
  "\\",
  "=?",
  "?=",
  "=?UTF-8?B?QmNjOiB4QHkueg==?=",
  "Bcc: victim@example.com",
  "\r\nBcc: victim@example.com",
  "\nX-Injected: 1",
  ".",
  "\r\n.\r\n",
  "é",
  "日本語",
  "😀",
  " ",
  "\t",
  "a".repeat(200),
];

function nastyString(next: () => number, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) {
    const roll = next();
    if (roll < 0.5) out += NASTY[Math.floor(next() * NASTY.length)];
    else if (roll < 0.8) out += String.fromCharCode(32 + Math.floor(next() * 95));
    else out += String.fromCodePoint(Math.floor(next() * 0x2ffff));
  }
  return out;
}

const EXPECTED_FIELDS = [
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

describe("cleanHeaderText", () => {
  it("removes CR, LF, NUL, Unicode line and paragraph separators and other control or format characters", () => {
    expect(cleanHeaderText("a\r\nBcc: x@y.z")).toBe("aBcc: x@y.z");
    expect(cleanHeaderText("a\u0000b c d\u0085e\u000bf\u001bg\u007fh")).toBe("abcdefgh");
    expect(cleanHeaderText("a​b‮c﻿d")).toBe("abcd");
    expect(cleanHeaderText("lone \ud800 surrogate")).toBe("lone surrogate");
  });

  it("collapses whitespace runs to one space and trims", () => {
    expect(cleanHeaderText("  a \t\t b  ")).toBe("a b");
  });

  it("keeps printable text, accents, scripts and emoji", () => {
    expect(cleanHeaderText("Blocked burst — café 日本 😀")).toBe("Blocked burst — café 日本 😀");
  });
});

describe("subjectFor", () => {
  it("reads [Airverse] <severity>: <title>", () => {
    expect(subjectFor("high", "Blocked burst")).toBe("[Airverse] High: Blocked burst");
    expect(subjectFor("critical", "x")).toBe("[Airverse] Critical: x");
    expect(subjectFor("medium", "\r\n\u2028 ")).toBe("[Airverse] Medium: (no title)");
  });

  it("cleans and truncates the title, never splitting a character", () => {
    expect(subjectFor("low", "a\r\nBcc: v@w.io")).toBe("[Airverse] Low: aBcc: v@w.io");
    const long = "😀".repeat(SUBJECT_TITLE_MAX + 10);
    const subject = subjectFor("info", long);
    expect([...subject.slice("[Airverse] Info: ".length)].length).toBe(SUBJECT_TITLE_MAX);
    expect(subject.endsWith("😀")).toBe(true);
  });
});

describe("quoted-printable", () => {
  it("encodes UTF-8, keeps lines at most 76 characters, and uses CRLF", () => {
    const text = `Café ${"x".repeat(200)}\nline two = equals\ttab \nend`;
    const encoded = encodeQuotedPrintable(text);
    for (const line of encoded.split("\r\n")) {
      expect(line.length).toBeLessThanOrEqual(76);
      expect(line).toMatch(/^[\x21-\x7e ]*$/);
      expect(line.endsWith(" ")).toBe(false);
    }
    expect(encoded).toContain("Caf=C3=A9");
    expect(encoded).not.toMatch(/(?<!\r)\n/);
    expect(decodeQuotedPrintable(encoded)).toBe(text.replaceAll("\n", "\r\n"));
  });

  it("round-trips any text, with every line breaking form normalised to CRLF", () => {
    const next = random(7);
    for (let i = 0; i < 300; i++) {
      const text = nastyString(next, Math.floor(next() * 120)).toWellFormed();
      const encoded = encodeQuotedPrintable(text);
      for (const line of encoded.split("\r\n")) expect(line.length).toBeLessThanOrEqual(76);
      expect(decodeQuotedPrintable(encoded)).toBe(text.replace(/\r\n|\r|\n/g, "\r\n"));
    }
  });
});

describe("buildMessage", () => {
  it("writes the header fields in order, a plain-text UTF-8 quoted-printable body, Date and Message-ID", () => {
    const message = build("[Airverse] High: Blocked burst");
    const { headers, body } = split(message);
    expect(fields(headers)).toEqual([
      'From: "Airverse" <alerts@airverse.example>',
      "To: <alice@example.com>",
      "Subject: [Airverse] High: Blocked burst",
      "Date: Tue, 10 Nov 2026 08:20:01 +0000",
      "Message-ID: <0123456789abcdef@airverse.example>",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=UTF-8",
      "Content-Transfer-Encoding: quoted-printable",
      "Auto-Submitted: auto-generated",
    ]);
    expect(body).toBe("Hello.\r\n");
  });

  it("encodes a non-ASCII subject as RFC 2047 words that decode back to it", () => {
    const subject = `[Airverse] High: ${"Café 日本語 😀 ".repeat(6).trim()}`;
    const message = build(subject);
    const { headers } = split(message);
    for (const line of headers) {
      expect(line.length).toBeLessThanOrEqual(78);
      expect(line).toMatch(/^[\x20-\x7e]*$/);
    }
    expect(decodeWords(headerValue(message, "Subject"))).toBe(subject);
  });

  it("folds a long ASCII subject so that no header line passes 78 characters", () => {
    const subject = `[Airverse] High: ${"word ".repeat(30).trim()}`;
    const message = build(subject);
    for (const line of split(message).headers) expect(line.length).toBeLessThanOrEqual(78);
    expect(decodeWords(headerValue(message, "Subject"))).toBe(subject);
  });

  it("quotes or encodes the display name, which cannot add a field either", () => {
    expect(headerValue(build("s", "b", "a@x.io", 'Air "verse" \\ ops'), "From")).toBe(
      '"Air \\"verse\\" \\\\ ops" <alerts@airverse.example>',
    );
    const message = build("s", "b", "a@x.io", "Airvérse\r\nBcc: v@w.io");
    expect(decodeWords(headerValue(message, "From"))).toBe("AirvérseBcc: v@w.io <alerts@airverse.example>");
    expect(fields(split(message).headers).map((line) => line.split(":")[0])).toEqual(EXPECTED_FIELDS);
  });

  it("refuses an address that is not a valid address (the envelope and To are never built from one)", () => {
    expect(() => build("s", "b", "a@x.io\r\nBcc: v@w.io")).toThrow();
    expect(() => build("s", "b", "<a@x.io>")).toThrow();
    expect(() =>
      buildMessage({
        from: { address: "x\r\n@y.io", name: "n" },
        to: "a@x.io",
        subject: "s",
        body: "b",
        date: DATE,
        messageId: "<a@b>",
      }),
    ).toThrow();
  });

  it("property: no subject, display name or body can add or break a header line", () => {
    const next = random(42);
    for (let i = 0; i < 500; i++) {
      const subject = subjectFor("high", nastyString(next, Math.floor(next() * 80)));
      const fromName = nastyString(next, Math.floor(next() * 30));
      const body = nastyString(next, Math.floor(next() * 300));
      const message = build(subject, body, "alice@example.com", fromName);
      const { headers, body: encodedBody } = split(message);
      // Exactly the expected fields, in order: nothing added, nothing broken in two.
      expect(fields(headers).map((line) => line.split(":")[0])).toEqual(EXPECTED_FIELDS);
      for (const line of headers) {
        expect(line.length).toBeLessThanOrEqual(78);
        expect(line).toMatch(/^[\x20-\x7e]+$/);
      }
      // The subject decodes to the cleaned text: nothing of a control character survives.
      expect(decodeWords(headerValue(message, "Subject"))).toBe(subject);
      expect(subject).not.toMatch(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Cs}]/u);
      // The body is 7-bit, CRLF lines of at most 76 characters.
      for (const line of encodedBody.split("\r\n")) {
        expect(line.length).toBeLessThanOrEqual(76);
        expect(line).toMatch(/^[\x20-\x7e]*$/);
      }
    }
  });
});

describe("the three mails", () => {
  const consoleUrl = "https://console.airverse.example";

  it("an Incident alert: title, severity, App, Environment, opened at (UTC) and the Console link", () => {
    const mail = alertMail({ incident: EXAMPLE_INCIDENT, appName: "Shop", consoleUrl });
    expect(mail.subject).toBe("[Airverse] High: Blocked burst");
    expect(mail.body).toBe(
      [
        "Incident: Blocked burst",
        "Severity: High",
        "App: Shop",
        "Environment: development",
        "Opened at: 2026-11-10 08:20:00 UTC",
        `Open in the Console: ${consoleUrl}/incidents/${EXAMPLE_INCIDENT.id}`,
        "",
        "You receive this mail because this address was confirmed for an alert channel of an Airverse Organization.",
        "",
      ].join("\n"),
    );
  });

  it("keeps tenant text on its own line in the body: an App name cannot add lines", () => {
    const mail = alertMail({
      incident: EXAMPLE_INCIDENT,
      appName: "Shop\r\nOpen in the Console: https://evil",
      consoleUrl,
    });
    expect(mail.body.split("\n").filter((line) => line.startsWith("Open in the Console:"))).toHaveLength(1);
    expect(mail.body).toContain("App: ShopOpen in the Console: https://evil\n");
  });

  it("a confirmation mail carries the link and no tenant text at all", () => {
    const mail = confirmationMail({ token: "T".repeat(43), consoleUrl });
    expect(mail.subject).toBe("[Airverse] Confirm alert emails");
    expect(mail.body).toContain(`${consoleUrl}/alerts/confirm?token=${"T".repeat(43)}`);
    expect(mail.body).toContain("72 hours");
  });

  it("a test alert says the channel is connected", () => {
    const mail = testAlertMail();
    expect(mail.subject).toBe("[Airverse] Test alert");
    expect(mail.body).toContain("this channel is connected");
  });
});
