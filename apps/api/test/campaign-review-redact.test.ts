import { STAND_IN_CATALOG } from "@antireverse/prove";
import { describe, expect, it } from "vitest";
import { BODY_WITHHELD, evidenceWindow, redactBody, redactText } from "../src/campaign/redact.ts";

// Slice 15a, independent safety review (M3, L1, L4): secrets the first redactor missed, bodies that are not text, and
// the linear-time property of the redactor and of the stand-in's own patterns on hostile 64 KB bodies.

describe("review M3: redaction gaps", () => {
  const cases: [string, string, string][] = [
    ["db_password assignment", "DB_PASSWORD=Tr0ub4dor-and-3", "Tr0ub4dor-and-3"],
    ["json user_password", '{"user_password":"hunter2hunter2"}', "hunter2hunter2"],
    [
      "aws secret access key",
      "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
    [
      "a bare base64 secret with slashes",
      "value wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY here",
      "K7MDENG/bPxRfiCYEXAMPLEKEY",
    ],
    ["refresh_token short", '{"refresh_token":"abc123def456"}', "abc123def456"],
    ["client-secret", "client-secret: s3cr3t-value", "s3cr3t-value"],
    ["apiKey", 'apiKey="k-12345"', "k-12345"],
    ["password with spaces", '{"password":"correct horse battery staple"}', "horse battery staple"],
    ["single-quoted passphrase", "passphrase = 'open sesame please'", "sesame please"],
    ["card after an order number", "order 1001 4111 1111 1111 1111 paid", "4111 1111 1111 1111"],
    ["card after a date", "2026-11-15 4111-1111-1111-1111", "4111-1111-1111-1111"],
    ["card with dots", "card 4111.1111.1111.1111", "4111.1111.1111.1111"],
    ["url-encoded email", "mailto:jane.doe%40acme-shop.io", "jane.doe%40acme-shop.io"],
    ["php session id in a body", "PHPSESSID=0a1b2c3d4e5f6a7b8c9d0e1f2a", "0a1b2c3d4e5f6a7b8c9d0e1f2a"],
  ];
  for (const [name, input, secret] of cases) {
    it(`redacts: ${name}`, () => {
      const out = redactText(input);
      expect(out).not.toContain(secret);
      // Stable: redacting again changes nothing.
      expect(redactText(out)).toBe(out);
    });
  }

  it("keeps what evidence needs: a stack frame, a path with an id, JSON keys, the marker", () => {
    const text =
      'Error: boom\n    at loadOrder (/srv/ar-range/orders.js:42:11) GET /api/orders/1001 {"reports":[{"id":"rpt_orders_weekly","rows":52}]} "><airverse-probe-marker> 2026-11-15T10:00:00.000Z';
    expect(redactText(text)).toBe(text);
  });

  it("withholds a body that is not text: a NUL anywhere, or a UTF-16 byte order mark", () => {
    const key = ["sk", "live", "SYNTHETICrangeKEY0000000a"].join("_");
    const asUtf8 = Buffer.from(`key ${key}`, "utf16le").toString("utf8");
    expect(redactText(asUtf8)).toBe(BODY_WITHHELD);
    expect(redactText(asUtf8).replaceAll("\u0000", "")).not.toContain(key);
    expect(redactBody(Buffer.from(`key ${key}`, "utf16le"))).toBe(BODY_WITHHELD);
    expect(redactBody(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("ab")]))).toBe(BODY_WITHHELD);
    expect(redactBody(Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from("ab")]))).toBe(BODY_WITHHELD);
    expect(redactBody(Buffer.from('\u0000{"reports":[]}'))).toBe(BODY_WITHHELD);
    expect(redactBody(Buffer.from("plain jane@acme-shop.io"))).toBe("plain [redacted-email]");
    expect(redactBody(Buffer.alloc(0))).toBe("");
  });
});

describe("review L1: an excerpt holds no control character", () => {
  // Third review (D-107): the excerpt is now the evidence window, which is redacted again on its own.
  it("replaces them, keeping line breaks and tabs", () => {
    const excerpt = evidenceWindow("a\u0001b c\u001fd\u007fe\nf\tg\u0085h");
    expect(excerpt).toBe("a b c d e\nf\tg h");
  });
  it("a window with a NUL is not text: withheld whole", () => {
    expect(evidenceWindow("a\u0001b\u0000c")).toBe(BODY_WITHHELD);
  });
});

describe("review: timing on hostile 64 KB bodies", () => {
  const N = 64 * 1024;
  const bodies: Record<string, string> = {
    a: "a".repeat(N),
    at: "@".repeat(N),
    "a@": "a@".repeat(N / 2),
    "a.a@a.a": "a.a@a.a ".repeat(N / 8),
    "%40": "a%40".repeat(N / 4),
    eyJ: "eyJ".repeat(N / 3),
    " eyJaaaaa.": " eyJaaaaa.".repeat(N / 10),
    digits: "1".repeat(N),
    "1 1 1": "1 ".repeat(N / 2),
    "1-": "1-".repeat(N / 2),
    "1.": "1.".repeat(N / 2),
    "luhn zeros": "0".repeat(N),
    bearer: `Bearer${" ".repeat(N - 6)}`,
    "Bearer ": "Bearer ".repeat(N / 7),
    "token:": "token:".repeat(N / 6),
    "token =": `token${" ".repeat(8)}=${" ".repeat(8)}`.repeat(N / 22),
    'password:"': 'password:"'.repeat(N / 10),
    "password: 'open quote": `password: '${"x ".repeat(N / 2)}`,
    "long name": `${"a_".repeat(N / 2)}=x`,
    pem: "-----BEGIN PRIVATE KEY-----".repeat(N / 27),
    "pem-open": "-----BEGIN ".repeat(N / 11),
    "pem A": `-----BEGIN ${"A ".repeat(20)}`.repeat(N / 51),
    b64: "aB3".repeat(N / 3),
    "b64/": "aB3/".repeat(N / 4),
    "23+sep": `${"aB3dE6gH9jK2mN5pQ8sT1vW".slice(0, 23)} `.repeat(N / 24),
    newlines: "\n".repeat(N),
    spaces: " ".repeat(N),
  };
  for (const [name, body] of Object.entries(bodies)) {
    it(`redactText is fast on: ${name}`, () => {
      const started = performance.now();
      redactText(body);
      expect(performance.now() - started).toBeLessThan(250);
    });
  }

  it("redactText grows linearly: four times the input takes far less than sixteen times as long", () => {
    // The best of five runs each: a busy machine slows a run down, it never speeds one up.
    const time = (text: string): number => {
      let best = Number.POSITIVE_INFINITY;
      for (let run = 0; run < 5; run++) {
        const started = performance.now();
        redactText(text);
        best = Math.min(best, performance.now() - started);
      }
      return best;
    };
    for (const unit of ["a@", "1 ", 'password:"', "eyJ", "aB3/"]) {
      time(unit.repeat(1000));
      const small = Math.max(time(unit.repeat(8 * 1024)), 0.5);
      const large = time(unit.repeat(32 * 1024));
      expect({ unit, ratio: large / small < 10 }).toEqual({ unit, ratio: true });
    }
  });

  const engineBodies: Record<string, string> = {
    "newline+spaces": "\n ".repeat(N / 2),
    newlines: "\n".repeat(N),
    "nl spaces at X (": `\n at ${"x".repeat(40)} (`.repeat(N / 47),
    "nl at a (a:1:": "\n at a (a:1:".repeat(N / 13),
    spaces: `\n${" ".repeat(N)}`,
  };
  for (const check of STAND_IN_CATALOG) {
    for (const [name, body] of Object.entries(engineBodies)) {
      it(`review L4: stand-in ${check.id} detect is fast on: ${name}`, () => {
        const started = performance.now();
        for (const status of [200, 302, 500]) {
          check.detect({
            ok: true,
            seq: 1,
            status,
            headers: {},
            body,
            truncated: false,
            location: null,
            withheld: false,
          });
        }
        expect(performance.now() - started).toBeLessThan(100);
      });
    }
  }
});
