import { describe, expect, it } from "vitest";
import { evidenceWindow, locationOf, redactHeaders, redactText } from "../src/campaign/redact.ts";

// Slice 15a: what the gate removes from a response before the engine, a Finding or a log can hold it.

const JWT =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

describe("redactText", () => {
  it("removes keys, tokens and JWTs", () => {
    const text = [
      "stripe sk_live_4eC39HqLyjWDarjtT1zdp7dc here",
      "aws AKIAIOSFODNN7EXAMPLE there",
      `admin aro_${"a".repeat(43)}`,
      "github ghp_16C7e42F292c6912E7710c838347Ae178B4a",
      `Authorization: Bearer ${JWT}`,
      'api_key="k3y-s3cr3t-value-123456"',
      "password=hunter2hunter2",
    ].join("\n");
    const redacted = redactText(text);
    for (const secret of [
      "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
      "AKIAIOSFODNN7EXAMPLE",
      "a".repeat(43),
      "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
      JWT,
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
      "k3y-s3cr3t-value-123456",
      "hunter2hunter2",
    ]) {
      expect(redacted).not.toContain(secret);
    }
    expect(redacted).toContain("stripe");
    expect(redacted).toContain("[redacted");
  });

  it("removes email addresses", () => {
    const redacted = redactText('{"customer":"jane.doe+orders@acme-shop.io","note":"mail ops@acme-shop.io"}');
    expect(redacted).not.toMatch(/@acme-shop\.io/);
    expect(redacted).toContain("[redacted-email]");
  });

  it("removes Luhn-valid digit runs, with or without separators, and keeps other numbers", () => {
    const redacted = redactText(
      "card 4111 1111 1111 1111, 5500-0000-0000-0004, 378282246310005; order 1234567890123457, id 1001",
    );
    expect(redacted).not.toContain("4111 1111 1111 1111");
    expect(redacted).not.toContain("5500-0000-0000-0004");
    expect(redacted).not.toContain("378282246310005");
    expect(redacted).toContain("[redacted-number]");
    // An ordinary long number stays: none of its windows of 13 to 19 digits passes the Luhn check.
    expect(redacted).toContain("1234567890123457");
    expect(redacted).toContain("1001");
  });

  it("removes high-entropy strings and keeps words, paths and markers", () => {
    const secret = "Zx9Qw3Er7Ty1Ui5Op2As6Df8Gh4Jk0Lz";
    const hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const redacted = redactText(
      `token ${secret} hash ${hex} path /api/orders/1001 at handleOrder (/srv/app/orders.js:42:7) "><airverse-probe-marker>`,
    );
    expect(redacted).not.toContain(secret);
    expect(redacted).not.toContain(hex);
    expect(redacted).toContain("/api/orders/1001");
    expect(redacted).toContain("at handleOrder (/srv/app/orders.js:42:7)");
    expect(redacted).toContain('"><airverse-probe-marker>');
  });

  it("is stable: redacting twice changes nothing more", () => {
    const once = redactText(`a@b.io sk_live_4eC39HqLyjWDarjtT1zdp7dc 4111111111111111 ${JWT}`);
    expect(redactText(once)).toBe(once);
  });
});

describe("redactText on hostile input", () => {
  it("takes linear time on long runs that almost match a pattern", () => {
    const size = 64 * 1024;
    const bodies = [
      "a".repeat(size),
      "a@".repeat(size / 2),
      "@".repeat(size),
      "eyJ".repeat(size / 3),
      "1 ".repeat(size / 2),
      "9".repeat(size),
      " ".repeat(size),
      `token${" ".repeat(size)}`,
      "-----BEGIN ".repeat(size / 11),
      "aB3".repeat(size / 3),
      "password=".repeat(size / 9),
    ];
    for (const body of bodies) {
      const started = performance.now();
      redactText(body);
      expect({ body: body.slice(0, 12), ms: performance.now() - started }).toMatchObject({ ms: expect.any(Number) });
      expect(performance.now() - started).toBeLessThan(500);
    }
  });
});

describe("redactHeaders", () => {
  it("keeps an allowlist, never a cookie's value, and a Location only as a category", () => {
    const headers = redactHeaders(
      {
        "content-type": "text/html; charset=utf-8",
        "content-length": "120",
        server: "nginx",
        "x-powered-by": "Express",
        "set-cookie": ["sid=s3cr3tSessionValue123; Path=/; HttpOnly; Secure", "theme=dark"],
        location: "https://evil.example.net/landing?token=abc",
        "x-internal-token": "should-not-pass",
        "retry-after": "30",
        "strict-transport-security": "max-age=63072000",
        etag: '"abc"',
      },
      "shop.acme-shop.io",
    );
    expect(headers).toEqual({
      "content-type": "text/html; charset=utf-8",
      "content-length": "120",
      server: "nginx",
      "x-powered-by": "Express",
      "set-cookie": "sid=[redacted]; HttpOnly; Secure, theme=[redacted]",
      location: "other-host",
      "retry-after": "30",
      "strict-transport-security": "max-age=63072000",
    });
    expect(JSON.stringify(headers)).not.toContain("s3cr3tSessionValue123");
    expect(JSON.stringify(headers)).not.toContain("evil.example.net");
  });
});

describe("locationOf", () => {
  it("is same-host only for the Campaign's own host over HTTPS on 443", () => {
    const host = "shop.acme-shop.io";
    expect(locationOf(undefined, host)).toBeNull();
    for (const same of ["/next", "next", "?a=1", "https://shop.acme-shop.io/x", "https://SHOP.acme-shop.io:443/x"]) {
      expect({ same, category: locationOf(same, host) }).toEqual({ same, category: "same-host" });
    }
    for (const other of [
      "https://evil.example.net/",
      "//evil.example.net/x",
      "http://shop.acme-shop.io/x",
      "https://shop.acme-shop.io:8443/x",
      "https://shop.acme-shop.io.evil.example.net/",
      "https://user@shop.acme-shop.io/",
      "javascript:alert(1)",
      "https://[::1]/",
      "\\\\evil.example.net",
      "https://%%%/",
    ]) {
      expect({ other, category: locationOf(other, host) }).toEqual({ other, category: "other-host" });
    }
  });
});

// Third review (D-107): `excerptAround` — up to 2 KB of a body around a position — is gone. What is kept of a body is
// the evidence window a check cut around its match: at most 200 characters.
describe("evidenceWindow", () => {
  it("is at most 200 characters, whole characters only", () => {
    const body = `${"é".repeat(3000)}MARK${"x".repeat(5000)}`;
    const at = body.indexOf("MARK");
    const window = evidenceWindow(body.slice(at - 40, at + 400));
    expect(window.length).toBe(200);
    expect(window).toContain("MARK");
    expect(window).not.toContain("�");
    expect(evidenceWindow("short")).toBe("short");
    expect(evidenceWindow("")).toBe("");
  });
});
