import { createHmac, timingSafeEqual } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { CreateAlertChannelResponseSchema, EXAMPLE_ALERT_CHANNEL } from "../src/index.ts";
import { generateSigningSecret, signWebhookBody, verifyWebhookSignature } from "../src/server.ts";

// Pass-through spy on the constant-time comparison, so a test can see that verification goes through it.
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});
const spy = vi.mocked(timingSafeEqual);

// Synthetic secret and body: no real credential.
const SECRET = `whsec_${"S".repeat(43)}`;
const BODY = '{"type":"test","incident":null,"console_url":null}';
const T = 1_794_300_000;
/** Independent computation of the expected signature with node:crypto directly. */
const expected = (secret: string, t: number, body: string): string =>
  createHmac("sha256", secret).update(`${t}.${body}`, "utf8").digest("hex");
const header = (t: number, v1: string): string => `t=${t},v1=${v1}`;

beforeEach(() => {
  spy.mockClear();
});

describe("generateSigningSecret", () => {
  it("returns whsec_ followed by 43 base64url characters (32 random bytes)", () => {
    const secret = generateSigningSecret();
    expect(secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(secret.slice("whsec_".length), "base64url")).toHaveLength(32);
  });

  it("is accepted by the creation response schema", () => {
    const response = { channel: EXAMPLE_ALERT_CHANNEL, signing_secret: generateSigningSecret() };
    expect(CreateAlertChannelResponseSchema.safeParse(response).success).toBe(true);
  });

  it("returns 1,000 unique secrets", () => {
    expect(new Set(Array.from({ length: 1000 }, generateSigningSecret)).size).toBe(1000);
  });
});

describe("signWebhookBody", () => {
  it("returns the lowercase hex HMAC-SHA256 of <t>.<body> (known-answer vector)", () => {
    const signature = signWebhookBody(SECRET, T, BODY);
    expect(signature).toBe(expected(SECRET, T, BODY));
    expect(signature).toMatch(/^[0-9a-f]{64}$/);
  });

  it("matches a fixed vector (also computed with `openssl dgst -sha256 -hmac whsec_test`)", () => {
    // printf '1700000000.{"type":"test"}' | openssl dgst -sha256 -hmac whsec_test
    expect(signWebhookBody("whsec_test", 1_700_000_000, '{"type":"test"}')).toBe(
      "5f32b1f20af8adf84aaaa8ffc92da0441bf4c05562faa71f5c27352c22b106a8",
    );
    expect(signWebhookBody("key", 1, "")).toBe(createHmac("sha256", "key").update("1.").digest("hex"));
  });

  it("treats the body as UTF-8", () => {
    const body = '{"title":"Blocked burst — ü"}';
    expect(signWebhookBody(SECRET, T, body)).toBe(expected(SECRET, T, body));
  });

  it("differs with the secret, the time and the body", () => {
    const base = signWebhookBody(SECRET, T, BODY);
    expect(signWebhookBody(`${SECRET}x`, T, BODY)).not.toBe(base);
    expect(signWebhookBody(SECRET, T + 1, BODY)).not.toBe(base);
    expect(signWebhookBody(SECRET, T, `${BODY} `)).not.toBe(base);
  });

  it("refuses a time that is not a non-negative safe integer", () => {
    for (const t of [1.5, -1, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(() => signWebhookBody(SECRET, t, BODY), String(t)).toThrow(TypeError);
    }
  });
});

describe("verifyWebhookSignature", () => {
  const valid = header(T, expected(SECRET, T, BODY));

  it("accepts a valid signature at the same second", () => {
    expect(verifyWebhookSignature(SECRET, valid, BODY, T)).toBe(true);
  });

  it("accepts a header produced by signWebhookBody", () => {
    expect(verifyWebhookSignature(SECRET, header(T, signWebhookBody(SECRET, T, BODY)), BODY, T + 10)).toBe(true);
  });

  it("refuses a wrong secret", () => {
    expect(verifyWebhookSignature(`whsec_${"W".repeat(43)}`, valid, BODY, T)).toBe(false);
  });

  it("refuses a tampered body", () => {
    expect(verifyWebhookSignature(SECRET, valid, BODY.replace("test", "tset"), T)).toBe(false);
    expect(verifyWebhookSignature(SECRET, valid, `${BODY}\n`, T)).toBe(false);
  });

  it("refuses a tampered time (the time is signed)", () => {
    const moved = header(T + 1, expected(SECRET, T, BODY));
    expect(verifyWebhookSignature(SECRET, moved, BODY, T)).toBe(false);
  });

  it("accepts up to the default tolerance of 300 seconds either way and refuses beyond", () => {
    expect(verifyWebhookSignature(SECRET, valid, BODY, T + 300)).toBe(true);
    expect(verifyWebhookSignature(SECRET, valid, BODY, T - 300)).toBe(true);
    expect(verifyWebhookSignature(SECRET, valid, BODY, T + 301)).toBe(false);
    expect(verifyWebhookSignature(SECRET, valid, BODY, T - 301)).toBe(false);
  });

  it("honours an explicit tolerance", () => {
    expect(verifyWebhookSignature(SECRET, valid, BODY, T + 30, 30)).toBe(true);
    expect(verifyWebhookSignature(SECRET, valid, BODY, T + 31, 30)).toBe(false);
    expect(verifyWebhookSignature(SECRET, valid, BODY, T + 1, 0)).toBe(false);
  });

  it("refuses an expired signature without comparing", () => {
    expect(verifyWebhookSignature(SECRET, valid, BODY, T + 3600)).toBe(false);
    expect(spy).not.toHaveBeenCalled();
  });

  it("ignores unknown fields in any position", () => {
    const v1 = expected(SECRET, T, BODY);
    expect(verifyWebhookSignature(SECRET, `v0=abc,t=${T},v1=${v1}`, BODY, T)).toBe(true);
    expect(verifyWebhookSignature(SECRET, `v1=${v1},x=1,t=${T}`, BODY, T)).toBe(true);
  });

  it("refuses malformed headers", () => {
    const v1 = expected(SECRET, T, BODY);
    const malformed = [
      "",
      "garbage",
      `t=${T}`,
      `v1=${v1}`,
      `t=,v1=${v1}`,
      `t=abc,v1=${v1}`,
      `t=-${T},v1=${v1}`,
      `t=${T}.5,v1=${v1}`,
      `t=1e9,v1=${v1}`,
      `t= ${T},v1=${v1}`,
      `t=${"9".repeat(20)},v1=${v1}`,
      `t=${T},v1=${v1.slice(0, 63)}`,
      `t=${T},v1=${v1}0`,
      `t=${T},v1=${v1.toUpperCase()}`,
      `t=${T},v1=${"z".repeat(64)}`,
      `t=${T},v1=${v1},`,
      `t=${T},,v1=${v1}`,
      `t=${T},v1`,
      `t=${T},t=${T},v1=${v1}`,
      `t=${T};v1=${v1}`,
      ` t=${T},v1=${v1}`,
    ];
    for (const value of malformed) {
      expect(verifyWebhookSignature(SECRET, value, BODY, T), value).toBe(false);
    }
    expect(spy).not.toHaveBeenCalled();
  });

  it("refuses non-string inputs and a non-finite clock without throwing", () => {
    const anyVerify = verifyWebhookSignature as (...args: unknown[]) => boolean;
    expect(anyVerify(SECRET, undefined, BODY, T)).toBe(false);
    expect(anyVerify(SECRET, valid, undefined, T)).toBe(false);
    expect(anyVerify(undefined, valid, BODY, T)).toBe(false);
    expect(anyVerify(SECRET, valid, BODY, Number.NaN)).toBe(false);
  });

  describe("several v1 values (secret rotation)", () => {
    const good = expected(SECRET, T, BODY);
    const other = expected(`whsec_${"O".repeat(43)}`, T, BODY);

    it("passes when any v1 matches, the first or a later one", () => {
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${other},v1=${good}`, BODY, T)).toBe(true);
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${good},v1=${other}`, BODY, T)).toBe(true);
      expect(verifyWebhookSignature(SECRET, `v1=${other},t=${T},v1=${good}`, BODY, T)).toBe(true);
    });

    it("fails when no v1 matches", () => {
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${other},v1=${"0".repeat(64)}`, BODY, T)).toBe(false);
    });

    it("still refuses a duplicate t", () => {
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${good},t=${T},v1=${other}`, BODY, T)).toBe(false);
    });

    it("accepts up to 8 v1 values and refuses 9", () => {
      const eight = [...Array.from({ length: 7 }, () => other), good].map((v) => `v1=${v}`).join(",");
      expect(verifyWebhookSignature(SECRET, `t=${T},${eight}`, BODY, T)).toBe(true);
      expect(verifyWebhookSignature(SECRET, `t=${T},${eight},v1=${other}`, BODY, T)).toBe(false);
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${other},${eight}`, BODY, T)).toBe(false);
    });

    it("refuses the whole header when any v1 is malformed, even if another matches", () => {
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${good},v1=${good.slice(1)}`, BODY, T)).toBe(false);
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=xyz,v1=${good}`, BODY, T)).toBe(false);
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${good},v1=`, BODY, T)).toBe(false);
    });

    it("compares every candidate with timingSafeEqual, without stopping at the first match", () => {
      expect(verifyWebhookSignature(SECRET, `t=${T},v1=${good},v1=${other},v1=${other}`, BODY, T)).toBe(true);
      expect(spy).toHaveBeenCalledTimes(3);
      for (const [a, b] of spy.mock.calls) {
        expect((a as Buffer).length).toBe(32);
        expect((b as Buffer).length).toBe(32);
      }
    });
  });

  it("compares with crypto.timingSafeEqual on two 32-byte buffers", () => {
    expect(verifyWebhookSignature(SECRET, valid, BODY, T)).toBe(true);
    expect(verifyWebhookSignature(SECRET, header(T, "0".repeat(64)), BODY, T)).toBe(false);
    expect(spy).toHaveBeenCalledTimes(2);
    for (const [a, b] of spy.mock.calls) {
      expect(Buffer.isBuffer(a) && Buffer.isBuffer(b)).toBe(true);
      expect((a as Buffer).length).toBe(32);
      expect((b as Buffer).length).toBe(32);
    }
  });
});
