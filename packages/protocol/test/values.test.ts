// The privacy allowlist covers values as well as keys (review findings F3 and F6): whatever a client
// sends, only a network prefix, a bounded rule identifier and storable text may pass.
import { describe, expect, it } from "vitest";
import { EXAMPLE_SHIELD_EVENT, type ShieldEvent, ShieldEventSchema } from "../src/index.ts";

function withActor(ip_prefix: unknown): unknown {
  return { ...EXAMPLE_SHIELD_EVENT, actor: { ip_prefix } };
}
function withRequest(patch: Partial<ShieldEvent["request"]>): unknown {
  return { ...EXAMPLE_SHIELD_EVENT, request: { ...EXAMPLE_SHIELD_EVENT.request, ...patch } };
}
function withDecision(patch: Record<string, unknown>): unknown {
  return { ...EXAMPLE_SHIELD_EVENT, decision: { ...EXAMPLE_SHIELD_EVENT.decision, ...patch } };
}
const accepts = (value: unknown) => ShieldEventSchema.safeParse(value).success;

describe("actor.ip_prefix", () => {
  it.each(["203.0.113.0/24", "0.0.0.0/24", "255.255.255.0/24", "2001:db8:abcd::/48", "0:0:0::/48", "fe80:0:1::/48"])(
    "accepts the network prefix %s",
    (prefix) => {
      expect(accepts(withActor(prefix))).toBe(true);
    },
  );

  it("accepts null for an unknown address", () => {
    expect(accepts(withActor(null))).toBe(true);
  });

  it.each([
    "203.0.113.77",
    "203.0.113.77/24",
    "203.0.113.0/32",
    "203.0.113.0",
    "256.0.0.0/24",
    "2001:db8:abcd:12::1",
    "2001:db8:abcd::/64",
    "2001:DB8:ABCD::/48",
    "alice@example.com session=abc",
    "",
  ])("rejects %j: only a /24 or /48 prefix may be stored", (value) => {
    expect(accepts(withActor(value))).toBe(false);
  });
});

describe("actor.ip_hash", () => {
  const withHash = (ip_hash: unknown): unknown => ({ ...EXAMPLE_SHIELD_EVENT, actor: { ip_prefix: null, ip_hash } });

  it("accepts a keyed hash and null", () => {
    expect(accepts(withHash("iph_0123456789abcdef0123456789abcdef"))).toBe(true);
    expect(accepts(withHash(null))).toBe(true);
  });

  it.each([
    "203.0.113.77",
    "::ffff:203.0.113.77",
    "2001:db8:abcd:12::1",
    "iph_203.0.113.77",
    "iph_0123456789abcdef0123456789abcdef 203.0.113.77",
    "alice@example.com",
  ])("rejects %j: an address or free text can never be stored as the actor hash", (value) => {
    expect(accepts(withHash(value))).toBe(false);
  });
});

describe("decision.containment_id", () => {
  it("accepts a Containment id and null, and nothing else", () => {
    expect(accepts(withDecision({ containment_id: "cnt_0123456789abcdef01234567" }))).toBe(true);
    expect(accepts(withDecision({ containment_id: null }))).toBe(true);
    expect(accepts(withDecision({ containment_id: "203.0.113.77" }))).toBe(false);
    expect(accepts(withDecision({ containment_id: "cnt_0123456789abcdef01234567\u0000" }))).toBe(false);
  });
});

describe("decision.rule_id", () => {
  it("accepts an identifier of 64 characters and rejects 65", () => {
    expect(accepts(withDecision({ rule_id: "r".repeat(64) }))).toBe(true);
    expect(accepts(withDecision({ rule_id: "r".repeat(65) }))).toBe(false);
  });

  it("rejects a NUL character", () => {
    expect(accepts(withDecision({ rule_id: "rule\u0000" }))).toBe(false);
  });
});

describe("text that must be storable", () => {
  it("rejects a route containing NUL or another control character", () => {
    expect(accepts(withRequest({ route: "/a\u0000b" }))).toBe(false);
    expect(accepts(withRequest({ route: "/a\nb" }))).toBe(false);
    expect(accepts(withRequest({ route: "/a\u007fb" }))).toBe(false);
  });

  it("rejects a route containing a lone surrogate", () => {
    expect(accepts(withRequest({ route: "/a\ud800b" }))).toBe(false);
    expect(accepts(withRequest({ route: "/a\udc00" }))).toBe(false);
  });

  it("accepts a route with ordinary non-ASCII text and a surrogate pair", () => {
    expect(accepts(withRequest({ route: "/produk/:id/ulasan-é-日本-😀" }))).toBe(true);
  });
});

describe("ts", () => {
  it.each(["2000-01-01T00:00:00Z", "2026-11-10T08:15:30.123Z", "2099-12-31T23:59:59.999Z"])("accepts %s", (ts) => {
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts })).toBe(true);
  });

  it.each(["0000-01-01T00:00:00Z", "1999-12-31T23:59:59Z", "2100-01-01T00:00:00Z", "9999-12-31T23:59:59Z"])(
    "rejects %s: outside the years 2000 to 2099",
    (ts) => {
      expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts })).toBe(false);
    },
  );
});
