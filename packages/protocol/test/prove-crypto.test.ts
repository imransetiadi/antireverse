import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  canonicalJson,
  EXAMPLE_RULES_OF_ENGAGEMENT,
  type RulesOfEngagementContent,
  VERIFICATION_TOKEN_PATTERN,
} from "../src/index.ts";
import { generateVerificationToken, rulesOfEngagementSha256 } from "../src/server.ts";

const content: RulesOfEngagementContent = {
  scope: ["tgt_0123456789abcdef01234567"],
  exclusions: ["/admin"],
  intensity: "safe-active",
  window: { days: ["mon", "tue"], from: "09:00", to: "17:00" },
  contacts: ["security@example.com"],
};

describe("generateVerificationToken", () => {
  it("returns 32 random bytes as 43 base64url characters", () => {
    const token = generateVerificationToken();
    expect(token).toMatch(VERIFICATION_TOKEN_PATTERN);
    expect(Buffer.from(token, "base64url")).toHaveLength(32);
  });
  it("returns 1,000 unique tokens", () => {
    expect(new Set(Array.from({ length: 1000 }, generateVerificationToken)).size).toBe(1000);
  });
});

describe("rulesOfEngagementSha256", () => {
  it("is the SHA-256 hex of the canonical JSON of the five content fields", () => {
    const expected = createHash("sha256").update(canonicalJson(content), "utf8").digest("hex");
    expect(rulesOfEngagementSha256(content)).toBe(expected);
    expect(rulesOfEngagementSha256(content)).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is stable over key order", () => {
    const reordered = {
      window: { to: "17:00", days: ["mon", "tue"], from: "09:00" },
      contacts: content.contacts,
      intensity: content.intensity,
      exclusions: content.exclusions,
      scope: content.scope,
    } as RulesOfEngagementContent;
    expect(rulesOfEngagementSha256(reordered)).toBe(rulesOfEngagementSha256(content));
  });

  it("ignores everything but the content: id, signer, time, hash and unknown keys", () => {
    const { id, signed_by, signed_at, content_sha256, ...rest } = EXAMPLE_RULES_OF_ENGAGEMENT;
    expect(rulesOfEngagementSha256(EXAMPLE_RULES_OF_ENGAGEMENT)).toBe(rulesOfEngagementSha256(rest));
    expect(rulesOfEngagementSha256({ ...content, extra: 1 } as RulesOfEngagementContent)).toBe(
      rulesOfEngagementSha256(content),
    );
    expect([id, signed_by, signed_at, content_sha256].every((value) => typeof value === "string")).toBe(true);
  });

  it("changes with any field and with array order", () => {
    const base = rulesOfEngagementSha256(content);
    expect(rulesOfEngagementSha256({ ...content, intensity: "full" })).not.toBe(base);
    expect(rulesOfEngagementSha256({ ...content, exclusions: [] })).not.toBe(base);
    expect(rulesOfEngagementSha256({ ...content, contacts: ["other@example.com"] })).not.toBe(base);
    expect(rulesOfEngagementSha256({ ...content, window: { ...content.window, days: ["tue", "mon"] } })).not.toBe(base);
    expect(rulesOfEngagementSha256({ ...content, window: { ...content.window, to: "17:01" } })).not.toBe(base);
  });

  it("is the hash the example version carries", () => {
    expect(EXAMPLE_RULES_OF_ENGAGEMENT.content_sha256).toBe(rulesOfEngagementSha256(EXAMPLE_RULES_OF_ENGAGEMENT));
  });

  it("refuses content that is not valid Rules of Engagement", () => {
    expect(() => rulesOfEngagementSha256({ ...content, intensity: "max" } as never)).toThrow(TypeError);
    expect(() => rulesOfEngagementSha256({} as never)).toThrow(TypeError);
  });
});
