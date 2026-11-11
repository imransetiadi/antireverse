import { describe, expect, it } from "vitest";
import {
  CANARY_KINDS,
  CANARY_LIMITS,
  CANARY_PLAN,
  CANARY_ROUTE_WORDS,
  CANARY_SIGNAL_PREFIX,
  CANARY_VALUE_PATTERNS,
  type Canary,
  type CanaryKind,
  CanarySchema,
  canarySignalId,
  EXAMPLE_CANARIES,
  ID_PATTERNS,
  LEAK_LIMITS,
  LEAK_RULES,
  type LeakAllowlist,
  LeakAllowlistSchema,
  type LeakRuleId,
  type LeakScanSummary,
  LeakScanSummarySchema,
  parseCanarySignal,
} from "../src/index.ts";

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;
const ID = "cny_0123456789abcdef01234567";
const KEY = `ak_live_${"0123456789ABCDEFGHIJabcdefghijXY"}`;
const ROUTE = "/api/internal/a1b2c3d4/export";

describe("canary constants", () => {
  it("has the kinds, the per-Build plan and the limits of contract P1", () => {
    const kind: CanaryKind = "key";
    expect(CANARY_KINDS).toEqual([kind, "route"]);
    expect(CANARY_PLAN).toEqual({ key: 1, route: 2 });
    expect(CANARY_LIMITS).toEqual({ perBuild: 10, perBundle: 100, buildsInBundle: 20 });
    expect(CANARY_ROUTE_WORDS).toEqual(["export", "debug", "config", "backup", "sync"]);
    expect(CANARY_SIGNAL_PREFIX).toBe("canary.touched:");
  });

  it("plans no more Canaries per Build than a Manifest may carry", () => {
    const planned = CANARY_KINDS.reduce((sum, kind) => sum + CANARY_PLAN[kind], 0);
    expect(planned).toBe(3);
    expect(planned).toBeLessThanOrEqual(CANARY_LIMITS.perBuild);
    expect(CANARY_LIMITS.perBuild * CANARY_LIMITS.buildsInBundle).toBeGreaterThanOrEqual(CANARY_LIMITS.perBundle);
  });

  it("freezes the plan and the route words", () => {
    expect(Object.isFrozen(CANARY_PLAN)).toBe(true);
    expect(Object.isFrozen(CANARY_ROUTE_WORDS)).toBe(true);
    expect(Object.isFrozen(CANARY_VALUE_PATTERNS)).toBe(true);
  });

  it("has the value patterns of contract P1", () => {
    // RegExp#source escapes "/" as "\\/"; compare with the plan's text.
    const plain = (pattern: RegExp) => pattern.source.replaceAll("\\/", "/");
    expect(plain(CANARY_VALUE_PATTERNS.key)).toBe("^ak_live_[0-9A-Za-z]{32}$");
    expect(plain(CANARY_VALUE_PATTERNS.route)).toBe("^/api/internal/[0-9a-z]{8}/(export|debug|config|backup|sync)$");
  });

  it("has a cny identifier pattern", () => {
    expect(ID_PATTERNS.cny.test(ID)).toBe(true);
    expect(ID_PATTERNS.cny.test("cny_0123456789ABCDEF01234567")).toBe(false);
    expect(ID_PATTERNS.cny.test("cny_0123")).toBe(false);
    expect(ID_PATTERNS.cny.test("bld_0123456789abcdef01234567")).toBe(false);
  });
});

describe("CanarySchema", () => {
  it("parses a key and a route Canary unchanged", () => {
    const key: Canary = { id: ID, kind: "key", value: KEY };
    const route: Canary = { id: ID, kind: "route", value: ROUTE };
    expect(CanarySchema.parse(key)).toEqual(key);
    expect(CanarySchema.parse(route)).toEqual(route);
  });

  it("requires id to match cny_<24 hex>", () => {
    expect(ok(CanarySchema, { id: "cny_0123", kind: "key", value: KEY })).toBe(false);
    expect(ok(CanarySchema, { id: "bld_0123456789abcdef01234567", kind: "key", value: KEY })).toBe(false);
  });

  it("requires a known kind", () => {
    expect(ok(CanarySchema, { id: ID, kind: "config", value: KEY })).toBe(false);
    expect(ok(CanarySchema, { id: ID, value: KEY })).toBe(false);
  });

  it.each([
    ["key", "ak_live_0123456789ABCDEFGHIJabcdefghijX"],
    ["key", "ak_live_0123456789ABCDEFGHIJabcdefghijXYZ"],
    ["key", "ak_test_0123456789ABCDEFGHIJabcdefghijXY"],
    ["key", "sk_live_0123456789ABCDEFGHIJabcdefghijXY"],
    ["key", "ak_live_0123456789ABCDEFGHIJabcdefghij-_"],
    ["key", ` ${KEY}`],
    ["key", ROUTE],
    ["route", KEY],
    ["route", "/api/internal/a1b2c3d4/delete"],
    ["route", "/api/internal/A1B2C3D4/export"],
    ["route", "/api/internal/a1b2c3d/export"],
    ["route", "/api/internal/a1b2c3d4e/export"],
    ["route", "/api/internal/a1b2c3d4/export/"],
    ["route", "/api/internal/a1b2c3d4/export?x=1"],
    ["route", "https://example.com/api/internal/a1b2c3d4/export"],
  ])("rejects a %s Canary with the value %j", (kind, value) => {
    expect(ok(CanarySchema, { id: ID, kind, value })).toBe(false);
  });

  it("accepts every route word", () => {
    for (const word of CANARY_ROUTE_WORDS) {
      expect(ok(CanarySchema, { id: ID, kind: "route", value: `/api/internal/0z9y8x7w/${word}` })).toBe(true);
    }
  });

  it("strips unknown keys", () => {
    const parsed = CanarySchema.parse({ id: ID, kind: "key", value: KEY, seed: 1 });
    expect(parsed).toEqual({ id: ID, kind: "key", value: KEY });
  });
});

describe("EXAMPLE_CANARIES", () => {
  it("is one key then two routes, valid, unique and deeply frozen", () => {
    expect(EXAMPLE_CANARIES.map((canary) => canary.kind)).toEqual(["key", "route", "route"]);
    for (const canary of EXAMPLE_CANARIES) expect(CanarySchema.parse(canary)).toEqual(canary);
    expect(new Set(EXAMPLE_CANARIES.map((canary) => canary.id)).size).toBe(3);
    expect(new Set(EXAMPLE_CANARIES.map((canary) => canary.value)).size).toBe(3);
    expect(Object.isFrozen(EXAMPLE_CANARIES)).toBe(true);
    expect(EXAMPLE_CANARIES.every((canary) => Object.isFrozen(canary))).toBe(true);
  });
});

describe("LEAK_RULES", () => {
  it("has the nine rules of the plan's table, in order, each with a title", () => {
    const id: LeakRuleId = "source-map";
    expect(LEAK_RULES.map((rule) => rule.id)).toEqual([
      id,
      "private-key",
      "aws-access-key",
      "github-token",
      "stripe-secret",
      "slack-token",
      "google-api-key",
      "secret-assignment",
      "internal-url",
    ]);
    expect(LEAK_RULES).toEqual([
      { id: "source-map", title: "Source map" },
      { id: "private-key", title: "Private key" },
      { id: "aws-access-key", title: "AWS access key" },
      { id: "github-token", title: "GitHub token" },
      { id: "stripe-secret", title: "Stripe secret key" },
      { id: "slack-token", title: "Slack token" },
      { id: "google-api-key", title: "Google API key" },
      { id: "secret-assignment", title: "Secret assigned to a secret-like name" },
      { id: "internal-url", title: "Internal URL" },
    ]);
  });

  it("is deeply frozen", () => {
    expect(Object.isFrozen(LEAK_RULES)).toBe(true);
    expect(LEAK_RULES.every((rule) => Object.isFrozen(rule))).toBe(true);
  });
});

describe("LeakScanSummarySchema", () => {
  it("parses a clean and a suppressed summary unchanged", () => {
    const clean: LeakScanSummary = { status: "clean", suppressed: 0 };
    const suppressed: LeakScanSummary = { status: "suppressed", suppressed: 2 };
    expect(LeakScanSummarySchema.parse(clean)).toEqual(clean);
    expect(LeakScanSummarySchema.parse(suppressed)).toEqual(suppressed);
  });

  it("requires clean to have none suppressed and suppressed to have at least one", () => {
    expect(ok(LeakScanSummarySchema, { status: "clean", suppressed: 1 })).toBe(false);
    expect(ok(LeakScanSummarySchema, { status: "suppressed", suppressed: 0 })).toBe(false);
  });

  it("requires a known status and a non-negative integer count", () => {
    expect(ok(LeakScanSummarySchema, { status: "failed", suppressed: 0 })).toBe(false);
    expect(ok(LeakScanSummarySchema, { status: "suppressed", suppressed: 1.5 })).toBe(false);
    expect(ok(LeakScanSummarySchema, { status: "clean", suppressed: -1 })).toBe(false);
    expect(ok(LeakScanSummarySchema, { status: "clean" })).toBe(false);
  });

  it("strips unknown keys: a finding cannot ride along", () => {
    const parsed = LeakScanSummarySchema.parse({ status: "clean", suppressed: 0, findings: [{ value: "x" }] });
    expect(parsed).toEqual({ status: "clean", suppressed: 0 });
  });
});

describe("LeakAllowlistSchema", () => {
  const entry = { fingerprint: "0123456789abcdef0123456789abcdef", reason: "Reviewed: test fixture." };
  const list = (allow: unknown[]) => ({ version: 1, allow });

  it("has the limits of contract P1", () => {
    expect(LEAK_LIMITS).toEqual({ allowMax: 1000, reasonMax: 200 });
  });

  it("parses an allowlist unchanged, including an empty one", () => {
    const allowlist: LeakAllowlist = list([entry]) as LeakAllowlist;
    expect(LeakAllowlistSchema.parse(allowlist)).toEqual(allowlist);
    expect(LeakAllowlistSchema.parse(list([]))).toEqual(list([]));
  });

  it("requires version to be the literal 1", () => {
    expect(ok(LeakAllowlistSchema, { version: 2, allow: [] })).toBe(false);
    expect(ok(LeakAllowlistSchema, { allow: [] })).toBe(false);
  });

  it("requires fingerprints of 32 lowercase hex characters", () => {
    expect(ok(LeakAllowlistSchema, list([{ ...entry, fingerprint: "0123" }]))).toBe(false);
    expect(ok(LeakAllowlistSchema, list([{ ...entry, fingerprint: "A".repeat(32) }]))).toBe(false);
    expect(ok(LeakAllowlistSchema, list([{ ...entry, fingerprint: "a".repeat(64) }]))).toBe(false);
  });

  it("requires a reason of 1..200 storable characters", () => {
    expect(ok(LeakAllowlistSchema, list([{ ...entry, reason: "a".repeat(200) }]))).toBe(true);
    expect(ok(LeakAllowlistSchema, list([{ ...entry, reason: "a".repeat(201) }]))).toBe(false);
    expect(ok(LeakAllowlistSchema, list([{ ...entry, reason: "" }]))).toBe(false);
    expect(ok(LeakAllowlistSchema, list([{ ...entry, reason: "a\u0000b" }]))).toBe(false);
    expect(ok(LeakAllowlistSchema, list([{ fingerprint: entry.fingerprint }]))).toBe(false);
  });

  it("accepts up to 1000 entries and rejects 1001", () => {
    const of = (count: number) => list(Array.from({ length: count }, () => entry));
    expect(ok(LeakAllowlistSchema, of(1000))).toBe(true);
    expect(ok(LeakAllowlistSchema, of(1001))).toBe(false);
  });

  it("rejects a malformed file shape", () => {
    expect(ok(LeakAllowlistSchema, [entry])).toBe(false);
    expect(ok(LeakAllowlistSchema, { version: 1, allow: {} })).toBe(false);
    expect(ok(LeakAllowlistSchema, null)).toBe(false);
  });
});

describe("Canary signals", () => {
  it("names the signal canary.touched:<cny id> within the 64-character signal id bound", () => {
    expect(canarySignalId(ID)).toBe(`canary.touched:${ID}`);
    expect(canarySignalId(ID).length).toBeLessThanOrEqual(64);
  });

  it("refuses to build a signal from anything but a Canary id", () => {
    for (const bad of ["cny_0123", "bld_0123456789abcdef01234567", "", `${ID} `, 42, null]) {
      expect(() => canarySignalId(bad as string)).toThrow(TypeError);
    }
  });

  it("parses a signal back to its Canary id", () => {
    expect(parseCanarySignal(canarySignalId(ID))).toBe(ID);
  });

  it.each([
    "canary.touched:",
    "canary.touched:cny_0123",
    "canary.touched:cny_0123456789ABCDEF01234567",
    `canary.touched:${ID}x`,
    `canary.touched:${ID} `,
    ` canary.touched:${ID}`,
    `canary.touched:${ID}\n`,
    `Canary.touched:${ID}`,
    `canary.touchedX${ID}`,
    `canary.touched:bld_0123456789abcdef01234567`,
    "tamper.integrity_mismatch",
    ID,
    "",
  ])("returns null for %j", (signal) => {
    expect(parseCanarySignal(signal)).toBeNull();
  });

  it("returns null for a non-string", () => {
    for (const value of [undefined, null, 1, {}, [ID]]) expect(parseCanarySignal(value)).toBeNull();
  });
});
