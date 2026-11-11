import { describe, expect, it } from "vitest";
import {
  ACTOR_HASH_PATTERN,
  ActorHashSchema,
  type AllowlistEntry,
  type AllowlistEntryResponse,
  AllowlistEntryResponseSchema,
  AllowlistEntrySchema,
  CIDR_PREFIX_BOUNDS,
  CidrSchema,
  CONTAINMENT_DEFAULT_TTL,
  CONTAINMENT_LIMITS,
  CONTAINMENT_STATUSES,
  CONTAINMENT_TTLS,
  type Containment,
  type ContainmentResponse,
  ContainmentResponseSchema,
  ContainmentSchema,
  type ContainmentStatus,
  type ContainmentTarget,
  ContainmentTargetSchema,
  type ContainmentTtl,
  type CreateAllowlistEntryRequest,
  CreateAllowlistEntryRequestSchema,
  type CreateContainmentRequest,
  CreateContainmentRequestSchema,
  cidrContains,
  cidrOverlapsPrefix,
  EXAMPLE_ALLOWLIST_ENTRY,
  EXAMPLE_CONTAINMENT,
  EXAMPLE_INCIDENT,
  ID_PATTERNS,
  type ListAllowlistResponse,
  ListAllowlistResponseSchema,
  type ListContainmentsResponse,
  ListContainmentsResponseSchema,
  type ParsedAddress,
  type ParsedCidr,
  parseAddress,
  parseCidr,
} from "../src/index.ts";

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;
const HASH = "iph_0123456789abcdef0123456789abcdef";
const PREFIX = "203.0.113.0/24";
const containment = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_CONTAINMENT, ...patch });
const entry = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_ALLOWLIST_ENTRY, ...patch });
const of = <T>(value: T, count: number): T[] => Array.from({ length: count }, () => value);

describe("containment constants", () => {
  it("has the TTL choices, the default and the limits of contract P1", () => {
    const ttl: ContainmentTtl = 3600;
    const status: ContainmentStatus = "active";
    expect(CONTAINMENT_TTLS).toEqual([900, ttl, 86_400]);
    expect(CONTAINMENT_DEFAULT_TTL).toBe(3600);
    expect(CONTAINMENT_TTLS).toContain(CONTAINMENT_DEFAULT_TTL);
    expect(CONTAINMENT_LIMITS).toEqual({ activePerAppEnv: 150, allowlistMax: 100, actorsListed: 10, noteMax: 80 });
    expect(CONTAINMENT_STATUSES).toEqual([status, "expired", "lifted"]);
    expect(CIDR_PREFIX_BOUNDS).toEqual({ 4: { min: 8, max: 32 }, 6: { min: 16, max: 128 } });
  });

  it("freezes the TTL choices and the prefix bounds", () => {
    expect(Object.isFrozen(CONTAINMENT_TTLS)).toBe(true);
    expect(Object.isFrozen(CIDR_PREFIX_BOUNDS)).toBe(true);
    expect(Object.isFrozen(CIDR_PREFIX_BOUNDS[4])).toBe(true);
  });

  it("has cnt and alw identifier patterns", () => {
    expect(ID_PATTERNS.cnt.test("cnt_0123456789abcdef01234567")).toBe(true);
    expect(ID_PATTERNS.cnt.test("cnt_0123456789ABCDEF01234567")).toBe(false);
    expect(ID_PATTERNS.cnt.test("cnt_0123")).toBe(false);
    expect(ID_PATTERNS.cnt.test("alw_0123456789abcdef01234567")).toBe(false);
    expect(ID_PATTERNS.alw.test("alw_0123456789abcdef01234567")).toBe(true);
    expect(ID_PATTERNS.alw.test("alw_0123456789abcdef012345678")).toBe(false);
    expect(ID_PATTERNS.alw.test("cnt_0123456789abcdef01234567")).toBe(false);
  });
});

describe("ActorHashSchema", () => {
  it("is iph_ followed by 32 lowercase hex characters", () => {
    expect(ACTOR_HASH_PATTERN.source).toBe("^iph_[0-9a-f]{32}$");
    expect(ActorHashSchema.parse(HASH)).toBe(HASH);
  });

  it.each([
    "iph_0123456789abcdef0123456789abcde",
    "iph_0123456789abcdef0123456789abcdef0",
    "iph_0123456789ABCDEF0123456789ABCDEF",
    "0123456789abcdef0123456789abcdef",
    "cnt_0123456789abcdef01234567",
    "203.0.113.7",
    ` ${HASH}`,
    `${HASH}\n`,
    "",
  ])("rejects %j", (value) => {
    expect(ok(ActorHashSchema, value)).toBe(false);
  });

  it("rejects a non-string", () => {
    for (const value of [null, undefined, 42, {}]) expect(ok(ActorHashSchema, value)).toBe(false);
  });
});

describe("ContainmentTargetSchema", () => {
  it("parses an actor target and a prefix target unchanged", () => {
    const actor: ContainmentTarget = { kind: "actor", ip_hash: HASH };
    const prefix: ContainmentTarget = { kind: "prefix", ip_prefix: PREFIX };
    expect(ContainmentTargetSchema.parse(actor)).toEqual(actor);
    expect(ContainmentTargetSchema.parse(prefix)).toEqual(prefix);
    expect(ok(ContainmentTargetSchema, { kind: "prefix", ip_prefix: "2001:db8:abcd::/48" })).toBe(true);
  });

  it("requires the value of its kind, in the form of its kind", () => {
    expect(ok(ContainmentTargetSchema, { kind: "actor" })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "actor", ip_prefix: PREFIX })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "actor", ip_hash: "203.0.113.7" })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "prefix" })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "prefix", ip_hash: HASH })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "prefix", ip_prefix: "203.0.113.7/32" })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "prefix", ip_prefix: "203.0.113.7" })).toBe(false);
    expect(ok(ContainmentTargetSchema, { kind: "prefix", ip_prefix: "203.0.0.0/16" })).toBe(false);
  });

  it("rejects an unknown or missing kind", () => {
    expect(ok(ContainmentTargetSchema, { kind: "device", ip_hash: HASH })).toBe(false);
    expect(ok(ContainmentTargetSchema, { ip_hash: HASH })).toBe(false);
    expect(ok(ContainmentTargetSchema, null)).toBe(false);
  });

  it("strips unknown keys, including the other kind's value", () => {
    expect(
      ContainmentTargetSchema.parse({ kind: "actor", ip_hash: HASH, ip_prefix: PREFIX, ip: "203.0.113.7" }),
    ).toEqual({ kind: "actor", ip_hash: HASH });
    expect(ContainmentTargetSchema.parse({ kind: "prefix", ip_prefix: PREFIX, ip_hash: HASH })).toEqual({
      kind: "prefix",
      ip_prefix: PREFIX,
    });
  });
});

describe("ContainmentSchema", () => {
  const lifted = {
    lifted_at: "2026-11-10T08:30:00.000Z",
    lifted_by: "key_89abcdef0123456789abcdef",
    status: "lifted",
  };

  it("parses the documented example unchanged, also after a round trip through JSON", () => {
    const parsed: Containment = ContainmentSchema.parse(EXAMPLE_CONTAINMENT);
    expect(parsed).toEqual(EXAMPLE_CONTAINMENT);
    expect(ContainmentSchema.parse(JSON.parse(JSON.stringify(EXAMPLE_CONTAINMENT)))).toEqual(EXAMPLE_CONTAINMENT);
    expect(Object.keys(parsed).sort()).toEqual([
      "app_id",
      "created_at",
      "created_by",
      "environment",
      "expires_at",
      "id",
      "incident_id",
      "lifted_at",
      "lifted_by",
      "status",
      "target",
    ]);
  });

  it("accepts a prefix target, no Incident, and each status", () => {
    expect(ok(ContainmentSchema, containment({ target: { kind: "prefix", ip_prefix: PREFIX } }))).toBe(true);
    expect(ok(ContainmentSchema, containment({ incident_id: null }))).toBe(true);
    expect(ok(ContainmentSchema, containment({ status: "expired" }))).toBe(true);
    expect(ok(ContainmentSchema, containment(lifted))).toBe(true);
    expect(ok(ContainmentSchema, containment({ status: "deleted" }))).toBe(false);
  });

  it("requires every key", () => {
    for (const key of Object.keys(EXAMPLE_CONTAINMENT)) {
      const { [key]: _removed, ...rest } = EXAMPLE_CONTAINMENT as Record<string, unknown>;
      expect(ok(ContainmentSchema, rest), key).toBe(false);
    }
  });

  it("requires identifiers of the right kind", () => {
    expect(ok(ContainmentSchema, containment({ id: "cnt_0123" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ id: "alw_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ app_id: "org_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ environment: "qa" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ incident_id: "dtc_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ created_by: "aro_synthetic" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ created_by: null }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ ...lifted, lifted_by: "someone" }))).toBe(false);
  });

  it("requires ISO-8601 UTC datetimes", () => {
    expect(ok(ContainmentSchema, containment({ created_at: "now" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ expires_at: 1_794_298_530_123 }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ expires_at: "2026-11-10T09:21:00+07:00" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ ...lifted, lifted_at: "yesterday" }))).toBe(false);
  });

  it("carries who lifted it and when exactly when its status is lifted", () => {
    expect(ok(ContainmentSchema, containment({ ...lifted, status: "active" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ ...lifted, status: "expired" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ status: "lifted" }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ ...lifted, lifted_by: null }))).toBe(false);
    expect(ok(ContainmentSchema, containment({ ...lifted, lifted_at: null }))).toBe(false);
  });

  it("strips unknown keys: no address and no Organization ride along", () => {
    const parsed = ContainmentSchema.parse(containment({ organization_id: "org_ffffffffffffffffffffffff", ip: "x" }));
    expect(parsed).toEqual(EXAMPLE_CONTAINMENT);
  });
});

describe("CreateContainmentRequestSchema", () => {
  it("parses an actor block unchanged", () => {
    const request: CreateContainmentRequest = CreateContainmentRequestSchema.parse({
      target: { kind: "actor", ip_hash: HASH },
      ttl_s: 3600,
    });
    expect(request).toEqual({ target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 });
  });

  it("parses a prefix block with its typed confirmation unchanged", () => {
    const request = CreateContainmentRequestSchema.parse({
      target: { kind: "prefix" },
      ttl_s: 900,
      confirm_prefix: PREFIX,
    });
    expect(request).toEqual({ target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: PREFIX });
    expect(
      ok(CreateContainmentRequestSchema, {
        target: { kind: "prefix" },
        ttl_s: 86_400,
        confirm_prefix: "2001:db8:abcd::/48",
      }),
    ).toBe(true);
  });

  it("refuses a prefix block without a confirmation in the form of a prefix", () => {
    const body = (confirm_prefix?: unknown) => ({ target: { kind: "prefix" }, ttl_s: 3600, confirm_prefix });
    const missing = CreateContainmentRequestSchema.safeParse({ target: { kind: "prefix" }, ttl_s: 3600 });
    expect(missing.success).toBe(false);
    expect(missing.error?.issues.map((issue) => issue.path)).toEqual([["confirm_prefix"]]);
    expect(ok(CreateContainmentRequestSchema, body(undefined))).toBe(false);
    expect(ok(CreateContainmentRequestSchema, body(null))).toBe(false);
    expect(ok(CreateContainmentRequestSchema, body(""))).toBe(false);
    expect(ok(CreateContainmentRequestSchema, body("yes"))).toBe(false);
    expect(ok(CreateContainmentRequestSchema, body("203.0.113.7"))).toBe(false);
    expect(ok(CreateContainmentRequestSchema, body("203.0.113.0/25"))).toBe(false);
    expect(ok(CreateContainmentRequestSchema, body(` ${PREFIX}`))).toBe(false);
  });

  it("takes the prefix from the Incident, never from the body: a prefix in the target is stripped", () => {
    const request = CreateContainmentRequestSchema.parse({
      target: { kind: "prefix", ip_prefix: "198.51.100.0/24" },
      ttl_s: 3600,
      confirm_prefix: PREFIX,
    });
    expect(request.target).toEqual({ kind: "prefix" });
  });

  it("does not need a confirmation for an actor block, and refuses a malformed one", () => {
    const body = (confirm_prefix: unknown) => ({
      target: { kind: "actor", ip_hash: HASH },
      ttl_s: 3600,
      confirm_prefix,
    });
    expect(ok(CreateContainmentRequestSchema, body(undefined))).toBe(true);
    expect(ok(CreateContainmentRequestSchema, body(PREFIX))).toBe(true);
    expect(ok(CreateContainmentRequestSchema, body("yes"))).toBe(false);
  });

  it("requires an actor block to name a well-formed actor hash", () => {
    expect(ok(CreateContainmentRequestSchema, { target: { kind: "actor" }, ttl_s: 3600 })).toBe(false);
    expect(ok(CreateContainmentRequestSchema, { target: { kind: "actor", ip_hash: "203.0.113.7" }, ttl_s: 3600 })).toBe(
      false,
    );
    expect(ok(CreateContainmentRequestSchema, { target: { kind: "device", ip_hash: HASH }, ttl_s: 3600 })).toBe(false);
    expect(ok(CreateContainmentRequestSchema, { ttl_s: 3600 })).toBe(false);
  });

  it("accepts only the three TTL choices, and requires one", () => {
    const body = (ttl_s?: unknown) => ({ target: { kind: "actor", ip_hash: HASH }, ttl_s });
    for (const ttl of CONTAINMENT_TTLS) expect(ok(CreateContainmentRequestSchema, body(ttl)), String(ttl)).toBe(true);
    for (const ttl of [0, 1, 899, 901, 3601, 86_401, 604_800, -3600, 900.5, "3600", null, undefined]) {
      expect(ok(CreateContainmentRequestSchema, body(ttl)), String(ttl)).toBe(false);
    }
    expect(ok(CreateContainmentRequestSchema, { target: { kind: "actor", ip_hash: HASH } })).toBe(false);
  });

  it("strips unknown keys: App, Environment and expiry are the API's", () => {
    const parsed = CreateContainmentRequestSchema.parse({
      target: { kind: "actor", ip_hash: HASH },
      ttl_s: 3600,
      app_id: "app_ffffffffffffffffffffffff",
      environment: "production",
      expires_at: "2099-01-01T00:00:00.000Z",
    });
    expect(parsed).toEqual({ target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 });
  });
});

describe("containment responses", () => {
  it("wraps one Containment", () => {
    const response: ContainmentResponse = ContainmentResponseSchema.parse({ containment: EXAMPLE_CONTAINMENT });
    expect(response).toEqual({ containment: EXAMPLE_CONTAINMENT });
    expect(ok(ContainmentResponseSchema, {})).toBe(false);
    expect(ok(ContainmentResponseSchema, { containment: containment({ id: "cnt_1" }) })).toBe(false);
  });

  it("wraps a list of Containments", () => {
    const list: ListContainmentsResponse = ListContainmentsResponseSchema.parse({
      containments: [EXAMPLE_CONTAINMENT, EXAMPLE_CONTAINMENT],
    });
    expect(list.containments).toEqual([EXAMPLE_CONTAINMENT, EXAMPLE_CONTAINMENT]);
    expect(ok(ListContainmentsResponseSchema, { containments: [] })).toBe(true);
    expect(ok(ListContainmentsResponseSchema, { containments: of(EXAMPLE_CONTAINMENT, 301) })).toBe(true);
    expect(ok(ListContainmentsResponseSchema, {})).toBe(false);
    expect(ok(ListContainmentsResponseSchema, { containments: [containment({ status: "gone" })] })).toBe(false);
  });
});

describe("CidrSchema: canonical text only", () => {
  it.each([
    "10.0.0.0/8",
    "0.0.0.0/8",
    "172.16.0.0/12",
    "192.168.128.0/17",
    "203.0.113.0/24",
    "203.0.113.7/32",
    "255.255.255.255/32",
    "2001::/16",
    "2001:db8::/32",
    "2001:db8:0:1::/64",
    "2001:db8::1/128",
    "2001:db8:0:1:1:1:1:1/128",
    "2001:0:0:1::1/128",
    "2001:db8::1:0:0:1/128",
    "::/16",
    "::1/128",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
  ])("accepts %s", (cidr) => {
    expect(CidrSchema.parse(cidr)).toBe(cidr);
  });

  it.each([
    ["host bits set", "10.0.0.1/8"],
    ["host bits set", "203.0.113.7/24"],
    ["host bits set", "2001:db8::1/64"],
    ["host bits set", "2001:db8::/16"],
    ["wider than /8", "10.0.0.0/7"],
    ["wider than /8", "0.0.0.0/0"],
    ["longer than /32", "10.0.0.0/33"],
    ["wider than /16", "::/15"],
    ["wider than /16", "::/0"],
    ["longer than /128", "::/129"],
    ["upper-case hex", "2001:DB8::/32"],
    ["leading zeros in a group", "2001:0db8::/32"],
    ["zeros not compressed", "2001:db8:0:0:0:0:0:0/32"],
    ["a single zero group compressed", "2001:db8::1:1:1:1:1/128"],
    ["not the longest run compressed", "2001::1:0:0:0:1/128"],
    ["not the first of two equal runs compressed", "2001:db8:0:0:1::1/128"],
    ["dotted tail", "64:ff9b::192.0.2.33/128"],
    ["leading zero in an octet", "010.0.0.0/8"],
    ["leading zero in the length", "10.0.0.0/08"],
    ["no length", "10.0.0.0"],
    ["surrounding space", " 10.0.0.0/8"],
    ["surrounding space", "10.0.0.0/8\n"],
    ["an IPv4-mapped block", "::ffff:10.0.0.0/104"],
    ["a zone id", "fe80::%eth0/64"],
    ["empty", ""],
  ])("rejects %s: %j", (_why, cidr) => {
    expect(ok(CidrSchema, cidr)).toBe(false);
  });

  it("rejects a non-string", () => {
    for (const value of [null, undefined, 8, ["10.0.0.0/8"]]) expect(ok(CidrSchema, value)).toBe(false);
  });
});

describe("AllowlistEntrySchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: AllowlistEntry = AllowlistEntrySchema.parse(EXAMPLE_ALLOWLIST_ENTRY);
    expect(parsed).toEqual(EXAMPLE_ALLOWLIST_ENTRY);
    expect(Object.keys(parsed).sort()).toEqual(["cidr", "created_at", "created_by", "id", "note"]);
  });

  it("requires every key, an alw id, an admin key id and a datetime", () => {
    for (const key of Object.keys(EXAMPLE_ALLOWLIST_ENTRY)) {
      const { [key]: _removed, ...rest } = EXAMPLE_ALLOWLIST_ENTRY as Record<string, unknown>;
      expect(ok(AllowlistEntrySchema, rest), key).toBe(false);
    }
    expect(ok(AllowlistEntrySchema, entry({ id: "cnt_0123456789abcdef01234567" }))).toBe(false);
    expect(ok(AllowlistEntrySchema, entry({ created_by: "admin" }))).toBe(false);
    expect(ok(AllowlistEntrySchema, entry({ created_at: "today" }))).toBe(false);
  });

  it("requires a canonical CIDR", () => {
    expect(ok(AllowlistEntrySchema, entry({ cidr: "2001:db8::/32" }))).toBe(true);
    expect(ok(AllowlistEntrySchema, entry({ cidr: "198.51.100.7/24" }))).toBe(false);
    expect(ok(AllowlistEntrySchema, entry({ cidr: "198.51.100.7" }))).toBe(false);
    expect(ok(AllowlistEntrySchema, entry({ cidr: "2001:DB8::/32" }))).toBe(false);
  });

  it("limits the note to 80 storable characters; it may be empty", () => {
    expect(ok(AllowlistEntrySchema, entry({ note: "" }))).toBe(true);
    expect(ok(AllowlistEntrySchema, entry({ note: "n".repeat(80) }))).toBe(true);
    expect(ok(AllowlistEntrySchema, entry({ note: "n".repeat(81) }))).toBe(false);
    expect(ok(AllowlistEntrySchema, entry({ note: "a\u0000b" }))).toBe(false);
    expect(ok(AllowlistEntrySchema, entry({ note: null }))).toBe(false);
  });

  it("strips unknown keys", () => {
    expect(AllowlistEntrySchema.parse(entry({ organization_id: "org_ffffffffffffffffffffffff" }))).toEqual(
      EXAMPLE_ALLOWLIST_ENTRY,
    );
  });
});

describe("CreateAllowlistEntryRequestSchema", () => {
  it("parses a canonical CIDR and a note, trimming the note", () => {
    const request: CreateAllowlistEntryRequest = CreateAllowlistEntryRequestSchema.parse({
      cidr: "198.51.100.0/24",
      note: "  Office network  ",
    });
    expect(request).toEqual({ cidr: "198.51.100.0/24", note: "Office network" });
    expect(CreateAllowlistEntryRequestSchema.parse({ cidr: "2001:db8::/32", note: "   " })).toEqual({
      cidr: "2001:db8::/32",
      note: "",
    });
  });

  it("refuses a CIDR that is not normalised instead of rewriting it", () => {
    const body = (cidr: unknown) => ({ cidr, note: "synthetic" });
    expect(ok(CreateAllowlistEntryRequestSchema, body("198.51.100.7/24"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body("2001:DB8::/32"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body(" 198.51.100.0/24"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body("10.0.0.0/7"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body("::/15"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body("198.51.100.7"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body(undefined))).toBe(false);
  });

  it("requires a note of at most 80 storable characters after trimming", () => {
    const body = (note?: unknown) => ({ cidr: "198.51.100.0/24", note });
    expect(ok(CreateAllowlistEntryRequestSchema, body(""))).toBe(true);
    expect(ok(CreateAllowlistEntryRequestSchema, body(` ${"n".repeat(80)} `))).toBe(true);
    expect(ok(CreateAllowlistEntryRequestSchema, body("n".repeat(81)))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body("a\u0007b"))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body(undefined))).toBe(false);
    expect(ok(CreateAllowlistEntryRequestSchema, body(7))).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = CreateAllowlistEntryRequestSchema.parse({ cidr: "198.51.100.0/24", note: "x", id: "alw_1" });
    expect(parsed).toEqual({ cidr: "198.51.100.0/24", note: "x" });
  });
});

describe("ListAllowlistResponseSchema", () => {
  it("wraps at most 100 entries", () => {
    const list: ListAllowlistResponse = ListAllowlistResponseSchema.parse({ entries: [EXAMPLE_ALLOWLIST_ENTRY] });
    expect(list.entries).toEqual([EXAMPLE_ALLOWLIST_ENTRY]);
    expect(ok(ListAllowlistResponseSchema, { entries: [] })).toBe(true);
    expect(ok(ListAllowlistResponseSchema, { entries: of(EXAMPLE_ALLOWLIST_ENTRY, 100) })).toBe(true);
    expect(ok(ListAllowlistResponseSchema, { entries: of(EXAMPLE_ALLOWLIST_ENTRY, 101) })).toBe(false);
    expect(ok(ListAllowlistResponseSchema, {})).toBe(false);
  });
});

describe("parseAddress", () => {
  it("parses an IPv4 address into two 16-bit words", () => {
    const parsed: ParsedAddress | null = parseAddress("203.0.113.7");
    expect(parsed).toEqual({ version: 4, words: [0xcb00, 0x7107] });
    expect(parseAddress("0.0.0.0")).toEqual({ version: 4, words: [0, 0] });
    expect(parseAddress("255.255.255.255")).toEqual({ version: 4, words: [0xffff, 0xffff] });
  });

  it("parses an IPv6 address into eight 16-bit words, whatever its spelling", () => {
    const words = [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1];
    expect(parseAddress("2001:db8::1")).toEqual({ version: 6, words });
    expect(parseAddress("2001:DB8::1")).toEqual({ version: 6, words });
    expect(parseAddress("2001:0db8:0000:0000:0000:0000:0000:0001")).toEqual({ version: 6, words });
    expect(parseAddress("2001:db8:0:0:0:0:0:1")).toEqual({ version: 6, words });
    expect(parseAddress("::")).toEqual({ version: 6, words: [0, 0, 0, 0, 0, 0, 0, 0] });
    expect(parseAddress("::1")).toEqual({ version: 6, words: [0, 0, 0, 0, 0, 0, 0, 1] });
    expect(parseAddress("1::")).toEqual({ version: 6, words: [1, 0, 0, 0, 0, 0, 0, 0] });
    expect(parseAddress("1:2:3:4:5:6:7::")).toEqual({ version: 6, words: [1, 2, 3, 4, 5, 6, 7, 0] });
    expect(parseAddress("::2:3:4:5:6:7:8")).toEqual({ version: 6, words: [0, 2, 3, 4, 5, 6, 7, 8] });
    expect(parseAddress("64:ff9b::192.0.2.33")).toEqual({
      version: 6,
      words: [0x64, 0xff9b, 0, 0, 0, 0, 0xc000, 0x221],
    });
    expect(parseAddress("1:2:3:4:5:6:192.0.2.33")).toEqual({ version: 6, words: [1, 2, 3, 4, 5, 6, 0xc000, 0x221] });
  });

  it("treats an IPv4-mapped IPv6 address as the IPv4 address, in every spelling", () => {
    const ipv4 = parseAddress("203.0.113.7");
    expect(parseAddress("::ffff:203.0.113.7")).toEqual(ipv4);
    expect(parseAddress("::FFFF:203.0.113.7")).toEqual(ipv4);
    expect(parseAddress("::ffff:cb00:7107")).toEqual(ipv4);
    expect(parseAddress("0:0:0:0:0:ffff:203.0.113.7")).toEqual(ipv4);
    expect(parseAddress("0000:0000:0000:0000:0000:ffff:cb00:7107")).toEqual(ipv4);
  });

  it("does not treat a neighbouring block as IPv4-mapped", () => {
    expect(parseAddress("::203.0.113.7")?.version).toBe(6);
    expect(parseAddress("::fffe:203.0.113.7")?.version).toBe(6);
    expect(parseAddress("::1:ffff:203.0.113.7")?.version).toBe(6);
    expect(parseAddress("64:ff9b::203.0.113.7")?.version).toBe(6);
  });

  it("strips the zone id of an IPv6 address", () => {
    expect(parseAddress("fe80::1%eth0")).toEqual(parseAddress("fe80::1"));
    expect(parseAddress("fe80::1%12")).toEqual(parseAddress("fe80::1"));
    expect(parseAddress("::ffff:203.0.113.7%eth0")).toEqual(parseAddress("203.0.113.7"));
  });

  it("returns a frozen value", () => {
    const parsed = parseAddress("203.0.113.7");
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.words)).toBe(true);
  });

  it.each([
    "",
    " ",
    "203.0.113",
    "203.0.113.7.1",
    "203.0.113.256",
    "203.0.113.07",
    "203.0.113.-1",
    "203.0.113.7 ",
    " 203.0.113.7",
    "203.0.113.7:443",
    "203.0.113.7/32",
    "203.0.113.7%eth0",
    "0x7f.0.0.1",
    "2130706433",
    "localhost",
    ":",
    ":::",
    "1::2::3",
    "1:2:3:4:5:6:7",
    "1:2:3:4:5:6:7:8:9",
    "1:2:3:4:5:6:7:8::",
    "::1:2:3:4:5:6:7:8",
    "1:2:3:4::5:6:7:8",
    "12345::",
    "g::1",
    "1:",
    ":1",
    "::1:",
    "[::1]",
    "[::1]:443",
    "::1/128",
    "fe80::1%",
    "1:2:3:4:5:6:7:192.0.2.33",
    "1:2:3:4:5:192.0.2.33:7",
    "192.0.2.33::",
    "::192.0.2",
    "::192.0.2.256",
    "::ffff:203.0.113.07",
    `2001:db8::${"1".repeat(200)}`,
  ])("returns null for %j", (text) => {
    expect(parseAddress(text)).toBeNull();
  });

  it("returns null for a non-string", () => {
    for (const value of [null, undefined, 42, {}, ["203.0.113.7"]]) expect(parseAddress(value)).toBeNull();
  });
});

describe("parseCidr", () => {
  it("parses an IPv4 CIDR", () => {
    const parsed: ParsedCidr | null = parseCidr("10.0.0.0/8");
    expect(parsed).toEqual({ version: 4, words: [0x0a00, 0], prefix: 8, cidr: "10.0.0.0/8" });
    expect(parseCidr("203.0.113.7/32")).toEqual({
      version: 4,
      words: [0xcb00, 0x7107],
      prefix: 32,
      cidr: "203.0.113.7/32",
    });
    expect(parseCidr("192.168.128.0/17")?.cidr).toBe("192.168.128.0/17");
  });

  it("parses an IPv6 CIDR", () => {
    expect(parseCidr("2001:db8::/32")).toEqual({
      version: 6,
      words: [0x2001, 0xdb8, 0, 0, 0, 0, 0, 0],
      prefix: 32,
      cidr: "2001:db8::/32",
    });
    expect(parseCidr("::1/128")?.cidr).toBe("::1/128");
  });

  it.each([
    ["2001:DB8::/32", "2001:db8::/32"],
    ["2001:0db8:0000:0000:0000:0000:0000:0000/32", "2001:db8::/32"],
    ["2001:db8:0:0:0:0:0:0/32", "2001:db8::/32"],
    ["2001:0db8:0000:0000:0000:0000:0000:0001/128", "2001:db8::1/128"],
    ["2001:db8:0:1:1:1:1:1/128", "2001:db8:0:1:1:1:1:1/128"],
    ["2001:db8::1:1:1:1:1/128", "2001:db8:0:1:1:1:1:1/128"],
    ["2001:0:0:1:0:0:0:1/128", "2001:0:0:1::1/128"],
    ["2001:db8:0:0:1:0:0:1/128", "2001:db8::1:0:0:1/128"],
    ["0:0:0:0:0:0:0:0/128", "::/128"],
    ["0:0:0:0:0:0:0:1/128", "::1/128"],
    ["1:0:0:0:0:0:0:0/16", "1::/16"],
    ["0:0:1:0:0:0:0:0/48", "0:0:1::/48"],
    ["64:ff9b::192.0.2.33/128", "64:ff9b::c000:221/128"],
    ["ABCD:EF01:2345:6789:ABCD:EF01:2345:6789/128", "abcd:ef01:2345:6789:abcd:ef01:2345:6789/128"],
  ])("gives %s the canonical text %s (RFC 5952)", (text, cidr) => {
    expect(parseCidr(text)?.cidr).toBe(cidr);
    expect(parseCidr(cidr)?.cidr).toBe(cidr);
  });

  it("accepts every prefix length of its range whose host bits are zero", () => {
    for (let length = 8; length <= 32; length++) {
      expect(parseCidr(`0.0.0.0/${length}`)?.prefix, String(length)).toBe(length);
      expect(parseCidr(`255.255.255.255/${length}`) === null, String(length)).toBe(length !== 32);
    }
    for (let length = 16; length <= 128; length++) {
      expect(parseCidr(`::/${length}`)?.prefix, String(length)).toBe(length);
      const ones = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
      expect(parseCidr(`${ones}/${length}`) === null, String(length)).toBe(length !== 128);
    }
  });

  it("checks the host bits at a length that is not on a 16-bit boundary", () => {
    expect(parseCidr("10.32.0.0/11")?.cidr).toBe("10.32.0.0/11");
    expect(parseCidr("10.48.0.0/11")).toBeNull();
    expect(parseCidr("10.0.0.128/25")?.cidr).toBe("10.0.0.128/25");
    expect(parseCidr("10.0.0.64/25")).toBeNull();
    expect(parseCidr("10.0.0.2/31")?.cidr).toBe("10.0.0.2/31");
    expect(parseCidr("10.0.0.1/31")).toBeNull();
    expect(parseCidr("2001:db8:8000::/33")?.cidr).toBe("2001:db8:8000::/33");
    expect(parseCidr("2001:db8:4000::/33")).toBeNull();
    expect(parseCidr("2001:db8::2/127")?.cidr).toBe("2001:db8::2/127");
    expect(parseCidr("2001:db8::1/127")).toBeNull();
  });

  it.each([
    "10.0.0.0/7",
    "10.0.0.0/0",
    "10.0.0.0/33",
    "::/15",
    "::/0",
    "::/129",
    "::/1000",
    "10.0.0.1/8",
    "203.0.113.7/24",
    "2001:db8::1/64",
    "2001:db8::/16",
    "10.0.0.0",
    "10.0.0.0/",
    "/8",
    "10.0.0.0/08",
    "10.0.0.0/+8",
    "10.0.0.0/8.0",
    "10.0.0.0/8 ",
    " 10.0.0.0/8",
    "10.0.0.0/8/8",
    "010.0.0.0/8",
    "10.0.0/8",
    "256.0.0.0/8",
    "fe80::%eth0/64",
    "::ffff:10.0.0.0/104",
    "::ffff:0:0/96",
    "::ffff:203.0.113.7/128",
    "1::2::3/128",
    "g::/16",
    "",
  ])("returns null for %j", (text) => {
    expect(parseCidr(text)).toBeNull();
  });

  it("returns null for a non-string and a frozen value otherwise", () => {
    for (const value of [null, undefined, 8, {}]) expect(parseCidr(value)).toBeNull();
    const parsed = parseCidr("10.0.0.0/8");
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.words)).toBe(true);
  });
});

describe("cidrContains", () => {
  it.each([
    ["10.0.0.0/8", "10.0.0.0", true],
    ["10.0.0.0/8", "10.255.255.255", true],
    ["10.0.0.0/8", "11.0.0.0", false],
    ["10.0.0.0/8", "9.255.255.255", false],
    ["10.32.0.0/11", "10.63.255.255", true],
    ["10.32.0.0/11", "10.64.0.0", false],
    ["10.32.0.0/11", "10.31.255.255", false],
    ["172.16.0.0/12", "172.31.255.255", true],
    ["172.16.0.0/12", "172.32.0.0", false],
    ["192.168.128.0/17", "192.168.128.0", true],
    ["192.168.128.0/17", "192.168.127.255", false],
    ["203.0.113.0/24", "203.0.113.77", true],
    ["203.0.113.0/24", "203.0.112.255", false],
    ["203.0.113.0/24", "203.0.114.0", false],
    ["203.0.113.128/25", "203.0.113.128", true],
    ["203.0.113.128/25", "203.0.113.127", false],
    ["203.0.113.6/31", "203.0.113.7", true],
    ["203.0.113.6/31", "203.0.113.8", false],
    ["203.0.113.7/32", "203.0.113.7", true],
    ["203.0.113.7/32", "203.0.113.8", false],
    ["203.0.113.7/32", "203.0.112.7", false],
    ["2001::/16", "2001:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true],
    ["2001::/16", "2002::", false],
    ["2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true],
    ["2001:db8::/32", "2001:DB8::1", true],
    ["2001:db8::/32", "2001:db9::", false],
    ["2001:db8:8000::/33", "2001:db8:8000::1", true],
    ["2001:db8:8000::/33", "2001:db8:7fff::1", false],
    ["2001:db8:0:1::/64", "2001:db8:0:1::1", true],
    ["2001:db8:0:1::/64", "2001:db8:0:1:ffff:ffff:ffff:ffff", true],
    ["2001:db8:0:1::/64", "2001:db8:0:2::1", false],
    ["2001:db8::2/127", "2001:db8::3", true],
    ["2001:db8::2/127", "2001:db8::4", false],
    ["2001:db8::1/128", "2001:db8::1", true],
    ["2001:db8::1/128", "2001:db8::2", false],
    ["2001:db8::1/128", "2001:db8:0:0:1::1", false],
  ])("%s contains %s: %s", (cidr, address, expected) => {
    expect(cidrContains(cidr, address)).toBe(expected);
  });

  it("matches an IPv4-mapped IPv6 address as its IPv4 address", () => {
    expect(cidrContains("203.0.113.0/24", "::ffff:203.0.113.77")).toBe(true);
    expect(cidrContains("203.0.113.0/24", "::FFFF:203.0.113.77")).toBe(true);
    expect(cidrContains("203.0.113.0/24", "::ffff:cb00:714d")).toBe(true);
    expect(cidrContains("203.0.113.0/24", "::ffff:203.0.114.77")).toBe(false);
    expect(cidrContains("203.0.113.0/24", "::203.0.113.77")).toBe(false);
  });

  it("never matches across address families: an IPv6 CIDR does not contain an IPv4 address", () => {
    expect(cidrContains("::/16", "203.0.113.77")).toBe(false);
    expect(cidrContains("::/16", "::ffff:203.0.113.77")).toBe(false);
    expect(cidrContains("::/16", "::203.0.113.77")).toBe(true);
    expect(cidrContains("203.0.113.0/24", "2001:db8::1")).toBe(false);
    expect(cidrContains("0.0.0.0/8", "::1")).toBe(false);
  });

  it("strips the zone id of the address", () => {
    expect(cidrContains("fe80::/64", "fe80::1%eth0")).toBe(true);
    expect(cidrContains("fe80::/64", "fe81::1%eth0")).toBe(false);
  });

  it("is false for an address that is not one", () => {
    for (const address of ["", "not an address", "10.0.0.1:443", "[::1]", "10.0.0.1%eth0", "10.0.0.1/32", "10.0.0"]) {
      expect(cidrContains("10.0.0.0/8", address), address).toBe(false);
    }
    expect(cidrContains("10.0.0.0/8", null)).toBe(false);
    expect(cidrContains("10.0.0.0/8", undefined)).toBe(false);
    expect(cidrContains("10.0.0.0/8", 167_772_161 as unknown as string)).toBe(false);
  });

  it("is false for a CIDR that is not a normalised one", () => {
    expect(cidrContains("10.0.0.1/8", "10.0.0.1")).toBe(false);
    expect(cidrContains("10.0.0.0/7", "10.0.0.1")).toBe(false);
    expect(cidrContains("10.0.0.0", "10.0.0.0")).toBe(false);
    expect(cidrContains("nope", "10.0.0.1")).toBe(false);
    expect(cidrContains("", "10.0.0.1")).toBe(false);
    expect(cidrContains(null as unknown as string, "10.0.0.1")).toBe(false);
  });

  it("takes a CIDR and an address that were parsed before", () => {
    const cidr = parseCidr("10.0.0.0/8") as ParsedCidr;
    expect(cidrContains(cidr, parseAddress("10.1.2.3"))).toBe(true);
    expect(cidrContains(cidr, parseAddress("11.1.2.3"))).toBe(false);
    expect(cidrContains(cidr, "10.1.2.3")).toBe(true);
    expect(cidrContains(cidr, parseAddress("nope"))).toBe(false);
    expect(cidrContains("2001:db8::/32", parseAddress("2001:db8::7"))).toBe(true);
  });
});

describe("cidrOverlapsPrefix", () => {
  it.each([
    ["203.0.113.0/24", "203.0.113.0/24", true],
    ["203.0.0.0/16", "203.0.113.0/24", true],
    ["10.0.0.0/8", "10.9.8.0/24", true],
    ["203.0.112.0/23", "203.0.113.0/24", true],
    ["203.0.113.7/32", "203.0.113.0/24", true],
    ["203.0.113.128/25", "203.0.113.0/24", true],
    ["203.0.113.254/31", "203.0.113.0/24", true],
    ["203.0.114.0/24", "203.0.113.0/24", false],
    ["203.0.112.0/24", "203.0.113.0/24", false],
    ["203.0.114.0/23", "203.0.113.0/24", false],
    ["198.51.100.7/32", "203.0.113.0/24", false],
    ["11.0.0.0/8", "10.9.8.0/24", false],
    ["2001:db8:abcd::/48", "2001:db8:abcd::/48", true],
    ["2001:db8::/32", "2001:db8:abcd::/48", true],
    ["2001::/16", "2001:db8:abcd::/48", true],
    ["2001:db8:abcd:12::/64", "2001:db8:abcd::/48", true],
    ["2001:db8:abcd:1::1/128", "2001:db8:abcd::/48", true],
    ["2001:db8:abce::/48", "2001:db8:abcd::/48", false],
    ["2001:db9::/32", "2001:db8:abcd::/48", false],
    ["2001:db8:abce::1/128", "2001:db8:abcd::/48", false],
    ["::/16", "0:0:0::/48", true],
    ["::1/128", "0:0:0::/48", true],
    ["0:0:1::/48", "0:0:0::/48", false],
  ])("%s overlaps the Event prefix %s: %s", (cidr, prefix, expected) => {
    expect(cidrOverlapsPrefix(cidr, prefix)).toBe(expected);
  });

  it("never overlaps across address families", () => {
    expect(cidrOverlapsPrefix("::/16", "203.0.113.0/24")).toBe(false);
    expect(cidrOverlapsPrefix("203.0.113.0/24", "2001:db8:abcd::/48")).toBe(false);
  });

  it("is false for a prefix that is not in the form of an Event prefix", () => {
    for (const prefix of ["203.0.113.7/32", "203.0.113.0/25", "203.0.113.0", "203.0.0.0/16", "2001:db8::/32", ""]) {
      expect(cidrOverlapsPrefix("203.0.113.0/24", prefix), prefix).toBe(false);
    }
    expect(cidrOverlapsPrefix("203.0.113.0/24", null as unknown as string)).toBe(false);
  });

  it("is false for a CIDR that is not a normalised one, and takes a parsed CIDR", () => {
    expect(cidrOverlapsPrefix("203.0.113.7/24", PREFIX)).toBe(false);
    expect(cidrOverlapsPrefix("nope", PREFIX)).toBe(false);
    expect(cidrOverlapsPrefix(null as unknown as string, PREFIX)).toBe(false);
    expect(cidrOverlapsPrefix(parseCidr("203.0.113.7/32") as ParsedCidr, PREFIX)).toBe(true);
  });
});

describe("containment examples", () => {
  it("are deeply frozen", () => {
    expect(Object.isFrozen(EXAMPLE_CONTAINMENT)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_CONTAINMENT.target)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ALLOWLIST_ENTRY)).toBe(true);
  });

  it("describe an active one-hour block of one Actor of the documented Incident", () => {
    expect(EXAMPLE_CONTAINMENT.incident_id).toBe(EXAMPLE_INCIDENT.id);
    expect(EXAMPLE_CONTAINMENT.app_id).toBe(EXAMPLE_INCIDENT.app_id);
    expect(EXAMPLE_CONTAINMENT.environment).toBe(EXAMPLE_INCIDENT.environment);
    expect(EXAMPLE_CONTAINMENT.target.kind).toBe("actor");
    expect(EXAMPLE_CONTAINMENT.status).toBe("active");
    const lifetime = Date.parse(EXAMPLE_CONTAINMENT.expires_at) - Date.parse(EXAMPLE_CONTAINMENT.created_at);
    expect(lifetime).toBe(CONTAINMENT_DEFAULT_TTL * 1000);
    expect(Date.parse(EXAMPLE_CONTAINMENT.created_at)).toBeGreaterThanOrEqual(Date.parse(EXAMPLE_INCIDENT.created_at));
  });

  it("show an allowlist entry that does not overlap the documented Incident's network", () => {
    expect(parseCidr(EXAMPLE_ALLOWLIST_ENTRY.cidr)?.cidr).toBe(EXAMPLE_ALLOWLIST_ENTRY.cidr);
    expect(cidrOverlapsPrefix(EXAMPLE_ALLOWLIST_ENTRY.cidr, EXAMPLE_INCIDENT.ip_prefix as string)).toBe(false);
    expect(EXAMPLE_ALLOWLIST_ENTRY.created_by).toBe(EXAMPLE_CONTAINMENT.created_by);
  });
});

describe("AllowlistEntryResponseSchema", () => {
  it("wraps the one entry created, and round-trips it unchanged", () => {
    const response: AllowlistEntryResponse = AllowlistEntryResponseSchema.parse({ entry: EXAMPLE_ALLOWLIST_ENTRY });
    expect(response).toEqual({ entry: EXAMPLE_ALLOWLIST_ENTRY });
    expect(AllowlistEntryResponseSchema.parse(JSON.parse(JSON.stringify(response)))).toEqual(response);
    expect(ok(AllowlistEntryResponseSchema, {})).toBe(false);
    expect(ok(AllowlistEntryResponseSchema, { entry: { ...EXAMPLE_ALLOWLIST_ENTRY, cidr: "198.51.100.1/24" } })).toBe(
      false,
    );
    expect(ok(AllowlistEntryResponseSchema, { entries: [EXAMPLE_ALLOWLIST_ENTRY] })).toBe(false);
  });
});
