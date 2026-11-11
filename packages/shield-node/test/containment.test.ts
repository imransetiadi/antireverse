// Slice 09, contract P3: Shield enforces the Containments of the signed bundle before Rules. An actor block matches
// the request's actor hash, a prefix block its /24 or /48; an allowlisted address is never contained; a block ends
// at its own `expires_at` by Shield's clock, also when the API cannot be reached. The Event carries the actor hash
// (never the address) and the id of the Containment that blocked. Review focus 1–3.
import { setTimeout as sleep } from "node:timers/promises";
import {
  ACTOR_HASH_PATTERN,
  BLOCK_RESPONSE_BODY,
  type BundlePayload,
  BundlePayloadSchema,
  CONTAINMENT_LIMITS,
  EventBatchSchema,
  EXAMPLE_CANARIES,
  ID_PATTERNS,
  IP_PREFIX_PATTERN,
  type ShieldEvent,
  UNMATCHED_ROUTE,
} from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createShield, type Shield } from "../src/index.ts";
import {
  ACTOR_HASH,
  ALLOWLIST_MAX,
  audienceOf,
  BLOCKS_MAX,
  CONTAINMENT_ID,
  IP_PREFIX,
  importPublicKey,
  verifyBundle,
} from "../src/policy/verify.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, DAY_MS, EPOCH, type FakeApi, fakeApi, NOW, payload, rule, signed } from "./policy-helpers.ts";

type BundleBlock = NonNullable<BundlePayload["blocks"]>[number];

const signer = createSigner();
const HOUR_MS = 3_600_000;
/** Blocks of the tests expire one hour after NOW. */
const EXPIRES = NOW + HOUR_MS;

const ATTACKER = "203.0.113.7";
const NEIGHBOUR = "203.0.113.8"; // same /24, another Actor
const ELSEWHERE = "198.18.0.9"; // another network
const ATTACKER_V6 = "2001:db8:0:1::1";
/** The customer-held key the actor hash is keyed with (review F1). Synthetic. */
const ACTOR_KEY = "ck_test_7Hq2Vn9xLp4Rt6Wz8Bm3Kd5Fs1Gj0Yc2";
const ATTACKER_HASH = actorHash(ACTOR_KEY, ATTACKER) as string;
const V6_HASH = actorHash(ACTOR_KEY, ATTACKER_V6) as string;

const cnt = (n: number): string => `cnt_${n.toString(16).padStart(24, "0")}`;
const actorBlock = (n: number, ipHash: string, expiresAt = EXPIRES): BundleBlock => ({
  id: cnt(n),
  kind: "actor",
  ip_hash: ipHash,
  expires_at: new Date(expiresAt).toISOString(),
});
const prefixBlock = (n: number, ipPrefix: string, expiresAt = EXPIRES): BundleBlock => ({
  id: cnt(n),
  kind: "prefix",
  ip_prefix: ipPrefix,
  expires_at: new Date(expiresAt).toISOString(),
});

const ACTOR = actorBlock(0xa, ATTACKER_HASH);
const PREFIX = prefixBlock(0xb, "203.0.113.0/24");
const ADMIN_RULE = rule(0xa1, { path: "/api/admin/**", mode: "enforce" });

const open: Listening[] = [];
const shields: Shield[] = [];
let consoleLines: string[] = [];

beforeEach(() => {
  consoleLines = [];
  for (const method of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      consoleLines.push(args.map(String).join(" "));
    });
  }
});

afterEach(async () => {
  for (const listening of open.splice(0)) await listening.stop();
  for (const shield of shields.splice(0)) await shield.close();
  vi.restoreAllMocks();
});

interface Contained {
  shield: Shield;
  api: FakeApi;
  warnings: string[];
  clock: { now: number };
  base: string;
  ran: Record<string, number>;
  /** Publishes a bundle (version 7 unless given, issued at the clock unless given) and refreshes. */
  publish(overrides: Partial<BundlePayload>): Promise<void>;
  /** A request from `address` (sent as `x-client`, which the test's `clientAddress` reads). */
  get(address: string | undefined, path?: string, headers?: Record<string, string>): ReturnType<typeof exchange>;
  /** Every Event sent so far, after `count` were recorded, parsed by the protocol. */
  events(count: number): Promise<ShieldEvent[]>;
  /** Every Event sent so far, as the JSON Shield wrote, unparsed. */
  raw(): Record<string, unknown>[];
  /** Everything that left the process towards the API, and every log line, as text. */
  leaked(): string;
}

/** A Shield in front of an Express application whose client address comes from the `x-client` header. */
async function contain(overrides: Partial<BundlePayload> = {}): Promise<Contained> {
  const api = fakeApi();
  const warnings: string[] = [];
  const clock = { now: NOW };
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    now: () => clock.now,
    actorKey: ACTOR_KEY,
    clientAddress: (req) => {
      const value = (req as { headers: Record<string, string | undefined> }).headers["x-client"];
      return value === "" ? undefined : value;
    },
    logger: { warn: (message) => void warnings.push(message) },
  });
  shields.push(shield);
  const ran: Record<string, number> = {};
  const app = express();
  app.disable("x-powered-by");
  app.use(shield.express());
  app.get("/api/data", (_req, res) => {
    ran.data = (ran.data ?? 0) + 1;
    res.json({ items: [1, 2, 3] });
  });
  app.get("/api/admin/reports", (_req, res) => {
    ran.admin = (ran.admin ?? 0) + 1;
    res.send("secret reports");
  });
  const listening = await listen(app);
  open.push(listening);

  const publish = async (given: Partial<BundlePayload>): Promise<void> => {
    api.publish(
      signed(signer, payload(KEY, { version: 7, issued_at: new Date(clock.now).toISOString(), rules: [], ...given })),
    );
    await shield.refreshPolicy();
  };
  await publish(overrides);
  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    warnings,
    clock,
    base: listening.base,
    ran,
    publish,
    get: (address, path = "/api/data", headers = {}) =>
      exchange(`${listening.base}${path}`, { headers: { ...headers, "x-client": address ?? "" } }),
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
    raw: () =>
      api.posts.flatMap((request) => (JSON.parse(request.body ?? "") as { events: Record<string, unknown>[] }).events),
    leaked: () =>
      [
        ...api.posts.map((request) => `${request.url} ${JSON.stringify(request.headers)} ${request.body ?? ""}`),
        ...api.gets.map((request) => `${request.url} ${JSON.stringify(request.headers)}`),
        ...warnings,
        ...consoleLines,
        shield.stats().lastPolicyError ?? "",
        shield.stats().lastError ?? "",
      ].join("\n"),
  };
}

describe("Shield's containment bounds are the protocol's", () => {
  it("identifier, hash and prefix patterns and both limits agree", () => {
    expect(CONTAINMENT_ID.source).toBe(ID_PATTERNS.cnt.source);
    expect(ACTOR_HASH.source).toBe(ACTOR_HASH_PATTERN.source);
    expect(IP_PREFIX.source).toBe(IP_PREFIX_PATTERN.source);
    expect(BLOCKS_MAX).toBe(CONTAINMENT_LIMITS.activePerAppEnv);
    expect(ALLOWLIST_MAX).toBe(CONTAINMENT_LIMITS.allowlistMax);
  });
});

describe("verifying the blocks and the allowlist of a bundle", () => {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("test key");
  const context = {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW + 1,
  };
  const verify = (overrides: Partial<BundlePayload> | Record<string, unknown>) =>
    verifyBundle(signed(signer, payload(KEY, overrides as Partial<BundlePayload>)), context);
  const many = (count: number): BundleBlock[] =>
    Array.from({ length: count }, (_, i) =>
      i % 2 === 0
        ? actorBlock(i, `iph_${i.toString(16).padStart(32, "0")}`)
        : prefixBlock(i, `10.${i >> 8}.${i & 255}.0/24`),
    );
  const cidrs = (count: number): string[] => Array.from({ length: count }, (_, i) => `100.${i}.0.0/16`);

  it("a bundle without the fields, as before slice 09, has no blocks and no allowlist", () => {
    const result = verify({});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.policy.blocksByHash.size).toBe(0);
    expect(result.policy.blocksByPrefix.size).toBe(0);
    expect(result.policy.allowlist).toEqual([]);
  });

  it("indexes actor blocks by hash and prefix blocks by prefix, with their expiry in milliseconds", () => {
    const result = verify({ blocks: [ACTOR, PREFIX], allowlist: ["198.51.100.0/24", "2001:db8::/32"] });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.policy.blocksByHash.get(ATTACKER_HASH)).toEqual({ id: ACTOR.id, expiresMs: EXPIRES });
    expect(result.policy.blocksByPrefix.get("203.0.113.0/24")).toEqual({ id: PREFIX.id, expiresMs: EXPIRES });
    expect(result.policy.allowlist.map((range) => range.cidr)).toEqual(["198.51.100.0/24", "2001:db8::/32"]);
  });

  it("of two blocks of the same target the later expiry stands", () => {
    const later = actorBlock(0xc, ATTACKER_HASH, EXPIRES + HOUR_MS);
    for (const blocks of [
      [ACTOR, later],
      [later, ACTOR],
    ]) {
      const result = verify({ blocks });
      expect(result.ok && result.policy.blocksByHash.get(ATTACKER_HASH)).toEqual({
        id: later.id,
        expiresMs: EXPIRES + HOUR_MS,
      });
    }
  });

  it(`accepts exactly ${CONTAINMENT_LIMITS.activePerAppEnv} blocks and ${CONTAINMENT_LIMITS.allowlistMax} CIDRs (valid protocol content)`, () => {
    const full = { blocks: many(BLOCKS_MAX), allowlist: cidrs(ALLOWLIST_MAX) };
    expect(BundlePayloadSchema.safeParse(payload(KEY, full)).success).toBe(true);
    const result = verify(full);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.policy.blocksByHash.size + result.policy.blocksByPrefix.size).toBe(BLOCKS_MAX);
    expect(result.policy.allowlist).toHaveLength(ALLOWLIST_MAX);
  });

  it("refuses one block or one CIDR more as invalid", () => {
    expect(verify({ blocks: many(BLOCKS_MAX + 1) })).toMatchObject({ ok: false, reason: "invalid" });
    expect(verify({ allowlist: cidrs(ALLOWLIST_MAX + 1) })).toMatchObject({ ok: false, reason: "invalid" });
  });

  const SECRET_HASH = "iph_5ec4e75ec4e75ec4e75ec4e75ec4e75e";
  it.each([
    ["blocks is not a list", { blocks: { 0: ACTOR } }],
    ["a block is not an object", { blocks: ["x"] }],
    ["the id is not a Containment id", { blocks: [{ ...ACTOR, id: "rul_000000000000000000000001" }] }],
    ["the kind is unknown", { blocks: [{ ...ACTOR, kind: "device" }] }],
    ["the hash is malformed", { blocks: [{ ...ACTOR, ip_hash: `${SECRET_HASH}0` }] }],
    ["the hash is upper case", { blocks: [{ ...ACTOR, ip_hash: SECRET_HASH.toUpperCase().replace("IPH", "iph") }] }],
    [
      "an actor block carries a prefix instead",
      { blocks: [{ id: ACTOR.id, kind: "actor", ip_prefix: "203.0.113.0/24", expires_at: ACTOR.expires_at }] },
    ],
    ["the prefix is a full address", { blocks: [{ ...PREFIX, ip_prefix: "203.0.113.77/32" }] }],
    ["the prefix has host bits", { blocks: [{ ...PREFIX, ip_prefix: "203.0.113.77/24" }] }],
    ["the prefix is a /64", { blocks: [{ ...PREFIX, ip_prefix: "2001:db8:0:1::/64" }] }],
    ["expires_at is not a time", { blocks: [{ ...ACTOR, expires_at: "tomorrow" }] }],
    ["expires_at is missing", { blocks: [{ id: ACTOR.id, kind: "actor", ip_hash: ATTACKER_HASH }] }],
    ["allowlist is not a list", { allowlist: "198.51.100.0/24" }],
    ["a CIDR is not a string", { allowlist: [24] }],
    ["a CIDR has host bits", { allowlist: ["203.0.113.77/24"] }],
    ["a CIDR is not canonical", { allowlist: ["2001:DB8::/32"] }],
    ["a CIDR is too wide", { allowlist: ["10.0.0.0/7"] }],
    ["a CIDR is a bare address", { allowlist: ["203.0.113.77"] }],
    ["a CIDR is IPv4-mapped", { allowlist: ["::ffff:10.0.0.0/104"] }],
  ])("refuses the bundle as invalid when %s, without repeating a value", (_name, overrides) => {
    const result = verify({ blocks: [ACTOR], ...overrides });
    expect(result).toMatchObject({ ok: false, reason: "invalid" });
    if (result.ok) return;
    for (const value of ["203.0.113", "2001:db8", "iph_", "5ec4e75e", "device", "tomorrow", "10.0.0.0", "198.51.100"]) {
      expect(result.detail).not.toContain(value);
    }
  });
});

describe("the Event of every request", () => {
  it("carries the actor hash of the client and containment_id null, as Shield wrote it", async () => {
    const shielded = await contain();
    await shielded.get(ATTACKER);
    await shielded.get(ATTACKER_V6);
    await shielded.get("::ffff:203.0.113.7");
    const events = await shielded.events(3);
    expect(events.map((event) => event.actor)).toEqual([
      { ip_prefix: "203.0.113.0/24", ip_hash: ATTACKER_HASH },
      { ip_prefix: "2001:db8:0::/48", ip_hash: V6_HASH },
      { ip_prefix: "203.0.113.0/24", ip_hash: ATTACKER_HASH },
    ]);
    // Written by Shield, not filled in by the protocol's defaults.
    for (const event of shielded.raw()) {
      expect(event.actor).toHaveProperty("ip_hash");
      expect(event.decision).toHaveProperty("containment_id", null);
    }
  });

  it("carries ip_hash null when the address is unknown", async () => {
    const shielded = await contain();
    await shielded.get(undefined);
    await shielded.get("not-an-address");
    const events = await shielded.events(2);
    expect(events.map((event) => event.actor)).toEqual([
      { ip_prefix: null, ip_hash: null },
      { ip_prefix: null, ip_hash: null },
    ]);
    for (const event of shielded.raw()) expect(event.actor).toHaveProperty("ip_hash", null);
  });

  it("never lets the full address leave: not in an Event, a request, a warning or a console line", async () => {
    const shielded = await contain({ blocks: [ACTOR, prefixBlock(0xd, "2001:db8:0::/48")] });
    await shielded.get(ATTACKER);
    await shielded.get(NEIGHBOUR);
    await shielded.get(ATTACKER_V6);
    await shielded.get("2001:db8:0:1:dead:beef:cafe:1");
    await shielded.events(4);
    expect(shielded.leaked()).toContain(ATTACKER_HASH);
    // Hashes are hex and could contain "cafe" by chance: they are removed before the check.
    const leaked = shielded.leaked().replace(/iph_[0-9a-f]{32}/g, "iph_");
    for (const value of [ATTACKER, NEIGHBOUR, "203.0.113.7", "2001:db8:0:1", "dead:beef", "cafe"]) {
      expect(leaked).not.toContain(value);
    }
  });
});

describe("an actor block", () => {
  it("blocks that client only: another address of the same /24 passes", async () => {
    const shielded = await contain({ blocks: [ACTOR] });
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    expect((await shielded.get(NEIGHBOUR)).status).toBe(200);
    expect((await shielded.get(ELSEWHERE)).status).toBe(200);
    expect(shielded.ran.data).toBe(2);
  });

  it("matches an IPv4-mapped client as its IPv4 address", async () => {
    const shielded = await contain({ blocks: [ACTOR] });
    expect((await shielded.get("::ffff:203.0.113.7")).status).toBe(403);
    expect((await shielded.get("::ffff:cb00:7107")).status).toBe(403);
    expect((await shielded.get("::ffff:203.0.113.8")).status).toBe(200);
  });

  it("matches every address of an IPv6 /64, and not the next /64", async () => {
    const shielded = await contain({ blocks: [actorBlock(0xe, V6_HASH)] });
    expect((await shielded.get("2001:db8:0:1::1")).status).toBe(403);
    expect((await shielded.get("2001:db8:0:1:ffff::9")).status).toBe(403);
    expect((await shielded.get("2001:db8:0:2::1")).status).toBe(200);
  });

  it("records decision block/enforce, rule_id null, the Containment id, and the unmatched route", async () => {
    const shielded = await contain({ blocks: [ACTOR] });
    await shielded.get(ATTACKER);
    await shielded.get(NEIGHBOUR);
    const [blocked, passed] = await shielded.events(2);
    expect(blocked?.decision).toEqual({
      action: "block",
      mode: "enforce",
      rule_id: null,
      policy_version: 7,
      containment_id: ACTOR.id,
      patch_id: null,
      patch_body: null,
      limit_rule_id: null,
    });
    expect(blocked?.request).toMatchObject({ method: "GET", route: UNMATCHED_ROUTE, status: 403 });
    expect(blocked?.actor).toEqual({ ip_prefix: "203.0.113.0/24", ip_hash: ATTACKER_HASH });
    expect(passed?.decision).toEqual({
      action: "allow",
      mode: "enforce",
      rule_id: null,
      policy_version: 7,
      containment_id: null,
      patch_id: null,
      patch_body: null,
      limit_rule_id: null,
    });
  });
});

describe("a prefix block", () => {
  it("blocks every client of the /24 and nothing outside it", async () => {
    const shielded = await contain({ blocks: [PREFIX] });
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    expect((await shielded.get(NEIGHBOUR)).status).toBe(403);
    expect((await shielded.get("::ffff:203.0.113.200")).status).toBe(403);
    expect((await shielded.get("203.0.114.7")).status).toBe(200);
    const events = await shielded.events(4);
    expect(events.map((event) => event.decision.containment_id)).toEqual([PREFIX.id, PREFIX.id, PREFIX.id, null]);
  });

  it("blocks every client of an IPv6 /48", async () => {
    const shielded = await contain({ blocks: [prefixBlock(0xf, "2001:db8:0::/48")] });
    expect((await shielded.get("2001:db8:0:1::1")).status).toBe(403);
    expect((await shielded.get("2001:db8:0:ffff::1")).status).toBe(403);
    expect((await shielded.get("2001:db8:1::1")).status).toBe(200);
  });
});

describe("the allowlist", () => {
  it("wins over an actor block and a prefix block", async () => {
    const shielded = await contain({ blocks: [ACTOR, PREFIX], allowlist: ["198.51.100.0/24", "203.0.113.0/28"] });
    expect((await shielded.get(ATTACKER)).status).toBe(200); // inside 203.0.113.0/28
    expect((await shielded.get(NEIGHBOUR)).status).toBe(200);
    expect((await shielded.get("203.0.113.16")).status).toBe(403); // outside the /28, inside the blocked /24
    const events = await shielded.events(3);
    expect(events.map((event) => event.decision.containment_id)).toEqual([null, null, PREFIX.id]);
  });

  it("an IPv4 CIDR covers an IPv4-mapped client", async () => {
    const shielded = await contain({ blocks: [ACTOR], allowlist: ["203.0.113.7/32"] });
    expect((await shielded.get("::ffff:203.0.113.7")).status).toBe(200);
  });

  it("an IPv6 CIDR covers an IPv6 client of a blocked /48", async () => {
    const shielded = await contain({
      blocks: [prefixBlock(0xf, "2001:db8:0::/48"), actorBlock(0xe, V6_HASH)],
      allowlist: ["2001:db8:0:1::/64"],
    });
    expect((await shielded.get("2001:db8:0:1::1")).status).toBe(200);
    expect((await shielded.get("2001:db8:0:2::1")).status).toBe(403);
  });

  it("does not let a Rule through: the allowlist exempts from Containments only", async () => {
    const shielded = await contain({ rules: [ADMIN_RULE], blocks: [ACTOR], allowlist: ["203.0.113.0/24"] });
    expect((await shielded.get(ATTACKER, "/api/admin/reports")).status).toBe(403);
    const [event] = await shielded.events(1);
    expect(event?.decision).toMatchObject({ rule_id: ADMIN_RULE.id, containment_id: null });
  });
});

describe("the block response", () => {
  it("is exactly the response of a Rule block, and the application never sees the request", async () => {
    const shielded = await contain({ rules: [ADMIN_RULE], blocks: [ACTOR] });
    const byRule = await shielded.get(NEIGHBOUR, "/api/admin/reports");
    const byContainment = await shielded.get(ATTACKER, "/api/data");
    expect(byRule.status).toBe(403);
    expect(byRule.body).toBe(BLOCK_RESPONSE_BODY);
    expect(byContainment).toEqual(byRule);
    expect(shielded.ran).toEqual({});
  });

  it("is decided before Rules: a request a Rule also blocks records the Containment, not the Rule", async () => {
    const shielded = await contain({ rules: [ADMIN_RULE], blocks: [ACTOR] });
    expect((await shielded.get(ATTACKER, "/api/admin/reports")).status).toBe(403);
    const [event] = await shielded.events(1);
    expect(event?.decision).toEqual({
      action: "block",
      mode: "enforce",
      rule_id: null,
      policy_version: 7,
      containment_id: ACTOR.id,
      patch_id: null,
      patch_body: null,
      limit_rule_id: null,
    });
    expect(event?.request.route).toBe(UNMATCHED_ROUTE);
  });

  it("still carries the Canary signals of the request", async () => {
    const decoy = EXAMPLE_CANARIES[0];
    if (decoy === undefined || decoy.kind !== "key") throw new Error("the first example Canary is a key");
    const shielded = await contain({ blocks: [ACTOR], canaries: [...EXAMPLE_CANARIES] });
    expect((await shielded.get(ATTACKER, "/api/data", { "x-api-key": decoy.value })).status).toBe(403);
    const [event] = await shielded.events(1);
    expect(event?.signals).toEqual([{ id: `canary.touched:${decoy.id}`, confidence: 1 }]);
    expect(event?.decision.containment_id).toBe(ACTOR.id);
  });
});

describe("expiry by Shield's clock", () => {
  it("blocks before expires_at and lets the client through from expires_at on", async () => {
    const shielded = await contain({ blocks: [ACTOR, prefixBlock(0xb, "198.18.0.0/24", EXPIRES + HOUR_MS)] });
    shielded.clock.now = EXPIRES - 1;
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    shielded.clock.now = EXPIRES;
    expect((await shielded.get(ATTACKER)).status).toBe(200);
    // Each entry has its own expiry.
    expect((await shielded.get(ELSEWHERE)).status).toBe(403);
    shielded.clock.now = EXPIRES + HOUR_MS + 1;
    expect((await shielded.get(ELSEWHERE)).status).toBe(200);
  });

  it("a block already expired when the bundle arrives is never enforced", async () => {
    const shielded = await contain({ blocks: [actorBlock(0xa, ATTACKER_HASH, NOW - 1)] });
    expect(shielded.shield.stats().lastPolicyError).toBeNull();
    expect((await shielded.get(ATTACKER)).status).toBe(200);
  });

  it("offline: with the API unreachable the applied blocks are enforced until each one's expiry, then stop", async () => {
    const shielded = await contain({ blocks: [ACTOR] });
    shielded.api.policyAnswer(new Error("connect ECONNREFUSED"));
    shielded.clock.now = NOW + HOUR_MS / 2;
    await shielded.shield.refreshPolicy();
    expect(shielded.shield.stats().lastPolicyError).not.toBeNull();
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    shielded.clock.now = EXPIRES + 1;
    await shielded.shield.refreshPolicy();
    expect(shielded.shield.stats().lastPolicyError).not.toBeNull();
    expect((await shielded.get(ATTACKER)).status).toBe(200);
  });
});

describe("a new issue of the bundle", () => {
  it("lifting: a later issue of the same version without the block lets the client through", async () => {
    const shielded = await contain({ blocks: [ACTOR] });
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    shielded.clock.now = NOW + 1_000;
    await shielded.publish({ blocks: [] });
    expect(shielded.shield.stats().lastPolicyError).toBeNull();
    expect((await shielded.get(ATTACKER)).status).toBe(200);
  });

  it("a replay of an older issue of the same version can neither drop nor resurrect a block", async () => {
    const lifted = actorBlock(0x1, actorHash(ACTOR_KEY, ELSEWHERE) as string);
    const shielded = await contain({ blocks: [lifted], issued_at: new Date(NOW).toISOString() });
    shielded.clock.now = NOW + 5_000;
    await shielded.publish({ blocks: [ACTOR], issued_at: new Date(NOW + 5_000).toISOString() });
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    expect((await shielded.get(ELSEWHERE)).status).toBe(200);

    // The issue of NOW again (it carried the lifted block and not ACTOR): refused, nothing changes.
    await shielded.publish({ blocks: [lifted], issued_at: new Date(NOW).toISOString() });
    expect(shielded.shield.stats().lastPolicyError).toMatch(/^Policy refused \(version\)/);
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    expect((await shielded.get(ELSEWHERE)).status).toBe(200);
    // An older version without blocks: refused as well.
    await shielded.publish({ version: 6, blocks: [], issued_at: new Date(NOW + 9_000).toISOString() });
    expect(shielded.shield.stats().lastPolicyError).toMatch(/^Policy refused \(version\)/);
    expect((await shielded.get(ATTACKER)).status).toBe(403);
  });

  it("a bundle with a malformed block is refused; the applied blocks and allowlist stay", async () => {
    const shielded = await contain({ blocks: [ACTOR], allowlist: ["203.0.113.8/32"] });
    shielded.clock.now = NOW + 1_000;
    await shielded.publish({ blocks: [prefixBlock(0xb, "203.0.113.7/32")] });
    expect(shielded.shield.stats().lastPolicyError).toMatch(/^Policy refused \(invalid\)/);
    expect(shielded.shield.stats().lastPolicyError).not.toContain("203.0.113");
    await shielded.publish({ blocks: [PREFIX], allowlist: ["203.0.113.8/24"] });
    expect(shielded.shield.stats().lastPolicyError).toMatch(/^Policy refused \(invalid\)/);
    expect((await shielded.get(ATTACKER)).status).toBe(403);
    expect((await shielded.get(NEIGHBOUR)).status).toBe(200);
  });
});

describe("failing open", () => {
  it("a clientAddress that throws gives no Containment: Rules still apply and the request proceeds", async () => {
    const api = fakeApi();
    let throwing = true;
    const shield = createShield({
      key: KEY,
      endpoint: "http://api.test",
      transport: api.transport,
      policyPublicKey: signer.publicKey,
      policyPollIntervalMs: 3_600_000,
      flushIntervalMs: 3_600_000,
      now: () => NOW,
      clientAddress: () => {
        if (throwing) throw new Error("boom");
        return ATTACKER;
      },
      logger: { warn: () => {} },
    });
    shields.push(shield);
    api.publish(signed(signer, payload(KEY, { version: 7, rules: [ADMIN_RULE], blocks: [PREFIX] })));
    await shield.refreshPolicy();
    const app = express();
    app.use(shield.express());
    app.get("/api/data", (_req, res) => void res.send("ok"));
    app.get("/api/admin/x", (_req, res) => void res.send("no"));
    const listening = await listen(app);
    open.push(listening);
    expect((await exchange(`${listening.base}/api/data`)).status).toBe(200);
    expect((await exchange(`${listening.base}/api/admin/x`)).status).toBe(403);
    expect(shield.stats().internalErrors).toBe(2);
    throwing = false;
    expect((await exchange(`${listening.base}/api/data`)).status).toBe(403);
  });

  it("a clock that returns nonsense while a block matches lets the request proceed", async () => {
    const shielded = await contain({ blocks: [ACTOR] });
    const before = shielded.shield.stats().internalErrors;
    shielded.clock.now = Number.NaN;
    expect((await shielded.get(ATTACKER)).status).toBe(200);
    expect(shielded.shield.stats().internalErrors).toBeGreaterThanOrEqual(before);
  });
});

describe("the bundle size bound", () => {
  it("50 Rules, 100 Canaries, 150 blocks and 100 CIDRs fit and are applied", () => {
    const publicKey = importPublicKey(signer.publicKey);
    if (publicKey === null) throw new Error("test key");
    const full = payload(KEY, {
      rules: Array.from({ length: 50 }, (_, i) => rule(i, { path: `/api/section-${i}/**` })),
      blocks: Array.from({ length: BLOCKS_MAX }, (_, i) => actorBlock(i, `iph_${i.toString(16).padStart(32, "f")}`)),
      canaries: Array.from({ length: 100 }, (_, i) => ({
        id: `cny_${i.toString(16).padStart(24, "0")}`,
        kind: "key" as const,
        value: `ak_live_${i.toString(36).padStart(32, "Z")}`,
      })),
      // Long canonical IPv6 text: the largest allowlist.
      allowlist: Array.from(
        { length: ALLOWLIST_MAX },
        (_, i) => `2001:db8:ffff:ffff:ffff:ffff:ffff:${(i + 1).toString(16)}/128`,
      ),
      epoch: EPOCH,
      not_after: new Date(NOW + 7 * DAY_MS).toISOString(),
    });
    expect(BundlePayloadSchema.safeParse(full).success).toBe(true);
    expect(JSON.stringify(full).length).toBeLessThanOrEqual(65_536);
    const result = verifyBundle(signed(signer, full), {
      publicKey,
      audience: audienceOf(KEY),
      appliedVersion: 0,
      appliedEpoch: null,
      appliedIssuedAt: 0,
      now: NOW,
    });
    expect(result).toMatchObject({ ok: true });
    if (!result.ok) return;
    expect(result.policy.blocksByHash.size).toBe(BLOCKS_MAX);
    expect(result.policy.allowlist).toHaveLength(ALLOWLIST_MAX);
    expect(result.policy.canaryKeys.size).toBe(100);
  });
});
