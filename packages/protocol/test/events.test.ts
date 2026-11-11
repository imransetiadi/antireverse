import { METHODS } from "node:http";
import { describe, expect, it } from "vitest";
import {
  ENVIRONMENTS,
  type Environment,
  type EventBatch,
  EventBatchSchema,
  EXAMPLE_EVENT_BATCH,
  EXAMPLE_SHIELD_EVENT,
  EXAMPLE_STORED_EVENT,
  LIMITS,
  PROTOCOL_VERSION,
  type ShieldEvent,
  ShieldEventSchema,
  type StoredEvent,
  StoredEventSchema,
  UNMATCHED_ROUTE,
} from "../src/index.ts";

const withRequest = (patch: Record<string, unknown>) => ({
  ...EXAMPLE_SHIELD_EVENT,
  request: { ...EXAMPLE_SHIELD_EVENT.request, ...patch },
});
const withDecision = (patch: Record<string, unknown>) => ({
  ...EXAMPLE_SHIELD_EVENT,
  decision: { ...EXAMPLE_SHIELD_EVENT.decision, ...patch },
});
const accepts = (value: unknown): boolean => ShieldEventSchema.safeParse(value).success;
const batchOf = (count: number) => ({
  ...EXAMPLE_EVENT_BATCH,
  events: Array.from({ length: count }, () => EXAMPLE_SHIELD_EVENT),
});

describe("constants", () => {
  it("has the values of contract C1", () => {
    const environment: Environment = "production";
    expect(PROTOCOL_VERSION).toBe(1);
    expect(ENVIRONMENTS).toEqual([environment, "staging", "development"]);
    expect(UNMATCHED_ROUTE).toBe("(unmatched)");
    expect(LIMITS).toEqual({
      batchMax: 500,
      bodyBytesMax: 262_144,
      routeMax: 256,
      nameMax: 80,
      listDefault: 50,
      listMax: 200,
      streamsPerOrganization: 20,
    });
  });
});

describe("ShieldEventSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: ShieldEvent = ShieldEventSchema.parse(EXAMPLE_SHIELD_EVENT);
    expect(parsed).toEqual(EXAMPLE_SHIELD_EVENT);
    expect(parsed.decision).toEqual({
      action: "allow",
      mode: "monitor",
      rule_id: null,
      policy_version: 0,
      containment_id: null,
    });
    expect(parsed.actor).toEqual({ ip_prefix: "203.0.113.0/24", ip_hash: null });
    expect(parsed.attestation).toBeNull();
  });

  it("strips an unknown key at top level, inside request and inside actor", () => {
    const parsed = ShieldEventSchema.parse({
      ...EXAMPLE_SHIELD_EVENT,
      organization_id: "org_000000000000000000000000",
      headers: { authorization: "synthetic" },
      request: { ...EXAMPLE_SHIELD_EVENT.request, query: "token=synthetic", body: "synthetic" },
      actor: { ...EXAMPLE_SHIELD_EVENT.actor, ip: "203.0.113.77", user_agent: "synthetic" },
    });
    expect(parsed).toEqual(EXAMPLE_SHIELD_EVENT);
    expect(parsed).not.toHaveProperty("organization_id");
    expect(parsed).not.toHaveProperty("headers");
    expect(parsed.request).not.toHaveProperty("query");
    expect(parsed.request).not.toHaveProperty("body");
    expect(parsed.actor).not.toHaveProperty("ip");
    expect(parsed.actor).not.toHaveProperty("user_agent");
  });

  it("strips an unknown key inside decision and inside a signal", () => {
    const parsed = ShieldEventSchema.parse({
      ...withDecision({ reason: "synthetic" }),
      signals: [{ id: "sig.synthetic", confidence: 0.5, evidence: "synthetic" }],
    });
    expect(parsed.decision).not.toHaveProperty("reason");
    expect(parsed.signals).toEqual([{ id: "sig.synthetic", confidence: 0.5 }]);
  });

  it("limits route to 1..256 characters", () => {
    expect(accepts(withRequest({ route: "/".padEnd(256, "a") }))).toBe(true);
    expect(accepts(withRequest({ route: UNMATCHED_ROUTE }))).toBe(true);
    expect(accepts(withRequest({ route: "/".padEnd(257, "a") }))).toBe(false);
    expect(accepts(withRequest({ route: "" }))).toBe(false);
  });

  it("limits status to the integers 100..599", () => {
    expect(accepts(withRequest({ status: 100 }))).toBe(true);
    expect(accepts(withRequest({ status: 599 }))).toBe(true);
    expect(accepts(withRequest({ status: 99 }))).toBe(false);
    expect(accepts(withRequest({ status: 600 }))).toBe(false);
    expect(accepts(withRequest({ status: 200.5 }))).toBe(false);
    expect(accepts(withRequest({ status: "200" }))).toBe(false);
  });

  it("limits latency_ms to 0..600000", () => {
    expect(accepts(withRequest({ latency_ms: 0 }))).toBe(true);
    expect(accepts(withRequest({ latency_ms: 0.25 }))).toBe(true);
    expect(accepts(withRequest({ latency_ms: 600_000 }))).toBe(true);
    expect(accepts(withRequest({ latency_ms: -1 }))).toBe(false);
    expect(accepts(withRequest({ latency_ms: 600_000.5 }))).toBe(false);
    expect(accepts(withRequest({ latency_ms: Number.NaN }))).toBe(false);
  });

  it("limits method to 1..16 uppercase characters", () => {
    for (const method of METHODS) {
      expect(accepts(withRequest({ method })), method).toBe(true);
    }
    expect(accepts(withRequest({ method: "get" }))).toBe(false);
    expect(accepts(withRequest({ method: "" }))).toBe(false);
    expect(accepts(withRequest({ method: "A".repeat(17) }))).toBe(false);
    expect(accepts(withRequest({ method: "GET /x" }))).toBe(false);
  });

  it("requires event_id to be a UUID of version 7", () => {
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, event_id: "not-a-uuid" })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, event_id: "2b7d0f0e-6c1a-4f5b-9d3e-8a1c2b3d4e5f" })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, event_id: 7 })).toBe(false);
  });

  it("requires ts to be an ISO-8601 UTC datetime", () => {
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts: new Date(Date.UTC(2026, 0, 1)).toISOString() })).toBe(true);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts: "yesterday" })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts: "2026-11-10 08:15:30" })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts: "2026-11-10T08:15:30+07:00" })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, ts: 1_794_298_530_123 })).toBe(false);
  });

  it("rejects an unknown type and an unknown surface", () => {
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, type: "request.blocked" })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, surface: "web" })).toBe(false);
  });

  it("limits the Decision to the known actions and modes", () => {
    for (const action of ["allow", "monitor", "challenge", "throttle", "block", "deceive"]) {
      expect(accepts(withDecision({ action })), action).toBe(true);
    }
    expect(accepts(withDecision({ mode: "enforce", rule_id: "rule_synthetic", policy_version: 3 }))).toBe(true);
    expect(accepts(withDecision({ action: "drop" }))).toBe(false);
    expect(accepts(withDecision({ mode: "shadow" }))).toBe(false);
    expect(accepts(withDecision({ rule_id: undefined }))).toBe(false);
    expect(accepts(withDecision({ policy_version: -1 }))).toBe(false);
    expect(accepts(withDecision({ policy_version: 1.5 }))).toBe(false);
  });

  it("limits actor.ip_prefix to null or at most 64 characters", () => {
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, actor: { ip_prefix: null } })).toBe(true);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, actor: { ip_prefix: "2001:db8:abcd::/48" } })).toBe(true);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, actor: { ip_prefix: "1".repeat(65) } })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, actor: {} })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, actor: undefined })).toBe(false);
  });

  it("limits signals to 32 entries with an id of at most 64 characters and a confidence of 0..1", () => {
    const signal = { id: "sig.synthetic", confidence: 1 };
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, signals: Array.from({ length: 32 }, () => signal) })).toBe(true);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, signals: Array.from({ length: 33 }, () => signal) })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, signals: [{ id: "s".repeat(65), confidence: 1 }] })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, signals: [{ id: "sig.synthetic", confidence: 1.1 }] })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, signals: [{ id: "sig.synthetic", confidence: -0.1 }] })).toBe(false);
    expect(accepts({ ...EXAMPLE_SHIELD_EVENT, signals: undefined })).toBe(false);
  });
});

describe("ShieldEventSchema: actor.ip_hash and decision.containment_id (slice 09)", () => {
  const HASH = "iph_0123456789abcdef0123456789abcdef";
  const CONTAINMENT = "cnt_0123456789abcdef01234567";
  const withActor = (patch: Record<string, unknown>) => ({
    ...EXAMPLE_SHIELD_EVENT,
    actor: { ...EXAMPLE_SHIELD_EVENT.actor, ...patch },
  });
  /** An Event exactly as a Shield from before slice 09 sends it: neither key exists. */
  const older = () => {
    const { containment_id: _containment, ...decision } = EXAMPLE_SHIELD_EVENT.decision;
    const { ip_hash: _hash, ...actor } = EXAMPLE_SHIELD_EVENT.actor;
    return { ...EXAMPLE_SHIELD_EVENT, decision, actor };
  };

  it("still parses an older Shield's Event: absent means null", () => {
    expect(older().actor).not.toHaveProperty("ip_hash");
    expect(older().decision).not.toHaveProperty("containment_id");
    const parsed = ShieldEventSchema.parse(older());
    expect(parsed.actor).toEqual({ ip_prefix: "203.0.113.0/24", ip_hash: null });
    expect(parsed.decision.containment_id).toBeNull();
    expect(parsed).toEqual(EXAMPLE_SHIELD_EVENT);
    expect(ShieldEventSchema.parse(JSON.parse(JSON.stringify(older())))).toEqual(EXAMPLE_SHIELD_EVENT);
  });

  it("still parses an older Shield's batch and an older stored Event", () => {
    const batch = EventBatchSchema.parse({ ...EXAMPLE_EVENT_BATCH, events: [older(), older()] });
    expect(batch.events).toEqual([EXAMPLE_SHIELD_EVENT, EXAMPLE_SHIELD_EVENT]);
    const { organization_id, app_id, environment, received_at } = EXAMPLE_STORED_EVENT;
    const stored = StoredEventSchema.parse({ ...older(), organization_id, app_id, environment, received_at });
    expect(stored).toEqual(EXAMPLE_STORED_EVENT);
  });

  it("treats an explicit undefined as absent", () => {
    expect(ShieldEventSchema.parse(withActor({ ip_hash: undefined })).actor.ip_hash).toBeNull();
    expect(ShieldEventSchema.parse(withDecision({ containment_id: undefined })).decision.containment_id).toBeNull();
  });

  it("round-trips an Event blocked by a Containment, with its actor hash, through JSON", () => {
    const blocked: ShieldEvent = {
      ...EXAMPLE_SHIELD_EVENT,
      request: { ...EXAMPLE_SHIELD_EVENT.request, status: 403 },
      decision: { action: "block", mode: "enforce", rule_id: null, policy_version: 3, containment_id: CONTAINMENT },
      actor: { ip_prefix: "203.0.113.0/24", ip_hash: HASH },
    };
    expect(ShieldEventSchema.parse(blocked)).toEqual(blocked);
    expect(ShieldEventSchema.parse(JSON.parse(JSON.stringify(blocked)))).toEqual(blocked);
    const stored: StoredEvent = { ...EXAMPLE_STORED_EVENT, ...blocked };
    expect(StoredEventSchema.parse(JSON.parse(JSON.stringify(stored)))).toEqual(stored);
  });

  it("accepts an actor hash without a prefix and a prefix without an actor hash", () => {
    expect(accepts(withActor({ ip_prefix: null, ip_hash: HASH }))).toBe(true);
    expect(accepts(withActor({ ip_prefix: "2001:db8:abcd::/48", ip_hash: null }))).toBe(true);
    expect(accepts(withActor({ ip_prefix: null, ip_hash: null }))).toBe(true);
  });

  it.each([
    "iph_0123456789abcdef0123456789abcde",
    "iph_0123456789abcdef0123456789abcdef0",
    "iph_0123456789ABCDEF0123456789ABCDEF",
    "0123456789abcdef0123456789abcdef",
    "203.0.113.77",
    "2001:db8:abcd:12::1",
    "203.0.113.0/24",
    "",
  ])("rejects the actor hash %j: only iph_ and 32 hex characters may be stored", (value) => {
    expect(accepts(withActor({ ip_hash: value }))).toBe(false);
  });

  it("rejects an actor hash or a containment id that is not text", () => {
    expect(accepts(withActor({ ip_hash: 7 }))).toBe(false);
    expect(accepts(withActor({ ip_hash: { value: HASH } }))).toBe(false);
    expect(accepts(withDecision({ containment_id: 7 }))).toBe(false);
    expect(accepts(withDecision({ containment_id: [CONTAINMENT] }))).toBe(false);
  });

  it.each([
    "cnt_0123",
    "cnt_0123456789ABCDEF01234567",
    "cnt_0123456789abcdef012345678",
    "rul_0123456789abcdef01234567",
    "containment",
    "",
  ])("rejects the containment id %j", (value) => {
    expect(accepts(withDecision({ containment_id: value }))).toBe(false);
  });

  it("accepts a containment id and null", () => {
    expect(accepts(withDecision({ action: "block", mode: "enforce", containment_id: CONTAINMENT }))).toBe(true);
    expect(accepts(withDecision({ containment_id: null }))).toBe(true);
  });
});

describe("ShieldEventSchema: attestation (slice 03)", () => {
  /** An Event exactly as a Shield from before slice 03 sends it: no attestation key. */
  const older = () => {
    const { attestation: _attestation, ...rest } = EXAMPLE_SHIELD_EVENT;
    return rest;
  };
  const withAttestation = (attestation: unknown) => ({ ...EXAMPLE_SHIELD_EVENT, attestation });

  it("documents an Event without a token: attestation null", () => {
    expect(EXAMPLE_SHIELD_EVENT.attestation).toBeNull();
    expect(EXAMPLE_STORED_EVENT.attestation).toBeNull();
  });

  it("still parses an older Shield's Event, batch and stored Event: absent means null", () => {
    expect(older()).not.toHaveProperty("attestation");
    expect(ShieldEventSchema.parse(older())).toEqual(EXAMPLE_SHIELD_EVENT);
    expect(ShieldEventSchema.parse(withAttestation(undefined)).attestation).toBeNull();
    expect(EventBatchSchema.parse({ ...EXAMPLE_EVENT_BATCH, events: [older()] }).events).toEqual([
      EXAMPLE_SHIELD_EVENT,
    ]);
    const { organization_id, app_id, environment, received_at } = EXAMPLE_STORED_EVENT;
    expect(StoredEventSchema.parse({ ...older(), organization_id, app_id, environment, received_at })).toEqual(
      EXAMPLE_STORED_EVENT,
    );
  });

  it("round-trips every status through JSON", () => {
    for (const attestation of [
      { status: "valid", verdict: "trusted", risk: 5 },
      { status: "valid", verdict: "hostile", risk: 100 },
      { status: "missing", verdict: null, risk: null },
      { status: "invalid", verdict: null, risk: null },
      { status: "expired", verdict: null, risk: null },
    ] as const) {
      const event: ShieldEvent = { ...EXAMPLE_SHIELD_EVENT, attestation };
      expect(ShieldEventSchema.parse(JSON.parse(JSON.stringify(event)))).toEqual(event);
      const stored: StoredEvent = { ...EXAMPLE_STORED_EVENT, attestation };
      expect(StoredEventSchema.parse(JSON.parse(JSON.stringify(stored)))).toEqual(stored);
    }
  });

  it("rejects an inconsistent or malformed attestation", () => {
    expect(accepts(withAttestation({ status: "valid", verdict: null, risk: null }))).toBe(false);
    expect(accepts(withAttestation({ status: "missing", verdict: "trusted", risk: 5 }))).toBe(false);
    expect(accepts(withAttestation({ status: "forged", verdict: null, risk: null }))).toBe(false);
    expect(accepts(withAttestation("valid"))).toBe(false);
    expect(accepts(withAttestation({}))).toBe(false);
  });

  it("never carries the token or the claims (privacy allowlist)", () => {
    const parsed = ShieldEventSchema.parse(
      withAttestation({ status: "valid", verdict: "suspect", risk: 70, token: "a.b.c", sub: "dev_0", jti: "0" }),
    );
    expect(parsed.attestation).toEqual({ status: "valid", verdict: "suspect", risk: 70 });
  });
});

describe("EventBatchSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: EventBatch = EventBatchSchema.parse(EXAMPLE_EVENT_BATCH);
    expect(parsed).toEqual(EXAMPLE_EVENT_BATCH);
    expect(parsed.protocol).toBe(PROTOCOL_VERSION);
  });

  it("accepts 1 to 500 Events and rejects 0 and 501", () => {
    expect(EventBatchSchema.safeParse(batchOf(1)).success).toBe(true);
    expect(EventBatchSchema.safeParse(batchOf(500)).success).toBe(true);
    expect(EventBatchSchema.safeParse(batchOf(0)).success).toBe(false);
    expect(EventBatchSchema.safeParse(batchOf(501)).success).toBe(false);
  });

  it("rejects another protocol version", () => {
    expect(EventBatchSchema.safeParse({ ...EXAMPLE_EVENT_BATCH, protocol: 2 }).success).toBe(false);
    expect(EventBatchSchema.safeParse({ ...EXAMPLE_EVENT_BATCH, protocol: "1" }).success).toBe(false);
  });

  it("limits the sdk name and version to 32 characters", () => {
    const long = "v".repeat(33);
    expect(EventBatchSchema.safeParse({ ...EXAMPLE_EVENT_BATCH, sdk: { name: long, version: "0" } }).success).toBe(
      false,
    );
    expect(EventBatchSchema.safeParse({ ...EXAMPLE_EVENT_BATCH, sdk: { name: "x", version: long } }).success).toBe(
      false,
    );
  });

  it("strips tenancy supplied by the client from the batch and from each Event", () => {
    const tenancy = { organization_id: "org_ffffffffffffffffffffffff", app_id: "app_ffffffffffffffffffffffff" };
    const parsed = EventBatchSchema.parse({
      ...EXAMPLE_EVENT_BATCH,
      ...tenancy,
      environment: "production",
      events: [{ ...EXAMPLE_SHIELD_EVENT, ...tenancy, environment: "production" }],
    });
    expect(parsed).toEqual({ ...EXAMPLE_EVENT_BATCH, events: [EXAMPLE_SHIELD_EVENT] });
  });
});

describe("StoredEventSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: StoredEvent = StoredEventSchema.parse(EXAMPLE_STORED_EVENT);
    expect(parsed).toEqual(EXAMPLE_STORED_EVENT);
    expect(parsed.organization_id).toMatch(/^org_[0-9a-f]{24}$/);
    expect(parsed.app_id).toMatch(/^app_[0-9a-f]{24}$/);
    expect(ENVIRONMENTS).toContain(parsed.environment);
  });

  it("requires Organization, App, Environment and the time of receipt", () => {
    for (const key of ["organization_id", "app_id", "environment", "received_at"]) {
      const { [key]: _removed, ...rest } = EXAMPLE_STORED_EVENT as Record<string, unknown>;
      expect(StoredEventSchema.safeParse(rest).success, key).toBe(false);
    }
    expect(StoredEventSchema.safeParse({ ...EXAMPLE_STORED_EVENT, environment: "qa" }).success).toBe(false);
    expect(StoredEventSchema.safeParse({ ...EXAMPLE_STORED_EVENT, organization_id: "acme" }).success).toBe(false);
    expect(
      StoredEventSchema.safeParse({ ...EXAMPLE_STORED_EVENT, app_id: "org_000000000000000000000000" }).success,
    ).toBe(false);
    expect(StoredEventSchema.safeParse({ ...EXAMPLE_STORED_EVENT, received_at: "now" }).success).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = StoredEventSchema.parse({ ...EXAMPLE_STORED_EVENT, payload: { raw: "synthetic" } });
    expect(parsed).toEqual(EXAMPLE_STORED_EVENT);
  });
});

describe("ShieldEventSchema: signature (slice 04)", () => {
  /** An Event exactly as a Shield from before slice 04 sends it: no signature key. */
  const older = () => {
    const { signature: _signature, ...rest } = EXAMPLE_SHIELD_EVENT;
    return rest;
  };
  const withSignature = (signature: unknown) => ({ ...EXAMPLE_SHIELD_EVENT, signature });

  it("documents an Event without a signature report: signature null", () => {
    expect(EXAMPLE_SHIELD_EVENT.signature).toBeNull();
    expect(EXAMPLE_STORED_EVENT.signature).toBeNull();
    expect(Object.keys(EXAMPLE_SHIELD_EVENT).at(-1)).toBe("signature");
  });

  it("still parses an older Shield's Event, batch and stored Event: absent means null", () => {
    expect(older()).not.toHaveProperty("signature");
    expect(ShieldEventSchema.parse(older())).toEqual(EXAMPLE_SHIELD_EVENT);
    expect(ShieldEventSchema.parse(withSignature(undefined)).signature).toBeNull();
    expect(EventBatchSchema.parse({ ...EXAMPLE_EVENT_BATCH, events: [older()] }).events).toEqual([
      EXAMPLE_SHIELD_EVENT,
    ]);
    const { organization_id, app_id, environment, received_at } = EXAMPLE_STORED_EVENT;
    expect(StoredEventSchema.parse({ ...older(), organization_id, app_id, environment, received_at })).toEqual(
      EXAMPLE_STORED_EVENT,
    );
  });

  it("round-trips a signature report through JSON", () => {
    for (const signature of [
      { status: "valid", body: "checked" },
      { status: "valid", body: "none" },
      { status: "valid", body: "unchecked" },
      { status: "invalid", body: "mismatch" },
      { status: "missing", body: null },
      { status: "stale", body: "none" },
      { status: "replayed", body: "checked" },
    ] as const) {
      const event: ShieldEvent = { ...EXAMPLE_SHIELD_EVENT, signature };
      expect(ShieldEventSchema.parse(JSON.parse(JSON.stringify(event)))).toEqual(event);
      const stored: StoredEvent = { ...EXAMPLE_STORED_EVENT, signature };
      expect(StoredEventSchema.parse(JSON.parse(JSON.stringify(stored)))).toEqual(stored);
    }
  });

  it("rejects a malformed signature report", () => {
    expect(accepts(withSignature({ status: "forged", body: null }))).toBe(false);
    expect(accepts(withSignature({ status: "valid", body: "mismatch" }))).toBe(false);
    expect(accepts(withSignature("valid"))).toBe(false);
    expect(accepts(withSignature({}))).toBe(false);
  });

  it("never carries the signature header, the nonce or the body hash (privacy allowlist)", () => {
    const parsed = ShieldEventSchema.parse(
      withSignature({ status: "valid", body: "checked", header: "v1,t=1,n=x,s=y", n: "x", content_sha256: "h" }),
    );
    expect(parsed.signature).toEqual({ status: "valid", body: "checked" });
  });
});
