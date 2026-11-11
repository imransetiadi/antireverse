// The Policy path through the public API of Shield: createShield, refreshPolicy, decide, stats.
// Review focus 2 (a bundle that should not be trusted) and 3 (the API unreachable for days).
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createShield, type Shield, type ShieldConfig } from "../src/index.ts";
import {
  createSigner,
  DAY_MS,
  type FakeApi,
  fakeApi,
  flip,
  NEW_EPOCH,
  NOW,
  payload,
  rule,
  type Signer,
  signed,
} from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const OTHER_KEY = generateKey("shield", "development").key;
const signer = createSigner();
const stranger = createSigner();

const ADMIN_REQUEST = { method: "GET", path: "/api/admin/reports" };

interface Harness {
  shield: Shield;
  api: FakeApi;
  warnings: string[];
  /** Publishes a bundle signed by `by` and has Shield fetch it now. */
  publish(bundle: Parameters<typeof payload>[1], by?: Signer): Promise<void>;
}

function harness(config: Partial<ShieldConfig> = {}): Harness {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    logger: { warn: (message) => void warnings.push(message) },
    now: () => Date.now(),
    ...config,
  });
  return {
    shield,
    api,
    warnings,
    async publish(bundle, by = signer) {
      api.publish(signed(by, payload(KEY, bundle)));
      await shield.refreshPolicy();
    },
  };
}

const unhandled: unknown[] = [];
const onUnhandled = (reason: unknown): void => {
  unhandled.push(reason);
};

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date(NOW));
  vi.spyOn(Math, "random").mockReturnValue(0);
  unhandled.length = 0;
  process.on("unhandledRejection", onUnhandled);
});

afterEach(async () => {
  await vi.advanceTimersByTimeAsync(0);
  process.off("unhandledRejection", onUnhandled);
  vi.restoreAllMocks();
  vi.useRealTimers();
  expect(unhandled).toEqual([]);
});

describe("Shield with a policyPublicKey", () => {
  it("starts with the built-in Policy and reports it in stats()", async () => {
    const { shield, warnings } = harness();
    expect(shield.stats()).toEqual({
      buffered: 0,
      sent: 0,
      dropped: 0,
      failedBatches: 0,
      internalErrors: 0,
      disabledReason: null,
      lastError: null,
      policyVersion: 0,
      policyStale: false,
      policyRules: 0,
      lastPolicyError: null,
      actorHashing: false,
      inventory: "pending",
    });
    expect(shield.decide(ADMIN_REQUEST)).toEqual({ action: "allow", mode: "monitor", ruleId: null, policyVersion: 0 });
    expect(warnings).toEqual([]);
    await shield.close();
  });

  it("fetches the bundle shortly after creation, without being asked, and applies it", async () => {
    const { shield, api } = harness();
    api.publish(
      signed(signer, payload(KEY, { version: 4, rules: [rule(1), rule(2, { path: "/x", mode: "monitor" })] })),
    );
    expect(api.gets).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(100);
    expect(api.gets).toHaveLength(1);
    expect(api.gets[0]).toMatchObject({ method: "GET", url: "http://api.test/v1/policy-bundle" });
    expect(api.gets[0]?.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(shield.stats()).toMatchObject({
      policyVersion: 4,
      policyRules: 2,
      policyStale: false,
      lastPolicyError: null,
    });
    expect(shield.decide(ADMIN_REQUEST)).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: rule(1).id,
      policyVersion: 4,
    });
    expect(shield.decide({ method: "GET", path: "/x" })).toMatchObject({ action: "block", mode: "monitor" });
    expect(shield.decide({ method: "GET", path: "/y" })).toEqual({
      action: "allow",
      mode: "enforce",
      ruleId: null,
      policyVersion: 4,
    });
    await shield.close();
  });

  it("refreshPolicy() fetches now; a publish and a rollback are applied by the next fetch", async () => {
    const { shield, api, publish } = harness({ policyPollIntervalMs: 250 });
    await publish({ version: 1, rules: [] });
    expect(shield.stats().policyVersion).toBe(1);
    expect(shield.decide(ADMIN_REQUEST).action).toBe("allow");

    api.publish(signed(signer, payload(KEY, { version: 2 })));
    await vi.advanceTimersByTimeAsync(250); // the poll, at the configured interval
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1 });
    expect(shield.decide(ADMIN_REQUEST).action).toBe("block");

    await publish({ version: 3, rules: [] }); // a rollback is a new version with the earlier Rules
    expect(shield.stats()).toMatchObject({ policyVersion: 3, policyRules: 0 });
    expect(shield.decide(ADMIN_REQUEST)).toMatchObject({ action: "allow", mode: "enforce", policyVersion: 3 });
    await shield.close();
  });

  it("decide stays synchronous and does no I/O: it never waits for a fetch that is in flight", async () => {
    const { shield, api, publish } = harness();
    await publish({ version: 1 });
    api.policyAnswer(() => new Promise(() => {})); // the API accepts the request and never answers
    const pending = shield.refreshPolicy();
    const gets = api.gets.length;
    for (let i = 0; i < 1_000; i++) {
      const decision: unknown = shield.decide(ADMIN_REQUEST);
      expect(decision).not.toBeInstanceOf(Promise);
      expect(decision).toMatchObject({ action: "block", policyVersion: 1 });
    }
    expect(api.gets).toHaveLength(gets);
    expect(api.posts).toHaveLength(0);
    void pending;
    await shield.close();
  });

  it("close() stops the polling, and refreshPolicy() does nothing afterwards", async () => {
    const { shield, api } = harness();
    api.publish(signed(signer, payload(KEY)));
    // The poller's first fetch and the inventory's 60 s fallback (slice 19); close() clears both.
    expect(vi.getTimerCount()).toBe(2);
    await shield.close();
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(60_000);
    await expect(shield.refreshPolicy()).resolves.toBeUndefined();
    expect(api.gets).toHaveLength(0);
  });
});

describe("Shield refuses a bundle that should not be trusted and keeps the last valid Policy", () => {
  const good = signed(signer, payload(KEY, { version: 9, rules: [] }));
  const refusals: [name: string, body: () => string, reason: string][] = [
    ["one flipped byte in the bundle", () => JSON.stringify({ ...good, bundle: flip(good.bundle) }), "signature"],
    [
      "one flipped byte in the signature",
      () => JSON.stringify({ ...good, signature: flip(good.signature) }),
      "signature",
    ],
    [
      "a valid signature made by another key",
      () => JSON.stringify(signed(stranger, payload(KEY, { version: 9, rules: [] }))),
      "signature",
    ],
    [
      "the bundle of another Shield key",
      () => JSON.stringify(signed(signer, payload(OTHER_KEY, { version: 9, rules: [] }))),
      "audience",
    ],
    ["an older version", () => JSON.stringify(signed(signer, payload(KEY, { version: 1, rules: [] }))), "version"],
    [
      "a bundle that expired before it arrived",
      () =>
        JSON.stringify(
          signed(signer, payload(KEY, { version: 9, rules: [], issued_at: new Date(NOW - 8 * DAY_MS).toISOString() })),
        ),
      "expired",
    ],
    [
      "51 Rules",
      () =>
        JSON.stringify(
          signed(
            signer,
            payload(KEY, { version: 9, rules: Array.from({ length: 51 }, (_, i) => rule(i, { mode: "monitor" })) }),
          ),
        ),
      "invalid",
    ],
    [
      "200 Rules",
      () =>
        JSON.stringify(
          signed(
            signer,
            payload(KEY, { version: 9, rules: Array.from({ length: 200 }, (_, i) => rule(i, { mode: "monitor" })) }),
          ),
        ),
      "invalid",
    ],
    [
      "a Rule with a malformed pattern",
      () => JSON.stringify(signed(signer, payload(KEY, { version: 9, rules: [rule(1, { path: "/api/**/admin" })] }))),
      "invalid",
    ],
    ["a response that is not JSON", () => "{not json", "invalid"],
    ["a signed bundle that is not JSON", () => JSON.stringify(signed(signer, "{not json")), "invalid"],
    ["a body of 1 MB", () => JSON.stringify({ ...good, padding: "x".repeat(1_048_576) }), "invalid"],
    [
      "another bundle format",
      () => JSON.stringify(signed(signer, { ...payload(KEY, { version: 9, rules: [] }), format: 2 })),
      "format",
    ],
  ];

  it.each(refusals)("%s", async (_name, body, reason) => {
    const { shield, api, warnings, publish } = harness();
    await publish({ version: 2 });
    expect(shield.decide(ADMIN_REQUEST).action).toBe("block");

    api.publish(body());
    await shield.refreshPolicy();

    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1, policyStale: false });
    expect(shield.stats().lastPolicyError).toContain(`Policy refused (${reason})`);
    expect(shield.decide(ADMIN_REQUEST)).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: rule(1).id,
      policyVersion: 2,
    });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^\[shield\] /);

    // The same refusal again: no second line.
    await shield.refreshPolicy();
    expect(warnings).toHaveLength(1);
    for (const line of [...warnings, shield.stats().lastPolicyError ?? ""]) {
      expect(line).not.toContain(KEY);
      expect(line).not.toContain(signer.publicKey);
      expect(line).not.toContain(stranger.publicKey);
    }
    await shield.close();
  });

  it("reports each cause with its own lastPolicyError", async () => {
    const { shield, api, publish } = harness();
    await publish({ version: 2 });
    const distinct = [
      "one flipped byte in the bundle",
      "the bundle of another Shield key",
      "an older version",
      "a bundle that expired before it arrived",
      "51 Rules",
      "a Rule with a malformed pattern",
      "a response that is not JSON",
      "a body of 1 MB",
      "another bundle format",
    ];
    const seen = new Set<string>();
    for (const name of distinct) {
      const entry = refusals.find((candidate) => candidate[0] === name);
      if (entry === undefined) throw new Error(`no refusal named ${name}`);
      api.publish(entry[1]());
      await shield.refreshPolicy();
      seen.add(String(shield.stats().lastPolicyError));
      expect(shield.stats().policyVersion).toBe(2);
    }
    expect(seen.size).toBe(distinct.length);
    await shield.close();
  });

  it("applies a good bundle after a refused one and clears lastPolicyError", async () => {
    const { shield, api, publish } = harness();
    await publish({ version: 2 });
    api.publish("{not json");
    await shield.refreshPolicy();
    expect(shield.stats().lastPolicyError).not.toBeNull();
    await publish({ version: 3, rules: [] });
    expect(shield.stats()).toMatchObject({ policyVersion: 3, policyRules: 0, lastPolicyError: null });
    await shield.close();
  });

  it("refuses every bundle when the configured key is another key than the API's", async () => {
    const { shield, publish, warnings } = harness({ policyPublicKey: stranger.publicKey });
    await publish({ version: 2 });
    expect(shield.stats()).toMatchObject({ policyVersion: 0, policyRules: 0 });
    expect(shield.stats().lastPolicyError).toContain("Policy refused (signature)");
    expect(shield.decide(ADMIN_REQUEST).action).toBe("allow");
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/policyPublicKey/);
    await shield.close();
  });
});

describe("Shield and the expiry of a bundle", () => {
  it("a bundle of the applied version that was issued anew carries a later not_after", async () => {
    const { shield, publish } = harness();
    await publish({ version: 2 });
    vi.setSystemTime(new Date(NOW + 6 * DAY_MS));
    await publish({ version: 2, issued_at: new Date(NOW + 6 * DAY_MS).toISOString() });
    expect(shield.stats().lastPolicyError).toBeNull();
    vi.setSystemTime(new Date(NOW + 7 * DAY_MS + 1)); // the first bundle would be stale now
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyStale: false });
    vi.setSystemTime(new Date(NOW + 13 * DAY_MS + 1));
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyStale: true });
    await shield.close();
  });

  it("is stale once not_after has passed, and still applies its Rules", async () => {
    let clock = NOW;
    const { shield, api, publish } = harness({ now: () => clock });
    await publish({ version: 2 });
    api.policyAnswer(new Error("connect ECONNREFUSED"));
    clock = NOW + 7 * DAY_MS;
    expect(shield.stats().policyStale).toBe(false);
    clock = NOW + 7 * DAY_MS + 1;
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1, policyStale: true });
    expect(shield.decide(ADMIN_REQUEST)).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: rule(1).id,
      policyVersion: 2,
    });
    await shield.close();
  });

  it("stats() survives a clock that throws", async () => {
    let broken = false;
    const { shield, publish } = harness({
      now: () => {
        if (broken) throw new Error("clock exploded");
        return Date.now();
      },
    });
    await publish({ version: 2 });
    broken = true;
    expect(() => shield.stats()).not.toThrow();
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyStale: false });
    await shield.close();
  });
});

describe("the API is unreachable for days", () => {
  it("Shield keeps enforcing the last valid Policy, reports it stale after not_after, and warns once", async () => {
    const { shield, api, warnings, publish } = harness();
    await publish({ version: 5 });
    api.policyAnswer(new Error("connect ECONNREFUSED 127.0.0.1:8787"));
    const getsBefore = api.gets.length;

    await vi.advanceTimersByTimeAsync(6 * DAY_MS);
    expect(shield.stats()).toMatchObject({ policyVersion: 5, policyRules: 1, policyStale: false });
    expect(shield.stats().lastPolicyError).toMatch(/unreachable/);
    expect(shield.decide(ADMIN_REQUEST).action).toBe("block");

    await vi.advanceTimersByTimeAsync(2 * DAY_MS); // eight days without the API: not_after has passed
    expect(shield.stats()).toMatchObject({ policyVersion: 5, policyRules: 1, policyStale: true });
    expect(shield.decide(ADMIN_REQUEST)).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: rule(1).id,
      policyVersion: 5,
    });
    expect(shield.decide({ method: "GET", path: "/api/products/1" }).action).toBe("allow");

    // It kept asking, about once a minute, and said so once.
    const asked = api.gets.length - getsBefore;
    expect(asked).toBeGreaterThan(8 * 24 * 60 * 0.7);
    expect(asked).toBeLessThan(8 * 24 * 60 * 1.1);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/cannot be reached/);

    // The API comes back with a bundle issued anew: no longer stale.
    vi.spyOn(Math, "random").mockReturnValue(0);
    api.publish(signed(signer, payload(KEY, { version: 5, issued_at: new Date(Date.now()).toISOString() })));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(shield.stats()).toMatchObject({ policyVersion: 5, policyStale: false, lastPolicyError: null });
    await shield.close();
  });
});

describe("the API's Policy history was reset (review 02, F4)", () => {
  it("applies the first bundle of a new epoch whatever its version, says so once, and refuses replays within it", async () => {
    const { shield, api, warnings, publish } = harness();
    await publish({ version: 5 });
    expect(shield.stats()).toMatchObject({ policyVersion: 5, policyRules: 1, lastPolicyError: null });
    expect(warnings).toEqual([]);

    // The API's database was wiped, its signing key kept: versions restart at 1 under a new epoch, in bundles
    // issued after the applied one.
    const later = (ms: number) => new Date(NOW + ms).toISOString();
    await publish({ version: 1, epoch: NEW_EPOCH, rules: [], issued_at: later(1_000) });
    expect(shield.stats()).toMatchObject({ policyVersion: 1, policyRules: 0, lastPolicyError: null });
    expect(shield.decide(ADMIN_REQUEST)).toEqual({ action: "allow", mode: "enforce", ruleId: null, policyVersion: 1 });
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/^\[shield\] /);
    expect(warnings[0]).toMatch(/reset/);
    expect(warnings[0]).not.toContain(NEW_EPOCH);

    await publish({ version: 2, epoch: NEW_EPOCH, issued_at: later(2_000) });
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1, lastPolicyError: null });

    // A replay of an earlier bundle of the current epoch is refused, and the Policy stays.
    api.publish(signed(signer, payload(KEY, { version: 1, epoch: NEW_EPOCH, rules: [], issued_at: later(1_000) })));
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1 });
    expect(shield.stats().lastPolicyError).toContain("Policy refused (version)");
    expect(shield.decide(ADMIN_REQUEST).action).toBe("block");
    expect(warnings).toHaveLength(2);
    expect(warnings[1]).toMatch(/refused \(version\)/);
    await shield.close();
  });

  it("the first bundle after start is applied without a line about a reset: the built-in Policy has no epoch", async () => {
    const { shield, warnings, publish } = harness();
    await publish({ version: 3, epoch: NEW_EPOCH });
    expect(shield.stats()).toMatchObject({ policyVersion: 3, lastPolicyError: null });
    expect(warnings).toEqual([]);
    await shield.close();
  });
});

describe("Shield without a policyPublicKey", () => {
  it.each([
    // The inventory is off here: its start timer is covered in shield.test.ts and inventory-shield.test.ts.
    ["no policyPublicKey", { inventory: false }],
    ["an empty policyPublicKey", { policyPublicKey: "", inventory: false }],
  ])(
    "%s: observes only — nothing is fetched, the Policy stays version 0, one informational line",
    async (_name, extra) => {
      const api = fakeApi();
      api.publish(signed(signer, payload(KEY, { version: 3 })));
      const warnings: string[] = [];
      const shield = createShield({
        key: KEY,
        endpoint: "http://api.test",
        transport: api.transport,
        logger: { warn: (message) => void warnings.push(message) },
        ...extra,
      });
      expect(vi.getTimerCount()).toBe(0);
      await vi.advanceTimersByTimeAsync(120_000);
      await expect(shield.refreshPolicy()).resolves.toBeUndefined();
      expect(api.gets).toHaveLength(0);
      expect(shield.stats()).toMatchObject({
        policyVersion: 0,
        policyRules: 0,
        policyStale: false,
        lastPolicyError: null,
      });
      expect(shield.decide(ADMIN_REQUEST)).toEqual({
        action: "allow",
        mode: "monitor",
        ruleId: null,
        policyVersion: 0,
      });
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/observes only/);
      expect(warnings[0]).toMatch(/policyPublicKey/);
      expect(warnings[0]).not.toContain(KEY);
      await shield.close();
      expect(warnings).toHaveLength(1);
    },
  );

  it.each([
    ["a truncated key", signer.publicKey.slice(0, 40)],
    ["a key in standard base64", `${signer.publicKey.slice(0, 42)}/`],
    ["a number", 42],
    ["a Shield key in the wrong place", KEY],
  ])(
    "a policyPublicKey that cannot be read (%s): observes only, says why once, never prints the value",
    async (_name, value) => {
      const api = fakeApi();
      api.publish(signed(signer, payload(KEY, { version: 3 })));
      const warnings: string[] = [];
      const shield = createShield({
        key: KEY,
        endpoint: "http://api.test",
        transport: api.transport,
        policyPublicKey: value as string,
        logger: { warn: (message) => void warnings.push(message) },
      });
      await vi.advanceTimersByTimeAsync(120_000);
      await shield.refreshPolicy();
      expect(api.gets).toHaveLength(0);
      expect(shield.stats().disabledReason).toBeNull(); // Events are still recorded
      expect(shield.stats()).toMatchObject({ policyVersion: 0, policyRules: 0 });
      expect(shield.stats().lastPolicyError).toMatch(/policyPublicKey/);
      expect(warnings).toHaveLength(1);
      expect(warnings[0]).toMatch(/policyPublicKey/);
      expect(warnings[0]).toMatch(/observes only/);
      expect(warnings[0]).not.toContain(String(value));
      expect(shield.stats().lastPolicyError).not.toContain(String(value));
      await shield.close();
    },
  );

  it("a disabled Shield fetches nothing, decides allow, and refreshPolicy() resolves", async () => {
    const api = fakeApi();
    const warnings: string[] = [];
    const shield = createShield({
      key: "",
      endpoint: "http://api.test",
      transport: api.transport,
      policyPublicKey: signer.publicKey,
      logger: { warn: (message) => void warnings.push(message) },
    });
    expect(vi.getTimerCount()).toBe(0);
    await expect(shield.refreshPolicy()).resolves.toBeUndefined();
    expect(api.gets).toHaveLength(0);
    expect(shield.stats()).toEqual({
      buffered: 0,
      sent: 0,
      dropped: 0,
      failedBatches: 0,
      internalErrors: 0,
      disabledReason: expect.any(String),
      lastError: null,
      policyVersion: 0,
      policyStale: false,
      policyRules: 0,
      lastPolicyError: null,
      actorHashing: false,
      inventory: "off",
    });
    expect(shield.decide(ADMIN_REQUEST)).toEqual({ action: "allow", mode: "monitor", ruleId: null, policyVersion: 0 });
    expect(warnings).toHaveLength(1); // the line about being disabled, nothing about the Policy
  });
});
