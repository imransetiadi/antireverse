// Review finding F1 (owner's decision): the actor hash is keyed with a CUSTOMER-HELD key, `actorKey` (or the
// environment variable AR_ACTOR_KEY), never with the Shield key — the API receives the Shield key on every request
// and could reverse a hash keyed with it. Without a usable actor key every Event carries `ip_hash: null`, actor
// blocks never match, and prefix blocks still apply. The actor key never leaves the process and is never logged.
import { setTimeout as sleep } from "node:timers/promises";
import { type BundlePayload, EventBatchSchema, type ShieldEvent } from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createShield, type Shield, type ShieldConfig } from "../src/index.ts";
import { KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, type FakeApi, fakeApi, NOW, payload, signed } from "./policy-helpers.ts";

const signer = createSigner();
/** Synthetic customer-held key: 40 characters, no whitespace. */
const ACTOR_KEY = "ck_test_7Hq2Vn9xLp4Rt6Wz8Bm3Kd5Fs1Gj0Yc2";
const OTHER_ACTOR_KEY = "ck_test_other_0000000000000000000000000000";
const ATTACKER = "203.0.113.7";
const EXPIRES = new Date(NOW + 3_600_000).toISOString();

const open: Listening[] = [];
const shields: Shield[] = [];
let consoleLines: string[] = [];

beforeEach(() => {
  vi.stubEnv("AR_ACTOR_KEY", "");
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
  vi.unstubAllEnvs();
});

interface Run {
  shield: Shield;
  api: FakeApi;
  warnings: string[];
  get(address: string): Promise<number>;
  events(count: number): Promise<ShieldEvent[]>;
  leaked(): string;
}

async function run(config: Partial<ShieldConfig>, bundle: Partial<BundlePayload> = {}): Promise<Run> {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    now: () => NOW,
    clientAddress: (req) => (req as { headers: Record<string, string | undefined> }).headers["x-client"],
    logger: { warn: (message) => void warnings.push(message) },
    ...config,
  });
  shields.push(shield);
  api.publish(signed(signer, payload(KEY, { version: 7, rules: [], ...bundle })));
  await shield.refreshPolicy();
  const app = express();
  app.use(shield.express());
  app.get("/api/data", (_req, res) => void res.send("ok"));
  const listening = await listen(app);
  open.push(listening);
  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    warnings,
    get: async (address) => (await fetch(`${listening.base}/api/data`, { headers: { "x-client": address } })).status,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
    leaked: () =>
      [
        ...api.posts.map((request) => `${request.url} ${JSON.stringify(request.headers)} ${request.body ?? ""}`),
        ...api.gets.map((request) => `${request.url} ${JSON.stringify(request.headers)}`),
        ...warnings,
        ...consoleLines,
        JSON.stringify(shield.stats()),
      ].join("\n"),
  };
}

describe("with an actor key", () => {
  it("ip_hash is keyed with the actor key, never with the Shield key", async () => {
    const shielded = await run({ actorKey: ACTOR_KEY });
    await shielded.get(ATTACKER);
    await shielded.get("2001:db8:0:1::1");
    const events = await shielded.events(2);
    expect(events.map((event) => event.actor.ip_hash)).toEqual([
      actorHash(ACTOR_KEY, ATTACKER),
      actorHash(ACTOR_KEY, "2001:db8:0:1::1"),
    ]);
    expect(events[0]?.actor.ip_hash).not.toBe(actorHash(KEY, ATTACKER));
    expect(shielded.warnings).toEqual([]);
    expect(shielded.shield.stats().actorHashing).toBe(true);
  });

  it("an actor block keyed with the actor key matches; one keyed with the Shield key never does", async () => {
    const byActorKey = await run(
      { actorKey: ACTOR_KEY },
      {
        blocks: [
          {
            id: "cnt_00000000000000000000000a",
            kind: "actor",
            ip_hash: actorHash(ACTOR_KEY, ATTACKER) as string,
            expires_at: EXPIRES,
          },
        ],
      },
    );
    expect(await byActorKey.get(ATTACKER)).toBe(403);
    const byShieldKey = await run(
      { actorKey: ACTOR_KEY },
      {
        blocks: [
          {
            id: "cnt_00000000000000000000000a",
            kind: "actor",
            ip_hash: actorHash(KEY, ATTACKER) as string,
            expires_at: EXPIRES,
          },
        ],
      },
    );
    expect(await byShieldKey.get(ATTACKER)).toBe(200);
  });

  it("is read from AR_ACTOR_KEY when the option is left out; the option wins over the variable", async () => {
    vi.stubEnv("AR_ACTOR_KEY", ACTOR_KEY);
    const fromEnv = await run({});
    await fromEnv.get(ATTACKER);
    expect((await fromEnv.events(1))[0]?.actor.ip_hash).toBe(actorHash(ACTOR_KEY, ATTACKER));
    expect(fromEnv.shield.stats().actorHashing).toBe(true);
    const fromOption = await run({ actorKey: OTHER_ACTOR_KEY });
    await fromOption.get(ATTACKER);
    expect((await fromOption.events(1))[0]?.actor.ip_hash).toBe(actorHash(OTHER_ACTOR_KEY, ATTACKER));
  });

  it("never lets the actor key leave: not in a request, a warning, a console line or the stats", async () => {
    const shielded = await run({ actorKey: ACTOR_KEY });
    await shielded.get(ATTACKER);
    await shielded.events(1);
    expect(shielded.leaked()).not.toContain(ACTOR_KEY);
    expect(shielded.leaked()).not.toContain(ACTOR_KEY.slice(8, 24));
  });
});

describe("without a usable actor key", () => {
  it("every Event carries ip_hash null: the Shield key is never used instead", async () => {
    const shielded = await run({});
    for (const address of [ATTACKER, "203.0.113.8", "2001:db8:0:1::1", "::ffff:203.0.113.7"])
      await shielded.get(address);
    const events = await shielded.events(4);
    expect(events.map((event) => event.actor.ip_hash)).toEqual([null, null, null, null]);
    expect(events[0]?.actor.ip_prefix).toBe("203.0.113.0/24");
    expect(shielded.leaked()).not.toContain(actorHash(KEY, ATTACKER) as string);
    expect(shielded.warnings).toEqual([]); // absent is not an error: nothing is said
    expect(shielded.shield.stats().actorHashing).toBe(false);
  });

  it("actor blocks never match and prefix blocks still apply", async () => {
    const shielded = await run(
      {},
      {
        blocks: [
          {
            id: "cnt_00000000000000000000000a",
            kind: "actor",
            ip_hash: actorHash(KEY, ATTACKER) as string,
            expires_at: EXPIRES,
          },
          { id: "cnt_00000000000000000000000b", kind: "prefix", ip_prefix: "198.18.0.0/24", expires_at: EXPIRES },
        ],
      },
    );
    expect(await shielded.get(ATTACKER)).toBe(200);
    expect(await shielded.get("198.18.0.9")).toBe(403);
    const events = await shielded.events(2);
    expect(events.map((event) => event.decision.containment_id)).toEqual([null, "cnt_00000000000000000000000b"]);
  });

  it.each([
    ["shorter than 32 characters", "ck_short_0123456789"],
    ["31 characters", "a".repeat(31)],
    ["with a space", `ck_test ${"x".repeat(32)}`],
    ["with a tab", `ck_test\t${"x".repeat(32)}`],
    ["with a newline", `${"x".repeat(32)}\n`],
    ["equal to the Shield key", KEY],
    ["not a string", { length: 40 } as unknown as string],
  ])("an actor key %s is treated as absent, with one warning that never contains it", async (_name, value) => {
    const shielded = await run({ actorKey: value });
    await shielded.get(ATTACKER);
    await shielded.get(ATTACKER);
    const events = await shielded.events(2);
    expect(events.map((event) => event.actor.ip_hash)).toEqual([null, null]);
    expect(shielded.shield.stats().actorHashing).toBe(false);
    expect(shielded.warnings).toHaveLength(1);
    expect(shielded.warnings[0]).toMatch(/actor/i);
    // Logs and stats only: the Shield key, one of the cases, is rightly in the Authorization header.
    const logged = [...shielded.warnings, ...consoleLines, JSON.stringify(shielded.shield.stats())].join("\n");
    expect(logged).not.toContain(String(value).trim().slice(0, 16));
  });

  it("an unusable AR_ACTOR_KEY is treated as absent with one warning", async () => {
    vi.stubEnv("AR_ACTOR_KEY", "too-short");
    const shielded = await run({});
    await shielded.get(ATTACKER);
    expect((await shielded.events(1))[0]?.actor.ip_hash).toBeNull();
    expect(shielded.shield.stats().actorHashing).toBe(false);
    expect(shielded.warnings).toHaveLength(1);
    expect(shielded.leaked()).not.toContain("too-short");
  });

  it("exactly 32 characters without whitespace is usable", async () => {
    const key = "k".repeat(32);
    const shielded = await run({ actorKey: key });
    await shielded.get(ATTACKER);
    expect((await shielded.events(1))[0]?.actor.ip_hash).toBe(actorHash(key, ATTACKER));
    expect(shielded.warnings).toEqual([]);
  });
});

describe("stats().actorHashing", () => {
  it("says whether a usable actor key was accepted, never the key itself", async () => {
    const on = await run({ actorKey: ACTOR_KEY });
    expect(on.shield.stats().actorHashing).toBe(true);
    expect(JSON.stringify(on.shield.stats())).not.toContain(ACTOR_KEY);
    expect((await run({})).shield.stats().actorHashing).toBe(false);
  });

  it("is false for a disabled Shield, even with an actor key", () => {
    const shield = createShield({
      key: KEY,
      endpoint: "http://api.test",
      disabled: true,
      actorKey: ACTOR_KEY,
      logger: { warn: () => {} },
    });
    expect(shield.stats().actorHashing).toBe(false);
  });
});
