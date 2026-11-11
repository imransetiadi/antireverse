// Slice 07, contract P4: Shield recognises a Canary in use. A request that carries a decoy key (bearer token,
// `x-api-key`, `api_key` query parameter) or asks for a decoy route (raw or canonical path) adds the signal
// `canary.touched:<id>` to its Event. Observe only: the response never changes, and the decoy value never leaves
// the process — not in the Event, not in a log line. Review focus 1 and 5.
import net from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import {
  type BundlePayload,
  BundlePayloadSchema,
  CANARY_LIMITS,
  CANARY_SIGNAL_PREFIX,
  CANARY_VALUE_PATTERNS,
  type Canary,
  canarySignalId,
  EventBatchSchema,
  EXAMPLE_CANARIES,
  ID_PATTERNS,
  parseCanarySignal,
  type ShieldEvent,
  ShieldEventSchema,
} from "@antireverse/protocol";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { canarySignals, CANARY_SIGNAL_PREFIX as SHIELD_SIGNAL_PREFIX, SIGNALS_MAX } from "../src/canary.ts";
import { createShield, type Shield } from "../src/index.ts";
import {
  audienceOf,
  CANARIES_MAX,
  CANARY_ID,
  CANARY_KEY_VALUE,
  CANARY_ROUTE_VALUE,
  importPublicKey,
  verifyBundle,
} from "../src/policy/verify.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, DAY_MS, EPOCH, type FakeApi, fakeApi, NOW, payload, rule, signed } from "./policy-helpers.ts";

const signer = createSigner();
const [KEY_CANARY, ROUTE_CANARY, ROUTE_CANARY_2] = EXAMPLE_CANARIES as [Canary, Canary, Canary];
const DECOY_KEY = KEY_CANARY.value; // ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE
const DECOY_ROUTE = ROUTE_CANARY.value; // /api/internal/un539n4s/backup
const KEY_SIGNAL = { id: canarySignalId(KEY_CANARY.id), confidence: 1 };
const ROUTE_SIGNAL = { id: canarySignalId(ROUTE_CANARY.id), confidence: 1 };

/** Every piece of a decoy value that must never leave the process. */
const SECRETS = [DECOY_KEY, DECOY_KEY.slice(8), "un539n4s", "60nekyby"];

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

interface Watched {
  shield: Shield;
  api: FakeApi;
  warnings: string[];
  /** Waits until `count` Events were recorded in total, flushes, and returns every Event sent so far. */
  events(count: number): Promise<ShieldEvent[]>;
  /** Everything that left the process towards the API, and every log line, as text. */
  leaked(): string;
  /** Publishes the payload (a new ETag) and refreshes. */
  publish(overrides: Partial<BundlePayload>): Promise<void>;
}

async function watch(overrides: Partial<BundlePayload> = { canaries: [...EXAMPLE_CANARIES] }): Promise<Watched> {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    logger: { warn: (message) => void warnings.push(message) },
  });
  shields.push(shield);
  const publish = async (given: Partial<BundlePayload>): Promise<void> => {
    api.publish(signed(signer, payload(KEY, { version: 7, issued_at: new Date().toISOString(), ...given })));
    await shield.refreshPolicy();
  };
  await publish(overrides);
  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    warnings,
    publish,
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
        shield.stats().lastPolicyError ?? "",
        shield.stats().lastError ?? "",
      ].join("\n"),
  };
}

/** An application with a data route, a mounted router, and a 404 of its own for everything else. */
function makeApp(shield?: Shield): express.Express {
  const app = express();
  app.disable("x-powered-by");
  if (shield) app.use(shield.express());
  app.get("/api/data", (_req, res) => {
    res.setHeader("x-data", "yes");
    res.json({ items: [1, 2, 3] });
  });
  const router = express.Router();
  router.get("/status", (_req, res) => res.send("ok"));
  app.use("/svc", router);
  app.use((_req, res) => {
    res.status(404).setHeader("x-app", "not-found");
    res.send("no such page");
  });
  return app;
}

async function serve(app: express.Express): Promise<Listening> {
  const listening = await listen(app);
  open.push(listening);
  return listening;
}

/** One request with the request target exactly as given: `fetch` would normalise dot segments. */
function raw(port: number, target: string, headers = ""): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1", () => {
      socket.write(`GET ${target} HTTP/1.1\r\nHost: target.test\r\n${headers}Connection: close\r\n\r\n`);
    });
    let data = "";
    socket.setEncoding("latin1");
    socket.on("data", (chunk: string) => {
      data += chunk;
    });
    socket.on("error", reject);
    socket.on("close", () => resolve(data.replace(/\r\nDate: [^\r]*/i, "")));
  });
}

describe("Shield's Canary bounds are the protocol's", () => {
  it("value patterns, id pattern and the bundle limit agree", () => {
    expect(CANARY_KEY_VALUE.source).toBe(CANARY_VALUE_PATTERNS.key.source);
    expect(CANARY_ROUTE_VALUE.source).toBe(CANARY_VALUE_PATTERNS.route.source);
    expect(CANARY_ID.source).toBe(ID_PATTERNS.cny.source);
    expect(CANARIES_MAX).toBe(CANARY_LIMITS.perBundle);
    expect(SHIELD_SIGNAL_PREFIX).toBe(CANARY_SIGNAL_PREFIX);
    expect(parseCanarySignal(SHIELD_SIGNAL_PREFIX + KEY_CANARY.id)).toBe(KEY_CANARY.id);
    const signals = (count: number) => Array.from({ length: count }, (_, i) => ({ id: `s${i}`, confidence: 1 }));
    expect(ShieldEventSchema.shape.signals.safeParse(signals(SIGNALS_MAX)).success).toBe(true);
    expect(ShieldEventSchema.shape.signals.safeParse(signals(SIGNALS_MAX + 1)).success).toBe(false);
  });

  it("the example Canaries are valid bundle content", () => {
    expect(BundlePayloadSchema.safeParse(payload(KEY, { canaries: [...EXAMPLE_CANARIES] })).success).toBe(true);
  });
});

describe("verifying the canaries of a bundle", () => {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("the test key could not be imported");
  const context = {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW,
  };
  const verifyWith = (canaries: unknown) => verifyBundle(signed(signer, { ...payload(KEY), canaries }), context);

  it("builds one lookup per kind, once per bundle", () => {
    const verified = verifyWith([...EXAMPLE_CANARIES]);
    if (!verified.ok) throw new Error(verified.detail);
    expect([...verified.policy.canaryKeys]).toEqual([[DECOY_KEY, KEY_CANARY.id]]);
    expect([...verified.policy.canaryRoutes]).toEqual([
      [ROUTE_CANARY.value, ROUTE_CANARY.id],
      [ROUTE_CANARY_2.value, ROUTE_CANARY_2.id],
    ]);
  });

  it("a bundle without the field, as before slice 07, has no Canaries", () => {
    const verified = verifyBundle(signed(signer, payload(KEY)), context);
    if (!verified.ok) throw new Error(verified.detail);
    expect(verified.policy.canaryKeys.size).toBe(0);
    expect(verified.policy.canaryRoutes.size).toBe(0);
  });

  it("an empty list is no Canaries; exactly the limit is accepted", () => {
    const empty = verifyWith([]);
    expect(empty.ok && empty.policy.canaryKeys.size + empty.policy.canaryRoutes.size).toBe(0);
    const full = verifyWith(manyKeys(CANARY_LIMITS.perBundle));
    expect(full.ok && full.policy.canaryKeys.size).toBe(CANARY_LIMITS.perBundle);
  });

  // The existing rule for malformed bundle content (a malformed Rule): the whole bundle is refused as `invalid`,
  // and the applied Policy stays. The detail names the entry, never its value.
  it.each([
    ["not a list", { id: KEY_CANARY.id }],
    ["more than the limit", manyKeys(CANARY_LIMITS.perBundle + 1)],
    ["an entry that is not an object", [DECOY_KEY]],
    ["a bad id", [{ ...KEY_CANARY, id: "cny_XYZ" }]],
    ["an unknown kind", [{ ...KEY_CANARY, kind: "config" }]],
    ["a key value that is not a decoy key", [{ ...KEY_CANARY, value: `${DECOY_KEY}x` }]],
    ["a route value given as a key", [{ ...KEY_CANARY, value: DECOY_ROUTE }]],
    ["a key value given as a route", [{ ...ROUTE_CANARY, value: DECOY_KEY }]],
    ["a value that is not text", [{ ...ROUTE_CANARY, value: 42 }]],
  ])("refuses the bundle as invalid for %s, without repeating a value", (_name, canaries) => {
    const verified = verifyWith(canaries);
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.reason).toBe("invalid");
    for (const secret of SECRETS) expect(verified.detail).not.toContain(secret);
  });
});

/** `count` distinct, well-formed key Canaries. */
function manyKeys(count: number): Canary[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `cny_${i.toString(16).padStart(24, "0")}`,
    kind: "key" as const,
    value: `ak_live_${i.toString(36).padStart(32, "Q")}`,
  }));
}

describe("a request that uses a Canary", () => {
  it.each([
    ["a bearer token", "/api/data", { authorization: `Bearer ${DECOY_KEY}` }],
    ["a bearer token, scheme in lower case", "/api/data", { authorization: `bearer ${DECOY_KEY}` }],
    ["a bearer token, scheme in upper case", "/api/data", { authorization: `BEARER ${DECOY_KEY}` }],
    ["a bearer token after two spaces", "/api/data", { authorization: `Bearer  ${DECOY_KEY}` }],
    ["a bearer token after a tab", "/api/data", { authorization: `Bearer\t${DECOY_KEY}` }],
    ["the x-api-key header", "/api/data", { "x-api-key": DECOY_KEY }],
    ["the api_key query parameter", `/api/data?api_key=${DECOY_KEY}`, {}],
    ["the api_key query parameter among others", `/api/data?page=2&api_key=${DECOY_KEY}&sort=asc`, {}],
    ["a key on an unrouted path", `/elsewhere?api_key=${DECOY_KEY}`, {}],
  ])("adds the key Canary's signal for %s", async (_name, path, headers) => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    await exchange(base + path, { headers });
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([KEY_SIGNAL]);
  });

  it.each([
    ["the raw path", DECOY_ROUTE],
    ["the raw path with a query", `${DECOY_ROUTE}?x=1`],
    ["the raw path with a trailing slash", `${DECOY_ROUTE}/`],
    ["a percent-encoded path", "/api/internal/%75n539n4s/backup"],
    ["a double-encoded path", "/api/internal/%2575n539n4s/backup"],
    ["a path with dot segments", "/api/data/../internal/./un539n4s/backup"],
    ["a path with an empty segment", "/api//internal/un539n4s/backup"],
    // Route Canaries match without regard to case, as Rules do and as Express routes (Jev: case_insensitive, 1.0).
    ["the path in upper case", DECOY_ROUTE.toUpperCase()],
    ["the path in mixed case", "/Api/INTERNAL/Un539N4s/BackUp"],
    ["an encoded mixed-case path", "/API/internal/%55n539N4S/Backup"],
  ])("adds the route Canary's signal for %s", async (_name, target) => {
    const watched = await watch();
    const { port } = await serve(makeApp(watched.shield));
    await raw(port, target);
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([ROUTE_SIGNAL]);
  });

  it("matches the full path under a mounted router (baseUrl + path)", async () => {
    const watched = await watch();
    const app = express();
    const router = express.Router();
    router.use(watched.shield.express());
    router.use((_req, res) => void res.status(404).send("none"));
    app.use("/api", router);
    const { port } = await serve(app);
    await raw(port, DECOY_ROUTE);
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([ROUTE_SIGNAL]);
  });

  it.each([
    ["a prefix of the key as bearer", "/api/data", { authorization: `Bearer ${DECOY_KEY.slice(0, -1)}` }],
    ["the key with a suffix as bearer", "/api/data", { authorization: `Bearer ${DECOY_KEY}0` }],
    ["the key in another case as bearer", "/api/data", { authorization: `Bearer ${DECOY_KEY.toUpperCase()}` }],
    ["the key under another scheme", "/api/data", { authorization: `Basic ${DECOY_KEY}` }],
    ["the key as the whole authorization header", "/api/data", { authorization: DECOY_KEY }],
    ["the key glued to the scheme", "/api/data", { authorization: `Bearer${DECOY_KEY}` }],
    ["the key followed by more text as bearer", "/api/data", { authorization: `Bearer ${DECOY_KEY} extra` }],
    ["the key in another header", "/api/data", { "x-api-token": DECOY_KEY }],
    ["a prefix of the key as x-api-key", "/api/data", { "x-api-key": DECOY_KEY.slice(0, -1) }],
    ["the key in another query parameter", `/api/data?apikey=${DECOY_KEY}`, {}],
    ["the key with a suffix as api_key", `/api/data?api_key=${DECOY_KEY}0`, {}],
    ["the key in the path", `/api/${DECOY_KEY}`, {}],
    ["a prefix of the route", "/api/internal/un539n4s", {}],
    ["the route with a suffix", `${DECOY_ROUTE}x`, {}],
    ["the route below another prefix", `/v2${DECOY_ROUTE}`, {}],
    ["another segment in upper case", "/API/INTERNAL/UN539N4X/BACKUP", {}],
    ["another word in mixed case", "/Api/Internal/Un539n4s/Export", {}],
    ["the route in the query", `/api/data?next=${DECOY_ROUTE}`, {}],
  ])("does not signal for %s", async (_name, path, headers) => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    await exchange(base + path, { headers });
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([]);
  });

  it("dedupes: the same key three ways is one signal; a key and a route are two", async () => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data?api_key=${DECOY_KEY}&api_key=${DECOY_KEY}`, {
      headers: { authorization: `Bearer ${DECOY_KEY}`, "x-api-key": DECOY_KEY },
    });
    await exchange(`${base}${DECOY_ROUTE}?api_key=${DECOY_KEY}`);
    const events = await watched.events(2);
    expect(events.map((event) => event.signals)).toEqual([[KEY_SIGNAL], [KEY_SIGNAL, ROUTE_SIGNAL]]);
  });

  it("adds at most 32 signals, and the Event stays valid", async () => {
    const keys = manyKeys(40);
    const watched = await watch({ canaries: keys });
    const { base } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data?${keys.map((canary) => `api_key=${canary.value}`).join("&")}`);
    const [event] = await watched.events(1);
    expect(event?.signals).toHaveLength(32);
    expect(new Set(event?.signals.map((signal) => signal.id)).size).toBe(32);
  });

  it("still signals on a request an Enforce Rule blocks", async () => {
    const watched = await watch({ canaries: [...EXAMPLE_CANARIES], rules: [rule(1, { path: "/api/data" })] });
    const { base } = await serve(makeApp(watched.shield));
    const response = await exchange(`${base}/api/data`, { headers: { "x-api-key": DECOY_KEY } });
    expect(response.status).toBe(403);
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([KEY_SIGNAL]);
  });

  it("never changes the response: status, headers and body as without Shield", async () => {
    const watched = await watch();
    const withShield = await serve(makeApp(watched.shield));
    const without = await serve(makeApp());
    const requests: [string, Record<string, string>][] = [
      ["/api/data", { authorization: `Bearer ${DECOY_KEY}` }],
      ["/api/data", { "x-api-key": DECOY_KEY }],
      [`/api/data?api_key=${DECOY_KEY}`, {}],
      [DECOY_ROUTE, {}],
      ["/svc/status", { "x-api-key": DECOY_KEY }],
    ];
    for (const [path, headers] of requests) {
      expect(await exchange(withShield.base + path, { headers }), path).toEqual(
        await exchange(without.base + path, { headers }),
      );
    }
    expect(await raw(withShield.port, "/api/internal/%75n539n4s/backup")).toBe(
      await raw(without.port, "/api/internal/%75n539n4s/backup"),
    );
    const events = await watched.events(requests.length + 1);
    expect(events.every((event) => event.signals.length === 1)).toBe(true);
  });

  it("never lets the decoy value leave: not in an Event, a request header, a warning or a console line", async () => {
    const watched = await watch();
    const { base, port } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data?api_key=${DECOY_KEY}`, {
      headers: { authorization: `Bearer ${DECOY_KEY}`, "x-api-key": DECOY_KEY },
    });
    await exchange(`${base}${DECOY_ROUTE}`);
    await exchange(`${base}${ROUTE_CANARY_2.value}`);
    await raw(port, "/api/internal/%75n539n4s/backup");
    const events = await watched.events(4);
    expect(events).toHaveLength(4);
    expect(events.flatMap((event) => event.signals).length).toBe(4);
    // A refused bundle with Canaries must not repeat them either.
    await watched.publish({ canaries: [{ ...KEY_CANARY, value: `${DECOY_KEY}!` }] });
    const leaked = watched.leaked();
    expect(leaked).toContain("canary.touched:");
    for (const secret of SECRETS) expect(leaked).not.toContain(secret);
  });
});

describe("a replayed bundle of the applied version", () => {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("the test key could not be imported");
  const applied = {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 7,
    appliedEpoch: EPOCH,
    appliedIssuedAt: NOW,
    now: NOW,
  };
  const at = (issuedAt: number, canaries: Canary[] | undefined) =>
    verifyBundle(
      signed(signer, payload(KEY, { version: 7, issued_at: new Date(issuedAt).toISOString(), canaries })),
      applied,
    );

  it("is refused when it was issued before the applied one, without repeating a value", () => {
    const verified = at(NOW - DAY_MS, undefined);
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.reason).toBe("version");
    for (const secret of SECRETS) expect(verified.detail).not.toContain(secret);
    expect(verified.detail).not.toContain(new Date(NOW).toISOString());
  });

  it("is accepted when it is the same issue (a re-fetch) or a later one with another Canary set", () => {
    const same = at(NOW, [...EXAMPLE_CANARIES]);
    expect(same.ok && same.policy.canaryKeys.size).toBe(1);
    const later = at(NOW + 1_000, []);
    expect(later.ok && later.policy.canaryKeys.size).toBe(0);
  });

  it("a newer version is accepted whatever its issued_at, as before", () => {
    const verified = verifyBundle(
      signed(signer, payload(KEY, { version: 8, issued_at: new Date(NOW - DAY_MS).toISOString() })),
      applied,
    );
    expect(verified.ok).toBe(true);
  });

  it("through the poller: the replay is refused and the applied Canaries stay", async () => {
    const watched = await watch({ canaries: [...EXAMPLE_CANARIES] });
    await watched.publish({ issued_at: new Date(Date.now() - DAY_MS).toISOString() });
    expect(watched.shield.stats().lastPolicyError).toMatch(/^Policy refused \(version\): /);
    const { base } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data`, { headers: { "x-api-key": DECOY_KEY } });
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([KEY_SIGNAL]);
  });
});

describe("applying Canaries", () => {
  it("applies a bundle of the same version whose Canary set changed (the API gives it a new ETag)", async () => {
    const watched = await watch({ canaries: [] });
    const { base } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data`, { headers: { "x-api-key": DECOY_KEY } });

    await watched.publish({ canaries: [...EXAMPLE_CANARIES] }); // still version 7
    expect(watched.shield.stats()).toMatchObject({ policyVersion: 7, lastPolicyError: null });
    await exchange(`${base}/api/data`, { headers: { "x-api-key": DECOY_KEY } });

    // The next poll sends the new ETag back and the 304 keeps the Canaries.
    await watched.shield.refreshPolicy();
    expect(watched.api.gets.at(-1)?.headers["if-none-match"]).toBe('"bundle-2"');
    await exchange(`${base}/api/data`, { headers: { "x-api-key": DECOY_KEY } });

    const events = await watched.events(3);
    expect(events.map((event) => event.signals)).toEqual([[], [KEY_SIGNAL], [KEY_SIGNAL]]);
  });

  it("a bundle without canaries clears them", async () => {
    const watched = await watch();
    const { base } = await serve(makeApp(watched.shield));
    await watched.publish({}); // the payload has no canaries field
    await exchange(`${base}${DECOY_ROUTE}`, { headers: { "x-api-key": DECOY_KEY } });
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([]);
  });

  it("a bundle as before slice 07 (no canaries field) still applies its Rules", async () => {
    const watched = await watch({ rules: [rule(1, { path: "/api/data" })] });
    expect(watched.shield.stats()).toMatchObject({ policyVersion: 7, policyRules: 1, lastPolicyError: null });
    const { base } = await serve(makeApp(watched.shield));
    expect((await exchange(`${base}/api/data`)).status).toBe(403);
  });

  it("a bundle with a malformed Canary is refused as invalid; the applied Policy and its Canaries stay", async () => {
    const watched = await watch();
    await watched.publish({ version: 8, canaries: [...EXAMPLE_CANARIES, { ...ROUTE_CANARY, kind: "key" }] });
    expect(watched.shield.stats().policyVersion).toBe(7);
    expect(watched.shield.stats().lastPolicyError).toMatch(
      /^Policy refused \(invalid\): Canary 4: value is not a decoy key$/,
    );
    const { base } = await serve(makeApp(watched.shield));
    await exchange(`${base}/api/data`, { headers: { "x-api-key": DECOY_KEY } });
    const [event] = await watched.events(1);
    expect(event?.signals).toEqual([KEY_SIGNAL]);
  });
});

describe("canarySignals, without Express", () => {
  it("reads the bearer token after one or more spaces or tabs, up to trailing whitespace, and compares it exactly", () => {
    const loaded = { canaryKeys: new Map([[DECOY_KEY, KEY_CANARY.id]]), canaryRoutes: new Map() };
    const signalsOf = (authorization: string) => canarySignals(loaded, { headers: { authorization } }, "/");
    for (const value of [
      `Bearer ${DECOY_KEY}`,
      `bearer  ${DECOY_KEY}`,
      `Bearer\t${DECOY_KEY}`,
      `BEARER \t ${DECOY_KEY}`,
      `Bearer ${DECOY_KEY} `,
      `Bearer ${DECOY_KEY}\t \t`,
    ]) {
      expect(signalsOf(value), JSON.stringify(value)).toEqual([KEY_SIGNAL]);
    }
    for (const value of [
      `Bearer${DECOY_KEY}`,
      `Bearer ${DECOY_KEY} extra`,
      `Bearer ${DECOY_KEY}x`,
      `Bearers ${DECOY_KEY}`,
      ` Bearer ${DECOY_KEY}`,
      `Bearer ${DECOY_KEY.toLowerCase()}`,
      "Bearer ",
      "Bearer",
    ]) {
      expect(signalsOf(value), JSON.stringify(value)).toEqual([]);
    }
  });

  it("reads the url of a plain node:http request and returns nothing when no Canary is loaded", () => {
    const empty = { canaryKeys: new Map(), canaryRoutes: new Map() };
    const request = { url: DECOY_ROUTE, headers: { "x-api-key": DECOY_KEY } };
    expect(canarySignals(empty, request, DECOY_ROUTE)).toEqual([]);
    const loaded = {
      canaryKeys: new Map([[DECOY_KEY, KEY_CANARY.id]]),
      canaryRoutes: new Map([[DECOY_ROUTE, ROUTE_CANARY.id]]),
    };
    expect(canarySignals(loaded, request, DECOY_ROUTE)).toEqual([KEY_SIGNAL, ROUTE_SIGNAL]);
  });

  it("never throws on headers it cannot read", () => {
    const loaded = { canaryKeys: new Map([[DECOY_KEY, KEY_CANARY.id]]), canaryRoutes: new Map() };
    const odd = { url: 42, headers: { authorization: ["Bearer", DECOY_KEY], "x-api-key": [DECOY_KEY] } };
    expect(canarySignals(loaded, odd as never, "")).toEqual([]);
    expect(canarySignals(loaded, { headers: undefined } as never, "/")).toEqual([]);
  });
});
