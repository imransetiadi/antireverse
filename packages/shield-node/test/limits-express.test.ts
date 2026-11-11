// Slice 08 through the Express adapter: an enforced limit answers 429 with Retry-After before the handler; a monitor
// limit changes nothing and records what would have happened; a failure limit counts 401 and 403 responses after the
// handler; limits come after Containments and Rules and before Virtual patches; the never-block list, preflights and
// HEAD; device keys; a custom counter store; fail open; and no counter key in an Event or a log line.
import net from "node:net";
import { setTimeout as sleep } from "node:timers/promises";
import {
  type BundleLimitRule,
  type BundlePayload,
  EventBatchSchema,
  RATE_LIMITED_RESPONSE_BODY,
  type ShieldEvent,
} from "@antireverse/protocol";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type CounterStore, createShield, MemoryCounterStore, type Shield, type ShieldConfig } from "../src/index.ts";
import { APP_ID, claims, createAttestationKey, token } from "./attestation-helpers.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, fakeApi, NOW, payload, rule, signed } from "./policy-helpers.ts";

const signer = createSigner();
const attestationKey = createAttestationKey();
const START = NOW + 60_000;
const ADDRESS = "203.0.113.9";
const OTHER_ADDRESS = "198.51.100.4";
const DEVICE_A = "dev_0123456789abcdef01234567";
const DEVICE_B = "dev_fedcba9876543210fedcba98";

function limitRule(n: number, overrides: Partial<BundleLimitRule> = {}): BundleLimitRule {
  return {
    id: `rul_${(0xc000 + n).toString(16).padStart(24, "0")}`,
    path: "/api/data",
    methods: [],
    action: "throttle",
    mode: "enforce",
    limit: { requests: 3, window_s: 60, key: "ip", count: "requests" },
    ...overrides,
  };
}

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

interface Setup {
  shield: Shield;
  base: string;
  port: number;
  /** What the handlers saw, in order. */
  calls: string[];
  /** The clock Shield reads; a test moves it. */
  clock: { now: number };
  /** The address Shield derives for the next requests. */
  client: { address: string | undefined };
  /** A valid Attestation Token of `device` at the clock's time. */
  tokenOf(device: string, n?: number): string;
  events(count: number): Promise<ShieldEvent[]>;
  leaked(): string;
}

async function setup(
  bundle: Partial<BundlePayload>,
  options: {
    config?: Partial<ShieldConfig>;
    withShield?: boolean;
    /** Routes registered before the default ones. */
    routes?: (app: express.Express, calls: string[]) => void;
  } = {},
): Promise<Setup> {
  const api = fakeApi();
  const warnings: string[] = [];
  const clock = { now: START };
  const client: { address: string | undefined } = { address: ADDRESS };
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    now: () => clock.now,
    clientAddress: () => client.address,
    actorKey: `ck_test_${"9".repeat(32)}`,
    logger: { warn: (message) => void warnings.push(message) },
    ...options.config,
  });
  shields.push(shield);
  api.publish(
    signed(signer, payload(KEY, { rules: [], app_id: APP_ID, attestation_keys: [attestationKey.entry], ...bundle })),
  );
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();

  const withShield = options.withShield ?? true;
  const calls: string[] = [];
  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  if (withShield) app.use(shield.express());
  app.use(withShield ? express.json({ verify: shield.verifyBody }) : express.json());
  options.routes?.(app, calls);
  app.get("/api/data", (_req, res) => {
    calls.push("data");
    res.setHeader("x-data", "yes");
    res.json({ items: [1, 2, 3] });
  });
  app.delete("/api/data", (_req, res) => {
    calls.push("delete");
    res.status(204).end();
  });
  app.options("/api/data", (_req, res) => {
    calls.push("options");
    res.status(204).end();
  });
  app.post("/login", (req, res) => {
    const password = (req.body as { password?: unknown } | undefined)?.password;
    calls.push(`login ${String(password)}`);
    if (password === "correct") res.json({ ok: true });
    else if (password === "locked") res.status(403).json({ error: "locked" });
    else if (password === "boom") res.status(500).json({ error: "boom" });
    else res.status(401).json({ error: "bad credentials" });
  });
  if (withShield) app.use(shield.errorHandler());
  app.use((_req, res) => void res.status(404).send("no such page"));
  const listening = await listen(app);
  open.push(listening);

  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  let jti = 1;
  return {
    shield,
    base: listening.base,
    port: listening.port,
    calls,
    clock,
    client,
    tokenOf: (device, n) =>
      token(attestationKey, claims(Math.floor(clock.now / 1000), { sub: device, aud: APP_ID }, n ?? jti++)),
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
        JSON.stringify(shield.stats()),
      ].join("\n"),
  };
}

const login = (base: string, password: string, headers: Record<string, string> = {}) =>
  exchange(`${base}/login`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ password }),
  });

describe("an enforced limit", () => {
  it("answers 429 with Retry-After and the rate-limited body before the handler, once the client is over", async () => {
    const { base, calls, events, client, shield } = await setup({ limit_rules: [limitRule(1)] });
    expect(shield.stats().policyRules).toBe(1);
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
    const refused = await exchange(`${base}/api/data`);
    expect(refused.status).toBe(429);
    expect(refused.body).toBe(RATE_LIMITED_RESPONSE_BODY);
    expect(refused.body).toBe('{"error":"rate_limited"}');
    expect(Object.fromEntries(refused.headers)).toMatchObject({
      "content-type": "application/json",
      "retry-after": "61",
    });
    expect(calls).toEqual(["data", "data", "data"]);

    // Another client is served.
    client.address = OTHER_ADDRESS;
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect(calls).toHaveLength(4);

    const seen = await events(5);
    expect(seen.map((event) => event.request.status)).toEqual([200, 200, 200, 429, 200]);
    expect(seen.map((event) => event.decision.action)).toEqual(["allow", "allow", "allow", "throttle", "allow"]);
    expect(seen[3]?.decision).toEqual({
      action: "throttle",
      mode: "enforce",
      rule_id: limitRule(1).id,
      policy_version: 1,
      containment_id: null,
      patch_id: null,
      patch_body: null,
      limit_rule_id: null,
    });
    // The route of a throttled request is the path pattern of the Rule, as for a blocked one.
    expect(seen[3]?.request.route).toBe("/api/data");
  });

  it("answers with the headers of a block response plus Retry-After, and nothing else", async () => {
    const { base } = await setup({
      rules: [rule(1, { path: "/api/blocked" })],
      limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
    });
    const blocked = await exchange(`${base}/api/blocked`);
    expect(blocked.status).toBe(403);
    await exchange(`${base}/api/data`);
    const throttled = await exchange(`${base}/api/data`);
    expect(throttled.status).toBe(429);
    const names = (headers: [string, string][]): string[] => headers.map(([name]) => name);
    expect(names(throttled.headers)).toEqual([...names(blocked.headers), "retry-after"].sort());
    const headerOf = (headers: [string, string][], name: string) => headers.find(([key]) => key === name)?.[1];
    expect(headerOf(throttled.headers, "content-type")).toBe(headerOf(blocked.headers, "content-type"));
    expect(headerOf(throttled.headers, "content-length")).toBe(String(RATE_LIMITED_RESPONSE_BODY.length));
  });

  it("Retry-After is whole seconds, at least 1, after which one more request is allowed — and not a second before", async () => {
    const { base, clock } = await setup({ limit_rules: [limitRule(1)] });
    for (let i = 0; i < 3; i++) await exchange(`${base}/api/data`);
    clock.now += 20_500;
    const refused = await exchange(`${base}/api/data`);
    const retry = Number(Object.fromEntries(refused.headers)["retry-after"]);
    expect(retry).toBe(40);
    // Hammering meanwhile neither extends the wait nor is counted.
    for (let i = 0; i < 20; i++) expect((await exchange(`${base}/api/data`)).status).toBe(429);
    clock.now += (retry - 1) * 1_000;
    const early = await exchange(`${base}/api/data`);
    expect(early.status).toBe(429);
    expect(Object.fromEntries(early.headers)["retry-after"]).toBe("1");
    clock.now += 1_000;
    // An exact window (A7 F2): the three requests have left it, so three more are allowed, and they are counted.
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
  });

  it("stats count limit Rules among the Rules of the Policy", async () => {
    const { shield } = await setup({
      rules: [rule(1)],
      signature_rules: [rule(2, { path: "/signed/**" })],
      limit_rules: [limitRule(1), limitRule(2, { mode: "monitor" })],
    });
    expect(shield.stats().policyRules).toBe(4);
  });
});

describe("a limit in monitor", () => {
  it("changes no response and records what would have happened", async () => {
    const bare = await setup({}, { withShield: false });
    const { base, calls, events } = await setup({ limit_rules: [limitRule(1, { mode: "monitor" })] });
    const expected = await exchange(`${bare.base}/api/data`);
    for (let i = 0; i < 5; i++) expect(await exchange(`${base}/api/data`)).toEqual(expected);
    expect(calls).toHaveLength(5);
    const seen = await events(5);
    expect(seen.map((event) => `${event.decision.action}/${event.decision.mode}`)).toEqual([
      "allow/enforce",
      "allow/enforce",
      "allow/enforce",
      "throttle/monitor",
      "throttle/monitor",
    ]);
    expect(seen[4]?.decision.rule_id).toBe(limitRule(1).id);
    expect(seen[4]?.request).toMatchObject({ status: 200, route: "/api/data" });
  });

  it("a monitor limit before an enforced one still counts; the enforced one refuses", async () => {
    const { base, events } = await setup({
      limit_rules: [
        limitRule(1, { mode: "monitor", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        limitRule(2, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
      ],
    });
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
    const seen = await events(3);
    expect(seen.map((event) => [event.decision.action, event.decision.mode, event.decision.rule_id])).toEqual([
      ["allow", "enforce", null],
      ["throttle", "monitor", limitRule(1).id],
      ["throttle", "enforce", limitRule(2).id],
    ]);
  });
});

describe("a limit that counts failures", () => {
  const protection = limitRule(1, {
    path: "/login",
    methods: ["POST"],
    limit: { requests: 3, window_s: 300, key: "ip", count: "failures" },
  });

  it("refuses further attempts once 401 and 403 responses reach the limit, while another client still logs in", async () => {
    const { base, calls, events, client, clock } = await setup({ limit_rules: [protection] });
    // Successes and other errors do not count.
    for (let i = 0; i < 4; i++) expect((await login(base, "correct")).status).toBe(200);
    expect((await login(base, "boom")).status).toBe(500);
    expect((await login(base, "wrong-1")).status).toBe(401);
    expect((await login(base, "locked")).status).toBe(403);
    expect((await login(base, "wrong-2")).status).toBe(401);
    const handled = calls.length;
    // Even the right password is refused now, before the handler.
    const refused = await login(base, "correct");
    expect(refused.status).toBe(429);
    expect(refused.body).toBe(RATE_LIMITED_RESPONSE_BODY);
    expect(Object.fromEntries(refused.headers)["retry-after"]).toBe("301");
    expect(calls).toHaveLength(handled);

    client.address = OTHER_ADDRESS;
    expect((await login(base, "correct")).status).toBe(200);
    client.address = ADDRESS;

    // Refused attempts are not failures: they extend nothing.
    for (let i = 0; i < 10; i++) expect((await login(base, "wrong")).status).toBe(429);
    clock.now += 301_000;
    expect((await login(base, "correct")).status).toBe(200);

    const seen = await events(21);
    const throttled = seen.filter((event) => event.decision.action === "throttle");
    expect(throttled).toHaveLength(11);
    expect(throttled[0]?.decision).toMatchObject({ mode: "enforce", rule_id: protection.id });
    expect(throttled[0]?.request).toMatchObject({ status: 429, route: "/login", method: "POST" });
  });

  it("in monitor every attempt reaches the handler and the Event records the throttle", async () => {
    const { base, calls, events } = await setup({ limit_rules: [{ ...protection, mode: "monitor" }] });
    for (let i = 0; i < 5; i++) expect((await login(base, `wrong-${i}`)).status).toBe(401);
    expect(calls).toHaveLength(5);
    const seen = await events(5);
    expect(seen.map((event) => `${event.decision.action}/${event.decision.mode}`)).toEqual([
      "allow/enforce",
      "allow/enforce",
      "allow/enforce",
      "throttle/monitor",
      "throttle/monitor",
    ]);
  });

  it("a 403 that Shield itself answered is not a failure of the application", async () => {
    // A Virtual patch refuses the request after the limits: its 403 is Shield's, not a failed login.
    const { base, calls } = await setup({
      limit_rules: [{ ...protection, limit: { ...protection.limit, requests: 1 } }],
      patches: [
        {
          id: "vp_header_probe",
          mode: "enforce",
          conditions: [{ target: "header", name: "x-probe", op: "present" }],
          advisory: "CVE-2021-44228",
        },
      ],
    });
    for (let i = 0; i < 3; i++) expect((await login(base, "wrong", { "x-probe": "1" })).status).toBe(403);
    expect(calls).toEqual([]);
    expect((await login(base, "correct")).status).toBe(200);
  });
});

describe("order: containment, then Rules, then limits, then patches", () => {
  it("a request a Rule blocks is not counted", async () => {
    const { base, calls } = await setup({
      rules: [rule(1, { path: "/api/data", methods: ["DELETE"] })],
      limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
    });
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`, { method: "DELETE" })).status).toBe(403);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
    expect(calls).toEqual(["data"]);
  });

  it("a request of a contained client is not counted", async () => {
    const expires = new Date(START + 3_600_000).toISOString();
    const touched: string[] = [];
    const store: CounterStore = {
      hit: () => touched.push("hit"),
      peek: () => {
        touched.push("peek");
        return 0;
      },
      size: () => 0,
    };
    const { base, client, events } = await setup(
      {
        blocks: [
          { id: "cnt_0123456789abcdef01234567", kind: "prefix", ip_prefix: "198.51.100.0/24", expires_at: expires },
        ],
        limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
      },
      { config: { counterStore: store } },
    );
    client.address = OTHER_ADDRESS;
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(403);
    expect(touched).toEqual([]);
    const seen = await events(3);
    expect(seen.map((event) => event.decision.action)).toEqual(["block", "block", "block"]);
    expect(seen.map((event) => event.decision.containment_id)).toEqual(Array(3).fill("cnt_0123456789abcdef01234567"));
  });

  it("a Rule in monitor keeps its mark; the limit still counts and, enforced, refuses", async () => {
    const { base, events } = await setup({
      rules: [rule(1, { path: "/api/data", mode: "monitor" })],
      limit_rules: [
        limitRule(1, { mode: "monitor", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        limitRule(2, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
      ],
    });
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
    const seen = await events(3);
    expect(seen.map((event) => [event.decision.action, event.decision.mode, event.decision.rule_id])).toEqual([
      ["block", "monitor", rule(1).id],
      ["block", "monitor", rule(1).id],
      ["throttle", "enforce", limitRule(2).id],
    ]);
  });

  it("a throttled request never reaches the patches; a monitor throttle is recorded instead of a monitor patch", async () => {
    const patch = {
      id: "vp_header_probe",
      mode: "monitor" as const,
      conditions: [{ target: "header" as const, name: "x-probe", op: "present" as const }],
      advisory: "CVE-2021-44228",
    };
    const { base, events } = await setup({
      limit_rules: [
        limitRule(1, { mode: "monitor", limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        limitRule(2, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
      ],
      patches: [patch],
    });
    const probe = { headers: { "x-probe": "1" } };
    for (let i = 0; i < 3; i++) await exchange(`${base}/api/data`, probe);
    const seen = await events(3);
    expect(seen.map((event) => [event.decision.action, event.decision.mode, event.decision.patch_id])).toEqual([
      ["block", "monitor", "vp_header_probe"],
      ["throttle", "monitor", null],
      ["throttle", "enforce", null],
    ]);
  });
});

describe("what is exempt, and what counts together", () => {
  it("an address on the never-block list is never throttled", async () => {
    const { base, events } = await setup({
      allowlist: ["203.0.113.0/24"],
      limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
    });
    for (let i = 0; i < 5; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
    const seen = await events(5);
    expect(seen.every((event) => event.decision.action === "allow")).toBe(true);
  });

  it("HEAD counts with GET", async () => {
    const { base } = await setup({
      limit_rules: [
        limitRule(1, { methods: ["GET"], limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } }),
      ],
    });
    expect((await exchange(`${base}/api/data`, { method: "HEAD" })).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`, { method: "HEAD" })).status).toBe(429);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
    // DELETE is not in the Rule's methods.
    expect((await exchange(`${base}/api/data`, { method: "DELETE" })).status).toBe(204);
  });

  it("spellings of the path that reach the same handler count on the same counter", async () => {
    const { base } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } })],
    });
    expect((await exchange(`${base}/api/data?x=1`)).status).toBe(200);
    expect((await exchange(`${base}/API/Data/`)).status).toBe(200);
    for (const path of ["/api/data", "/api/data/", "/Api/Data?y=2", "/api/data?x=1"]) {
      expect((await exchange(`${base}${path}`)).status).toBe(429);
    }
  });

  it("IPv6 addresses of one /64 count together", async () => {
    const { base, client } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } })],
    });
    client.address = "2001:db8:1:2::1";
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    client.address = "2001:db8:1:2:aaaa:bbbb:cccc:dddd";
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    client.address = "2001:db8:1:2:ffff::9";
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
    client.address = "2001:db8:1:3::1";
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
  });
});

describe("the device key", () => {
  const perDevice = limitRule(1, { limit: { requests: 2, window_s: 60, key: "device", count: "requests" } });
  const perAddress = limitRule(2, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } });
  const get = (base: string, attestation?: string) =>
    exchange(`${base}/api/data`, attestation === undefined ? {} : { headers: { "ar-attestation": attestation } });

  it("a device-keyed limit counts per attested device, wherever the device comes from", async () => {
    const { base, tokenOf, client, events } = await setup({ limit_rules: [perDevice] });
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(200);
    client.address = OTHER_ADDRESS;
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(200);
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(429);
    // Another device behind the same address has its own count.
    expect((await get(base, tokenOf(DEVICE_B))).status).toBe(200);
    const seen = await events(4);
    expect(seen.map((event) => event.attestation?.status)).toEqual(["valid", "valid", "valid", "valid"]);
  });

  it("without a valid token a device-keyed limit counts the address: missing, forged and expired tokens alike", async () => {
    const { base, tokenOf, clock } = await setup({ limit_rules: [perDevice] });
    const valid = tokenOf(DEVICE_A);
    const forged = `${valid.slice(0, valid.lastIndexOf("."))}.${tokenOf(DEVICE_B).split(".")[2]}`;
    expect((await get(base)).status).toBe(200);
    expect((await get(base, forged)).status).toBe(200);
    expect((await get(base, "not-a-token")).status).toBe(429);
    expect((await get(base)).status).toBe(429);
    const old = tokenOf(DEVICE_B);
    clock.now += 400_000; // the token expired; the window cleared
    expect((await get(base, old)).status).toBe(200);
    expect((await get(base)).status).toBe(200);
    expect((await get(base, old)).status).toBe(429);
  });

  it("an ip-keyed limit cannot be escaped with a token, valid or forged, nor by dropping it", async () => {
    const { base, tokenOf } = await setup({ limit_rules: [perAddress] });
    const valid = tokenOf(DEVICE_A);
    expect((await get(base, valid)).status).toBe(200);
    expect((await get(base)).status).toBe(200);
    expect((await get(base)).status).toBe(429);
    expect((await get(base, valid)).status).toBe(429);
    expect((await get(base, tokenOf(DEVICE_B))).status).toBe(429);
    expect((await get(base, "forged")).status).toBe(429);
  });

  it("a device over its limit that drops the token is refused: the address counted its requests too", async () => {
    const { base, tokenOf } = await setup({ limit_rules: [perDevice] });
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(200);
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(200);
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(429);
    expect((await get(base)).status).toBe(429);
    expect((await get(base, "forged")).status).toBe(429);
    expect((await get(base, tokenOf(DEVICE_A))).status).toBe(429);
  });

  it("minting device ids behind one address is refused at 5 times the limit", async () => {
    const { base, tokenOf, client, events } = await setup({ limit_rules: [perDevice] });
    const device = (n: number): string => `dev_${n.toString(16).padStart(24, "0")}`;
    const statuses: number[] = [];
    for (let n = 1; n <= 12; n++) statuses.push((await get(base, tokenOf(device(n)))).status);
    expect(statuses).toEqual([...Array(10).fill(200), 429, 429]);
    // A device behind another address is served.
    client.address = OTHER_ADDRESS;
    expect((await get(base, tokenOf(device(1)))).status).toBe(200);
    const seen = await events(13);
    expect(seen[10]?.decision).toMatchObject({ action: "throttle", mode: "enforce", rule_id: perDevice.id });
  });
});

describe("the counter store option", () => {
  it("uses the store given as `counterStore`", async () => {
    const inner = new MemoryCounterStore();
    const seen: string[] = [];
    const store: CounterStore = {
      hit(key, windowMs, now) {
        seen.push("hit");
        return inner.hit(key, windowMs, now);
      },
      peek(key, windowMs, now) {
        seen.push("peek");
        return inner.peek(key, windowMs, now);
      },
      size: () => inner.size(),
    };
    const { base } = await setup(
      { limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 30, key: "ip", count: "requests" } })] },
      { config: { counterStore: store } },
    );
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    const refused = await exchange(`${base}/api/data`);
    expect(refused.status).toBe(429);
    // A store without `retryAfterMs`: the whole window.
    expect(Object.fromEntries(refused.headers)["retry-after"]).toBe("30");
    expect(seen).toEqual(["peek", "hit", "peek"]);
    expect(inner.size()).toBe(1);
  });

  it("a store that is not a counter store is replaced by the in-memory one, with one warning", async () => {
    const warnings: string[] = [];
    const { base } = await setup(
      { limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 30, key: "ip", count: "requests" } })] },
      {
        config: {
          counterStore: { hit: "no" } as unknown as CounterStore,
          logger: { warn: (message) => void warnings.push(message) },
        },
      },
    );
    expect(warnings.filter((line) => line.includes("counterStore"))).toHaveLength(1);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
  });

  it("a store that throws fails open: every request is served and the errors are counted", async () => {
    const store: CounterStore = {
      hit: () => {
        throw new Error("store down");
      },
      peek: () => {
        throw new Error("store down");
      },
      size: () => 0,
    };
    const bare = await setup({}, { withShield: false });
    const { base, shield, events } = await setup(
      {
        limit_rules: [
          limitRule(1, { limit: { requests: 1, window_s: 30, key: "ip", count: "requests" } }),
          limitRule(2, { path: "/login", limit: { requests: 1, window_s: 30, key: "ip", count: "failures" } }),
        ],
      },
      { config: { counterStore: store } },
    );
    const expected = await exchange(`${bare.base}/api/data`);
    for (let i = 0; i < 3; i++) expect(await exchange(`${base}/api/data`)).toEqual(expected);
    for (let i = 0; i < 3; i++) expect((await login(base, "wrong")).status).toBe(401);
    const seen = await events(6);
    expect(seen.every((event) => event.decision.action === "allow")).toBe(true);
    expect(shield.stats().internalErrors).toBeGreaterThanOrEqual(6);
  });

  it("a store that answers nonsense, or asynchronously, never refuses a request", async () => {
    const store = {
      hit: () => Promise.resolve(1_000_000),
      peek: () => Promise.resolve(1_000_000),
      size: () => 0,
    } as unknown as CounterStore;
    const { base } = await setup(
      { limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 30, key: "ip", count: "requests" } })] },
      { config: { counterStore: store } },
    );
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
  });
});

describe("fail open and privacy", () => {
  it("a client without an address is not limited", async () => {
    const { base, client } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
    });
    client.address = undefined;
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
    // An address that is there but cannot be parsed is counted by its text (A7 F7): see the test of F7 below.
  });

  it("a response that has already started cannot be throttled: the request proceeds and the error is counted", async () => {
    const { shield, events } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
    });
    const app = express();
    app.use((_req, res, next) => {
      res.setHeader("x-early", "1");
      res.flushHeaders();
      next();
    });
    app.use(shield.express());
    app.get("/api/data", (_req, res) => void res.end("served"));
    const listening = await listen(app);
    open.push(listening);
    expect((await exchange(`${listening.base}/api/data`)).body).toBe("served");
    const second = await exchange(`${listening.base}/api/data`);
    expect(second.status).toBe(200);
    expect(second.body).toBe("served");
    expect(shield.stats().internalErrors).toBe(1);
    const seen = await events(2);
    expect(seen[1]?.decision.action).toBe("allow");
  });

  it("a clock that returns nonsense or throws refuses nothing", async () => {
    const { base, clock } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } })],
    });
    clock.now = Number.NaN;
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
    Object.defineProperty(clock, "now", {
      get() {
        throw new Error("clock");
      },
    });
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
  });

  it("no address, device id or token is in an Event, a warning, a log line or the stats", async () => {
    const { base, tokenOf, events, leaked } = await setup({
      limit_rules: [
        limitRule(1, { limit: { requests: 1, window_s: 60, key: "ip", count: "requests" } }),
        limitRule(2, { mode: "monitor", limit: { requests: 1, window_s: 60, key: "device", count: "requests" } }),
        limitRule(3, { path: "/login", limit: { requests: 1, window_s: 60, key: "device", count: "failures" } }),
      ],
    });
    const valid = tokenOf(DEVICE_A);
    for (let i = 0; i < 3; i++) await exchange(`${base}/api/data`, { headers: { "ar-attestation": valid } });
    for (let i = 0; i < 3; i++) await login(base, "wrong", { "ar-attestation": valid });
    const seen = await events(6);
    expect(seen.filter((event) => event.decision.action === "throttle").length).toBeGreaterThanOrEqual(3);
    const text = leaked();
    expect(text).not.toContain(ADDRESS);
    expect(text).not.toContain(DEVICE_A);
    expect(text).not.toContain(DEVICE_A.slice(4));
    expect(text).not.toContain(valid.split(".")[2]);
    // Only the network prefix and the actor hash of the client are recorded, as before this slice.
    expect(seen[0]?.actor.ip_prefix).toBe("203.0.113.0/24");
  });
});

// --- Amendment A7: the review's findings, through the adapter ------------------------------------------------------

/**
 * One raw HTTP/1.1 request on its own connection (as the reviewer's scripts send them): the status. A connection
 * the listen backlog refused before anything was answered is tried again (up to 5 times): it never reached Shield.
 */
function rawPost(port: number, path: string, body: string, tries = 5): Promise<number> {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, "127.0.0.1");
    let data = "";
    let sent = false;
    socket.on("connect", () => {
      sent = true;
      socket.write(
        `POST ${path} HTTP/1.1\r\nhost: x.test\r\nconnection: close\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
      );
    });
    socket.on("data", (chunk) => {
      data += chunk.toString("latin1");
    });
    const status = (): number => Number(/^HTTP\/1\.1 (\d+)/.exec(data)?.[1] ?? 0);
    // The server closes a connection whose request body it did not read once it has answered (any 403 or 429 of
    // Shield): the client may see a reset after the answer. The answer counts.
    socket.on("error", (error) => {
      if (status() !== 0) resolve(status());
      else if (!sent && tries > 1) {
        setTimeout(() => rawPost(port, path, body, tries - 1).then(resolve, reject), 20);
      } else reject(error);
    });
    socket.on("close", (hadError) => {
      if (!hadError) resolve(status());
    });
  });
}

describe("A7 F1: parallel guesses under a failure limit", () => {
  const protection = limitRule(1, {
    path: "/slow-login",
    methods: ["POST"],
    limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
  });

  it("t3 D: 1,000 guesses in parallel, answered only after all arrived: at most 10 reach the handler", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let arrived = 0;
    const { port, calls } = await setup(
      { limit_rules: [protection] },
      {
        routes: (app, seen) =>
          app.post("/slow-login", (_req, res) => {
            arrived += 1;
            void gate.then(() => {
              seen.push("guess");
              res.status(401).json({ error: "bad credentials" });
            });
          }),
      },
    );
    const answers: Promise<number>[] = [];
    let refused = 0;
    for (let i = 0; i < 1_000; i += 25) {
      for (let k = 0; k < 25; k++) {
        const answer = rawPost(port, "/slow-login", '{"password":"guess"}');
        void answer.then((status) => {
          if (status === 429) refused += 1;
        });
        answers.push(answer);
      }
      await sleep(10);
    }
    // Every guess is either at the handler or already refused.
    for (let i = 0; i < 2_000 && arrived + refused < 1_000; i++) await sleep(10);
    release();
    const statuses = await Promise.all(answers);
    expect(arrived).toBe(10);
    expect(calls).toHaveLength(10);
    expect(statuses.filter((status) => status === 401)).toHaveLength(10);
    expect(statuses.filter((status) => status === 429)).toHaveLength(990);
    expect(await rawPost(port, "/slow-login", '{"password":"next"}')).toBe(429);
  }, 30_000);

  it("a slot is released when the client aborts: the limit is not used up by connections that went away", async () => {
    let held: (() => void)[] = [];
    const { port, calls, base } = await setup(
      { limit_rules: [{ ...protection, limit: { ...protection.limit, requests: 2 } }] },
      {
        routes: (app, seen) =>
          app.post("/slow-login", (_req, res) => {
            seen.push("guess");
            held.push(() => res.status(401).json({ error: "bad" }));
          }),
      },
    );
    // Two requests hold both slots, then their clients go away.
    const sockets = [0, 1].map(() => {
      const socket = net.connect(port, "127.0.0.1");
      socket.write(
        "POST /slow-login HTTP/1.1\r\nhost: x.test\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
      );
      return socket;
    });
    for (let i = 0; i < 200 && calls.length < 2; i++) await sleep(5);
    expect(calls).toHaveLength(2);
    expect(await rawPost(port, "/slow-login", "{}")).toBe(429);
    for (const socket of sockets) socket.destroy();
    held = [];
    await sleep(50);
    // Both slots are free again and nothing was counted: two more guesses reach the handler.
    const next = [rawPost(port, "/slow-login", "{}"), rawPost(port, "/slow-login", "{}")];
    for (let i = 0; i < 200 && calls.length < 4; i++) await sleep(5);
    expect(calls).toHaveLength(4);
    for (const answer of held) answer();
    expect(await Promise.all(next)).toEqual([401, 401]);
    expect((await exchange(`${base}/slow-login`, { method: "POST" })).status).toBe(429);
  });
});

describe("A7 F2, F3, F6, F7 through the adapter", () => {
  it("t3b F: under 10 per 60 s, no real 60 s window holds more than 10 accepted requests", async () => {
    const { base, clock } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 10, window_s: 60, key: "ip", count: "requests" } })],
    });
    const start = clock.now;
    const accepted: number[] = [];
    const go = async (at: number) => {
      clock.now = start + at;
      if ((await exchange(`${base}/api/data`)).status === 200) accepted.push(at);
    };
    await go(0);
    for (let i = 0; i < 20; i++) await go(59_900);
    for (let t = 60_000; t <= 119_800; t += 400) await go(t);
    let worst = 0;
    for (const a of accepted) worst = Math.max(worst, accepted.filter((x) => x >= a && x < a + 60_000).length);
    expect(worst).toBeLessThanOrEqual(10);
  });

  it("t3b H: requests one Rule refuses do not count on another", async () => {
    const { base, clock } = await setup({
      limit_rules: [
        limitRule(1, { path: "/**", limit: { requests: 20, window_s: 3_600, key: "ip", count: "requests" } }),
        limitRule(2, {
          methods: ["POST"],
          path: "/login",
          limit: { requests: 3, window_s: 10, key: "ip", count: "requests" },
        }),
      ],
    });
    const statuses: number[] = [];
    for (let i = 0; i < 25; i++) statuses.push((await login(base, "wrong")).status);
    expect(statuses).toEqual([...Array(3).fill(401), ...Array(22).fill(429)]);
    clock.now += 22_000;
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
  });

  it("t1, F6: a CORS preflight is not counted, and is refused 429 once the client is over", async () => {
    const { base, calls } = await setup({
      limit_rules: [limitRule(1, { limit: { requests: 2, window_s: 60, key: "ip", count: "requests" } })],
    });
    const preflight = {
      method: "OPTIONS",
      headers: { "access-control-request-method": "GET", origin: "http://a.test" },
    };
    for (let i = 0; i < 3; i++) expect((await exchange(`${base}/api/data`, preflight)).status).toBe(204);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/api/data`)).status).toBe(429);
    const refused = await exchange(`${base}/api/data`, preflight);
    expect(refused.status).toBe(429);
    expect(Object.fromEntries(refused.headers)["retry-after"]).toBe("61");
    expect(calls).toEqual(["options", "options", "options", "data", "data"]);
  });

  it("t2 A, F7: an address Shield cannot parse is limited by its text, with one warning that names no address", async () => {
    const warnings: string[] = [];
    const { base, client, leaked } = await setup(
      { limit_rules: [limitRule(1, { limit: { requests: 3, window_s: 60, key: "ip", count: "requests" } })] },
      { config: { logger: { warn: (message) => void warnings.push(message) } } },
    );
    for (const address of ["banana", "203.0.113.9:4444", "203.0.113.9, 10.0.0.1"]) {
      client.address = address;
      const statuses: number[] = [];
      for (let i = 0; i < 5; i++) statuses.push((await exchange(`${base}/api/data`)).status);
      expect(statuses, address).toEqual([200, 200, 200, 429, 429]);
    }
    const lines = warnings.filter((line) => line.includes("could not be parsed"));
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toMatch(/banana|203\.0\.113|4444/);
    expect(leaked()).not.toContain("banana");
    client.address = undefined;
    for (let i = 0; i < 5; i++) expect((await exchange(`${base}/api/data`)).status).toBe(200);
  });
});

describe("A7: limit_rule_id on the Event", () => {
  const protection = limitRule(1, {
    path: "/login",
    methods: ["POST"],
    limit: { requests: 2, window_s: 300, key: "ip", count: "failures" },
  });

  it("names the failure-counting limit Rule of every request it matched, throttled or not; null otherwise", async () => {
    const { base, events } = await setup({
      limit_rules: [limitRule(2, { path: "/api/data" }), protection],
    });
    expect((await login(base, "wrong")).status).toBe(401);
    expect((await login(base, "correct")).status).toBe(200);
    expect((await login(base, "wrong")).status).toBe(401);
    expect((await login(base, "wrong")).status).toBe(429);
    expect((await exchange(`${base}/api/data`)).status).toBe(200);
    expect((await exchange(`${base}/nothing`)).status).toBe(404);
    const seen = await events(6);
    expect(seen.map((event) => [event.request.status, event.decision.limit_rule_id])).toEqual([
      [401, protection.id],
      [200, protection.id],
      [401, protection.id],
      [429, protection.id],
      [200, null],
      [404, null],
    ]);
    // Shield always sends the member, null included.
    expect(seen.every((event) => "limit_rule_id" in event.decision)).toBe(true);
  });

  it("is set by a monitor failure limit too, and not for a request a Rule blocked before the limits", async () => {
    const { base, events } = await setup({
      rules: [rule(1, { path: "/login", methods: ["DELETE"] })],
      limit_rules: [{ ...protection, mode: "monitor", methods: [] }],
    });
    expect((await login(base, "wrong")).status).toBe(401);
    expect((await exchange(`${base}/login`, { method: "DELETE" })).status).toBe(403);
    const seen = await events(2);
    expect(seen.map((event) => event.decision.limit_rule_id)).toEqual([protection.id, null]);
  });
});
