// Slice 04, contract P4, through the Express adapter with a real `express.json({ verify: shield.verifyBody })`:
// every Event carries `signature { status, body }`; a body mismatch is refused with 403 before the handler; a
// requirement Rule applies in monitor and enforce only when the requirement is not met; unrelated routes are never
// changed; no signature, nonce, hash, token or body ever reaches an Event or a log line.
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";
import {
  type BundlePayload,
  type BundleRule,
  EMPTY_CONTENT_SHA256,
  EventBatchSchema,
  type ShieldEvent,
} from "@antireverse/protocol";
import { jwkThumbprint, signRequestForTest } from "@antireverse/protocol/server";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createShield, type Shield, type ShieldConfig } from "../src/index.ts";
import { APP_ID, claims, createAttestationKey, token } from "./attestation-helpers.ts";
import { exchange, KEY, type Listening, listen } from "./helpers.ts";
import { createSigner, type FakeApi, fakeApi, NOW, payload, rule, signed } from "./policy-helpers.ts";

const signer = createSigner();
const attestationKey = createAttestationKey();
const stranger = createAttestationKey();
const CLOCK = NOW + 60_000;
const CLOCK_S = Math.floor(CLOCK / 1000);

function sessionKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: exported.x as string, y: exported.y as string };
  return { privateKey, jwk, jkt: jwkThumbprint(jwk) };
}
const session = sessionKey();
const otherSession = sessionKey();
const JTI = "00000000000000000000000000000abc";
const sha = (text: string): string => createHash("sha256").update(text, "utf8").digest("base64url");

/** A token for `session` (with cnf.jwk unless `withJwk` is false). */
function sessionToken(options: { withJwk?: boolean; key?: typeof attestationKey } = {}): string {
  const cnf = options.withJwk === false ? { jkt: session.jkt } : { jkt: session.jkt, jwk: session.jwk };
  return token(options.key ?? attestationKey, claims(CLOCK_S, { jti: JTI, cnf }));
}
const TOKEN = sessionToken();

let nonceCounter = 0;
/** A fresh 22-character canonical nonce. */
function freshNonce(): string {
  nonceCounter += 1;
  const bytes = Buffer.alloc(16);
  bytes.writeUInt32BE(nonceCounter, 12);
  bytes.writeUInt32BE(process.pid, 0);
  return bytes.toString("base64url");
}

function signedHeaders(options: {
  method: string;
  target: string;
  body?: string;
  t?: number;
  n?: string;
  privateKey?: KeyObject;
  token?: string;
  hash?: string;
  /** The content type signed (review F1); the caller sends it. Default "": none sent. */
  contentType?: string;
}): Record<string, string> {
  const hash = options.hash ?? sha(options.body ?? "");
  return {
    "ar-attestation": options.token ?? TOKEN,
    "ar-signature": signRequestForTest({
      privateKey: options.privateKey ?? session.privateKey,
      method: options.method,
      target: options.target,
      contentType: options.contentType ?? "",
      contentSha256: hash,
      jti: JTI,
      t: options.t ?? CLOCK_S,
      n: options.n ?? freshNonce(),
    }),
    "ar-content-sha256": hash,
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
  api: FakeApi;
  base: string;
  calls: string[];
  events(count: number): Promise<ShieldEvent[]>;
  leaked(): string;
}

async function setup(
  bundle: Partial<BundlePayload> = {},
  config: Partial<ShieldConfig> = {},
  withShield = true,
  after?: (app: express.Express, shield: Shield) => void,
): Promise<Setup> {
  const api = fakeApi();
  const warnings: string[] = [];
  const shield = createShield({
    key: KEY,
    endpoint: "http://api.test",
    transport: api.transport,
    policyPublicKey: signer.publicKey,
    policyPollIntervalMs: 3_600_000,
    flushIntervalMs: 3_600_000,
    now: () => CLOCK,
    logger: { warn: (message) => void warnings.push(message) },
    ...config,
  });
  shields.push(shield);
  api.publish(
    signed(signer, payload(KEY, { app_id: APP_ID, attestation_keys: [attestationKey.entry], rules: [], ...bundle })),
  );
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();

  const calls: string[] = [];
  const app = express();
  app.disable("x-powered-by");
  app.disable("etag");
  if (withShield) app.use(shield.express());
  app.use(withShield ? express.json({ verify: shield.verifyBody }) : express.json());
  app.get("/api/data", (_req, res) => {
    calls.push("data");
    res.setHeader("x-data", "yes");
    res.json({ items: [1, 2, 3] });
  });
  app.get("/api/secure", (_req, res) => {
    calls.push("secure");
    res.json({ secure: true });
  });
  app.post("/api/orders", (req, res) => {
    calls.push(`orders ${JSON.stringify(req.body)}`);
    res.status(201).json({ ok: true });
  });
  app.post("/api/notes", express.text(), (req, res) => {
    calls.push(`notes ${String(req.body)}`);
    res.json({ ok: true });
  });
  app.post("/api/raw", (req, res) => {
    // No parser for this route's types: the body is never read by a hook.
    req.resume();
    req.on("end", () => {
      calls.push("raw");
      res.json({ ok: true });
    });
  });
  app.use((_req, res) => void res.status(404).send("no such page"));
  after?.(app, shield);
  const listening = await listen(app);
  open.push(listening);

  const recorded = (): number => shield.stats().buffered + shield.stats().sent + shield.stats().dropped;
  return {
    shield,
    api,
    base: listening.base,
    calls,
    async events(count) {
      for (let i = 0; i < 400 && recorded() < count; i++) await sleep(5);
      await shield.flush();
      return api.posts.flatMap((request) => EventBatchSchema.parse(JSON.parse(request.body ?? "")).events);
    },
    leaked: () =>
      [
        ...api.posts.map((request) => `${JSON.stringify(request.headers)} ${request.body ?? ""}`),
        ...warnings,
        ...consoleLines,
        shield.stats().lastPolicyError ?? "",
        shield.stats().lastError ?? "",
      ].join("\n"),
  };
}

const JSON_TYPE = { "content-type": "application/json" };

describe("the signature on every Event", () => {
  it("missing without ar-signature: body null; the response is the one without Shield", async () => {
    const withShield = await setup();
    const without = await setup({}, {}, false);
    const a = await exchange(`${withShield.base}/api/data`);
    const b = await exchange(`${without.base}/api/data`);
    expect(a).toEqual(b);
    const [event] = await withShield.events(1);
    expect(event?.signature).toEqual({ status: "missing", body: null });
  });

  it("valid with body none for a signed GET; the target is the raw request target with its query", async () => {
    const s = await setup();
    const target = "/api/data?q=a%20b&x=1";
    const response = await exchange(`${s.base}${target}`, { headers: signedHeaders({ method: "GET", target }) });
    expect(response.status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "valid", body: "none" });
    expect(event?.attestation?.status).toBe("valid");
  });

  it("replayed: the same headers sent again", async () => {
    const s = await setup();
    const headers = signedHeaders({ method: "GET", target: "/api/data" });
    await exchange(`${s.base}/api/data`, { headers });
    await exchange(`${s.base}/api/data`, { headers });
    const events = await s.events(2);
    expect(events.map((e) => e.signature?.status)).toEqual(["valid", "replayed"]);
  });

  it("stale beyond 60 s in both directions", async () => {
    const s = await setup();
    for (const t of [CLOCK_S - 61, CLOCK_S + 61]) {
      await exchange(`${s.base}/api/data`, { headers: signedHeaders({ method: "GET", target: "/api/data", t }) });
    }
    const events = await s.events(2);
    expect(events.map((e) => e.signature)).toEqual([
      { status: "stale", body: "none" },
      { status: "stale", body: "none" },
    ]);
  });

  it.each([
    ["no token", () => ({ ...signedHeaders({ method: "GET", target: "/api/data" }), "ar-attestation": "" })],
    [
      "a token without cnf.jwk",
      () => signedHeaders({ method: "GET", target: "/api/data", token: sessionToken({ withJwk: false }) }),
    ],
    [
      "a token signed by a key not in the bundle",
      () => signedHeaders({ method: "GET", target: "/api/data", token: sessionToken({ key: stranger }) }),
    ],
    [
      "a signature by another session key",
      () => signedHeaders({ method: "GET", target: "/api/data", privateKey: otherSession.privateKey }),
    ],
    ["a signature over another target", () => signedHeaders({ method: "GET", target: "/api/data?x=1" })],
    [
      "a malformed content hash header",
      () => ({ ...signedHeaders({ method: "GET", target: "/api/data" }), "ar-content-sha256": "not-a-hash" }),
    ],
    [
      "a GET whose hash is not the empty hash",
      () => signedHeaders({ method: "GET", target: "/api/data", hash: sha("x") }),
    ],
  ])("invalid for %s; the response is unchanged", async (_name, headersOf) => {
    const s = await setup();
    const headers: Record<string, string> = headersOf();
    if (headers["ar-attestation"] === "") delete (headers as Record<string, string | undefined>)["ar-attestation"];
    const response = await exchange(`${s.base}/api/data`, { headers });
    expect(response.status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "invalid", body: "none" });
  });

  it("an invalid request does not burn its nonce: the genuine request with that nonce is valid", async () => {
    const s = await setup();
    const n = freshNonce();
    await exchange(`${s.base}/api/data`, {
      headers: signedHeaders({ method: "GET", target: "/api/data", n, privateKey: otherSession.privateKey }),
    });
    await exchange(`${s.base}/api/data`, { headers: signedHeaders({ method: "GET", target: "/api/data", n }) });
    const events = await s.events(2);
    expect(events.map((e) => e.signature?.status)).toEqual(["invalid", "valid"]);
  });
});

describe("the body through express.json({ verify: shield.verifyBody })", () => {
  it("checked when the bytes have the signed hash; the handler gets the parsed body", async () => {
    const s = await setup();
    const body = '{"item":"book","qty":2}';
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: "application/json" }),
      },
      body,
    });
    expect(response.status).toBe(201);
    expect(s.calls).toEqual(['orders {"item":"book","qty":2}']);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "valid", body: "checked" });
  });

  it("mismatch on a route without a requirement: the handler runs; recorded mismatch and invalid", async () => {
    const s = await setup();
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body: '{"qty":1}', contentType: "application/json" }),
      },
      body: '{"qty":9}',
    });
    expect(response.status).toBe(201);
    expect(s.calls).toEqual(['orders {"qty":9}']);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "invalid", body: "mismatch" });
    expect(event?.decision).toMatchObject({ action: "allow", rule_id: null });
  });

  it("unchecked when the parser does not run for the body (another content type)", async () => {
    const s = await setup();
    const body = "plain words";
    const response = await exchange(`${s.base}/api/notes`, {
      method: "POST",
      headers: {
        "content-type": "text/plain",
        ...signedHeaders({ method: "POST", target: "/api/notes", body, contentType: "text/plain" }),
      },
      body,
    });
    expect(response.status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "valid", body: "unchecked" });
  });

  it("an unsigned body passes the hook untouched", async () => {
    const s = await setup();
    const response = await exchange(`${s.base}/api/orders`, { method: "POST", headers: JSON_TYPE, body: '{"a":1}' });
    expect(response.status).toBe(201);
    expect(s.calls).toEqual(['orders {"a":1}']);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "missing", body: null });
  });

  it("an empty body (content-length 0) is none and must carry the empty hash", async () => {
    const s = await setup();
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body: "", contentType: "application/json" }),
      },
      body: "",
    });
    expect(response.status).toBe(201);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "valid", body: "none" });
  });
});

const ENFORCE_ORDERS: BundleRule = rule(20, { path: "/api/orders", methods: ["POST"], mode: "enforce" });
const ENFORCE_SECURE: BundleRule = rule(21, { path: "/api/secure", mode: "enforce" });
const MONITOR_SECURE: BundleRule = rule(22, { path: "/api/secure", mode: "monitor" });
const BLOCK_BODY = '{"error":"request_blocked"}';

describe("requirement Rules (signature_rules)", () => {
  it("enforce: an unsigned request is answered 403 with the block body; a signed one proceeds", async () => {
    const s = await setup({ signature_rules: [ENFORCE_SECURE] });
    const blocked = await exchange(`${s.base}/api/secure`);
    expect(blocked.status).toBe(403);
    expect(blocked.body).toBe(BLOCK_BODY);
    const allowed = await exchange(`${s.base}/api/secure`, {
      headers: signedHeaders({ method: "GET", target: "/api/secure" }),
    });
    expect(allowed.status).toBe(200);
    expect(s.calls).toEqual(["secure"]);
    const events = await s.events(2);
    expect(events[0]?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ENFORCE_SECURE.id });
    expect(events[0]?.request.route).toBe("/api/secure");
    expect(events[0]?.signature).toEqual({ status: "missing", body: null });
    expect(events[1]?.decision).toMatchObject({ action: "allow", rule_id: null });
    expect(events[1]?.signature).toEqual({ status: "valid", body: "none" });
  });

  it("enforce: replayed, stale and invalid requests are blocked", async () => {
    const s = await setup({ signature_rules: [ENFORCE_SECURE] });
    const headers = signedHeaders({ method: "GET", target: "/api/secure" });
    expect((await exchange(`${s.base}/api/secure`, { headers })).status).toBe(200);
    expect((await exchange(`${s.base}/api/secure`, { headers })).status).toBe(403);
    const stale = signedHeaders({ method: "GET", target: "/api/secure", t: CLOCK_S - 100 });
    expect((await exchange(`${s.base}/api/secure`, { headers: stale })).status).toBe(403);
    const forged = signedHeaders({ method: "GET", target: "/api/secure", privateKey: otherSession.privateKey });
    expect((await exchange(`${s.base}/api/secure`, { headers: forged })).status).toBe(403);
    expect(s.calls).toEqual(["secure"]);
  });

  it("enforce matches the canonical form of the path too", async () => {
    const s = await setup({ signature_rules: [ENFORCE_SECURE] });
    const response = await exchange(`${s.base}/api/%73ecure`);
    expect(response.status).toBe(403);
  });

  it("monitor: an unsigned request proceeds and the Event names the Rule in Monitor mode", async () => {
    const s = await setup({ signature_rules: [MONITOR_SECURE] });
    const response = await exchange(`${s.base}/api/secure`);
    expect(response.status).toBe(200);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "monitor", rule_id: MONITOR_SECURE.id });
  });

  it("monitor: a signed request records no Rule", async () => {
    const s = await setup({ signature_rules: [MONITOR_SECURE] });
    await exchange(`${s.base}/api/secure`, { headers: signedHeaders({ method: "GET", target: "/api/secure" }) });
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "allow", rule_id: null });
  });

  it("routes the Rule does not name are unchanged, signed or not", async () => {
    const s = await setup({ signature_rules: [ENFORCE_SECURE, ENFORCE_ORDERS] });
    const without = await setup({}, {}, false);
    expect(await exchange(`${s.base}/api/data`)).toEqual(await exchange(`${without.base}/api/data`));
    // ENFORCE_ORDERS names POST only.
    const get = await exchange(`${s.base}/api/orders`);
    expect(get.status).toBe(404);
  });

  it("enforce on a route with a body, without bodyVerified: blocked even when signed (the body cannot be checked in time)", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] });
    const body = '{"qty":1}';
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: "application/json" }),
      },
      body,
    });
    expect(response.status).toBe(403);
    expect(response.body).toBe(BLOCK_BODY);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ENFORCE_ORDERS.id });
    expect(event?.signature).toEqual({ status: "valid", body: "unchecked" });
  });

  it("enforce on a route with a body, with bodyVerified: defers to the hook — checked proceeds", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, { bodyVerified: { types: ["application/json"] } });
    const body = '{"qty":1}';
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: "application/json" }),
      },
      body,
    });
    expect(response.status).toBe(201);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "allow", rule_id: null });
    expect(event?.signature).toEqual({ status: "valid", body: "checked" });
  });

  it("enforce with bodyVerified: a mismatch is refused by the hook and the Event names the Rule", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, { bodyVerified: { types: ["application/json"] } });
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body: '{"qty":1}', contentType: "application/json" }),
      },
      body: '{"qty":5}',
    });
    expect(response.status).toBe(403);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ENFORCE_ORDERS.id });
    expect(event?.request.route).toBe("/api/orders");
    expect(event?.signature).toEqual({ status: "invalid", body: "mismatch" });
  });

  it("monitor with bodyVerified: a mismatch lets the handler run; the Event names the Rule in Monitor mode", async () => {
    const monitorOrders = rule(23, { path: "/api/orders", methods: ["POST"], mode: "monitor" });
    const s = await setup({ signature_rules: [monitorOrders] }, { bodyVerified: { types: ["application/json"] } });
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body: '{"qty":1}', contentType: "application/json" }),
      },
      body: '{"qty":5}',
    });
    expect(response.status).toBe(201);
    expect(s.calls).toEqual(['orders {"qty":5}']);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "monitor", rule_id: monitorOrders.id });
    expect(event?.signature).toEqual({ status: "invalid", body: "mismatch" });
  });

  it("monitor without bodyVerified: a mismatch lets the handler run, Monitor decision recorded", async () => {
    const monitorOrders = rule(24, { path: "/api/orders", methods: ["POST"], mode: "monitor" });
    const s = await setup({ signature_rules: [monitorOrders] });
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body: '{"qty":1}', contentType: "application/json" }),
      },
      body: '{"qty":6}',
    });
    expect(response.status).toBe(201);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "monitor", rule_id: monitorOrders.id });
    expect(event?.signature).toEqual({ status: "invalid", body: "mismatch" });
  });

  it("enforce with bodyVerified: an unsigned request with a body is still blocked at once", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, { bodyVerified: { types: ["application/json"] } });
    const response = await exchange(`${s.base}/api/orders`, { method: "POST", headers: JSON_TYPE, body: "{}" });
    expect(response.status).toBe(403);
    expect(s.calls).toEqual([]);
  });

  it("a plain Rule still blocks first, signed or not", async () => {
    const s = await setup({
      rules: [rule(1, { path: "/api/secure", mode: "enforce" })],
      signature_rules: [MONITOR_SECURE],
    });
    const response = await exchange(`${s.base}/api/secure`, {
      headers: signedHeaders({ method: "GET", target: "/api/secure" }),
    });
    expect(response.status).toBe(403);
    const [event] = await s.events(1);
    expect(event?.decision.rule_id).toBe(rule(1).id);
  });
});

const JSON_ONLY = { bodyVerified: { types: ["application/json"] } };

describe("review F1: bodyVerified lists media types; other bodies under an enforced requirement are blocked", () => {
  it.each<[string, unknown]>([
    ["true (the old form)", true],
    ["false", false],
    ["a list without the object", ["application/json"]],
    ["an object without types", {}],
    ["types that is not a list", { types: "application/json" }],
    ["a type that is not a string", { types: [7] }],
    ["an empty type", { types: [" "] }],
    ["a type that is not type/subtype", { types: ["json"] }],
    ["a wildcard", { types: ["application/*"] }],
  ])("createShield throws a TypeError at startup for bodyVerified %s", (_name, bodyVerified) => {
    const config = { key: KEY, endpoint: "http://api.test", bodyVerified } as unknown as ShieldConfig;
    expect(() => createShield(config)).toThrow(TypeError);
    expect(() => createShield(config)).toThrow(/bodyVerified/);
    // A configuration error is reported even where Shield would be disabled.
    expect(() => createShield({ ...config, disabled: true })).toThrow(TypeError);
  });

  it('accepts { types: [] }, and media types in any case and with parameters (compared before ";")', async () => {
    expect(() =>
      createShield({ key: KEY, endpoint: "http://api.test", disabled: true, bodyVerified: { types: [] } }),
    ).not.toThrow();
    const s = await setup(
      { signature_rules: [ENFORCE_ORDERS] },
      { bodyVerified: { types: [" Application/JSON; charset=utf-8 "] } },
    );
    const body = '{"qty":1}';
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: "application/json" }),
      },
      body,
    });
    expect(response.status).toBe(201);
  });

  it("a listed type with parameters and in another case defers to the hook (checked, proceeds)", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY);
    const body = '{"qty":3}';
    const type = "Application/JSON; charset=utf-8";
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        "content-type": type,
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: type }),
      },
      body,
    });
    expect(response.status).toBe(201);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "allow", rule_id: null });
    expect(event?.signature).toEqual({ status: "valid", body: "checked" });
  });

  it("a validly signed body of a type not listed is blocked at decision time", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY);
    const body = "qty=1";
    const type = "text/plain";
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        "content-type": type,
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: type }),
      },
      body,
    });
    expect(response.status).toBe(403);
    expect(response.body).toBe(BLOCK_BODY);
    expect(s.calls).toEqual([]);
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ENFORCE_ORDERS.id });
    expect(event?.signature).toEqual({ status: "valid", body: "unchecked" });
  });

  it("a validly signed body without a content type is blocked at decision time", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY);
    const body = '{"qty":1}';
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: signedHeaders({ method: "POST", target: "/api/orders", body, contentType: "" }),
      body: new TextEncoder().encode(body), // bytes: fetch adds no content type
    });
    expect(response.status).toBe(403);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "valid", body: "unchecked" });
  });

  it("a deferred enforced requirement whose hook never ran is recorded as the Rule's block when the response closes", async () => {
    const enforceRaw = rule(25, { path: "/api/raw", methods: ["POST"], mode: "enforce" });
    const s = await setup(
      { signature_rules: [enforceRaw] },
      { bodyVerified: { types: ["application/json", "application/octet-stream"] } },
    );
    const body = "raw bytes";
    const type = "application/octet-stream";
    const response = await exchange(`${s.base}/api/raw`, {
      method: "POST",
      headers: {
        "content-type": type,
        ...signedHeaders({ method: "POST", target: "/api/raw", body, contentType: type }),
      },
      body,
    });
    // The response already went out (Shield could not know the hook would not run) ...
    expect(response.status).toBe(200);
    expect(s.calls).toEqual(["raw"]);
    // ... but the Event says honestly that the requirement was not met.
    const [event] = await s.events(1);
    expect(event?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: enforceRaw.id });
    expect(event?.request.route).toBe("/api/raw");
    expect(event?.signature).toEqual({ status: "valid", body: "unchecked" });
  });

  it("the content type is bound: a body sent with another type than the signed one is invalid and blocked", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY);
    const body = '{"qty":1}';
    const response = await exchange(`${s.base}/api/orders`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...signedHeaders({ method: "POST", target: "/api/orders", body, contentType: "text/plain" }),
      },
      body,
    });
    expect(response.status).toBe(403);
    const [event] = await s.events(1);
    expect(event?.signature).toEqual({ status: "invalid", body: "unchecked" });
  });
});

describe("review F2 and F3: HEAD and CORS preflights", () => {
  it("F2: a requirement Rule for GET applies to HEAD", async () => {
    const getOnly = rule(26, { path: "/api/secure", methods: ["GET"], mode: "enforce" });
    const s = await setup({ signature_rules: [getOnly] });
    const head = await exchange(`${s.base}/api/secure`, { method: "HEAD" });
    expect(head.status).toBe(403);
    expect(s.calls).toEqual([]);
    const signedHead = await exchange(`${s.base}/api/secure`, {
      method: "HEAD",
      headers: signedHeaders({ method: "HEAD", target: "/api/secure" }),
    });
    expect(signedHead.status).toBe(200);
  });

  const PREFLIGHT = { origin: "https://app.example.test", "access-control-request-method": "GET" };

  it("F3: a preflight is exempt from an all-methods enforced requirement; a plain OPTIONS is not", async () => {
    const s = await setup({ signature_rules: [ENFORCE_SECURE] });
    const preflight = await exchange(`${s.base}/api/secure`, { method: "OPTIONS", headers: PREFLIGHT });
    expect(preflight.status).toBe(404); // the application's own answer (its catch-all), not Shield's 403
    const plain = await exchange(`${s.base}/api/secure`, { method: "OPTIONS" });
    expect(plain.status).toBe(403);
    const events = await s.events(2);
    expect(events[0]?.decision).toMatchObject({ action: "allow", rule_id: null });
    expect(events[1]?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ENFORCE_SECURE.id });
  });

  it("F3: a preflight is still subject to plain Rules", async () => {
    const s = await setup({ rules: [rule(2, { path: "/api/secure", mode: "enforce" })] });
    const preflight = await exchange(`${s.base}/api/secure`, { method: "OPTIONS", headers: PREFLIGHT });
    expect(preflight.status).toBe(403);
  });
});

describe("review F6: shield.errorHandler() answers Shield's body refusal with the standard block response", () => {
  const mismatch = (base: string) =>
    exchange(`${base}/api/orders`, {
      method: "POST",
      headers: {
        ...JSON_TYPE,
        ...signedHeaders({ method: "POST", target: "/api/orders", body: '{"qty":1}', contentType: "application/json" }),
      },
      body: '{"qty":7}',
    });

  it("with it: 403, the block body and the same headers as a block at decision time", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY, true, (app, shield) => {
      app.use(shield.errorHandler());
    });
    const refused = await mismatch(s.base);
    const blocked = await exchange(`${s.base}/api/orders`, { method: "POST", headers: JSON_TYPE, body: "{}" });
    expect(blocked.status).toBe(403);
    expect(refused.status).toBe(403);
    expect(refused.body).toBe(BLOCK_BODY);
    expect(refused.headers).toEqual(blocked.headers);
    expect(s.calls).toEqual([]);
  });

  it("without it: still 403 before the handler, but Express renders its own page", async () => {
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY);
    const refused = await mismatch(s.base);
    expect(refused.status).toBe(403);
    expect(refused.body).not.toBe(BLOCK_BODY);
    expect(refused.body).not.toContain("qty"); // never the request body
    expect(s.calls).toEqual([]);
  });

  it("the error carries the block body, expose false and its type, whatever the parser adds", async () => {
    const seen: unknown[] = [];
    const s = await setup({ signature_rules: [ENFORCE_ORDERS] }, JSON_ONLY, true, (app) => {
      app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        seen.push(error);
        const err = error as { status: number; body: string };
        res.status(err.status).type("application/json").send(err.body);
      });
    });
    const refused = await mismatch(s.base);
    expect(refused.body).toBe(BLOCK_BODY);
    expect(seen[0]).toMatchObject({ status: 403, expose: false, type: "entity.verify.failed", body: BLOCK_BODY });
  });

  it("passes every other error on, unchanged", async () => {
    const seen: unknown[] = [];
    const s = await setup({}, {}, true, (app, shield) => {
      app.use(shield.errorHandler());
      app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
        seen.push(error);
        res.status(500).send("mine");
      });
    });
    const parse = await exchange(`${s.base}/api/orders`, { method: "POST", headers: JSON_TYPE, body: "{not json" });
    expect(parse.status).toBe(500);
    expect(parse.body).toBe("mine");
    expect(seen[0]).toMatchObject({ type: "entity.parse.failed" });
  });

  it("is a four-argument Express error middleware, also on a disabled Shield", () => {
    const disabled = createShield({ key: "", endpoint: "" });
    const handler = disabled.errorHandler();
    expect(handler.length).toBe(4);
    const next = vi.fn();
    const error = new Error("x");
    handler(error, {} as never, {} as never, next);
    expect(next).toHaveBeenCalledWith(error);
  });
});

describe("privacy: no signature, nonce, hash, token or body leaves the process", () => {
  it("in Events, batches or log lines", async () => {
    const s = await setup({ signature_rules: [MONITOR_SECURE] });
    const body = '{"secret":"hunter2-body-marker"}';
    const n = freshNonce();
    const headers: Record<string, string> = {
      ...JSON_TYPE,
      ...signedHeaders({ method: "POST", target: "/api/orders", body, n, contentType: "application/json" }),
    };
    await exchange(`${s.base}/api/orders`, { method: "POST", headers, body });
    await exchange(`${s.base}/api/orders`, { method: "POST", headers, body: '{"secret":"other-body-marker"}' });
    await s.events(2);
    const leaked = s.leaked();
    const signature = (headers["ar-signature"] as string).split("s=")[1] as string;
    for (const secret of [signature, n, headers["ar-content-sha256"] as string, TOKEN, "hunter2", "other-body", JTI]) {
      expect(leaked).not.toContain(secret);
    }
  });
});

describe("the disabled Shield", () => {
  it("has a verifyBody that does nothing", () => {
    const shield = createShield({ key: "", endpoint: "" });
    expect(() => shield.verifyBody({} as never, {} as never, Buffer.from("x"), "utf-8")).not.toThrow();
  });
});

describe("EMPTY_CONTENT_SHA256", () => {
  it("is the hash of the empty body", () => {
    expect(sha("")).toBe(EMPTY_CONTENT_SHA256);
  });
});

describe("an internal error in the signature check (owner: fail closed only under an enforced requirement)", () => {
  async function serveWith(bundleRules: { signature: BundleRule[] }) {
    const { createExpressMiddleware } = await import("../src/express.ts");
    const { decide } = await import("../src/decide.ts");
    const { buildPolicy, routeOfDecision } = await import("../src/policy/store.ts");
    const { compilePattern } = await import("../src/policy/match.ts");
    const policy = buildPolicy({
      version: 3,
      issuedAt: NOW,
      notAfter: NOW + 86_400_000,
      rules: [],
      signatureRules: bundleRules.signature.map((r) => ({
        id: r.id,
        path: r.path,
        methods: r.methods,
        mode: r.mode,
        pattern: compilePattern(r.path) as NonNullable<ReturnType<typeof compilePattern>>,
      })),
    });
    const events: ShieldEvent[] = [];
    let internalErrors = 0;
    const calls: string[] = [];
    const app = express();
    app.use(
      createExpressMiddleware({
        decide: (input) => decide(policy, input),
        signature: () => {
          throw new Error("injected");
        },
        routeOf: routeOfDecision,
        record: (event) => void events.push(event),
        now: () => CLOCK,
        clientAddress: undefined,
        onInternalError: () => {
          internalErrors += 1;
        },
      }),
    );
    app.get("/api/secure", (_req, res) => {
      calls.push("secure");
      res.json({ ok: true });
    });
    app.get("/api/data", (_req, res) => {
      calls.push("data");
      res.json({ ok: true });
    });
    const listening = await listen(app);
    open.push(listening);
    return { base: listening.base, events, calls, internalErrors: () => internalErrors };
  }

  it("blocks with the standard 403 where an enforced requirement applies; records invalid", async () => {
    const s = await serveWith({ signature: [ENFORCE_SECURE] });
    const blocked = await exchange(`${s.base}/api/secure`);
    expect(blocked.status).toBe(403);
    expect(blocked.body).toBe(BLOCK_BODY);
    expect(s.calls).toEqual([]);
    for (let i = 0; i < 100 && s.events.length < 1; i++) await sleep(5);
    expect(s.events[0]?.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ENFORCE_SECURE.id });
    expect(s.events[0]?.signature?.status).toBe("invalid");
    expect(s.internalErrors()).toBe(1);
  });

  it("lets the request through elsewhere (no requirement on the route; a Monitor requirement); records invalid", async () => {
    const s = await serveWith({ signature: [ENFORCE_SECURE] });
    expect((await exchange(`${s.base}/api/data`)).status).toBe(200);
    const m = await serveWith({ signature: [MONITOR_SECURE] });
    expect((await exchange(`${m.base}/api/secure`)).status).toBe(200);
    for (let i = 0; i < 100 && (s.events.length < 1 || m.events.length < 1); i++) await sleep(5);
    expect(s.calls).toEqual(["data"]);
    expect(m.calls).toEqual(["secure"]);
    expect(s.events[0]?.decision).toMatchObject({ action: "allow" });
    expect(s.events[0]?.signature?.status).toBe("invalid");
    expect(m.events[0]?.decision).toMatchObject({ action: "block", mode: "monitor", rule_id: MONITOR_SECURE.id });
  });
});
