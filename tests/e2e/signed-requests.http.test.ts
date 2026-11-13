// Slice 04 over HTTP: a request signed with the session key of its Attestation Token passes a Rule that requires a
// signed request; the same request replayed, a stale one, one whose body changed after signing and an unsigned one
// do not. Shield verifies offline against `cnf.jwk` of the token and binds the body through the app's own body parser
// (`express.json({ verify: shield.verifyBody })`, `bodyVerified: { types: ["application/json"] }`). Every Event records the signature status
// and the body state; none records the signature, the nonce, the content hash or the token.
//
// The customer's server is built here rather than taken from ar-range: ar-range has no body parser and no route
// that takes a body. The token comes from the real challenge/attest endpoints with a P-256 key made in Node, the
// way Guard makes one in the browser; requests are signed with the protocol's reference signer.
//
// Two tests depend on the Shield change "verifyBody answers 403 only where an enforced requirement applies" (plan 04
// A5): a body changed after signing on a route with a Monitor requirement, or with no requirement, is recorded
// (invalid, mismatch) and the request continues.
import { createHash, generateKeyPairSync, type KeyObject } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  ATTESTATION_HEADER,
  AttestResponseSchema,
  BLOCK_RESPONSE_BODY,
  BundlePayloadSchema,
  ChallengeResponseSchema,
  CONTENT_HASH_HEADER,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  EMPTY_CONTENT_SHA256,
  ListEventsResponseSchema,
  PolicyResponseSchema,
  type PolicyRule,
  type PolicyRuleInput,
  SIGNATURE_HEADER,
  SignedBundleSchema,
  type StoredEvent,
} from "@antireverse/protocol";
import { jwkThumbprint, signRequestForTest, verifyRequestSignature } from "@antireverse/protocol/server";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
/** PB-16: a published Policy is applied within 15 seconds. */
const APPLIED_BUDGET_MS = 15_000;

type SessionJwk = { kty: "EC"; crv: "P-256"; x: string; y: string };

let api: RunningApi;
let adminKey: string;
let shieldKey: string;
let appId: string;
let shield: Shield;
let customer: http.Server;
let customerUrl: string;
let token: string;
let jti: string;
let jwk: SessionJwk;
let privateKey: KeyObject;
/** The Rules of the enforced version, by name. */
const ruleIds: Record<string, string> = {};
/** Every handler call, as `METHOD path`, and the bodies the order handlers received. */
const handled: string[] = [];
const received: unknown[] = [];
/** Every signature header sent: none may appear in a stored Event. */
const signatureHeaders: string[] = [];

function call(path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  // Slice 18a: every change carries a reason, as an operator gives one; sensitive changes refuse to go without.
  if (init.key && (init.method ?? "GET") !== "GET") headers["x-airverse-reason"] = "End-to-end test";
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return fetch(`${api.url}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
}

async function until<T>(what: string, budgetMs: number, probe: () => Promise<T | undefined>): Promise<T> {
  const started = Date.now();
  for (;;) {
    const value = await probe();
    if (value !== undefined) return value;
    if (Date.now() - started > budgetMs) throw new Error(`${what}: not within ${budgetMs} ms`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

const sha256 = (body: string): string => createHash("sha256").update(body, "utf8").digest("base64url");

async function publish(
  rules: PolicyRuleInput[],
  expectedVersion: number,
): Promise<{ version: number; rules: PolicyRule[] }> {
  const response = await call(`/v1/apps/${appId}/policies/development`, {
    method: "PUT",
    key: adminKey,
    body: { rules, expected_version: expectedVersion },
  });
  expect(response.status).toBe(201);
  const { policy } = PolicyResponseSchema.parse(await response.json());
  return { version: policy.version, rules: policy.rules };
}

async function storedEvents(): Promise<{ events: StoredEvent[]; raw: string }> {
  const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
  expect(response.status).toBe(200);
  const raw = await response.text();
  return { events: ListEventsResponseSchema.parse(JSON.parse(raw)).events, raw };
}

interface Sent {
  method: string;
  path: string;
  headers: Record<string, string>;
  body?: string;
}

/**
 * A request signed as Guard signs it: the token, the signature over method, target, body hash, t, n and the token's
 * jti, and the body hash. `t` and `n` default to now and fresh random bytes.
 */
function signed(method: string, path: string, body?: string, options: { t?: number } = {}): Sent {
  const contentSha256 = body === undefined ? EMPTY_CONTENT_SHA256 : sha256(body);
  const header = signRequestForTest({
    privateKey,
    method,
    target: path,
    contentType: body === undefined ? "" : "application/json",
    contentSha256,
    jti,
    ...(options.t === undefined ? {} : { t: options.t }),
  });
  signatureHeaders.push(header);
  const headers: Record<string, string> = {
    [ATTESTATION_HEADER]: token,
    [SIGNATURE_HEADER]: header,
    [CONTENT_HASH_HEADER]: contentSha256,
  };
  if (body !== undefined) headers["content-type"] = "application/json";
  return { method, path, headers, ...(body === undefined ? {} : { body }) };
}

/** A request with the token and no signature. */
function unsigned(method: string, path: string, body?: string): Sent {
  const headers: Record<string, string> = { [ATTESTATION_HEADER]: token };
  if (body !== undefined) headers["content-type"] = "application/json";
  return { method, path, headers, ...(body === undefined ? {} : { body }) };
}

/**
 * Sends one request to the customer's server and waits for its Event. Requests go one at a time, so the newest
 * Event is this request's.
 */
async function through(request: Sent) {
  const before = (await storedEvents()).events.length;
  const handledBefore = handled.length;
  const sentAt = Date.now();
  const response = await fetch(`${customerUrl}${request.path}`, {
    method: request.method,
    headers: request.headers,
    ...(request.body === undefined ? {} : { body: request.body }),
  });
  const body = await response.text();
  const event = await until("Event stored", VISIBLE_BUDGET_MS, async () => {
    const { events } = await storedEvents();
    if (events.length <= before) return undefined;
    return [...events].sort((a, b) => b.event_id.localeCompare(a.event_id))[0];
  });
  return {
    status: response.status,
    body,
    event,
    handlerRan: handled.length > handledBefore,
    visibleMs: Date.now() - sentAt,
  };
}

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });
  const organization = CreateOrganizationResponseSchema.parse(
    await (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
  );
  appId = created.app.id;
  shieldKey = created.shield_key.key;

  // The session key, made in Node as Guard makes it in the browser; the token carries its public half.
  const pair = generateKeyPairSync("ec", { namedCurve: "P-256" });
  privateKey = pair.privateKey;
  const exported = pair.publicKey.export({ format: "jwk" }) as SessionJwk;
  jwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
  const challenge = await call("/v1/attest/challenge", { method: "POST", body: { app_id: appId } });
  expect(challenge.status).toBe(200);
  const { nonce } = ChallengeResponseSchema.parse(await challenge.json());
  const attest = await call("/v1/attest", {
    method: "POST",
    body: {
      app_id: appId,
      nonce,
      device: "AAAAAAAAAAAAAAAAAAAAAA",
      signals: [],
      cnf: { jkt: jwkThumbprint(jwk), jwk },
    },
  });
  expect(attest.status).toBe(200);
  token = AttestResponseSchema.parse(await attest.json()).token;
  const claims = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
  expect(claims.cnf).toEqual({ jkt: jwkThumbprint(jwk), jwk });
  jti = claims.jti;

  // The customer's server: Shield first, then the body parser with Shield's verify hook, then the routes.
  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    bodyVerified: { types: ["application/json"] },
    logger: { warn() {} },
  });
  const app = express();
  app.disable("x-powered-by");
  app.use(shield.express());
  app.use(express.json({ verify: shield.verifyBody }));
  const route = (method: "get" | "post", path: string) =>
    app[method](path, (req, res) => {
      handled.push(`${method.toUpperCase()} ${path}`);
      if (method === "post") received.push(req.body);
      res.json({ ok: true });
    });
  route("post", "/api/orders"); // Enforce requirement
  route("get", "/api/admin/reports"); // Enforce requirement
  route("post", "/api/cart"); // Monitor requirement
  route("get", "/api/catalog"); // no Rule
  route("post", "/api/feedback"); // no Rule
  customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  customerUrl = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;

  // Requirement Rules start in Monitor mode (version 1); two are then promoted to Enforce (version 2), as the
  // Console does it.
  const rules: PolicyRuleInput[] = [
    { name: "Orders", path: "/api/orders", methods: ["POST"], requires: "signature" },
    { name: "Admin area", path: "/api/admin/**", methods: ["GET"], requires: "signature" },
    { name: "Cart", path: "/api/cart", methods: ["POST"], requires: "signature" },
  ];
  const first = await publish(rules, 0);
  const promoted = await publish(
    first.rules.map((rule) => (rule.name === "Cart" ? rule : { ...rule, mode: "enforce" as const })),
    first.version,
  );
  for (const rule of promoted.rules) ruleIds[rule.name] = rule.id;
  expect(promoted.rules.map((r) => [r.name, r.mode, r.requires])).toEqual([
    ["Orders", "enforce", "signature"],
    ["Admin area", "enforce", "signature"],
    ["Cart", "monitor", "signature"],
  ]);

  // Shield polls on its own; refreshPolicy only shortens the wait.
  await until("Policy applied", APPLIED_BUDGET_MS, async () => {
    await shield.refreshPolicy();
    return shield.stats().policyVersion === promoted.version ? true : undefined;
  });
  expect(shield.stats()).toMatchObject({ policyRules: 3, lastPolicyError: null });
});

afterAll(async () => {
  await shield?.close();
  if (customer) {
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 04 signed requests over HTTP", () => {
  it("ships the requirement Rules in signature_rules only, without name or requires", async () => {
    const response = await call("/v1/policy-bundle", { key: shieldKey });
    expect(response.status).toBe(200);
    const text = SignedBundleSchema.parse(await response.json()).bundle;
    const bundle = BundlePayloadSchema.parse(JSON.parse(text));
    expect(bundle.rules).toEqual([]);
    expect(bundle.signature_rules).toEqual([
      { id: ruleIds.Orders, path: "/api/orders", methods: ["POST"], action: "block", mode: "enforce" },
      { id: ruleIds["Admin area"], path: "/api/admin/**", methods: ["GET"], action: "block", mode: "enforce" },
      { id: ruleIds.Cart, path: "/api/cart", methods: ["POST"], action: "block", mode: "monitor" },
    ]);
    // An older Shield must not find a requirement it could read as a plain block.
    expect(text).not.toContain("requires");
    expect(text).not.toContain("Orders");
  });

  it("signs as the protocol's reference verifier expects", () => {
    const request = signed("GET", "/api/admin/reports?week=12");
    expect(
      verifyRequestSignature({
        method: "GET",
        target: "/api/admin/reports?week=12",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        header: request.headers[SIGNATURE_HEADER],
        jti,
        jwk,
        nowS: Math.floor(Date.now() / 1000),
      }),
    ).toBe("valid");
  });

  it("serves a correctly signed GET on an enforced route: signature valid, no body", async () => {
    const result = await through(signed("GET", "/api/admin/reports?week=12"));
    expect(result.status).toBe(200);
    expect(result.handlerRan).toBe(true);
    expect(result.event.signature).toEqual({ status: "valid", body: "none" });
    expect(result.event.attestation).toMatchObject({ status: "valid" });
    expect(result.event.decision).toMatchObject({ action: "allow", rule_id: null });
    console.info(`signed-requests e2e: signed GET -> Event ${result.visibleMs} ms`);
  });

  it("serves a signed POST with a JSON body (body checked), and blocks the same request replayed", async () => {
    const body = JSON.stringify({ sku: "lantern", quantity: 2 });
    const request = signed("POST", "/api/orders", body);
    received.length = 0;
    const first = await through(request);
    expect(first.status).toBe(200);
    expect(first.handlerRan).toBe(true);
    expect(received).toEqual([{ sku: "lantern", quantity: 2 }]);
    expect(first.event.signature).toEqual({ status: "valid", body: "checked" });
    expect(first.event.decision).toMatchObject({ action: "allow", rule_id: null });

    // Byte for byte the same request again: the nonce was used.
    const replay = await through(request);
    expect([replay.status, replay.body]).toEqual([403, BLOCK_RESPONSE_BODY]);
    expect(replay.handlerRan).toBe(false);
    expect(replay.event.signature).toEqual({ status: "replayed", body: "unchecked" });
    expect(replay.event.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ruleIds.Orders });
    expect(replay.event.request).toMatchObject({ method: "POST", route: "/api/orders", status: 403 });
  });

  it("blocks a request signed more than 60 s ago as stale", async () => {
    const result = await through(
      signed("GET", "/api/admin/reports", undefined, { t: Math.floor(Date.now() / 1000) - 61 }),
    );
    expect([result.status, result.body]).toEqual([403, BLOCK_RESPONSE_BODY]);
    expect(result.handlerRan).toBe(false);
    expect(result.event.signature).toEqual({ status: "stale", body: "none" });
    expect(result.event.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ruleIds["Admin area"] });
  });

  it("refuses a signed POST whose body changed after signing, before the handler", async () => {
    const request = signed("POST", "/api/orders", JSON.stringify({ sku: "lantern", quantity: 2 }));
    const tampered = { ...request, body: JSON.stringify({ sku: "lantern", quantity: 200 }) };
    const result = await through(tampered);
    expect(result.status).toBe(403);
    expect(result.handlerRan).toBe(false);
    expect(result.event.signature).toEqual({ status: "invalid", body: "mismatch" });
    expect(result.event.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ruleIds.Orders });
    expect(result.event.request).toMatchObject({ method: "POST", route: "/api/orders", status: 403 });
  });

  it("blocks unsigned requests on the enforced routes (signature missing)", async () => {
    const get = await through(unsigned("GET", "/api/admin/reports"));
    expect([get.status, get.body]).toEqual([403, BLOCK_RESPONSE_BODY]);
    expect(get.handlerRan).toBe(false);
    expect(get.event.signature).toEqual({ status: "missing", body: null });
    expect(get.event.attestation).toMatchObject({ status: "valid" });
    expect(get.event.decision).toMatchObject({ action: "block", mode: "enforce", rule_id: ruleIds["Admin area"] });

    const post = await through(unsigned("POST", "/api/orders", JSON.stringify({ sku: "rope", quantity: 1 })));
    expect([post.status, post.body]).toEqual([403, BLOCK_RESPONSE_BODY]);
    expect(post.handlerRan).toBe(false);
    expect(post.event.signature).toEqual({ status: "missing", body: null });
  });

  it("serves an unsigned request on the Monitor requirement route and marks it", async () => {
    const result = await through(unsigned("POST", "/api/cart", JSON.stringify({ sku: "tarp" })));
    expect(result.status).toBe(200);
    expect(result.handlerRan).toBe(true);
    expect(result.event.signature).toEqual({ status: "missing", body: null });
    expect(result.event.decision).toMatchObject({ action: "block", mode: "monitor", rule_id: ruleIds.Cart });
    expect(result.event.request).toMatchObject({ route: "/api/cart", status: 200 });
  });

  it("serves an unsigned request on a route without a requirement (signature missing)", async () => {
    const result = await through(unsigned("GET", "/api/catalog"));
    expect(result.status).toBe(200);
    expect(result.handlerRan).toBe(true);
    expect(result.event.signature).toEqual({ status: "missing", body: null });
    expect(result.event.decision).toMatchObject({ action: "allow", rule_id: null });
  });

  // Depends on the Shield change of plan 04 A5: verifyBody answers 403 only where an enforced requirement applies.
  it("records a changed body on the Monitor requirement route and lets the request through", async () => {
    const request = signed("POST", "/api/cart", JSON.stringify({ sku: "tarp", quantity: 1 }));
    const result = await through({ ...request, body: JSON.stringify({ sku: "tarp", quantity: 9 }) });
    expect(result.status).toBe(200);
    expect(result.handlerRan).toBe(true);
    expect(result.event.signature).toEqual({ status: "invalid", body: "mismatch" });
    expect(result.event.decision).toMatchObject({ mode: "monitor", rule_id: ruleIds.Cart });
  });

  // Depends on the same Shield change.
  it("records a changed body on a route without a requirement and lets the request through", async () => {
    const request = signed("POST", "/api/feedback", JSON.stringify({ text: "great" }));
    const result = await through({ ...request, body: JSON.stringify({ text: "awful" }) });
    expect(result.status).toBe(200);
    expect(result.handlerRan).toBe(true);
    expect(result.event.signature).toEqual({ status: "invalid", body: "mismatch" });
    expect(result.event.decision).toMatchObject({ action: "allow", rule_id: null });
  });

  it("keeps the token, signatures, nonces and body hashes out of the stored Events", async () => {
    const { events, raw } = await storedEvents();
    expect(events.length).toBeGreaterThanOrEqual(10);
    expect(raw).not.toContain(token.split(".")[2] ?? token);
    expect(raw).not.toContain(jti);
    for (const header of signatureHeaders) {
      const [, , n = "", s = ""] = header.split(/,[tns]=/);
      expect(raw).not.toContain(s);
      expect(raw).not.toContain(n);
    }
    expect(raw).not.toContain(EMPTY_CONTENT_SHA256);
    expect(raw).not.toContain("lantern");
    for (const event of events) expect(event.signature).not.toBeNull();
  });
});
