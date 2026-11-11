// Slice 03 over HTTP: the public Attestation service issues tokens that verify with the attestation keys of the
// signed Policy Bundle; Shield, in front of the reference target (ar-range), verifies the `ar-attestation` header
// offline and records the result on every request's Event — valid with the verdict, missing, invalid (forged
// signature, a key outside the bundle, another App's token) or expired — and never changes the response. The
// endpoints are public and cross-origin, refuse an unknown App, any bad nonce and (slice 04) a missing session public
// key or one whose thumbprint is not `cnf.jkt` with one fixed 400, and limit a caller's network prefix. No token
// reaches a stored Event.
//
// The expired token: no real token can be waited out here (300 s lifetime plus 30 s skew), and startApi's `now`
// would move every clock of the API at once. The running API's own key set signs it instead (`api.attestation`,
// the same object the attest route signs with), with `iat`/`exp` set 400/100 s in the past: a genuine signature by
// the bundle's current key, so the only thing wrong with it is its expiry.
//
// All requests of this file come from 127.0.0.1, one caller prefix (127.0.0.0/24) with a budget of 60 requests per
// minute across both endpoints: the tests spend about 20 and the last one uses up the rest.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  ATTESTATION_HEADER,
  type AttestationClaims,
  AttestResponseSchema,
  type BundleAttestationKey,
  BundlePayloadSchema,
  ChallengeResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  type EventAttestation,
  ListEventsResponseSchema,
  ProblemSchema,
  SignedBundleSchema,
  type StoredEvent,
  verdictFor,
} from "@antireverse/protocol";
import {
  attestationKid,
  deviceSubject,
  jwkThumbprint,
  signAttestationToken,
  verifyAttestationToken,
} from "@antireverse/protocol/server";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
const TTL_S = 300;
const PER_PREFIX_PER_MINUTE = 60;

let api: RunningApi;
let adminKey: string;
let appId: string;
let otherAppId: string;
let bundleKeys: BundleAttestationKey[];
let shield: Shield;
let range: http.Server;
let rangeUrl: string;
/** Every token this file obtained or made: none may appear in a stored Event. */
const tokens: string[] = [];
/** The Suspect (webdriver) token of the App, used for the requests through Shield. */
let suspectToken: string;
let attestRoundTripMs = 0;

function call(path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
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

type SessionJwk = { kty: "EC"; crv: "P-256"; x: string; y: string };

/**
 * The `cnf` of a fresh P-256 session key, as Guard sends it (slice 04 made `jwk` required): the public JWK (the four
 * public members only) and its RFC 7638 thumbprint.
 */
function sessionCnf(): { jkt: string; jwk: SessionJwk } {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = publicKey.export({ format: "jwk" }) as SessionJwk;
  const jwk: SessionJwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
  return { jkt: jwkThumbprint(jwk), jwk };
}

/** Guard's device id: 128 random bits as 22 base64url characters. */
const newDevice = () => randomBytes(16).toString("base64url");

async function challenge(app: string): Promise<string> {
  const response = await call("/v1/attest/challenge", { method: "POST", body: { app_id: app } });
  expect(response.status).toBe(200);
  expect(response.headers.get("access-control-allow-origin")).toBe("*");
  const body = ChallengeResponseSchema.parse(await response.json());
  // Valid for 60 s.
  const lifetime = Date.parse(body.expires_at) - Date.now();
  expect(lifetime).toBeGreaterThan(50_000);
  expect(lifetime).toBeLessThanOrEqual(60_000);
  return body.nonce;
}

function attestRequest(
  app: string,
  nonce: string,
  device: string,
  signals: string[],
  cnf: { jkt: string; jwk?: SessionJwk },
) {
  return call("/v1/attest", { method: "POST", body: { app_id: app, nonce, device, signals, cnf } });
}

/** Challenge and attest, as Guard does; the token, its claims (verified with the bundle) and the inputs. */
async function attest(app: string, signals: string[]) {
  const device = newDevice();
  const cnf = sessionCnf();
  const started = Date.now();
  const nonce = await challenge(app);
  const response = await attestRequest(app, nonce, device, signals, cnf);
  attestRoundTripMs = Date.now() - started;
  expect(response.status).toBe(200);
  expect(response.headers.get("access-control-allow-origin")).toBe("*");
  const { token, expires_at } = AttestResponseSchema.parse(await response.json());
  tokens.push(token);
  return { token, expiresAt: expires_at, device, cnf, nonce };
}

/** The token's verification with the bundle's attestation keys, as Shield does it offline. */
const verifyWithBundle = (token: string, app = appId) =>
  verifyAttestationToken(token, bundleKeys, { appId: app, nowS: Math.floor(Date.now() / 1000) });

const decodePart = (token: string, index: number): Record<string, unknown> =>
  JSON.parse(Buffer.from(token.split(".")[index] ?? "", "base64url").toString("utf8"));

async function storedEvents(): Promise<{ events: StoredEvent[]; raw: string }> {
  const response = await call(`/v1/apps/${appId}/events?limit=200`, { key: adminKey });
  expect(response.status).toBe(200);
  const raw = await response.text();
  return { events: ListEventsResponseSchema.parse(JSON.parse(raw)).events, raw };
}

/**
 * One request through Shield with `token` in `ar-attestation` (none when undefined); waits for its Event and
 * returns its attestation with the response. Requests go one at a time, so the newest Event is this request's.
 */
async function through(token: string | undefined, path = "/api/products/7") {
  const before = (await storedEvents()).events.length;
  const sentAt = Date.now();
  const response = await fetch(`${rangeUrl}${path}`, {
    headers: token === undefined ? {} : { [ATTESTATION_HEADER]: token },
  });
  const body = await response.text();
  const event = await until("Event stored", VISIBLE_BUDGET_MS, async () => {
    const { events } = await storedEvents();
    if (events.length <= before) return undefined;
    return [...events].sort((a, b) => b.event_id.localeCompare(a.event_id))[0];
  });
  const headers = Object.fromEntries([...response.headers].filter(([name]) => name !== "date"));
  return {
    attestation: event.attestation as EventAttestation | null,
    event,
    response: { status: response.status, headers, body },
    visibleMs: Date.now() - sentAt,
  };
}

/** Claims as the API would make them for the App, issued `ageS` seconds ago. */
function claimsFor(app: string, ageS = 0): AttestationClaims {
  const iat = Math.floor(Date.now() / 1000) - ageS;
  return {
    iss: "antireverse",
    aud: app,
    sub: deviceSubject(app, newDevice()),
    iat,
    exp: iat + TTL_S,
    jti: randomBytes(16).toString("hex"),
    cnf: sessionCnf(),
    verdict: "trusted",
    risk: 5,
    sig: [],
    pv: 1,
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
  const other = CreateAppResponseSchema.parse(
    await (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-admin" } })).json(),
  );
  otherAppId = other.app.id;

  const bundleResponse = await call("/v1/policy-bundle", { key: created.shield_key.key });
  expect(bundleResponse.status).toBe(200);
  const bundle = BundlePayloadSchema.parse(JSON.parse(SignedBundleSchema.parse(await bundleResponse.json()).bundle));
  bundleKeys = bundle.attestation_keys ?? [];

  // The customer's server: Shield (Shield key, policy public key, default poll interval) in front of ar-range.
  const signingKey = (await (await call("/v1/signing-key")).json()) as { public_key: string };
  shield = createShield({
    key: created.shield_key.key,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  range = http.createServer(createRangeServer({ shield }));
  await new Promise<void>((resolve) => range.listen(0, "127.0.0.1", resolve));
  rangeUrl = `http://127.0.0.1:${(range.address() as AddressInfo).port}`;
});

afterAll(async () => {
  await shield?.close();
  if (range) {
    range.closeAllConnections();
    await new Promise<void>((resolve) => range.close(() => resolve()));
  }
  await api?.close();
});

describe("slice 03 attestation over HTTP", () => {
  it("publishes the attestation keys in the bundle: current and next, each kid derived from its key", () => {
    // A fresh set: no previous yet, current signs, next is published ahead of use.
    expect(bundleKeys).toHaveLength(2);
    for (const key of bundleKeys) {
      expect(key.kid).toBe(attestationKid(Buffer.from(key.public_key, "base64url")));
    }
    expect(bundleKeys.map((k) => k.kid)).toEqual(api.attestation.attestationKeys().map((k) => k.kid));
    expect(bundleKeys.map((k) => k.kid)).toContain(api.attestation.currentKid());
  });

  it.each([
    { name: "no signal", signals: [] as string[], verdict: "trusted", risk: 5 },
    { name: "webdriver", signals: ["automation.webdriver"], verdict: "suspect", risk: 70 },
    {
      name: "webdriver and headless",
      signals: ["automation.webdriver", "automation.headless"],
      verdict: "hostile",
      risk: 100,
    },
  ])(
    "issues a token that verifies with the bundle's keys: $name → $verdict $risk",
    async ({ signals, verdict, risk }) => {
      const { token, expiresAt, device, cnf } = await attest(appId, signals);
      expect(verdictFor(signals)).toEqual({ verdict, risk });

      const header = decodePart(token, 0);
      expect(header).toEqual({ alg: "EdDSA", typ: "JWT", kid: api.attestation.currentKid() });
      const verified = verifyWithBundle(token);
      expect(verified.status).toBe("valid");
      if (verified.status !== "valid") return;
      const { claims } = verified;
      expect(claims).toMatchObject({
        iss: "antireverse",
        aud: appId,
        sub: deviceSubject(appId, device),
        // The session key itself travels in the token (slice 04), beside its thumbprint.
        cnf,
        verdict,
        risk,
        sig: signals,
        pv: 1,
      });
      expect(claims.sub).toMatch(/^dev_[0-9a-f]{24}$/);
      expect(claims.jti).toMatch(/^[0-9a-f]{32}$/);
      expect(claims.exp - claims.iat).toBe(TTL_S);
      expect(Math.abs(claims.iat - Date.now() / 1000)).toBeLessThan(5);
      expect(Date.parse(expiresAt)).toBe(claims.exp * 1000);
      // The raw device id never appears in the token.
      expect(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")).not.toContain(device);
      // Not for another App.
      expect(verifyWithBundle(token, otherAppId).status).toBe("invalid");
      if (verdict === "suspect") suspectToken = token;
    },
  );

  it("records valid with the verdict on the Event of a request with a token, and missing without one", async () => {
    const valid = await through(suspectToken);
    expect(valid.response.status).toBe(200);
    expect(valid.attestation).toEqual({ status: "valid", verdict: "suspect", risk: 70 });
    expect(valid.event.request).toMatchObject({ method: "GET", route: "/api/products/:id", status: 200 });

    // The same token again: answered from Shield's cache, the same result.
    expect((await through(suspectToken)).attestation).toEqual({ status: "valid", verdict: "suspect", risk: 70 });

    const missing = await through(undefined);
    expect(missing.attestation).toEqual({ status: "missing", verdict: null, risk: null });
    console.info(`attestation e2e: attest round trip ${attestRoundTripMs} ms; request -> Event ${valid.visibleMs} ms`);
  });

  it("records invalid for a forged signature, a key outside the bundle and another App's token", async () => {
    // One signature character flipped (not the last: its unused bits could leave the bytes unchanged).
    const [h, p, s = ""] = suspectToken.split(".");
    const flipped = `${h}.${p}.${s.slice(0, 10)}${s[10] === "A" ? "B" : "A"}${s.slice(11)}`;
    tokens.push(flipped);
    expect(verifyWithBundle(flipped).status).toBe("invalid");

    // A key the bundle does not carry: once under its own kid, once claiming the current kid.
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const raw = Buffer.from((publicKey.export({ format: "jwk" }) as { x: string }).x, "base64url");
    const ownKid = signAttestationToken(privateKey, attestationKid(raw), claimsFor(appId));
    const stolenKid = signAttestationToken(privateKey, api.attestation.currentKid(), claimsFor(appId));
    tokens.push(ownKid, stolenKid);

    // A genuine token of another App of the same Organization.
    const { token: foreign } = await attest(otherAppId, []);
    expect(verifyWithBundle(foreign, otherAppId).status).toBe("valid");

    const invalid = { status: "invalid", verdict: null, risk: null };
    for (const token of [flipped, ownKid, stolenKid, foreign]) {
      const result = await through(token);
      expect(result.response.status).toBe(200);
      expect(result.attestation).toEqual(invalid);
    }
  });

  it("records expired for a genuinely signed token past its expiry", async () => {
    const claims = { ...claimsFor(appId, 400), verdict: "suspect" as const, risk: 70, sig: ["automation.webdriver"] };
    expect(claims.exp - claims.iat).toBe(TTL_S);
    const expired = api.attestation.sign(claims);
    tokens.push(expired);
    expect(decodePart(expired, 0).kid).toBe(api.attestation.currentKid());
    expect(verifyWithBundle(expired).status).toBe("expired");
    expect((await through(expired)).attestation).toEqual({ status: "expired", verdict: null, risk: null });
  });

  it("answers the same with and without a token, whatever its state", async () => {
    const plain = (await through(undefined)).response;
    expect(plain.status).toBe(200);
    for (const token of [suspectToken, `${suspectToken.slice(0, -5)}AAAAA`, "not-a-token"]) {
      expect((await through(token)).response).toEqual(plain);
    }
    // An unruled 401 route too.
    const login = await fetch(`${rangeUrl}/api/login`, { method: "POST" });
    const loginWith = await fetch(`${rangeUrl}/api/login`, {
      method: "POST",
      headers: { [ATTESTATION_HEADER]: suspectToken },
    });
    expect([loginWith.status, await loginWith.text()]).toEqual([login.status, await login.text()]);
  });

  it("uses a nonce once, binds it to its App, requires a matching cnf.jwk, and refuses every bad case with one fixed 400", async () => {
    const device = newDevice();
    const cnf = sessionCnf();
    const nonce = await challenge(appId);
    expect((await attestRequest(appId, nonce, device, [], cnf)).status).toBe(200);

    const refusals = [
      // The same nonce again.
      await attestRequest(appId, nonce, device, [], cnf),
      // A nonce never issued.
      await attestRequest(appId, randomBytes(16).toString("hex"), device, [], cnf),
      // A nonce of this App presented for another.
      await attestRequest(otherAppId, await challenge(appId), device, [], cnf),
      // A fresh nonce, but no session public key (slice 04: cnf.jwk is required).
      await attestRequest(appId, await challenge(appId), device, [], { jkt: cnf.jkt }),
      // A fresh nonce, and a session public key whose thumbprint is not cnf.jkt.
      await attestRequest(appId, await challenge(appId), device, [], { jkt: cnf.jkt, jwk: sessionCnf().jwk }),
      // An unknown App.
      await call("/v1/attest/challenge", {
        method: "POST",
        body: { app_id: `app_${randomBytes(12).toString("hex")}` },
      }),
    ];
    const bodies: string[] = [];
    for (const response of refusals) {
      expect(response.status).toBe(400);
      expect(response.headers.get("access-control-allow-origin")).toBe("*");
      expect(response.headers.get("content-type")).toBe("application/problem+json");
      bodies.push(await response.text());
    }
    expect(new Set(bodies).size).toBe(1);
    expect(ProblemSchema.parse(JSON.parse(bodies[0] ?? "")).title).toBe("Attestation refused");
  });

  it("allows cross-origin calls without credentials", async () => {
    for (const path of ["/v1/attest/challenge", "/v1/attest"]) {
      const preflight = await fetch(`${api.url}${path}`, {
        method: "OPTIONS",
        headers: {
          origin: "https://shop.example",
          "access-control-request-method": "POST",
          "access-control-request-headers": "content-type",
        },
      });
      expect(preflight.status).toBe(204);
      expect(preflight.headers.get("access-control-allow-origin")).toBe("*");
      expect(preflight.headers.get("access-control-allow-methods")).toBe("POST, OPTIONS");
      expect(preflight.headers.get("access-control-allow-headers")).toBe("content-type");
      expect(preflight.headers.get("access-control-allow-credentials")).toBeNull();
    }
  });

  it("keeps every token out of the stored Events", async () => {
    const { events, raw } = await storedEvents();
    expect(events.length).toBeGreaterThanOrEqual(12);
    for (const token of tokens) {
      expect(raw).not.toContain(token);
      // Nor any part of it: the signature, the payload, the jti.
      const [, payload = "", signature = ""] = token.split(".");
      expect(raw).not.toContain(signature);
      expect(raw).not.toContain(payload);
      const jti = decodePart(token, 1).jti;
      if (typeof jti === "string") expect(raw).not.toContain(jti);
    }
    expect(raw).not.toContain("not-a-token");
    // Every Event of this file was made by a Shield that reports attestation.
    for (const event of events) expect(event.attestation).not.toBeNull();
  });

  it("limits a caller's network prefix: 429 with Retry-After once its minute is spent", async () => {
    let allowed = 0;
    let limited: Response | undefined;
    for (let i = 0; i <= PER_PREFIX_PER_MINUTE; i++) {
      const response = await call("/v1/attest/challenge", { method: "POST", body: { app_id: appId } });
      if (response.status === 429) {
        limited = response;
        break;
      }
      expect(response.status).toBe(200);
      await response.arrayBuffer();
      allowed++;
    }
    expect(limited, "a 429 within one minute's budget").toBeDefined();
    // The earlier tests of this file spent part of the same minute.
    expect(allowed).toBeGreaterThan(0);
    expect(allowed).toBeLessThan(PER_PREFIX_PER_MINUTE);
    const retryAfter = Number(limited?.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(1);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect(limited?.headers.get("access-control-allow-origin")).toBe("*");
    expect(ProblemSchema.parse(await limited?.json()).status).toBe(429);
    // Both endpoints count: attest is refused too, before its nonce is looked at.
    const attestLimited = await attestRequest(appId, randomBytes(16).toString("hex"), newDevice(), [], sessionCnf());
    expect(attestLimited.status).toBe(429);
    console.info(`attestation e2e: ${allowed} challenges left in the prefix's minute before 429`);
  });
});
